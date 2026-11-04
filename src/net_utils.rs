use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::warn;

const SOCKET_BUF_SIZE: usize = 512 * 1024;
const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_UDP_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
#[allow(dead_code)]
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_CLASS_IN: u16 = 1;

/// Normalize an IPv4-mapped IPv6 `SocketAddr` (`[::ffff:a.b.c.d]:port`) to `SocketAddr::V4`.
pub fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(v4), v6.port())
            } else {
                SocketAddr::V6(v6)
            }
        }
        SocketAddr::V4(v4) => SocketAddr::V4(v4),
    }
}

/// Format an IP + port into a valid socket address string (`[ipv6]:port` or `ipv4:port`).
pub fn format_bind_addr(bind_ip: &str, port: u16) -> String {
    let trimmed = bind_ip.trim();
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        format!("{}:{}", trimmed, port)
    } else if trimmed.contains(':') {
        format!("[{}]:{}", trimmed, port)
    } else {
        format!("{}:{}", trimmed, port)
    }
}

/// Replace the control port of `server_addr` with `remote_port` while preserving host/IPv6 formatting.
pub fn format_server_proxy_addr(server_addr: &str, remote_port: u16) -> String {
    let trimmed = server_addr.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once("]:") {
            return format_bind_addr(host, remote_port);
        }
    }
    if let Some((host, _)) = trimmed.rsplit_once(':') {
        return format_bind_addr(host, remote_port);
    }
    format_bind_addr(trimmed, remote_port)
}

/// Resolve an address string (supporting hostnames, IPv4, and IPv6) into a list of `SocketAddr`.
pub async fn resolve_socket_addrs(addr_str: &str) -> Result<Vec<SocketAddr>> {
    let trimmed = addr_str.trim();
    if let Ok(sa) = trimmed.parse::<SocketAddr>() {
        return Ok(vec![sa]);
    }

    if let Ok((host, port)) = split_host_port(trimmed) {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        let hosts_addrs = lookup_etc_hosts(host, port);
        if !hosts_addrs.is_empty() {
            return Ok(prioritize_routable_addrs(hosts_addrs));
        }

        let dns_addrs = lookup_dns_strict(host, port).await;
        if !dns_addrs.is_empty() {
            return Ok(prioritize_routable_addrs(dns_addrs));
        }
    }

    let addrs: Vec<SocketAddr> = timeout(DNS_RESOLVE_TIMEOUT, lookup_host(trimmed))
        .await
        .with_context(|| format!("timed out resolving address '{}'", trimmed))?
        .with_context(|| format!("failed to resolve address '{}'", trimmed))?
        .collect();
    if addrs.is_empty() {
        return Err(anyhow!("no socket addresses resolved for '{}'", trimmed));
    }
    Ok(prioritize_routable_addrs(addrs))
}

/// Split `host:port` / `[ipv6]:port` into its parts, validating the port.
pub fn split_host_port(addr_str: &str) -> Result<(&str, u16)> {
    if let Some(rest) = addr_str.strip_prefix('[') {
        let (host, port_part) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow!("invalid bracketed address '{}'", addr_str))?;
        let port: u16 = port_part
            .parse()
            .with_context(|| format!("invalid port in '{}'", addr_str))?;
        Ok((host, port))
    } else {
        let (host, port_part) = addr_str
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("missing port in address '{}'", addr_str))?;
        let port: u16 = port_part
            .parse()
            .with_context(|| format!("invalid port in '{}'", addr_str))?;
        Ok((host, port))
    }
}

fn lookup_etc_hosts(host: &str, port: u16) -> Vec<SocketAddr> {
    let target = host.trim_end_matches('.');
    if target.is_empty() {
        return Vec::new();
    }
    let Ok(content) = fs::read_to_string("/etc/hosts") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(ip_str) = parts.next() else {
            continue;
        };
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            continue;
        };
        for alias in parts {
            if alias.trim_end_matches('.').eq_ignore_ascii_case(target) {
                let sa = SocketAddr::new(ip, port);
                if !out.contains(&sa) {
                    out.push(sa);
                }
            }
        }
    }
    out
}

fn system_nameservers() -> Vec<SocketAddr> {
    let Ok(content) = fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    let mut servers = Vec::new();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let line = line.split(';').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        if parts.next() == Some("nameserver") {
            if let Some(ip_str) = parts.next() {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    let ns = SocketAddr::new(ip, 53);
                    if !servers.contains(&ns) {
                        servers.push(ns);
                    }
                }
            }
        }
    }
    servers
}

async fn lookup_dns_strict(host: &str, port: u16) -> Vec<SocketAddr> {
    let nameservers = system_nameservers();
    if nameservers.is_empty() {
        return Vec::new();
    }

    for ns in nameservers {
        // Query A and AAAA on two separate ephemeral UDP sockets so NAT/WSL2 DNS proxies
        // never drop concurrent queries from the same source port, and strictly validate
        // RR owner names so glue records in ANCOUNT (a known WSL2 + musl bug) are ignored.
        let (v4_ips, v6_ips) = tokio::join!(
            query_dns_single(ns, host, DNS_TYPE_A),
            query_dns_single(ns, host, DNS_TYPE_AAAA)
        );

        let mut addrs = Vec::with_capacity(v4_ips.len() + v6_ips.len());
        for ip in v4_ips.into_iter().chain(v6_ips) {
            let sa = SocketAddr::new(ip, port);
            if !addrs.contains(&sa) {
                addrs.push(sa);
            }
        }
        if !addrs.is_empty() {
            return addrs;
        }
    }

    Vec::new()
}

async fn query_dns_single(ns: SocketAddr, host: &str, qtype: u16) -> Vec<IpAddr> {
    let qid = (rand::rngs::OsRng.next_u32() & 0xFFFF) as u16;
    let Some(query_pkt) = build_dns_query(qid, host, qtype) else {
        return Vec::new();
    };
    let Ok(sock) = bind_ephemeral_udp_for_target(ns) else {
        return Vec::new();
    };
    if sock.send_to(&query_pkt, ns).await.is_err() {
        return Vec::new();
    }

    let mut recv_buf = [0u8; 2048];
    let Ok(Ok((n, _from))) = timeout(DNS_UDP_QUERY_TIMEOUT, sock.recv_from(&mut recv_buf)).await
    else {
        return Vec::new();
    };

    parse_dns_response(&recv_buf[..n], qid, host, qtype)
}

fn build_dns_query(qid: u16, host: &str, qtype: u16) -> Option<Vec<u8>> {
    let clean = host.trim().trim_end_matches('.');
    if clean.is_empty() {
        return None;
    }
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&qid.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD (Recursion Desired)
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    for label in clean.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        pkt.push(bytes.len() as u8);
        pkt.extend_from_slice(bytes);
    }
    pkt.push(0); // root label
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Some(pkt)
}

fn decode_dns_name(pkt: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end_offset = None;
    let mut jumps = 0usize;

    loop {
        if offset >= pkt.len() || jumps > 16 {
            return None;
        }
        let b = pkt[offset];
        if b == 0 {
            let final_offset = end_offset.unwrap_or(offset + 1);
            return Some((labels.join("."), final_offset));
        } else if (b & 0xC0) == 0xC0 {
            if offset + 1 >= pkt.len() {
                return None;
            }
            if end_offset.is_none() {
                end_offset = Some(offset + 2);
            }
            let ptr = (((b & 0x3F) as usize) << 8) | (pkt[offset + 1] as usize);
            offset = ptr;
            jumps += 1;
        } else if (b & 0xC0) == 0 {
            let len = b as usize;
            if offset + 1 + len > pkt.len() {
                return None;
            }
            let label = std::str::from_utf8(&pkt[offset + 1..offset + 1 + len]).ok()?;
            labels.push(label.to_ascii_lowercase());
            offset += 1 + len;
        } else {
            return None;
        }
    }
}

struct ParsedDnsRecord {
    owner: String,
    rtype: u16,
    rclass: u16,
    rdata_offset: usize,
    rdlength: usize,
}

fn parse_dns_response(
    pkt: &[u8],
    expected_qid: u16,
    query_host: &str,
    expected_qtype: u16,
) -> Vec<IpAddr> {
    if pkt.len() < 12 {
        return Vec::new();
    }
    let qid = u16::from_be_bytes([pkt[0], pkt[1]]);
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    if qid != expected_qid {
        return Vec::new();
    }
    // Must be a response (QR=1), not truncated (TC=0), and NOERROR (RCODE=0)
    if (flags & 0x8000) == 0 || (flags & 0x0200) != 0 || (flags & 0x000F) != 0 {
        return Vec::new();
    }

    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;

    let mut offset = 12;
    for _ in 0..qdcount {
        let Some((_qname, next_off)) = decode_dns_name(pkt, offset) else {
            return Vec::new();
        };
        if next_off + 4 > pkt.len() {
            return Vec::new();
        }
        offset = next_off + 4;
    }

    let mut records = Vec::with_capacity(ancount.min(64));
    for _ in 0..ancount {
        let Some((owner, next_off)) = decode_dns_name(pkt, offset) else {
            break;
        };
        if next_off + 10 > pkt.len() {
            break;
        }
        let rtype = u16::from_be_bytes([pkt[next_off], pkt[next_off + 1]]);
        let rclass = u16::from_be_bytes([pkt[next_off + 2], pkt[next_off + 3]]);
        let rdlength = u16::from_be_bytes([pkt[next_off + 8], pkt[next_off + 9]]) as usize;
        let rdata_offset = next_off + 10;
        if rdata_offset + rdlength > pkt.len() {
            break;
        }
        records.push(ParsedDnsRecord {
            owner,
            rtype,
            rclass,
            rdata_offset,
            rdlength,
        });
        offset = rdata_offset + rdlength;
    }

    let mut accepted_names = vec![query_host.trim().trim_end_matches('.').to_ascii_lowercase()];
    loop {
        let mut added = false;
        for rec in &records {
            if rec.rclass == DNS_CLASS_IN
                && rec.rtype == DNS_TYPE_CNAME
                && accepted_names.iter().any(|n| n == &rec.owner)
            {
                if let Some((cname_target, _)) = decode_dns_name(pkt, rec.rdata_offset) {
                    if !accepted_names.contains(&cname_target) {
                        accepted_names.push(cname_target);
                        added = true;
                    }
                }
            }
        }
        if !added {
            break;
        }
    }

    let mut ips = Vec::new();
    for rec in &records {
        if rec.rclass != DNS_CLASS_IN
            || rec.rtype != expected_qtype
            || !accepted_names.iter().any(|n| n == &rec.owner)
        {
            continue;
        }
        match (rec.rtype, rec.rdlength) {
            (DNS_TYPE_A, 4) => {
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&pkt[rec.rdata_offset..rec.rdata_offset + 4]);
                let ip = IpAddr::V4(Ipv4Addr::from(octets));
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            (DNS_TYPE_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&pkt[rec.rdata_offset..rec.rdata_offset + 16]);
                let ip = IpAddr::V6(Ipv6Addr::from(octets));
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            _ => {}
        }
    }

    ips
}

fn is_addr_routable(addr: SocketAddr) -> bool {
    let bind_addr = match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let Ok(sock) = std::net::UdpSocket::bind(bind_addr) else {
        return false;
    };
    sock.connect(addr).is_ok()
}

fn prioritize_routable_addrs(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    if addrs.len() <= 1 {
        return addrs;
    }
    let mut routable = Vec::with_capacity(addrs.len());
    let mut unroutable = Vec::new();
    for addr in addrs {
        if is_addr_routable(addr) {
            if !routable.contains(&addr) {
                routable.push(addr);
            }
        } else if !unroutable.contains(&addr) {
            unroutable.push(addr);
        }
    }
    routable.extend(unroutable);
    routable
}

/// When the host has IPv6 disabled entirely (common on minimal VPS images), binding the default
/// dual-stack wildcard `[::]` fails. Fall back to the IPv4 wildcard so the default configuration
/// still works there instead of refusing to start.
fn ipv4_wildcard_fallback(addr: SocketAddr, error: &std::io::Error) -> Option<SocketAddr> {
    let SocketAddr::V6(v6) = addr else {
        return None;
    };
    if !v6.ip().is_unspecified() {
        return None;
    }
    let ipv6_unavailable = matches!(
        error.raw_os_error(),
        Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL | libc::EPROTONOSUPPORT)
    );
    ipv6_unavailable.then(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), v6.port()))
}

fn bind_tcp_listener_at(
    addr: SocketAddr,
    defer_accept: Option<Duration>,
) -> std::io::Result<TcpListener> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    if let SocketAddr::V6(v6) = addr {
        if v6.ip().is_unspecified() {
            // Enable dual-stack IPv4 + IPv6 when binding to [::]:port
            let _ = socket.set_only_v6(false);
        }
    }

    // SO_REUSEADDR lets a restarted server rebind while old connections sit in TIME_WAIT. It does
    // not allow two live TCP listeners on the same port, so proxy port conflicts still surface.
    let _ = socket.set_reuse_address(true);
    let _ = socket.set_nodelay(true);
    let _ = socket.set_recv_buffer_size(SOCKET_BUF_SIZE);
    let _ = socket.set_send_buffer_size(SOCKET_BUF_SIZE);
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    if let Some(wait) = defer_accept {
        set_tcp_defer_accept(&socket, wait);
    }

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// `TCP_DEFER_ACCEPT`: the kernel keeps a completed connection out of the accept queue until the
/// peer sends data or `wait` elapses. A port scanner or idle flood therefore occupies no file
/// descriptor and no task on the server for that long. Only for listeners whose protocol has the
/// client speak first, which the rrp control port does; a proxied service may greet first.
#[cfg(target_os = "linux")]
fn set_tcp_defer_accept(socket: &Socket, wait: Duration) {
    use std::os::fd::AsRawFd;
    let secs: libc::c_int = wait.as_secs().clamp(1, i32::MAX as u64) as libc::c_int;
    // SAFETY: plain setsockopt on a socket we own, with a correctly sized c_int value.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_DEFER_ACCEPT,
            &secs as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        warn!(
            "failed to set TCP_DEFER_ACCEPT: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn set_tcp_defer_accept(_socket: &Socket, _wait: Duration) {}

/// Make `close` send a RST instead of a FIN and skip TIME_WAIT. Used for connections the server
/// refuses before authentication, so a flood leaves no lingering state behind and the peer gets
/// nothing but a reset.
///
/// A zero linger never blocks on close (the kernel just emits the RST), which is why this does
/// not go through tokio's deprecated `set_linger`.
pub fn reset_on_close(stream: &TcpStream) {
    let _ = SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

/// Undo [`reset_on_close`] once a connection has authenticated.
pub fn graceful_close(stream: &TcpStream) {
    let _ = SockRef::from(stream).set_linger(None);
}

/// Bind a high-performance TCP listener supporting IPv4, IPv6, and dual-stack (`[::]:port`).
pub fn bind_tcp_listener(addr_str: &str) -> Result<TcpListener> {
    bind_tcp_listener_with(addr_str, None)
}

/// Like [`bind_tcp_listener`], additionally enabling `TCP_DEFER_ACCEPT` for `defer_accept` where
/// the platform supports it (Linux). Use only when the client is the first to send data.
pub fn bind_tcp_listener_with(
    addr_str: &str,
    defer_accept: Option<Duration>,
) -> Result<TcpListener> {
    let addr: SocketAddr = addr_str
        .parse()
        .with_context(|| format!("invalid TCP bind address '{}'", addr_str))?;

    match bind_tcp_listener_at(addr, defer_accept) {
        Ok(listener) => Ok(listener),
        Err(error) => {
            if let Some(v4_addr) = ipv4_wildcard_fallback(addr, &error) {
                warn!(
                    "IPv6 appears unavailable ({}); binding TCP listener on {} instead of {}",
                    error, v4_addr, addr
                );
                return bind_tcp_listener_at(v4_addr, defer_accept)
                    .with_context(|| format!("failed to bind TCP socket on {}", v4_addr));
            }
            Err(error).with_context(|| format!("failed to bind TCP socket on {}", addr))
        }
    }
}

fn bind_udp_socket_at(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    if let SocketAddr::V6(v6) = addr {
        if v6.ip().is_unspecified() {
            // Enable dual-stack IPv4 + IPv6 when binding to [::]:port
            let _ = socket.set_only_v6(false);
        }
    }

    // Deliberately no SO_REUSEADDR: on Linux and BSD/macOS it lets several UDP sockets bind the
    // same port, so two clients registering the same UDP remote_port would both "succeed" and
    // visitor traffic would silently reach only one of them. Binding must be exclusive.
    let _ = socket.set_recv_buffer_size(SOCKET_BUF_SIZE);
    let _ = socket.set_send_buffer_size(SOCKET_BUF_SIZE);
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    let std_udp: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_udp)
}

/// Bind a high-performance UDP socket supporting IPv4, IPv6, and dual-stack (`[::]:port`).
pub fn bind_udp_socket(addr_str: &str) -> Result<UdpSocket> {
    let addr: SocketAddr = addr_str
        .parse()
        .with_context(|| format!("invalid UDP bind address '{}'", addr_str))?;

    match bind_udp_socket_at(addr) {
        Ok(socket) => Ok(socket),
        Err(error) => {
            if let Some(v4_addr) = ipv4_wildcard_fallback(addr, &error) {
                warn!(
                    "IPv6 appears unavailable ({}); binding UDP socket on {} instead of {}",
                    error, v4_addr, addr
                );
                return bind_udp_socket_at(v4_addr)
                    .with_context(|| format!("failed to bind UDP socket on {}", v4_addr));
            }
            Err(error).with_context(|| format!("failed to bind UDP socket on {}", addr))
        }
    }
}

/// Bind an ephemeral local UDP socket matching the address family (IPv4 or IPv6) of `target`.
/// This allows transparent IPv4 <-> IPv6 UDP translation across the tunnel.
pub fn bind_ephemeral_udp_for_target(target: SocketAddr) -> Result<UdpSocket> {
    let bind_addr = match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    bind_udp_socket(&bind_addr.to_string())
}

/// Connect to a target TCP endpoint (supporting IPv4, IPv6, and hostnames) with TCP_NODELAY and tuned buffers.
pub async fn connect_tcp(target_str: &str) -> Result<TcpStream> {
    let addrs = resolve_socket_addrs(target_str).await?;
    let mut preferred_err: Option<std::io::Error> = None;
    let mut fallback_err: Option<std::io::Error> = None;

    for addr in addrs {
        let connect_res = match timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(res) => res,
            Err(_) => Err(std::io::Error::new(
                ErrorKind::TimedOut,
                format!(
                    "connection to {} timed out after {:?}",
                    addr, TCP_CONNECT_TIMEOUT
                ),
            )),
        };

        match connect_res {
            Ok(stream) => {
                configure_tcp_stream(&stream);
                return Ok(stream);
            }
            Err(e) => {
                let is_unroutable_family = matches!(e.kind(), ErrorKind::AddrNotAvailable)
                    || matches!(
                        e.raw_os_error(),
                        Some(libc::ENETUNREACH | libc::EHOSTUNREACH | libc::EAFNOSUPPORT)
                    );
                if is_unroutable_family {
                    fallback_err = Some(e);
                } else {
                    preferred_err = Some(e);
                }
            }
        }
    }

    let final_err = preferred_err.or(fallback_err);
    Err(anyhow!(
        "failed to connect to '{}': {}",
        target_str,
        final_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no addresses".to_string())
    ))
}

/// Connect to an already-resolved socket address with the standard connect timeout and tuning.
pub async fn connect_tcp_addr(addr: SocketAddr) -> Result<TcpStream> {
    let stream = timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .with_context(|| {
            format!(
                "connection to {} timed out after {:?}",
                addr, TCP_CONNECT_TIMEOUT
            )
        })?
        .with_context(|| format!("failed to connect to {}", addr))?;
    configure_tcp_stream(&stream);
    Ok(stream)
}

/// Configure low-latency & high-throughput parameters on an active `TcpStream`.
///
/// Keepalive probes start after 30s of idle time instead of the kernel default (two hours on
/// Linux), so tunnel and work connections whose peer vanished behind a NAT or a crashed host are
/// torn down in about a minute rather than lingering indefinitely.
pub fn configure_tcp_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock_ref = socket2::SockRef::from(stream);
    let _ = sock_ref.set_recv_buffer_size(SOCKET_BUF_SIZE);
    let _ = sock_ref.set_send_buffer_size(SOCKET_BUF_SIZE);
    let keepalive = TcpKeepalive::new().with_time(TCP_KEEPALIVE_IDLE);
    #[cfg(any(
        target_os = "android",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "tvos",
        target_os = "watchos",
    ))]
    let keepalive = keepalive.with_interval(TCP_KEEPALIVE_INTERVAL);
    let _ = sock_ref.set_tcp_keepalive(&keepalive);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_response_ignores_glue_records_in_answer_section() {
        // Simulated WSL2 DNS proxy response where ANCOUNT=2 contains both the target host A record
        // and an unrelated nameserver glue A record (`f1g1ns1.dnspod.net`).
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x2222u16.to_be_bytes()); // QID
        pkt.extend_from_slice(&0x8100u16.to_be_bytes()); // Flags: QR=1, RD=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&2u16.to_be_bytes()); // ANCOUNT=2
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0

        // Question: txin.feuler.cn A IN
        pkt.extend_from_slice(b"\x04txin\x06feuler\x02cn\x00");
        pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        // Answer 1: txin.feuler.cn -> 114.132.221.111
        pkt.extend_from_slice(b"\x04txin\x06feuler\x02cn\x00");
        pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&600u32.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes());
        pkt.extend_from_slice(&[114, 132, 221, 111]);

        // Answer 2 (bogus glue in AN section): f1g1ns1.dnspod.net -> 163.177.5.35
        pkt.extend_from_slice(b"\x07f1g1ns1\x06dnspod\x03net\x00");
        pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&600u32.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes());
        pkt.extend_from_slice(&[163, 177, 5, 35]);

        let ips = parse_dns_response(&pkt, 0x2222, "txin.feuler.cn", DNS_TYPE_A);
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(114, 132, 221, 111))]);
    }
}
