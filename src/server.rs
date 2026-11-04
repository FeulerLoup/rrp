use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use crate::cli::RunMode;
use crate::config::ServerConfig;
use crate::crypto::{key_id_hex, server_handshake_timed, EncryptedStream, KeyId, ServerAuthorizer};
use crate::ebpf::EbpfAccelerator;
use crate::guard::{HandshakeGuard, HandshakePermit};
use crate::net_utils::{
    bind_tcp_listener, bind_tcp_listener_with, bind_udp_socket, format_bind_addr, graceful_close,
    normalize_socket_addr, reset_on_close,
};
use crate::protocol::{
    ControlSignal, ProxySpec, RoleHandshake, TunnelBinding, TunnelFrame, TunnelRequest,
    TUNNEL_PROTOCOL_VERSION,
};
use crate::relay::relay_encrypted_and_plain_with_status;
use crate::status::{wait_for_shutdown_signal, ConnectionStatus, RuntimeStatus, StatusReporter};
use crate::tunnel::bpf_types::{FAMILY_V4, FAMILY_V6, PROTO_TCP, PROTO_UDP};
use crate::tunnel::{ResolvedBinding, TunnelLease, TunnelServer};

/// Upper bound on the whole pre-session exchange (crypto handshake plus `RoleHandshake`). The
/// unauthenticated part is additionally bounded per message by `handshake.hello_timeout_secs`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WORK_CONN_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_MAX_PACKET_SIZE: usize = 65535;
/// Datagrams queued towards one client's control channel. Anything beyond this is dropped at the
/// server instead of being buffered without bound while the client link is slow or stalled.
const UDP_OUTBOUND_QUEUE_LEN: usize = 1024;
/// Pause after a transient `accept`/`recv_from` failure (e.g. EMFILE) so a persistent error does
/// not turn into a hot loop that starves the rest of the runtime.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
/// How often kernel traffic counters are copied into `rrp status` for tunnel sessions.
const TUNNEL_STATS_INTERVAL: Duration = Duration::from_secs(1);

/// A visitor waiting for the client to open a matching work connection. The entry is bound to the
/// client identity and proxy that requested it, so another authorized client cannot claim it.
struct PendingWorkConn {
    key_id: KeyId,
    proxy_name: String,
    tx: oneshot::Sender<EncryptedStream<TcpStream>>,
}

type PendingWorkConnections = Arc<DashMap<u64, PendingWorkConn>>;

#[derive(Clone)]
struct ServerRuntime {
    config: Arc<ServerConfig>,
    authorizer: ServerAuthorizer,
    guard: Arc<HandshakeGuard>,
    pending_work_conns: PendingWorkConnections,
    next_conn_id: Arc<AtomicU64>,
    status: RuntimeStatus,
    /// Kernel tunnel data plane, when it came up successfully.
    tunnel: Option<Arc<TunnelServer>>,
}

pub struct Server {
    config: ServerConfig,
    listener: TcpListener,
    local_addr: SocketAddr,
    authorizer: ServerAuthorizer,
    guard: Arc<HandshakeGuard>,
    ebpf: EbpfAccelerator,
    pending_work_conns: PendingWorkConnections,
    next_conn_id: Arc<AtomicU64>,
    status: RuntimeStatus,
}

impl Server {
    pub fn new(config: ServerConfig) -> Result<Self> {
        config.validate()?;
        let authorizer = ServerAuthorizer::new(&config.authorized_keys)?;
        if authorizer.is_empty() {
            warn!(
                "no authorized_keys configured: every client handshake will be rejected until `rrp approve <PUBLIC_KEY>` is run"
            );
        }
        let ebpf = EbpfAccelerator::try_init(config.enable_ebpf);
        let guard = HandshakeGuard::new(config.handshake.clone());
        // The rrp client always speaks first, so the kernel can hold silent connections back.
        let listener =
            bind_tcp_listener_with(&config.bind_addr, Some(config.handshake.hello_timeout()))?;
        let local_addr = listener
            .local_addr()
            .context("failed to query server local_addr")?;
        let status = RuntimeStatus::new(
            RunMode::Server,
            ebpf.status_reason(),
            Some(local_addr.to_string()),
        );

        info!(
            "rrp server listening on {} (data plane: {})",
            local_addr,
            ebpf.status_reason()
        );

        Ok(Self {
            config,
            listener,
            local_addr,
            authorizer,
            guard,
            ebpf,
            pending_work_conns: Arc::new(DashMap::new()),
            next_conn_id: Arc::new(AtomicU64::new(1)),
            status,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn ebpf(&self) -> &EbpfAccelerator {
        &self.ebpf
    }

    pub fn status(&self) -> RuntimeStatus {
        self.status.clone()
    }

    /// Admission control state for the control port.
    pub fn guard(&self) -> Arc<HandshakeGuard> {
        Arc::clone(&self.guard)
    }

    /// Try to bring up the kernel tunnel data plane; on any failure keep serving with the
    /// user-space relay and say why in the status output.
    async fn start_tunnel(&self) -> Option<Arc<TunnelServer>> {
        if !self.ebpf.enabled() {
            return None;
        }
        match TunnelServer::start(&self.config.tunnel).await {
            Ok(tunnel) => {
                self.ebpf.set_active(tunnel.description());
                self.status.set_ebpf_status(self.ebpf.status_reason());
                Some(Arc::new(tunnel))
            }
            Err(error) => {
                let reason = format!("{:#}", error);
                if cfg!(target_os = "linux") {
                    warn!(
                        "kernel tunnel data plane unavailable, using user-space relay: {}",
                        reason
                    );
                } else {
                    debug!("kernel tunnel data plane unavailable: {}", reason);
                }
                self.ebpf.set_fallback(reason);
                self.status.set_ebpf_status(self.ebpf.status_reason());
                None
            }
        }
    }

    pub async fn run(self) -> Result<()> {
        let tunnel = self.start_tunnel().await;
        let runtime = ServerRuntime {
            config: Arc::new(self.config),
            authorizer: self.authorizer,
            guard: self.guard,
            pending_work_conns: self.pending_work_conns,
            next_conn_id: self.next_conn_id,
            status: self.status,
            tunnel,
        };

        loop {
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    // EMFILE/ENFILE/ECONNABORTED etc. are transient: a production server must
                    // keep serving existing tunnels rather than exit on the first failed accept.
                    warn!("failed to accept incoming connection: {}; retrying", e);
                    sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            };
            let peer_addr = normalize_socket_addr(peer_addr);

            // Nothing is known about the peer yet. Until the handshake proves it holds an approved
            // key, close on RST rather than FIN so refused and failed attempts leave no TIME_WAIT
            // state and get no protocol-level answer.
            reset_on_close(&stream);
            let permit = match runtime.guard.try_admit(peer_addr.ip()) {
                Ok(permit) => permit,
                Err(refusal) => {
                    debug!("refused connection from {}: {}", peer_addr, refusal);
                    drop(stream);
                    continue;
                }
            };
            let runtime = runtime.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_incoming_connection(stream, peer_addr, runtime, permit).await
                {
                    debug!("connection from {} ended: {:#}", peer_addr, e);
                }
            });
        }
    }
}

async fn handle_incoming_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    runtime: ServerRuntime,
    permit: HandshakePermit,
) -> Result<()> {
    let handshake = timeout(
        HANDSHAKE_TIMEOUT,
        server_handshake_timed(
            stream,
            &runtime.authorizer,
            runtime.config.handshake.hello_timeout(),
        ),
    )
    .await
    .context("mlkem768x25519plus server handshake timed out")
    .and_then(|result| result);
    // The handshake slot is only needed while the peer is unauthenticated.
    drop(permit);
    let (mut enc_stream, key_id) = match handshake {
        Ok(authenticated) => authenticated,
        Err(error) => {
            runtime.guard.record_failure(peer_addr.ip());
            return Err(error);
        }
    };
    graceful_close(enc_stream.get_ref());

    let role_frame = timeout(HANDSHAKE_TIMEOUT, enc_stream.recv_frame())
        .await
        .context("reading RoleHandshake timed out")??
        .ok_or_else(|| anyhow!("EOF before RoleHandshake"))?;

    let role = RoleHandshake::decode(&role_frame)?;

    match role {
        RoleHandshake::WorkTcp {
            conn_id,
            proxy_name,
        } => {
            let claimed = runtime
                .pending_work_conns
                .remove_if(&conn_id, |_, pending| {
                    pending.key_id == key_id && pending.proxy_name == proxy_name
                });
            match claimed {
                Some((_, pending)) => {
                    let _ = pending.tx.send(enc_stream);
                    debug!(
                        "paired work connection conn_id={} for proxy '{}' from {}",
                        conn_id, proxy_name, peer_addr
                    );
                }
                None if runtime.pending_work_conns.contains_key(&conn_id) => {
                    warn!(
                        "client {} (key {}) tried to claim work connection conn_id={} for proxy '{}' that belongs to a different client or proxy; refused",
                        peer_addr,
                        key_id_hex(&key_id),
                        conn_id,
                        proxy_name
                    );
                }
                None => {
                    debug!(
                        "received unknown or expired work connection conn_id={} for proxy '{}' from {}",
                        conn_id, proxy_name, peer_addr
                    );
                }
            }
            Ok(())
        }
        RoleHandshake::Control { proxies, tunnel } => {
            info!(
                "authenticated client control connection from {} (key {}) with {} proxy rule(s){}",
                peer_addr,
                key_id_hex(&key_id),
                proxies.len(),
                if tunnel.is_some() {
                    ", tunnel requested"
                } else {
                    ""
                }
            );
            handle_control_session(enc_stream, peer_addr, key_id, proxies, tunnel, runtime).await
        }
    }
}

async fn handle_control_session(
    enc_stream: EncryptedStream<TcpStream>,
    peer_addr: SocketAddr,
    key_id: KeyId,
    proxies: Vec<ProxySpec>,
    tunnel_request: Option<TunnelRequest>,
    runtime: ServerRuntime,
) -> Result<()> {
    let mut proxy_statuses = HashMap::with_capacity(proxies.len());
    let mut statuses = Vec::with_capacity(proxies.len().max(1));

    if proxies.is_empty() {
        statuses.push(runtime.status.server_session(peer_addr.to_string()));
    } else {
        for proxy in &proxies {
            let bind_ip = proxy
                .remote_bind_ip
                .as_deref()
                .unwrap_or(&runtime.config.proxy_bind_ip);
            let server_addr = format_bind_addr(bind_ip, proxy.remote_port);
            let target_addr = if proxy.local_addr.is_empty() {
                peer_addr.to_string()
            } else {
                proxy.local_addr.clone()
            };
            let conn = runtime.status.server_proxy_session(
                peer_addr.to_string(),
                proxy.name.clone(),
                proxy.proxy_type.to_string(),
                server_addr,
                target_addr,
            );
            proxy_statuses.insert(proxy.name.clone(), conn.clone());
            statuses.push(conn);
        }
    }

    for status in &statuses {
        status.mark_connecting();
    }
    let result = handle_control_session_inner(
        enc_stream,
        peer_addr,
        key_id,
        proxies,
        tunnel_request,
        runtime.clone(),
        proxy_statuses,
        statuses.clone(),
    )
    .await;
    match &result {
        Ok(()) => {
            for status in &statuses {
                status.mark_disconnected(None);
            }
        }
        Err(error) => {
            let err_str = format!("{:#}", error);
            for status in &statuses {
                status.mark_disconnected(Some(&err_str));
            }
        }
    }
    for status in &statuses {
        runtime.status.remove_connection(status.id());
    }
    result
}

/// Bind every listener/socket a client asked for, or report the first failure to the client as a
/// failed `RegisterAck` and abort the session. Already-bound sockets are released on failure.
async fn bind_requested_proxies(
    enc_stream: &mut EncryptedStream<TcpStream>,
    proxies: &[ProxySpec],
    default_bind_ip: &str,
) -> Result<(Vec<(String, TcpListener)>, HashMap<String, Arc<UdpSocket>>)> {
    let mut tcp_listeners: Vec<(String, TcpListener)> = Vec::new();
    let mut udp_sockets: HashMap<String, Arc<UdpSocket>> = HashMap::new();

    validate_proxy_specs(enc_stream, proxies).await?;

    for proxy in proxies {
        let bind_ip = proxy.remote_bind_ip.as_deref().unwrap_or(default_bind_ip);
        let bind_addr = format_bind_addr(bind_ip, proxy.remote_port);

        if proxy.proxy_type.has_tcp() {
            match bind_tcp_listener(&bind_addr) {
                Ok(listener) => {
                    info!(
                        "proxy '{}' [TCP] listening on {}",
                        proxy.name,
                        listener.local_addr()?
                    );
                    tcp_listeners.push((proxy.name.clone(), listener));
                }
                Err(e) => {
                    let msg = format!(
                        "failed to bind TCP listener for proxy '{}' on {}: {:#}",
                        proxy.name, bind_addr, e
                    );
                    reject_registration(enc_stream, &msg).await;
                    bail!("{}", msg);
                }
            }
        }

        if proxy.proxy_type.has_udp() {
            match bind_udp_socket(&bind_addr) {
                Ok(udp_sock) => {
                    info!(
                        "proxy '{}' [UDP] bound on {}",
                        proxy.name,
                        udp_sock.local_addr()?
                    );
                    udp_sockets.insert(proxy.name.clone(), Arc::new(udp_sock));
                }
                Err(e) => {
                    let msg = format!(
                        "failed to bind UDP socket for proxy '{}' on {}: {:#}",
                        proxy.name, bind_addr, e
                    );
                    reject_registration(enc_stream, &msg).await;
                    bail!("{}", msg);
                }
            }
        }
    }

    Ok((tcp_listeners, udp_sockets))
}

async fn validate_proxy_specs(
    enc_stream: &mut EncryptedStream<TcpStream>,
    proxies: &[ProxySpec],
) -> Result<()> {
    let mut seen_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for proxy in proxies {
        if !seen_names.insert(proxy.name.as_str()) {
            let msg = format!("duplicate proxy name '{}' in registration", proxy.name);
            reject_registration(enc_stream, &msg).await;
            bail!("{}", msg);
        }
        if proxy.remote_port == 0 {
            let msg = format!("proxy '{}' requested remote_port 0", proxy.name);
            reject_registration(enc_stream, &msg).await;
            bail!("{}", msg);
        }
    }
    Ok(())
}

async fn reject_registration(enc_stream: &mut EncryptedStream<TcpStream>, message: &str) {
    let ack = TunnelFrame::Signal(ControlSignal::RegisterAck {
        success: false,
        message: message.to_string(),
        tunnel: None,
    });
    if let Ok(bytes) = ack.encode() {
        let _ = enc_stream.send_frame(&bytes).await;
    }
}

/// State of one control session served through the kernel tunnel.
struct TunnelSession {
    server: Arc<TunnelServer>,
    lease: TunnelLease,
    installed: bool,
    stats_task: Option<JoinHandle<()>>,
}

impl Drop for TunnelSession {
    fn drop(&mut self) {
        if let Some(task) = self.stats_task.take() {
            task.abort();
        }
        self.server.remove_client(&self.lease);
    }
}

/// Address families a proxy spec allows, derived from its `remote_bind_ip`.
fn spec_families(spec: &ProxySpec) -> Vec<u8> {
    match spec.remote_bind_ip.as_deref().map(|ip| {
        ip.trim()
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<IpAddr>()
    }) {
        Some(Ok(IpAddr::V4(ip))) if !ip.is_unspecified() => vec![FAMILY_V4],
        Some(Ok(IpAddr::V6(ip))) if !ip.is_unspecified() => vec![FAMILY_V6],
        _ => vec![FAMILY_V4, FAMILY_V6],
    }
}

/// Match the client's reported in-tunnel ports against the registered proxies.
pub fn resolve_tunnel_bindings(
    proxies: &[ProxySpec],
    bindings: &[TunnelBinding],
) -> Result<Vec<ResolvedBinding>> {
    let mut resolved = Vec::new();
    for spec in proxies {
        let binding = bindings
            .iter()
            .find(|b| b.proxy_name == spec.name)
            .ok_or_else(|| anyhow!("client reported no tunnel ports for proxy '{}'", spec.name))?;
        for family in spec_families(spec) {
            if spec.proxy_type.has_tcp() {
                let port = match family {
                    FAMILY_V4 => binding.tcp_v4,
                    _ => binding.tcp_v6,
                };
                let tunnel_port = port.ok_or_else(|| {
                    anyhow!(
                        "client reported no IPv{} TCP tunnel port for proxy '{}'",
                        family,
                        spec.name
                    )
                })?;
                resolved.push(ResolvedBinding {
                    proxy_name: spec.name.clone(),
                    family,
                    proto: PROTO_TCP,
                    public_port: spec.remote_port,
                    tunnel_port,
                });
            }
            if spec.proxy_type.has_udp() {
                let port = match family {
                    FAMILY_V4 => binding.udp_v4,
                    _ => binding.udp_v6,
                };
                let tunnel_port = port.ok_or_else(|| {
                    anyhow!(
                        "client reported no IPv{} UDP tunnel port for proxy '{}'",
                        family,
                        spec.name
                    )
                })?;
                resolved.push(ResolvedBinding {
                    proxy_name: spec.name.clone(),
                    family,
                    proto: PROTO_UDP,
                    public_port: spec.remote_port,
                    tunnel_port,
                });
            }
        }
    }
    Ok(resolved)
}

#[allow(clippy::too_many_arguments)]
async fn handle_control_session_inner(
    mut enc_stream: EncryptedStream<TcpStream>,
    peer_addr: SocketAddr,
    key_id: KeyId,
    proxies: Vec<ProxySpec>,
    tunnel_request: Option<TunnelRequest>,
    runtime: ServerRuntime,
    proxy_statuses: HashMap<String, ConnectionStatus>,
    statuses: Vec<ConnectionStatus>,
) -> Result<()> {
    // Decide the data plane for this session. Any problem bringing the tunnel side up falls
    // back to the relay so an old or misconfigured client still gets service.
    let mut tunnel_session: Option<TunnelSession> = None;
    let mut assignment = None;
    if let (Some(request), Some(tunnel_server)) = (&tunnel_request, runtime.tunnel.as_ref()) {
        if request.version != TUNNEL_PROTOCOL_VERSION {
            warn!(
                "client {} requested tunnel protocol version {}, server speaks {}; using relay",
                peer_addr, request.version, TUNNEL_PROTOCOL_VERSION
            );
        } else if let Some(auth) = runtime.authorizer.get(&key_id) {
            match tunnel_server.add_client(
                key_id,
                auth.x25519_public_bytes(),
                enc_stream.tunnel_psk(),
            ) {
                Ok((lease, assigned)) => {
                    info!(
                        "client {} assigned tunnel addresses {} / {}",
                        peer_addr, assigned.client_ipv4, assigned.client_ipv6
                    );
                    assignment = Some(assigned);
                    tunnel_session = Some(TunnelSession {
                        server: Arc::clone(tunnel_server),
                        lease,
                        installed: false,
                        stats_task: None,
                    });
                }
                Err(e) => {
                    warn!(
                        "could not add client {} to the tunnel, using relay: {:#}",
                        peer_addr, e
                    );
                }
            }
        }
    }

    let (tcp_listeners, udp_sockets) = if tunnel_session.is_some() {
        validate_proxy_specs(&mut enc_stream, &proxies).await?;
        (Vec::new(), HashMap::new())
    } else {
        bind_requested_proxies(&mut enc_stream, &proxies, &runtime.config.proxy_bind_ip).await?
    };

    let ack = TunnelFrame::Signal(ControlSignal::RegisterAck {
        success: true,
        message: if assignment.is_some() {
            "registered (tunnel data plane)".to_string()
        } else {
            "registered".to_string()
        },
        tunnel: assignment,
    });
    enc_stream.send_frame(&ack.encode()?).await?;
    if tunnel_session.is_none() {
        for status in &statuses {
            status.mark_connected();
        }
        info!(
            "client {} connected successfully ({} proxy rule(s) registered)",
            peer_addr,
            proxies.len()
        );
    }

    let (mut enc_read, mut enc_write) = enc_stream.into_split();
    // Control signals (work-connection requests, heartbeats) are few and must never be dropped;
    // UDP datagrams are bulk traffic that may be dropped under back-pressure.
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<TunnelFrame>();
    let (udp_tx, mut udp_rx) = mpsc::channel::<TunnelFrame>(UDP_OUTBOUND_QUEUE_LEN);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn control channel writer; signals take priority over queued datagrams.
    let mut writer_shutdown = shutdown_rx.clone();
    let writer_handle = tokio::spawn(async move {
        // The UDP queue closes once every producer is gone (e.g. no UDP proxies registered);
        // that must only disable the branch, not end the writer for control signals.
        let mut udp_open = true;
        loop {
            let frame = tokio::select! {
                biased;
                _ = writer_shutdown.changed() => break,
                maybe_frame = ctrl_rx.recv() => match maybe_frame {
                    Some(frame) => frame,
                    None => break,
                },
                maybe_frame = udp_rx.recv(), if udp_open => match maybe_frame {
                    Some(frame) => frame,
                    None => {
                        udp_open = false;
                        continue;
                    }
                },
            };
            match frame.encode() {
                Ok(bytes) => {
                    if enc_write.send_frame(&bytes).await.is_err() {
                        break;
                    }
                }
                Err(e) => debug!("dropping unencodable tunnel frame: {:#}", e),
            }
        }
    });

    // Spawn TCP proxy accept tasks
    let mut proxy_tasks = Vec::new();
    for (proxy_name, listener) in tcp_listeners {
        let ctrl_tx = ctrl_tx.clone();
        let pending_work_conns = Arc::clone(&runtime.pending_work_conns);
        let next_conn_id = Arc::clone(&runtime.next_conn_id);
        let Some(connection) = proxy_statuses
            .get(&proxy_name)
            .cloned()
            .or_else(|| statuses.first().cloned())
        else {
            continue;
        };
        let mut task_shutdown = shutdown_rx.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_res = listener.accept() => {
                        let (visitor_stream, visitor_addr) = match accept_res {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("TCP accept error on proxy '{}': {}; retrying", proxy_name, e);
                                sleep(ACCEPT_ERROR_BACKOFF).await;
                                continue;
                            }
                        };
                        let visitor_addr = normalize_socket_addr(visitor_addr);
                        let conn_id = next_conn_id.fetch_add(1, Ordering::Relaxed);
                        let (work_tx, work_rx) = oneshot::channel();
                        pending_work_conns.insert(
                            conn_id,
                            PendingWorkConn {
                                key_id,
                                proxy_name: proxy_name.clone(),
                                tx: work_tx,
                            },
                        );

                        let req = TunnelFrame::Signal(ControlSignal::ReqWorkConn {
                            conn_id,
                            proxy_name: proxy_name.clone(),
                            visitor_addr: visitor_addr.to_string(),
                        });
                        if ctrl_tx.send(req).is_err() {
                            pending_work_conns.remove(&conn_id);
                            break;
                        }

                        let pending_clone = Arc::clone(&pending_work_conns);
                        let connection_status = connection.clone();
                        let pname = proxy_name.clone();
                        tokio::spawn(async move {
                            match timeout(WORK_CONN_WAIT_TIMEOUT, work_rx).await {
                                Ok(Ok(work_enc_stream)) => {
                                    let _ = relay_encrypted_and_plain_with_status(
                                        work_enc_stream,
                                        visitor_stream,
                                        Some(&connection_status),
                                    )
                                    .await;
                                }
                                _ => {
                                    pending_clone.remove(&conn_id);
                                    debug!(
                                        "timed out waiting for work connection conn_id={} on proxy '{}' (visitor {})",
                                        conn_id, pname, visitor_addr
                                    );
                                }
                            }
                        });
                    }
                    _ = task_shutdown.changed() => {
                        break;
                    }
                }
            }
        });
        proxy_tasks.push(handle);
    }

    // Spawn UDP proxy receive tasks
    for (proxy_name, udp_sock) in &udp_sockets {
        let proxy_name = proxy_name.clone();
        let udp_sock = Arc::clone(udp_sock);
        let udp_tx = udp_tx.clone();
        let Some(connection) = proxy_statuses
            .get(&proxy_name)
            .cloned()
            .or_else(|| statuses.first().cloned())
        else {
            continue;
        };
        let mut task_shutdown = shutdown_rx.clone();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_MAX_PACKET_SIZE];
            let mut dropped: u64 = 0;
            loop {
                tokio::select! {
                    recv_res = udp_sock.recv_from(&mut buf) => {
                        match recv_res {
                            Ok((n, visitor_addr)) => {
                                let frame = TunnelFrame::UdpDatagram {
                                    proxy_name: proxy_name.clone(),
                                    visitor_addr: normalize_socket_addr(visitor_addr),
                                    payload: Bytes::copy_from_slice(&buf[..n]),
                                };
                                match udp_tx.try_send(frame) {
                                    Ok(()) => connection.record_sent(n),
                                    Err(TrySendError::Full(_)) => {
                                        dropped += 1;
                                        if dropped.is_power_of_two() {
                                            warn!(
                                                "proxy '{}' [UDP]: client link is saturated, dropped {} datagram(s) so far",
                                                proxy_name, dropped
                                            );
                                        }
                                    }
                                    Err(TrySendError::Closed(_)) => break,
                                }
                            }
                            Err(e) => {
                                debug!("UDP recv_from error on proxy '{}': {}", proxy_name, e);
                                sleep(ACCEPT_ERROR_BACKOFF).await;
                            }
                        }
                    }
                    _ = task_shutdown.changed() => {
                        break;
                    }
                }
            }
        });
        proxy_tasks.push(handle);
    }

    // Control reader loop
    let heartbeat_timeout = Duration::from_secs(runtime.config.heartbeat_timeout_secs.max(10));
    let mut session_error: Option<anyhow::Error> = None;
    loop {
        match timeout(heartbeat_timeout, enc_read.recv_frame()).await {
            Ok(Ok(Some(raw_frame))) => {
                let frame = match TunnelFrame::decode(raw_frame) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!("invalid tunnel frame from {}: {}", peer_addr, e);
                        break;
                    }
                };
                match frame {
                    TunnelFrame::Signal(ControlSignal::Ping { timestamp_ms }) => {
                        for status in &statuses {
                            status.record_heartbeat(None);
                        }
                        let _ =
                            ctrl_tx.send(TunnelFrame::Signal(ControlSignal::Pong { timestamp_ms }));
                    }
                    TunnelFrame::Signal(ControlSignal::TunnelReady { bindings }) => {
                        let Some(session) = tunnel_session.as_mut() else {
                            warn!(
                                "client {} sent TunnelReady without a tunnel assignment",
                                peer_addr
                            );
                            break;
                        };
                        if session.installed {
                            debug!("ignoring duplicate TunnelReady from {}", peer_addr);
                            continue;
                        }
                        let outcome =
                            resolve_tunnel_bindings(&proxies, &bindings).and_then(|resolved| {
                                session
                                    .server
                                    .install_bindings(&session.lease, &resolved)
                                    .map(|()| resolved.len())
                            });
                        match outcome {
                            Ok(count) => {
                                session.installed = true;
                                for status in &statuses {
                                    status.mark_connected();
                                }
                                info!(
                                    "client {} connected through the tunnel ({} proxy rule(s), {} port redirection(s))",
                                    peer_addr,
                                    proxies.len(),
                                    count
                                );
                                let _ =
                                    ctrl_tx.send(TunnelFrame::Signal(ControlSignal::TunnelAck {
                                        success: true,
                                        message: "tunnel redirections installed".to_string(),
                                    }));
                                session.stats_task = Some(spawn_tunnel_stats_task(
                                    Arc::clone(&session.server),
                                    session.lease,
                                    proxy_statuses.clone(),
                                ));
                            }
                            Err(e) => {
                                let msg = format!("{:#}", e);
                                warn!("rejecting tunnel registration from {}: {}", peer_addr, msg);
                                let _ =
                                    ctrl_tx.send(TunnelFrame::Signal(ControlSignal::TunnelAck {
                                        success: false,
                                        message: msg.clone(),
                                    }));
                                // Give the writer a moment to flush the verdict, then end the
                                // session; the client reconnects in relay mode.
                                sleep(Duration::from_millis(200)).await;
                                session_error =
                                    Some(anyhow!("tunnel registration rejected: {}", msg));
                                break;
                            }
                        }
                    }
                    TunnelFrame::Signal(_) => {}
                    TunnelFrame::UdpDatagram {
                        proxy_name,
                        visitor_addr,
                        payload,
                    } => {
                        if let Some(connection) =
                            proxy_statuses.get(&proxy_name).or_else(|| statuses.first())
                        {
                            connection.record_received(payload.len());
                        }
                        if let Some(udp_sock) = udp_sockets.get(&proxy_name) {
                            if let Err(e) = udp_sock.send_to(&payload, visitor_addr).await {
                                debug!(
                                    "failed to send UDP reply to visitor {} on proxy '{}': {}",
                                    visitor_addr, proxy_name, e
                                );
                            }
                        }
                    }
                }
            }
            Ok(Ok(None)) => {
                info!("client {} closed control connection", peer_addr);
                break;
            }
            Ok(Err(e)) => {
                warn!("control connection read error from {}: {}", peer_addr, e);
                break;
            }
            Err(_) => {
                warn!(
                    "client {} heartbeat timed out (no frame for {:?})",
                    peer_addr, heartbeat_timeout
                );
                break;
            }
        }
    }

    let _ = shutdown_tx.send(true);
    for task in proxy_tasks {
        task.abort();
    }
    writer_handle.abort();
    drop(udp_tx);
    drop(tunnel_session);

    match session_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Copy kernel byte counters into the status entries so `rrp status` shows tunnel traffic.
fn spawn_tunnel_stats_task(
    server: Arc<TunnelServer>,
    lease: TunnelLease,
    proxy_statuses: HashMap<String, ConnectionStatus>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TUNNEL_STATS_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            for (proxy, traffic) in server.traffic(&lease) {
                if let Some(status) = proxy_statuses.get(&proxy) {
                    status.set_counters(traffic.client_to_visitor, traffic.visitor_to_client);
                }
            }
        }
    })
}

pub async fn run_server(config: ServerConfig) -> Result<()> {
    let server = Server::new(config)?;
    let mut status_reporter = match StatusReporter::start(server.status()).await {
        Ok(reporter) => Some(reporter),
        Err(error) => {
            warn!("runtime status reporting is unavailable: {:#}", error);
            None
        }
    };
    let res = tokio::select! {
        res = server.run() => res,
        _ = wait_for_shutdown_signal() => {
            info!("rrp server shutting down");
            Ok(())
        }
    };
    if let Some(reporter) = &mut status_reporter {
        reporter.shutdown().await;
    }
    res
}
