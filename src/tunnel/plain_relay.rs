//! Client-side listeners inside the tunnel. Visitor traffic arrives on the client's tunnel
//! addresses in plaintext (WireGuard already decrypted it) and is relayed to the local service
//! with ordinary sockets, so IPv4/IPv6 translation and loopback-bound services work as usual.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;
use crate::net_utils::{
    bind_ephemeral_udp_for_target, bind_tcp_listener, bind_udp_socket, connect_tcp,
    format_bind_addr, resolve_socket_addrs,
};
use crate::protocol::TunnelBinding;
use crate::relay::relay_plain_with_status;
use crate::status::ConnectionStatus;

const UDP_MAX_PACKET_SIZE: usize = 65535;
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_SESSION_QUEUE_LEN: usize = 256;
const UDP_MAX_SESSIONS: usize = 4096;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Listeners for every proxy of one server session. Dropping it stops all of them.
pub struct TunnelListenerSet {
    pub bindings: Vec<TunnelBinding>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for TunnelListenerSet {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Bind one listener per (proxy, protocol, family) on the client's tunnel addresses using
/// ephemeral ports, and report the ports so the server can install its redirections.
pub async fn start_tunnel_listeners(
    client_v4: Ipv4Addr,
    client_v6: Ipv6Addr,
    proxies: &[ProxyConfig],
    status_for: impl Fn(&str) -> Option<ConnectionStatus>,
) -> Result<TunnelListenerSet> {
    let mut bindings = Vec::with_capacity(proxies.len());
    let mut tasks = Vec::new();

    for proxy in proxies {
        let local_addr = proxy.resolved_local_addr()?;
        let status = status_for(&proxy.name);
        let mut binding = TunnelBinding {
            proxy_name: proxy.name.clone(),
            ..Default::default()
        };
        let families = allowed_families(proxy);

        if proxy.proxy_type.has_tcp() {
            for family in &families {
                let bind_ip: IpAddr = match family {
                    4 => client_v4.into(),
                    _ => client_v6.into(),
                };
                let listener = bind_tcp_listener(&format_bind_addr(&bind_ip.to_string(), 0))
                    .with_context(|| {
                        format!(
                            "failed to bind tunnel TCP listener for proxy '{}'",
                            proxy.name
                        )
                    })?;
                let port = listener.local_addr()?.port();
                match family {
                    4 => binding.tcp_v4 = Some(port),
                    _ => binding.tcp_v6 = Some(port),
                }
                info!(
                    "proxy '{}' [TCP] listening inside tunnel on {}:{} -> {}",
                    proxy.name, bind_ip, port, local_addr
                );
                tasks.push(tokio::spawn(tcp_accept_loop(
                    listener,
                    proxy.name.clone(),
                    local_addr.clone(),
                    status.clone(),
                )));
            }
        }

        if proxy.proxy_type.has_udp() {
            for family in &families {
                let bind_ip: IpAddr = match family {
                    4 => client_v4.into(),
                    _ => client_v6.into(),
                };
                let socket = bind_udp_socket(&format_bind_addr(&bind_ip.to_string(), 0))
                    .with_context(|| {
                        format!(
                            "failed to bind tunnel UDP socket for proxy '{}'",
                            proxy.name
                        )
                    })?;
                let port = socket.local_addr()?.port();
                match family {
                    4 => binding.udp_v4 = Some(port),
                    _ => binding.udp_v6 = Some(port),
                }
                info!(
                    "proxy '{}' [UDP] listening inside tunnel on {}:{} -> {}",
                    proxy.name, bind_ip, port, local_addr
                );
                tasks.push(tokio::spawn(udp_loop(
                    Arc::new(socket),
                    proxy.name.clone(),
                    local_addr.clone(),
                    status.clone(),
                )));
            }
        }

        bindings.push(binding);
    }

    Ok(TunnelListenerSet { bindings, tasks })
}

/// A proxy whose `remote_bind_ip` is a concrete IPv4 or IPv6 literal only gets a listener
/// (and a server-side redirection) for that family.
fn allowed_families(proxy: &ProxyConfig) -> Vec<u8> {
    match proxy.remote_bind_ip.as_deref().map(|ip| {
        ip.trim()
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<IpAddr>()
    }) {
        Some(Ok(IpAddr::V4(ip))) if !ip.is_unspecified() => vec![4],
        Some(Ok(IpAddr::V6(ip))) if !ip.is_unspecified() => vec![6],
        _ => vec![4, 6],
    }
}

async fn tcp_accept_loop(
    listener: TcpListener,
    proxy_name: String,
    local_addr: String,
    status: Option<ConnectionStatus>,
) {
    loop {
        let (visitor, visitor_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!(
                    "tunnel TCP accept error on proxy '{}': {}; retrying",
                    proxy_name, e
                );
                sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let local_addr = local_addr.clone();
        let proxy_name = proxy_name.clone();
        let status = status.clone();
        tokio::spawn(async move {
            let local = match connect_tcp(&local_addr).await {
                Ok(stream) => stream,
                Err(e) => {
                    debug!(
                        "proxy '{}': failed to connect local service {} for visitor {}: {:#}",
                        proxy_name, local_addr, visitor_addr, e
                    );
                    return;
                }
            };
            // visitor -> local counts as "received" from the visitor's point of view.
            let _ = relay_plain_with_status(local, visitor, status.as_ref()).await;
        });
    }
}

struct UdpSession {
    generation: u64,
    tx: mpsc::Sender<Bytes>,
}

async fn udp_loop(
    socket: Arc<UdpSocket>,
    proxy_name: String,
    local_addr: String,
    status: Option<ConnectionStatus>,
) {
    let sessions: Arc<DashMap<SocketAddr, UdpSession>> = Arc::new(DashMap::new());
    let mut generation = 0u64;
    let mut buf = vec![0u8; UDP_MAX_PACKET_SIZE];
    loop {
        let (n, visitor) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(e) => {
                debug!("tunnel UDP recv error on proxy '{}': {}", proxy_name, e);
                sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        if let Some(status) = &status {
            status.record_received(n);
        }
        let payload = Bytes::copy_from_slice(&buf[..n]);

        let payload = match sessions.get(&visitor) {
            Some(session) => match session.tx.try_send(payload) {
                Ok(()) => continue,
                Err(TrySendError::Full(_)) => continue,
                Err(TrySendError::Closed(payload)) => payload,
            },
            None => payload,
        };
        if sessions.len() >= UDP_MAX_SESSIONS {
            warn!(
                "proxy '{}': UDP session limit reached, dropping datagram from {}",
                proxy_name, visitor
            );
            continue;
        }

        let (tx, rx) = mpsc::channel(UDP_SESSION_QUEUE_LEN);
        let _ = tx.try_send(payload);
        generation += 1;
        let my_generation = generation;
        sessions.insert(
            visitor,
            UdpSession {
                generation: my_generation,
                tx,
            },
        );

        let sessions_clone = Arc::clone(&sessions);
        let socket_clone = Arc::clone(&socket);
        let local_addr = local_addr.clone();
        let status = status.clone();
        tokio::spawn(async move {
            if let Err(e) = udp_session(socket_clone, visitor, rx, &local_addr, status).await {
                debug!("tunnel UDP session for {} ended: {:#}", visitor, e);
            }
            sessions_clone.remove_if(&visitor, |_, s| s.generation == my_generation);
        });
    }
}

async fn udp_session(
    tunnel_socket: Arc<UdpSocket>,
    visitor: SocketAddr,
    mut rx: mpsc::Receiver<Bytes>,
    local_addr: &str,
    status: Option<ConnectionStatus>,
) -> Result<()> {
    let target = resolve_socket_addrs(local_addr).await?[0];
    let local = bind_ephemeral_udp_for_target(target)?;
    local.connect(target).await?;
    let mut buf = vec![0u8; UDP_MAX_PACKET_SIZE];
    loop {
        tokio::select! {
            outbound = rx.recv() => match outbound {
                Some(payload) => { local.send(&payload).await?; }
                None => break,
            },
            inbound = timeout(UDP_SESSION_IDLE_TIMEOUT, local.recv(&mut buf)) => match inbound {
                Ok(Ok(n)) => {
                    if tunnel_socket.send_to(&buf[..n], visitor).await.is_ok() {
                        if let Some(status) = &status {
                            status.record_sent(n);
                        }
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            },
        }
    }
    Ok(())
}
