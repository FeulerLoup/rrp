use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use crate::cli::RunMode;
use crate::config::ServerConfig;
use crate::crypto::{key_id_hex, server_handshake, EncryptedStream, KeyId, ServerAuthorizer};
use crate::ebpf::EbpfAccelerator;
use crate::net_utils::{
    bind_tcp_listener, bind_udp_socket, format_bind_addr, normalize_socket_addr,
};
use crate::protocol::{ControlSignal, ProxySpec, RoleHandshake, TunnelFrame};
use crate::relay::relay_encrypted_and_plain_with_status;
use crate::status::{wait_for_shutdown_signal, ConnectionStatus, RuntimeStatus, StatusReporter};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WORK_CONN_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_MAX_PACKET_SIZE: usize = 65535;
/// Datagrams queued towards one client's control channel. Anything beyond this is dropped at the
/// server instead of being buffered without bound while the client link is slow or stalled.
const UDP_OUTBOUND_QUEUE_LEN: usize = 1024;
/// Pause after a transient `accept`/`recv_from` failure (e.g. EMFILE) so a persistent error does
/// not turn into a hot loop that starves the rest of the runtime.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

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
    ebpf: EbpfAccelerator,
    pending_work_conns: PendingWorkConnections,
    next_conn_id: Arc<AtomicU64>,
    status: RuntimeStatus,
}

pub struct Server {
    config: ServerConfig,
    listener: TcpListener,
    local_addr: SocketAddr,
    authorizer: ServerAuthorizer,
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
        let listener = bind_tcp_listener(&config.bind_addr)?;
        let local_addr = listener
            .local_addr()
            .context("failed to query server local_addr")?;
        let status = RuntimeStatus::new(
            RunMode::Server,
            ebpf.status_reason().to_string(),
            Some(local_addr.to_string()),
        );

        info!(
            "rrp server listening on {} (ebpf: {})",
            local_addr,
            ebpf.status_reason()
        );

        Ok(Self {
            config,
            listener,
            local_addr,
            authorizer,
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

    pub async fn run(self) -> Result<()> {
        let runtime = ServerRuntime {
            config: Arc::new(self.config),
            authorizer: self.authorizer,
            ebpf: self.ebpf,
            pending_work_conns: self.pending_work_conns,
            next_conn_id: self.next_conn_id,
            status: self.status,
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
            let runtime = runtime.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_incoming_connection(stream, peer_addr, runtime).await {
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
) -> Result<()> {
    let (mut enc_stream, key_id) = timeout(
        HANDSHAKE_TIMEOUT,
        server_handshake(stream, &runtime.authorizer),
    )
    .await
    .context("mlkem768x25519plus server handshake timed out")??;

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
        RoleHandshake::Control { proxies } => {
            info!(
                "authenticated client control connection from {} (key {}) with {} proxy rule(s)",
                peer_addr,
                key_id_hex(&key_id),
                proxies.len()
            );
            handle_control_session(enc_stream, peer_addr, key_id, proxies, runtime).await
        }
    }
}

async fn handle_control_session(
    enc_stream: EncryptedStream<TcpStream>,
    peer_addr: SocketAddr,
    key_id: KeyId,
    proxies: Vec<ProxySpec>,
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

async fn reject_registration(enc_stream: &mut EncryptedStream<TcpStream>, message: &str) {
    let ack = TunnelFrame::Signal(ControlSignal::RegisterAck {
        success: false,
        message: message.to_string(),
    });
    if let Ok(bytes) = ack.encode() {
        let _ = enc_stream.send_frame(&bytes).await;
    }
}

async fn handle_control_session_inner(
    mut enc_stream: EncryptedStream<TcpStream>,
    peer_addr: SocketAddr,
    key_id: KeyId,
    proxies: Vec<ProxySpec>,
    runtime: ServerRuntime,
    proxy_statuses: HashMap<String, ConnectionStatus>,
    statuses: Vec<ConnectionStatus>,
) -> Result<()> {
    let (tcp_listeners, udp_sockets) =
        bind_requested_proxies(&mut enc_stream, &proxies, &runtime.config.proxy_bind_ip).await?;

    let ack = TunnelFrame::Signal(ControlSignal::RegisterAck {
        success: true,
        message: "registered".to_string(),
    });
    enc_stream.send_frame(&ack.encode()?).await?;
    for status in &statuses {
        status.mark_connected();
    }
    info!(
        "client {} connected successfully ({} proxy rule(s) registered)",
        peer_addr,
        proxies.len()
    );

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
        let ebpf = runtime.ebpf.clone();
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
                        let ebpf_clone = ebpf.clone();
                        let connection_status = connection.clone();
                        let pname = proxy_name.clone();
                        tokio::spawn(async move {
                            match timeout(WORK_CONN_WAIT_TIMEOUT, work_rx).await {
                                Ok(Ok(work_enc_stream)) => {
                                    let _ = relay_encrypted_and_plain_with_status(
                                        work_enc_stream,
                                        visitor_stream,
                                        Some(&ebpf_clone),
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

    Ok(())
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
