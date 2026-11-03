use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

use crate::cli::RunMode;
use crate::config::{ClientConfig, ProxyConfig, ResolvedServerConfig};
use crate::crypto::{client_handshake, ClientKeyPair};
use crate::ebpf::EbpfAccelerator;
use crate::net_utils::{
    bind_ephemeral_udp_for_target, connect_tcp, format_server_proxy_addr, resolve_socket_addrs,
};
use crate::protocol::{ControlSignal, ProxySpec, RoleHandshake, TunnelFrame};
use crate::relay::relay_encrypted_and_plain_with_status;
use crate::status::{
    wait_for_shutdown_signal, ConnectionStatus, RuntimeStatus, StatusReporter,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_MAX_PACKET_SIZE: usize = 65535;

#[derive(Clone)]
struct ServerEndpoint {
    resolved: ResolvedServerConfig,
    keypair: ClientKeyPair,
    proxies_by_name: Arc<HashMap<String, ProxyConfig>>,
    proxy_statuses: Arc<HashMap<String, ConnectionStatus>>,
    statuses: Vec<ConnectionStatus>,
}

impl ServerEndpoint {
    fn display_name(&self) -> String {
        self.resolved.display_name()
    }

    fn mark_connecting(&self) {
        for status in &self.statuses {
            status.mark_connecting();
        }
    }

    fn mark_connected(&self) {
        for status in &self.statuses {
            status.mark_connected();
        }
    }

    fn mark_disconnected(&self, error: Option<&str>) {
        for status in &self.statuses {
            status.mark_disconnected(error);
        }
    }

    fn record_heartbeat(&self, rtt_ms: Option<u64>) {
        for status in &self.statuses {
            status.record_heartbeat(rtt_ms);
        }
    }

    fn proxy_status(&self, proxy_name: &str) -> Option<ConnectionStatus> {
        self.proxy_statuses
            .get(proxy_name)
            .cloned()
            .or_else(|| self.statuses.first().cloned())
    }
}

pub struct Client {
    config: ClientConfig,
    ebpf: EbpfAccelerator,
    endpoints: Vec<ServerEndpoint>,
    status: RuntimeStatus,
}

impl Client {
    pub fn new(config: ClientConfig) -> Result<Self> {
        let resolved_servers = config.resolve_servers()?;
        let ebpf = EbpfAccelerator::try_init(config.enable_ebpf);
        let status = RuntimeStatus::new(
            RunMode::Client,
            ebpf.status_reason().to_string(),
            None,
        );

        let multi_server = resolved_servers.len() > 1;
        let mut endpoints = Vec::with_capacity(resolved_servers.len());
        for srv in resolved_servers {
            let keypair = ClientKeyPair::from_base64(&srv.private_key)?;
            let mut proxies_by_name = HashMap::with_capacity(srv.proxies.len());
            let mut proxy_statuses = HashMap::with_capacity(srv.proxies.len());
            let mut statuses = Vec::with_capacity(srv.proxies.len().max(1));

            if srv.proxies.is_empty() {
                statuses.push(status.endpoint(
                    srv.server_addr.clone(),
                    srv.display_name(),
                    srv.server_addr.clone(),
                ));
            } else {
                for p in &srv.proxies {
                    let target_addr = p.resolved_local_addr()?;
                    let server_proxy_addr =
                        format_server_proxy_addr(&srv.server_addr, p.remote_port);
                    let id = if multi_server {
                        format!("{}#{}", srv.server_addr, p.name)
                    } else {
                        p.name.clone()
                    };
                    let conn_status = status.proxy_endpoint(
                        id,
                        p.name.clone(),
                        p.proxy_type.to_string(),
                        server_proxy_addr,
                        target_addr,
                    );
                    proxies_by_name.insert(p.name.clone(), p.clone());
                    proxy_statuses.insert(p.name.clone(), conn_status.clone());
                    statuses.push(conn_status);
                }
            }

            endpoints.push(ServerEndpoint {
                resolved: srv,
                keypair,
                proxies_by_name: Arc::new(proxies_by_name),
                proxy_statuses: Arc::new(proxy_statuses),
                statuses,
            });
        }

        let server_names: Vec<String> = endpoints.iter().map(|e| e.display_name()).collect();
        info!(
            "rrp client initialized for {} server(s) [{}] (ebpf: {})",
            endpoints.len(),
            server_names.join(", "),
            ebpf.status_reason()
        );

        Ok(Self {
            config,
            ebpf,
            endpoints,
            status,
        })
    }

    pub fn ebpf(&self) -> &EbpfAccelerator {
        &self.ebpf
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn resolved_servers(&self) -> Vec<ResolvedServerConfig> {
        self.endpoints.iter().map(|e| e.resolved.clone()).collect()
    }

    pub fn status(&self) -> RuntimeStatus {
        self.status.clone()
    }

    /// Establish a single-shot control session for a specific server (matched by `server_addr` or `name`).
    pub async fn run_server_session(
        &self,
        target: &str,
        ready_tx: Option<oneshot::Sender<Result<()>>>,
    ) -> Result<()> {
        let endpoint = self
            .endpoints
            .iter()
            .find(|e| {
                e.resolved.server_addr == target
                    || e.resolved.name.as_deref() == Some(target)
            })
            .ok_or_else(|| anyhow!("no configured server matching '{}'", target))?;

        run_endpoint_session(endpoint, &self.ebpf, ready_tx).await
    }

    /// Establish control session(s) with all configured servers concurrently.
    /// If `ready_tx` is provided, sends `Ok(())` once all configured servers acknowledge
    /// proxy registration (`RegisterAck`), or `Err` if any server fails registration.
    pub async fn run_session(&self, mut ready_tx: Option<oneshot::Sender<Result<()>>>) -> Result<()> {
        if self.endpoints.len() == 1 {
            return run_endpoint_session(&self.endpoints[0], &self.ebpf, ready_tx).await;
        }

        let mut join_set = JoinSet::new();
        let mut ready_rxs = Vec::with_capacity(self.endpoints.len());

        for endpoint in &self.endpoints {
            let endpoint = endpoint.clone();
            let ebpf = self.ebpf.clone();
            let (ep_tx, ep_rx) = oneshot::channel();
            ready_rxs.push((endpoint.display_name(), ep_rx));

            join_set.spawn(async move {
                run_endpoint_session(&endpoint, &ebpf, Some(ep_tx)).await
            });
        }

        for (srv_name, rx) in ready_rxs {
            match rx.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    let err_msg = format!("server {} failed registration: {:#}", srv_name, e);
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(Err(anyhow!("{}", err_msg)));
                    }
                    join_set.abort_all();
                    return Err(anyhow!("{}", err_msg));
                }
                Err(_) => {
                    // Task exited before signaling ready_tx; retrieve task error if available
                    let err_msg = if let Some(Ok(Err(task_err))) = join_set.join_next().await {
                        format!("server {} session failed: {:#}", srv_name, task_err)
                    } else {
                        format!("server {} session terminated before registration completed", srv_name)
                    };
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(Err(anyhow!("{}", err_msg)));
                    }
                    join_set.abort_all();
                    return Err(anyhow!("{}", err_msg));
                }
            }
        }

        if let Some(tx) = ready_tx.take() {
            let _ = tx.send(Ok(()));
        }

        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    join_set.abort_all();
                    return Err(e);
                }
                Err(join_err) if !join_err.is_cancelled() => {
                    join_set.abort_all();
                    return Err(anyhow!("server session task panicked: {}", join_err));
                }
                Err(_) => {}
            }
        }

        Ok(())
    }

    /// Run independent auto-reconnecting control loops for all configured servers concurrently.
    /// Each server connection is isolated: if one server disconnects or is temporarily unreachable,
    /// other servers continue forwarding traffic while the disconnected server retries in the background.
    /// If `ready_tx` is provided, sends `Ok(())` once all configured servers have registered at least once.
    pub async fn run_with_ready(&self, ready_tx: Option<oneshot::Sender<Result<()>>>) -> Result<()> {
        let mut join_set = JoinSet::new();
        let mut ready_rxs = Vec::new();

        for endpoint in &self.endpoints {
            let endpoint = endpoint.clone();
            let ebpf = self.ebpf.clone();
            let mut ep_ready_tx = if ready_tx.is_some() {
                let (tx, rx) = oneshot::channel();
                ready_rxs.push(rx);
                Some(tx)
            } else {
                None
            };

            join_set.spawn(async move {
                loop {
                    let (attempt_tx, attempt_rx) = oneshot::channel();
                    let session_fut = run_endpoint_session(&endpoint, &ebpf, Some(attempt_tx));

                    tokio::pin!(session_fut);
                    let mut attempt_rx_opt = Some(attempt_rx);

                    let res = loop {
                        tokio::select! {
                            res = &mut session_fut => break res,
                            attempt_res = async {
                                match attempt_rx_opt.as_mut() {
                                    Some(rx) => rx.await,
                                    None => std::future::pending().await,
                                }
                            } => {
                                attempt_rx_opt = None;
                                if let Ok(Ok(())) = attempt_res {
                                    if let Some(tx) = ep_ready_tx.take() {
                                        let _ = tx.send(());
                                    }
                                }
                            }
                        }
                    };

                    match res {
                        Ok(()) => {
                            warn!(
                                "client control session for server {} closed; reconnecting in {:?}...",
                                endpoint.display_name(),
                                RECONNECT_DELAY
                            );
                        }
                        Err(e) => {
                            error!(
                                "client session for server {} disconnected: {:#}; retrying in {:?}...",
                                endpoint.display_name(),
                                e,
                                RECONNECT_DELAY
                            );
                        }
                    }
                    tokio::time::sleep(RECONNECT_DELAY).await;
                }
            });
        }

        if let Some(tx) = ready_tx {
            tokio::spawn(async move {
                for rx in ready_rxs {
                    if rx.await.is_err() {
                        return;
                    }
                }
                let _ = tx.send(Ok(()));
            });
        }

        while let Some(res) = join_set.join_next().await {
            if let Err(e) = res {
                if !e.is_cancelled() {
                    error!("server supervisor task panicked: {}", e);
                }
            }
        }

        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        self.run_with_ready(None).await
    }
}

async fn run_endpoint_session(
    endpoint: &ServerEndpoint,
    ebpf: &EbpfAccelerator,
    ready_tx: Option<oneshot::Sender<Result<()>>>,
) -> Result<()> {
    endpoint.mark_connecting();
    let result = run_endpoint_session_inner(endpoint, ebpf, ready_tx).await;
    match &result {
        Ok(()) => endpoint.mark_disconnected(None),
        Err(error) => endpoint.mark_disconnected(Some(&format!("{:#}", error))),
    }
    result
}

async fn run_endpoint_session_inner(
    endpoint: &ServerEndpoint,
    ebpf: &EbpfAccelerator,
    mut ready_tx: Option<oneshot::Sender<Result<()>>>,
) -> Result<()> {
    let server_addr = &endpoint.resolved.server_addr;
    let display_name = endpoint.display_name();

    let tcp = connect_tcp(server_addr)
        .await
        .with_context(|| format!("failed to connect to rrp server at {}", display_name))?;

    let mut enc_stream = timeout(HANDSHAKE_TIMEOUT, client_handshake(tcp, &endpoint.keypair))
        .await
        .with_context(|| format!("mlkem768x25519plus client handshake timed out for {}", display_name))??;

    info!(
        "authenticated control connection to server {}",
        display_name
    );

    let specs: Vec<ProxySpec> = endpoint
        .resolved
        .proxies
        .iter()
        .map(|p| ProxySpec {
            name: p.name.clone(),
            proxy_type: p.proxy_type,
            local_addr: p.resolved_local_addr().unwrap_or_default(),
            remote_port: p.remote_port,
            remote_bind_ip: p.remote_bind_ip.clone(),
        })
        .collect();

    let role = RoleHandshake::Control { proxies: specs };
    enc_stream.send_frame(&role.encode()?).await?;

    let ack_raw = timeout(HANDSHAKE_TIMEOUT, enc_stream.recv_frame())
        .await
        .with_context(|| format!("timed out waiting for RegisterAck from server {}", display_name))??
        .ok_or_else(|| anyhow!("server {} closed connection before RegisterAck", display_name))?;

    match TunnelFrame::decode(ack_raw)? {
        TunnelFrame::Signal(ControlSignal::RegisterAck { success, message }) => {
            if !success {
                let err = anyhow!(
                    "server {} rejected proxy registration: {}",
                    display_name,
                    message
                );
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(Err(anyhow!("{}", err)));
                }
                return Err(err);
            }
            endpoint.mark_connected();
            info!(
                "connected to server {} successfully ({} proxies registered: {})",
                display_name,
                endpoint.resolved.proxies.len(),
                message
            );
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(Ok(()));
            }
        }
        other => {
            bail!(
                "unexpected frame while waiting for RegisterAck from {}: {:?}",
                display_name,
                other
            );
        }
    }

    let (mut enc_read, mut enc_write) = enc_stream.into_split();
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<TunnelFrame>();

    let writer_handle = tokio::spawn(async move {
        while let Some(frame) = ctrl_rx.recv().await {
            if let Ok(bytes) = frame.encode() {
                if enc_write.send_frame(&bytes).await.is_err() {
                    break;
                }
            }
        }
    });

    let hb_secs = endpoint.resolved.heartbeat_interval_secs.max(5);
    let hb_tx = ctrl_tx.clone();
    let hb_handle = tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(hb_secs));
        loop {
            ticker.tick().await;
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if hb_tx
                .send(TunnelFrame::Signal(ControlSignal::Ping {
                    timestamp_ms: now_ms,
                }))
                .is_err()
            {
                break;
            }
        }
    });

    let udp_sessions: Arc<DashMap<(String, SocketAddr), mpsc::Sender<Bytes>>> =
        Arc::new(DashMap::new());
    let read_timeout = Duration::from_secs(hb_secs.saturating_mul(3).max(15));

    let read_res: Result<()> = async {
        loop {
            let raw_frame = match timeout(read_timeout, enc_read.recv_frame()).await {
                Ok(Ok(Some(frame))) => frame,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {
                    bail!(
                        "heartbeat timed out waiting for server {} ({:?})",
                        display_name,
                        read_timeout
                    );
                }
            };
            let frame = match TunnelFrame::decode(raw_frame) {
                Ok(f) => f,
                Err(e) => {
                    warn!("failed to decode frame from server {}: {}", display_name, e);
                    continue;
                }
            };

            match frame {
                TunnelFrame::Signal(ControlSignal::ReqWorkConn {
                    conn_id,
                    proxy_name,
                    visitor_addr,
                }) => {
                    let Some(proxy_cfg) = endpoint.proxies_by_name.get(&proxy_name).cloned() else {
                        warn!(
                            "server {} requested work conn for unknown proxy '{}'",
                            display_name, proxy_name
                        );
                        continue;
                    };
                    let server_addr = endpoint.resolved.server_addr.clone();
                    let keypair = endpoint.keypair.clone();
                    let ebpf = ebpf.clone();
                    let Some(status) = endpoint.proxy_status(&proxy_name) else {
                        continue;
                    };

                    tokio::spawn(async move {
                        if let Err(e) = handle_work_tcp(
                            conn_id,
                            proxy_cfg,
                            visitor_addr,
                            server_addr,
                            keypair,
                            ebpf,
                            status,
                        )
                        .await
                        {
                            debug!(
                                "work connection conn_id={} failed: {:#}",
                                conn_id, e
                            );
                        }
                    });
                }
                TunnelFrame::Signal(ControlSignal::Pong { timestamp_ms }) => {
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    endpoint.record_heartbeat(Some(now_ms.saturating_sub(timestamp_ms)));
                    debug!(
                        "received heartbeat pong from {} (timestamp_ms={})",
                        display_name, timestamp_ms
                    );
                }
                TunnelFrame::Signal(_) => {}
                TunnelFrame::UdpDatagram {
                    proxy_name,
                    visitor_addr,
                    payload,
                } => {
                    let Some(proxy_cfg) = endpoint.proxies_by_name.get(&proxy_name).cloned() else {
                        continue;
                    };
                    let Some(status) = endpoint.proxy_status(&proxy_name) else {
                        continue;
                    };
                    status.record_received(payload.len());
                    let key = (proxy_name.clone(), visitor_addr);
                    if let Some(existing_tx) = udp_sessions.get(&key) {
                        if existing_tx.try_send(payload.clone()).is_ok() {
                            continue;
                        }
                    }

                    let (pkt_tx, pkt_rx) = mpsc::channel::<Bytes>(256);
                    let _ = pkt_tx.try_send(payload);
                    udp_sessions.insert(key.clone(), pkt_tx);

                    let sessions_clone = Arc::clone(&udp_sessions);
                    let ctrl_tx_clone = ctrl_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = run_udp_session(
                            proxy_cfg,
                            visitor_addr,
                            pkt_rx,
                            ctrl_tx_clone,
                            status,
                        )
                        .await
                        {
                            debug!("UDP session for visitor {} ended: {:#}", visitor_addr, e);
                        }
                        sessions_clone.remove(&key);
                    });
                }
            }
        }
        Ok(())
    }
    .await;

    udp_sessions.clear();
    hb_handle.abort();
    writer_handle.abort();
    read_res
}

async fn handle_work_tcp(
    conn_id: u64,
    proxy_cfg: ProxyConfig,
    visitor_addr: String,
    server_addr: String,
    keypair: ClientKeyPair,
    ebpf: EbpfAccelerator,
    status: ConnectionStatus,
) -> Result<()> {
    let local_addr = proxy_cfg.resolved_local_addr()?;

    // Connect to local target service (supports IPv4 or IPv6 transparently) and server in parallel
    let (local_res, server_res) = tokio::join!(
        connect_tcp(&local_addr),
        connect_tcp(&server_addr)
    );

    let local_stream = local_res.with_context(|| {
        format!(
            "failed to connect to local service '{}' for proxy '{}' (visitor {})",
            local_addr, proxy_cfg.name, visitor_addr
        )
    })?;
    let server_stream = server_res.with_context(|| {
        format!(
            "failed to connect work channel to server '{}' for conn_id={}",
            server_addr, conn_id
        )
    })?;

    let mut enc_work = timeout(HANDSHAKE_TIMEOUT, client_handshake(server_stream, &keypair))
        .await
        .context("work channel mlkem768x25519plus handshake timed out")??;

    let role = RoleHandshake::WorkTcp {
        conn_id,
        proxy_name: proxy_cfg.name.clone(),
    };
    enc_work.send_frame(&role.encode()?).await?;

    let _ =
        relay_encrypted_and_plain_with_status(enc_work, local_stream, Some(&ebpf), Some(&status))
            .await?;
    Ok(())
}

async fn run_udp_session(
    proxy_cfg: ProxyConfig,
    visitor_addr: SocketAddr,
    mut pkt_rx: mpsc::Receiver<Bytes>,
    ctrl_tx: mpsc::UnboundedSender<TunnelFrame>,
    status: ConnectionStatus,
) -> Result<()> {
    let local_addr_str = proxy_cfg.resolved_local_addr()?;
    let resolved_addrs = resolve_socket_addrs(&local_addr_str).await?;
    let target_addr = resolved_addrs[0];

    // Bind ephemeral UDP socket matching target_addr's IP version (V4 or V6),
    // enabling seamless IPv4 <-> IPv6 UDP translation!
    let local_udp = bind_ephemeral_udp_for_target(target_addr)?;
    let mut recv_buf = vec![0u8; UDP_MAX_PACKET_SIZE];

    loop {
        tokio::select! {
            maybe_outbound = pkt_rx.recv() => {
                match maybe_outbound {
                    Some(payload) => {
                        local_udp.send_to(&payload, target_addr).await?;
                    }
                    None => break,
                }
            }
            recv_res = timeout(UDP_SESSION_IDLE_TIMEOUT, local_udp.recv_from(&mut recv_buf)) => {
                match recv_res {
                    Ok(Ok((n, _from_addr))) => {
                        let reply = TunnelFrame::UdpDatagram {
                            proxy_name: proxy_cfg.name.clone(),
                            visitor_addr,
                            payload: Bytes::copy_from_slice(&recv_buf[..n]),
                        };
                        if ctrl_tx.send(reply).is_err() {
                            break;
                        }
                        status.record_sent(n);
                    }
                    Ok(Err(e)) => {
                        return Err(e.into());
                    }
                    Err(_) => {
                        // Idle timeout elapsed
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn run_client(config: ClientConfig) -> Result<()> {
    let client = Client::new(config)?;
    let mut status_reporter = match StatusReporter::start(client.status()).await {
        Ok(reporter) => Some(reporter),
        Err(error) => {
            warn!("runtime status reporting is unavailable: {:#}", error);
            None
        }
    };
    let res = tokio::select! {
        res = client.run() => res,
        _ = wait_for_shutdown_signal() => {
            info!("rrp client shutting down");
            Ok(())
        }
    };
    if let Some(reporter) = &mut status_reporter {
        reporter.shutdown().await;
    }
    res
}
