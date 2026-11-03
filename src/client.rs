use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::{interval, timeout, MissedTickBehavior};
use tracing::{debug, error, info, warn};

use crate::cli::RunMode;
use crate::config::{ClientConfig, ProxyConfig, ResolvedServerConfig, TunnelMode};
use crate::crypto::{client_handshake, ClientKeyPair};
use crate::ebpf::EbpfAccelerator;
use crate::net_utils::{
    bind_ephemeral_udp_for_target, connect_tcp, connect_tcp_addr, format_server_proxy_addr,
    resolve_socket_addrs,
};
use crate::protocol::{
    ControlSignal, ProxySpec, RoleHandshake, TunnelFrame, TunnelRequest, TUNNEL_PROTOCOL_VERSION,
};
use crate::relay::relay_encrypted_and_plain_with_status;
use crate::status::{wait_for_shutdown_signal, ConnectionStatus, RuntimeStatus, StatusReporter};
use crate::tunnel::plain_relay::{start_tunnel_listeners, TunnelListenerSet};
use crate::tunnel::{host_supports_tunnel, TunnelClient};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// First retry happens quickly; subsequent failures back off exponentially up to the maximum so a
/// server that is down for hours is not hammered (and the log not flooded) every two seconds.
const RECONNECT_DELAY_INITIAL: Duration = Duration::from_secs(2);
const RECONNECT_DELAY_MAX: Duration = Duration::from_secs(60);
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_MAX_PACKET_SIZE: usize = 65535;
/// Per-visitor queue of datagrams waiting to be delivered to the local service.
const UDP_SESSION_QUEUE_LEN: usize = 256;
/// Datagrams queued from all local services towards one server's control channel.
const UDP_OUTBOUND_QUEUE_LEN: usize = 1024;
/// Upper bound on simultaneously tracked UDP visitors per server session. Each session owns a
/// socket and a task, so an unbounded number would let a spoofed-source flood exhaust the client.
const UDP_MAX_SESSIONS: usize = 4096;
/// Policy-routing table and rule priority base for client tunnel interfaces (one per server).
const TUNNEL_ROUTE_TABLE_BASE: u32 = 7200;
/// How long sessions get to tear down their tunnels after a shutdown signal.
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct ServerEndpoint {
    index: usize,
    resolved: ResolvedServerConfig,
    keypair: ClientKeyPair,
    proxies_by_name: Arc<HashMap<String, ProxyConfig>>,
    proxy_statuses: Arc<HashMap<String, ConnectionStatus>>,
    statuses: Vec<ConnectionStatus>,
    tunnel_mode: TunnelMode,
    /// Set once a tunnel attempt failed in `auto` mode; later sessions use the relay.
    tunnel_failed: Arc<AtomicBool>,
    /// Process-wide status, so a session can report which data plane it ended up on.
    runtime_status: RuntimeStatus,
    /// Flips to `true` when the process is shutting down; sessions then tear down cleanly
    /// (tunnel interfaces, policy rules) instead of being cancelled mid-flight.
    shutdown: watch::Receiver<bool>,
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

    fn tunnel_interface(&self) -> String {
        format!("rrpc-wg{}", self.index)
    }

    fn tunnel_table(&self) -> u32 {
        TUNNEL_ROUTE_TABLE_BASE + self.index as u32
    }

    /// Whether this session should ask the server for the tunnel data plane.
    fn wants_tunnel(&self) -> Result<bool> {
        match self.tunnel_mode {
            TunnelMode::Relay => Ok(false),
            TunnelMode::Tunnel => match host_supports_tunnel() {
                Ok(()) => Ok(true),
                Err(reason) => bail!("tunnel_mode = \"tunnel\" but {}", reason),
            },
            TunnelMode::Auto => {
                if self.tunnel_failed.load(Ordering::Relaxed) {
                    return Ok(false);
                }
                match host_supports_tunnel() {
                    Ok(()) => Ok(true),
                    Err(reason) => {
                        debug!(
                            "server {}: tunnel data plane not used ({}), relaying instead",
                            self.display_name(),
                            reason
                        );
                        Ok(false)
                    }
                }
            }
        }
    }
}

pub struct Client {
    config: ClientConfig,
    ebpf: EbpfAccelerator,
    endpoints: Vec<ServerEndpoint>,
    status: RuntimeStatus,
    shutdown_tx: watch::Sender<bool>,
}

impl Client {
    pub fn new(config: ClientConfig) -> Result<Self> {
        let resolved_servers = config.resolve_servers()?;
        let ebpf = EbpfAccelerator::try_init(config.enable_ebpf);
        let status = RuntimeStatus::new(RunMode::Client, ebpf.status_reason(), None);

        let tunnel_mode = if config.enable_ebpf {
            config.tunnel_mode
        } else {
            TunnelMode::Relay
        };
        if tunnel_mode == TunnelMode::Relay {
            ebpf.set_fallback("relay data plane selected by configuration");
            status.set_ebpf_status(ebpf.status_reason());
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let multi_server = resolved_servers.len() > 1;
        let mut endpoints = Vec::with_capacity(resolved_servers.len());
        for (index, srv) in resolved_servers.into_iter().enumerate() {
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
                index,
                resolved: srv,
                keypair,
                proxies_by_name: Arc::new(proxies_by_name),
                proxy_statuses: Arc::new(proxy_statuses),
                statuses,
                tunnel_mode,
                tunnel_failed: Arc::new(AtomicBool::new(false)),
                runtime_status: status.clone(),
                shutdown: shutdown_rx.clone(),
            });
        }

        let server_names: Vec<String> = endpoints.iter().map(|e| e.display_name()).collect();
        info!(
            "rrp client initialized for {} server(s) [{}] (data plane: {}, tunnel_mode: {})",
            endpoints.len(),
            server_names.join(", "),
            ebpf.status_reason(),
            tunnel_mode.as_str()
        );

        Ok(Self {
            config,
            ebpf,
            endpoints,
            status,
            shutdown_tx,
        })
    }

    /// Ask every session to end and clean up; `run`/`run_with_ready` return once they have.
    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub fn shutdown_handle(&self) -> watch::Sender<bool> {
        self.shutdown_tx.clone()
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
                e.resolved.server_addr == target || e.resolved.name.as_deref() == Some(target)
            })
            .ok_or_else(|| anyhow!("no configured server matching '{}'", target))?;

        run_endpoint_session(endpoint, &self.ebpf, ready_tx).await
    }

    /// Establish control session(s) with all configured servers concurrently.
    /// If `ready_tx` is provided, sends `Ok(())` once all configured servers acknowledge
    /// proxy registration (`RegisterAck`), or `Err` if any server fails registration.
    pub async fn run_session(
        &self,
        mut ready_tx: Option<oneshot::Sender<Result<()>>>,
    ) -> Result<()> {
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

            join_set
                .spawn(async move { run_endpoint_session(&endpoint, &ebpf, Some(ep_tx)).await });
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
                        format!(
                            "server {} session terminated before registration completed",
                            srv_name
                        )
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
    pub async fn run_with_ready(
        &self,
        ready_tx: Option<oneshot::Sender<Result<()>>>,
    ) -> Result<()> {
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
                let mut reconnect_delay = RECONNECT_DELAY_INITIAL;
                let mut shutdown = endpoint.shutdown.clone();
                loop {
                    if *shutdown.borrow() {
                        break;
                    }
                    let (attempt_tx, attempt_rx) = oneshot::channel();
                    let session_fut = run_endpoint_session(&endpoint, &ebpf, Some(attempt_tx));

                    tokio::pin!(session_fut);
                    let mut attempt_rx_opt = Some(attempt_rx);
                    let mut registered = false;

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
                                    registered = true;
                                    if let Some(tx) = ep_ready_tx.take() {
                                        let _ = tx.send(());
                                    }
                                }
                            }
                        }
                    };

                    // A session that registered successfully resets the back-off: the next
                    // failure is a fresh incident, not a continuation of an outage.
                    if registered {
                        reconnect_delay = RECONNECT_DELAY_INITIAL;
                    }
                    if *shutdown.borrow() {
                        break;
                    }

                    match res {
                        Ok(()) => {
                            warn!(
                                "client control session for server {} closed; reconnecting in {:?}...",
                                endpoint.display_name(),
                                reconnect_delay
                            );
                        }
                        Err(e) => {
                            error!(
                                "client session for server {} disconnected: {:#}; retrying in {:?}...",
                                endpoint.display_name(),
                                e,
                                reconnect_delay
                            );
                        }
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(reconnect_delay) => {}
                        _ = shutdown.changed() => break,
                    }
                    reconnect_delay = (reconnect_delay * 2).min(RECONNECT_DELAY_MAX);
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

/// Live state of one UDP visitor session: the queue feeding its socket task and a generation
/// number so a finished task only removes its own map entry, never a successor's.
struct UdpSessionHandle {
    generation: u64,
    tx: mpsc::Sender<Bytes>,
}

type UdpSessions = Arc<DashMap<(String, SocketAddr), UdpSessionHandle>>;

/// Everything the client holds while a session runs over the tunnel data plane. Dropping the
/// listeners stops them; the interface is removed explicitly so netlink errors can be logged.
struct ClientTunnelState {
    tunnel: TunnelClient,
    listeners: TunnelListenerSet,
}

async fn run_endpoint_session_inner(
    endpoint: &ServerEndpoint,
    ebpf: &EbpfAccelerator,
    mut ready_tx: Option<oneshot::Sender<Result<()>>>,
) -> Result<()> {
    let server_addr = &endpoint.resolved.server_addr;
    let display_name = endpoint.display_name();
    let want_tunnel = endpoint.wants_tunnel()?;

    let tcp = connect_tcp(server_addr)
        .await
        .with_context(|| format!("failed to connect to rrp server at {}", display_name))?;
    // Work connections dial the exact address the control session landed on, so they never
    // re-resolve a hostname (and never land on a different host than the session they serve).
    let server_socket_addr = tcp
        .peer_addr()
        .with_context(|| format!("failed to query peer address of server {}", display_name))?;

    let mut enc_stream = timeout(HANDSHAKE_TIMEOUT, client_handshake(tcp, &endpoint.keypair))
        .await
        .with_context(|| {
            format!(
                "mlkem768x25519plus client handshake timed out for {}",
                display_name
            )
        })??;

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

    let role = RoleHandshake::Control {
        proxies: specs,
        tunnel: want_tunnel.then_some(TunnelRequest {
            version: TUNNEL_PROTOCOL_VERSION,
        }),
    };
    enc_stream.send_frame(&role.encode()?).await?;

    let ack_raw = timeout(HANDSHAKE_TIMEOUT, enc_stream.recv_frame())
        .await
        .with_context(|| {
            format!(
                "timed out waiting for RegisterAck from server {}",
                display_name
            )
        })??
        .ok_or_else(|| {
            anyhow!(
                "server {} closed connection before RegisterAck",
                display_name
            )
        })?;

    let assignment = match TunnelFrame::decode(ack_raw)? {
        TunnelFrame::Signal(ControlSignal::RegisterAck {
            success,
            message,
            tunnel,
        }) => {
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
            if tunnel.is_none() {
                if want_tunnel && endpoint.tunnel_mode == TunnelMode::Tunnel {
                    bail!(
                        "server {} does not offer the tunnel data plane but tunnel_mode = \"tunnel\"",
                        display_name
                    );
                }
                if want_tunnel {
                    info!(
                        "server {} does not offer the tunnel data plane; relaying instead",
                        display_name
                    );
                    ebpf.set_fallback(format!(
                        "server {} does not offer the tunnel data plane",
                        display_name
                    ));
                    endpoint
                        .runtime_status
                        .set_ebpf_status(ebpf.status_reason());
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
            tunnel
        }
        other => {
            bail!(
                "unexpected frame while waiting for RegisterAck from {}: {:?}",
                display_name,
                other
            );
        }
    };

    // Tunnel data plane: bring up WireGuard, bind in-tunnel listeners, report the ports.
    let mut tunnel_state: Option<ClientTunnelState> = None;
    if let Some(assignment) = assignment {
        let setup = async {
            let tunnel = TunnelClient::setup(
                &endpoint.tunnel_interface(),
                &assignment,
                server_socket_addr.ip(),
                endpoint.keypair.x25519_private_bytes(),
                enc_stream.tunnel_psk(),
                endpoint.tunnel_table(),
            )
            .await?;
            let listeners = match start_tunnel_listeners(
                tunnel.client_v4,
                tunnel.client_v6,
                &endpoint.resolved.proxies,
                |name| endpoint.proxy_status(name),
            )
            .await
            {
                Ok(listeners) => listeners,
                Err(e) => {
                    tunnel.teardown().await;
                    return Err(e);
                }
            };
            Ok::<_, anyhow::Error>(ClientTunnelState { tunnel, listeners })
        };
        let state = match setup.await {
            Ok(state) => state,
            Err(e) => {
                let err = tunnel_failure(endpoint, &display_name, e);
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(Err(anyhow!("{}", err)));
                }
                return Err(err);
            }
        };

        let ready = TunnelFrame::Signal(ControlSignal::TunnelReady {
            bindings: state.listeners.bindings.clone(),
        });
        if let Err(e) = enc_stream.send_frame(&ready.encode()?).await {
            state.tunnel.teardown().await;
            return Err(e.into());
        }
        let ack = timeout(HANDSHAKE_TIMEOUT, enc_stream.recv_frame()).await;
        let verdict = match ack {
            Ok(Ok(Some(raw))) => match TunnelFrame::decode(raw) {
                Ok(TunnelFrame::Signal(ControlSignal::TunnelAck { success, message })) => {
                    if success {
                        Ok(message)
                    } else {
                        Err(anyhow!(
                            "server {} rejected tunnel: {}",
                            display_name,
                            message
                        ))
                    }
                }
                Ok(other) => Err(anyhow!(
                    "unexpected frame while waiting for TunnelAck from {}: {:?}",
                    display_name,
                    other
                )),
                Err(e) => Err(e),
            },
            Ok(Ok(None)) => Err(anyhow!(
                "server {} closed connection before TunnelAck",
                display_name
            )),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(anyhow!(
                "timed out waiting for TunnelAck from server {}",
                display_name
            )),
        };
        match verdict {
            Ok(message) => {
                endpoint.mark_connected();
                ebpf.set_active(format!(
                    "active (WireGuard tunnel {} to {})",
                    endpoint.tunnel_interface(),
                    display_name
                ));
                endpoint
                    .runtime_status
                    .set_ebpf_status(ebpf.status_reason());
                info!(
                    "connected to server {} through the tunnel ({} proxies registered: {})",
                    display_name,
                    endpoint.resolved.proxies.len(),
                    message
                );
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(Ok(()));
                }
                tunnel_state = Some(state);
            }
            Err(e) => {
                state.tunnel.teardown().await;
                let err = tunnel_failure(endpoint, &display_name, e);
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(Err(anyhow!("{}", err)));
                }
                return Err(err);
            }
        }
    }

    let (mut enc_read, mut enc_write) = enc_stream.into_split();
    // Heartbeats must never be starved by bulk UDP replies, so they travel on their own channel
    // and the writer prefers it; datagrams are dropped (not buffered forever) under back-pressure.
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<TunnelFrame>();
    let (udp_tx, mut udp_rx) = mpsc::channel::<TunnelFrame>(UDP_OUTBOUND_QUEUE_LEN);

    let writer_handle = tokio::spawn(async move {
        let mut udp_open = true;
        loop {
            let frame = tokio::select! {
                biased;
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

    let hb_secs = endpoint.resolved.heartbeat_interval_secs.max(5);
    let hb_tx = ctrl_tx.clone();
    let hb_handle = tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(hb_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
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

    let udp_sessions: UdpSessions = Arc::new(DashMap::new());
    let mut udp_generation: u64 = 0;
    let read_timeout = Duration::from_secs(hb_secs.saturating_mul(3).max(15));

    let mut shutdown = endpoint.shutdown.clone();
    let read_res: Result<()> = async {
        loop {
            let received = tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    info!("closing control session to server {} for shutdown", display_name);
                    break;
                }
                res = timeout(read_timeout, enc_read.recv_frame()) => res,
            };
            let raw_frame = match received {
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
                    warn!(
                        "failed to decode frame from server {}: {}",
                        display_name, e
                    );
                    continue;
                }
            };

            match frame {
                TunnelFrame::Signal(ControlSignal::ReqWorkConn {
                    conn_id,
                    proxy_name,
                    visitor_addr,
                }) => {
                    let Some(proxy_cfg) = endpoint.proxies_by_name.get(&proxy_name).cloned()
                    else {
                        warn!(
                            "server {} requested work conn for unknown proxy '{}'",
                            display_name, proxy_name
                        );
                        continue;
                    };
                    let keypair = endpoint.keypair.clone();
                    let Some(status) = endpoint.proxy_status(&proxy_name) else {
                        continue;
                    };

                    tokio::spawn(async move {
                        if let Err(e) = handle_work_tcp(
                            conn_id,
                            proxy_cfg,
                            visitor_addr,
                            server_socket_addr,
                            keypair,
                            status,
                        )
                        .await
                        {
                            debug!("work connection conn_id={} failed: {:#}", conn_id, e);
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
                    let Some(proxy_cfg) = endpoint.proxies_by_name.get(&proxy_name).cloned()
                    else {
                        continue;
                    };
                    let Some(status) = endpoint.proxy_status(&proxy_name) else {
                        continue;
                    };
                    status.record_received(payload.len());
                    let key = (proxy_name.clone(), visitor_addr);

                    // Deliver to the existing session when there is one. A full queue means the
                    // local service is slower than the visitor: drop this datagram (UDP semantics)
                    // rather than spawning a competing session for the same visitor.
                    let payload = match udp_sessions.get(&key) {
                        Some(session) => match session.tx.try_send(payload) {
                            Ok(()) => continue,
                            Err(TrySendError::Full(_)) => {
                                debug!(
                                    "UDP session {}:{} queue full, dropping datagram",
                                    proxy_name, visitor_addr
                                );
                                continue;
                            }
                            Err(TrySendError::Closed(payload)) => payload,
                        },
                        None => payload,
                    };

                    if udp_sessions.len() >= UDP_MAX_SESSIONS {
                        warn!(
                            "UDP session limit ({}) reached on server {}, dropping datagram from {}",
                            UDP_MAX_SESSIONS, display_name, visitor_addr
                        );
                        continue;
                    }

                    let (pkt_tx, pkt_rx) = mpsc::channel::<Bytes>(UDP_SESSION_QUEUE_LEN);
                    let _ = pkt_tx.try_send(payload);
                    udp_generation += 1;
                    let generation = udp_generation;
                    udp_sessions.insert(
                        key.clone(),
                        UdpSessionHandle {
                            generation,
                            tx: pkt_tx,
                        },
                    );

                    let sessions_clone = Arc::clone(&udp_sessions);
                    let udp_tx_clone = udp_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            run_udp_session(proxy_cfg, visitor_addr, pkt_rx, udp_tx_clone, status)
                                .await
                        {
                            debug!("UDP session for visitor {} ended: {:#}", visitor_addr, e);
                        }
                        sessions_clone
                            .remove_if(&key, |_, session| session.generation == generation);
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
    if let Some(state) = tunnel_state.take() {
        drop(state.listeners);
        state.tunnel.teardown().await;
    }
    read_res
}

/// Record a failed tunnel attempt: in `auto` mode later sessions fall back to the relay, in
/// `tunnel` mode the error is surfaced as-is and the session keeps retrying the tunnel.
fn tunnel_failure(
    endpoint: &ServerEndpoint,
    display_name: &str,
    e: anyhow::Error,
) -> anyhow::Error {
    match endpoint.tunnel_mode {
        TunnelMode::Auto => {
            endpoint.tunnel_failed.store(true, Ordering::Relaxed);
            endpoint
                .runtime_status
                .set_ebpf_status(format!("fallback (tunnel failed: {:#})", e));
            warn!(
                "tunnel data plane failed for server {}; falling back to relay on reconnect: {:#}",
                display_name, e
            );
            e.context("tunnel data plane failed (falling back to relay)")
        }
        _ => e.context(format!(
            "tunnel data plane failed for server {}",
            display_name
        )),
    }
}

async fn handle_work_tcp(
    conn_id: u64,
    proxy_cfg: ProxyConfig,
    visitor_addr: String,
    server_addr: SocketAddr,
    keypair: ClientKeyPair,
    status: ConnectionStatus,
) -> Result<()> {
    let local_addr = proxy_cfg.resolved_local_addr()?;

    // Connect to local target service (supports IPv4 or IPv6 transparently) and server in parallel
    let (local_res, server_res) =
        tokio::join!(connect_tcp(&local_addr), connect_tcp_addr(server_addr));

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

    let _ = relay_encrypted_and_plain_with_status(enc_work, local_stream, Some(&status)).await?;
    Ok(())
}

async fn run_udp_session(
    proxy_cfg: ProxyConfig,
    visitor_addr: SocketAddr,
    mut pkt_rx: mpsc::Receiver<Bytes>,
    udp_tx: mpsc::Sender<TunnelFrame>,
    status: ConnectionStatus,
) -> Result<()> {
    let local_addr_str = proxy_cfg.resolved_local_addr()?;
    let resolved_addrs = resolve_socket_addrs(&local_addr_str).await?;
    let target_addr = resolved_addrs[0];

    // Bind ephemeral UDP socket matching target_addr's IP version (V4 or V6),
    // enabling seamless IPv4 <-> IPv6 UDP translation. Connecting it makes the kernel discard
    // datagrams from any other source and surfaces ICMP "port unreachable" as an error, so a
    // session towards a dead local service ends immediately instead of idling for a minute.
    let local_udp = bind_ephemeral_udp_for_target(target_addr)?;
    local_udp.connect(target_addr).await.with_context(|| {
        format!(
            "failed to connect UDP socket to local service {}",
            target_addr
        )
    })?;
    let mut recv_buf = vec![0u8; UDP_MAX_PACKET_SIZE];

    loop {
        tokio::select! {
            maybe_outbound = pkt_rx.recv() => {
                match maybe_outbound {
                    Some(payload) => {
                        local_udp.send(&payload).await?;
                    }
                    None => break,
                }
            }
            recv_res = timeout(UDP_SESSION_IDLE_TIMEOUT, local_udp.recv(&mut recv_buf)) => {
                match recv_res {
                    Ok(Ok(n)) => {
                        let reply = TunnelFrame::UdpDatagram {
                            proxy_name: proxy_cfg.name.clone(),
                            visitor_addr,
                            payload: Bytes::copy_from_slice(&recv_buf[..n]),
                        };
                        match udp_tx.try_send(reply) {
                            Ok(()) => status.record_sent(n),
                            Err(TrySendError::Full(_)) => {
                                debug!(
                                    "server link saturated, dropping UDP reply for visitor {}",
                                    visitor_addr
                                );
                            }
                            Err(TrySendError::Closed(_)) => break,
                        }
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
    // On SIGTERM/SIGINT ask the sessions to end so tunnel interfaces and policy rules are
    // removed; give them a bounded grace period before exiting regardless.
    let shutdown_tx = client.shutdown_handle();
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        info!("rrp client shutting down");
        let _ = shutdown_tx.send(true);
    });
    let res = tokio::select! {
        res = client.run() => res,
        _ = async {
            let _ = shutdown_rx.changed().await;
            tokio::time::sleep(SHUTDOWN_GRACE_PERIOD).await;
        } => {
            warn!("sessions did not finish within {:?}; exiting anyway", SHUTDOWN_GRACE_PERIOD);
            Ok(())
        }
    };
    if let Some(reporter) = &mut status_reporter {
        reporter.shutdown().await;
    }
    res
}
