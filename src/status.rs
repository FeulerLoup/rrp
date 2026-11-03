use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tokio::time::interval;
use tracing::warn;

use crate::cli::RunMode;

const STATUS_SCHEMA_VERSION: u32 = 1;
const STATUS_UPDATE_INTERVAL: Duration = Duration::from_secs(1);
const STATUS_STALE_AFTER: Duration = Duration::from_secs(10);

const STATE_DISCONNECTED: u8 = 0;
const STATE_CONNECTING: u8 = 1;
const STATE_CONNECTED: u8 = 2;

#[derive(Default)]
struct Counters {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

struct ConnectionInner {
    order: u64,
    id: String,
    name: String,
    proxy_type: String,
    server_addr: String,
    target_addr: String,
    address: String,
    state: AtomicU8,
    connected_at_unix_ms: AtomicU64,
    last_heartbeat_unix_ms: AtomicU64,
    last_heartbeat_rtt_ms: AtomicU64,
    last_error: RwLock<Option<String>>,
    counters: Arc<Counters>,
}

struct RuntimeStatusInner {
    mode: RunMode,
    running: AtomicBool,
    pid: u32,
    started_at_unix_ms: u64,
    listen_addr: Option<String>,
    ebpf_status: String,
    counters: Arc<Counters>,
    connections: DashMap<String, Arc<ConnectionInner>>,
    next_connection_id: AtomicU64,
}

/// In-memory metrics for a running client or server process.
#[derive(Clone)]
pub struct RuntimeStatus {
    inner: Arc<RuntimeStatusInner>,
}

/// Metrics associated with one client-to-server control connection.
#[derive(Clone)]
pub struct ConnectionStatus {
    inner: Arc<ConnectionInner>,
    global_counters: Arc<Counters>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSnapshot {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub proxy_type: String,
    #[serde(default)]
    pub server_addr: String,
    #[serde(default)]
    pub target_addr: String,
    pub address: String,
    pub state: String,
    pub connected_at_unix_ms: Option<u64>,
    pub connected_for_secs: Option<u64>,
    pub last_heartbeat_unix_ms: Option<u64>,
    pub last_heartbeat_age_secs: Option<u64>,
    pub last_heartbeat_rtt_ms: Option<u64>,
    pub traffic: TrafficSnapshot,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusSnapshot {
    pub schema_version: u32,
    pub mode: String,
    pub running: bool,
    pub pid: u32,
    pub started_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub uptime_secs: u64,
    pub listen_addr: Option<String>,
    pub ebpf_status: String,
    pub traffic: TrafficSnapshot,
    pub connections: Vec<ConnectionSnapshot>,
}

impl RuntimeStatus {
    pub fn new(mode: RunMode, ebpf_status: impl Into<String>, listen_addr: Option<String>) -> Self {
        Self {
            inner: Arc::new(RuntimeStatusInner {
                mode,
                running: AtomicBool::new(true),
                pid: std::process::id(),
                started_at_unix_ms: now_unix_ms(),
                listen_addr,
                ebpf_status: ebpf_status.into(),
                counters: Arc::new(Counters::default()),
                connections: DashMap::new(),
                next_connection_id: AtomicU64::new(1),
            }),
        }
    }

    pub fn mode(&self) -> RunMode {
        self.inner.mode
    }

    pub fn mark_offline(&self) {
        self.inner.running.store(false, Ordering::Relaxed);
        for entry in self.inner.connections.iter() {
            entry
                .value()
                .state
                .store(STATE_DISCONNECTED, Ordering::Relaxed);
            entry
                .value()
                .connected_at_unix_ms
                .store(0, Ordering::Relaxed);
        }
    }

    /// Create or return the persistent status entry for a configured proxy endpoint.
    pub fn proxy_endpoint(
        &self,
        id: impl Into<String>,
        name: impl Into<String>,
        proxy_type: impl Into<String>,
        server_addr: impl Into<String>,
        target_addr: impl Into<String>,
    ) -> ConnectionStatus {
        let id = id.into();
        let name = name.into();
        let proxy_type = proxy_type.into();
        let server_addr = server_addr.into();
        let target_addr = target_addr.into();
        let address = server_addr.clone();
        let inner = self
            .inner
            .connections
            .entry(id.clone())
            .or_insert_with(|| {
                let order = self
                    .inner
                    .next_connection_id
                    .fetch_add(1, Ordering::Relaxed);
                Arc::new(ConnectionInner {
                    order,
                    id,
                    name,
                    proxy_type,
                    server_addr,
                    target_addr,
                    address,
                    state: AtomicU8::new(STATE_DISCONNECTED),
                    connected_at_unix_ms: AtomicU64::new(0),
                    last_heartbeat_unix_ms: AtomicU64::new(0),
                    last_heartbeat_rtt_ms: AtomicU64::new(u64::MAX),
                    last_error: RwLock::new(None),
                    counters: Arc::new(Counters::default()),
                })
            })
            .clone();

        ConnectionStatus {
            inner,
            global_counters: Arc::clone(&self.inner.counters),
        }
    }

    /// Create or return the persistent status entry for a configured client endpoint.
    pub fn endpoint(
        &self,
        id: impl Into<String>,
        name: impl Into<String>,
        address: impl Into<String>,
    ) -> ConnectionStatus {
        let address = address.into();
        self.proxy_endpoint(id, name, "tcp", address, "-")
    }

    /// Add a uniquely identified server-side proxy session.
    pub fn server_proxy_session(
        &self,
        peer_addr: impl Into<String>,
        name: impl Into<String>,
        proxy_type: impl Into<String>,
        server_addr: impl Into<String>,
        target_addr: impl Into<String>,
    ) -> ConnectionStatus {
        let peer_addr = peer_addr.into();
        let name = name.into();
        let sequence = self
            .inner
            .next_connection_id
            .fetch_add(1, Ordering::Relaxed);
        let id = format!("{}#{}#{}", peer_addr, name, sequence);
        self.proxy_endpoint(id, name, proxy_type, server_addr, target_addr)
    }

    /// Add a uniquely identified server-side client session.
    pub fn server_session(&self, peer_addr: impl Into<String>) -> ConnectionStatus {
        let address = peer_addr.into();
        let sequence = self
            .inner
            .next_connection_id
            .fetch_add(1, Ordering::Relaxed);
        let id = format!("{}#{}", address, sequence);
        self.endpoint(id, address.clone(), address)
    }

    pub fn remove_connection(&self, id: &str) {
        self.inner.connections.remove(id);
    }

    pub fn snapshot(&self) -> StatusSnapshot {
        let now_ms = now_unix_ms();
        let global = &self.inner.counters;
        let mut connections: Vec<(u64, ConnectionSnapshot)> = self
            .inner
            .connections
            .iter()
            .map(|entry| (entry.value().order, snapshot_connection(entry.value(), now_ms)))
            .collect();
        connections.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.id.cmp(&b.1.id)));
        let connections = connections.into_iter().map(|(_, snapshot)| snapshot).collect();

        StatusSnapshot {
            schema_version: STATUS_SCHEMA_VERSION,
            mode: self.inner.mode.as_str().to_string(),
            running: self.inner.running.load(Ordering::Relaxed),
            pid: self.inner.pid,
            started_at_unix_ms: self.inner.started_at_unix_ms,
            updated_at_unix_ms: now_ms,
            uptime_secs: elapsed_secs(self.inner.started_at_unix_ms, now_ms),
            listen_addr: self.inner.listen_addr.clone(),
            ebpf_status: self.inner.ebpf_status.clone(),
            traffic: traffic_snapshot(global),
            connections,
        }
    }
}

impl ConnectionStatus {
    pub fn id(&self) -> &str {
        &self.inner.id
    }

    pub fn mark_connecting(&self) {
        self.inner.state.store(STATE_CONNECTING, Ordering::Relaxed);
        self.inner.connected_at_unix_ms.store(0, Ordering::Relaxed);
        self.inner
            .last_heartbeat_unix_ms
            .store(0, Ordering::Relaxed);
        self.inner
            .last_heartbeat_rtt_ms
            .store(u64::MAX, Ordering::Relaxed);
    }

    pub fn mark_connected(&self) {
        self.inner
            .connected_at_unix_ms
            .store(now_unix_ms(), Ordering::Relaxed);
        self.inner.state.store(STATE_CONNECTED, Ordering::Relaxed);
        if let Ok(mut last_error) = self.inner.last_error.write() {
            *last_error = None;
        }
    }

    pub fn mark_disconnected(&self, error: Option<&str>) {
        self.inner
            .state
            .store(STATE_DISCONNECTED, Ordering::Relaxed);
        self.inner.connected_at_unix_ms.store(0, Ordering::Relaxed);
        if let Some(error) = error {
            if let Ok(mut last_error) = self.inner.last_error.write() {
                *last_error = Some(error.to_string());
            }
        }
    }

    pub fn record_heartbeat(&self, rtt_ms: Option<u64>) {
        self.inner
            .last_heartbeat_unix_ms
            .store(now_unix_ms(), Ordering::Relaxed);
        self.inner
            .last_heartbeat_rtt_ms
            .store(rtt_ms.unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub fn record_sent(&self, bytes: usize) {
        let bytes = bytes as u64;
        self.inner
            .counters
            .bytes_sent
            .fetch_add(bytes, Ordering::Relaxed);
        self.global_counters
            .bytes_sent
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_received(&self, bytes: usize) {
        let bytes = bytes as u64;
        self.inner
            .counters
            .bytes_received
            .fetch_add(bytes, Ordering::Relaxed);
        self.global_counters
            .bytes_received
            .fetch_add(bytes, Ordering::Relaxed);
    }
}

fn snapshot_connection(connection: &ConnectionInner, now_ms: u64) -> ConnectionSnapshot {
    let connected_at = nonzero(connection.connected_at_unix_ms.load(Ordering::Relaxed));
    let last_heartbeat = nonzero(connection.last_heartbeat_unix_ms.load(Ordering::Relaxed));
    let heartbeat_rtt = connection.last_heartbeat_rtt_ms.load(Ordering::Relaxed);
    let state = match connection.state.load(Ordering::Relaxed) {
        STATE_CONNECTING => "connecting",
        STATE_CONNECTED => "connected",
        _ => "disconnected",
    };

    ConnectionSnapshot {
        id: connection.id.clone(),
        name: connection.name.clone(),
        proxy_type: connection.proxy_type.clone(),
        server_addr: connection.server_addr.clone(),
        target_addr: connection.target_addr.clone(),
        address: connection.address.clone(),
        state: state.to_string(),
        connected_at_unix_ms: connected_at,
        connected_for_secs: connected_at.map(|started| elapsed_secs(started, now_ms)),
        last_heartbeat_unix_ms: last_heartbeat,
        last_heartbeat_age_secs: last_heartbeat.map(|last| elapsed_secs(last, now_ms)),
        last_heartbeat_rtt_ms: (heartbeat_rtt != u64::MAX).then_some(heartbeat_rtt),
        traffic: traffic_snapshot(&connection.counters),
        last_error: connection
            .last_error
            .read()
            .ok()
            .and_then(|value| value.clone()),
    }
}

fn traffic_snapshot(counters: &Counters) -> TrafficSnapshot {
    let bytes_sent = counters.bytes_sent.load(Ordering::Relaxed);
    let bytes_received = counters.bytes_received.load(Ordering::Relaxed);
    TrafficSnapshot {
        bytes_sent,
        bytes_received,
        total_bytes: bytes_sent.saturating_add(bytes_received),
    }
}

/// Periodically publishes a runtime status snapshot to an atomic JSON file.
pub struct StatusReporter {
    path: PathBuf,
    runtime: RuntimeStatus,
    pid: u32,
    started_at_unix_ms: u64,
    preserve_on_drop: bool,
    task: JoinHandle<()>,
}

impl StatusReporter {
    pub async fn start(runtime: RuntimeStatus) -> Result<Self> {
        let mut last_error = None;
        for path in publisher_paths(runtime.mode()) {
            match Self::start_at(runtime.clone(), path.clone()).await {
                Ok(reporter) => return Ok(reporter),
                Err(error) => {
                    last_error = Some(anyhow!(
                        "failed to publish status at {}: {:#}",
                        path.display(),
                        error
                    ));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("no status path is available")))
    }

    pub async fn start_at(runtime: RuntimeStatus, path: PathBuf) -> Result<Self> {
        write_snapshot(&path, &runtime.snapshot()).await?;

        let task_path = path.clone();
        let task_runtime = runtime.clone();
        let task = tokio::spawn(async move {
            let mut ticker = interval(STATUS_UPDATE_INTERVAL);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(error) = write_snapshot(&task_path, &task_runtime.snapshot()).await {
                    warn!(
                        "failed to update runtime status at {}: {:#}",
                        task_path.display(),
                        error
                    );
                }
            }
        });

        Ok(Self {
            path,
            pid: runtime.inner.pid,
            started_at_unix_ms: runtime.inner.started_at_unix_ms,
            runtime,
            preserve_on_drop: false,
            task,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn shutdown(&mut self) {
        self.preserve_on_drop = true;
        self.task.abort();
        self.runtime.mark_offline();
        let _ = write_snapshot(&self.path, &self.runtime.snapshot()).await;
    }
}

impl Drop for StatusReporter {
    fn drop(&mut self) {
        self.task.abort();
        if self.preserve_on_drop {
            return;
        }

        let belongs_to_this_process = fs::read(&self.path)
            .ok()
            .and_then(|data| serde_json::from_slice::<StatusSnapshot>(&data).ok())
            .map(|snapshot| {
                snapshot.pid == self.pid && snapshot.started_at_unix_ms == self.started_at_unix_ms
            })
            .unwrap_or(false);
        if belongs_to_this_process {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).ok();
        let mut sigint = signal(SignalKind::interrupt()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                match &mut sigterm {
                    Some(s) => {
                        s.recv().await;
                    }
                    None => std::future::pending().await,
                }
            } => {}
            _ = async {
                match &mut sigint {
                    Some(s) => {
                        s.recv().await;
                    }
                    None => std::future::pending().await,
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn write_snapshot(path: &Path, snapshot: &StatusSnapshot) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("failed to create status directory {}", parent.display()))?;

    let data = serde_json::to_vec(snapshot).context("failed to serialize runtime status")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("status.json");
    let temporary_path = parent.join(format!(".{}.{}.tmp", file_name, std::process::id()));
    tokio::fs::write(&temporary_path, data)
        .await
        .with_context(|| {
            format!(
                "failed to write temporary status file {}",
                temporary_path.display()
            )
        })?;
    tokio::fs::rename(&temporary_path, path)
        .await
        .with_context(|| format!("failed to replace status file {}", path.display()))
}

pub fn load_statuses(
    mode: Option<RunMode>,
    explicit_path: Option<&Path>,
) -> Result<Vec<StatusSnapshot>> {
    if let Some(path) = explicit_path {
        return Ok(vec![load_status_file(path)?]);
    }

    let modes: Vec<RunMode> = match mode {
        Some(mode) => vec![mode],
        None => vec![RunMode::Client, RunMode::Server],
    };
    let mut snapshots = Vec::new();
    let mut searched_paths = Vec::new();
    let mut last_error = None;

    for mode in modes {
        let mut candidates = Vec::new();
        for path in reader_paths(mode) {
            if candidates.iter().all(|candidate| candidate != &path) {
                candidates.push(path);
            }
        }
        searched_paths.extend(candidates.iter().cloned());

        let mut newest: Option<StatusSnapshot> = None;
        for path in candidates {
            if !path.exists() {
                continue;
            }
            match load_status_file(&path) {
                Ok(snapshot)
                    if newest
                        .as_ref()
                        .map(|current| snapshot.updated_at_unix_ms > current.updated_at_unix_ms)
                        .unwrap_or(true) =>
                {
                    newest = Some(snapshot);
                }
                Ok(_) => {}
                Err(error) => last_error = Some(error),
            }
        }
        if let Some(snapshot) = newest {
            snapshots.push(snapshot);
        }
    }

    if snapshots.is_empty() {
        if let Some(error) = last_error {
            return Err(error);
        }
        let paths = searched_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(anyhow!(
            "rrp is not running (no status file found; searched: {})",
            paths
        ));
    }

    Ok(snapshots)
}

pub fn load_status_file(path: &Path) -> Result<StatusSnapshot> {
    let data =
        fs::read(path).with_context(|| format!("failed to read status file {}", path.display()))?;
    let mut snapshot: StatusSnapshot = serde_json::from_slice(&data)
        .with_context(|| format!("failed to parse status file {}", path.display()))?;
    refresh_snapshot(&mut snapshot);
    Ok(snapshot)
}

fn refresh_snapshot(snapshot: &mut StatusSnapshot) {
    let now_ms = now_unix_ms();
    snapshot.running = snapshot.running
        && process_is_alive(snapshot.pid)
        && now_ms.saturating_sub(snapshot.updated_at_unix_ms)
            <= STATUS_STALE_AFTER.as_millis() as u64;
    let runtime_reference_ms = if snapshot.running {
        now_ms
    } else {
        snapshot.updated_at_unix_ms
    };
    snapshot.uptime_secs = elapsed_secs(snapshot.started_at_unix_ms, runtime_reference_ms);

    for connection in &mut snapshot.connections {
        if snapshot.running {
            connection.connected_for_secs = connection
                .connected_at_unix_ms
                .map(|started| elapsed_secs(started, runtime_reference_ms));
        } else {
            connection.state = "disconnected".to_string();
            connection.connected_at_unix_ms = None;
            connection.connected_for_secs = None;
        }
        connection.last_heartbeat_age_secs = connection
            .last_heartbeat_unix_ms
            .map(|last| elapsed_secs(last, now_ms));
    }
}

pub fn render_human(snapshots: &[StatusSnapshot]) -> String {
    let mut output = String::new();
    for (index, snapshot) in snapshots.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        if snapshot.running {
            output.push_str(&format!(
                "RRP {} — RUNNING (PID {})\n",
                snapshot.mode.to_uppercase(),
                snapshot.pid
            ));
        } else {
            output.push_str(&format!(
                "RRP {} — STALE/OFFLINE\n",
                snapshot.mode.to_uppercase()
            ));
        }
        output.push_str(&format!(
            "  Uptime: {}\n",
            format_duration(snapshot.uptime_secs)
        ));
        if let Some(listen_addr) = &snapshot.listen_addr {
            output.push_str(&format!("  Listen address: {}\n", listen_addr));
        }
        output.push_str(&format!("  eBPF: {}\n", snapshot.ebpf_status));
        output.push_str(&format!(
            "  Traffic: sent {}, received {}, total {}\n",
            format_bytes(snapshot.traffic.bytes_sent),
            format_bytes(snapshot.traffic.bytes_received),
            format_bytes(snapshot.traffic.total_bytes)
        ));

        if snapshot.connections.is_empty() {
            output.push_str("  Connections: none\n");
            continue;
        }

        output.push_str(&format!(
            "  Connections ({}):\n",
            snapshot.connections.len()
        ));
        for connection in &snapshot.connections {
            output.push_str(&format!(
                "    - {} [{}]\n",
                connection.name, connection.state
            ));
            let proxy_type = if connection.proxy_type.is_empty() {
                "tcp"
            } else {
                &connection.proxy_type
            };
            let server_addr = if connection.server_addr.is_empty() {
                &connection.address
            } else {
                &connection.server_addr
            };
            let target_addr = if connection.target_addr.is_empty() {
                "-"
            } else {
                &connection.target_addr
            };
            output.push_str(&format!(
                "      {} {} -> {}\n",
                proxy_type, server_addr, target_addr
            ));
            output.push_str(&format!(
                "      Connected for: {}\n",
                connection
                    .connected_for_secs
                    .map(format_duration)
                    .unwrap_or_else(|| "-".to_string())
            ));
            output.push_str(&format!(
                "      Traffic: sent {}, received {}\n",
                format_bytes(connection.traffic.bytes_sent),
                format_bytes(connection.traffic.bytes_received)
            ));
            let heartbeat = match connection.last_heartbeat_age_secs {
                Some(age) => match connection.last_heartbeat_rtt_ms {
                    Some(rtt) => format!("{} ago (RTT {} ms)", format_duration(age), rtt),
                    None => format!("{} ago", format_duration(age)),
                },
                None => "never".to_string(),
            };
            output.push_str(&format!("      Last heartbeat: {}\n", heartbeat));
            if let Some(error) = &connection.last_error {
                output.push_str(&format!("      Last error: {}\n", error));
            }
        }
    }
    output.trim_end().to_string()
}

pub fn render_json(snapshots: &[StatusSnapshot]) -> Result<String> {
    if snapshots.len() == 1 {
        serde_json::to_string_pretty(&snapshots[0]).context("failed to render status JSON")
    } else {
        serde_json::to_string_pretty(snapshots).context("failed to render status JSON")
    }
}

fn publisher_paths(mode: RunMode) -> Vec<PathBuf> {
    if let Some(directory) = std::env::var_os("RRP_STATUS_DIR") {
        return vec![PathBuf::from(directory).join(status_file_name(mode))];
    }
    vec![
        system_status_dir().join(status_file_name(mode)),
        fallback_status_dir().join(status_file_name(mode)),
    ]
}

fn reader_paths(mode: RunMode) -> Vec<PathBuf> {
    publisher_paths(mode)
}

fn status_file_name(mode: RunMode) -> &'static str {
    match mode {
        RunMode::Client => "client.json",
        RunMode::Server => "server.json",
    }
}

fn system_status_dir() -> PathBuf {
    if cfg!(target_os = "linux") {
        PathBuf::from("/run/rrp")
    } else {
        PathBuf::from("/var/run/rrp")
    }
}

fn fallback_status_dir() -> PathBuf {
    #[cfg(unix)]
    let user_id = unsafe { libc::geteuid() };
    #[cfg(not(unix))]
    let user_id = std::process::id();

    std::env::temp_dir().join(format!("rrp-{}", user_id))
}

fn process_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn elapsed_secs(start_ms: u64, end_ms: u64) -> u64 {
    end_ms.saturating_sub(start_ms) / 1_000
}

fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

fn format_duration(total_secs: u64) -> String {
    let days = total_secs / 86_400;
    let hours = (total_secs % 86_400) / 3_600;
    let minutes = (total_secs % 3_600) / 60;
    let seconds = total_secs % 60;

    if days > 0 {
        format!("{}d {:02}h {:02}m {:02}s", days, hours, minutes, seconds)
    } else if hours > 0 {
        format!("{}h {:02}m {:02}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {:02}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{} B", bytes);
    }

    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{:.2} {}", value, UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_snapshot_tracks_connection_metrics() {
        let runtime = RuntimeStatus::new(RunMode::Client, "disabled", None);
        let connection = runtime.endpoint("server-a", "server-a", "127.0.0.1:3700");
        connection.mark_connected();
        connection.record_sent(1_024);
        connection.record_received(2_048);
        connection.record_heartbeat(Some(7));

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.traffic.bytes_sent, 1_024);
        assert_eq!(snapshot.traffic.bytes_received, 2_048);
        assert_eq!(snapshot.connections[0].state, "connected");
        assert_eq!(snapshot.connections[0].last_heartbeat_rtt_ms, Some(7));
    }

    #[tokio::test]
    async fn reporter_writes_and_removes_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.json");
        let runtime = RuntimeStatus::new(RunMode::Client, "active", None);
        let reporter = StatusReporter::start_at(runtime, path.clone())
            .await
            .unwrap();

        let snapshot = load_status_file(&path).unwrap();
        assert_eq!(snapshot.mode, "client");
        assert!(snapshot.running);
        drop(reporter);
        assert!(!path.exists());
    }

    #[test]
    fn human_output_contains_requested_status_fields() {
        let runtime = RuntimeStatus::new(
            RunMode::Server,
            "disabled by configuration",
            Some("[::]:3700".into()),
        );
        let connection = runtime.server_proxy_session(
            "127.0.0.1:12345",
            "example_tcp",
            "tcp",
            "[::]:18080",
            "127.0.0.1:8080",
        );
        connection.mark_connected();
        connection.record_heartbeat(None);

        let output = render_human(&[runtime.snapshot()]);
        assert!(output.contains("RRP SERVER — RUNNING (PID "));
        assert!(output.contains("    - example_tcp [connected]\n      tcp [::]:18080 -> 127.0.0.1:8080\n"));
        assert!(output.contains("Connected for:"));
        assert!(output.contains("Traffic:"));
        assert!(output.contains("Last heartbeat:"));
        assert!(!output.contains("Active:"));
        assert!(!output.contains("Last update:"));
        assert!(!output.contains("Proxies:"));
    }

    #[test]
    fn offline_snapshot_resets_connections_and_hides_pid() {
        let runtime = RuntimeStatus::new(RunMode::Client, "disabled by configuration", None);
        let connection = runtime.proxy_endpoint(
            "example_tcp",
            "example_tcp",
            "tcp",
            "127.0.0.1:18080",
            "127.0.0.1:8080",
        );
        connection.mark_connected();

        let mut snapshot = runtime.snapshot();
        snapshot.running = false;
        refresh_snapshot(&mut snapshot);

        assert!(!snapshot.running);
        assert_eq!(snapshot.connections[0].state, "disconnected");
        assert!(snapshot.connections[0].connected_at_unix_ms.is_none());
        assert!(snapshot.connections[0].connected_for_secs.is_none());

        let output = render_human(&[snapshot]);
        assert!(output.starts_with("RRP CLIENT — STALE/OFFLINE\n"));
        assert!(!output.contains("PID"));
        assert!(output.contains("    - example_tcp [disconnected]\n"));
        assert!(output.contains("      Connected for: -\n"));
    }
}
