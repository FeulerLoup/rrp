use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::{generate_keypair, AuthorizedPublicKey, ClientKeyPair};
use crate::net_utils::split_host_port;
use crate::tunnel::ipam::{Cidr4, Cidr6};

/// Private keys live in the client config, so it must never be world-readable.
#[cfg(unix)]
const CLIENT_CONFIG_MODE: u32 = 0o600;

/// Write `content` to `path` atomically (temp file + rename) so a crash mid-write never leaves a
/// truncated config behind, optionally forcing a Unix permission mode on the result.
fn write_file_atomic(path: &Path, content: &str, #[allow(unused)] mode: Option<u32>) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create config directory {}", parent.display()))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.toml");
    let temporary_path = parent.join(format!(".{}.{}.tmp", file_name, std::process::id()));

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let result = (|| -> Result<()> {
        let mut file = options
            .open(&temporary_path)
            .with_context(|| format!("failed to create {}", temporary_path.display()))?;
        file.write_all(content.as_bytes())
            .with_context(|| format!("failed to write {}", temporary_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to flush {}", temporary_path.display()))?;
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            // The mode on open() is masked by umask; enforce the exact mode afterwards.
            fs::set_permissions(&temporary_path, fs::Permissions::from_mode(mode)).with_context(
                || format!("failed to set permissions on {}", temporary_path.display()),
            )?;
        }
        fs::rename(&temporary_path, path)
            .with_context(|| format!("failed to replace {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

/// Parse a bind/remote IP as written in configs (`::`, `0.0.0.0`, `[::1]`, `127.0.0.1`).
fn validate_ip_literal(value: &str, what: &str) -> Result<IpAddr> {
    let trimmed = value.trim();
    let bare = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed);
    bare.parse::<IpAddr>()
        .with_context(|| format!("{} '{}' is not a valid IP address", what, value))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    Tcp,
    Udp,
    All,
}

impl ProxyType {
    pub fn has_tcp(self) -> bool {
        matches!(self, ProxyType::Tcp | ProxyType::All)
    }

    pub fn has_udp(self) -> bool {
        matches!(self, ProxyType::Udp | ProxyType::All)
    }
}

impl std::fmt::Display for ProxyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyType::Tcp => write!(f, "tcp"),
            ProxyType::Udp => write!(f, "udp"),
            ProxyType::All => write!(f, "all"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: ProxyType,
    /// Full local address (e.g. "127.0.0.1:8080" or "[::1]:8080").
    /// Alternatively, `local_ip` + `local_port` can be used (frp style).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>,
    pub remote_port: u16,
    /// Optional bind IP on server for this proxy (e.g. "::", "0.0.0.0", "127.0.0.1", "::1").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_bind_ip: Option<String>,
    /// Optional target server address or server name for this proxy (supports comma-separated list).
    #[serde(default, alias = "server", skip_serializing_if = "Option::is_none")]
    pub server_addr: Option<String>,
    /// Optional list of target server addresses or server names for this proxy.
    #[serde(default, alias = "servers", skip_serializing_if = "Vec::is_empty")]
    pub server_addrs: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            proxy_type: ProxyType::Tcp,
            local_addr: None,
            local_ip: None,
            local_port: None,
            remote_port: 0,
            remote_bind_ip: None,
            server_addr: None,
            server_addrs: Vec::new(),
        }
    }
}

impl ProxyConfig {
    pub fn resolved_local_addr(&self) -> Result<String> {
        if let Some(addr) = &self.local_addr {
            if !addr.trim().is_empty() {
                return Ok(addr.trim().to_string());
            }
        }
        let ip = self.local_ip.as_deref().unwrap_or("127.0.0.1").trim();
        let port = self.local_port.ok_or_else(|| {
            anyhow::anyhow!(
                "proxy '{}' must specify either `local_addr` or `local_port`",
                self.name
            )
        })?;
        if ip.contains(':') && !ip.starts_with('[') {
            Ok(format!("[{}]:{}", ip, port))
        } else {
            Ok(format!("{}:{}", ip, port))
        }
    }

    /// Return the list of explicit target server addresses/names configured on this proxy.
    pub fn target_servers(&self) -> Vec<String> {
        let mut targets = Vec::new();
        if let Some(addr) = &self.server_addr {
            for part in addr.split(',') {
                let trimmed = part.trim();
                if !trimmed.is_empty() && !targets.iter().any(|t| t == trimmed) {
                    targets.push(trimmed.to_string());
                }
            }
        }
        for entry in &self.server_addrs {
            for part in entry.split(',') {
                let trimmed = part.trim();
                if !trimmed.is_empty() && !targets.iter().any(|t| t == trimmed) {
                    targets.push(trimmed.to_string());
                }
            }
        }
        targets
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("proxy name cannot be empty");
        }
        if self.remote_port == 0 {
            bail!("proxy '{}' remote_port cannot be 0", self.name);
        }
        let local_addr = self.resolved_local_addr()?;
        split_host_port(&local_addr).with_context(|| {
            format!(
                "proxy '{}' local address '{}' must be in `host:port` or `[ipv6]:port` form",
                self.name, local_addr
            )
        })?;
        if let Some(bind_ip) = &self.remote_bind_ip {
            validate_ip_literal(bind_ip, &format!("proxy '{}' remote_bind_ip", self.name))?;
        }
        Ok(())
    }

    /// Key identifying the server-side socket this proxy occupies, used to detect two proxies on
    /// the same server that would fight over one `remote_bind_ip:remote_port`.
    fn remote_socket_key(&self) -> (String, u16) {
        let bind_ip = self
            .remote_bind_ip
            .as_deref()
            .map(|ip| ip.trim().trim_matches(|c| c == '[' || c == ']').to_string())
            .unwrap_or_default();
        (bind_ip, self.remote_port)
    }
}

/// Reject proxies on one server whose TCP or UDP side would bind the same remote socket; the
/// server would otherwise refuse the whole registration at runtime with a less helpful error.
fn check_remote_port_conflicts(endpoint: &ResolvedServerConfig) -> Result<()> {
    let mut tcp_owners: HashMap<(String, u16), &str> = HashMap::new();
    let mut udp_owners: HashMap<(String, u16), &str> = HashMap::new();
    for proxy in &endpoint.proxies {
        let key = proxy.remote_socket_key();
        if proxy.proxy_type.has_tcp() {
            if let Some(other) = tcp_owners.insert(key.clone(), proxy.name.as_str()) {
                bail!(
                    "proxies '{}' and '{}' both bind TCP remote_port {} on server '{}'",
                    other,
                    proxy.name,
                    proxy.remote_port,
                    endpoint.display_name()
                );
            }
        }
        if proxy.proxy_type.has_udp() {
            if let Some(other) = udp_owners.insert(key, proxy.name.as_str()) {
                bail!(
                    "proxies '{}' and '{}' both bind UDP remote_port {} on server '{}'",
                    other,
                    proxy.name,
                    proxy.remote_port,
                    endpoint.display_name()
                );
            }
        }
    }
    Ok(())
}

/// Server-side settings for the kernel tunnel data plane (TC eBPF redirect + WireGuard).
/// Only used when `enable_ebpf = true` on a Linux server with CAP_NET_ADMIN/CAP_BPF.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TunnelServerConfig {
    /// Name of the WireGuard interface rrp creates and owns.
    pub interface: String,
    /// UDP port the kernel WireGuard endpoint listens on.
    pub listen_port: u16,
    /// Interface that receives visitor traffic; auto-detected from the default route if unset.
    pub public_interface: Option<String>,
    /// Public IPv4/IPv6 used as the source of replies; auto-detected from the interface if unset.
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    /// Address pools for tunnel endpoints; the first host is the server, the rest are clients.
    pub ipv4_cidr: String,
    pub ipv6_cidr: String,
    /// MTU of the WireGuard interface; the TC program clamps visitor MSS to fit.
    pub mtu: u16,
}

impl Default for TunnelServerConfig {
    fn default() -> Self {
        Self {
            interface: "rrp-wg0".to_string(),
            listen_port: 3701,
            public_interface: None,
            public_ipv4: None,
            public_ipv6: None,
            ipv4_cidr: "10.199.0.0/16".to_string(),
            ipv6_cidr: "fd00:7272::/64".to_string(),
            mtu: 1420,
        }
    }
}

impl TunnelServerConfig {
    pub fn validate(&self) -> Result<()> {
        let name = self.interface.trim();
        if name.is_empty() || name.len() > 15 || name.contains(['/', ' ']) {
            bail!(
                "tunnel.interface '{}' is not a valid Linux interface name",
                self.interface
            );
        }
        if self.listen_port == 0 {
            bail!("tunnel.listen_port cannot be 0");
        }
        if !(1280..=9000).contains(&self.mtu) {
            bail!("tunnel.mtu {} must be between 1280 and 9000", self.mtu);
        }
        let v4 = Cidr4::parse(&self.ipv4_cidr)
            .with_context(|| format!("tunnel.ipv4_cidr '{}' is invalid", self.ipv4_cidr))?;
        if v4.host_capacity() < 2 {
            bail!(
                "tunnel.ipv4_cidr '{}' has no room for clients",
                self.ipv4_cidr
            );
        }
        Cidr6::parse(&self.ipv6_cidr)
            .with_context(|| format!("tunnel.ipv6_cidr '{}' is invalid", self.ipv6_cidr))?;
        if let Some(ip) = &self.public_ipv4 {
            let parsed = validate_ip_literal(ip, "tunnel.public_ipv4")?;
            if !parsed.is_ipv4() {
                bail!("tunnel.public_ipv4 '{}' is not an IPv4 address", ip);
            }
        }
        if let Some(ip) = &self.public_ipv6 {
            let parsed = validate_ip_literal(ip, "tunnel.public_ipv6")?;
            if !parsed.is_ipv6() {
                bail!("tunnel.public_ipv6 '{}' is not an IPv6 address", ip);
            }
        }
        if let Some(iface) = &self.public_interface {
            if iface.trim().is_empty() || iface.len() > 15 {
                bail!(
                    "tunnel.public_interface '{}' is not a valid interface name",
                    iface
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_server_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_proxy_bind_ip")]
    pub proxy_bind_ip: String,
    #[serde(default)]
    pub authorized_keys: Vec<String>,
    /// Enable the kernel tunnel data plane (TC eBPF redirect into a WireGuard interface).
    /// Falls back to the user-space relay when unavailable.
    #[serde(default = "default_true")]
    pub enable_ebpf: bool,
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    #[serde(default)]
    pub tunnel: TunnelServerConfig,
}

fn default_server_bind_addr() -> String {
    "[::]:3700".to_string()
}

fn default_proxy_bind_ip() -> String {
    "::".to_string()
}

fn default_true() -> bool {
    true
}

fn default_heartbeat_timeout_secs() -> u64 {
    60
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_server_bind_addr(),
            proxy_bind_ip: default_proxy_bind_ip(),
            authorized_keys: Vec::new(),
            enable_ebpf: true,
            heartbeat_timeout_secs: default_heartbeat_timeout_secs(),
            tunnel: TunnelServerConfig::default(),
        }
    }
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read server config from {}", path.display()))?;
        let cfg: Self = toml::from_str(&content)
            .with_context(|| format!("failed to parse server config from {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self).context("failed to serialize ServerConfig")?;
        write_file_atomic(path, &content, None)
            .with_context(|| format!("failed to write server config to {}", path.display()))
    }

    pub fn validate(&self) -> Result<()> {
        self.bind_addr
            .trim()
            .parse::<SocketAddr>()
            .with_context(|| {
                format!(
                    "server `bind_addr` '{}' is not a valid socket address",
                    self.bind_addr
                )
            })?;
        validate_ip_literal(&self.proxy_bind_ip, "server `proxy_bind_ip`")?;
        for key in &self.authorized_keys {
            AuthorizedPublicKey::from_base64(key)?;
        }
        self.tunnel.validate()?;
        Ok(())
    }

    pub fn approve_key(&mut self, pubkey_b64: &str) -> Result<bool> {
        let parsed = AuthorizedPublicKey::from_base64(pubkey_b64)?;
        let normalized = parsed.to_base64();
        if self.authorized_keys.iter().any(|k| k.trim() == normalized) {
            return Ok(false);
        }
        self.authorized_keys.push(normalized);
        Ok(true)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientServerConfig {
    /// Optional alias/name for this server endpoint (can be referenced by proxies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Server address (e.g. "203.0.113.10:3700" or "[2001:db8::1]:3700").
    #[serde(default, alias = "addr")]
    pub server_addr: String,
    /// Optional server-specific client private key (falls back to top-level `private_key` if omitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// Optional server-specific heartbeat interval in seconds (falls back to top-level `heartbeat_interval_secs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_interval_secs: Option<u64>,
    /// Optional proxies registered specifically on this server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<ProxyConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedServerConfig {
    pub name: Option<String>,
    pub server_addr: String,
    pub private_key: String,
    pub heartbeat_interval_secs: u64,
    pub proxies: Vec<ProxyConfig>,
}

impl ResolvedServerConfig {
    pub fn display_name(&self) -> String {
        match &self.name {
            Some(name) if !name.trim().is_empty() && name.trim() != self.server_addr => {
                format!("{} ({})", name.trim(), self.server_addr)
            }
            _ => self.server_addr.clone(),
        }
    }
}

fn add_proxy_to_endpoint(endpoint: &mut ResolvedServerConfig, proxy: &ProxyConfig) -> Result<()> {
    if let Some(existing) = endpoint.proxies.iter().find(|p| p.name == proxy.name) {
        let same_spec = existing.proxy_type == proxy.proxy_type
            && existing.resolved_local_addr().ok() == proxy.resolved_local_addr().ok()
            && existing.remote_port == proxy.remote_port
            && existing.remote_bind_ip == proxy.remote_bind_ip;
        if same_spec {
            return Ok(());
        }
        bail!(
            "duplicate proxy name '{}' with conflicting configuration on server '{}'",
            proxy.name,
            endpoint.display_name()
        );
    }
    endpoint.proxies.push(proxy.clone());
    Ok(())
}

/// Which data plane the client asks for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelMode {
    /// Use the kernel tunnel when this host supports it and the server offers it, else relay.
    #[default]
    Auto,
    /// Never use the tunnel; always relay through encrypted work connections.
    Relay,
    /// Require the tunnel; fail instead of silently relaying.
    Tunnel,
}

impl TunnelMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TunnelMode::Auto => "auto",
            TunnelMode::Relay => "relay",
            TunnelMode::Tunnel => "tunnel",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Primary server address (supports single address or comma-separated addresses).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_addr: String,
    /// Multiple server addresses to connect and register proxies to simultaneously.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_addrs: Vec<String>,
    /// Detailed per-server configurations (`[[servers]]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<ClientServerConfig>,
    #[serde(default)]
    pub private_key: String,
    #[serde(default = "default_true")]
    pub enable_ebpf: bool,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    /// `auto` (default), `relay`, or `tunnel`. The tunnel needs Linux with CAP_NET_ADMIN and
    /// a server running with `enable_ebpf = true`.
    #[serde(default)]
    pub tunnel_mode: TunnelMode,
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,
}

fn default_client_server_addr() -> String {
    "127.0.0.1:3700".to_string()
}

fn default_heartbeat_interval_secs() -> u64 {
    20
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: default_client_server_addr(),
            server_addrs: Vec::new(),
            servers: Vec::new(),
            private_key: String::new(),
            enable_ebpf: true,
            heartbeat_interval_secs: default_heartbeat_interval_secs(),
            tunnel_mode: TunnelMode::Auto,
            proxies: vec![ProxyConfig {
                name: "example_tcp".to_string(),
                proxy_type: ProxyType::Tcp,
                local_addr: Some("127.0.0.1:8080".to_string()),
                local_ip: None,
                local_port: None,
                remote_port: 18080,
                remote_bind_ip: None,
                server_addr: None,
                server_addrs: Vec::new(),
            }],
        }
    }
}

impl ClientConfig {
    pub fn load_unvalidated(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read client config from {}", path.display()))?;
        let cfg: Self = toml::from_str(&content)
            .with_context(|| format!("failed to parse client config from {}", path.display()))?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let cfg = Self::load_unvalidated(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self).context("failed to serialize ClientConfig")?;
        #[cfg(unix)]
        let mode = Some(CLIENT_CONFIG_MODE);
        #[cfg(not(unix))]
        let mode = None;
        write_file_atomic(path, &content, mode)
            .with_context(|| format!("failed to write client config to {}", path.display()))
    }

    /// Resolve all configured server endpoints and their associated proxies.
    pub fn resolve_servers(&self) -> Result<Vec<ResolvedServerConfig>> {
        let mut endpoints: Vec<ResolvedServerConfig> = Vec::new();

        // 1. Process explicit `[[servers]]` blocks
        for srv in &self.servers {
            let raw_addr = srv.server_addr.trim();
            if raw_addr.is_empty() {
                bail!("server entry in `[[servers]]` must specify a non-empty `server_addr`");
            }
            let clean_name = srv
                .name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string);

            if let Some(ref name) = clean_name {
                if endpoints
                    .iter()
                    .any(|e| e.name.as_deref() == Some(name.as_str()) && e.server_addr != raw_addr)
                {
                    bail!("duplicate server name '{}' in `[[servers]]`", name);
                }
            }

            let priv_key = srv
                .private_key
                .as_deref()
                .map(str::trim)
                .filter(|k| !k.is_empty())
                .unwrap_or_else(|| self.private_key.trim())
                .to_string();
            let hb_secs = srv
                .heartbeat_interval_secs
                .unwrap_or(self.heartbeat_interval_secs);

            for p in &srv.proxies {
                p.validate()?;
            }

            for part in raw_addr.split(',') {
                let addr = part.trim();
                if addr.is_empty() {
                    continue;
                }
                if let Some(existing) = endpoints.iter_mut().find(|e| e.server_addr == addr) {
                    if existing.name.is_none() && clean_name.is_some() {
                        existing.name = clean_name.clone();
                    }
                    if srv.private_key.is_some() {
                        existing.private_key = priv_key.clone();
                    }
                    if srv.heartbeat_interval_secs.is_some() {
                        existing.heartbeat_interval_secs = hb_secs;
                    }
                    for p in &srv.proxies {
                        add_proxy_to_endpoint(existing, p)?;
                    }
                } else {
                    let mut ep = ResolvedServerConfig {
                        name: clean_name.clone(),
                        server_addr: addr.to_string(),
                        private_key: priv_key.clone(),
                        heartbeat_interval_secs: hb_secs,
                        proxies: Vec::with_capacity(srv.proxies.len()),
                    };
                    for p in &srv.proxies {
                        add_proxy_to_endpoint(&mut ep, p)?;
                    }
                    endpoints.push(ep);
                }
            }
        }

        // 2. Process top-level `server_addr` and `server_addrs`
        let has_explicit_multi = !self.server_addrs.is_empty() || !self.servers.is_empty();
        let trimmed_primary = self.server_addr.trim();
        if !trimmed_primary.is_empty()
            && !(has_explicit_multi && trimmed_primary == default_client_server_addr())
        {
            for part in trimmed_primary.split(',') {
                let addr = part.trim();
                if !addr.is_empty() && !endpoints.iter().any(|e| e.server_addr == addr) {
                    endpoints.push(ResolvedServerConfig {
                        name: None,
                        server_addr: addr.to_string(),
                        private_key: self.private_key.trim().to_string(),
                        heartbeat_interval_secs: self.heartbeat_interval_secs,
                        proxies: Vec::new(),
                    });
                }
            }
        }

        for entry in &self.server_addrs {
            for part in entry.split(',') {
                let addr = part.trim();
                if !addr.is_empty() && !endpoints.iter().any(|e| e.server_addr == addr) {
                    endpoints.push(ResolvedServerConfig {
                        name: None,
                        server_addr: addr.to_string(),
                        private_key: self.private_key.trim().to_string(),
                        heartbeat_interval_secs: self.heartbeat_interval_secs,
                        proxies: Vec::new(),
                    });
                }
            }
        }

        let base_endpoint_count = endpoints.len();
        let server_defined_names: Vec<std::collections::HashSet<String>> = endpoints
            .iter()
            .map(|ep| ep.proxies.iter().map(|p| p.name.clone()).collect())
            .collect();

        // 3. Validate and assign top-level `proxies`
        for proxy in &self.proxies {
            proxy.validate()?;
            let targets = proxy.target_servers();
            if targets.is_empty() {
                for (idx, ep) in endpoints.iter_mut().take(base_endpoint_count).enumerate() {
                    if server_defined_names[idx].contains(&proxy.name) {
                        continue;
                    }
                    add_proxy_to_endpoint(ep, proxy)?;
                }
            } else {
                for target in targets {
                    let matched_indices: Vec<usize> = endpoints
                        .iter()
                        .enumerate()
                        .filter(|(_, e)| {
                            e.server_addr == target || e.name.as_deref() == Some(target.as_str())
                        })
                        .map(|(i, _)| i)
                        .collect();

                    if matched_indices.is_empty() {
                        let mut ep = ResolvedServerConfig {
                            name: None,
                            server_addr: target,
                            private_key: self.private_key.trim().to_string(),
                            heartbeat_interval_secs: self.heartbeat_interval_secs,
                            proxies: Vec::new(),
                        };
                        add_proxy_to_endpoint(&mut ep, proxy)?;
                        endpoints.push(ep);
                    } else {
                        for idx in matched_indices {
                            add_proxy_to_endpoint(&mut endpoints[idx], proxy)?;
                        }
                    }
                }
            }
        }

        // If no top-level server was configured and servers came solely from targeted proxies,
        // attach any untargeted global proxies to all discovered endpoints.
        if base_endpoint_count == 0 && !endpoints.is_empty() {
            for proxy in &self.proxies {
                if proxy.target_servers().is_empty() {
                    for ep in &mut endpoints {
                        add_proxy_to_endpoint(ep, proxy)?;
                    }
                }
            }
        }

        if endpoints.is_empty() {
            bail!(
                "client configuration must specify at least one server (via `server_addr`, `server_addrs`, or `[[servers]]`)"
            );
        }

        for ep in &endpoints {
            check_remote_port_conflicts(ep)?;
            if ep.private_key.trim().is_empty() {
                bail!(
                    "client `private_key` is missing for server '{}'; run `rrp install` first",
                    ep.display_name()
                );
            }
            ClientKeyPair::from_base64(&ep.private_key).with_context(|| {
                format!(
                    "invalid client `private_key` for server '{}'",
                    ep.display_name()
                )
            })?;
        }

        Ok(endpoints)
    }

    pub fn validate(&self) -> Result<()> {
        let _ = self.resolve_servers()?;
        if self.tunnel_mode == TunnelMode::Tunnel && !cfg!(target_os = "linux") {
            bail!("tunnel_mode = \"tunnel\" requires a Linux client (use \"auto\" or \"relay\")");
        }
        Ok(())
    }
}

/// Outcome of `install_client_key_with`: whether a new keypair was generated or an existing one
/// was kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledClientKey {
    pub private_key: String,
    pub public_key: String,
    pub generated: bool,
}

/// Ensure the client config at `path` holds a mlkem768x25519 private key, generating one if the
/// file does not exist or has no usable key. An existing valid key is preserved unless
/// `regenerate` is set: re-running `rrp install` to add autostart must not silently rotate the key
/// and invalidate the public key already approved on the server.
///
/// A config file that exists but cannot be parsed is an error, never silently replaced.
pub fn install_client_key_with(path: &Path, regenerate: bool) -> Result<InstalledClientKey> {
    let mut cfg = if path.exists() {
        ClientConfig::load_unvalidated(path).with_context(|| {
            format!(
                "refusing to overwrite unreadable client config {} (fix or remove it first)",
                path.display()
            )
        })?
    } else {
        ClientConfig::default()
    };
    if cfg.server_addr.trim().is_empty() && cfg.server_addrs.is_empty() && cfg.servers.is_empty() {
        cfg.server_addr = default_client_server_addr();
    }

    if !regenerate {
        if let Ok(existing) = ClientKeyPair::from_base64(&cfg.private_key) {
            let public_key = existing.public_key_base64();
            // Re-save so permissions and formatting are normalized even when nothing changed.
            cfg.save(path)?;
            return Ok(InstalledClientKey {
                private_key: cfg.private_key.trim().to_string(),
                public_key,
                generated: false,
            });
        }
    }

    let (priv_b64, pub_b64) = generate_keypair();
    cfg.private_key = priv_b64.clone();
    cfg.save(path)?;
    Ok(InstalledClientKey {
        private_key: priv_b64,
        public_key: pub_b64,
        generated: true,
    })
}

/// Ensure a mlkem768x25519 keypair exists in the client config at `path`, keeping any existing
/// valid key. Returns `(private_key_b64, public_key_b64)`.
pub fn install_client_key(path: &Path) -> Result<(String, String)> {
    let installed = install_client_key_with(path, false)?;
    Ok((installed.private_key, installed.public_key))
}

/// Approve a client public key and persist it into the server config at `path`.
/// Returns `true` if newly added, `false` if already present.
///
/// A config file that exists but cannot be parsed is an error: replacing it with defaults would
/// silently discard every previously approved key.
pub fn approve_client_key(path: &Path, pubkey_b64: &str) -> Result<bool> {
    let mut cfg = if path.exists() {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read server config from {}", path.display()))?;
        toml::from_str::<ServerConfig>(&content).with_context(|| {
            format!(
                "refusing to overwrite unreadable server config {} (fix or remove it first)",
                path.display()
            )
        })?
    } else {
        ServerConfig::default()
    };
    let added = cfg.approve_key(pubkey_b64)?;
    cfg.save(path)?;
    Ok(added)
}
