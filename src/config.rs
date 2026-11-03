use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::{generate_keypair, AuthorizedPublicKey, ClientKeyPair};

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
        let port = self
            .local_port
            .ok_or_else(|| anyhow::anyhow!("proxy '{}' must specify either `local_addr` or `local_port`", self.name))?;
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
        let _ = self.resolved_local_addr()?;
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
    #[serde(default = "default_true")]
    pub enable_ebpf: bool,
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
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
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let content = toml::to_string_pretty(self).context("failed to serialize ServerConfig")?;
        fs::write(path, content)
            .with_context(|| format!("failed to write server config to {}", path.display()))
    }

    pub fn validate(&self) -> Result<()> {
        for key in &self.authorized_keys {
            AuthorizedPublicKey::from_base64(key)?;
        }
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
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let content = toml::to_string_pretty(self).context("failed to serialize ClientConfig")?;
        fs::write(path, content)
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
            if ep.private_key.trim().is_empty() {
                bail!(
                    "client `private_key` is missing for server '{}'; run `rrp install` first",
                    ep.display_name()
                );
            }
            ClientKeyPair::from_base64(&ep.private_key).with_context(|| {
                format!("invalid client `private_key` for server '{}'", ep.display_name())
            })?;
        }

        Ok(endpoints)
    }

    pub fn validate(&self) -> Result<()> {
        let _ = self.resolve_servers()?;
        Ok(())
    }
}

/// Generate a new mlkem768x25519 keypair and write the private key to the client config at `path`.
/// Returns `(private_key_b64, public_key_b64)`.
pub fn install_client_key(path: &Path) -> Result<(String, String)> {
    let (priv_b64, pub_b64) = generate_keypair();
    let mut cfg = if path.exists() {
        let content = fs::read_to_string(path)?;
        toml::from_str::<ClientConfig>(&content).unwrap_or_default()
    } else {
        ClientConfig::default()
    };
    if cfg.server_addr.trim().is_empty() && cfg.server_addrs.is_empty() && cfg.servers.is_empty() {
        cfg.server_addr = default_client_server_addr();
    }
    cfg.private_key = priv_b64.clone();
    cfg.save(path)?;
    Ok((priv_b64, pub_b64))
}

/// Approve a client public key and persist it into the server config at `path`.
/// Returns `true` if newly added, `false` if already present.
pub fn approve_client_key(path: &Path, pubkey_b64: &str) -> Result<bool> {
    let mut cfg = if path.exists() {
        let content = fs::read_to_string(path)?;
        toml::from_str::<ServerConfig>(&content).unwrap_or_default()
    } else {
        ServerConfig::default()
    };
    let added = cfg.approve_key(pubkey_b64)?;
    cfg.save(path)?;
    Ok(added)
}
