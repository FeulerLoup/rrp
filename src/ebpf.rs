use std::sync::{Arc, RwLock};

/// Describes which data plane a running process uses, for logs and `rrp status`.
///
/// The accelerated data plane is the kernel tunnel: on the server, TC eBPF programs rewrite
/// visitor packets into a WireGuard interface without any user-space socket on the proxied
/// ports; on the client, traffic arrives through the WireGuard interface and is relayed in
/// plaintext to the local service. When the tunnel is unavailable (non-Linux host, missing
/// capabilities, server without eBPF support) both sides fall back to the user-space relay
/// over per-connection encrypted work connections.
#[derive(Clone, Debug)]
pub struct EbpfAccelerator {
    inner: Arc<RwLock<State>>,
}

#[derive(Debug)]
struct State {
    enabled: bool,
    active: bool,
    status_reason: String,
}

impl EbpfAccelerator {
    /// Record the configured intent. Whether the tunnel actually comes up is only known once
    /// the server or client session has tried to bring it up; see [`Self::set_active`].
    pub fn try_init(enabled: bool) -> Self {
        let (active, status_reason) = if !enabled {
            (false, "disabled by configuration".to_string())
        } else if cfg!(target_os = "linux") {
            (
                false,
                "pending (tunnel data plane not started yet)".to_string(),
            )
        } else {
            (false, "fallback (non-Linux platform)".to_string())
        };
        Self {
            inner: Arc::new(RwLock::new(State {
                enabled,
                active,
                status_reason,
            })),
        }
    }

    pub fn enabled(&self) -> bool {
        self.inner.read().map(|s| s.enabled).unwrap_or(false)
    }

    pub fn is_active(&self) -> bool {
        self.inner.read().map(|s| s.active).unwrap_or(false)
    }

    pub fn status_reason(&self) -> String {
        self.inner
            .read()
            .map(|s| s.status_reason.clone())
            .unwrap_or_default()
    }

    pub fn set_active(&self, reason: impl Into<String>) {
        if let Ok(mut state) = self.inner.write() {
            state.active = true;
            state.status_reason = reason.into();
        }
    }

    pub fn set_fallback(&self, reason: impl Into<String>) {
        if let Ok(mut state) = self.inner.write() {
            state.active = false;
            state.status_reason = format!("fallback ({})", reason.into());
        }
    }
}
