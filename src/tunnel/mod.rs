//! Kernel tunnel data plane.
//!
//! Server: TC eBPF programs on the public interface and on a WireGuard interface rewrite
//! visitor packets to/from each client's tunnel address with a static port table, so no
//! user-space socket ever listens on a proxied port and the server never sees plaintext
//! payload in memory. Client: a WireGuard interface plus plain user-space relays bound to the
//! tunnel addresses. Encryption on the wire is WireGuard (Noise, ChaCha20-Poly1305) with a
//! post-quantum preshared key derived from the mlkem768x25519plus control handshake.
//!
//! Everything that talks to the kernel is Linux-only; the other modules are portable and
//! unit-tested everywhere.

pub mod bpf_types;
pub mod ipam;
pub mod plain_relay;

#[cfg(target_os = "linux")]
mod client_linux;
#[cfg(target_os = "linux")]
mod server_linux;

#[cfg(target_os = "linux")]
pub use client_linux::TunnelClient;
#[cfg(target_os = "linux")]
pub use server_linux::TunnelServer;

#[cfg(not(target_os = "linux"))]
mod unsupported;
#[cfg(not(target_os = "linux"))]
pub use unsupported::{TunnelClient, TunnelServer};

use crate::crypto::KeyId;

/// Identifies one client session's tunnel resources on the server. A later session from the
/// same key supersedes earlier ones, so removal is a no-op unless the generation matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelLease {
    pub key_id: KeyId,
    pub generation: u64,
}

/// One (family, protocol, public port) -> client tunnel port redirection to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBinding {
    pub proxy_name: String,
    pub family: u8,
    pub proto: u8,
    pub public_port: u16,
    pub tunnel_port: u16,
}

/// Byte counters for one public port, summed over both address families.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PortTraffic {
    /// Bytes from visitors towards the client.
    pub visitor_to_client: u64,
    /// Bytes from the client towards visitors.
    pub client_to_visitor: u64,
}

/// Human-readable capability check used for `auto` mode decisions and log messages.
pub fn host_supports_tunnel() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return Err("not running as root (CAP_NET_ADMIN and CAP_BPF are required)".into());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("kernel tunnel data plane is only available on Linux".into())
    }
}
