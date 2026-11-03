//! Stand-ins for non-Linux builds so the server and client code stay free of `cfg` noise.
//! Every operation reports that the tunnel data plane is unavailable.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};

use crate::config::TunnelServerConfig;
use crate::crypto::KeyId;
use crate::protocol::TunnelAssignment;

use super::{PortTraffic, ResolvedBinding, TunnelLease};

pub struct TunnelServer;

impl TunnelServer {
    pub async fn start(_config: &TunnelServerConfig) -> Result<Self> {
        bail!("kernel tunnel data plane is only available on Linux")
    }

    pub fn description(&self) -> String {
        String::new()
    }

    pub fn add_client(
        &self,
        _key_id: KeyId,
        _client_wg_public: [u8; 32],
        _psk: [u8; 32],
    ) -> Result<(TunnelLease, TunnelAssignment)> {
        bail!("kernel tunnel data plane is only available on Linux")
    }

    pub fn install_bindings(
        &self,
        _lease: &TunnelLease,
        _bindings: &[ResolvedBinding],
    ) -> Result<()> {
        bail!("kernel tunnel data plane is only available on Linux")
    }

    pub fn traffic(&self, _lease: &TunnelLease) -> Vec<(String, PortTraffic)> {
        Vec::new()
    }

    pub fn remove_client(&self, _lease: &TunnelLease) {}
}

pub struct TunnelClient {
    pub client_v4: Ipv4Addr,
    pub client_v6: Ipv6Addr,
}

impl TunnelClient {
    pub async fn setup(
        _interface: &str,
        _assignment: &TunnelAssignment,
        _server_ip: IpAddr,
        _private_key: [u8; 32],
        _psk: [u8; 32],
        _table_id: u32,
    ) -> Result<Self> {
        bail!("kernel tunnel data plane is only available on Linux")
    }

    pub async fn teardown(self) {}
}
