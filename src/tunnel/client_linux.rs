//! Client side of the tunnel data plane on Linux: a WireGuard interface peered with the
//! server plus policy routing that sends everything sourced from the tunnel addresses back
//! through the tunnel, so replies to visitors (whose real addresses are preserved) never leak
//! onto the client's default route.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use futures::TryStreamExt;
use netlink_packet_route::route::RouteScope;
use netlink_packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::{Handle, IpVersion};
use tracing::{debug, info, warn};
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

use crate::protocol::{TunnelAssignment, TUNNEL_PROTOCOL_VERSION};

const WG_KEEPALIVE_SECS: u16 = 25;

pub struct TunnelClient {
    iface: InterfaceName,
    ifindex: u32,
    handle: Handle,
    rules: Vec<RuleMessage>,
    pub client_v4: Ipv4Addr,
    pub client_v6: Ipv6Addr,
}

impl TunnelClient {
    pub async fn setup(
        interface: &str,
        assignment: &TunnelAssignment,
        server_ip: IpAddr,
        private_key: [u8; 32],
        psk: [u8; 32],
        table_id: u32,
    ) -> Result<Self> {
        if assignment.version != TUNNEL_PROTOCOL_VERSION {
            bail!(
                "server offers tunnel protocol version {}, this client speaks {}",
                assignment.version,
                TUNNEL_PROTOCOL_VERSION
            );
        }
        let client_v4: Ipv4Addr = assignment
            .client_ipv4
            .parse()
            .context("invalid client_ipv4 in tunnel assignment")?;
        let client_v6: Ipv6Addr = assignment
            .client_ipv6
            .parse()
            .context("invalid client_ipv6 in tunnel assignment")?;
        let server_public = decode_key(&assignment.server_public_key)?;
        let iface: InterfaceName = interface
            .parse()
            .map_err(|e| anyhow!("invalid tunnel interface name '{}': {}", interface, e))?;

        if let Ok(stale) = Device::get(&iface, Backend::Kernel) {
            debug!("removing stale WireGuard interface {}", interface);
            let _ = stale.delete();
        }

        let peer = PeerConfigBuilder::new(&Key(server_public))
            .set_preshared_key(Key(psk))
            .set_endpoint(SocketAddr::new(server_ip, assignment.endpoint_port))
            .set_persistent_keepalive_interval(WG_KEEPALIVE_SECS)
            .replace_allowed_ips()
            // Visitors keep their real source addresses, so any address may arrive from the
            // server peer. No routes are installed from allowed-ips; we add our own below.
            .add_allowed_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .add_allowed_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        DeviceUpdate::new()
            .set_private_key(Key(private_key))
            .replace_peers()
            .add_peer(peer)
            .apply(&iface, Backend::Kernel)
            .with_context(|| {
                format!(
                    "failed to create WireGuard interface {} (is the wireguard kernel module available?)",
                    interface
                )
            })?;

        let (connection, handle, _) =
            rtnetlink::new_connection().context("failed to open rtnetlink socket")?;
        tokio::spawn(connection);

        let mut this = Self {
            iface,
            ifindex: 0,
            handle,
            rules: Vec::new(),
            client_v4,
            client_v6,
        };
        match this.configure(assignment, table_id).await {
            Ok(()) => {
                info!(
                    "tunnel {} up: {}/{} and {}/{} via WireGuard endpoint {}:{} (mtu {})",
                    interface,
                    client_v4,
                    assignment.ipv4_prefix_len,
                    client_v6,
                    assignment.ipv6_prefix_len,
                    server_ip,
                    assignment.endpoint_port,
                    assignment.mtu
                );
                Ok(this)
            }
            Err(e) => {
                this.teardown().await;
                Err(e)
            }
        }
    }

    async fn configure(&mut self, assignment: &TunnelAssignment, table_id: u32) -> Result<()> {
        let name = self.iface.as_str_lossy().to_string();
        let mut links = self.handle.link().get().match_name(name.clone()).execute();
        self.ifindex = links
            .try_next()
            .await?
            .ok_or_else(|| anyhow!("interface {} vanished after creation", name))?
            .header
            .index;

        add_address(
            &self.handle,
            self.ifindex,
            IpAddr::V4(self.client_v4),
            assignment.ipv4_prefix_len,
        )
        .await?;
        add_address(
            &self.handle,
            self.ifindex,
            IpAddr::V6(self.client_v6),
            assignment.ipv6_prefix_len,
        )
        .await?;
        self.handle
            .link()
            .set(self.ifindex)
            .mtu(u32::from(assignment.mtu))
            .up()
            .execute()
            .await
            .context("failed to bring up the tunnel interface")?;

        // Policy routing: anything we send from a tunnel address goes back through the
        // tunnel. The same rule also satisfies strict reverse-path filtering for visitor
        // packets arriving on the tunnel interface.
        self.delete_stale_rules(table_id).await;
        let mut v4_rule = self
            .handle
            .rule()
            .add()
            .v4()
            .source_prefix(self.client_v4, 32)
            .table_id(table_id)
            .priority(table_id)
            .action(RuleAction::ToTable);
        self.rules.push(v4_rule.message_mut().clone());
        v4_rule
            .execute()
            .await
            .context("failed to add IPv4 policy rule for the tunnel")?;

        let mut v6_rule = self
            .handle
            .rule()
            .add()
            .v6()
            .source_prefix(self.client_v6, 128)
            .table_id(table_id)
            .priority(table_id)
            .action(RuleAction::ToTable);
        self.rules.push(v6_rule.message_mut().clone());
        v6_rule
            .execute()
            .await
            .context("failed to add IPv6 policy rule for the tunnel")?;

        self.handle
            .route()
            .add()
            .v4()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .output_interface(self.ifindex)
            .scope(RouteScope::Link)
            .table_id(table_id)
            .replace()
            .execute()
            .await
            .context("failed to add IPv4 default route in the tunnel table")?;
        self.handle
            .route()
            .add()
            .v6()
            .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
            .output_interface(self.ifindex)
            .scope(RouteScope::Link)
            .table_id(table_id)
            .replace()
            .execute()
            .await
            .context("failed to add IPv6 default route in the tunnel table")?;
        Ok(())
    }

    async fn delete_stale_rules(&self, priority: u32) {
        for version in [IpVersion::V4, IpVersion::V6] {
            let mut rules = self.handle.rule().get(version).execute();
            loop {
                match rules.try_next().await {
                    Ok(Some(rule)) => {
                        let ours = rule.attributes.iter().any(
                            |attr| matches!(attr, RuleAttribute::Priority(p) if *p == priority),
                        );
                        if ours {
                            let _ = self.handle.rule().del(rule).execute().await;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
    }

    /// Remove the policy rules and the interface (its routes go with it).
    pub async fn teardown(self) {
        for rule in &self.rules {
            if let Err(e) = self.handle.rule().del(rule.clone()).execute().await {
                debug!("failed to delete tunnel policy rule: {}", e);
            }
        }
        if self.ifindex != 0 {
            if let Err(e) = self.handle.link().del(self.ifindex).execute().await {
                warn!("failed to delete tunnel interface {}: {}", self.iface, e);
            }
        } else if let Ok(device) = Device::get(&self.iface, Backend::Kernel) {
            let _ = device.delete();
        }
    }
}

fn decode_key(b64: &str) -> Result<[u8; 32]> {
    let raw = BASE64_STANDARD
        .decode(b64.trim())
        .context("server WireGuard public key is not valid base64")?;
    let key: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("server WireGuard public key must be 32 bytes"))?;
    Ok(key)
}

async fn add_address(handle: &Handle, index: u32, ip: IpAddr, prefix: u8) -> Result<()> {
    match handle.address().add(index, ip, prefix).execute().await {
        Ok(()) => Ok(()),
        Err(rtnetlink::Error::NetlinkError(err)) if err.raw_code() == -libc::EEXIST => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to add address {}/{}", ip, prefix)),
    }
}
