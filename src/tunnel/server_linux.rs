//! Server side of the tunnel data plane on Linux: owns the WireGuard interface, the TC eBPF
//! programs on the public and tunnel interfaces, and the port redirection tables.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, PerCpuHashMap, PerCpuValues};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::util::nr_cpus;
use aya::Ebpf;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use futures::TryStreamExt;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::route::RouteAttribute;
use rtnetlink::{Handle, IpVersion};
use tracing::{debug, info, warn};
use wireguard_control::{
    Backend, Device, DeviceUpdate, InterfaceName, Key, KeyPair, PeerConfigBuilder,
};

use crate::config::TunnelServerConfig;
use crate::crypto::{key_id_hex, KeyId};
use crate::protocol::{TunnelAssignment, TUNNEL_PROTOCOL_VERSION};

use super::bpf_types::{ip_bytes, Config, PortKey, PortVal, RevKey, RevVal, Stats, FAMILY_V4};
use super::ipam::{Cidr4, Cidr6, TunnelPool};
use super::{PortTraffic, ResolvedBinding, TunnelLease};

/// Compiled TC programs (see `bpf/rrp_tc.c`, rebuilt with `bpf/build.sh`).
const RRP_TC_OBJECT: &[u8] = include_bytes!("../../bpf/rrp_tc.o");
const RT_TABLE_MAIN: u32 = 254;

struct ClientState {
    generation: u64,
    wg_public: [u8; 32],
    v4: Ipv4Addr,
    v6: Ipv6Addr,
    /// Installed redirections: (proxy name, forward key, reverse key).
    ports: Vec<(String, PortKey, RevKey)>,
}

struct Inner {
    // Keeps programs attached and maps alive for the lifetime of the server.
    _ebpf: Ebpf,
    portmap: BpfHashMap<MapData, PortKey, PortVal>,
    revmap: BpfHashMap<MapData, RevKey, RevVal>,
    stats: PerCpuHashMap<MapData, PortKey, Stats>,
    pool: TunnelPool,
    clients: HashMap<KeyId, ClientState>,
    port_owner: HashMap<PortKey, KeyId>,
    iface: InterfaceName,
    ncpus: usize,
    next_generation: u64,
}

pub struct TunnelServer {
    inner: Mutex<Inner>,
    description: String,
    endpoint_port: u16,
    server_public_key_b64: String,
    server_v4: Ipv4Addr,
    server_v6: Ipv6Addr,
    v4_prefix: u8,
    v6_prefix: u8,
    mtu: u16,
    has_v4: bool,
    has_v6: bool,
}

impl TunnelServer {
    /// Bring up the WireGuard interface, load and attach the TC programs, and write the
    /// static configuration map. Fails (so the caller can fall back) when the host lacks
    /// WireGuard, eBPF privileges, or a usable public address.
    pub async fn start(config: &TunnelServerConfig) -> Result<Self> {
        config.validate()?;
        raise_memlock_limit();

        let (connection, handle, _) =
            rtnetlink::new_connection().context("failed to open rtnetlink socket")?;
        tokio::spawn(connection);

        // 1. Public interface and addresses.
        let public_ifindex = match &config.public_interface {
            Some(name) => link_index(&handle, name)
                .await
                .with_context(|| format!("tunnel.public_interface '{}' not found", name))?,
            None => default_route_interface(&handle).await.context(
                "could not auto-detect the public interface (set tunnel.public_interface)",
            )?,
        };
        let public_name = link_name(&handle, public_ifindex).await?;
        let addrs = interface_addresses(&handle, public_ifindex).await?;
        let public_v4 = match &config.public_ipv4 {
            Some(ip) => Some(ip.trim().parse::<Ipv4Addr>()?),
            None => pick_public_v4(&addrs),
        };
        let public_v6 = match &config.public_ipv6 {
            Some(ip) => Some(
                ip.trim()
                    .trim_matches(|c| c == '[' || c == ']')
                    .parse::<Ipv6Addr>()?,
            ),
            None => pick_public_v6(&addrs),
        };
        if public_v4.is_none() && public_v6.is_none() {
            bail!(
                "interface {} has no usable public IPv4 or IPv6 address (set tunnel.public_ipv4/ipv6)",
                public_name
            );
        }

        // 2. Address pools and the WireGuard interface.
        let pool = TunnelPool::new(
            Cidr4::parse(&config.ipv4_cidr)?,
            Cidr6::parse(&config.ipv6_cidr)?,
        );
        let (server_v4, server_v6) = pool.server_addrs();
        let (v4_prefix, v6_prefix) = pool.prefixes();
        let iface: InterfaceName = config
            .interface
            .parse()
            .map_err(|e| anyhow!("invalid tunnel interface name: {}", e))?;
        if let Ok(stale) = Device::get(&iface, Backend::Kernel) {
            warn!(
                "removing stale WireGuard interface {} left by a previous run",
                config.interface
            );
            let _ = stale.delete();
        }
        let keypair = KeyPair::generate();
        DeviceUpdate::new()
            .set_keypair(keypair.clone())
            .set_listen_port(config.listen_port)
            .replace_peers()
            .apply(&iface, Backend::Kernel)
            .with_context(|| {
                format!(
                    "failed to create WireGuard interface {} (is the wireguard kernel module available?)",
                    config.interface
                )
            })?;
        let tunnel_ifindex = link_index(&handle, &config.interface).await?;
        add_address(&handle, tunnel_ifindex, server_v4.into(), v4_prefix).await?;
        add_address(&handle, tunnel_ifindex, server_v6.into(), v6_prefix).await?;
        handle
            .link()
            .set(tunnel_ifindex)
            .mtu(u32::from(config.mtu))
            .up()
            .execute()
            .await
            .context("failed to bring up the WireGuard interface")?;

        // 3. eBPF programs.
        let mut ebpf = Ebpf::load(RRP_TC_OBJECT).context("failed to load rrp TC programs")?;
        ensure_clsact(&public_name)?;
        ensure_clsact(&config.interface)?;
        attach_tc(&mut ebpf, "rrp_public_ingress", &public_name)?;
        attach_tc(&mut ebpf, "rrp_tunnel_ingress", &config.interface)?;

        let mut cfg_map: Array<MapData, Config> = Array::try_from(
            ebpf.take_map("rrp_config")
                .ok_or_else(|| anyhow!("rrp_config map missing from BPF object"))?,
        )?;
        cfg_map.set(
            0,
            Config {
                public_ifindex,
                tunnel_ifindex,
                public_ipv4: public_v4.map(|ip| ip.octets()).unwrap_or_default(),
                public_ipv6: public_v6.map(|ip| ip.octets()).unwrap_or_default(),
                mss_clamp_v4: config.mtu.saturating_sub(40),
                mss_clamp_v6: config.mtu.saturating_sub(60),
            },
            0,
        )?;
        let portmap = BpfHashMap::try_from(
            ebpf.take_map("rrp_portmap")
                .ok_or_else(|| anyhow!("rrp_portmap map missing from BPF object"))?,
        )?;
        let revmap = BpfHashMap::try_from(
            ebpf.take_map("rrp_revmap")
                .ok_or_else(|| anyhow!("rrp_revmap map missing from BPF object"))?,
        )?;
        let stats = PerCpuHashMap::try_from(
            ebpf.take_map("rrp_stats")
                .ok_or_else(|| anyhow!("rrp_stats map missing from BPF object"))?,
        )?;
        let ncpus = nr_cpus().map_err(|(what, e)| anyhow!("{}: {}", what, e))?;

        let description = format!(
            "active (TC redirect {} <-> {}, WireGuard udp/{}, public v4 {}, v6 {})",
            public_name,
            config.interface,
            config.listen_port,
            public_v4
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "none".into()),
            public_v6
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "none".into()),
        );
        info!("tunnel data plane {}", description);

        Ok(Self {
            inner: Mutex::new(Inner {
                _ebpf: ebpf,
                portmap,
                revmap,
                stats,
                pool,
                clients: HashMap::new(),
                port_owner: HashMap::new(),
                iface,
                ncpus,
                next_generation: 1,
            }),
            description,
            endpoint_port: config.listen_port,
            server_public_key_b64: BASE64_STANDARD.encode(keypair.public.as_bytes()),
            server_v4,
            server_v6,
            v4_prefix,
            v6_prefix,
            mtu: config.mtu,
            has_v4: public_v4.is_some(),
            has_v6: public_v6.is_some(),
        })
    }

    pub fn description(&self) -> String {
        self.description.clone()
    }

    /// Register (or re-register) a client: allocate tunnel addresses and add it as a
    /// WireGuard peer. A previous session of the same key is superseded.
    pub fn add_client(
        &self,
        key_id: KeyId,
        client_wg_public: [u8; 32],
        psk: [u8; 32],
    ) -> Result<(TunnelLease, TunnelAssignment)> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow!("tunnel state poisoned"))?;
        if let Some(previous) = inner.clients.remove(&key_id) {
            debug!(
                "superseding tunnel session generation {} for key {}",
                previous.generation,
                key_id_hex(&key_id)
            );
            inner.remove_ports(&previous.ports);
        }
        let (v4, v6) = inner.pool.allocate(key_id)?;
        let generation = inner.next_generation;
        inner.next_generation += 1;

        let peer = PeerConfigBuilder::new(&Key(client_wg_public))
            .set_preshared_key(Key(psk))
            .replace_allowed_ips()
            .add_allowed_ip(IpAddr::V4(v4), 32)
            .add_allowed_ip(IpAddr::V6(v6), 128);
        DeviceUpdate::new()
            .add_peer(peer)
            .apply(&inner.iface, Backend::Kernel)
            .context("failed to add WireGuard peer")?;

        inner.clients.insert(
            key_id,
            ClientState {
                generation,
                wg_public: client_wg_public,
                v4,
                v6,
                ports: Vec::new(),
            },
        );
        let lease = TunnelLease { key_id, generation };
        let assignment = TunnelAssignment {
            version: TUNNEL_PROTOCOL_VERSION,
            server_public_key: self.server_public_key_b64.clone(),
            endpoint_port: self.endpoint_port,
            client_ipv4: v4.to_string(),
            ipv4_prefix_len: self.v4_prefix,
            client_ipv6: v6.to_string(),
            ipv6_prefix_len: self.v6_prefix,
            server_ipv4: self.server_v4.to_string(),
            server_ipv6: self.server_v6.to_string(),
            mtu: self.mtu,
        };
        Ok((lease, assignment))
    }

    /// Install the port redirections for a client that reported its tunnel listeners.
    /// Either all bindings are installed or none (a conflicting port rolls back the batch).
    pub fn install_bindings(
        &self,
        lease: &TunnelLease,
        bindings: &[ResolvedBinding],
    ) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow!("tunnel state poisoned"))?;
        let (v4, v6) = {
            let client = inner
                .clients
                .get(&lease.key_id)
                .filter(|c| c.generation == lease.generation)
                .ok_or_else(|| anyhow!("tunnel session is no longer current"))?;
            (client.v4, client.v6)
        };

        let mut installed: Vec<(String, PortKey, RevKey)> = Vec::with_capacity(bindings.len());
        let result = (|| -> Result<()> {
            for binding in bindings {
                if binding.family == FAMILY_V4 && !self.has_v4 {
                    continue;
                }
                if binding.family != FAMILY_V4 && !self.has_v6 {
                    continue;
                }
                let key = PortKey {
                    family: binding.family,
                    proto: binding.proto,
                    port: binding.public_port,
                };
                if let Some(owner) = inner.port_owner.get(&key) {
                    if *owner != lease.key_id {
                        bail!(
                            "{} port {} is already served for another client",
                            proto_name(binding.proto),
                            binding.public_port
                        );
                    }
                }
                let tunnel_ip = if binding.family == FAMILY_V4 {
                    ip_bytes(IpAddr::V4(v4))
                } else {
                    ip_bytes(IpAddr::V6(v6))
                };
                let rev = RevKey {
                    family: binding.family,
                    proto: binding.proto,
                    tunnel_port: binding.tunnel_port,
                    tunnel_ip,
                };
                let ncpus = inner.ncpus;
                inner.portmap.insert(
                    key,
                    PortVal {
                        tunnel_ip,
                        tunnel_port: binding.tunnel_port,
                        pad: 0,
                    },
                    0,
                )?;
                inner.revmap.insert(
                    rev,
                    RevVal {
                        public_port: binding.public_port,
                        pad: 0,
                    },
                    0,
                )?;
                let zeroed = PerCpuValues::try_from(vec![Stats::default(); ncpus])?;
                inner.stats.insert(key, zeroed, 0)?;
                inner.port_owner.insert(key, lease.key_id);
                installed.push((binding.proxy_name.clone(), key, rev));
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                if let Some(client) = inner.clients.get_mut(&lease.key_id) {
                    client.ports.extend(installed);
                }
                Ok(())
            }
            Err(e) => {
                inner.remove_ports(&installed);
                Err(e)
            }
        }
    }

    /// Current byte counters per proxy for this session, summed across address families.
    pub fn traffic(&self, lease: &TunnelLease) -> Vec<(String, PortTraffic)> {
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };
        let Some(client) = inner
            .clients
            .get(&lease.key_id)
            .filter(|c| c.generation == lease.generation)
        else {
            return Vec::new();
        };
        let mut totals: Vec<(String, PortTraffic)> = Vec::new();
        for (proxy, key, _) in &client.ports {
            let Ok(values) = inner.stats.get(key, 0) else {
                continue;
            };
            let mut traffic = PortTraffic::default();
            for v in values.iter() {
                traffic.visitor_to_client += v.rx_bytes;
                traffic.client_to_visitor += v.tx_bytes;
            }
            match totals.iter_mut().find(|(name, _)| name == proxy) {
                Some((_, existing)) => {
                    existing.visitor_to_client += traffic.visitor_to_client;
                    existing.client_to_visitor += traffic.client_to_visitor;
                }
                None => totals.push((proxy.clone(), traffic)),
            }
        }
        totals
    }

    /// Tear down a session's redirections and WireGuard peer, unless a newer session of the
    /// same key has already replaced it.
    pub fn remove_client(&self, lease: &TunnelLease) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let current = inner
            .clients
            .get(&lease.key_id)
            .map(|c| c.generation == lease.generation)
            .unwrap_or(false);
        if !current {
            return;
        }
        let client = inner.clients.remove(&lease.key_id).expect("checked above");
        inner.remove_ports(&client.ports);
        inner.pool.release(&lease.key_id);
        if let Err(e) = DeviceUpdate::new()
            .remove_peer_by_key(&Key(client.wg_public))
            .apply(&inner.iface, Backend::Kernel)
        {
            warn!(
                "failed to remove WireGuard peer for key {}: {}",
                key_id_hex(&lease.key_id),
                e
            );
        }
    }
}

impl Inner {
    fn remove_ports(&mut self, ports: &[(String, PortKey, RevKey)]) {
        for (_, key, rev) in ports {
            let _ = self.portmap.remove(key);
            let _ = self.revmap.remove(rev);
            let _ = self.stats.remove(key);
            self.port_owner.remove(key);
        }
    }
}

impl Drop for TunnelServer {
    fn drop(&mut self) {
        if let Ok(inner) = self.inner.lock() {
            if let Ok(device) = Device::get(&inner.iface, Backend::Kernel) {
                let _ = device.delete();
            }
        }
    }
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        super::bpf_types::PROTO_TCP => "TCP",
        super::bpf_types::PROTO_UDP => "UDP",
        _ => "IP",
    }
}

fn raise_memlock_limit() {
    // Kernels before 5.11 charge BPF maps against RLIMIT_MEMLOCK; make sure it is not the
    // conservative default of 64 KiB.
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    if rc != 0 {
        debug!(
            "could not raise RLIMIT_MEMLOCK: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn ensure_clsact(ifname: &str) -> Result<()> {
    match tc::qdisc_add_clsact(ifname) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to add clsact qdisc on {}", ifname)),
    }
}

fn attach_tc(ebpf: &mut Ebpf, program: &str, ifname: &str) -> Result<()> {
    let prog: &mut SchedClassifier = ebpf
        .program_mut(program)
        .ok_or_else(|| anyhow!("program {} missing from BPF object", program))?
        .try_into()?;
    prog.load()
        .with_context(|| format!("kernel rejected TC program {} (verifier)", program))?;
    prog.attach(ifname, TcAttachType::Ingress)
        .with_context(|| format!("failed to attach {} to {} ingress", program, ifname))?;
    info!("attached TC program {} to {} ingress", program, ifname);
    Ok(())
}

async fn default_route_interface(handle: &Handle) -> Result<u32> {
    for version in [IpVersion::V4, IpVersion::V6] {
        let mut routes = handle.route().get(version).execute();
        let mut best: Option<(u32, u32)> = None; // (metric, oif)
        while let Some(route) = routes.try_next().await? {
            if route.header.destination_prefix_length != 0 {
                continue;
            }
            let table = route
                .attributes
                .iter()
                .find_map(|attr| match attr {
                    RouteAttribute::Table(t) => Some(*t),
                    _ => None,
                })
                .unwrap_or(u32::from(route.header.table));
            if table != RT_TABLE_MAIN {
                continue;
            }
            let mut oif = None;
            let mut metric = 0u32;
            for attr in &route.attributes {
                match attr {
                    RouteAttribute::Oif(idx) => oif = Some(*idx),
                    RouteAttribute::Priority(p) => metric = *p,
                    _ => {}
                }
            }
            if let Some(idx) = oif {
                if best.map(|(m, _)| metric < m).unwrap_or(true) {
                    best = Some((metric, idx));
                }
            }
        }
        if let Some((_, idx)) = best {
            return Ok(idx);
        }
    }
    bail!("no default route found")
}

async fn link_index(handle: &Handle, name: &str) -> Result<u32> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    match links.try_next().await? {
        Some(link) => Ok(link.header.index),
        None => bail!("interface {} not found", name),
    }
}

async fn link_name(handle: &Handle, index: u32) -> Result<String> {
    let mut links = handle.link().get().match_index(index).execute();
    let link = links
        .try_next()
        .await?
        .ok_or_else(|| anyhow!("interface index {} not found", index))?;
    link.attributes
        .iter()
        .find_map(|attr| match attr {
            LinkAttribute::IfName(name) => Some(name.clone()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("interface index {} has no name", index))
}

async fn interface_addresses(handle: &Handle, index: u32) -> Result<Vec<IpAddr>> {
    let mut stream = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute();
    let mut out = Vec::new();
    while let Some(msg) = stream.try_next().await? {
        let mut local = None;
        let mut address = None;
        for attr in &msg.attributes {
            match attr {
                AddressAttribute::Local(ip) => local = Some(*ip),
                AddressAttribute::Address(ip) => address = Some(*ip),
                _ => {}
            }
        }
        if let Some(ip) = local.or(address) {
            out.push(ip);
        }
    }
    Ok(out)
}

fn pick_public_v4(addrs: &[IpAddr]) -> Option<Ipv4Addr> {
    addrs.iter().find_map(|ip| match ip {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified() => {
            Some(*v4)
        }
        _ => None,
    })
}

fn pick_public_v6(addrs: &[IpAddr]) -> Option<Ipv6Addr> {
    let candidates: Vec<Ipv6Addr> = addrs
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V6(v6)
                if !v6.is_loopback()
                    && !v6.is_unspecified()
                    && (v6.segments()[0] & 0xffc0) != 0xfe80 =>
            {
                Some(*v6)
            }
            _ => None,
        })
        .collect();
    candidates
        .iter()
        .find(|v6| (v6.segments()[0] & 0xe000) == 0x2000)
        .or(candidates.first())
        .copied()
}

async fn add_address(handle: &Handle, index: u32, ip: IpAddr, prefix: u8) -> Result<()> {
    match handle.address().add(index, ip, prefix).execute().await {
        Ok(()) => Ok(()),
        Err(rtnetlink::Error::NetlinkError(err)) if err.raw_code() == -libc::EEXIST => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to add address {}/{}", ip, prefix)),
    }
}
