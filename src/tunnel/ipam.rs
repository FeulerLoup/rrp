//! Tunnel address allocation: each client key gets one IPv4 and one IPv6 host address out of
//! the configured pools, with the server taking the first host of each.

use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail, Result};

use crate::crypto::KeyId;

const SERVER_INDEX: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr4 {
    base: Ipv4Addr,
    prefix: u8,
}

impl Cidr4 {
    pub fn parse(text: &str) -> Result<Self> {
        let (ip, prefix) = split_cidr(text)?;
        let ip: Ipv4Addr = ip
            .parse()
            .map_err(|_| anyhow!("'{}' is not an IPv4 network", text))?;
        if prefix > 30 {
            bail!("IPv4 prefix /{} leaves no usable hosts", prefix);
        }
        let mask = u32::MAX << (32 - prefix);
        let base = Ipv4Addr::from(u32::from(ip) & mask);
        Ok(Self { base, prefix })
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Usable host indices: 1 ..= capacity (network and broadcast excluded).
    pub fn host_capacity(&self) -> u32 {
        (1u64 << (32 - self.prefix))
            .saturating_sub(2)
            .min(u32::MAX as u64) as u32
    }

    pub fn host(&self, index: u32) -> Option<Ipv4Addr> {
        if index == 0 || index > self.host_capacity() {
            return None;
        }
        Some(Ipv4Addr::from(u32::from(self.base) + index))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr6 {
    base: Ipv6Addr,
    prefix: u8,
}

impl Cidr6 {
    pub fn parse(text: &str) -> Result<Self> {
        let (ip, prefix) = split_cidr(text)?;
        let ip: Ipv6Addr = ip
            .parse()
            .map_err(|_| anyhow!("'{}' is not an IPv6 network", text))?;
        if prefix > 112 {
            bail!("IPv6 prefix /{} is too small for a client pool", prefix);
        }
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        let base = Ipv6Addr::from(u128::from(ip) & mask);
        Ok(Self { base, prefix })
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn host(&self, index: u32) -> Option<Ipv6Addr> {
        if index == 0 {
            return None;
        }
        let capacity = 1u128 << (128 - self.prefix);
        if u128::from(index) >= capacity {
            return None;
        }
        Some(Ipv6Addr::from(u128::from(self.base) + u128::from(index)))
    }
}

fn split_cidr(text: &str) -> Result<(&str, u8)> {
    let (ip, prefix) = text
        .trim()
        .split_once('/')
        .ok_or_else(|| anyhow!("'{}' is missing a /prefix", text))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| anyhow!("'{}' has an invalid prefix length", text))?;
    Ok((ip, prefix))
}

/// Stable per-key allocation: a reconnecting client gets its previous addresses back whenever
/// they are still free, so port tables and WireGuard allowed-ips stay predictable.
#[derive(Debug)]
pub struct TunnelPool {
    v4: Cidr4,
    v6: Cidr6,
    assigned: HashMap<KeyId, u32>,
    preferred: HashMap<KeyId, u32>,
    in_use: BTreeSet<u32>,
    cursor: u32,
}

impl TunnelPool {
    pub fn new(v4: Cidr4, v6: Cidr6) -> Self {
        let mut in_use = BTreeSet::new();
        in_use.insert(SERVER_INDEX);
        Self {
            v4,
            v6,
            assigned: HashMap::new(),
            preferred: HashMap::new(),
            in_use,
            cursor: SERVER_INDEX + 1,
        }
    }

    pub fn server_addrs(&self) -> (Ipv4Addr, Ipv6Addr) {
        (
            self.v4.host(SERVER_INDEX).expect("validated pool"),
            self.v6.host(SERVER_INDEX).expect("validated pool"),
        )
    }

    pub fn prefixes(&self) -> (u8, u8) {
        (self.v4.prefix(), self.v6.prefix())
    }

    pub fn capacity(&self) -> u32 {
        self.v4.host_capacity().saturating_sub(1)
    }

    pub fn lookup(&self, key: &KeyId) -> Option<(Ipv4Addr, Ipv6Addr)> {
        self.assigned.get(key).map(|idx| self.addrs(*idx))
    }

    pub fn allocate(&mut self, key: KeyId) -> Result<(Ipv4Addr, Ipv6Addr)> {
        if let Some(idx) = self.assigned.get(&key) {
            return Ok(self.addrs(*idx));
        }
        if let Some(idx) = self.preferred.get(&key).copied() {
            if !self.in_use.contains(&idx) {
                return Ok(self.take(key, idx));
            }
        }
        let capacity = self.v4.host_capacity();
        if capacity < 2 {
            bail!("tunnel address pool has no room for clients");
        }
        let mut probes = 0;
        while probes < capacity {
            let candidate = self.cursor;
            self.cursor = if self.cursor >= capacity {
                SERVER_INDEX + 1
            } else {
                self.cursor + 1
            };
            probes += 1;
            if candidate != SERVER_INDEX && !self.in_use.contains(&candidate) {
                return Ok(self.take(key, candidate));
            }
        }
        bail!(
            "tunnel address pool exhausted ({} client addresses in use)",
            self.in_use.len() - 1
        )
    }

    pub fn release(&mut self, key: &KeyId) {
        if let Some(idx) = self.assigned.remove(key) {
            self.in_use.remove(&idx);
            self.preferred.insert(*key, idx);
        }
    }

    fn take(&mut self, key: KeyId, idx: u32) -> (Ipv4Addr, Ipv6Addr) {
        self.in_use.insert(idx);
        self.assigned.insert(key, idx);
        self.preferred.insert(key, idx);
        self.addrs(idx)
    }

    fn addrs(&self, idx: u32) -> (Ipv4Addr, Ipv6Addr) {
        (
            self.v4.host(idx).expect("index within pool"),
            self.v6.host(idx).expect("index within pool"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> KeyId {
        [n; 32]
    }

    #[test]
    fn parses_and_normalizes_cidrs() {
        let v4 = Cidr4::parse("10.199.3.9/16").unwrap();
        assert_eq!(v4.host(1), Some("10.199.0.1".parse().unwrap()));
        assert_eq!(v4.host_capacity(), 65534);
        assert!(Cidr4::parse("10.0.0.0/31").is_err());
        assert!(Cidr4::parse("10.0.0.0").is_err());

        let v6 = Cidr6::parse("fd00:7272::abcd/64").unwrap();
        assert_eq!(v6.host(1), Some("fd00:7272::1".parse().unwrap()));
        assert!(Cidr6::parse("fd00::/120").is_err());
    }

    #[test]
    fn allocates_stably_and_reuses_after_release() {
        let mut pool = TunnelPool::new(
            Cidr4::parse("10.199.0.0/29").unwrap(),
            Cidr6::parse("fd00:7272::/64").unwrap(),
        );
        assert_eq!(
            pool.server_addrs(),
            (
                "10.199.0.1".parse().unwrap(),
                "fd00:7272::1".parse().unwrap()
            )
        );
        let a = pool.allocate(key(1)).unwrap();
        let b = pool.allocate(key(2)).unwrap();
        assert_eq!(a.0, "10.199.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(b.0, "10.199.0.3".parse::<Ipv4Addr>().unwrap());
        assert_eq!(pool.allocate(key(1)).unwrap(), a, "same key, same address");

        pool.release(&key(1));
        let c = pool.allocate(key(3)).unwrap();
        assert_ne!(
            c, a,
            "cursor keeps moving so a fresh key does not grab a recent address"
        );
        assert_eq!(
            pool.allocate(key(1)).unwrap(),
            a,
            "preferred address restored"
        );

        // /29 has 6 hosts: server + 5 clients.
        pool.allocate(key(4)).unwrap();
        pool.allocate(key(5)).unwrap();
        assert!(pool.allocate(key(6)).is_err());
        pool.release(&key(2));
        assert!(pool.allocate(key(6)).is_ok());
    }
}
