//! Map key/value layouts shared with `bpf/rrp_tc.c`. Every struct here mirrors its C twin
//! byte for byte (`#[repr(C)]`, same field order and widths); the size tests below guard that.

pub const FAMILY_V4: u8 = 4;
pub const FAMILY_V6: u8 = 6;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PortKey {
    pub family: u8,
    pub proto: u8,
    /// Public port, host byte order.
    pub port: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PortVal {
    /// Client tunnel address in network order; IPv4 occupies the first four bytes.
    pub tunnel_ip: [u8; 16],
    /// Client listener port, host byte order.
    pub tunnel_port: u16,
    pub pad: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RevKey {
    pub family: u8,
    pub proto: u8,
    pub tunnel_port: u16,
    pub tunnel_ip: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RevVal {
    pub public_port: u16,
    pub pad: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Config {
    pub public_ifindex: u32,
    pub tunnel_ifindex: u32,
    pub public_ipv4: [u8; 4],
    pub public_ipv6: [u8; 16],
    pub mss_clamp_v4: u16,
    pub mss_clamp_v6: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
}

#[cfg(target_os = "linux")]
mod pod {
    use super::*;
    // SAFETY: plain `#[repr(C)]` structs of integers and byte arrays without padding-sensitive
    // invariants; any bit pattern is a valid value.
    unsafe impl aya::Pod for PortKey {}
    unsafe impl aya::Pod for PortVal {}
    unsafe impl aya::Pod for RevKey {}
    unsafe impl aya::Pod for RevVal {}
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for Stats {}
}

/// Network-order 16-byte representation used in map values and keys.
pub fn ip_bytes(ip: std::net::IpAddr) -> [u8; 16] {
    let mut out = [0u8; 16];
    match ip {
        std::net::IpAddr::V4(v4) => out[..4].copy_from_slice(&v4.octets()),
        std::net::IpAddr::V6(v6) => out.copy_from_slice(&v6.octets()),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn layouts_match_the_c_program() {
        assert_eq!(size_of::<PortKey>(), 4);
        assert_eq!(size_of::<PortVal>(), 20);
        assert_eq!(size_of::<RevKey>(), 20);
        assert_eq!(size_of::<RevVal>(), 4);
        assert_eq!(size_of::<Config>(), 32);
        assert_eq!(size_of::<Stats>(), 32);
    }

    #[test]
    fn ip_bytes_places_v4_in_leading_octets() {
        let bytes = ip_bytes("10.199.0.7".parse().unwrap());
        assert_eq!(&bytes[..4], &[10, 199, 0, 7]);
        assert!(bytes[4..].iter().all(|b| *b == 0));
        let v6: std::net::Ipv6Addr = "fd00:7272::7".parse().unwrap();
        assert_eq!(ip_bytes(v6.into()), v6.octets());
    }
}
