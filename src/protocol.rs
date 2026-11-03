use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::config::ProxyType;

const TAG_JSON_CONTROL: u8 = 0x01;
const TAG_UDP_PACKET: u8 = 0x02;

const ADDR_V4: u8 = 4;
const ADDR_V6: u8 = 6;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySpec {
    pub name: String,
    pub proxy_type: ProxyType,
    #[serde(default)]
    pub local_addr: String,
    pub remote_port: u16,
    pub remote_bind_ip: Option<String>,
}

/// First message sent by client after completing the mlkem768x25519plus handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoleHandshake {
    Control {
        proxies: Vec<ProxySpec>,
    },
    WorkTcp {
        conn_id: u64,
        proxy_name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlSignal {
    RegisterAck {
        success: bool,
        message: String,
    },
    ReqWorkConn {
        conn_id: u64,
        proxy_name: String,
        visitor_addr: String,
    },
    Ping {
        timestamp_ms: u64,
    },
    Pong {
        timestamp_ms: u64,
    },
}

#[derive(Debug, Clone)]
pub enum TunnelFrame {
    Signal(ControlSignal),
    UdpDatagram {
        proxy_name: String,
        visitor_addr: SocketAddr,
        payload: Bytes,
    },
}

impl RoleHandshake {
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("failed to encode RoleHandshake")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("failed to decode RoleHandshake")
    }
}

impl TunnelFrame {
    pub fn encode(&self) -> Result<Bytes> {
        match self {
            TunnelFrame::Signal(sig) => {
                let json = serde_json::to_vec(sig).context("failed to serialize ControlSignal")?;
                let mut buf = BytesMut::with_capacity(1 + json.len());
                buf.put_u8(TAG_JSON_CONTROL);
                buf.put_slice(&json);
                Ok(buf.freeze())
            }
            TunnelFrame::UdpDatagram {
                proxy_name,
                visitor_addr,
                payload,
            } => {
                let name_bytes = proxy_name.as_bytes();
                if name_bytes.len() > u16::MAX as usize {
                    bail!("proxy_name too long for UDP frame");
                }
                let addr_len = match visitor_addr {
                    SocketAddr::V4(_) => 1 + 4 + 2,
                    SocketAddr::V6(_) => 1 + 16 + 2,
                };
                let mut buf =
                    BytesMut::with_capacity(1 + 2 + name_bytes.len() + addr_len + payload.len());
                buf.put_u8(TAG_UDP_PACKET);
                buf.put_u16(name_bytes.len() as u16);
                buf.put_slice(name_bytes);
                match visitor_addr {
                    SocketAddr::V4(v4) => {
                        buf.put_u8(ADDR_V4);
                        buf.put_slice(&v4.ip().octets());
                        buf.put_u16(v4.port());
                    }
                    SocketAddr::V6(v6) => {
                        buf.put_u8(ADDR_V6);
                        buf.put_slice(&v6.ip().octets());
                        buf.put_u16(v6.port());
                    }
                }
                buf.put_slice(payload);
                Ok(buf.freeze())
            }
        }
    }

    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.is_empty() {
            bail!("empty tunnel frame");
        }
        let tag = data.get_u8();
        match tag {
            TAG_JSON_CONTROL => {
                let sig: ControlSignal =
                    serde_json::from_slice(&data).context("failed to decode ControlSignal")?;
                Ok(TunnelFrame::Signal(sig))
            }
            TAG_UDP_PACKET => {
                if data.len() < 2 {
                    bail!("truncated UDP frame (missing name length)");
                }
                let name_len = data.get_u16() as usize;
                if data.len() < name_len + 1 {
                    bail!("truncated UDP frame (missing proxy name or addr family)");
                }
                let name_bytes = data.split_to(name_len);
                let proxy_name = String::from_utf8(name_bytes.to_vec())
                    .context("invalid UTF-8 proxy_name in UDP frame")?;

                let family = data.get_u8();
                let visitor_addr = match family {
                    ADDR_V4 => {
                        if data.len() < 6 {
                            bail!("truncated IPv4 address in UDP frame");
                        }
                        let mut octets = [0u8; 4];
                        data.copy_to_slice(&mut octets);
                        let port = data.get_u16();
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)
                    }
                    ADDR_V6 => {
                        if data.len() < 18 {
                            bail!("truncated IPv6 address in UDP frame");
                        }
                        let mut octets = [0u8; 16];
                        data.copy_to_slice(&mut octets);
                        let port = data.get_u16();
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
                    }
                    other => return Err(anyhow!("unknown UDP address family tag: {}", other)),
                };

                Ok(TunnelFrame::UdpDatagram {
                    proxy_name,
                    visitor_addr,
                    payload: data,
                })
            }
            other => bail!("unknown tunnel frame tag: 0x{:02x}", other),
        }
    }
}
