//! Wire format for `open_ports` keys and values.
//!
//! Must stay byte-identical to `struct port_key` / `struct port_val` in
//! `dispatch.bpf.c`:
//!
//! ```c
//! struct port_key { __u16 port; __u16 family; __u32 addr[4]; };  // 20 bytes
//! struct port_val { __u8 group; __u8 shards; __u16 _pad; };      //  4 bytes
//! ```
//!
//! Byte order follows `struct bpf_sk_lookup`: `local_port` is host order,
//! `local_ip4` / `local_ip6` are network order. A wildcard destination is the
//! all-zero address, which is what single-VIP deployments use.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};
use serde::{Serialize, Serializer};

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

pub const PORT_KEY_SIZE: usize = 20;
pub const PORT_VAL_SIZE: usize = 4;

/// Destination address of a steered port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Dest {
    /// Any address on this host, IPv4 (`0.0.0.0`).
    #[default]
    AnyV4,
    /// Any address on this host, IPv6 (`[::]`).
    AnyV6,
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl Dest {
    pub fn family(&self) -> u16 {
        match self {
            Dest::AnyV4 | Dest::V4(_) => AF_INET,
            Dest::AnyV6 | Dest::V6(_) => AF_INET6,
        }
    }

    pub fn is_wildcard(&self) -> bool {
        matches!(self, Dest::AnyV4 | Dest::AnyV6)
    }

    /// Network-order words as the BPF program reads them.
    pub fn addr_words(&self) -> [u32; 4] {
        match self {
            Dest::AnyV4 | Dest::AnyV6 => [0; 4],
            Dest::V4(ip) => [u32::from_ne_bytes(ip.octets()), 0, 0, 0],
            Dest::V6(ip) => {
                let o = ip.octets();
                let mut w = [0u32; 4];
                for (i, word) in w.iter_mut().enumerate() {
                    *word =
                        u32::from_ne_bytes([o[i * 4], o[i * 4 + 1], o[i * 4 + 2], o[i * 4 + 3]]);
                }
                w
            }
        }
    }

    /// Parse the address part of a port spec. `*`, empty, `0.0.0.0` are IPv4
    /// wildcards; `[::]` is the IPv6 wildcard.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() || s == "*" || s == "0.0.0.0" {
            return Ok(Dest::AnyV4);
        }
        if s == "::" || s == "[::]" || s == "*6" {
            return Ok(Dest::AnyV6);
        }
        let stripped = s
            .strip_prefix('[')
            .and_then(|r| r.strip_suffix(']'))
            .unwrap_or(s);
        match stripped.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) if ip.is_unspecified() => Ok(Dest::AnyV4),
            Ok(IpAddr::V4(ip)) => Ok(Dest::V4(ip)),
            Ok(IpAddr::V6(ip)) if ip.is_unspecified() => Ok(Dest::AnyV6),
            Ok(IpAddr::V6(ip)) => Ok(Dest::V6(ip)),
            Err(_) => bail!("invalid destination address {s:?}"),
        }
    }
}

impl fmt::Display for Dest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dest::AnyV4 => write!(f, "*"),
            Dest::AnyV6 => write!(f, "[::]"),
            Dest::V4(ip) => write!(f, "{ip}"),
            Dest::V6(ip) => write!(f, "[{ip}]"),
        }
    }
}

/// A full `open_ports` key: which (family, address, port) is steered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortKey {
    pub port: u16,
    pub dest: Dest,
}

impl PortKey {
    pub fn wildcard_v4(port: u16) -> Self {
        Self {
            port,
            dest: Dest::AnyV4,
        }
    }

    pub fn new(port: u16, dest: Dest) -> Self {
        Self { port, dest }
    }

    pub fn to_bytes(self) -> [u8; PORT_KEY_SIZE] {
        let mut out = [0u8; PORT_KEY_SIZE];
        out[0..2].copy_from_slice(&self.port.to_ne_bytes());
        out[2..4].copy_from_slice(&self.dest.family().to_ne_bytes());
        for (i, word) in self.dest.addr_words().iter().enumerate() {
            let off = 4 + i * 4;
            out[off..off + 4].copy_from_slice(&word.to_ne_bytes());
        }
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() < PORT_KEY_SIZE {
            bail!(
                "open_ports key is {} bytes, want {PORT_KEY_SIZE}",
                raw.len()
            );
        }
        let port = u16::from_ne_bytes([raw[0], raw[1]]);
        let family = u16::from_ne_bytes([raw[2], raw[3]]);
        let mut words = [0u32; 4];
        for (i, word) in words.iter_mut().enumerate() {
            let off = 4 + i * 4;
            *word = u32::from_ne_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
        }
        let all_zero = words.iter().all(|w| *w == 0);
        let dest = match (family, all_zero) {
            (AF_INET, true) => Dest::AnyV4,
            (AF_INET6, true) => Dest::AnyV6,
            (AF_INET, false) => Dest::V4(Ipv4Addr::from(words[0].to_ne_bytes())),
            (AF_INET6, false) => {
                let mut octets = [0u8; 16];
                for (i, word) in words.iter().enumerate() {
                    octets[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
                }
                Dest::V6(Ipv6Addr::from(octets))
            }
            (other, _) => bail!("open_ports key has unsupported family {other}"),
        };
        Ok(Self { port, dest })
    }
}

/// Serialize as the human-readable form (`18081` or `10.0.0.7:443`) so JSON
/// status output stays readable and diffable in runbooks.
impl Serialize for PortKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl Serialize for Dest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl fmt::Display for PortKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.dest.is_wildcard() && self.dest.family() == AF_INET {
            write!(f, "{}", self.port)
        } else {
            write!(f, "{}:{}", self.dest, self.port)
        }
    }
}

/// `open_ports` value: protocol group plus the live shard count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize)]
pub struct PortVal {
    pub group: u8,
    pub shards: u8,
}

impl PortVal {
    pub fn new(group: u8, shards: u8) -> Self {
        Self { group, shards }
    }

    pub fn to_bytes(self) -> [u8; PORT_VAL_SIZE] {
        [self.group, self.shards.max(1), 0, 0]
    }

    pub fn from_bytes(raw: &[u8]) -> Self {
        Self {
            group: raw.first().copied().unwrap_or(0),
            shards: raw.get(1).copied().unwrap_or(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip_v4_wildcard() {
        let k = PortKey::wildcard_v4(18081);
        let raw = k.to_bytes();
        assert_eq!(raw.len(), 20);
        assert_eq!(PortKey::from_bytes(&raw).unwrap(), k);
        assert_eq!(k.to_string(), "18081");
    }

    #[test]
    fn key_roundtrip_v4_specific() {
        let k = PortKey::new(443, Dest::V4("10.0.0.7".parse().unwrap()));
        assert_eq!(PortKey::from_bytes(&k.to_bytes()).unwrap(), k);
        assert_eq!(k.to_string(), "10.0.0.7:443");
    }

    #[test]
    fn key_roundtrip_v6() {
        let k = PortKey::new(8443, Dest::V6("2001:db8::1".parse().unwrap()));
        assert_eq!(PortKey::from_bytes(&k.to_bytes()).unwrap(), k);
        let w = PortKey::new(8443, Dest::AnyV6);
        assert_eq!(PortKey::from_bytes(&w.to_bytes()).unwrap(), w);
        assert_eq!(w.to_string(), "[::]:8443");
    }

    #[test]
    fn family_is_encoded_so_v4_and_v6_wildcards_differ() {
        // Regression: port-only keys made an IPv6 SYN match an IPv4 entry and
        // then get silently dropped by bpf_sk_assign(-EAFNOSUPPORT).
        assert_ne!(
            PortKey::new(18081, Dest::AnyV4).to_bytes(),
            PortKey::new(18081, Dest::AnyV6).to_bytes()
        );
    }

    #[test]
    fn dest_parses_wildcards_and_literals() {
        assert_eq!(Dest::parse("*").unwrap(), Dest::AnyV4);
        assert_eq!(Dest::parse("").unwrap(), Dest::AnyV4);
        assert_eq!(Dest::parse("0.0.0.0").unwrap(), Dest::AnyV4);
        assert_eq!(Dest::parse("[::]").unwrap(), Dest::AnyV6);
        assert_eq!(Dest::parse("::").unwrap(), Dest::AnyV6);
        assert_eq!(
            Dest::parse("10.1.2.3").unwrap(),
            Dest::V4("10.1.2.3".parse().unwrap())
        );
        assert_eq!(
            Dest::parse("[2001:db8::5]").unwrap(),
            Dest::V6("2001:db8::5".parse().unwrap())
        );
        assert!(Dest::parse("not-an-ip").is_err());
    }

    #[test]
    fn val_roundtrip_and_shards_floor() {
        let v = PortVal::new(1, 8);
        assert_eq!(PortVal::from_bytes(&v.to_bytes()), v);
        // shards must never be zero: the BPF program treats 0 as invalid.
        assert_eq!(PortVal::new(0, 0).to_bytes()[1], 1);
    }
}
