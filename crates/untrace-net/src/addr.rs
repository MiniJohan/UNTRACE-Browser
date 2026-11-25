//! Which network an address or name belongs to (local-network protection, D-040).
//!
//! The classes follow the WICG Local Network Access specification: *loopback* (this computer),
//! *local* (the local network: private, link-local, carrier-grade NAT and unique-local ranges)
//! and *public*. Names are classified only when their text says where they are (IP literals,
//! `localhost`, local suffixes, names without a dot); every other name is public until DNS says
//! otherwise.

use std::net::{IpAddr, Ipv4Addr};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Space {
    Loopback,
    Local,
    Public,
}

impl Space {
    /// Loopback or local network.
    pub fn is_local(self) -> bool {
        self != Space::Public
    }
}

fn v4_space(ip: Ipv4Addr) -> Space {
    let o = ip.octets();
    match o {
        [127, ..] | [0, ..] => Space::Loopback,
        [10, ..] | [192, 168, ..] | [169, 254, ..] => Space::Local,
        [172, b, ..] if (16..=31).contains(&b) => Space::Local,
        [100, b, ..] if (64..=127).contains(&b) => Space::Local, // carrier-grade NAT
        [198, 18 | 19, ..] => Space::Local,                      // benchmarking
        _ => Space::Public,
    }
}

pub fn ip_space(ip: IpAddr) -> Space {
    match ip {
        IpAddr::V4(v4) => v4_space(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4_space(v4);
            }
            if v6.is_loopback() || v6.is_unspecified() {
                return Space::Loopback;
            }
            let s0 = v6.segments()[0];
            if (s0 & 0xfe00) == 0xfc00 || (s0 & 0xffc0) == 0xfe80 || (s0 & 0xffc0) == 0xfec0 {
                Space::Local // unique-local, link-local, (deprecated) site-local
            } else {
                Space::Public
            }
        }
    }
}

/// Suffixes that only exist on local networks.
pub const LOCAL_SUFFIXES: [&str; 6] = ["local", "lan", "home", "home.arpa", "internal", "localdomain"];

fn clean(host: &str) -> String {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// An IP literal in a URL host (with or without brackets).
pub fn literal(host: &str) -> Option<IpAddr> {
    clean(host).parse().ok()
}

/// A name that is local by its text alone.
pub fn is_local_name(host: &str) -> bool {
    let h = clean(host);
    if h.is_empty() || literal(&h).is_some() {
        return false;
    }
    h == "localhost"
        || h.ends_with(".localhost")
        || !h.contains('.')
        || LOCAL_SUFFIXES.iter().any(|s| h.ends_with(&format!(".{s}")))
}

/// Where a host is, when its text says so; `None` for a public name (DNS decides).
pub fn host_space(host: &str) -> Option<Space> {
    let h = clean(host);
    if let Some(ip) = literal(&h) {
        return Some(ip_space(ip));
    }
    if h == "localhost" || h.ends_with(".localhost") {
        return Some(Space::Loopback);
    }
    is_local_name(&h).then_some(Space::Local)
}

/// Where a page lives, for deciding whether its requests may reach the local network: public
/// unless its host is loopback or local by text.
pub fn page_space(host: &str) -> Space {
    host_space(host).unwrap_or(Space::Public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_classified_like_local_network_access() {
        let s = |t: &str| ip_space(t.parse().unwrap());
        for l in ["127.0.0.1", "127.9.9.9", "0.0.0.0", "::1", "::", "::ffff:127.0.0.1"] {
            assert_eq!(s(l), Space::Loopback, "{l}");
        }
        for l in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.26",
            "169.254.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.0.1",
        ] {
            assert_eq!(s(l), Space::Local, "{l}");
        }
        for p in [
            "8.8.8.8",
            "172.32.0.1",
            "172.15.0.1",
            "100.128.0.1",
            "2606:4700::1111",
            "9.9.9.9",
        ] {
            assert_eq!(s(p), Space::Public, "{p}");
        }
    }

    #[test]
    fn names_are_local_only_when_their_text_says_so() {
        assert_eq!(host_space("localhost"), Some(Space::Loopback));
        assert_eq!(host_space("app.localhost"), Some(Space::Loopback));
        assert_eq!(host_space("[::1]"), Some(Space::Loopback));
        assert_eq!(host_space("192.168.1.1"), Some(Space::Local));
        for l in [
            "nas",
            "printer.local",
            "router.lan",
            "box.home.arpa",
            "svc.internal",
            "NAS.Local.",
        ] {
            assert_eq!(host_space(l), Some(Space::Local), "{l}");
        }
        for p in ["example.com", "local.example.com", "lan.example.org", "8.8.8.8"] {
            assert_ne!(host_space(p), Some(Space::Local), "{p}");
        }
        assert_eq!(host_space("example.com"), None);
        assert_eq!(page_space("example.com"), Space::Public);
        assert!(!is_local_name("10.0.0.1"));
    }
}
