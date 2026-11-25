//! Read-only DNS facts about this computer, for Diagnostics and for "Automatic" mode (D-023).
//! Nothing here changes Windows settings.
//!
//! - Network adapters that are up, and the DNS servers Windows uses on them
//!   (`GetAdaptersAddresses`).
//! - Windows' own table of DNS servers with a known DNS-over-HTTPS address
//!   (`Dnscache\Parameters\DohWellKnownServers`).
//! - Whether the user turned on Windows' DNS encryption for a server on an adapter
//!   (`Dnscache\InterfaceSpecificParameters\<adapter>\DohInterfaceSettings`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;
use windows::{
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
        NetworkManagement::{IpHelper::*, Ndis::IfOperStatusUp},
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6},
        System::Registry::*,
    },
    core::HSTRING,
};

const DNSCACHE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsServer {
    pub address: String,
    /// Windows' DNS-over-HTTPS address for this server, if Windows knows one.
    pub doh_template: Option<String>,
    /// Where that address comes from: "windows_list" or "adapter_setting".
    pub doh_template_source: Option<&'static str>,
    /// The user turned on Windows' own DNS encryption for this server on this adapter.
    pub windows_encryption_set: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Adapter {
    pub name: String,
    /// Has a default gateway: the adapter that reaches the internet.
    pub has_gateway: bool,
    pub dns_servers: Vec<DnsServer>,
    #[serde(skip)]
    pub guid: String,
}

fn sockaddr_ip(sa: *const SOCKADDR) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: Windows returns a SOCKADDR of the family it names, valid while the buffer lives.
    unsafe {
        match (*sa).sa_family {
            AF_INET => {
                let v4 = &*(sa as *const SOCKADDR_IN);
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.S_un.S_addr))))
            }
            AF_INET6 => {
                let v6 = &*(sa as *const SOCKADDR_IN6);
                Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)))
            }
            _ => None,
        }
    }
}

/// Deprecated site-local addresses Windows lists when an adapter has no IPv6 DNS server.
fn placeholder(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfec0)
}

fn reg_string(path: &str, value: &str) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: valid strings and a writable buffer of `size` bytes.
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &HSTRING::from(path),
            &HSTRING::from(value),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if r != ERROR_SUCCESS {
        return None;
    }
    let len = (size as usize / 2).saturating_sub(1).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]))
        .map(|s| s.trim_end_matches('\0').to_string())
        .filter(|s| !s.is_empty())
}

fn reg_number(path: &str, value: &str) -> Option<u64> {
    let mut q = 0u64;
    let mut size = 8u32;
    // SAFETY: an 8-byte writable buffer; DWORD or QWORD accepted.
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &HSTRING::from(path),
            &HSTRING::from(value),
            RRF_RT_DWORD | RRF_RT_QWORD,
            None,
            Some((&mut q as *mut u64).cast()),
            Some(&mut size),
        )
    };
    (r == ERROR_SUCCESS).then_some(if size == 4 { q & 0xffff_ffff } else { q })
}

/// Windows' list of DNS servers with a known DNS-over-HTTPS template.
pub fn known_template(ip: &IpAddr) -> Option<String> {
    reg_string(&format!(r"{DNSCACHE}\Parameters\DohWellKnownServers\{ip}"), "Template")
        .filter(|t| t.starts_with("https://"))
}

fn adapter_setting(guid: &str, ip: &IpAddr) -> (Option<String>, bool) {
    let family = if ip.is_ipv4() { "Doh" } else { "Doh6" };
    let key = format!(r"{DNSCACHE}\InterfaceSpecificParameters\{guid}\DohInterfaceSettings\{family}\{ip}");
    let template = reg_string(&key, "DohTemplate").filter(|t| t.starts_with("https://"));
    let flags = reg_number(&key, "DohFlags").unwrap_or(0);
    (template, flags != 0)
}

/// Adapters that are up, with their DNS servers (read-only).
pub fn adapters() -> Vec<Adapter> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS;
    let mut size = 32 * 1024u32;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..3 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: an 8-byte aligned buffer of `size` bytes.
        let r = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buf.as_mut_ptr().cast()),
                &mut size,
            )
        };
        if r == ERROR_SUCCESS.0 {
            break;
        }
        if r != ERROR_BUFFER_OVERFLOW.0 {
            return Vec::new();
        }
    }
    let mut out = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: walking the linked list Windows wrote into `buf`, which outlives the loop.
    unsafe {
        while !p.is_null() {
            let a = &*p;
            p = a.Next;
            if a.OperStatus != IfOperStatusUp || a.IfType == 24 {
                continue; // down, or the software loopback interface
            }
            let name = a.FriendlyName.to_string().unwrap_or_default();
            let guid = if a.AdapterName.is_null() {
                String::new()
            } else {
                a.AdapterName.to_string().unwrap_or_default()
            };
            let mut servers = Vec::new();
            let mut d = a.FirstDnsServerAddress;
            while !d.is_null() {
                if let Some(ip) = sockaddr_ip((*d).Address.lpSockaddr)
                    && !placeholder(&ip)
                    && !servers.iter().any(|s: &DnsServer| s.address == ip.to_string())
                {
                    let (adapter_template, encrypt) = adapter_setting(&guid, &ip);
                    let (template, source) = match (adapter_template, known_template(&ip)) {
                        (Some(t), _) => (Some(t), Some("adapter_setting")),
                        (None, Some(t)) => (Some(t), Some("windows_list")),
                        _ => (None, None),
                    };
                    servers.push(DnsServer {
                        address: ip.to_string(),
                        doh_template: template,
                        doh_template_source: source,
                        windows_encryption_set: encrypt,
                    });
                }
                d = (*d).Next;
            }
            if servers.is_empty() {
                continue;
            }
            out.push(Adapter {
                name,
                has_gateway: !a.FirstGatewayAddress.is_null(),
                dns_servers: servers,
                guid,
            });
        }
    }
    out
}

/// DNS servers Windows uses for the internet: those of adapters with a default gateway (all
/// adapters if none has one), in order, without repeats.
pub fn system_dns_servers(adapters: &[Adapter]) -> Vec<DnsServer> {
    let any_gateway = adapters.iter().any(|a| a.has_gateway);
    let mut out: Vec<DnsServer> = Vec::new();
    for a in adapters.iter().filter(|a| a.has_gateway || !any_gateway) {
        for s in &a.dns_servers {
            if !out.iter().any(|o| o.address == s.address) {
                out.push(s.clone());
            }
        }
    }
    out
}

/// Windows' global DNS-over-HTTPS policy values, as stored (`None` when not set).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsDohPolicy {
    /// `Dnscache\Parameters\EnableAutoDoh`.
    pub enable_auto_doh: Option<u64>,
    /// Group Policy "Configure DNS over HTTPS (DoH) name resolution" (1 prohibit, 2 allow, 3 require).
    pub group_policy: Option<u64>,
}

pub fn windows_policy() -> WindowsDohPolicy {
    WindowsDohPolicy {
        enable_auto_doh: reg_number(&format!(r"{DNSCACHE}\Parameters"), "EnableAutoDoh"),
        group_policy: reg_number(r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "DoHPolicy"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_this_computers_dns_setup_without_failing() {
        let a = adapters();
        // Every listed server is a parseable address and every template is https.
        for ad in &a {
            for s in &ad.dns_servers {
                assert!(s.address.parse::<IpAddr>().is_ok());
                assert!(s.doh_template.as_deref().is_none_or(|t| t.starts_with("https://")));
            }
        }
        let _ = system_dns_servers(&a);
        let _ = windows_policy();
        // Windows 11 ships Quad9 in its list.
        assert_eq!(
            known_template(&"9.9.9.9".parse().unwrap()).as_deref(),
            Some("https://dns.quad9.net/dns-query")
        );
    }
}
