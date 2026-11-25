//! Name resolution for the proxy (D-023, D-024, D-041), through the Windows DNS client:
//! `DnsQueryEx` with a DNS-over-HTTPS custom server, or the ordinary Windows resolver.
//!
//! - **Automatic**: if a DNS server Windows uses has a known DNS-over-HTTPS address (Windows'
//!   own list, or the adapter's setting), names are resolved over HTTPS with that same server.
//!   Otherwise, or if that fails, the Windows resolver answers (which follows any encryption
//!   the user set in Windows).
//! - **Strict**: only the chosen provider, over HTTPS. If it fails, the name is not resolved.
//!
//! In both modes, names that exist only on the local network (`*.local`, `*.lan`, names
//! without a dot …) go to the Windows resolver: public providers cannot answer them.
//! Answers are cached in memory for this session, within the record's TTL (30 s – 5 min).

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use serde::Serialize;
use windows::{
    Win32::NetworkManagement::Dns::*,
    core::{PCWSTR, PWSTR},
};

use crate::{addr, diag};

/// Providers offered for "Strict" (D-041). Templates and addresses as each provider publishes
/// them for unfiltered resolution.
pub struct Provider {
    pub id: &'static str,
    pub name: &'static str,
    pub template: &'static str,
    pub addresses: &'static [&'static str],
}

pub const PROVIDERS: [Provider; 3] = [
    Provider {
        id: "quad9",
        name: "Quad9",
        template: "https://dns.quad9.net/dns-query",
        addresses: &["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
    },
    Provider {
        id: "cloudflare",
        name: "Cloudflare",
        template: "https://cloudflare-dns.com/dns-query",
        addresses: &["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
    },
    Provider {
        id: "mullvad",
        name: "Mullvad",
        template: "https://dns.mullvad.net/dns-query",
        addresses: &["194.242.2.2", "2a07:e340::2"],
    },
];

pub fn provider(id: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.id == id)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohServer {
    pub address: IpAddr,
    pub template: String,
}

impl Provider {
    pub fn servers(&self) -> Vec<DohServer> {
        self.addresses
            .iter()
            .filter_map(|a| a.parse().ok())
            .map(|address| DohServer {
                address,
                template: self.template.to_string(),
            })
            .collect()
    }
}

/// Check a custom DNS-over-HTTPS server: an `https://` template with a host and path, and an
/// IP address to reach it (Windows needs both; the host name is not looked up).
pub fn custom_server(template: &str, address: &str) -> Result<DohServer, String> {
    let t = template.trim();
    let rest = t
        .strip_prefix("https://")
        .ok_or("The address must start with https://")?;
    let (host, path) = rest
        .split_once('/')
        .ok_or("The address needs a path, such as /dns-query")?;
    if host.is_empty() || path.is_empty() || t.len() > 512 || t.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("This is not a valid DNS-over-HTTPS address.".into());
    }
    let ip: IpAddr = address
        .trim()
        .parse()
        .map_err(|_| "The server's IP address is not valid.".to_string())?;
    if addr::ip_space(ip) == addr::Space::Loopback {
        return Err("The server cannot be on this computer.".into());
    }
    Ok(DohServer {
        address: ip,
        template: t.to_string(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Automatic,
    Strict { name: String, servers: Vec<DohServer> },
}

/// How a name was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// An IP address, nothing to resolve.
    Literal,
    /// DNS over HTTPS.
    Encrypted,
    /// The Windows resolver (encrypted only if Windows is set to encrypt).
    Windows,
    /// SELF-CHECK ONLY: an address given by the self-check.
    Test,
}

#[derive(Debug, Clone)]
pub struct Answer {
    pub addrs: Vec<IpAddr>,
    pub via: Via,
    /// Host of the DNS-over-HTTPS address used (e.g. "dns.quad9.net").
    pub server: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    NotFound,
    Failed(String),
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolverStats {
    pub encrypted: u64,
    pub windows: u64,
    pub cached: u64,
    pub failed: u64,
    /// Automatic mode: encrypted lookups that failed and were answered by Windows instead.
    pub fallbacks: u64,
}

struct Entry {
    answer: Answer,
    expires: Instant,
}

const MIN_TTL: u32 = 30;
const MAX_TTL: u32 = 300;
const MAX_CACHE: usize = 4096;
const PLAN_AGE: Duration = Duration::from_secs(30);

pub struct Resolver {
    mode: RwLock<Mode>,
    cache: Mutex<HashMap<String, Entry>>,
    plan: Mutex<Option<(Instant, Vec<DohServer>)>>,
    test: RwLock<HashMap<String, Vec<IpAddr>>>,
    encrypted: AtomicU64,
    windows: AtomicU64,
    cached: AtomicU64,
    failed: AtomicU64,
    fallbacks: AtomicU64,
}

fn template_host(t: &str) -> Option<String> {
    t.strip_prefix("https://")
        .and_then(|r| r.split(['/', ':']).next())
        .map(str::to_string)
}

impl Resolver {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode: RwLock::new(mode),
            cache: Mutex::new(HashMap::new()),
            plan: Mutex::new(None),
            test: RwLock::new(HashMap::new()),
            encrypted: AtomicU64::new(0),
            windows: AtomicU64::new(0),
            cached: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode.read().unwrap().clone()
    }

    /// Switch mode; cached answers from the old mode are dropped.
    pub fn set_mode(&self, mode: Mode) {
        *self.mode.write().unwrap() = mode;
        self.cache.lock().unwrap().clear();
        *self.plan.lock().unwrap() = None;
    }

    /// Drop every cached answer (memory-only data).
    pub fn clear_cache(&self) {
        self.cache.lock().unwrap().clear();
    }

    pub fn cache_len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// SELF-CHECK ONLY: answer these names with these addresses, without any lookup.
    pub fn set_test_hosts(&self, hosts: HashMap<String, Vec<IpAddr>>) {
        *self.test.write().unwrap() = hosts;
    }

    /// SELF-CHECK ONLY: is this name answered by the self-check's table?
    pub fn has_test_host(&self, host: &str) -> bool {
        let t = self.test.read().unwrap();
        !t.is_empty() && t.contains_key(&host.trim_end_matches('.').to_ascii_lowercase())
    }

    pub fn stats(&self) -> ResolverStats {
        ResolverStats {
            encrypted: self.encrypted.load(Ordering::Relaxed),
            windows: self.windows.load(Ordering::Relaxed),
            cached: self.cached.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            fallbacks: self.fallbacks.load(Ordering::Relaxed),
        }
    }

    /// The servers "Automatic" would use right now (empty: the Windows resolver).
    pub fn automatic_servers(&self) -> Vec<DohServer> {
        let mut plan = self.plan.lock().unwrap();
        if let Some((at, servers)) = plan.as_ref()
            && at.elapsed() < PLAN_AGE
        {
            return servers.clone();
        }
        let servers: Vec<DohServer> = diag::system_dns_servers(&diag::adapters())
            .into_iter()
            .filter_map(|s| {
                Some(DohServer {
                    address: s.address.parse().ok()?,
                    template: s.doh_template?,
                })
            })
            .collect();
        *plan = Some((Instant::now(), servers.clone()));
        servers
    }

    pub fn resolve(&self, host: &str) -> Result<Answer, ResolveError> {
        if let Some(ip) = addr::literal(host) {
            return Ok(Answer {
                addrs: vec![ip],
                via: Via::Literal,
                server: None,
            });
        }
        let name = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(a) = self.test.read().unwrap().get(&name) {
            return Ok(Answer {
                addrs: a.clone(),
                via: Via::Test,
                server: None,
            });
        }
        if let Some(e) = self.cache.lock().unwrap().get(&name)
            && e.expires > Instant::now()
        {
            self.cached.fetch_add(1, Ordering::Relaxed);
            return Ok(e.answer.clone());
        }
        let result = if addr::is_local_name(&name) {
            self.via_windows(&name)
        } else {
            match self.mode() {
                Mode::Strict { servers, .. } => self.via_doh(&name, &servers),
                Mode::Automatic => {
                    let servers = self.automatic_servers();
                    if servers.is_empty() {
                        self.via_windows(&name)
                    } else {
                        match self.via_doh(&name, &servers) {
                            Err(ResolveError::Failed(_)) => {
                                self.fallbacks.fetch_add(1, Ordering::Relaxed);
                                self.via_windows(&name)
                            }
                            other => other,
                        }
                    }
                }
            }
        };
        match result {
            Ok((answer, ttl)) => {
                let mut c = self.cache.lock().unwrap();
                if c.len() >= MAX_CACHE {
                    let now = Instant::now();
                    c.retain(|_, e| e.expires > now);
                    if c.len() >= MAX_CACHE {
                        c.clear();
                    }
                }
                c.insert(
                    name,
                    Entry {
                        answer: answer.clone(),
                        expires: Instant::now() + Duration::from_secs(u64::from(ttl.clamp(MIN_TTL, MAX_TTL))),
                    },
                );
                Ok(answer)
            }
            Err(e) => {
                self.failed.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    fn via_doh(&self, name: &str, servers: &[DohServer]) -> Result<(Answer, u32), ResolveError> {
        if servers.is_empty() {
            // Without a server, DnsQueryEx would use the ordinary resolver: never let that happen.
            return Err(ResolveError::Failed("no encrypted DNS server is set".into()));
        }
        let r = lookup(name, Some(servers));
        if r.is_ok() {
            self.encrypted.fetch_add(1, Ordering::Relaxed);
        }
        r.map(|(addrs, ttl)| {
            (
                Answer {
                    addrs,
                    via: Via::Encrypted,
                    server: servers.first().and_then(|s| template_host(&s.template)),
                },
                ttl,
            )
        })
    }

    fn via_windows(&self, name: &str) -> Result<(Answer, u32), ResolveError> {
        let r = lookup(name, None);
        if r.is_ok() {
            self.windows.fetch_add(1, Ordering::Relaxed);
        }
        r.map(|(addrs, ttl)| {
            (
                Answer {
                    addrs,
                    via: Via::Windows,
                    server: None,
                },
                ttl,
            )
        })
    }
}

const NAME_ERROR: u32 = 9003; // DNS_ERROR_RCODE_NAME_ERROR
const NO_RECORDS: u32 = 9501; // DNS_INFO_NO_RECORDS

/// A and AAAA in parallel; addresses with IPv6 first when both exist.
fn lookup(name: &str, servers: Option<&[DohServer]>) -> Result<(Vec<IpAddr>, u32), ResolveError> {
    let (a, aaaa) = std::thread::scope(|s| {
        let h = s.spawn(|| query(name, DNS_TYPE_AAAA.0, servers));
        let a = query(name, DNS_TYPE_A.0, servers);
        (a, h.join().unwrap_or(Err(1)))
    });
    let mut addrs = Vec::new();
    let mut ttl = u32::MAX;
    for (list, t) in [&aaaa, &a].into_iter().flatten() {
        addrs.extend(list.iter().copied());
        ttl = ttl.min(*t);
    }
    if !addrs.is_empty() {
        return Ok((addrs, if ttl == u32::MAX { MIN_TTL } else { ttl }));
    }
    let gone = |r: &Result<(Vec<IpAddr>, u32), u32>| matches!(r, Err(NAME_ERROR | NO_RECORDS) | Ok(_));
    if gone(&a) && gone(&aaaa) {
        Err(ResolveError::NotFound)
    } else {
        let code = a.err().or(aaaa.err()).unwrap_or(0);
        Err(ResolveError::Failed(format!("DNS error {code}")))
    }
}

/// One synchronous `DnsQueryEx`. With `servers`, only over HTTPS to those servers (no UDP
/// fallback, port 0 as Windows requires).
fn query(name: &str, qtype: u16, servers: Option<&[DohServer]>) -> Result<(Vec<IpAddr>, u32), u32> {
    let qname: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let templates: Vec<Vec<u16>> = servers
        .unwrap_or(&[])
        .iter()
        .map(|s| s.template.encode_utf16().chain(Some(0)).collect())
        .collect();
    let mut custom: Vec<DNS_CUSTOM_SERVER> = servers
        .unwrap_or(&[])
        .iter()
        .zip(&templates)
        .map(|(s, t)| {
            let mut c = DNS_CUSTOM_SERVER {
                dwServerType: DNS_CUSTOM_SERVER_TYPE_DOH,
                ullFlags: 0, // no fallback to unencrypted UDP
                ..Default::default()
            };
            c.Anonymous1.pwszTemplate = PWSTR(t.as_ptr() as *mut u16);
            let mut sa = [0u8; 32];
            match s.address {
                IpAddr::V4(v4) => {
                    sa[0..2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET, port 0
                    sa[4..8].copy_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    sa[0..2].copy_from_slice(&23u16.to_le_bytes()); // AF_INET6, port 0
                    sa[8..24].copy_from_slice(&v6.octets());
                }
            }
            c.Anonymous2.MaxSa = sa.map(|b| b as i8);
            c
        })
        .collect();
    let req = DNS_QUERY_REQUEST3 {
        Version: DNS_QUERY_REQUEST_VERSION3.0,
        QueryName: PCWSTR(qname.as_ptr()),
        QueryType: qtype,
        QueryOptions: u64::from(DNS_QUERY_STANDARD.0),
        cCustomServers: custom.len() as u32,
        pCustomServers: if custom.is_empty() {
            std::ptr::null_mut()
        } else {
            custom.as_mut_ptr()
        },
        ..Default::default()
    };
    let mut res = DNS_QUERY_RESULT {
        Version: DNS_QUERY_RESULTS_VERSION1.0,
        ..Default::default()
    };
    // SAFETY: the request and every string and server it points to live until the call
    // returns (synchronous: no completion callback). Records are freed below.
    let status = unsafe {
        DnsQueryEx(
            &req as *const DNS_QUERY_REQUEST3 as *const DNS_QUERY_REQUEST,
            &mut res,
            None,
        )
    } as u32;
    let mut addrs = Vec::new();
    let mut ttl = u32::MAX;
    // SAFETY: Windows returns a list of wide-string records for a wide-string query.
    unsafe {
        let mut p = res.pQueryRecords as *const DNS_RECORDW;
        while !p.is_null() {
            let r = &*p;
            if r.wType == DNS_TYPE_A.0 && qtype == DNS_TYPE_A.0 {
                addrs.push(IpAddr::from(r.Data.A.IpAddress.to_le_bytes()));
                ttl = ttl.min(r.dwTtl);
            } else if r.wType == DNS_TYPE_AAAA.0 && qtype == DNS_TYPE_AAAA.0 {
                addrs.push(IpAddr::from(r.Data.AAAA.Ip6Address.IP6Byte));
                ttl = ttl.min(r.dwTtl);
            }
            p = r.pNext;
        }
        if !res.pQueryRecords.is_null() {
            DnsFree(Some(res.pQueryRecords as *const _), DnsFreeRecordList);
        }
    }
    drop(custom);
    if status != 0 {
        return Err(status);
    }
    if addrs.is_empty() {
        return Err(NO_RECORDS);
    }
    Ok((addrs, ttl))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_and_custom_servers_are_checked() {
        for p in &PROVIDERS {
            assert!(p.template.starts_with("https://"));
            assert_eq!(p.servers().len(), p.addresses.len(), "{}", p.id);
        }
        assert!(provider("quad9").is_some() && provider("google").is_none());
        let s = custom_server(" https://dns.example/dns-query ", "203.0.113.7").unwrap();
        assert_eq!(s.template, "https://dns.example/dns-query");
        assert!(custom_server("http://dns.example/dns-query", "203.0.113.7").is_err());
        assert!(custom_server("https://dns.example", "203.0.113.7").is_err());
        assert!(custom_server("https://dns.example/q", "dns.example").is_err());
        assert!(custom_server("https://dns.example/q", "127.0.0.1").is_err());
        assert!(custom_server("https://dns.example/q x", "203.0.113.7").is_err());
    }

    #[test]
    fn literals_test_names_and_local_names_never_reach_a_provider() {
        // A Strict resolver pointed at an unroutable test address: any lookup it made would fail.
        let r = Resolver::new(Mode::Strict {
            name: "test".into(),
            servers: vec![DohServer {
                address: "192.0.2.1".parse().unwrap(),
                template: "https://192.0.2.1/dns-query".into(),
            }],
        });
        let a = r.resolve("192.168.1.1").unwrap();
        assert_eq!((a.via, a.addrs.len()), (Via::Literal, 1));
        assert_eq!(r.resolve("[::1]").unwrap().via, Via::Literal);
        r.set_test_hosts([("t.untrace.invalid".to_string(), vec!["127.0.0.1".parse().unwrap()])].into());
        assert_eq!(r.resolve("T.untrace.invalid.").unwrap().via, Via::Test);
        // "localhost" is a local name: the Windows resolver answers, not the provider.
        let l = r.resolve("localhost").unwrap();
        assert_eq!(l.via, Via::Windows);
        assert!(l.addrs.iter().all(|ip| addr::ip_space(*ip) == addr::Space::Loopback));
        assert_eq!(r.stats().encrypted, 0);
        // Strict with no server fails closed instead of using the Windows resolver.
        let empty = Resolver::new(Mode::Strict {
            name: "custom".into(),
            servers: vec![],
        });
        assert!(matches!(empty.resolve("example.com"), Err(ResolveError::Failed(_))));
        assert_eq!(empty.stats().windows, 0);
    }
}
