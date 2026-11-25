//! The loopback proxy the content engine is pointed at (D-006, D-025, D-026, D-040, D-042).
//!
//! - Listens on `127.0.0.1:<random port>` only, and serves only clients that present this
//!   launch's random credentials (WebView2 supplies them through `BasicAuthenticationRequested`).
//!   Everything else, including the runtime's own background traffic, gets `407` and nothing
//!   more (D-025).
//! - `CONNECT host:port` tunnels (HTTPS, WebSockets) are blind byte copies: no TLS
//!   interception, ever (D-007). Absolute-form `http://` requests are forwarded once, with
//!   `Connection: close`.
//! - Names are resolved by [`Resolver`] (encrypted DNS); the engine resolves nothing itself.
//! - Backstop (D-042): hosts on the malware/phishing lists are refused unless the user chose
//!   "Continue anyway" for them this session.
//! - DNS-rebinding guard (D-040): a public name that resolves to a loopback or local-network
//!   address is refused unless UNTRACE announced it (the user opened it, or a site the user
//!   allowed asked for it), and never after it resolved to a public address this session.
//! - Keeps an in-memory record of hosts contacted this session (connection view); nothing is
//!   written to disk.

use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use untrace_filter::{ListId, engine::Threats};

use crate::{
    addr,
    http::{self, Target},
    rand,
    resolver::{Mode, ResolveError, Resolver, ResolverStats, Via},
};

/// Suffix of names UNTRACE uses for its own checks; never resolved, always refused.
pub const CHECK_SUFFIX: &str = ".untrace.invalid";
const MAX_ACTIVE: usize = 1024;
const MAX_HOSTS: usize = 2000;
const MAX_NAMES: usize = 4096;
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const STAGGER: Duration = Duration::from_millis(250);

/// What the proxy knows about one host this session (memory only).
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostRecord {
    pub host: String,
    /// Connections opened for the engine (with its credentials).
    pub connections: u32,
    /// Requests that carried this launch's credentials, whatever happened next.
    pub authenticated: u32,
    /// Of those, plain-HTTP requests (absolute form), as opposed to tunnels.
    pub plain_http: u32,
    /// Attempts without credentials (the runtime's background traffic, D-025; also the
    /// engine's first try before it is asked for them).
    pub refused_unauthenticated: u32,
    /// Refused because the host is on a malware or phishing list.
    pub blocked_threat: u32,
    pub threat_list: Option<ListId>,
    /// Refused by the DNS-rebinding guard.
    pub blocked_local: u32,
    pub failed: u32,
    pub via: Option<Via>,
    /// DNS-over-HTTPS server that resolved it, if encrypted.
    pub dns_server: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStats {
    pub port: u16,
    pub connections: u64,
    pub active: usize,
    pub refused_unauthenticated: u64,
    pub blocked_threats: u64,
    pub blocked_local: u64,
    pub failed: u64,
    pub malformed: u64,
    /// Hosts beyond the record limit (counted, not listed).
    pub hosts_not_listed: u64,
    pub resolver: ResolverStats,
    pub dns_cache_entries: usize,
}

#[derive(Default)]
struct Names {
    allowed_local: HashSet<String>,
    public: HashSet<String>,
}

struct Shared {
    expected: String,
    realm: String,
    resolver: Resolver,
    threats: RwLock<Arc<Threats>>,
    threat_exceptions: Mutex<HashSet<String>>,
    local_guard: AtomicBool,
    names: Mutex<Names>,
    hosts: Mutex<HashMap<String, HostRecord>>,
    probes: Mutex<HashSet<String>>,
    paused: AtomicBool,
    stopped: AtomicBool,
    active: AtomicUsize,
    connections: AtomicU64,
    unauthenticated: AtomicU64,
    blocked_threats: AtomicU64,
    blocked_local: AtomicU64,
    failed: AtomicU64,
    malformed: AtomicU64,
    unlisted: AtomicU64,
}

/// A running proxy. Cheap to clone; the listener lives until [`Proxy::stop`] or process exit.
#[derive(Clone)]
pub struct Proxy {
    port: u16,
    user: String,
    pass: String,
    shared: Arc<Shared>,
}

/// The rebinding guard's decision for a public name (pure, for tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDecision {
    Allow,
    /// It resolved to a public address earlier this session (DNS rebinding).
    RefuseChanged,
    /// A public name pointing into the local network that nobody announced.
    RefuseUnannounced,
}

pub fn local_decision(addrs: &[IpAddr], announced: bool, was_public: bool) -> LocalDecision {
    if !addrs.iter().any(|ip| addr::ip_space(*ip).is_local()) {
        return LocalDecision::Allow;
    }
    if was_public {
        LocalDecision::RefuseChanged
    } else if announced {
        LocalDecision::Allow
    } else {
        LocalDecision::RefuseUnannounced
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Proxy {
    /// Start listening on a random loopback port.
    pub fn start(mode: Mode) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let user = format!("u{}", rand::token(8));
        let pass = rand::token(24);
        let shared = Arc::new(Shared {
            expected: format!("Basic {}", rand::base64(format!("{user}:{pass}").as_bytes())),
            realm: format!("UNTRACE-{}", rand::token(8)),
            resolver: Resolver::new(mode),
            threats: RwLock::new(Arc::new(Threats::default())),
            threat_exceptions: Mutex::new(HashSet::new()),
            local_guard: AtomicBool::new(true),
            names: Mutex::new(Names::default()),
            hosts: Mutex::new(HashMap::new()),
            probes: Mutex::new(HashSet::new()),
            paused: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            connections: AtomicU64::new(0),
            unauthenticated: AtomicU64::new(0),
            blocked_threats: AtomicU64::new(0),
            blocked_local: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            unlisted: AtomicU64::new(0),
        });
        let s = shared.clone();
        thread::Builder::new().name("untrace-proxy".into()).spawn(move || {
            for c in listener.incoming() {
                if s.stopped.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(c) = c else { continue };
                if s.active.load(Ordering::SeqCst) >= MAX_ACTIVE {
                    let mut c = c;
                    let _ = c.write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    continue;
                }
                let s = s.clone();
                s.active.fetch_add(1, Ordering::SeqCst);
                let spawned = thread::Builder::new()
                    .name("untrace-proxy-conn".into())
                    .stack_size(256 * 1024)
                    .spawn({
                        let s = s.clone();
                        move || {
                            serve(c, &s);
                            s.active.fetch_sub(1, Ordering::SeqCst);
                        }
                    });
                if spawned.is_err() {
                    s.active.fetch_sub(1, Ordering::SeqCst);
                }
            }
        })?;
        Ok(Self {
            port,
            user,
            pass,
            shared,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// This launch's credentials (given to the engine only).
    pub fn credentials(&self) -> (&str, &str) {
        (&self.user, &self.pass)
    }

    /// The realm in this proxy's challenge: tells a proxy challenge from a site's.
    pub fn realm(&self) -> &str {
        &self.shared.realm
    }

    /// Browser arguments that send every request of the content engine through this proxy,
    /// loopback included (`<-loopback>`), so the engine never resolves a name or connects
    /// anywhere itself.
    pub fn browser_arguments(&self) -> String {
        format!(
            "--proxy-server=http://127.0.0.1:{} --proxy-bypass-list=<-loopback>",
            self.port
        )
    }

    pub fn resolver(&self) -> &Resolver {
        &self.shared.resolver
    }

    pub fn set_mode(&self, mode: Mode) {
        self.shared.resolver.set_mode(mode);
    }

    /// The malware/phishing host sets in use (swapped when lists change).
    pub fn set_threats(&self, threats: Arc<Threats>) {
        *self.shared.threats.write().unwrap() = threats;
    }

    /// "Continue anyway" for a host, this session (D-033).
    pub fn allow_threat_host(&self, host: &str) {
        self.shared
            .threat_exceptions
            .lock()
            .unwrap()
            .insert(host.to_ascii_lowercase());
    }

    pub fn set_local_guard(&self, on: bool) {
        self.shared.local_guard.store(on, Ordering::SeqCst);
    }

    pub fn local_guard(&self) -> bool {
        self.shared.local_guard.load(Ordering::SeqCst)
    }

    /// The user opened this name, or a site allowed to reach the local network asked for it:
    /// it may resolve to a local address (unless it was public before, D-040).
    pub fn announce_local(&self, host: &str) {
        if addr::host_space(host).is_some() {
            return; // literals and local names are not the guard's business
        }
        let mut n = self.shared.names.lock().unwrap();
        if n.allowed_local.len() < MAX_NAMES {
            n.allowed_local.insert(host.to_ascii_lowercase());
        }
    }

    /// SELF-CHECK ONLY: refuse every connection without answering (simulates a dead proxy).
    pub fn set_paused(&self, paused: bool) {
        self.shared.paused.store(paused, Ordering::SeqCst);
    }

    /// A fresh check name. When the engine asks for it with credentials, [`Proxy::probe_seen`]
    /// turns true: proof that its requests reach this proxy.
    pub fn new_probe(&self) -> String {
        format!("netcheck-{}{CHECK_SUFFIX}", rand::token(8))
    }

    pub fn probe_seen(&self, name: &str) -> bool {
        self.shared.probes.lock().unwrap().contains(&name.to_ascii_lowercase())
    }

    pub fn record(&self, host: &str) -> Option<HostRecord> {
        self.shared
            .hosts
            .lock()
            .unwrap()
            .get(&host.to_ascii_lowercase())
            .cloned()
    }

    /// Hosts contacted (or refused) this session.
    pub fn hosts(&self) -> Vec<HostRecord> {
        let mut v: Vec<HostRecord> = self.shared.hosts.lock().unwrap().values().cloned().collect();
        v.sort_by(|a, b| a.host.cmp(&b.host));
        v
    }

    /// Forget the connection record and cached DNS answers (memory-only data).
    pub fn clear_records(&self) {
        self.shared.hosts.lock().unwrap().clear();
        self.shared.resolver.clear_cache();
    }

    pub fn stats(&self) -> ProxyStats {
        let s = &self.shared;
        ProxyStats {
            port: self.port,
            connections: s.connections.load(Ordering::Relaxed),
            active: s.active.load(Ordering::Relaxed),
            refused_unauthenticated: s.unauthenticated.load(Ordering::Relaxed),
            blocked_threats: s.blocked_threats.load(Ordering::Relaxed),
            blocked_local: s.blocked_local.load(Ordering::Relaxed),
            failed: s.failed.load(Ordering::Relaxed),
            malformed: s.malformed.load(Ordering::Relaxed),
            hosts_not_listed: s.unlisted.load(Ordering::Relaxed),
            resolver: s.resolver.stats(),
            dns_cache_entries: s.resolver.cache_len(),
        }
    }

    /// Stop accepting connections (tests and probes; UNTRACE keeps it for the whole session).
    pub fn stop(&self) {
        self.shared.stopped.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], self.port)), Duration::from_secs(1));
    }
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never prints the credentials.
        f.debug_struct("Proxy")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

fn note(s: &Shared, host: &str, f: impl FnOnce(&mut HostRecord)) {
    let mut hosts = s.hosts.lock().unwrap();
    if let Some(r) = hosts.get_mut(host) {
        f(r);
    } else if hosts.len() < MAX_HOSTS {
        let mut r = HostRecord {
            host: host.to_string(),
            ..Default::default()
        };
        f(&mut r);
        hosts.insert(host.to_string(), r);
    } else {
        s.unlisted.fetch_add(1, Ordering::Relaxed);
    }
}

fn reply(c: &mut TcpStream, status: &str, extra: &str) {
    let _ =
        c.write_all(format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
    let _ = c.flush();
}

fn fail(s: &Shared, c: &mut TcpStream, host: &str, why: String) {
    s.failed.fetch_add(1, Ordering::Relaxed);
    note(s, host, |r| {
        r.failed += 1;
        r.last_error = Some(why);
    });
    reply(c, "502 Bad Gateway", "");
}

fn serve(mut c: TcpStream, s: &Shared) {
    if s.paused.load(Ordering::SeqCst) {
        let _ = c.shutdown(Shutdown::Both);
        return;
    }
    let _ = c.set_read_timeout(Some(HEAD_TIMEOUT));
    let _ = c.set_nodelay(true);
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    let end = loop {
        match c.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if let Some(e) = http::head_end(&buf) {
            break e;
        }
        if buf.len() > http::MAX_HEAD {
            s.malformed.fetch_add(1, Ordering::Relaxed);
            reply(&mut c, "431 Request Header Fields Too Large", "");
            return;
        }
    };
    let head = match http::parse(&buf[..end]) {
        Ok(h) => h,
        Err(_) => {
            s.malformed.fetch_add(1, Ordering::Relaxed);
            reply(&mut c, "400 Bad Request", "");
            return;
        }
    };
    let rest = buf[end + 4..].to_vec();
    let host = head.host.clone();
    let authorised = head
        .header("Proxy-Authorization")
        .is_some_and(|v| ct_eq(v.as_bytes(), s.expected.as_bytes()));
    if !authorised {
        s.unauthenticated.fetch_add(1, Ordering::Relaxed);
        note(s, &host, |r| r.refused_unauthenticated += 1);
        reply(
            &mut c,
            "407 Proxy Authentication Required",
            &format!("Proxy-Authenticate: Basic realm=\"{}\"\r\n", s.realm),
        );
        return;
    }
    let plain = head.target != Target::Connect;
    note(s, &host, |r| {
        r.authenticated += 1;
        r.plain_http += u32::from(plain);
    });
    let threat = s.threats.read().unwrap().host(&host);
    if let Some(list) = threat
        && !s.threat_exceptions.lock().unwrap().contains(&host)
    {
        s.blocked_threats.fetch_add(1, Ordering::Relaxed);
        note(s, &host, |r| {
            r.blocked_threat += 1;
            r.threat_list = Some(list);
        });
        reply(&mut c, "403 Forbidden", "");
        return;
    }
    if host.ends_with(CHECK_SUFFIX) && !s.resolver.has_test_host(&host) {
        // UNTRACE's own check names: proof the engine's requests arrive here; never resolved.
        let mut p = s.probes.lock().unwrap();
        if p.len() < MAX_NAMES {
            p.insert(host.clone());
        }
        drop(p);
        reply(&mut c, "403 Forbidden", "");
        return;
    }
    let answer = match s.resolver.resolve(&host) {
        Ok(a) => a,
        Err(ResolveError::NotFound) => {
            return fail(s, &mut c, &host, "The name does not exist (DNS).".into());
        }
        Err(ResolveError::Failed(e)) => {
            let how = match s.resolver.mode() {
                Mode::Strict { name, .. } => {
                    format!("Encrypted DNS ({name}) did not answer ({e}). Strict mode does not fall back.")
                }
                Mode::Automatic => format!("The name could not be resolved ({e})."),
            };
            return fail(s, &mut c, &host, how);
        }
    };
    // D-040: public names that point into the local network.
    if s.local_guard.load(Ordering::SeqCst) && addr::host_space(&host).is_none() {
        let mut n = s.names.lock().unwrap();
        let d = local_decision(&answer.addrs, n.allowed_local.contains(&host), n.public.contains(&host));
        if d == LocalDecision::Allow
            && !answer.addrs.iter().any(|ip| addr::ip_space(*ip).is_local())
            && n.public.len() < MAX_NAMES
        {
            n.public.insert(host.clone());
        }
        drop(n);
        if d != LocalDecision::Allow {
            s.blocked_local.fetch_add(1, Ordering::Relaxed);
            note(s, &host, |r| {
                r.blocked_local += 1;
                r.last_error = Some(match d {
                    LocalDecision::RefuseChanged => "This name first pointed to the internet and now points into your local network (DNS rebinding); UNTRACE refused it.".into(),
                    _ => "This public name points into your local network; UNTRACE refused it.".into(),
                });
            });
            reply(&mut c, "403 Forbidden", "");
            return;
        }
    }
    let Some(mut up) = connect_any(&answer.addrs, head.port) else {
        return fail(s, &mut c, &host, format!("Could not connect to {}.", head.authority()));
    };
    s.connections.fetch_add(1, Ordering::Relaxed);
    note(s, &host, |r| {
        r.connections += 1;
        r.via = Some(answer.via);
        r.dns_server = answer.server.clone();
        r.last_error = None;
    });
    let _ = up.set_nodelay(true);
    match &head.target {
        Target::Connect => {
            if c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
                return;
            }
        }
        Target::Forward { .. } => {
            let Some(fwd) = head.forward_head() else { return };
            if up.write_all(&fwd).is_err() {
                return;
            }
        }
    }
    if !rest.is_empty() && up.write_all(&rest).is_err() {
        return;
    }
    tunnel(c, up);
}

/// Connect to the first address that answers; later addresses start 250 ms apart.
fn connect_any(addrs: &[IpAddr], port: u16) -> Option<TcpStream> {
    // Alternate families so one broken family does not delay the other.
    let (v6, v4): (Vec<IpAddr>, Vec<IpAddr>) = addrs.iter().partition(|ip| ip.is_ipv6());
    let mut order = Vec::new();
    for i in 0..v6.len().max(v4.len()) {
        order.extend(v6.get(i));
        order.extend(v4.get(i));
    }
    order.truncate(6);
    let (tx, rx) = mpsc::channel::<Option<TcpStream>>();
    let total = order.len();
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut failed = 0;
    for ip in order {
        let tx = tx.clone();
        let _ = thread::Builder::new().stack_size(64 * 1024).spawn(move || {
            let _ = tx.send(TcpStream::connect_timeout(&SocketAddr::new(ip, port), CONNECT_TIMEOUT).ok());
        });
        match rx.recv_timeout(STAGGER) {
            Ok(Some(s)) => return Some(s),
            Ok(None) => failed += 1,
            Err(_) => {}
        }
    }
    drop(tx);
    while failed < total {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Some(s)) => return Some(s),
            Ok(None) => failed += 1,
            Err(_) => return None,
        }
    }
    None
}

fn copy(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    let _ = from.shutdown(Shutdown::Read);
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

fn tunnel(c: TcpStream, up: TcpStream) {
    let _ = c.set_read_timeout(None);
    let _ = up.set_read_timeout(None);
    let (Ok(c2), Ok(up2)) = (c.try_clone(), up.try_clone()) else {
        return;
    };
    let t = thread::Builder::new()
        .name("untrace-proxy-copy".into())
        .stack_size(64 * 1024)
        .spawn(move || copy(c2, up2));
    copy(up, c);
    if let Ok(t) = t {
        let _ = t.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;

    fn echo_server() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            for c in l.incoming().flatten() {
                thread::spawn(move || {
                    let mut c = c;
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = c.read(&mut buf) {
                        if n == 0 || c.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    fn ask(port: u16, req: &str) -> (String, TcpStream) {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(req.as_bytes()).unwrap();
        let mut r = std::io::BufReader::new(c.try_clone().unwrap());
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        loop {
            let mut l = String::new();
            if r.read_line(&mut l).unwrap_or(0) == 0 || l == "\r\n" {
                break;
            }
            line.push_str(&l);
        }
        (line, c)
    }

    fn auth(p: &Proxy) -> String {
        let (u, pw) = p.credentials();
        format!(
            "Proxy-Authorization: Basic {}\r\n",
            rand::base64(format!("{u}:{pw}").as_bytes())
        )
    }

    #[test]
    fn rebinding_decisions() {
        let public: Vec<IpAddr> = vec!["93.184.215.14".parse().unwrap()];
        let local: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap()];
        let mixed: Vec<IpAddr> = vec!["93.184.215.14".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        assert_eq!(local_decision(&public, false, false), LocalDecision::Allow);
        assert_eq!(local_decision(&local, false, false), LocalDecision::RefuseUnannounced);
        assert_eq!(local_decision(&mixed, false, false), LocalDecision::RefuseUnannounced);
        assert_eq!(local_decision(&local, true, false), LocalDecision::Allow);
        assert_eq!(local_decision(&local, true, true), LocalDecision::RefuseChanged);
    }

    #[test]
    fn credentials_tunnels_backstop_and_guard() {
        let echo = echo_server();
        let p = Proxy::start(Mode::Automatic).unwrap();
        p.resolver().set_test_hosts(
            [
                ("echo.test".to_string(), vec!["127.0.0.1".parse().unwrap()]),
                ("evil.test".to_string(), vec!["127.0.0.1".parse().unwrap()]),
            ]
            .into(),
        );
        let port = p.port();

        // No credentials: 407 with this launch's realm, nothing connected.
        let (h, _) = ask(port, &format!("CONNECT echo.test:{echo} HTTP/1.1\r\n\r\n"));
        assert!(h.starts_with("HTTP/1.1 407"), "{h}");
        assert!(h.contains(&format!("realm=\"{}\"", p.realm())));
        // Wrong credentials: the same.
        let (h, _) = ask(
            port,
            &format!("CONNECT echo.test:{echo} HTTP/1.1\r\nProxy-Authorization: Basic eDp5\r\n\r\n"),
        );
        assert!(h.starts_with("HTTP/1.1 407"), "{h}");
        assert_eq!(p.stats().connections, 0);

        // A public name resolving to loopback is refused until announced (D-040).
        let (h, _) = ask(port, &format!("CONNECT echo.test:{echo} HTTP/1.1\r\n{}\r\n", auth(&p)));
        assert!(h.starts_with("HTTP/1.1 403"), "{h}");
        assert_eq!(p.record("echo.test").unwrap().blocked_local, 1);
        p.announce_local("echo.test");
        let (h, mut c) = ask(port, &format!("CONNECT echo.test:{echo} HTTP/1.1\r\n{}\r\n", auth(&p)));
        assert!(h.starts_with("HTTP/1.1 200"), "{h}");
        c.write_all(b"ping").unwrap();
        let mut b = [0u8; 4];
        c.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"ping");
        let rec = p.record("echo.test").unwrap();
        assert_eq!((rec.connections, rec.via), (1, Some(Via::Test)));

        // IP literals are not the guard's business (the request layer decides by page).
        let (h, _) = ask(port, &format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\n{}\r\n", auth(&p)));
        assert!(h.starts_with("HTTP/1.1 200"), "{h}");

        // Check names are never resolved, and prove the request arrived with credentials.
        let probe = p.new_probe();
        let (h, _) = ask(port, &format!("CONNECT {probe}:443 HTTP/1.1\r\n\r\n"));
        assert!(h.starts_with("HTTP/1.1 407") && !p.probe_seen(&probe));
        let (h, _) = ask(port, &format!("CONNECT {probe}:443 HTTP/1.1\r\n{}\r\n", auth(&p)));
        assert!(h.starts_with("HTTP/1.1 403") && p.probe_seen(&probe), "{h}");

        // Malformed requests: 400, counted.
        let (h, _) = ask(port, "CONNECT bad host:443 HTTP/1.1\r\n\r\n");
        assert!(h.starts_with("HTTP/1.1 400"), "{h}");
        assert_eq!(p.stats().malformed, 1);

        // Paused: the connection is closed without an answer.
        p.set_paused(true);
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = c.write_all(b"CONNECT echo.test:1 HTTP/1.1\r\n\r\n");
        let mut b = [0u8; 16];
        assert!(matches!(c.read(&mut b), Ok(0) | Err(_)));
        p.set_paused(false);
        p.stop();
    }

    #[test]
    fn plain_http_is_forwarded_once_without_proxy_headers() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let sport = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut buf = vec![0u8; 4096];
            let n = c.read(&mut buf).unwrap();
            tx.send(String::from_utf8_lossy(&buf[..n]).to_string()).unwrap();
            c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });
        let p = Proxy::start(Mode::Automatic).unwrap();
        let (h, _) = ask(
            p.port(),
            &format!(
                "GET http://127.0.0.1:{sport}/x?y=1 HTTP/1.1\r\nHost: 127.0.0.1:{sport}\r\n{}Proxy-Connection: keep-alive\r\n\r\n",
                auth(&p)
            ),
        );
        assert!(h.starts_with("HTTP/1.1 200 OK"), "{h}");
        let seen = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(seen.starts_with("GET /x?y=1 HTTP/1.1\r\n"), "{seen}");
        assert!(!seen.to_ascii_lowercase().contains("proxy-"), "{seen}");
        assert!(seen.contains("Connection: close"));
        p.stop();
    }

    #[test]
    fn threat_hosts_are_refused_unless_continued() {
        let p = Proxy::start(Mode::Automatic).unwrap();
        let list = "0.0.0.0 bad.test\n";
        p.set_threats(Arc::new(Threats::build(&[untrace_filter::engine::Source {
            id: ListId::Malware,
            text: list,
        }])));
        p.resolver()
            .set_test_hosts([("bad.test".to_string(), vec!["127.0.0.1".parse().unwrap()])].into());
        p.announce_local("bad.test");
        let (h, _) = ask(p.port(), &format!("CONNECT bad.test:9 HTTP/1.1\r\n{}\r\n", auth(&p)));
        assert!(h.starts_with("HTTP/1.1 403"), "{h}");
        let r = p.record("bad.test").unwrap();
        assert_eq!((r.blocked_threat, r.threat_list), (1, Some(ListId::Malware)));
        // After "Continue anyway" the backstop lets it through (port 9 is closed: 502).
        p.allow_threat_host("bad.test");
        let (h, _) = ask(p.port(), &format!("CONNECT bad.test:9 HTTP/1.1\r\n{}\r\n", auth(&p)));
        assert!(h.starts_with("HTTP/1.1 502"), "{h}");
        p.stop();
    }
}
