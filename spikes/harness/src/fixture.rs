//! Tiny HTTP/1.1 (+ optional TLS) fixture server. One request per connection.
//! Every request is logged so spikes can compare "what the server saw" with
//! "what the engine reported".

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct Req {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub tls: bool,
    pub t_ms: u128,
    /// The request body (M8 collects results by POST); at most 16 MB is kept.
    pub body: Vec<u8>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    /// Path without query string.
    pub fn route(&self) -> &str {
        self.path.split('?').next().unwrap_or("")
    }
}

pub struct Resp {
    pub status: u16,
    pub ctype: String,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

impl Resp {
    pub fn new(status: u16, ctype: &str, body: impl Into<Vec<u8>>) -> Self {
        Self { status, ctype: ctype.into(), body: body.into(), headers: vec![] }
    }
    pub fn html(s: impl Into<String>) -> Self {
        Self::new(200, "text/html; charset=utf-8", s.into().into_bytes())
    }
    pub fn js(s: impl Into<String>) -> Self {
        Self::new(200, "text/javascript", s.into().into_bytes())
    }
    pub fn css(s: impl Into<String>) -> Self {
        Self::new(200, "text/css", s.into().into_bytes())
    }
    pub fn text(s: impl Into<String>) -> Self {
        Self::new(200, "text/plain", s.into().into_bytes())
    }
    pub fn png() -> Self {
        Self::new(200, "image/png", PNG_1X1.to_vec())
    }
    pub fn with(mut self, k: &str, v: impl Into<String>) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
}

pub const PNG_1X1: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0xF8, 0xCF, 0xC0, 0xF0,
    0x1F, 0x00, 0x05, 0x00, 0x01, 0xFF, 0x89, 0x99, 0x3D, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
    0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
];

pub type Router = Arc<dyn Fn(&Req) -> Resp + Send + Sync>;
pub type Log = Arc<Mutex<Vec<Req>>>;

pub struct Fixture {
    pub http_port: u16,
    pub https_port: u16,
    pub log: Log,
}

impl Fixture {
    pub fn mark(&self) -> usize {
        self.log.lock().unwrap().len()
    }
    pub fn since(&self, mark: usize) -> Vec<Req> {
        self.log.lock().unwrap()[mark..].to_vec()
    }
}

pub fn start(router: Router, tls: Option<Arc<rustls::ServerConfig>>) -> Fixture {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let t0 = Instant::now();
    let http = TcpListener::bind("127.0.0.1:0").expect("bind http");
    let http_port = http.local_addr().unwrap().port();
    {
        let (router, log) = (router.clone(), log.clone());
        thread::spawn(move || {
            for s in http.incoming().flatten() {
                let (router, log) = (router.clone(), log.clone());
                thread::spawn(move || {
                    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                    let mut s = s;
                    handle(&mut s, false, http_port, &router, &log, t0);
                });
            }
        });
    }
    let mut https_port = 0;
    if let Some(cfg) = tls {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind https");
        https_port = l.local_addr().unwrap().port();
        let (router, log) = (router.clone(), log.clone());
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                let (router, log, cfg) = (router.clone(), log.clone(), cfg.clone());
                thread::spawn(move || {
                    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                    let Ok(conn) = rustls::ServerConnection::new(cfg) else { return };
                    let mut tls = rustls::StreamOwned::new(conn, s);
                    handle(&mut tls, true, https_port, &router, &log, t0);
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
    }
    Fixture { http_port, https_port, log }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Status",
    }
}

fn handle<S: Read + Write>(s: &mut S, tls: bool, port: u16, router: &Router, log: &Log, t0: Instant) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p;
        }
        if buf.len() > 65536 {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    let host = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.split(':').next().unwrap_or("").to_string())
        .unwrap_or_default();
    // Drain a request body if one was announced.
    let clen: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body: Vec<u8> = buf[head_end + 4..].to_vec();
    while body.len() < clen {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
        }
    }
    body.truncate(clen.min(16 << 20));
    let req = Req { host, port, method, path, headers, tls, t_ms: t0.elapsed().as_millis(), body };
    log.lock().unwrap().push(req.clone());
    let resp = router(&req);
    let mut out = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        resp.status,
        reason(resp.status),
        resp.ctype,
        resp.body.len()
    );
    for (k, v) in &resp.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let _ = s.write_all(out.as_bytes());
    let _ = s.write_all(&resp.body);
    let _ = s.flush();
}

/// Self-signed TLS server config for fixture host names.
pub fn tls_config(names: &[&str]) -> Arc<rustls::ServerConfig> {
    let ck = rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .expect("cert");
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        ck.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

#[allow(dead_code)]
pub fn connect_ok(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).is_ok()
}
