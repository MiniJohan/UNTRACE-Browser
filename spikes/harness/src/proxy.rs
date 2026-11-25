//! Spike loopback proxy: CONNECT tunnels + absolute-form plain HTTP, Basic proxy auth,
//! host mapping (acts as the resolver), and a log of everything it sees.
//! Hosts the mapper does not know are refused (spikes never reach the internet).

use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

pub type Mapper = Arc<dyn Fn(&str, u16) -> Option<u16> + Send + Sync>;

#[derive(Clone, Debug)]
pub struct Event {
    pub kind: String,
    pub target: String,
    pub t_ms: u128,
}

pub struct Proxy {
    pub port: u16,
    pub user: String,
    pub pass: String,
    pub log: Arc<Mutex<Vec<Event>>>,
    stop: Arc<AtomicBool>,
}

impl Proxy {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port)); // unblock accept()
        thread::sleep(Duration::from_millis(100));
    }
    pub fn events(&self) -> Vec<Event> {
        self.log.lock().unwrap().clone()
    }
}

pub fn b64(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn start(mapper: Mapper, require_auth: bool) -> Proxy {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let port = l.local_addr().unwrap().port();
    let user = format!("u{}", std::process::id());
    let pass = format!("p{:x}", Instant::now().elapsed().as_nanos() ^ 0x5eed_1234_abcd);
    let expected = format!("Basic {}", b64(format!("{user}:{pass}").as_bytes()));
    let log = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let t0 = Instant::now();
    {
        let (log, stop) = (log.clone(), stop.clone());
        thread::spawn(move || {
            for c in l.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break; // listener dropped -> further connections refused
                }
                let Ok(c) = c else { continue };
                let (log, mapper, expected) = (log.clone(), mapper.clone(), expected.clone());
                thread::spawn(move || {
                    let _ = c.set_read_timeout(Some(Duration::from_secs(30)));
                    client(c, &mapper, require_auth, &expected, &log, t0);
                });
            }
        });
    }
    Proxy { port, user, pass, log, stop }
}

fn push(log: &Arc<Mutex<Vec<Event>>>, kind: &str, target: &str, t0: Instant) {
    log.lock().unwrap().push(Event { kind: kind.into(), target: target.into(), t_ms: t0.elapsed().as_millis() });
}

fn client(mut c: TcpStream, mapper: &Mapper, require_auth: bool, expected: &str, log: &Arc<Mutex<Vec<Event>>>, t0: Instant) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        match c.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > 65536 {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let rest = buf[head_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("").to_string();
    let mut parts = first.split(' ');
    let (method, target, version) = (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("HTTP/1.1").to_string(),
    );
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    let auth = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization")).map(|(_, v)| v.as_str());

    // Destination host/port.
    let (host, port, origin_path) = if method == "CONNECT" {
        let (h, p) = target.rsplit_once(':').unwrap_or((&target, "443"));
        (h.to_string(), p.parse().unwrap_or(443), String::new())
    } else if let Some(rest_url) = target.strip_prefix("http://") {
        let (authority, path) = rest_url.split_once('/').map(|(a, p)| (a, format!("/{p}"))).unwrap_or((rest_url, "/".into()));
        let (h, p) = authority.rsplit_once(':').map(|(h, p)| (h, p.parse().unwrap_or(80))).unwrap_or((authority, 80));
        (h.to_string(), p, path)
    } else {
        push(log, "malformed", &first, t0);
        let _ = c.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        return;
    };
    let label = format!("{method} {host}:{port}");

    if require_auth && auth != Some(expected) {
        push(log, if auth.is_some() { "auth-bad" } else { "auth-challenge" }, &label, t0);
        let _ = c.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"untrace-spike\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    let Some(up_port) = mapper(&host, port) else {
        push(log, "refused-unmapped", &label, t0);
        let _ = c.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        return;
    };
    let Ok(mut up) = TcpStream::connect(("127.0.0.1", up_port)) else {
        push(log, "upstream-failed", &label, t0);
        let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        return;
    };
    if method == "CONNECT" {
        push(log, "connect", &label, t0);
        let _ = c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
        if !rest.is_empty() {
            let _ = up.write_all(&rest);
        }
    } else {
        push(log, "http", &format!("{label}{origin_path}"), t0);
        let mut out = format!("{method} {origin_path} {version}\r\n");
        for (k, v) in &headers {
            if k.eq_ignore_ascii_case("proxy-authorization") || k.eq_ignore_ascii_case("proxy-connection") {
                continue;
            }
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("\r\n");
        let _ = up.write_all(out.as_bytes());
        let _ = up.write_all(&rest);
    }
    pipe(c, up);
}

fn pipe(c: TcpStream, up: TcpStream) {
    let (Ok(mut c2), Ok(mut up2)) = (c.try_clone(), up.try_clone()) else { return };
    let _ = c.set_read_timeout(None);
    let t = thread::spawn(move || {
        let mut c = c;
        let mut up = up;
        let _ = io::copy(&mut c, &mut up);
        let _ = up.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut up2, &mut c2);
    let _ = c2.shutdown(Shutdown::Both);
    let _ = t.join();
}
