//! The proxy's request head: parsed strictly, bounded, and never trusted beyond what is needed
//! to pick a destination. Only two forms exist: `CONNECT host:port` (HTTPS and WebSocket
//! tunnels) and absolute-form `http://` requests (plain HTTP, forwarded with `Connection: close`).

use std::net::Ipv6Addr;

/// Longest request head accepted (request line plus headers).
pub const MAX_HEAD: usize = 16 * 1024;
pub const MAX_HEADERS: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A tunnel: the proxy answers 200 and then copies bytes both ways.
    Connect,
    /// Plain HTTP: forwarded once, in origin form.
    Forward { path: String },
}

#[derive(Debug, Clone)]
pub struct Head {
    pub method: String,
    /// Lower-case name or IP literal (IPv6 without brackets).
    pub host: String,
    pub port: u16,
    pub target: Target,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

/// End of the head (index of the blank line's first byte), if complete.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn valid_name(h: &str) -> bool {
    (1..=253).contains(&h.len())
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        && !h.starts_with('.')
        && !h.contains("..")
}

/// `host:port`, `[v6]:port`, or a bare host when a default port is given.
fn authority(a: &str, default_port: Option<u16>) -> Result<(String, u16), &'static str> {
    let (host, port) = if let Some(rest) = a.strip_prefix('[') {
        let (v6, after) = rest.split_once(']').ok_or("bad IPv6 literal")?;
        v6.parse::<Ipv6Addr>().map_err(|_| "bad IPv6 literal")?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p),
            None if after.is_empty() => None,
            None => return Err("bad authority"),
        };
        (v6.to_ascii_lowercase(), port)
    } else {
        let (h, p) = match a.rsplit_once(':') {
            Some((h, p)) => (h.to_ascii_lowercase(), Some(p)),
            None => (a.to_ascii_lowercase(), None),
        };
        // Only a bracketed IPv6 literal may contain ':'.
        if !valid_name(&h) {
            return Err("bad host");
        }
        (h, p)
    };
    let port = match port {
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err("bad port");
            }
            p.parse::<u16>().map_err(|_| "bad port")?
        }
        None => default_port.ok_or("missing port")?,
    };
    if port == 0 {
        return Err("bad port");
    }
    Ok((host, port))
}

/// Parse a complete head (without the final blank line).
pub fn parse(head: &[u8]) -> Result<Head, &'static str> {
    if head.len() > MAX_HEAD {
        return Err("head too large");
    }
    if head
        .iter()
        .any(|&b| b >= 0x80 || (b < 0x20 && b != b'\r' && b != b'\n' && b != b'\t') || b == 0x7f)
    {
        return Err("invalid byte in head");
    }
    let text = std::str::from_utf8(head).map_err(|_| "invalid byte in head")?;
    // CR and LF only as a pair ending a line. A lone one inside a line would be passed on to
    // the server, which may read it as a line break: a header or request smuggled in (found by
    // the M8 fuzzing campaign).
    if text.split("\r\n").any(|l| l.contains(['\r', '\n'])) {
        return Err("bare CR or LF in head");
    }
    let mut lines = text.split("\r\n");
    let line = lines.next().unwrap_or("");
    // The request line has no tabs either (it is split on single spaces).
    if line.contains('\t') {
        return Err("bad request line");
    }
    let parts: Vec<&str> = line.split(' ').collect();
    let [method, target, version] = parts[..] else {
        return Err("bad request line");
    };
    if !is_token(method) {
        return Err("bad method");
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err("bad version");
    }
    let (host, port, target) = if method == "CONNECT" {
        let (h, p) = authority(target, None)?;
        (h, p, Target::Connect)
    } else {
        let rest = target
            .strip_prefix("http://")
            .ok_or("only http:// requests are forwarded")?;
        let (auth, path) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        if auth.contains('@') {
            return Err("credentials in URL");
        }
        let (h, p) = authority(auth, Some(80))?;
        let path = if path.starts_with('?') {
            format!("/{path}")
        } else {
            path
        };
        (h, p, Target::Forward { path })
    };
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            return Err("empty header line");
        }
        if l.starts_with([' ', '\t']) {
            return Err("folded header");
        }
        let (k, v) = l.split_once(':').ok_or("bad header")?;
        if !is_token(k) {
            return Err("bad header name");
        }
        headers.push((k.to_string(), v.trim_matches([' ', '\t']).to_string()));
        if headers.len() > MAX_HEADERS {
            return Err("too many headers");
        }
    }
    Ok(Head {
        method: method.to_string(),
        host,
        port,
        target,
        version: version.to_string(),
        headers,
    })
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `host:port` for display and logs (IPv6 in brackets).
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The request as sent to the server: origin form, without proxy and hop-by-hop headers,
    /// and with `Connection: close` (one request per proxy connection).
    pub fn forward_head(&self) -> Option<Vec<u8>> {
        let Target::Forward { path } = &self.target else {
            return None;
        };
        let named: Vec<String> = self
            .header("Connection")
            .map(|c| c.split(',').map(|t| t.trim().to_ascii_lowercase()).collect())
            .unwrap_or_default();
        let mut out = format!("{} {} {}\r\n", self.method, path, self.version);
        for (k, v) in &self.headers {
            let lk = k.to_ascii_lowercase();
            let hop = matches!(
                lk.as_str(),
                "proxy-authorization" | "proxy-connection" | "connection" | "keep-alive" | "upgrade" | "te" | "trailer"
            );
            if hop || named.contains(&lk) {
                continue;
            }
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("Connection: close\r\n\r\n");
        Some(out.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_and_forward_heads_parse() {
        let h = parse(
            b"CONNECT www.Example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\nProxy-Authorization: Basic eDp5",
        )
        .unwrap();
        assert_eq!(
            (h.host.as_str(), h.port, &h.target),
            ("www.example.com", 443, &Target::Connect)
        );
        assert_eq!(h.header("proxy-authorization"), Some("Basic eDp5"));
        let h = parse(b"CONNECT [2606:4700::1111]:443 HTTP/1.1").unwrap();
        assert_eq!(
            (h.host.as_str(), h.authority()),
            ("2606:4700::1111", "[2606:4700::1111]:443".to_string())
        );
        let h = parse(b"GET http://127.0.0.1:8080/a/b?c=1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive, X-Secret\r\nX-Secret: 1\r\nAccept: */*").unwrap();
        assert_eq!(
            h.target,
            Target::Forward {
                path: "/a/b?c=1".into()
            }
        );
        let fwd = String::from_utf8(h.forward_head().unwrap()).unwrap();
        assert_eq!(
            fwd,
            "GET /a/b?c=1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        let h = parse(b"GET http://example.com?x HTTP/1.1").unwrap();
        assert_eq!((h.port, h.target), (80, Target::Forward { path: "/?x".into() }));
    }

    #[test]
    fn malformed_heads_are_refused() {
        for bad in [
            &b"CONNECT example.com HTTP/1.1"[..],
            b"CONNECT example.com:0 HTTP/1.1",
            b"CONNECT example.com:65536 HTTP/1.1",
            b"CONNECT example.com:+443 HTTP/1.1",
            b"CONNECT exa mple.com:443 HTTP/1.1",
            b"CONNECT [::1:443 HTTP/1.1",
            b"CONNECT ..:443 HTTP/1.1",
            b"CONNECT @[fe80::1]:1 HTTP/1.1",
            b"CONNECT fe80::1:443 HTTP/1.1",
            b"GET https://example.com/ HTTP/1.1",
            b"GET /relative HTTP/1.1",
            b"GET http://user:pw@example.com/ HTTP/1.1",
            b"GET http://example.com/ HTTP/2",
            b"GET  http://example.com/ HTTP/1.1",
            b"G\xc3\xa9T http://example.com/ HTTP/1.1",
            b"GET http://example.com/ HTTP/1.1\r\n folded: x",
            b"GET http://example.com/ HTTP/1.1\r\nBad Name: x",
            b"GET http://example.com/ HTTP/1.1\r\nNoColon",
            b"GET http://exa\x00mple.com/ HTTP/1.1",
            // M8 fuzzing: a lone CR or LF inside a line, or a tab in the request line, would
            // reach the server, which may split the line there.
            b"GET http://example.com/ HTTP/1.1\r\nX-Foo: 1\r#\nY: 2",
            b"GET http://example.com/ HTTP/1.1\r\nX-Foo: 1\rInjected: 2",
            b"GET http://example.com/ HTTP/1.1\r\nX-Foo: 1\nInjected: 2",
            b"GET http://example.com/a\nInjected: 1 HTTP/1.1",
            b"GET http://example.com/a\tb HTTP/1.1",
            b"CONNECT example.com:443 HTTP/1.1\r\nX: a\n\nGET http://evil.example/ HTTP/1.1",
        ] {
            assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let many: String = (0..=MAX_HEADERS).map(|i| format!("\r\nH{i}: v")).collect();
        assert!(parse(format!("CONNECT a.b:443 HTTP/1.1{many}").as_bytes()).is_err());
        assert!(parse(&vec![b'a'; MAX_HEAD + 1]).is_err());
    }

    /// Randomised robustness: mutated and random heads never panic, and whatever parses keeps
    /// the invariants the proxy relies on. (Not coverage-guided fuzzing; see TESTING.)
    #[test]
    fn random_and_mutated_heads_never_panic() {
        let seeds: [&[u8]; 4] = [
            b"CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443",
            b"GET http://[::1]:8080/x?y HTTP/1.1\r\nConnection: close",
            b"POST http://a.b/c HTTP/1.0\r\nContent-Length: 3",
            b"CONNECT [fe80::1]:1 HTTP/1.1",
        ];
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for i in 0..200_000u32 {
            let mut buf = seeds[(i % 4) as usize].to_vec();
            let edits = 1 + next() % 6;
            for _ in 0..edits {
                let r = next();
                let pos = (r >> 8) as usize % (buf.len() + 1);
                match r % 4 {
                    0 if pos < buf.len() => buf[pos] = (r >> 32) as u8,
                    1 => buf.insert(pos, b" :[]/@.\r\n\x00\xff0"[((r >> 40) % 12) as usize]),
                    2 if pos < buf.len() => {
                        buf.remove(pos);
                    }
                    _ => buf.truncate(pos),
                }
            }
            if let Ok(h) = parse(&buf) {
                assert!(h.port != 0);
                assert!(
                    !h.host.is_empty() && !h.host.contains([' ', '/', '@', '\r', '\n']),
                    "{:?} -> {:?}",
                    String::from_utf8_lossy(&buf),
                    h.host
                );
                assert!(h.version == "HTTP/1.1" || h.version == "HTTP/1.0");
                if let Some(f) = h.forward_head() {
                    let s = String::from_utf8(f).unwrap();
                    assert!(s.ends_with("Connection: close\r\n\r\n"));
                    assert!(!s.to_ascii_lowercase().contains("proxy-authorization"));
                }
            }
        }
    }
}
