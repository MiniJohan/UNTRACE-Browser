//! The loopback proxy's request-head parser (untrusted: anything a page or another local
//! process sends to the proxy port).
#![no_main]
use libfuzzer_sys::fuzz_target;
use untrace_net::http;

fuzz_target!(|data: &[u8]| {
    let _ = http::head_end(data);
    let Ok(h) = http::parse(data) else { return };
    assert!(h.port != 0);
    assert!(!h.host.is_empty() && !h.host.contains([' ', '/', '@', '\r', '\n', '\\']), "host {:?}", h.host);
    assert!(h.version == "HTTP/1.1" || h.version == "HTTP/1.0");
    let _ = h.authority();
    if let Some(f) = h.forward_head() {
        let s = String::from_utf8(f).expect("forwarded head is text");
        assert!(s.ends_with("Connection: close\r\n\r\n"));
        let lines: Vec<&str> = s.trim_end_matches("\r\n\r\n").split("\r\n").collect();
        for l in &lines[1..] {
            // No header smuggled through: one header per line, never the proxy's credentials or
            // hop-by-hop headers, and no line breaks inside a header.
            assert!(!l.contains(['\r', '\n']), "line break inside {l:?}");
            let name = l.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
            assert!(
                !matches!(name.as_str(), "proxy-authorization" | "proxy-connection" | "keep-alive" | "upgrade" | "te" | "trailer"),
                "hop-by-hop header forwarded: {l:?}"
            );
        }
    }
});
