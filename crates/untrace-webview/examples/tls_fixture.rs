//! HTTPS fixture with a self-signed certificate, for the self-check's certificate test.
//! Test tooling only (dev-dependencies); never part of UNTRACE.
//!
//! Prints `PORT <n>` on stdout, then serves on 127.0.0.1 until `<seconds>` (default 180) pass.
//!   cargo run --release -p untrace-webview --example tls_fixture -- 180

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

pub const FIXTURE_NAME: &str = "untrace-selfcheck-fixture.invalid";

fn main() {
    let secs: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(180);
    // Self-signed, issued for a name that is not the address served: two reasons to refuse it.
    let mut params = rcgen::CertificateParams::new(vec![FIXTURE_NAME.to_string()]).expect("params");
    params.distinguished_name.push(rcgen::DnType::CommonName, FIXTURE_NAME);
    let signing_key = rcgen::KeyPair::generate().expect("key");
    let cert = params.self_signed(&signing_key).expect("certificate");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .expect("server config"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    println!("PORT {}", listener.local_addr().expect("addr").port());
    let _ = std::io::stdout().flush();
    listener.set_nonblocking(true).expect("nonblocking");
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                let cfg = cfg.clone();
                thread::spawn(move || {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let Ok(conn) = rustls::ServerConnection::new(cfg) else {
                        return;
                    };
                    let mut tls = rustls::StreamOwned::new(conn, stream);
                    let mut buf = [0u8; 4096];
                    // A correct client rejects the certificate during this handshake.
                    if tls.read(&mut buf).is_ok() {
                        let body = "<!doctype html><title>fixture</title>";
                        let _ = write!(
                            tls,
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        tls.conn.send_close_notify();
                        let _ = tls.flush();
                    }
                });
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}
