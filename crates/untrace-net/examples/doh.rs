//! M5 check: does each "Strict" provider answer over DNS over HTTPS through the Windows DNS
//! client, on IPv4 and IPv6 addresses, and does a wrong DoH path fail (negative control: proof
//! there is no silent fallback)? Also prints what "Automatic" would use on this computer.
//! Queries `example.com` only.
//!
//! Run: cargo run -p untrace-net --example doh --release

use std::time::Instant;

use untrace_net::{
    diag,
    resolver::{self, DohServer, Mode, Resolver},
};

fn try_servers(label: &str, servers: Vec<DohServer>) -> serde_json_lite::Line {
    let r = Resolver::new(Mode::Strict {
        name: label.into(),
        servers,
    });
    let t = Instant::now();
    let res = r.resolve("example.com");
    serde_json_lite::Line {
        label: label.to_string(),
        ms: t.elapsed().as_secs_f64() * 1e3,
        result: match res {
            Ok(a) => format!("ok via {:?} ({}): {:?}", a.via, a.server.unwrap_or_default(), a.addrs),
            Err(e) => format!("error: {e:?}"),
        },
    }
}

mod serde_json_lite {
    pub struct Line {
        pub label: String,
        pub ms: f64,
        pub result: String,
    }
}

fn main() {
    let mut lines = Vec::new();
    for p in &resolver::PROVIDERS {
        let all = p.servers();
        let v4: Vec<DohServer> = all.iter().filter(|s| s.address.is_ipv4()).cloned().collect();
        let v6: Vec<DohServer> = all.iter().filter(|s| s.address.is_ipv6()).cloned().collect();
        lines.push(try_servers(&format!("{} IPv4", p.name), v4));
        lines.push(try_servers(&format!("{} IPv6", p.name), v6));
    }
    // Negative control: Quad9's address with a path that is not a DoH endpoint.
    lines.push(try_servers(
        "negative control (wrong path)",
        vec![DohServer {
            address: "9.9.9.9".parse().unwrap(),
            template: "https://dns.quad9.net/not-a-doh-path".into(),
        }],
    ));
    for l in &lines {
        println!("{:<34} {:>8.1} ms  {}", l.label, l.ms, l.result);
    }
    let a = diag::adapters();
    println!("\nAdapters:");
    for ad in &a {
        println!("  {} (gateway: {})", ad.name, ad.has_gateway);
        for s in &ad.dns_servers {
            println!(
                "    {} template={:?} source={:?} windows_encryption_set={}",
                s.address, s.doh_template, s.doh_template_source, s.windows_encryption_set
            );
        }
    }
    let auto = Resolver::new(Mode::Automatic);
    println!("Automatic would use: {:?}", auto.automatic_servers());
    let t = Instant::now();
    println!(
        "Automatic example.com: {:?} in {:.1} ms; stats {:?}",
        auto.resolve("example.com").map(|a| (a.via, a.addrs)),
        t.elapsed().as_secs_f64() * 1e3,
        auto.stats()
    );
    println!("Windows policy: {:?}", diag::windows_policy());
}
