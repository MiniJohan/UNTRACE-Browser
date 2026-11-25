//! S3 — Loopback proxy + DNS: is `--proxy-server` honoured for all page traffic, does proxy
//! auth work through BasicAuthenticationRequested, does WebView2 fail closed when the proxy
//! dies, do page host names leak to the OS resolver, what does the runtime contact on its own,
//! and can the Windows 11 native DoH query API resolve names (no extra dependency)?

use std::{process::Command, sync::Arc, time::{Duration, Instant}};

use serde_json::{json, Value};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::NetworkManagement::Dns::*,
};

use crate::{
    fixture::{self, Req, Resp},
    host, note, proxy, pump,
};

fn page(pid: u32, http_port: u16) -> String {
    r#"<!doctype html><html><head><meta charset=utf-8><title>s3</title>
<link rel="dns-prefetch" href="//leak1-{PID}.test"><link rel="preconnect" href="https://leak2-{PID}.test">
</head><body><img src="https://b-{PID}.test/s3/img.png">
<script>
  try { new WebSocket('ws://ws-{PID}.test/s3/socket'); } catch (e) {}
  fetch('http://127.0.0.1:{HP}/s3/loopback').catch(() => {});
  setTimeout(() => { document.title = 's3-done'; }, 2500);
</script></body></html>"#
        .replace("{PID}", &pid.to_string())
        .replace("{HP}", &http_port.to_string())
}

fn dns_cache_entries(needle: &str) -> Vec<String> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-DnsClientCache | ForEach-Object { $_.Entry + ' ' + $_.Status }"])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).lines().filter(|l| l.contains(needle)).map(|s| s.trim().to_string()).collect(),
        Err(e) => vec![format!("ERR {e}")],
    }
}

struct AsyncDone {
    event: windows::Win32::Foundation::HANDLE,
}

unsafe extern "system" fn dns_done(ctx: *const core::ffi::c_void, _res: *mut DNS_QUERY_RESULT) {
    let d = unsafe { &*(ctx as *const AsyncDone) };
    unsafe {
        let _ = windows::Win32::System::Threading::SetEvent(d.event);
    }
}

#[derive(Clone, Copy)]
pub struct DohVariant {
    pub server_type: u32,
    pub port: u16,
    pub options: u32,
    pub asynchronous: bool,
}

fn doh_query(name: &str, template: &str, ip: [u8; 4], udp_fallback: bool, v: DohVariant) -> Value {
    let tmpl: Vec<u16> = template.encode_utf16().chain(Some(0)).collect();
    let qname: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut server = DNS_CUSTOM_SERVER::default();
    server.dwServerType = v.server_type;
    server.ullFlags = if udp_fallback { DNS_CUSTOM_SERVER_UDP_FALLBACK as u64 } else { 0 };
    if v.server_type == DNS_CUSTOM_SERVER_TYPE_DOH {
        server.Anonymous1.pwszTemplate = PWSTR(tmpl.as_ptr() as *mut u16);
    }
    let mut sa = [0i8; 32];
    sa[0] = 2; // AF_INET
    let pb = v.port.to_be_bytes();
    sa[2] = pb[0] as i8;
    sa[3] = pb[1] as i8;
    for i in 0..4 {
        sa[4 + i] = ip[i] as i8;
    }
    server.Anonymous2.MaxSa = sa;
    let done = AsyncDone {
        event: unsafe { windows::Win32::System::Threading::CreateEventW(None, true, false, None).expect("event") },
    };
    let mut req = DNS_QUERY_REQUEST3::default();
    req.Version = DNS_QUERY_REQUEST_VERSION3.0;
    req.QueryName = PCWSTR(qname.as_ptr());
    req.QueryType = DNS_TYPE_A.0;
    req.QueryOptions = v.options as u64;
    req.cCustomServers = 1;
    req.pCustomServers = &mut server;
    if v.asynchronous {
        req.pQueryCompletionCallback = Some(dns_done);
        req.pQueryContext = &done as *const _ as *mut _;
    }
    let mut res = DNS_QUERY_RESULT::default();
    res.Version = DNS_QUERY_RESULTS_VERSION1.0;
    let mut cancel = DNS_QUERY_CANCEL::default();
    let t = Instant::now();
    let mut status = unsafe {
        DnsQueryEx(
            &req as *const _ as *const DNS_QUERY_REQUEST,
            &mut res,
            if v.asynchronous { Some(&mut cancel) } else { None },
        )
    };
    if v.asynchronous && status == 9506 {
        // DNS_REQUEST_PENDING
        unsafe { windows::Win32::System::Threading::WaitForSingleObject(done.event, 15000) };
        status = res.QueryStatus;
    }
    let ms = t.elapsed().as_secs_f64() * 1e3;
    let mut ips = vec![];
    unsafe {
        let mut p = res.pQueryRecords as *mut DNS_RECORDW;
        while !p.is_null() {
            let r = &*p;
            if r.wType == DNS_TYPE_A.0 {
                let a = r.Data.A.IpAddress.to_le_bytes();
                ips.push(format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]));
            }
            p = r.pNext;
        }
        if !res.pQueryRecords.is_null() {
            DnsFree(Some(res.pQueryRecords as *const _), DnsFreeRecordList);
        }
    }
    json!({
        "name": name, "template": template, "udp_fallback": udp_fallback,
        "server_type": if v.server_type == DNS_CUSTOM_SERVER_TYPE_DOH { "doh" } else { "udp" },
        "port": v.port, "options": v.options, "async": v.asynchronous,
        "status": status, "query_status": res.QueryStatus, "a_records": ips, "ms": ms
    })
}

/// For other probes (M5): the same net-log search.
pub fn netlog_resolutions_pub(path: &std::path::Path, needles: &[String]) -> Value {
    netlog_resolutions(path, needles)
}

/// Search a Chromium net-log for host-resolution events mentioning `needle`.
fn netlog_resolutions(path: &std::path::Path, needles: &[String]) -> Value {
    let Ok(mut text) = std::fs::read_to_string(path) else {
        return json!({ "error": format!("net-log not found at {}", path.display()) });
    };
    let parsed: Option<Value> = serde_json::from_str(&text).ok().or_else(|| {
        // Log may be unterminated if the browser has not finished writing it.
        text.push_str("]}");
        serde_json::from_str(&text).ok()
    });
    let Some(v) = parsed else {
        let hits: Vec<Value> = needles.iter().map(|n| json!({ "name": n, "raw_mentions": text.matches(n.as_str()).count() })).collect();
        return json!({ "parsed": false, "hits": hits });
    };
    let types = &v["constants"]["logEventTypes"];
    let mut names_by_id = std::collections::HashMap::new();
    if let Some(m) = types.as_object() {
        for (k, id) in m {
            if let Some(i) = id.as_i64() {
                names_by_id.insert(i, k.clone());
            }
        }
    }
    let events = v["events"].as_array().cloned().unwrap_or_default();
    let mut out = vec![];
    for n in needles {
        let mut resolver = std::collections::BTreeSet::new();
        let mut any = 0;
        for e in &events {
            let s = e["params"].to_string();
            if s.contains(n.as_str()) {
                any += 1;
                let tn = e["type"].as_i64().and_then(|i| names_by_id.get(&i)).cloned().unwrap_or_default();
                if tn.contains("HOST_RESOLVER") || tn.contains("DNS") {
                    resolver.insert(tn);
                }
            }
        }
        out.push(json!({ "name": n, "events_mentioning": any, "resolver_event_types": resolver }));
    }
    json!({ "parsed": true, "events_total": events.len(), "hits": out })
}

pub fn run() -> Value {
    let pid = std::process::id();
    let suffix = format!("-{pid}.test");
    let names: Vec<String> = ["a", "b", "ws", "leak1", "leak2", "ctrl"].iter().map(|n| format!("{n}{suffix}")).collect();
    let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    let tls = fixture::tls_config(&name_refs);

    let http_port_cell = Arc::new(std::sync::OnceLock::<u16>::new());
    let hp = http_port_cell.clone();
    let router: fixture::Router = Arc::new(move |r: &Req| match r.route() {
        "/s3/page.html" => Resp::html(page(pid, *hp.get().unwrap_or(&0))),
        "/s3/socket" => Resp::new(400, "text/plain", "no websocket"),
        p if p.ends_with(".png") => Resp::png(),
        _ => Resp::text("ok"),
    });
    let fx = fixture::start(router, Some(tls));
    http_port_cell.set(fx.http_port).ok();
    let (hp, sp) = (fx.http_port, fx.https_port);
    let sfx = suffix.clone();
    let mapper: proxy::Mapper = Arc::new(move |h: &str, port: u16| {
        if h.ends_with(&sfx) {
            Some(if port == 443 { sp } else { hp })
        } else if h == "127.0.0.1" && (port == hp || port == sp) {
            Some(port)
        } else {
            None
        }
    });
    let px = proxy::start(mapper, true);
    note(&format!("fixture http {hp} https {sp}; proxy {}", px.port));

    // Control: no proxy. Chromium must resolve ctrl-*.test itself (fails). Tells us whether the
    // OS DNS cache check below can see Chromium's own lookups at all.
    let ctrl_udf = crate::fresh_udf("s3c");
    let ctrl_netlog = ctrl_udf.join("netlog.json");
    let ctrl_nav = {
        let env = host::create_env(
            &ctrl_udf,
            &host::EnvOpts { args: format!("--log-net-log={}", ctrl_netlog.display()), ..Default::default() },
        );
        let hwnd = host::create_window("S3 control (no proxy)", 700, 500);
        let c = host::create_controller(&env, hwnd, "default", false);
        let wv = host::webview(&c);
        let n = host::navigate(&wv, &format!("http://ctrl{suffix}/"), host::T);
        host::close(c);
        host::destroy_window(hwnd);
        n
    };

    // Proxied environment.
    let udf = crate::fresh_udf("s3p");
    let netlog = udf.join("netlog.json");
    let args = format!(
        "--proxy-server=http://127.0.0.1:{} --proxy-bypass-list=<-loopback> --log-net-log={}",
        px.port,
        netlog.display()
    );
    let env = host::create_env(&udf, &host::EnvOpts { args: args.clone(), tracking_prevention: true, ..Default::default() });
    let hwnd = host::create_window("S3 proxied", 900, 650);
    let c = host::create_controller(&env, hwnd, "default", false);
    let wv = host::webview(&c);
    host::harden(&wv);
    unsafe {
        use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Settings8;
        use windows::core::Interface;
        let s8: ICoreWebView2Settings8 = wv.Settings().expect("settings").cast().expect("Settings8");
        s8.SetIsReputationCheckingRequired(false).expect("smartscreen off");
    }
    host::allow_fixture_certs(&wv);
    host::proxy_credentials(&wv, px.port, &px.user, &px.pass);

    let mark = fx.mark();
    let nav = host::navigate(&wv, &format!("http://a{suffix}/s3/page.html"), host::T);
    let done = host::wait_title(&wv, "s3-done", Duration::from_secs(10));
    pump::sleep(Duration::from_millis(800));
    let served: Vec<String> = fx.since(mark).iter().map(|r| format!("{}{} tls={} {}", r.host, r.path, r.tls, if r.header("upgrade").is_some() { "(websocket upgrade)" } else { "" })).collect();

    // Idle: what does the runtime contact by itself?
    note("idle 20 s on about:blank to observe runtime background connections");
    let _ = host::navigate(&wv, "about:blank", host::T);
    pump::sleep(Duration::from_secs(20));
    let events_before_stop = px.events();

    // Fail-closed: stop the proxy, then try a loopback URL that would work directly.
    px.stop();
    let mark2 = fx.mark();
    let nav_direct = host::navigate(&wv, &format!("http://127.0.0.1:{hp}/s3/direct"), host::T);
    let nav_named = host::navigate(&wv, &format!("http://a{suffix}/s3/page.html"), host::T);
    let after_stop: Vec<String> = fx.since(mark2).iter().map(|r| format!("{}{}", r.host, r.path)).collect();
    host::close(c);
    host::destroy_window(hwnd);

    let mut kinds: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for e in &events_before_stop {
        kinds.entry(e.kind.clone()).or_default().push(e.target.clone());
    }
    let background: Vec<String> = events_before_stop.iter().filter(|e| e.kind == "refused-unmapped").map(|e| e.target.clone()).collect();

    // DNS leak check: OS resolver cache, and Chromium's own net-log (authoritative).
    drop(env);
    pump::sleep(Duration::from_secs(5)); // let browser processes exit and flush net-logs
    let cache = dns_cache_entries(&format!("{pid}.test"));
    let control_netlog = netlog_resolutions(&ctrl_netlog, &[format!("ctrl{suffix}")]);
    let proxied_netlog = netlog_resolutions(
        &netlog,
        &["a", "b", "ws", "leak1", "leak2"].iter().map(|n| format!("{n}{suffix}")).collect::<Vec<_>>(),
    );

    // Windows native DoH API (DnsQueryEx + DNS_CUSTOM_SERVER), several request shapes.
    note("Windows DnsQueryEx custom-server tests (queries for example.com to Quad9)");
    let std_opts = DNS_QUERY_STANDARD.0;
    let bypass = DNS_QUERY_BYPASS_CACHE.0 | DNS_QUERY_NO_HOSTS_FILE.0;
    let variants = [
        DohVariant { server_type: DNS_CUSTOM_SERVER_TYPE_DOH, port: 443, options: bypass, asynchronous: false },
        DohVariant { server_type: DNS_CUSTOM_SERVER_TYPE_DOH, port: 0, options: std_opts, asynchronous: false },
        DohVariant { server_type: DNS_CUSTOM_SERVER_TYPE_DOH, port: 443, options: bypass, asynchronous: true },
        DohVariant { server_type: DNS_CUSTOM_SERVER_TYPE_DOH, port: 0, options: std_opts, asynchronous: true },
        DohVariant { server_type: DNS_CUSTOM_SERVER_TYPE_UDP, port: 53, options: bypass, asynchronous: true },
    ];
    let mut doh: Vec<Value> = variants
        .iter()
        .map(|v| doh_query("example.com", "https://dns.quad9.net/dns-query", [9, 9, 9, 9], false, *v))
        .collect();
    // Negative control: a wrong DoH path must fail if the query really goes over DoH.
    if let Some(ok) = doh.iter().zip(variants.iter()).find(|(r, v)| r["a_records"].as_array().map(|a| !a.is_empty()).unwrap_or(false) && v.server_type == DNS_CUSTOM_SERVER_TYPE_DOH).map(|(_, v)| *v) {
        let mut r = doh_query("example.com", "https://dns.quad9.net/not-a-doh-path", [9, 9, 9, 9], false, ok);
        r["negative_control"] = json!(true);
        doh.push(r);
    }

    json!({
        "spike": "S3 proxy & DNS",
        "browser_args": args,
        "control_no_proxy_nav": format!("{ctrl_nav:?}"),
        "proxied_nav": format!("{nav:?}"),
        "page_script_done": done,
        "fixture_served": served,
        "proxy_events_by_kind": kinds,
        "runtime_background_hosts_refused": background,
        "fail_closed": {
            "direct_loopback_nav_after_proxy_stop": format!("{nav_direct:?}"),
            "named_nav_after_proxy_stop": format!("{nav_named:?}"),
            "fixture_requests_after_stop": after_stop,
        },
        "os_dns_cache_entries_for_test_names": cache,
        "netlog_control_no_proxy": control_netlog,
        "netlog_proxied": proxied_netlog,
        "smartscreen_in_proxied_env": "disabled via IsReputationCheckingRequired=false (first run had it at default=on)",
        "windows_doh_api": doh,
    })
}
