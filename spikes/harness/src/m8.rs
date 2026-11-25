//! M8 probe — fingerprinting (D-048, D-049) and WebRTC.
//!
//! One loopback test server (`spikes/m8-fingerprint/page`) serves a page that collects what a
//! fingerprinting script can read in the page, a fresh `about:blank` frame, same-origin and
//! cross-site frames, and dedicated, shared and service workers. It posts the result back; the
//! server also records every request's headers.
//!
//! Browsers: Google Chrome (throwaway profile in a temporary folder, deleted afterwards), a bare
//! WebView2 (defaults), UNTRACE's real content host (`compat visit`, two separate runs), and
//! WebView2 with each candidate measure against WebView2 tells.
//!
//! WebRTC: a UDP listener on this computer's LAN address plays the STUN server. Packets that
//! arrive while the engine runs behind UNTRACE's network layer went around it. A STUN name
//! under `.invalid` is looked for in the engine's net-log (resolution outside encrypted DNS).
//!
//! Nothing leaves the machine except, possibly, a DNS query for the `.invalid` name if the
//! engine resolves it itself (which is what the test detects).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, UdpSocket},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use serde_json::{Value, json};
use untrace_net::{Proxy, resolver::Mode};
use webview2_com::Microsoft::Web::WebView2::Win32::*;
use windows::core::*;

use crate::{
    fixture::{self, Req, Resp},
    host, note, pump,
};

type Results = Arc<Mutex<HashMap<String, Value>>>;

const PAGES: &[&str] = &["fp.html", "fp.js", "frame.html", "worker.js", "shared.js", "sw.js", "rtc.html", "dnt.html"];
const CHROME: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";

fn page_dir() -> PathBuf {
    crate::spikes_dir().join("m8-fingerprint").join("page")
}

fn query<'a>(path: &'a str, key: &str) -> Option<&'a str> {
    path.split_once('?')?
        .1
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

fn router(results: Results) -> fixture::Router {
    Arc::new(move |r: &Req| {
        let route = r.route().to_string();
        if route == "/fp/result" && r.method == "POST" {
            let run = query(&r.path, "run").unwrap_or("unnamed").to_string();
            let v: Value = serde_json::from_slice(&r.body)
                .unwrap_or_else(|e| json!({ "parse_error": e.to_string(), "bytes": r.body.len() }));
            results.lock().unwrap().insert(run, v);
            return Resp::new(204, "text/plain", Vec::<u8>::new());
        }
        if route == "/fp/echo" {
            return Resp::text("ok");
        }
        if let Some(name) = route.strip_prefix("/fp/") {
            if PAGES.contains(&name) {
                if let Ok(b) = std::fs::read(page_dir().join(name)) {
                    let ct = if name.ends_with(".js") { "text/javascript" } else { "text/html; charset=utf-8" };
                    return Resp::new(200, ct, b);
                }
            }
        }
        Resp::new(404, "text/plain", "not found")
    })
}

/// This computer's LAN address, found without sending anything (UDP connect only picks a route).
fn lan_ip() -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

struct Udp {
    ip: IpAddr,
    port: u16,
    count: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>,
}

fn udp_listener(ip: IpAddr) -> Udp {
    let s = UdpSocket::bind((ip, 0)).expect("udp bind");
    let port = s.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (c, v) = (count.clone(), seen.clone());
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = s.recv_from(&mut buf) {
            c.fetch_add(1, Ordering::SeqCst);
            let kind = if n >= 2 && buf[0] == 0x00 && buf[1] == 0x01 { "STUN binding request" } else { "other" };
            let mut l = v.lock().unwrap();
            if l.len() < 20 {
                l.push(format!("{n} bytes from {from}: {kind}"));
            }
        }
    });
    Udp { ip, port, count, seen }
}

fn wait_result(results: &Results, label: &str, secs: u64) -> Option<Value> {
    pump::until(Duration::from_secs(secs), || results.lock().unwrap().contains_key(label));
    results.lock().unwrap().get(label).cloned()
}

#[derive(Default)]
struct WvOpts<'a> {
    args: String,
    profile: &'a str,
    inprivate: bool,
    harden: bool,
    init_script: Option<&'a str>,
    cdp_ua: Option<String>,
    set_ua: Option<String>,
    prefs: Option<Value>,
    proxy: Option<&'a Proxy>,
    netlog: bool,
    /// Start the environment with tracking prevention off (WebView2's default is on).
    no_tracking_prevention: bool,
}

/// One page load in a fresh WebView2 environment. Returns facts about the run; the page's own
/// result arrives in `results` under `label`.
fn wv_run(label: &str, url: &str, results: &Results, o: WvOpts) -> Value {
    let udf = crate::fresh_udf(label);
    let profile = if o.profile.is_empty() { "standard" } else { o.profile };
    if let Some(p) = &o.prefs {
        let dir = udf.join("EBWebView").join(format!("WV2Profile_{profile}"));
        std::fs::create_dir_all(&dir).expect("profile dir");
        std::fs::write(dir.join("Preferences"), p.to_string()).expect("prefs");
    }
    let netlog = udf.join("netlog.json");
    let mut args = o.args.clone();
    if o.netlog {
        args = format!("{args} --log-net-log={}", netlog.display());
    }
    let env = host::create_env(
        &udf,
        &host::EnvOpts { args: args.trim().to_string(), tracking_prevention: !o.no_tracking_prevention, ..Default::default() },
    );
    let hwnd = host::create_window(&format!("M8 {label}"), 1000, 700);
    let c = host::create_controller(&env, hwnd, profile, o.inprivate);
    let wv = host::webview(&c);
    let auth = Arc::new(Mutex::new(Vec::new()));
    if let Some(p) = o.proxy {
        crate::m5::credentials(&wv, p, auth.clone());
    }
    if o.harden {
        host::harden(&wv);
    }
    let mut setup = serde_json::Map::new();
    if let Some(js) = o.init_script {
        setup.insert("init_script".into(), json!(host::add_init_script(&wv, js).map(|_| "added")));
    }
    if let Some(ua) = &o.set_ua {
        let r = unsafe {
            wv.Settings()
                .and_then(|s| s.cast::<ICoreWebView2Settings2>())
                .and_then(|s| s.SetUserAgent(&HSTRING::from(ua.as_str())))
        };
        setup.insert("set_user_agent".into(), json!(r.map(|_| "set").map_err(|e| format!("{e:?}"))));
    }
    if let Some(params) = &o.cdp_ua {
        setup.insert("cdp_set_user_agent_override".into(), json!(host::cdp(&wv, "Emulation.setUserAgentOverride", params)));
    }
    let nav = host::navigate(&wv, url, host::T);
    let got = wait_result(results, label, 90).is_some();
    if !got {
        // The page could not post its result: read what it left on the page.
        let v = host::exec_json(&wv, "JSON.stringify(window.__fp || null)");
        if let Some(s) = v.as_str() {
            if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                if !parsed.is_null() {
                    results.lock().unwrap().insert(label.to_string(), parsed);
                }
            }
        }
    }
    let version = host::browser_version(&env);
    host::close(c);
    drop(wv);
    drop(env);
    host::destroy_window(hwnd);
    pump::sleep(Duration::from_secs(if o.netlog { 8 } else { 2 }));
    json!({
        "label": label,
        "runtime": version,
        "args": args,
        "profile": profile,
        "inprivate": o.inprivate,
        "navigation": format!("{nav:?}"),
        "posted_result": got,
        "setup": setup,
        "proxy_auth": auth.lock().unwrap().clone(),
        "netlog": o.netlog.then(|| netlog.display().to_string()),
    })
}

fn chrome_run(label: &str, url: &str, results: &Results) -> Value {
    let dir = std::env::temp_dir().join(format!("untrace-m8-chrome-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let child = Command::new(CHROME)
        .arg(format!("--user-data-dir={}", dir.display()))
        .args([
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--new-window",
            url,
        ])
        .spawn();
    let Ok(child) = child else {
        return json!({ "label": label, "error": "Chrome could not start" });
    };
    let got = wait_result(results, label, 90).is_some();
    pump::sleep(Duration::from_secs(1));
    // Ends only the browser started here (its own profile folder, its own process tree).
    let kill = Command::new("taskkill").args(["/PID", &child.id().to_string(), "/T", "/F"]).output();
    let mut removed = false;
    for _ in 0..20 {
        pump::sleep(Duration::from_millis(500));
        if std::fs::remove_dir_all(&dir).is_ok() || !dir.exists() {
            removed = true;
            break;
        }
    }
    json!({
        "label": label,
        "posted_result": got,
        "stopped": kill.map(|o| o.status.success()).unwrap_or(false),
        "temporary_profile_removed": removed,
    })
}

fn untrace_run(label: &str, url: &str, results: &Results) -> Value {
    let exe = crate::spikes_dir().join("..").join("target").join("release").join("examples").join("compat.exe");
    let data = crate::fresh_udf(label);
    let child = Command::new(&exe).arg("visit").arg(url).arg(&data).spawn();
    let Ok(mut child) = child else {
        return json!({ "label": label, "error": format!("{} could not start", exe.display()) });
    };
    let got = wait_result(results, label, 120).is_some();
    let exited = pump::until(Duration::from_secs(30), || matches!(child.try_wait(), Ok(Some(_))));
    if !exited {
        let _ = child.kill();
    }
    json!({ "label": label, "posted_result": got, "exited_by_itself": exited })
}

// ---------------------------------------------------------------------------------------------
// Analysis

fn flatten(v: &Value, prefix: &str, scalars: &mut BTreeMap<String, String>, sets: &mut BTreeMap<String, BTreeSet<String>>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten(x, &key, scalars, sets);
            }
        }
        Value::Array(a) => {
            sets.insert(
                prefix.to_string(),
                a.iter().map(|x| x.as_str().map(String::from).unwrap_or_else(|| x.to_string())).collect(),
            );
        }
        Value::String(s) => {
            scalars.insert(prefix.to_string(), s.clone());
        }
        other => {
            scalars.insert(prefix.to_string(), other.to_string());
        }
    }
}

const SKIP: &[&str] = &["where", "echo"];

fn diff(a: &Value, b: &Value) -> Value {
    let (mut sa, mut ta, mut sb, mut tb) = (BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    flatten(a, "", &mut sa, &mut ta);
    flatten(b, "", &mut sb, &mut tb);
    let keys: BTreeSet<&String> = sa.keys().chain(sb.keys()).collect();
    let scalars: Vec<Value> = keys
        .into_iter()
        .filter(|k| !SKIP.contains(&k.as_str()))
        .filter(|k| sa.get(*k) != sb.get(*k))
        .map(|k| json!({ "key": k, "a": sa.get(k), "b": sb.get(k) }))
        .collect();
    let skeys: BTreeSet<&String> = ta.keys().chain(tb.keys()).collect();
    let empty = BTreeSet::new();
    let sets: Vec<Value> = skeys
        .into_iter()
        .filter_map(|k| {
            let (x, y) = (ta.get(k).unwrap_or(&empty), tb.get(k).unwrap_or(&empty));
            let only_a: Vec<&String> = x.difference(y).collect();
            let only_b: Vec<&String> = y.difference(x).collect();
            (!only_a.is_empty() || !only_b.is_empty())
                .then(|| json!({ "key": k, "only_a": only_a, "only_b": only_b }))
        })
        .collect();
    json!({ "scalars": scalars, "sets": sets })
}

/// Values a page can compare between contexts to catch a lie.
const CONSISTENCY_KEYS: &[&str] = &[
    "userAgent", "appVersion", "platform", "vendor", "language", "languages", "hardwareConcurrency", "deviceMemory",
    "webdriver", "globalPrivacyControl", "uaBrands", "uaMobile", "uaPlatform", "uaHigh.fullVersionList",
    "uaHigh.uaFullVersion", "uaHigh.platformVersion", "uaHigh.architecture", "uaHigh.bitness", "intl", "tzOffset",
    "math", "canvas2d", "webgl.unmaskedRenderer", "chromeObject", "chromeWebview",
];
const CONTEXTS: &[&str] = &["blankFrame", "sameFrame", "crossFrame", "worker", "sharedWorker", "serviceWorker"];

fn scalars(v: &Value) -> BTreeMap<String, String> {
    let (mut s, mut t) = (BTreeMap::new(), BTreeMap::new());
    flatten(v, "", &mut s, &mut t);
    // A whole sub-object (e.g. chromeWebview) compares as one value.
    for (k, set) in t {
        s.insert(k, set.into_iter().collect::<Vec<_>>().join(","));
    }
    s
}

fn get_flat(m: &BTreeMap<String, String>, key: &str) -> String {
    if let Some(v) = m.get(key) {
        return v.clone();
    }
    let parts: Vec<String> = m
        .iter()
        .filter(|(k, _)| k.starts_with(&format!("{key}.")))
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    if parts.is_empty() { "(missing)".into() } else { parts.join(";") }
}

/// Every place where a context disagrees with the page itself, as "context: key".
fn mismatches(run: &Value) -> Vec<String> {
    let top = scalars(&run["top"]);
    let mut out = vec![];
    for ctx in CONTEXTS {
        let c = &run[*ctx];
        if !c.is_object() {
            out.push(format!("{ctx}: did not report ({})", c.as_str().unwrap_or("?")));
            continue;
        }
        let m = scalars(c);
        for k in CONSISTENCY_KEYS {
            let (a, b) = (get_flat(&top, k), get_flat(&m, k));
            if a != b {
                out.push(format!("{ctx}: {k}"));
            }
        }
    }
    let bi = &run["blankImmediate"];
    let top_wv = run["top"]["chromeWebview"].is_object();
    if bi["chromeWebview"].as_bool() != Some(top_wv) {
        out.push("blankImmediate: chromeWebview".into());
    }
    out
}

fn headers_of(reqs: &[Req]) -> Vec<Value> {
    const KEEP: &[&str] = &[
        "user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "accept-language", "dnt", "sec-gpc",
        "accept-encoding",
    ];
    reqs.iter()
        .filter(|r| r.route().starts_with("/fp/") && r.route() != "/fp/result")
        .map(|r| {
            let ctx = if r.route() == "/fp/echo" {
                query(&r.path, "ctx").unwrap_or("?").to_string()
            } else {
                r.route().trim_start_matches("/fp/").to_string()
            };
            let h: serde_json::Map<String, Value> = r
                .headers
                .iter()
                .filter(|(k, _)| KEEP.contains(&k.to_ascii_lowercase().as_str()))
                .map(|(k, v)| (k.to_ascii_lowercase(), json!(v)))
                .collect();
            json!({ "ctx": ctx, "host": r.host, "headers": h })
        })
        .collect()
}

fn header_summary(h: &[Value]) -> Value {
    let distinct = |name: &str| -> Vec<String> {
        h.iter()
            .map(|x| x["headers"][name].as_str().unwrap_or("(absent)").to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    json!({
        "requests": h.len(),
        "sec-ch-ua": distinct("sec-ch-ua"),
        "user-agent": distinct("user-agent"),
        "accept-language": distinct("accept-language"),
        "sec-gpc": distinct("sec-gpc"),
        "dnt": distinct("dnt"),
        "brand_webview2_in_any_header": h.iter().any(|x| x["headers"]["sec-ch-ua"].as_str().unwrap_or("").contains("WebView2")),
    })
}

fn brands_from(s: &str) -> Vec<(String, String)> {
    s.split(", ")
        .filter_map(|b| b.rsplit_once('/'))
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

/// `Emulation.setUserAgentOverride` parameters equal to the engine's own values, minus the
/// WebView2 brand.
fn cdp_override(top: &Value) -> String {
    let strip = |s: &str| -> Vec<Value> {
        brands_from(s)
            .into_iter()
            .filter(|(n, _)| !n.contains("WebView2"))
            .map(|(n, v)| json!({ "brand": n, "version": v }))
            .collect()
    };
    let h = &top["uaHigh"];
    json!({
        "userAgent": top["userAgent"],
        "userAgentMetadata": {
            "brands": strip(top["uaBrands"].as_str().unwrap_or("")),
            "fullVersionList": strip(h["fullVersionList"].as_str().unwrap_or("")),
            "fullVersion": h["uaFullVersion"],
            "platform": top["uaPlatform"],
            "platformVersion": h["platformVersion"],
            "architecture": h["architecture"],
            "model": h["model"],
            "mobile": false,
            "bitness": h["bitness"],
            "wow64": h["wow64"] == "true" || h["wow64"] == true,
        }
    })
    .to_string()
}

const HIDE_WEBVIEW: &str = r#"(() => { try { delete window.chrome.webview; } catch (e) {} })();"#;

const STRIP_BRAND: &str = r#"(() => {
  try { delete window.chrome.webview; } catch (e) {}
  const P = window.NavigatorUAData && NavigatorUAData.prototype;
  if (!P) return;
  const strip = l => l.filter(b => !/WebView2/.test(b.brand));
  const bd = Object.getOwnPropertyDescriptor(P, 'brands');
  Object.defineProperty(P, 'brands', { configurable: true, enumerable: bd.enumerable, get: function () { return strip(bd.get.call(this)); } });
  const ghev = P.getHighEntropyValues;
  P.getHighEntropyValues = function (h) {
    return ghev.call(this, h).then(v => { if (v.brands) v.brands = strip(v.brands); if (v.fullVersionList) v.fullVersionList = strip(v.fullVersionList); return v; });
  };
  const tj = P.toJSON;
  P.toJSON = function () { const v = tj.call(this); v.brands = strip(v.brands); return v; };
})();"#;

fn rtc_summary(label: &str, results: &Results, udp: &Udp, before: usize, meta: Value, stun_name: &str) -> Value {
    let page = results.lock().unwrap().get(label).cloned().unwrap_or(Value::Null);
    let packets = udp.count.load(Ordering::SeqCst) - before;
    let netlog = meta["netlog"].as_str().map(|p| crate::s3::netlog_resolutions_pub(Path::new(p), &[stun_name.to_string()]));
    json!({
        "label": label,
        "udp_packets_to_lan_listener": packets,
        "candidates": page["candidates"],
        "ice_errors": page["iceErrors"],
        "loopback_data_channel": page["loopbackChannel"],
        "page_error": page["error"],
        "netlog_resolution_of_stun_name": netlog,
        "run": meta,
    })
}

/// Host names the engine connected to or requested, from its net-log (start order).
fn netlog_hosts(path: &Path) -> Value {
    let Ok(text) = std::fs::read_to_string(path) else { return json!("net-log missing") };
    let mut seen: Vec<String> = Vec::new();
    for cap in text.split("\"url\":\"").skip(1) {
        let url = cap.split('"').next().unwrap_or("");
        if let Some(rest) = url.split_once("://").map(|x| x.1) {
            let host = rest.split(['/', ':', '?']).next().unwrap_or("").to_string();
            if !host.is_empty() && !seen.contains(&host) {
                seen.push(host);
            }
        }
    }
    for cap in text.split("\"host\":\"").skip(1) {
        let host = cap.split(['"', ':']).next().unwrap_or("").to_string();
        if !host.is_empty() && !seen.contains(&host) {
            seen.push(host);
        }
    }
    json!(seen)
}

/// Runtime-update regression probe: does a page served by `SetVirtualHostNameToFolderMapping`
/// under a `.invalid` name load (bare, behind the proxy, with a catch-all request filter)?
fn vhost_case(label: &str, proxy: Option<&Proxy>, filter: bool, warm: bool, host_name: &str, extra_args: &str) -> Value {
    let udf = crate::fresh_udf(label);
    let folder = udf.join("pages");
    std::fs::create_dir_all(&folder).expect("pages");
    std::fs::write(folder.join("p.html"), "<!doctype html><title>vhost-ok</title><p>ok").expect("page");
    let args = format!("{} {extra_args}", proxy.map(|p| p.browser_arguments()).unwrap_or_default()).trim().to_string();
    let env = host::create_env(&udf, &host::EnvOpts { args: args.clone(), tracking_prevention: true, ..Default::default() });
    let version = host::browser_version(&env);
    let hwnd = host::create_window(&format!("M8 {label}"), 900, 600);
    let c = host::create_controller(&env, hwnd, "standard", false);
    let wv = host::webview(&c);
    host::harden(&wv);
    let auth = Arc::new(Mutex::new(Vec::new()));
    if let Some(p) = proxy {
        crate::m5::credentials(&wv, p, auth.clone());
    }
    if filter {
        unsafe {
            let w22: ICoreWebView2_22 = wv.cast().expect("WebView2_22");
            w22.AddWebResourceRequestedFilterWithRequestSourceKinds(
                w!("*"),
                COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL,
            )
            .expect("filter");
        }
    }
    let mapped = unsafe {
        wv.cast::<ICoreWebView2_3>().and_then(|w3| {
            w3.SetVirtualHostNameToFolderMapping(
                &HSTRING::from(host_name),
                &HSTRING::from(folder.as_os_str()),
                COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_DENY_CORS,
            )
        })
    };
    // As UNTRACE's start-up check does: one request to a check name, so the engine answers the
    // proxy's challenge and sends credentials from then on.
    let navs = Arc::new(Mutex::new(Vec::new()));
    crate::m5::nav_log(&wv, navs.clone());
    let warm_nav = if warm {
        let probe = proxy.map(|p| p.new_probe()).unwrap_or_default();
        Some(format!("{:?}", host::navigate(&wv, &format!("https://{probe}/"), host::T)))
    } else {
        None
    };
    let nav = host::navigate(&wv, &format!("https://{host_name}/p.html"), host::T);
    let loaded = host::wait_title(&wv, "vhost-ok", Duration::from_secs(8));
    pump::sleep(Duration::from_secs(2));
    let where_ = host::exec(&wv, "location.href + ' | ' + location.origin + ' | ' + document.title");
    host::close(c);
    drop(wv);
    drop(env);
    host::destroy_window(hwnd);
    pump::sleep(Duration::from_secs(1));
    json!({ "label": label, "runtime": version, "args": args, "mapped": mapped.is_ok(), "navigation": format!("{nav:?}"),
            "loaded": loaded, "page": where_, "warm_up": warm_nav, "events": navs.lock().unwrap().clone(), "proxy_auth": auth.lock().unwrap().clone() })
}

pub fn run() -> Value {
    let results: Results = Arc::new(Mutex::new(HashMap::new()));
    let fx = fixture::start(router(results.clone()), None);
    let port = fx.http_port;
    let base = format!("http://127.0.0.1:{port}");
    let cross = format!("http://localhost:{port}");
    let fp = |label: &str| format!("{base}/fp/fp.html?run={label}&cross={cross}");
    note(&format!("m8 server on {base}"));

    let mut runs = serde_json::Map::new();
    let mut headers = serde_json::Map::new();
    let mut record = |label: &str, meta: Value, mark: usize, runs: &mut serde_json::Map<String, Value>| {
        headers.insert(label.to_string(), json!(headers_of(&fx.since(mark))));
        runs.insert(label.to_string(), meta);
    };

    let only: Option<String> = std::env::args().nth(2);
    // A comma-separated list of label prefixes; nothing = every run.
    let want = |label: &str| only.as_deref().is_none_or(|o| o.split(',').any(|p| label.starts_with(p)));

    // 1. Baselines and UNTRACE.
    if want("chrome") {
        let m = fx.mark();
        let meta = chrome_run("chrome", &fp("chrome"), &results);
        record("chrome", meta, m, &mut runs);
    }
    if want("bare") || want("m-") {
        let m = fx.mark();
        let meta = wv_run("bare", &fp("bare"), &results, WvOpts::default());
        record("bare", meta, m, &mut runs);
    }
    for label in ["untrace", "untrace2"] {
        if want(label) {
            let m = fx.mark();
            let meta = untrace_run(label, &fp(label), &results);
            record(label, meta, m, &mut runs);
        }
    }

    // 2. Candidate measures against WebView2 tells, on a bare WebView2.
    let bare_top = results.lock().unwrap().get("bare").map(|v| v["top"].clone());
    if let Some(top) = bare_top.filter(|_| want("m-")) {
        let ua = top["userAgent"].as_str().unwrap_or_default().to_string();
        let override_params = cdp_override(&top);
        let ua_features = "--enable-features=msWebView2SetUserAgentOverrideOnIframes,msWebView2SetUserAgentOverrideOnWorkers,msWebView2SetUserAgentOverrideOnServiceWorker";
        let retain = "--enable-features=msWebView2RetainUserAgentMetadataOnSetUserAgent,msWebView2SetUserAgentOverrideOnIframes,msWebView2SetUserAgentOverrideOnWorkers,msWebView2SetUserAgentOverrideOnServiceWorker";
        let cases: Vec<(&str, WvOpts)> = vec![
            ("m-hide-webview", WvOpts { init_script: Some(HIDE_WEBVIEW), ..Default::default() }),
            ("m-script-brand", WvOpts { init_script: Some(STRIP_BRAND), ..Default::default() }),
            ("m-cdp-override", WvOpts { cdp_ua: Some(override_params.clone()), ..Default::default() }),
            (
                "m-cdp-override-features",
                WvOpts { cdp_ua: Some(override_params.clone()), args: ua_features.into(), ..Default::default() },
            ),
            ("m-set-ua", WvOpts { set_ua: Some(ua.clone()), ..Default::default() }),
            ("m-set-ua-retain", WvOpts { set_ua: Some(ua.clone()), args: retain.into(), ..Default::default() }),
        ];
        for (label, o) in cases {
            if want(label) {
                let m = fx.mark();
                let meta = wv_run(label, &fp(label), &results, o);
                record(label, meta, m, &mut runs);
            }
        }
    }

    // 2b. When does "DNT: 1" start, and what did the engine contact before it?
    let mut dnt = serde_json::Map::new();
    let dnt_proxy = want("dnt").then(|| {
        let p = Proxy::start(Mode::Automatic).expect("network layer");
        p.announce_local("127.0.0.1");
        p
    });
    let dnt_cases: Vec<(&str, WvOpts)> = vec![
        ("dnt-a", WvOpts { netlog: true, ..Default::default() }),
        ("dnt-b", WvOpts { netlog: true, ..Default::default() }),
        (
            "dnt-network-layer",
            WvOpts {
                args: dnt_proxy.as_ref().map(|p| p.browser_arguments()).unwrap_or_default(),
                proxy: dnt_proxy.as_ref(),
                netlog: true,
                ..Default::default()
            },
        ),
        ("dnt-pref-off", WvOpts { prefs: Some(json!({ "enable_do_not_track": false })), netlog: true, ..Default::default() }),
        ("dnt-no-field-trials", WvOpts { args: "--disable-field-trial-config".into(), netlog: true, ..Default::default() }),
        ("dnt-no-tracking-prevention", WvOpts { no_tracking_prevention: true, netlog: true, ..Default::default() }),
    ];
    for (label, o) in dnt_cases {
        if want(label) {
            let m = fx.mark();
            let meta = wv_run(label, &format!("{base}/fp/dnt.html?run={label}"), &results, o);
            let reqs = fx.since(m);
            let t_first = reqs.first().map(|r| r.t_ms).unwrap_or(0);
            let seq: Vec<Value> = reqs
                .iter()
                .filter(|r| r.route() == "/fp/echo")
                .map(|r| json!([r.t_ms - t_first, r.header("dnt").unwrap_or("-")]))
                .collect();
            let hosts = meta["netlog"].as_str().map(|p| netlog_hosts(Path::new(p))).unwrap_or(Value::Null);
            let prefs_after = std::fs::read_to_string(
                crate::udf_root().join(format!("{label}-{}", std::process::id())).join("EBWebView").join("WV2Profile_standard").join("Preferences"),
            )
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .map(|v| v["enable_do_not_track"].clone());
            dnt.insert(
                label.into(),
                json!({ "run": meta, "dnt_by_request_ms": seq, "engine_contacted": hosts, "pref_enable_do_not_track_after": prefs_after }),
            );
        }
    }
    if let Some(p) = &dnt_proxy {
        dnt.insert("network_layer_hosts".into(), json!(format!("{:?}", p.hosts())));
        p.stop();
    }

    // 2c. Virtual-host pages after a runtime update.
    let mut vhost = serde_json::Map::new();
    if want("vhost") {
        let p = Proxy::start(Mode::Automatic).expect("network layer");
        const SC: &str = "selfcheck.untrace.invalid";
        vhost.insert("proxy-authenticated".into(), vhost_case("vhost-auth", Some(&p), true, true, SC, ""));
        vhost.insert(
            "proxy-authenticated, other name".into(),
            vhost_case("vhost-auth-name", Some(&p), true, true, "selfcheck-pages.invalid", ""),
        );
        vhost.insert(
            "proxy-authenticated, hardening off".into(),
            vhost_case("vhost-auth-nohard", Some(&p), true, true, SC, "--disable-features=msWebView2HostResourceAccessHardening"),
        );
        vhost.insert("network_layer_hosts".into(), json!(format!("{:?}", p.hosts())));
        p.stop();
    }

    // 3. WebRTC.
    let mut rtc = serde_json::Map::new();
    if want("rtc") {
        if let Some(ip) = lan_ip() {
            let udp = udp_listener(ip);
            let stun_name = format!("stun-m8-{}.invalid", std::process::id());
            let rtc_url = |label: &str| {
                format!("{base}/fp/rtc.html?run={label}&lan={}&port={}&name={stun_name}", udp.ip, udp.port)
            };
            let proxy = Proxy::start(Mode::Automatic).expect("network layer");
            proxy.announce_local("127.0.0.1");
            proxy.announce_local("localhost");
            let pargs = proxy.browser_arguments();
            let pref = json!({ "webrtc": { "ip_handling_policy": "disable_non_proxied_udp" } });
            let cases: Vec<(&str, WvOpts)> = vec![
                ("rtc-bare", WvOpts { netlog: true, ..Default::default() }),
                ("rtc-network-layer", WvOpts { args: pargs.clone(), proxy: Some(&proxy), netlog: true, ..Default::default() }),
                (
                    "rtc-network-layer-switch",
                    WvOpts {
                        args: format!("{pargs} --force-webrtc-ip-handling-policy=disable_non_proxied_udp"),
                        proxy: Some(&proxy),
                        netlog: true,
                        ..Default::default()
                    },
                ),
                (
                    "rtc-network-layer-pref",
                    WvOpts { args: pargs.clone(), proxy: Some(&proxy), prefs: Some(pref.clone()), netlog: true, ..Default::default() },
                ),
                (
                    "rtc-network-layer-pref-inprivate",
                    WvOpts {
                        args: pargs.clone(),
                        proxy: Some(&proxy),
                        prefs: Some(pref.clone()),
                        profile: "temp-m8",
                        inprivate: true,
                        netlog: true,
                        ..Default::default()
                    },
                ),
            ];
            for (label, o) in cases {
                if want(label) {
                    let before = udp.count.load(Ordering::SeqCst);
                    let meta = wv_run(label, &rtc_url(label), &results, o);
                    rtc.insert(label.into(), rtc_summary(label, &results, &udp, before, meta, &stun_name));
                }
            }
            if want("rtc-untrace") {
                let before = udp.count.load(Ordering::SeqCst);
                let meta = untrace_run("rtc-untrace", &rtc_url("rtc-untrace"), &results);
                rtc.insert("rtc-untrace".into(), rtc_summary("rtc-untrace", &results, &udp, before, meta, &stun_name));
            }
            rtc.insert("listener".into(), json!({ "lan_ip": udp.ip.to_string(), "port": udp.port, "seen": udp.seen.lock().unwrap().clone() }));
            proxy.stop();
        } else {
            rtc.insert("error".into(), json!("no LAN address found"));
        }
    }

    // 4. Analysis.
    let res = results.lock().unwrap().clone();
    let fp_runs: Vec<&String> = runs.keys().collect();
    let mut consistency = serde_json::Map::new();
    let mut header_sum = serde_json::Map::new();
    for l in &fp_runs {
        if let Some(r) = res.get(*l) {
            consistency.insert((*l).clone(), json!(mismatches(r)));
        }
        if let Some(h) = headers.get(*l).and_then(|v| v.as_array()) {
            header_sum.insert((*l).clone(), header_summary(h));
        }
    }
    let pair = |a: &str, b: &str| -> Value {
        match (res.get(a), res.get(b)) {
            (Some(x), Some(y)) => diff(&x["top"], &y["top"]),
            _ => json!("(missing run)"),
        }
    };
    let mut diffs = serde_json::Map::new();
    for (a, b) in [("chrome", "bare"), ("bare", "untrace"), ("untrace", "untrace2"), ("chrome", "untrace")] {
        diffs.insert(format!("{a} vs {b}"), pair(a, b));
    }
    for l in &fp_runs {
        if l.starts_with("m-") {
            diffs.insert(format!("bare vs {l}"), pair("bare", l));
        }
    }

    json!({
        "server": base,
        "runs": runs,
        "consistency_mismatches": consistency,
        "headers": header_sum,
        "diffs_top": diffs,
        "webrtc": rtc,
        "dnt": dnt,
        "vhost": vhost,
        "raw": res,
        "raw_headers": headers,
    })
}
