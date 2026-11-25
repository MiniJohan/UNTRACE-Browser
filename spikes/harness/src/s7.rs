//! S7 (M5 pre-check) — Local Network Access under the loopback proxy.
//!
//! Chromium decides whether a page may reach the local network from the *address it connected
//! to*. Through an explicit proxy that is the proxy's own address (WICG LNA §4.2). Question: does
//! routing pages through UNTRACE's loopback proxy switch the engine's local-network protection
//! off, and does a candidate fix restore it?
//!
//! A "device" server on loopback stands in for the local network (public → loopback is checked
//! the same way as public → local). Everything runs on this machine.
//!
//! - C0 no proxy: the page's port is declared public with `--ip-address-space-overrides`.
//! - C1 the S3 design: `--proxy-server` + `--proxy-bypass-list=<-loopback>` (loopback through
//!   the proxy too).
//! - C2 candidate fix: the proxy's address declared public, local destinations bypass the proxy
//!   (Chromium's default loopback bypass plus private ranges), so the engine itself connects to
//!   them and sees their real address.

use std::{sync::Arc, sync::Mutex, time::Duration};

use serde_json::{json, Value};
use webview2_com::{Microsoft::Web::WebView2::Win32::*, *};
use windows::core::*;

use crate::{
    fixture::{self, Req, Resp},
    host, note, proxy, pump,
};

fn page(pid: u32, device_port: u16) -> String {
    r#"<!doctype html><html><head><meta charset=utf-8><title>s7</title></head><body>s7
<script>
const r = {};
async function t(name, url) {
  try { const x = await fetch(url, { mode: 'no-cors', cache: 'no-store' }); r[name] = 'ok:' + x.type; }
  catch (e) { r[name] = 'error:' + e.message; }
}
(async () => {
  await Promise.all([
    t('ip_literal', 'http://127.0.0.1:{DP}/s7/ip_literal'),
    t('localhost', 'http://localhost:{DP}/s7/localhost'),
    t('public_name_to_local', 'https://rebind-{PID}.test/s7/public_name_to_local'),
  ]);
  window.__r = r; document.title = 's7-done';
})();
</script></body></html>"#
        .replace("{PID}", &pid.to_string())
        .replace("{DP}", &device_port.to_string())
}

fn permission_log(wv: &ICoreWebView2) -> Arc<Mutex<Vec<String>>> {
    let log = Arc::new(Mutex::new(Vec::new()));
    let l2 = log.clone();
    let mut token = 0i64;
    let h = PermissionRequestedEventHandler::create(Box::new(move |_s, args| {
        if let Some(a) = args {
            let mut kind = COREWEBVIEW2_PERMISSION_KIND(0);
            let mut p = PWSTR::null();
            unsafe {
                a.PermissionKind(&mut kind)?;
                a.Uri(&mut p)?;
                a.SetState(COREWEBVIEW2_PERMISSION_STATE_DENY)?; // UNTRACE denies unknown kinds
            }
            l2.lock().unwrap().push(format!("kind={} uri={}", kind.0, host::take(p)));
        }
        Ok(())
    }));
    unsafe { wv.add_PermissionRequested(&h, &mut token).expect("permission handler") };
    log
}

/// The engine's own view of each request's address spaces and local-network policy.
fn cdp_log(wv: &ICoreWebView2) -> Arc<Mutex<Vec<Value>>> {
    let log = Arc::new(Mutex::new(Vec::new()));
    let _ = host::cdp(wv, "Network.enable", "{}");
    for ev in ["Network.requestWillBeSentExtraInfo", "Network.responseReceivedExtraInfo", "Network.loadingFailed"] {
        let l2 = log.clone();
        let name = ev.to_string();
        let recv = unsafe { wv.GetDevToolsProtocolEventReceiver(&HSTRING::from(ev)).expect("receiver") };
        let mut token = 0i64;
        let h = DevToolsProtocolEventReceivedEventHandler::create(Box::new(move |_s, args| {
            if let Some(a) = args {
                let mut p = PWSTR::null();
                unsafe { a.ParameterObjectAsJson(&mut p)? };
                let v: Value = serde_json::from_str(&host::take(p)).unwrap_or(Value::Null);
                let keep = json!({
                    "event": name,
                    "requestId": v["requestId"],
                    "clientSecurityState": v["clientSecurityState"],
                    "resourceIPAddressSpace": v["resourceIPAddressSpace"],
                    "errorText": v["errorText"],
                    "blockedReason": v["blockedReason"],
                    "corsErrorStatus": v["corsErrorStatus"],
                    "url": v["associatedCookies"].as_array().map(|_| Value::Null).unwrap_or(Value::Null),
                    "headersHost": v["headers"]["Host"].clone(),
                });
                l2.lock().unwrap().push(keep);
            }
            Ok(())
        }));
        unsafe { recv.add_DevToolsProtocolEventReceived(&h, &mut token).expect("cdp event") };
    }
    log
}

fn run_case(name: &str, args: String, url: &str, device: &fixture::Fixture, px: Option<&proxy::Proxy>) -> Value {
    note(&format!("{name}: {args}"));
    let udf = crate::fresh_udf(&format!("s7{name}"));
    let env = host::create_env(&udf, &host::EnvOpts { args: args.clone(), tracking_prevention: true, ..Default::default() });
    let version = host::browser_version(&env);
    let hwnd = host::create_window(&format!("S7 {name}"), 800, 600);
    let c = host::create_controller(&env, hwnd, "default", false);
    let wv = host::webview(&c);
    host::allow_fixture_certs(&wv);
    let perms = permission_log(&wv);
    let cdp = cdp_log(&wv);
    let mark = device.mark();
    let pmark = px.map(|p| p.events().len()).unwrap_or(0);
    let nav = host::navigate(&wv, url, host::T);
    let done = host::wait_title(&wv, "s7-done", Duration::from_secs(15));
    let results = host::exec_json(&wv, "JSON.stringify(window.__r || null)");
    pump::sleep(Duration::from_millis(500));
    let device_saw: Vec<String> = device.since(mark).iter().map(|r: &Req| r.route().to_string()).collect();
    let proxy_saw: Vec<String> = px
        .map(|p| p.events()[pmark..].iter().map(|e| format!("{} {}", e.kind, e.target)).collect())
        .unwrap_or_default();
    host::close(c);
    host::destroy_window(hwnd);
    drop(env);
    json!({
        "args": args,
        "runtime": version,
        "page": url,
        "navigation": format!("{nav:?}"),
        "page_script_done": done,
        "fetch_results": serde_json::from_str::<Value>(results.as_str().unwrap_or("null")).unwrap_or(results),
        "permission_requests": perms.lock().unwrap().clone(),
        "cdp_events": cdp.lock().unwrap().clone(),
        "device_server_received": device_saw,
        "proxy_saw": proxy_saw,
    })
}

pub fn run() -> Value {
    let pid = std::process::id();
    let pub_host = format!("pub-{pid}.test");
    let rebind_host = format!("rebind-{pid}.test");

    // The local "device": plain HTTP for the IP-literal and localhost cases, TLS for the public
    // name that resolves to it.
    let device = fixture::start(
        Arc::new(|_r: &Req| Resp::text("device").with("Access-Control-Allow-Origin", "*")),
        Some(fixture::tls_config(&[rebind_host.as_str()])),
    );
    let dp = device.http_port;
    let dsp = device.https_port;

    // The public site.
    let web = {
        let p = pid;
        fixture::start(
            Arc::new(move |r: &Req| match r.route() {
                "/s7/page.html" => Resp::html(page(p, dp)),
                _ => Resp::text("ok"),
            }),
            Some(fixture::tls_config(&[pub_host.as_str()])),
        )
    };
    let (wp, wsp) = (web.http_port, web.https_port);

    // Proxy "resolver": the public name → web fixture, the rebinding name → the device, and
    // loopback literals → themselves.
    let (ph, rh) = (pub_host.clone(), rebind_host.clone());
    let mapper: proxy::Mapper = Arc::new(move |h: &str, port: u16| {
        if h == ph {
            Some(if port == 443 { wsp } else { wp })
        } else if h == rh {
            Some(dsp)
        } else if (h == "127.0.0.1" || h == "localhost") && port == dp {
            Some(dp)
        } else {
            None
        }
    });
    let px = proxy::start(mapper, false);
    note(&format!("web http {wp} https {wsp}; device http {dp} https {dsp}; proxy {}", px.port));

    let c0 = run_case(
        "c0-no-proxy",
        format!("--ip-address-space-overrides=127.0.0.1:{wp}=public"),
        &format!("http://127.0.0.1:{wp}/s7/page.html"),
        &device,
        None,
    );
    let c1 = run_case(
        "c1-proxy-loopback-through",
        format!("--proxy-server=http://127.0.0.1:{} --proxy-bypass-list=<-loopback>", px.port),
        &format!("https://{pub_host}/s7/page.html"),
        &device,
        Some(&px),
    );
    let c2 = run_case(
        "c2-proxy-public-local-direct",
        format!(
            "--proxy-server=http://127.0.0.1:{p} --proxy-bypass-list=10.0.0.0/8;172.16.0.0/12;192.168.0.0/16;fc00::/7 \
             --ip-address-space-overrides=127.0.0.1:{p}=public",
            p = px.port
        ),
        &format!("https://{pub_host}/s7/page.html"),
        &device,
        Some(&px),
    );
    px.stop();
    json!({
        "spike": "S7 local network access under the loopback proxy",
        "c0_no_proxy": c0,
        "c1_s3_design": c1,
        "c2_candidate_fix": c2,
    })
}
