//! M5 probe — the real UNTRACE network layer (`untrace-net`) with the real engine:
//!
//! 1. DNS leak: page traffic through the proxy, then Chromium's own net-log is searched for
//!    host-resolution events for the page's names (S3 method). Expect none.
//! 2. Every name the page used reached the proxy (CONNECT), with credentials.
//! 3. First navigation of a fresh profile (InPrivate) without a warm-up: which completion events
//!    arrive when the proxy asks for credentials (D-026), and does the page load?
//! 4. Fail closed: the proxy stopped, the next load fails and the fixture receives nothing.
//!
//! Names resolve from the proxy's self-check table to the local fixture; nothing leaves the
//! machine.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::{json, Value};
use untrace_net::{Proxy, resolver::Mode};
use webview2_com::{Microsoft::Web::WebView2::Win32::*, *};
use windows::core::*;

use crate::{
    fixture::{self, Req, Resp},
    host, note, pump,
};

pub(crate) fn credentials(wv: &ICoreWebView2, proxy: &Proxy, log: Arc<Mutex<Vec<String>>>) {
    let wv10: ICoreWebView2_10 = wv.cast().expect("WebView2_10");
    let (user, pass) = proxy.credentials();
    let (user, pass, realm) = (user.to_string(), pass.to_string(), proxy.realm().to_string());
    let mut token = 0i64;
    let h = BasicAuthenticationRequestedEventHandler::create(Box::new(move |_s, args| {
        if let Some(a) = args {
            let mut p = PWSTR::null();
            unsafe { a.Challenge(&mut p)? };
            let challenge = host::take(p);
            let ours = challenge.contains(&realm);
            log.lock().unwrap().push(format!("auth requested (ours: {ours})"));
            if ours {
                unsafe {
                    let r = a.Response()?;
                    r.SetUserName(&HSTRING::from(user.as_str()))?;
                    r.SetPassword(&HSTRING::from(pass.as_str()))?;
                }
            }
        }
        Ok(())
    }));
    unsafe { wv10.add_BasicAuthenticationRequested(&h, &mut token).expect("auth handler") };
}

/// Every NavigationStarting / NavigationCompleted, in order.
pub(crate) fn nav_log(wv: &ICoreWebView2, log: Arc<Mutex<Vec<String>>>) {
    let mut t = 0i64;
    let l1 = log.clone();
    let h1 = NavigationStartingEventHandler::create(Box::new(move |_s, args| {
        if let Some(a) = args {
            let mut id = 0u64;
            unsafe { a.NavigationId(&mut id)? };
            l1.lock().unwrap().push(format!("starting id={id}"));
        }
        Ok(())
    }));
    let h2 = NavigationCompletedEventHandler::create(Box::new(move |_s, args| {
        if let Some(a) = args {
            let mut id = 0u64;
            let mut ok = BOOL(0);
            let mut st = COREWEBVIEW2_WEB_ERROR_STATUS(0);
            unsafe {
                a.NavigationId(&mut id)?;
                a.IsSuccess(&mut ok)?;
                a.WebErrorStatus(&mut st)?;
            }
            log.lock().unwrap().push(format!("completed id={id} ok={} status={}", ok.as_bool(), st.0));
        }
        Ok(())
    }));
    unsafe {
        wv.add_NavigationStarting(&h1, &mut t).expect("starting");
        wv.add_NavigationCompleted(&h2, &mut t).expect("completed");
    }
}

fn page(pid: u32, sp: u16) -> String {
    r#"<!doctype html><html><head><meta charset=utf-8><title>m5</title>
<link rel="dns-prefetch" href="//prefetch-{PID}.test"><link rel="preconnect" href="https://preconnect-{PID}.test:{SP}">
</head><body><img src="https://img-{PID}.test:{SP}/m5/img.png">
<script>
  fetch('https://api-{PID}.test:{SP}/m5/api', { mode: 'no-cors' }).catch(() => {});
  try { new WebSocket('wss://ws-{PID}.test:{SP}/m5/socket'); } catch (e) {}
  setTimeout(() => { document.title = 'm5-done'; }, 2500);
</script></body></html>"#
        .replace("{PID}", &pid.to_string())
        .replace("{SP}", &sp.to_string())
}

pub fn run() -> Value {
    let pid = std::process::id();
    let names: Vec<String> = ["page", "img", "api", "ws", "prefetch", "preconnect", "temp", "cancelled", "blocked", "plain"]
        .iter()
        .map(|n| format!("{n}-{pid}.test"))
        .collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let sp_cell = Arc::new(std::sync::OnceLock::<u16>::new());
    let sp2 = sp_cell.clone();
    let fx = fixture::start(
        Arc::new(move |r: &Req| match r.route() {
            "/m5/page.html" => Resp::html(page(pid, *sp2.get().unwrap_or(&0))),
            p if p.ends_with(".png") => Resp::png(),
            _ => Resp::text("ok"),
        }),
        Some(fixture::tls_config(&refs)),
    );
    let sp = fx.https_port;
    sp_cell.set(sp).ok();

    let proxy = Proxy::start(Mode::Automatic).expect("proxy");
    proxy
        .resolver()
        .set_test_hosts(names.iter().map(|n| (n.clone(), vec!["127.0.0.1".parse().unwrap()])).collect());
    for n in &names {
        proxy.announce_local(n); // the fixture is on this computer
    }
    note(&format!("fixture https {sp}; proxy {}", proxy.port()));

    // 1–2. Standard profile: page with sub-resources, prefetch hints and a WebSocket.
    let udf = crate::fresh_udf("m5");
    let netlog = udf.join("netlog.json");
    let args = format!("{} --log-net-log={}", proxy.browser_arguments(), netlog.display());
    let env = host::create_env(&udf, &host::EnvOpts { args: args.clone(), tracking_prevention: true, ..Default::default() });
    let version = host::browser_version(&env);
    let hwnd = host::create_window("M5 probe", 900, 650);
    let c = host::create_controller(&env, hwnd, "standard", false);
    let wv = host::webview(&c);
    host::allow_fixture_certs(&wv);
    let auth = Arc::new(Mutex::new(Vec::new()));
    let navs = Arc::new(Mutex::new(Vec::new()));
    credentials(&wv, &proxy, auth.clone());
    nav_log(&wv, navs.clone());
    let mark = fx.mark();
    let nav = host::navigate(&wv, &format!("https://page-{pid}.test:{sp}/m5/page.html"), host::T);
    let done = host::wait_title(&wv, "m5-done", Duration::from_secs(15));
    pump::sleep(Duration::from_millis(800));
    let served: Vec<String> = fx.since(mark).iter().map(|r| format!("{}{}", r.host, r.path)).collect();
    let standard_navs = navs.lock().unwrap().clone();
    let netlog_while_running = netlog.exists();
    let udf_files: Vec<String> = std::fs::read_dir(&udf).map(|r| r.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect()).unwrap_or_default();

    // 3. A fresh InPrivate profile: its first navigation meets the proxy's challenge.
    let c2 = host::create_controller(&env, hwnd, "temp-m5probe", true);
    let wv2 = host::webview(&c2);
    host::allow_fixture_certs(&wv2);
    let auth2 = Arc::new(Mutex::new(Vec::new()));
    let navs2 = Arc::new(Mutex::new(Vec::new()));
    credentials(&wv2, &proxy, auth2.clone());
    nav_log(&wv2, navs2.clone());
    let first = host::navigate(&wv2, &format!("https://temp-{pid}.test:{sp}/m5/page.html"), host::T);
    let temp_loaded = host::wait_title(&wv2, "m5-done", Duration::from_secs(15));
    pump::sleep(Duration::from_millis(500));
    let temp_navs = navs2.lock().unwrap().clone();

    // 5. A navigation cancelled at NavigationStarting, as UNTRACE's malware/phishing warning
    //    does: does the engine still open a connection to that host (speculative preconnect)?
    let cancelled_host = format!("cancelled-{pid}.test");
    {
        let ch = cancelled_host.clone();
        let bh = format!("blocked-{pid}.test");
        let mut t = 0i64;
        let h = NavigationStartingEventHandler::create(Box::new(move |_s, args| {
            if let Some(a) = args {
                let mut p = PWSTR::null();
                unsafe { a.Uri(&mut p)? };
                let u = host::take(p);
                if u.contains(&ch) || u.contains(&bh) || u.starts_with("http://plain-") {
                    unsafe { a.SetCancel(true)? };
                }
            }
            Ok(())
        }));
        unsafe { wv.add_NavigationStarting(&h, &mut t).expect("cancel handler") };
    }
    let mark3 = fx.mark();
    let cancelled_nav = host::navigate(&wv, &format!("https://{cancelled_host}:{sp}/m5/cancelled"), host::T);
    pump::sleep(Duration::from_secs(3));
    let cancelled_record = proxy.record(&cancelled_host);
    let cancelled_fixture: Vec<String> = fx.since(mark3).iter().map(|r| format!("{}{}", r.host, r.path)).collect();

    // 5b. The same, plus the page's own request answered with 403 in WebResourceRequested (the
    //     candidate fix): does the request event fire for a cancelled navigation, and does the
    //     server still see the request?
    let blocked_host = format!("blocked-{pid}.test");
    let doc_events = Arc::new(Mutex::new(Vec::new()));
    {
        let de = doc_events.clone();
        let env2 = env.clone();
        let mut t = 0i64;
        unsafe {
            wv.AddWebResourceRequestedFilter(&HSTRING::from(format!("*{blocked_host}*")), COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL)
                .expect("filter");
        }
        let h = WebResourceRequestedEventHandler::create(Box::new(move |_s, args| {
            if let Some(a) = args {
                let req = unsafe { a.Request()? };
                let mut p = PWSTR::null();
                unsafe { req.Uri(&mut p)? };
                let mut ctx = COREWEBVIEW2_WEB_RESOURCE_CONTEXT(0);
                unsafe { a.ResourceContext(&mut ctx)? };
                de.lock().unwrap().push(format!("context={} {}", ctx.0, host::take(p)));
                let resp = unsafe {
                    env2.CreateWebResourceResponse(None, 403, &HSTRING::from("Blocked"), &HSTRING::from("Cache-Control: no-store"))?
                };
                unsafe { a.SetResponse(&resp)? };
            }
            Ok(())
        }));
        unsafe { wv.add_WebResourceRequested(&h, &mut t).expect("request handler") };
    }
    let mark4 = fx.mark();
    let blocked_nav = host::navigate(&wv, &format!("https://{blocked_host}:{sp}/m5/blocked"), host::T);
    pump::sleep(Duration::from_secs(3));
    let blocked_record = proxy.record(&blocked_host);
    let blocked_fixture: Vec<String> = fx.since(mark4).iter().map(|r| format!("{}{}", r.host, r.path)).collect();

    // 5c. HTTPS-only's upgrade cancels the http:// navigation at NavigationStarting: does the
    //     plain-text request still go out?
    let mark5 = fx.mark();
    let plain_nav = host::navigate(&wv, &format!("http://plain-{pid}.test:{}/m5/plain?secret=1", fx.http_port), host::T);
    pump::sleep(Duration::from_secs(2));
    let plain_fixture: Vec<String> = fx.since(mark5).iter().map(|r| format!("{} {}{} tls={}", r.method, r.host, r.path, r.tls)).collect();

    // 6. Bypass detection (M5 exit criterion): UNTRACE's start-up check sends a request to a
    //    random check name. Through the proxy it must arrive; from an engine started without the
    //    proxy arguments (bypassed) it must not, so the check fails and Settings shows
    //    "not verified".
    let probe_js = |name: &str| format!("fetch('https://{name}/', {{ mode: 'no-cors', cache: 'no-store' }}).catch(() => 0); 0");
    let routed_name = proxy.new_probe();
    host::exec(&wv, &probe_js(&routed_name));
    let routed_seen = pump::until(Duration::from_secs(5), || proxy.probe_seen(&routed_name));
    let bypass_udf = crate::fresh_udf("m5bypass");
    let bypass_env = host::create_env(&bypass_udf, &host::EnvOpts { tracking_prevention: true, ..Default::default() });
    let bypass_c = host::create_controller(&bypass_env, hwnd, "standard", false);
    let bypass_wv = host::webview(&bypass_c);
    let _ = host::navigate(&bypass_wv, "about:blank", host::T);
    let bypass_name = proxy.new_probe();
    host::exec(&bypass_wv, &probe_js(&bypass_name));
    let bypass_seen = pump::until(Duration::from_secs(5), || proxy.probe_seen(&bypass_name));
    host::close(bypass_c);
    drop(bypass_wv);
    drop(bypass_env);

    // 4. Fail closed.
    let records = proxy.hosts();
    proxy.stop();
    pump::sleep(Duration::from_millis(300));
    let mark2 = fx.mark();
    let after_stop = host::navigate(&wv, &format!("https://page-{pid}.test:{sp}/m5/after-stop"), host::T);
    let loopback_after_stop = host::navigate(&wv, &format!("http://127.0.0.1:{}/m5/direct", fx.http_port), host::T);
    let reached_after_stop: Vec<String> = fx.since(mark2).iter().map(|r| format!("{}{}", r.host, r.path)).collect();

    host::close(c2);
    host::close(c);
    drop(wv2);
    drop(wv);
    host::destroy_window(hwnd);
    drop(env);
    pump::sleep(Duration::from_secs(10)); // browser processes exit and finish the net-log

    let leak = crate::s3::netlog_resolutions_pub(&netlog, &names);
    json!({
        "probe": "M5 network layer with the real engine",
        "runtime": version,
        "browser_arguments": args,
        "standard_profile": {
            "navigation": format!("{nav:?}"),
            "page_script_done": done,
            "navigation_events": standard_navs,
            "auth_events": auth.lock().unwrap().clone(),
            "fixture_served": served,
        },
        "proxy_records": records.iter().map(|r| json!({ "host": r.host, "connections": r.connections,
            "authenticated": r.authenticated, "refused_unauthenticated": r.refused_unauthenticated, "via": format!("{:?}", r.via) })).collect::<Vec<_>>(),
        "proxy_stats": serde_json::to_value(proxy.stats()).unwrap_or(Value::Null),
        "inprivate_first_navigation": {
            "first_completion": format!("{first:?}"),
            "page_loaded": temp_loaded,
            "navigation_events": temp_navs,
            "auth_events": auth2.lock().unwrap().clone(),
        },
        "fail_closed": {
            "named_after_stop": format!("{after_stop:?}"),
            "loopback_after_stop": format!("{loopback_after_stop:?}"),
            "fixture_requests_after_stop": reached_after_stop,
        },
        "netlog_dns_for_page_names": leak,
        "netlog_exists_while_running": netlog_while_running,
        "udf_files_while_running": udf_files,
        "cancelled_navigation_plus_request_blocked": {
            "completion": format!("{blocked_nav:?}"),
            "request_events": doc_events.lock().unwrap().clone(),
            "proxy_record": blocked_record.map(|r| json!({ "connections": r.connections, "authenticated": r.authenticated,
                "refused_unauthenticated": r.refused_unauthenticated })),
            "fixture_requests": blocked_fixture,
        },
        "bypass_detection": {
            "check_request_seen_through_proxy": routed_seen,
            "check_request_seen_from_engine_without_proxy_arguments": bypass_seen,
        },
        "cancelled_plain_http_navigation": {
            "completion": format!("{plain_nav:?}"),
            "fixture_requests": plain_fixture,
        },
        "cancelled_navigation": {
            "completion": format!("{cancelled_nav:?}"),
            "proxy_record": cancelled_record.map(|r| json!({ "connections": r.connections, "authenticated": r.authenticated,
                "refused_unauthenticated": r.refused_unauthenticated })),
            "fixture_requests": cancelled_fixture,
        },
    })
}
