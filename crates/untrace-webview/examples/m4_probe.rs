//! M4 engine-behaviour probe. Not shipped; offline (a local HTTP fixture on 127.0.0.1).
//!
//! Checks what the M4 design relies on:
//! 1. A tracking parameter on a page address: the server never sees it (307 from the request
//!    event), the page's own address is clean, the tab counts it.
//! 2. A server redirect *to* an address with tracking parameters.
//! 3. A frame address with tracking parameters.
//! 4. A form POST to an address with tracking parameters is left alone.
//! 5. Temporary tab: InPrivate profile, isolation from normal tabs, tracking level, worker
//!    requests counted once, nothing on disk after it closes (positive control in the
//!    normal profile).
//! 6. Cookies of the normal profile listed by site and deleted, read back.
//!
//! Usage: cargo run -p untrace-webview --example m4_probe -- <data-dir> <out.json>

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    rc::Rc,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use untrace_core::registry::{Applier, Value as PV};
use untrace_filter::{
    ListId,
    engine::{Filters, Source},
};
use untrace_webview::{ClearKinds, ContentHost, HostConfig, HostEvent, TRACKING_PREVENTION_ID, TabInfo};
use windows::{
    Win32::{
        Foundation::*,
        System::{
            Com::{COINIT_APARTMENTTHREADED, CoInitializeEx},
            LibraryLoader::GetModuleHandleW,
        },
        UI::WindowsAndMessaging::*,
    },
    core::*,
};

const TEMP_MARKER: &str = "M4TEMPRESIDUE7731";
const STD_MARKER: &str = "M4STDCONTROL7731";

// ------------------------------------------------------------------ fixture

fn serve(listener: TcpListener, log: Arc<Mutex<Vec<String>>>) {
    for stream in listener.incoming().flatten() {
        let log = log.clone();
        std::thread::spawn(move || handle(stream, log));
    }
}

fn handle(mut s: TcpStream, log: Arc<Mutex<Vec<String>>>) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let Ok(n) = s.read(&mut tmp) else { return };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let line = head.lines().next().unwrap_or_default().to_string();
    let len: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap_or(0))
        })
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let Ok(n) = s.read(&mut tmp) else { break };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body_in = String::from_utf8_lossy(&buf[head_end..]).to_string();
    log.lock().unwrap().push(if body_in.is_empty() {
        line.clone()
    } else {
        format!("{line} body={body_in}")
    });
    let target = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    let path = target.split('?').next().unwrap_or("/");
    let html = |b: &str| ("200 OK", "text/html", String::new(), b.to_string());
    let (status, ctype, extra, body) = match path {
        "/r" => ("302 Found", "text/plain", "Location: /landing?utm_source=redir&keep=1\r\n".into(), String::new()),
        "/frame-host" => html("<!doctype html><title>frames</title><iframe src=\"/landing?utm_medium=frame&k=2\"></iframe>"),
        "/form" => html(
            "<!doctype html><title>form</title><form id=f method=post action=\"/landing?utm_source=post&p=1\">\
             <input name=a value=b></form><script>setTimeout(() => f.submit(), 100)</script>",
        ),
        "/setcookie" => {
            let name = target.split("name=").nth(1).unwrap_or("x").to_string();
            let marker = if name == "temp" { TEMP_MARKER } else { STD_MARKER };
            (
                "200 OK",
                "text/html",
                format!("Set-Cookie: m4{name}={marker}; Path=/; Max-Age=3600\r\n"),
                format!(
                    "<!doctype html><title>cookie</title><script>localStorage.setItem('m4{name}', '{marker}'); \
                     indexedDB.open('m4{name}', 1).onupgradeneeded = e => e.target.result.createObjectStore('s').put('{marker}', 'k');</script>"
                ),
            )
        }
        "/worker" => html(
            "<!doctype html><title>worker</title><script>new SharedWorker('/sw.js').port.start()</script>",
        ),
        "/sw.js" => (
            "200 OK",
            "text/javascript",
            String::new(),
            "fetch('https://tracker.canary.untrace.invalid/from-worker', { mode: 'no-cors', cache: 'no-store' }).catch(() => {});".into(),
        ),
        _ => html("<!doctype html><title>landing</title><p>landing</p>"),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = s.write_all(resp.as_bytes());
}

// ------------------------------------------------------------------ driver

fn pump_once() {
    // SAFETY: standard message pumping on this (UI) thread.
    unsafe {
        let mut msg = MSG::default();
        while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        MsgWaitForMultipleObjects(None, false, 10, QS_ALLINPUT);
    }
}

fn pump_for(d: Duration) {
    let end = Instant::now() + d;
    while Instant::now() < end {
        pump_once();
    }
}

fn until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if cond() {
            return true;
        }
        pump_once();
    }
    cond()
}

extern "system" fn wndproc(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    // SAFETY: default handling for our own window.
    unsafe { DefWindowProcW(h, m, w, l) }
}

fn window() -> HWND {
    // SAFETY: plain Win32 window creation on the UI thread.
    unsafe {
        let hinst = HINSTANCE(GetModuleHandleW(None).expect("module").0);
        let class = w!("UntraceM4Probe");
        RegisterClassW(&WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            lpszClassName: class,
            hInstance: hinst,
            ..Default::default()
        });
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            w!("UNTRACE M4 probe"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            80,
            80,
            1000,
            700,
            None,
            None,
            Some(hinst),
            None,
        )
        .expect("window")
    }
}

fn tab(h: &ContentHost, id: u32) -> TabInfo {
    h.snapshot().tabs.into_iter().find(|t| t.id == id).expect("tab")
}

fn load(h: &ContentHost, id: u32, url: &str) {
    until(Duration::from_secs(10), || !tab(h, id).loading);
    h.activate(id);
    h.navigate_active(url);
    until(Duration::from_secs(5), || tab(h, id).loading);
    until(Duration::from_secs(15), || !tab(h, id).loading);
    pump_for(Duration::from_millis(800));
}

fn eval(h: &ContentHost, id: u32, js: &str) -> Value {
    let (tx, rx) = mpsc::channel();
    h.execute(id, js, move |j| {
        let _ = tx.send(j);
    });
    let mut out = Value::Null;
    until(Duration::from_secs(10), || match rx.try_recv() {
        Ok(j) => {
            out = serde_json::from_str(&j).unwrap_or(Value::String(j));
            true
        }
        Err(_) => false,
    });
    out
}

fn wait_result<T: 'static>(start: impl FnOnce(Box<dyn FnOnce(T)>)) -> Option<T> {
    let slot = Rc::new(std::cell::RefCell::new(None));
    let s2 = slot.clone();
    start(Box::new(move |v| *s2.borrow_mut() = Some(v)));
    until(Duration::from_secs(15), || slot.borrow().is_some());
    slot.borrow_mut().take()
}

fn files_containing(dir: &Path, needle: &[u8], out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            files_containing(&p, needle, out);
        } else if let Ok(bytes) = std::fs::read(&p)
            && bytes.windows(needle.len()).any(|w| w == needle)
        {
            out.push(p.display().to_string());
        }
    }
}

fn dirs(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn requests(log: &Arc<Mutex<Vec<String>>>, from: usize) -> Vec<String> {
    log.lock().unwrap()[from..].to_vec()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (data, out) = (std::path::PathBuf::from(&args[1]), &args[2]);
    let _ = std::fs::remove_dir_all(&data);

    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let log = Arc::new(Mutex::new(Vec::new()));
    let l2 = log.clone();
    std::thread::spawn(move || serve(listener, l2));

    // SAFETY: COM initialisation for this UI thread.
    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok().expect("COM");
    }
    let hwnd = window();
    let cfg = HostConfig {
        data_dir: data.clone(),
        profile: "standard".into(),
        devtools: false,
        https_only: true,
        background: [14, 14, 15],
        network: None,
        webrtc_proxy_only: true,
    };
    let host = ContentHost::new(hwnd, cfg, Rc::new(|_: HostEvent| {})).expect("host");
    let sources: Vec<Source> = ListId::ALL
        .iter()
        .map(|id| Source {
            id: *id,
            text: untrace_filter::info(*id).bundled,
        })
        .collect();
    host.set_filters(Filters::build(&sources));
    let mut r = RECT::default();
    // SAFETY: reading our own window's client rectangle.
    unsafe {
        let _ = GetClientRect(hwnd, &mut r);
    }
    host.set_bounds(r, true);
    let std_tab = host.new_tab(None);
    assert!(until(Duration::from_secs(30), || tab(&host, std_tab).ready), "engine");
    pump_for(Duration::from_millis(1500));
    let mut res = serde_json::Map::new();
    let href = "location.href";

    // 1. Page address with tracking parameters.
    let n = log.lock().unwrap().len();
    load(&host, std_tab, &format!("{base}/landing?utm_source=a&keep=1&fbclid=x"));
    let t = tab(&host, std_tab);
    res.insert(
        "1_page".into(),
        json!({ "href": eval(&host, std_tab, href), "tab_url": t.url, "params": t.blocked.params,
                "names": t.blocked.param_names, "server_saw": requests(&log, n) }),
    );

    // 2. Server redirect to an address with tracking parameters.
    let n = log.lock().unwrap().len();
    load(&host, std_tab, &format!("{base}/r"));
    let t = tab(&host, std_tab);
    res.insert(
        "2_redirect".into(),
        json!({ "href": eval(&host, std_tab, href), "params": t.blocked.params, "server_saw": requests(&log, n) }),
    );

    // 3. Frame address.
    let n = log.lock().unwrap().len();
    load(&host, std_tab, &format!("{base}/frame-host"));
    let t = tab(&host, std_tab);
    res.insert(
        "3_frame".into(),
        json!({ "frame_href": eval(&host, std_tab, "document.querySelector('iframe').contentWindow.location.href"),
                "params": t.blocked.params, "server_saw": requests(&log, n) }),
    );

    // 4. Form POST.
    let n = log.lock().unwrap().len();
    load(&host, std_tab, &format!("{base}/form"));
    until(Duration::from_secs(5), || log.lock().unwrap().len() > n + 1);
    pump_for(Duration::from_millis(1500));
    res.insert(
        "4_post".into(),
        json!({ "href": eval(&host, std_tab, href), "server_saw": requests(&log, n) }),
    );

    // 5. Temporary tab.
    let mut a = host.clone();
    let _ = a.apply(TRACKING_PREVENTION_ID, &PV::Choice("balanced".into()));
    let temp = host.new_temporary_tab(None);
    assert!(until(Duration::from_secs(30), || tab(&host, temp).ready), "temp tab");
    pump_for(Duration::from_millis(800));
    load(&host, temp, &format!("{base}/setcookie?name=temp"));
    let temp_seen = eval(&host, temp, "document.cookie + ' | ' + localStorage.getItem('m4temp')");
    load(&host, temp, &format!("{base}/worker"));
    pump_for(Duration::from_secs(3));
    let info = host.engine_info();
    load(&host, std_tab, &format!("{base}/landing"));
    let std_sees = eval(
        &host,
        std_tab,
        "document.cookie + ' | ' + localStorage.getItem('m4temp')",
    );
    let profiles_open = dirs(&data.join("EBWebView"));
    let sites_with_temp_open = wait_result(|d| host.cookie_sites(d));
    // Positive control: the same kinds of data in the normal profile reach the disk.
    load(&host, std_tab, &format!("{base}/setcookie?name=std"));
    host.close_tab(temp);
    pump_for(Duration::from_secs(8));
    let mut temp_files = Vec::new();
    files_containing(&data, TEMP_MARKER.as_bytes(), &mut temp_files);
    let mut std_files = Vec::new();
    files_containing(&data, STD_MARKER.as_bytes(), &mut std_files);
    res.insert(
        "5_temporary".into(),
        json!({
            "temp_tab_sees": temp_seen,
            "normal_tab_sees": std_sees,
            "temp_tracking_level": info.temp_tracking_prevention_level,
            "std_tracking_level": info.tracking_prevention_level,
            "worker_owner_std": info.worker_requests_tab,
            "worker_blocked_after_temp_worker": info.worker_requests_blocked,
            "profile_folders_while_open": profiles_open,
            "cookie_sites_while_temp_open": sites_with_temp_open.map(|r| r.map(|v| serde_json::to_value(v).unwrap())),
            "files_with_temp_marker_after_close": temp_files,
            "files_with_std_marker (positive control)": std_files,
            "profile_folders_after_close": dirs(&data.join("EBWebView")),
        }),
    );

    // 6. Normal-profile cookies: list, delete one site, read back.
    let before = wait_result(|d| host.cookie_sites(d));
    let left = wait_result(|d| host.delete_site_data("127.0.0.1", d));
    pump_for(Duration::from_secs(1));
    load(&host, std_tab, &format!("{base}/landing"));
    let after_js = eval(
        &host,
        std_tab,
        "document.cookie + ' | ' + localStorage.getItem('m4std')",
    );
    let cleared = wait_result(|d: Box<dyn FnOnce(std::result::Result<(), String>)>| {
        let started = host.clear_data(
            ClearKinds {
                cache: true,
                ..Default::default()
            },
            d,
        );
        assert!(started, "clear_data refused");
    });
    res.insert(
        "6_cookies".into(),
        json!({
            "sites_before": before.map(|r| r.map(|v| serde_json::to_value(v).unwrap())),
            "cookies_left_after_delete": left,
            "page_sees_after_delete": after_js,
            "cache_clear": cleared.map(|r| r.is_ok()),
        }),
    );

    // 7. After clearing everything the engine API offers, which files still name the site?
    // Leave the site first, so no open page records anything after the clearing.
    load(&host, std_tab, "about:blank");
    pump_for(Duration::from_secs(2));
    let all = wait_result(|d: Box<dyn FnOnce(std::result::Result<(), String>)>| {
        let started = host.clear_data(
            ClearKinds {
                cache: true,
                site_data: true,
                history: true,
                site_settings: std::env::var_os("M4_CLEAR_SETTINGS").is_some(),
            },
            d,
        );
        assert!(started, "clear_data refused");
    });
    // Preferences and other engine files are written lazily (Chromium commits about every
    // 10 s): wait, then close the engine so everything is flushed, then look.
    pump_for(Duration::from_secs(15));
    let needle = base.trim_start_matches("http://").to_string();
    let mut traces_running = Vec::new();
    files_containing(&data, b"127.0.0.1", &mut traces_running);
    host.shutdown();
    pump_for(Duration::from_secs(4));
    let mut traces = Vec::new();
    files_containing(&data, needle.as_bytes(), &mut traces);
    let mut host_only = Vec::new();
    files_containing(&data, b"127.0.0.1", &mut host_only);
    res.insert(
        "7_after_clear_all".into(),
        json!({ "cleared": all.map(|r| r.is_ok()), "files_naming_127.0.0.1_15s_after_clear": traces_running,
                "after_engine_closed": { "files_naming_host_and_port": traces, "files_naming_127.0.0.1": host_only } }),
    );

    // 8. D-039/D-028: UNTRACE's start-up clean-up of the engine's files, then a real restart on
    //    the same folder: pages must still load, and the temporary profile must not come back.
    let scrub = untrace_webview::scrub_engine_files(&data);
    let mut after_scrub = Vec::new();
    files_containing(&data, b"127.0.0.1", &mut after_scrub);
    let temp_dirs = |d: &std::path::Path| {
        dirs(&d.join("EBWebView"))
            .into_iter()
            .filter(|n| n.to_ascii_lowercase().starts_with("wv2profile_temp-"))
            .collect::<Vec<_>>()
    };
    let temp_after_scrub = temp_dirs(&data);
    let cfg2 = HostConfig {
        data_dir: data.clone(),
        profile: "standard".into(),
        devtools: false,
        https_only: true,
        background: [14, 14, 15],
        network: None,
        webrtc_proxy_only: true,
    };
    let host2 = ContentHost::new(hwnd, cfg2, Rc::new(|_: HostEvent| {})).expect("host after clean-up");
    host2.set_bounds(r, true);
    let t2 = host2.new_tab(None);
    let ready2 = until(Duration::from_secs(30), || tab(&host2, t2).ready);
    pump_for(Duration::from_millis(1500));
    load(&host2, t2, &format!("{base}/landing?keep=2"));
    let loaded2 = eval(&host2, t2, "document.title");
    pump_for(Duration::from_secs(3));
    let temp_after_restart = temp_dirs(&data);
    host2.shutdown();
    pump_for(Duration::from_secs(3));
    let local_state: Value = std::fs::read(data.join("EBWebView").join("Local State"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    res.insert(
        "8_engine_file_cleanup".into(),
        json!({
            "report": serde_json::to_value(&scrub).unwrap(),
            "files_naming_127.0.0.1_after_cleanup": after_scrub,
            "temp_folders_after_cleanup": temp_after_scrub,
            "engine_restarted": ready2,
            "page_after_restart": loaded2,
            "temp_folders_after_restart": temp_after_restart,
            "local_state_last_used_after_restart": local_state["profile"]["last_used"],
        }),
    );

    let doc = Value::Object(res);
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    std::fs::write(out, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
}
