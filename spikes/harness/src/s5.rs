//! S5 — Sessions & storage: does an InPrivate (temporary) profile leave data on disk, are
//! profiles isolated, does clearing history remove it from disk, are cookies encrypted at
//! rest, do downloads get Mark-of-the-Web, and where do crash dumps go when custom crash
//! reporting is enabled?

use std::{
    path::{Path, PathBuf},
    sync::{mpsc, Arc},
    time::Duration,
};

use serde_json::{json, Value};
use webview2_com::{Microsoft::Web::WebView2::Win32::*, *};
use windows::core::*;

use crate::{
    fixture::{Req, Resp},
    host, kit, note, pump,
};

const STORE_PAGE: &str = r#"<!doctype html><title>store</title><script>
(async () => {
  const M = new URLSearchParams(location.search).get('m');
  document.cookie = 'jc=' + M + '; max-age=86400; path=/; secure';
  localStorage.setItem('ls', M);
  try {
    await new Promise((res, rej) => {
      const r = indexedDB.open('db', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('s');
      r.onsuccess = () => { const tx = r.result.transaction('s', 'readwrite'); tx.objectStore('s').put(M, 'k'); tx.oncomplete = res; tx.onerror = rej; };
      r.onerror = rej;
    });
  } catch (e) {}
  try { const c = await caches.open('c'); await c.put('/s5/cached', new Response('CACHE' + M)); } catch (e) {}
  document.title = 'stored';
})();
</script>"#;

fn scan(dir: &Path, marker: &str) -> Vec<String> {
    let ascii = marker.as_bytes().to_vec();
    let utf16: Vec<u8> = marker.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut hits = vec![];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(b) = std::fs::read(&p) {
                if b.len() > 64 * 1024 * 1024 {
                    continue;
                }
                let a = b.windows(ascii.len()).any(|w| w == ascii.as_slice());
                let u = b.windows(utf16.len()).any(|w| w == utf16.as_slice());
                if a || u {
                    let rel = p.strip_prefix(dir).unwrap_or(&p).display().to_string();
                    hits.push(format!("{rel}{}", if u && !a { " (utf16)" } else { "" }));
                }
            }
        }
    }
    hits.sort();
    hits
}

fn dirs_named(root: &Path, needle: &str) -> Vec<String> {
    let mut out = vec![];
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().map(|n| n.to_string_lossy().to_lowercase().contains(needle)).unwrap_or(false) {
                    out.push(p.strip_prefix(root).unwrap_or(&p).display().to_string());
                }
                stack.push(p);
            }
        }
    }
    out
}

fn visit_store(wv: &ICoreWebView2, k: &kit::Kit, marker: &str) -> bool {
    let url = format!("https://{}/s5/store.html?m={marker}", k.host("site"));
    let _ = host::navigate(wv, &url, host::T);
    host::wait_title(wv, "stored", Duration::from_secs(10))
}

fn download(wv: &ICoreWebView2, k: &kit::Kit, dir: &Path) -> Value {
    let _ = std::fs::create_dir_all(dir);
    let target = dir.join("spike-download.exe");
    let _ = std::fs::remove_file(&target);
    let w4: ICoreWebView2_4 = wv.cast().expect("WebView2_4");
    let (tx, rx) = mpsc::channel::<String>();
    let t2 = target.clone();
    let mut tok = 0i64;
    let h = DownloadStartingEventHandler::create(Box::new(move |_w, args| {
        if let Some(a) = args {
            let mut p = PWSTR::null();
            unsafe { a.ResultFilePath(&mut p)? };
            let suggested = host::take(p);
            unsafe {
                a.SetResultFilePath(&HSTRING::from(t2.as_os_str()))?;
                a.SetHandled(true)?; // suppress the runtime's own download UI
            }
            let _ = tx.send(suggested);
        }
        Ok(())
    }));
    unsafe { w4.add_DownloadStarting(&h, &mut tok).expect("download handler") };
    let url = format!("https://{}/s5/file.exe", k.host("dl"));
    let _ = host::navigate(wv, &url, Duration::from_secs(5));
    let suggested = pump::wait(&rx, Duration::from_secs(10));
    let done = pump::until(Duration::from_secs(15), || target.exists());
    pump::sleep(Duration::from_millis(1500));
    let ads = std::fs::read_to_string(format!("{}:Zone.Identifier", target.display())).ok();
    json!({
        "download_starting_raised": suggested.is_some(),
        "suggested_path": suggested,
        "file_written": done,
        "zone_identifier": ads,
    })
}

pub fn run() -> Value {
    let pid = std::process::id();
    let router: crate::fixture::Router = Arc::new(|r: &Req| match r.route() {
        "/s5/store.html" => {
            let m = r.path.split("m=").nth(1).unwrap_or("").to_string();
            Resp::html(STORE_PAGE).with("Set-Cookie", format!("hc={m}; Max-Age=86400; Path=/; Secure"))
        }
        "/s5/file.exe" => Resp::new(200, "application/octet-stream", b"MZ-spike-not-a-real-exe".to_vec())
            .with("Content-Disposition", "attachment; filename=\"spike-download.exe\""),
        _ => Resp::text("ok"),
    });
    let k = kit::start(&["site", "dl"], &[], router);
    let udf = crate::fresh_udf("s5");
    let env = host::create_env(
        &udf,
        &host::EnvOpts { args: k.env_args(""), tracking_prevention: true, crash_local: true, ..Default::default() },
    );
    let hwnd = host::create_window("S5 sessions & storage", 900, 650);

    let m_persist = format!("UNTRACEP{pid}PERSIST");
    let m_private = format!("UNTRACEP{pid}PRIVATE");
    let m_hist = format!("UNTRACEP{pid}HISTCLR");
    let site = format!("https://{}/", k.host("site"));

    // A: persistent profile (positive control for the disk scan).
    let ca = host::create_controller(&env, hwnd, "persistA", false);
    let wa = host::webview(&ca);
    kit::prepare(&wa);
    let a_stored = visit_store(&wa, &k, &m_persist);
    let a_cookies = kit::cookie_count(&wa, &site);

    // B: InPrivate profile.
    let cb = host::create_controller(&env, hwnd, "tempB", true);
    let wb = host::webview(&cb);
    kit::prepare(&wb);
    let b_stored = visit_store(&wb, &k, &m_private);
    let b_cookies = kit::cookie_count(&wb, &site);

    // Isolation: a second InPrivate profile and a second persistent profile see nothing.
    let cc = host::create_controller(&env, hwnd, "tempC", true);
    let wc = host::webview(&cc);
    let c_cookies = kit::cookie_count(&wc, &site);
    let cd = host::create_controller(&env, hwnd, "persistD", false);
    let wd = host::webview(&cd);
    let d_cookies_before = kit::cookie_count(&wd, &site);

    // H: persistent profile that clears history after the visit.
    let ch = host::create_controller(&env, hwnd, "persistH", false);
    let wh = host::webview(&ch);
    kit::prepare(&wh);
    let h_stored = visit_store(&wh, &k, &m_hist);
    let _ = host::navigate(&wh, "about:blank", host::T);
    let h_cleared = kit::clear_browsing_data(&wh, COREWEBVIEW2_BROWSING_DATA_KINDS_BROWSING_HISTORY);

    // Downloads + Mark-of-the-Web.
    let dl = download(&wa, &k, &crate::udf_root().join(format!("dl-{pid}")));

    // Crash dumps: where do they go, and does a renderer crash produce one locally?
    let env11: ICoreWebView2Environment11 = env.cast().expect("Environment11");
    let mut p = PWSTR::null();
    let crash_dir = unsafe { env11.FailureReportFolderPath(&mut p).ok().map(|_| host::take(p)) };
    let count = |d: &Option<String>| d.as_ref().map(|d| walk_count(Path::new(d))).unwrap_or(0);
    let before = count(&crash_dir);
    let crash_call = host::cdp(&wd, "Page.crash", "{}");
    pump::sleep(Duration::from_secs(6));
    let after = count(&crash_dir);

    // Close everything; let the browser exit, then scan the disk.
    for c in [ca, cb, cc, cd, ch] {
        host::close(c);
    }
    host::destroy_window(hwnd);
    drop(env);
    note("waiting for browser exit before disk scan");
    pump::sleep(Duration::from_secs(6));

    let a_hits = scan(&udf, &m_persist);
    let b_hits = scan(&udf, &m_private);
    let h_hits = scan(&udf, &m_hist);
    json!({
        "spike": "S5 sessions & storage",
        "persistent_A": { "page_stored": a_stored, "cookies_visible": a_cookies, "disk_hits": a_hits },
        "inprivate_B": {
            "page_stored": b_stored, "cookies_visible_during_session": b_cookies, "disk_hits_after_close": b_hits,
            "profile_dirs_named_tempb": dirs_named(&udf, "tempb"),
        },
        "isolation": { "inprivate_C_sees_cookies": c_cookies, "persistent_D_sees_cookies": d_cookies_before },
        "history_clear_H": { "page_stored": h_stored, "clear_ok": h_cleared, "disk_hits_after_clear": h_hits },
        "download": dl,
        "crash": {
            "failure_report_folder": crash_dir, "custom_crash_reporting": true,
            "page_crash_cdp": format!("{crash_call:?}"), "files_before": before, "files_after": after,
        },
        "udf": udf.display().to_string(),
    })
}

fn walk_count(d: &Path) -> usize {
    let mut n = 0;
    let mut stack: Vec<PathBuf> = vec![d.to_path_buf()];
    while let Some(x) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&x) {
            for e in rd.flatten() {
                if e.path().is_dir() {
                    stack.push(e.path());
                } else {
                    n += 1;
                }
            }
        }
    }
    n
}
