//! Shared setup for spikes that need real-looking host names: a fixture server (HTTP + TLS)
//! reached through the spike proxy, which maps `<name>-<pid>.test` (and a few explicit
//! names) to the fixture. Nothing leaves the machine; unknown hosts are refused and logged.

use std::{sync::mpsc, sync::Arc};

use webview2_com::{Microsoft::Web::WebView2::Win32::*, *};
use windows::core::*;

use crate::{
    fixture::{self, Fixture, Router},
    host, proxy, pump,
};

pub struct Kit {
    pub fx: Fixture,
    pub px: proxy::Proxy,
    pub suffix: String,
}

pub fn sfx() -> String {
    format!("-{}.test", std::process::id())
}

/// `names`: short labels (become `<label>-<pid>.test`); `exact`: literal host names to map too.
pub fn start(names: &[&str], exact: &[&str], router: Router) -> Kit {
    let suffix = sfx();
    let mut all: Vec<String> = names.iter().map(|n| format!("{n}{suffix}")).collect();
    all.extend(exact.iter().map(|s| s.to_string()));
    let refs: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
    let fx = fixture::start(router, Some(fixture::tls_config(&refs)));
    let (hp, sp) = (fx.http_port, fx.https_port);
    let (s2, exact): (String, Vec<String>) = (suffix.clone(), exact.iter().map(|s| s.to_string()).collect());
    let mapper: proxy::Mapper = Arc::new(move |h: &str, port: u16| {
        if h.ends_with(&s2) || exact.iter().any(|e| e == h) {
            Some(if port == 443 { sp } else { hp })
        } else {
            None
        }
    });
    let px = proxy::start(mapper, false);
    Kit { fx, px, suffix }
}

impl Kit {
    pub fn host(&self, label: &str) -> String {
        format!("{label}{}", self.suffix)
    }
    pub fn env_args(&self, extra: &str) -> String {
        format!("--proxy-server=http://127.0.0.1:{} {extra}", self.px.port)
    }
}

pub fn cookie_count(wv: &ICoreWebView2, uri: &str) -> i64 {
    let w2: ICoreWebView2_2 = wv.cast().expect("WebView2_2");
    let cm = unsafe { w2.CookieManager().expect("cookie manager") };
    let (tx, rx) = mpsc::channel();
    let h = GetCookiesCompletedHandler::create(Box::new(move |hr, list| {
        let mut n = 0u32;
        if hr.is_ok() {
            if let Some(l) = list {
                unsafe { l.Count(&mut n)? };
            }
        }
        let _ = tx.send(if hr.is_ok() { n as i64 } else { -1 });
        Ok(())
    }));
    unsafe {
        if cm.GetCookies(&HSTRING::from(uri), &h).is_err() {
            return -2;
        }
    }
    pump::wait(&rx, host::T).unwrap_or(-3)
}

pub fn profile(wv: &ICoreWebView2) -> ICoreWebView2Profile {
    let w13: ICoreWebView2_13 = wv.cast().expect("WebView2_13");
    unsafe { w13.Profile().expect("profile") }
}

pub fn clear_browsing_data(wv: &ICoreWebView2, kinds: COREWEBVIEW2_BROWSING_DATA_KINDS) -> bool {
    let p2: ICoreWebView2Profile2 = profile(wv).cast().expect("Profile2");
    let (tx, rx) = mpsc::channel();
    let h = ClearBrowsingDataCompletedHandler::create(Box::new(move |hr| {
        let _ = tx.send(hr.is_ok());
        Ok(())
    }));
    unsafe {
        if p2.ClearBrowsingData(kinds, &h).is_err() {
            return false;
        }
    }
    pump::wait(&rx, host::T).unwrap_or(false)
}

/// Standard preparation for a content view in a kit environment.
pub fn prepare(wv: &ICoreWebView2) {
    host::harden(wv);
    host::allow_fixture_certs(wv);
}
