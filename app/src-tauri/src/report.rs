//! M7: the local security audit report: one self-contained HTML page the user saves.
//!
//! It shows how UNTRACE is set up and what it could verify. It never contains where the user
//! has been: no host names contacted, no cookies, no downloads, no saved per-site permissions or
//! exceptions. Every mention of the user's profile folder is shown as `%USERPROFILE%`, so the
//! user name does not appear.

use std::collections::BTreeMap;

use serde_json::Value as Json;
use untrace_core::registry::{Observed, ProtectionStatus, Value};

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// Every mention of the user's profile folder, anywhere in the page, as `%USERPROFILE%`, so the
/// user name does not appear. Covers the folder as plain text, inside JSON text (doubled
/// backslashes) and HTML-escaped, in any ASCII case.
fn mask_home(page: &str, home: &str) -> String {
    let home = home.trim_end_matches('\\');
    if home.len() < 4 {
        return page.to_string();
    }
    let json = home.replace('\\', "\\\\");
    let mut out = page.to_string();
    // Longest forms first, so a shorter form never splits a longer one.
    for needle in [esc(&json), json.clone(), esc(home), home.to_string()] {
        out = replace_ascii_ci(&out, &needle, "%USERPROFILE%");
    }
    out
}

/// Replace `needle` ignoring ASCII case. ASCII lowercasing keeps every byte offset, so the
/// matches found in the lowered copy are valid in the original.
fn replace_ascii_ci(s: &str, needle: &str, with: &str) -> String {
    let hay = s.to_ascii_lowercase();
    let n = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for (i, _) in hay.match_indices(&n) {
        out.push_str(&s[last..i]);
        out.push_str(with);
        last = i + n.len();
    }
    out.push_str(&s[last..]);
    out
}

fn value(v: &Value) -> String {
    match v {
        Value::Bool(true) => "On".into(),
        Value::Bool(false) => "Off".into(),
        Value::Choice(c) => {
            let mut s = c.clone();
            if let Some(f) = s.get_mut(0..1) {
                f.make_ascii_uppercase();
            }
            s
        }
    }
}

fn text(v: &Json) -> String {
    match v {
        Json::String(s) => s.clone(),
        Json::Null => "—".into(),
        other => other.to_string(),
    }
}

fn row(cells: &[String]) -> String {
    format!(
        "<tr>{}</tr>",
        cells.iter().map(|c| format!("<td>{c}</td>")).collect::<String>()
    )
}

fn table(head: &[&str], rows: &[String]) -> String {
    format!(
        "<table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>",
        head.iter().map(|h| format!("<th>{}</th>", esc(h))).collect::<String>(),
        rows.concat()
    )
}

fn badge(ok: Option<bool>, yes: &str, no: &str, unknown: &str) -> String {
    match ok {
        Some(true) => format!("<span class=ok>{}</span>", esc(yes)),
        Some(false) => format!("<span class=bad>{}</span>", esc(no)),
        None => format!("<span class=unk>{}</span>", esc(unknown)),
    }
}

/// Count events by type and keep the last few (the log never holds URLs or sites).
fn audit_summary(lines: &[String]) -> (BTreeMap<String, usize>, Vec<(String, String)>) {
    let mut counts = BTreeMap::new();
    let mut last = Vec::new();
    for l in lines {
        let Ok(v) = serde_json::from_str::<Json>(l) else {
            continue;
        };
        let ev = v["event"].as_str().unwrap_or("?").to_string();
        *counts.entry(ev.clone()).or_insert(0) += 1;
        let mut rest = v.clone();
        if let Json::Object(o) = &mut rest {
            o.remove("event");
            o.remove("ts");
        }
        last.push((format!("{} {}", text(&v["ts"]), ev), rest.to_string()));
    }
    let keep = last.len().saturating_sub(30);
    (counts, last.split_off(keep))
}

pub struct Inputs<'a> {
    pub generated_at: String,
    pub diagnostics: &'a Json,
    pub protections: &'a [ProtectionStatus],
    pub self_test: Option<&'a Json>,
    pub self_test_by_protection: &'a BTreeMap<String, Json>,
    pub audit: &'a [String],
}

/// The report page. Every mention of the user's profile folder is masked (`mask_home`).
pub fn html(i: &Inputs<'_>) -> String {
    let page = build(i);
    match std::env::var("USERPROFILE") {
        Ok(home) => mask_home(&page, &home),
        Err(_) => page,
    }
}

fn build(i: &Inputs<'_>) -> String {
    let d = i.diagnostics;
    let e = &d["engine"];
    let mut out = String::new();

    // Protections.
    let prot_rows: Vec<String> = i
        .protections
        .iter()
        .map(|p| {
            let state = match &p.observed {
                Observed::Verified(v) => format!("<span class=ok>{} · verified</span>", esc(&value(v))),
                Observed::Unverifiable(r) => format!("<span class=unk>not verified</span> — {}", esc(r)),
            };
            let st = i.self_test_by_protection.get(p.def.id);
            let self_test = match st.and_then(|s| s["state"].as_str()) {
                Some("passed") => "<span class=ok>passed</span>".to_string(),
                Some("failed") => format!(
                    "<span class=bad>failed</span>: {}",
                    esc(&st.map(|s| text(&s["failed"])).unwrap_or_default())
                ),
                Some("partly") => "<span class=unk>partly run</span>".to_string(),
                _ => "<span class=unk>not run</span>".to_string(),
            };
            row(&[
                esc(p.def.group),
                esc(p.def.title),
                esc(&value(&p.configured)),
                state,
                self_test,
            ])
        })
        .collect();

    // Checks.
    let check_rows: Vec<String> = d["checks"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|c| {
                    row(&[
                        badge(c["ok"].as_bool(), "passed", "failed", "not verified"),
                        esc(&text(&c["name"])),
                        esc(&text(&c["detail"])),
                    ])
                })
                .collect()
        })
        .unwrap_or_default();

    // Block lists.
    let list_rows: Vec<String> = d["filterLists"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|l| {
                    row(&[
                        esc(&text(&l["title"])),
                        if l["enabled"] == true {
                            "on".into()
                        } else {
                            "off".into()
                        },
                        esc(&format!("{} {}", text(&l["origin"]), text(&l["version"]))),
                        esc(&text(&l["rules"])),
                        esc(&text(&l["lastCheck"])),
                        esc(&text(&l["lastError"])),
                    ])
                })
                .collect()
        })
        .unwrap_or_default();

    // Network and DNS (configuration only: never the hosts contacted).
    let n = &d["network"];
    let dns_rows: Vec<String> = n["adapters"]
        .as_array()
        .map(|a| {
            a.iter()
                .flat_map(|ad| {
                    let name = text(&ad["name"]);
                    ad["dnsServers"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .map(move |s| {
                            row(&[
                                esc(&name),
                                esc(&text(&s["address"])),
                                esc(&text(&s["dohTemplate"])),
                                if s["windowsEncryptionSet"] == true {
                                    "yes".into()
                                } else {
                                    "no".into()
                                },
                            ])
                        })
                })
                .collect()
        })
        .unwrap_or_default();

    // Self-check.
    let self_check = match i.self_test {
        Some(r) => {
            let failed: Vec<String> = r["checks"]
                .as_array()
                .map(|c| {
                    c.iter()
                        .filter(|x| x["ok"] == false)
                        .map(|x| text(&x["name"]))
                        .collect()
                })
                .unwrap_or_default();
            let total = r["checks"].as_array().map_or(0, |c| c.len());
            let skipped = r["skipped"].as_array().map_or(0, |s| s.len());
            format!(
                "<p>Last run {} (UNTRACE {}): {} of {} checks passed, {} not run{}.</p>",
                esc(&text(&r["at"])),
                esc(&text(&r["untrace_version"])),
                total - failed.len() - skipped,
                total,
                skipped,
                if failed.is_empty() {
                    String::new()
                } else {
                    format!("; failed: {}", esc(&failed.join("; ")))
                }
            )
        }
        None => "<p>The self-check has not been run on this computer yet (Diagnostics › Run self-check).</p>".into(),
    };

    // Activity log.
    let (counts, last) = audit_summary(i.audit);
    let count_rows: Vec<String> = counts.iter().map(|(k, v)| row(&[esc(k), v.to_string()])).collect();
    let last_rows: Vec<String> = last.iter().rev().map(|(a, b)| row(&[esc(a), esc(b)])).collect();

    out.push_str(&format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8>\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
<meta name=viewport content=\"width=device-width,initial-scale=1\">\
<title>UNTRACE security report</title><style>\
body{{font:14px/1.5 'Segoe UI',system-ui,sans-serif;margin:32px auto;max-width:1000px;padding:0 16px;color:#1b1b1d;background:#fff}}\
h1{{font-size:22px}}h2{{font-size:17px;margin-top:28px}}table{{border-collapse:collapse;width:100%;margin:8px 0}}\
th,td{{border-bottom:1px solid #e3e3e6;padding:6px 8px;text-align:left;vertical-align:top}}th{{font-weight:600}}\
.ok{{color:#16733a;font-weight:600}}.bad{{color:#b3261e;font-weight:600}}.unk{{color:#6b6b70;font-weight:600}}\
.note{{color:#55555a}}code{{font-family:Consolas,monospace}}\
@media (prefers-color-scheme:dark){{body{{background:#121214;color:#e8e8ea}}th,td{{border-color:#2c2c30}}.note{{color:#a0a0a6}}}}\
</style></head><body>\
<h1>UNTRACE security report</h1>\
<p>Generated {at} (UTC) by UNTRACE {app} with WebView2 Runtime {rt}.</p>\
<p class=note>This report describes how UNTRACE is set up on this computer and what it could verify. \
It contains no sites you visited, no host names contacted, no cookies, downloads, saved permissions or per-site exceptions.</p>",
        at = esc(&i.generated_at),
        app = esc(&text(&d["appVersion"])),
        rt = esc(&text(&e["runtimeVersion"])),
    ));
    out.push_str("<h2>Protections</h2><p class=note>Each setting as UNTRACE reads it back from the engine or its own policy, and the result of its self-test.</p>");
    out.push_str(&table(
        &["Group", "Protection", "Setting", "State", "Self-test"],
        &prot_rows,
    ));
    out.push_str("<h2>Checks</h2>");
    out.push_str(&table(&["Result", "Check", "Detail"], &check_rows));
    out.push_str("<h2>Self-check</h2>");
    out.push_str(&self_check);
    out.push_str("<h2>Block lists</h2>");
    out.push_str(&table(
        &["List", "Switch", "Copy in use", "Rules", "Last checked", "Last problem"],
        &list_rows,
    ));
    out.push_str(&format!(
        "<h2>Network and DNS</h2><p>Encrypted DNS: <b>{}</b> (configured: {}). {}</p><p>Start-up check: {}</p>",
        esc(&text(&n["running"])),
        esc(&text(&n["configured"])),
        esc(&text(&n["resolver"])),
        esc(&match n["check"]["state"].as_str() {
            Some("passed") => format!("passed in {} ms", text(&n["check"]["ms"])),
            Some("failed") => format!("failed: {}", text(&n["check"]["reason"])),
            Some(s) => s.to_string(),
            None => "—".into(),
        }),
    ));
    out.push_str(&table(
        &["Adapter", "DNS server", "Known encrypted address", "Windows encrypts"],
        &dns_rows,
    ));
    out.push_str(&format!(
        "<h2>Activity log</h2><p class=note>{} entries. The log never records addresses or sites.</p>",
        i.audit.len()
    ));
    out.push_str(&table(&["Event", "Count"], &count_rows));
    out.push_str("<p>Last 30 entries, newest first:</p>");
    out.push_str(&table(&["When and what", "Details"], &last_rows));
    out.push_str(&format!(
        "<h2>Where UNTRACE keeps its data</h2><p><code>{}</code></p>",
        esc(&text(&d["dataRoot"]))
    ));
    out.push_str("</body></html>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn report_escapes_and_leaves_browsing_out() {
        let diag = json!({
            "appVersion": "0.1.0", "engine": { "runtimeVersion": "157" },
            "checks": [{ "name": "<b>x</b>", "ok": true, "detail": "fine & good" }],
            "filterLists": [], "dataRoot": "C:\\data",
            "network": { "running": "automatic", "configured": "automatic", "resolver": "r", "check": { "state": "passed", "ms": 5 },
                         "adapters": [], "hosts": [{ "host": "secret-site.example" }] }
        });
        let audit = vec![r#"{"event":"app_started","version":"0.1.0","ts":"2026-11-23T10:00:00Z"}"#.to_string()];
        let h = html(&Inputs {
            generated_at: "2026-11-23T10:00:00Z".into(),
            diagnostics: &diag,
            protections: &[],
            self_test: None,
            self_test_by_protection: &BTreeMap::new(),
            audit: &audit,
        });
        assert!(h.contains("&lt;b&gt;x&lt;/b&gt;") && h.contains("fine &amp; good"));
        assert!(!h.contains("secret-site.example"), "hosts contacted never appear");
        assert!(!h.contains("<script"), "no script");
        assert!(h.contains("app_started"));
    }

    #[test]
    fn the_profile_folder_is_masked_everywhere() {
        // Plain (any case), inside JSON text, and HTML-escaped (the apostrophe).
        let home = r"C:\Users\Jo O'Brien";
        let page = format!(
            r#"<td>Folder: c:\users\jo o'brien\AppData\x</td><td>{{"p":"C:\\Users\\Jo O'Brien\\y"}}</td><td>{}</td>"#,
            esc(r"C:\Users\Jo O'Brien\z")
        );
        let m = mask_home(&page, home);
        assert!(!m.to_ascii_lowercase().contains("brien"), "{m}");
        assert!(m.contains(r"Folder: %USERPROFILE%\AppData\x"), "{m}");
        assert!(m.contains(r"%USERPROFILE%\\y"), "{m}");
        assert!(m.contains(r"%USERPROFILE%\z"), "{m}");
        assert_eq!(mask_home("nothing here", home), "nothing here");

        // Through the whole report: a check's free-text detail, the data folder and a log entry.
        if let Ok(real) = std::env::var("USERPROFILE") {
            let diag = json!({
                "appVersion": "0.1.0", "engine": { "runtimeVersion": "157" },
                "checks": [{ "name": "c", "ok": true, "detail": format!(r"Folder: {real}\AppData\Local\x") }],
                "filterLists": [], "dataRoot": format!(r"{real}\AppData\Local\UNTRACE"),
                "network": { "running": "automatic", "configured": "automatic", "resolver": "r", "check": { "state": "passed", "ms": 5 }, "adapters": [] }
            });
            let audit = vec![
                json!({ "event": "error", "message": format!(r"{real}\a.txt"), "ts": "2026-11-23T10:00:00Z" })
                    .to_string(),
            ];
            let h = html(&Inputs {
                generated_at: "2026-11-23T10:00:00Z".into(),
                diagnostics: &diag,
                protections: &[],
                self_test: None,
                self_test_by_protection: &BTreeMap::new(),
                audit: &audit,
            });
            let low = h.to_ascii_lowercase();
            assert!(
                !low.contains(&real.to_ascii_lowercase()),
                "profile folder in the report"
            );
            assert!(!low.contains(&real.replace('\\', r"\\").to_ascii_lowercase()));
            assert!(h.contains("%USERPROFILE%"));
        }
    }
}
