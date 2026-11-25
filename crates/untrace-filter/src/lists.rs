//! List text: header fields, host lists, and validation of downloads.

use std::collections::HashSet;

use adblock::lists::{ParseOptions, RuleTypes, parse_filter};

use crate::catalog::{Format, ListInfo};

/// Downloads larger than this are refused (EasyList is about 2 MB).
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
/// Shortest and longest update interval UNTRACE accepts from a list's `Expires` header.
pub const MIN_EXPIRES_HOURS: u32 = 6;
pub const MAX_EXPIRES_HOURS: u32 = 14 * 24;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    pub title: Option<String>,
    /// `Version:` (EasyList) or `Updated:` (malware-filter).
    pub version: Option<String>,
    pub expires_hours: Option<u32>,
}

/// Read the comment header (`! Key: value` or `# Key: value`) at the top of a list.
pub fn header(text: &str) -> Header {
    let mut h = Header::default();
    for line in text.lines().take(40) {
        let line = line.trim();
        let Some(body) = line.strip_prefix('!').or_else(|| line.strip_prefix('#')) else {
            if line.starts_with('[') || line.is_empty() {
                continue;
            }
            break; // first rule: the header is over
        };
        let Some((key, value)) = body.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "title" => h.title = Some(value.to_string()),
            "version" | "updated" => h.version = Some(value.to_string()),
            "expires" => h.expires_hours = parse_expires(value),
            _ => {}
        }
    }
    h
}

/// "4 days (update frequency)" → 96; "12 hours" → 12. Clamped to a sane range.
pub fn parse_expires(v: &str) -> Option<u32> {
    let mut parts = v.split_whitespace();
    let n: u32 = parts.next()?.parse().ok()?;
    let unit = parts.next()?.to_ascii_lowercase();
    let hours = if unit.starts_with("day") {
        n.checked_mul(24)?
    } else if unit.starts_with("hour") {
        n
    } else {
        return None;
    };
    Some(hours.clamp(MIN_EXPIRES_HOURS, MAX_EXPIRES_HOURS))
}

/// Normalise a host for matching: lower case, no trailing dot, no IPv6 brackets.
pub fn normalise_host(h: &str) -> String {
    h.trim()
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

fn is_host_like(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    if h.contains(':') {
        // IPv6 literal
        return h.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
    }
    h.contains('.')
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// Parse a host list. Accepts `host` and hosts-file style `0.0.0.0 host` lines.
/// Returns the hosts and the number of lines that were not valid hosts.
pub fn hosts(text: &str) -> (HashSet<String>, usize) {
    let mut set = HashSet::new();
    let mut invalid = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let first = tokens.next().unwrap_or_default();
        let host = match (first, tokens.next()) {
            ("0.0.0.0" | "127.0.0.1" | "::" | "::1", Some(second)) => second,
            _ => first,
        };
        let host = normalise_host(host);
        if is_host_like(&host) {
            set.insert(host);
        } else {
            invalid += 1;
        }
    }
    (set, invalid)
}

/// Count rule lines in an Adblock list and how many adblock-rust cannot parse as network rules.
fn adblock_rules(text: &str) -> (usize, usize) {
    let opts = ParseOptions {
        rule_types: RuleTypes::All,
        ..ParseOptions::default()
    };
    let (mut rules, mut invalid) = (0, 0);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            continue;
        }
        rules += 1;
        if parse_filter(line, false, opts).is_err() {
            invalid += 1;
        }
    }
    (rules, invalid)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    TooLarge { bytes: usize },
    NotText,
    NotThisList { found: Option<String> },
    TooFewRules { rules: usize, min: usize },
    Shrank { rules: usize, previous: usize },
    TooManyInvalid { invalid: usize, rules: usize },
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejection::TooLarge { bytes } => write!(f, "the download is too large ({bytes} bytes)"),
            Rejection::NotText => write!(f, "the download is not a text file"),
            Rejection::NotThisList { found: Some(t) } => write!(f, "the download is a different list (\"{t}\")"),
            Rejection::NotThisList { found: None } => write!(f, "the download is not a block list"),
            Rejection::TooFewRules { rules, min } => {
                write!(f, "the download has only {rules} rules (expected at least {min})")
            }
            Rejection::Shrank { rules, previous } => {
                write!(
                    f,
                    "the download has {rules} rules, far fewer than the {previous} before"
                )
            }
            Rejection::TooManyInvalid { invalid, rules } => {
                write!(f, "{invalid} of {rules} rules in the download are not valid")
            }
        }
    }
}

/// A list that passed validation.
#[derive(Debug, Clone)]
pub struct Checked {
    pub text: String,
    pub header: Header,
    pub rules: usize,
}

/// Validate list text (a download, or a stored copy being loaded) before UNTRACE uses it.
pub fn validate(info: &ListInfo, bytes: Vec<u8>, previous_rules: Option<usize>) -> Result<Checked, Rejection> {
    if bytes.len() > MAX_BYTES {
        return Err(Rejection::TooLarge { bytes: bytes.len() });
    }
    let text = String::from_utf8(bytes).map_err(|_| Rejection::NotText)?;
    if text.contains('\0') {
        return Err(Rejection::NotText);
    }
    let header = header(&text);
    if header.title.as_deref() != Some(info.expected_title) {
        return Err(Rejection::NotThisList { found: header.title });
    }
    let (rules, invalid, max_invalid_pct) = match info.format {
        Format::Adblock => {
            let (r, i) = adblock_rules(&text);
            (r, i, 10)
        }
        Format::Hosts => {
            let (set, i) = hosts(&text);
            (set.len() + i, i, 2)
        }
    };
    if rules < info.min_rules {
        return Err(Rejection::TooFewRules {
            rules,
            min: info.min_rules,
        });
    }
    if let Some(previous) = previous_rules
        && rules.saturating_mul(info.max_shrink) < previous
    {
        return Err(Rejection::Shrank { rules, previous });
    }
    if invalid * 100 > rules * max_invalid_pct {
        return Err(Rejection::TooManyInvalid { invalid, rules });
    }
    Ok(Checked { text, header, rules })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{ListId, info};

    #[test]
    fn expires_parses_and_clamps() {
        assert_eq!(parse_expires("4 days (update frequency)"), Some(96));
        assert_eq!(parse_expires("12 hours (update frequency)"), Some(12));
        assert_eq!(parse_expires("1 hour"), Some(MIN_EXPIRES_HOURS));
        assert_eq!(parse_expires("90 days"), Some(MAX_EXPIRES_HOURS));
        assert_eq!(parse_expires("soon"), None);
    }

    #[test]
    fn header_reads_both_comment_styles() {
        let h = header(
            "[Adblock Plus 2.0]\n! Version: 202611220945\n! Title: EasyList\n! Expires: 4 days\n||ads.example^\n! Title: later",
        );
        assert_eq!(h.title.as_deref(), Some("EasyList"));
        assert_eq!(h.version.as_deref(), Some("202611220945"));
        assert_eq!(h.expires_hours, Some(96));
        let h = header(
            "# Title: Phishing Domains Blocklist\n# Updated: 2026-11-22T00:03:04Z\n# Expires: 12 hours\nevil.example\n",
        );
        assert_eq!(h.title.as_deref(), Some("Phishing Domains Blocklist"));
        assert_eq!(h.expires_hours, Some(12));
    }

    #[test]
    fn host_lists_accept_plain_and_hosts_file_lines() {
        let (set, invalid) =
            hosts("# c\nEvil.Example.\n0.0.0.0 bad.example\n1.2.3.4\n2001:db8::1\nnot a host!\n-bad-.example\n");
        assert!(set.contains("evil.example"));
        assert!(set.contains("bad.example"));
        assert!(set.contains("1.2.3.4"));
        assert!(set.contains("2001:db8::1"));
        assert_eq!(invalid, 2);
    }

    #[test]
    fn bundled_snapshots_pass_validation() {
        for id in ListId::ALL {
            let i = info(id);
            let c = validate(i, i.bundled.as_bytes().to_vec(), None).unwrap_or_else(|e| panic!("{id:?}: {e}"));
            assert!(c.rules >= i.min_rules, "{id:?}");
            assert!(c.header.expires_hours.is_some(), "{id:?} states its update interval");
        }
    }

    #[test]
    fn validation_rejects_wrong_truncated_and_hostile_downloads() {
        let el = info(ListId::EasyList);
        // Another list (or an HTML error page) under the right URL.
        let html = b"<!doctype html><title>404</title>".to_vec();
        assert!(matches!(validate(el, html, None), Err(Rejection::NotThisList { .. })));
        let ep = info(ListId::EasyPrivacy).bundled.as_bytes().to_vec();
        assert!(matches!(
            validate(el, ep, None),
            Err(Rejection::NotThisList { found: Some(_) })
        ));
        // Truncated: right header, few rules.
        let truncated: String = el.bundled.lines().take(500).collect::<Vec<_>>().join("\n");
        assert!(matches!(
            validate(el, truncated.into_bytes(), None),
            Err(Rejection::TooFewRules { .. })
        ));
        // Binary and oversized.
        assert!(matches!(
            validate(el, vec![0xff, 0xfe, 0x00], None),
            Err(Rejection::NotText)
        ));
        assert!(matches!(
            validate(el, vec![b'a'; MAX_BYTES + 1], None),
            Err(Rejection::TooLarge { .. })
        ));
        // Shrank to a third of the previous version.
        let full = validate(el, el.bundled.as_bytes().to_vec(), None).unwrap();
        assert!(matches!(
            validate(el, el.bundled.as_bytes().to_vec(), Some(full.rules * 3)),
            Err(Rejection::Shrank { .. })
        ));
        // Mostly garbage under a correct header.
        let mut junk = String::from("# Title: Phishing Domains Blocklist\n");
        for i in 0..2000 {
            junk.push_str(&format!("not a host {i}\n"));
        }
        assert!(matches!(
            validate(info(ListId::Phishing), junk.into_bytes(), None),
            Err(Rejection::TooManyInvalid { .. })
        ));
    }
}
