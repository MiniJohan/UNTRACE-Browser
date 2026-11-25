//! Tracking-parameter cleanup (D-027).
//!
//! Link decoration (`utm_source`, `gclid`, `fbclid`, …) identifies the click or the campaign that
//! brought you to a page. UNTRACE removes the parameters on this reviewed list from page and frame
//! addresses before the request is sent, so neither the site nor its scripts receive them.
//!
//! The list is deliberately small: only parameters that exist to track and never change what a
//! page shows. adblock-rust's `$removeparam` matches exact names only (no `utm_*`), so UNTRACE
//! matches these itself.

/// Removed on every site. Compared without regard to case.
const ANY_SITE: &[&str] = &[
    // Google Ads, Analytics and Merchant Center
    "gclid",
    "gclsrc",
    "dclid",
    "gbraid",
    "wbraid",
    "gad_source",
    "gad_campaignid",
    "srsltid",
    "_gl",
    // Microsoft Advertising
    "msclkid",
    // Meta (Facebook, Instagram)
    "fbclid",
    "igshid",
    // X (Twitter), TikTok, LinkedIn, Reddit, Snapchat, Pinterest
    "twclid",
    "ttclid",
    "li_fat_id",
    "rdt_cid",
    "sccid",
    "epik",
    // Yandex
    "yclid",
    "ysclid",
    // E-mail marketing: Mailchimp, HubSpot, Marketo, Klaviyo, Vero, Omeda
    "mc_cid",
    "mc_eid",
    "_hsenc",
    "_hsmi",
    "__hstc",
    "__hssc",
    "__hsfp",
    "hsctatracking",
    "mkt_tok",
    "_kx",
    "vero_id",
    "vero_conv",
    "oly_anon_id",
    "oly_enc_id",
    // Matomo / Piwik campaign tracking
    "mtm_campaign",
    "mtm_source",
    "mtm_medium",
    "mtm_keyword",
    "mtm_content",
    "mtm_cid",
    "mtm_group",
    "mtm_placement",
    "pk_campaign",
    "pk_source",
    "pk_medium",
    "pk_keyword",
    "pk_content",
    "pk_cid",
];

/// Removed on every site: any parameter starting with one of these.
const ANY_SITE_PREFIX: &[&str] = &["utm_"];

/// Share-tracking parameters with generic names, removed only on the site that uses them.
const ON_SITE: &[(&str, &str)] = &[
    ("youtube.com", "si"),
    ("youtu.be", "si"),
    ("open.spotify.com", "si"),
    ("instagram.com", "igsh"),
];

fn host_matches(host: &str, site: &str) -> bool {
    host == site || host.strip_suffix(site).is_some_and(|rest| rest.ends_with('.'))
}

fn is_tracking(host: &str, name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ANY_SITE.contains(&lower.as_str())
        || ANY_SITE_PREFIX.iter().any(|p| lower.starts_with(p))
        || ON_SITE.iter().any(|(site, n)| *n == lower && host_matches(host, site))
}

/// The result of cleaning one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cleaned {
    pub url: String,
    /// Names of the removed parameters, as they appeared.
    pub removed: Vec<String>,
}

/// Remove tracking parameters from an `http(s)` address. `None` when there is nothing to remove.
///
/// Works on the text: every other parameter, its order and its encoding stay exactly as they
/// were (re-encoding could break signed addresses). The fragment is kept.
pub fn clean(url: &str) -> Option<Cleaned> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    // The query ends at the fragment; a '?' inside the fragment is not a query.
    let frag = url.find('#').unwrap_or(url.len());
    let q = url[..frag].find('?')?;
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..host_end];
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    let query = &url[q + 1..frag];
    let mut kept = Vec::new();
    let mut removed = Vec::new();
    for pair in query.split('&') {
        let name = pair.split('=').next().unwrap_or(pair);
        if !name.is_empty() && is_tracking(&host, name) {
            removed.push(name.to_string());
        } else {
            kept.push(pair);
        }
    }
    if removed.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(url.len());
    out.push_str(&url[..q]);
    let kept: Vec<&str> = kept.into_iter().filter(|p| !p.is_empty()).collect();
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    out.push_str(&url[frag..]);
    Some(Cleaned { url: out, removed })
}

/// Number of parameter names on the list (for Settings and Diagnostics).
pub fn rule_count() -> usize {
    ANY_SITE.len() + ANY_SITE_PREFIX.len() + ON_SITE.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_listed_parameters_and_keeps_the_rest_verbatim() {
        let c = clean("https://shop.example/item?id=7&utm_source=news&q=a%20b+c&gclid=XyZ&Utm_Medium=mail#reviews")
            .unwrap();
        assert_eq!(c.url, "https://shop.example/item?id=7&q=a%20b+c#reviews");
        assert_eq!(c.removed, ["utm_source", "gclid", "Utm_Medium"]);
    }

    #[test]
    fn drops_the_question_mark_when_nothing_is_left() {
        assert_eq!(clean("https://a.example/?fbclid=1").unwrap().url, "https://a.example/");
        assert_eq!(
            clean("http://a.example/p?msclkid=2#top").unwrap().url,
            "http://a.example/p#top"
        );
    }

    #[test]
    fn leaves_clean_and_non_web_addresses_alone() {
        assert_eq!(clean("https://a.example/?id=1&page=2"), None);
        assert_eq!(clean("https://a.example/utm_source"), None);
        assert_eq!(clean("https://a.example/#utm_source=x"), None); // fragments never reach the server
        assert_eq!(clean("https://a.example/#x?utm_source=1"), None);
        assert_eq!(clean("data:text/html,?utm_source=x"), None);
        assert_eq!(clean("https://a.example/?utm"), None);
    }

    #[test]
    fn site_specific_names_apply_only_on_their_site() {
        assert_eq!(
            clean("https://www.youtube.com/watch?v=abc&si=TRACK").unwrap().url,
            "https://www.youtube.com/watch?v=abc"
        );
        assert_eq!(
            clean("https://youtu.be/abc?si=TRACK").unwrap().url,
            "https://youtu.be/abc"
        );
        assert_eq!(clean("https://example.com/?si=1"), None);
        assert_eq!(clean("https://notyoutube.com/?si=1"), None);
    }

    #[test]
    fn host_is_read_from_the_authority_only() {
        // A host-like string in the path or in user info must not enable site-specific names.
        assert_eq!(clean("https://evil.example/youtube.com?si=1"), None);
        assert!(clean("https://user@www.youtube.com:443/watch?si=1").is_some());
    }
}
