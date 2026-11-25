//! Address-field input → navigation target. Pure logic, no network access.
//!
//! Rules:
//! - Explicit `http://` / `https://` URLs and `about:blank` navigate.
//! - Script-capable or internal schemes (`javascript:`, `data:`, `file:`, `edge:` …) are refused.
//! - Host-like input without a scheme (`example.com`, `localhost:3000`, `10.0.0.1`) navigates
//!   over **HTTPS**.
//! - Everything else is a search using the configured engine.

use serde::{Deserialize, Serialize};
use url::Url;

pub const MAX_INPUT_LEN: usize = 8 * 1024;

/// Schemes that are never accepted from the address field.
const REFUSED_SCHEMES: &[&str] = &[
    "javascript",
    "vbscript",
    "data",
    "file",
    "blob",
    "filesystem",
    "edge",
    "chrome",
    "chrome-extension",
    "extension",
    "view-source",
    "devtools",
    "ms-settings",
    "search-ms",
    "ftp",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SearchEngine {
    DuckDuckGo,
    Startpage,
    BraveSearch,
    Mojeek,
    Custom,
}

impl SearchEngine {
    pub const ALL: [SearchEngine; 5] = [
        Self::DuckDuckGo,
        Self::Startpage,
        Self::BraveSearch,
        Self::Mojeek,
        Self::Custom,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::DuckDuckGo => "DuckDuckGo",
            Self::Startpage => "Startpage",
            Self::BraveSearch => "Brave Search",
            Self::Mojeek => "Mojeek",
            Self::Custom => "Custom",
        }
    }

    pub fn template(self) -> Option<&'static str> {
        match self {
            Self::DuckDuckGo => Some("https://duckduckgo.com/?q={q}"),
            Self::Startpage => Some("https://www.startpage.com/sp/search?query={q}"),
            Self::BraveSearch => Some("https://search.brave.com/search?q={q}"),
            Self::Mojeek => Some("https://www.mojeek.com/search?q={q}"),
            Self::Custom => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Navigate(Url),
    Search(Url),
}

impl Target {
    pub fn url(&self) -> &Url {
        match self {
            Target::Navigate(u) | Target::Search(u) => u,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    Empty,
    TooLong,
    RefusedScheme(String),
    InvalidUrl,
    InvalidSearchTemplate,
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "Nothing to open."),
            Self::TooLong => write!(f, "That address is too long."),
            Self::RefusedScheme(s) => write!(f, "UNTRACE does not open \"{s}:\" addresses from the address field."),
            Self::InvalidUrl => write!(f, "That is not a valid web address."),
            Self::InvalidSearchTemplate => write!(f, "The custom search address is not valid."),
        }
    }
}

/// Validate a custom search template: must be an `https://` URL containing `{q}`.
pub fn validate_template(t: &str) -> Result<(), AddressError> {
    if t.len() > 2048 || !t.contains("{q}") {
        return Err(AddressError::InvalidSearchTemplate);
    }
    match Url::parse(&t.replace("{q}", "test")) {
        Ok(u) if u.scheme() == "https" && u.host_str().is_some() => Ok(()),
        _ => Err(AddressError::InvalidSearchTemplate),
    }
}

pub fn search_url(query: &str, engine: SearchEngine, custom: Option<&str>) -> Result<Url, AddressError> {
    let template = match engine.template() {
        Some(t) => t,
        None => {
            let t = custom.ok_or(AddressError::InvalidSearchTemplate)?;
            validate_template(t)?;
            t
        }
    };
    let q: String = url::form_urlencoded::byte_serialize(query.as_bytes()).collect();
    Url::parse(&template.replace("{q}", &q)).map_err(|_| AddressError::InvalidSearchTemplate)
}

fn is_scheme_like(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn is_port(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 5
        && s.chars().all(|c| c.is_ascii_digit())
        && s.parse::<u32>().map(|p| p <= 65_535).unwrap_or(false)
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
}

/// Does `s` (no whitespace, no scheme) look like `host[:port][/path…]`?
fn looks_like_host(s: &str) -> bool {
    let authority = s.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    if authority.starts_with('[') {
        // IPv6 literal, optionally with port.
        return match authority.find(']') {
            Some(end) => {
                let rest = &authority[end + 1..];
                rest.is_empty() || rest.strip_prefix(':').map(is_port).unwrap_or(false)
            }
            None => false,
        };
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if let Some(p) = port
        && !is_port(p)
    {
        return false;
    }
    if host.eq_ignore_ascii_case("localhost") || is_ipv4(host) {
        return true;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty() || l.len() > 63) {
        return false;
    }
    let valid_chars = labels
        .iter()
        .all(|l| l.chars().all(|c| c.is_alphanumeric() || c == '-'));
    let tld = labels[labels.len() - 1];
    valid_chars && tld.chars().count() >= 2 && tld.chars().all(|c| c.is_alphabetic())
}

/// Resolve address-field input.
pub fn resolve(input: &str, engine: SearchEngine, custom_template: Option<&str>) -> Result<Target, AddressError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(AddressError::Empty);
    }
    if s.len() > MAX_INPUT_LEN {
        return Err(AddressError::TooLong);
    }
    if s.eq_ignore_ascii_case("about:blank") {
        return Ok(Target::Navigate(Url::parse("about:blank").expect("static URL")));
    }
    let has_space = s.chars().any(char::is_whitespace);
    if let Some((scheme, rest)) = s.split_once(':')
        && is_scheme_like(scheme)
    {
        let lower = scheme.to_ascii_lowercase();
        if (lower == "http" || lower == "https") && rest.starts_with("//") {
            if has_space {
                return Err(AddressError::InvalidUrl);
            }
            return match Url::parse(s) {
                Ok(u) if u.host_str().map(|h| !h.is_empty()).unwrap_or(false) => Ok(Target::Navigate(u)),
                _ => Err(AddressError::InvalidUrl),
            };
        }
        if REFUSED_SCHEMES.contains(&lower.as_str()) {
            return Err(AddressError::RefusedScheme(lower));
        }
        if rest.starts_with("//") && !has_space {
            // Some other explicit scheme (e.g. "gopher://"): not something UNTRACE opens.
            return Err(AddressError::RefusedScheme(lower));
        }
        // Otherwise fall through: "localhost:3000", "c++: tutorial", "note: x" …
    }
    if !has_space && looks_like_host(s) {
        return Url::parse(&format!("https://{s}"))
            .map(Target::Navigate)
            .map_err(|_| AddressError::InvalidUrl);
    }
    search_url(s, engine, custom_template).map(Target::Search)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nav(s: &str) -> String {
        match resolve(s, SearchEngine::DuckDuckGo, None) {
            Ok(Target::Navigate(u)) => u.to_string(),
            other => panic!("{s:?} should navigate, got {other:?}"),
        }
    }

    fn search(s: &str) -> String {
        match resolve(s, SearchEngine::DuckDuckGo, None) {
            Ok(Target::Search(u)) => u.to_string(),
            other => panic!("{s:?} should search, got {other:?}"),
        }
    }

    #[test]
    fn explicit_urls_navigate() {
        assert_eq!(nav("https://example.com/a?b=1"), "https://example.com/a?b=1");
        assert_eq!(nav("  http://example.com  "), "http://example.com/");
        assert_eq!(nav("HTTPS://EXAMPLE.COM"), "https://example.com/");
        assert_eq!(nav("about:blank"), "about:blank");
    }

    #[test]
    fn host_like_input_defaults_to_https() {
        assert_eq!(nav("example.com"), "https://example.com/");
        assert_eq!(
            nav("sub.example.co.uk/path?x=1#f"),
            "https://sub.example.co.uk/path?x=1#f"
        );
        assert_eq!(nav("localhost:3000"), "https://localhost:3000/");
        assert_eq!(nav("localhost"), "https://localhost/");
        assert_eq!(nav("10.0.0.1:8080/x"), "https://10.0.0.1:8080/x");
        assert_eq!(nav("[::1]:8443"), "https://[::1]:8443/");
        assert_eq!(nav("bücher.de"), "https://xn--bcher-kva.de/");
    }

    #[test]
    fn everything_else_searches() {
        assert_eq!(search("privacy browser"), "https://duckduckgo.com/?q=privacy+browser");
        assert_eq!(search("3.14"), "https://duckduckgo.com/?q=3.14");
        assert_eq!(search("c++: tutorial"), "https://duckduckgo.com/?q=c%2B%2B%3A+tutorial");
        assert_eq!(
            search("user@example.com"),
            "https://duckduckgo.com/?q=user%40example.com"
        );
        assert_eq!(search("what is a.b"), "https://duckduckgo.com/?q=what+is+a.b");
        assert_eq!(search("hello"), "https://duckduckgo.com/?q=hello");
        assert_eq!(
            search("example.com:99999"),
            "https://duckduckgo.com/?q=example.com%3A99999"
        );
    }

    #[test]
    fn refuses_dangerous_schemes() {
        for s in [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "data:text/html,x",
            "file:///C:/x",
            "edge://settings",
            "view-source:https://x.com",
            "ftp://x.org",
        ] {
            assert!(
                matches!(
                    resolve(s, SearchEngine::DuckDuckGo, None),
                    Err(AddressError::RefusedScheme(_))
                ),
                "{s}"
            );
        }
    }

    #[test]
    fn rejects_empty_long_and_broken() {
        assert_eq!(resolve("   ", SearchEngine::DuckDuckGo, None), Err(AddressError::Empty));
        assert_eq!(
            resolve(&"a".repeat(MAX_INPUT_LEN + 1), SearchEngine::DuckDuckGo, None),
            Err(AddressError::TooLong)
        );
        assert_eq!(
            resolve("https://", SearchEngine::DuckDuckGo, None),
            Err(AddressError::InvalidUrl)
        );
        assert_eq!(
            resolve("https://a b.com", SearchEngine::DuckDuckGo, None),
            Err(AddressError::InvalidUrl)
        );
    }

    #[test]
    fn search_engines_and_custom_templates() {
        for e in SearchEngine::ALL {
            if e != SearchEngine::Custom {
                let u = search_url("a b", e, None).unwrap();
                assert_eq!(u.scheme(), "https");
            }
        }
        assert_eq!(
            search_url("x", SearchEngine::Custom, Some("https://s.example/?q={q}"))
                .unwrap()
                .as_str(),
            "https://s.example/?q=x"
        );
        assert!(validate_template("http://s.example/?q={q}").is_err());
        assert!(validate_template("https://s.example/").is_err());
        assert!(search_url("x", SearchEngine::Custom, None).is_err());
    }
}
