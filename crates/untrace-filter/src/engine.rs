//! Matching (D-032).
//!
//! - Ads and trackers: one adblock-rust engine (network rules only), so exception rules in one
//!   list also cover blocks from the other, as the list authors intend.
//! - Malware and phishing: host sets. A listed host also covers its subdomains, never its parent.
//!
//! Each enabled list also gets a canary rule on a reserved `.invalid` name (RFC 6761: never
//! resolves, never a real site). Matching the canary proves the list is loaded and working; it
//! is how Settings reads back each switch and how a cached engine is verified after loading.

use std::{collections::HashSet, sync::Arc};

use adblock::{
    Engine, FilterSet,
    lists::{ParseOptions, RuleTypes},
    request::Request,
    url_parser,
};

use crate::{
    catalog::{Format, ListId, info},
    lists::{hosts, normalise_host},
};

/// adblock-rust version the engine cache format belongs to. A unit test checks it against
/// Cargo.lock, so upgrading the crate without updating this fails the build's tests.
pub const ADBLOCK_VERSION: &str = "0.13.6";

/// Page that canary requests pretend to come from (third-party context).
pub const CANARY_PAGE: &str = "https://page.canary.untrace.invalid/";

/// D-058: the host of the regular-expression canary.
pub const REGEX_CANARY_HOST: &str = "regex.canary.untrace.invalid";

/// D-058: two rules with the same options, which the matching library fuses into one set of
/// regular expressions: one it cannot compile (lookahead), one it can. They are filtered like
/// the lists' rules ([`crate::preprocess::network_text`]). Had the first reached the library,
/// the second would stop matching as well: the canary proves that working rules are not
/// disabled by the rules they are fused with.
const REGEX_CANARY_RULES: &str = "/^https:\\/\\/regex\\.canary\\.untrace\\.invalid\\/(?=[a-z])[a-z]+\\.js$/$xhr\n\
                                  /^https:\\/\\/regex\\.canary\\.untrace\\.invalid\\/[a-z]+\\.js$/$xhr\n";

/// D-058: a host blocked as a page (`$document`), as the lists block ad, scam and badware
/// pages. Part of every content engine, for the self-check of page redirects.
pub const DOCUMENT_CANARY_HOST: &str = "document.canary.untrace.invalid";

/// The address the regular-expression canary matches (as a request from a page, [`ResourceKind::Xhr`]).
pub fn regex_canary_url() -> String {
    format!("https://{REGEX_CANARY_HOST}/check.js")
}

pub fn canary_host(id: ListId) -> &'static str {
    match id {
        ListId::EasyList => "ads.canary.untrace.invalid",
        ListId::EasyPrivacy => "tracker.canary.untrace.invalid",
        ListId::Malware => "malware.canary.untrace.invalid",
        ListId::Phishing => "phishing.canary.untrace.invalid",
        ListId::UboFilters => "ublock.canary.untrace.invalid",
        ListId::UboBadware => "ublock-badware.canary.untrace.invalid",
        ListId::UboPrivacy => "ublock-privacy.canary.untrace.invalid",
        ListId::UboQuickFixes => "ublock-quick-fixes.canary.untrace.invalid",
        ListId::UboUnbreak => "ublock-unbreak.canary.untrace.invalid",
    }
}

pub fn canary_url(id: ListId) -> String {
    format!("https://{}/canary.js", canary_host(id))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Document,
    Subdocument,
    Script,
    Stylesheet,
    Image,
    Font,
    Media,
    Xhr,
    Ping,
    WebSocket,
    Other,
}

impl ResourceKind {
    fn as_adblock(self) -> &'static str {
        match self {
            ResourceKind::Document => "document",
            ResourceKind::Subdocument => "subdocument",
            ResourceKind::Script => "script",
            ResourceKind::Stylesheet => "stylesheet",
            ResourceKind::Image => "image",
            ResourceKind::Font => "font",
            ResourceKind::Media => "media",
            ResourceKind::Xhr => "xmlhttprequest",
            ResourceKind::Ping => "ping",
            ResourceKind::WebSocket => "websocket",
            ResourceKind::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Blocked by the ads/trackers engine.
    Block,
    /// The host is on a malware or phishing list.
    Threat(ListId),
}

/// List text handed to the builders.
#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    pub id: ListId,
    pub text: &'a str,
}

/// The ads/trackers engine and the lists it was built from.
pub struct ContentEngine {
    engine: Engine,
    lists: Vec<ListId>,
}

impl ContentEngine {
    /// Build from Adblock-format sources (others are ignored). About 0.1 s for both lists.
    pub fn build(sources: &[Source<'_>]) -> Option<Self> {
        let opts = ParseOptions {
            rule_types: RuleTypes::NetworkOnly,
            ..ParseOptions::default()
        };
        let mut set = FilterSet::new(false);
        let mut lists = vec![];
        for s in sources.iter().filter(|s| info(s.id).format == Format::Adblock) {
            let text = crate::preprocess::network_text(s);
            // Rules that name `popup` beside other types: the library drops them whole, so
            // their other types are added back without `popup` (crate::popup).
            set.add_filter_list(crate::popup::split(&text).rest.join("\n"), opts);
            set.add_filter_list(text.into_owned(), opts);
            set.add_filter_list(format!("||{}^\n", canary_host(s.id)), opts);
            lists.push(s.id);
        }
        if lists.is_empty() {
            return None;
        }
        let canary = crate::preprocess::without_unsupported_regex(REGEX_CANARY_RULES.into());
        set.add_filter_list(canary.into_owned(), opts);
        set.add_filter_list(format!("||{DOCUMENT_CANARY_HOST}^$document\n"), opts);
        Some(Self {
            engine: Engine::new_with_filter_set(set),
            lists,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.engine.serialize()
    }

    /// Restore a cached engine, then prove it: every list's canary must be blocked.
    pub fn deserialize(lists: Vec<ListId>, bytes: &[u8]) -> Result<Self, String> {
        let mut engine = Engine::default();
        engine
            .deserialize(bytes)
            .map_err(|e| format!("cached filter engine unreadable: {e:?}"))?;
        let me = Self { engine, lists };
        match me.lists.iter().find(|id| !me.blocks_canary(**id)) {
            Some(id) => Err(format!("cached filter engine does not block the {id:?} canary")),
            None if !me.blocks_regex_canary() => {
                Err("cached filter engine does not block the regular-expression canary".into())
            }
            None => Ok(me),
        }
    }

    /// D-058: do rules fused with one the matching library cannot compile still match?
    pub fn blocks_regex_canary(&self) -> bool {
        self.matches(&regex_canary_url(), CANARY_PAGE, ResourceKind::Xhr)
    }

    pub fn lists(&self) -> &[ListId] {
        &self.lists
    }

    fn matches(&self, url: &str, source_url: &str, kind: ResourceKind) -> bool {
        Request::new(url, source_url, kind.as_adblock(), "GET")
            .map(|r| self.engine.check_network_request(&r).should_block())
            .unwrap_or(false)
    }

    pub fn blocks_canary(&self, id: ListId) -> bool {
        self.lists.contains(&id) && self.matches(&canary_url(id), CANARY_PAGE, ResourceKind::Script)
    }
}

/// Malware and phishing host sets.
#[derive(Default)]
pub struct Threats {
    sets: Vec<(ListId, HashSet<String>)>,
}

impl Threats {
    pub fn build(sources: &[Source<'_>]) -> Self {
        let sets = sources
            .iter()
            .filter(|s| info(s.id).format == Format::Hosts)
            .map(|s| {
                let (mut set, _) = hosts(s.text);
                set.insert(canary_host(s.id).to_string());
                (s.id, set)
            })
            .collect();
        Self { sets }
    }

    pub fn lists(&self) -> impl Iterator<Item = ListId> + '_ {
        self.sets.iter().map(|(id, _)| *id)
    }

    pub fn len(&self, id: ListId) -> usize {
        self.sets.iter().find(|(i, _)| *i == id).map_or(0, |(_, s)| s.len())
    }

    /// Which list names this host (or a domain it belongs to)?
    pub fn host(&self, host: &str) -> Option<ListId> {
        if self.sets.is_empty() {
            return None;
        }
        let host = normalise_host(host);
        let is_ip = host.contains(':') || host.parse::<std::net::Ipv4Addr>().is_ok();
        for (id, set) in &self.sets {
            if is_ip {
                if set.contains(&host) {
                    return Some(*id);
                }
                continue;
            }
            // evil.example listed → a.evil.example matches; sub.weebly.com listed → weebly.com does not.
            let mut h = host.as_str();
            loop {
                if set.contains(h) {
                    return Some(*id);
                }
                match h.find('.') {
                    Some(i) => h = &h[i + 1..],
                    None => break,
                }
            }
        }
        None
    }
}

/// Everything UNTRACE matches requests and navigations against.
#[derive(Default)]
pub struct Filters {
    content: Option<ContentEngine>,
    /// Shared with the network layer's backstop (M5, D-042).
    threats: Arc<Threats>,
    /// Element-hiding rules of the Adblock lists (M6).
    cosmetic: Option<Arc<crate::cosmetic::CosmeticRules>>,
    /// Pop-up rules of the Adblock lists (crate::popup).
    popups: Option<crate::popup::PopupRules>,
    /// Scriptlet rules of the Adblock lists, with uBlock Origin's scriptlets (D-057).
    scriptlets: Option<crate::scriptlets::Scriptlets>,
}

impl Filters {
    pub fn new(content: Option<ContentEngine>, threats: Threats) -> Self {
        Self {
            content,
            threats: Arc::new(threats),
            cosmetic: None,
            popups: None,
            scriptlets: None,
        }
    }

    /// Attach the scriptlet rules built from the same lists.
    pub fn with_scriptlets(mut self, s: crate::scriptlets::Scriptlets) -> Self {
        self.scriptlets = Some(s);
        self
    }

    pub fn scriptlets(&self) -> Option<&crate::scriptlets::Scriptlets> {
        self.scriptlets.as_ref()
    }

    /// Attach the pop-up rules built from the same lists.
    pub fn with_popups(mut self, rules: crate::popup::PopupRules) -> Self {
        self.popups = Some(rules);
        self
    }

    pub fn popups(&self) -> Option<&crate::popup::PopupRules> {
        self.popups.as_ref()
    }

    /// Should a page at `opener` be stopped from opening `target` in a new window? Pop-up
    /// rules, and any address on a malware or phishing list.
    pub fn blocks_popup(&self, target: &str, opener: &str) -> bool {
        if !(target.starts_with("http://") || target.starts_with("https://")) {
            return false;
        }
        self.threat(target).is_some() || self.popups.as_ref().is_some_and(|p| p.blocks(target, opener))
    }

    /// Attach the element-hiding rules built from the same lists.
    pub fn with_cosmetic(mut self, rules: crate::cosmetic::CosmeticRules) -> Self {
        self.cosmetic = Some(Arc::new(rules));
        self
    }

    pub fn cosmetic(&self) -> Option<&Arc<crate::cosmetic::CosmeticRules>> {
        self.cosmetic.as_ref()
    }

    /// The malware/phishing host sets, for use on another thread.
    pub fn shared_threats(&self) -> Arc<Threats> {
        self.threats.clone()
    }

    /// Build every part from the enabled lists.
    pub fn build(sources: &[Source<'_>]) -> Self {
        Self::new(ContentEngine::build(sources), Threats::build(sources))
            .with_cosmetic(crate::cosmetic::CosmeticRules::build(sources))
            .with_popups(crate::popup::PopupRules::build(sources))
            .with_scriptlets(crate::scriptlets::Scriptlets::build(sources))
    }

    pub fn content(&self) -> Option<&ContentEngine> {
        self.content.as_ref()
    }

    pub fn threats(&self) -> &Threats {
        &self.threats
    }

    /// The host of `url` is on a malware or phishing list.
    pub fn threat(&self, url: &str) -> Option<ListId> {
        url_parser::parse_url(url).and_then(|u| self.threats.host(u.hostname()))
    }

    /// Match one request. `source_url` is the page the request belongs to.
    pub fn check(&self, url: &str, source_url: &str, kind: ResourceKind) -> Verdict {
        if let Some(t) = self.threat(url) {
            return Verdict::Threat(t);
        }
        if self.content_blocks(url, source_url, kind) {
            Verdict::Block
        } else {
            Verdict::Allow
        }
    }

    /// Ads and trackers only (for hosts the user chose to continue to, D-033).
    pub fn content_blocks(&self, url: &str, source_url: &str, kind: ResourceKind) -> bool {
        self.content.as_ref().is_some_and(|c| c.matches(url, source_url, kind))
    }

    /// Is this list loaded and matching right now? (Settings read-back.)
    pub fn verify(&self, id: ListId) -> bool {
        match info(id).format {
            Format::Adblock => self.content.as_ref().is_some_and(|c| c.blocks_canary(id)),
            Format::Hosts => self.threat(&canary_url(id)) == Some(id),
        }
    }
}

/// The site a URL belongs to (registrable domain, e.g. `news.example.co.uk` → `example.co.uk`).
pub fn registrable_domain(url: &str) -> Option<String> {
    url_parser::parse_url(url)
        .map(|u| u.domain().to_string())
        .filter(|d| !d.is_empty())
}

/// FNV-1a over the inputs of a content engine: the cache key.
pub fn cache_key(sources: &[Source<'_>]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    };
    eat(ADBLOCK_VERSION.as_bytes());
    eat(env!("CARGO_PKG_VERSION").as_bytes());
    // What UNTRACE adds to the library's rules (crate::popup): bumped when that changes.
    eat(b"popup-rest-1;ublock-preprocess-3;regex-compiles-1");
    for s in sources.iter().filter(|s| info(s.id).format == Format::Adblock) {
        eat(s.id.stem().as_bytes());
        eat(&[0]);
        eat(s.text.as_bytes());
        eat(&[0]);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundled(ids: &[ListId]) -> Vec<Source<'static>> {
        ids.iter()
            .map(|id| Source {
                id: *id,
                text: info(*id).bundled,
            })
            .collect()
    }

    #[test]
    fn adblock_version_matches_cargo_lock() {
        let lock = include_str!("../../../Cargo.lock");
        let pos = lock.find("name = \"adblock\"").expect("adblock in Cargo.lock");
        let version = lock[pos..].lines().nth(1).unwrap_or_default();
        assert_eq!(version, format!("version = \"{ADBLOCK_VERSION}\""));
    }

    #[test]
    fn bundled_lists_block_known_trackers_and_ads_but_not_first_party() {
        let f = Filters::build(&bundled(&ListId::ALL));
        let page = "https://news.example.org/article";
        let blocked = [
            ("https://www.google-analytics.com/analytics.js", ResourceKind::Script),
            ("https://connect.facebook.net/en_US/fbevents.js", ResourceKind::Script),
            (
                "https://securepubads.g.doubleclick.net/tag/js/gpt.js",
                ResourceKind::Script,
            ),
        ];
        for (u, k) in blocked {
            assert_eq!(f.check(u, page, k), Verdict::Block, "{u}");
        }
        let allowed = [
            ("https://news.example.org/style.css", ResourceKind::Stylesheet),
            (
                "https://cdn.jsdelivr.net/npm/react@18.3.1/umd/react.production.min.js",
                ResourceKind::Script,
            ),
        ];
        for (u, k) in allowed {
            assert_eq!(f.check(u, page, k), Verdict::Allow, "{u}");
        }
    }

    /// D-058, found on 9anime.es: the library fuses rules with the same options, and one rule
    /// it cannot compile (lookahead) disables the whole set.
    #[test]
    fn rules_fused_with_an_unsupported_regex_still_match() {
        let good = "/^https:\\/\\/[a-z]{2}\\.[a-z]{7,14}\\.com\\/[rt][0-9A-Za-z]{10,16}\\/[A-Za-z]{4,5}$/$script,xhr,3p,match-case";
        let lookahead = "/^https:\\/\\/(?:[0-9a-z]+\\.){1,2}cfd\\/[a-z](?=[a-z]*[0-9A-Z])[0-9A-Za-z]{10,27}\\/(?:\\d{6}|[A-Za-z]{5})$/$script,xhr,3p,match-case";
        let text = format!("{lookahead}\n{good}\n");
        let (url, page) = (
            "https://pr.snarescarate.com/rOhVQoppdUGnO/VNGBo",
            "https://cdn.9animez.to/v/x",
        );
        // The library on its own: the working rule is lost with the other.
        let mut raw = FilterSet::new(false);
        raw.add_filter_list(
            text.clone(),
            ParseOptions {
                rule_types: RuleTypes::NetworkOnly,
                ..ParseOptions::default()
            },
        );
        let req = Request::new(url, page, "script", "GET").unwrap();
        assert!(
            !Engine::new_with_filter_set(raw)
                .check_network_request(&req)
                .should_block()
        );
        // As UNTRACE builds it.
        let e = ContentEngine::build(&[Source {
            id: ListId::UboFilters,
            text: &text,
        }])
        .unwrap();
        assert!(e.matches(url, page, ResourceKind::Script));
        assert!(e.blocks_regex_canary());
    }

    /// The ad network on 9anime.es's player (2026-11-26): its pop-up scripts are blocked; the
    /// site's and the player's own scripts are not.
    #[test]
    fn bundled_lists_block_the_player_ad_scripts_seen_on_9anime() {
        let f = Filters::build(&bundled(&ListId::ALL));
        for (u, page) in [
            (
                "https://pr.snarescarate.com/rOhVQoppdUGnO/VNGBo",
                "https://cdn.9animez.to/v/XnMDNiPWwWrAbOz",
            ),
            (
                "https://zw.kantiannogg.com/spOtuAaE4Vxq6Mp/162821",
                "https://cdn.9animez.to/v/XnMDNiPWwWrAbOz",
            ),
            (
                "https://py.paniscamaroon.cfd/r6b089ce9b5bd3/152726",
                "https://9anime.es/",
            ),
        ] {
            assert_eq!(f.check(u, page, ResourceKind::Script), Verdict::Block, "{u}");
        }
        for (u, page) in [
            (
                "https://cdn.9animez.to/movi/element.slim.global.js?v=1795637767",
                "https://9anime.es/watch/x",
            ),
            (
                "https://9anime.es/assets/assets/js/main.min.js?v=1795521866",
                "https://9anime.es/",
            ),
        ] {
            assert_eq!(f.check(u, page, ResourceKind::Script), Verdict::Allow, "{u}");
        }
        assert!(f.content().unwrap().blocks_regex_canary());
    }

    /// D-058: which addresses the lists block as pages. As uBlock Origin's "strict blocking":
    /// rules that name pages (`$document`), and rules that name nothing but a host
    /// (`||ads.example^`); never rules for one kind of request. The links people follow every
    /// day (shorteners, link wrappers, affiliate links) are not among them.
    #[test]
    fn pages_blocked_by_the_lists() {
        let f = Filters::build(&bundled(&ListId::ALL));
        let page = |u: &str| f.content_blocks(u, u, ResourceKind::Document);
        for u in [
            format!("https://{DOCUMENT_CANARY_HOST}/landing"),
            "https://ads.canary.untrace.invalid/".into(),
            "https://fhvfd.com/api/reverse?var=1".into(),
            "https://www.popads.net/".into(),
            "https://ad.doubleclick.net/ddm/clk/1".into(),
        ] {
            assert!(page(&u), "{u}");
        }
        for u in [
            "https://pr.snarescarate.com/rOhVQoppdUGnO/VNGBo", // a rule for scripts only
            "https://9anime.es/",
            "https://www.youtube.com/watch?v=x",
            "https://t.co/abc",
            "https://bit.ly/abc",
            "https://l.facebook.com/l.php?u=x",
            "https://out.reddit.com/t3_x",
            "https://www.google.com/url?q=x",
            "https://duckduckgo.com/l/?uddg=x",
            "https://click.linksynergy.com/deeplink?id=x",
            "https://go.skimresources.com/?id=x",
            "https://www.awin1.com/cread.php?a=1",
            "https://www.paypal.com/",
            "https://accounts.google.com/",
        ] {
            assert!(!page(u), "{u}");
        }
    }

    #[test]
    fn every_list_proves_itself_with_its_canary() {
        let all = Filters::build(&bundled(&ListId::ALL));
        for id in ListId::ALL {
            assert!(all.verify(id), "{id:?}");
        }
        // Only what was built is reported as working.
        let ads_only = Filters::build(&bundled(&[ListId::EasyList]));
        assert!(ads_only.verify(ListId::EasyList));
        assert!(!ads_only.verify(ListId::EasyPrivacy));
        assert!(!ads_only.verify(ListId::Malware));
        assert!(!Filters::default().verify(ListId::EasyList));
    }

    #[test]
    fn threat_hosts_cover_subdomains_but_never_parents() {
        let t = Threats::build(&[Source {
            id: ListId::Phishing,
            text: "# Title: x\nevil.example\nsite123.weebly.com\n203.0.113.9\n",
        }]);
        assert_eq!(t.host("evil.example"), Some(ListId::Phishing));
        assert_eq!(t.host("login.evil.example."), Some(ListId::Phishing));
        assert_eq!(t.host("EVIL.EXAMPLE"), Some(ListId::Phishing));
        assert_eq!(t.host("site123.weebly.com"), Some(ListId::Phishing));
        assert_eq!(t.host("weebly.com"), None);
        assert_eq!(t.host("other.weebly.com"), None);
        assert_eq!(t.host("notevil.example"), None);
        assert_eq!(t.host("203.0.113.9"), Some(ListId::Phishing));
        assert_eq!(t.host("3.0.113.9"), None);
    }

    #[test]
    fn threats_are_reported_before_content_rules() {
        let f = Filters::build(&bundled(&ListId::ALL));
        let page = "https://news.example.org/";
        assert_eq!(
            f.check(&canary_url(ListId::Malware), page, ResourceKind::Image),
            Verdict::Threat(ListId::Malware)
        );
        assert_eq!(
            f.threat("https://phishing.canary.untrace.invalid/login"),
            Some(ListId::Phishing)
        );
        assert_eq!(f.threat("https://example.org/"), None);
    }

    #[test]
    fn cached_engine_round_trips_and_is_verified() {
        let sources = bundled(&[ListId::EasyList, ListId::EasyPrivacy]);
        let built = ContentEngine::build(&sources).unwrap();
        let bytes = built.serialize();
        let restored = ContentEngine::deserialize(built.lists().to_vec(), &bytes).unwrap();
        assert!(restored.blocks_canary(ListId::EasyList));
        assert!(restored.blocks_canary(ListId::EasyPrivacy));
        // A cache claiming a list it was not built with is refused.
        let only_ads = ContentEngine::build(&bundled(&[ListId::EasyList])).unwrap().serialize();
        assert!(ContentEngine::deserialize(vec![ListId::EasyList, ListId::EasyPrivacy], &only_ads).is_err());
        // Garbage is refused.
        assert!(ContentEngine::deserialize(vec![ListId::EasyList], b"not an engine").is_err());
    }

    #[test]
    fn cache_key_changes_with_inputs() {
        let a = cache_key(&bundled(&[ListId::EasyList, ListId::EasyPrivacy]));
        let b = cache_key(&bundled(&[ListId::EasyList]));
        let c = cache_key(&[Source {
            id: ListId::EasyList,
            text: "! Title: EasyList\n||x^",
        }]);
        assert_ne!(a, b);
        assert_ne!(b, c);
        // Threat lists do not affect the content engine.
        assert_eq!(b, cache_key(&bundled(&[ListId::EasyList, ListId::Malware])));
    }

    #[test]
    fn registrable_domain_uses_the_public_suffix_list() {
        assert_eq!(
            registrable_domain("https://news.example.co.uk/a").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable_domain("https://www.example.com/").as_deref(),
            Some("example.com")
        );
    }
}
