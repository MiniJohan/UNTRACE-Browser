//! Pop-up rules (`$popup`), 2026-11-26.
//!
//! The matching library (adblock-rust) does not know the `popup` option, so it drops every rule
//! that names it: about 3,000 in EasyList, the rules that stop ad pop-ups and pop-unders. It
//! also drops what such a rule says about other request types (`$popup,subdocument`). UNTRACE
//! reads these rules itself: the pop-up part goes into a small engine of its own, matched when
//! a page opens a window; any other types go back into the main engine.

use adblock::{
    Engine,
    lists::{FilterSet, ParseOptions, RuleTypes},
    request::Request,
};

use crate::{Format, info};

/// Pop-ups to this host are refused whenever an Adblock-format list is on: the self-check's
/// proof that pop-up rules are loaded and applied.
pub const POPUP_CANARY_HOST: &str = "popup.canary.untrace.invalid";

/// Request types a rule can name. In a pop-up rule they are dropped (the pop-up is a page);
/// other modifiers (domain, party, case, important) are kept.
const TYPES: &[&str] = &[
    "script",
    "image",
    "stylesheet",
    "css",
    "object",
    "object-subrequest",
    "xmlhttprequest",
    "xhr",
    "subdocument",
    "frame",
    "ping",
    "beacon",
    "media",
    "font",
    "other",
    "websocket",
    "webrtc",
    "document",
    "doc",
];

/// A list's network rules that name `popup`, rewritten: `popup` holds the pop-up part as rules
/// for a page (`$document`), `rest` the same rules for their other types, if any.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Split {
    pub popup: Vec<String>,
    pub rest: Vec<String>,
}

/// Find and rewrite the rules that name `popup`. Comments and element-hiding rules are skipped.
pub fn split(text: &str) -> Split {
    let mut out = Split::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('!')
            || line.starts_with('[')
            || line.contains("##")
            || line.contains("#@#")
            || line.contains("#?#")
            || line.contains("#$#")
        {
            continue;
        }
        let Some((pattern, options)) = line.rsplit_once('$') else {
            continue;
        };
        if pattern.is_empty() || pattern == "@@" {
            continue;
        }
        let tokens: Vec<&str> = options.split(',').map(str::trim).collect();
        if !tokens.iter().any(|t| t.eq_ignore_ascii_case("popup")) {
            continue;
        }
        let is_type = |t: &str| {
            let t = t.trim_start_matches('~').to_ascii_lowercase();
            t == "popup" || t == "popunder" || TYPES.contains(&t.as_str())
        };
        let mods: Vec<&str> = tokens.iter().copied().filter(|t| !is_type(t)).collect();
        let mut popup = vec!["document"];
        popup.extend(&mods);
        out.popup.push(format!("{pattern}${}", popup.join(",")));
        let others: Vec<&str> = tokens
            .iter()
            .copied()
            .filter(|t| !t.eq_ignore_ascii_case("popup") && !t.starts_with('~') && is_type(t))
            .collect();
        if !others.is_empty() {
            let rest: Vec<&str> = tokens
                .iter()
                .copied()
                .filter(|t| !t.eq_ignore_ascii_case("popup"))
                .collect();
            out.rest.push(format!("{pattern}${}", rest.join(",")));
        }
    }
    out
}

/// The pop-up rules of the enabled Adblock-format lists.
pub struct PopupRules {
    engine: Engine,
    rules: usize,
}

impl PopupRules {
    pub fn build(sources: &[crate::engine::Source<'_>]) -> Self {
        let opts = ParseOptions {
            rule_types: RuleTypes::NetworkOnly,
            ..ParseOptions::default()
        };
        let mut set = FilterSet::new(false);
        let mut rules = 0;
        for s in sources.iter().filter(|s| info(s.id).format == Format::Adblock) {
            let split = split(&crate::preprocess::list_text(s));
            rules += split.popup.len();
            set.add_filter_list(split.popup.join("\n"), opts);
        }
        if rules > 0 {
            set.add_filter_list(format!("||{POPUP_CANARY_HOST}^$document"), opts);
        }
        Self {
            engine: Engine::new_with_filter_set(set),
            rules,
        }
    }

    /// Rules read (some may still be refused by the matching library).
    pub fn len(&self) -> usize {
        self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.rules == 0
    }

    /// Do the lists stop a page at `opener` from opening `target` in a new window?
    pub fn blocks(&self, target: &str, opener: &str) -> bool {
        Request::new(target, opener, "document", "GET")
            .map(|r| self.engine.check_network_request(&r).should_block())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ListId, engine::Source};

    #[test]
    fn rules_that_name_popup_are_rewritten() {
        let s = split(
            "! comment\n\
             ||pop.example^$popup\n\
             ||both.example^$popup,subdocument,third-party\n\
             @@||ok.example^$popup,domain=site.example\n\
             /earn.php?z=$popup,subdocument\n\
             ||plain.example^$script\n\
             example.com##.ad\n\
             ||neg.example^$popup,~third-party\n",
        );
        assert_eq!(
            s.popup,
            vec![
                "||pop.example^$document",
                "||both.example^$document,third-party",
                "@@||ok.example^$document,domain=site.example",
                "/earn.php?z=$document",
                "||neg.example^$document,~third-party",
            ]
        );
        assert_eq!(
            s.rest,
            vec!["||both.example^$subdocument,third-party", "/earn.php?z=$subdocument"]
        );
    }

    fn rules(text: &str) -> PopupRules {
        PopupRules::build(&[Source {
            id: ListId::EasyList,
            text,
        }])
    }

    #[test]
    fn popups_match_by_address_party_and_opener() {
        let r = rules(
            "||pop.example^$popup\n\
             ||third.example^$popup,third-party\n\
             ||only-here.example^$popup,domain=site.example\n\
             ||ok.example^$popup\n\
             @@||ok.example/fine^$popup\n",
        );
        assert_eq!(r.len(), 5);
        assert!(r.blocks("https://pop.example/x?y", "https://site.example/watch"));
        assert!(r.blocks("https://cdn.pop.example/", "https://other.example/"));
        assert!(!r.blocks("https://unrelated.example/", "https://site.example/"));
        assert!(r.blocks("https://third.example/", "https://site.example/"));
        assert!(
            !r.blocks("https://www.third.example/", "https://third.example/"),
            "first party"
        );
        assert!(r.blocks("https://only-here.example/", "https://site.example/"));
        assert!(!r.blocks("https://only-here.example/", "https://elsewhere.example/"));
        assert!(r.blocks("https://ok.example/bad", "https://site.example/"));
        assert!(
            !r.blocks("https://ok.example/fine", "https://site.example/"),
            "exception"
        );
        assert!(!r.blocks("about:blank", "https://site.example/"));
        assert!(r.blocks(&format!("https://{POPUP_CANARY_HOST}/x"), "https://site.example/"));
        assert!(!rules("||x.example^$script\n").blocks(&format!("https://{POPUP_CANARY_HOST}/"), "https://s.example/"));
    }

    #[test]
    fn easylist_popup_rules_are_used() {
        let text = info(ListId::EasyList).bundled;
        let split = split(text);
        assert!(split.popup.len() > 2000, "{} pop-up rules", split.popup.len());
        let r = rules(text);
        // Every plain `||host^$popup` rule in the bundled list blocks a pop-up to its host.
        let hosts: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("||")?.strip_suffix("^$popup"))
            .filter(|h| h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
            .take(200)
            .collect();
        assert!(hosts.len() > 50, "{} plain pop-up hosts", hosts.len());
        for h in hosts {
            assert!(r.blocks(&format!("https://{h}/"), "https://site.example/"), "{h}");
        }
        assert!(!r.blocks("https://en.wikipedia.org/wiki/Pop-up_ad", "https://site.example/"));
    }
}
