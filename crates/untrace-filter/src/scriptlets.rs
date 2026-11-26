//! Scriptlets (`##+js(…)`), D-057.
//!
//! Some ads cannot be stopped by blocking requests: YouTube serves its video ads from its own
//! servers inside the player's data. uBlock Origin's lists handle these with scriptlets, small
//! functions that run in the page before its own scripts and change what the page sees (remove
//! the ad data, stop a pop-up opener, defuse an anti-adblock check). UNTRACE runs uBlock
//! Origin's own scriptlets (`resources/ubo-scriptlets.json`, GPL-3.0, built from a pinned
//! uBlock Origin release by `scripts/ubo-scriptlets`), as the lists' rules ask:
//! - only scriptlets from that bundled file run; a list chooses which and with what arguments;
//! - "trusted" scriptlets (which can put any text into a page) only for uBlock Origin's lists;
//! - the per-site "Block ads and trackers" switch turns them off for that site (host.rs).

use adblock::{
    Engine,
    lists::{FilterSet, ParseOptions, RuleTypes},
    resources::{PermissionMask, Resource},
};
use serde::Deserialize;

use crate::{Format, engine::Source, info};

/// The bundled resource file.
const RESOURCES: &str = include_str!("../resources/ubo-scriptlets.json");

/// Pages on this host get a scriptlet that sets `window.untraceScriptletCanary` to `true`:
/// the self-check's proof that scriptlets are loaded and run before the page's own scripts.
pub const SCRIPTLET_CANARY_HOST: &str = "selfcheck.untrace.invalid";
const TRUSTED: PermissionMask = PermissionMask::from_bits(1);

#[derive(Deserialize)]
struct ResourceFile {
    version: String,
    resources: Vec<Resource>,
}

/// The scriptlet rules of the enabled lists, with uBlock Origin's scriptlets.
pub struct Scriptlets {
    engine: Engine,
    rules: usize,
    version: String,
}

/// uBlock Origin's version the bundled scriptlets come from.
pub fn resources_version() -> String {
    serde_json::from_str::<ResourceFile>(RESOURCES)
        .map(|f| f.version)
        .unwrap_or_default()
}

impl Scriptlets {
    pub fn build(sources: &[Source<'_>]) -> Self {
        let mut set = FilterSet::new(false);
        let mut rules = 0;
        for s in sources.iter().filter(|s| info(s.id).format == Format::Adblock) {
            let text = crate::preprocess::list_text(s);
            let lines: Vec<&str> = text.lines().filter(|l| l.contains("#+js(")).collect();
            rules += lines.len();
            let opts = ParseOptions {
                rule_types: RuleTypes::CosmeticOnly,
                permissions: if s.id.is_ublock() {
                    TRUSTED
                } else {
                    PermissionMask::default()
                },
                ..ParseOptions::default()
            };
            set.add_filter_list(lines.join("\n"), opts);
        }
        if !sources.is_empty() {
            set.add_filter_list(
                format!("{SCRIPTLET_CANARY_HOST}##+js(set, untraceScriptletCanary, true)"),
                ParseOptions {
                    rule_types: RuleTypes::CosmeticOnly,
                    ..ParseOptions::default()
                },
            );
        }
        let mut engine = Engine::new_with_filter_set(set);
        let (version, resources) = match serde_json::from_str::<ResourceFile>(RESOURCES) {
            Ok(f) => (f.version, f.resources),
            Err(_) => (String::new(), Vec::new()),
        };
        engine.use_resources(resources);
        Self { engine, rules, version }
    }

    /// Scriptlet rules read from the lists.
    pub fn len(&self) -> usize {
        self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.rules == 0
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// The scriptlet code for a page at `url`, or `None` if no rule applies there.
    pub fn code_for(&self, url: &str) -> Option<String> {
        let code = self.engine.url_cosmetic_resources(url).injected_script;
        (!code.trim().is_empty()).then_some(code)
    }
}

/// Wrap scriptlet code for one host: it runs once per document, only on that host, inside a
/// function of its own (as uBlock Origin wraps it), with the shared object the scriptlets expect.
pub fn page_script(host: &str, code: &str) -> String {
    let host = serde_json::to_string(&host.trim_end_matches('.').to_ascii_lowercase()).unwrap_or_default();
    format!(
        r##"(function untraceScriptlets() {{
let h = "";
try {{
  const o = self.origin;
  h = (o && o !== "null" ? new URL(o).hostname : location.hostname) || "";
}} catch (e) {{}}
if (h.toLowerCase().replace(/\.$/, "") !== {host}) return;
const K = Symbol.for("untrace.scriptlets");
if (self[K]) return;
try {{ Object.defineProperty(self, K, {{ value: true }}); }} catch (e) {{}}
const scriptletGlobals = {{}};
{code}
}})();"##
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ListId;

    fn bundled(ids: &[ListId]) -> Vec<Source<'static>> {
        ids.iter()
            .map(|id| Source {
                id: *id,
                text: info(*id).bundled,
            })
            .collect()
    }

    #[test]
    fn the_bundled_scriptlets_load() {
        let f: ResourceFile = serde_json::from_str(RESOURCES).expect("resource file");
        assert!(f.resources.len() > 100, "{}", f.resources.len());
        assert!(!f.version.is_empty());
    }

    #[test]
    fn youtube_gets_the_ad_scriptlets_and_the_canary_its_own() {
        let s = Scriptlets::build(&bundled(&ListId::ALL));
        assert!(s.len() > 1000, "{} scriptlet rules", s.len());
        let yt = s
            .code_for("https://www.youtube.com/watch?v=x")
            .expect("YouTube scriptlets");
        // uBlock Origin's rules remove the player's ad data (set-constant / json-prune).
        assert!(yt.contains("adPlacements"), "ad data rules");
        assert!(
            yt.contains("function setConstant") || yt.contains("function jsonPrune"),
            "{}",
            &yt[..200.min(yt.len())]
        );
        let canary = s
            .code_for(&format!("https://{SCRIPTLET_CANARY_HOST}/probe.html"))
            .expect("canary");
        assert!(canary.contains("untraceScriptletCanary"));
        assert!(
            s.code_for("https://example.com/")
                .is_none_or(|c| !c.contains("adPlacements"))
        );
    }

    #[test]
    fn trusted_scriptlets_only_for_ublock_lists() {
        let rule = "trusted.example##+js(trusted-set-constant, a, '{}')";
        let mk = |id: ListId| {
            let mut set = FilterSet::new(false);
            set.add_filter_list(
                rule.to_string(),
                ParseOptions {
                    rule_types: RuleTypes::CosmeticOnly,
                    permissions: if id.is_ublock() {
                        TRUSTED
                    } else {
                        PermissionMask::default()
                    },
                    ..ParseOptions::default()
                },
            );
            let mut e = Engine::new_with_filter_set(set);
            e.use_resources(serde_json::from_str::<ResourceFile>(RESOURCES).unwrap().resources);
            e.url_cosmetic_resources("https://trusted.example/").injected_script
        };
        assert!(
            mk(ListId::UboFilters).contains("trustedSetConstant"),
            "uBlock list may use it"
        );
        assert!(!mk(ListId::EasyList).contains("trustedSetConstant"), "EasyList may not");
    }

    #[test]
    fn the_page_script_runs_once_and_only_on_its_host() {
        let p = page_script("WWW.Example.com.", "doIt();");
        assert!(p.contains("\"www.example.com\""));
        assert!(p.contains("const scriptletGlobals = {};"));
        assert!(p.contains("Symbol.for(\"untrace.scriptlets\")"));
        assert!(p.trim_end().ends_with("})();"));
    }
}
