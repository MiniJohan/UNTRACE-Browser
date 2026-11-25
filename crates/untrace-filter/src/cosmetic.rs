//! Cosmetic filtering (M6, D-015): the element-hiding rules of the enabled Adblock lists,
//! sorted so that one document-start script can apply them in every frame without asking
//! UNTRACE anything (content views have no bridge, D-002).
//!
//! - **Generic** rules (`##selector`) apply on every site. Those that are just `.class` or
//!   `#id`, or start with one, are kept by that class or id, so the script only applies the
//!   ones whose class or id occurs on the page. The rest ("misc") always apply.
//! - **Site-specific** rules (`example.com##selector`, `example.*##…`) and **exceptions**
//!   (`example.com#@#selector`) are kept per host name.
//! - Network exceptions with `$generichide` / `$elemhide` switch generic (or all) hiding off for
//!   a host.
//! - Not applied as CSS, only counted: extended rules (`#?#`, `:has-text()` …), rules with an
//!   action (`:remove()`, `:style()`), scriptlets (`##+js(…)`), and rules the parser rejects.
//!
//! Every selector is validated by adblock-rust's parser (the same one Brave uses) before use.

use std::collections::{BTreeMap, BTreeSet};

use adblock::{filters::cosmetic::CosmeticFilter, resources::PermissionMask};
use serde::Serialize;

use crate::catalog::{Format, ListId, info};

/// Host under which each list's site-specific canary rule is filed. The self-check's pages
/// (`*.untrace.invalid`) fall under it; no real site does.
pub const CANARY_HOST: &str = "untrace.invalid";
/// Class hidden on `CANARY_HOST` pages by every Adblock list's site-specific canary.
pub const CANARY_SPECIFIC_CLASS: &str = "untrace-canary-specific";

/// Class hidden by a list's generic canary rule: proof that list's hiding rules are applied.
pub fn canary_class(id: ListId) -> String {
    format!("untrace-canary-{}", id.stem())
}

/// Rules for one host name (and its subdomains), or one `name.*` entity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostRules {
    pub hide: Vec<String>,
    pub unhide: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CosmeticStats {
    pub generic: usize,
    pub generic_by_class_or_id: usize,
    pub specific: usize,
    pub exceptions: usize,
    /// Extended (procedural) rules: not applied.
    pub procedural: usize,
    /// Rules with an action such as `:remove()` or `:style()`: not applied.
    pub actions: usize,
    /// Scriptlet rules: not applied (they need code from a resource set, D-017).
    pub scriptlets: usize,
    /// Lines the parser rejects or UNTRACE does not support.
    pub unsupported: usize,
    pub hosts: usize,
}

#[derive(Debug, Clone, Default)]
pub struct CosmeticRules {
    /// Generic `.name` rules, by class.
    pub simple_classes: BTreeSet<String>,
    /// Generic `#name` rules, by id.
    pub simple_ids: BTreeSet<String>,
    /// Generic rules starting with a class (`.name …`), by that class.
    pub complex_classes: BTreeMap<String, Vec<String>>,
    pub complex_ids: BTreeMap<String, Vec<String>>,
    /// Other generic rules (applied on every page).
    pub misc: Vec<String>,
    /// Host name (or `name.*`) → its rules.
    pub hosts: BTreeMap<String, HostRules>,
    /// Hosts where generic rules do not apply (`$generichide`).
    pub generichide: BTreeSet<String>,
    /// Hosts where no cosmetic rule applies (`$elemhide`).
    pub elemhide: BTreeSet<String>,
    pub stats: CosmeticStats,
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && !s.as_bytes()[0].is_ascii_digit()
}

/// `(".", "name")` for `.name`, or for a selector starting with `.name` followed by a
/// combinator, attribute, pseudo-class or another simple selector.
fn leading(selector: &str) -> Option<(char, &str, bool)> {
    let first = selector.chars().next()?;
    if first != '.' && first != '#' {
        return None;
    }
    let rest = &selector[1..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .unwrap_or(rest.len());
    let name = &rest[..end];
    if !is_ident(name) {
        return None;
    }
    let tail = &rest[end..];
    // A selector list (",") applies to more than this class or id: keep it general.
    if tail.contains(',') {
        return None;
    }
    // An escape right after the name means the name continues: not a plain identifier.
    if tail.starts_with('\\') {
        return None;
    }
    Some((first, name, tail.is_empty()))
}

/// Extended (procedural) operators: they need code, not CSS, so they are not applied.
const EXTENDED: [&str; 24] = [
    ":-abp-contains(",
    ":-abp-properties(",
    ":has-text(",
    ":contains(",
    ":matches-css(",
    ":matches-css-before(",
    ":matches-css-after(",
    ":matches-attr(",
    ":matches-path(",
    ":matches-prop(",
    ":matches-media(",
    ":min-text-length(",
    ":upward(",
    ":xpath(",
    ":watch-attr(",
    ":if(",
    ":if-not(",
    ":others(",
    ":remove(",
    ":style(",
    ":remove-attr(",
    ":remove-class(",
    ":nth-ancestor(",
    ":shadow-root",
];

enum Rejected {
    Extended,
    Unsafe,
}

/// A selector UNTRACE may put into a style sheet, in standard CSS:
/// - `{`, `}`, a comment or an at-rule could carry declarations (and with them `url(…)`
///   requests) out of the selector, so such a selector is refused outright;
/// - `:-abp-has(` is standard `:has(`;
/// - other extended operators are not CSS.
fn normalise(selector: &str) -> Result<String, Rejected> {
    let s = selector.trim();
    if s.is_empty() || s.contains(['{', '}']) || s.contains("/*") || s.starts_with('@') || s.len() > 1024 {
        return Err(Rejected::Unsafe);
    }
    let s = s.replace(":-abp-has(", ":has(");
    if EXTENDED.iter().any(|op| s.contains(op)) || s.contains(":-abp-") {
        return Err(Rejected::Extended);
    }
    Ok(s)
}

/// The host part of `@@||host^$…generichide|elemhide`.
fn hide_exception(line: &str) -> Option<(String, bool, bool)> {
    let body = line.strip_prefix("@@||")?;
    let (pattern, options) = body.split_once('$')?;
    let host = pattern.strip_suffix('^').unwrap_or(pattern);
    if host.is_empty() || host.contains(['/', '*', '^', '|']) {
        return None;
    }
    let opts: Vec<&str> = options.split(',').map(str::trim).collect();
    let generic = opts.iter().any(|o| *o == "generichide" || *o == "ghide");
    let all = opts.iter().any(|o| *o == "elemhide" || *o == "ehide");
    (generic || all).then(|| (host.to_ascii_lowercase(), generic, all))
}

impl CosmeticRules {
    /// Sort the cosmetic rules of the given Adblock-format lists (others are ignored).
    pub fn build(sources: &[crate::engine::Source<'_>]) -> Self {
        let mut r = Self::default();
        for s in sources.iter().filter(|s| info(s.id).format == Format::Adblock) {
            for line in s.text.lines() {
                r.add_line(line.trim());
            }
            // Canaries (like the network canaries, M3): a generic rule and a site-specific rule
            // per list, so the self-check and Settings can verify hiding end to end.
            r.simple_classes.insert(canary_class(s.id));
            let canary = r.hosts.entry(CANARY_HOST.to_string()).or_default();
            if !canary.hide.iter().any(|h| h == &format!(".{CANARY_SPECIFIC_CLASS}")) {
                canary.hide.push(format!(".{CANARY_SPECIFIC_CLASS}"));
            }
        }
        r.stats.hosts = r.hosts.len();
        // Exceptions also cancel generic rules with the same selector on that host; that is
        // done in the script. Keep host lists sorted and unique for stable output.
        for h in r.hosts.values_mut() {
            h.hide.sort();
            h.hide.dedup();
            h.unhide.sort();
            h.unhide.dedup();
        }
        for v in r.complex_classes.values_mut().chain(r.complex_ids.values_mut()) {
            v.sort();
            v.dedup();
        }
        r.misc.sort();
        r.misc.dedup();
        r
    }

    fn add_line(&mut self, line: &str) {
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            return;
        }
        if line.starts_with("@@") {
            if let Some((host, generic, all)) = hide_exception(line) {
                if all {
                    self.elemhide.insert(host);
                } else if generic {
                    self.generichide.insert(host);
                }
            }
            return;
        }
        let Some(sharp) = line.find('#') else { return };
        let marker = &line[sharp..];
        if !(marker.starts_with("##")
            || marker.starts_with("#@#")
            || marker.starts_with("#?#")
            || marker.starts_with("#@?#")
            || marker.starts_with("#$#")
            || marker.starts_with("#@$#")
            || marker.starts_with("#%#")
            || marker.starts_with("#@%#"))
        {
            return; // a network rule that happens to contain '#'
        }
        if marker.starts_with("##+js(") || marker.starts_with("#@#+js(") || marker.starts_with("#$#") {
            self.stats.scriptlets += 1;
            return;
        }
        let Ok(f) = CosmeticFilter::parse(line, false, PermissionMask::default()) else {
            self.stats.unsupported += 1;
            return;
        };
        if f.action.is_some() {
            self.stats.actions += 1;
            return;
        }
        let Some(selector) = f.plain_css_selector() else {
            self.stats.procedural += 1;
            return;
        };
        let selector = match normalise(selector) {
            Ok(s) => s,
            Err(Rejected::Extended) => {
                self.stats.procedural += 1;
                return;
            }
            Err(Rejected::Unsafe) => {
                self.stats.unsupported += 1;
                return;
            }
        };
        let unhide = marker.starts_with("#@");
        let domains = &line[..sharp];
        let (mut on, mut off) = (Vec::new(), Vec::new());
        for d in domains.split(',').map(str::trim).filter(|d| !d.is_empty()) {
            match d.strip_prefix('~') {
                Some(n) => off.push(n.to_ascii_lowercase()),
                None => on.push(d.to_ascii_lowercase()),
            }
        }
        if unhide {
            self.stats.exceptions += 1;
            for h in on {
                self.hosts.entry(h).or_default().unhide.push(selector.clone());
            }
            return;
        }
        if on.is_empty() {
            // Generic, possibly with sites it must not apply to.
            self.stats.generic += 1;
            for h in off {
                self.hosts.entry(h).or_default().unhide.push(selector.clone());
            }
            match leading(&selector) {
                Some(('.', name, true)) => {
                    self.simple_classes.insert(name.to_string());
                    self.stats.generic_by_class_or_id += 1;
                }
                Some(('#', name, true)) => {
                    self.simple_ids.insert(name.to_string());
                    self.stats.generic_by_class_or_id += 1;
                }
                Some(('.', name, false)) => {
                    self.complex_classes.entry(name.to_string()).or_default().push(selector);
                    self.stats.generic_by_class_or_id += 1;
                }
                Some((_, name, false)) => {
                    self.complex_ids.entry(name.to_string()).or_default().push(selector);
                    self.stats.generic_by_class_or_id += 1;
                }
                _ => self.misc.push(selector),
            }
            return;
        }
        self.stats.specific += 1;
        for h in on {
            self.hosts.entry(h).or_default().hide.push(selector.clone());
        }
        for h in off {
            self.hosts.entry(h).or_default().unhide.push(selector.clone());
        }
    }

    /// Rules for one host name, as the script will find them: the host, each parent domain,
    /// and the `name.*` entity forms. For tests and the site panel.
    pub fn for_host(&self, host: &str) -> HostRules {
        let mut out = HostRules::default();
        for key in lookup_keys(host) {
            if let Some(h) = self.hosts.get(&key) {
                out.hide.extend(h.hide.iter().cloned());
                out.unhide.extend(h.unhide.iter().cloned());
            }
        }
        out
    }

    /// Does this rule set carry the given list's canaries? (Settings read-back.)
    pub fn has_canary(&self, id: ListId) -> bool {
        self.simple_classes.contains(&canary_class(id))
            && self
                .hosts
                .get(CANARY_HOST)
                .is_some_and(|h| h.hide.iter().any(|s| s == &format!(".{CANARY_SPECIFIC_CLASS}")))
    }

    /// Nothing to hide (no Adblock list enabled).
    pub fn is_empty(&self) -> bool {
        self.simple_classes.is_empty() && self.simple_ids.is_empty() && self.misc.is_empty() && self.hosts.is_empty()
    }
}

/// The names a host's rules are filed under: `a.b.example.com`, `b.example.com`,
/// `example.com`, `com`, plus entity forms `a.b.example.*`, `b.example.*`, `example.*` (the last
/// one or two labels replaced by `*`, which covers one- and two-label public suffixes).
pub fn lookup_keys(host: &str) -> Vec<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let mut keys = Vec::new();
    for i in 0..labels.len() {
        keys.push(labels[i..].join("."));
    }
    for cut in 1..=2 {
        if labels.len() > cut {
            for i in 0..labels.len() - cut {
                let k = format!("{}.*", labels[i..labels.len() - cut].join("."));
                if !keys.contains(&k) {
                    keys.push(k);
                }
            }
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Source;

    fn rules(text: &str) -> CosmeticRules {
        CosmeticRules::build(&[Source {
            id: ListId::EasyList,
            text,
        }])
    }

    #[test]
    fn rules_are_sorted_by_kind() {
        let r = rules(
            "! comment\n##.ad-banner\n###top-ad\n##.ad-slot > img\n###sidebar-ad div\n##a[href*=\"/ad/\"]\n\
             example.com##.promo\nexample.com,~shop.example.com##.box\nnews.example#@#.ad-banner\n\
             softonic.*##.sponsored\n~exempt.org##.everywhere\n\
             example.org#?#div:-abp-contains(Sponsored)\nexample.org##.x:remove()\nexample.org##+js(noeval)\n\
             @@||quiet.example^$generichide\n@@||silent.example^$elemhide\n||ads.example^\n",
        );
        assert!(r.simple_classes.contains("ad-banner") && r.simple_classes.contains("everywhere"));
        assert!(r.simple_ids.contains("top-ad"));
        assert_eq!(r.complex_classes["ad-slot"], vec![".ad-slot > img".to_string()]);
        assert_eq!(r.complex_ids["sidebar-ad"], vec!["#sidebar-ad div".to_string()]);
        assert_eq!(r.misc, vec!["a[href*=\"/ad/\"]".to_string()]);
        assert_eq!(
            r.hosts["example.com"].hide,
            vec![".box".to_string(), ".promo".to_string()]
        );
        assert_eq!(r.hosts["shop.example.com"].unhide, vec![".box".to_string()]);
        assert_eq!(r.hosts["news.example"].unhide, vec![".ad-banner".to_string()]);
        assert_eq!(r.hosts["softonic.*"].hide, vec![".sponsored".to_string()]);
        assert_eq!(r.hosts["exempt.org"].unhide, vec![".everywhere".to_string()]);
        assert!(r.generichide.contains("quiet.example") && r.elemhide.contains("silent.example"));
        assert!(r.has_canary(ListId::EasyList) && !r.has_canary(ListId::EasyPrivacy));
        assert_eq!((r.stats.procedural, r.stats.actions, r.stats.scriptlets), (1, 1, 1));
        assert_eq!(r.stats.generic, 6);
        assert_eq!(r.stats.specific, 3);
        assert_eq!(r.stats.exceptions, 1);
    }

    #[test]
    fn selectors_are_standard_css_and_cannot_carry_declarations() {
        let r = rules(
            "example.org#?#div:-abp-has(> .ad)
example.org##div:has-text(Ad)
             ##.x{background:url(https://evil.example/)}
##.y /* c */
##@import
example.org##.ok
",
        );
        assert_eq!(
            r.hosts["example.org"].hide,
            vec![".ok".to_string(), "div:has(> .ad)".to_string()]
        );
        assert_eq!(r.stats.procedural, 1);
        assert_eq!(r.stats.unsupported, 3);
        // Only the list's own canary class is a generic rule here.
        assert!(r.misc.is_empty() && r.simple_classes.iter().all(|c| c.starts_with("untrace-canary-")));
    }

    #[test]
    fn host_lookup_covers_parents_and_entities() {
        let k = lookup_keys("www.softonic.co.uk");
        for want in [
            "www.softonic.co.uk",
            "softonic.co.uk",
            "co.uk",
            "uk",
            "www.softonic.*",
            "softonic.*",
        ] {
            assert!(k.contains(&want.to_string()), "{want} in {k:?}");
        }
        let r = rules("softonic.*##.sponsored\nsoftonic.com##.only-com\n");
        assert_eq!(
            r.for_host("en.softonic.com").hide,
            vec![".only-com".to_string(), ".sponsored".to_string()]
        );
        assert!(r.for_host("example.com").hide.is_empty());
    }

    #[test]
    fn bundled_easylist_sorts_without_surprises() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/lists/easylist.txt")).unwrap();
        let r = rules(&text);
        let s = &r.stats;
        // Most generic rules are keyed by a class or id (that is what makes observation cheap).
        assert!(
            s.generic > 10_000 && s.generic_by_class_or_id * 10 > s.generic * 8,
            "{s:?}"
        );
        assert!(s.specific > 5_000 && s.hosts > 3_000, "{s:?}");
        assert!(s.unsupported * 100 < s.generic, "{s:?}");
    }
}

/// How the document-start script applies generic rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericMode {
    /// Watch the page's classes and ids; apply only the generic rules keyed by those.
    Observe,
    /// Apply every generic rule at once (one large stylesheet per frame).
    All,
}

#[derive(Debug, Clone)]
pub struct ScriptOptions {
    pub generic: GenericMode,
    /// Sites (registrable domains) where cosmetic filtering is off (the user's per-site switch).
    pub off_sites: Vec<String>,
    /// SPIKE/SELF-CHECK ONLY: record timing and counts in a page-visible variable.
    pub debug: bool,
    /// Carry every site's own rules in this script (about 0.5 MB more in every document).
    /// UNTRACE sends them per site instead (`site_script`); kept for measurements.
    pub embed_site_rules: bool,
}

const HIDE: &str = "{display:none!important}";

/// Separators inside the embedded data. They never occur in a selector or host name, and as
/// raw characters they cost one byte each (escaped, six): the script is about 10 % smaller and
/// cheaper for the engine to read in every frame.
const ROW: &str = "\u{1d}";
const HIDE_UNHIDE: &str = "\u{1e}";
const ITEM: &str = "\u{1f}";

/// A JavaScript string literal. Only what JavaScript requires is escaped; tabs and the data
/// separators stay raw.
fn js(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            '\t' | '\u{1d}' | '\u{1e}' | '\u{1f}' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{7f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl CosmeticRules {
    /// The document-start script (D-015): data embedded, no request, no bridge. Runs in every
    /// frame's main world before the page's own scripts.
    pub fn script(&self, o: &ScriptOptions) -> String {
        let rule = |s: &str| format!("{s}{HIDE} ");
        let misc: String = self.misc.iter().map(|s| rule(s)).collect();
        let all_generic: String = match o.generic {
            GenericMode::All => self
                .simple_classes
                .iter()
                .map(|c| rule(&format!(".{c}")))
                .chain(self.simple_ids.iter().map(|i| rule(&format!("#{i}"))))
                .chain(
                    self.complex_classes
                        .values()
                        .chain(self.complex_ids.values())
                        .flatten()
                        .map(|s| rule(s)),
                )
                .collect(),
            GenericMode::Observe => String::new(),
        };
        let join = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(ROW);
        let keyed = |m: &BTreeMap<String, Vec<String>>| {
            m.iter()
                .map(|(k, v)| format!("{k}\t{}", v.join(ITEM)))
                .collect::<Vec<_>>()
                .join(ROW)
        };
        // Site-specific hide rules travel in the small per-site script (`site_script`) unless
        // asked for here; the exceptions stay, because they also cancel generic rules.
        let hosts: String = self
            .hosts
            .iter()
            .filter(|(_, h)| o.embed_site_rules || !h.unhide.is_empty())
            .map(|(k, h)| {
                let hide = if o.embed_site_rules {
                    h.hide.join(ITEM)
                } else {
                    String::new()
                };
                format!("{ROW}{k}\t{hide}{HIDE_UNHIDE}{}", h.unhide.join(ITEM))
            })
            .collect::<String>()
            + ROW;
        let lines = |v: &[String]| format!("{ROW}{}{ROW}", v.join(ROW));
        let generichide: Vec<String> = self.generichide.iter().cloned().collect();
        let elemhide: Vec<String> = self.elemhide.iter().cloned().collect();
        format!(
            r##"(() => {{
"use strict";
const T0 = performance.now();
const DEBUG = {debug};
const OBSERVE = {observe};
const MISC = {misc};
const ALL = {all};
const SC = {sc}, SI = {si}, CC = {cc}, CI = {ci};
const H = {hosts};
const OFF = {off}, GH = {gh}, EH = {eh};
const HIDE = "{HIDE}";
let host = "";
try {{
  const o = self.origin;
  host = (o && o !== "null" ? new URL(o).hostname : location.hostname) || "";
}} catch (e) {{}}
host = host.toLowerCase().replace(/\.$/, "");
const labels = host ? host.split(".") : [];
const suffixes = labels.map((_, i) => labels.slice(i).join("."));
const R = "\u001d", IT = "\u001f";
const inList = (list) => suffixes.some((s) => list.indexOf(R + s + R) >= 0);
if (inList(OFF) || inList(EH)) {{ if (DEBUG) self.__untraceCosmetic = {{ off: true, started: T0, setupMs: performance.now() - T0 }}; return; }}
const keys = suffixes.slice();
for (const cut of [1, 2]) {{
  for (let i = 0; i < labels.length - cut; i++) {{
    const k = labels.slice(i, labels.length - cut).join(".") + ".*";
    if (!keys.includes(k)) keys.push(k);
  }}
}}
const hide = [], unhide = new Set();
for (const k of keys) {{
  const at = H.indexOf(R + k + "\t");
  if (at < 0) continue;
  const end = H.indexOf(R, at + 1);
  const row = H.slice(at + k.length + 2, end);
  const sep = row.indexOf("\u001e");
  const hs = row.slice(0, sep), us = row.slice(sep + 1);
  if (hs) for (const s of hs.split(IT)) hide.push(s);
  if (us) for (const s of us.split(IT)) unhide.add(s);
}}
const generic = !inList(GH);
let css = "";
for (const s of hide) if (!unhide.has(s)) css += s + HIDE + " ";
if (generic) css += MISC + ALL;
const base = new CSSStyleSheet();
const extra = new CSSStyleSheet();
try {{ base.replaceSync(css); }} catch (e) {{}}
const adopt = () => {{
  try {{
    const cur = document.adoptedStyleSheets;
    if (!cur.includes(base)) document.adoptedStyleSheets = [...cur, base, extra];
  }} catch (e) {{}}
}};
adopt();
let matched = 0;
if (generic && OBSERVE) {{
  let sc = null, si = null, cc = null, ci = null;
  const sets = () => {{
    sc = new Set(SC.split(R));
    si = new Set(SI.split(R));
    cc = new Map(); for (const l of CC.split(R)) {{ const t = l.indexOf("\t"); if (t > 0) cc.set(l.slice(0, t), l.slice(t + 1).split(IT)); }}
    ci = new Map(); for (const l of CI.split(R)) {{ const t = l.indexOf("\t"); if (t > 0) ci.set(l.slice(0, t), l.slice(t + 1).split(IT)); }}
  }};
  const seen = new Set();
  const add = (sel) => {{
    if (unhide.has(sel)) return;
    try {{ extra.insertRule(sel + HIDE, extra.cssRules.length); matched++; }} catch (e) {{}}
  }};
  const token = (kind, name) => {{
    const t = kind + name;
    if (seen.has(t)) return;
    seen.add(t);
    if (!sc) sets();
    if (kind === ".") {{
      if (sc.has(name)) add(t);
      const c = cc.get(name); if (c) for (const s of c) add(s);
    }} else {{
      if (si.has(name)) add(t);
      const c = ci.get(name); if (c) for (const s of c) add(s);
    }}
  }};
  const look = (el) => {{
    const id = el.id; if (id) token("#", id);
    const cl = el.classList; if (cl) for (let i = 0; i < cl.length; i++) token(".", cl[i]);
  }};
  const scan = (n) => {{
    if (n.nodeType !== 1) return;
    look(n);
    const all = n.querySelectorAll("[class],[id]");
    for (let i = 0; i < all.length; i++) look(all[i]);
  }};
  new MutationObserver((records) => {{
    adopt();
    for (const r of records) {{
      if (r.type === "attributes") look(r.target);
      else for (const n of r.addedNodes) scan(n);
    }}
    if (DEBUG) self.__untraceCosmetic = {{ setupMs, matched, host, hide: hide.length, started: T0 }};
  }}).observe(document, {{ childList: true, subtree: true, attributes: true, attributeFilter: ["class", "id"] }});
}}
const setupMs = performance.now() - T0;
if (DEBUG) self.__untraceCosmetic = {{ setupMs, matched, host, hide: hide.length, started: T0 }};
}})();"##,
            debug = o.debug,
            observe = o.generic == GenericMode::Observe,
            misc = js(&misc),
            all = js(&all_generic),
            sc = js(&join(&self.simple_classes)),
            si = js(&join(&self.simple_ids)),
            cc = js(&keyed(&self.complex_classes)),
            ci = js(&keyed(&self.complex_ids)),
            hosts = js(&hosts),
            off = js(&lines(&o.off_sites)),
            gh = js(&lines(&generichide)),
            eh = js(&lines(&elemhide)),
        )
    }

    /// The CSS of one site's own rules (minus its exceptions), or `None` if it has none or no
    /// hiding applies there (`$elemhide`).
    pub fn site_css(&self, host: &str) -> Option<String> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let suffixes: Vec<String> = {
            let labels: Vec<&str> = host.split('.').collect();
            (0..labels.len()).map(|i| labels[i..].join(".")).collect()
        };
        if suffixes.iter().any(|s| self.elemhide.contains(s)) {
            return None;
        }
        let rules = self.for_host(&host);
        let unhide: BTreeSet<&String> = rules.unhide.iter().collect();
        let mut seen = BTreeSet::new();
        let css: String = rules
            .hide
            .iter()
            .filter(|s| !unhide.contains(s) && seen.insert(s.as_str()))
            .map(|s| format!("{s}{HIDE} "))
            .collect();
        (!css.is_empty()).then_some(css)
    }
}

/// Marker a document gets once its site's rules are applied (so the fallback never applies
/// them twice). Public list data only.
pub const SITE_MARKER: &str = "untrace.cosmetic.site";

/// The small per-site script: registered for the site a tab is navigating to, and run again
/// when its content starts loading in case the registration came too late for that page. It
/// applies `css` only in documents of `host` itself, once.
pub fn site_script(host: &str, css: &str) -> String {
    format!(
        r##"(() => {{
"use strict";
const HOST = {host};
let h = "";
try {{
  const o = self.origin;
  h = (o && o !== "null" ? new URL(o).hostname : location.hostname) || "";
}} catch (e) {{}}
if (h.toLowerCase().replace(/\.$/, "") !== HOST) return;
const K = Symbol.for({marker});
if (self[K]) return;
try {{
  const s = new CSSStyleSheet();
  s.replaceSync({css});
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, s];
  Object.defineProperty(self, K, {{ value: true }});
}} catch (e) {{}}
}})();"##,
        host = js(&host.trim_end_matches('.').to_ascii_lowercase()),
        marker = js(SITE_MARKER),
        css = js(css),
    )
}

#[cfg(test)]
mod script_tests {
    use super::*;
    use crate::engine::Source;

    #[test]
    fn literals_escape_only_what_javascript_requires() {
        assert_eq!(js("a\"b\\c\nd\u{2028}"), r#""a\"b\\c\nd\u2028""#);
        assert_eq!(js("x\u{1d}y\u{1f}z\tw"), "\"x\u{1d}y\u{1f}z\tw\"");
        assert_eq!(js("\u{1}"), r#""\u0001""#);
    }

    #[test]
    fn the_script_embeds_rules_with_raw_separators() {
        let r = CosmeticRules::build(&[Source {
            id: ListId::EasyList,
            text: "##.ad-banner\nexample.com##.promo\nnews.example#@#.ad-banner\n",
        }]);
        let opts = |embed| ScriptOptions {
            generic: GenericMode::Observe,
            off_sites: vec!["off.example".into()],
            debug: false,
            embed_site_rules: embed,
        };
        let embedded = r.script(&opts(true));
        assert!(embedded.contains("\u{1d}example.com\t.promo\u{1e}"));
        // The script every document gets leaves site rules out but keeps exceptions, which
        // also cancel generic rules there.
        let script = r.script(&opts(false));
        assert!(!script.contains(".promo"));
        assert!(script.contains("\u{1d}news.example\t\u{1e}.ad-banner"));
        assert!(script.contains("\u{1d}off.example\u{1d}"));
        assert!(script.len() < embedded.len());
        // Only the code names the separators (once each); the data carries them raw.
        assert_eq!(script.matches(r"\u001f").count(), 1, "data separators are raw");
        assert_eq!(script.matches(r"\u001d").count(), 1, "data separators are raw");
    }

    #[test]
    fn site_rules_come_per_site_minus_exceptions() {
        let r = CosmeticRules::build(&[Source {
            id: ListId::EasyList,
            text: "example.com##.promo\nexample.com##.box\nshop.example.com#@#.box\nexample.*##.everywhere\n\
                   @@||quiet.example^$elemhide\nquiet.example##.x\n",
        }]);
        assert_eq!(
            r.site_css("www.example.com").as_deref(),
            Some(".box{display:none!important} .promo{display:none!important} .everywhere{display:none!important} ")
        );
        assert_eq!(
            r.site_css("shop.example.com").as_deref(),
            Some(".promo{display:none!important} .everywhere{display:none!important} ")
        );
        assert_eq!(r.site_css("quiet.example"), None, "$elemhide: nothing");
        assert_eq!(r.site_css("nothing.test"), None);
        let s = site_script("www.example.com", ".promo{display:none!important} ");
        assert!(s.contains(r#"const HOST = "www.example.com";"#));
        assert!(s.contains(SITE_MARKER));
    }
}
