//! Settings schema (version 1).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    address::{SearchEngine, validate_template},
    registry::{ProtectionDef, Value},
};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Theme {
    #[default]
    System,
    Dark,
    /// True-black surfaces (D-053).
    Black,
    Light,
}

/// The accent colour of UNTRACE's own interface (D-053). Grey keeps the neutral look; the
/// others colour the active tab, switches, the focus outline, progress and primary buttons.
/// Presets only, each with a shade for dark and black backgrounds and one for light ones,
/// checked for contrast by a unit test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Accent {
    #[default]
    Grey,
    Blue,
    Teal,
    Green,
    Amber,
    Rose,
    Violet,
}

/// An accent's colours (`#rrggbb`): the colour and the text drawn on it, for dark and black
/// themes and for the light theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccentColors {
    pub dark: &'static str,
    pub dark_on: &'static str,
    pub light: &'static str,
    pub light_on: &'static str,
}

impl Accent {
    pub const ALL: [Accent; 7] = [
        Accent::Grey,
        Accent::Blue,
        Accent::Teal,
        Accent::Green,
        Accent::Amber,
        Accent::Rose,
        Accent::Violet,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Accent::Grey => "Grey",
            Accent::Blue => "Blue",
            Accent::Teal => "Teal",
            Accent::Green => "Green",
            Accent::Amber => "Amber",
            Accent::Rose => "Rose",
            Accent::Violet => "Violet",
        }
    }

    /// `None` for Grey: the interface keeps its neutral colours.
    pub fn colors(self) -> Option<AccentColors> {
        let c = |dark, dark_on, light, light_on| {
            Some(AccentColors {
                dark,
                dark_on,
                light,
                light_on,
            })
        };
        match self {
            Accent::Grey => None,
            Accent::Blue => c("#6ea8fe", "#07111f", "#1a5fd6", "#ffffff"),
            Accent::Teal => c("#3cc8bf", "#03201d", "#0b7a73", "#ffffff"),
            Accent::Green => c("#5ccf7e", "#05200e", "#1b7a3b", "#ffffff"),
            Accent::Amber => c("#f0b44a", "#231602", "#8f5500", "#ffffff"),
            Accent::Rose => c("#f47fa4", "#2a0914", "#bf2b5b", "#ffffff"),
            Accent::Violet => c("#a99cff", "#130d33", "#6346d5", "#ffffff"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Search {
    pub engine: SearchEngine,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_template: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub schema: u32,
    pub theme: Theme,
    pub search: Search,
    /// Only values that differ from, or were explicitly set to, a protection's default.
    #[serde(default)]
    pub protections: BTreeMap<String, Value>,
    /// Sites (registrable domains, e.g. `example.co.uk`) where the user turned ads/trackers
    /// blocking off. Malware/phishing warnings still apply there (D-033).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filter_exceptions: Vec<String>,
    /// Sites (registrable domains) the user allowed to reach this computer and the local
    /// network (D-040).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_network_sites: Vec<String>,
    /// The user's own DNS-over-HTTPS server for "Strict" encrypted DNS (D-041).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_doh: Option<CustomDoh>,
    /// D-053: the interface's accent colour.
    #[serde(default)]
    pub accent: Accent,
    /// D-053: tell websites UNTRACE's light/dark choice (otherwise they follow Windows).
    #[serde(default = "yes")]
    pub pages_follow_theme: bool,
    /// M9: the one-screen welcome has been shown and closed.
    #[serde(default)]
    pub welcome_seen: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomDoh {
    /// `https://host/path` of the server's DNS-over-HTTPS endpoint.
    pub template: String,
    /// IP address Windows connects to (the host name is not looked up).
    pub address: String,
}

impl CustomDoh {
    /// Shape check only; `untrace-net` checks it again before use.
    pub fn is_valid(&self) -> bool {
        let t = &self.template;
        t.len() <= 512
            && t.strip_prefix("https://")
                .and_then(|r| r.split_once('/'))
                .is_some_and(|(h, p)| !h.is_empty() && !p.is_empty())
            && !t.chars().any(|c| c.is_whitespace() || c.is_control())
            && self.address.parse::<std::net::IpAddr>().is_ok()
    }
}

/// Most sites a user can exclude from blocking (keeps the settings file small).
pub const MAX_FILTER_EXCEPTIONS: usize = 1000;

/// A site name as stored in `filter_exceptions`: lower-case DNS labels, at least one dot.
pub fn is_site_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            theme: Theme::System,
            // D-018 (product owner, 2026-11-25): DuckDuckGo; suggestions stay off.
            search: Search {
                engine: SearchEngine::DuckDuckGo,
                custom_template: None,
            },
            protections: BTreeMap::new(),
            filter_exceptions: Vec::new(),
            local_network_sites: Vec::new(),
            custom_doh: None,
            accent: Accent::Grey,
            pages_follow_theme: true,
            welcome_seen: false,
        }
    }
}

impl Settings {
    /// Check a loaded file against the schema and the known protections.
    /// `Err` = unusable (reset); `Ok(repairs)` = usable, with the listed fixes applied.
    pub fn validate(&mut self, defs: &[ProtectionDef]) -> Result<Vec<String>, String> {
        if self.schema != SCHEMA_VERSION {
            return Err(format!("unsupported settings schema {}", self.schema));
        }
        let mut repairs = vec![];
        if self.search.engine == SearchEngine::Custom {
            let ok = self
                .search
                .custom_template
                .as_deref()
                .map(|t| validate_template(t).is_ok())
                .unwrap_or(false);
            if !ok {
                self.search = Settings::default().search;
                repairs.push("custom search address was invalid; reset to the default engine".into());
            }
        } else if self.search.custom_template.is_some() {
            self.search.custom_template = None;
        }
        let ids: Vec<String> = self.protections.keys().cloned().collect();
        for id in ids {
            match defs.iter().find(|d| d.id == id) {
                None => {
                    self.protections.remove(&id);
                    repairs.push(format!("removed unknown setting \"{id}\""));
                }
                Some(def) if !def.accepts(&self.protections[&id]) => {
                    self.protections.insert(id.clone(), def.default_value());
                    repairs.push(format!("invalid value for \"{id}\"; restored the default"));
                }
                Some(_) => {}
            }
        }
        let before = self.filter_exceptions.len();
        let mut seen = std::collections::BTreeSet::new();
        self.filter_exceptions
            .retain(|s| is_site_name(s) && seen.insert(s.clone()));
        self.filter_exceptions.truncate(MAX_FILTER_EXCEPTIONS);
        if self.filter_exceptions.len() != before {
            repairs.push(format!(
                "removed {} invalid or duplicate site exceptions",
                before - self.filter_exceptions.len()
            ));
        }
        let before = self.local_network_sites.len();
        let mut seen = std::collections::BTreeSet::new();
        self.local_network_sites
            .retain(|s| is_site_name(s) && seen.insert(s.clone()));
        self.local_network_sites.truncate(MAX_FILTER_EXCEPTIONS);
        if self.local_network_sites.len() != before {
            repairs.push(format!(
                "removed {} invalid or duplicate local-network sites",
                before - self.local_network_sites.len()
            ));
        }
        if self.custom_doh.as_ref().is_some_and(|c| !c.is_valid()) {
            self.custom_doh = None;
            repairs.push("custom encrypted-DNS server was invalid; removed".into());
        }
        Ok(repairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn luminance(hex: &str) -> f64 {
        let v = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap();
        let ch = |shift: u32| {
            let c = ((v >> shift) & 0xff) as f64 / 255.0;
            if c <= 0.03928 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * ch(16) + 0.7152 * ch(8) + 0.0722 * ch(0)
    }

    fn contrast(a: &str, b: &str) -> f64 {
        let (x, y) = (luminance(a), luminance(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    /// The backgrounds an accent sits on, as defined in the UI's tokens.css (dark, black and
    /// light themes). The test also checks they are still there, so the two cannot drift apart.
    const DARK_BACKGROUNDS: [&str; 8] = [
        "#0e0e0f", "#141415", "#1a1a1c", "#232326", "#000000", "#060607", "#0d0d0e", "#161618",
    ];
    const LIGHT_BACKGROUNDS: [&str; 3] = ["#ffffff", "#f4f4f5", "#e9e9ec"];

    #[test]
    fn accent_presets_are_readable_on_every_theme() {
        let tokens = include_str!("../../../app/ui/src/styles/tokens.css");
        for bg in DARK_BACKGROUNDS.iter().chain(&LIGHT_BACKGROUNDS) {
            assert!(tokens.contains(bg), "tokens.css no longer uses {bg}; update this test");
        }
        assert_eq!(Accent::Grey.colors(), None);
        for a in Accent::ALL.into_iter().filter(|a| *a != Accent::Grey) {
            let c = a.colors().unwrap();
            // WCAG 2.2: 3:1 for interface components against what is next to them, 4.5:1 for
            // text drawn on the accent.
            for bg in DARK_BACKGROUNDS {
                assert!(
                    contrast(c.dark, bg) >= 3.0,
                    "{a:?} dark on {bg}: {:.2}",
                    contrast(c.dark, bg)
                );
            }
            for bg in LIGHT_BACKGROUNDS {
                assert!(
                    contrast(c.light, bg) >= 3.0,
                    "{a:?} light on {bg}: {:.2}",
                    contrast(c.light, bg)
                );
            }
            assert!(contrast(c.dark, c.dark_on) >= 4.5, "{a:?} text on dark accent");
            assert!(contrast(c.light, c.light_on) >= 4.5, "{a:?} text on light accent");
        }
    }

    #[test]
    fn settings_from_before_d053_load_with_the_new_defaults() {
        let old = r#"{"schema":1,"theme":"dark","search":{"engine":"duck-duck-go"},"protections":{}}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert_eq!(
            (s.theme, s.accent, s.pages_follow_theme),
            (Theme::Dark, Accent::Grey, true)
        );
        let new: Settings = serde_json::from_str(
            r#"{"schema":1,"theme":"black","search":{"engine":"duck-duck-go"},"accent":"teal","pages_follow_theme":false}"#,
        )
        .unwrap();
        assert_eq!(
            (new.theme, new.accent, new.pages_follow_theme),
            (Theme::Black, Accent::Teal, false)
        );
        assert!(
            serde_json::from_str::<Settings>(
                r#"{"schema":1,"theme":"system","search":{"engine":"duck-duck-go"},"accent":"plaid"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn site_names_are_strict() {
        assert!(is_site_name("example.com"));
        assert!(is_site_name("example.co.uk"));
        assert!(is_site_name("xn--bcher-kva.example"));
        assert!(!is_site_name("Example.com"));
        assert!(!is_site_name("localhost"));
        assert!(!is_site_name("exa mple.com"));
        assert!(!is_site_name("https://example.com"));
        assert!(!is_site_name("-bad.example"));
    }

    #[test]
    fn invalid_and_duplicate_exceptions_are_repaired() {
        let mut s = Settings {
            filter_exceptions: vec![
                "example.com".into(),
                "example.com".into(),
                "not a site".into(),
                "news.example.org".into(),
            ],
            ..Settings::default()
        };
        let repairs = s.validate(&[]).unwrap();
        assert_eq!(s.filter_exceptions, ["example.com", "news.example.org"]);
        assert_eq!(repairs.len(), 1);
    }

    #[test]
    fn files_without_exceptions_still_load() {
        let json = r#"{"schema":1,"theme":"system","search":{"engine":"duck-duck-go"},"protections":{}}"#;
        let s: Settings = serde_json::from_str(json).unwrap();
        assert!(s.filter_exceptions.is_empty());
        // And an empty list is not written back.
        assert!(!serde_json::to_string(&s).unwrap().contains("filter_exceptions"));
    }
}
