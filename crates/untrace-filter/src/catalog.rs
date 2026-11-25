//! The block lists UNTRACE offers (D-032). Snapshots are bundled for an offline first run.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListId {
    EasyList,
    EasyPrivacy,
    Malware,
    Phishing,
}

impl ListId {
    pub const ALL: [ListId; 4] = [ListId::EasyList, ListId::EasyPrivacy, ListId::Malware, ListId::Phishing];

    /// File-name stem for stored copies.
    pub fn stem(self) -> &'static str {
        match self {
            ListId::EasyList => "easylist",
            ListId::EasyPrivacy => "easyprivacy",
            ListId::Malware => "malware",
            ListId::Phishing => "phishing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// Adblock Plus syntax (network rules are used; cosmetic rules arrive with M6).
    Adblock,
    /// One host or IP address per line; `#` comments.
    Hosts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Requests are blocked silently and counted.
    Content,
    /// Pages are replaced by UNTRACE's warning panel (D-033).
    Threat,
}

#[derive(Debug)]
pub struct ListInfo {
    pub id: ListId,
    /// Protection id in Settings.
    pub protection: &'static str,
    pub title: &'static str,
    pub kind: Kind,
    pub format: Format,
    /// HTTPS download address.
    pub url: &'static str,
    pub homepage: &'static str,
    pub licence: &'static str,
    /// The list's own `Title:` header; a download with another title is not this list.
    pub expected_title: &'static str,
    /// Snapshot shipped with UNTRACE.
    pub bundled: &'static str,
    /// A download with fewer rules than this is rejected.
    pub min_rules: usize,
    /// A download may not shrink below previous ÷ this (catches truncated or emptied lists).
    pub max_shrink: usize,
    /// Update interval when the list states none, in hours.
    pub default_expires_hours: u32,
}

pub const BLOCK_ADS_ID: &str = "filter.block_ads";
pub const BLOCK_TRACKERS_ID: &str = "filter.block_trackers";
pub const WARN_MALWARE_ID: &str = "filter.warn_malware";
pub const WARN_PHISHING_ID: &str = "filter.warn_phishing";

static CATALOG: [ListInfo; 4] = [
    ListInfo {
        id: ListId::EasyList,
        protection: BLOCK_ADS_ID,
        title: "EasyList",
        kind: Kind::Content,
        format: Format::Adblock,
        url: "https://easylist.to/easylist/easylist.txt",
        homepage: "https://easylist.to/",
        licence: "CC BY-SA 3.0 (dual-licensed with GPLv3)",
        expected_title: "EasyList",
        bundled: include_str!("../lists/easylist.txt"),
        min_rules: 20_000,
        max_shrink: 2,
        default_expires_hours: 96,
    },
    ListInfo {
        id: ListId::EasyPrivacy,
        protection: BLOCK_TRACKERS_ID,
        title: "EasyPrivacy",
        kind: Kind::Content,
        format: Format::Adblock,
        url: "https://easylist.to/easylist/easyprivacy.txt",
        homepage: "https://easylist.to/",
        licence: "CC BY-SA 3.0 (dual-licensed with GPLv3)",
        expected_title: "EasyPrivacy",
        bundled: include_str!("../lists/easyprivacy.txt"),
        min_rules: 15_000,
        max_shrink: 2,
        default_expires_hours: 96,
    },
    ListInfo {
        id: ListId::Malware,
        protection: WARN_MALWARE_ID,
        title: "URLhaus malware domains",
        kind: Kind::Threat,
        format: Format::Hosts,
        url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt",
        homepage: "https://gitlab.com/malware-filter/urlhaus-filter",
        licence: "CC0 1.0 and MIT (data from abuse.ch URLhaus, CC0)",
        expected_title: "Online Malicious Domains Blocklist",
        bundled: include_str!("../lists/urlhaus-domains.txt"),
        // The "online" list follows live threats and can legitimately shrink a lot overnight.
        min_rules: 100,
        max_shrink: 10,
        default_expires_hours: 12,
    },
    ListInfo {
        id: ListId::Phishing,
        protection: WARN_PHISHING_ID,
        title: "Phishing domains",
        kind: Kind::Threat,
        format: Format::Hosts,
        url: "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt",
        homepage: "https://gitlab.com/malware-filter/phishing-filter",
        licence: "CC BY-SA 4.0 (sources: OpenPhish, PhishTank, IPThreat)",
        expected_title: "Phishing Domains Blocklist",
        bundled: include_str!("../lists/phishing-domains.txt"),
        min_rules: 1_000,
        max_shrink: 4,
        default_expires_hours: 12,
    },
];

pub fn catalog() -> &'static [ListInfo] {
    &CATALOG
}

pub fn info(id: ListId) -> &'static ListInfo {
    CATALOG
        .iter()
        .find(|l| l.id == id)
        .expect("every ListId is in the catalog")
}

pub fn by_protection(protection: &str) -> Option<&'static ListInfo> {
    CATALOG.iter().find(|l| l.protection == protection)
}
