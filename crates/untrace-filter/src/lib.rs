//! UNTRACE network filtering (Milestone 3, D-004, D-005, D-032).
//!
//! - [`catalog`]: the block lists UNTRACE offers, with their bundled snapshots.
//! - [`lists`]: header parsing and validation of downloaded list text.
//! - [`engine`]: matching. Ads and trackers in one adblock-rust engine; malware and phishing
//!   as host sets, so UNTRACE can say which list matched.
//! - [`store`]: downloaded copies, the last good copy, per-list status and the engine cache.
//! - [`params`]: tracking-parameter cleanup (M4, D-027).
//! - [`cosmetic`]: element-hiding rules and the document-start script that applies them (M6, D-015).
//!
//! This crate never touches the network: the application downloads, this crate validates.
#![forbid(unsafe_code)]

pub mod catalog;
pub mod cosmetic;
pub mod engine;
pub mod lists;
pub mod params;
pub mod store;

pub use catalog::{Format, Kind, ListId, ListInfo, catalog, info};
pub use engine::{Filters, ResourceKind, Verdict, registrable_domain};
