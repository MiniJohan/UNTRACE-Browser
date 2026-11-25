//! UNTRACE core logic. Platform-independent and free of `unsafe`.
//!
//! - [`address`]: turns address-field input into a navigation or a search (no network).
//! - [`settings`] / [`store`]: versioned settings, validated on load, written atomically.
//! - [`registry`]: protection definitions and the apply → observe → commit/revert flow.
//! - [`audit`]: size-capped local audit log that never records URLs.
//! - [`bookmarks`]: bookmarks on this computer only, and the standard bookmarks file format.

#![forbid(unsafe_code)]

pub mod address;
pub mod audit;
pub mod bookmarks;
pub mod paths;
pub mod policy;
pub mod registry;
pub mod settings;
pub mod store;
pub mod time;

/// UNTRACE version, from Cargo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
