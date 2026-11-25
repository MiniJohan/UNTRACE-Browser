//! UNTRACE network layer (Milestone 5; D-006, D-023, D-024, D-025, D-026, D-040, D-041, D-042).
//!
//! - [`proxy`]: the loopback proxy the content engine sends all of its traffic through.
//! - [`resolver`]: name resolution through the Windows DNS client, over HTTPS where possible.
//! - [`addr`]: which addresses and names belong to this computer or the local network.
//! - [`diag`]: read-only DNS facts about this computer.
//! - [`http`]: the proxy's strict request-head parser.
//!
//! No TLS interception, ever (D-007). Nothing here changes Windows settings.

pub mod addr;
pub mod diag;
pub mod http;
pub mod proxy;
mod rand;
pub mod resolver;

pub use addr::Space;
pub use proxy::{HostRecord, Proxy, ProxyStats};
pub use resolver::{Mode, PROVIDERS, Resolver, ResolverStats, Via};
