//! The M5 network layer in the shell (D-006, D-023, D-041): starts the proxy before the engine,
//! routes the encrypted-DNS settings, and gathers what Diagnostics shows.
//!
//! - "Encrypted DNS" (Off / Automatic / Strict) decides whether the engine runs through the
//!   proxy at all, so it takes effect when UNTRACE restarts (Scope::Environment).
//! - The Strict provider can change at once: the running proxy switches resolver.
//! - If the network layer is wanted but cannot start, UNTRACE does not open pages without it
//!   (fail closed); Settings still works so it can be turned off.

use std::sync::Mutex;

use serde::Serialize;
use untrace_core::{
    registry::{Observed, Value},
    settings::CustomDoh,
};
use untrace_net::{
    Proxy, ProxyStats,
    diag::{self, Adapter, WindowsDohPolicy},
    proxy::HostRecord,
    resolver::{self, DohServer, Mode},
};
use untrace_webview::NetworkCheck;

pub const DNS_MODE_ID: &str = "network.encrypted_dns";
pub const DNS_MODES: [&str; 3] = ["off", "automatic", "strict"];
pub const DOH_PROVIDER_ID: &str = "network.doh_provider";
pub const DOH_PROVIDERS: [&str; 4] = ["quad9", "cloudflare", "mullvad", "custom"];

pub struct NetworkService {
    proxy: Option<Proxy>,
    /// What the engine was started with: "off", "automatic" or "strict".
    running: String,
    start_error: Option<String>,
    provider: Mutex<String>,
    custom: Mutex<Option<DohServer>>,
}

fn custom_server(c: Option<&CustomDoh>) -> Option<DohServer> {
    c.and_then(|c| resolver::custom_server(&c.template, &c.address).ok())
}

/// The resolver mode for "Strict" with this provider. A custom provider without a valid
/// server gets no server at all, which fails closed (no lookups) rather than open.
fn strict(provider: &str, custom: Option<&DohServer>) -> Mode {
    match resolver::provider(provider) {
        Some(p) => Mode::Strict {
            name: p.name.into(),
            servers: p.servers(),
        },
        None => Mode::Strict {
            name: "your own server".into(),
            servers: custom.cloned().into_iter().collect(),
        },
    }
}

impl NetworkService {
    /// Start the proxy if the configured mode wants it.
    pub fn start(mode: &str, provider: &str, custom: Option<&CustomDoh>) -> Self {
        let custom = custom_server(custom);
        let resolver_mode = match mode {
            "automatic" => Some(Mode::Automatic),
            "strict" => Some(strict(provider, custom.as_ref())),
            _ => None,
        };
        let (proxy, start_error) = match resolver_mode {
            None => (None, None),
            Some(m) => match Proxy::start(m) {
                Ok(p) => (Some(p), None),
                Err(e) => (None, Some(format!("The network layer could not start ({e})."))),
            },
        };
        Self {
            proxy,
            running: if start_error.is_some() {
                "off".into()
            } else {
                mode.to_string()
            },
            start_error,
            provider: Mutex::new(provider.to_string()),
            custom: Mutex::new(custom),
        }
    }

    pub fn proxy(&self) -> Option<Proxy> {
        self.proxy.clone()
    }

    pub fn running(&self) -> &str {
        &self.running
    }

    pub fn start_error(&self) -> Option<&str> {
        self.start_error.as_deref()
    }

    /// Save a new custom server (already validated) and use it if Strict runs with it.
    pub fn set_custom(&self, server: Option<DohServer>) {
        *self.custom.lock().unwrap() = server;
        self.refresh_strict();
    }

    fn refresh_strict(&self) {
        if self.running == "strict"
            && let Some(p) = &self.proxy
        {
            let provider = self.provider.lock().unwrap().clone();
            p.set_mode(strict(&provider, self.custom.lock().unwrap().as_ref()));
        }
    }

    /// Settings routed here: `Some` if the id is one of the network settings.
    pub fn apply(&self, id: &str, value: &Value) -> Option<Result<(), String>> {
        match (id, value) {
            // Applied when the engine starts (setup reads the same value); a change waits for a
            // restart, which the registry handles (Scope::Environment).
            (DNS_MODE_ID, Value::Choice(_)) => Some(Ok(())),
            (DOH_PROVIDER_ID, Value::Choice(p)) => {
                *self.provider.lock().unwrap() = p.clone();
                self.refresh_strict();
                Some(Ok(()))
            }
            (DNS_MODE_ID | DOH_PROVIDER_ID, _) => Some(Err("unexpected value".into())),
            _ => None,
        }
    }

    pub fn observe(&self, id: &str, check: Option<NetworkCheck>) -> Option<Observed> {
        match id {
            DNS_MODE_ID => Some(if let Some(e) = &self.start_error {
                Observed::Unverifiable(format!("{e} No page is opened without it."))
            } else if self.running == "off" {
                Observed::Verified(Value::Choice("off".into()))
            } else {
                match check {
                    Some(NetworkCheck::Passed { .. }) => Observed::Verified(Value::Choice(self.running.clone())),
                    Some(NetworkCheck::Failed { reason }) => Observed::Unverifiable(reason),
                    Some(NetworkCheck::Pending) => {
                        Observed::Unverifiable("UNTRACE is still checking the network layer.".into())
                    }
                    _ => Observed::Unverifiable("No tab has started yet to check from.".into()),
                }
            }),
            DOH_PROVIDER_ID => Some({
                let provider = self.provider.lock().unwrap().clone();
                match (&self.proxy, self.running.as_str()) {
                    (Some(p), "strict") => {
                        let expected = strict(&provider, self.custom.lock().unwrap().as_ref());
                        match (p.resolver().mode(), expected) {
                            (Mode::Strict { servers, .. }, Mode::Strict { servers: want, .. })
                                if servers == want && !servers.is_empty() =>
                            {
                                Observed::Verified(Value::Choice(provider))
                            }
                            (Mode::Strict { servers, .. }, _) if servers.is_empty() => Observed::Unverifiable(
                                "No server is saved yet; names are not resolved until you add one.".into(),
                            ),
                            _ => Observed::Unverifiable("The network layer uses a different server.".into()),
                        }
                    }
                    _ => Observed::Unverifiable("Used only when Encrypted DNS is set to Strict.".into()),
                }
            }),
            _ => None,
        }
    }

    pub fn custom_server(&self) -> Option<DohServer> {
        self.custom.lock().unwrap().clone()
    }
}

/// Everything Diagnostics shows about DNS and the network layer (read-only).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkReport {
    /// Configured mode (may differ from `running` until a restart).
    pub configured: String,
    pub running: String,
    pub start_error: Option<String>,
    pub check: Option<NetworkCheck>,
    pub proxy: Option<ProxyStats>,
    /// What the resolver does right now, in words.
    pub resolver: String,
    pub adapters: Vec<Adapter>,
    pub windows_policy: WindowsDohPolicy,
    /// Hosts contacted this session through the network layer (memory only).
    pub hosts: Vec<HostRecord>,
}

pub fn report(service: &NetworkService, configured: &str, check: Option<NetworkCheck>) -> NetworkReport {
    let adapters = diag::adapters();
    let resolver = match (&service.proxy, service.running.as_str()) {
        (None, _) => {
            "The engine resolves names itself (Chromium's own DNS client); queries are usually unencrypted.".into()
        }
        (Some(p), _) => match p.resolver().mode() {
            Mode::Strict { name, servers } if servers.is_empty() => {
                format!("Strict, {name}: no server saved, so no name is resolved.")
            }
            Mode::Strict { name, .. } => format!("Strict: every name over HTTPS with {name}; no fallback."),
            Mode::Automatic => {
                let servers = p.resolver().automatic_servers();
                match servers.first() {
                    Some(s) => format!(
                        "Automatic: over HTTPS with your DNS server {} ({}); Windows' resolver if that fails.",
                        s.address, s.template
                    ),
                    None => "Automatic: your DNS server has no known encrypted address, so Windows resolves names \
                             (encrypted only if Windows is set to encrypt them)."
                        .into(),
                }
            }
        },
    };
    NetworkReport {
        configured: configured.to_string(),
        running: service.running.clone(),
        start_error: service.start_error.clone(),
        check,
        proxy: service.proxy.as_ref().map(Proxy::stats),
        resolver,
        adapters,
        windows_policy: diag::windows_policy(),
        hosts: service.proxy.as_ref().map(Proxy::hosts).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified(o: Option<Observed>) -> Option<Value> {
        match o {
            Some(Observed::Verified(v)) => Some(v),
            _ => None,
        }
    }

    /// M5 exit criterion: if the engine's requests do not reach the proxy (bypassed), Encrypted
    /// DNS reads back as not verified, never as on.
    #[test]
    fn encrypted_dns_is_verified_only_by_a_passed_start_up_check() {
        let s = NetworkService::start("automatic", "quad9", None);
        assert!(s.proxy().is_some());
        let obs = |c: Option<NetworkCheck>| s.observe(DNS_MODE_ID, c);
        assert_eq!(
            verified(obs(Some(NetworkCheck::Passed { ms: 5 }))),
            Some(Value::Choice("automatic".into()))
        );
        let bypassed = obs(Some(NetworkCheck::Failed {
            reason: "A test request from the engine did not reach the network layer.".into(),
        }));
        assert!(matches!(bypassed, Some(Observed::Unverifiable(ref r)) if r.contains("did not reach")));
        assert!(matches!(
            obs(Some(NetworkCheck::Pending)),
            Some(Observed::Unverifiable(_))
        ));
        assert!(matches!(obs(None), Some(Observed::Unverifiable(_))));
        // Off is a plain fact: no proxy, nothing to check.
        let off = NetworkService::start("off", "quad9", None);
        assert!(off.proxy().is_none());
        assert_eq!(
            verified(off.observe(DNS_MODE_ID, Some(NetworkCheck::Off))),
            Some(Value::Choice("off".into()))
        );
    }

    #[test]
    fn strict_provider_reads_back_from_the_running_resolver() {
        let s = NetworkService::start("strict", "quad9", None);
        assert_eq!(
            verified(s.observe(DOH_PROVIDER_ID, None)),
            Some(Value::Choice("quad9".into()))
        );
        // Switching provider applies at once and reads back.
        assert!(matches!(
            s.apply(DOH_PROVIDER_ID, &Value::Choice("mullvad".into())),
            Some(Ok(()))
        ));
        assert_eq!(
            verified(s.observe(DOH_PROVIDER_ID, None)),
            Some(Value::Choice("mullvad".into()))
        );
        // "Custom" without a saved server: no server at all (fails closed), reported as such.
        s.apply(DOH_PROVIDER_ID, &Value::Choice("custom".into()));
        assert!(matches!(
            s.proxy().unwrap().resolver().mode(),
            Mode::Strict { ref servers, .. } if servers.is_empty()
        ));
        assert!(
            matches!(s.observe(DOH_PROVIDER_ID, None), Some(Observed::Unverifiable(ref r)) if r.contains("No server"))
        );
        // In Automatic the provider is not in use, so it is not claimed as verified.
        let a = NetworkService::start("automatic", "quad9", None);
        assert!(matches!(
            a.observe(DOH_PROVIDER_ID, None),
            Some(Observed::Unverifiable(_))
        ));
    }
}
