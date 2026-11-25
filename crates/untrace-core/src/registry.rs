//! Protection registry: the single source of truth for user-facing protections.
//!
//! Every change follows the same flow: validate → apply → observe (read back from the engine)
//! → commit to disk, or revert to the previous value. Every outcome is audited. A protection
//! whose state cannot be read back is reported as *unverified*, never as plainly "on".

use serde::{Deserialize, Serialize};

use crate::{
    audit::{AuditEvent, AuditLog},
    store::SettingsStore,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Bool(bool),
    Choice(String),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Bool(true) => write!(f, "on"),
            Value::Bool(false) => write!(f, "off"),
            Value::Choice(c) => write!(f, "{c}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// UNTRACE itself.
    App,
    /// The content WebView2 environment; takes effect after restart.
    Environment,
    /// A WebView2 profile.
    Profile,
    /// Every open content view; takes effect immediately.
    View,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Kind {
    Toggle {
        default: bool,
    },
    Choice {
        options: &'static [&'static str],
        default: &'static str,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtectionDef {
    pub id: &'static str,
    pub group: &'static str,
    pub title: &'static str,
    pub explanation: &'static str,
    pub limitations: &'static str,
    pub scope: Scope,
    pub kind: Kind,
}

impl ProtectionDef {
    pub fn default_value(&self) -> Value {
        match self.kind {
            Kind::Toggle { default } => Value::Bool(default),
            Kind::Choice { default, .. } => Value::Choice(default.to_string()),
        }
    }

    pub fn accepts(&self, v: &Value) -> bool {
        match (&self.kind, v) {
            (Kind::Toggle { .. }, Value::Bool(_)) => true,
            (Kind::Choice { options, .. }, Value::Choice(c)) => options.contains(&c.as_str()),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum Observed {
    /// The engine reports this value.
    Verified(Value),
    /// The state cannot be read back right now; the reason is shown to the user.
    Unverifiable(String),
}

/// Implemented by whatever actually enforces protections (the content view manager).
pub trait Applier {
    fn apply(&mut self, id: &str, value: &Value) -> Result<(), String>;
    fn observe(&self, id: &str) -> Observed;
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ChangeOutcome {
    Verified,
    Unverified { reason: String },
    PendingRestart,
    Reverted { reason: String },
    Rejected { reason: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtectionStatus {
    #[serde(flatten)]
    pub def: ProtectionDef,
    pub configured: Value,
    pub observed: Observed,
}

pub struct Registry {
    defs: Vec<ProtectionDef>,
}

impl Registry {
    pub fn new(defs: Vec<ProtectionDef>) -> Self {
        Self { defs }
    }

    pub fn defs(&self) -> &[ProtectionDef] {
        &self.defs
    }

    pub fn get(&self, id: &str) -> Option<&ProtectionDef> {
        self.defs.iter().find(|d| d.id == id)
    }

    pub fn configured(&self, store: &SettingsStore, def: &ProtectionDef) -> Value {
        store
            .settings()
            .protections
            .get(def.id)
            .cloned()
            .unwrap_or_else(|| def.default_value())
    }

    /// Apply every configured value (startup). Failures are audited and returned.
    pub fn apply_all(
        &self,
        store: &SettingsStore,
        audit: &AuditLog,
        applier: &mut dyn Applier,
    ) -> Vec<(String, String)> {
        let mut failures = vec![];
        for def in &self.defs {
            let v = self.configured(store, def);
            if let Err(e) = applier.apply(def.id, &v) {
                let _ = audit.record(AuditEvent::Error {
                    component: "registry".into(),
                    message: format!("{}: {e}", def.id),
                });
                failures.push((def.id.to_string(), e));
            }
        }
        failures
    }

    pub fn status(&self, store: &SettingsStore, applier: &dyn Applier) -> Vec<ProtectionStatus> {
        self.defs
            .iter()
            .map(|d| ProtectionStatus {
                def: d.clone(),
                configured: self.configured(store, d),
                observed: applier.observe(d.id),
            })
            .collect()
    }

    /// Change one protection: validate → apply → observe → commit, or revert.
    pub fn change(
        &self,
        id: &str,
        value: Value,
        store: &mut SettingsStore,
        audit: &AuditLog,
        applier: &mut dyn Applier,
    ) -> ChangeOutcome {
        let Some(def) = self.get(id) else {
            return ChangeOutcome::Rejected {
                reason: format!("unknown protection \"{id}\""),
            };
        };
        if !def.accepts(&value) {
            return ChangeOutcome::Rejected {
                reason: "value not allowed for this protection".into(),
            };
        }
        let previous = self.configured(store, def);
        let persist = |store: &mut SettingsStore| {
            store.update(|s| {
                s.protections.insert(def.id.to_string(), value.clone());
            })
        };

        if def.scope == Scope::Environment {
            if let Err(e) = persist(store) {
                return self.reverted(audit, def, &value, format!("could not save settings: {e}"));
            }
            let _ = audit.record(AuditEvent::SettingChanged {
                id: def.id.into(),
                from: previous.to_string(),
                to: value.to_string(),
                verified: false,
            });
            return ChangeOutcome::PendingRestart;
        }

        if let Err(e) = applier.apply(def.id, &value) {
            let _ = applier.apply(def.id, &previous);
            return self.reverted(audit, def, &value, format!("could not apply: {e}"));
        }
        let observed = applier.observe(def.id);
        let outcome = match &observed {
            Observed::Verified(v) if *v == value => ChangeOutcome::Verified,
            Observed::Verified(v) => {
                let _ = applier.apply(def.id, &previous);
                return self.reverted(audit, def, &value, format!("engine reports \"{v}\" after the change"));
            }
            Observed::Unverifiable(reason) => ChangeOutcome::Unverified { reason: reason.clone() },
        };
        if let Err(e) = persist(store) {
            let _ = applier.apply(def.id, &previous);
            return self.reverted(audit, def, &value, format!("could not save settings: {e}"));
        }
        let _ = audit.record(AuditEvent::SettingChanged {
            id: def.id.into(),
            from: previous.to_string(),
            to: value.to_string(),
            verified: outcome == ChangeOutcome::Verified,
        });
        outcome
    }

    fn reverted(&self, audit: &AuditLog, def: &ProtectionDef, attempted: &Value, reason: String) -> ChangeOutcome {
        let _ = audit.record(AuditEvent::SettingReverted {
            id: def.id.into(),
            attempted: attempted.to_string(),
            reason: reason.clone(),
        });
        ChangeOutcome::Reverted { reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::temp_dir;
    use std::collections::HashMap;

    const VIEW_TOGGLE: ProtectionDef = ProtectionDef {
        id: "test.view",
        group: "Test",
        title: "View toggle",
        explanation: "",
        limitations: "",
        scope: Scope::View,
        kind: Kind::Toggle { default: false },
    };
    const ENV_CHOICE: ProtectionDef = ProtectionDef {
        id: "test.env",
        group: "Test",
        title: "Env choice",
        explanation: "",
        limitations: "",
        scope: Scope::Environment,
        kind: Kind::Choice {
            options: &["a", "b"],
            default: "a",
        },
    };

    #[derive(Default)]
    struct Fake {
        engine: HashMap<String, Value>,
        fail_apply: bool,
        lie: Option<Value>,
        unverifiable: bool,
        calls: Vec<(String, Value)>,
    }

    impl Applier for Fake {
        fn apply(&mut self, id: &str, v: &Value) -> Result<(), String> {
            self.calls.push((id.into(), v.clone()));
            if self.fail_apply && *v == Value::Bool(true) {
                return Err("boom".into());
            }
            self.engine.insert(id.into(), v.clone());
            Ok(())
        }
        fn observe(&self, id: &str) -> Observed {
            if self.unverifiable {
                return Observed::Unverifiable("no open tabs".into());
            }
            if let Some(l) = &self.lie {
                return Observed::Verified(l.clone());
            }
            self.engine
                .get(id)
                .cloned()
                .map(Observed::Verified)
                .unwrap_or(Observed::Unverifiable("unknown".into()))
        }
    }

    fn setup() -> (Registry, SettingsStore, AuditLog) {
        let dir = temp_dir("registry");
        let reg = Registry::new(vec![VIEW_TOGGLE, ENV_CHOICE]);
        let (store, _) = SettingsStore::open(&dir, reg.defs()).unwrap();
        let audit = AuditLog::open(&dir).unwrap();
        (reg, store, audit)
    }

    #[test]
    fn verified_change_is_committed_and_audited() {
        let (reg, mut store, audit) = setup();
        let mut f = Fake::default();
        assert_eq!(
            reg.change("test.view", Value::Bool(true), &mut store, &audit, &mut f),
            ChangeOutcome::Verified
        );
        assert_eq!(store.settings().protections["test.view"], Value::Bool(true));
        assert!(
            audit
                .tail(5)
                .iter()
                .any(|l| l.contains("setting_changed") && l.contains("\"verified\":true"))
        );
    }

    #[test]
    fn mismatched_read_back_reverts() {
        let (reg, mut store, audit) = setup();
        let mut f = Fake {
            lie: Some(Value::Bool(false)),
            ..Default::default()
        };
        let out = reg.change("test.view", Value::Bool(true), &mut store, &audit, &mut f);
        assert!(matches!(out, ChangeOutcome::Reverted { .. }));
        assert!(!store.settings().protections.contains_key("test.view"));
        assert_eq!(
            f.calls.last().unwrap().1,
            Value::Bool(false),
            "previous value re-applied"
        );
    }

    #[test]
    fn apply_failure_reverts() {
        let (reg, mut store, audit) = setup();
        let mut f = Fake {
            fail_apply: true,
            ..Default::default()
        };
        assert!(matches!(
            reg.change("test.view", Value::Bool(true), &mut store, &audit, &mut f),
            ChangeOutcome::Reverted { .. }
        ));
        assert!(audit.tail(5).iter().any(|l| l.contains("setting_reverted")));
    }

    #[test]
    fn unverifiable_is_saved_but_reported() {
        let (reg, mut store, audit) = setup();
        let mut f = Fake {
            unverifiable: true,
            ..Default::default()
        };
        let out = reg.change("test.view", Value::Bool(true), &mut store, &audit, &mut f);
        assert_eq!(
            out,
            ChangeOutcome::Unverified {
                reason: "no open tabs".into()
            }
        );
        assert_eq!(store.settings().protections["test.view"], Value::Bool(true));
    }

    #[test]
    fn environment_scope_waits_for_restart() {
        let (reg, mut store, audit) = setup();
        let mut f = Fake::default();
        assert_eq!(
            reg.change("test.env", Value::Choice("b".into()), &mut store, &audit, &mut f),
            ChangeOutcome::PendingRestart
        );
        assert!(f.calls.is_empty(), "environment settings are not applied live");
        assert_eq!(store.settings().protections["test.env"], Value::Choice("b".into()));
    }

    #[test]
    fn invalid_requests_are_rejected() {
        let (reg, mut store, audit) = setup();
        let mut f = Fake::default();
        assert!(matches!(
            reg.change("nope", Value::Bool(true), &mut store, &audit, &mut f),
            ChangeOutcome::Rejected { .. }
        ));
        assert!(matches!(
            reg.change("test.view", Value::Choice("x".into()), &mut store, &audit, &mut f),
            ChangeOutcome::Rejected { .. }
        ));
        assert!(matches!(
            reg.change("test.env", Value::Choice("c".into()), &mut store, &audit, &mut f),
            ChangeOutcome::Rejected { .. }
        ));
    }
}
