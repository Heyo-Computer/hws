//! Which namespace each deployment lives in, and which namespaces have the obs
//! plugin installed.
//!
//! app-obs is one collector per region, shared by every tenant. What a tenant
//! sees is decided in app-lb — the obs plugin is installed per namespace there,
//! and app-lb is the only door a namespace-confined caller has onto this
//! service — but two things have to happen here for that to mean anything:
//!
//! - **Attribution.** Every stored row carries the namespace its deployment
//!   belonged to when it was written, so a namespace view filters on a column
//!   rather than on whatever the deployment list says today. A deployment id
//!   that is deleted and re-registered in another namespace must not hand its
//!   old history to the new owner.
//! - **The install gate.** A namespace that has not installed the plugin is not
//!   collected at all: its logs and metrics are dropped before they are
//!   written, rather than stored and hidden.
//!
//! Both come from the app-lb poller ([`crate::sources::applb`]) — `/metrics`
//! names each deployment's namespace, `/api/plugins/obs/installs` names the
//! installs — and both are applied in one place, [`crate::ingest::Sink`], so no
//! source (poll, daemon tail, HTTP push, syslog) can write past them.
//!
//! # When the gate is open
//!
//! Collection is fleet-wide, exactly as before namespaces existed, whenever the
//! install set does not apply:
//!
//! - `APP_OBS_REQUIRE_INSTALL=0`;
//! - app-lb predates the installs endpoint (it answered 404); or
//! - the operator has not switched the fleet obs plugin on. Installs are made
//!   *under* the fleet plugin, so with it off there is nothing to honour, and
//!   turning this collector into a no-op until somebody notices would be a
//!   worse default than collecting what it always has.
//!
//! Until the first answer arrives the gate is *unknown*, and tenant
//! deployments are not collected: failing closed for a few seconds at startup
//! costs a few seconds of data, failing open writes a namespace that never
//! asked for collection.
//!
//! Rows nobody's namespace owns — the platform partitions (`_host`, `_lb`,
//! `_unmanaged`, `syslog`) and deployments app-lb has not reported yet — are
//! always collected and stamped [`UNATTRIBUTED`], which no namespace route can
//! name.

use crate::store::schema::UNATTRIBUTED;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// Whether the install set applies, as last learned from app-lb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// Collect every namespace: the gate is configured off, app-lb is too old
    /// to have one, or the fleet plugin is disabled.
    Open,
    /// No answer from app-lb yet. Tenant deployments wait.
    Unknown,
    /// Collect only these namespaces.
    Installed(HashSet<String>),
}

#[derive(Debug)]
struct State {
    /// Deployment id → namespace, replaced wholesale on every successful poll.
    namespaces: HashMap<String, String>,
    gate: Gate,
}

/// Shared between the poller (which writes it) and the sink, the API and the
/// tailers (which read it).
#[derive(Debug)]
pub struct Directory {
    state: RwLock<State>,
    /// `APP_OBS_REQUIRE_INSTALL`. Off pins the gate open for the life of the
    /// process, whatever app-lb says.
    require_install: bool,
}

impl Directory {
    pub fn new(require_install: bool) -> Self {
        Self {
            state: RwLock::new(State {
                namespaces: HashMap::new(),
                gate: if require_install {
                    Gate::Unknown
                } else {
                    Gate::Open
                },
            }),
            require_install,
        }
    }

    /// Replace the deployment → namespace map from a fresh `/metrics`.
    pub fn set_namespaces(&self, namespaces: HashMap<String, String>) {
        self.state.write().unwrap().namespaces = namespaces;
    }

    /// Whether app-lb's installs need asking about at all.
    pub fn requires_install(&self) -> bool {
        self.require_install
    }

    /// Record what app-lb said about installs. Ignored when the gate was
    /// configured off.
    pub fn set_gate(&self, gate: Gate) {
        if self.require_install {
            self.state.write().unwrap().gate = gate;
        }
    }

    pub fn gate(&self) -> Gate {
        self.state.read().unwrap().gate.clone()
    }

    /// The namespace app-lb last reported for a deployment.
    pub fn namespace_of(&self, deployment: &str) -> Option<String> {
        self.state
            .read()
            .unwrap()
            .namespaces
            .get(deployment)
            .cloned()
    }

    /// Every deployment app-lb last reported in `namespace`, sorted.
    pub fn deployments_in(&self, namespace: &str) -> Vec<String> {
        let state = self.state.read().unwrap();
        let mut out: Vec<String> = state
            .namespaces
            .iter()
            .filter(|(_, ns)| ns.as_str() == namespace)
            .map(|(id, _)| id.clone())
            .collect();
        out.sort();
        out
    }

    /// The namespace to stamp on a row for `deployment`, or `None` to drop it.
    pub fn admit(&self, deployment: &str) -> Option<String> {
        let state = self.state.read().unwrap();
        let Some(ns) = state.namespaces.get(deployment) else {
            // Platform partitions, and anything app-lb has not reported (a
            // deployment registered since the last poll, a host service pushing
            // under its own name). Kept, but owned by no namespace.
            return Some(UNATTRIBUTED.to_string());
        };
        let collected = match &state.gate {
            Gate::Open => true,
            Gate::Unknown => false,
            Gate::Installed(set) => set.contains(ns),
        };
        collected.then(|| ns.clone())
    }
}

/// A namespace name a route may be asked for. app-lb's own rule is lowercase
/// letters, digits and `-`; the underscore that [`UNATTRIBUTED`] and the
/// platform partitions start with is therefore never one.
pub fn is_valid_namespace(ns: &str) -> bool {
    !ns.is_empty()
        && ns.len() <= 63
        && ns
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Deployment ids that are the platform's, not a tenant's, unless app-lb itself
/// reports one in a namespace.
pub fn is_platform_id(id: &str) -> bool {
    id.starts_with('_') || id == "syslog"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(require: bool) -> Directory {
        let d = Directory::new(require);
        d.set_namespaces(HashMap::from([
            ("web".to_string(), "team-a".to_string()),
            ("api".to_string(), "team-b".to_string()),
        ]));
        d
    }

    #[test]
    fn only_installed_namespaces_are_collected() {
        let d = dir(true);
        d.set_gate(Gate::Installed(HashSet::from(["team-a".to_string()])));
        assert_eq!(d.admit("web").as_deref(), Some("team-a"));
        assert_eq!(d.admit("api"), None, "team-b never installed obs");
        assert_eq!(
            d.admit("_host").as_deref(),
            Some(UNATTRIBUTED),
            "platform rows are always kept and owned by nobody"
        );
        assert_eq!(d.admit("not-yet-polled").as_deref(), Some(UNATTRIBUTED));
    }

    #[test]
    fn an_unknown_gate_holds_tenants_back_and_an_open_one_does_not() {
        let d = dir(true);
        assert_eq!(d.admit("web"), None, "no answer from app-lb yet");
        d.set_gate(Gate::Open);
        assert_eq!(d.admit("api").as_deref(), Some("team-b"));
    }

    #[test]
    fn require_install_off_pins_the_gate_open() {
        let d = dir(false);
        d.set_gate(Gate::Installed(HashSet::new()));
        assert_eq!(d.gate(), Gate::Open);
        assert_eq!(d.admit("web").as_deref(), Some("team-a"));
    }

    #[test]
    fn namespace_names_never_reach_the_platform() {
        assert!(is_valid_namespace("team-a"));
        assert!(is_valid_namespace("default"));
        for bad in ["", "_", "_host", "Team", "a/b", "a.b"] {
            assert!(!is_valid_namespace(bad), "{bad:?}");
        }
        assert!(is_platform_id("_lb") && is_platform_id("syslog"));
        assert!(!is_platform_id("web"));
    }

    #[test]
    fn deployments_in_lists_one_namespace() {
        let d = dir(true);
        assert_eq!(d.deployments_in("team-a"), vec!["web".to_string()]);
        assert!(d.deployments_in("team-c").is_empty());
    }
}
