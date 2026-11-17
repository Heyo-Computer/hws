//! The alert state machine, kept free of I/O so it can be driven tick by tick
//! in tests: observations in, transitions and notifications out.
//!
//! One alert per `(namespace, rule, deployment)`, identified by a stable
//! [`fingerprint`]. Its life:
//!
//! ```text
//!   inactive ──cond──▶ pending ──for_secs──▶ firing ──!cond──▶ resolved
//!                         │                    │
//!                       !cond ──▶ (forgotten)  └─ every repeat_secs: re-notify
//!                                                 (unless acked or silenced)
//! ```
//!
//! A firing alert is announced once it is not silenced — so a silence that
//! lapses while the alert still fires announces it then — and a resolve is
//! announced for every alert whose firing was. An acknowledgement stops the
//! repeats and is cleared when the alert resolves.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::config::{AlertingConfig, Condition, Rule, Severity};

/// Resolved alerts kept per namespace, newest last.
pub const MAX_RESOLVED: usize = 100;
pub const MAX_SILENCES: usize = 100;
/// Samples kept per deployment: a day at the default tick, and a bound on
/// memory at any tick.
const MAX_SAMPLES: usize = 6000;
/// The longest counter window a rule may name, which is how far back samples
/// are kept.
const SAMPLE_HORIZON_SECS: u64 = 86_400;

/// `sha256(namespace \0 rule \0 deployment)`, the first 16 bytes in hex.
pub fn fingerprint(ns: &str, rule: &str, deployment: &str) -> String {
    let mut h = Sha256::new();
    h.update(ns.as_bytes());
    h.update([0]);
    h.update(rule.as_bytes());
    h.update([0]);
    h.update(deployment.as_bytes());
    hex(&h.finalize()[..16])
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

// ---- what the engine is told -------------------------------------------------

/// The cumulative per-deployment counters windowed conditions read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub create_failures: u64,
    pub boot_timeouts: u64,
    pub cold_start_timeouts: u64,
}

impl Counters {
    /// `self - base`, where a counter that went backwards (the deployment was
    /// re-registered and its metrics started over) counts from zero.
    fn since(self, base: Counters) -> Counters {
        let d = |now: u64, then: u64| if now >= then { now - then } else { now };
        Counters {
            create_failures: d(self.create_failures, base.create_failures),
            boot_timeouts: d(self.boot_timeouts, base.boot_timeouts),
            cold_start_timeouts: d(self.cold_start_timeouts, base.cold_start_timeouts),
        }
    }
}

/// One deployment of the namespace, as of this tick.
#[derive(Debug, Clone, Default)]
pub struct Observation {
    /// Replicas that could take a request now.
    pub available: u32,
    /// Replicas the deployment has or is meant to have: ready, booting, or
    /// its minimum. Zero for a pool scaled to zero, which is not an outage.
    pub wanted: u32,
    /// For a static deployment, the upstreams failing their health check.
    pub unhealthy_upstreams: Vec<String>,
    pub counters: Counters,
    /// Why a rollout is stalled, when one is.
    pub rollout_stall: Option<String>,
}

/// The last result of one check.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub deployment: String,
    pub path: String,
    pub ok: bool,
    pub passing: u32,
    pub total: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub checked_at: u64,
}

/// Counter samples per deployment, for windowed conditions.
#[derive(Debug, Default)]
pub struct Samples {
    rings: HashMap<String, VecDeque<(u64, Counters)>>,
}

impl Samples {
    pub fn record(&mut self, deployment: &str, now: u64, c: Counters) {
        let ring = self.rings.entry(deployment.to_string()).or_default();
        ring.push_back((now, c));
        // Keep one sample older than the horizon, so a full-horizon window
        // still has a base.
        while ring.len() > MAX_SAMPLES
            || (ring.len() > 1 && ring[1].0.saturating_add(SAMPLE_HORIZON_SECS) <= now)
        {
            ring.pop_front();
        }
    }

    /// Forget deployments not seen this tick.
    pub fn retain(&mut self, live: impl Fn(&str) -> bool) {
        self.rings.retain(|d, _| live(d));
    }

    /// How much each counter grew over the last `window` seconds: against the
    /// newest sample at least `window` old, or the oldest there is.
    pub fn delta(&self, deployment: &str, now: u64, window: u64) -> Counters {
        let Some(ring) = self.rings.get(deployment) else {
            return Counters::default();
        };
        let Some(&(_, latest)) = ring.back() else {
            return Counters::default();
        };
        let cutoff = now.saturating_sub(window);
        let base = ring
            .iter()
            .rev()
            .find(|(t, _)| *t <= cutoff)
            .or_else(|| ring.front())
            .map(|(_, c)| *c)
            .unwrap_or_default();
        latest.since(base)
    }
}

/// Whether `cond` holds for `deployment`, and if so a one-line summary.
pub fn evaluate(
    cond: &Condition,
    deployment: &str,
    obs: &Observation,
    checks: &BTreeMap<String, CheckResult>,
    samples: &Samples,
    now: u64,
) -> Option<String> {
    match cond {
        Condition::NoHealthyReplicas => (obs.wanted > 0 && obs.available == 0).then(|| {
            format!("{deployment}: no healthy replicas (0 of {} available)", obs.wanted)
        }),
        Condition::HealthyReplicasBelow { n } => (obs.available < *n).then(|| {
            format!(
                "{deployment}: {} healthy replica{}, below {n}",
                obs.available,
                if obs.available == 1 { "" } else { "s" }
            )
        }),
        Condition::CreateFailures { n, window_secs } => {
            let d = samples.delta(deployment, now, *window_secs).create_failures;
            (d >= *n).then(|| format!("{deployment}: {d} VM creates failed in the last {window_secs}s"))
        }
        Condition::BootTimeouts { n, window_secs } => {
            let d = samples.delta(deployment, now, *window_secs).boot_timeouts;
            (d >= *n).then(|| format!("{deployment}: {d} VMs timed out booting in the last {window_secs}s"))
        }
        Condition::ColdStartTimeouts { n, window_secs } => {
            let d = samples.delta(deployment, now, *window_secs).cold_start_timeouts;
            (d >= *n).then(|| {
                format!("{deployment}: {d} requests timed out waiting for a cold start in the last {window_secs}s")
            })
        }
        Condition::UpstreamUnhealthy => (!obs.unhealthy_upstreams.is_empty()).then(|| {
            format!(
                "{deployment}: upstream{} unhealthy: {}",
                if obs.unhealthy_upstreams.len() == 1 { "" } else { "s" },
                obs.unhealthy_upstreams.join(", ")
            )
        }),
        Condition::RolloutStalled => obs
            .rollout_stall
            .as_ref()
            .map(|why| format!("{deployment}: rollout stalled: {why}")),
        Condition::CheckFailing { check } => {
            let r = checks.get(check).filter(|r| r.deployment == deployment)?;
            (!r.ok).then(|| {
                let mut s = format!(
                    "{deployment}: check {check} ({}) failing: {} of {} replicas passing",
                    r.path, r.passing, r.total
                );
                if let Some(e) = &r.last_error {
                    s.push_str(&format!(" ({e})"));
                }
                s
            })
        }
    }
}

/// The deployments a rule applies to, out of the namespace's own.
pub fn targets<'a>(rule: &'a Rule, cfg: &'a AlertingConfig, deployments: &'a BTreeMap<String, Observation>) -> Vec<&'a str> {
    let named: Option<&str> = match &rule.condition {
        // A check probes one deployment; a `*` rule over it means that one.
        Condition::CheckFailing { check } => cfg
            .checks
            .iter()
            .find(|c| &c.id == check)
            .map(|c| c.deployment.as_str()),
        _ => None,
    };
    let wanted = match (rule.deployment.as_str(), named) {
        ("*", Some(d)) => Some(d),
        ("*", None) => None,
        (d, _) => Some(d),
    };
    match wanted {
        Some(d) => deployments.get_key_value(d).map(|(k, _)| k.as_str()).into_iter().collect(),
        None => deployments.keys().map(String::as_str).collect(),
    }
}

// ---- state -----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    Pending,
    Firing,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub fingerprint: String,
    pub rule: String,
    pub deployment: String,
    pub severity: Severity,
    pub condition: String,
    pub status: AlertStatus,
    pub summary: String,
    /// When the condition was first seen holding.
    pub pending_since: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<u64>,
    /// Whether the firing notification went out (it is held while silenced).
    #[serde(default)]
    pub notified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_notified_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acked_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_comment: Option<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matchers {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Silence {
    pub id: String,
    pub matchers: Matchers,
    /// Unix seconds.
    pub until: u64,
    #[serde(default)]
    pub comment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    pub created_at: u64,
}

impl Silence {
    pub fn matches(&self, a: &Alert, now: u64) -> bool {
        self.until > now
            && self.matchers.rule.as_ref().is_none_or(|r| *r == a.rule)
            && self.matchers.deployment.as_ref().is_none_or(|d| *d == a.deployment)
            && self.matchers.severity.is_none_or(|s| s == a.severity)
    }
}

/// One namespace's alerts and silences: what is persisted.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NsState {
    /// Pending and firing, by fingerprint.
    #[serde(default)]
    pub alerts: BTreeMap<String, Alert>,
    #[serde(default)]
    pub resolved: VecDeque<Alert>,
    #[serde(default)]
    pub silences: Vec<Silence>,
}

impl NsState {
    pub fn silenced(&self, a: &Alert, now: u64) -> bool {
        self.silences.iter().any(|s| s.matches(a, now))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Firing,
    Resolved,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Event::Firing => "firing",
            Event::Resolved => "resolved",
        }
    }
}

/// A notification to send.
#[derive(Debug, Clone)]
pub struct Notification {
    pub event: Event,
    pub alert: Alert,
    pub receivers: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub notifications: Vec<Notification>,
    /// Whether anything worth persisting changed.
    pub changed: bool,
}

/// Advance one namespace's alerts by one tick. `active` is every
/// `(rule, deployment)` the rules were evaluated for, with the summary of
/// those whose condition holds; an alert not in it (its rule or deployment is
/// gone) counts as no longer holding.
pub fn step(
    state: &mut NsState,
    ns: &str,
    cfg: &AlertingConfig,
    active: &[(String, String, Option<String>)],
    now: u64,
) -> Outcome {
    let mut out = Outcome::default();
    let before = state.silences.len();
    state.silences.retain(|s| s.until > now);
    out.changed |= state.silences.len() != before;

    let rules: HashMap<&str, &Rule> = cfg.rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let mut holding = std::collections::HashSet::new();

    for (rule_id, deployment, summary) in active {
        let Some(rule) = rules.get(rule_id.as_str()) else { continue };
        let Some(summary) = summary else {
            continue; // handled with the vanished ones below
        };
        let fp = fingerprint(ns, rule_id, deployment);
        holding.insert(fp.clone());
        let alert = state.alerts.entry(fp.clone()).or_insert_with(|| {
            out.changed = true;
            Alert {
                fingerprint: fp.clone(),
                rule: rule_id.clone(),
                deployment: deployment.clone(),
                severity: rule.severity,
                condition: rule.condition.kind().to_string(),
                status: AlertStatus::Pending,
                summary: summary.clone(),
                pending_since: now,
                started_at: None,
                resolved_at: None,
                notified: false,
                last_notified_at: None,
                acked_by: None,
                acked_at: None,
                ack_comment: None,
                labels: BTreeMap::from([
                    ("namespace".to_string(), ns.to_string()),
                    ("deployment".to_string(), deployment.clone()),
                    ("rule".to_string(), rule_id.clone()),
                    ("severity".to_string(), rule.severity.as_str().to_string()),
                    ("condition".to_string(), rule.condition.kind().to_string()),
                ]),
            }
        });
        alert.summary = summary.clone();
        // A rule edited in place takes effect on its live alert.
        alert.severity = rule.severity;
        if alert.status == AlertStatus::Pending
            && now.saturating_sub(alert.pending_since) >= rule.for_secs
        {
            alert.status = AlertStatus::Firing;
            alert.started_at = Some(now);
            out.changed = true;
        }
    }

    // Announce, repeat, and resolve.
    let fps: Vec<String> = state.alerts.keys().cloned().collect();
    for fp in fps {
        let holds = holding.contains(&fp);
        let silenced = state.silenced(&state.alerts[&fp], now);
        let alert = state.alerts.get_mut(&fp).expect("listed above");
        let rule = rules.get(alert.rule.as_str());
        let receivers = rule.map(|r| r.receivers.clone()).unwrap_or_default();
        if holds {
            if alert.status != AlertStatus::Firing || silenced {
                continue;
            }
            let repeat = rule.map_or(0, |r| r.repeat_secs);
            let due = if !alert.notified {
                true
            } else {
                alert.acked_by.is_none()
                    && repeat > 0
                    && alert
                        .last_notified_at
                        .is_none_or(|t| now.saturating_sub(t) >= repeat)
            };
            if due {
                alert.notified = true;
                alert.last_notified_at = Some(now);
                out.changed = true;
                out.notifications.push(Notification {
                    event: Event::Firing,
                    alert: alert.clone(),
                    receivers,
                });
            }
            continue;
        }
        // No longer holding.
        let mut alert = state.alerts.remove(&fp).expect("listed above");
        out.changed = true;
        if alert.status == AlertStatus::Pending {
            continue; // never fired: nothing to resolve
        }
        alert.status = AlertStatus::Resolved;
        alert.resolved_at = Some(now);
        alert.acked_by = None;
        alert.acked_at = None;
        alert.ack_comment = None;
        if alert.notified {
            alert.last_notified_at = Some(now);
            out.notifications.push(Notification {
                event: Event::Resolved,
                alert: alert.clone(),
                receivers,
            });
        }
        state.resolved.push_back(alert);
        while state.resolved.len() > MAX_RESOLVED {
            state.resolved.pop_front();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::alerting::config::parse_install;
    use serde_json::json;

    fn cfg(rule: serde_json::Value) -> AlertingConfig {
        let open = crate::net_guard::Policy {
            allow_insecure: true,
            allow_private: true,
        };
        parse_install(
            &json!({
                "receivers": [{"id": "ops", "url": "https://hooks.example.com/"}],
                "rules": [rule],
            }),
            open,
        )
        .unwrap()
    }

    fn on(rule: &str) -> Vec<(String, String, Option<String>)> {
        vec![(rule.into(), "web".into(), Some("web is down".into()))]
    }
    fn off(rule: &str) -> Vec<(String, String, Option<String>)> {
        vec![(rule.into(), "web".into(), None)]
    }
    fn events(o: &Outcome) -> Vec<Event> {
        o.notifications.iter().map(|n| n.event).collect()
    }

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        let a = fingerprint("team-a", "down", "web");
        assert_eq!(a, fingerprint("team-a", "down", "web"));
        assert_eq!(a.len(), 32);
        assert_ne!(a, fingerprint("team-b", "down", "web"));
        assert_ne!(a, fingerprint("team-a", "down", "api"));
        // The separator keeps the parts from running together.
        assert_ne!(fingerprint("a", "bc", "d"), fingerprint("ab", "c", "d"));
        // Pinned: a fingerprint is an id clients keep.
        assert_eq!(fingerprint("ns", "r", "d"), "55ddd906e01934c74877501a7397c83a");
    }

    #[test]
    fn pending_waits_for_for_secs_then_fires_once_and_resolves() {
        let c = cfg(json!({"id": "down", "deployment": "web", "condition": {"type": "no_healthy_replicas"},
            "for_secs": 60, "receivers": ["ops"], "repeat_secs": 0}));
        let mut s = NsState::default();
        let o = step(&mut s, "a", &c, &on("down"), 1000);
        assert!(o.changed && o.notifications.is_empty());
        let a = s.alerts.values().next().unwrap();
        assert_eq!(a.status, AlertStatus::Pending);

        let o = step(&mut s, "a", &c, &on("down"), 1059);
        assert!(o.notifications.is_empty(), "not yet");
        let o = step(&mut s, "a", &c, &on("down"), 1060);
        assert_eq!(events(&o), [Event::Firing]);
        assert_eq!(o.notifications[0].receivers, ["ops"]);
        assert_eq!(o.notifications[0].alert.started_at, Some(1060));
        assert!(step(&mut s, "a", &c, &on("down"), 5000).notifications.is_empty(), "repeat_secs 0");

        let o = step(&mut s, "a", &c, &off("down"), 5015);
        assert_eq!(events(&o), [Event::Resolved]);
        assert_eq!(o.notifications[0].alert.resolved_at, Some(5015));
        assert!(s.alerts.is_empty());
        assert_eq!(s.resolved.len(), 1);
        assert_eq!(s.resolved[0].status, AlertStatus::Resolved);
    }

    #[test]
    fn a_blip_shorter_than_for_secs_never_notifies() {
        let c = cfg(json!({"id": "down", "deployment": "web", "condition": {"type": "no_healthy_replicas"},
            "for_secs": 60, "receivers": ["ops"]}));
        let mut s = NsState::default();
        step(&mut s, "a", &c, &on("down"), 0);
        let o = step(&mut s, "a", &c, &off("down"), 30);
        assert!(o.notifications.is_empty());
        assert!(s.alerts.is_empty() && s.resolved.is_empty());
    }

    #[test]
    fn repeats_every_repeat_secs_until_acked_and_ack_clears_on_resolve() {
        let c = cfg(json!({"id": "down", "deployment": "web", "condition": {"type": "no_healthy_replicas"},
            "receivers": ["ops"], "repeat_secs": 600}));
        let mut s = NsState::default();
        assert_eq!(events(&step(&mut s, "a", &c, &on("down"), 0)), [Event::Firing]);
        assert!(step(&mut s, "a", &c, &on("down"), 599).notifications.is_empty());
        assert_eq!(events(&step(&mut s, "a", &c, &on("down"), 600)), [Event::Firing]);
        let a = s.alerts.values_mut().next().unwrap();
        a.acked_by = Some("user:1".into());
        a.acked_at = Some(700);
        assert!(step(&mut s, "a", &c, &on("down"), 5000).notifications.is_empty(), "acked");
        let o = step(&mut s, "a", &c, &off("down"), 5001);
        assert_eq!(events(&o), [Event::Resolved], "a resolve still goes out");
        assert!(s.resolved[0].acked_by.is_none());
        // Fires again later as a fresh, unacked alert.
        assert_eq!(events(&step(&mut s, "a", &c, &on("down"), 6000)), [Event::Firing]);
        assert!(s.alerts.values().next().unwrap().acked_by.is_none());
    }

    #[test]
    fn a_silence_holds_notifications_until_it_lapses_and_is_then_pruned() {
        let c = cfg(json!({"id": "down", "deployment": "web", "severity": "critical",
            "condition": {"type": "no_healthy_replicas"}, "receivers": ["ops"]}));
        let mut s = NsState::default();
        s.silences.push(Silence {
            id: "s1".into(),
            matchers: Matchers { rule: Some("down".into()), deployment: None, severity: Some(Severity::Critical) },
            until: 100,
            comment: "maintenance".into(),
            created_by: None,
            created_at: 0,
        });
        // A silence for another rule does nothing to this one.
        s.silences.push(Silence {
            id: "s2".into(),
            matchers: Matchers { rule: Some("other".into()), ..Default::default() },
            until: 10_000,
            comment: String::new(),
            created_by: None,
            created_at: 0,
        });
        let o = step(&mut s, "a", &c, &on("down"), 10);
        assert!(o.notifications.is_empty(), "silenced");
        assert_eq!(s.alerts.values().next().unwrap().status, AlertStatus::Firing);
        let o = step(&mut s, "a", &c, &on("down"), 100);
        assert_eq!(events(&o), [Event::Firing], "announced once the silence lapses");
        assert_eq!(s.silences.len(), 1, "the lapsed silence is pruned");
        assert_eq!(s.silences[0].id, "s2");
    }

    #[test]
    fn an_alert_silenced_throughout_resolves_quietly() {
        let c = cfg(json!({"id": "down", "deployment": "web",
            "condition": {"type": "no_healthy_replicas"}, "receivers": ["ops"]}));
        let mut s = NsState::default();
        s.silences.push(Silence {
            id: "s".into(),
            matchers: Matchers { deployment: Some("web".into()), ..Default::default() },
            until: 1000,
            comment: String::new(),
            created_by: None,
            created_at: 0,
        });
        step(&mut s, "a", &c, &on("down"), 10);
        let o = step(&mut s, "a", &c, &off("down"), 20);
        assert!(o.notifications.is_empty());
        assert_eq!(s.resolved.len(), 1);
    }

    #[test]
    fn a_removed_rule_or_deployment_resolves_its_alert() {
        let c = cfg(json!({"id": "down", "deployment": "web",
            "condition": {"type": "no_healthy_replicas"}, "receivers": ["ops"]}));
        let mut s = NsState::default();
        step(&mut s, "a", &c, &on("down"), 10);
        let o = step(&mut s, "a", &c, &[], 20);
        assert_eq!(events(&o), [Event::Resolved]);
    }

    #[test]
    fn windowed_counters_use_deltas_and_survive_resets() {
        let mut s = Samples::default();
        let c = |n| Counters { create_failures: n, ..Default::default() };
        s.record("web", 0, c(5));
        s.record("web", 300, c(6));
        s.record("web", 600, c(9));
        assert_eq!(s.delta("web", 600, 300).create_failures, 3);
        assert_eq!(s.delta("web", 600, 600).create_failures, 4);
        assert_eq!(s.delta("web", 600, 10_000).create_failures, 4, "oldest sample is the base");
        s.record("web", 900, c(1));
        assert_eq!(s.delta("web", 900, 300).create_failures, 1, "a reset counts from zero");
        assert_eq!(s.delta("api", 900, 300), Counters::default());
        s.retain(|d| d != "web");
        assert_eq!(s.delta("web", 900, 300), Counters::default());
    }

    #[test]
    fn conditions_read_their_observation() {
        let samples = Samples::default();
        let checks = BTreeMap::new();
        let obs = Observation { available: 0, wanted: 2, ..Default::default() };
        assert!(evaluate(&Condition::NoHealthyReplicas, "web", &obs, &checks, &samples, 0).is_some());
        let idle = Observation { available: 0, wanted: 0, ..Default::default() };
        assert!(evaluate(&Condition::NoHealthyReplicas, "web", &idle, &checks, &samples, 0).is_none(), "scaled to zero");
        let one = Observation { available: 1, wanted: 3, ..Default::default() };
        assert!(evaluate(&Condition::HealthyReplicasBelow { n: 2 }, "web", &one, &checks, &samples, 0).is_some());
        assert!(evaluate(&Condition::HealthyReplicasBelow { n: 1 }, "web", &one, &checks, &samples, 0).is_none());
        let up = Observation { unhealthy_upstreams: vec!["10.0.0.1:80".into()], ..Default::default() };
        assert!(evaluate(&Condition::UpstreamUnhealthy, "web", &up, &checks, &samples, 0).unwrap().contains("10.0.0.1:80"));
        assert!(evaluate(&Condition::RolloutStalled, "web", &obs, &checks, &samples, 0).is_none());
        let stalled = Observation { rollout_stall: Some("candidate unhealthy".into()), ..Default::default() };
        assert!(evaluate(&Condition::RolloutStalled, "web", &stalled, &checks, &samples, 0).is_some());

        let mut checks = BTreeMap::new();
        checks.insert("home".to_string(), CheckResult {
            id: "home".into(), deployment: "web".into(), path: "/".into(),
            ok: false, passing: 0, total: 2, last_error: Some("503".into()), checked_at: 0,
        });
        let cond = Condition::CheckFailing { check: "home".into() };
        assert!(evaluate(&cond, "web", &obs, &checks, &samples, 0).unwrap().contains("0 of 2"));
        assert!(evaluate(&cond, "api", &obs, &checks, &samples, 0).is_none(), "another deployment's check");
        checks.get_mut("home").unwrap().ok = true;
        assert!(evaluate(&cond, "web", &obs, &checks, &samples, 0).is_none());
    }
}
