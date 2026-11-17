//! The alerting plugin's two configurations: the operator's fleet switch and
//! each namespace's install (receivers, rules, checks).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::net_guard;
use crate::secrets::SecretRef;

pub const MAX_RECEIVERS: usize = 20;
pub const MAX_RULES: usize = 100;
pub const MAX_CHECKS: usize = 50;
const MAX_ID: usize = 63;
const MAX_HEADERS: usize = 10;
const MAX_FOR_SECS: u64 = 7 * 86_400;
const MAX_WINDOW_SECS: u64 = 86_400;
pub const DEFAULT_TICK_SECS: u64 = 15;
const DEFAULT_CHECK_INTERVAL: u64 = 30;
const DEFAULT_CHECK_TIMEOUT: u64 = 5;
const DEFAULT_REPEAT_SECS: u64 = 3600;

// ---- the operator's configuration ------------------------------------------

/// What the operator enables the plugin with. Everything is optional; `{}`
/// is the usual configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FleetConfig {
    /// Let receivers use plain `http://`. Outranks
    /// `APP_LB_ALERTING_ALLOW_INSECURE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_insecure: Option<bool>,
    /// Let receivers resolve to private, loopback, link-local, CGNAT or ULA
    /// addresses. Outranks `APP_LB_ALERTING_ALLOW_PRIVATE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_private: Option<bool>,
    /// How often rules are evaluated, in seconds.
    #[serde(default = "default_tick_secs")]
    pub tick_secs: u64,
}

fn default_tick_secs() -> u64 {
    DEFAULT_TICK_SECS
}

impl FleetConfig {
    pub fn policy(&self) -> net_guard::Policy {
        net_guard::Policy::resolve(self.allow_insecure, self.allow_private)
    }
}

pub fn parse_fleet(config: &Value) -> Result<FleetConfig, String> {
    let config = if config.is_null() {
        Value::Object(Default::default())
    } else {
        config.clone()
    };
    let cfg: FleetConfig = serde_json::from_value(config).map_err(|e| e.to_string())?;
    if !(1..=3600).contains(&cfg.tick_secs) {
        return Err("tick_secs must be between 1 and 3600".into());
    }
    Ok(cfg)
}

// ---- a namespace's install ---------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlertingConfig {
    #[serde(default)]
    pub receivers: Vec<Receiver>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// The JSON payload documented in the README.
    #[default]
    Generic,
    /// `{"text": …}`, for a Slack incoming webhook.
    Slack,
}

/// Somewhere notifications go.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receiver {
    pub id: String,
    pub url: String,
    /// The signing key, as a reference into the namespace's own secrets.
    /// Resolved at every send, in the installing namespace whatever the
    /// reference says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretRef>,
    #[serde(default)]
    pub format: Format,
    /// Extra request headers. Not for credentials: `Authorization`,
    /// `Cookie` and the headers the plugin sets itself are refused.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    #[default]
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

/// What a rule watches. Tagged by `type`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    /// The deployment has replicas to serve with and none is available.
    NoHealthyReplicas,
    /// Fewer than `n` replicas are available.
    HealthyReplicasBelow { n: u32 },
    /// At least `n` VM creates were refused within the window.
    CreateFailures { n: u64, window_secs: u64 },
    /// At least `n` VMs never passed their health check within the window.
    BootTimeouts { n: u64, window_secs: u64 },
    /// At least `n` requests gave up waiting for a cold start in the window.
    ColdStartTimeouts { n: u64, window_secs: u64 },
    /// A static (`upstreams`) deployment has an upstream failing its health
    /// check.
    UpstreamUnhealthy,
    /// A rolling rollout of the deployment has stopped making progress.
    RolloutStalled,
    /// The named check is failing.
    CheckFailing { check: String },
}

impl Condition {
    pub fn kind(&self) -> &'static str {
        match self {
            Condition::NoHealthyReplicas => "no_healthy_replicas",
            Condition::HealthyReplicasBelow { .. } => "healthy_replicas_below",
            Condition::CreateFailures { .. } => "create_failures",
            Condition::BootTimeouts { .. } => "boot_timeouts",
            Condition::ColdStartTimeouts { .. } => "cold_start_timeouts",
            Condition::UpstreamUnhealthy => "upstream_unhealthy",
            Condition::RolloutStalled => "rollout_stalled",
            Condition::CheckFailing { .. } => "check_failing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    /// A deployment id in the namespace, or `"*"` for every one.
    pub deployment: String,
    pub condition: Condition,
    /// How long the condition must hold before the alert fires.
    #[serde(default)]
    pub for_secs: u64,
    #[serde(default)]
    pub severity: Severity,
    /// Receiver ids. Empty: the alert shows on the page and API only.
    #[serde(default)]
    pub receivers: Vec<String>,
    /// Re-notify this often while firing and unacknowledged. 0: never.
    #[serde(default = "default_repeat_secs")]
    pub repeat_secs: u64,
}

fn default_repeat_secs() -> u64 {
    DEFAULT_REPEAT_SECS
}

/// An HTTP check against every available replica of one deployment.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub id: String,
    pub deployment: String,
    pub path: String,
    #[serde(default = "default_check_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_check_timeout")]
    pub timeout_secs: u64,
    /// The status a replica must answer. Default: any 2xx or 3xx.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_status: Option<u16>,
    /// How many replicas must pass for the check to pass.
    #[serde(default = "default_min_passing")]
    pub min_passing: u32,
}

fn default_check_interval() -> u64 {
    DEFAULT_CHECK_INTERVAL
}
fn default_check_timeout() -> u64 {
    DEFAULT_CHECK_TIMEOUT
}
fn default_min_passing() -> u32 {
    1
}

impl Check {
    pub fn passes(&self, status: u16) -> bool {
        match self.expect_status {
            Some(want) => status == want,
            None => (200..400).contains(&status),
        }
    }
}

/// Ids for receivers, rules and checks: what can sit in a URL unescaped.
pub fn is_valid_id(id: &str) -> bool {
    let mut b = id.bytes();
    matches!(b.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && id.len() <= MAX_ID
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

fn is_valid_deployment(d: &str) -> bool {
    d.len() <= 128 && crate::config::is_valid_namespace(d)
}

/// Headers a receiver may not set: the ones the plugin owns, and the ones
/// that carry credentials (which belong in a secret, not in configuration).
fn reserved_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("x-heyo-")
        || matches!(
            n.as_str(),
            "authorization"
                | "proxy-authorization"
                | "cookie"
                | "host"
                | "content-type"
                | "content-length"
                | "transfer-encoding"
                | "connection"
        )
}

fn unique<'a>(what: &str, ids: impl Iterator<Item = &'a str>) -> Result<BTreeSet<&'a str>, String> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !is_valid_id(id) {
            return Err(format!(
                "{what} id {id:?}: use 1–{MAX_ID} lowercase letters, digits, '-' or '_', starting with a letter or digit"
            ));
        }
        if !seen.insert(id) {
            return Err(format!("{what} id {id:?} is used twice"));
        }
    }
    Ok(seen)
}

fn check_window(rule: &str, n: u64, window: u64) -> Result<(), String> {
    if n == 0 {
        return Err(format!("rule {rule:?}: n must be at least 1"));
    }
    if !(60..=MAX_WINDOW_SECS).contains(&window) {
        return Err(format!(
            "rule {rule:?}: window_secs must be between 60 and {MAX_WINDOW_SECS}"
        ));
    }
    Ok(())
}

/// Parse and check a namespace's install. URLs are checked for shape only —
/// every send re-checks them with DNS.
pub fn parse_install(config: &Value, policy: net_guard::Policy) -> Result<AlertingConfig, String> {
    let cfg: AlertingConfig = match config {
        Value::Null => AlertingConfig::default(),
        v => serde_json::from_value(v.clone()).map_err(|e| e.to_string())?,
    };
    if cfg.receivers.len() > MAX_RECEIVERS {
        return Err(format!("at most {MAX_RECEIVERS} receivers"));
    }
    if cfg.rules.len() > MAX_RULES {
        return Err(format!("at most {MAX_RULES} rules"));
    }
    if cfg.checks.len() > MAX_CHECKS {
        return Err(format!("at most {MAX_CHECKS} checks"));
    }
    let receivers = unique("receiver", cfg.receivers.iter().map(|r| r.id.as_str()))?;
    unique("rule", cfg.rules.iter().map(|r| r.id.as_str()))?;
    unique("check", cfg.checks.iter().map(|c| c.id.as_str()))?;

    for r in &cfg.receivers {
        net_guard::check_syntax(&r.url, policy).map_err(|e| format!("receiver {:?}: {e}", r.id))?;
        if let Some(s) = &r.secret {
            s.validate().map_err(|e| format!("receiver {:?}: secret: {e}", r.id))?;
        }
        if r.headers.len() > MAX_HEADERS {
            return Err(format!("receiver {:?}: at most {MAX_HEADERS} headers", r.id));
        }
        for (name, value) in &r.headers {
            if http::HeaderName::from_bytes(name.as_bytes()).is_err()
                || http::HeaderValue::from_str(value).is_err()
                || value.len() > 1024
            {
                return Err(format!("receiver {:?}: header {name:?} is not a valid header", r.id));
            }
            if reserved_header(name) {
                return Err(format!(
                    "receiver {:?}: header {name:?} is set by the plugin or carries a credential; \
                     use the receiver's secret to sign requests instead",
                    r.id
                ));
            }
        }
    }

    for c in &cfg.checks {
        if !is_valid_deployment(&c.deployment) {
            return Err(format!(
                "check {:?}: deployment {:?} is not a deployment id (a check names one deployment, not \"*\")",
                c.id, c.deployment
            ));
        }
        if !c.path.starts_with('/')
            || c.path.len() > 1024
            || c.path.bytes().any(|b| b.is_ascii_control() || b == b' ')
        {
            return Err(format!(
                "check {:?}: path must start with '/' and hold no spaces or control characters",
                c.id
            ));
        }
        if !(10..=86_400).contains(&c.interval_secs) {
            return Err(format!("check {:?}: interval_secs must be between 10 and 86400", c.id));
        }
        if !(1..=30).contains(&c.timeout_secs) || c.timeout_secs > c.interval_secs {
            return Err(format!(
                "check {:?}: timeout_secs must be between 1 and 30, and no longer than interval_secs",
                c.id
            ));
        }
        if let Some(s) = c.expect_status
            && !(100..=599).contains(&s)
        {
            return Err(format!("check {:?}: expect_status must be an HTTP status", c.id));
        }
        if c.min_passing == 0 {
            return Err(format!("check {:?}: min_passing must be at least 1", c.id));
        }
    }

    for r in &cfg.rules {
        if r.deployment != "*" && !is_valid_deployment(&r.deployment) {
            return Err(format!(
                "rule {:?}: deployment {:?} is neither a deployment id nor \"*\"",
                r.id, r.deployment
            ));
        }
        if r.for_secs > MAX_FOR_SECS {
            return Err(format!("rule {:?}: for_secs must be at most {MAX_FOR_SECS}", r.id));
        }
        if r.repeat_secs != 0 && r.repeat_secs < 60 {
            return Err(format!(
                "rule {:?}: repeat_secs must be 0 (never) or at least 60",
                r.id
            ));
        }
        for rcv in &r.receivers {
            if !receivers.contains(rcv.as_str()) {
                return Err(format!("rule {:?}: no receiver named {rcv:?}", r.id));
            }
        }
        match &r.condition {
            Condition::HealthyReplicasBelow { n } if *n == 0 => {
                return Err(format!("rule {:?}: n must be at least 1", r.id));
            }
            Condition::CreateFailures { n, window_secs }
            | Condition::BootTimeouts { n, window_secs }
            | Condition::ColdStartTimeouts { n, window_secs } => {
                check_window(&r.id, *n, *window_secs)?
            }
            Condition::CheckFailing { check } => {
                let Some(c) = cfg.checks.iter().find(|c| &c.id == check) else {
                    return Err(format!("rule {:?}: no check named {check:?}", r.id));
                };
                if r.deployment != "*" && r.deployment != c.deployment {
                    return Err(format!(
                        "rule {:?}: check {check:?} probes deployment {:?}, not {:?}",
                        r.id, c.deployment, r.deployment
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const POLICY: net_guard::Policy = net_guard::Policy {
        allow_insecure: false,
        allow_private: false,
    };

    fn good() -> Value {
        json!({
            "receivers": [
                {"id": "ops", "url": "https://hooks.example.com/a", "secret": {"secret": "hook", "key": "key"}},
                {"id": "slack", "url": "https://hooks.slack.com/services/x", "format": "slack",
                 "headers": {"X-Team": "a"}}
            ],
            "rules": [
                {"id": "down", "deployment": "*", "condition": {"type": "no_healthy_replicas"},
                 "severity": "critical", "receivers": ["ops", "slack"]},
                {"id": "thin", "deployment": "web", "condition": {"type": "healthy_replicas_below", "n": 2},
                 "for_secs": 120},
                {"id": "creates", "deployment": "web",
                 "condition": {"type": "create_failures", "n": 3, "window_secs": 600}},
                {"id": "home", "deployment": "web", "condition": {"type": "check_failing", "check": "home"}},
                {"id": "stall", "deployment": "web", "condition": {"type": "rollout_stalled"}}
            ],
            "checks": [{"id": "home", "deployment": "web", "path": "/healthz"}]
        })
    }

    #[test]
    fn a_full_install_parses_with_defaults() {
        let cfg = parse_install(&good(), POLICY).unwrap();
        assert_eq!(cfg.rules[0].repeat_secs, 3600);
        assert_eq!(cfg.rules[1].severity, Severity::Warning);
        assert_eq!(cfg.checks[0].interval_secs, 30);
        assert_eq!(cfg.checks[0].timeout_secs, 5);
        assert_eq!(cfg.checks[0].min_passing, 1);
        assert_eq!(cfg.receivers[1].format, Format::Slack);
        assert!(parse_install(&Value::Null, POLICY).unwrap().rules.is_empty());
        assert!(parse_install(&json!({}), POLICY).is_ok());
    }

    #[test]
    fn bad_installs_say_what_is_wrong() {
        type Mutate = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(&str, Mutate)> = vec![
            ("unknown", Box::new(|v| v["extra"] = json!(1))),
            ("no receiver named", Box::new(|v| v["rules"][0]["receivers"] = json!(["nope"]))),
            ("no check named", Box::new(|v| v["rules"][3]["condition"]["check"] = json!("nope"))),
            ("used twice", Box::new(|v| v["rules"][1]["id"] = json!("down"))),
            ("id", Box::new(|v| v["receivers"][0]["id"] = json!("Ops!"))),
            ("https", Box::new(|v| v["receivers"][0]["url"] = json!("http://hooks.example.com/"))),
            ("private", Box::new(|v| v["receivers"][0]["url"] = json!("https://10.0.0.1/"))),
            ("metadata", Box::new(|v| v["receivers"][0]["url"] = json!("https://169.254.169.254/"))),
            ("credential", Box::new(|v| v["receivers"][1]["headers"] = json!({"Authorization": "x"}))),
            ("set by the plugin", Box::new(|v| v["receivers"][1]["headers"] = json!({"X-Heyo-Event": "x"}))),
            ("path", Box::new(|v| v["checks"][0]["path"] = json!("healthz"))),
            ("interval_secs", Box::new(|v| v["checks"][0]["interval_secs"] = json!(5))),
            ("min_passing", Box::new(|v| v["checks"][0]["min_passing"] = json!(0))),
            ("not a deployment id", Box::new(|v| v["checks"][0]["deployment"] = json!("*"))),
            ("window_secs", Box::new(|v| v["rules"][2]["condition"]["window_secs"] = json!(10))),
            ("n must be", Box::new(|v| v["rules"][1]["condition"]["n"] = json!(0))),
            ("repeat_secs", Box::new(|v| v["rules"][0]["repeat_secs"] = json!(5))),
            ("probes deployment", Box::new(|v| v["rules"][3]["deployment"] = json!("api"))),
            ("unknown variant", Box::new(|v| v["rules"][0]["condition"] = json!({"type": "cpu_high"}))),
            ("neither", Box::new(|v| v["rules"][0]["deployment"] = json!("a/b"))),
        ];
        for (want, mutate) in cases {
            let mut v = good();
            mutate(&mut v);
            let e = parse_install(&v, POLICY).unwrap_err();
            assert!(e.contains(want), "expected {want:?} in {e:?}");
        }
        let mut many = good();
        many["checks"] = json!((0..51).map(|i| json!({"id": format!("c{i}"), "deployment": "web", "path": "/"})).collect::<Vec<_>>());
        many["rules"] = json!([]);
        assert!(parse_install(&many, POLICY).unwrap_err().contains("at most"));
    }

    #[test]
    fn the_operator_can_allow_http_and_private_receivers() {
        let mut v = good();
        v["receivers"][0]["url"] = json!("http://127.0.0.1:9000/hook");
        assert!(parse_install(&v, POLICY).is_err());
        let open = net_guard::Policy {
            allow_insecure: true,
            allow_private: true,
        };
        assert!(parse_install(&v, open).is_ok());
    }

    #[test]
    fn the_fleet_configuration_is_optional() {
        assert_eq!(parse_fleet(&Value::Null).unwrap().tick_secs, 15);
        assert!(parse_fleet(&json!({"allow_private": true})).unwrap().allow_private == Some(true));
        assert!(parse_fleet(&json!({"bogus": 1})).is_err());
        assert!(parse_fleet(&json!({"tick_secs": 0})).is_err());
    }
}
