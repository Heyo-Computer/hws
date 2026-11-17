//! A namespace's alerts, through app-lb's `alerting` plugin.
//!
//! The operator switches the plugin on for the fleet; a namespace
//! administrator installs it with the namespace's receivers, rules and checks
//! as the install configuration ([`Client::install_plugin`]). From then on
//! app-lb evaluates the rules against the namespace's own deployments and
//! posts signed webhooks when an alert fires and when it resolves. This
//! client reads what it found and acknowledges, silences and tests.
//!
//! ```no_run
//! # async fn f() -> hws::Result<()> {
//! use hws::{Client, NewSilence};
//!
//! let lb = Client::builder("https://admin.example.com")
//!     .token(std::env::var("APP_LB_TOKEN").unwrap())
//!     .build()?;
//!
//! let alerting = lb.alerting("team-a");
//! for a in alerting.alerts().await?.active {
//!     println!("{} {} {}", a.status, a.rule, a.summary);
//!     alerting.ack(&a.fingerprint, Some("looking")).await?;
//! }
//! let until = std::time::SystemTime::now()
//!     .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600;
//! alerting.silence(&NewSilence::until(until).deployment("web").comment("deploy")).await?;
//! # Ok(()) }
//! ```

use crate::api::{Client, Raw, seg};
use crate::error::Result;
use crate::transport::{Method, Request};
use crate::types::*;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

/// The plugin id of the alerting plugin.
pub const ALERTING_PLUGIN: &str = "alerting";

impl Client {
    /// One namespace's alerts, through app-lb's `alerting` plugin.
    ///
    /// Cheap: it borrows nothing and makes no request until a method is
    /// called.
    pub fn alerting(&self, namespace: impl Into<String>) -> AlertingClient {
        AlertingClient {
            client: self.clone(),
            namespace: namespace.into(),
        }
    }
}

/// What [`AlertingClient::silence`] creates. Every matcher left unset
/// matches anything; none set silences the whole namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewSilence {
    pub rule: Option<String>,
    pub deployment: Option<String>,
    /// `info`, `warning` or `critical`.
    pub severity: Option<String>,
    /// Unix seconds; at most 90 days ahead.
    pub until: u64,
    pub comment: String,
}

impl NewSilence {
    pub fn until(until: u64) -> Self {
        Self {
            until,
            ..Default::default()
        }
    }
    pub fn rule(mut self, rule: impl Into<String>) -> Self {
        self.rule = Some(rule.into());
        self
    }
    pub fn deployment(mut self, deployment: impl Into<String>) -> Self {
        self.deployment = Some(deployment.into());
        self
    }
    pub fn severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = Some(severity.into());
        self
    }
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }

    fn body(&self) -> Value {
        let mut matchers = Map::new();
        for (k, v) in [
            ("rule", &self.rule),
            ("deployment", &self.deployment),
            ("severity", &self.severity),
        ] {
            if let Some(v) = v {
                matchers.insert(k.into(), Value::from(v.as_str()));
            }
        }
        json!({"matchers": matchers, "until": self.until, "comment": self.comment})
    }
}

/// One namespace's alerts. See [`Client::alerting`].
///
/// Every method answers [`crate::Error::Conflict`] when the `alerting`
/// plugin is not installed in the namespace (or is switched off for the
/// fleet); the error's message says which, and how to fix it.
#[derive(Debug, Clone)]
pub struct AlertingClient {
    client: Client,
    namespace: String,
}

impl AlertingClient {
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    fn path(&self, rest: &str) -> String {
        format!(
            "/namespaces/{}/plugins/{ALERTING_PLUGIN}/api/{rest}",
            seg(&self.namespace)
        )
    }

    async fn get<T: DeserializeOwned>(&self, rest: &str) -> Result<T> {
        self.client
            .read(
                Request::new(Method::Get, self.path(rest)),
                "namespace",
                &self.namespace,
            )
            .await
    }

    /// Receivers, rules and counts.
    pub async fn status(&self) -> Result<AlertingStatus> {
        self.get("status").await
    }

    /// Pending and firing alerts, and the recently resolved.
    pub async fn alerts(&self) -> Result<AlertingAlerts> {
        self.get("alerts").await
    }

    /// Acknowledge a pending or firing alert: no more repeat notifications
    /// until it resolves. Needs `admin` in the namespace.
    pub async fn ack(&self, fingerprint: &str, comment: Option<&str>) -> Result<AlertingAlert> {
        let body = match comment {
            Some(c) => json!({"comment": c}),
            None => json!({}),
        };
        self.client
            .read(
                Request::new(
                    Method::Post,
                    self.path(&format!("alerts/{}/ack", seg(fingerprint))),
                )
                .json(body),
                "alert",
                fingerprint,
            )
            .await
    }

    /// The silences in force.
    pub async fn silences(&self) -> Result<AlertingSilences> {
        self.get("silences").await
    }

    /// Hold notifications for matching alerts until `until`. Needs `admin`.
    pub async fn silence(&self, new: &NewSilence) -> Result<AlertingSilence> {
        self.client
            .read(
                Request::new(Method::Post, self.path("silences")).json(new.body()),
                "namespace",
                &self.namespace,
            )
            .await
    }

    /// Remove a silence. Needs `admin`.
    pub async fn unsilence(&self, id: &str) -> Result<DeletedAlertingSilence> {
        self.client
            .read(
                Request::new(Method::Delete, self.path(&format!("silences/{}", seg(id)))),
                "silence",
                id,
            )
            .await
    }

    /// Each check and its last result.
    pub async fn checks(&self) -> Result<AlertingChecks> {
        self.get("checks").await
    }

    /// The last webhooks sent, newest first.
    pub async fn deliveries(&self) -> Result<AlertingDeliveries> {
        self.get("deliveries").await
    }

    /// Queue an `alert.test` webhook to a receiver. Needs `admin`.
    pub async fn test_receiver(&self, receiver: &str) -> Result<AlertingTestDelivery> {
        self.client
            .read(
                Request::new(
                    Method::Post,
                    self.path(&format!("receivers/{}/test", seg(receiver))),
                ),
                "receiver",
                receiver,
            )
            .await
    }
}

/// The same reads, unparsed — for printing a response without losing what
/// this build does not name. See [`Client::raw`].
impl Raw<'_> {
    pub async fn alerting(&self, namespace: &str, what: AlertingRead) -> Result<Value> {
        self.0.alerting(namespace).get(what.path()).await
    }
}

/// Which read [`Raw::alerting`] makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertingRead {
    Status,
    Alerts,
    Silences,
    Checks,
    Deliveries,
}

impl AlertingRead {
    fn path(self) -> &'static str {
        match self {
            AlertingRead::Status => "status",
            AlertingRead::Alerts => "alerts",
            AlertingRead::Silences => "silences",
            AlertingRead::Checks => "checks",
            AlertingRead::Deliveries => "deliveries",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::stub::Stub;
    use std::sync::Arc;

    #[tokio::test]
    async fn alerting_goes_through_the_namespace_plugin_prefix() {
        let stub = Arc::new(
            Stub::new()
                .json(200, json!({"namespace": "team a", "active": [{"fingerprint": "f1", "rule": "down",
                    "deployment": "web", "status": "firing", "severity": "critical", "summary": "x",
                    "silenced": false}], "resolved": []}))
                .json(200, json!({"fingerprint": "f1", "acked_by": "user:1"}))
                .json(201, json!({"id": "sil_1", "matchers": {"deployment": "web"}, "until": 99}))
                .json(200, json!({"deleted": "sil_1"}))
                .json(202, json!({"delivery_id": "dlv_1", "receiver": "ops", "status": "queued"})),
        );
        let c = Client::with_transport(stub.clone());
        let a = c.alerting("team a");
        let list = a.alerts().await.unwrap();
        assert_eq!(list.active[0].status, "firing");
        assert_eq!(a.ack("f1", Some("on it")).await.unwrap().acked_by.as_deref(), Some("user:1"));
        let s = a
            .silence(&NewSilence::until(99).deployment("web"))
            .await
            .unwrap();
        assert_eq!(s.matchers.deployment.as_deref(), Some("web"));
        assert_eq!(a.unsilence("sil_1").await.unwrap().deleted, "sil_1");
        assert_eq!(a.test_receiver("ops").await.unwrap().delivery_id, "dlv_1");

        let calls = stub.calls();
        let seen: Vec<(Method, &str)> = calls.iter().map(|c| (c.method, c.path.as_str())).collect();
        let base = "/namespaces/team%20a/plugins/alerting/api";
        assert_eq!(
            seen,
            [
                (Method::Get, format!("{base}/alerts").as_str()),
                (Method::Post, format!("{base}/alerts/f1/ack").as_str()),
                (Method::Post, format!("{base}/silences").as_str()),
                (Method::Delete, format!("{base}/silences/sil_1").as_str()),
                (Method::Post, format!("{base}/receivers/ops/test").as_str()),
            ]
        );
        assert_eq!(calls[1].body, Some(json!({"comment": "on it"})));
        assert_eq!(
            calls[2].body,
            Some(json!({"matchers": {"deployment": "web"}, "until": 99, "comment": ""}))
        );
    }
}
