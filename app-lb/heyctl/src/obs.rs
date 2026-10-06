//! Namespace plugins, and the telemetry the `obs` plugin collects.
//!
//! # Installing a plugin into a namespace
//!
//! Some of app-lb's plugins install per namespace rather than fleet-wide. The
//! operator switches one on for the fleet ([`Client::set_plugin`]); a namespace
//! administrator then installs it into their namespace
//! ([`Client::install_plugin`]). It does nothing for a namespace unless both
//! have happened, and [`Client::namespace_plugins`] shows each half.
//!
//! # Telemetry
//!
//! Installing `obs` into a namespace makes app-obs collect metrics and logs
//! for every deployment in it. A namespace-scoped credential then reads them
//! through app-lb with [`Client::obs`] — app-lb checks the caller reaches the
//! namespace, and talks to app-obs on the caller's behalf with app-obs's own
//! credential, so nothing here needs to know where app-obs lives.
//!
//! ```no_run
//! # async fn f() -> hws::Result<()> {
//! use hws::{Client, LogQuery};
//!
//! let lb = Client::builder("https://admin.example.com")
//!     .token(std::env::var("APP_LB_TOKEN").unwrap())
//!     .build()?;
//!
//! lb.install_plugin("team-a", "obs", None).await?;
//!
//! let obs = lb.obs("team-a");
//! for row in obs.fleet(Some("1h")).await?.deployments {
//!     println!("{}: {} log lines, {} errors", row.id, row.log_lines, row.error_logs);
//! }
//! let page = obs.logs("web", &LogQuery::new().level("error").limit(50)).await?;
//! for line in page.rows {
//!     println!("{} {}", line.ts, line.message);
//! }
//! # Ok(()) }
//! ```

use crate::api::{Client, Raw, seg};
use crate::error::Result;
use crate::transport::{Method, Request};
use crate::types::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// The plugin id of the telemetry plugin.
pub const OBS_PLUGIN: &str = "obs";

impl Client {
    /// `GET /namespaces/:ns/plugins` — the plugins that install per namespace,
    /// and whether each is switched on for the fleet and installed here.
    pub async fn namespace_plugins(&self, namespace: &str) -> Result<Vec<NamespacePlugin>> {
        self.read(
            Request::new(
                Method::Get,
                format!("/namespaces/{}/plugins", seg(namespace)),
            ),
            "namespace",
            namespace,
        )
        .await
    }

    /// `PUT /namespaces/:ns/plugins/:id` — install a plugin into a namespace,
    /// or replace its per-namespace configuration. Idempotent.
    ///
    /// Needs `admin` over the whole namespace. Fails with
    /// [`crate::Error::Conflict`] while the operator has the plugin switched
    /// off for the fleet.
    pub async fn install_plugin(
        &self,
        namespace: &str,
        id: &str,
        config: Option<&Value>,
    ) -> Result<NamespacePlugin> {
        let mut body = json!({});
        if let Some(c) = config {
            body["config"] = c.clone();
        }
        self.read(
            Request::new(
                Method::Put,
                format!("/namespaces/{}/plugins/{}", seg(namespace), seg(id)),
            )
            .json(body),
            "plugin",
            id,
        )
        .await
    }

    /// `DELETE /namespaces/:ns/plugins/:id` — uninstall. For `obs` this stops
    /// collection for the namespace; what was already collected ages out with
    /// app-obs's retention.
    pub async fn uninstall_plugin(&self, namespace: &str, id: &str) -> Result<NamespacePlugin> {
        self.read(
            Request::new(
                Method::Delete,
                format!("/namespaces/{}/plugins/{}", seg(namespace), seg(id)),
            ),
            "plugin",
            id,
        )
        .await
    }

    /// `GET /api/plugins/:id/installs` — every namespace a plugin is installed
    /// in. Fleet scope only.
    pub async fn plugin_installs(&self, id: &str) -> Result<PluginInstalls> {
        self.read(
            Request::new(Method::Get, format!("/api/plugins/{}/installs", seg(id))),
            "plugin",
            id,
        )
        .await
    }

    /// The telemetry of one namespace, read through app-lb's `obs` plugin.
    ///
    /// Cheap: it borrows nothing and makes no request until a method is
    /// called.
    pub fn obs(&self, namespace: impl Into<String>) -> ObsClient {
        ObsClient {
            client: self.clone(),
            namespace: namespace.into(),
        }
    }
}

/// One namespace's telemetry. See [`Client::obs`].
///
/// Every method answers [`crate::Error::Conflict`] when the `obs` plugin is
/// not installed in the namespace (or is switched off for the fleet); the
/// error's message says which, and how to fix it.
#[derive(Debug, Clone)]
pub struct ObsClient {
    client: Client,
    namespace: String,
}

impl ObsClient {
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    fn path(&self, rest: &str) -> String {
        format!(
            "/namespaces/{}/plugins/{OBS_PLUGIN}/api/{rest}",
            seg(&self.namespace)
        )
    }

    /// Every deployment in the namespace that has telemetry in `window`
    /// (`15m`, `1h`, `6h`, `1d`, `7d`, … — `None` is the server's default),
    /// with a coarse series and log counts per deployment.
    pub async fn fleet(&self, window: Option<&str>) -> Result<ObsFleet> {
        self.fleet_as(window).await
    }

    async fn fleet_as<T: DeserializeOwned>(&self, window: Option<&str>) -> Result<T> {
        let path = match window {
            Some(w) => self.path(&format!("fleet?window={}", seg(w))),
            None => self.path("fleet"),
        };
        self.client
            .read(
                Request::new(Method::Get, path),
                "namespace",
                &self.namespace,
            )
            .await
    }

    /// One deployment's metrics and log volume over `window`.
    ///
    /// A deployment outside this namespace is a [`crate::Error::NotFound`],
    /// exactly as one that does not exist.
    pub async fn deployment(&self, id: &str, window: Option<&str>) -> Result<ObsDeployment> {
        self.deployment_as(id, window).await
    }

    async fn deployment_as<T: DeserializeOwned>(
        &self,
        id: &str,
        window: Option<&str>,
    ) -> Result<T> {
        let mut path = self.path(&format!("deployments/{}", seg(id)));
        if let Some(w) = window {
            path.push_str(&format!("?window={}", seg(w)));
        }
        self.client
            .read(Request::new(Method::Get, path), "deployment", id)
            .await
    }

    /// One page of a deployment's logs, newest first.
    ///
    /// To page back, pass [`ObsLogs::next_before_ms`] as
    /// [`LogQuery::before`] until it comes back `None`.
    pub async fn logs(&self, id: &str, query: &LogQuery) -> Result<ObsLogs> {
        self.logs_as(id, query).await
    }

    async fn logs_as<T: DeserializeOwned>(&self, id: &str, query: &LogQuery) -> Result<T> {
        let path = format!(
            "{}{}",
            self.path(&format!("deployments/{}/logs", seg(id))),
            query.to_query_string()
        );
        self.client
            .read(Request::new(Method::Get, path), "deployment", id)
            .await
    }

    /// The namespace's alert rules.
    pub async fn alerts(&self) -> Result<Vec<ObsAlert>> {
        self.alerts_as().await
    }

    async fn alerts_as<T: DeserializeOwned>(&self) -> Result<T> {
        self.client
            .read(Request::new(Method::Get, self.path("alerts")), "alert", "")
            .await
    }

    /// Create an alert rule: POST `webhook_url` whenever `deployment` logs
    /// more than `threshold` errors in a minute. Needs `admin` in the
    /// namespace.
    pub async fn create_alert(&self, alert: &NewAlert) -> Result<ObsAlert> {
        let mut body = json!({
            "deployment": alert.deployment,
            "threshold": alert.threshold,
            "webhook_url": alert.webhook_url,
        });
        if let Some(m) = &alert.metric {
            body["metric"] = json!(m);
        }
        self.client
            .read(
                Request::new(Method::Post, self.path("alerts")).json(body),
                "alert",
                &alert.deployment,
            )
            .await
    }

    /// Delete an alert rule. Deleting one that does not exist succeeds.
    pub async fn delete_alert(&self, id: &str) -> Result<()> {
        self.client
            .unit(
                Request::new(Method::Delete, self.path(&format!("alerts/{}", seg(id)))),
                "alert",
                id,
            )
            .await
    }
}

/// The same reads, unparsed — for printing a response without losing what
/// this build does not name. See [`Client::raw`].
impl Raw<'_> {
    pub async fn namespace_plugins(&self, namespace: &str) -> Result<Value> {
        self.0
            .read(
                Request::new(
                    Method::Get,
                    format!("/namespaces/{}/plugins", seg(namespace)),
                ),
                "namespace",
                namespace,
            )
            .await
    }

    pub async fn plugin_installs(&self, id: &str) -> Result<Value> {
        self.0
            .read(
                Request::new(Method::Get, format!("/api/plugins/{}/installs", seg(id))),
                "plugin",
                id,
            )
            .await
    }

    pub async fn obs_fleet(&self, namespace: &str, window: Option<&str>) -> Result<Value> {
        self.0.obs(namespace).fleet_as(window).await
    }

    pub async fn obs_deployment(
        &self,
        namespace: &str,
        id: &str,
        window: Option<&str>,
    ) -> Result<Value> {
        self.0.obs(namespace).deployment_as(id, window).await
    }

    pub async fn obs_logs(&self, namespace: &str, id: &str, query: &LogQuery) -> Result<Value> {
        self.0.obs(namespace).logs_as(id, query).await
    }

    pub async fn obs_alerts(&self, namespace: &str) -> Result<Value> {
        self.0.obs(namespace).alerts_as().await
    }
}

/// Which log lines [`ObsClient::logs`] returns. Every filter is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogQuery {
    pub window: Option<String>,
    /// Range start, epoch milliseconds. Overrides `window`'s start.
    pub from: Option<i64>,
    /// Range end, epoch milliseconds.
    pub to: Option<i64>,
    pub level: Option<String>,
    /// One VM (sandbox id) or upstream.
    pub backend: Option<String>,
    /// Case-insensitive substring of the message.
    pub search: Option<String>,
    pub limit: Option<usize>,
    /// Page boundary, epoch milliseconds, inclusive. See
    /// [`ObsLogs::next_before_ms`].
    pub before: Option<i64>,
}

impl LogQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn window(mut self, w: impl Into<String>) -> Self {
        self.window = Some(w.into());
        self
    }

    pub fn from(mut self, ms: i64) -> Self {
        self.from = Some(ms);
        self
    }

    pub fn to(mut self, ms: i64) -> Self {
        self.to = Some(ms);
        self
    }

    pub fn level(mut self, level: impl Into<String>) -> Self {
        self.level = Some(level.into());
        self
    }

    pub fn backend(mut self, backend: impl Into<String>) -> Self {
        self.backend = Some(backend.into());
        self
    }

    pub fn search(mut self, text: impl Into<String>) -> Self {
        self.search = Some(text.into());
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    pub fn before(mut self, ms: i64) -> Self {
        self.before = Some(ms);
        self
    }

    /// `?window=…&level=…`, or empty when nothing is set.
    pub fn to_query_string(&self) -> String {
        let mut q: Vec<String> = Vec::new();
        let mut text = |k: &str, v: &Option<String>| {
            if let Some(v) = v.as_deref().filter(|v| !v.is_empty()) {
                q.push(format!("{k}={}", seg(v)));
            }
        };
        text("window", &self.window);
        text("level", &self.level);
        text("backend", &self.backend);
        text("q", &self.search);
        for (k, v) in [
            ("from", self.from),
            ("to", self.to),
            ("before", self.before),
        ] {
            if let Some(v) = v {
                q.push(format!("{k}={v}"));
            }
        }
        if let Some(n) = self.limit {
            q.push(format!("limit={n}"));
        }
        if q.is_empty() {
            String::new()
        } else {
            format!("?{}", q.join("&"))
        }
    }
}

/// The body of [`ObsClient::create_alert`].
#[derive(Debug, Clone, PartialEq)]
pub struct NewAlert {
    pub deployment: String,
    pub threshold: f64,
    pub webhook_url: String,
    /// `errors` when `None` — currently the only metric.
    pub metric: Option<String>,
}

impl NewAlert {
    pub fn errors(
        deployment: impl Into<String>,
        threshold: f64,
        webhook_url: impl Into<String>,
    ) -> Self {
        Self {
            deployment: deployment.into(),
            threshold,
            webhook_url: webhook_url.into(),
            metric: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::stub::Stub;
    use std::sync::Arc;

    fn client(stub: Stub) -> (Client, Arc<Stub>) {
        let stub = Arc::new(stub);
        (Client::with_transport(stub.clone()), stub)
    }

    #[test]
    fn a_log_query_encodes_only_what_is_set() {
        assert_eq!(LogQuery::new().to_query_string(), "");
        assert_eq!(
            LogQuery::new()
                .window("1h")
                .level("error")
                .search("disk full")
                .before(1_700_000_000_000)
                .limit(50)
                .to_query_string(),
            "?window=1h&level=error&q=disk%20full&before=1700000000000&limit=50"
        );
        assert_eq!(
            LogQuery::new().level("").to_query_string(),
            "",
            "a cleared filter is no filter"
        );
    }

    #[tokio::test]
    async fn telemetry_is_read_through_the_namespace_plugin_prefix() {
        let (c, stub) = client(
            Stub::new()
                .json(
                    200,
                    json!({"window": "1h", "deployments": [{"id": "web", "log_lines": 3}]}),
                )
                .json(
                    200,
                    json!({"id": "web", "rows": [{"ts": 1, "message": "hi", "source": "stdout"}],
                    "next_before_ms": null, "limit": 50}),
                )
                .json(
                    201,
                    json!({"id": "a1", "deployment": "web", "metric": "errors",
                    "threshold": 0.0, "webhook_url": "https://hook", "namespace": "team a"}),
                )
                .reply(204, ""),
        );
        let obs = c.obs("team a");
        let fleet = obs.fleet(Some("1h")).await.unwrap();
        assert_eq!(fleet.deployments[0].id, "web");
        assert_eq!(fleet.deployments[0].log_lines, 3);
        let logs = obs.logs("web", &LogQuery::new().limit(50)).await.unwrap();
        assert_eq!(logs.rows[0].message, "hi");
        assert!(logs.next_before_ms.is_none());
        let alert = obs
            .create_alert(&NewAlert::errors("web", 0.0, "https://hook"))
            .await
            .unwrap();
        assert_eq!(alert.namespace.as_deref(), Some("team a"));
        obs.delete_alert("a1").await.unwrap();

        let paths: Vec<String> = stub.calls().into_iter().map(|s| s.path).collect();
        assert_eq!(
            paths,
            [
                "/namespaces/team%20a/plugins/obs/api/fleet?window=1h",
                "/namespaces/team%20a/plugins/obs/api/deployments/web/logs?limit=50",
                "/namespaces/team%20a/plugins/obs/api/alerts",
                "/namespaces/team%20a/plugins/obs/api/alerts/a1",
            ]
        );
        assert_eq!(
            stub.calls()[2].body,
            Some(json!({"deployment": "web", "threshold": 0.0, "webhook_url": "https://hook"}))
        );
    }

    #[tokio::test]
    async fn not_installed_is_a_conflict_that_says_how_to_install() {
        let (c, _) = client(Stub::new().json(
            409,
            json!({"error": "the obs plugin is not installed in namespace \"a\"; install it with `heyctl plugins install obs -n a`",
                "code": "plugin_not_installed"}),
        ));
        let e = c.obs("a").fleet(None).await.unwrap_err();
        assert!(matches!(e, crate::Error::Conflict { .. }), "{e:?}");
        assert!(
            e.to_string().contains("heyctl plugins install obs -n a"),
            "{e}"
        );
    }

    #[tokio::test]
    async fn install_and_uninstall_address_the_namespace_route() {
        let (c, stub) = client(
            Stub::new()
                .json(
                    200,
                    json!({"id": "obs", "enabled": true, "installed": true, "installed_at": 5}),
                )
                .json(
                    200,
                    json!({"id": "obs", "enabled": true, "installed": false}),
                ),
        );
        let p = c.install_plugin("a", "obs", None).await.unwrap();
        assert!(p.installed && p.enabled);
        let p = c.uninstall_plugin("a", "obs").await.unwrap();
        assert!(!p.installed);
        let calls = stub.calls();
        assert_eq!(calls[0].method, Method::Put);
        assert_eq!(calls[0].path, "/namespaces/a/plugins/obs");
        assert_eq!(calls[0].body, Some(json!({})));
        assert_eq!(calls[1].method, Method::Delete);
        assert_eq!(calls[1].path, "/namespaces/a/plugins/obs");
    }
}
