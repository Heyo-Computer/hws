//! The ci plugin: a namespace's own CI on the region's shared ci service.
//!
//! ci is one service per region, run by the operator, and builds on heyvm
//! networks the operator owns. This plugin is how a tenant gets a slice of it.
//! The operator enables it with ci's URL, a reference to ci's
//! `CI_PLUGIN_API_TOKEN`, and the heyvm network tenant builds run on; each
//! namespace then *installs* it, which does two things:
//!
//! - ci admits that namespace. It reads `GET /api/plugins/ci` on every poll:
//!   the install list says which namespaces may register repositories and
//!   submit, and the configuration says which network their jobs are confined
//!   to. Neither is the tenant's to choose, which is why the install takes no
//!   configuration.
//! - The namespace gets `/namespaces/<ns>/plugins/ci/…`: ci's runs,
//!   repositories and live logs, narrowed to that namespace, through the
//!   shared [`NsProxy`]. ci records who did what from the actor headers the
//!   proxy sets, so the caller's identity reaches it without their credential.
//!
//! Unlike obs, ci does not install itself: a build is the right to run code
//! on the operator's hosts, so each namespace opts in.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::extract::Request;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::ns_proxy::{NsProxy, Upstream, check_url};
use super::{Plugin, PluginMeta};
use crate::secrets::{SecretRef, SecretStore};

const DEFAULT_POLL_SECS: u64 = 30;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CiConfig {
    /// ci's listener, e.g. `http://127.0.0.1:9500`.
    pub url: String,
    /// ci's `CI_PLUGIN_API_TOKEN`, as a reference into the secret store:
    /// `{"secret": "ci", "key": "plugin_api_token"}`. ci serves no namespace
    /// routes without one, so this is required.
    pub api_token: SecretRef,
    #[serde(default = "default_poll_secs")]
    pub poll_secs: u64,
    /// Install into every namespace automatically. Off unless the operator
    /// says otherwise; see the module docs.
    #[serde(default)]
    pub auto_install: bool,
    /// The heyvm network tenant jobs run on. ci refuses a tenant workflow
    /// that names any other, and refuses this one if it is its own default.
    pub tenant_network: String,
    /// A network of its own for a namespace that should not share
    /// `tenant_network` with the others.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub namespace_networks: BTreeMap<String, String>,
}

fn default_poll_secs() -> u64 {
    DEFAULT_POLL_SECS
}

/// What ci accepts as a network name; app-lb checks only that it could be one.
fn is_network_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn parse_config(config: &Value) -> Result<CiConfig, String> {
    let cfg: CiConfig = serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
    check_url(&cfg.url)?;
    if !(5..=3600).contains(&cfg.poll_secs) {
        return Err("poll_secs must be between 5 and 3600".into());
    }
    cfg.api_token
        .validate()
        .map_err(|e| format!("api_token: {e}"))?;
    if !is_network_name(&cfg.tenant_network) {
        return Err(format!(
            "tenant_network {:?} is not a network name",
            cfg.tenant_network
        ));
    }
    for (ns, net) in &cfg.namespace_networks {
        if !crate::config::is_valid_namespace(ns) {
            return Err(format!(
                "namespace_networks: {ns:?} is not a namespace name"
            ));
        }
        if !is_network_name(net) {
            return Err(format!(
                "namespace_networks.{ns}: {net:?} is not a network name"
            ));
        }
    }
    Ok(cfg)
}

pub struct CiPlugin {
    proxy: Arc<NsProxy>,
    tenant_network: std::sync::RwLock<Option<String>>,
}

impl CiPlugin {
    pub fn new(secrets: Arc<SecretStore>) -> Arc<Self> {
        Arc::new(Self {
            // ci has several pages, and records who registered a repository
            // or started a run.
            proxy: NsProxy::new("ci", "ci", secrets, true, true),
            tenant_network: std::sync::RwLock::new(None),
        })
    }
}

#[async_trait]
impl Plugin for CiPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "ci",
            name: "CI",
            description: "Builds, tests and releases for a namespace's repositories on the \
                 region's ci service. The operator points it at ci and picks the network tenant \
                 jobs run on; each namespace installs it to register repositories, mint submit \
                 tokens and follow its runs.",
            config_schema: json!({
                "type": "object",
                "required": ["url", "api_token", "tenant_network"],
                "properties": {
                    "url": {"type": "string", "description": "ci's listener, e.g. http://127.0.0.1:9500"},
                    "api_token": {
                        "type": "object",
                        "description": "A secret reference to CI_PLUGIN_API_TOKEN: {\"secret\": \"ci\", \"key\": \"plugin_api_token\"}.",
                        "required": ["secret"],
                        "properties": {"secret": {"type": "string"}, "key": {"type": "string"}}
                    },
                    "poll_secs": {"type": "integer", "minimum": 5, "maximum": 3600, "default": DEFAULT_POLL_SECS},
                    "auto_install": {"type": "boolean", "default": false, "description": "Install into every namespace automatically. Off by default: installing grants the right to run builds."},
                    "tenant_network": {"type": "string", "description": "The heyvm network tenant jobs run on. Must not be ci's own default network."},
                    "namespace_networks": {
                        "type": "object",
                        "description": "A network of its own for particular namespaces: {\"team-a\": \"tenants-team-a\"}.",
                        "additionalProperties": {"type": "string"}
                    }
                }
            }),
        }
    }

    fn validate(&self, config: &Value) -> Result<(), String> {
        parse_config(config).map(|_| ())
    }

    async fn apply(&self, config: Option<Value>) -> Result<(), String> {
        let Some(config) = config else {
            *self.tenant_network.write().unwrap() = None;
            return self.proxy.configure(None, Duration::ZERO).await;
        };
        let cfg = parse_config(&config)?;
        *self.tenant_network.write().unwrap() = Some(cfg.tenant_network.clone());
        self.proxy
            .configure(
                Some(Upstream {
                    url: cfg.url,
                    api_token: Some(cfg.api_token),
                }),
                Duration::from_secs(cfg.poll_secs),
            )
            .await
    }

    async fn status(&self) -> Value {
        let Some(up) = self.proxy.upstream() else {
            return json!({});
        };
        let health = self.proxy.health();
        json!({
            "url": up.url,
            "authenticated": up.api_token.is_some(),
            "tenant_network": self.tenant_network.read().unwrap().clone(),
            "up": health.up,
            "error": health.error,
            "polled_at": health.polled_at,
        })
    }

    fn per_namespace(&self) -> bool {
        true
    }

    fn auto_install(&self, config: &Value) -> bool {
        parse_config(config).is_ok_and(|c| c.auto_install)
    }

    fn validate_install(&self, _namespace: &str, config: &Value) -> Result<(), String> {
        match config {
            Value::Null => Ok(()),
            Value::Object(m) if m.is_empty() => Ok(()),
            _ => Err(
                "the ci plugin takes no per-namespace configuration; the operator sets a \
                 namespace's network in the fleet configuration's namespace_networks; send {}"
                    .into(),
            ),
        }
    }

    fn namespace_routes(self: Arc<Self>) -> Router {
        Router::new().fallback(proxy).with_state(self)
    }

    fn dashboard_path(&self) -> Option<&'static str> {
        Some("ui")
    }
}

async fn proxy(
    axum::extract::State(p): axum::extract::State<Arc<CiPlugin>>,
    req: Request,
) -> Response {
    p.proxy.forward(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::ns_proxy::NamespaceActor;
    use crate::plugins::{PluginHost, PluginStore};
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    fn secrets_with(token: &str) -> Arc<SecretStore> {
        let dir = std::env::temp_dir().join(format!("app-lb-ci-{}-{token}", std::process::id()));
        let store = Arc::new(SecretStore::new(dir.join("secrets.json"), None));
        store.put(crate::secrets::SecretSpec {
            id: "ci".into(),
            namespace: crate::config::DEFAULT_NAMESPACE.into(),
            description: None,
            data: [("plugin_api_token".to_string(), token.to_string())].into(),
            updated_at: 0,
        });
        store
    }

    /// A ci-shaped server: `/healthz` open, everything else behind the bearer,
    /// echoing what it was sent; a form post answers 303 to the repos page.
    async fn fake_ci(token: &str) -> String {
        let expected = format!("Bearer {token}");
        let app = Router::new().fallback(move |req: Request| {
            let expected = expected.clone();
            async move {
                if req.uri().path() == "/healthz" {
                    return "ok".into_response();
                }
                let auth = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if auth != expected {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                // Copied out: the request's body is not `Sync`, so nothing
                // may borrow the request across the await below.
                let headers = req.headers().clone();
                let h = |n: &str| {
                    headers
                        .get(n)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string)
                };
                let base = h("x-heyo-base").unwrap_or_default();
                if req.method() == axum::http::Method::POST {
                    let ct = h("content-type");
                    let body = axum::body::to_bytes(req.into_body(), 1 << 20)
                        .await
                        .unwrap();
                    assert_eq!(ct.as_deref(), Some("application/x-www-form-urlencoded"));
                    assert_eq!(&body[..], b"url=https%3A%2F%2Fgit.example%2Fa.git");
                    return (
                        StatusCode::SEE_OTHER,
                        [(header::LOCATION, format!("{base}/ui/repos"))],
                    )
                        .into_response();
                }
                axum::Json(json!({
                    "path": req.uri().path(),
                    "base": base,
                    "actor": h("x-heyo-actor"),
                    "admin": h("x-heyo-actor-admin"),
                }))
                .into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("app-lb-ci-host-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn configured(url: &str) -> Value {
        json!({
            "url": url,
            "api_token": {"secret": "ci", "key": "plugin_api_token"},
            "tenant_network": "tenants",
        })
    }

    #[test]
    fn a_config_is_checked_before_it_is_stored() {
        assert!(parse_config(&configured("http://127.0.0.1:9500")).is_ok());
        let mut with_ns = configured("http://127.0.0.1:9500");
        with_ns["namespace_networks"] = json!({"team-a": "tenants-a"});
        assert!(parse_config(&with_ns).is_ok());
        for bad in [
            json!({"url": "http://x", "tenant_network": "t"}),
            json!({"url": "http://x", "api_token": {"secret": "ci"}}),
            json!({"url": "ftp://x", "api_token": {"secret": "ci"}, "tenant_network": "t"}),
            json!({"url": "http://x", "api_token": {"secret": "ci"}, "tenant_network": "a b"}),
            json!({"url": "http://x", "api_token": {"secret": "ci"}, "tenant_network": "t",
                   "namespace_networks": {"Not A Namespace": "n"}}),
            json!({"url": "http://x", "api_token": {"secret": "ci"}, "tenant_network": "t",
                   "network": "fleet"}),
        ] {
            assert!(parse_config(&bad).is_err(), "accepted {bad}");
        }
        assert!(!CiPlugin::new(secrets_with("x")).auto_install(&configured("http://x")));
    }

    async fn call(
        host: &PluginHost,
        ns: &str,
        req: axum::http::Request<axum::body::Body>,
    ) -> Response {
        host.dispatch_namespace("ci", ns, req).await
    }

    #[tokio::test]
    async fn a_namespace_reads_and_acts_through_the_proxy_once_installed() {
        let url = fake_ci("ci-svc").await;
        let dir = TempDir::new("flow");
        let plugin = CiPlugin::new(secrets_with("ci-svc"));
        let host = PluginHost::new(vec![plugin.clone()], PluginStore::new(&dir.0));
        host.set("ci", true, Some(configured(&url))).await.unwrap();
        assert!(
            host.auto_install("team-a", None).await.is_empty(),
            "ci is opt-in per namespace"
        );
        assert!(
            host.install("ci", "team-a", json!({"network": "fleet"}), None)
                .await
                .is_err(),
            "a namespace cannot pick its network"
        );
        host.install("ci", "team-a", json!({}), None).await.unwrap();
        assert_eq!(
            host.namespace_plugin("ci", "team-a").unwrap().dashboard,
            Some("ui")
        );
        assert_eq!(plugin.status().await["tenant_network"], "tenants");

        let get = |uri: &str| {
            let mut r = axum::http::Request::get(uri)
                .body(axum::body::Body::empty())
                .unwrap();
            r.extensions_mut().insert(NamespaceActor {
                principal: Some("user:u1".into()),
                email: None,
                admin: false,
            });
            r
        };
        let resp = call(&host, "team-a", get("/ui/runs/42/jobs/build")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["path"], "/ns/team-a/runs/42/jobs/build");
        assert_eq!(v["base"], "/namespaces/team-a/plugins/ci");
        assert_eq!(v["actor"], "user:u1");
        assert_eq!(v["admin"], "false");

        let post = axum::http::Request::post("/ui/repos")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(
                "url=https%3A%2F%2Fgit.example%2Fa.git",
            ))
            .unwrap();
        let resp = call(&host, "team-a", post).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers()["location"],
            "/namespaces/team-a/plugins/ci/ui/repos"
        );

        // Not installed elsewhere, and nothing climbs out of the namespace.
        let resp = call(&host, "team-b", get("/ui")).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let resp = call(&host, "team-a", get("/ui/../../vms")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        plugin.apply(None).await.unwrap();
    }

    #[tokio::test]
    async fn a_wrong_stored_token_is_a_bad_gateway() {
        let url = fake_ci("ci-right").await;
        let dir = TempDir::new("wrong");
        let plugin = CiPlugin::new(secrets_with("ci-wrong"));
        let host = PluginHost::new(vec![plugin.clone()], PluginStore::new(&dir.0));
        host.set("ci", true, Some(configured(&url))).await.unwrap();
        host.install("ci", "a", json!({}), None).await.unwrap();
        let req = axum::http::Request::get("/api/runs")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            call(&host, "a", req).await.status(),
            StatusCode::BAD_GATEWAY
        );
        plugin.apply(None).await.unwrap();
    }
}
