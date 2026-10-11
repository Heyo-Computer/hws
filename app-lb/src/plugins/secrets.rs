//! The secrets plugin: a namespace's own secrets, in the plugin console.
//!
//! app-lb already keeps a secret store walled by namespace — the one a
//! deployment's `env_from` and git credential read, and the one tenant CI
//! reads its workflow secrets from (see [`super::ci`]). The admin API's
//! `/secrets?namespace=<ns>` routes let a namespace's own administrator manage
//! it, but nothing put a page on it. This plugin is that page and nothing
//! more: it has no storage and no upstream, and the page drives the existing
//! routes with the caller's own session, so the namespace wall and the tier
//! split (`GET /secrets` lists key names, never values; every change needs
//! admin) are decided exactly where they always were.
//!
//! It installs itself in every namespace unless the operator says otherwise:
//! installing grants nothing the namespace's credentials could not already do
//! through the API.

use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::ns_proxy::fail;
use crate::secrets::SecretStore;
use super::{NamespaceScope, Plugin, PluginMeta};

pub(crate) const PAGE_HTML: &str = include_str!("../secrets_plugin.html");

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// Install into every namespace automatically. On unless the operator
    /// says otherwise; see the module docs.
    #[serde(default = "default_auto_install")]
    pub auto_install: bool,
}

fn default_auto_install() -> bool {
    true
}

fn parse_config(config: &Value) -> Result<SecretsConfig, String> {
    // A plugin switched on with no configuration at all is the common case.
    let config = if config.is_null() {
        json!({})
    } else {
        config.clone()
    };
    serde_json::from_value(config).map_err(|e| e.to_string())
}

pub struct SecretsPlugin {
    secrets: Arc<SecretStore>,
}

impl SecretsPlugin {
    pub fn new(secrets: Arc<SecretStore>) -> Arc<Self> {
        Arc::new(Self { secrets })
    }
}

#[async_trait]
impl Plugin for SecretsPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "secrets",
            name: "Secrets",
            description: "A page for a namespace's own secrets: the store deployments' env_from, \
                 git credentials and tenant CI read. Lists key names, never values; a namespace \
                 admin creates, rotates and deletes.",
            config_schema: json!({
                "type": "object",
                "properties": {
                    "auto_install": {"type": "boolean", "default": true, "description": "Install into every namespace automatically; a namespace that uninstalls is left alone."}
                }
            }),
        }
    }

    fn validate(&self, config: &Value) -> Result<(), String> {
        parse_config(config).map(|_| ())
    }

    async fn apply(&self, config: Option<Value>) -> Result<(), String> {
        // Nothing runs: the page is the whole plugin.
        if let Some(config) = config {
            parse_config(&config)?;
        }
        Ok(())
    }

    async fn status(&self) -> Value {
        json!({})
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
            _ => Err("the secrets plugin takes no per-namespace configuration; send {}".into()),
        }
    }

    fn namespace_routes(self: Arc<Self>) -> Router {
        Router::new()
            .route("/ui", get(ui))
            .route("/api/secrets", get(list_secrets))
            .fallback(|| async {
                fail(StatusCode::NOT_FOUND, "no secrets plugin route here")
            })
            .with_state(self)
    }

    fn dashboard_path(&self) -> Option<&'static str> {
        Some("ui")
    }
}

/// `GET …/secrets/api/secrets` — this namespace's secrets: ids, descriptions
/// and key names, never values.
///
/// On the namespace surface, so it is view tier: the admin API's `GET
/// /secrets` is CRUD tier for the whole fleet, and lowering it would show every
/// fleet view token every namespace's secret names. Here a caller sees only the
/// namespace the gate already admitted it to.
async fn list_secrets(State(p): State<Arc<SecretsPlugin>>, req: Request) -> Response {
    let Some(NamespaceScope(ns)) = req.extensions().get::<NamespaceScope>().cloned() else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "no namespace on this request");
    };
    let mut out = axum::Json(p.secrets.list(Some(&ns))).into_response();
    out.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    out
}

/// `GET …/secrets/ui` — the page.
async fn ui(req: Request) -> Response {
    match req.extensions().get::<NamespaceScope>() {
        Some(NamespaceScope(ns)) => super::page(PAGE_HTML, ns, &req),
        None => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no namespace scope on the request",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{PluginHost, PluginStore};

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "app-lb-secrets-plugin-{}-{tag}",
                std::process::id()
            ));
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

    #[test]
    fn a_config_is_checked_before_it_is_stored() {
        let p = SecretsPlugin::new(Arc::new(SecretStore::new(std::env::temp_dir().join("app-lb-secrets-plugin-unused.json"), None)));
        assert!(p.validate(&json!({})).is_ok());
        assert!(p.validate(&Value::Null).is_ok());
        assert!(p.auto_install(&json!({})), "on by default");
        assert!(!p.auto_install(&json!({"auto_install": false})));
        assert!(p.validate(&json!({"store": "elsewhere"})).is_err());
        assert!(p.validate_install("a", &json!({"x": 1})).is_err());
    }

    #[tokio::test]
    async fn it_installs_itself_and_serves_its_page_for_the_namespace() {
        let dir = TempDir::new("page");
        let store = Arc::new(SecretStore::new(dir.0.join("secrets.json"), None));
        let host = PluginHost::new(vec![SecretsPlugin::new(store)], PluginStore::new(&dir.0));
        host.set("secrets", true, Some(json!({}))).await.unwrap();
        assert_eq!(host.auto_install("team-a", None).await, vec!["secrets"]);

        let get = |uri: &str| {
            axum::http::Request::get(uri)
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let resp = host
            .dispatch_namespace("secrets", "team-a", get("/ui"))
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        for (h, v) in [
            ("x-frame-options", "SAMEORIGIN"),
            ("cache-control", "no-store"),
            ("x-content-type-options", "nosniff"),
        ] {
            assert_eq!(resp.headers()[h], v);
        }
        let html = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = String::from_utf8_lossy(&html);
        assert!(html.contains(r#"<meta name="plugin-namespace" content="team-a">"#));
        assert!(!html.contains("{{"), "an unfilled placeholder shipped");

        let resp = host
            .dispatch_namespace("secrets", "team-a", get("/api/x"))
            .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = host
            .dispatch_namespace("secrets", "team-b", get("/ui"))
            .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "not installed there");
    }
}
