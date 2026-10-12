//! The artifacts plugin: the global artifact store, and each namespace's
//! corner of it.
//!
//! An `art serve` store holds one shared key that reads and writes every
//! namespace's images, so app-lb keeps the key and puts a namespace wall in
//! front of it ([`crate::store_gateway`]). This plugin is how the operator
//! says which store that is, and how a namespace gets the API:
//!
//! - **Fleet configuration** names the store: `url`, and `api_key` as a
//!   reference into the secret store. Both are optional and default to
//!   `APP_LB_ARTIFACT_STORE` and `APP_LB_ARTIFACT_STORE_API_KEY`, so on a host
//!   already configured that way enabling the plugin with `{}` changes nothing
//!   but where the setting lives. Disabling it falls back to the environment.
//! - **The namespace surface**, `/namespaces/<ns>/plugins/artifacts/api/…`,
//!   is the store's own paths (`tags`, `manifests`, `blobs`, `repos`) confined
//!   to `<ns>/`, exactly as `/namespaces/<ns>/artifacts/…`, which stays for
//!   the clients that predate the plugin. Publishing needs `admin` over the
//!   whole namespace.
//!
//! Pulls of a storeless `artifact` block use whichever store is current
//! whether or not the deployment's namespace installed the plugin: the store
//! is where images come from, and a namespace that uninstalls it keeps
//! booting what it already deploys. It installs itself unless the operator
//! says otherwise.

use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::ns_proxy::{NamespaceActor, fail};
use super::{NamespaceScope, Plugin, PluginMeta};
use crate::secrets::{SecretRef, SecretStore};
use crate::store_gateway::{GlobalStore, KEY_ENV, STORE_ENV, StoreSlot};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactsConfig {
    /// The store, e.g. `https://art.us2.heyo.work`. Defaults to
    /// `APP_LB_ARTIFACT_STORE`.
    #[serde(default)]
    pub url: Option<String>,
    /// The store's `ART_API_KEY`, as a secret reference. Defaults to
    /// `APP_LB_ARTIFACT_STORE_API_KEY` when `url` is (or defaults to) that
    /// same store; without either the store is used anonymously: public
    /// repositories pull, and nothing can be published.
    #[serde(default)]
    pub api_key: Option<SecretRef>,
    /// Install into every namespace automatically.
    #[serde(default = "default_auto_install")]
    pub auto_install: bool,
}

fn default_auto_install() -> bool {
    true
}

fn parse_config(config: &Value) -> Result<ArtifactsConfig, String> {
    let cfg: ArtifactsConfig = match config {
        Value::Null => ArtifactsConfig {
            auto_install: true,
            ..Default::default()
        },
        v => serde_json::from_value(v.clone()).map_err(|e| e.to_string())?,
    };
    if let Some(url) = &cfg.url {
        GlobalStore::new(url, None).map_err(|e| e.replace(STORE_ENV, "url"))?;
    }
    if let Some(key) = &cfg.api_key {
        key.validate().map_err(|e| format!("api_key: {e}"))?;
    }
    Ok(cfg)
}

pub struct ArtifactsPlugin {
    secrets: Arc<SecretStore>,
    slot: Arc<StoreSlot>,
}

impl ArtifactsPlugin {
    pub fn new(secrets: Arc<SecretStore>, slot: Arc<StoreSlot>) -> Arc<Self> {
        Arc::new(Self { secrets, slot })
    }

    /// The store `cfg` describes, with its defaults filled from the
    /// environment.
    fn store_for(&self, cfg: &ArtifactsConfig) -> Result<GlobalStore, String> {
        let env = self.slot.env();
        let url = match (&cfg.url, env) {
            (Some(u), _) => u.clone(),
            (None, Some(e)) => e.base().to_string(),
            (None, None) => {
                return Err(format!(
                    "no store: set `url` in the plugin's configuration, or {STORE_ENV} on this host"
                ));
            }
        };
        let key = match &cfg.api_key {
            Some(r) => Some(
                self.secrets
                    .resolve(r)
                    .map_err(|e| format!("api_key: {e}"))?,
            ),
            None => env
                .filter(|e| e.is_this(&url))
                .and_then(GlobalStore::key)
                .map(str::to_string),
        };
        GlobalStore::new(&url, key)
    }
}

#[async_trait]
impl Plugin for ArtifactsPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "artifacts",
            name: "Artifacts",
            description: "The global artifact store: where a deployment's `artifact` images come \
                 from, and each namespace's own tags, manifests, blobs and repositories in it, \
                 walled to `<namespace>/`. The operator names the store (by default the one \
                 APP_LB_ARTIFACT_STORE names); each namespace gets it installed.",
            config_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": format!("The store, e.g. https://art.us2.heyo.work. Defaults to {STORE_ENV}.")},
                    "api_key": {
                        "type": "object",
                        "description": format!("A secret reference to the store's ART_API_KEY: {{\"secret\": \"artifact-store\", \"key\": \"api-key\"}}. Defaults to {KEY_ENV} for that same store; without one the store is read-only."),
                        "required": ["secret"],
                        "properties": {"secret": {"type": "string"}, "key": {"type": "string"}}
                    },
                    "auto_install": {"type": "boolean", "default": true, "description": "Install into every namespace automatically (new ones as they appear, existing ones when switched on); a namespace that uninstalls is left alone."}
                }
            }),
        }
    }

    fn validate(&self, config: &Value) -> Result<(), String> {
        parse_config(config).map(|_| ())
    }

    async fn apply(&self, config: Option<Value>) -> Result<(), String> {
        let Some(config) = config else {
            self.slot.set_plugin(None);
            return Ok(());
        };
        let cfg = parse_config(&config)?;
        match self.store_for(&cfg) {
            Ok(store) => {
                tracing::info!(
                    store = store.base(),
                    key = store.has_key(),
                    "artifacts plugin: global artifact store"
                );
                self.slot.set_plugin(Some(Arc::new(store)));
                Ok(())
            }
            Err(e) => {
                // Leave the environment's store in force rather than none.
                self.slot.set_plugin(None);
                Err(e)
            }
        }
    }

    async fn status(&self) -> Value {
        let current = self.slot.current();
        json!({
            "source": self.slot.source(),
            "url": current.as_ref().map(|s| s.base()),
            "writable": current.as_ref().is_some_and(|s| s.has_key()),
            "env_url": self.slot.env().map(GlobalStore::base),
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
            _ => Err("the artifacts plugin takes no per-namespace configuration; send {}".into()),
        }
    }

    fn namespace_routes(self: Arc<Self>) -> Router {
        Router::new()
            .route("/api", axum::routing::get(info))
            .fallback(api)
            .with_state(self)
    }
}

#[allow(clippy::result_large_err)]
fn scope(req: &Request) -> Result<String, Response> {
    req.extensions()
        .get::<NamespaceScope>()
        .map(|s| s.0.clone())
        .ok_or_else(|| {
            fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "no namespace scope on the request",
            )
        })
}

/// `GET …/artifacts/api` — see [`crate::store_gateway::describe`].
async fn info(State(p): State<Arc<ArtifactsPlugin>>, req: Request) -> Response {
    match scope(&req) {
        Ok(ns) => crate::store_gateway::describe(&ns, p.slot.current().as_deref()),
        Err(r) => r,
    }
}

/// `…/artifacts/api/{tags,manifests,blobs,repos}/…` — the namespace's corner
/// of the store. Reads on the view tier; anything else needs `admin` over the
/// whole namespace, as on `/namespaces/:name/artifacts`.
async fn api(State(p): State<Arc<ArtifactsPlugin>>, req: Request) -> Response {
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let Some(rest) = req.uri().path().strip_prefix("/api/") else {
        return fail(
            StatusCode::NOT_FOUND,
            "the artifacts API is under …/plugins/artifacts/api/",
        );
    };
    // Decoded, as axum hands `/namespaces/:name/artifacts/*rest` its path,
    // so `web%3Av1` and `web:v1` are the same tag to the wall.
    let Some(rest) = crate::site::percent_decode(rest) else {
        return fail(
            StatusCode::BAD_REQUEST,
            "malformed percent-encoding in the path",
        );
    };
    let Ok(method) = reqwest::Method::from_bytes(req.method().as_str().as_bytes()) else {
        return fail(StatusCode::METHOD_NOT_ALLOWED, "unsupported method");
    };
    let read = method == reqwest::Method::GET || method == reqwest::Method::HEAD;
    if !read
        && !req
            .extensions()
            .get::<NamespaceActor>()
            .is_some_and(|a| a.admin)
    {
        return fail(
            StatusCode::FORBIDDEN,
            format!("publishing artifacts needs an admin credential for all of namespace \"{ns}\""),
        );
    }
    let (parts, body) = req.into_parts();
    let body = (!read).then_some(body);
    crate::store_gateway::serve(p.slot.current(), &ns, &rest, method, &parts.headers, body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{PluginHost, PluginStore};
    use axum::http::header;
    use axum::response::IntoResponse;
    use std::sync::Mutex;

    const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("app-lb-artifacts-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn secrets(d: &std::path::Path) -> Arc<SecretStore> {
        let store = Arc::new(SecretStore::new(d.join("secrets.json"), None));
        store.put(crate::secrets::SecretSpec {
            id: "artifact-store".into(),
            namespace: crate::config::DEFAULT_NAMESPACE.into(),
            description: None,
            data: [("api-key".to_string(), "plugin-key".to_string())].into(),
            updated_at: 0,
        });
        store
    }

    /// A store that records what reached it and with which key.
    async fn fake_store() -> (String, Arc<Mutex<Vec<String>>>) {
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let log = seen.clone();
        let app = Router::new().fallback(move |req: Request| {
            let log = log.clone();
            async move {
                let auth = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-")
                    .to_string();
                log.lock()
                    .unwrap()
                    .push(format!("{} {} {auth}", req.method(), req.uri().path()));
                match req.uri().path() {
                    "/tags" => axum::Json(json!([
                        {"tag": "team-a/web:v1", "digest": D},
                        {"tag": "team-b/web:v1", "digest": D},
                    ]))
                    .into_response(),
                    _ => StatusCode::NO_CONTENT.into_response(),
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), seen)
    }

    async fn call(
        host: &PluginHost,
        ns: &str,
        method: &str,
        uri: &str,
        admin: bool,
    ) -> (StatusCode, Value) {
        let mut req = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .body(axum::body::Body::from(D))
            .unwrap();
        req.extensions_mut().insert(NamespaceActor {
            principal: None,
            email: None,
            admin,
        });
        let resp = host.dispatch_namespace("artifacts", ns, req).await;
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[test]
    fn a_config_is_checked_before_it_is_stored() {
        assert!(parse_config(&json!({})).is_ok());
        assert!(parse_config(&Value::Null).is_ok());
        assert!(parse_config(&json!({"url": "https://art.example.com"})).is_ok());
        assert!(
            parse_config(&json!({"url": "http://art.example.com"})).is_err(),
            "the key must not travel in plaintext"
        );
        assert!(parse_config(&json!({"api_key": {"secret": ""}})).is_err());
        assert!(parse_config(&json!({"bucket": "x"})).is_err());
    }

    #[tokio::test]
    async fn empty_config_adopts_the_environments_store_and_key() {
        let d = dir("env");
        let slot = Arc::new(StoreSlot::new(Some(
            GlobalStore::new("https://art.example.com", Some("env-key".into())).unwrap(),
        )));
        let p = ArtifactsPlugin::new(secrets(&d), slot.clone());
        p.apply(Some(json!({}))).await.unwrap();
        assert_eq!(slot.source(), "plugin");
        let s = slot.current().unwrap();
        assert_eq!(
            (s.base(), s.key()),
            ("https://art.example.com", Some("env-key"))
        );
        // Another store does not get the environment's key…
        p.apply(Some(json!({"url": "https://other.example.com"})))
            .await
            .unwrap();
        assert_eq!(slot.current().unwrap().key(), None);
        // …but can be given its own.
        p.apply(Some(json!({"url": "https://other.example.com", "api_key": {"secret": "artifact-store", "key": "api-key"}}))).await.unwrap();
        assert_eq!(slot.current().unwrap().key(), Some("plugin-key"));
        assert_eq!(p.status().await["source"], "plugin");
        // Disabling falls back to the environment.
        p.apply(None).await.unwrap();
        assert_eq!(slot.source(), "env");
        // With neither, enabling says what is missing.
        let bare = ArtifactsPlugin::new(secrets(&d), Arc::new(StoreSlot::new(None)));
        assert!(
            bare.apply(Some(json!({})))
                .await
                .unwrap_err()
                .contains(STORE_ENV)
        );
    }

    #[tokio::test]
    async fn the_namespace_surface_is_walled_and_publishing_needs_admin() {
        let d = dir("surface");
        let (url, seen) = fake_store().await;
        let slot = Arc::new(StoreSlot::new(Some(
            GlobalStore::new(&url, Some("k".into())).unwrap(),
        )));
        let plugin = ArtifactsPlugin::new(secrets(&d), slot);
        let host = PluginHost::new(vec![plugin], PluginStore::new(d.join("plugins")));
        host.set("artifacts", true, Some(json!({}))).await.unwrap();

        // Not installed yet: the plugin says so.
        let (status, v) = call(&host, "team-a", "GET", "/api", false).await;
        assert_eq!(status, StatusCode::CONFLICT, "{v}");
        host.install("artifacts", "team-a", json!({}), None)
            .await
            .unwrap();

        let (status, v) = call(&host, "team-a", "GET", "/api", false).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            v,
            json!({"namespace": "team-a", "available": true, "writable": true, "prefix": "team-a/"})
        );
        assert!(
            !v.to_string().contains("127.0.0.1"),
            "the store's URL stays on app-lb"
        );
        crate::admin::wire_golden::golden("artifact-store-info", &v);

        let (status, v) = call(&host, "team-a", "GET", "/api/tags", false).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            v,
            json!([{"tag": "team-a/web:v1", "digest": D}]),
            "only the namespace's own tags"
        );

        let (status, _) = call(&host, "team-a", "GET", "/api/tags/team-b/web:v1", false).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "another namespace's tag");
        let (status, _) = call(&host, "team-a", "PUT", "/api/tags/team-a/web:v2", false).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a non-admin cannot publish");
        let (status, _) = call(&host, "team-a", "PUT", "/api/tags/team-a/web:v2", true).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = call(&host, "team-a", "HEAD", &format!("/api/blobs/{D}"), false).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = call(&host, "team-a", "DELETE", "/api/tags/team-a/web%3Av2", true).await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "an encoded ref is the same ref"
        );
        let (status, _) = call(
            &host,
            "team-a",
            "GET",
            "/api/tags/team-a%2F..%2Fteam-b/web",
            false,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "encoding does not get past the wall"
        );

        let seen = seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            [
                "GET /tags Bearer k".to_string(),
                "PUT /tags/team-a/web:v2 Bearer k".to_string(),
                format!("HEAD /blobs/{D} Bearer k"),
                "DELETE /tags/team-a/web:v2 Bearer k".to_string(),
            ]
        );
    }
}
