//! The remote plugin: a namespace's git repos, from the region's git remote.
//!
//! `remote` (`git.<region>`, `remote.heyo.work`) stores every namespace's repos
//! in S3 and already resolves `applb_` tokens through this app-lb's
//! `/whoami`. This plugin brings its pages into app-lb's plugin console, so a
//! namespace browses its repos, creates them and mints repo tokens beside its
//! deployments, signed in once. The operator enables it with remote's URL and
//! a reference to remote's `REMOTE_PLUGIN_API_TOKEN`; each namespace installs
//! it, and gets `/namespaces/<ns>/plugins/remote/…` through the shared
//! [`NsProxy`].
//!
//! remote's own root belongs to namespaces (`/<ns>/<repo>`), so its namespace
//! surface is `/-/ns/<ns>/…` rather than `/ns/<ns>/…`: `…/remote/ui` is the
//! namespace's repositories and `…/remote/ui/<page>` every other page
//! (`<repo>`, `<repo>/tree/<ref>/<path>`, `-/new`, `-/tokens`, …). remote
//! takes the caller's identity from the actor headers the proxy sets: a
//! namespace admin may create and delete repos and mint tokens, anyone else
//! reads.
//!
//! It installs itself unless the operator says otherwise. Installing grants
//! nothing a namespace's own tokens could not already do at remote directly;
//! it only puts the pages where the namespace already is.

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

/// Where remote serves a namespace's pages.
pub const NS_PREFIX: &str = "/-/ns";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    /// remote's listener, e.g. `https://git.us5.heyo.work`.
    pub url: String,
    /// remote's `REMOTE_PLUGIN_API_TOKEN`, as a reference into the secret
    /// store: `{"secret": "remote-plugin", "key": "api-token"}`. remote serves
    /// no namespace pages without one, so this is required.
    pub api_token: SecretRef,
    #[serde(default = "default_poll_secs")]
    pub poll_secs: u64,
    /// Install into every namespace automatically. See the module docs.
    #[serde(default = "default_auto_install")]
    pub auto_install: bool,
}

fn default_poll_secs() -> u64 {
    DEFAULT_POLL_SECS
}

fn default_auto_install() -> bool {
    true
}

fn parse_config(config: &Value) -> Result<RemoteConfig, String> {
    let cfg: RemoteConfig = serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
    check_url(&cfg.url)?;
    if !(5..=3600).contains(&cfg.poll_secs) {
        return Err("poll_secs must be between 5 and 3600".into());
    }
    cfg.api_token
        .validate()
        .map_err(|e| format!("api_token: {e}"))?;
    Ok(cfg)
}

pub struct RemotePlugin {
    proxy: Arc<NsProxy>,
}

impl RemotePlugin {
    pub fn new(secrets: Arc<SecretStore>) -> Arc<Self> {
        Arc::new(Self {
            // remote has many pages, and records who minted a token.
            proxy: NsProxy::new_at("remote", "remote", NS_PREFIX, secrets, true, true),
        })
    }
}

#[async_trait]
impl Plugin for RemotePlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "remote",
            name: "Git",
            description: "A namespace's git repositories on the region's git remote: browse \
                 code, history and branches, create repositories and mint repo tokens. The \
                 operator points it at remote; each namespace gets it installed.",
            config_schema: json!({
                "type": "object",
                "required": ["url", "api_token"],
                "properties": {
                    "url": {"type": "string", "description": "remote's listener, e.g. https://git.us5.heyo.work"},
                    "api_token": {
                        "type": "object",
                        "description": "A secret reference to REMOTE_PLUGIN_API_TOKEN: {\"secret\": \"remote-plugin\", \"key\": \"api-token\"}.",
                        "required": ["secret"],
                        "properties": {"secret": {"type": "string"}, "key": {"type": "string"}}
                    },
                    "poll_secs": {"type": "integer", "minimum": 5, "maximum": 3600, "default": DEFAULT_POLL_SECS},
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
            return self.proxy.configure(None, Duration::ZERO).await;
        };
        let cfg = parse_config(&config)?;
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
            _ => Err("the remote plugin takes no per-namespace configuration; send {}".into()),
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
    axum::extract::State(p): axum::extract::State<Arc<RemotePlugin>>,
    req: Request,
) -> Response {
    p.proxy.forward(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::ns_proxy::{NamespaceActor, upstream_path_at};
    use crate::plugins::{PluginHost, PluginStore};
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    fn secrets_with(token: &str) -> Arc<SecretStore> {
        let dir =
            std::env::temp_dir().join(format!("app-lb-remote-{}-{token}", std::process::id()));
        let store = Arc::new(SecretStore::new(dir.join("secrets.json"), None));
        store.put(crate::secrets::SecretSpec {
            id: "remote-plugin".into(),
            namespace: crate::config::DEFAULT_NAMESPACE.into(),
            description: None,
            data: [("api-token".to_string(), token.to_string())].into(),
            updated_at: 0,
        });
        store
    }

    /// A remote-shaped server: `/healthz` open, everything else behind the
    /// bearer, echoing what it was sent; a form post answers 303 to the new
    /// repo under the base.
    async fn fake_remote(token: &str) -> String {
        let expected = format!("Bearer {token}");
        let app = Router::new().fallback(move |req: Request| {
            let expected = expected.clone();
            async move {
                if req.uri().path() == "/healthz" {
                    return "ok".into_response();
                }
                let headers = req.headers().clone();
                let h = |n: &str| {
                    headers
                        .get(n)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string)
                };
                if h("authorization").as_deref() != Some(expected.as_str()) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                let base = h("x-heyo-base").unwrap_or_default();
                if req.method() == axum::http::Method::POST {
                    let body = axum::body::to_bytes(req.into_body(), 1 << 20)
                        .await
                        .unwrap();
                    assert_eq!(&body[..], b"name=docs");
                    return (
                        StatusCode::SEE_OTHER,
                        [(header::LOCATION, format!("{base}/ui/docs"))],
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
            let path = std::env::temp_dir()
                .join(format!("app-lb-remote-host-{}-{tag}", std::process::id()));
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
        json!({"url": url, "api_token": {"secret": "remote-plugin", "key": "api-token"}})
    }

    #[test]
    fn a_config_is_checked_before_it_is_stored() {
        assert!(parse_config(&configured("https://git.us5.heyo.work")).is_ok());
        for bad in [
            json!({"url": "http://x"}),
            json!({"url": "ftp://x", "api_token": {"secret": "remote-plugin"}}),
            json!({"url": "http://x", "api_token": {"secret": "remote-plugin"}, "poll_secs": 1}),
            json!({"url": "http://x", "api_token": {"secret": "remote-plugin"}, "token": "inline"}),
        ] {
            assert!(parse_config(&bad).is_err(), "accepted {bad}");
        }
        let plugin = RemotePlugin::new(secrets_with("x"));
        assert!(plugin.auto_install(&configured("http://x")));
        let mut off = configured("http://x");
        off["auto_install"] = json!(false);
        assert!(!plugin.auto_install(&off));
    }

    #[test]
    fn pages_go_under_remotes_namespace_prefix() {
        assert_eq!(
            upstream_path_at(NS_PREFIX, "a", "/ui", true).as_deref(),
            Some("/-/ns/a/")
        );
        assert_eq!(
            upstream_path_at(NS_PREFIX, "a", "/ui/site/tree/main/src", true).as_deref(),
            Some("/-/ns/a/site/tree/main/src")
        );
        for bad in ["/ui/../../b/site", "/ui/%2e%2e/b", "/healthz", "/"] {
            assert_eq!(upstream_path_at(NS_PREFIX, "a", bad, true), None, "{bad}");
        }
    }

    async fn call(
        host: &PluginHost,
        ns: &str,
        req: axum::http::Request<axum::body::Body>,
    ) -> Response {
        host.dispatch_namespace("remote", ns, req).await
    }

    #[tokio::test]
    async fn a_namespace_browses_and_creates_through_the_proxy() {
        let url = fake_remote("remote-svc").await;
        let dir = TempDir::new("flow");
        let plugin = RemotePlugin::new(secrets_with("remote-svc"));
        let host = PluginHost::new(vec![plugin.clone()], PluginStore::new(&dir.0));
        host.set("remote", true, Some(configured(&url)))
            .await
            .unwrap();
        assert!(
            host.install("remote", "team-a", json!({"x": 1}), None)
                .await
                .is_err(),
            "no per-namespace configuration"
        );
        host.install("remote", "team-a", json!({}), None)
            .await
            .unwrap();
        assert_eq!(
            host.namespace_plugin("remote", "team-a").unwrap().dashboard,
            Some("ui")
        );
        assert_eq!(plugin.status().await["up"], true);

        let mut get = axum::http::Request::get("/ui/site/commits")
            .body(axum::body::Body::empty())
            .unwrap();
        get.extensions_mut().insert(NamespaceActor {
            principal: Some("user:u1".into()),
            email: None,
            admin: true,
        });
        let resp = call(&host, "team-a", get).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["path"], "/-/ns/team-a/site/commits");
        assert_eq!(v["base"], "/namespaces/team-a/plugins/remote");
        assert_eq!(v["actor"], "user:u1");
        assert_eq!(v["admin"], "true");

        let post = axum::http::Request::post("/ui/-/new")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from("name=docs"))
            .unwrap();
        let resp = call(&host, "team-a", post).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers()["location"],
            "/namespaces/team-a/plugins/remote/ui/docs"
        );

        let get = axum::http::Request::get("/ui")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            call(&host, "team-b", get).await.status(),
            StatusCode::CONFLICT,
            "not installed in team-b"
        );
        plugin.apply(None).await.unwrap();
    }
}
