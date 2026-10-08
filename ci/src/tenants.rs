//! Which app-lb namespaces have installed the `ci` plugin, and where their
//! builds run.
//!
//! **app-lb is the authority, and this is a cache of it.** A namespace installs
//! `ci` in app-lb, and an operator configures the plugin there — the tenant
//! network, and per-namespace overrides. ci polls `GET /api/plugins/ci` with
//! the same `CI_APP_LB_URL`/`CI_APP_LB_TOKEN` it reads workflow objects with,
//! and every namespace route and tenant submit asks this cache rather than
//! app-lb, so a slow admin API never slows a page.
//!
//! The answers to a failed poll are chosen so that being wrong is safe:
//!
//! - **A transport error or a 5xx** keeps the last good answer. A blip in
//!   app-lb must not take every namespace's dashboard down with it.
//! - **A 409** is app-lb saying the plugin is disabled: no tenants.
//! - **A 404** is an app-lb that predates the plugin: no tenants, warned once.
//! - **Never polled successfully** is no tenants. An instance that has not yet
//!   heard from app-lb serves the fleet and nobody else.

use crate::config::Config;
use arc_swap::ArcSwap;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// The slice of app-lb's `PluginView` this app reads. Everything else in it —
/// status, timestamps, the redacted plugin token — is ignored, so app-lb can
/// grow the view without a lockstep release here.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct PluginView {
    enabled: bool,
    /// Omitted by app-lb when empty.
    installed_in: Vec<String>,
    config: PluginConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct PluginConfig {
    tenant_network: Option<String>,
    namespace_networks: BTreeMap<String, String>,
}

/// One poll's answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantSet {
    pub enabled: bool,
    pub installed_in: Vec<String>,
    /// The network every tenant builds in unless overridden below.
    pub tenant_network: Option<String>,
    /// Per-namespace overrides, for tenants that must not share a network.
    pub namespace_networks: BTreeMap<String, String>,
}

impl TenantSet {
    /// Whether `namespace` may use ci right now.
    ///
    /// `require_install` off is the escape hatch [`Config::require_install`]
    /// documents: every namespace counts as installed while the plugin is on.
    pub fn is_installed(&self, namespace: &str, require_install: bool) -> bool {
        self.enabled
            && crate::tenancy::valid_namespace(namespace)
            && (!require_install || self.installed_in.iter().any(|n| n == namespace))
    }

    /// The network a namespace's builds are configured to run in, before
    /// [`crate::tenancy::resolve_network`] checks it against what is served.
    pub fn network_for(&self, namespace: &str) -> Option<&str> {
        self.namespace_networks
            .get(namespace)
            .or(self.tenant_network.as_ref())
            .map(String::as_str)
            .map(str::trim)
            .filter(|n| !n.is_empty())
    }

    fn from_view(view: PluginView) -> Self {
        Self {
            enabled: view.enabled,
            installed_in: view.installed_in,
            tenant_network: view.config.tenant_network,
            namespace_networks: view.config.namespace_networks,
        }
    }
}

/// What a poll concluded, before it is stored.
#[derive(Debug, PartialEq, Eq)]
enum Poll {
    /// Replace the cache with this.
    Answer(TenantSet),
    /// app-lb has no `ci` plugin at all.
    Unsupported,
    /// Keep what we have; the reason is logged.
    Keep(String),
}

/// Map an app-lb response onto what to do with the cache. Separate from the
/// HTTP call so every branch is testable without a server.
fn classify(status: u16, body: &[u8]) -> Poll {
    match status {
        200..=299 => match serde_json::from_slice::<PluginView>(body) {
            Ok(view) => Poll::Answer(TenantSet::from_view(view)),
            Err(e) => Poll::Keep(format!(
                "app-lb sent a plugin view this build cannot read: {e}"
            )),
        },
        // app-lb wraps every plugin route so it answers 409 while the plugin
        // is disabled. That is an answer, not a failure.
        409 => Poll::Answer(TenantSet::default()),
        404 => Poll::Unsupported,
        _ => Poll::Keep(format!(
            "app-lb answered {status} for GET /api/plugins/ci: {}. \
             A 401 usually means CI_APP_LB_TOKEN is missing or unscoped.",
            String::from_utf8_lossy(&body[..body.len().min(200)])
        )),
    }
}

/// Polls app-lb and caches the result.
pub struct Tenants {
    http: reqwest::Client,
    base_url: Option<String>,
    token: Option<String>,
    interval: Duration,
    require_install: bool,
    cache: ArcSwap<TenantSet>,
    warned_unsupported: AtomicBool,
}

impl Tenants {
    pub fn new(config: &Config) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            base_url: config.app_lb_url.clone(),
            token: config.app_lb_token.clone(),
            interval: config.heyvm.refresh_interval,
            require_install: config.require_install,
            cache: ArcSwap::from_pointee(TenantSet::default()),
            warned_unsupported: AtomicBool::new(false),
        }
    }

    /// A cache holding `set`, for tests that need a namespace installed.
    #[cfg(test)]
    pub fn fixed(set: TenantSet, require_install: bool) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: None,
            token: None,
            interval: Duration::from_secs(30),
            require_install,
            cache: ArcSwap::from_pointee(set),
            warned_unsupported: AtomicBool::new(false),
        }
    }

    pub fn snapshot(&self) -> Arc<TenantSet> {
        self.cache.load_full()
    }

    pub fn is_installed(&self, namespace: &str) -> bool {
        self.snapshot()
            .is_installed(namespace, self.require_install)
    }

    /// Re-read from app-lb. Errors keep the previous answer.
    pub async fn refresh(&self) -> Result<(), String> {
        let Some(base) = &self.base_url else {
            return Ok(());
        };
        let mut request = self.http.get(format!("{base}/api/plugins/ci"));
        if let Some(t) = &self.token {
            request = request.bearer_auth(t);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("could not reach app-lb: {e}. Check CI_APP_LB_URL."))?;
        let status = response.status().as_u16();
        let body = response.bytes().await.map_err(|e| e.to_string())?;
        match classify(status, &body) {
            Poll::Answer(set) => {
                self.cache.store(Arc::new(set));
                Ok(())
            }
            Poll::Unsupported => {
                if !self.warned_unsupported.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        "app-lb has no `ci` plugin (GET /api/plugins/ci answered 404); \
                         no namespace can use ci until it is upgraded"
                    );
                }
                self.cache.store(Arc::new(TenantSet::default()));
                Ok(())
            }
            Poll::Keep(why) => Err(why),
        }
    }

    pub fn spawn_refresh_loop(self: Arc<Self>) {
        if self.base_url.is_none() {
            tracing::info!("CI_APP_LB_URL is not set, so no namespace can install ci");
            return;
        }
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(e) = self.refresh().await {
                    tracing::warn!(
                        "could not read the ci plugin's installs, keeping the last answer: {e}"
                    );
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(ns: &[&str]) -> TenantSet {
        TenantSet {
            enabled: true,
            installed_in: ns.iter().map(|s| s.to_string()).collect(),
            tenant_network: Some("tenants".into()),
            namespace_networks: BTreeMap::from([("team-b".into(), "team-b-net".into())]),
        }
    }

    #[test]
    fn app_lbs_plugin_view_is_read_and_its_extra_fields_ignored() {
        let body = br#"{"id":"ci","name":"CI","per_namespace":true,"enabled":true,
            "installed_in":["team-a"],"updated_at":1,"status":{},
            "config":{"url":"http://ci","api_token":{"secret":"redacted"},"poll_secs":30,
                      "tenant_network":"tenants","namespace_networks":{"team-b":"b-net"}}}"#;
        let Poll::Answer(set) = classify(200, body) else {
            panic!()
        };
        assert!(set.enabled);
        assert_eq!(set.installed_in, vec!["team-a"]);
        assert_eq!(set.network_for("team-a"), Some("tenants"));
        assert_eq!(set.network_for("team-b"), Some("b-net"));
    }

    /// `installed_in` is omitted when empty, which must read as "none".
    #[test]
    fn an_omitted_install_list_is_empty() {
        let Poll::Answer(set) = classify(200, br#"{"enabled":true,"config":{}}"#) else {
            panic!()
        };
        assert!(set.installed_in.is_empty());
        assert!(!set.is_installed("team-a", true));
        assert_eq!(set.network_for("team-a"), None);
    }

    #[test]
    fn disabled_and_missing_plugins_mean_no_tenants_and_errors_keep_the_last_answer() {
        assert_eq!(classify(409, b"{}"), Poll::Answer(TenantSet::default()));
        assert_eq!(classify(404, b""), Poll::Unsupported);
        assert!(matches!(classify(502, b"bad gateway"), Poll::Keep(_)));
        assert!(matches!(classify(401, b""), Poll::Keep(_)));
        assert!(matches!(classify(200, b"not json"), Poll::Keep(_)));
    }

    #[test]
    fn installation_is_per_namespace_and_needs_the_plugin_on() {
        let set = installed(&["team-a"]);
        assert!(set.is_installed("team-a", true));
        assert!(!set.is_installed("team-b", true));
        // A name app-lb could never have installed is never installed.
        assert!(!set.is_installed("..", false));
        assert!(!set.is_installed("", false));
        // CI_REQUIRE_INSTALL=false admits every valid namespace...
        assert!(set.is_installed("team-b", false));
        // ...but never while the plugin is disabled.
        let off = TenantSet {
            enabled: false,
            ..installed(&["team-a"])
        };
        assert!(!off.is_installed("team-a", true));
        assert!(!off.is_installed("team-a", false));
    }

    #[tokio::test]
    async fn the_cache_starts_with_no_tenants() {
        let t = Tenants::fixed(TenantSet::default(), true);
        assert!(!t.is_installed("team-a"));
    }
}
