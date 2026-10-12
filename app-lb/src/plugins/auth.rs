//! Auth provider plugins: sign-in a namespace's deployments inherit, declared
//! by installing a plugin rather than by writing a provider by hand.
//!
//! An auth provider ([`crate::auth_providers`]) is the identity half of a
//! deployment's sign-in gate, declared once per namespace and inherited with
//! `auth.provider_ref`. These plugins declare one on install and remove it on
//! uninstall, so "this namespace signs in with Heyo" or "…with our Google
//! Workspace" is a plugin a namespace administrator switches on, beside its
//! other plugins:
//!
//! - **`auth-heyo`** declares `heyo`: Heyo gate tokens verified against the
//!   auth service's published key set (the `heyo-jwks` preset), which holds
//!   nothing secret. It is **enabled by default** wherever app-lb knows its
//!   auth service (`APP_LB_AUTH_URL`), and installs itself into every
//!   namespace, so `"auth": {"provider_ref": "heyo"}` works out of the box.
//!   A namespace narrows who gets in with `require` in its install
//!   configuration (`{"require": {"accountId": ["acct_…"]}}`).
//! - **`auth-google`** declares `google`: Google sign-in with the namespace's
//!   own OAuth client. Opt-in: the operator enables it, and a namespace
//!   installs it with its client id, a reference to the namespace secret
//!   holding the client secret, and who is admitted.
//!
//! A provider these plugins declare says so in its `description`, and they
//! only ever replace or remove their own: installing over a provider of the
//! same name somebody declared by hand is refused (install with another
//! `name`), and uninstalling while a deployment still inherits the provider
//! is refused exactly as deleting it would be, since its gate would fail
//! closed.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Plugin, PluginMeta, SetError};
use crate::auth_providers::AuthProviderStore;
use crate::config::{AuthProvider, AuthProviderSpec, JwtSpec, Providers};
use crate::registry::Registry;
use crate::secrets::SecretRef;

/// Which provider a plugin declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Heyo,
    Google,
}

impl Kind {
    fn id(self) -> &'static str {
        match self {
            Kind::Heyo => "auth-heyo",
            Kind::Google => "auth-google",
        }
    }

    fn default_name(self) -> &'static str {
        match self {
            Kind::Heyo => "heyo",
            Kind::Google => "google",
        }
    }

    /// The `description` a provider this plugin declared carries: how it
    /// tells its own from one declared by hand.
    fn marker(self) -> String {
        format!(
            "Declared by the {} plugin; uninstall the plugin to remove it.",
            self.id()
        )
    }
}

/// `auth-heyo`'s fleet configuration. Every field is optional.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeyoFleetConfig {
    /// Where the auth service publishes its key set. Defaults to
    /// `{APP_LB_AUTH_URL}/.well-known/jwks.json`.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// The hosted sign-in page a browser is sent to, and the cookie it sets.
    #[serde(default)]
    pub login_url: Option<String>,
    #[serde(default)]
    pub cookie: Option<String>,
    #[serde(default = "yes")]
    pub auto_install: bool,
}

/// `auth-heyo`'s per-namespace configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeyoInstall {
    /// The provider's name in the namespace. Default `heyo`.
    #[serde(default)]
    pub name: Option<String>,
    /// Claims every admitted token must carry, merged over the preset's
    /// `role` check, e.g. `{"accountId": ["acct_7f3c"]}`.
    #[serde(default)]
    pub require: BTreeMap<String, Value>,
}

/// `auth-google`'s fleet configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleFleetConfig {
    /// Off by default: each namespace brings its own OAuth client.
    #[serde(default)]
    pub auto_install: bool,
}

/// `auth-google`'s per-namespace configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleInstall {
    #[serde(default)]
    pub name: Option<String>,
    pub client_id: String,
    /// A secret in the namespace holding the OAuth client secret:
    /// `{"secret": "google", "key": "client_secret"}`.
    pub client_secret: SecretRef,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allowed_emails: Vec<String>,
    /// One sign-in across this domain's subdomains.
    #[serde(default)]
    pub cookie_domain: Option<String>,
    /// Also admit app-tokens, for scripts calling the same deployments.
    #[serde(default)]
    pub app_token: bool,
}

fn yes() -> bool {
    true
}

fn parse<T: serde::de::DeserializeOwned + Default>(config: &Value) -> Result<T, String> {
    match config {
        Value::Null => Ok(T::default()),
        Value::Object(m) if m.is_empty() => {
            serde_json::from_value(json!({})).map_err(|e| e.to_string())
        }
        v => serde_json::from_value(v.clone()).map_err(|e| e.to_string()),
    }
}

pub struct AuthPlugin {
    kind: Kind,
    providers: Arc<AuthProviderStore>,
    registry: Arc<Registry>,
    /// `APP_LB_AUTH_URL`, which `auth-heyo` derives its key set from.
    auth_url: Option<String>,
}

impl AuthPlugin {
    pub fn new(
        kind: Kind,
        providers: Arc<AuthProviderStore>,
        registry: Arc<Registry>,
        auth_url: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            kind,
            providers,
            registry,
            auth_url: auth_url.map(|u| u.trim_end_matches('/').to_string()),
        })
    }

    fn jwks_url(&self, fleet: &HeyoFleetConfig) -> Option<String> {
        fleet
            .jwks_url
            .clone()
            .filter(|u| !u.trim().is_empty())
            .or_else(|| {
                self.auth_url
                    .as_ref()
                    .map(|b| format!("{b}/.well-known/jwks.json"))
            })
    }

    /// The provider `namespace`'s install describes, fully materialised.
    fn provider(
        &self,
        namespace: &str,
        install: &Value,
        fleet: &Value,
    ) -> Result<AuthProviderSpec, SetError> {
        let invalid = |e: String| SetError::Invalid(e);
        let mut spec = AuthProviderSpec {
            name: String::new(),
            namespace: namespace.to_string(),
            description: Some(self.kind.marker()),
            created_at: 0,
            provider: Providers::default(),
            client_id: None,
            client_secret: None,
            allowed_domains: Vec::new(),
            allowed_emails: Vec::new(),
            jwt: None,
            cookie_domain: None,
        };
        match self.kind {
            Kind::Heyo => {
                let fleet: HeyoFleetConfig = parse(fleet).map_err(invalid)?;
                let install: HeyoInstall = parse(install).map_err(invalid)?;
                let jwks = self.jwks_url(&fleet).ok_or_else(|| {
                    SetError::Invalid(
                        "auth-heyo needs the auth service's key set: set APP_LB_AUTH_URL, or \
                         `jwks_url` in the plugin's configuration"
                            .into(),
                    )
                })?;
                let mut jwt = JwtSpec::heyo_jwks(jwks);
                jwt.require.extend(install.require);
                if fleet.login_url.is_some() {
                    jwt.login_url = fleet.login_url;
                }
                if fleet.cookie.is_some() {
                    jwt.cookie = fleet.cookie;
                }
                spec.name = install
                    .name
                    .unwrap_or_else(|| self.kind.default_name().into());
                spec.provider = Providers::one(AuthProvider::Jwt);
                spec.jwt = Some(jwt);
            }
            Kind::Google => {
                let install: GoogleInstall = serde_json::from_value(install.clone()).map_err(|e| {
                    SetError::Invalid(format!(
                        "{e}; auth-google installs with {{\"client_id\": \"….apps.googleusercontent.com\", \
                         \"client_secret\": {{\"secret\": \"google\", \"key\": \"client_secret\"}}, \
                         \"allowed_domains\": [\"example.com\"]}}"
                    ))
                })?;
                spec.name = install
                    .name
                    .unwrap_or_else(|| self.kind.default_name().into());
                let mut providers = vec![AuthProvider::Google];
                if install.app_token {
                    providers.push(AuthProvider::AppToken);
                }
                spec.provider = Providers::many(providers);
                spec.client_id = Some(install.client_id);
                spec.client_secret = Some(install.client_secret);
                spec.allowed_domains = install.allowed_domains;
                spec.allowed_emails = install.allowed_emails;
                spec.cookie_domain = install.cookie_domain;
            }
        }
        // Secret references bind to the provider's own namespace, as for a
        // provider declared through the API.
        spec.normalize();
        spec.validate()
            .map_err(|e| SetError::Invalid(e.to_string()))?;
        Ok(spec)
    }

    fn ours(&self, p: &AuthProviderSpec) -> bool {
        p.description.as_deref() == Some(self.kind.marker().as_str())
    }

    fn users(&self, namespace: &str, name: &str) -> Vec<String> {
        let mut users: Vec<String> = self
            .registry
            .deployments()
            .values()
            .filter(|d| {
                d.spec.namespace == namespace
                    && d.spec.auth.as_ref().and_then(|g| g.provider_ref.as_deref()) == Some(name)
            })
            .map(|d| d.spec.id.clone())
            .collect();
        users.sort();
        users
    }

    fn installed_name(&self, install: &Value) -> String {
        install
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(self.kind.default_name())
            .to_string()
    }
}

#[async_trait]
impl Plugin for AuthPlugin {
    fn meta(&self) -> PluginMeta {
        match self.kind {
            Kind::Heyo => PluginMeta {
                id: "auth-heyo",
                name: "Heyo sign-in",
                description: "Sign-in with Heyo accounts for a namespace's deployments: declares \
                     the auth provider `heyo` (Heyo gate tokens, verified against the auth \
                     service's published keys) that a deployment inherits with \
                     `auth.provider_ref`. On by default and installed in every namespace; a \
                     namespace narrows who gets in with `require`.",
                config_schema: json!({
                    "type": "object",
                    "properties": {
                        "jwks_url": {"type": "string", "description": "The auth service's key set. Defaults to {APP_LB_AUTH_URL}/.well-known/jwks.json."},
                        "login_url": {"type": "string", "description": "The hosted sign-in page a browser is sent to."},
                        "cookie": {"type": "string", "description": "The cookie the sign-in page sets."},
                        "auto_install": {"type": "boolean", "default": true}
                    }
                }),
            },
            Kind::Google => PluginMeta {
                id: "auth-google",
                name: "Google sign-in",
                description: "Sign-in with Google for a namespace's deployments, with the \
                     namespace's own OAuth client: declares the auth provider `google` that a \
                     deployment inherits with `auth.provider_ref`. A namespace installs it with \
                     its client id, the secret holding the client secret, and the domains or \
                     addresses admitted.",
                config_schema: json!({
                    "type": "object",
                    "properties": {
                        "auto_install": {"type": "boolean", "default": false}
                    }
                }),
            },
        }
    }

    fn validate(&self, config: &Value) -> Result<(), String> {
        match self.kind {
            Kind::Heyo => {
                let fleet: HeyoFleetConfig = parse(config)?;
                if self.jwks_url(&fleet).is_none() {
                    return Err(
                        "no key set: set `jwks_url`, or APP_LB_AUTH_URL on this host".into(),
                    );
                }
                Ok(())
            }
            Kind::Google => parse::<GoogleFleetConfig>(config).map(|_| ()),
        }
    }

    async fn apply(&self, _config: Option<Value>) -> Result<(), String> {
        Ok(())
    }

    async fn status(&self) -> Value {
        match self.kind {
            Kind::Heyo => json!({
                "jwks_url": self.jwks_url(&HeyoFleetConfig::default()),
            }),
            Kind::Google => json!({}),
        }
    }

    fn per_namespace(&self) -> bool {
        true
    }

    fn auto_install(&self, config: &Value) -> bool {
        match self.kind {
            Kind::Heyo => parse::<HeyoFleetConfig>(config).is_ok_and(|c| c.auto_install),
            Kind::Google => parse::<GoogleFleetConfig>(config).is_ok_and(|c| c.auto_install),
        }
    }

    fn validate_install(&self, _namespace: &str, config: &Value) -> Result<(), String> {
        match self.kind {
            Kind::Heyo => parse::<HeyoInstall>(config).map(|_| ()),
            // Checked in full by `on_install`, which builds the provider.
            Kind::Google => Ok(()),
        }
    }

    fn default_config(&self) -> Option<Value> {
        // On out of the box only where there is a key set to verify against.
        (self.kind == Kind::Heyo && self.auth_url.is_some()).then(|| json!({}))
    }

    async fn on_install(
        &self,
        namespace: &str,
        config: &Value,
        fleet: &Value,
    ) -> Result<(), SetError> {
        let mut spec = self.provider(namespace, config, fleet)?;
        if let Some(existing) = self.providers.get(namespace, &spec.name) {
            if !self.ours(&existing) {
                return Err(SetError::Conflict(format!(
                    "namespace \"{namespace}\" already declares an auth provider named {:?} by hand; \
                     install {} with {{\"name\": \"…\"}} to use another name, or delete that provider first",
                    spec.name,
                    self.kind.id()
                )));
            }
            spec.created_at = existing.created_at;
        } else {
            spec.created_at = crate::deployment::now_secs();
        }
        self.providers
            .upsert(spec)
            .map(|_| ())
            .map_err(SetError::Io)
    }

    async fn on_uninstall(&self, namespace: &str, config: &Value) -> Result<(), SetError> {
        let name = self.installed_name(config);
        let Some(existing) = self.providers.get(namespace, &name) else {
            return Ok(());
        };
        if !self.ours(&existing) {
            return Ok(());
        }
        let users = self.users(namespace, &name);
        if !users.is_empty() {
            return Err(SetError::Conflict(format!(
                "auth provider {name:?} is inherited by deployment(s) {}; their sign-in gates would \
                 fail closed. Repoint or remove them before uninstalling {}",
                users.join(", "),
                self.kind.id()
            )));
        }
        self.providers
            .remove(namespace, &name)
            .map(|_| ())
            .map_err(SetError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{PluginHost, PluginStore};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "app-lb-auth-plugin-{}-{tag}-{n}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        _dir: TempDir,
        providers: Arc<AuthProviderStore>,
        registry: Arc<Registry>,
        host: PluginHost,
    }

    fn fixture(tag: &str, auth_url: Option<&str>) -> Fixture {
        let dir = TempDir::new(tag);
        let providers = Arc::new(AuthProviderStore::new(dir.0.join("providers")));
        let registry = Arc::new(Registry::new(dir.0.join("state.json").to_str().unwrap()));
        let auth_url = auth_url.map(str::to_string);
        let host = PluginHost::new(
            vec![
                AuthPlugin::new(
                    Kind::Heyo,
                    providers.clone(),
                    registry.clone(),
                    auth_url.clone(),
                ),
                AuthPlugin::new(Kind::Google, providers.clone(), registry.clone(), auth_url),
            ],
            PluginStore::new(dir.0.join("plugins")),
        );
        Fixture {
            _dir: dir,
            providers,
            registry,
            host,
        }
    }

    fn gated(id: &str, ns: &str, provider: &str) -> crate::config::DeploymentSpec {
        let mut spec: crate::config::DeploymentSpec = serde_json::from_value(json!({
            "id": id, "namespace": ns,
            "routes": [{"host": format!("{id}.example.com")}],
            "upstreams": ["127.0.0.1:8080"],
            "auth": {"provider_ref": provider}
        }))
        .unwrap();
        spec.normalize();
        spec
    }

    #[tokio::test]
    async fn heyo_is_on_by_default_only_where_there_is_a_key_set() {
        let f = fixture("default", Some("https://auth.example.com/"));
        assert_eq!(f.host.start_enabled().await, vec!["auth-heyo"]);
        assert!(f.host.is_enabled("auth-heyo"));
        assert!(!f.host.is_enabled("auth-google"), "google is opt-in");
        // A later boot leaves the record alone, so a disable sticks.
        f.host.set("auth-heyo", false, None).await.unwrap();
        assert!(f.host.start_enabled().await.is_empty());
        assert!(!f.host.is_enabled("auth-heyo"));

        let bare = fixture("default-bare", None);
        assert!(
            bare.host.start_enabled().await.is_empty(),
            "nothing to verify against"
        );
        assert!(
            bare.host
                .set("auth-heyo", true, Some(json!({})))
                .await
                .is_err()
        );
        assert!(
            bare.host
                .set(
                    "auth-heyo",
                    true,
                    Some(json!({"jwks_url": "https://idp.example/jwks"}))
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn installing_heyo_declares_a_provider_and_uninstalling_removes_it() {
        let f = fixture("heyo", Some("https://auth.example.com"));
        f.host.start_enabled().await;
        assert_eq!(f.host.auto_install("team-a", None).await, vec!["auth-heyo"]);
        let p = f.providers.get("team-a", "heyo").expect("declared");
        let jwt = p.jwt.as_ref().unwrap();
        assert_eq!(
            jwt.jwks_url.as_deref(),
            Some("https://auth.example.com/.well-known/jwks.json")
        );
        assert_eq!(jwt.audience.as_deref(), Some("heyo-gate"));
        assert!(p.description.as_deref().unwrap().contains("auth-heyo"));
        let created = p.created_at;

        // Narrowing re-declares it in place, keeping its clock and the role check.
        f.host
            .install(
                "auth-heyo",
                "team-a",
                json!({"require": {"accountId": ["acct_1"]}}),
                None,
            )
            .await
            .unwrap();
        let p = f.providers.get("team-a", "heyo").unwrap();
        assert_eq!(p.created_at, created);
        let require = &p.jwt.as_ref().unwrap().require;
        assert_eq!(require["accountId"], json!(["acct_1"]));
        assert!(require.contains_key("role"));

        // In use: the uninstall is refused, and names who uses it.
        f.registry.upsert(gated("reports", "team-a", "heyo"));
        let e = f.host.uninstall("auth-heyo", "team-a").await.unwrap_err();
        assert!(
            matches!(&e, SetError::Conflict(m) if m.contains("reports")),
            "{e}"
        );
        assert!(f.host.is_installed("auth-heyo", "team-a"));
        assert!(f.providers.get("team-a", "heyo").is_some());

        f.registry.remove("reports");
        f.host.uninstall("auth-heyo", "team-a").await.unwrap();
        assert!(f.providers.get("team-a", "heyo").is_none());
        assert!(
            f.host.auto_install("team-a", None).await.is_empty(),
            "the opt-out sticks"
        );
    }

    #[tokio::test]
    async fn a_provider_declared_by_hand_is_never_replaced_or_removed() {
        let f = fixture("hand", Some("https://auth.example.com"));
        f.host.start_enabled().await;
        let mut hand = AuthProviderSpec {
            name: "heyo".into(),
            namespace: "team-a".into(),
            description: Some("ours, by hand".into()),
            created_at: 1,
            provider: Providers::one(AuthProvider::Jwt),
            client_id: None,
            client_secret: None,
            allowed_domains: vec![],
            allowed_emails: vec![],
            jwt: Some(JwtSpec::heyo_jwks("https://other.example/jwks".into())),
            cookie_domain: None,
        };
        hand.normalize();
        f.providers.upsert(hand).unwrap();

        assert!(
            f.host.auto_install("team-a", None).await.is_empty(),
            "the auto-install steps aside"
        );
        let e = f
            .host
            .install("auth-heyo", "team-a", json!({}), None)
            .await
            .unwrap_err();
        assert!(
            matches!(&e, SetError::Conflict(m) if m.contains("by hand")),
            "{e}"
        );
        // Under another name it installs beside it.
        f.host
            .install("auth-heyo", "team-a", json!({"name": "heyo-gate"}), None)
            .await
            .unwrap();
        assert!(f.providers.get("team-a", "heyo-gate").is_some());
        assert_eq!(
            f.providers
                .get("team-a", "heyo")
                .unwrap()
                .description
                .as_deref(),
            Some("ours, by hand")
        );
        f.host.uninstall("auth-heyo", "team-a").await.unwrap();
        assert!(f.providers.get("team-a", "heyo-gate").is_none());
        assert!(
            f.providers.get("team-a", "heyo").is_some(),
            "the hand-made one stays"
        );
    }

    #[tokio::test]
    async fn google_installs_with_the_namespaces_own_client() {
        let f = fixture("google", None);
        f.host
            .set("auth-google", true, Some(json!({})))
            .await
            .unwrap();
        assert!(
            f.host.auto_install("team-a", None).await.is_empty(),
            "opt-in"
        );

        let e = f
            .host
            .install(
                "auth-google",
                "team-a",
                json!({"allowed_domains": ["example.com"]}),
                None,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&e, SetError::Invalid(m) if m.contains("client_id")),
            "{e}"
        );

        f.host
            .install(
                "auth-google",
                "team-a",
                json!({
                    "client_id": "1234.apps.googleusercontent.com",
                    "client_secret": {"secret": "google", "key": "client_secret"},
                    "allowed_domains": ["example.com"],
                    "app_token": true
                }),
                None,
            )
            .await
            .unwrap();
        let p = f.providers.get("team-a", "google").expect("declared");
        assert_eq!(
            p.client_id.as_deref(),
            Some("1234.apps.googleusercontent.com")
        );
        assert!(
            p.provider.contains(AuthProvider::Google)
                && p.provider.contains(AuthProvider::AppToken)
        );
        assert_eq!(p.allowed_domains, ["example.com"]);
        let secret = p.client_secret.as_ref().unwrap();
        assert_eq!(
            secret.namespace.as_deref(),
            Some("team-a"),
            "bound to the namespace's own secrets"
        );
    }
}
