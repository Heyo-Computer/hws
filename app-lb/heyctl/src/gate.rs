//! Putting a deployment behind sign-in, from a program.
//!
//! Who may sign in is a namespace **auth provider**: `heyo` from the
//! `auth-heyo` plugin (on by default), `google` from `auth-google`, or one
//! declared with [`Client::create_auth_provider`]. A deployment's gate
//! *inherits* one by name, and keeps only what is the deployment's own: which
//! paths skip sign-in, how long a session lasts, where the sign-in endpoints
//! live. [`Client::set_auth`] writes that gate; [`Client::clear_auth`] removes
//! it.
//!
//! ```no_run
//! # async fn f() -> hws::Result<()> {
//! use hws::{Client, Gate};
//!
//! let lb = Client::builder("https://admin.example.com")
//!     .token(std::env::var("APP_LB_TOKEN").unwrap())
//!     .build()?;
//!
//! // Heyo sign-in in front of `reports`, except its health check and webhooks.
//! lb.set_auth("reports", &Gate::provider("heyo").public("/healthz").public("/webhooks/"))
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! Both are a read and a whole-spec replace of the deployment, the same edit
//! `heyctl set auth` makes. Changing only the gate does not recycle the
//! deployment's VMs.

use crate::api::Client;
use crate::error::{Error, Result};
use crate::types::DeploymentStatus;
use serde_json::{Map, Value, json};

/// A sign-in gate that inherits its identity from a namespace auth provider.
///
/// Every field but the provider is optional; one left `None` keeps what the
/// deployment's gate already has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gate {
    /// The auth provider's name in the deployment's namespace: `heyo`,
    /// `google`, or one declared by hand.
    pub provider: String,
    /// Path prefixes that skip sign-in, and what app-lb requires on them
    /// instead. Replaces the list when set.
    pub public_paths: Option<Vec<GatePath>>,
    /// How long a session lasts, in seconds.
    pub session_ttl_secs: Option<u64>,
    /// Where the sign-in endpoints live under the deployment's hostname.
    /// Default `/__applb/auth`; set it under the deployment's path prefix if it
    /// is routed by one.
    pub base_path: Option<String>,
    pub cookie_name: Option<String>,
    /// Send the signed-in identity upstream as `x-auth-request-*` headers.
    /// On by default.
    pub forward_identity: Option<bool>,
}

/// A path prefix that skips the sign-in gate, and the scope app-lb requires
/// on it instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatePath {
    pub path: String,
    /// `public` (no credential at all), `none`, `view` or `admin` (an
    /// app-token of that tier).
    pub scope: String,
}

impl Gate {
    pub fn provider(name: impl Into<String>) -> Self {
        Self {
            provider: name.into(),
            public_paths: None,
            session_ttl_secs: None,
            base_path: None,
            cookie_name: None,
            forward_identity: None,
        }
    }

    /// Let anyone reach paths under `prefix` without signing in.
    pub fn public(self, prefix: impl Into<String>) -> Self {
        self.path(prefix, "public")
    }

    /// Paths under `prefix` skip sign-in but need an app-token of `scope`.
    pub fn path(mut self, prefix: impl Into<String>, scope: impl Into<String>) -> Self {
        self.public_paths
            .get_or_insert_with(Vec::new)
            .push(GatePath {
                path: prefix.into(),
                scope: scope.into(),
            });
        self
    }

    pub fn session_ttl_secs(mut self, secs: u64) -> Self {
        self.session_ttl_secs = Some(secs);
        self
    }

    pub fn base_path(mut self, path: impl Into<String>) -> Self {
        self.base_path = Some(path.into());
        self
    }

    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.cookie_name = Some(name.into());
        self
    }

    pub fn forward_identity(mut self, on: bool) -> Self {
        self.forward_identity = Some(on);
        self
    }

    /// Write this gate onto `spec`'s `auth` block: the reference, the
    /// route-scoped fields that are set, and none of the inline identity
    /// fields, which app-lb refuses beside a reference.
    pub fn apply_to(&self, spec: &mut Value) -> Result<()> {
        let obj = spec
            .as_object_mut()
            .ok_or_else(|| Error::Invalid("a deployment spec must be a JSON object".into()))?;
        let auth = obj
            .entry("auth")
            .or_insert_with(|| Value::Object(Map::new()));
        if !auth.is_object() {
            *auth = Value::Object(Map::new());
        }
        let auth = auth.as_object_mut().expect("made an object above");
        auth.insert("provider_ref".into(), Value::String(self.provider.clone()));
        for identity in [
            "provider",
            "client_id",
            "client_secret",
            "allowed_domains",
            "allowed_emails",
            "jwt",
            "cookie_domain",
        ] {
            auth.remove(identity);
        }
        if let Some(paths) = &self.public_paths {
            auth.insert(
                "public_paths".into(),
                paths
                    .iter()
                    .map(|p| json!({"path": p.path, "scope": p.scope}))
                    .collect(),
            );
        }
        if let Some(ttl) = self.session_ttl_secs {
            auth.insert("session_ttl_secs".into(), ttl.into());
        }
        if let Some(b) = &self.base_path {
            auth.insert("base_path".into(), b.clone().into());
        }
        if let Some(c) = &self.cookie_name {
            auth.insert("cookie_name".into(), c.clone().into());
        }
        if let Some(f) = self.forward_identity {
            auth.insert("forward_identity".into(), f.into());
        }
        Ok(())
    }
}

/// The plugin that declares the provider `name`, when one does by default.
fn plugin_for(name: &str) -> Option<&'static str> {
    match name {
        "heyo" => Some("auth-heyo"),
        "google" => Some("auth-google"),
        _ => None,
    }
}

impl Client {
    /// Put deployment `id` behind sign-in with `gate`'s provider, keeping the
    /// gate's route-scoped settings that `gate` leaves `None`.
    ///
    /// Checks first that the provider is declared in the deployment's
    /// namespace, and says which plugin declares it when it is not.
    pub async fn set_auth(&self, id: &str, gate: &Gate) -> Result<DeploymentStatus> {
        let mut spec = self.raw().spec(id).await?;
        let namespace = spec
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or("default")
            .to_string();
        if !self
            .auth_provider_exists(&namespace, &gate.provider)
            .await?
        {
            let how = match plugin_for(&gate.provider) {
                Some(plugin) => format!(
                    "install the {plugin} plugin there (`install_plugin({namespace:?}, {plugin:?}, …)`)"
                ),
                None => "declare it with `create_auth_provider`".to_string(),
            };
            return Err(Error::Invalid(format!(
                "namespace {namespace:?} has no auth provider {:?}; {how}",
                gate.provider
            )));
        }
        gate.apply_to(&mut spec)?;
        self.replace_deployment(id, &spec).await
    }

    /// Remove deployment `id`'s sign-in gate: it serves everyone again.
    pub async fn clear_auth(&self, id: &str) -> Result<DeploymentStatus> {
        let mut spec = self.raw().spec(id).await?;
        if let Some(obj) = spec.as_object_mut() {
            obj.remove("auth");
        }
        self.replace_deployment(id, &spec).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Method;
    use crate::transport::stub::Stub;
    use std::sync::Arc;

    fn client(stub: Stub) -> (Client, Arc<Stub>) {
        let stub = Arc::new(stub);
        (Client::with_transport(stub.clone()), stub)
    }

    fn status(auth: Value) -> Value {
        json!({"spec": {"id": "reports", "namespace": "team-a", "routes": [{"host": "r.example.com"}],
            "upstreams": ["127.0.0.1:8080"], "auth": auth}})
    }

    #[test]
    fn a_gate_replaces_inline_identity_and_keeps_what_it_leaves_unset() {
        let mut spec = status(json!({
            "provider": "google", "client_id": "x", "client_secret": {"secret": "g"},
            "allowed_domains": ["example.com"], "session_ttl_secs": 600, "cookie_name": "s"
        }))["spec"]
            .clone();
        Gate::provider("heyo")
            .public("/healthz")
            .apply_to(&mut spec)
            .unwrap();
        assert_eq!(
            spec["auth"],
            json!({"provider_ref": "heyo", "session_ttl_secs": 600, "cookie_name": "s",
                "public_paths": [{"path": "/healthz", "scope": "public"}]})
        );
        let mut bare = json!({"id": "web"});
        Gate::provider("google")
            .path("/api/", "view")
            .forward_identity(false)
            .apply_to(&mut bare)
            .unwrap();
        assert_eq!(
            bare["auth"],
            json!({"provider_ref": "google", "forward_identity": false,
                "public_paths": [{"path": "/api/", "scope": "view"}]})
        );
    }

    #[tokio::test]
    async fn set_auth_checks_the_provider_then_replaces_the_spec() {
        let (c, stub) = client(
            Stub::new()
                .json(200, status(Value::Null))
                .json(
                    200,
                    json!({"name": "heyo", "namespace": "team-a", "provider": "jwt"}),
                )
                .json(200, status(json!({"provider_ref": "heyo"}))),
        );
        c.set_auth("reports", &Gate::provider("heyo").public("/healthz"))
            .await
            .unwrap();
        let calls = stub.calls();
        let seen: Vec<String> = calls
            .iter()
            .map(|c| format!("{} {}", c.method.as_str(), c.path))
            .collect();
        assert_eq!(
            seen,
            [
                "GET /deployments/reports",
                "GET /auth-providers/team-a/heyo",
                "PUT /deployments/reports"
            ]
        );
        assert_eq!(calls[2].method, Method::Put);
        assert_eq!(
            calls[2].body.as_ref().unwrap()["auth"],
            json!({"provider_ref": "heyo", "public_paths": [{"path": "/healthz", "scope": "public"}]})
        );
    }

    #[tokio::test]
    async fn a_missing_provider_names_the_plugin_that_declares_it() {
        let (c, stub) = client(Stub::new().json(200, status(Value::Null)).json(
            404,
            json!({"error": "no auth provider \"google\" in namespace \"team-a\""}),
        ));
        let e = c
            .set_auth("reports", &Gate::provider("google"))
            .await
            .unwrap_err();
        assert!(matches!(e, Error::Invalid(_)), "{e:?}");
        assert!(e.to_string().contains("auth-google"), "{e}");
        assert_eq!(stub.call_count(), 2, "nothing was written");
    }

    #[tokio::test]
    async fn clear_auth_removes_the_gate() {
        let (c, stub) = client(
            Stub::new()
                .json(200, status(json!({"provider_ref": "heyo"})))
                .json(200, status(Value::Null)),
        );
        c.clear_auth("reports").await.unwrap();
        let body = stub.calls()[1].body.clone().unwrap();
        assert!(body.get("auth").is_none(), "{body}");
    }
}
