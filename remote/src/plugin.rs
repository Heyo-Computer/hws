//! The namespace surface app-lb's `remote` plugin proxies to.
//!
//! An app-lb namespace that installs the `remote` plugin gets its repos in
//! app-lb's plugin console, at `/namespaces/<ns>/plugins/remote/ui[/…]`. app-lb
//! has already decided who the caller is and that they reach `<ns>`; it
//! rewrites the request onto `/-/ns/<ns>/…` here and sends:
//!
//! ```text
//! authorization: Bearer <REMOTE_PLUGIN_API_TOKEN>
//! x-heyo-base: /namespaces/<ns>/plugins/remote
//! x-heyo-actor: <principal>      x-heyo-actor-email: <email>
//! x-heyo-actor-admin: true|false
//! ```
//!
//! The bearer is what makes the other headers app-lb's word rather than
//! anybody's, which is why these routes are not mounted at all without
//! `REMOTE_PLUGIN_API_TOKEN`. `-` is not a namespace name, so `/-/ns/…` can
//! never be a repo's path.
//!
//! The pages are the web UI's own, served with a [`Mount`] in scope: the
//! caller is a [`Principal`] confined to `<ns>` (admin if app-lb says they
//! administer it, read otherwise), and every link the page renders is spelled
//! under app-lb's base, so the browser only ever sees app-lb's URLs. A form
//! post's origin is app-lb's to check; it reaches this service only through
//! app-lb's CRUD tier.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::{RawPathParams, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::api::AppState;
use crate::auth::{self, Kind, Principal, Tier};
use crate::registry::valid_namespace;

/// app-lb's plugin id, which is in every base it sends.
pub const PLUGIN_ID: &str = "remote";

/// What a request through the plugin surface is: one namespace, one caller,
/// and where the browser sees it.
#[derive(Debug, Clone)]
pub struct Mount {
    pub ns: String,
    /// app-lb's base for this namespace's plugin, when the request came
    /// through it. Exact match only: see [`base_for`].
    pub base: Option<String>,
    pub principal: Arc<Principal>,
}

impl Mount {
    /// The namespace page's URL. Every other URL on a page is this plus a
    /// suffix, exactly as the native `/<ns>` is.
    pub fn root(&self) -> String {
        match &self.base {
            Some(base) => format!("{base}/ui"),
            None => format!("/-/ns/{}", self.ns),
        }
    }
}

tokio::task_local! {
    static MOUNT: Mount;
}

/// The mount the current request is being served under, if it came through
/// the plugin surface. Pages render inside the handler's own task, so this is
/// in scope for everything they do.
pub fn current() -> Option<Mount> {
    MOUNT.try_with(Mount::clone).ok()
}

/// The base app-lb sent, if it is exactly this namespace's. The base ends up
/// in every `href` and `Location` on the page, so a value that is merely
/// plausible falls back to the native paths rather than being echoed.
pub fn base_for(ns: &str, sent: Option<&str>) -> Option<String> {
    let expected = format!("/namespaces/{ns}/plugins/{PLUGIN_ID}");
    sent.filter(|b| *b == expected).map(str::to_string)
}

/// The caller app-lb vouches for, confined to `ns`.
pub fn principal_for(ns: &str, headers: &HeaderMap) -> Principal {
    let get = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    let admin = get("x-heyo-actor-admin").as_deref() == Some("true");
    let actor = get("x-heyo-actor");
    let email = get("x-heyo-actor-email");
    Principal {
        kind: Kind::Plugin,
        // No actor is app-lb's operator, who administers every namespace.
        subject: format!("applb:{}", actor.as_deref().unwrap_or("operator")),
        fleet: None,
        namespaces: BTreeMap::from([(
            ns.to_string(),
            if admin { Tier::Admin } else { Tier::Read },
        )]),
        accounts: BTreeMap::new(),
        own_account: None,
        repos: None,
        token_id: None,
        display: email.or(actor),
    }
}

#[derive(Clone)]
struct Gate {
    /// SHA-256 of `REMOTE_PLUGIN_API_TOKEN`, compared in constant time.
    token_hash: [u8; 32],
}

impl Gate {
    fn admits(&self, headers: &HeaderMap) -> bool {
        let Some(bearer) = auth::bearer(headers) else {
            return false;
        };
        let got: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        got.ct_eq(&self.token_hash).into()
    }
}

/// `pages` behind the gate, under `/-/ns`. `None` without
/// `REMOTE_PLUGIN_API_TOKEN`.
pub fn router(token: Option<&str>, pages: Router<AppState>) -> Option<Router<AppState>> {
    let gate = Gate {
        token_hash: Sha256::digest(token?.as_bytes()).into(),
    };
    // `route_layer`, so a path no route matches is a plain 404 that never
    // reaches the gate.
    Some(Router::new().nest(
        "/-/ns",
        pages.route_layer(middleware::from_fn_with_state(gate, guard)),
    ))
}

async fn guard(
    State(gate): State<Gate>,
    params: RawPathParams,
    request: Request,
    next: Next,
) -> Response {
    // First, before the path is looked at: without the bearer, the actor
    // headers are anybody's.
    if !gate.admits(request.headers()) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            axum::Json(
                serde_json::json!({ "error": "this route takes the remote plugin's bearer token" }),
            ),
        )
            .into_response();
    }
    let ns = params
        .iter()
        .find(|(name, _)| *name == "ns")
        .map(|(_, value)| value.to_string())
        .unwrap_or_default();
    if !valid_namespace(&ns) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let headers = request.headers();
    let mount = Mount {
        base: base_for(
            &ns,
            headers.get("x-heyo-base").and_then(|v| v.to_str().ok()),
        ),
        principal: Arc::new(principal_for(&ns, headers)),
        ns,
    };
    MOUNT.scope(mount, next.run(request)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn only_this_namespaces_base_is_echoed() {
        assert_eq!(
            base_for("a", Some("/namespaces/a/plugins/remote")).as_deref(),
            Some("/namespaces/a/plugins/remote")
        );
        for bad in [
            "/namespaces/b/plugins/remote",
            "/namespaces/a/plugins/ci",
            "/namespaces/a/plugins/remote/",
            "https://evil.example/namespaces/a/plugins/remote",
            "/namespaces/a/plugins/remote?x",
        ] {
            assert_eq!(base_for("a", Some(bad)), None, "echoed {bad}");
        }
        assert_eq!(base_for("a", None), None);
    }

    #[test]
    fn the_actor_is_confined_to_the_namespace_at_app_lbs_tier() {
        let admin = principal_for(
            "a",
            &headers(&[
                ("x-heyo-actor", "user:7"),
                ("x-heyo-actor-email", "u@example.com"),
                ("x-heyo-actor-admin", "true"),
            ]),
        );
        assert_eq!(admin.subject, "applb:user:7");
        assert_eq!(admin.display(), "u@example.com");
        assert!(admin.allows("a", None, Tier::Admin));
        assert!(!admin.allows("b", None, Tier::Read));
        assert_eq!(admin.fleet, None);

        let viewer = principal_for("a", &headers(&[("x-heyo-actor", "token:t1")]));
        assert_eq!(viewer.tier_in("a"), Some(Tier::Read));
        assert!(!viewer.allows("a", None, Tier::Write));

        let operator = principal_for("a", &headers(&[("x-heyo-actor-admin", "true")]));
        assert_eq!(operator.subject, "applb:operator");
        assert!(operator.allows("a", None, Tier::Admin));
    }

    #[test]
    fn the_gate_wants_the_exact_token() {
        let gate = Gate {
            token_hash: Sha256::digest(b"plug").into(),
        };
        assert!(gate.admits(&headers(&[("authorization", "Bearer plug")])));
        assert!(!gate.admits(&headers(&[("authorization", "Bearer plug2")])));
        assert!(!gate.admits(&headers(&[])));
    }
}
