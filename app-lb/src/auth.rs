//! The sign-in gate in front of a deployment.
//!
//! A gated deployment's requests do not reach a backend until the caller has
//! presented a credential the gate accepts. The application behind it is
//! unchanged and unaware: it sees only requests that got through, optionally
//! with the caller's identity in `x-auth-request-*` headers.
//!
//! Three kinds of credential, and a gate may take any combination of them —
//! they are alternatives, not requirements:
//!
//! * **Google sign-in**, below: an OAuth redirect and a session cookie, for
//!   people in browsers.
//! * **An app-token** this LB minted ([`crate::tokens`]), for programs.
//! * **A JWT somebody else issued** ([`crate::jwt`]), for an application whose
//!   users already sign in elsewhere. The only one where app-lb holds no state
//!   at all: no session to issue, no table to look in, just a key and a policy.
//!
//! The flow is the OAuth 2.0 authorization code grant with PKCE, run by the
//! proxy on the deployment's own hostname:
//!
//! ```text
//! GET /anything          →  302 accounts.google.com/…  + a short-lived flow cookie
//! GET <base>/callback    →  POST oauth2.googleapis.com/token
//!                        →  302 back to /anything      + the session cookie
//! GET /anything          →  proxied to the backend
//! ```
//!
//! **No server-side session store.** Both cookies are self-describing and signed
//! with HMAC-SHA256, so a restart does not sign everyone out, and there is no
//! table to grow or to replicate. The key lives in one file (`APP_LB_AUTH_KEY`),
//! generated on first use.
//!
//! **The id token's signature is deliberately not verified.** It arrives in the
//! body of app-lb's own HTTPS POST to Google's token endpoint, authenticated by
//! the client secret — not from the browser — so the channel already establishes
//! the issuer. OpenID Connect Core §3.1.3.7 says exactly this: a token received
//! directly from the token endpoint over a TLS-protected channel may be
//! validated by that fact instead of by its signature, which is why there is no
//! JWKS fetch, cache or rotation to get wrong here. The *claims* are still
//! checked: audience, issuer, expiry, and `email_verified`.

use crate::config::AuthGate;
use crate::deployment::now_secs;
use crate::secrets::SecretStore;
use base64::Engine;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

mod heyo_login;

/// Where the browser is sent to sign in.
const GOOGLE_AUTHORIZE: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// Where app-lb exchanges the code for tokens, server to server.
const GOOGLE_TOKEN: &str = "https://oauth2.googleapis.com/token";
/// Both spellings Google uses for `iss`.
const GOOGLE_ISSUERS: [&str; 2] = ["accounts.google.com", "https://accounts.google.com"];

/// The sign-in round trip has to outlive a password prompt and a 2FA push, and
/// nothing else. The flow cookie is worthless afterwards.
const FLOW_TTL: Duration = Duration::from_secs(600);
/// Ceiling on the token exchange. A login blocks a request, so this is a
/// latency budget, not a generosity budget.
const TOKEN_TIMEOUT: Duration = Duration::from_secs(10);
/// Cookie carrying the in-flight sign-in (nonce, return path, PKCE verifier).
const FLOW_COOKIE: &str = "applb_auth_flow";

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// Who the caller is, as far as the provider says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The provider's stable subject id — the only field that is guaranteed not
    /// to change when someone's address does.
    pub subject: String,
    pub email: String,
    pub name: Option<String>,
    /// The Google Workspace domain governing the account, when there is one.
    pub hosted_domain: Option<String>,
    /// An app-token minted for this session, to be presented upstream on its
    /// behalf. `None` unless the gate sets `session_scope`.
    ///
    /// The secret itself, not its id: the proxy has to put it in a header, and
    /// the only alternative is a lookup on every request for a value the
    /// session already carries.
    pub session_token: Option<String>,
}

/// What the gate decided.
pub enum Decision {
    /// Let the request through. `Some` when there is an identity to forward;
    /// `None` for a path the gate does not cover.
    Allow(Box<Option<Identity>>),
    /// The gate answered the request itself — a redirect, a 403, the callback.
    /// Nothing more should happen to it.
    Answered(Response),
}

/// A response the gate wants written. Kept as data rather than written here so
/// this module needs no pingora types, and every decision is unit-testable.
pub struct Response {
    pub status: u16,
    pub body: String,
    pub content_type: &'static str,
    pub location: Option<String>,
    /// Complete `Set-Cookie` values.
    pub cookies: Vec<String>,
}

impl Response {
    fn redirect(location: String, cookies: Vec<String>) -> Self {
        Self {
            status: 302,
            body: String::new(),
            content_type: "text/plain; charset=utf-8",
            location: Some(location),
            cookies,
        }
    }

    fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            content_type: "text/plain; charset=utf-8",
            location: None,
            cookies: Vec::new(),
        }
    }

    fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            content_type: "application/json",
            location: None,
            cookies: Vec::new(),
        }
    }
}

/// The parts of a request the gate needs. A plain struct rather than a borrowed
/// `Session` so the decision logic can be exercised without a live connection.
pub struct RequestInfo<'a> {
    pub host: &'a str,
    pub path: &'a str,
    /// Raw query string, without `?`.
    pub query: Option<&'a str>,
    /// Every `Cookie` header value, joined by the caller or passed in order.
    pub cookies: Vec<String>,
    /// Whether the client reached app-lb over TLS. Decides the `Secure`
    /// attribute — setting it on a plaintext connection would make the cookie
    /// unusable, and omitting it on an encrypted one would leak the session.
    pub secure: bool,
    /// True when the caller looks like a browser navigating, which is what makes
    /// a redirect the right answer instead of a 401.
    pub wants_html: bool,
    /// Whether this deployment's upstream is app-lb's own admin listener. When
    /// it is, the gate checks a scoped public path's *tier* and leaves
    /// deployment and namespace scoping to the admin API, which does it better.
    /// See [`Authenticator::fronts_admin_api`].
    pub fronts_admin_api: bool,
    /// The value of an `Authorization: Bearer …` header, if there was one. An
    /// app-token gate checks this; a Google gate ignores it.
    pub bearer: Option<String>,
    /// The socket peer, for the SIEM's per-source rules. `None` in tests and for
    /// a non-inet peer. Never derived from a forwarded header — see
    /// `proxy::request_info`.
    pub client: Option<std::net::IpAddr>,
}

pub struct Authenticator {
    key: Vec<u8>,
    secrets: Arc<SecretStore>,
    /// Minted app-tokens, for gates that accept them. `None` in the tests that
    /// only exercise the Google path.
    tokens: Option<Arc<crate::tokens::TokenStore>>,
    http: reqwest::Client,
    /// Overridable so the token exchange can be pointed at a stub in tests.
    token_endpoint: String,
    authorize_endpoint: String,
    /// Queues rejected sign-ins for analysis. `None` when `APP_LB_SIEM=0`, and in
    /// tests.
    security: Option<crate::siem::SecuritySink>,
    /// This process's admin listener address, so a deployment fronting it can
    /// be recognised. `None` in tests and anywhere the gate stands only in
    /// front of ordinary applications.
    admin_addr: Option<String>,
    /// Issuer key sets for `jwks_url` gates. One cache for the whole LB, so two
    /// deployments behind the same issuer fetch its keys once between them.
    jwks: crate::jwt::JwksCache,
}

impl Authenticator {
    /// Whether this deployment's upstream is app-lb's own admin listener.
    ///
    /// The one upstream that authorizes *better* than the gate in front of it
    /// can. Every other upstream is an application with no idea what an
    /// app-token's namespace means, so the gate has to answer "may this
    /// credential touch this deployment" on its behalf. The admin API answers a
    /// finer question — may this credential touch this *deployment it is being
    /// asked about* — and asking the coarse one first can only ever refuse
    /// callers the fine one would have admitted.
    ///
    /// Compared as *addresses*, not as strings. A byte comparison was the first
    /// version and it was wrong on the first fleet that ran it: app-lb bound
    /// `0.0.0.0:9090` while the deployment fronting it named `127.0.0.1:9090` —
    /// the same listener, spelled the way each side naturally spells it. The
    /// mismatch is invisible (everything routes, the dashboard works) and
    /// surfaces only as a namespace-scoped token refused at the gate for no
    /// discoverable reason.
    pub fn fronts_admin_api(&self, spec: &crate::config::DeploymentSpec) -> bool {
        self.admin_addr
            .as_deref()
            .is_some_and(|addr| spec.upstreams.iter().any(|u| same_listener(addr, u)))
    }

    /// Queue one refused sign-in for analysis.
    ///
    /// Never carries a token or a code — only which step refused, and for the
    /// allow-list case the address that was refused, which is already in the
    /// `tracing::info!` beside it and is what the enumeration rule counts.
    fn observe_auth(
        &self,
        deployment: &str,
        req: &RequestInfo<'_>,
        action: crate::siem::AuthAction,
        subject: Option<&str>,
    ) {
        if let Some(siem) = &self.security {
            siem.observe_auth(crate::siem::AuthObs {
                ts: crate::obs::now_millis(),
                client: req.client,
                deployment: Some(Box::from(deployment)),
                path: Box::from(req.path),
                action,
                scheme: match req.bearer {
                    Some(_) => crate::siem::AuthScheme::Bearer,
                    None => crate::siem::AuthScheme::None,
                },
                subject: subject.map(Box::from),
            });
        }
    }
}

impl std::fmt::Debug for Authenticator {
    /// Hand-written so no `{:?}` can print the signing key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("token_endpoint", &self.token_endpoint)
            .finish()
    }
}

impl Authenticator {
    pub fn new(
        key: Vec<u8>,
        secrets: Arc<SecretStore>,
        tokens: Option<Arc<crate::tokens::TokenStore>>,
        security: Option<crate::siem::SecuritySink>,
    ) -> Self {
        Self::with_admin_addr(key, secrets, tokens, security, None)
    }

    /// As [`new`](Self::new), plus the address of this process's own admin
    /// listener — so the gate can recognise a deployment that fronts it.
    pub fn with_admin_addr(
        key: Vec<u8>,
        secrets: Arc<SecretStore>,
        tokens: Option<Arc<crate::tokens::TokenStore>>,
        security: Option<crate::siem::SecuritySink>,
        admin_addr: Option<String>,
    ) -> Self {
        Self {
            key,
            secrets,
            tokens,
            security,
            admin_addr,
            http: reqwest::Client::builder()
                .timeout(TOKEN_TIMEOUT)
                // A login is a person waiting; there is no retry that helps.
                .build()
                .unwrap_or_default(),
            token_endpoint: GOOGLE_TOKEN.to_string(),
            authorize_endpoint: GOOGLE_AUTHORIZE.to_string(),
            jwks: crate::jwt::JwksCache::new(),
        }
    }

    /// Load the session signing key, generating it on first use.
    ///
    /// Persisted rather than random-per-boot so a restart doesn't sign everyone
    /// out, and `0600` because anyone holding it can mint a session for any
    /// gated deployment.
    pub fn load_key(path: &Path) -> std::io::Result<Vec<u8>> {
        match std::fs::read(path) {
            Ok(bytes) if bytes.len() >= 32 => return Ok(bytes),
            Ok(_) => {
                return Err(std::io::Error::other(format!(
                    "{} is too short to be a signing key; delete it to have a new one \
                     generated (every session will be invalidated)",
                    path.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }

        let mut key = vec![0u8; 32];
        openssl::rand::rand_bytes(&mut key)
            .map_err(|e| std::io::Error::other(format!("no entropy for a signing key: {e}")))?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            crate::tls::create_dir_private(parent)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, b"")?;
        crate::tls::restrict(&tmp)?;
        std::fs::write(&tmp, &key)?;
        std::fs::rename(&tmp, path)?;
        tracing::info!(path = %path.display(), "generated a session signing key");
        Ok(key)
    }

    // -- the gate ----------------------------------------------------------

    /// Decide what happens to one request.
    ///
    /// Everything except the token exchange is pure; the exchange is the one
    /// await, and only on the callback path.
    pub async fn decide(
        &self,
        gate: &AuthGate,
        deployment_id: &str,
        deployment_namespace: &str,
        req: &RequestInfo<'_>,
    ) -> Decision {
        // app-lb's own endpoints first — they live under the deployment's
        // hostname, so they have to be claimed before the app sees them.
        if req.path == gate.callback_path() {
            return Decision::Answered(self.callback(gate, deployment_id, deployment_namespace, req).await);
        }
        if req.path == gate.logout_path() {
            return Decision::Answered(self.logout(gate, req));
        }
        if req.path == gate.login_path() {
            // An explicit sign-in link. Always starts a fresh flow, so it also
            // works as "switch account" after a logout.
            return Decision::Answered(self.start(gate, deployment_id, deployment_namespace, req, "/"));
        }

        // A path the sign-in gate does not sit in front of. That has never
        // meant "no authorization" — it means an API client is not sent to
        // Google — so what it requires instead is the entry's scope, checked
        // right here rather than left to an upstream that may not be checking.
        if let Some(scope) = gate.public_scope(req.path) {
            let Some(want) = scope.required() else {
                // `public`: the only spelling that admits a request presenting
                // nothing. Either the upstream authorizes, or there is nothing
                // behind this path to protect.
                return Decision::Allow(Box::new(None));
            };
            return self
                .scoped_public(gate, deployment_id, deployment_namespace, req, want)
                .await;
        }

        // An app-token, if this gate takes them. Checked before the session
        // cookie because a request carrying an explicit credential means it, and
        // because a program presenting a token should never be handed a redirect
        // to a sign-in page.
        //
        // Providers are alternatives: a gate listing both admits a person with a
        // Google session *or* a program with a token, and neither has to know
        // the other exists.
        // `admits` is skipped in front of app-lb's own admin API, for the same
        // reason it is skipped on a scoped public path there: the caller is not
        // acting on the deployment that fronts the API, and the API behind it
        // scope-checks every request against the deployment actually being
        // addressed. See `Authenticator::fronts_admin_api`.
        //
        // Both places need it. A path listed in `public_paths` takes the scoped
        // branch; everything else takes this one — so fixing only the first
        // leaves a namespace token able to reach `/metrics` and not
        // `/deployments`, which is a distinction nobody asked for.
        //
        // Admitting here is not authorizing: no tier is checked at this gate at
        // all, and the admin listener refuses an `admin: none` token on every
        // route it guards.
        if gate.accepts_app_token()
            && let Some(presented) = &req.bearer
            && let Some(tokens) = &self.tokens
            && let Some(token) = tokens.verify(presented, now_secs())
            && (req.fronts_admin_api || token.admits(deployment_id, deployment_namespace))
        {
            // No `Identity`: a token is not a person, and forwarding
            // `x-auth-request-email` for one would put a name upstream that
            // belongs to nobody. The token's own name is in the LB's logs.
            tracing::debug!(
                deployment = %deployment_id,
                token = %token.id,
                "request admitted by app-token",
            );
            return Decision::Allow(Box::new(None));
        }

        // A JWT, if this gate takes them. Checked before the session cookie for
        // the same reason an app-token is, and after the app-token because that
        // one is a cheap table lookup while this may have to reach the issuer
        // for a key.
        //
        // `reported` keeps a gate that accepts *both* machine credentials from
        // counting one bad bearer twice. The SIEM's brute-force rule counts
        // observations per source per window, so a mixed gate would otherwise
        // reach its threshold at half the failures a single-provider one does —
        // and the second observation says nothing the first did not.
        let mut reported = false;
        if let Some(policy) = gate.jwt_policy()
            && let Some(presented) = self.jwt_candidate(policy, req)
        {
            match self.verify_jwt(policy, &presented, req.host, Some(deployment_namespace)).await {
                Ok(identity) => {
                    tracing::debug!(
                        deployment = %deployment_id,
                        subject = %identity.subject,
                        "request admitted by JWT",
                    );
                    return Decision::Allow(Box::new(Some(identity)));
                }
                Err(e) => {
                    // The reason goes here and to the SIEM; the caller gets a
                    // bare 401. "Expired" and "signed with the wrong key" are
                    // precisely the feedback somebody probing a gate wants.
                    tracing::info!(
                        deployment = %deployment_id,
                        path = %req.path,
                        error = %e,
                        "refused a JWT at the gate",
                    );
                    self.observe_auth(
                        deployment_id,
                        req,
                        crate::siem::AuthAction::GateJwt,
                        None,
                    );
                    reported = true;
                }
            }
        }

        // Reaching here with a bearer in hand means it was presented and did not
        // admit — expired, revoked, forged, or scoped to another deployment.
        //
        // Gated on `bearer.is_some()` deliberately: a browser sends no
        // `Authorization` header on any request to a gated deployment, so
        // observing the no-credential case would flood the queue with the single
        // most common non-event there is.
        if gate.accepts_app_token() && req.bearer.is_some() && !reported {
            self.observe_auth(deployment_id, req, crate::siem::AuthAction::GateToken, None);
        }

        match self.session(gate, deployment_id, req) {
            Some(identity) => Decision::Allow(Box::new(Some(identity))),
            None => {
                // A token this store *recognises* that did not admit this deployment is
                // a different answer from no credential at all, and until this branch
                // the gate gave both the same one: a 401 naming a browser sign-in URL.
                // To a program that reads as "your connection is broken" — so the
                // holder of a perfectly valid token goes looking at transport,
                // credentials and DNS, none of which is the problem. The scoped-public
                // path has explained this since it was written (`scoped_public`); every
                // other path did not, which is an inconsistency nobody could have
                // guessed at from the outside.
                //
                // Discloses nothing: it is the caller's own token, and they reached
                // this deployment by naming it.
                //
                // Placed *after* the session check rather than beside the
                // admitting branch above, so this can only ever change a
                // refusal and never create one. A browser holding a valid
                // session that also happens to send an `Authorization` header
                // is let in exactly as before; only a caller with no other way
                // through reaches this, and for them the alternative was the
                // sign-in redirect that started the confusion.
                if gate.accepts_app_token()
                    && let Some(presented) = &req.bearer
                    && let Some(tokens) = &self.tokens
                    && let Some(token) = tokens.verify(presented, now_secs())
                {
                    // The admitting branch above returns on exactly one condition, so
                    // reaching here with a verified token means precisely that it does
                    // not admit this deployment. Never the tier: this gate does not
                    // check one, and saying "insufficient tier" here would send someone
                    // to mint a wider token that would be refused identically.
                    debug_assert!(
                        !req.fronts_admin_api,
                        "in front of the admin API `admits` is skipped, so a verified token \
                         cannot reach this branch",
                    );
                    tracing::info!(
                        deployment = %deployment_id,
                        namespace = %deployment_namespace,
                        token = %token.id,
                        path = %req.path,
                        "refused a recognised token that does not admit this deployment",
                    );
                    // Built with `serde_json` rather than `format!`, unlike the older
                    // bodies in this file: this one interpolates a deployment id, a
                    // namespace and a token name, none of which this module controls.
                    // Hand-escaping three caller-influenced strings into JSON is a bug
                    // waiting for the first id with a quote in it.
                    let scope = match &token.namespace {
                        Some(ns) => format!("confined to namespace \"{ns}\""),
                        None => "not confined to a namespace".to_string(),
                    };
                    let body = serde_json::json!({
                        "error": "insufficient_scope",
                        "detail": format!(
                            "this token is {scope} and its deployment scope does not cover \
                             \"{deployment_id}\" in namespace \"{deployment_namespace}\". This gate \
                             checks reach, never the admin tier, so a wider tier will not change \
                             this answer — the token needs this deployment, or its namespace, in \
                             scope."
                        ),
                        "deployment": deployment_id,
                        "namespace": deployment_namespace,
                        // Enough of the presenting token to explain *this* refusal, and
                        // deliberately not its full `deployments` list. The caller
                        // already holds the token, so nothing here is new to them — but
                        // this body is reachable at every gated hostname on the public
                        // internet, and a stolen token that answers "and here is
                        // everything else I open" at the first door is worse than one
                        // whose reach has to be probed. `GET /whoami` on the admin API
                        // gives the whole scope; that listener is loopback by default,
                        // which is the surface that difference is about.
                        "token_id": token.id,
                        "token_admin_scope": token.admin.as_str(),
                        "token_namespace": token.namespace,
                    });
                    return Decision::Answered(Response::json(
                        403,
                        serde_json::to_string(&body).unwrap_or_else(|_| {
                            // Unreachable — every value above is a string, a list of
                            // strings or null — but a gate must refuse rather than
                            // panic on the request path.
                            r#"{"error":"insufficient_scope"}"#.to_string()
                        }) + "\n",
                    ));
                }

                let return_to = match req.query {
                    Some(q) if !q.is_empty() => format!("{}?{}", req.path, q),
                    _ => req.path.to_string(),
                };
                Decision::Answered(self.start(gate, deployment_id, deployment_namespace, req, &return_to))
            }
        }
    }

    /// Decide a request on a scoped public path: no sign-in, but a credential.
    ///
    /// Deliberately never redirects. Every caller of one of these paths is a
    /// program — that is what taking the path out of the sign-in flow was for —
    /// and a program handed a 302 to an HTML login page fails in a way nobody
    /// can read. So the refusal is a 401 that names what would work.
    ///
    /// An app-token must both carry the tier *and* be scoped to this
    /// deployment: `admits` is what stops a token minted for one deployment
    /// walking in through another's public path. A JWT satisfies only the
    /// lowest tier, because a JWT carries an identity and no admin scope —
    /// there is nothing in it to compare against `view` or `admin`.
    async fn scoped_public(
        &self,
        gate: &AuthGate,
        deployment_id: &str,
        deployment_namespace: &str,
        req: &RequestInfo<'_>,
        want: crate::tokens::AdminScope,
    ) -> Decision {
        // `admits` asks "may this credential touch *this deployment*", which is
        // the right question for an ordinary application: the upstream has no
        // idea what a namespace is, so the gate answers on its behalf.
        //
        // It is the wrong question in front of app-lb's own admin API. A caller
        // there is not acting on the deployment that fronts it — they are acting
        // on whatever the admin API routes to, and the admin API scope-checks
        // that per request, per deployment, per namespace. Asking the coarse
        // question first can only refuse callers the fine one would admit: a
        // token confined to a namespace admits no deployment outside it, so it
        // could never pass a gate on a fronting deployment sitting in
        // `default` — and would then be refused for a namespace it never asked
        // about.
        if let Some(presented) = &req.bearer
            && let Some(tokens) = &self.tokens
            && let Some(token) = tokens.verify(presented, now_secs())
            && (req.fronts_admin_api || token.admits(deployment_id, deployment_namespace))
            && token.admin.satisfies(want)
        {
            tracing::debug!(
                deployment = %deployment_id,
                token = %token.id,
                path = %req.path,
                scope = ?want,
                "scoped public path admitted by app-token",
            );
            return Decision::Allow(Box::new(None));
        }

        // A JWT is an identity, not a tier. It answers "who", which is all the
        // lowest scope asks for.
        if want == crate::tokens::AdminScope::None
            && let Some(policy) = gate.jwt_policy()
            && let Some(presented) = self.jwt_candidate(policy, req)
            && let Ok(identity) = self.verify_jwt(policy, &presented, req.host, Some(deployment_namespace)).await
        {
            return Decision::Allow(Box::new(Some(identity)));
        }

        // A token this store knows, that simply does not satisfy this path, is a
        // *different answer* from a token nothing recognises — and conflating
        // them costs an afternoon, because the fixes have nothing in common.
        // One means "mint a wider token"; the other means "your token is not
        // from this server, or something in front answered before app-lb did".
        //
        // 403 discloses nothing here that the caller does not already hold: it
        // is their own token, and they reached this deployment by name. The
        // admin listener behind answers exactly this way for exactly this
        // situation (`decide_access`), so the two layers now agree.
        let known = req
            .bearer
            .as_ref()
            .and_then(|b| self.tokens.as_ref().and_then(|t| t.verify(b, now_secs())));

        if req.bearer.is_some() {
            self.observe_auth(deployment_id, req, crate::siem::AuthAction::GateToken, None);
        }
        tracing::info!(
            deployment = %deployment_id,
            path = %req.path,
            scope = ?want,
            recognised = known.is_some(),
            "refused a scoped public path",
        );

        if let Some(token) = known {
            let why = if !token.admin.satisfies(want) {
                format!(
                    "this token's admin scope is '{}', and this path needs '{}' or higher",
                    token.admin.as_str(),
                    want.as_str(),
                )
            } else {
                format!(
                    "this token does not admit deployment \"{deployment_id}\" — a token \
                     confined to a namespace admits only deployments in that namespace, so \
                     it cannot pass a gate on one outside it",
                )
            };
            debug_assert!(
                !req.fronts_admin_api || !token.admin.satisfies(want),
                "in front of the admin API only the tier is checked, so a refusal here \
                 can only ever be about the tier",
            );
            return Decision::Answered(Response::json(
                403,
                format!(
                    "{{\"error\":\"{}\",\"scope\":\"{}\"}}\n",
                    why.replace('"', "\\\""),
                    want.as_str(),
                ),
            ));
        }

        Decision::Answered(Response::json(
            401,
            format!(
                "{{\"error\":\"authentication required\",\"scope\":\"{}\",\
                 \"detail\":\"this path is outside the sign-in gate but still needs an \
                 app-token scoped to this deployment with admin scope '{}' or higher, as \
                 `Authorization: Bearer applb_…`\"}}\n",
                want.as_str(),
                want.as_str(),
            ),
        ))
    }

    /// The token a JWT gate should try, from the `Authorization` header or the
    /// cookie the gate names.
    ///
    /// The header wins when both are present: a request that sets
    /// `Authorization` is stating what it is presenting, and preferring a cookie
    /// it happens to also carry would make the outcome depend on something the
    /// caller did not mean to send.
    ///
    /// Only the *first* cookie of that name is considered, unlike the session
    /// cookie's several-candidates walk. A session cookie is app-lb's own and a
    /// realm can legitimately put two on one host; a JWT cookie belongs to the
    /// application, and trying each of a browser's cookies against an issuer's
    /// key is a way to turn one request into several signature checks.
    fn jwt_candidate(&self, policy: &crate::config::JwtSpec, req: &RequestInfo<'_>) -> Option<String> {
        if let Some(bearer) = &req.bearer {
            return Some(bearer.clone());
        }
        let name = policy.cookie.as_deref()?;
        cookie_values(&req.cookies, name)
            .into_iter()
            .next()
            .filter(|v| !v.is_empty())
    }

    /// Verify a presented token and turn its claims into an identity.
    ///
    /// A token that says where it may be used is held to it, whichever way it
    /// arrived: a `gateHost` claim must name the host this request reached, and
    /// a `namespace` claim the namespace of the deployment behind it (when the
    /// caller knows it). A scoped sign-in token minted for one host is
    /// otherwise a bearer credential for every gate that trusts the issuer.
    async fn verify_jwt(
        &self,
        policy: &crate::config::JwtSpec,
        token: &str,
        host: &str,
        namespace: Option<&str>,
    ) -> Result<Identity, crate::jwt::JwtError> {
        self.verify_jwt_claims(policy, token, host, namespace)
            .await
            .map(|(identity, _)| identity)
    }

    /// [`verify_jwt`](Self::verify_jwt), keeping the claims for a caller that
    /// needs more than the identity.
    async fn verify_jwt_claims(
        &self,
        policy: &crate::config::JwtSpec,
        token: &str,
        host: &str,
        namespace: Option<&str>,
    ) -> Result<(Identity, crate::jwt::Claims), crate::jwt::JwtError> {
        // Resolved per request rather than at registration, so rotating the
        // secret in the store takes effect on the next request instead of on the
        // next time somebody re-registers the deployment.
        let key = match (&policy.secret, &policy.public_key) {
            (Some(reference), _) => Some(crate::jwt::Key::Secret(
                self.secrets
                    .resolve(reference)
                    .map_err(|e| crate::jwt::JwtError::Key(e.to_string()))?
                    .into_bytes(),
            )),
            (None, Some(pem)) => Some(crate::jwt::Key::Public(
                crate::jwt::public_key_from_pem(pem).map_err(crate::jwt::JwtError::Key)?,
            )),
            // Neither: a `jwks_url` gate, whose key comes from the cache.
            (None, None) => None,
        };

        let claims = crate::jwt::verify(token, policy, key.as_ref(), &self.jwks, now_secs()).await?;

        if let Some(bound) = claims.string("gateHost")
            && !bound.eq_ignore_ascii_case(&bare_host(host))
        {
            return Err(crate::jwt::JwtError::Claim("the token was issued for another host"));
        }
        if let (Some(bound), Some(namespace)) = (claims.string("namespace"), namespace)
            && bound != namespace
        {
            return Err(crate::jwt::JwtError::Claim("the token was issued for another namespace"));
        }

        // The subject is the one claim a gate cannot do without: it is what goes
        // upstream as `x-auth-request-user`, and a token missing it means
        // `subject_claim` names something this issuer does not send. Refused
        // rather than defaulted, because the alternative is every request
        // arriving upstream as the same anonymous user.
        let subject = claims
            .string(&policy.subject_claim)
            .ok_or_else(|| crate::jwt::JwtError::Require(policy.subject_claim.clone()))?;

        let identity = Identity {
            subject,
            // Optional: a token issued to a service has no address, and a gate
            // that required one would refuse exactly the machine-to-machine case
            // this provider is good at.
            email: claims.string(&policy.email_claim).unwrap_or_default(),
            name: claims.string(&policy.name_claim),
            // A Google Workspace concept. Nothing else issues it, and inventing
            // one from an email suffix is the mistake `AuthGate::allows`
            // documents at length.
            hosted_domain: None,
            // A JWT is its own credential; there is no session behind it and
            // nothing to mint one from.
            session_token: None,
        };
        Ok((identity, claims))
    }

    /// Begin a sign-in: redirect to Google, remembering where to come back to.
    fn start(
        &self,
        gate: &AuthGate,
        deployment_id: &str,
        namespace: &str,
        req: &RequestInfo<'_>,
        return_to: &str,
    ) -> Response {
        if let Some(policy) = gate.jwt_policy()
            && let Some((authorize_url, _)) = policy.scoped_signin()
        {
            return self.start_scoped(gate, deployment_id, namespace, req, return_to, authorize_url);
        }
        if req.wants_html && gate.jwt_policy().is_some_and(|p| p.login_endpoint.is_some()) {
            return self.heyo_login_page(gate, deployment_id, req, return_to);
        }
        // A token-only gate has no sign-in flow to start: there is no provider to
        // redirect to and no cookie to set. Say what would actually work rather
        // than sending a browser into an OAuth round trip that ends in a blank
        // `client_id`.
        let Some((client_id, _)) = gate.google_credentials() else {
            // Unless the JWT provider names a hosted sign-in page: then a
            // *browser* holding no token is redirected there with the URL it
            // wanted, the issuer signs the person in and sets the JWT cookie,
            // and the return navigation is admitted by the cookie the gate
            // already knows to read. app-lb holds no flow state here — the
            // issuer's cookie is the whole session. See `JwtSpec::login_url`.
            //
            // A program (no HTML in `Accept`) falls through to the 401 below:
            // it can act on that, and cannot follow a redirect into an HTML
            // sign-in page anyway.
            if req.wants_html
                && let Some(policy) = gate.jwt_policy()
                && let Some(login_url) = policy.login_url.as_deref()
            {
                // The return URL is this deployment's own origin plus the safe
                // local path — never a caller-supplied absolute URL, so this
                // cannot be turned into an open redirect through the issuer.
                let return_uri = format!("{}{}", origin(req), safe_return_path(return_to));
                let sep = if login_url.contains('?') { '&' } else { '?' };
                let url = format!(
                    "{login_url}{sep}{}",
                    form_urlencoded::Serializer::new(String::new())
                        .append_pair(policy.login_redirect_param(), &return_uri)
                        .finish()
                );
                return Response::redirect(url, vec![]);
            }
            let mut accepts: Vec<&str> = Vec::new();
            let mut detail: Vec<&str> = Vec::new();
            if gate.accepts_app_token() {
                accepts.push("\"app-token\"");
                // The header, and only the header. `?app_token=` was advertised
                // here for a long time and has never worked at this gate: the
                // credential is read from `Authorization` alone
                // (`proxy::request_info`), and the query form exists on exactly
                // one route in the whole system — the admin API's WebSocket
                // shell, because a browser's `WebSocket` constructor cannot set
                // headers. Advertising it here sent programmatic callers to
                // generalise a form that is refused everywhere they would try
                // it, and a 401 that names a mechanism the path rejects is
                // worse than one that names nothing.
                detail.push("an app-token as `Authorization: Bearer applb_…`");
            }
            if gate.accepts_jwt() {
                accepts.push("\"jwt\"");
                detail.push("a JWT from this deployment's issuer as `Authorization: Bearer …`");
            }
            return Response::json(
                401,
                format!(
                    "{{\"error\":\"authentication required\",\"accepts\":[{}],\
                     \"detail\":\"present {}\"}}\n",
                    accepts.join(","),
                    detail.join(", or "),
                ),
            );
        };

        // An API client gets a 401 it can act on rather than a redirect it would
        // follow into an HTML sign-in page and then fail to parse.
        if !req.wants_html {
            let login = format!("{}{}", origin(req), gate.login_path());
            return Response::json(
                401,
                format!(
                    "{{\"error\":\"authentication required\",\"login_url\":\"{login}\"}}\n"
                ),
            );
        }

        let nonce = random_token();
        let verifier = random_token();
        let flow = Flow {
            nonce: nonce.clone(),
            return_to: safe_return_path(return_to),
            verifier: verifier.clone(),
            deployment: deployment_id.to_string(),
            exp: now_secs() + FLOW_TTL.as_secs(),
        };
        let redirect_uri = self.redirect_uri(gate, req);

        let url = format!(
            "{}?{}",
            self.authorize_endpoint,
            form_urlencoded::Serializer::new(String::new())
                .append_pair("client_id", client_id)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", "openid email profile")
                // The nonce is the `state`: an opaque value the browser echoes
                // back, which we compare against the signed cookie. That pairing
                // is what stops a third party from completing a login into
                // somebody else's browser.
                .append_pair("state", &nonce)
                .append_pair("code_challenge", &pkce_challenge(&verifier))
                .append_pair("code_challenge_method", "S256")
                // Ask for the account chooser rather than silently reusing
                // whichever Google session the browser happens to have.
                .append_pair("prompt", "select_account")
                .finish()
        );

        Response::redirect(
            url,
            // The flow cookie stays host-only even in a shared realm: it is a
            // single round trip that starts and ends on this hostname, and
            // widening it would put a live PKCE verifier on every sibling host
            // for no gain.
            vec![set_cookie(
                FLOW_COOKIE,
                &self.sign(&flow.encode()),
                req.secure,
                Some(FLOW_TTL.as_secs()),
                None,
            )],
        )
    }

    /// Handle Google's redirect back: verify, exchange, admit or refuse.
    async fn callback(
        &self,
        gate: &AuthGate,
        deployment_id: &str,
        namespace: &str,
        req: &RequestInfo<'_>,
    ) -> Response {
        let params = query_pairs(req.query);
        let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());

        // Google reports a refusal (`access_denied` when the user cancels) here
        // rather than by not coming back at all.
        if let Some(error) = get("error") {
            tracing::info!(deployment = %deployment_id, %error, "sign-in was refused at the provider");
            return Response::text(
                403,
                format!("sign-in was not completed ({error})\n"),
            );
        }

        let (Some(code), Some(state)) = (get("code"), get("state")) else {
            return Response::text(400, "the sign-in callback is missing `code` or `state`\n");
        };

        let presented = cookie_values(&req.cookies, FLOW_COOKIE);
        if presented.is_empty() {
            // Usually a bookmarked callback URL or a cookie dropped by a
            // `SameSite` policy, not an attack. Start over rather than dead-end.
            tracing::debug!(deployment = %deployment_id, "sign-in callback with no flow cookie");
            return self.start(gate, deployment_id, namespace, req, "/");
        }
        let verified: Vec<Flow> = presented
            .iter()
            .filter_map(|raw| self.verify(raw))
            .filter_map(|bytes| Flow::decode(&bytes))
            .collect();
        // More than one means a sibling host's flow cookie is in the jar too.
        // The live one is whichever nonce the provider just echoed back; falling
        // back to the first keeps the mismatch below reporting a real failure
        // rather than a missing cookie.
        let Some(flow) = verified
            .iter()
            .find(|f| ct_eq(state.as_bytes(), f.nonce.as_bytes()))
            .or_else(|| verified.first())
        else {
            return Response::text(400, "the sign-in state could not be verified\n");
        };
        if flow.exp <= now_secs() {
            return self.start(gate, deployment_id, namespace, req, &flow.return_to);
        }
        // The state parameter came back through the browser; the nonce it is
        // compared against came from a signed cookie. Constant-time because the
        // comparison is against a secret-ish value.
        if flow.deployment != deployment_id || !ct_eq(state.as_bytes(), flow.nonce.as_bytes()) {
            tracing::warn!(
                deployment = %deployment_id,
                "sign-in state did not match the flow cookie; refusing",
            );
            self.observe_auth(deployment_id, req, crate::siem::AuthAction::SigninState, None);
            return Response::text(400, "the sign-in state did not match\n");
        }

        if let Some(policy) = gate.jwt_policy()
            && let Some((_, token_url)) = policy.scoped_signin()
        {
            return self
                .finish_scoped(gate, deployment_id, namespace, req, policy, token_url, code, flow)
                .await;
        }

        let Some((client_id, client_secret)) = gate.google_credentials() else {
            tracing::error!(
                deployment = %deployment_id,
                "a sign-in callback arrived for a gate with no Google credentials",
            );
            return Response::text(500, "the sign-in gate is misconfigured on the server\n");
        };
        let secret = match self.secrets.resolve(client_secret) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(deployment = %deployment_id, error = %e, "auth client secret is missing");
                return Response::text(500, "the sign-in gate is misconfigured on the server\n");
            }
        };

        let redirect_uri = self.redirect_uri(gate, req);
        let claims = match self
            .exchange(client_id, &secret, code, &flow.verifier, &redirect_uri)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(deployment = %deployment_id, error = %e, "token exchange failed");
                self.observe_auth(
                    deployment_id,
                    req,
                    crate::siem::AuthAction::SigninExchange,
                    None,
                );
                return Response::text(502, "could not complete sign-in with the provider\n");
            }
        };

        let identity = match validate_claims(&claims, client_id) {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(deployment = %deployment_id, error = %e, "id token rejected");
                self.observe_auth(deployment_id, req, crate::siem::AuthAction::SigninToken, None);
                return Response::text(403, format!("sign-in was rejected: {e}\n"));
            }
        };

        if !gate.allows(&identity.email, identity.hosted_domain.as_deref()) {
            // Deliberately says who was refused: the person is looking at this
            // page, and "which account am I signed in as" is the first thing
            // they need. The logout link lets them switch without clearing
            // cookies by hand.
            tracing::info!(
                deployment = %deployment_id,
                email = %identity.email,
                "sign-in refused by the allow-list",
            );
            self.observe_auth(
                deployment_id,
                req,
                crate::siem::AuthAction::SigninRefused,
                Some(&identity.email),
            );
            return Response::text(
                403,
                format!(
                    "{} is not allowed to access this deployment.\n\nSign in with a \
                     different account: {}{}\n",
                    identity.email,
                    origin(req),
                    gate.login_path()
                ),
            );
        }

        // Computed from the host that actually served the callback, not from the
        // spec alone: a realm that does not cover this hostname must fall back
        // to a host-only cookie, or the browser drops it and the user loops.
        let realm = gate.cookie_domain_for(req.host);
        if gate.cookie_domain.is_some() && realm.is_none() {
            tracing::warn!(
                deployment = %deployment_id,
                host = %req.host,
                cookie_domain = ?gate.cookie_domain,
                "auth.cookie_domain does not cover this hostname; issuing a host-only \
                 session cookie, so sign-in will not be shared with sibling deployments",
            );
        }

        // The credential this session will present upstream, if the gate says
        // a sign-in is worth one. Minted here rather than on first use because
        // this is the one moment the identity has been proven; every later
        // request only has a cookie saying it once was.
        let (token, token_id) = self.mint_session_token(gate, deployment_id, &identity);

        let session = Session {
            subject: identity.subject.clone(),
            email: identity.email.clone(),
            name: identity.name.clone(),
            hosted_domain: identity.hosted_domain.clone(),
            deployment: deployment_id.to_string(),
            policy: gate.policy_fingerprint(),
            exp: now_secs() + gate.session_ttl_secs,
            token,
            token_id,
        };
        tracing::info!(
            deployment = %deployment_id,
            email = %identity.email,
            "sign-in succeeded",
        );

        Response::redirect(
            format!("{}{}", origin(req), flow.return_to),
            vec![
                set_cookie(
                    &gate.cookie_name,
                    &self.sign(&session.encode()),
                    req.secure,
                    Some(gate.session_ttl_secs),
                    realm.as_deref(),
                ),
                clear_cookie(FLOW_COOKIE, req.secure, None),
            ],
        )
    }

    /// Begin a scoped sign-in: send the browser to the issuer's authorization
    /// endpoint asking for this deployment's namespace. See
    /// [`JwtSpec::authorize_url`](crate::config::JwtSpec::authorize_url).
    ///
    /// The same flow cookie, `state` and PKCE as the Google path; what differs
    /// is the `scope`, which is this gate telling the issuer what access it
    /// needs, and the issuer deciding.
    fn start_scoped(
        &self,
        gate: &AuthGate,
        deployment_id: &str,
        namespace: &str,
        req: &RequestInfo<'_>,
        return_to: &str,
        authorize_url: &str,
    ) -> Response {
        if !req.wants_html {
            let login = format!("{}{}", origin(req), gate.login_path());
            return Response::json(
                401,
                serde_json::json!({
                    "error": "authentication required",
                    "login_url": login,
                    "detail": "sign in in a browser, or present a token from this deployment's \
                               issuer as `Authorization: Bearer …`",
                })
                .to_string()
                    + "\n",
            );
        }
        let nonce = random_token();
        let verifier = random_token();
        let flow = Flow {
            nonce: nonce.clone(),
            return_to: safe_return_path(return_to),
            verifier: verifier.clone(),
            deployment: deployment_id.to_string(),
            exp: now_secs() + FLOW_TTL.as_secs(),
        };
        let sep = if authorize_url.contains('?') { '&' } else { '?' };
        let url = format!(
            "{authorize_url}{sep}{}",
            form_urlencoded::Serializer::new(String::new())
                .append_pair("response_type", "code")
                .append_pair("redirect_uri", &self.redirect_uri(gate, req))
                .append_pair("scope", &format!("namespace:{namespace}"))
                .append_pair("state", &nonce)
                .append_pair("code_challenge", &pkce_challenge(&verifier))
                .append_pair("code_challenge_method", "S256")
                .finish()
        );
        Response::redirect(
            url,
            vec![set_cookie(
                FLOW_COOKIE,
                &self.sign(&flow.encode()),
                req.secure,
                Some(FLOW_TTL.as_secs()),
                None,
            )],
        )
    }

    /// Finish a scoped sign-in once the flow cookie and `state` have checked
    /// out: redeem the code, verify the token against this gate's policy, and
    /// insist it names this host and this deployment's namespace.
    ///
    /// The claims are *required* here, not merely checked when present: the
    /// token came back from an exchange this gate asked to be scoped, and one
    /// that is not means the issuer ignored the request.
    #[allow(clippy::too_many_arguments)]
    async fn finish_scoped(
        &self,
        gate: &AuthGate,
        deployment_id: &str,
        namespace: &str,
        req: &RequestInfo<'_>,
        policy: &crate::config::JwtSpec,
        token_url: &str,
        code: &str,
        flow: &Flow,
    ) -> Response {
        let redirect_uri = self.redirect_uri(gate, req);
        let token = match self.exchange_scoped(token_url, code, &flow.verifier, &redirect_uri).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(deployment = %deployment_id, error = %e, "scoped sign-in exchange failed");
                self.observe_auth(deployment_id, req, crate::siem::AuthAction::SigninExchange, None);
                return Response::text(502, "could not complete sign-in with the issuer\n");
            }
        };
        let (identity, claims) = match self
            .verify_jwt_claims(policy, &token, req.host, Some(namespace))
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(deployment = %deployment_id, error = %e, "scoped sign-in token rejected");
                self.observe_auth(deployment_id, req, crate::siem::AuthAction::SigninToken, None);
                return Response::text(403, format!("sign-in was rejected: {e}\n"));
            }
        };
        if claims.string("gateHost").is_none() || claims.string("namespace").is_none() {
            tracing::warn!(
                deployment = %deployment_id,
                "scoped sign-in token carries no gateHost or namespace; refusing",
            );
            self.observe_auth(deployment_id, req, crate::siem::AuthAction::SigninToken, None);
            return Response::text(403, "sign-in was rejected: the token is not scoped to this host\n");
        }

        // The session ends when the token would have, if that is sooner: the
        // issuer's lifetime is its statement of how long this grant holds.
        let token_exp = claims
            .get("exp")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX);
        let exp = (now_secs() + gate.session_ttl_secs).min(token_exp);
        let session = Session {
            subject: identity.subject.clone(),
            email: identity.email.clone(),
            name: identity.name.clone(),
            hosted_domain: None,
            deployment: deployment_id.to_string(),
            policy: gate.policy_fingerprint(),
            exp,
            token: None,
            token_id: None,
        };
        tracing::info!(
            deployment = %deployment_id,
            namespace = %namespace,
            subject = %identity.subject,
            "scoped sign-in succeeded",
        );
        Response::redirect(
            format!("{}{}", origin(req), flow.return_to),
            vec![
                // Host-only, always: validation refuses a realm on this flow.
                set_cookie(
                    &gate.cookie_name,
                    &self.sign(&session.encode()),
                    req.secure,
                    Some(exp.saturating_sub(now_secs())),
                    None,
                ),
                clear_cookie(FLOW_COOKIE, req.secure, None),
            ],
        )
    }

    /// Redeem a scoped sign-in code at the issuer's token endpoint. A public
    /// client: the PKCE verifier is the proof, as RFC 7636 intends.
    async fn exchange_scoped(
        &self,
        token_url: &str,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<String, String> {
        let response = self
            .http
            .post(token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", verifier),
            ])
            .send()
            .await
            .map_err(|e| format!("could not reach the token endpoint: {e}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| format!("could not read the token response: {e}"))?;
        if !status.is_success() {
            return Err(format!(
                "the issuer rejected the exchange (HTTP {status}): {}",
                body.chars().take(300).collect::<String>()
            ));
        }
        #[derive(Deserialize)]
        struct ScopedToken {
            access_token: String,
        }
        serde_json::from_str::<ScopedToken>(&body)
            .map(|t| t.access_token)
            .map_err(|e| format!("token response was not the expected JSON: {e}"))
    }

    /// Mint the app-token a session presents upstream, if this gate asks for
    /// one. Returns `(secret, id)`, both `None` when it does not.
    ///
    /// Scoped to the whole fleet rather than to this deployment, because the
    /// case it exists for is a dashboard whose upstream *is* the admin API —
    /// a token admitting only the deployment it was minted at could not read
    /// the deployment list that dashboard is for. That is a real grant, which
    /// is why `session_scope` has no default and has to be written down.
    ///
    /// A failure to mint is logged and not fatal: the session is still valid
    /// for the gate itself, so the person gets in and the upstream refuses
    /// them, which is a far better failure than a sign-in that dead-ends.
    fn mint_session_token(
        &self,
        gate: &AuthGate,
        deployment_id: &str,
        identity: &Identity,
    ) -> (Option<String>, Option<String>) {
        let (Some(scope), Some(tokens)) = (gate.session_scope, self.tokens.as_ref()) else {
            return (None, None);
        };
        // Named for the person and the deployment, because this list is read
        // by an operator deciding what to revoke, and "session" alone would be
        // a page of identical rows.
        let name = format!("session {} @ {}", identity.email, deployment_id);
        let req = crate::tokens::NewToken {
            name,
            admin: scope,
            namespace: None,
            deployments: vec!["*".to_string()],
            // Expires with the session. A token outliving the cookie that
            // carries it is a credential nobody can present and nobody revokes.
            expires_in_secs: Some(gate.session_ttl_secs),
        };
        match tokens.mint(req, now_secs()) {
            Ok((summary, secret)) => {
                if let Err(e) = tokens.persist() {
                    // In memory and working; gone on restart. Worth saying,
                    // not worth refusing the sign-in over.
                    tracing::warn!(error = %e, "session token minted but not persisted");
                }
                tracing::info!(
                    deployment = %deployment_id,
                    email = %identity.email,
                    token = %summary.id,
                    scope = %scope.as_str(),
                    "minted a session token",
                );
                (Some(secret), Some(summary.id))
            }
            Err(e) => {
                tracing::error!(deployment = %deployment_id, error = %e, "could not mint a session token");
                (None, None)
            }
        }
    }

    fn logout(&self, gate: &AuthGate, req: &RequestInfo<'_>) -> Response {
        // Revoke the session's token before dropping the cookie that carries
        // it. Clearing the cookie alone would leave a live fleet-scoped
        // credential in the store with nothing pointing at it — unreachable by
        // its owner and unnoticed by everyone else until it expired.
        if let Some(tokens) = self.tokens.as_ref() {
            for raw in cookie_values(&req.cookies, &gate.cookie_name) {
                let Some(session) = self.verify(&raw).and_then(|b| Session::decode(&b)) else {
                    continue;
                };
                if let Some(id) = &session.token_id
                    && tokens.revoke(id)
                {
                    if let Err(e) = tokens.persist() {
                        tracing::warn!(error = %e, "session token revoked but not persisted");
                    }
                    tracing::info!(token = %id, email = %session.email, "revoked a session token");
                }
            }
        }

        // Only app-lb's own cookie is cleared: signing the user out of Google
        // itself is not app-lb's to do, and doing it would sign them out of
        // every other tab they have open.
        let mut response = Response::redirect(
            format!("{}{}", origin(req), gate.login_path()),
            vec![
                clear_cookie(&gate.cookie_name, req.secure, gate.cookie_domain_for(req.host).as_deref()),
                clear_cookie(FLOW_COOKIE, req.secure, None),
            ],
        );
        if let Some(policy) = gate.jwt_policy()
            && policy.login_endpoint.is_some()
            && let Some(cookie) = policy.cookie.as_deref()
        {
            response.cookies.push(clear_cookie(cookie, req.secure, None));
        }
        response
    }

    /// The identity in the request's session cookie, if it has a valid one.
    ///
    /// "The" cookie is a simplification the browser does not share — see
    /// [`cookie_values`]. A request can carry several under this name and only
    /// one of them be this gate's, so every candidate is tried and the first
    /// that stands up wins. Refusing on the first one that does not is what
    /// turned a stale neighbouring cookie into a permanent sign-in loop.
    fn session(
        &self,
        gate: &AuthGate,
        deployment_id: &str,
        req: &RequestInfo<'_>,
    ) -> Option<Identity> {
        let presented = cookie_values(&req.cookies, &gate.cookie_name);
        let found = presented
            .iter()
            .enumerate()
            .find_map(|(i, raw)| Some((i, self.session_from(gate, deployment_id, raw)?)));

        // Several cookies under one name means some other gate's realm covers
        // this hostname. Benign once it is handled, and worth saying out loud
        // when none of them is a session: that is the shape of the loop this
        // used to cause, and previously it produced a wall of redirects with
        // nothing anywhere to say why.
        if presented.len() > 1 {
            match &found {
                Some((i, _)) => tracing::debug!(
                    deployment = %deployment_id,
                    host = %req.host,
                    cookie = %gate.cookie_name,
                    presented = presented.len(),
                    accepted = i,
                    "several cookies share this gate's session cookie name",
                ),
                None => tracing::warn!(
                    deployment = %deployment_id,
                    host = %req.host,
                    cookie = %gate.cookie_name,
                    presented = presented.len(),
                    "{presented} cookies named {name:?} reached this hostname and none is a \
                     session for it; a sibling gate's `auth.cookie_domain` almost certainly \
                     covers this host. Give one of the two gates a distinct `auth.cookie_name`, \
                     or drop the realm",
                    presented = presented.len(),
                    name = gate.cookie_name,
                ),
            }
        }
        found.map(|(_, identity)| identity)
    }

    /// One candidate cookie, checked end to end. `None` for anything that is not
    /// a live session *this* gate would honour — which is the same standard as
    /// before, applied to each cookie rather than only to the first.
    fn session_from(&self, gate: &AuthGate, deployment_id: &str, raw: &str) -> Option<Identity> {
        let session = Session::decode(&self.verify(raw)?)?;
        if session.exp <= now_secs() {
            return None;
        }
        // A session does not outlive a tightened allow-list: the fingerprint
        // covers the provider, the client id, both allow-lists, and whether the
        // gate shares sessions at all.
        if session.policy != gate.policy_fingerprint() {
            return None;
        }
        // And it is scoped to the deployment that issued it — unless this gate
        // opted into a shared realm, which is what makes one sign-in cover every
        // deployment under a parent domain instead of one per hostname.
        //
        // Relaxing this is safe *because* of the check above, not in spite of
        // it. Reaching here means the two gates have byte-identical policy, so
        // whoever holds this session is somebody this gate would have admitted
        // anyway; the round trip it skips would have ended in exactly this
        // identity. A gate with a different allow-list has a different
        // fingerprint and refuses the cookie, shared realm or not.
        if session.deployment != deployment_id && gate.cookie_domain.is_none() {
            return None;
        }
        Some(Identity {
            subject: session.subject,
            email: session.email,
            name: session.name,
            hosted_domain: session.hosted_domain,
            // Carried straight through to the proxy, which presents it
            // upstream. Absent on every session issued before the gate asked
            // for one, and on every gate that still does not.
            session_token: session.token,
        })
    }

    /// `https://<host><base_path>/callback`, or the spec's override.
    fn redirect_uri(&self, gate: &AuthGate, req: &RequestInfo<'_>) -> String {
        match &gate.redirect_url {
            Some(u) => u.clone(),
            None => format!("{}{}", origin(req), gate.callback_path()),
        }
    }

    /// Trade the authorization code for tokens. Server to server, authenticated
    /// with the client secret, which is why the id token that comes back can be
    /// trusted without checking its signature.
    async fn exchange(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<IdClaims, String> {
        let response = self
            .http
            .post(&self.token_endpoint)
            .form(&[
                ("code", code),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
                ("code_verifier", verifier),
            ])
            .send()
            .await
            .map_err(|e| format!("could not reach the token endpoint: {e}"))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| format!("could not read the token response: {e}"))?;
        if !status.is_success() {
            // Google's error body names the cause (`redirect_uri_mismatch` is
            // the usual one), and it contains no credential, so it is worth
            // keeping — it is the difference between a five-minute fix and an
            // afternoon.
            return Err(format!(
                "the provider rejected the exchange (HTTP {status}): {}",
                body.chars().take(300).collect::<String>()
            ));
        }

        let token: TokenResponse =
            serde_json::from_str(&body).map_err(|e| format!("token response was not JSON: {e}"))?;
        let id_token = token
            .id_token
            .ok_or("the token response carried no id_token")?;
        decode_id_token(&id_token)
    }

    // -- signing -----------------------------------------------------------

    /// `<payload>.<mac>`, both base64url. The payload is not encrypted: it holds
    /// an email address and an expiry, which the person it belongs to already
    /// knows. The signature is what makes it unforgeable.
    fn sign(&self, payload: &[u8]) -> String {
        let encoded = b64().encode(payload);
        let mac = hmac(&self.key, encoded.as_bytes());
        format!("{encoded}.{}", b64().encode(mac))
    }

    fn verify(&self, token: &str) -> Option<Vec<u8>> {
        let (encoded, mac) = token.rsplit_once('.')?;
        let presented = b64().decode(mac).ok()?;
        let expected = hmac(&self.key, encoded.as_bytes());
        if !ct_eq(&presented, &expected) {
            return None;
        }
        b64().decode(encoded).ok()
    }
}

/// The in-flight sign-in, carried in a cookie for the duration of the round trip.
#[derive(Debug, serde::Serialize, Deserialize, PartialEq, Eq)]
struct Flow {
    #[serde(rename = "n")]
    nonce: String,
    #[serde(rename = "r")]
    return_to: String,
    /// PKCE code verifier. In the cookie and never in the URL — the challenge
    /// (its hash) is what goes to the provider.
    #[serde(rename = "v")]
    verifier: String,
    #[serde(rename = "d")]
    deployment: String,
    #[serde(rename = "e")]
    exp: u64,
}

impl Flow {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("flow state serializes")
    }
    fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// A signed-in session.
#[derive(Debug, serde::Serialize, Deserialize, PartialEq, Eq)]
struct Session {
    #[serde(rename = "s")]
    subject: String,
    #[serde(rename = "m")]
    email: String,
    #[serde(rename = "nm", skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "hd", skip_serializing_if = "Option::is_none")]
    hosted_domain: Option<String>,
    #[serde(rename = "d")]
    deployment: String,
    /// Fingerprint of the allow-list this was issued under.
    #[serde(rename = "p")]
    policy: String,
    #[serde(rename = "e")]
    exp: u64,
    /// The minted token's secret, presented upstream while this session lasts.
    #[serde(rename = "t", skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    /// Its id, so signing out can revoke it. Kept apart from the secret because
    /// revocation needs the id and the header needs the secret, and carrying
    /// only one would mean deriving the other — which for a hashed secret is
    /// not possible in that direction.
    #[serde(rename = "ti", skip_serializing_if = "Option::is_none")]
    token_id: Option<String>,
}

impl Session {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("session serializes")
    }
    fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

/// The claims app-lb reads out of the id token.
#[derive(Debug, Deserialize, Default)]
struct IdClaims {
    iss: Option<String>,
    aud: Option<String>,
    sub: Option<String>,
    email: Option<String>,
    #[serde(default)]
    email_verified: BoolLike,
    hd: Option<String>,
    name: Option<String>,
    exp: Option<u64>,
}

/// `email_verified` is a boolean in Google's tokens, but the spec allows the
/// string form and other providers send it — accepting both costs nothing and
/// avoids a parse failure that would read as "sign-in is broken".
#[derive(Debug, Deserialize, Default)]
#[serde(untagged)]
enum BoolLike {
    Bool(bool),
    Str(String),
    #[default]
    Missing,
}

impl BoolLike {
    fn is_true(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Str(s) => s.eq_ignore_ascii_case("true"),
            Self::Missing => false,
        }
    }
}

/// Pull the claim set out of a JWT without verifying its signature — see the
/// module docs for why that is sound here, and only here.
fn decode_id_token(token: &str) -> Result<IdClaims, String> {
    let mut parts = token.split('.');
    let (_header, payload) = (
        parts.next().ok_or("id_token is not a JWT")?,
        parts.next().ok_or("id_token has no payload")?,
    );
    let bytes = b64()
        .decode(payload)
        .map_err(|e| format!("id_token payload is not base64url: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("id_token payload is not JSON: {e}"))
}

/// Check the claims that decide whether this token is about the right person,
/// from the right issuer, for this client, right now.
fn validate_claims(claims: &IdClaims, client_id: &str) -> Result<Identity, String> {
    let iss = claims.iss.as_deref().unwrap_or_default();
    if !GOOGLE_ISSUERS.contains(&iss) {
        return Err(format!("unexpected issuer {iss:?}"));
    }
    // Without this, a token minted for *another* application could be replayed
    // here — the single most important check in the set.
    match claims.aud.as_deref() {
        Some(aud) if ct_eq(aud.as_bytes(), client_id.as_bytes()) => {}
        _ => return Err("the id token was issued for a different client".into()),
    }
    if claims.exp.is_none_or(|exp| exp <= now_secs()) {
        return Err("the id token has expired".into());
    }
    let email = claims
        .email
        .clone()
        .ok_or("the id token carried no email address")?;
    if !claims.email_verified.is_true() {
        return Err(format!("{email} is not a verified address"));
    }

    Ok(Identity {
        subject: claims.sub.clone().unwrap_or_else(|| email.clone()),
        email: email.to_ascii_lowercase(),
        name: claims.name.clone(),
        hosted_domain: claims.hd.clone(),
        // Minted by the callback once the allow-list has had its say, not here:
        // these are the provider's claims, and being able to prove who you are
        // is not the same as being allowed in.
        session_token: None,
    })
}

// -- small helpers ---------------------------------------------------------

/// Whether two `host:port` strings name the same local listener.
///
/// The port must match exactly; the host is compared by what it *means*:
///
/// * a wildcard bind (`0.0.0.0`, `::`, `*`, or an empty host) answers on every
///   local address, so any host on that port reaches it;
/// * otherwise the two must be the same address — textually, as parsed IPs, or
///   as two spellings of loopback.
///
/// No DNS. This runs on the request path, and a name lookup there would trade a
/// comparison for a network round trip; a hostname that needs one falls through
/// to `false`, which refuses rather than admits.
fn same_listener(admin: &str, upstream: &str) -> bool {
    fn split(s: &str) -> Option<(String, String)> {
        let (host, port) = s.trim().rsplit_once(':')?;
        let host = host.trim().trim_start_matches('[').trim_end_matches(']');
        Some((host.to_ascii_lowercase(), port.trim().to_string()))
    }
    let (Some((ah, ap)), Some((uh, up))) = (split(admin), split(upstream)) else {
        return false;
    };
    if ap != up {
        return false;
    }
    // A wildcard bind is reachable at every local address on that port, so the
    // upstream's choice of spelling cannot make it a different listener. Nor can
    // anything else be listening there: binding 0.0.0.0:P and 127.0.0.1:P at
    // once is what the OS refuses.
    if matches!(ah.as_str(), "0.0.0.0" | "::" | "*" | "") {
        return true;
    }
    if ah == uh {
        return true;
    }
    let loopback = |h: &str| {
        h == "localhost"
            || h.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
    };
    if loopback(&ah) && loopback(&uh) {
        return true;
    }
    match (ah.parse::<std::net::IpAddr>(), uh.parse::<std::net::IpAddr>()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let pkey = openssl::pkey::PKey::hmac(key).expect("hmac key");
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey)
        .expect("hmac signer");
    signer.update(data).expect("hmac update");
    signer.sign_to_vec().expect("hmac sign")
}

/// Length-then-content comparison that doesn't short-circuit, so a matching
/// prefix cannot be timed out of a signature or a nonce.
///
/// Shared with [`crate::jwt`], which compares an HMAC for the same reason.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn random_token() -> String {
    let mut bytes = [0u8; 24];
    openssl::rand::rand_bytes(&mut bytes).expect("entropy for a sign-in nonce");
    b64().encode(bytes)
}

/// S256: the provider gets the hash, the cookie keeps the verifier.
fn pkce_challenge(verifier: &str) -> String {
    let digest = openssl::hash::hash(
        openssl::hash::MessageDigest::sha256(),
        verifier.as_bytes(),
    )
    .expect("sha256 of a byte string cannot fail");
    b64().encode(digest)
}

/// `https://host` or `http://host`, for building absolute URLs.
/// A request host without port or trailing dot, lowercased — the form a
/// `gateHost` claim names.
fn bare_host(host: &str) -> String {
    let host = host.trim_end_matches('.');
    let host = match host.rsplit_once(':') {
        // An IPv6 literal keeps its colons; only a trailing `:port` goes.
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && !h.ends_with(':') => h,
        _ => host,
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn origin(req: &RequestInfo<'_>) -> String {
    let scheme = if req.secure { "https" } else { "http" };
    format!("{scheme}://{}", req.host)
}

/// Reduce a return target to something that cannot leave this site.
///
/// The value comes from the request line and is later used as a `Location`, so
/// it has to be a path and only a path: `//evil.example` is a protocol-relative
/// URL that browsers follow off-site, and a full URL would be an open redirect.
fn safe_return_path(path: &str) -> String {
    let ok = path.starts_with('/')
        && !path.starts_with("//")
        && !path.starts_with("/\\")
        && !path.contains(|c: char| c.is_control())
        && path.len() <= 2048;
    if ok { path.to_string() } else { "/".to_string() }
}

/// Every cookie with this name, across every `Cookie` header on the request.
///
/// Plural on purpose, and the plural case is not exotic. A cookie jar keys an
/// entry on name *and* domain *and* path (RFC 6265 §5.3), so a browser can hold
/// a host-only `applb_session` for `admin.example.com` and a realm-scoped one
/// for `example.com` at the same time, and it sends **both** — ordered by path
/// length, then by which was created first (§5.4). Nothing about that order
/// favours the one this gate issued.
///
/// Reading only the first is therefore a sign-in loop waiting to happen: a
/// foreign cookie shadows the real session, the gate refuses it, redirects to
/// the provider, sets a fresh cookie that still sorts second, and the round trip
/// repeats forever with nothing in any log to explain it. Callers try every
/// candidate and take the first that actually verifies.
fn cookie_values(headers: &[String], name: &str) -> Vec<String> {
    let mut found = Vec::new();
    for header in headers {
        for pair in header.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=')
                && k.trim() == name
            {
                found.push(v.trim().to_string());
            }
        }
    }
    found
}

fn set_cookie(
    name: &str,
    value: &str,
    secure: bool,
    max_age: Option<u64>,
    domain: Option<&str>,
) -> String {
    let mut c = format!("{name}={value}; Path=/; HttpOnly");
    // Lax, not Strict: the provider's redirect back is a cross-site top-level
    // navigation, and Strict would withhold the flow cookie on exactly that
    // request — the sign-in would loop forever. It is also what lets a link from
    // the admin directory into a gated deployment carry the session, since that
    // navigation is cross-site too.
    c.push_str("; SameSite=Lax");
    // Present only for a realm session. A `Domain` widens the cookie to every
    // host under it, so it is never added by default and never guessed at — see
    // `AuthGate::cookie_domain`.
    if let Some(d) = domain {
        c.push_str(&format!("; Domain={d}"));
    }
    if secure {
        c.push_str("; Secure");
    }
    if let Some(age) = max_age {
        c.push_str(&format!("; Max-Age={age}"));
    }
    c
}

/// The `Domain` matters here too, and getting it wrong is a silent failure: a
/// cookie set with `Domain=example.com` and one set host-only are two different
/// cookies, and clearing the wrong one leaves the user signed in with a logout
/// that reported success.
fn clear_cookie(name: &str, secure: bool, domain: Option<&str>) -> String {
    let mut c = format!("{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if let Some(d) = domain {
        c.push_str(&format!("; Domain={d}"));
    }
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn query_pairs(query: Option<&str>) -> Vec<(String, String)> {
    form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// A header value the caller's identity can safely be put in: printable ASCII,
/// bounded. A display name comes from the provider and can hold anything.
pub fn header_safe(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(256)
        .collect()
}

/// The headers app-lb sets from the session — and strips from every incoming
/// request to a gated deployment, so a client cannot forge them.
pub const IDENTITY_HEADERS: [&str; 3] = [
    "x-auth-request-email",
    "x-auth-request-user",
    "x-auth-request-name",
];

/// The key file's default location.
pub fn default_key_path() -> PathBuf {
    PathBuf::from("app-lb-auth-key")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::config::AuthProvider;
    use crate::secrets::{SecretRef, SecretSpec};
    use std::collections::BTreeMap;

    fn gate() -> AuthGate {
        AuthGate {
            session_scope: None,
            provider: Default::default(),
            client_id: Some("cid.apps.googleusercontent.com".into()),
            client_secret: Some(SecretRef {
                namespace: None,
                secret: "google".into(),
                key: "client_secret".into(),
                username: None,
            }),
            allowed_domains: vec!["example.com".into()],
            allowed_emails: vec![],
            public_paths: vec![],
            base_path: "/__applb/auth".into(),
            session_ttl_secs: 3600,
            cookie_name: "applb_session".into(),
            cookie_domain: None,
            redirect_url: None,
            forward_identity: true,
            jwt: None,
            provider_ref: None,
        }
    }

    fn auth() -> Authenticator {
        let store = Arc::new(SecretStore::new("unused.json", None));
        store.put(SecretSpec {
            namespace: crate::config::DEFAULT_NAMESPACE.to_string(),
            id: "google".into(),
            description: None,
            data: BTreeMap::from([("client_secret".to_string(), "s3cret".to_string())]),
            updated_at: 0,
        });
        Authenticator::new(vec![7u8; 32], store, None, None)
    }

    fn req<'a>(path: &'a str, cookies: Vec<String>) -> RequestInfo<'a> {
        RequestInfo {
            host: "app.example.com",
            path,
            query: None,
            cookies,
            secure: true,
            wants_html: true,
            // The ordinary case: a gate in front of an application, where the
            // deployment check is the gate's to make.
            fronts_admin_api: false,
            bearer: None,
            client: None,
        }
    }

    fn identity(email: &str, hd: Option<&str>) -> Identity {
        Identity {
            session_token: None,
            subject: "sub-1".into(),
            email: email.into(),
            name: Some("A Person".into()),
            hosted_domain: hd.map(str::to_string),
        }
    }

    fn session_cookie(a: &Authenticator, g: &AuthGate, id: &Identity, exp: u64) -> String {
        let s = Session {
            token: None,
            token_id: None,
            subject: id.subject.clone(),
            email: id.email.clone(),
            name: id.name.clone(),
            hosted_domain: id.hosted_domain.clone(),
            deployment: "web".into(),
            policy: g.policy_fingerprint(),
            exp,
        };
        format!("{}={}", g.cookie_name, a.sign(&s.encode()))
    }

    // -- shared sign-in across sibling hostnames ---------------------------

    /// One sign-in covering every deployment under a parent domain is the whole
    /// point of `cookie_domain`; without this the session is refused at the
    /// second hostname and the user goes back to the provider for each card they
    /// open from the directory.
    mod realm {
        use super::*;

        fn realm_gate() -> AuthGate {
            AuthGate {
                cookie_domain: Some("example.com".into()),
                ..gate()
            }
        }

        fn at<'a>(host: &'a str, cookies: Vec<String>) -> RequestInfo<'a> {
            RequestInfo {
                host,
                ..req("/private", cookies)
            }
        }

        #[tokio::test]
        async fn a_session_from_one_deployment_is_accepted_at_a_sibling() {
            let (a, g) = (auth(), realm_gate());
            let id = identity("someone@example.com", Some("example.com"));
            // Issued by `web`, presented at `api`.
            let cookie = session_cookie(&a, &g, &id, now_secs() + 3600);
            let Decision::Allow(who) = a
                .decide(&g, "api", "default", &at("api.example.com", vec![cookie]))
                .await
            else {
                panic!("a realm session must be accepted at a sibling deployment");
            };
            assert_eq!(who.unwrap().email, "someone@example.com");
        }

        /// The default. A host-only gate must keep refusing a session another
        /// deployment issued, or adding this feature would have quietly widened
        /// every existing gate.
        #[tokio::test]
        async fn without_a_realm_a_foreign_session_is_still_refused() {
            let (a, g) = (auth(), gate());
            let id = identity("someone@example.com", Some("example.com"));
            let cookie = session_cookie(&a, &g, &id, now_secs() + 3600);
            let Decision::Answered(r) = a
                .decide(&g, "api", "default", &at("api.example.com", vec![cookie]))
                .await
            else {
                panic!("a host-only gate must not accept another deployment's session");
            };
            assert_eq!(r.status, 302, "and it starts a fresh sign-in");
        }

        /// The security property that makes sharing safe: sibling gates share a
        /// session only when either would have admitted the same person. A gate
        /// with a narrower allow-list has a different fingerprint and refuses.
        #[tokio::test]
        async fn a_sibling_with_a_different_allow_list_refuses_the_session() {
            let a = auth();
            let issuer = realm_gate();
            let id = identity("someone@example.com", Some("example.com"));
            let cookie = session_cookie(&a, &issuer, &id, now_secs() + 3600);

            let stricter = AuthGate {
                allowed_domains: vec![],
                allowed_emails: vec!["only-me@example.com".into()],
                ..realm_gate()
            };
            let Decision::Answered(r) = a
                .decide(&stricter, "api", "default", &at("api.example.com", vec![cookie]))
                .await
            else {
                panic!("a differently-scoped gate must not honour the shared session");
            };
            assert_eq!(r.status, 302);
        }

        /// Turning sharing on changes the fingerprint, so a session minted by
        /// the host-only version of the same gate cannot be replayed once the
        /// realm is switched on — and vice versa.
        #[test]
        fn the_realm_is_part_of_the_policy_fingerprint() {
            assert_ne!(gate().policy_fingerprint(), realm_gate().policy_fingerprint());
            // And an unshared gate hashes exactly what it did before the field
            // existed, so upgrading does not sign everybody out.
            let other = AuthGate {
                cookie_domain: None,
                ..gate()
            };
            assert_eq!(gate().policy_fingerprint(), other.policy_fingerprint());
        }

        #[test]
        fn the_cookie_carries_the_domain_only_when_the_realm_covers_the_host() {
            let g = realm_gate();
            assert_eq!(g.cookie_domain_for("api.example.com").as_deref(), Some("example.com"));
            assert_eq!(g.cookie_domain_for("example.com").as_deref(), Some("example.com"));
            assert_eq!(g.cookie_domain_for("EXAMPLE.COM").as_deref(), Some("example.com"));
            // Suffix, but not at a label boundary — the classic way to write a
            // rule that looks right and matches the wrong domain.
            assert_eq!(g.cookie_domain_for("notexample.com"), None);
            assert_eq!(g.cookie_domain_for("example.com.evil.test"), None);
            assert_eq!(gate().cookie_domain_for("api.example.com"), None);
        }

        /// Regression, and the reason [`cookie_values`] is plural.
        ///
        /// The moment one gate in a fleet opts into a realm, every sibling host
        /// under it receives that cookie *in addition to* its own host-only one
        /// — same name, two jar entries, order decided by which was created
        /// first. A gate that read only the first refused its own live session,
        /// redirected to the provider, set a fresh cookie that still sorted
        /// second, and looped forever. It showed up on exactly one host: the one
        /// whose policy differed from the realm's.
        #[tokio::test]
        async fn a_foreign_cookie_of_the_same_name_does_not_shadow_the_session() {
            let a = auth();
            let id = identity("someone@example.com", Some("example.com"));

            // A neighbour's realm covers this hostname, so its session arrives
            // here too — under the same name, with a policy of its own.
            let neighbour = AuthGate {
                cookie_domain: Some("example.com".into()),
                allowed_emails: vec!["someone-else@example.com".into()],
                ..gate()
            };
            let foreign = session_cookie(&a, &neighbour, &id, now_secs() + 3600);

            // This gate's own, host-only, entirely valid session.
            let g = gate();
            let mine = session_cookie(&a, &g, &id, now_secs() + 3600);

            for cookies in [
                vec![foreign.clone(), mine.clone()],
                vec![mine.clone(), foreign.clone()],
                // Both in one header, which is how a browser actually sends
                // them, with the shadowing one first.
                vec![format!("{foreign}; {mine}")],
            ] {
                let Decision::Allow(who) = a.decide(&g, "web", "default", &req("/dashboard", cookies)).await
                else {
                    panic!("a live session must be honoured whatever order the jar sends it in");
                };
                assert_eq!(who.unwrap().email, "someone@example.com");
            }

            // And the foreign cookie on its own is still refused — the fix
            // widens which cookies are *looked at*, never which are accepted.
            assert!(
                matches!(
                    a.decide(&g, "web", "default", &req("/dashboard", vec![foreign])).await,
                    Decision::Answered(_)
                ),
                "a session issued under another policy must not be honoured",
            );
        }

        /// A logout must clear the cookie it actually set. A `Domain` cookie and
        /// a host-only one are two different cookies, so clearing the wrong one
        /// reports success and leaves the user signed in.
        #[test]
        fn logout_clears_the_realm_cookie_not_a_host_only_one() {
            let (a, g) = (auth(), realm_gate());
            let r = a.logout(&g, &at("api.example.com", vec![]));
            let session = r
                .cookies
                .iter()
                .find(|c| c.starts_with(&g.cookie_name))
                .expect("the session cookie is cleared");
            assert!(session.contains("Domain=example.com"), "{session}");
            assert!(session.contains("Max-Age=0"), "{session}");
            // The flow cookie was never widened, so clearing it must not be.
            let flow = r
                .cookies
                .iter()
                .find(|c| c.starts_with(FLOW_COOKIE))
                .expect("the flow cookie is cleared");
            assert!(!flow.contains("Domain="), "{flow}");
        }
    }

    // -- JWTs at the data plane --------------------------------------------

    mod jwt_gate {
        use super::*;
        use base64::Engine;
        use serde_json::json;

        const SECRET: &str = "a-shared-secret-of-some-length";

        #[tokio::test]
        async fn browser_login_uses_issuer_then_checks_policy_and_sets_host_cookie() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}/login", listener.local_addr().unwrap());
            let token = heyo_token(json!({}));
            let router = axum::Router::new().route("/login", axum::routing::post(
                move |axum::Json(body): axum::Json<serde_json::Value>| {
                    let token = token.clone();
                    async move {
                        assert_eq!(body, json!({"email":"someone@example.com","password":"p&ss word"}));
                        axum::Json(json!({"success":true,"data":{"tokens":{"accessToken":token,"expiresIn":3600}}}))
                    }
                },
            ));
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let a = with_secret();
            let mut g = jwt_gate(r#""jwt""#, &format!(r#", "cookie":"heyo_login", "login_endpoint":"{endpoint}""#));
            let page = a.start(&g, "web", "default", &req("/runs/abc", vec![]), "/runs/abc?before=17");
            assert_eq!(page.status, 200);
            assert!(page.body.contains("autocomplete=\"current-password\""));
            assert!(page.cookies[0].contains("Secure") && page.cookies[0].contains("HttpOnly"));
            if let Ok(path) = std::env::var("HEYO_LOGIN_HTML") { std::fs::write(path, &page.body).unwrap(); }
            let raw = cookie_values(&page.cookies, FLOW_COOKIE).remove(0);
            let flow = Flow::decode(&a.verify(&raw).unwrap()).unwrap();
            assert!(page.body.contains("name=\"return_to\" value=\"/runs/abc?before=17\""));
            // Another tab refreshes the browser cookie before the original
            // form is submitted. Both its CSRF state and destination survive.
            let second = a.start(&g, "web", "default", &req("/runs/other", page.cookies), "/runs/other");
            let second_raw = cookie_values(&second.cookies, FLOW_COOKIE).remove(0);
            let second_flow = Flow::decode(&a.verify(&second_raw).unwrap()).unwrap();
            assert_eq!(second_flow.nonce, flow.nonce);
            assert_eq!(second_flow.return_to, "/runs/other");
            let body = form_urlencoded::Serializer::new(String::new())
                .append_pair("state", &flow.nonce).append_pair("email", "someone@example.com")
                .append_pair("return_to", "/runs/abc?before=17")
                .append_pair("password", "p&ss word").finish();
            let request = req("/__applb/auth/login", second.cookies);
            let r = a.heyo_login_submit(&g, "web", &request, Some("https://app.example.com:443"), body.as_bytes()).await;
            assert_eq!(r.status, 302);
            assert_eq!(r.location.as_deref(), Some("/runs/abc?before=17"));
            assert!(r.cookies[0].starts_with("heyo_login="));
            assert!(r.cookies[0].contains("Secure") && r.cookies[0].contains("HttpOnly"));
            assert!(!r.cookies[0].contains("Domain="));
            assert!(matches!(a.decide(&g, "web", "default", &req("/runs/abc", r.cookies)).await, Decision::Allow(identity) if identity.is_some()));
            let external = body.replace("%2Fruns%2Fabc%3Fbefore%3D17", "%2F%2Fevil.example.com");
            assert_ne!(external, body);
            let r = a.heyo_login_submit(&g, "web", &request, Some("https://app.example.com"), external.as_bytes()).await;
            assert_eq!(r.status, 302);
            assert_eq!(r.location.as_deref(), Some("/"));
            g.jwt.as_mut().unwrap().require.insert("email".into(), json!("other@example.com"));
            let denied = a.heyo_login_submit(&g, "web", &request, Some("https://app.example.com"), body.as_bytes()).await;
            assert_eq!(denied.status, 403);
            assert!(denied.cookies.is_empty());
            let logout = a.logout(&g, &request);
            assert!(logout.cookies.iter().any(|c| c.starts_with("heyo_login=") && c.contains("Max-Age=0")));
            server.abort();
        }

        #[tokio::test]
        async fn browser_login_rejects_cross_site_expired_and_wrong_deployment_flows() {
            let a = with_secret();
            let g = jwt_gate(r#""jwt""#, r#", "cookie":"heyo_login", "login_endpoint":"http://127.0.0.1:9/login""#);
            let mut request = req("/__applb/auth/login", vec![]);
            for origin in [None, Some("https://evil.example.com"), Some("https://app.example.com:444"), Some("http://app.example.com")] {
                assert_eq!(a.heyo_login_submit(&g, "web", &request, origin, b"state=a").await.status, 403);
            }
            for (deployment, exp, nonce) in [("other", now_secs()+60, "a"), ("web", now_secs(), "a"), ("web", now_secs()+60, "wrong")] {
                let flow = Flow { deployment:deployment.into(), exp, nonce:nonce.into(), verifier:String::new(), return_to:"/".into() };
                request.cookies = vec![format!("{FLOW_COOKIE}={}", a.sign(&flow.encode()))];
                assert_eq!(a.heyo_login_submit(&g, "web", &request, Some("https://app.example.com"), b"state=a&email=a&password=b").await.status, 403);
                if deployment != "web" || exp <= now_secs() {
                    let page = a.start(&g, "web", "default", &request, "/");
                    let raw = cookie_values(&page.cookies, FLOW_COOKIE).remove(0);
                    assert_ne!(Flow::decode(&a.verify(&raw).unwrap()).unwrap().nonce, nonce);
                }
            }
            request.secure = false;
            assert_eq!(a.start(&g, "web", "default", &request, "/").status, 403);
            request.secure = true;
            request.wants_html = false;
            assert_eq!(a.start(&g, "web", "default", &request, "/").status, 401);
            assert_eq!(a.heyo_login_submit(&g, "web", &request, Some("https://app.example.com"), &vec![b'x';8193]).await.status, 413);
        }

        #[tokio::test]
        async fn browser_login_does_not_forward_passwords_through_redirects() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}/login", listener.local_addr().unwrap());
            let captured = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let observed = captured.clone();
            let router = axum::Router::new()
                .route("/login", axum::routing::post(|| async { axum::response::Redirect::temporary("/capture") }))
                .route("/capture", axum::routing::post(move || {
                    observed.store(true, std::sync::atomic::Ordering::SeqCst);
                    async { "unexpected credential forwarding" }
                }));
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let a = with_secret();
            let g = jwt_gate(r#""jwt""#, &format!(r#", "cookie":"heyo_login", "login_endpoint":"{endpoint}""#));
            let flow = Flow { deployment:"web".into(), exp:now_secs()+60, nonce:"a".into(), verifier:String::new(), return_to:"/".into() };
            let request = req("/__applb/auth/login", vec![format!("{FLOW_COOKIE}={}", a.sign(&flow.encode()))]);
            let response = a.heyo_login_submit(&g, "web", &request, Some("https://app.example.com"), b"state=a&email=a%40example.com&password=b").await;
            assert_eq!(response.status, 502);
            assert!(!captured.load(std::sync::atomic::Ordering::SeqCst));
            server.abort();
        }

        /// An authenticator whose secret store holds the issuer's signing key,
        /// as a real deployment's would.
        fn with_secret() -> Authenticator {
            let secrets = Arc::new(SecretStore::new("/nonexistent/secrets.json", None));
            secrets.put(SecretSpec {
                namespace: crate::config::DEFAULT_NAMESPACE.to_string(),
                id: "heyo-auth".into(),
                description: None,
                data: BTreeMap::from([("jwt_secret".to_string(), SECRET.to_string())]),
                updated_at: 0,
            });
            Authenticator::new(vec![7u8; 32], secrets, None, None)
        }

        /// A gate for the Heyo auth API, plus whatever other providers are named.
        fn jwt_gate(providers: &str, extra: &str) -> AuthGate {
            serde_json::from_str(&format!(
                r#"{{"provider":{providers},
                     "client_id":"cid","client_secret":{{"secret":"g"}},
                     "allowed_domains":["example.com"],
                     "jwt":{{
                       "secret":{{"secret":"heyo-auth","key":"jwt_secret"}},
                       "algorithms":["HS256"],
                       "issuer":"auth-service",
                       "audience":"heyo-app",
                       "subject_claim":"userId"
                       {extra}
                     }}}}"#
            ))
            .unwrap()
        }

        /// A token the Heyo auth API would have issued.
        fn heyo_token(overrides: serde_json::Value) -> String {
            let mut claims = json!({
                "userId": "u_1f2e",
                "email": "someone@example.com",
                "name": "A Person",
                "role": "admin",
                "iss": "auth-service",
                "aud": "heyo-app",
                "exp": now_secs() + 3600,
            });
            for (k, v) in overrides.as_object().unwrap() {
                claims[k] = v.clone();
            }
            let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
            let signed = format!(
                "{}.{}",
                b64(json!({"alg": "HS256", "typ": "JWT"}).to_string().as_bytes()),
                b64(claims.to_string().as_bytes())
            );
            format!("{signed}.{}", b64(&hmac(SECRET.as_bytes(), signed.as_bytes())))
        }

        fn bearing<'a>(path: &'a str, token: &str) -> RequestInfo<'a> {
            RequestInfo {
                bearer: Some(token.to_string()),
                ..req(path, vec![])
            }
        }

        /// A gate running scoped sign-in against a stub token endpoint that
        /// answers with whatever claims `claims` holds at the time.
        async fn scoped_signin(
            claims: Arc<std::sync::Mutex<serde_json::Value>>,
        ) -> (AuthGate, Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>>, tokio::task::JoinHandle<()>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let token_url = format!("http://{}/oauth/token", listener.local_addr().unwrap());
            let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
            let recorded = seen.clone();
            let router = axum::Router::new().route("/oauth/token", axum::routing::post(
                move |body: String| {
                    let claims = claims.lock().unwrap().clone();
                    recorded.lock().unwrap().push(form_urlencoded::parse(body.as_bytes()).into_owned().collect());
                    async move { axum::Json(json!({"access_token": heyo_token(claims), "token_type": "Bearer"})) }
                },
            ));
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let g = jwt_gate(r#""jwt""#, &format!(
                r#", "authorize_url":"https://auth.example.com/oauth/authorize", "token_url":"{token_url}""#
            ));
            (g, seen, server)
        }

        fn callback_req<'a>(path: &'a str, query: &'a str, cookies: Vec<String>) -> RequestInfo<'a> {
            RequestInfo { query: Some(query), ..req(path, cookies) }
        }

        #[tokio::test]
        async fn scoped_signin_asks_for_the_namespace_and_admits_a_host_bound_token() {
            let claims = Arc::new(std::sync::Mutex::new(json!({"gateHost": "app.example.com", "namespace": "acme"})));
            let (g, seen, server) = scoped_signin(claims.clone()).await;
            let a = with_secret();

            // No session: off to the issuer, asking for this deployment's namespace.
            let Decision::Answered(r) = a.decide(&g, "web", "acme", &req("/runs/7", vec![])).await else {
                panic!("expected a redirect to the issuer");
            };
            assert_eq!(r.status, 302);
            let location = reqwest::Url::parse(r.location.as_deref().unwrap()).unwrap();
            assert_eq!(location.as_str().split('?').next(), Some("https://auth.example.com/oauth/authorize"));
            let q: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
            assert_eq!(q["scope"], "namespace:acme");
            assert_eq!(q["redirect_uri"], "https://app.example.com/__applb/auth/callback");
            assert_eq!(q["code_challenge_method"], "S256");
            let flow_cookies = r.cookies.clone();
            let flow = Flow::decode(&a.verify(&cookie_values(&flow_cookies, FLOW_COOKIE)[0]).unwrap()).unwrap();
            assert_eq!(q["state"], flow.nonce);
            assert_eq!(q["code_challenge"], pkce_challenge(&flow.verifier));

            // The issuer comes back with a code; the gate redeems it with the verifier.
            let query = format!("code=c-1&state={}", flow.nonce);
            let back = callback_req("/__applb/auth/callback", &query, flow_cookies.clone());
            let Decision::Answered(done) = a.decide(&g, "web", "acme", &back).await else {
                panic!("the callback answers itself");
            };
            assert_eq!(done.status, 302, "{}", done.body);
            assert_eq!(done.location.as_deref(), Some("https://app.example.com/runs/7"));
            let sent = seen.lock().unwrap().last().cloned().unwrap();
            let field = |k: &str| sent.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
            assert_eq!(field("grant_type").as_deref(), Some("authorization_code"));
            assert_eq!(field("code").as_deref(), Some("c-1"));
            assert_eq!(field("code_verifier"), Some(flow.verifier.clone()));
            assert_eq!(field("redirect_uri").as_deref(), Some("https://app.example.com/__applb/auth/callback"));
            // A host-only session of app-lb's own, not the issuer's token.
            let session = done.cookies.iter().find(|c| c.starts_with("applb_session=")).unwrap();
            assert!(!session.contains("Domain="));
            assert!(matches!(
                a.decide(&g, "web", "acme", &req("/runs/7", done.cookies.clone())).await,
                Decision::Allow(identity) if identity.as_ref().as_ref().is_some_and(|i| i.subject == "u_1f2e")
            ));
            // Bound to the deployment that issued it, like any session.
            assert!(matches!(
                a.decide(&g, "other", "acme", &req("/", done.cookies)).await,
                Decision::Answered(_)
            ));

            // A token for another host, another namespace, or with no scope at
            // all is refused, and no session is issued.
            for bad in [
                json!({"gateHost": "elsewhere.example.com", "namespace": "acme"}),
                json!({"gateHost": "app.example.com", "namespace": "other"}),
                json!({}),
            ] {
                *claims.lock().unwrap() = bad.clone();
                let Decision::Answered(r) = a.decide(&g, "web", "acme", &back).await else {
                    panic!("the callback answers itself");
                };
                assert_eq!(r.status, 403, "{bad}: {}", r.body);
                assert!(r.cookies.is_empty(), "{bad}");
            }
            server.abort();
        }

        #[tokio::test]
        async fn a_scoped_signin_gate_tells_a_program_where_to_sign_in() {
            let (g, _, server) = scoped_signin(Arc::new(std::sync::Mutex::new(json!({})))).await;
            let a = with_secret();
            let program = RequestInfo { wants_html: false, ..req("/api", vec![]) };
            let Decision::Answered(r) = a.decide(&g, "web", "acme", &program).await else {
                panic!("expected a 401");
            };
            assert_eq!(r.status, 401);
            assert!(r.body.contains("/__applb/auth/login"), "{}", r.body);
            server.abort();
        }

        #[tokio::test]
        async fn a_token_bound_to_another_host_or_namespace_is_refused_as_a_bearer() {
            let a = with_secret();
            let g = jwt_gate(r#""jwt""#, "");
            let elsewhere = heyo_token(json!({"gateHost": "elsewhere.example.com"}));
            assert!(!matches!(a.decide(&g, "web", "default", &bearing("/", &elsewhere)).await, Decision::Allow(_)));
            let here = heyo_token(json!({"gateHost": "APP.example.com", "namespace": "default"}));
            assert!(matches!(a.decide(&g, "web", "default", &bearing("/", &here)).await, Decision::Allow(_)));
            let other_ns = heyo_token(json!({"namespace": "acme"}));
            assert!(!matches!(a.decide(&g, "web", "default", &bearing("/", &other_ns)).await, Decision::Allow(_)));
        }

        #[test]
        fn bare_host_drops_port_and_case() {
            assert_eq!(bare_host("App.Example.com:443"), "app.example.com");
            assert_eq!(bare_host("app.example.com."), "app.example.com");
            assert_eq!(bare_host("[::1]:8443"), "[::1]");
        }

        #[tokio::test]
        async fn a_token_from_the_issuer_gets_through_and_brings_its_identity() {
            let a = with_secret();
            let g = jwt_gate(r#""jwt""#, "");

            let Decision::Allow(identity) =
                a.decide(&g, "web", "default", &bearing("/private", &heyo_token(json!({})))).await
            else {
                panic!("a valid token should have been admitted");
            };
            let identity = identity.expect("a JWT gate forwards who the caller is");
            // `userId`, because that is what `subject_claim` named — the whole
            // reason the claim is configurable.
            assert_eq!(identity.subject, "u_1f2e");
            assert_eq!(identity.email, "someone@example.com");
            assert_eq!(identity.name.as_deref(), Some("A Person"));
            // Nothing but Google issues one, and inventing it from an email
            // suffix is the mistake `AuthGate::allows` documents at length.
            assert_eq!(identity.hosted_domain, None);
        }

        #[tokio::test]
        async fn a_token_the_gate_will_not_take_does_not_get_through() {
            let a = with_secret();
            let g = jwt_gate(r#""jwt""#, "");

            for (what, token) in [
                ("expired", heyo_token(json!({"exp": now_secs() - 1}))),
                ("another issuer", heyo_token(json!({"iss": "somewhere-else"}))),
                ("another audience", heyo_token(json!({"aud": "heyo-server"}))),
                ("no expiry", {
                    // Built by hand: `heyo_token` always sets one.
                    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
                    let claims = json!({"userId": "u", "iss": "auth-service", "aud": "heyo-app"});
                    let signed = format!(
                        "{}.{}",
                        b64(json!({"alg": "HS256"}).to_string().as_bytes()),
                        b64(claims.to_string().as_bytes())
                    );
                    format!("{signed}.{}", b64(&hmac(SECRET.as_bytes(), signed.as_bytes())))
                }),
                ("not a token at all", "nonsense".to_string()),
            ] {
                assert!(
                    matches!(
                        a.decide(&g, "web", "default", &bearing("/private", &token)).await,
                        Decision::Answered(_)
                    ),
                    "{what} was admitted",
                );
            }
        }

        /// The gate's allow-list. A token that is perfectly valid and belongs to
        /// somebody this deployment does not admit.
        #[tokio::test]
        async fn require_keeps_out_a_valid_token_from_the_wrong_person() {
            let a = with_secret();
            let g = jwt_gate(r#""jwt""#, r#", "require": {"role": "admin"}"#);

            let Decision::Allow(_) =
                a.decide(&g, "web", "default", &bearing("/private", &heyo_token(json!({})))).await
            else {
                panic!("an admin should have been admitted");
            };
            assert!(
                matches!(
                    a.decide(
                        &g,
                        "web",
                        "default",
                        &bearing("/private", &heyo_token(json!({"role": "user"})))
                    )
                    .await,
                    Decision::Answered(_)
                ),
                "a non-admin was admitted through a `require` that names admin",
            );
        }

        /// A browser navigating cannot set an `Authorization` header, so a gate
        /// can be told to read the token out of the cookie the application put
        /// it in.
        #[tokio::test]
        async fn a_token_can_arrive_in_a_cookie() {
            let a = with_secret();
            let g = jwt_gate(r#""jwt""#, r#", "cookie": "heyo_access_token""#);
            let token = heyo_token(json!({}));

            let in_cookie = req("/private", vec![format!("heyo_access_token={token}")]);
            let Decision::Allow(identity) = a.decide(&g, "web", "default", &in_cookie).await else {
                panic!("a token in the named cookie should have been admitted");
            };
            assert_eq!(identity.unwrap().subject, "u_1f2e");

            // A gate that names no cookie reads none, however the browser
            // spells it — the header is the only credential it asked for.
            let g = jwt_gate(r#""jwt""#, "");
            assert!(matches!(
                a.decide(&g, "web", "default", &in_cookie).await,
                Decision::Answered(_)
            ));
        }

        /// The header states what the caller is presenting. A cookie the browser
        /// happens to also carry must not decide the outcome.
        #[tokio::test]
        async fn the_authorization_header_wins_over_the_cookie() {
            let a = with_secret();
            let g = jwt_gate(r#""jwt""#, r#", "cookie": "heyo_access_token""#);
            let good = heyo_token(json!({}));

            let mut r = req("/private", vec![format!("heyo_access_token={good}")]);
            r.bearer = Some(heyo_token(json!({"exp": now_secs() - 1})));
            assert!(
                matches!(a.decide(&g, "web", "default", &r).await, Decision::Answered(_)),
                "the valid cookie was used in place of the expired header",
            );
        }

        /// The providers are alternatives. A person signs into the UI with
        /// Google; the UI's own calls carry the token the issuer gave it.
        #[tokio::test]
        async fn a_gate_can_accept_a_session_or_a_jwt() {
            let a = with_secret();
            let g = jwt_gate(r#"["google","jwt"]"#, "");

            // The token path.
            let Decision::Allow(who) =
                a.decide(&g, "web", "default", &bearing("/api", &heyo_token(json!({}))))
                    .await
            else {
                panic!("a valid token should have been admitted");
            };
            assert_eq!(who.unwrap().subject, "u_1f2e");

            // The session path, unchanged.
            let id = identity("someone@example.com", Some("example.com"));
            let cookie = session_cookie(&a, &g, &id, now_secs() + 3600);
            let Decision::Allow(who) =
                a.decide(&g, "web", "default", &req("/dashboard", vec![cookie])).await
            else {
                panic!("a live Google session should still be honoured");
            };
            assert_eq!(who.unwrap().email, "someone@example.com");

            // Neither: a browser is still sent to Google, because that is the
            // only one of the two a browser can start.
            let Decision::Answered(r) = a.decide(&g, "web", "default", &req("/dashboard", vec![])).await
            else {
                panic!("an unauthenticated browser must not be let through");
            };
            assert_eq!(r.status, 302);
        }

        /// A gate that takes no browser credential has no sign-in to start, so
        /// it answers with what would actually work rather than redirecting to a
        /// flow that cannot complete.
        #[tokio::test]
        async fn a_browser_at_a_jwt_only_gate_is_told_what_it_needs() {
            let a = with_secret();
            let g: AuthGate = serde_json::from_str(
                r#"{"provider":"jwt","jwt":{"secret":{"secret":"heyo-auth","key":"jwt_secret"},
                    "algorithms":["HS256"],"issuer":"auth-service"}}"#,
            )
            .unwrap();

            let Decision::Answered(r) = a.decide(&g, "web", "default", &req("/", vec![])).await else {
                panic!("an unauthenticated request must not be let through");
            };
            assert_eq!(r.status, 401);
            // Valid JSON, not just a string with the right substrings in it —
            // this is what an API client parses to find out what to do next.
            let body: serde_json::Value =
                serde_json::from_str(&r.body).unwrap_or_else(|e| panic!("{}: {e}", r.body));
            assert_eq!(body["accepts"], serde_json::json!(["jwt"]));
            assert_eq!(body["error"], "authentication required");
            assert!(body["detail"].as_str().is_some_and(|d| d.contains("Bearer")), "{body}");
            assert!(r.location.is_none(), "there is no flow to redirect to");
        }

        /// With a hosted sign-in configured, a token-less *browser* is redirected
        /// to it carrying where it was going, while a program still gets the 401
        /// it can act on.
        #[tokio::test]
        async fn a_hosted_login_redirects_a_browser_and_still_401s_a_program() {
            let a = with_secret();
            let g: AuthGate = serde_json::from_str(
                r#"{"provider":"jwt","jwt":{"secret":{"secret":"heyo-auth","key":"jwt_secret"},
                    "algorithms":["HS256"],"issuer":"auth-service",
                    "cookie":"heyo_access_token",
                    "login_url":"https://auth.example.com/login"}}"#,
            )
            .unwrap();

            // A browser with no token is bounced to the hosted sign-in, with the
            // URL it wanted so the issuer can send it back.
            let mut browser = req("/dashboard", vec![]);
            browser.query = Some("tab=usage");
            let Decision::Answered(r) = a.decide(&g, "web", "default", &browser).await else {
                panic!("a token-less browser must be answered, not let through");
            };
            assert_eq!(r.status, 302);
            let loc = r.location.expect("a redirect carries a Location");
            assert!(loc.starts_with("https://auth.example.com/login?"), "{loc}");
            assert!(
                loc.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Fdashboard%3Ftab%3Dusage"),
                "the return URL is this deployment's own path, encoded: {loc}",
            );

            // A program (no HTML in Accept) still gets the actionable 401: it
            // cannot follow a redirect into an HTML sign-in page.
            let mut program = req("/dashboard", vec![]);
            program.wants_html = false;
            let Decision::Answered(r) = a.decide(&g, "web", "default", &program).await else {
                panic!("must not let a token-less program through");
            };
            assert_eq!(r.status, 401);
            assert!(r.location.is_none(), "a program is not redirected");
        }

        /// The return parameter's name is configurable, for issuers that do not
        /// call it `redirect_uri`.
        #[tokio::test]
        async fn the_return_parameter_name_is_configurable() {
            let a = with_secret();
            let g: AuthGate = serde_json::from_str(
                r#"{"provider":"jwt","jwt":{"secret":{"secret":"heyo-auth","key":"jwt_secret"},
                    "algorithms":["HS256"],"issuer":"auth-service",
                    "cookie":"heyo_access_token",
                    "login_url":"https://auth.example.com/login",
                    "login_redirect_param":"next"}}"#,
            )
            .unwrap();
            let Decision::Answered(r) =
                a.decide(&g, "web", "default", &req("/", vec![])).await
            else {
                panic!("a token-less browser must be answered");
            };
            let loc = r.location.expect("a redirect carries a Location");
            assert!(loc.contains("next=https%3A%2F%2Fapp.example.com%2F"), "{loc}");
            assert!(!loc.contains("redirect_uri="), "the default name must not leak in: {loc}");
        }

        /// A 401 must not name a mechanism the path will refuse.
        ///
        /// `?app_token=` was advertised here for a long time and has never been
        /// read at this gate — `proxy::request_info` takes the bearer from the
        /// `Authorization` header alone. The cost of the wrong sentence is not
        /// abstract: a client generalised it to another host, spent a
        /// permission grant proving it did not work, and reported the wrong
        /// cause. The query form exists on exactly one route in the system
        /// (the admin API's WebSocket shell, which cannot set headers), and
        /// this is not that route.
        #[tokio::test]
        async fn an_app_token_gate_advertises_only_the_header_it_reads() {
            let a = with_secret();
            let g: AuthGate =
                serde_json::from_str(r#"{"provider":"app-token"}"#).unwrap();

            let Decision::Answered(r) = a.decide(&g, "web", "default", &req("/", vec![])).await
            else {
                panic!("an unauthenticated request must not be let through");
            };
            assert_eq!(r.status, 401);
            let body: serde_json::Value =
                serde_json::from_str(&r.body).unwrap_or_else(|e| panic!("{}: {e}", r.body));
            assert_eq!(body["accepts"], serde_json::json!(["app-token"]));
            let detail = body["detail"].as_str().unwrap_or_default();
            assert!(detail.contains("Authorization: Bearer applb_"), "{body}");
            assert!(
                !detail.contains("app_token="),
                "the gate advertised a query parameter it does not read: {body}",
            );
        }

        /// A gate taking both machine credentials names both.
        #[tokio::test]
        async fn a_gate_taking_both_machine_credentials_says_so() {
            let a = with_secret();
            let g: AuthGate = serde_json::from_str(
                r#"{"provider":["app-token","jwt"],"jwt":{"secret":{"secret":"heyo-auth","key":"jwt_secret"},
                    "algorithms":["HS256"],"issuer":"auth-service"}}"#,
            )
            .unwrap();
            let Decision::Answered(r) = a.decide(&g, "web", "default", &req("/", vec![])).await else {
                panic!("an unauthenticated request must not be let through");
            };
            let body: serde_json::Value =
                serde_json::from_str(&r.body).unwrap_or_else(|e| panic!("{}: {e}", r.body));
            assert_eq!(body["accepts"], serde_json::json!(["app-token", "jwt"]));
        }

        #[tokio::test]
        async fn a_google_only_gate_ignores_jwts_entirely() {
            let a = with_secret();
            // Same block, but `jwt` is not among the providers, so it is inert.
            let mut g = jwt_gate(r#""google""#, "");
            assert!(g.jwt.is_some());
            assert!(g.jwt_policy().is_none(), "the block is inert without the provider");

            assert!(
                matches!(
                    a.decide(&g, "web", "default", &bearing("/private", &heyo_token(json!({})))).await,
                    Decision::Answered(_)
                ),
                "a JWT was honoured by a gate that does not list the provider",
            );

            // And with the provider added, the same request gets through.
            g.provider = serde_json::from_str(r#"["google","jwt"]"#).unwrap();
            assert!(matches!(
                a.decide(&g, "web", "default", &bearing("/private", &heyo_token(json!({})))).await,
                Decision::Allow(_)
            ));
        }

        #[tokio::test]
        async fn public_paths_are_still_public_on_a_jwt_gate() {
            let a = with_secret();
            let mut g = jwt_gate(r#""jwt""#, "");
            g.public_paths = vec![crate::config::PublicPath::public("/healthz")];
            let Decision::Allow(identity) = a.decide(&g, "web", "default", &req("/healthz", vec![])).await
            else {
                panic!("a public path must be served without a credential");
            };
            assert!(identity.is_none(), "an ungated request carries no identity");
        }

        /// Rotating the signing key in the store takes effect on the next
        /// request, not on the next time somebody re-registers the deployment.
        #[tokio::test]
        async fn rotating_the_secret_invalidates_tokens_immediately() {
            let secrets = Arc::new(SecretStore::new("/nonexistent/secrets.json", None));
            secrets.put(SecretSpec {
                namespace: crate::config::DEFAULT_NAMESPACE.to_string(),
                id: "heyo-auth".into(),
                description: None,
                data: BTreeMap::from([("jwt_secret".to_string(), SECRET.to_string())]),
                updated_at: 0,
            });
            let a = Authenticator::new(vec![7u8; 32], secrets.clone(), None, None);
            let g = jwt_gate(r#""jwt""#, "");
            let token = heyo_token(json!({}));

            assert!(matches!(
                a.decide(&g, "web", "default", &bearing("/private", &token)).await,
                Decision::Allow(_)
            ));

            secrets.put(SecretSpec {
                namespace: crate::config::DEFAULT_NAMESPACE.to_string(),
                id: "heyo-auth".into(),
                description: None,
                data: BTreeMap::from([("jwt_secret".to_string(), "rotated".to_string())]),
                updated_at: 1,
            });
            assert!(
                matches!(
                    a.decide(&g, "web", "default", &bearing("/private", &token)).await,
                    Decision::Answered(_)
                ),
                "a token signed with the previous secret still verified",
            );
        }
    }

    // -- app-tokens at the data plane --------------------------------------

    mod app_token {
        use super::*;
        use crate::tokens::{AdminScope, NewToken, TokenStore};

        /// An authenticator that knows about tokens, plus the store to mint from.
        fn with_tokens() -> (Authenticator, Arc<TokenStore>) {
            let tokens = Arc::new(TokenStore::new("/nonexistent/tokens.json"));
            let secrets = Arc::new(SecretStore::new("/nonexistent/secrets.json", None));
            (
                Authenticator::new(vec![7u8; 32], secrets, Some(tokens.clone()), None),
                tokens,
            )
        }

        fn mint(t: &TokenStore, deployments: &[&str]) -> String {
            t.mint(
                NewToken {
                    name: "agent".into(),
                    namespace: None,
                    // No admin API access at all — the point of this credential is
                    // to reach the application, not the LB.
                    admin: AdminScope::None,
                    deployments: deployments.iter().map(|d| d.to_string()).collect(),
                    expires_in_secs: None,
                },
                now_secs(),
            )
            .unwrap()
            .1
        }

        fn token_gate(providers: &str) -> AuthGate {
            serde_json::from_str(&format!(
                r#"{{"provider":{providers},"client_id":"cid","client_secret":{{"secret":"g"}},
                    "allowed_domains":["example.com"]}}"#
            ))
            .unwrap()
        }

        fn bearing<'a>(path: &'a str, token: &str) -> RequestInfo<'a> {
            RequestInfo {
                bearer: Some(token.to_string()),
                ..req(path, vec![])
            }
        }

        #[tokio::test]
        async fn a_scoped_token_gets_through_a_token_gate() {
            let (a, t) = with_tokens();
            let g = token_gate(r#""app-token""#);
            let secret = mint(&t, &["web"]);

            let Decision::Allow(identity) = a.decide(&g, "web", "default", &bearing("/private", &secret)).await
            else {
                panic!("a scoped token should have been admitted");
            };
            assert!(
                identity.is_none(),
                "a token is not a person: nothing should be forwarded as an identity"
            );
        }

        #[tokio::test]
        async fn a_token_scoped_elsewhere_does_not_get_through() {
            let (a, t) = with_tokens();
            let g = token_gate(r#""app-token""#);
            let secret = mint(&t, &["other"]);

            // A 403 that says why, not a 401 that implies the credential was
            // never understood. This used to answer 401 "as if no credential
            // were presented", and that reads to a program as a broken
            // connection: the holder of a valid token goes and checks
            // transport, DNS and the token itself, none of which is wrong.
            // What is disclosed is the caller's own token and a deployment they
            // named, so the discretion bought nothing.
            let Decision::Answered(r) = a.decide(&g, "web", "default", &bearing("/private", &secret)).await
            else {
                panic!("expected a refusal");
            };
            assert_eq!(r.status, 403);
            let body: serde_json::Value =
                serde_json::from_str(&r.body).unwrap_or_else(|e| panic!("{}: {e}", r.body));
            assert_eq!(body["error"], "insufficient_scope");
            assert_eq!(body["deployment"], "web");
            assert_eq!(body["namespace"], "default");
            // The other deployment this token *is* scoped to stays that
            // token's business: this body is reachable from every gated
            // hostname on the internet.
            assert!(body.get("token_deployments").is_none(), "{body}");
            assert!(!r.body.contains("other"), "{}", r.body);
        }

        #[tokio::test]
        async fn a_namespace_token_stops_at_its_namespace_wall() {
            let (a, t) = with_tokens();
            let g = token_gate(r#""app-token""#);
            let secret = t
                .mint(
                    NewToken {
                        name: "team-a agent".into(),
                        namespace: Some("team-a".into()),
                        admin: AdminScope::None,
                        // Empty on purpose: inside a namespace this means every
                        // deployment there.
                        deployments: vec![],
                        expires_in_secs: None,
                    },
                    now_secs(),
                )
                .unwrap()
                .1;

            let Decision::Allow(_) = a.decide(&g, "web", "team-a", &bearing("/private", &secret)).await
            else {
                panic!("a namespace token should reach a deployment in its namespace");
            };
            // The same deployment id elsewhere is a different deployment.
            let Decision::Answered(r) = a.decide(&g, "web", "default", &bearing("/private", &secret)).await
            else {
                panic!("expected a refusal outside the namespace");
            };
            assert_eq!(r.status, 403);
            let body: serde_json::Value =
                serde_json::from_str(&r.body).unwrap_or_else(|e| panic!("{}: {e}", r.body));
            // The wall that actually refused this, named — a namespace token
            // refused outside its namespace looked identical to a bad password
            // before, which is a long way from the fix (mint in the right
            // namespace, or widen the token).
            assert_eq!(body["token_namespace"], "team-a");
            assert_eq!(body["namespace"], "default");
            assert!(
                body["detail"].as_str().is_some_and(|d| d.contains("namespace")),
                "{body}"
            );
        }

        /// The new explanation must only ever change a *refusal*, never create
        /// one. A gate taking both providers, a session that is valid, and a
        /// bearer scoped somewhere else: the session wins, exactly as before.
        #[tokio::test]
        async fn a_valid_session_still_wins_over_a_bearer_scoped_elsewhere() {
            let (a, t) = with_tokens();
            let g = token_gate(r#"["google","app-token"]"#);
            let elsewhere = mint(&t, &["other"]);
            let who = super::identity("someone@example.com", Some("example.com"));
            let cookie = super::session_cookie(&a, &g, &who, now_secs() + 3600);

            let req = RequestInfo {
                bearer: Some(elsewhere.clone()),
                cookies: vec![cookie],
                ..req("/private", vec![])
            };
            let Decision::Allow(identity) = a.decide(&g, "web", "default", &req).await else {
                panic!("a valid session must still admit, bearer or no bearer");
            };
            let identity = identity.expect("a session carries an identity");
            assert_eq!(identity.email, "someone@example.com");
        }

        #[tokio::test]
        async fn a_google_only_gate_ignores_tokens_entirely() {
            let (a, t) = with_tokens();
            let g = token_gate(r#""google""#);
            let secret = mint(&t, &["web"]);

            // A perfectly good token, on a gate that was never told to accept
            // one. Opting in is the spec's job, not the token's.
            let Decision::Answered(r) = a.decide(&g, "web", "default", &bearing("/private", &secret)).await
            else {
                panic!("expected a redirect to the provider");
            };
            assert_eq!(r.status, 302);
        }

        /// The "both, either satisfies" shape: a person signs in, a program
        /// presents a token, and neither has to know the other exists.
        #[tokio::test]
        async fn a_gate_can_accept_a_session_or_a_token() {
            let (a, t) = with_tokens();
            let g = token_gate(r#"["google","app-token"]"#);
            let secret = mint(&t, &["web"]);

            // Program.
            assert!(matches!(
                a.decide(&g, "web", "default", &bearing("/private", &secret)).await,
                Decision::Allow(_)
            ));

            // Person.
            let id = identity("someone@example.com", Some("example.com"));
            let cookie = session_cookie(&a, &g, &id, now_secs() + 3600);
            let Decision::Allow(who) = a.decide(&g, "web", "default", &req("/private", vec![cookie])).await
            else {
                panic!("a signed-in person should still get through");
            };
            assert_eq!(who.as_ref().as_ref().map(|i| i.email.as_str()), Some("someone@example.com"));

            // Neither.
            assert!(matches!(
                a.decide(&g, "web", "default", &req("/private", vec![])).await,
                Decision::Answered(_)
            ));
        }

        #[tokio::test]
        async fn a_revoked_token_stops_working_at_the_data_plane_too() {
            let (a, t) = with_tokens();
            let g = token_gate(r#""app-token""#);
            let secret = mint(&t, &["web"]);
            assert!(matches!(
                a.decide(&g, "web", "default", &bearing("/private", &secret)).await,
                Decision::Allow(_)
            ));

            t.revoke(&t.list()[0].id);
            assert!(matches!(
                a.decide(&g, "web", "default", &bearing("/private", &secret)).await,
                Decision::Answered(_)
            ));
        }

        /// A token-only gate has no sign-in flow, so a browser must be told what
        /// would actually work rather than bounced into an OAuth round trip that
        /// ends at an empty `client_id`.
        #[tokio::test]
        async fn a_browser_at_a_token_only_gate_is_told_what_it_needs() {
            let (a, _) = with_tokens();
            let g: AuthGate = serde_json::from_str(r#"{"provider":"app-token"}"#).unwrap();

            let Decision::Answered(r) = a.decide(&g, "web", "default", &req("/private", vec![])).await else {
                panic!("expected a refusal");
            };
            assert_eq!(r.status, 401);
            assert!(r.location.is_none(), "there is nowhere to redirect to");
            assert!(r.body.contains("app-token"), "{}", r.body);
        }

        #[tokio::test]
        async fn public_paths_are_still_public_on_a_token_gate() {
            let (a, _) = with_tokens();
            let g: AuthGate = serde_json::from_str(
                r#"{"provider":"app-token","public_paths":[{"path":"/healthz","scope":"public"}]}"#,
            )
            .unwrap();
            assert!(matches!(
                a.decide(&g, "web", "default", &req("/healthz", vec![])).await,
                Decision::Allow(_)
            ));
        }
    }

    #[tokio::test]
    async fn an_unauthenticated_browser_is_sent_to_the_provider() {
        let (a, g) = (auth(), gate());
        let Decision::Answered(r) = a.decide(&g, "web", "default", &req("/dashboard", vec![])).await else {
            panic!("expected a redirect");
        };
        assert_eq!(r.status, 302);
        let location = r.location.unwrap();
        assert!(location.starts_with(GOOGLE_AUTHORIZE), "{location}");
        assert!(location.contains("client_id=cid.apps.googleusercontent.com"));
        assert!(location.contains("code_challenge_method=S256"));
        assert!(
            location.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2F__applb%2Fauth%2Fcallback"),
            "{location}",
        );
        // The verifier must never reach the provider — only its hash.
        let flow_cookie = r.cookies.iter().find(|c| c.starts_with(FLOW_COOKIE)).unwrap();
        assert!(flow_cookie.contains("HttpOnly"), "{flow_cookie}");
        assert!(flow_cookie.contains("Secure"), "{flow_cookie}");
        assert!(flow_cookie.contains("SameSite=Lax"), "{flow_cookie}");
    }

    /// Regression: `SameSite=Strict` withholds the cookie on the provider's
    /// redirect back, which turns sign-in into an infinite loop.
    #[tokio::test]
    async fn the_flow_cookie_is_lax_so_the_callback_can_read_it() {
        let (a, g) = (auth(), gate());
        let Decision::Answered(r) = a.decide(&g, "web", "default", &req("/", vec![])).await else {
            panic!("expected a redirect");
        };
        let flow = r.cookies.iter().find(|c| c.starts_with(FLOW_COOKIE)).unwrap();
        assert!(flow.contains("SameSite=Lax") && !flow.contains("Strict"), "{flow}");
    }

    #[tokio::test]
    async fn an_api_client_gets_a_401_with_a_login_url_instead_of_a_redirect() {
        let (a, g) = (auth(), gate());
        let mut r = req("/api/things", vec![]);
        r.wants_html = false;
        let Decision::Answered(response) = a.decide(&g, "web", "default", &r).await else {
            panic!("expected a 401");
        };
        assert_eq!(response.status, 401);
        assert_eq!(response.content_type, "application/json");
        assert!(response.body.contains("https://app.example.com/__applb/auth/login"));
    }

    #[tokio::test]
    async fn a_valid_session_passes_through_with_its_identity() {
        let (a, g) = (auth(), gate());
        let id = identity("someone@example.com", Some("example.com"));
        let cookie = session_cookie(&a, &g, &id, now_secs() + 600);

        let Decision::Allow(got) = a.decide(&g, "web", "default", &req("/dashboard", vec![cookie])).await
        else {
            panic!("expected the request to pass");
        };
        assert_eq!(*got, Some(id));
    }

    #[tokio::test]
    async fn a_public_scoped_path_skips_the_gate_entirely() {
        let (a, mut g) = (auth(), gate());
        // `public` is the only scope that admits a request presenting nothing.
        // Written out, because a bare string now means `admin`.
        g.public_paths = vec![
            crate::config::PublicPath::public("/healthz"),
            crate::config::PublicPath::public("/hooks/"),
        ];

        for path in ["/healthz", "/hooks/github"] {
            let Decision::Allow(id) = a.decide(&g, "web", "default", &req(path, vec![])).await else {
                panic!("{path} should be public");
            };
            assert_eq!(*id, None, "a public path has no identity to forward");
        }
        // ...and only those.
        assert!(matches!(
            a.decide(&g, "web", "default", &req("/health", vec![])).await,
            Decision::Answered(_)
        ));
    }

    /// The whole point of the change: a path outside the sign-in gate is not a
    /// path outside authorization. These four cases are the contract.
    mod scoped_public_paths {
        use super::*;
        use crate::config::{PathScope, PublicPath};
        use crate::secrets::SecretStore;
        use crate::tokens::{AdminScope, NewToken, TokenStore};
        use std::sync::Arc;

        /// A local copy rather than reaching into `app_token::with_tokens`:
        /// these tests need a token store too, and a sibling module's private
        /// helper is not theirs to borrow.
        fn with_tokens() -> (Authenticator, Arc<TokenStore>) {
            let tokens = Arc::new(TokenStore::new("/nonexistent/tokens.json"));
            let secrets = Arc::new(SecretStore::new("/nonexistent/secrets.json", None));
            (
                Authenticator::new(vec![7u8; 32], secrets, Some(tokens.clone()), None),
                tokens,
            )
        }

        fn scoped(path: &str, scope: PathScope) -> PublicPath {
            PublicPath { path: path.into(), scope }
        }

        fn bearer<'a>(path: &'a str, token: &'a str) -> RequestInfo<'a> {
            let mut r = req(path, vec![]);
            r.bearer = Some(token.to_string());
            // A program, not a browser: the refusal must be a 401 it can read.
            r.wants_html = false;
            r
        }

        fn admin_token(t: &TokenStore, deployments: &[&str], admin: AdminScope) -> String {
            t.mint(
                NewToken {
                    name: "api".into(),
                    namespace: None,
                    admin,
                    deployments: deployments.iter().map(|d| d.to_string()).collect(),
                    expires_in_secs: None,
                },
                now_secs(),
            )
            .unwrap()
            .1
        }

        /// The migration default, and the reason this is a breaking change: a
        /// spec written before scopes existed lists bare strings, and every one
        /// of them now demands `admin` rather than standing open.
        #[test]
        fn a_bare_string_means_admin() {
            let g: AuthGate = serde_json::from_str(
                r#"{"provider":"google","public_paths":["/deployments","/healthz"]}"#,
            )
            .unwrap();
            assert_eq!(g.public_scope("/deployments"), Some(PathScope::Admin));
            assert_eq!(g.public_scope("/healthz"), Some(PathScope::Admin));
            assert_eq!(g.public_scope("/elsewhere"), None);
        }

        /// The shipped art-store gate opens `/blobs/` to anonymous callers and
        /// nothing else. That is safe only because `art serve` itself answers
        /// an anonymous request for a *public* blob's GET/HEAD and refuses the
        /// rest (`artifacts/src/http.rs`, `authorize`) — the keyless installer
        /// (`.ci/install-apps.sh`) depends on this. Tags, manifests and usage
        /// still need an admin credential at the gate.
        #[test]
        fn the_art_store_example_opens_blobs_only() {
            let spec: serde_json::Value =
                serde_json::from_str(include_str!("../examples/artifacts-gated.json")).unwrap();
            let g: AuthGate = serde_json::from_value(spec["auth"].clone()).unwrap();
            assert_eq!(g.public_scope("/blobs/abc"), Some(PathScope::Public));
            for p in ["/tags", "/tags/x", "/manifests/x", "/usage"] {
                assert_eq!(g.public_scope(p), Some(PathScope::Admin), "{p}");
            }
        }

        /// Longest prefix wins, so a narrow entry can tighten a broad one and
        /// the answer never depends on the order somebody typed them in.
        #[test]
        fn the_most_specific_entry_decides() {
            let mut g = gate();
            g.public_paths = vec![
                scoped("/api/", PathScope::View),
                scoped("/api/admin/", PathScope::Admin),
                PublicPath::public("/api/health"),
            ];
            assert_eq!(g.public_scope("/api/things"), Some(PathScope::View));
            assert_eq!(g.public_scope("/api/admin/wipe"), Some(PathScope::Admin));
            assert_eq!(g.public_scope("/api/health"), Some(PathScope::Public));
        }

        #[tokio::test]
        async fn a_scoped_path_refuses_an_empty_hand_without_a_redirect() {
            let (a, _) = with_tokens();
            let mut g = gate();
            g.public_paths = vec![scoped("/deployments", PathScope::Admin)];

            let mut r = req("/deployments", vec![]);
            r.wants_html = false;
            let Decision::Answered(res) = a.decide(&g, "web", "default", &r).await else {
                panic!("a scoped path must not admit an unauthenticated request");
            };
            assert_eq!(res.status, 401, "not a redirect: the caller is a program");
            assert!(res.body.contains("admin"), "{}", res.body);
            assert!(
                !res.body.contains("login_url"),
                "a program handed a sign-in URL fails unreadably: {}",
                res.body
            );
        }

        #[tokio::test]
        async fn the_tier_and_the_deployment_both_have_to_match() {
            let (a, tokens) = with_tokens();
            let mut g = gate();
            g.public_paths = vec![scoped("/deployments", PathScope::Admin)];

            // Right tier, right deployment.
            let ok = admin_token(&tokens, &["web"], AdminScope::Admin);
            assert!(matches!(
                a.decide(&g, "web", "default", &bearer("/deployments", &ok)).await,
                Decision::Allow(_)
            ));

            // Right deployment, tier too low. `view` does not reach `admin`.
            let weak = admin_token(&tokens, &["web"], AdminScope::View);
            assert!(matches!(
                a.decide(&g, "web", "default", &bearer("/deployments", &weak)).await,
                Decision::Answered(_)
            ));

            // Right tier, wrong deployment — this is what stops a token minted
            // for one deployment walking in through another's public path.
            let elsewhere = admin_token(&tokens, &["other"], AdminScope::Admin);
            assert!(matches!(
                a.decide(&g, "web", "default", &bearer("/deployments", &elsewhere)).await,
                Decision::Answered(_)
            ));

            // And a `public` entry still needs nothing at all.
            g.public_paths = vec![PublicPath::public("/healthz")];
            assert!(matches!(
                a.decide(&g, "web", "default", &req("/healthz", vec![])).await,
                Decision::Allow(_)
            ));
        }

        /// 401 and 403 are different answers with different fixes, and the
        /// gate used to give 401 for both. That cost real time: a
        /// namespace-confined token was reported as one the server did not
        /// recognise, which sends you to look at the token instead of the gate.
        #[tokio::test]
        async fn a_known_token_is_refused_differently_from_an_unknown_one() {
            let (a, tokens) = with_tokens();
            let mut g = gate();
            g.public_paths = vec![scoped("/deployments", PathScope::Admin)];

            // Known, right tier, but confined to a namespace this deployment is
            // not in — `admits` fails, and the reason is worth saying.
            let confined = tokens
                .mint(
                    NewToken {
                        name: "ns".into(),
                        admin: AdminScope::Admin,
                        namespace: Some("samcurrie".into()),
                        deployments: Vec::new(),
                        expires_in_secs: None,
                    },
                    now_secs(),
                )
                .unwrap()
                .1;
            let Decision::Answered(r) =
                a.decide(&g, "app-lb-admin", "default", &bearer("/deployments", &confined)).await
            else {
                panic!("a namespace token cannot pass a gate outside its namespace");
            };
            assert_eq!(r.status, 403, "known but not admitted is a 403");
            assert!(r.body.contains("does not admit"), "{}", r.body);
            assert!(r.body.contains("app-lb-admin"), "{}", r.body);

            // Known, wrong tier: also 403, and says which tier.
            let low = admin_token(&tokens, &["app-lb-admin"], AdminScope::View);
            let Decision::Answered(r) =
                a.decide(&g, "app-lb-admin", "default", &bearer("/deployments", &low)).await
            else {
                panic!("view does not reach admin");
            };
            assert_eq!(r.status, 403);
            assert!(r.body.contains("'view'") && r.body.contains("'admin'"), "{}", r.body);

            // Not known at all: 401, because nothing verified it — a different
            // problem with a different fix.
            let Decision::Answered(r) = a
                .decide(&g, "app-lb-admin", "default", &bearer("/deployments", "applb_dead_nope"))
                .await
            else {
                panic!("an unknown token is refused");
            };
            assert_eq!(r.status, 401, "unrecognised is a 401");
        }

        /// The comparison that decides whether a deployment fronts the admin API.
    /// A byte-for-byte version of this shipped and was wrong in production:
    /// `0.0.0.0:9090` and `127.0.0.1:9090` are the same listener.
    #[test]
    fn the_admin_listener_is_matched_by_address_not_by_spelling() {
        // The case that broke: a wildcard bind, an upstream naming loopback.
        assert!(same_listener("0.0.0.0:9090", "127.0.0.1:9090"));
        assert!(same_listener("0.0.0.0:9090", "localhost:9090"));
        assert!(same_listener("[::]:9090", "127.0.0.1:9090"));
        // Two spellings of loopback.
        assert!(same_listener("127.0.0.1:9090", "localhost:9090"));
        assert!(same_listener("localhost:9090", "127.0.0.1:9090"));
        assert!(same_listener("[::1]:9090", "127.0.0.1:9090"));
        // Identical, and equivalent IPv6 spellings.
        assert!(same_listener("127.0.0.1:9090", "127.0.0.1:9090"));
        assert!(same_listener("[0:0:0:0:0:0:0:1]:9090", "[::1]:9090"));

        // The port is never negotiable — a different port is a different
        // process, whatever the host says.
        assert!(!same_listener("0.0.0.0:9090", "127.0.0.1:9091"));
        assert!(!same_listener("127.0.0.1:9090", "127.0.0.1:8080"));
        // A specific non-loopback bind is not every address.
        assert!(!same_listener("10.0.0.5:9090", "127.0.0.1:9090"));
        assert!(!same_listener("10.0.0.5:9090", "10.0.0.6:9090"));
        // A name needing DNS is refused rather than resolved on the hot path.
        assert!(!same_listener("127.0.0.1:9090", "some-host:9090"));
        // Malformed input refuses.
        assert!(!same_listener("9090", "127.0.0.1:9090"));
        assert!(!same_listener("", ""));
    }

    /// In front of app-lb's own admin API the gate checks the tier and
        /// nothing else, because the API behind it scope-checks better than the
        /// gate can. Without this a namespace-confined token could not reach
        /// the admin API at all through its hostname — it admits no deployment
        /// outside its namespace, and the fronting deployment lives in
        /// `default`.
        #[tokio::test]
        async fn the_admin_api_does_its_own_scoping_so_the_gate_does_not_double_check() {
            let (a, tokens) = with_tokens();
            let mut g = gate();
            g.public_paths = vec![scoped("/deployments", PathScope::Admin)];

            let confined = tokens
                .mint(
                    NewToken {
                        name: "ns".into(),
                        admin: AdminScope::Admin,
                        namespace: Some("samcurrie".into()),
                        deployments: Vec::new(),
                        expires_in_secs: None,
                    },
                    now_secs(),
                )
                .unwrap()
                .1;

            // The fronting deployment is in `default`; the token is walled into
            // `samcurrie`. `admits` says no, and for an ordinary app that is the
            // right answer.
            let mut ordinary = bearer("/deployments", &confined);
            ordinary.fronts_admin_api = false;
            assert!(matches!(
                a.decide(&g, "app-lb-admin", "default", &ordinary).await,
                Decision::Answered(_)
            ));

            // In front of the admin API it is the wrong question, and is not
            // asked. The tier still is.
            let mut fronting = bearer("/deployments", &confined);
            fronting.fronts_admin_api = true;
            assert!(matches!(
                a.decide(&g, "app-lb-admin", "default", &fronting).await,
                Decision::Allow(_)
            ));

            // Tier is still enforced here — skipping `admits` is not skipping
            // authorization, and a `view` token gets no further than before.
            let low = tokens
                .mint(
                    NewToken {
                        name: "low".into(),
                        admin: AdminScope::View,
                        namespace: Some("samcurrie".into()),
                        deployments: Vec::new(),
                        expires_in_secs: None,
                    },
                    now_secs(),
                )
                .unwrap()
                .1;
            let mut low_req = bearer("/deployments", &low);
            low_req.fronts_admin_api = true;
            let Decision::Answered(r) = a.decide(&g, "app-lb-admin", "default", &low_req).await
            else {
                panic!("view does not reach admin, wherever the gate stands");
            };
            assert_eq!(r.status, 403);
            assert!(r.body.contains("'view'"), "{}", r.body);
        }

        /// The same relaxation on the *ordinary* gate path, which is the one a
        /// request takes when the route is not in `public_paths` at all. Both
        /// branches need it: fixing only the scoped one leaves a namespace
        /// token able to reach a listed path and not an unlisted one, which is
        /// a distinction nobody asked for and nobody could predict.
        #[tokio::test]
        async fn the_ordinary_gate_path_skips_admits_in_front_of_the_admin_api_too() {
            let (a, tokens) = with_tokens();
            // No public_paths at all — the shape after `/deployments` is removed
            // from the list, which is what a hardened admin gate looks like.
            let g: AuthGate = serde_json::from_str(r#"{"provider":"app-token"}"#).unwrap();

            // Exactly the token that failed: namespaced, admin tier, `*`.
            // `*` inside a wall means every deployment *there*, so it does not
            // help across one.
            let t = tokens
                .mint(
                    NewToken {
                        name: "sam".into(),
                        admin: AdminScope::Admin,
                        namespace: Some("samcurrie".into()),
                        deployments: vec!["*".into()],
                        expires_in_secs: None,
                    },
                    now_secs(),
                )
                .unwrap()
                .1;

            let mut ordinary = bearer("/deployments", &t);
            ordinary.fronts_admin_api = false;
            assert!(
                matches!(a.decide(&g, "app-lb-admin", "default", &ordinary).await, Decision::Answered(_)),
                "in front of an application the namespace wall is the gate's to enforce",
            );

            let mut fronting = bearer("/deployments", &t);
            fronting.fronts_admin_api = true;
            assert!(
                matches!(a.decide(&g, "app-lb-admin", "default", &fronting).await, Decision::Allow(_)),
                "in front of the admin API it is the API's to enforce, per request",
            );
        }

        /// A token admitted at a scoped path forwards no identity, exactly as
        /// one admitted at the gate does: a token is not a person.
        #[tokio::test]
        async fn an_admitted_token_still_forwards_nobody() {
            let (a, tokens) = with_tokens();
            let mut g = gate();
            g.public_paths = vec![scoped("/api/", PathScope::None)];
            let t = admin_token(&tokens, &["web"], AdminScope::None);
            let Decision::Allow(id) = a.decide(&g, "web", "default", &bearer("/api/x", &t)).await
            else {
                panic!("an app-token with `none` satisfies the lowest tier");
            };
            assert_eq!(*id, None);
        }
    }

    /// A sign-in that mints a credential the upstream can actually check —
    /// the thing whose absence made operators turn their admin API's own
    /// authentication off.
    mod session_tokens {
        use super::*;
        use crate::secrets::SecretStore;
        use crate::tokens::{AdminScope, TokenStore};
        use std::sync::Arc;

        fn with_tokens() -> (Authenticator, Arc<TokenStore>) {
            let tokens = Arc::new(TokenStore::new("/nonexistent/tokens.json"));
            let secrets = Arc::new(SecretStore::new("/nonexistent/secrets.json", None));
            (
                Authenticator::new(vec![7u8; 32], secrets, Some(tokens.clone()), None),
                tokens,
            )
        }

        #[test]
        fn no_scope_means_no_token() {
            // The default, and the one that matters: a gate in front of an
            // ordinary web app must not hand the browser a credential for
            // app-lb's admin API just because somebody signed in.
            let (a, tokens) = with_tokens();
            let g = gate();
            assert!(g.session_scope.is_none(), "unset is the default");
            let (secret, id) = a.mint_session_token(&g, "web", &identity("a@example.com", None));
            assert!(secret.is_none() && id.is_none());
            assert!(tokens.list().is_empty(), "nothing was minted");
        }

        #[test]
        fn a_scoped_gate_mints_a_real_token_that_expires_with_the_session() {
            let (a, tokens) = with_tokens();
            let mut g = gate();
            g.session_scope = Some(AdminScope::Admin);
            g.session_ttl_secs = 3600;

            let (secret, id) = a.mint_session_token(&g, "app-lb-admin", &identity("a@example.com", None));
            let (secret, id) = (secret.expect("a secret"), id.expect("an id"));

            // It is a real app-token: the store verifies it like any other, and
            // that is the whole point — the upstream's existing check works.
            let t = tokens.verify(&secret, now_secs()).expect("the store knows it");
            assert_eq!(t.id, id);
            assert_eq!(t.admin, AdminScope::Admin);
            assert!(t.deployments.iter().any(|d| d == "*"), "fleet-scoped: the dashboard reads every deployment");
            assert!(t.name.contains("a@example.com"), "named so it can be recognised: {}", t.name);

            // Expiring with the session, not outliving it.
            let exp = t.expires_at.expect("a session token must expire");
            assert!(exp > now_secs() && exp <= now_secs() + 3600 + 2, "exp={exp}");
        }

        #[tokio::test]
        async fn the_token_rides_the_session_cookie_and_dies_at_logout() {
            let (a, tokens) = with_tokens();
            let mut g = gate();
            g.session_scope = Some(AdminScope::Admin);

            let (secret, id) = a.mint_session_token(&g, "web", &identity("a@example.com", None));
            let (secret, id) = (secret.unwrap(), id.unwrap());
            let session = Session {
                subject: "sub-1".into(),
                email: "a@example.com".into(),
                name: None,
                hosted_domain: None,
                deployment: "web".into(),
                policy: g.policy_fingerprint(),
                exp: now_secs() + 600,
                token: Some(secret.clone()),
                token_id: Some(id.clone()),
            };
            let cookie = format!("{}={}", g.cookie_name, a.sign(&session.encode()));

            // The proxy reads it off the identity, which is the only way it
            // reaches the upstream.
            let Decision::Allow(who) = a.decide(&g, "web", "default", &req("/", vec![cookie.clone()])).await
            else {
                panic!("a valid session admits");
            };
            assert_eq!(who.as_ref().as_ref().unwrap().session_token.as_deref(), Some(secret.as_str()));

            // Signing out revokes it. Clearing the cookie alone would leave a
            // live fleet-scoped credential nobody could reach or notice.
            let _ = a.decide(&g, "web", "default", &req(&g.logout_path(), vec![cookie])).await;
            assert!(tokens.verify(&secret, now_secs()).is_none(), "revoked");
            assert!(tokens.get(&id).is_none());
        }
    }

    #[tokio::test]
    async fn a_tampered_or_expired_session_is_not_a_session() {
        let (a, g) = (auth(), gate());
        let id = identity("someone@example.com", Some("example.com"));

        // Expired.
        let stale = session_cookie(&a, &g, &id, now_secs() - 1);
        assert!(matches!(
            a.decide(&g, "web", "default", &req("/", vec![stale])).await,
            Decision::Answered(_)
        ));

        // Signed with a different key.
        let other = Authenticator::new(vec![9u8; 32], Arc::new(SecretStore::new("x.json", None)), None, None);
        let forged = session_cookie(&other, &g, &id, now_secs() + 600);
        assert!(matches!(
            a.decide(&g, "web", "default", &req("/", vec![forged])).await,
            Decision::Answered(_)
        ));

        // Payload edited, signature left alone.
        let good = session_cookie(&a, &g, &id, now_secs() + 600);
        let (name, token) = good.split_once('=').unwrap();
        let (payload, mac) = token.rsplit_once('.').unwrap();
        let mut edited = b64().decode(payload).unwrap();
        edited[0] ^= 0x20;
        let tampered = format!("{name}={}.{mac}", b64().encode(edited));
        assert!(matches!(
            a.decide(&g, "web", "default", &req("/", vec![tampered])).await,
            Decision::Answered(_)
        ));
    }

    /// A session must not be usable at a different deployment, whose allow-list
    /// may be narrower.
    #[tokio::test]
    async fn a_session_is_bound_to_its_deployment() {
        let (a, g) = (auth(), gate());
        let cookie = session_cookie(&a, &g, &identity("someone@example.com", Some("example.com")), now_secs() + 600);
        assert!(matches!(
            a.decide(&g, "other", "default", &req("/", vec![cookie])).await,
            Decision::Answered(_)
        ));
    }

    /// Removing somebody from the allow-list has to sign them out, not wait for
    /// their cookie to expire.
    #[tokio::test]
    async fn tightening_the_allow_list_invalidates_existing_sessions() {
        let (a, g) = (auth(), gate());
        let id = identity("someone@example.com", Some("example.com"));
        let cookie = session_cookie(&a, &g, &id, now_secs() + 600);
        assert!(matches!(
            a.decide(&g, "web", "default", &req("/", vec![cookie.clone()])).await,
            Decision::Allow(_)
        ));

        let mut tightened = gate();
        tightened.allowed_domains = vec!["other.example".into()];
        assert!(matches!(
            a.decide(&tightened, "web", "default", &req("/", vec![cookie])).await,
            Decision::Answered(_)
        ));
    }

    #[test]
    fn the_allow_list_matches_the_hosted_domain_not_the_email_suffix() {
        let mut g = gate();
        g.allowed_domains = vec!["example.com".into()];

        assert!(g.allows("someone@example.com", Some("example.com")));
        // A personal account whose address merely *looks* like the domain: the
        // `hd` claim is absent, so it is not governed by that Workspace.
        assert!(!g.allows("someone@example.com", None));
        assert!(!g.allows("someone@example.com", Some("elsewhere.com")));

        // An explicit address gets in regardless of domain.
        g.allowed_emails = vec!["Contractor@Gmail.com".into()];
        assert!(g.allows("contractor@gmail.com", None));

        // The escape hatch.
        let any = AuthGate {
            allowed_domains: vec!["*".into()],
            allowed_emails: vec![],
            ..gate()
        };
        assert!(any.allows("anyone@anywhere.example", None));
    }

    #[test]
    fn claims_are_checked_for_audience_issuer_expiry_and_verification() {
        let ok = IdClaims {
            iss: Some("https://accounts.google.com".into()),
            aud: Some("cid.apps.googleusercontent.com".into()),
            sub: Some("sub-1".into()),
            email: Some("Someone@Example.com".into()),
            email_verified: BoolLike::Bool(true),
            hd: Some("example.com".into()),
            name: Some("A Person".into()),
            exp: Some(now_secs() + 300),
        };
        let id = validate_claims(&ok, "cid.apps.googleusercontent.com").unwrap();
        assert_eq!(id.email, "someone@example.com", "normalized");
        assert_eq!(id.hosted_domain.as_deref(), Some("example.com"));

        // A token minted for another application must not be accepted here.
        let err = validate_claims(&ok, "someone-elses-client").unwrap_err();
        assert!(err.contains("different client"), "{err}");

        for (mutate, expect) in [
            (
                IdClaims { iss: Some("https://evil.example".into()), ..clone_claims(&ok) },
                "issuer",
            ),
            (IdClaims { exp: Some(now_secs() - 1), ..clone_claims(&ok) }, "expired"),
            (
                IdClaims { email_verified: BoolLike::Bool(false), ..clone_claims(&ok) },
                "not a verified",
            ),
            (IdClaims { email: None, ..clone_claims(&ok) }, "no email"),
        ] {
            let err = validate_claims(&mutate, "cid.apps.googleusercontent.com").unwrap_err();
            assert!(err.contains(expect), "expected {expect:?}, got {err:?}");
        }
    }

    /// `IdClaims` is not `Clone` (it is only ever built by serde), so the test
    /// above builds variants from a copy made here.
    fn clone_claims(c: &IdClaims) -> IdClaims {
        IdClaims {
            iss: c.iss.clone(),
            aud: c.aud.clone(),
            sub: c.sub.clone(),
            email: c.email.clone(),
            email_verified: match &c.email_verified {
                BoolLike::Bool(b) => BoolLike::Bool(*b),
                BoolLike::Str(s) => BoolLike::Str(s.clone()),
                BoolLike::Missing => BoolLike::Missing,
            },
            hd: c.hd.clone(),
            name: c.name.clone(),
            exp: c.exp,
        }
    }

    #[test]
    fn email_verified_is_accepted_as_a_bool_or_a_string() {
        assert!(BoolLike::Bool(true).is_true());
        assert!(BoolLike::Str("true".into()).is_true());
        assert!(BoolLike::Str("TRUE".into()).is_true());
        assert!(!BoolLike::Str("false".into()).is_true());
        // Absent means unverified, never "assume yes".
        assert!(!BoolLike::Missing.is_true());
    }

    #[test]
    fn an_id_token_payload_is_decoded_without_its_signature() {
        let payload = serde_json::json!({
            "iss": "https://accounts.google.com",
            "aud": "cid",
            "email": "a@b.com",
            "email_verified": true,
        });
        let token = format!(
            "{}.{}.{}",
            b64().encode(b"{\"alg\":\"RS256\"}"),
            b64().encode(payload.to_string()),
            b64().encode(b"not-a-real-signature"),
        );
        let claims = decode_id_token(&token).unwrap();
        assert_eq!(claims.email.as_deref(), Some("a@b.com"));

        assert!(decode_id_token("not-a-jwt").is_err());
        assert!(decode_id_token("aaa.!!!not-base64!!!.ccc").is_err());
    }

    /// A `Location` built from the request must not be able to leave the site.
    #[test]
    fn return_paths_cannot_become_an_open_redirect() {
        assert_eq!(safe_return_path("/dashboard?tab=1"), "/dashboard?tab=1");
        for hostile in [
            "//evil.example/",
            "https://evil.example/",
            "/\\evil.example",
            "dashboard",
            "",
        ] {
            assert_eq!(safe_return_path(hostile), "/", "{hostile:?} should be dropped");
        }
    }

    #[test]
    fn cookies_are_found_across_headers_and_neighbours() {
        let headers = vec![
            "other=1; applb_session=abc.def".to_string(),
            "unrelated=2".to_string(),
        ];
        assert_eq!(cookie_values(&headers, "applb_session"), ["abc.def"]);
        assert_eq!(cookie_values(&headers, "unrelated"), ["2"]);
        assert!(cookie_values(&headers, "missing").is_empty());
        // A cookie whose *name* merely ends with the one we want must not match.
        let confusable = vec!["not_applb_session=nope".to_string()];
        assert!(cookie_values(&confusable, "applb_session").is_empty());
    }

    /// Same name, two entries — a host-only cookie and a realm one from a
    /// sibling gate. The browser sends both and nothing says which comes first,
    /// so both have to be visible to the caller.
    #[test]
    fn every_cookie_sharing_a_name_is_returned_in_order() {
        let headers = vec![
            "applb_session=from-the-realm; other=1".to_string(),
            "applb_session=host-only".to_string(),
        ];
        assert_eq!(
            cookie_values(&headers, "applb_session"),
            ["from-the-realm", "host-only"]
        );
    }

    #[test]
    fn signing_round_trips_and_rejects_anything_edited() {
        let a = auth();
        let token = a.sign(b"hello");
        assert_eq!(a.verify(&token).as_deref(), Some(&b"hello"[..]));
        assert_eq!(a.verify("garbage"), None);
        assert_eq!(a.verify(&format!("{token}x")), None);

        let other = Authenticator::new(vec![1u8; 32], Arc::new(SecretStore::new("x.json", None)), None, None);
        assert_eq!(other.verify(&token), None, "a different key must not verify");
    }

    #[test]
    fn the_pkce_challenge_is_the_hash_of_the_verifier() {
        // Vector from RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_key_file_is_created_once_and_reused() {
        let dir = std::env::temp_dir().join(format!("app-lb-authkey-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let path = dir.join("auth-key");

        let first = Authenticator::load_key(&path).unwrap();
        assert_eq!(first.len(), 32);
        let second = Authenticator::load_key(&path).unwrap();
        assert_eq!(first, second, "a restart must not invalidate every session");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "group/other bits set: {mode:o}");
        }

        // A truncated key is an error, not a silent regeneration that would
        // invalidate sessions without saying so.
        std::fs::write(&path, b"short").unwrap();
        assert!(Authenticator::load_key(&path).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn the_callback_refuses_a_state_that_does_not_match_the_cookie() {
        let (a, g) = (auth(), gate());
        let flow = Flow {
            nonce: "the-real-nonce".into(),
            return_to: "/dashboard".into(),
            verifier: "v".into(),
            deployment: "web".into(),
            exp: now_secs() + 300,
        };
        let cookie = format!("{FLOW_COOKIE}={}", a.sign(&flow.encode()));

        let mut r = req("/__applb/auth/callback", vec![cookie]);
        r.query = Some("code=abc&state=a-different-nonce");
        let Decision::Answered(response) = a.decide(&g, "web", "default", &r).await else {
            panic!("the callback always answers");
        };
        assert_eq!(response.status, 400);
        assert!(response.body.contains("did not match"), "{}", response.body);
    }

    #[tokio::test]
    async fn the_callback_reports_a_refusal_at_the_provider() {
        let (a, g) = (auth(), gate());
        let mut r = req("/__applb/auth/callback", vec![]);
        r.query = Some("error=access_denied");
        let Decision::Answered(response) = a.decide(&g, "web", "default", &r).await else {
            panic!("the callback always answers");
        };
        assert_eq!(response.status, 403);
        assert!(response.body.contains("access_denied"));
    }

    /// The same shadowing one step earlier: a leftover flow cookie ahead of the
    /// live one must not turn the provider's redirect back into "the sign-in
    /// state did not match", which would strand the browser on a 400 with a
    /// spent authorization code.
    #[tokio::test]
    async fn a_stale_flow_cookie_does_not_shadow_the_live_one() {
        let mut a = auth();
        // Nothing listening, so the exchange fails fast on connect. Reaching it
        // at all is the property under test.
        a.token_endpoint = "http://127.0.0.1:1/token".into();
        let g = gate();

        let flow = |nonce: &str, verifier: &str| Flow {
            nonce: nonce.into(),
            return_to: "/dashboard".into(),
            verifier: verifier.into(),
            deployment: "web".into(),
            exp: now_secs() + 300,
        };
        let stale = format!("{FLOW_COOKIE}={}", a.sign(&flow("an-older-nonce", "v0").encode()));
        let live = format!("{FLOW_COOKIE}={}", a.sign(&flow("the-live-nonce", "v1").encode()));

        let mut r = req("/__applb/auth/callback", vec![stale, live]);
        r.query = Some("code=abc&state=the-live-nonce");
        let Decision::Answered(response) = a.decide(&g, "web", "default", &r).await else {
            panic!("the callback always answers");
        };
        assert_eq!(
            response.status, 502,
            "the callback must get as far as the token exchange: {}",
            response.body,
        );
    }

    /// A bookmarked callback URL has no flow cookie; starting over beats a
    /// dead-end error page.
    #[tokio::test]
    async fn a_callback_without_a_flow_cookie_starts_a_new_sign_in() {
        let (a, g) = (auth(), gate());
        let mut r = req("/__applb/auth/callback", vec![]);
        r.query = Some("code=abc&state=xyz");
        let Decision::Answered(response) = a.decide(&g, "web", "default", &r).await else {
            panic!("the callback always answers");
        };
        assert_eq!(response.status, 302);
        assert!(response.location.unwrap().starts_with(GOOGLE_AUTHORIZE));
    }

    #[tokio::test]
    async fn logout_clears_the_session_cookie() {
        let (a, g) = (auth(), gate());
        let id = identity("someone@example.com", Some("example.com"));
        let cookie = session_cookie(&a, &g, &id, now_secs() + 600);
        let Decision::Answered(r) = a
            .decide(&g, "web", "default", &req("/__applb/auth/logout", vec![cookie]))
            .await
        else {
            panic!("logout always answers");
        };
        assert_eq!(r.status, 302);
        let cleared = r.cookies.iter().find(|c| c.starts_with(&g.cookie_name)).unwrap();
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
    }

    #[test]
    fn a_plaintext_connection_gets_a_cookie_it_can_actually_send() {
        // `Secure` on a cookie set over http is dropped by the browser, which
        // would make the session invisible and loop the sign-in.
        assert!(!set_cookie("n", "v", false, None, None).contains("Secure"));
        assert!(set_cookie("n", "v", true, None, None).contains("Secure"));
    }

    #[test]
    fn identity_headers_are_reduced_to_something_a_header_can_hold() {
        assert_eq!(header_safe("A Person"), "A Person");
        assert_eq!(header_safe("bad\r\ninjected: yes"), "badinjected: yes");
        assert_eq!(header_safe("naïve 🙂").trim(), "nave");
        assert!(header_safe(&"x".repeat(500)).len() <= 256);
    }
}
