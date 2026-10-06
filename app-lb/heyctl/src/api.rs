//! The admin API, as methods.
//!
//! # Typed reads, `Value` writes
//!
//! Reads come back as the structs in [`crate::types`]. Writes take
//! `serde_json::Value`.
//!
//! That asymmetry is deliberate and load-bearing. `PUT /deployments/:id`
//! replaces a *whole* spec, so a client that parsed one into a struct it only
//! half-understood and wrote it back would silently delete every field this
//! build has never heard of. Round-tripping the `Value` cannot lose anything.
//! The read types are lenient for the mirror-image reason — unknown fields land
//! in `extra` and missing ones default, so a client a version behind still
//! renders what it understands.
//!
//! Typed *builders* for writes are a reasonable thing to want, and the way to
//! have them without the hazard is to build a `Value` and pass it here.

use crate::error::{Error, Result};
use crate::transport::{Auth, HttpTransport, Method, Request, Response, Transport};
use crate::types::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// Default deadline for an ordinary request.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// app-lb's own default `cold_start_timeout_secs`.
///
/// Used to size the deadline on a waking `exec`, because the caller's wall clock
/// is the command timeout *plus* however long a VM takes to appear — and the
/// client cannot know a deployment's configured value without asking. A
/// deployment configured higher needs [`ExecRequest::patience`].
pub const ASSUMED_COLD_START_SECS: u64 = 120;

/// Margin over the server-side deadline, so the client is never the one that
/// gives up first. Abandoning a request app-lb is still serving turns a
/// well-defined answer into an unexplained transport error.
const EXEC_MARGIN_SECS: u64 = 15;

/// Percent-encode one path segment.
///
/// Deployment and secret ids are constrained server-side, but a *token* id, a
/// job id or a sandbox id all arrive from elsewhere, and a stray `/` or `?`
/// would silently address a different route.
/// `/secrets/<id>` with the query the item routes take: the namespace the id is
/// looked up in, and `force` where a delete accepts one.
fn secret_path(namespace: Option<&str>, id: &str, force: Option<bool>) -> String {
    let mut path = format!("/secrets/{}", seg(id));
    let mut query: Vec<String> = Vec::new();
    if let Some(ns) = namespace {
        query.push(format!("namespace={}", seg(ns)));
    }
    if let Some(force) = force {
        query.push(format!("force={}", if force { "true" } else { "false" }));
    }
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query.join("&"));
    }
    path
}

pub(crate) fn seg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Which admin routes a server is gating.
///
/// app-lb has two independent gates, and which are on is not discoverable from
/// configuration — only by asking. Reported so a caller can say "you need
/// credentials" before a write fails rather than after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gates {
    /// `/metrics` and `/dashboard` need a credential.
    pub view: bool,
    /// The CRUD routes need one.
    pub crud: bool,
}

impl Gates {
    /// Whether anything at all is gated. `false` means there is no credential
    /// to log in *with*, which is a different thing from being logged out.
    pub fn any(&self) -> bool {
        self.view || self.crud
    }
}

/// A client for one app-lb.
///
/// Cheap to clone: everything behind it is an `Arc`.
#[derive(Debug, Clone)]
pub struct Client {
    transport: Arc<dyn Transport>,
    /// Kept alongside the transport so the shell can build a `ws://` URL and
    /// authenticate its own upgrade — it does not go through `Transport`.
    ws: Option<Arc<WsConfig>>,
}

/// What [`crate::shell`] needs that the HTTP transport cannot provide.
#[derive(Debug)]
pub(crate) struct WsConfig {
    pub base: String,
    pub auth: Auth,
    pub insecure: bool,
}

impl Client {
    /// Connect to `server`, which may be a URL or a bare `host:port`.
    pub fn new(server: impl Into<String>, auth: Auth) -> Result<Self> {
        Self::builder(server).auth(auth).build()
    }

    pub fn builder(server: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            server: server.into(),
            auth: Auth::None,
            timeout: DEFAULT_TIMEOUT,
            insecure: false,
        }
    }

    /// Build on an arbitrary transport — a stub, a recorder, a proxy.
    ///
    /// Shell sessions are unavailable on a client made this way: a WebSocket
    /// does not go through [`Transport`], so there is nothing to point it at.
    pub fn with_transport(transport: Arc<dyn Transport>) -> Self {
        Self {
            transport,
            ws: None,
        }
    }

    // -- plumbing ----------------------------------------------------------

    pub(crate) async fn send(&self, req: Request, kind: &'static str, name: &str) -> Result<Response> {
        let r = self.transport.send(req).await?;
        if r.is_success() {
            Ok(r)
        } else {
            Err(Error::from_response(
                r.status,
                &r.body,
                kind,
                name,
                self.transport.credential(),
            ))
        }
    }

    pub(crate) async fn read<T: DeserializeOwned>(
        &self,
        req: Request,
        kind: &'static str,
        name: &str,
    ) -> Result<T> {
        let r = self.send(req, kind, name).await?;
        serde_json::from_str(&r.body).map_err(Error::Decode)
    }

    pub(crate) async fn unit(&self, req: Request, kind: &'static str, name: &str) -> Result<()> {
        self.send(req, kind, name).await.map(|_| ())
    }

    // -- health and discovery ----------------------------------------------

    /// `GET /healthz`. Never gated, so this also proves reachability without a
    /// credential.
    pub async fn healthz(&self) -> Result<()> {
        self.unit(Request::new(Method::Get, "/healthz"), "server", "")
            .await
    }

    /// Which tiers this server gates, discovered by probing anonymously.
    ///
    /// Two requests, and they must be *unauthenticated* — the point is to learn
    /// what an anonymous caller is refused. Uses a throwaway transport rather
    /// than this client's, which is carrying a credential.
    pub async fn gates(server: &str, insecure: bool) -> Result<Gates> {
        let anon = Client::builder(server).insecure(insecure).build()?;
        let refused = |e: &Error| matches!(e, Error::Unauthorized { .. });
        let view = anon
            .read::<Value>(Request::new(Method::Get, "/metrics"), "server", "")
            .await
            .err()
            .as_ref()
            .is_some_and(refused);
        let crud = anon
            .read::<Value>(Request::new(Method::Get, "/deployments"), "server", "")
            .await
            .err()
            .as_ref()
            .is_some_and(refused);
        Ok(Gates { view, crud })
    }

    /// `GET /whoami` — what the server makes of this client's credential: its
    /// tier, whether it is confined, and to which namespace.
    ///
    /// Needs no tier at all, so it answers even for a token every other route
    /// refuses. [`WhoAmI::sole_namespace`] is the namespace a namespace-scoped
    /// caller may leave implicit.
    pub async fn whoami(&self) -> Result<WhoAmI> {
        self.read(Request::new(Method::Get, "/whoami"), "server", "")
            .await
    }

    // -- deployments --------------------------------------------------------

    pub async fn deployments(&self) -> Result<Vec<DeploymentStatus>> {
        self.read(Request::new(Method::Get, "/deployments"), "deployment", "")
            .await
    }

    pub async fn deployment(&self, id: &str) -> Result<DeploymentStatus> {
        self.read(
            Request::new(Method::Get, format!("/deployments/{}", seg(id))),
            "deployment",
            id,
        )
        .await
    }

    /// Read one deployment with a caller-supplied deadline. Drain polling uses
    /// this so its `--timeout` remains a wall-clock bound rather than inheriting
    /// the ordinary 30-second request timeout on every iteration.
    pub async fn deployment_with_timeout(
        &self,
        id: &str,
        timeout: Duration,
    ) -> Result<DeploymentStatus> {
        self.read(
            Request::new(Method::Get, format!("/deployments/{}", seg(id))).timeout(timeout),
            "deployment",
            id,
        )
        .await
    }

    /// Whether a deployment exists, without treating absence as an error.
    pub async fn deployment_exists(&self, id: &str) -> Result<bool> {
        match self.deployment(id).await {
            Ok(_) => Ok(true),
            Err(Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `POST /deployments`.
    ///
    /// Note app-lb answers `201` even when this *replaced* an existing
    /// deployment, so the status does not distinguish create from update.
    /// Certificate issuance is asynchronous: a success here does not mean a
    /// certificate exists yet.
    pub async fn create_deployment(&self, spec: &Value) -> Result<DeploymentStatus> {
        let id = spec.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
        self.read(
            Request::new(Method::Post, "/deployments").json(spec.clone()),
            "deployment",
            &id,
        )
        .await
    }

    /// `PUT /deployments/:id` — a whole-spec replace.
    ///
    /// Takes a `Value` so nothing this build does not understand is dropped on
    /// the way through. Read with [`Client::deployment`], edit the `spec` field,
    /// pass it back.
    pub async fn replace_deployment(&self, id: &str, spec: &Value) -> Result<DeploymentStatus> {
        self.read(
            Request::new(Method::Put, format!("/deployments/{}", seg(id))).json(spec.clone()),
            "deployment",
            id,
        )
        .await
    }

    /// `PATCH /deployments/:id/scaling` — a shallow merge onto the current
    /// policy. Only meaningful for a managed (VM-pool) deployment.
    pub async fn patch_scaling(&self, id: &str, patch: &Value) -> Result<DeploymentStatus> {
        self.read(
            Request::new(
                Method::Patch,
                format!("/deployments/{}/scaling", seg(id)),
            )
            .json(patch.clone()),
            "deployment",
            id,
        )
        .await
    }

    pub async fn delete_deployment(&self, id: &str) -> Result<()> {
        self.unit(
            Request::new(Method::Delete, format!("/deployments/{}", seg(id))),
            "deployment",
            id,
        )
        .await
    }

    /// Evict one VM. `force` kills immediately; otherwise it drains.
    pub async fn evict_vm(&self, id: &str, sandbox: &str, force: bool) -> Result<EvictOutcome> {
        // app-lb parses query booleans with `str::parse::<bool>()`, which takes
        // only `true`/`false` — `?force=1` is a 400, not a truthy value.
        let path = format!(
            "/deployments/{}/vms/{}?force={}",
            seg(id),
            seg(sandbox),
            if force { "true" } else { "false" }
        );
        self.read(Request::new(Method::Delete, path), "vm", sandbox)
            .await
    }

    /// Stop new requests to one static upstream. Existing requests remain until
    /// they finish; use the returned `in_flight` count to observe the drain.
    pub async fn cordon_upstream(
        &self,
        id: &str,
        upstream: &str,
        force: bool,
        reason: Option<&str>,
    ) -> Result<UpstreamTrafficStatus> {
        let mut body = json!({ "force": force });
        if let Some(reason) = reason {
            body["reason"] = json!(reason);
        }
        self.read(
            Request::new(
                Method::Put,
                format!(
                    "/deployments/{}/upstreams/{}/drain",
                    seg(id),
                    seg(upstream),
                ),
            )
            .json(body),
            "upstream",
            upstream,
        )
        .await
    }

    /// Remove an administrative drain. Health remains independent: an
    /// unhealthy upstream is still excluded until its probe recovers.
    pub async fn uncordon_upstream(
        &self,
        id: &str,
        upstream: &str,
    ) -> Result<UpstreamTrafficStatus> {
        self.read(
            Request::new(
                Method::Delete,
                format!(
                    "/deployments/{}/upstreams/{}/drain",
                    seg(id),
                    seg(upstream),
                ),
            ),
            "upstream",
            upstream,
        )
        .await
    }

    /// `POST /deployments/:id/rollouts` — replace a managed deployment's spec by
    /// rolling a fresh pool beside the old one, verifying it, and only then
    /// draining the old one.
    ///
    /// `expected_revision` is the deployment's
    /// [`DeploymentStatus::rollout_revision`] as last read: the rollout is
    /// refused (409) if anything changed it since. `operation_id` makes the
    /// call idempotent — repeating it with the same payload returns the same
    /// operation rather than starting a second one, so a caller that lost the
    /// reply retries with the same id. Answers `202` with the operation; poll
    /// [`Client::rollout`] until [`RolloutOperation::is_finished`].
    pub async fn start_rollout(
        &self,
        id: &str,
        operation_id: &str,
        expected_revision: &str,
        spec: &Value,
    ) -> Result<RolloutOperation> {
        let body = json!({
            "operation_id": operation_id,
            "expected_revision": expected_revision,
            "spec": spec,
        });
        self.read(
            Request::new(Method::Post, format!("/deployments/{}/rollouts", seg(id))).json(body),
            "deployment",
            id,
        )
        .await
    }

    /// `GET /deployments/:id/rollouts/:operation`.
    pub async fn rollout(&self, id: &str, operation_id: &str) -> Result<RolloutOperation> {
        self.read(
            Request::new(
                Method::Get,
                format!("/deployments/{}/rollouts/{}", seg(id), seg(operation_id)),
            ),
            "rollout",
            operation_id,
        )
        .await
    }

    /// `GET /deployments/:id/discovery-status` — what this gateway publishes
    /// for the deployment to discovery. `staged: true` asks about the spec a
    /// pending change would publish instead of the live one.
    pub async fn discovery_status(&self, id: &str, staged: bool) -> Result<DiscoveryStatus> {
        let path = if staged {
            format!("/deployments/{}/discovery-status?staged=true", seg(id))
        } else {
            format!("/deployments/{}/discovery-status", seg(id))
        };
        self.read(Request::new(Method::Get, path), "deployment", id).await
    }

    // -- running things inside a VM ----------------------------------------

    /// Run a command in the deployment's VM and wait for it to finish.
    ///
    /// Two things to know:
    ///
    /// - **A non-zero exit is `Ok`.** The command ran; it failed. Only an
    ///   inability to *run* it is an `Err`.
    /// - **The timeout does not kill anything.** `timeout_secs` bounds app-lb's
    ///   own call to the daemon; when it expires app-lb gives up and answers
    ///   [`Error::Upstream`], and **the command keeps running in the guest**.
    ///   There is no cancellation to offer — the daemon has no streaming or
    ///   cancel API, so output is buffered until the command exits.
    pub async fn exec(&self, id: &str, req: &ExecRequest) -> Result<ExecOutput> {
        if req.command.trim().is_empty() {
            return Err(Error::Invalid("a command to exec must not be blank".into()));
        }
        let mut body = json!({ "command": req.command, "wake": req.wake });
        if let Some(cwd) = &req.cwd {
            body["cwd"] = json!(cwd);
        }
        if let Some(env) = &req.env {
            body["env"] = json!(env);
        }
        if let Some(t) = req.timeout_secs {
            body["timeout_secs"] = json!(t);
        }
        self.read(
            Request::new(Method::Post, format!("/deployments/{}/exec", seg(id)))
                .json(body)
                .timeout(req.patience()),
            "deployment",
            id,
        )
        .await
    }

    // -- secrets ------------------------------------------------------------

    /// `GET /workflows` — every CI workflow object.
    pub async fn workflows(&self) -> Result<Vec<WorkflowView>> {
        let list: WorkflowList = self
            .read(Request::new(Method::Get, "/workflows"), "workflow", "")
            .await?;
        Ok(list.workflows)
    }

    pub async fn workflow(&self, id: &str) -> Result<WorkflowView> {
        self.read(
            Request::new(Method::Get, format!("/workflows/{}", seg(id))),
            "workflow",
            id,
        )
        .await
    }

    /// `POST /workflows` — create or replace.
    ///
    /// Takes a `Value` rather than a typed spec for the same reason the
    /// deployment writes do: the CLI round-trips whatever the user wrote,
    /// including fields this build does not know about, so an older `heyctl`
    /// cannot silently drop a newer field on an edit.
    pub async fn create_workflow(&self, spec: &Value) -> Result<WorkflowView> {
        let id = spec
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        self.read(
            Request::new(Method::Post, "/workflows").json(spec.clone()),
            "workflow",
            &id,
        )
        .await
    }

    pub async fn replace_workflow(&self, id: &str, spec: &Value) -> Result<WorkflowView> {
        self.read(
            Request::new(Method::Put, format!("/workflows/{}", seg(id))).json(spec.clone()),
            "workflow",
            id,
        )
        .await
    }

    pub async fn delete_workflow(&self, id: &str) -> Result<()> {
        self.unit(
            Request::new(Method::Delete, format!("/workflows/{}", seg(id))),
            "workflow",
            id,
        )
        .await
    }

    pub async fn secrets(&self) -> Result<Vec<SecretSummary>> {
        self.secrets_in(None).await
    }

    /// The secrets of one namespace, or of every namespace this credential
    /// reaches.
    ///
    /// A namespace is a wall, not a filter: a deployment in `team-a` resolves
    /// `team-a`'s secrets and cannot name another namespace's, so a secret
    /// stored in the wrong one is invisible rather than merely misfiled.
    pub async fn secrets_in(&self, namespace: Option<&str>) -> Result<Vec<SecretSummary>> {
        let path = match namespace {
            Some(ns) => format!("/secrets?namespace={}", seg(ns)),
            None => "/secrets".to_string(),
        };
        self.read(Request::new(Method::Get, path), "secret", "").await
    }

    pub async fn secret(&self, id: &str) -> Result<SecretSummary> {
        self.secret_in(None, id).await
    }

    pub async fn secret_in(&self, namespace: Option<&str>, id: &str) -> Result<SecretSummary> {
        self.read(
            Request::new(Method::Get, secret_path(namespace, id, None)),
            "secret",
            id,
        )
        .await
    }

    pub async fn secret_exists(&self, id: &str) -> Result<bool> {
        self.secret_exists_in(None, id).await
    }

    pub async fn secret_exists_in(&self, namespace: Option<&str>, id: &str) -> Result<bool> {
        match self.secret_in(namespace, id).await {
            Ok(_) => Ok(true),
            Err(Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Store a secret. Values enter here and are never readable again — no
    /// endpoint returns one.
    pub async fn put_secret(&self, spec: &Value) -> Result<SecretSummary> {
        let id = spec.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
        self.read(
            Request::new(Method::Post, "/secrets").json(spec.clone()),
            "secret",
            &id,
        )
        .await
    }

    /// Change individual keys. A `null` value deletes that key; absent keys are
    /// left alone.
    pub async fn patch_secret(&self, id: &str, patch: &Value) -> Result<SecretSummary> {
        self.patch_secret_in(None, id, patch).await
    }

    pub async fn patch_secret_in(
        &self,
        namespace: Option<&str>,
        id: &str,
        patch: &Value,
    ) -> Result<SecretSummary> {
        self.read(
            Request::new(Method::Patch, secret_path(namespace, id, None)).json(patch.clone()),
            "secret",
            id,
        )
        .await
    }

    /// Delete a secret. Refused with [`Error::Conflict`] if a deployment still
    /// references it, unless `force`.
    pub async fn delete_secret(&self, id: &str, force: bool) -> Result<()> {
        self.delete_secret_in(None, id, force).await
    }

    pub async fn delete_secret_in(
        &self,
        namespace: Option<&str>,
        id: &str,
        force: bool,
    ) -> Result<()> {
        self.unit(
            Request::new(Method::Delete, secret_path(namespace, id, Some(force))),
            "secret",
            id,
        )
        .await
    }

    // -- auth providers ------------------------------------------------------

    /// The declared auth providers this credential can see, or those of one
    /// namespace.
    ///
    /// The listing narrows itself server-side — a namespace-confined token gets
    /// its own namespace's providers rather than a refusal — so calling this
    /// without a namespace is the right way to ask "what identity is declared
    /// anywhere I can reach".
    pub async fn auth_providers(&self, namespace: Option<&str>) -> Result<Vec<AuthProviderView>> {
        let path = match namespace {
            Some(ns) => format!("/auth-providers?namespace={}", seg(ns)),
            None => "/auth-providers".to_string(),
        };
        self.read(Request::new(Method::Get, path), "auth provider", "")
            .await
    }

    /// One provider, by the pair that identifies it. A provider is unique
    /// within its namespace, not across the fleet, so both halves are required.
    pub async fn auth_provider(&self, namespace: &str, name: &str) -> Result<AuthProviderView> {
        self.read(
            Request::new(
                Method::Get,
                format!("/auth-providers/{}/{}", seg(namespace), seg(name)),
            ),
            "auth provider",
            name,
        )
        .await
    }

    pub async fn auth_provider_exists(&self, namespace: &str, name: &str) -> Result<bool> {
        match self.auth_provider(namespace, name).await {
            Ok(_) => Ok(true),
            Err(Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Declare or replace a provider. Upserts, keeping the original
    /// `created_at`, so applying the same object twice is not an error.
    ///
    /// Takes a `Value` for the reason [`Client::create_namespace`] does, and one
    /// more: the body may carry `preset` and `secret`, which are request-only
    /// conveniences the server expands and never stores, so there is no stored
    /// type that could round-trip it.
    pub async fn create_auth_provider(&self, spec: &Value) -> Result<AuthProviderView> {
        let name = spec.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
        self.read(
            Request::new(Method::Post, "/auth-providers").json(spec.clone()),
            "auth provider",
            &name,
        )
        .await
    }

    /// Undeclare a provider. Refused with [`Error::Conflict`] while a
    /// deployment's gate still inherits it — resolution fails closed, so
    /// removing one out from under a live gate would take it offline.
    pub async fn delete_auth_provider(&self, namespace: &str, name: &str) -> Result<()> {
        self.unit(
            Request::new(
                Method::Delete,
                format!("/auth-providers/{}/{}", seg(namespace), seg(name)),
            ),
            "auth provider",
            name,
        )
        .await
    }

    // -- app-tokens ---------------------------------------------------------

    /// Mint a token. **The secret in the reply is shown once** — app-lb keeps
    /// only its hash, and no endpoint reads it back.
    pub async fn mint_token(&self, req: &NewToken) -> Result<MintedToken> {
        if req.name.trim().is_empty() {
            return Err(Error::Invalid(
                "a token needs a name — it is how you know what to revoke".into(),
            ));
        }
        let mut body = json!({
            "name": req.name,
            "admin": req.admin,
            "deployments": req.deployments,
        });
        if let Some(ns) = &req.namespace {
            body["namespace"] = json!(ns);
        }
        if let Some(s) = req.expires_in_secs {
            body["expires_in_secs"] = json!(s);
        }
        if req.all_servers {
            body["fleet"] = json!(true);
        }
        self.read(
            Request::new(Method::Post, "/tokens").json(body),
            "token",
            &req.name,
        )
        .await
    }

    pub async fn tokens(&self) -> Result<Vec<TokenSummary>> {
        self.read(Request::new(Method::Get, "/tokens"), "token", "")
            .await
    }

    // -- namespaces ----------------------------------------------------------

    /// The namespaces this credential can see, with how many of their
    /// deployments it may view.
    ///
    /// Narrowed server-side to what `GET /deployments` would already show, so
    /// this never names a room the caller cannot open. A credential confined to
    /// one namespace gets that one back even when nothing is in it yet.
    pub async fn namespaces(&self) -> Result<Vec<NamespaceEntry>> {
        self.read(Request::new(Method::Get, "/namespaces"), "namespace", "")
            .await
    }

    /// Declare a namespace. Idempotent: re-declaring updates the description
    /// and keeps the original `created_at`.
    ///
    /// Fleet-scoped and `admin` server-side — a credential confined to one
    /// namespace cannot mint another. Takes the spec as a `Value` for the same
    /// reason `create_deployment` does: `apply` reads objects from a file and
    /// must send what was written, not a round-trip through this build's idea
    /// of the shape.
    pub async fn create_namespace(&self, spec: &Value) -> Result<Value> {
        let name = spec.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
        self.read(
            Request::new(Method::Post, "/namespaces").json(spec.clone()),
            "namespace",
            &name,
        )
        .await
    }

    /// Undeclare a namespace. Refused while deployments are still in it.
    pub async fn delete_namespace(&self, name: &str) -> Result<()> {
        self.unit(
            Request::new(Method::Delete, format!("/namespaces/{}", seg(name))),
            "namespace",
            name,
        )
        .await
    }

    // -- the event feed ------------------------------------------------------

    /// The namespaces that have feed events, narrowed to what this credential
    /// may read.
    pub async fn feeds(&self) -> Result<Vec<FeedIndexEntry>> {
        self.read(Request::new(Method::Get, "/feeds"), "feed", "")
            .await
    }

    /// A namespace's feed events as structured data, newest first.
    pub async fn feed_events(&self, namespace: &str) -> Result<Vec<FeedEvent>> {
        self.read(
            Request::new(Method::Get, format!("/feeds/{}?format=json", seg(namespace))),
            "feed",
            namespace,
        )
        .await
    }

    /// A namespace's feed as the RSS document a reader would fetch, verbatim.
    pub async fn feed_rss(&self, namespace: &str) -> Result<String> {
        self.send(
            Request::new(Method::Get, format!("/feeds/{}", seg(namespace))),
            "feed",
            namespace,
        )
        .await
        .map(|r| r.body)
    }

    pub async fn token(&self, id: &str) -> Result<TokenSummary> {
        self.read(
            Request::new(Method::Get, format!("/tokens/{}", seg(id))),
            "token",
            id,
        )
        .await
    }

    /// Re-scope a token **without changing its secret**, so narrowing a
    /// credential does not mean redistributing it.
    pub async fn patch_token(&self, id: &str, patch: &Value) -> Result<TokenSummary> {
        self.read(
            Request::new(Method::Patch, format!("/tokens/{}", seg(id))).json(patch.clone()),
            "token",
            id,
        )
        .await
    }

    /// Revoke. Effective on the next request — verification is a store lookup,
    /// not a signature check.
    pub async fn revoke_token(&self, id: &str) -> Result<()> {
        self.unit(
            Request::new(Method::Delete, format!("/tokens/{}", seg(id))),
            "token",
            id,
        )
        .await
    }

    // -- jobs ---------------------------------------------------------------

    /// Start an image build. Returns immediately with the job to poll — see
    /// [`Client::wait_for_job`](crate::wait).
    pub async fn start_build(&self, id: &str, git_ref: Option<&str>) -> Result<JobRecord> {
        // Always a body with a content-type, even when empty: app-lb takes these
        // as `Option<Json<T>>`, and axum silently swallows a malformed or
        // untyped body into the default rather than rejecting it.
        let body = git_ref.map_or_else(|| json!({}), |r| json!({ "ref": r }));
        self.read(
            Request::new(Method::Post, format!("/deployments/{}/build", seg(id))).json(body),
            "deployment",
            id,
        )
        .await
    }

    pub async fn start_pull(&self, id: &str, artifact_ref: Option<&str>, force: bool) -> Result<JobRecord> {
        let mut body = json!({ "force": force });
        if let Some(r) = artifact_ref {
            body["ref"] = json!(r);
        }
        self.read(
            Request::new(Method::Post, format!("/deployments/{}/pull", seg(id))).json(body),
            "deployment",
            id,
        )
        .await
    }

    /// Unpack a managed deployment's guest mounts and roll the pool onto the
    /// trees. No reference override, unlike `start_pull`: one job covers every
    /// mount, so a single `ref` would have nothing to attach itself to.
    pub async fn start_mount_pull(&self, id: &str, force: bool) -> Result<JobRecord> {
        self.read(
            Request::new(Method::Post, format!("/deployments/{}/mounts/pull", seg(id)))
                .json(json!({ "force": force })),
            "deployment",
            id,
        )
        .await
    }

    pub async fn start_update(&self, id: &str) -> Result<JobRecord> {
        self.read(
            Request::new(Method::Post, format!("/deployments/{}/update", seg(id))).json(json!({})),
            "deployment",
            id,
        )
        .await
    }

    pub async fn jobs(&self) -> Result<Vec<JobRecord>> {
        self.read(Request::new(Method::Get, "/jobs"), "job", "")
            .await
    }

    pub async fn deployment_jobs(&self, id: &str) -> Result<Vec<JobRecord>> {
        self.read(
            Request::new(Method::Get, format!("/deployments/{}/jobs", seg(id))),
            "deployment",
            id,
        )
        .await
    }

    /// One job. A `404` here can mean it aged out of the bounded history rather
    /// than that it never existed.
    pub async fn job(&self, job_id: &str) -> Result<JobRecord> {
        self.read(
            Request::new(Method::Get, format!("/jobs/{}", seg(job_id))),
            "job",
            job_id,
        )
        .await
    }

    // -- observability ------------------------------------------------------

    /// `GET /metrics`, scoped by `query`.
    ///
    /// The unfiltered response is megabytes at fleet scale, so prefer
    /// [`MetricsQuery::summary`] and paging. Note `fleet`, `global` and `host`
    /// always describe everything the credential can see, never the page.
    pub async fn metrics(&self, query: &MetricsQuery) -> Result<MetricsResponse> {
        self.read(
            Request::new(Method::Get, format!("/metrics{}", query.to_query_string())),
            "server",
            "",
        )
        .await
    }

    pub async fn certs(&self) -> Result<Vec<CertStatus>> {
        self.read(Request::new(Method::Get, "/certs"), "certificate", "")
            .await
    }

    /// The host's disk inventory: what each sandbox occupies, whether anything
    /// still claims it, and what the expiry sweep would reclaim.
    ///
    /// One object rather than a bare list — the totals and the `complete` flag
    /// are the half that makes the list safe to act on, and dropping them here
    /// would leave the caller unable to tell "no orphans" from "the daemon did
    /// not answer, so nothing was classified".
    pub async fn disks(&self) -> Result<DiskInventory> {
        self.read(Request::new(Method::Get, "/disks"), "disk", "")
            .await
    }

    // -- plugins ------------------------------------------------------------

    /// Every built-in plugin, whether or not it is enabled.
    pub async fn plugins(&self) -> Result<Vec<PluginView>> {
        self.read(Request::new(Method::Get, "/api/plugins"), "plugin", "").await
    }

    pub async fn plugin(&self, id: &str) -> Result<PluginView> {
        self.read(Request::new(Method::Get, format!("/api/plugins/{}", seg(id))), "plugin", id)
            .await
    }

    /// Write a plugin's record. `config: None` keeps the stored configuration.
    ///
    /// Succeeds when the record was saved, even if applying it failed — check
    /// `last_error` on the result, which is how app-lb reports "enabled, but
    /// could not start".
    pub async fn set_plugin(&self, id: &str, enabled: bool, config: Option<&Value>) -> Result<PluginView> {
        let mut body = json!({ "enabled": enabled });
        if let Some(c) = config {
            body["config"] = c.clone();
        }
        self.read(
            Request::new(Method::Put, format!("/api/plugins/{}", seg(id))).json(body),
            "plugin",
            id,
        )
        .await
    }

    pub(crate) fn ws(&self) -> Option<&Arc<WsConfig>> {
        self.ws.as_ref()
    }

    /// The status a `GET` answers with, treating 4xx as an answer rather than an
    /// error.
    ///
    /// For probing: which gate is on, and whether a credential satisfies it.
    /// Every other method turns a non-2xx into an [`Error`], which is right for
    /// a request you meant and wrong for a question you are asking.
    pub async fn probe(&self, path: &str) -> Result<u16> {
        Ok(self.probe_detail(path).await?.0)
    }

    /// The status *and* whatever the server said about it.
    ///
    /// A refusal from app-lb names the actual reason — which token, which
    /// scope, which deployment it does not admit — and a caller that keeps only
    /// the status has to guess at all of it. `login` guessed wrong twice: a
    /// namespace-confined token was reported as an unrecognised one, and the
    /// operator went looking at the token instead of the gate.
    pub async fn probe_detail(&self, path: &str) -> Result<(u16, Option<String>)> {
        let r = self
            .transport
            .send(Request::new(Method::Get, path.to_string()))
            .await?;
        // `error` alone is often the useless half. app-lb's gate answers
        // `{"error":"authentication required","scope":"admin","detail":"…"}`,
        // where `detail` is the sentence that says what would actually work —
        // dropping it turns a diagnosis back into "authentication required".
        let detail = serde_json::from_str::<serde_json::Value>(&r.body)
            .ok()
            .and_then(|v| {
                let field = |k: &str| {
                    v.get(k)
                        .and_then(|x| x.as_str())
                        .map(str::trim)
                        .filter(|x| !x.is_empty())
                        .map(str::to_owned)
                };
                match (field("error"), field("detail")) {
                    (Some(e), Some(d)) => Some(format!("{e} — {d}")),
                    (Some(e), None) => Some(e),
                    (None, Some(d)) => Some(d),
                    (None, None) => None,
                }
            });
        Ok((r.status, detail))
    }

    /// The base URL, when this client was built from one.
    pub fn server(&self) -> Option<&str> {
        self.ws.as_ref().map(|w| w.base.as_str())
    }

    /// Whether any credential is being presented.
    pub fn has_credentials(&self) -> bool {
        self.transport.credential() != crate::error::Credential::None
    }

    /// The same reads, as unparsed JSON.
    ///
    /// Two callers need this and neither is being lazy:
    ///
    /// - anything that **prints** a response. Re-serializing one of the typed
    ///   views would drop whatever this build does not name, so
    ///   `heyctl get … -o json` would quietly print less than the server
    ///   sent.
    /// - the read half of a read-modify-write. `PUT /deployments/:id` replaces
    ///   the whole spec, so the thing you edit has to be the thing that came
    ///   back — see the module docs.
    pub fn raw(&self) -> Raw<'_> {
        Raw(self)
    }
}

/// Unparsed reads. See [`Client::raw`].
#[derive(Debug, Clone, Copy)]
pub struct Raw<'a>(pub(crate) &'a Client);

/// A collection route: no id, fixed path.
macro_rules! raw_list {
    ($($name:ident => $kind:literal, $path:literal;)*) => {
        $(
            pub async fn $name(&self) -> Result<Value> {
                self.0.read(Request::new(Method::Get, $path), $kind, "").await
            }
        )*
    };
}

/// An item route: the id goes into the path, percent-encoded.
macro_rules! raw_item {
    ($($name:ident => $kind:literal, $fmt:literal;)*) => {
        $(
            pub async fn $name(&self, id: &str) -> Result<Value> {
                self.0
                    .read(Request::new(Method::Get, format!($fmt, seg(id))), $kind, id)
                    .await
            }
        )*
    };
}

impl Raw<'_> {
    raw_list! {
        deployments => "deployment", "/deployments";
        secrets     => "secret",     "/secrets";
        tokens      => "token",      "/tokens";
        jobs        => "job",        "/jobs";
        certs       => "certificate", "/certs";
        workflows   => "workflow",   "/workflows";
        feeds       => "feed",       "/feeds";
        namespaces  => "namespace",  "/namespaces";
        disks       => "disk",       "/disks";
        plugins     => "plugin",     "/api/plugins";
    }

    /// Deployments in one namespace, as app-lb sent them.
    ///
    /// A separate method rather than an argument on `deployments()` because the
    /// unfiltered listing is the overwhelmingly common call and threading an
    /// `Option` through the `raw_list!` macro for it would cost every other
    /// resource a parameter none of them have.
    pub async fn deployments_in(&self, namespace: &str) -> Result<Value> {
        self.0
            .read(
                Request::new(Method::Get, format!("/deployments?namespace={}", seg(namespace))),
                "deployment",
                "",
            )
            .await
    }

    /// The secrets of one namespace as app-lb sent them.
    pub async fn secrets_in(&self, namespace: Option<&str>) -> Result<Value> {
        let path = match namespace {
            Some(ns) => format!("/secrets?namespace={}", seg(ns)),
            None => "/secrets".to_string(),
        };
        self.0.read(Request::new(Method::Get, path), "secret", "").await
    }

    /// One secret as app-lb sent it, looked up in `namespace`.
    pub async fn secret_in(&self, namespace: Option<&str>, id: &str) -> Result<Value> {
        self.0
            .read(
                Request::new(Method::Get, secret_path(namespace, id, None)),
                "secret",
                id,
            )
            .await
    }

    /// The auth providers as app-lb sent them, fleet-wide or for one namespace.
    pub async fn auth_providers(&self, namespace: Option<&str>) -> Result<Value> {
        let path = match namespace {
            Some(ns) => format!("/auth-providers?namespace={}", seg(ns)),
            None => "/auth-providers".to_string(),
        };
        self.0
            .read(Request::new(Method::Get, path), "auth provider", "")
            .await
    }

    /// One auth provider as app-lb sent it.
    pub async fn auth_provider(&self, namespace: &str, name: &str) -> Result<Value> {
        self.0
            .read(
                Request::new(
                    Method::Get,
                    format!("/auth-providers/{}/{}", seg(namespace), seg(name)),
                ),
                "auth provider",
                name,
            )
            .await
    }

    /// A namespace's feed events as app-lb sent them.
    pub async fn feed_events(&self, namespace: &str) -> Result<Value> {
        self.0
            .read(
                Request::new(Method::Get, format!("/feeds/{}?format=json", seg(namespace))),
                "feed",
                namespace,
            )
            .await
    }

    raw_item! {
        deployment      => "deployment", "/deployments/{}";
        secret          => "secret",     "/secrets/{}";
        token           => "token",      "/tokens/{}";
        job             => "job",        "/jobs/{}";
        deployment_jobs => "deployment", "/deployments/{}/jobs";
        workflow        => "workflow",   "/workflows/{}";
    }

    pub async fn metrics(&self, query: &MetricsQuery) -> Result<Value> {
        self.0
            .read(
                Request::new(Method::Get, format!("/metrics{}", query.to_query_string())),
                "server",
                "",
            )
            .await
    }

    // The write side, for the same reason: a caller that prints what a write
    // returned should print what the server said, not a re-serialization of a
    // struct that may know fewer fields than the server sent.

    pub async fn create_deployment(&self, spec: &Value) -> Result<Value> {
        let id = spec.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
        self.0
            .read(
                Request::new(Method::Post, "/deployments").json(spec.clone()),
                "deployment",
                &id,
            )
            .await
    }

    pub async fn replace_deployment(&self, id: &str, spec: &Value) -> Result<Value> {
        self.0
            .read(
                Request::new(Method::Put, format!("/deployments/{}", seg(id))).json(spec.clone()),
                "deployment",
                id,
            )
            .await
    }

    pub async fn patch_scaling(&self, id: &str, patch: &Value) -> Result<Value> {
        self.0
            .read(
                Request::new(Method::Patch, format!("/deployments/{}/scaling", seg(id)))
                    .json(patch.clone()),
                "deployment",
                id,
            )
            .await
    }

    pub async fn put_secret(&self, spec: &Value) -> Result<Value> {
        let id = spec.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
        self.0
            .read(
                Request::new(Method::Post, "/secrets").json(spec.clone()),
                "secret",
                &id,
            )
            .await
    }

    /// Patch a secret in `namespace`. See [`Client::patch_secret_in`].
    pub async fn patch_secret_in(
        &self,
        namespace: Option<&str>,
        id: &str,
        patch: &Value,
    ) -> Result<Value> {
        self.0
            .read(
                Request::new(Method::Patch, secret_path(namespace, id, None)).json(patch.clone()),
                "secret",
                id,
            )
            .await
    }

    pub async fn patch_secret(&self, id: &str, patch: &Value) -> Result<Value> {
        self.0
            .read(
                Request::new(Method::Patch, format!("/secrets/{}", seg(id))).json(patch.clone()),
                "secret",
                id,
            )
            .await
    }

    pub async fn mint_token(&self, req: &NewToken) -> Result<Value> {
        let body = json!({
            "name": req.name,
            "admin": req.admin,
            "namespace": req.namespace,
            "deployments": req.deployments,
            "expires_in_secs": req.expires_in_secs,
            "fleet": req.all_servers,
        });
        self.0
            .read(
                Request::new(Method::Post, "/tokens").json(body),
                "token",
                &req.name,
            )
            .await
    }

    pub async fn patch_token(&self, id: &str, patch: &Value) -> Result<Value> {
        self.0
            .read(
                Request::new(Method::Patch, format!("/tokens/{}", seg(id))).json(patch.clone()),
                "token",
                id,
            )
            .await
    }

    pub async fn evict_vm(&self, id: &str, sandbox: &str, force: bool) -> Result<Value> {
        self.0
            .read(
                Request::new(
                    Method::Delete,
                    format!(
                        "/deployments/{}/vms/{}?force={}",
                        seg(id),
                        seg(sandbox),
                        if force { "true" } else { "false" }
                    ),
                ),
                "vm",
                sandbox,
            )
            .await
    }

    pub async fn cordon_upstream(
        &self,
        id: &str,
        upstream: &str,
        force: bool,
        reason: Option<&str>,
    ) -> Result<Value> {
        let mut body = json!({ "force": force });
        if let Some(reason) = reason {
            body["reason"] = json!(reason);
        }
        self.0
            .read(
                Request::new(
                    Method::Put,
                    format!(
                        "/deployments/{}/upstreams/{}/drain",
                        seg(id),
                        seg(upstream),
                    ),
                )
                .json(body),
                "upstream",
                upstream,
            )
            .await
    }

    pub async fn uncordon_upstream(&self, id: &str, upstream: &str) -> Result<Value> {
        self.0
            .read(
                Request::new(
                    Method::Delete,
                    format!(
                        "/deployments/{}/upstreams/{}/drain",
                        seg(id),
                        seg(upstream),
                    ),
                ),
                "upstream",
                upstream,
            )
            .await
    }

    pub async fn start_build(&self, id: &str, git_ref: Option<&str>) -> Result<Value> {
        let body = git_ref.map_or_else(|| json!({}), |r| json!({ "ref": r }));
        self.0
            .read(
                Request::new(Method::Post, format!("/deployments/{}/build", seg(id))).json(body),
                "deployment",
                id,
            )
            .await
    }

    pub async fn start_pull(&self, id: &str, artifact_ref: Option<&str>, force: bool) -> Result<Value> {
        let mut body = json!({ "force": force });
        if let Some(r) = artifact_ref {
            body["ref"] = json!(r);
        }
        self.0
            .read(
                Request::new(Method::Post, format!("/deployments/{}/pull", seg(id))).json(body),
                "deployment",
                id,
            )
            .await
    }

    pub async fn start_mount_pull(&self, id: &str, force: bool) -> Result<Value> {
        self.0
            .read(
                Request::new(Method::Post, format!("/deployments/{}/mounts/pull", seg(id)))
                    .json(json!({ "force": force })),
                "deployment",
                id,
            )
            .await
    }

    pub async fn start_update(&self, id: &str) -> Result<Value> {
        self.0
            .read(
                Request::new(Method::Post, format!("/deployments/{}/update", seg(id)))
                    .json(json!({})),
                "deployment",
                id,
            )
            .await
    }

    /// A deployment's spec alone, ready to edit and hand back to
    /// [`Client::replace_deployment`].
    pub async fn spec(&self, id: &str) -> Result<Value> {
        let status = self.deployment(id).await?;
        status
            .get("spec")
            .cloned()
            .ok_or_else(|| Error::Decode(serde::de::Error::custom("the response had no `spec`")))
    }
}

pub struct ClientBuilder {
    server: String,
    auth: Auth,
    timeout: Duration,
    insecure: bool,
}

impl ClientBuilder {
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }

    /// Authenticate with an app-token. The normal choice for a program.
    pub fn token(self, token: impl Into<String>) -> Self {
        self.auth(Auth::Token(token.into()))
    }

    /// Authenticate with the operator credential.
    pub fn basic(self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth(Auth::Basic {
            user: user.into(),
            password: password.into(),
        })
    }

    /// Per-request deadline. `exec` computes its own, larger, one.
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    /// Skip TLS verification. For a self-signed admin listener behind a tunnel.
    pub fn insecure(mut self, yes: bool) -> Self {
        self.insecure = yes;
        self
    }

    pub fn build(self) -> Result<Client> {
        let base = crate::transport::normalize_base(&self.server);
        let transport = HttpTransport::new(
            base.clone(),
            self.auth.clone(),
            self.timeout,
            self.insecure,
        )?;
        Ok(Client {
            transport: Arc::new(transport),
            ws: Some(Arc::new(WsConfig {
                base,
                auth: self.auth,
                insecure: self.insecure,
            })),
        })
    }
}

/// A command to run in a VM.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    /// Run through `sh -c` in the guest.
    pub command: String,
    pub cwd: Option<String>,
    pub env: Option<std::collections::BTreeMap<String, String>>,
    /// Bounds app-lb's call to the daemon. Clamped server-side to `1..=3600`.
    pub timeout_secs: Option<u64>,
    /// Boot or resume a VM if none is running. On by default: a sandbox that
    /// scaled to zero should still answer. `false` asks for
    /// [`Error::NoRunningVm`] instead of a wait.
    pub wake: bool,
    /// Override the client-side deadline. See [`ExecRequest::patience`].
    pub patience: Option<Duration>,
}

impl ExecRequest {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            cwd: None,
            env: None,
            timeout_secs: None,
            wake: true,
            patience: None,
        }
    }

    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env
            .get_or_insert_with(Default::default)
            .insert(key.into(), value.into());
        self
    }

    pub fn timeout_secs(mut self, s: u64) -> Self {
        self.timeout_secs = Some(s);
        self
    }

    /// Ask for [`Error::NoRunningVm`] rather than waiting on a cold start.
    pub fn no_wake(mut self) -> Self {
        self.wake = false;
        self
    }

    /// How long the *client* waits, overriding the computed default.
    pub fn patient_for(mut self, d: Duration) -> Self {
        self.patience = Some(d);
        self
    }

    /// The client-side deadline.
    ///
    /// Must exceed what the server might take, or the client abandons a request
    /// app-lb is still serving and the caller gets a transport error instead of
    /// an answer. The server's worst case is the command timeout **plus** a cold
    /// start when `wake` is set — a deployment's actual
    /// `cold_start_timeout_secs` is not knowable without another round trip, so
    /// this assumes app-lb's default. Override on a deployment configured
    /// higher.
    pub fn patience(&self) -> Duration {
        if let Some(d) = self.patience {
            return d;
        }
        let command = self.timeout_secs.unwrap_or(60).clamp(1, 3600);
        let cold = if self.wake { ASSUMED_COLD_START_SECS } else { 0 };
        Duration::from_secs(command + cold + EXEC_MARGIN_SECS)
    }
}

/// What to ask `/metrics` for.
#[derive(Debug, Clone, Default)]
pub struct MetricsQuery {
    /// Exactly one deployment.
    pub deployment: Option<String>,
    /// Every deployment whose id starts with this.
    pub prefix: Option<String>,
    /// Drop per-VM detail, which is most of the payload.
    pub summary: bool,
    pub limit: Option<usize>,
    pub offset: usize,
}

impl MetricsQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn deployment(mut self, id: impl Into<String>) -> Self {
        self.deployment = Some(id.into());
        self
    }

    pub fn prefix(mut self, p: impl Into<String>) -> Self {
        self.prefix = Some(p.into());
        self
    }

    pub fn summary(mut self, yes: bool) -> Self {
        self.summary = yes;
        self
    }

    pub fn page(mut self, offset: usize, limit: usize) -> Self {
        self.offset = offset;
        self.limit = Some(limit);
        self
    }

    fn to_query_string(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(d) = &self.deployment {
            parts.push(format!("deployment={}", seg(d)));
        }
        if let Some(p) = &self.prefix {
            parts.push(format!("prefix={}", seg(p)));
        }
        if self.summary {
            // Only `true`/`false` parse server-side.
            parts.push("summary=true".into());
        }
        if let Some(l) = self.limit {
            parts.push(format!("limit={l}"));
        }
        if self.offset > 0 {
            parts.push(format!("offset={}", self.offset));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("?{}", parts.join("&"))
        }
    }
}

/// A token to mint.
///
/// Both scope fields default to nothing: a token minted with no scope can do
/// nothing, which is a harmless mistake. The other default would turn a
/// forgotten field into fleet-wide credentials.
#[derive(Debug, Clone, Default)]
pub struct NewToken {
    pub name: String,
    pub admin: AdminScope,
    pub namespace: Option<String>,
    pub deployments: Vec<String>,
    pub expires_in_secs: Option<u64>,
    /// Valid on every server of the fleet. See [`NewToken::on_all_servers`].
    pub all_servers: bool,
}

impl NewToken {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn admin(mut self, scope: AdminScope) -> Self {
        self.admin = scope;
        self
    }

    /// Scope to specific deployments. Such a token is refused the fleet-wide
    /// routes, including minting — so it cannot widen itself.
    pub fn for_deployments<I, S>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.deployments = ids.into_iter().map(Into::into).collect();
        self
    }

    /// Scope to every deployment.
    pub fn fleet_wide(mut self) -> Self {
        self.deployments = vec!["*".into()];
        self
    }

    /// Confine the token to one namespace. With no `deployments` list this
    /// reaches every deployment in the namespace, now and in the future — and
    /// nothing outside it, ever.
    pub fn in_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    pub fn expires_in(mut self, d: Duration) -> Self {
        self.expires_in_secs = Some(d.as_secs());
        self
    }

    /// Valid on every server that mirrors this control plane's tokens, not
    /// only the one minting it. Sent as `fleet: true`; only a control-plane
    /// app-lb (one with gateways configured) accepts it.
    pub fn on_all_servers(mut self) -> Self {
        self.all_servers = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::stub::Stub;

    fn client(stub: Stub) -> (Client, Arc<Stub>) {
        let s = Arc::new(stub);
        (Client::with_transport(s.clone()), s)
    }

    #[tokio::test]
    async fn a_read_is_typed_and_a_write_is_not() {
        let (c, stub) = client(Stub::new().json(
            201,
            json!({"spec": {"id": "demo", "routes": [], "unknown_future_field": 7},
                   "kind": "vm", "desired_replicas": 1, "ready": 0, "pending": 1,
                   "total_in_flight": 0, "vms": []}),
        ));
        let spec = json!({"id": "demo", "routes": [], "unknown_future_field": 7});
        let got = c.create_deployment(&spec).await.unwrap();
        assert_eq!(got.kind, "vm");

        // The body went out verbatim — a field this build has never heard of is
        // not something a client gets to drop.
        assert_eq!(stub.calls()[0].body.as_ref().unwrap(), &spec);
    }

    #[tokio::test]
    async fn a_failed_request_becomes_a_typed_error() {
        let (c, _) = client(Stub::new().json(404, json!({"error": "no deployment \"demo\""})));
        let e = c.deployment("demo").await.unwrap_err();
        assert!(matches!(&e, Error::NotFound { kind: "deployment", name } if name == "demo"));
    }

    #[tokio::test]
    async fn absence_is_a_bool_not_an_error_where_that_is_the_question() {
        let (c, _) = client(Stub::new().json(404, json!({"error": "no deployment \"demo\""})));
        assert!(!c.deployment_exists("demo").await.unwrap());

        // But a *real* failure still propagates rather than reading as absence.
        let (c, _) = client(Stub::new().reply(401, "authentication required\n"));
        assert!(c.deployment_exists("demo").await.is_err());
    }

    #[tokio::test]
    async fn a_nonzero_exit_is_not_an_error() {
        let (c, _) = client(Stub::new().json(
            200,
            json!({"sandbox_id": "sb-1", "exit_code": 42, "stdout": "", "stderr": "nope\n",
                   "output": "nope\n"}),
        ));
        let out = c.exec("demo", &ExecRequest::new("false")).await.unwrap();
        assert_eq!(out.exit_code, 42);
        assert!(!out.ok());
    }

    #[tokio::test]
    async fn a_blank_command_never_reaches_the_wire() {
        let (c, stub) = client(Stub::new());
        let e = c.exec("demo", &ExecRequest::new("   ")).await.unwrap_err();
        assert!(matches!(e, Error::Invalid(_)));
        assert_eq!(stub.call_count(), 0, "nothing should have been sent");
    }

    /// The CLI this replaces waited `timeout + 30s`, which is shorter than the
    /// server's own worst case whenever a cold start is possible — so it
    /// abandoned requests app-lb was still serving.
    #[test]
    fn the_exec_deadline_outlasts_the_servers_worst_case() {
        let waking = ExecRequest::new("x").timeout_secs(60);
        assert!(
            waking.patience() > Duration::from_secs(60 + ASSUMED_COLD_START_SECS),
            "a waking exec must outlast command timeout + cold start"
        );

        // With no wake there is no boot to wait through.
        let not_waking = ExecRequest::new("x").timeout_secs(60).no_wake();
        assert!(not_waking.patience() < waking.patience());
        assert!(not_waking.patience() > Duration::from_secs(60));

        // The server clamps its own timeout to 3600; the client must still
        // outlast that rather than trusting the number it was handed.
        let absurd = ExecRequest::new("x").timeout_secs(99_999).no_wake();
        assert!(absurd.patience() > Duration::from_secs(3600));

        assert_eq!(
            ExecRequest::new("x").patient_for(Duration::from_secs(5)).patience(),
            Duration::from_secs(5),
            "an explicit override wins"
        );
    }

    #[tokio::test]
    async fn query_booleans_are_spelled_the_only_way_app_lb_accepts() {
        // `?force=1` is a 400 server-side, not a truthy value.
        let (c, stub) = client(Stub::new().json(200, json!({"sandbox_id": "s", "outcome": "killed"})));
        c.evict_vm("demo", "sb-1", true).await.unwrap();
        assert!(stub.calls()[0].path.ends_with("?force=true"), "{:?}", stub.calls()[0].path);

        let (c, stub) = client(Stub::new().json(200, json!({"sandbox_id": "s", "outcome": "killed"})));
        c.evict_vm("demo", "sb-1", false).await.unwrap();
        assert!(stub.calls()[0].path.ends_with("?force=false"));
    }

    #[tokio::test]
    async fn ids_are_escaped_into_the_path() {
        let (c, stub) = client(Stub::new().json(404, json!({"error": "no deployment"})));
        let _ = c.deployment("a/b?c=d").await;
        assert_eq!(stub.calls()[0].path, "/deployments/a%2Fb%3Fc%3Dd");
    }

    /// app-lb takes these as `Option<Json<T>>`, and axum turns *any* extractor
    /// rejection on an `Option` into the default — so a build started with no
    /// content-type silently loses its `ref` instead of failing.
    #[tokio::test]
    async fn build_and_pull_always_send_a_json_body() {
        let (c, stub) = client(Stub::new().json(202, json!({"id": "j1", "deployment": "d",
            "kind": "image-build", "status": "running", "started_at": 0})));
        c.start_build("demo", None).await.unwrap();
        assert_eq!(stub.calls()[0].body, Some(json!({})));

        let (c, stub) = client(Stub::new().json(202, json!({"id": "j1", "deployment": "d",
            "kind": "image-build", "status": "running", "started_at": 0})));
        c.start_build("demo", Some("v2")).await.unwrap();
        assert_eq!(stub.calls()[0].body, Some(json!({"ref": "v2"})));
    }

    #[test]
    fn a_metrics_query_serializes_only_what_was_asked_for() {
        assert_eq!(MetricsQuery::new().to_query_string(), "");
        assert_eq!(
            MetricsQuery::new().deployment("sb-1").to_query_string(),
            "?deployment=sb-1"
        );
        assert_eq!(
            MetricsQuery::new().summary(true).page(20, 10).to_query_string(),
            "?summary=true&limit=10&offset=20"
        );
        // offset 0 is the default and adds nothing.
        assert_eq!(
            MetricsQuery::new().page(0, 10).to_query_string(),
            "?limit=10"
        );
    }

    #[tokio::test]
    async fn minting_requires_a_name_before_anything_is_sent() {
        let (c, stub) = client(Stub::new());
        let e = c.mint_token(&NewToken::new("  ")).await.unwrap_err();
        assert!(matches!(e, Error::Invalid(_)));
        assert_eq!(stub.call_count(), 0);
    }

    #[tokio::test]
    async fn a_minted_token_carries_its_secret_exactly_once() {
        let (c, stub) = client(Stub::new().json(
            201,
            json!({"id": "abc", "name": "ci", "admin": "admin", "deployments": ["*"],
                   "created_at": 1, "token": "applb_abc_secret"}),
        ));
        let t = c
            .mint_token(&NewToken::new("ci").admin(AdminScope::Admin).fleet_wide())
            .await
            .unwrap();
        assert_eq!(t.token, "applb_abc_secret");
        assert_eq!(t.summary.id, "abc");
        assert_eq!(
            stub.calls()[0].body,
            Some(json!({"name": "ci", "admin": "admin", "deployments": ["*"]}))
        );
    }

    #[tokio::test]
    async fn a_scoped_mint_does_not_quietly_become_fleet_wide() {
        let (c, stub) = client(Stub::new().json(
            201,
            json!({"id": "abc", "name": "a", "admin": "none", "deployments": ["sb-1"],
                   "created_at": 1, "token": "applb_abc_s"}),
        ));
        c.mint_token(&NewToken::new("a").for_deployments(["sb-1"]))
            .await
            .unwrap();
        let body = stub.calls()[0].body.clone().unwrap();
        assert_eq!(body["deployments"], json!(["sb-1"]));
        assert_eq!(body["admin"], json!("none"), "the safe default, not admin");
    }

    #[tokio::test]
    async fn gates_are_discovered_from_what_an_anonymous_caller_is_refused() {
        // Not reachable through the stub (it builds its own client), so this
        // pins the shape of the decision instead.
        let refused = Error::from_response(
            401,
            "authentication required\n",
            "server",
            "",
            crate::error::Credential::None,
        );
        assert!(matches!(refused, Error::Unauthorized { .. }));
    }
}
