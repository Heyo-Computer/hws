//! Read-side views of the admin API's JSON.
//!
//! Deliberately lenient: every field defaults, so a client a version behind the
//! app-lb it is talking to still renders what it understands instead of failing
//! to parse. Writes go through `serde_json::Value` so nothing is dropped on a
//! round trip — see [`crate::api`].
//!
//! # `extra`, and why leniency needed a counterweight
//!
//! Leniency alone is how these types silently fell behind: to a defaulting
//! deserializer an unknown field and an absent one are the same thing, so
//! `DeploymentView::urls`, `PoolStatus::boot_timeout_secs`,
//! `MetricsResponse::matched` and two more went missing without a single test
//! failing.
//!
//! Every response type therefore carries a `#[serde(flatten)] extra` map. It
//! keeps the leniency — an unknown field parses fine, and is *reachable* rather
//! than discarded — and it makes the gap visible: the tests in
//! `tests/wire_contract.rs` read `testdata/wire/*.json`, written by app-lb's own
//! response types, and assert `extra` is empty. A field this crate stops
//! understanding fails a test instead of blanking a column.

use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// Fields the server sent that this build has no name for.
///
/// Empty in a matched pair of versions. Non-empty means app-lb is ahead, and
/// what is in here is exactly what this crate is not yet reading.
pub type Extra = serde_json::Map<String, Value>;

// -- GET /deployments, GET /deployments/:id --------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DeploymentStatus {
    pub rollout_revision: String,
    pub spec: DeploymentSpec,
    /// `"vm"` (managed pool), `"static"` (fixed proxy_pass upstreams) or
    /// `"site"` (files served off disk).
    pub kind: String,
    pub desired_replicas: u32,
    pub ready: usize,
    pub pending: usize,
    pub total_in_flight: usize,
    pub vms: Vec<VmStatus>,
    /// Present when the spec declares `vm.workspace`.
    pub workspace: Option<WorkspaceStatus>,
    /// Present for a site: whether its root on the LB host can serve.
    pub site: Option<SiteRootStatus>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// A site's root as the LB host sees it.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct SiteRootStatus {
    pub root: String,
    /// `ok`, `missing`, `not_a_directory`, `unreadable` or `empty`.
    pub status: String,
    pub index_present: Option<bool>,
    /// Why it cannot serve, and how to fill it.
    pub hint: Option<String>,
}

/// `vm.workspace`, mirrored read-only like [`MountSpec`].
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct WorkspaceSpec {
    /// Defaults to `/workspace` server-side.
    pub path: Option<String>,
    pub store: String,
    #[serde(rename = "ref")]
    pub artifact_ref: Option<String>,
    pub auth: Option<SecretRef>,
    /// Recycle the replica for a snapshot at least this often. Unset: only
    /// when it retires for another reason.
    pub snapshot_interval_secs: Option<u64>,
}

/// Where a deployment's workspace stands: the snapshot its pool runs from,
/// whether the store has it, and what is holding the pool if anything is.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct WorkspaceStatus {
    pub path: String,
    pub store: String,
    pub digest: Option<String>,
    pub captured_at: Option<u64>,
    pub captured_from: Option<String>,
    pub files: u64,
    pub bytes: u64,
    pub pushed: Option<String>,
    pub pushed_at: Option<u64>,
    pub push_pending: bool,
    /// `idle`, `restoring`, `capturing`, `pushing` or `blocked`.
    pub phase: String,
    pub blocked: Option<String>,
    pub pending: Vec<PendingCapture>,
    pub last_error: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct PendingCapture {
    pub sandbox_id: String,
    pub then: String,
    pub queued_at: u64,
    pub attempts: u32,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct VmStatus {
    pub sandbox_id: String,
    pub addr: String,
    pub in_flight: usize,
    pub healthy: bool,
    pub draining: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

impl VmStatus {
    /// The single-word status column, in precedence order: a draining VM is
    /// still serving, so that fact outranks its health.
    pub fn status(&self) -> &'static str {
        if self.draining {
            "Draining"
        } else if self.healthy {
            "Ready"
        } else {
            "NotReady"
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DeploymentSpec {
    pub id: String,
    /// The namespace wall this deployment sits behind. Omitted on the wire when
    /// it is `default` — a single-tenant app-lb's specs look exactly as they did
    /// before namespaces — so read it through
    /// [`namespace()`](DeploymentSpec::namespace) rather than directly.
    pub namespace: String,
    /// The heyo account this deployment's VMs are metered to, and the user
    /// who registered it. Set by the managed service; absent on a
    /// self-hosted app-lb.
    pub account_id: Option<String>,
    pub user_id: Option<String>,
    pub routes: Vec<RouteRule>,
    pub maintenance: bool,
    pub vm: Option<VmSpec>,
    pub scaling: ScalingPolicy,
    pub health: HealthCheck,
    pub upstreams: Vec<String>,
    pub discovery: Option<DiscoverySpec>,
    pub build: Option<BuildSpec>,
    pub artifact: Option<ArtifactSpec>,
    pub update: Option<UpdateSpec>,
    pub auth: Option<AuthGate>,
    pub site: Option<SiteSpec>,
}

impl DeploymentSpec {
    /// The namespace this deployment is in, filling in the default the server
    /// omits.
    pub fn namespace(&self) -> &str {
        if self.namespace.is_empty() {
            crate::DEFAULT_NAMESPACE
        } else {
            &self.namespace
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DiscoverySpec {
    pub service_id: String,
}

/// A static site: a directory on the app-lb host, served straight off disk.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SiteSpec {
    pub root: String,
    pub index: String,
    pub not_found: Option<String>,
    pub spa: bool,
    pub cache_control: String,
}

impl DeploymentSpec {
    /// Forwards to fixed upstreams. **Not** true for a site, which has no
    /// backends of any kind.
    pub fn is_static(&self) -> bool {
        !self.upstreams.is_empty() || self.discovery.is_some()
    }

    /// Serves files off disk rather than proxying anywhere.
    pub fn is_site(&self) -> bool {
        self.site.is_some()
    }

    /// The routes as one column: `secrets.local`, `*.apps.example.com/api`, …
    pub fn routes_summary(&self) -> String {
        if self.routes.is_empty() {
            return "<none>".into();
        }
        let shown: Vec<String> = self.routes.iter().take(3).map(RouteRule::render).collect();
        let extra = self.routes.len().saturating_sub(shown.len());
        if extra > 0 {
            format!("{} +{extra} more", shown.join(","))
        } else {
            shown.join(",")
        }
    }

    /// What traffic actually lands on: the image for a managed pool, the
    /// upstream list for a static one, the directory for a site.
    pub fn backend_summary(&self) -> String {
        if let Some(site) = &self.site {
            return site.root.clone();
        }
        if self.is_static() {
            if let Some(discovery) = &self.discovery {
                let upstreams = self.upstreams.join(",");
                return if upstreams.is_empty() {
                    format!("discovery:{}", discovery.service_id)
                } else {
                    format!("discovery:{} ({upstreams})", discovery.service_id)
                };
            }
            return self.upstreams.join(",");
        }
        match &self.vm {
            Some(vm) => {
                let image = vm.image.as_deref().unwrap_or("ubuntu:24.04 (default)");
                format!("{image}:{}", vm.port)
            }
            None => "<none>".into(),
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct RouteRule {
    pub host: Option<String>,
    pub host_suffix: Option<String>,
    pub path_prefix: Option<String>,
    pub strip_prefix: bool,
}

impl RouteRule {
    /// One rule as a single token. A `host_suffix` is shown with the `*.` that
    /// its semantics imply (apex *and* any subdomain).
    pub fn render(&self) -> String {
        let mut s = String::new();
        if let Some(h) = &self.host {
            s.push_str(h);
        }
        if let Some(suffix) = &self.host_suffix {
            if !s.is_empty() {
                s.push('+');
            }
            s.push_str("*.");
            s.push_str(suffix.trim_start_matches('.'));
        }
        if let Some(p) = &self.path_prefix {
            if s.is_empty() {
                s.push('*');
            }
            s.push_str(p);
        }
        if s.is_empty() { "<empty>".into() } else { s }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct VmSpec {
    pub driver: String,
    pub image: Option<String>,
    pub port: u16,
    pub start_command: Option<String>,
    pub size_class: Option<String>,
    pub disk_size_gb: Option<u32>,
    pub working_directory: Option<String>,
    pub env_vars: Option<BTreeMap<String, String>>,
    pub setup_hooks: Option<Vec<String>>,
    pub open_ports: Vec<u16>,
    /// Directories the guests boot with, unpacked from tarballs in an artifact
    /// store. Empty on a deployment that declares none.
    pub mounts: Vec<MountSpec>,
    /// A writable directory owned by the deployment, captured when a replica
    /// retires and seeded into the next. See the server's `WorkspaceSpec`.
    pub workspace: Option<WorkspaceSpec>,
    pub ttl_seconds: u64,
}

/// One directory handed to every replica, unpacked from a tarball in an artifact
/// store.
///
/// Read-only here, like every other spec mirror in this file: `heyctl apply`
/// sends the file the user wrote rather than a reserialization of this struct,
/// so a field this build has no name for still reaches the server intact.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct MountSpec {
    /// Where it appears inside the guest.
    pub path: String,
    pub store: String,
    #[serde(rename = "ref")]
    pub artifact_ref: String,
    pub auth: Option<SecretRef>,
    pub strip_components: Option<usize>,
    /// Defaults to true server-side; a spec that omits it is read-only.
    pub read_only: bool,
    /// What `ref` resolved to on the last pull. `None` means nothing has been
    /// pulled yet — and a deployment whose mounts have no digest has no pool
    /// either, because the autoscaler will not boot a guest without its data.
    pub digest: Option<String>,
}

impl MountSpec {
    /// One line: `/data/corpus <- 127.0.0.1:8080/corpus-2026-08 (ro)`.
    ///
    /// The store is trimmed the same way [`ArtifactSpec::summary`] trims it, so
    /// the two read alike when a deployment has both.
    pub fn summary(&self) -> String {
        let store = self
            .store
            .trim_end_matches('/')
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        format!(
            "{} <- {store}/{} ({})",
            self.path,
            self.artifact_ref,
            if self.read_only { "ro" } else { "rw" },
        )
    }
}

/// Where a managed deployment's image is built from: a git checkout, or a
/// Dockerfile manifest in an artifact store. Exactly one of `repo` and `store`
/// is set.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct BuildSpec {
    /// Empty when the recipe comes from `store`. A `String` rather than an
    /// `Option` because `#[serde(default)]` already renders an absent field
    /// empty, and every read of it on this side is a display.
    pub repo: String,
    /// Empty when the recipe comes from `repo`.
    pub store: String,
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
    pub dockerfile: Option<String>,
    pub context: Option<String>,
    pub image_name: Option<String>,
    pub image_size_mb: Option<u64>,
    pub auth: Option<SecretRef>,
}

impl BuildSpec {
    /// One column: `github.com/acme/web@main`, or `art:8080/web-rootfs` when the
    /// recipe comes out of a store.
    ///
    /// The store form deliberately reads like [`ArtifactSpec::summary`] rather
    /// than like the git form: the two share the SOURCE column, and what a
    /// reader scanning a fleet wants from it is *where this came from*. Which
    /// column it appears in already says whether it is built or pulled.
    pub fn summary(&self) -> String {
        if !self.store.is_empty() {
            let store = self
                .store
                .trim_end_matches('/')
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            return match &self.git_ref {
                Some(r) => format!("{store}/{r}"),
                // Refused by the server, so only reachable from a hand-edited
                // state file. Rendered rather than panicked on: a listing is how
                // somebody would find that out.
                None => format!("{store}/(no ref)"),
            };
        }
        let repo = self
            .repo
            .trim_end_matches(".git")
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_start_matches("ssh://");
        match &self.git_ref {
            Some(r) => format!("{repo}@{r}"),
            None => format!("{repo}@(default branch)"),
        }
    }
}

/// Where a managed deployment's image is pulled from. The other image source,
/// and mutually exclusive with [`BuildSpec`].
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ArtifactSpec {
    pub store: String,
    #[serde(rename = "ref")]
    pub artifact_ref: String,
    pub image_name: Option<String>,
    pub grow_gb: Option<u64>,
    pub auth: Option<SecretRef>,
    /// Site bundles only: leading path components to drop while unpacking.
    pub strip_components: Option<usize>,
}

impl ArtifactSpec {
    /// One column: `10.0.0.4:8080/web-v2`. Shaped like [`BuildSpec::summary`] on
    /// purpose — the two share the SOURCE column, and a reader scanning a fleet
    /// should be able to tell a repo from a store at a glance without the
    /// column changing format underneath them.
    pub fn summary(&self) -> String {
        let store = self
            .store
            .trim_end_matches('/')
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        format!("{store}/{}", self.artifact_ref)
    }
}

/// What one guest mount's pull did.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct MountOutcome {
    /// The guest path, which is the mount's identity within the deployment.
    pub path: String,
    pub store: String,
    #[serde(rename = "ref")]
    pub artifact_ref: String,
    pub digest: Option<String>,
    /// The tree on this host the guests mount.
    pub tree: Option<String>,
    pub files: Option<usize>,
    /// Bytes transferred from the store. `0` with `reused` means the tree was
    /// already on the host.
    pub bytes: Option<u64>,
    /// Uncompressed size of the tree — what this mount costs the host's disk.
    pub unpacked: Option<u64>,
    pub reused: bool,
    /// Whether this mount's digest changed, which is what recycles the pool.
    pub changed: bool,
}

impl MountOutcome {
    /// The store side of the mount, trimmed the same way [`MountSpec::summary`]
    /// trims it. Without the guest path, which the caller has already used as
    /// the label.
    pub fn summary(&self) -> String {
        let store = self
            .store
            .trim_end_matches('/')
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        format!("{store}/{}", self.artifact_ref)
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct SecretRef {
    pub secret: String,
    pub key: String,
    pub username: Option<String>,
    /// The namespace the reference resolves in. Stamped by app-lb from the
    /// owning object's namespace, so it is never the client's choice — but it
    /// is worth rendering when it is *not* the namespace being looked at, which
    /// would otherwise read as a secret that does not exist.
    pub namespace: Option<String>,
}

impl SecretRef {
    pub fn render(&self) -> String {
        format!("{}/{}", self.secret, self.key)
    }

    /// The same thing, said from inside `ns`: qualified only when the reference
    /// resolves somewhere else.
    pub fn render_in(&self, ns: &str) -> String {
        match self.namespace.as_deref() {
            Some(other) if other != ns => format!("{}/{} in namespace {other}", self.secret, self.key),
            _ => self.render(),
        }
    }
}

/// Where a static deployment's backend is updated: a directory on the app-lb
/// host, and commands to run in it.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct UpdateSpec {
    pub working_dir: String,
    pub commands: Vec<String>,
    pub env: Option<BTreeMap<String, String>>,
    pub env_from: Vec<SecretEnv>,
    pub auth: Option<SecretRef>,
    pub timeout_secs: Option<u64>,
    pub verify_timeout_secs: Option<u64>,
}

impl UpdateSpec {
    /// One column: `/srv/app-obs (3 commands)`.
    pub fn summary(&self) -> String {
        format!(
            "{} ({} command{})",
            self.working_dir,
            self.commands.len(),
            if self.commands.len() == 1 { "" } else { "s" }
        )
    }
}

/// One entry in [`AuthGate::public_paths`]: a path prefix, and what app-lb
/// requires on it in place of the sign-in gate.
///
/// No `#[serde(default)]`: app-lb always sends both fields, and a row with an
/// empty `path` would silently match every request when rendered.
#[derive(Debug, Clone, Deserialize)]
pub struct PublicPath {
    pub path: String,
    /// `public` | `none` | `view` | `admin`. Only `public` admits a request
    /// that presents no credential at all.
    pub scope: String,
}

/// An optional sign-in gate in front of a deployment.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct AuthGate {
    /// One provider (`"google"`) or several (`["google", "app-token"]`). A
    /// `Value` rather than a `String` because the server serializes a
    /// single-provider gate as a bare string and a multi-provider one as an
    /// array — modelling only the first would fail to parse the second, and
    /// with `#[serde(default)]` that failure would look like an *absent* gate.
    pub provider: Value,
    /// Required for `google`, absent on a token-only gate.
    pub client_id: Option<String>,
    pub client_secret: Option<SecretRef>,
    pub allowed_domains: Vec<String>,
    pub allowed_emails: Vec<String>,
    /// Path prefixes the *sign-in* gate does not sit in front of, and what
    /// app-lb requires in its place.
    ///
    /// Read as objects rather than strings since scopes were added. app-lb
    /// always serializes the object form, so a bare string only ever appears in
    /// a spec somebody wrote by hand — where it means `scope: "admin"`, the
    /// fail-closed default.
    pub public_paths: Vec<PublicPath>,
    /// When set, signing in at this gate mints an app-token with this scope,
    /// which app-lb presents upstream for the life of the session. Absent on
    /// every gate that does not — which is most of them.
    pub session_scope: Option<String>,
    pub base_path: String,
    pub session_ttl_secs: u64,
    pub cookie_name: String,
    /// Set to share one sign-in across every deployment under a parent domain;
    /// `None` is a per-host session.
    pub cookie_domain: Option<String>,
    pub redirect_url: Option<String>,
    pub forward_identity: bool,
    /// How a JWT is verified, when `jwt` is among the providers.
    pub jwt: Option<JwtSpec>,
    /// The namespace auth provider this gate inherits its identity from, if it
    /// inherits one. Mutually exclusive with every identity field above — the
    /// server refuses a gate that sets both — so a gate with this set looks
    /// empty until the provider is fetched.
    pub provider_ref: Option<String>,
}

/// How a gate verifies a JWT somebody else issued, and which ones it admits.
///
/// Exactly one of `secret`, `public_key` and `jwks_url` is set — the server
/// refuses a spec with none or several.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct JwtSpec {
    pub secret: Option<SecretRef>,
    pub public_key: Option<String>,
    pub jwks_url: Option<String>,
    pub algorithms: Vec<String>,
    pub issuer: String,
    pub audience: Option<String>,
    /// Claims a token must satisfy. Free-form: the keys are whatever the issuer
    /// sends, so this stays a `Value` rather than being modelled.
    pub require: BTreeMap<String, Value>,
    pub subject_claim: String,
    pub email_claim: String,
    pub name_claim: String,
    pub leeway_secs: Option<u64>,
    pub cookie: Option<String>,
    /// Where a token-less *browser* is sent to acquire one. Requires `cookie`:
    /// a navigation can only carry a credential in one.
    pub login_url: Option<String>,
    /// The query parameter that sign-in page reads the return URL from.
    /// `redirect_uri` when unset.
    pub login_redirect_param: Option<String>,
    /// Scoped sign-in: the issuer's authorization endpoint. With `token_url`,
    /// a token-less browser is sent through an OAuth code flow for this
    /// deployment's namespace and gets a host-only app-lb session.
    pub authorize_url: Option<String>,
    /// Scoped sign-in: where app-lb redeems the code, server to server.
    pub token_url: Option<String>,
}

impl JwtSpec {
    /// Where the verifying key comes from, in one column.
    pub fn key_summary(&self) -> String {
        match (&self.secret, &self.public_key, &self.jwks_url) {
            (Some(r), _, _) => format!("shared secret {}", r.render()),
            (_, Some(_), _) => "an inline public key".to_string(),
            (_, _, Some(url)) => format!("the key set at {url}"),
            _ => "<none>".to_string(),
        }
    }

    /// The claims a token has to satisfy, rendered the way the spec reads:
    /// `role=admin|owner, accountId=acct_7f3c`.
    pub fn require_summary(&self) -> String {
        if self.require.is_empty() {
            return "any token this issuer signed".to_string();
        }
        self.require
            .iter()
            .map(|(claim, wanted)| {
                let rendered = match wanted {
                    Value::Array(vs) => vs
                        .iter()
                        .map(render_claim_value)
                        .collect::<Vec<_>>()
                        .join("|"),
                    single => render_claim_value(single),
                };
                format!("{claim}={rendered}")
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// A claim value without JSON's quotes around a string, since every other value
/// in this view is printed bare.
fn render_claim_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

impl AuthGate {
    /// Who may enter, as one line.
    pub fn allow_summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.allowed_domains.iter().any(|d| d == "*") {
            parts.push("any Google account".into());
        } else {
            parts.extend(self.allowed_domains.iter().map(|d| format!("@{d}")));
        }
        parts.extend(self.allowed_emails.iter().cloned());
        if parts.is_empty() {
            "<nobody>".into()
        } else {
            parts.join(", ")
        }
    }

    /// The providers this gate accepts, however the server spelled them.
    ///
    /// Empty in the payload means Google, which is what an `auth` block written
    /// before app-tokens existed says by omission.
    pub fn providers(&self) -> Vec<String> {
        match &self.provider {
            Value::String(s) if !s.is_empty() => vec![s.clone()],
            Value::Array(items) => items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => vec!["google".to_string()],
        }
    }

    /// Whether a program can get past this gate with an app-token.
    pub fn accepts_app_token(&self) -> bool {
        self.providers().iter().any(|p| p == "app-token")
    }

    /// Whether a JWT from the configured issuer gets past this gate.
    pub fn accepts_jwt(&self) -> bool {
        self.providers().iter().any(|p| p == "jwt")
    }

    /// The URL that has to be registered with the provider, given a hostname.
    pub fn callback_url(&self, host: &str) -> String {
        format!(
            "https://{host}{}/callback",
            self.base_path.trim_end_matches('/')
        )
    }
}

// -- GET /auth-providers, GET /auth-providers/:namespace/:name -------------

/// A declared auth provider: the identity half of a gate, named and owned by a
/// namespace.
///
/// The same fields an [`AuthGate`] carries for identity — who may enter and how
/// they are verified — with none of the route-scoped ones. A deployment
/// inherits it with `auth.provider_ref`, and app-lb resolves it on every gated
/// request, so editing this object reaches every deployment that names it.
///
/// Secrets appear as references, never values, which is what makes the object
/// safe to print.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct AuthProviderView {
    pub name: String,
    pub namespace: String,
    pub description: Option<String>,
    pub created_at: u64,
    /// One provider or several, spelled as the server spells it — a `Value` for
    /// the reason [`AuthGate::provider`] is one.
    pub provider: Value,
    pub client_id: Option<String>,
    pub client_secret: Option<SecretRef>,
    pub allowed_domains: Vec<String>,
    pub allowed_emails: Vec<String>,
    pub jwt: Option<JwtSpec>,
    pub cookie_domain: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl AuthProviderView {
    /// The providers this object admits, however the server spelled them.
    /// Shares [`AuthGate::providers`]'s rule, including that an empty value
    /// means Google.
    pub fn providers(&self) -> Vec<String> {
        match &self.provider {
            Value::String(s) if !s.is_empty() => vec![s.clone()],
            Value::Array(items) => items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => vec!["google".to_string()],
        }
    }

    /// Who this provider lets in, in one column: the Google allow-list, the
    /// JWT `require` map, or — for `app-token` — a statement that the token's
    /// own scope decides.
    pub fn admits(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if !self.allowed_domains.is_empty() || !self.allowed_emails.is_empty() {
            if self.allowed_domains.iter().any(|d| d == "*") {
                parts.push("any Google account".into());
            } else {
                parts.extend(self.allowed_domains.iter().map(|d| format!("@{d}")));
            }
            parts.extend(self.allowed_emails.iter().cloned());
        }
        if let Some(jwt) = &self.jwt {
            parts.push(jwt.require_summary());
        }
        if parts.is_empty() && self.providers().iter().any(|p| p == "app-token") {
            parts.push("whatever the app-token is scoped to".into());
        }
        if parts.is_empty() {
            "<nobody>".into()
        } else {
            parts.join(", ")
        }
    }

    /// Where the trust comes from, for the listing's one column: the issuer for
    /// a JWT provider, the OAuth client for Google.
    pub fn trust_summary(&self) -> String {
        match (&self.jwt, &self.client_id) {
            (Some(jwt), _) => jwt.issuer.clone(),
            (None, Some(id)) => id.clone(),
            (None, None) => "—".into(),
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct SecretEnv {
    pub secret: String,
    pub key: String,
    #[serde(rename = "as")]
    pub env: Option<String>,
}

impl SecretEnv {
    /// The variable the command sees. Mirrors the server's default of the
    /// upper-cased key.
    pub fn env_name(&self) -> String {
        self.env
            .clone()
            .unwrap_or_else(|| self.key.to_ascii_uppercase())
    }

    pub fn render(&self) -> String {
        format!("{}={}/{}", self.env_name(), self.secret, self.key)
    }
}

// -- GET /secrets ----------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SecretSummary {
    pub id: String,
    pub description: Option<String>,
    /// Key names only. app-lb has no endpoint that returns a value.
    pub keys: Vec<String>,
    pub updated_at: u64,
    pub encrypted_at_rest: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

// -- GET /workflows, GET /workflows/:id ------------------------------------

/// A CI workflow object.
///
/// Lenient like every other read type here: unknown fields land in `extra`, and
/// `tests/wire_contract.rs` asserts `extra` is empty against app-lb's own
/// fixture. That assertion is the only thing that catches a field this struct
/// stopped understanding — to a defaulting deserializer, an unknown field and an
/// absent one are the same thing.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct WorkflowView {
    pub id: String,
    pub repo: String,
    /// `ref` on the wire; a Rust keyword here.
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub path: String,
    pub network: String,
    /// A reference to a stored secret, never a value.
    pub auth: Option<Value>,
    pub secrets_prefix: Option<String>,
    pub enabled: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `GET /workflows` is enveloped so it can grow a cursor later without that
/// being a breaking change.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct WorkflowList {
    pub workflows: Vec<WorkflowView>,
    #[serde(flatten)]
    pub extra: Extra,
}

// -- GET /jobs, POST /deployments/:id/{build,update} -----------------------

/// One deploy job. Two kinds share the type, and the fields the other kind uses
/// are simply absent — `image-build` carries `image`/`commit`, `host-update`
/// carries `working_dir`/`commands_*`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct JobRecord {
    pub id: String,
    pub deployment: String,
    /// `image-build` or `host-update`.
    pub kind: String,
    /// `running`, `succeeded` or `failed`.
    pub status: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,

    // image-build
    pub repo: String,
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
    pub commit: Option<String>,
    pub dockerfile: Option<String>,
    pub image: Option<String>,
    pub rolled_out: bool,

    // artifact-pull
    pub store: Option<String>,
    /// What was asked for: a tag or a digest. Spelled `artifact` on the wire so
    /// it does not collide with a build's `ref`.
    #[serde(rename = "artifact")]
    pub artifact_ref: Option<String>,
    /// What it resolved to — the pull's answer to "which bytes are live?".
    pub digest: Option<String>,
    /// Bytes transferred. `0` with `reused` is a skipped fetch, not a no-op job;
    /// `0` without it is a local store hardlinking the blob rather than copying.
    pub bytes: Option<u64>,
    pub reused: bool,
    /// Set only when the pull was a *site* pull — a bundle unpacked into this
    /// directory rather than a rootfs written to an image.
    pub site_root: Option<String>,
    /// Regular files unpacked, for the same kind of pull. The answer `bytes`
    /// cannot give when the blob was hardlinked and the transfer was free.
    pub files: Option<usize>,

    // mount-pull
    /// One entry per guest mount. A mount pull covers all of a deployment's
    /// mounts in one job, so the single `digest`/`store` fields above stay empty
    /// on this kind and this carries the outcome instead.
    pub mounts: Vec<MountOutcome>,

    // host-update
    pub working_dir: Option<String>,
    pub commands_total: Option<usize>,
    pub commands_run: Option<usize>,
    pub verified: Option<bool>,

    pub error: Option<String>,
    pub log: Vec<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl JobRecord {
    pub fn is_running(&self) -> bool {
        self.status == "running"
    }

    pub fn succeeded(&self) -> bool {
        self.status == "succeeded"
    }

    pub fn is_update(&self) -> bool {
        self.kind == "host-update"
    }

    /// Whether this job pulled its image from an artifact store rather than
    /// building it. The two produce the same thing — a new `vm.image` and a
    /// recycled pool — but describe it with different fields, so every renderer
    /// has to tell them apart.
    pub fn is_pull(&self) -> bool {
        self.kind == "artifact-pull"
    }

    /// Whether this job materialized the deployment's guest mounts. Distinct
    /// from [`Self::is_pull`] even though both fetch from a store: this one
    /// changes what the guests *hold*, not what they boot, and its outcome is in
    /// `mounts` rather than in `image`.
    pub fn is_mount_pull(&self) -> bool {
        self.kind == "mount-pull"
    }

    /// The commit, short enough for a column.
    pub fn short_commit(&self) -> String {
        match &self.commit {
            Some(c) => c.chars().take(12).collect(),
            None => "—".into(),
        }
    }

    /// The resolved digest, short enough for a column. The pull's counterpart of
    /// [`short_commit`](Self::short_commit).
    pub fn short_digest(&self) -> String {
        match &self.digest {
            Some(d) => d.chars().take(12).collect(),
            None => "—".into(),
        }
    }

    /// What this job produced, as one column: the image for either image
    /// source, how far the commands got for an update.
    pub fn result_summary(&self) -> String {
        if self.is_update() {
            return match (self.commands_run, self.commands_total) {
                (Some(run), Some(total)) => format!("{run}/{total} commands"),
                _ => "—".into(),
            };
        }
        if self.is_mount_pull() {
            // What changed, not what was pulled: a mount pull that moved
            // nothing is the common case, and reporting "3 mounts" for it would
            // read as three deployments' worth of work.
            let changed = self.mounts.iter().filter(|m| m.changed).count();
            return match (self.mounts.len(), changed) {
                (0, _) => "—".into(),
                (total, 0) => format!("{total} unchanged"),
                (total, n) => format!("{n}/{total} updated"),
            };
        }
        self.image.clone().unwrap_or_else(|| "—".into())
    }

    /// What it was asked to act on: a git ref for a build, a store reference for
    /// a pull, the directory for an update.
    pub fn target_summary(&self) -> String {
        if self.is_update() {
            return self.working_dir.clone().unwrap_or_else(|| "—".into());
        }
        if self.is_pull() {
            return self.artifact_ref.clone().unwrap_or_else(|| "—".into());
        }
        if self.is_mount_pull() {
            let paths: Vec<&str> = self.mounts.iter().map(|m| m.path.as_str()).take(2).collect();
            return match (paths.is_empty(), self.mounts.len().saturating_sub(paths.len())) {
                (true, _) => "—".into(),
                (false, 0) => paths.join(","),
                (false, more) => format!("{} +{more} more", paths.join(",")),
            };
        }
        self.git_ref.clone().unwrap_or_else(|| "(default)".into())
    }

    /// How long it ran (or has been running), given the server's clock.
    pub fn elapsed_secs(&self, now: u64) -> u64 {
        self.finished_at
            .unwrap_or(now)
            .saturating_sub(self.started_at)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ScalingPolicy {
    pub min_replicas: u32,
    pub max_replicas: u32,
    pub warm_pool: u32,
    pub target_concurrency: u32,
    pub scale_to_zero_after_secs: u64,
    pub cold_start_timeout_secs: u64,
    pub drain_timeout_secs: u64,
    pub boot_timeout_secs: u64,
    /// `destroy` or `retain` — what becomes of a VM the autoscaler retires.
    /// A `String` rather than an enum so a value this build has not heard of
    /// displays as-is instead of failing the whole read.
    pub idle_action: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct HealthCheck {
    pub expected_header: Option<ExpectedHeader>,
    pub path: Option<String>,
    pub port: Option<u16>,
    pub timeout_secs: u64,
}

#[derive(Debug, Default, Deserialize)]
pub struct ExpectedHeader {
    pub name: String,
    pub value: String,
}

// -- GET /metrics ----------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MetricsResponse {
    pub generated_at: u64,
    pub uptime_secs: u64,
    pub host: HostUsage,
    pub fleet: FleetPool,
    pub global: DeploymentMetrics,
    /// Absent when the LB is not shipping logs to app-obs.
    pub obs: Option<ObsStats>,
    /// Absent when the LB has security monitoring off (`APP_LB_SIEM=0`).
    pub security: Option<SecuritySummary>,
    /// Whether app-lb can reach the VM daemon. When it cannot, the autoscaler
    /// abandons every tick, so nothing scales or boots and every other number
    /// here is frozen at whatever it was when the daemon went away.
    pub daemon: DaemonStatus,
    pub deployments: Vec<DeploymentView>,
    /// How many deployments matched before `limit`/`offset`, so a caller can
    /// page without guessing.
    pub matched: usize,
    /// How many deployments hold their own counters. Climbing past the number
    /// registered means retirement is not keeping up.
    pub tracked_deployments: usize,
    /// Sandboxes on the host that no deployment owns — created through the
    /// heyvm CLI, the cloud API or the desktop rather than by app-lb. They
    /// share the host with every pool; absent from an older app-lb, emptied by
    /// `summary=true`, and narrowed to the caller's own accounts for a
    /// namespace caller.
    #[serde(default)]
    pub host_sandboxes: Vec<HostSandboxView>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// One sandbox on the host that app-lb reports but does not manage.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct HostSandboxView {
    pub sandbox_id: String,
    pub name: String,
    /// The daemon's status string: `running`, `stopped`, `provisioning`, ….
    pub status: String,
    pub image: String,
    pub size_class: Option<String>,
    pub guest_ip: Option<String>,
    pub uptime_secs: u64,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
    /// The heyo account the sandbox is billed to, when the daemon knows.
    pub account_id: Option<String>,
    /// RFC 3339, when the daemon reports it.
    pub created_at: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Alert counts from the detection engine, carried on `/metrics` so a status
/// display can show one without a second request. The alerts themselves are on
/// `GET /security`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SecuritySummary {
    /// Alerts currently held in the LB's in-memory ring.
    pub open: usize,
    /// How many of those are `high` or `critical`.
    pub urgent: u64,
    /// Observations dropped because the analysis queue was full. Non-zero means
    /// detection is sampling rather than complete — the same failure mode, and
    /// the same warning, as [`ObsStats::dropped`].
    pub dropped: u64,
    /// Whether the per-source table is full, which means the same for addresses
    /// as `dropped` does for events.
    pub clients_at_capacity: bool,
    /// Guard rules the data plane is enforcing, and how many requests they have
    /// refused. Reported beside the alert counts because "we are blocking
    /// traffic" belongs next to "we are seeing attacks".
    pub rules: usize,
    pub blocked: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Log-shipping counters. Worth surfacing because the pipeline drops rather than
/// blocks by design, and `dropped` is the only trace a lost record leaves.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ObsStats {
    pub queued: u64,
    pub dropped: u64,
    pub shipped: u64,
    pub failed: u64,
    pub healthy: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct HostUsage {
    /// False until the daemon has produced a sample.
    pub available: bool,
    pub cpu_count: u64,
    pub cpu_percent: f64,
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub sampled_at_ms: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FleetPool {
    pub deployments: usize,
    pub ready: usize,
    pub draining: usize,
    pub pending: usize,
    pub total_in_flight: usize,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DeploymentView {
    pub id: String,
    /// Empty when the server omitted the default namespace.
    pub namespace: String,
    /// `"vm"`, `"static"` or `"site"`.
    pub kind: String,
    pub upstreams: Vec<String>,
    /// Whether at least one data-plane route points at this deployment.
    pub routed: bool,
    /// Exact hostnames this deployment is routed on — `host` rules only, since
    /// a `host_suffix` names no single certificate subject.
    pub hosts: Vec<String>,
    /// The same routes as URLs, with the *data plane's* scheme and port. Built
    /// server-side because the admin listener knows neither.
    pub urls: Vec<String>,
    /// For a site, the directory it serves. Absent for every other kind.
    pub site_root: Option<String>,
    pub site_spa: bool,
    /// `"build"` or `"update"` — which deploy job this deployment accepts, if
    /// either.
    pub job_kind: Option<String>,
    pub pool: PoolStatus,
    pub vms: Vec<VmView>,
    /// Booting VMs, oldest first — the ones holding a cold start open. A count
    /// alone cannot tell a 3-second boot from a guest that has been failing its
    /// health check for six minutes.
    pub pending_vms: Vec<PendingVmView>,
    pub metrics: DeploymentMetrics,
    #[serde(flatten)]
    pub extra: Extra,
}

/// A VM created but not yet in the pool.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PendingVmView {
    pub sandbox_id: String,
    /// Seconds since the daemon accepted the create call.
    pub age_secs: u64,
    /// The daemon's last reported status, absent before the first observation:
    /// `provisioning`, `running`, `stopped`, `paused`, `failed`, `cold-stored`
    /// or `unknown`.
    pub status: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PoolStatus {
    pub desired_replicas: u32,
    pub ready: usize,
    pub draining: usize,
    pub pending: usize,
    pub total_in_flight: usize,
    pub target_concurrency: u32,
    pub min_replicas: u32,
    pub max_replicas: u32,
    pub warm_pool: u32,
    /// `None` when there is no available capacity to divide by — rendered as
    /// "—", never as a fake 0%.
    pub utilization: Option<f64>,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
    /// How long a booting VM gets before the autoscaler kills it; `0` waits
    /// indefinitely.
    pub boot_timeout_secs: u64,
    /// How long a request waits on a cold start. A pending VM older than this
    /// has already cost somebody a 503.
    pub cold_start_timeout_secs: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct VmView {
    pub sandbox_id: String,
    pub addr: String,
    pub in_flight: usize,
    pub healthy: bool,
    pub draining: bool,
    pub uptime_secs: u64,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl VmView {
    pub fn status(&self) -> &'static str {
        if self.draining {
            "Draining"
        } else if self.healthy {
            "Ready"
        } else {
            "NotReady"
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DeploymentMetrics {
    pub requests: StatusCounts,
    pub latency_ms: Histogram,
    pub cold_start_s: Histogram,
    pub autoscale: AutoscaleCounts,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct StatusCounts {
    pub total: u64,
    pub c2xx: u64,
    pub c3xx: u64,
    pub c4xx: u64,
    pub c5xx: u64,
    pub errors: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Histogram {
    pub count: u64,
    pub sum: u64,
    pub mean: f64,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AutoscaleCounts {
    pub vms_created: u64,
    pub vms_drained: u64,
    pub vms_reaped: u64,
    pub scale_up_events: u64,
    pub scale_down_events: u64,
    pub cold_start_waits: u64,
    pub cold_start_hits: u64,
    pub cold_start_timeouts: u64,
    /// VMs killed for never passing their health check inside the boot timeout.
    /// Was absent from this struct while app-lb had been sending it — the exact
    /// silent drift `extra` exists to catch, and the reason `describe` could not
    /// tell "the guest never became healthy" from "no VM was ever created".
    pub boot_timeouts: u64,
    /// Creates the daemon refused outright. The distinguishing counter: with
    /// `vms_created` and `boot_timeouts` both zero, a non-zero value here means
    /// no VM ever existed, so the guest image is not the thing to debug.
    pub create_failures: u64,
    /// What the daemon said the last time it refused.
    pub last_create_error: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DaemonStatus {
    pub reachable: bool,
    pub last_error: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

// -- GET /certs ------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct CertStatus {
    pub host: String,
    pub not_after: String,
    pub issuer: String,
    pub needs_renewal: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

// -- GET /disks ------------------------------------------------------------

/// What the daemon thinks of the sandbox a disk belongs to.
///
/// `Unknown` is not a parse failure — it is what app-lb reports when it could
/// not reach the daemon, and such a disk is never reclaimed. A state this build
/// does not recognise degrades to `Unknown` for the same reason: an unfamiliar
/// word must not blank the whole listing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiskState {
    Running,
    Stopped,
    Orphan,
    #[default]
    #[serde(other)]
    Unknown,
}

impl DiskState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Orphan => "orphan",
            Self::Unknown => "unknown",
        }
    }
}

/// One file on the host and what it is for.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DiskPart {
    pub kind: String,
    pub path: String,
    /// Blocks actually allocated. The number that matters: a `data.ext4` is
    /// created sparse at its full nominal size, so `apparent_bytes` routinely
    /// reads tens of GiB for a fraction of that in real occupancy.
    pub bytes: u64,
    pub apparent_bytes: u64,
    pub modified_at: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DiskArchiveRecord {
    pub uri: String,
    pub at: u64,
    pub bytes: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DiskArchiveView {
    pub id: String,
    pub sandbox_id: String,
    pub uri: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub status: String,
    pub bytes: u64,
    pub expected_bytes: u64,
    pub error: Option<String>,
    pub purged: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Everything on the host belonging to one sandbox.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DiskInfo {
    pub sandbox_id: String,
    /// The daemon's name for it, when the daemon still has a record.
    pub name: Option<String>,
    /// The deployment that owns it, from an `applb-<deployment>-<nonce>` name.
    /// `None` for a sandbox app-lb did not create, or one whose name is gone.
    pub deployment: Option<String>,
    pub state: DiskState,
    /// A live deployment lists this sandbox as one it intends to resume. A
    /// claimed disk is never reclaimed, at any age.
    pub claimed: bool,
    /// Set by an operator: never reclaim this, whatever its age.
    pub retain: bool,
    pub note: Option<String>,
    pub bytes: u64,
    pub apparent_bytes: u64,
    pub modified_at: u64,
    /// When the sweep would reclaim this, or `None` if it never would.
    pub expires_at: Option<u64>,
    /// Why it will not be reclaimed, in a phrase meant to be shown verbatim.
    pub held_by: Option<String>,
    pub archived: Option<DiskArchiveRecord>,
    pub parts: Vec<DiskPart>,
    /// The directories a purge would remove.
    pub roots: Vec<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DiskTotals {
    pub disks: usize,
    pub bytes: u64,
    pub apparent_bytes: u64,
    pub running: usize,
    pub stopped: usize,
    pub orphan: usize,
    pub retained: usize,
    /// Disks the sweep would reclaim right now, and what that would free.
    pub expiring_now: usize,
    pub reclaimable_bytes: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `GET /disks` — the host's per-sandbox disk inventory.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DiskInventory {
    /// Whether both daemon listings succeeded. When false nothing is classified
    /// as an orphan and the sweep declines to run — so a listing that says
    /// `complete: false` must not be read as "these disks are residue".
    pub complete: bool,
    pub incomplete_reason: Option<String>,
    pub data_dir: String,
    pub tmp_dir: String,
    /// `0` when expiry is disabled.
    pub ttl_secs: u64,
    pub sweep_secs: u64,
    pub archive_enabled: bool,
    pub archive_on_expire: bool,
    pub archive_target: Option<String>,
    /// Free and total bytes on the filesystem holding the guest disks, when it
    /// could be measured. `None` means unknown, never "full".
    pub free_bytes: Option<u64>,
    pub filesystem_bytes: Option<u64>,
    /// How long a disk with no daemon record survives, against `ttl_secs` for
    /// everything else. Far shorter: an orphan is the disk of a VM that failed
    /// to create or died without a trace, and nothing will ever resume it.
    pub orphan_ttl_secs: u64,
    pub totals: DiskTotals,
    pub disks: Vec<DiskInfo>,
    pub archives: Vec<DiskArchiveView>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `GET /api/plugins` and `/api/plugins/:id` — a built-in plugin, its stored
/// record and its live status.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct PluginView {
    pub id: String,
    pub name: String,
    pub description: String,
    /// JSON Schema for `config`. Advisory; app-lb validates on write.
    pub config_schema: Value,
    /// Whether namespaces install this plugin for themselves (`heyctl plugins
    /// install`), on top of the fleet-wide switch.
    pub per_namespace: bool,
    /// The namespaces it is installed in. Empty for a fleet-only plugin.
    pub installed_in: Vec<String>,
    pub enabled: bool,
    /// Kept while disabled, so re-enabling does not lose it.
    pub config: Value,
    pub updated_at: u64,
    /// Why the last apply failed. A plugin can be enabled *and* failing.
    pub last_error: Option<String>,
    /// Whatever the plugin reports about itself; shape is per plugin.
    pub status: Value,
    #[serde(flatten)]
    pub extra: Extra,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deployment_parses_from_a_partial_body() {
        // Everything defaults, so a server that grows a field — or drops one
        // this build knows about — still renders.
        let d: DeploymentStatus = serde_json::from_str(r#"{"spec":{"id":"web"},"ready":2}"#).unwrap();
        assert_eq!(d.spec.id, "web");
        assert_eq!(d.ready, 2);
        assert_eq!(d.desired_replicas, 0);
    }

    #[test]
    fn routes_render_with_their_matching_semantics() {
        let exact = RouteRule {
            host: Some("secrets.local".into()),
            ..Default::default()
        };
        assert_eq!(exact.render(), "secrets.local");

        let wild = RouteRule {
            host_suffix: Some(".apps.example.com".into()),
            path_prefix: Some("/api".into()),
            ..Default::default()
        };
        assert_eq!(wild.render(), "*.apps.example.com/api");

        let path_only = RouteRule {
            path_prefix: Some("/legacy".into()),
            ..Default::default()
        };
        assert_eq!(path_only.render(), "*/legacy");

        assert_eq!(RouteRule::default().render(), "<empty>");
    }

    #[test]
    fn many_routes_collapse_to_a_summary() {
        let spec = DeploymentSpec {
            routes: (0..5)
                .map(|i| RouteRule {
                    host: Some(format!("h{i}.local")),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        assert_eq!(spec.routes_summary(), "h0.local,h1.local,h2.local +2 more");
    }

    #[test]
    fn a_build_source_renders_as_one_column() {
        let b = BuildSpec {
            repo: "https://github.com/acme/web.git".into(),
            git_ref: Some("main".into()),
            ..Default::default()
        };
        assert_eq!(b.summary(), "github.com/acme/web@main");

        let default_branch = BuildSpec {
            repo: "git@github.com:acme/web.git".into(),
            ..Default::default()
        };
        assert_eq!(
            default_branch.summary(),
            "git@github.com:acme/web@(default branch)"
        );

        // A recipe out of a store reads like the store column, not like a repo:
        // both share SOURCE, and which column it lands in already says whether
        // this is built or pulled.
        let from_store = BuildSpec {
            store: "http://art.internal:8080".into(),
            git_ref: Some("web-rootfs".into()),
            ..Default::default()
        };
        assert_eq!(from_store.summary(), "art.internal:8080/web-rootfs");

        // `store` wins over an empty `repo` without either being an Option: an
        // absent field is empty under #[serde(default)], and that is the whole
        // signal.
        let parsed: BuildSpec =
            serde_json::from_str(r#"{"store":"/srv/artifacts","ref":"web"}"#).unwrap();
        assert_eq!(parsed.summary(), "/srv/artifacts/web");
    }

    #[test]
    fn a_job_record_parses_from_a_partial_body() {
        let r: JobRecord =
            serde_json::from_str(r#"{"id":"job-1","status":"running","started_at":100}"#).unwrap();
        assert!(r.is_running());
        assert!(!r.succeeded());
        assert_eq!(r.short_commit(), "—");
        assert_eq!(r.elapsed_secs(130), 30, "a running job measures against now");

        let done: JobRecord = serde_json::from_str(
            r#"{"id":"job-1","kind":"image-build","status":"succeeded","started_at":100,
                "finished_at":160,"commit":"0123456789abcdef","ref":"main","image":"web-0123"}"#,
        )
        .unwrap();
        assert!(done.succeeded());
        assert_eq!(done.short_commit(), "0123456789ab");
        assert_eq!(done.elapsed_secs(999), 60, "a finished one measures its own span");
        assert_eq!(done.target_summary(), "main");
        assert_eq!(done.result_summary(), "web-0123");
    }

    /// The two kinds share the type, so the columns have to mean the right thing
    /// for each: a host update has no image and no commit.
    #[test]
    fn an_update_record_summarizes_its_own_fields() {
        let update: JobRecord = serde_json::from_str(
            r#"{"id":"job-2","kind":"host-update","status":"failed","started_at":100,
                "working_dir":"/srv/app-obs","commands_total":3,"commands_run":1,
                "verified":false}"#,
        )
        .unwrap();
        assert!(update.is_update());
        assert_eq!(update.target_summary(), "/srv/app-obs");
        assert_eq!(update.result_summary(), "1/3 commands");
        assert_eq!(update.verified, Some(false));
    }

    #[test]
    fn an_artifact_source_renders_as_one_column_shaped_like_a_build_one() {
        let a = ArtifactSpec {
            store: "http://10.0.0.4:8080/".into(),
            artifact_ref: "web-v2".into(),
            ..Default::default()
        };
        assert_eq!(a.summary(), "10.0.0.4:8080/web-v2");

        // A store root keeps its leading slash — it is a path, and stripping it
        // would make an absolute one look relative in the SOURCE column.
        let local = ArtifactSpec {
            store: "/srv/artifacts".into(),
            artifact_ref: "debian-hermes".into(),
            ..Default::default()
        };
        assert_eq!(local.summary(), "/srv/artifacts/debian-hermes");
    }

    #[test]
    fn a_pull_record_summarizes_the_store_side_fields_not_the_git_ones() {
        let pull: JobRecord = serde_json::from_str(
            r#"{"id":"job-3","kind":"artifact-pull","status":"succeeded","started_at":100,
                "store":"http://127.0.0.1:8080","artifact":"debian-hermes",
                "digest":"c74abee2ce8409f1aaaa","image":"web-c74abee2ce84",
                "bytes":609222656,"rolled_out":true}"#,
        )
        .unwrap();
        assert!(pull.is_pull());
        assert!(!pull.is_update());
        // The reference asked for, not a git ref it does not have.
        assert_eq!(pull.target_summary(), "debian-hermes");
        assert_eq!(pull.result_summary(), "web-c74abee2ce84");
        assert_eq!(pull.short_digest(), "c74abee2ce84");
        assert_eq!(pull.short_commit(), "—", "a pull has no commit");
        assert!(!pull.reused);
    }

    #[test]
    fn a_reused_image_is_distinguishable_from_a_pull_that_never_ran() {
        let reused: JobRecord = serde_json::from_str(
            r#"{"id":"job-4","kind":"artifact-pull","status":"succeeded","started_at":1,
                "bytes":0,"reused":true}"#,
        )
        .unwrap();
        assert!(reused.reused);
        assert_eq!(reused.bytes, Some(0));

        // A record with neither is one that failed before it got that far.
        let failed: JobRecord = serde_json::from_str(
            r#"{"id":"job-5","kind":"artifact-pull","status":"failed","started_at":1}"#,
        )
        .unwrap();
        assert!(!failed.reused);
        assert_eq!(failed.bytes, None);
    }

    #[test]
    fn an_update_source_renders_its_directory_and_command_count() {
        let u = UpdateSpec {
            working_dir: "/srv/app-obs".into(),
            commands: vec!["git pull".into(), "cargo build --release".into()],
            ..Default::default()
        };
        assert_eq!(u.summary(), "/srv/app-obs (2 commands)");

        let one = UpdateSpec {
            working_dir: "/srv/x".into(),
            commands: vec!["make deploy".into()],
            ..Default::default()
        };
        assert_eq!(one.summary(), "/srv/x (1 command)");
    }

    #[test]
    fn a_gate_says_who_may_enter_and_where_the_provider_redirects() {
        let g = AuthGate {
            allowed_domains: vec!["example.com".into()],
            allowed_emails: vec!["contractor@gmail.com".into()],
            base_path: "/__applb/auth".into(),
            ..Default::default()
        };
        assert_eq!(g.allow_summary(), "@example.com, contractor@gmail.com");
        assert_eq!(
            g.callback_url("app.example.com"),
            "https://app.example.com/__applb/auth/callback"
        );

        // The escape hatch reads as what it is, not as a literal `@*`.
        let any = AuthGate {
            allowed_domains: vec!["*".into()],
            ..Default::default()
        };
        assert_eq!(any.allow_summary(), "any Google account");

        // A server a version ahead could send a gate this build understands
        // nothing about; it must still render rather than fail to parse.
        let unknown: AuthGate = serde_json::from_str(r#"{"provider":"okta","client_id":"x"}"#).unwrap();
        assert_eq!(unknown.provider, "okta");
        assert_eq!(unknown.allow_summary(), "<nobody>");
    }

    #[test]
    fn a_secret_env_defaults_to_the_upper_cased_key() {
        let e = SecretEnv {
            secret: "obs".into(),
            key: "ingest_token".into(),
            env: None,
        };
        assert_eq!(e.env_name(), "INGEST_TOKEN");
        assert_eq!(e.render(), "INGEST_TOKEN=obs/ingest_token");

        let renamed = SecretEnv {
            env: Some("APP_OBS_INGEST_TOKEN".into()),
            ..e
        };
        assert_eq!(renamed.render(), "APP_OBS_INGEST_TOKEN=obs/ingest_token");
    }

    #[test]
    fn vm_status_puts_draining_ahead_of_health() {
        let vm = VmStatus {
            healthy: true,
            draining: true,
            ..Default::default()
        };
        assert_eq!(vm.status(), "Draining");
    }
}

// -- POST /deployments/:id/exec --------------------------------------------

/// What a command did. A non-zero `exit_code` is a successful *request* — the
/// command ran and failed, which is not the same as being unable to run it.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ExecOutput {
    /// Which VM ran it. Worth having even for a single-VM sandbox: after a
    /// resume or a rebuild it is a different sandbox than last time.
    pub sandbox_id: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    /// stdout and stderr interleaved as the guest wrote them. Not
    /// `stdout + stderr` — the only faithful rendering of interleaved output.
    pub output: String,
    #[serde(flatten)]
    pub extra: Extra,
}

impl ExecOutput {
    /// Whether the command itself succeeded.
    pub fn ok(&self) -> bool {
        self.exit_code == 0
    }
}

// -- DELETE /deployments/:id/vms/:sandbox_id -------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct EvictOutcome {
    pub sandbox_id: String,
    /// `"killed"` (immediate) or `"draining"` (still serving what it has).
    pub outcome: String,
    #[serde(flatten)]
    pub extra: Extra,
}

impl EvictOutcome {
    pub fn is_draining(&self) -> bool {
        self.outcome == "draining"
    }
}

// -- PUT/DELETE /deployments/:id/upstreams/:upstream/drain ----------------

#[derive(Debug, Default, Deserialize, serde::Serialize)]
#[serde(default)]
pub struct UpstreamTrafficStatus {
    pub deployment_id: String,
    pub upstream: String,
    /// `accepting`, `draining`, or `drained`.
    pub state: String,
    /// Probe state, independent from the administrative traffic state above.
    pub healthy: bool,
    pub in_flight: usize,
    pub reason: Option<String>,
    pub started_at: Option<u64>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl UpstreamTrafficStatus {
    pub fn is_drained(&self) -> bool {
        self.state == "drained" && self.in_flight == 0
    }

    pub fn is_accepting(&self) -> bool {
        self.state == "accepting"
    }
}

// -- app-tokens -------------------------------------------------------------

/// What a token may do on the admin API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdminScope {
    /// Nothing. Still usable against a deployment's own gate, which is the
    /// point of a token handed to an application.
    #[default]
    None,
    /// `/metrics` and `/dashboard`.
    View,
    /// Everything, within the token's `deployments` scope.
    Admin,
}

impl std::fmt::Display for AdminScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::View => "view",
            Self::Admin => "admin",
        })
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct TokenSummary {
    pub id: String,
    pub name: String,
    pub admin: AdminScope,
    /// The namespace this token is confined to, if any. Inside it, an empty
    /// `deployments` list means every deployment there; outside it the token
    /// reaches nothing.
    pub namespace: Option<String>,
    /// Deployment ids, or `["*"]` for all of them.
    pub deployments: Vec<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    /// `None` also means "not used since the store was last written" — the
    /// stamp is flushed opportunistically, not per request, so a busy token can
    /// still read as unused.
    pub last_used_at: Option<u64>,
    /// Minted at a control plane and valid on every server that mirrors it.
    pub fleet: bool,
    /// Set when this server holds the token only as a mirror: the control
    /// plane it came from, which is where it is changed or revoked.
    pub mirrored_from: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl TokenSummary {
    /// Whether this token's scope covers the whole fleet. A namespace token
    /// never does — `["*"]` inside a namespace means everything *there*.
    pub fn covers_fleet(&self) -> bool {
        self.namespace.is_none() && self.deployments.iter().any(|d| d == "*")
    }

    pub fn allows(&self, deployment: &str) -> bool {
        self.deployments.iter().any(|d| d == "*" || d == deployment)
    }
}

// -- namespaces -------------------------------------------------------------

/// One namespace, from `GET /namespaces`.
///
/// Distinct from [`FeedIndexEntry`], which answers a narrower question: that one
/// lists namespaces with *feed events*, this one lists namespaces with
/// deployments the caller can see. A namespace appears here the moment
/// something is registered in it and disappears when the last thing leaves —
/// there is no namespace object to create or delete.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct NamespaceEntry {
    pub namespace: String,
    /// Deployments in it that *this credential* may see. Narrowed server-side,
    /// so a scoped token sees its own arithmetic rather than the fleet's.
    pub deployments: u64,
    /// Whether a namespace *object* exists, as opposed to the name being one a
    /// deployment happens to mention. Both scope identically; the difference is
    /// whether there is anything to delete or describe.
    pub declared: bool,
    pub description: Option<String>,
    /// Present only when `declared`.
    pub created_at: Option<u64>,
    #[serde(flatten)]
    pub extra: Extra,
}

// -- the event feed ---------------------------------------------------------

/// One namespace that has feed events, from `GET /feeds`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct FeedIndexEntry {
    pub namespace: String,
    pub events: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

/// One event from a namespace's feed, from `GET /feeds/:ns?format=json`.
///
/// The same entries the RSS document carries; `id` is the RSS `<guid>`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct FeedEvent {
    pub id: u64,
    /// When the event first happened.
    pub ts: u64,
    /// When it last happened — repeats of the same issue fold into one entry.
    pub last_ts: u64,
    pub count: u64,
    pub namespace: String,
    pub deployment: String,
    /// `deployed`, `updated`, `removed` or `issue`.
    pub kind: String,
    pub title: String,
    pub detail: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The reply to a mint. **`token` is the only time the secret is ever
/// returned** — app-lb stores only its hash, and there is no endpoint that
/// reads it back. Store it here or mint another one.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct MintedToken {
    #[serde(flatten)]
    pub summary: TokenSummary,
    pub token: String,
}

// -- GET /whoami ------------------------------------------------------------

/// What the server makes of the credential presented, from `GET /whoami`.
///
/// The one admin route with no tier requirement, so even a token minted with
/// `admin: none` can ask it why everything else refuses.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct WhoAmI {
    /// `ungated`, `operator`, `app-token` or `federated`.
    pub caller: String,
    /// `none`, `view`, `admin` — or `unchecked` on an ungated listener. For a
    /// federated caller, the strongest tier it holds anywhere.
    pub admin_scope: String,
    /// Whether this credential may use the fleet-wide routes.
    pub fleet: bool,
    /// Whether it is behind a namespace wall.
    pub confined: bool,
    pub may: WhoAmIMay,
    /// An app-token's id and name.
    pub token: Option<WhoAmIToken>,
    /// An app-token's namespace, when it is confined to one.
    pub namespace: Option<String>,
    /// An app-token's deployment list, verbatim: `["*"]` is every deployment,
    /// and empty on a namespace token is everything in that namespace.
    pub deployments: Option<Vec<String>>,
    pub expires_at: Option<u64>,
    pub expires_in_secs: Option<u64>,
    /// A federated caller's identity, as the auth service reported it.
    pub subject: Option<Value>,
    /// A federated caller's namespaces and the tier it holds in each.
    pub namespaces: Option<BTreeMap<String, String>>,
    pub detail: Option<String>,
    pub note: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl WhoAmI {
    /// The single namespace this credential is confined to, if there is
    /// exactly one — the namespace a command may assume when none is named.
    pub fn sole_namespace(&self) -> Option<&str> {
        if !self.confined {
            return None;
        }
        if let Some(ns) = self.namespace.as_deref() {
            return Some(ns);
        }
        match &self.namespaces {
            Some(map) if map.len() == 1 => map.keys().next().map(String::as_str),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct WhoAmIMay {
    pub read_view_routes: bool,
    pub use_admin_routes: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct WhoAmIToken {
    pub id: String,
    pub name: String,
    #[serde(flatten)]
    pub extra: Extra,
}

// -- rollouts ---------------------------------------------------------------

/// A replace-by-rollout operation, from `POST /deployments/:id/rollouts` and
/// `GET /deployments/:id/rollouts/:operation`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct RolloutOperation {
    pub operation_id: String,
    pub deployment: String,
    /// The deployment's `rollout_revision` the operation was admitted against.
    pub source_revision: String,
    pub target_spec_sha256: String,
    /// `running`, `succeeded`, `failed` or `reconciliation_required`.
    pub status: String,
    pub phase: String,
    pub readiness_verified: bool,
    pub previous_stopped: bool,
    pub error: Option<String>,
    pub preparation_stage: Option<String>,
    /// Present once a failed rollout's candidates have been reclaimed.
    pub failure_settlement: Option<Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl RolloutOperation {
    /// Whether the operation has stopped moving, successfully or not.
    pub fn is_finished(&self) -> bool {
        !matches!(self.status.as_str(), "running" | "reconciliation_required")
    }
}

// -- discovery --------------------------------------------------------------

/// What a gateway publishes about a deployment for discovery, from
/// `GET /deployments/:id/discovery-status`. camelCase on the wire.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DiscoveryStatus {
    pub service_id: String,
    pub source_url: Option<String>,
    pub version: Option<u64>,
    /// The regional discovery state, when the deployment declares one. Its
    /// shape belongs to the regional protocol, so it is carried opaquely.
    pub regional: Option<Value>,
    pub upstreams: Vec<DiscoveryUpstream>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DiscoveryUpstream {
    pub peer: String,
    pub draining: bool,
    pub in_flight: usize,
    #[serde(flatten)]
    pub extra: Extra,
}

// -- namespace plugins ------------------------------------------------------

/// A plugin as one namespace sees it, from `GET /namespaces/:ns/plugins`.
///
/// Only plugins that install per namespace are listed. `enabled` is the
/// fleet-wide switch the operator controls; `installed` is this namespace's.
/// A plugin does nothing for a namespace unless both are true.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct NamespacePlugin {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub installed: bool,
    pub installed_at: Option<u64>,
    /// Who installed it — `token:<id>` or `user:<id>`; absent for the operator.
    pub installed_by: Option<String>,
    pub config: Option<Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Every namespace a plugin is installed in, from
/// `GET /api/plugins/:id/installs`. Fleet scope only.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct PluginInstalls {
    pub plugin: String,
    pub enabled: bool,
    pub namespaces: Vec<String>,
    pub installs: BTreeMap<String, NamespaceInstall>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct NamespaceInstall {
    pub installed_at: u64,
    pub installed_by: Option<String>,
    pub config: Value,
    #[serde(flatten)]
    pub extra: Extra,
}

// -- telemetry (the obs plugin) ---------------------------------------------

/// Whether recently ingested telemetry is queryable yet.
///
/// app-obs flushes on a timer, so the newest rows are legitimately missing
/// from a query until `flush_secs` has passed.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ObsFreshness {
    pub buffered_rows: usize,
    pub flush_secs: u64,
    /// Records dropped because the ingest buffer was full.
    pub dropped: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

/// One time bucket of a deployment's metrics.
///
/// Every measure is optional: `None` means nothing was sampled in the bucket,
/// which is different from zero.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ObsMetricBucket {
    /// Bucket start, epoch milliseconds UTC.
    pub t: i64,
    pub requests_per_sec: Option<f64>,
    pub errors_per_sec: Option<f64>,
    pub mean_latency_ms: Option<f64>,
    /// Cumulative since app-lb started, not windowed.
    pub p50_ms: Option<f64>,
    pub p90_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<f64>,
    pub in_flight: Option<f64>,
    pub ready: Option<f64>,
    pub pending: Option<f64>,
    pub draining: Option<f64>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// One time bucket of a deployment's log volume.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ObsLogBucket {
    pub t: i64,
    pub lines: u64,
    pub errors: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

/// A namespace's telemetry overview, from `…/plugins/obs/api/fleet`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ObsFleet {
    pub generated_at_ms: i64,
    pub from_ms: i64,
    pub to_ms: i64,
    pub step_secs: u32,
    /// The window this answer covers, e.g. `1h`.
    pub window: String,
    /// Every window label the server accepts.
    pub windows: Vec<String>,
    pub retain_days: u32,
    pub freshness: ObsFreshness,
    /// Whole-host usage. Operator view only; absent in a namespace's.
    pub host: Option<Vec<ObsMetricBucket>>,
    pub deployments: Vec<ObsFleetRow>,
    /// Sandboxes outside every deployment. Operator view only.
    pub host_sandboxes: Option<Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// One deployment's row in [`ObsFleet`].
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ObsFleetRow {
    pub id: String,
    pub buckets: Vec<ObsMetricBucket>,
    pub log_buckets: Vec<ObsLogBucket>,
    /// The most recent non-null value of each measure in the window.
    pub latest: ObsMetricBucket,
    pub log_lines: u64,
    pub error_logs: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

/// One deployment's telemetry, from `…/plugins/obs/api/deployments/:id`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ObsDeployment {
    pub id: String,
    pub generated_at_ms: i64,
    pub from_ms: i64,
    pub to_ms: i64,
    pub step_secs: u32,
    pub window: String,
    pub windows: Vec<String>,
    pub retain_days: u32,
    pub freshness: ObsFreshness,
    pub buckets: Vec<ObsMetricBucket>,
    pub log_buckets: Vec<ObsLogBucket>,
    pub latest: ObsMetricBucket,
    pub log_lines: u64,
    pub error_logs: u64,
    /// Backends that logged in the window.
    pub backends: Vec<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// One page of a deployment's logs, from
/// `…/plugins/obs/api/deployments/:id/logs`. Newest first.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ObsLogs {
    pub id: String,
    pub from_ms: i64,
    pub to_ms: i64,
    pub rows: Vec<ObsLogRow>,
    /// Pass back as [`crate::LogQuery::before`] for the next page; `None` at
    /// the end. Inclusive, so the next page may repeat lines from the same
    /// millisecond — drop the ones already seen.
    pub next_before_ms: Option<i64>,
    pub limit: usize,
    #[serde(flatten)]
    pub extra: Extra,
}

/// One stored log line.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ObsLogRow {
    /// Epoch milliseconds UTC.
    pub ts: i64,
    pub level: Option<String>,
    /// `stdout`, `stderr`, `console`, `access`, `security`, …
    pub source: String,
    pub message: String,
    /// The VM (sandbox id) or upstream that produced it.
    pub backend: Option<String>,
    pub host: Option<String>,
    /// The structured payload, still a JSON string.
    pub fields: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// An alert rule, from `…/plugins/obs/api/alerts`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ObsAlert {
    pub id: String,
    pub deployment: String,
    /// The namespace the rule belongs to. Absent on rules made before
    /// namespaces existed in app-obs.
    pub namespace: Option<String>,
    /// `errors` — errors over the trailing minute.
    pub metric: String,
    pub threshold: f64,
    pub webhook_url: String,
    #[serde(flatten)]
    pub extra: Extra,
}

// -- heyvm's image catalog ------------------------------------------------

/// `GET /images`: heyvm's image catalog as app-lb manages it. Fleet scope.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ImageInventory {
    pub generated_at: u64,
    /// False when what references the images could not be determined; the
    /// server then offloads and deletes nothing.
    pub complete: bool,
    pub error: Option<String>,
    /// Whether heyvm can delete images; `None` until one was tried.
    pub delete_supported: Option<bool>,
    /// Whether automatic offload is on.
    pub offload: bool,
    pub disk_used_pct: Option<f64>,
    pub pressure_pct: u8,
    pub local_bytes: u64,
    pub images: Vec<ImageEntry>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// One image: its record, and — in an inventory — what holds it.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ImageEntry {
    pub name: String,
    /// `pull`, `build` or `unknown`.
    pub source: String,
    /// `local` or `offloaded`.
    pub tier: String,
    pub digest: Option<String>,
    pub store: Option<String>,
    #[serde(rename = "ref")]
    pub artifact_ref: Option<String>,
    pub grow_gb: Option<u64>,
    pub bytes: u64,
    pub first_seen: u64,
    pub last_used: u64,
    pub pinned: bool,
    pub offloaded_to: Option<String>,
    pub offloaded_at: Option<u64>,
    pub failures: u32,
    /// After a failed offload, not retried before this.
    pub next_attempt_at: u64,
    pub last_error: Option<String>,
    /// The store's API key, as a secret reference — never a value.
    pub auth: Option<Value>,
    /// In heyvm's catalog right now. Inventory only.
    pub present: bool,
    /// What holds it. Inventory only.
    pub references: Vec<ImageReference>,
    /// Why the offload pacer would leave it alone; absent when it would not.
    pub kept_because: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Something that holds an image: `deployment`, `rollout`, `sandbox`, `job`
/// or `pinned`, with the fields that kind carries.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ImageReference {
    pub kind: String,
    pub id: Option<String>,
    pub deployment: Option<String>,
    pub operation: Option<String>,
    pub job: Option<String>,
}

impl std::fmt::Display for ImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.kind.as_str(), &self.id, &self.deployment) {
            ("deployment", Some(id), _) => write!(f, "deployment/{id}"),
            ("sandbox", Some(id), _) => write!(f, "sandbox/{id}"),
            ("rollout", _, Some(d)) => write!(f, "rollout of {d}"),
            ("job", _, Some(d)) => write!(f, "job {} of {d}", self.job.as_deref().unwrap_or("?")),
            (kind, _, _) => f.write_str(kind),
        }
    }
}

/// `POST /images/sweep`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ImageSweep {
    pub skipped: Option<String>,
    pub pressure: bool,
    pub offloaded: Vec<String>,
    /// `(image, why)`.
    pub failed: Vec<(String, String)>,
}
