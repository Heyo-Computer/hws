//! The postgres plugin: a namespace's own Postgres databases, on the region's
//! pg-fc pool.
//!
//! pg-fc (pg-vm-pool) provisions *dedicated databases*: a database with its
//! own role and password, where the pooler refuses that role every other
//! database name with `42501`. That is the whole tenancy boundary, and it is
//! pg-fc's. What pg-fc does not know is namespaces — its admin API is one
//! Basic credential that can create and revoke anything — so this plugin is
//! the policy layer in front of it, the way [`super::ci`] is for ci:
//!
//! - **Names.** A namespace asks for `app`; pg-fc is asked for
//!   `ns_<namespace>_app` (lowercased, `-` and `.` folded to `_`). The
//!   folding is lossy — `team-a` and `team_a` fold alike — so the plugin also
//!   keeps an ownership file and refuses any physical name already in it,
//!   whoever holds it. A namespace can never be handed a database that was
//!   provisioned for another.
//! - **Ownership.** `{database → namespace, name, created_by, created_at}`,
//!   one JSON file beside the plugin records, written with write-then-rename
//!   like them. A namespace lists and deletes only what that file says it
//!   owns; pg-fc's own list is consulted for liveness, never for ownership.
//! - **Credentials.** pg-fc returns the password once. The plugin hands it
//!   back once too, and — unless asked not to — also writes it into the
//!   namespace's own app-lb secret `pg-<name>` (`url`, `host`, `port`,
//!   `database`, `user`, `password`), where a deployment's `env_from` and
//!   tenant CI can read it without anyone copying it around.
//!
//! The operator enables the plugin with pg-fc's dashboard URL and a reference
//! to its password; each namespace installs it. It never installs itself: a
//! database is a VM on the operator's hosts.
//!
//! Deleting a database revokes its credential at pg-fc and forgets the
//! ownership record. pg-fc keeps the VM and its data — purging is an operator
//! action there — and the `pg-<name>` secret is left for the namespace to
//! delete once nothing uses it.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use pg_fc_api::{CreateDatabase, CreatedDatabase, DatabaseInfo, Health};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::ns_proxy::{NamespaceActor, check_url, fail};
use super::{NamespaceScope, Plugin, PluginMeta};
use crate::secrets::{SecretRef, SecretSpec, SecretStore};

pub(crate) const PAGE_HTML: &str = include_str!("../postgres_plugin.html");

/// Provisioning returns once the credential is written; the VM comes up in
/// the background. Generous anyway, so a slow pg-fc is an error, not a hang.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_POLL_SECS: u64 = 30;
const DEFAULT_PG_PORT: u16 = 6432;
const DEFAULT_SSLMODE: &str = "require";
const DEFAULT_MAX_PER_NAMESPACE: usize = 10;
/// Postgres truncates identifiers past 63 bytes, so pg-fc refuses them.
const MAX_IDENTIFIER: usize = 63;
const MAX_NAME: usize = 31;
const SSLMODES: &[&str] = &[
    "disable",
    "allow",
    "prefer",
    "require",
    "verify-ca",
    "verify-full",
];

// ---- configuration --------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresConfig {
    /// pg-fc's dashboard listener (`PG_VM_POOL_DASHBOARD_LISTEN`), where its
    /// admin API is.
    pub url: String,
    /// `PG_VM_POOL_DASHBOARD_USER`. Omit when the dashboard has no auth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// `PG_VM_POOL_DASHBOARD_PASSWORD`, as a reference into app-lb's secret
    /// store: `{"secret": "pg-fc", "key": "password"}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretRef>,
    /// Where clients reach the pooler, for connection strings: the public
    /// name its certificate is for (`pg.us5.heyo.work`). Defaults to the host
    /// in `url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg_host: Option<String>,
    #[serde(default = "default_pg_port")]
    pub pg_port: u16,
    /// The `sslmode` connection strings carry.
    #[serde(default = "default_sslmode")]
    pub sslmode: String,
    /// How many databases one namespace may hold.
    #[serde(default = "default_max_per_namespace")]
    pub max_per_namespace: usize,
    #[serde(default = "default_poll_secs")]
    pub poll_secs: u64,
}

fn default_pg_port() -> u16 {
    DEFAULT_PG_PORT
}
fn default_sslmode() -> String {
    DEFAULT_SSLMODE.into()
}
fn default_max_per_namespace() -> usize {
    DEFAULT_MAX_PER_NAMESPACE
}
fn default_poll_secs() -> u64 {
    DEFAULT_POLL_SECS
}

impl PostgresConfig {
    fn pg_host(&self) -> String {
        self.pg_host.clone().unwrap_or_else(|| {
            url::Url::parse(&self.url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .unwrap_or_else(|| "127.0.0.1".into())
        })
    }
}

fn parse_config(config: &Value) -> Result<PostgresConfig, String> {
    let cfg: PostgresConfig = serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
    check_url(&cfg.url)?;
    if !(5..=3600).contains(&cfg.poll_secs) {
        return Err("poll_secs must be between 5 and 3600".into());
    }
    if let Some(p) = &cfg.password {
        p.validate().map_err(|e| format!("password: {e}"))?;
        if cfg.user.is_none() {
            return Err("a password needs a user".into());
        }
    }
    if !SSLMODES.contains(&cfg.sslmode.as_str()) {
        return Err(format!("sslmode must be one of {}", SSLMODES.join(", ")));
    }
    if !(1..=1000).contains(&cfg.max_per_namespace) {
        return Err("max_per_namespace must be between 1 and 1000".into());
    }
    if cfg.pg_port == 0 {
        return Err("pg_port must not be 0".into());
    }
    if let Some(h) = &cfg.pg_host
        && (h.is_empty() || h.contains(['/', '@', '?', '#', ' ']))
    {
        return Err(format!("pg_host {h:?} is not a host name"));
    }
    Ok(cfg)
}

// ---- names ----------------------------------------------------------------

/// What a namespace may call a database: what pg-fc accepts as an identifier,
/// short enough to leave room for the namespace prefix.
fn is_valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= MAX_NAME
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The database pg-fc is asked for: `ns_<namespace>_<name>`, or `None` when
/// that is longer than Postgres allows. Lossy on purpose (see the module
/// docs), which is why creation also checks the ownership file.
fn physical_name(ns: &str, name: &str) -> Option<String> {
    let ns: String = ns
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' => c,
            'A'..='Z' => c.to_ascii_lowercase(),
            _ => '_',
        })
        .collect();
    let db = format!("ns_{ns}_{name}");
    (db.len() <= MAX_IDENTIFIER).then_some(db)
}

/// The namespace secret a database's credentials are written to.
fn secret_id(name: &str) -> String {
    format!("pg-{name}")
}

/// `postgres://user:password@host:port/database?sslmode=…`, with the
/// password percent-encoded so any generated character survives.
fn connection_url(
    host: &str,
    port: u16,
    database: &str,
    user: &str,
    password: &str,
    sslmode: &str,
) -> Option<String> {
    let mut url = url::Url::parse(&format!("postgres://{host}:{port}/{database}")).ok()?;
    url.set_username(user).ok()?;
    url.set_password(Some(password)).ok()?;
    url.query_pairs_mut().append_pair("sslmode", sslmode);
    Some(url.to_string())
}

// ---- ownership ------------------------------------------------------------

/// One database a namespace owns.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Owned {
    pub namespace: String,
    /// The name the namespace asked for.
    pub name: String,
    /// Who created it, in the form tokens record their minter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct OwnershipFile {
    version: u32,
    /// Physical database name → its owner.
    #[serde(default)]
    databases: BTreeMap<String, Owned>,
}

/// The ownership file, held in memory and rewritten whole on every change.
struct Ownership {
    path: PathBuf,
    records: Mutex<BTreeMap<String, Owned>>,
    /// Why the file could not be read at start-up. While set, nothing is
    /// created or deleted: starting empty would let a namespace claim a name
    /// another one still owns.
    broken: Option<String>,
}

impl Ownership {
    fn open(path: PathBuf) -> Self {
        let (records, broken) = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<OwnershipFile>(&bytes) {
                Ok(f) if f.version == 1 => (f.databases, None),
                Ok(f) => (
                    BTreeMap::new(),
                    Some(format!(
                        "version {} was written by a newer app-lb",
                        f.version
                    )),
                ),
                Err(e) => (BTreeMap::new(), Some(format!("unreadable: {e}"))),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (BTreeMap::new(), None),
            Err(e) => (BTreeMap::new(), Some(e.to_string())),
        };
        if let Some(e) = &broken {
            tracing::error!(path = %path.display(), error = %e,
                "the postgres plugin's ownership file cannot be read; namespaces cannot create or delete databases until it is fixed");
        }
        Self {
            path,
            records: Mutex::new(records),
            broken,
        }
    }

    fn snapshot(&self) -> BTreeMap<String, Owned> {
        self.records.lock().unwrap().clone()
    }

    fn of(&self, ns: &str) -> Vec<(String, Owned)> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, o)| o.namespace == ns)
            .map(|(db, o)| (db.clone(), o.clone()))
            .collect()
    }

    /// Write `next` and, once it is on disk, make it current.
    fn commit(&self, next: BTreeMap<String, Owned>) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OwnershipFile {
            version: 1,
            databases: next,
        };
        let json = serde_json::to_vec_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &self.path)?;
        *self.records.lock().unwrap() = file.databases;
        Ok(())
    }
}

// ---- the plugin -----------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize)]
struct PoolHealth {
    up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    polled_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

pub struct PostgresPlugin {
    me: std::sync::Weak<PostgresPlugin>,
    secrets: Arc<SecretStore>,
    http: reqwest::Client,
    config: RwLock<Option<Arc<PostgresConfig>>>,
    ownership: Ownership,
    /// Held across a create or delete, so two of them cannot both pass the
    /// limit or name checks before either is recorded.
    writes: tokio::sync::Mutex<()>,
    health: RwLock<PoolHealth>,
    poller: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl PostgresPlugin {
    /// `state_dir` holds the ownership file, `postgres.json`.
    pub fn new(secrets: Arc<SecretStore>, state_dir: impl Into<PathBuf>) -> Arc<Self> {
        let ownership = Ownership::open(state_dir.into().join("postgres.json"));
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            secrets,
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("reqwest client builds"),
            config: RwLock::new(None),
            ownership,
            writes: tokio::sync::Mutex::new(()),
            health: RwLock::new(PoolHealth::default()),
            poller: Mutex::new(None),
        })
    }

    fn config(&self) -> Option<Arc<PostgresConfig>> {
        self.config.read().unwrap().clone()
    }

    /// A request to pg-fc's `/api<path>` with its credential attached. The
    /// password is resolved per request, so rotating it needs no re-apply.
    fn request(
        &self,
        cfg: &PostgresConfig,
        method: reqwest::Method,
        path: &str,
    ) -> Result<reqwest::RequestBuilder, String> {
        let url = format!("{}/api{path}", cfg.url.trim_end_matches('/'));
        let mut req = self.http.request(method, url);
        if let Some(user) = &cfg.user {
            let password = match &cfg.password {
                Some(r) => Some(
                    self.secrets
                        .resolve(r)
                        .map_err(|e| format!("cannot resolve pg-fc's password: {e}"))?,
                ),
                None => None,
            };
            req = req.basic_auth(user, password);
        }
        Ok(req)
    }

    /// Send `req` and read pg-fc's answer as `(status, body)`. A 401 means
    /// *app-lb's* stored credential is wrong — passing it through would read
    /// as the caller's own session failing — so it is a 502 here.
    async fn send(&self, req: reqwest::RequestBuilder) -> Result<(StatusCode, Value), Response> {
        let resp = req.send().await.map_err(|e| {
            fail(
                StatusCode::BAD_GATEWAY,
                format!("pg-fc is unreachable: {}", e.without_url()),
            )
        })?;
        let status = resp.status().as_u16();
        if status == 401 {
            return Err(fail(
                StatusCode::BAD_GATEWAY,
                "pg-fc rejected the credentials configured for the postgres plugin",
            ));
        }
        let body = resp.bytes().await.map_err(|e| {
            fail(
                StatusCode::BAD_GATEWAY,
                format!("reading pg-fc's response: {}", e.without_url()),
            )
        })?;
        let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
        Ok((
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            body,
        ))
    }

    async fn poll(&self, cfg: &PostgresConfig) {
        let polled_at = crate::deployment::now_secs();
        let result: Result<Health, String> = async {
            let resp = self
                .request(cfg, reqwest::Method::GET, "/health")?
                .timeout(POLL_TIMEOUT)
                .send()
                .await
                .map_err(|e| format!("/api/health: {}", e.without_url()))?;
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                return Err("pg-fc rejected the configured credentials (401)".to_string());
            }
            if !resp.status().is_success() {
                return Err(format!("/api/health: HTTP {}", resp.status()));
            }
            resp.json::<Health>()
                .await
                .map_err(|e| format!("/api/health: {e}"))
        }
        .await;
        *self.health.write().unwrap() = match result {
            Ok(h) => PoolHealth {
                up: true,
                error: None,
                polled_at,
                version: Some(h.version),
            },
            Err(e) => PoolHealth {
                up: false,
                error: Some(e),
                polled_at,
                version: None,
            },
        };
    }

    fn stop_poller(&self) {
        if let Some(h) = self.poller.lock().unwrap().take() {
            h.abort();
        }
    }
}

#[async_trait]
impl Plugin for PostgresPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "postgres",
            name: "Postgres",
            description: "Dedicated Postgres databases for a namespace on the region's pg-fc pool: \
                 each with its own role and password, named and owned per namespace, with the \
                 credentials written to a namespace secret. The operator points it at pg-fc; each \
                 namespace installs it.",
            config_schema: json!({
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "description": "pg-fc's dashboard listener (PG_VM_POOL_DASHBOARD_LISTEN), e.g. http://127.0.0.1:8080"},
                    "user": {"type": "string", "description": "PG_VM_POOL_DASHBOARD_USER"},
                    "password": {
                        "type": "object",
                        "description": "A secret reference to PG_VM_POOL_DASHBOARD_PASSWORD: {\"secret\": \"pg-fc\", \"key\": \"password\"}.",
                        "required": ["secret"],
                        "properties": {"secret": {"type": "string"}, "key": {"type": "string"}}
                    },
                    "pg_host": {"type": "string", "description": "The pooler's public name, for connection strings, e.g. pg.us5.heyo.work. Defaults to the host in url."},
                    "pg_port": {"type": "integer", "default": DEFAULT_PG_PORT},
                    "sslmode": {"type": "string", "enum": SSLMODES, "default": DEFAULT_SSLMODE},
                    "max_per_namespace": {"type": "integer", "minimum": 1, "maximum": 1000, "default": DEFAULT_MAX_PER_NAMESPACE},
                    "poll_secs": {"type": "integer", "minimum": 5, "maximum": 3600, "default": DEFAULT_POLL_SECS}
                }
            }),
        }
    }

    fn validate(&self, config: &Value) -> Result<(), String> {
        parse_config(config).map(|_| ())
    }

    async fn apply(&self, config: Option<Value>) -> Result<(), String> {
        self.stop_poller();
        let Some(config) = config else {
            *self.config.write().unwrap() = None;
            *self.health.write().unwrap() = PoolHealth::default();
            return Ok(());
        };
        let cfg = Arc::new(parse_config(&config)?);
        *self.config.write().unwrap() = Some(cfg.clone());
        // First poll inline, so enabling reports an unreachable pg-fc on the
        // spot rather than as a quiet "down" later.
        self.poll(&cfg).await;
        let me = self.me.clone();
        let every = Duration::from_secs(cfg.poll_secs);
        let poll_cfg = cfg.clone();
        *self.poller.lock().unwrap() = Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(me) = me.upgrade() else { return };
                me.poll(&poll_cfg).await;
            }
        }));
        match self.health.read().unwrap().error.clone() {
            None => Ok(()),
            Some(e) => Err(format!("pg-fc at {}: {e}", cfg.url)),
        }
    }

    async fn status(&self) -> Value {
        let Some(cfg) = self.config() else {
            return json!({});
        };
        let health = self.health.read().unwrap().clone();
        json!({
            "url": cfg.url,
            "pg_host": cfg.pg_host(),
            "pg_port": cfg.pg_port,
            "up": health.up,
            "error": health.error,
            "version": health.version,
            "polled_at": health.polled_at,
            "databases": self.ownership.snapshot().len(),
            "ownership_error": self.ownership.broken,
        })
    }

    fn per_namespace(&self) -> bool {
        true
    }

    fn validate_install(&self, _namespace: &str, config: &Value) -> Result<(), String> {
        match config {
            Value::Null => Ok(()),
            Value::Object(m) if m.is_empty() => Ok(()),
            _ => Err("the postgres plugin takes no per-namespace configuration; send {}".into()),
        }
    }

    fn namespace_routes(self: Arc<Self>) -> Router {
        Router::new()
            .route("/ui", get(ui))
            .route("/api/databases", get(list_databases).post(create_database))
            .route("/api/databases/:name", delete(delete_database))
            .fallback(|| async { fail(StatusCode::NOT_FOUND, "no postgres plugin route here") })
            .with_state(self)
    }

    fn dashboard_path(&self) -> Option<&'static str> {
        Some("ui")
    }
}

// ---- handlers -------------------------------------------------------------

// The error is the answer to send, built once here rather than at every caller.
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

#[allow(clippy::result_large_err)]
fn configured(p: &PostgresPlugin) -> Result<Arc<PostgresConfig>, Response> {
    p.config().ok_or_else(|| {
        fail(
            StatusCode::CONFLICT,
            "the postgres plugin is not configured",
        )
    })
}

/// `GET …/postgres/ui` — the page.
async fn ui(req: Request) -> Response {
    match scope(&req) {
        Ok(ns) => super::page(PAGE_HTML, &ns, &req),
        Err(r) => r,
    }
}

/// `GET …/postgres/api/databases` — this namespace's databases, from the
/// ownership file, with what pg-fc says about each.
async fn list_databases(State(p): State<Arc<PostgresPlugin>>, req: Request) -> Response {
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let cfg = match configured(&p) {
        Ok(c) => c,
        Err(r) => return r,
    };
    // Liveness only, and best effort: a list that fails because pg-fc is down
    // would hide the very names someone needs to go and look at.
    let mut error = None;
    let mut live: HashMap<String, DatabaseInfo> = HashMap::new();
    match p.request(&cfg, reqwest::Method::GET, "/databases") {
        Err(e) => error = Some(e),
        Ok(req) => match p.send(req).await {
            Ok((status, body)) if status.is_success() => {
                match serde_json::from_value::<Vec<DatabaseInfo>>(body) {
                    Ok(rows) => live = rows.into_iter().map(|d| (d.database.clone(), d)).collect(),
                    Err(e) => {
                        error = Some(format!(
                            "pg-fc sent a database list this build cannot read: {e}"
                        ))
                    }
                }
            }
            Ok((status, _)) => {
                error = Some(format!("pg-fc answered {status} for its database list"))
            }
            Err(_) => error = Some("pg-fc could not be asked which databases are live".into()),
        },
    }
    let databases: Vec<Value> = p
        .ownership
        .of(&ns)
        .into_iter()
        .map(|(db, o)| {
            let info = live.get(&db);
            let secret = secret_id(&o.name);
            json!({
                "name": o.name,
                "database": db,
                "user": info.map(|i| i.username.clone()).unwrap_or_else(|| db.clone()),
                "created_by": o.created_by,
                "created_at": o.created_at,
                "secret": p.secrets.get(&ns, &secret).is_some().then_some(secret),
                "live": error.is_none().then_some(info.is_some()),
                "tier": info.and_then(|i| i.tier.clone()),
            })
        })
        .collect();
    axum::Json(json!({
        "namespace": ns,
        "host": cfg.pg_host(),
        "port": cfg.pg_port,
        "sslmode": cfg.sslmode,
        "limit": cfg.max_per_namespace,
        "databases": databases,
        "error": error,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    name: String,
    /// Also write the credentials to the namespace secret `pg-<name>`.
    #[serde(default = "yes")]
    secret: bool,
}

fn yes() -> bool {
    true
}

/// `POST …/postgres/api/databases` — `{name, secret?}`. CRUD tier, like
/// every non-`GET` on a namespace surface.
async fn create_database(State(p): State<Arc<PostgresPlugin>>, req: Request) -> Response {
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let created_by = req
        .extensions()
        .get::<NamespaceActor>()
        .and_then(|a| a.principal.clone());
    let cfg = match configured(&p) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body = match axum::body::to_bytes(req.into_body(), 16 * 1024).await {
        Ok(b) => b,
        Err(_) => return fail(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"),
    };
    let body: CreateBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            return fail(
                StatusCode::BAD_REQUEST,
                format!("expected {{\"name\": …}}: {e}"),
            );
        }
    };
    if !is_valid_name(&body.name) {
        return fail(
            StatusCode::BAD_REQUEST,
            format!(
                "database name {:?}: use 1–{MAX_NAME} lowercase letters, digits or '_', starting with a letter",
                body.name
            ),
        );
    }
    let Some(database) = physical_name(&ns, &body.name) else {
        return fail(
            StatusCode::BAD_REQUEST,
            format!(
                "\"ns_{ns}_{}\" is longer than Postgres' {MAX_IDENTIFIER}-byte limit; choose a shorter name",
                body.name
            ),
        );
    };

    let _held = p.writes.lock().await;
    if let Some(e) = &p.ownership.broken {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "the postgres plugin's ownership file cannot be read ({e}); an operator must fix it"
            ),
        );
    }
    let owned = p.ownership.snapshot();
    let mine = owned.values().filter(|o| o.namespace == ns).count();
    if mine >= cfg.max_per_namespace {
        return fail(
            StatusCode::CONFLICT,
            format!(
                "namespace \"{ns}\" already has {mine} databases, the most this host allows ({})",
                cfg.max_per_namespace
            ),
        );
    }
    if let Some(o) = owned.get(&database) {
        return fail(
            StatusCode::CONFLICT,
            if o.namespace == ns {
                format!(
                    "namespace \"{ns}\" already has a database named {:?}",
                    body.name
                )
            } else {
                // Not who: that is another namespace's business.
                format!("the database {database:?} is taken; choose another name")
            },
        );
    }
    let secret = secret_id(&body.name);
    if body.secret && p.secrets.get(&ns, &secret).is_some() {
        return fail(
            StatusCode::CONFLICT,
            format!(
                "namespace \"{ns}\" already has a secret {secret:?}; delete it first, or create \
                 the database with \"secret\": false"
            ),
        );
    }

    let request = match p.request(&cfg, reqwest::Method::POST, "/databases") {
        Ok(r) => r.json(&CreateDatabase {
            database: database.clone(),
            username: Some(database.clone()),
            password: None,
        }),
        Err(e) => return fail(StatusCode::BAD_GATEWAY, e),
    };
    let created: CreatedDatabase = match p.send(request).await {
        Err(r) => return r,
        Ok((status, body)) if status.is_success() => match serde_json::from_value(body) {
            Ok(c) => c,
            Err(e) => {
                return fail(
                    StatusCode::BAD_GATEWAY,
                    format!("pg-fc created {database:?} but its answer could not be read: {e}"),
                );
            }
        },
        Ok((status, body)) => {
            let why = body["error"]
                .as_str()
                .unwrap_or("no reason given")
                .to_string();
            let code = if status.is_client_error() {
                status
            } else {
                StatusCode::BAD_GATEWAY
            };
            return fail(code, format!("pg-fc refused {database:?}: {why}"));
        }
    };

    let mut next = owned;
    next.insert(
        database.clone(),
        Owned {
            namespace: ns.clone(),
            name: body.name.clone(),
            created_by,
            created_at: crate::deployment::now_secs(),
        },
    );
    if let Err(e) = p.ownership.commit(next) {
        // Unrecorded, the database would belong to nobody, so give it back.
        tracing::error!(database = %database, error = %e, "could not record a postgres database's owner; revoking it");
        if let Ok(r) = p.request(
            &cfg,
            reqwest::Method::DELETE,
            &format!("/databases/{database}"),
        ) {
            let _ = p.send(r).await;
        }
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("the database could not be recorded, so it was revoked: {e}"),
        );
    }
    tracing::info!(namespace = %ns, name = %body.name, database = %database, "postgres database created");

    let host = cfg.pg_host();
    let url = connection_url(
        &host,
        cfg.pg_port,
        &created.database,
        &created.username,
        &created.password,
        &cfg.sslmode,
    );
    let mut secret_written = None;
    let mut secret_error = None;
    if body.secret {
        let mut data = BTreeMap::from([
            ("host".to_string(), host.clone()),
            ("port".to_string(), cfg.pg_port.to_string()),
            ("database".to_string(), created.database.clone()),
            ("user".to_string(), created.username.clone()),
            ("password".to_string(), created.password.clone()),
        ]);
        if let Some(u) = &url {
            data.insert("url".into(), u.clone());
        }
        p.secrets.put(SecretSpec {
            id: secret.clone(),
            namespace: ns.clone(),
            description: Some(format!("Postgres database {} (postgres plugin)", body.name)),
            data,
            updated_at: 0,
        });
        match p.secrets.persist() {
            Ok(()) => secret_written = Some(secret),
            Err(e) => {
                tracing::error!(namespace = %ns, secret = %secret, error = %e, "failed to persist a postgres plugin secret");
                secret_error = Some(format!("the secret {secret:?} was not saved: {e}"));
            }
        }
    }
    let mut out = (
        StatusCode::CREATED,
        axum::Json(json!({
            "name": body.name,
            "database": created.database,
            "user": created.username,
            "password": created.password,
            "host": host,
            "port": cfg.pg_port,
            "sslmode": cfg.sslmode,
            "url": url,
            "secret": secret_written,
            "secret_error": secret_error,
            "status": created.status,
            "note": "This is the only time the password is shown.",
        })),
    )
        .into_response();
    out.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    out
}

/// `DELETE …/postgres/api/databases/:name` — revoke the credential and forget
/// the database. Data stays on pg-fc; the secret stays in the namespace.
async fn delete_database(
    State(p): State<Arc<PostgresPlugin>>,
    Path(name): Path<String>,
    req: Request,
) -> Response {
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let cfg = match configured(&p) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let _held = p.writes.lock().await;
    if let Some(e) = &p.ownership.broken {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "the postgres plugin's ownership file cannot be read ({e}); an operator must fix it"
            ),
        );
    }
    let mut owned = p.ownership.snapshot();
    let Some(database) = owned
        .iter()
        .find(|(_, o)| o.namespace == ns && o.name == name)
        .map(|(db, _)| db.clone())
    else {
        return fail(
            StatusCode::NOT_FOUND,
            format!("namespace \"{ns}\" has no database named {name:?}"),
        );
    };
    let request = match p.request(
        &cfg,
        reqwest::Method::DELETE,
        &format!("/databases/{database}"),
    ) {
        Ok(r) => r,
        Err(e) => return fail(StatusCode::BAD_GATEWAY, e),
    };
    match p.send(request).await {
        Err(r) => return r,
        // Already gone at pg-fc is as good as revoked.
        Ok((status, _)) if status.is_success() || status == StatusCode::NOT_FOUND => {}
        Ok((status, body)) => {
            let why = body["error"].as_str().unwrap_or("no reason given");
            return fail(
                StatusCode::BAD_GATEWAY,
                format!("pg-fc could not revoke {database:?} ({status}): {why}"),
            );
        }
    }
    owned.remove(&database);
    if let Err(e) = p.ownership.commit(owned) {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "the credential was revoked but the ownership record could not be removed: {e}"
            ),
        );
    }
    tracing::info!(namespace = %ns, name = %name, database = %database, "postgres database deleted");
    let secret = secret_id(&name);
    let kept = p.secrets.get(&ns, &secret).is_some().then_some(secret);
    axum::Json(json!({
        "deleted": name,
        "database": database,
        "secret_kept": kept,
        "note": "The credential is revoked. The database's data stays on the pool until an \
                 operator purges it, and any pg-* secret is left in place: delete it from the \
                 Secrets page once nothing uses it.",
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{PluginHost, PluginStore};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("app-lb-postgres-{}-{tag}-{n}", std::process::id()));
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

    fn secrets(dir: &TempDir, password: &str) -> Arc<SecretStore> {
        let store = Arc::new(SecretStore::new(dir.0.join("secrets.json"), None));
        store.put(SecretSpec {
            id: "pg-fc".into(),
            namespace: crate::config::DEFAULT_NAMESPACE.into(),
            description: None,
            data: [("password".to_string(), password.to_string())].into(),
            updated_at: 0,
        });
        store
    }

    /// A pg-fc that insists on the right Basic credential and keeps a real
    /// list, so create, list and delete see each other.
    async fn fake_pg_fc() -> String {
        let expected = format!(
            "Basic {}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "admin:s3cret")
        );
        let dbs: Arc<Mutex<BTreeMap<String, String>>> = Arc::default();
        let app = Router::new().fallback(move |req: Request| {
            let expected = expected.clone();
            let dbs = dbs.clone();
            async move {
                let auth = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
                if auth != expected {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                let path = req.uri().path().to_string();
                let method = req.method().clone();
                match (method.as_str(), path.as_str()) {
                    ("GET", "/api/health") => axum::Json(json!({"version": "9.9.9", "uptime_secs": 1,
                        "listen": "x", "warm_schemas": 0, "known_schemas": 0, "tls": true, "replication": false}))
                        .into_response(),
                    ("GET", "/api/databases") => {
                        let rows: Vec<Value> = dbs.lock().unwrap().iter()
                            .map(|(d, u)| json!({"database": d, "username": u, "created_at": 1, "tier": "warm"}))
                            .collect();
                        axum::Json(rows).into_response()
                    }
                    ("POST", "/api/databases") => {
                        let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap();
                        let c: CreateDatabase = serde_json::from_slice(&body).unwrap();
                        let mut dbs = dbs.lock().unwrap();
                        if dbs.contains_key(&c.database) {
                            return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "exists"}))).into_response();
                        }
                        let user = c.username.unwrap_or_else(|| c.database.clone());
                        dbs.insert(c.database.clone(), user.clone());
                        (StatusCode::CREATED, axum::Json(json!({"database": c.database, "username": user,
                            "password": "p@ss/w:rd", "status": "provisioning", "created_at": 1})))
                            .into_response()
                    }
                    ("DELETE", p) if p.starts_with("/api/databases/") => {
                        match dbs.lock().unwrap().remove(&p["/api/databases/".len()..]) {
                            Some(_) => StatusCode::NO_CONTENT.into_response(),
                            None => (StatusCode::NOT_FOUND, axum::Json(json!({"error": "no such"}))).into_response(),
                        }
                    }
                    _ => StatusCode::NOT_FOUND.into_response(),
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn configured_for(url: &str) -> Value {
        json!({"url": url, "user": "admin", "password": {"secret": "pg-fc", "key": "password"},
            "pg_host": "pg.example", "max_per_namespace": 2})
    }

    async fn setup(
        tag: &str,
        password: &str,
    ) -> (TempDir, Arc<SecretStore>, Arc<PostgresPlugin>, PluginHost) {
        let url = fake_pg_fc().await;
        let dir = TempDir::new(tag);
        let store = secrets(&dir, password);
        let plugin = PostgresPlugin::new(store.clone(), dir.0.join("state"));
        let host = PluginHost::new(
            vec![plugin.clone()],
            PluginStore::new(dir.0.join("plugins")),
        );
        let _ = host
            .set("postgres", true, Some(configured_for(&url)))
            .await
            .unwrap();
        (dir, store, plugin, host)
    }

    async fn call(
        host: &PluginHost,
        ns: &str,
        method: &str,
        uri: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut req = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(if body.is_null() {
                String::new()
            } else {
                body.to_string()
            }))
            .unwrap();
        req.extensions_mut().insert(NamespaceActor {
            principal: Some(format!("user:{ns}-admin")),
            email: None,
            admin: true,
        });
        let resp = host.dispatch_namespace("postgres", ns, req).await;
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
        assert!(parse_config(&json!({"url": "http://127.0.0.1:8080"})).is_ok());
        assert!(parse_config(&configured_for("http://127.0.0.1:8080")).is_ok());
        for bad in [
            json!({}),
            json!({"url": "ftp://x"}),
            json!({"url": "http://x", "password": {"secret": "pg-fc"}}),
            json!({"url": "http://x", "sslmode": "sometimes"}),
            json!({"url": "http://x", "max_per_namespace": 0}),
            json!({"url": "http://x", "pg_host": "a/b"}),
            json!({"url": "http://x", "poll_secs": 1}),
            json!({"url": "http://x", "database": "shared"}),
        ] {
            assert!(parse_config(&bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn names_map_onto_the_namespace_and_stay_inside_postgres_limits() {
        assert_eq!(
            physical_name("team-a", "app").as_deref(),
            Some("ns_team_a_app")
        );
        assert_eq!(
            physical_name("Team.A", "app").as_deref(),
            Some("ns_team_a_app")
        );
        assert_eq!(physical_name(&"n".repeat(60), "app"), None);
        for ok in ["app", "a", "app_2", &"a".repeat(MAX_NAME)] {
            assert!(is_valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            "App",
            "2app",
            "_app",
            "app-db",
            "app.db",
            &"a".repeat(MAX_NAME + 1),
        ] {
            assert!(!is_valid_name(bad), "{bad}");
        }
        let url = connection_url(
            "pg.example",
            6432,
            "ns_a_app",
            "ns_a_app",
            "p@ss/w:rd",
            "require",
        )
        .unwrap();
        assert_eq!(
            url,
            "postgres://ns_a_app:p%40ss%2Fw%3Ard@pg.example:6432/ns_a_app?sslmode=require"
        );
    }

    #[tokio::test]
    async fn a_namespace_creates_lists_and_deletes_only_its_own_databases() {
        let (dir, store, plugin, host) = setup("flow", "s3cret").await;
        assert!(
            host.auto_install("team-a", None).await.is_empty(),
            "opt-in per namespace"
        );
        for ns in ["team-a", "team-b", "team_a"] {
            host.install("postgres", ns, json!({}), None).await.unwrap();
        }

        let (status, v) = call(
            &host,
            "team-a",
            "POST",
            "/api/databases",
            json!({"name": "app"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{v}");
        assert_eq!(v["database"], "ns_team_a_app");
        assert_eq!(v["user"], "ns_team_a_app");
        assert_eq!(v["password"], "p@ss/w:rd");
        assert_eq!(v["secret"], "pg-app");
        assert_eq!(
            v["url"],
            "postgres://ns_team_a_app:p%40ss%2Fw%3Ard@pg.example:6432/ns_team_a_app?sslmode=require"
        );

        // The secret is in the creating namespace and nowhere else, and is
        // on disk, not only in memory.
        let secret = store.get("team-a", "pg-app").expect("written");
        assert_eq!(secret.data["password"], "p@ss/w:rd");
        assert_eq!(secret.data["host"], "pg.example");
        assert_eq!(secret.data["port"], "6432");
        assert_eq!(secret.data["database"], "ns_team_a_app");
        assert!(store.get("team-b", "pg-app").is_none());
        let reloaded = SecretStore::new(dir.0.join("secrets.json"), None);
        reloaded.load().unwrap();
        assert!(reloaded.get("team-a", "pg-app").is_some());

        // `team_a` folds onto the same physical name and is refused.
        let (status, v) = call(
            &host,
            "team_a",
            "POST",
            "/api/databases",
            json!({"name": "app", "secret": false}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{v}");
        assert!(
            !v["error"].as_str().unwrap().contains("team-a"),
            "the owner is not named: {v}"
        );
        // The same name twice in one namespace is refused too.
        let (status, _) = call(
            &host,
            "team-a",
            "POST",
            "/api/databases",
            json!({"name": "app", "secret": false}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, _) = call(
            &host,
            "team-a",
            "POST",
            "/api/databases",
            json!({"name": "Bad-Name"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // team-b sees none of it and cannot delete it.
        let (status, v) = call(&host, "team-b", "GET", "/api/databases", Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["databases"], json!([]));
        let (status, _) = call(&host, "team-b", "DELETE", "/api/databases/app", Value::Null).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, v) = call(&host, "team-a", "GET", "/api/databases", Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["databases"][0]["name"], "app");
        assert_eq!(v["databases"][0]["live"], true);
        assert_eq!(v["databases"][0]["secret"], "pg-app");
        assert_eq!(v["databases"][0]["created_by"], "user:team-a-admin");
        assert_eq!(v["host"], "pg.example");
        assert!(
            !v.to_string().contains("p@ss"),
            "a list never carries a password"
        );

        // The limit is per namespace.
        let (status, _) = call(
            &host,
            "team-a",
            "POST",
            "/api/databases",
            json!({"name": "two", "secret": false}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, v) = call(
            &host,
            "team-a",
            "POST",
            "/api/databases",
            json!({"name": "three", "secret": false}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{v}");

        // Ownership survives a restart.
        let again = PostgresPlugin::new(store.clone(), dir.0.join("state"));
        assert_eq!(again.ownership.of("team-a").len(), 2);

        let (status, v) = call(&host, "team-a", "DELETE", "/api/databases/app", Value::Null).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert_eq!(v["secret_kept"], "pg-app");
        assert_eq!(plugin.ownership.of("team-a").len(), 1);
        let (_, v) = call(&host, "team-a", "GET", "/api/databases", Value::Null).await;
        assert_eq!(v["databases"].as_array().unwrap().len(), 1);
        plugin.apply(None).await.unwrap();
    }

    #[tokio::test]
    async fn a_wrong_stored_credential_is_a_bad_gateway_not_the_callers_401() {
        let (_dir, _store, plugin, host) = setup("wrong", "wrong").await;
        assert!(
            host.get("postgres")
                .await
                .unwrap()
                .last_error
                .unwrap()
                .contains("rejected")
        );
        host.install("postgres", "a", json!({}), None)
            .await
            .unwrap();
        let (status, v) = call(&host, "a", "POST", "/api/databases", json!({"name": "app"})).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{v}");
        assert!(
            plugin.ownership.of("a").is_empty(),
            "nothing recorded on a failure"
        );
        plugin.apply(None).await.unwrap();
    }

    #[tokio::test]
    async fn the_page_is_served_for_the_namespace() {
        let (_dir, _store, plugin, host) = setup("page", "s3cret").await;
        host.install("postgres", "team-a", json!({}), None)
            .await
            .unwrap();
        let req = axum::http::Request::get("/ui")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = host.dispatch_namespace("postgres", "team-a", req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["x-frame-options"], "SAMEORIGIN");
        let html = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = String::from_utf8_lossy(&html);
        assert!(html.contains(r#"<meta name="plugin-namespace" content="team-a">"#));
        assert!(!html.contains("{{"), "an unfilled placeholder shipped");
        plugin.apply(None).await.unwrap();
    }
}
