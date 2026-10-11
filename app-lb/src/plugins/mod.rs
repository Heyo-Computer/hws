//! Plugins: optional capabilities compiled into app-lb and switched on at runtime.
//!
//! Every other optional integration app-lb has — log shipping, discovery,
//! Incus, Route53 — is decided by an env var at startup and cannot change
//! without a restart. A plugin is the same idea with the switch moved to the
//! admin API: the set of plugins is fixed at compile time (there is no dynamic
//! loading, and there is not going to be), but whether each one runs, and with
//! what configuration, is an object on disk that the dashboard's Plugins page
//! and `heyctl plugins` edit.
//!
//! ## What a plugin owns
//!
//! Its own tasks. pingora's background services are started once and never
//! stopped, which is the wrong shape for something an operator can switch off,
//! so [`Plugin::apply`] is handed the new configuration (or `None`) and starts,
//! restarts or stops whatever it runs. The host serialises calls per plugin, so
//! an implementation never sees two `apply`s at once.
//!
//! Its own routes. Each plugin contributes a view-tier and a CRUD-tier router,
//! nested at `/api/plugins/<id>` and put behind the same gate as the rest of the
//! admin API. They are always mounted — the set is static — and answer 409
//! while the plugin is disabled, which is a more useful answer than a 404 on a
//! route the page knows exists.
//!
//! ## Credentials
//!
//! A plugin's configuration is stored in plain JSON beside the deployment
//! state, so it must never carry a credential. Fields that need one take a
//! [`crate::secrets::SecretRef`] and resolve it through the secret store when
//! they use it — the same indirection a deployment's git credential uses.
//!
//! ## Installing into a namespace
//!
//! Most plugins are host capabilities an operator switches on for the fleet.
//! A plugin that answers [`Plugin::per_namespace`] is also something a
//! namespace *installs*: the operator still enables it (and holds whatever
//! credential it needs), and then each namespace's administrator decides
//! whether their namespace uses it. Installs live on the plugin's record, keyed
//! by namespace, and the plugin's namespace surface is served at
//! `/namespaces/<ns>/plugins/<id>/…` — behind the namespace wall rather than
//! the fleet one, so a namespace token reaches its own namespace's view of the
//! plugin and nobody else's. The plugin is told which namespace a request is
//! for through a [`NamespaceScope`] extension; it never reads it off a path
//! the caller wrote.
//!
//! A plugin whose namespace surface includes a page answers
//! [`Plugin::dashboard_path`], and app-lb's plugin console at
//! `/namespaces/<ns>/plugin-console/<id>` frames that page under its own
//! navigation. A plugin backed by a fleet service proxies that page from the
//! service; one that is app-lb all the way down serves its own with [`page`].
//!
//! ## Machine routes
//!
//! Some plugins are also called *by* the service they front: ci asks app-lb
//! for a tenant run's secrets. Those callers hold the plugin's own shared
//! token, not an app-lb credential, so [`Plugin::machine_routes`] are mounted
//! at `/api/plugins/<id>/machine/…` outside the admin gate, answer 404 while
//! the plugin is disabled, and authenticate every request themselves.

pub mod ci;
pub mod ns_proxy;
pub mod obs;
pub mod pgfc;
pub mod postgres;
pub mod remote;
pub mod secrets;
pub mod vapi;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// What the Plugins page shows about a plugin before it is switched on.
#[derive(Debug, Clone, Serialize)]
pub struct PluginMeta {
    /// Stable identifier: the file name on disk and the path segment under
    /// `/api/plugins`. Lowercase ASCII, digits and `-`.
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    /// JSON Schema for the configuration object, for the page's editor and for
    /// `heyctl plugins set`. Advisory: [`Plugin::validate`] is the authority.
    pub config_schema: Value,
}

/// A built-in plugin.
#[async_trait]
pub trait Plugin: Send + Sync + 'static {
    fn meta(&self) -> PluginMeta;

    /// Reject a configuration before it is persisted. The message is returned
    /// to the caller as a 400, so it should say what to change.
    fn validate(&self, _config: &Value) -> Result<(), String> {
        Ok(())
    }

    /// Start, reconfigure or (with `None`) stop the plugin.
    ///
    /// An error leaves the plugin's record as written — the operator asked for
    /// it, and a transient failure (heyvmd down, a peer unreachable) should
    /// retry on the next start rather than silently revert — and is reported
    /// on the plugin's status as `last_error`.
    async fn apply(&self, config: Option<Value>) -> Result<(), String>;

    /// Live status for the page: whatever the plugin wants an operator to see.
    async fn status(&self) -> Value;

    /// View-tier routes, relative to `/api/plugins/<id>`.
    fn view_routes(self: Arc<Self>) -> Router {
        Router::new()
    }

    /// CRUD-tier routes, relative to `/api/plugins/<id>`.
    fn crud_routes(self: Arc<Self>) -> Router {
        Router::new()
    }

    /// Whether a namespace can install this plugin. See the module docs.
    fn per_namespace(&self) -> bool {
        false
    }

    /// Whether, under this fleet configuration, the plugin installs itself in
    /// every namespace: when one is created, when a deployment first lands
    /// in one, and in every known namespace when the plugin is switched on.
    fn auto_install(&self, _config: &Value) -> bool {
        false
    }

    /// Reject a namespace's install configuration before it is persisted.
    fn validate_install(&self, _namespace: &str, _config: &Value) -> Result<(), String> {
        Ok(())
    }

    /// The namespace surface, served at `/namespaces/<ns>/plugins/<id>/…` and
    /// only once the plugin is enabled and installed there. Requests arrive
    /// with that prefix stripped and a [`NamespaceScope`] extension naming the
    /// namespace. A `GET` is admitted on the view tier and every other method
    /// on the CRUD tier, so a route that changes something must not be a `GET`.
    fn namespace_routes(self: Arc<Self>) -> Router {
        Router::new()
    }

    /// Where the plugin's dashboard page sits on its namespace surface,
    /// relative to `/namespaces/<ns>/plugins/<id>/` (`"ui"`), for a plugin
    /// that has one. The plugin console frames it.
    fn dashboard_path(&self) -> Option<&'static str> {
        None
    }

    /// Routes for the service behind the plugin rather than for a person,
    /// relative to `/api/plugins/<id>/machine`. Mounted **outside** the admin
    /// gate and only reachable while the plugin is enabled, so each route must
    /// authenticate its caller itself — with a credential the plugin holds,
    /// compared in constant time. Requests arrive with an [`Installs`]
    /// extension naming the namespaces that installed the plugin.
    fn machine_routes(self: Arc<Self>) -> Router {
        Router::new()
    }
}

/// The namespaces that have installed a plugin, as of the request. Handed to
/// [`Plugin::machine_routes`], which have no namespace wall in front of them
/// and so must check an install themselves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Installs(pub BTreeSet<String>);

/// The namespace a request to a plugin's namespace surface is for, already
/// checked against the caller's reach by the admin gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceScope(pub String);

/// One namespace's install of a plugin.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct NamespaceInstall {
    pub installed_at: u64,
    /// Who installed it, in the form tokens record their minter.
    #[serde(default)]
    pub installed_by: Option<String>,
    #[serde(default)]
    pub config: Value,
}

/// One plugin's persisted state.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct PluginRecord {
    pub enabled: bool,
    /// The plugin's configuration, kept while it is disabled so switching it
    /// back on does not mean typing it in again.
    #[serde(default)]
    pub config: Value,
    #[serde(default)]
    pub updated_at: u64,
    /// Namespaces that installed this plugin. Survives disabling, like the
    /// configuration: switching the plugin off pauses every install rather
    /// than forgetting them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub installs: BTreeMap<String, NamespaceInstall>,
    /// Namespaces whose administrator uninstalled this plugin. Automatic
    /// installs ([`PluginHost::auto_install`]) skip them, so an opt-out sticks;
    /// an explicit install clears it.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub declined: BTreeSet<String>,
}

// ---- the store ------------------------------------------------------------

/// One JSON file per plugin, in the shape `namespaces.rs` uses: an unreadable
/// record loses itself rather than every plugin, and no write rewrites the
/// others.
#[derive(Debug)]
pub struct PluginStore {
    records: ArcSwap<HashMap<String, PluginRecord>>,
    dir: PathBuf,
}

impl PluginStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            records: ArcSwap::from_pointee(HashMap::new()),
            dir: dir.into(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn get(&self, id: &str) -> Option<PluginRecord> {
        self.records.load().get(id).cloned()
    }

    /// Replace, then persist. Write-then-rename, so a crash mid-write leaves
    /// the previous version.
    pub fn put(&self, id: &str, record: PluginRecord) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(&self.dir)?;
        let json = serde_json::to_vec_pretty(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let path = self.dir.join(format!("{id}.json"));
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &path)?;
        let mut next = (**self.records.load()).clone();
        next.insert(id.to_string(), record);
        self.records.store(Arc::new(next));
        Ok(())
    }

    /// Load every record, skipping any that will not parse. Returns
    /// `(loaded, skipped)`, like the other object stores.
    pub fn load(&self) -> (usize, usize) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return (0, 0);
        };
        let mut loaded = HashMap::new();
        let mut skipped = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(id) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .filter(|s| is_valid_id(s))
            else {
                skipped += 1;
                continue;
            };
            match std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice::<PluginRecord>(&b).ok())
            {
                Some(record) => {
                    loaded.insert(id.to_string(), record);
                }
                None => {
                    tracing::warn!(
                        "skipping unreadable plugin record {}; it is still on disk",
                        path.display()
                    );
                    skipped += 1;
                }
            }
        }
        let n = loaded.len();
        self.records.store(Arc::new(loaded));
        (n, skipped)
    }
}

fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `app-lb-state.json` -> `app-lb-plugins.d`, beside it.
pub fn plugin_dir(state_path: &str) -> PathBuf {
    let path = Path::new(state_path);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("app-lb-state");
    let name = match stem.strip_suffix("-state") {
        Some(prefix) => format!("{prefix}-plugins.d"),
        None => format!("{stem}-plugins.d"),
    };
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

// ---- the host -------------------------------------------------------------

/// What `GET /api/plugins` returns per plugin.
#[derive(Debug, Clone, Serialize)]
pub struct PluginView {
    #[serde(flatten)]
    pub meta: PluginMeta,
    /// Whether namespaces install this plugin themselves.
    pub per_namespace: bool,
    /// The dashboard page on the namespace surface; see [`Plugin::dashboard_path`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<&'static str>,
    /// The namespaces that have, for a per-namespace plugin.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub installed_in: Vec<String>,
    pub enabled: bool,
    pub config: Value,
    pub updated_at: u64,
    /// Why the last `apply` failed, if it did. Cleared by the next success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub status: Value,
}

/// What `GET /namespaces/<ns>/plugins` returns per installable plugin.
#[derive(Debug, Clone, Serialize)]
pub struct NamespacePluginView {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    /// The fleet switch. An install of a disabled plugin is kept but idle.
    pub enabled: bool,
    pub installed: bool,
    /// The dashboard page on the namespace surface; see [`Plugin::dashboard_path`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
}

/// What `GET /api/plugins/<id>/installs` returns: the fleet-wide list a
/// collector reads to learn which namespaces opted in.
#[derive(Debug, Clone, Serialize)]
pub struct InstallsView {
    pub plugin: &'static str,
    pub enabled: bool,
    pub namespaces: Vec<String>,
    pub installs: BTreeMap<String, NamespaceInstall>,
}

#[derive(Debug)]
pub enum SetError {
    NotFound,
    Invalid(String),
    Io(std::io::Error),
    /// The fleet switch is off, so a namespace cannot install it.
    Disabled(&'static str),
}

impl std::fmt::Display for SetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SetError::NotFound => f.write_str("no such plugin"),
            SetError::Invalid(m) => write!(f, "invalid configuration: {m}"),
            SetError::Io(e) => write!(f, "could not save the plugin record: {e}"),
            SetError::Disabled(id) => write!(
                f,
                "the {id} plugin is disabled on this host; an operator enables it with \
                 `heyctl plugins enable {id}` before a namespace can install it"
            ),
        }
    }
}

struct Slot {
    plugin: Arc<dyn Plugin>,
    /// The plugin's namespace surface, built once: the set is static.
    namespace_router: Option<Router>,
    /// Held across `apply`, so two edits to one plugin cannot interleave.
    lock: tokio::sync::Mutex<()>,
    last_error: std::sync::Mutex<Option<String>>,
}

/// The built-in plugins and their records.
pub struct PluginHost {
    slots: Vec<Arc<Slot>>,
    store: PluginStore,
}

impl PluginHost {
    pub fn new(plugins: Vec<Arc<dyn Plugin>>, store: PluginStore) -> Self {
        let slots = plugins
            .into_iter()
            .map(|plugin| {
                debug_assert!(
                    is_valid_id(plugin.meta().id),
                    "plugin id {:?}",
                    plugin.meta().id
                );
                // Not filtered on `has_routes`: a proxy is a fallback, which
                // that does not count.
                let namespace_router = plugin
                    .per_namespace()
                    .then(|| plugin.clone().namespace_routes());
                Arc::new(Slot {
                    plugin,
                    namespace_router,
                    lock: tokio::sync::Mutex::new(()),
                    last_error: std::sync::Mutex::new(None),
                })
            })
            .collect();
        Self { slots, store }
    }

    #[cfg(test)]
    pub fn store(&self) -> &PluginStore {
        &self.store
    }

    fn slot(&self, id: &str) -> Option<&Arc<Slot>> {
        self.slots.iter().find(|s| s.plugin.meta().id == id)
    }

    pub fn is_enabled(&self, id: &str) -> bool {
        self.store.get(id).is_some_and(|r| r.enabled)
    }

    pub async fn list(&self) -> Vec<PluginView> {
        let mut out = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            out.push(self.view(slot).await);
        }
        out
    }

    pub async fn get(&self, id: &str) -> Option<PluginView> {
        let slot = self.slot(id)?;
        Some(self.view(slot).await)
    }

    async fn view(&self, slot: &Slot) -> PluginView {
        let meta = slot.plugin.meta();
        let record = self.store.get(meta.id).unwrap_or_default();
        // Read before the await: the guard is a std mutex and must not be
        // held across it.
        let last_error = slot.last_error.lock().unwrap().clone();
        let status = slot.plugin.status().await;
        PluginView {
            per_namespace: slot.plugin.per_namespace(),
            dashboard: slot.plugin.dashboard_path(),
            installed_in: record.installs.keys().cloned().collect(),
            enabled: record.enabled,
            config: record.config,
            updated_at: record.updated_at,
            last_error,
            status,
            meta,
        }
    }

    /// Write a plugin's record and apply it. `config: None` keeps the stored
    /// configuration, which is what enable/disable want.
    pub async fn set(
        &self,
        id: &str,
        enabled: bool,
        config: Option<Value>,
    ) -> Result<PluginView, SetError> {
        let slot = self.slot(id).ok_or(SetError::NotFound)?.clone();
        let _held = slot.lock.lock().await;
        let current = self.store.get(id).unwrap_or_default();
        let config = config.unwrap_or(current.config);
        if enabled {
            slot.plugin.validate(&config).map_err(SetError::Invalid)?;
        }
        let record = PluginRecord {
            enabled,
            config: config.clone(),
            updated_at: crate::deployment::now_secs(),
            installs: current.installs,
            declined: current.declined,
        };
        self.store.put(id, record).map_err(SetError::Io)?;
        self.apply_slot(&slot, enabled.then_some(config)).await;
        drop(_held);
        Ok(self.view(&slot).await)
    }

    fn installable(&self, id: &str) -> Option<&Arc<Slot>> {
        self.slot(id).filter(|s| s.plugin.per_namespace())
    }

    fn namespace_view(&self, slot: &Slot, ns: &str) -> NamespacePluginView {
        let meta = slot.plugin.meta();
        let record = self.store.get(meta.id).unwrap_or_default();
        let install = record.installs.get(ns);
        NamespacePluginView {
            id: meta.id,
            name: meta.name,
            description: meta.description,
            enabled: record.enabled,
            installed: install.is_some(),
            dashboard: slot.plugin.dashboard_path(),
            installed_at: install.map(|i| i.installed_at),
            installed_by: install.and_then(|i| i.installed_by.clone()),
            config: install.map(|i| i.config.clone()),
        }
    }

    /// One installable plugin as `ns` sees it.
    pub fn namespace_plugin(&self, id: &str, ns: &str) -> Option<NamespacePluginView> {
        self.installable(id).map(|s| self.namespace_view(s, ns))
    }

    /// Every plugin a namespace may install, and whether `ns` has.
    pub fn namespace_plugins(&self, ns: &str) -> Vec<NamespacePluginView> {
        self.slots
            .iter()
            .filter(|s| s.plugin.per_namespace())
            .map(|s| self.namespace_view(s, ns))
            .collect()
    }

    pub fn is_installed(&self, id: &str, ns: &str) -> bool {
        self.store
            .get(id)
            .is_some_and(|r| r.installs.contains_key(ns))
    }

    /// The fleet-wide install list of one per-namespace plugin.
    pub fn installs(&self, id: &str) -> Option<InstallsView> {
        let slot = self.installable(id)?;
        let meta = slot.plugin.meta();
        let record = self.store.get(meta.id).unwrap_or_default();
        Some(InstallsView {
            plugin: meta.id,
            enabled: record.enabled,
            namespaces: record.installs.keys().cloned().collect(),
            installs: record.installs,
        })
    }

    /// Install `id` into `ns`, or replace that install's configuration.
    pub async fn install(
        &self,
        id: &str,
        ns: &str,
        config: Value,
        by: Option<String>,
    ) -> Result<NamespacePluginView, SetError> {
        let slot = self.installable(id).ok_or(SetError::NotFound)?.clone();
        let _held = slot.lock.lock().await;
        let mut record = self.store.get(id).unwrap_or_default();
        if !record.enabled {
            return Err(SetError::Disabled(slot.plugin.meta().id));
        }
        slot.plugin
            .validate_install(ns, &config)
            .map_err(SetError::Invalid)?;
        let installed_at = record
            .installs
            .get(ns)
            .map(|i| i.installed_at)
            .unwrap_or_else(crate::deployment::now_secs);
        record.installs.insert(
            ns.to_string(),
            NamespaceInstall {
                installed_at,
                installed_by: by,
                config,
            },
        );
        record.declined.remove(ns);
        self.store.put(id, record).map_err(SetError::Io)?;
        tracing::info!(plugin = id, namespace = ns, "plugin installed in namespace");
        Ok(self.namespace_view(&slot, ns))
    }

    /// Remove `id` from `ns`. Allowed while the plugin is disabled — leaving
    /// should never need the operator.
    pub async fn uninstall(&self, id: &str, ns: &str) -> Result<NamespacePluginView, SetError> {
        let slot = self.installable(id).ok_or(SetError::NotFound)?.clone();
        let _held = slot.lock.lock().await;
        let mut record = self.store.get(id).unwrap_or_default();
        let removed = record.installs.remove(ns).is_some();
        let newly_declined = record.declined.insert(ns.to_string());
        if removed || newly_declined {
            self.store.put(id, record).map_err(SetError::Io)?;
            tracing::info!(
                plugin = id,
                namespace = ns,
                "plugin uninstalled from namespace"
            );
        }
        Ok(self.namespace_view(&slot, ns))
    }

    /// Install every enabled, auto-installing plugin into `ns`, unless `ns`
    /// already has it or declined it. Idempotent and cheap when there is
    /// nothing to do, so callers run it on every namespace event rather than
    /// working out whether the namespace is new. Returns what it installed.
    pub async fn auto_install(&self, ns: &str, by: Option<String>) -> Vec<&'static str> {
        let mut installed = Vec::new();
        for slot in self.slots.iter().filter(|s| s.plugin.per_namespace()) {
            let id = slot.plugin.meta().id;
            let Some(record) = self.store.get(id) else {
                continue;
            };
            if !record.enabled
                || !slot.plugin.auto_install(&record.config)
                || record.installs.contains_key(ns)
                || record.declined.contains(ns)
            {
                continue;
            }
            match self
                .install(id, ns, Value::Object(Default::default()), by.clone())
                .await
            {
                Ok(_) => installed.push(id),
                Err(e) => {
                    tracing::warn!(plugin = id, namespace = ns, error = %e, "automatic plugin install failed")
                }
            }
        }
        installed
    }

    /// Serve one request on a plugin's namespace surface. `req`'s URI is
    /// already relative to `/namespaces/<ns>/plugins/<id>`; the gate has
    /// already checked the caller reaches `ns`.
    pub async fn dispatch_namespace(&self, id: &str, ns: &str, mut req: Request) -> Response {
        let Some(slot) = self.installable(id) else {
            return plugin_error(
                StatusCode::NOT_FOUND,
                None,
                format!("no plugin named {id:?} can be installed in a namespace"),
            );
        };
        let Some(router) = slot.namespace_router.clone() else {
            unreachable!("installable() only returns per-namespace plugins");
        };
        if !self.is_enabled(id) {
            return plugin_error(
                StatusCode::CONFLICT,
                Some("plugin_disabled"),
                SetError::Disabled(slot.plugin.meta().id).to_string(),
            );
        }
        if !self.is_installed(id, ns) {
            return plugin_error(
                StatusCode::CONFLICT,
                Some("plugin_not_installed"),
                format!(
                    "the {id} plugin is not installed in namespace \"{ns}\"; install it with \
                     `heyctl plugins install {id} -n {ns}`"
                ),
            );
        }
        req.extensions_mut().insert(NamespaceScope(ns.to_string()));
        let mut router = router;
        match tower_service::Service::call(&mut router, req).await {
            Ok(resp) => resp,
            Err(never) => match never {},
        }
    }

    async fn apply_slot(&self, slot: &Slot, config: Option<Value>) {
        let id = slot.plugin.meta().id;
        let on = config.is_some();
        let result = slot.plugin.apply(config).await;
        if let Err(e) = &result {
            tracing::warn!(plugin = id, enabled = on, error = %e, "plugin apply failed");
        } else {
            tracing::info!(plugin = id, enabled = on, "plugin applied");
        }
        *slot.last_error.lock().unwrap() = result.err();
    }

    /// Apply every enabled record — the boot path.
    pub async fn start_enabled(&self) {
        for slot in &self.slots {
            let id = slot.plugin.meta().id;
            let Some(record) = self.store.get(id).filter(|r| r.enabled) else {
                continue;
            };
            let _held = slot.lock.lock().await;
            if let Err(e) = slot.plugin.validate(&record.config) {
                tracing::warn!(plugin = id, error = %e, "stored plugin configuration is invalid; not starting it");
                *slot.last_error.lock().unwrap() = Some(format!("invalid configuration: {e}"));
                continue;
            }
            self.apply_slot(slot, Some(record.config)).await;
        }
    }

    /// Stop every plugin — the shutdown path.
    pub async fn stop_all(&self) {
        for slot in &self.slots {
            if self.is_enabled(slot.plugin.meta().id) {
                let _held = slot.lock.lock().await;
                let _ = slot.plugin.apply(None).await;
            }
        }
    }

    /// Every plugin's routes, nested at `/api/plugins/<id>`, as `(view, crud)`.
    ///
    /// Each is wrapped so it answers 409 while its plugin is disabled. The
    /// caller puts the auth gate on top.
    pub fn routers(self: &Arc<Self>) -> (Router, Router) {
        let mut view = Router::new();
        let mut crud = Router::new();
        for slot in &self.slots {
            let id = slot.plugin.meta().id;
            let prefix = format!("/api/plugins/{id}");
            let guard = axum::middleware::from_fn({
                let host = self.clone();
                move |req: Request, next: Next| {
                    let host = host.clone();
                    async move {
                        if host.is_enabled(id) {
                            next.run(req).await
                        } else {
                            disabled(id)
                        }
                    }
                }
            });
            // `route_layer` panics on a router with no routes, and a plugin
            // with nothing to say on one tier is ordinary.
            let v = slot.plugin.clone().view_routes();
            if v.has_routes() {
                view = view.nest(&prefix, v.route_layer(guard.clone()));
            }
            let c = slot.plugin.clone().crud_routes();
            if c.has_routes() {
                crud = crud.nest(&prefix, c.route_layer(guard));
            }
        }
        (view, crud)
    }
}

impl PluginHost {
    /// Every plugin's machine routes, nested at `/api/plugins/<id>/machine`.
    ///
    /// Not gated: see [`Plugin::machine_routes`]. Each answers 404 while its
    /// plugin is disabled — to a caller with no app-lb credential, a switched
    /// off plugin is indistinguishable from one that is not there — and is
    /// handed the plugin's current install list.
    pub fn machine_router(self: &Arc<Self>) -> Router {
        let mut out = Router::new();
        for slot in &self.slots {
            let id = slot.plugin.meta().id;
            let routes = slot.plugin.clone().machine_routes();
            if !routes.has_routes() {
                continue;
            }
            let guard = axum::middleware::from_fn({
                let host = self.clone();
                move |mut req: Request, next: Next| {
                    let host = host.clone();
                    async move {
                        let Some(record) = host.store.get(id).filter(|r| r.enabled) else {
                            return plugin_error(
                                StatusCode::NOT_FOUND,
                                None,
                                format!("no {id} machine route here"),
                            );
                        };
                        req.extensions_mut()
                            .insert(Installs(record.installs.keys().cloned().collect()));
                        next.run(req).await
                    }
                }
            });
            out = out.nest(
                &format!("/api/plugins/{id}/machine"),
                routes.route_layer(guard),
            );
        }
        out
    }
}

/// Serve one of a native plugin's own pages on its namespace surface.
///
/// `html` is the page, compiled in. `{{NAMESPACE}}` in it is filled with the
/// request's namespace, escaped for HTML (the page reads it back from a meta
/// tag rather than having it spliced into script), and `{{HTML_ATTRS}}` with
/// the theme from the request's cookie, as app-lb's own pages are, so the
/// frame's first paint is already the right palette. The response carries the
/// same headers as a proxied page — framable only by app-lb, talking only to
/// app-lb, never cached — because it is served on the admin origin inside the
/// plugin console just the same.
pub fn page(html: &str, ns: &str, req: &Request) -> Response {
    static COOKIES: std::sync::OnceLock<crate::heyo_ui::CookieConfig> = std::sync::OnceLock::new();
    let cookies = req
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok());
    let attrs = COOKIES
        .get_or_init(|| crate::heyo_ui::CookieConfig::from_env("APP_LB"))
        .attrs(cookies);
    let body = html
        .replace("{{HTML_ATTRS}}", &attrs)
        .replace("{{NAMESPACE}}", &crate::heyo_ui::escape(ns));
    let mut out = Response::new(axum::body::Body::from(body));
    out.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    ns_proxy::harden(out.headers_mut());
    out
}

fn plugin_error(status: StatusCode, code: Option<&str>, error: String) -> Response {
    let mut body = serde_json::json!({ "error": error });
    if let Some(code) = code {
        body["code"] = Value::from(code);
    }
    (status, axum::Json(body)).into_response()
}

fn disabled(id: &str) -> Response {
    (
        StatusCode::CONFLICT,
        axum::Json(serde_json::json!({
            "error": format!("the {id} plugin is disabled; enable it on /plugins or with `heyctl plugins enable {id}`"),
        })),
    )
        .into_response()
}

/// Runs the enabled plugins for the life of the process.
pub struct PluginService {
    host: Arc<PluginHost>,
}

impl PluginService {
    pub fn new(host: Arc<PluginHost>) -> Self {
        Self { host }
    }
}

#[async_trait]
impl pingora_core::services::background::BackgroundService for PluginService {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        self.host.start_enabled().await;
        while shutdown.changed().await.is_ok() {
            if *shutdown.borrow() {
                break;
            }
        }
        self.host.stop_all().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("app-lb-plugins-{}-{n}", std::process::id()));
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

    /// Records every `apply` it is given.
    #[derive(Default)]
    struct Probe {
        applied: std::sync::Mutex<Vec<Option<Value>>>,
        fail: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl Plugin for Probe {
        fn meta(&self) -> PluginMeta {
            PluginMeta {
                id: "probe",
                name: "Probe",
                description: "test plugin",
                config_schema: serde_json::json!({"type": "object"}),
            }
        }
        fn validate(&self, config: &Value) -> Result<(), String> {
            if config.get("bad").is_some() {
                Err("bad is not allowed".into())
            } else {
                Ok(())
            }
        }
        async fn apply(&self, config: Option<Value>) -> Result<(), String> {
            self.applied.lock().unwrap().push(config);
            if self.fail.load(Ordering::Relaxed) {
                Err("boom".into())
            } else {
                Ok(())
            }
        }
        async fn status(&self) -> Value {
            serde_json::json!({"applies": self.applied.lock().unwrap().len()})
        }
        fn view_routes(self: Arc<Self>) -> Router {
            Router::new().route("/ping", axum::routing::get(|| async { "pong" }))
        }
    }

    fn host(dir: &TempDir) -> (Arc<Probe>, PluginHost) {
        let probe = Arc::new(Probe::default());
        let host = PluginHost::new(vec![probe.clone()], PluginStore::new(&dir.0));
        (probe, host)
    }

    #[tokio::test]
    async fn enabling_applies_and_persists_and_disabling_keeps_the_config() {
        let dir = TempDir::new();
        let (probe, host) = host(&dir);
        let cfg = serde_json::json!({"x": 1});

        let view = host.set("probe", true, Some(cfg.clone())).await.unwrap();
        assert!(view.enabled);
        assert_eq!(view.status["applies"], 1);

        let view = host.set("probe", false, None).await.unwrap();
        assert!(!view.enabled);
        assert_eq!(view.config, cfg, "disabling must keep the configuration");
        assert_eq!(
            *probe.applied.lock().unwrap(),
            vec![Some(cfg.clone()), None]
        );

        let reloaded = PluginStore::new(&dir.0);
        assert_eq!(reloaded.load(), (1, 0));
        assert_eq!(reloaded.get("probe").unwrap().config, cfg);
    }

    #[tokio::test]
    async fn an_invalid_config_is_refused_before_it_is_written() {
        let dir = TempDir::new();
        let (probe, host) = host(&dir);
        let e = host
            .set("probe", true, Some(serde_json::json!({"bad": 1})))
            .await
            .unwrap_err();
        assert!(matches!(e, SetError::Invalid(_)));
        assert!(host.store().get("probe").is_none());
        assert!(probe.applied.lock().unwrap().is_empty());
        assert!(matches!(
            host.set("nope", true, None).await,
            Err(SetError::NotFound)
        ));
    }

    #[tokio::test]
    async fn a_failed_apply_is_kept_and_reported() {
        let dir = TempDir::new();
        let (probe, host) = host(&dir);
        probe.fail.store(true, Ordering::Relaxed);
        let view = host
            .set("probe", true, Some(serde_json::json!({})))
            .await
            .unwrap();
        assert!(view.enabled, "the operator's intent is kept");
        assert_eq!(view.last_error.as_deref(), Some("boom"));

        probe.fail.store(false, Ordering::Relaxed);
        host.start_enabled().await;
        assert_eq!(host.get("probe").await.unwrap().last_error, None);
    }

    #[tokio::test]
    async fn plugin_routes_are_nested_and_refuse_while_disabled() {
        use tower_service::Service;
        let dir = TempDir::new();
        let (_, host) = host(&dir);
        let host = Arc::new(host);
        let (mut view, crud) = host.routers();
        assert!(
            !crud.has_routes(),
            "a plugin with no CRUD routes contributes none"
        );

        let get = || {
            axum::http::Request::get("/api/plugins/probe/ping")
                .body(axum::body::Body::empty())
                .unwrap()
        };
        assert_eq!(
            view.call(get()).await.unwrap().status(),
            StatusCode::CONFLICT
        );

        host.set("probe", true, Some(serde_json::json!({})))
            .await
            .unwrap();
        let resp = view.call(get()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn unreadable_records_are_skipped_and_the_directory_sits_beside_the_state() {
        let dir = TempDir::new();
        std::fs::write(dir.0.join("good.json"), br#"{"enabled":true,"config":{}}"#).unwrap();
        std::fs::write(dir.0.join("bad.json"), b"{ nope").unwrap();
        std::fs::write(dir.0.join("Bad Name.json"), br#"{"enabled":true}"#).unwrap();
        let store = PluginStore::new(&dir.0);
        assert_eq!(store.load(), (1, 2));
        assert_eq!(
            plugin_dir("/var/lib/app-lb/app-lb-state.json"),
            PathBuf::from("/var/lib/app-lb/app-lb-plugins.d"),
        );
    }
}
