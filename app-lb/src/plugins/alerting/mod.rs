//! The alerting plugin: rules over a namespace's own deployments, HTTP
//! checks against their replicas, and signed webhooks when something fires
//! and when it resolves.
//!
//! The operator enables it (`{}` is a complete configuration); each
//! namespace installs it with its receivers, rules and checks as the install
//! configuration. It never installs itself.
//!
//! ## What it watches
//!
//! Only what app-lb already knows about a deployment: how many replicas are
//! available, the cumulative create-failure / boot-timeout / cold-start
//! timeout counters (as deltas over a window), a static deployment's upstream
//! health, a rollout's progress, and the plugin's own HTTP checks. A rule
//! names one deployment or `*`; either way only deployments whose spec is in
//! the installing namespace are ever evaluated or probed — a deployment named
//! by another namespace's id simply is not there.
//!
//! ## Where it runs
//!
//! Wherever the plugin record's `home` is: [`super::PluginHost`] applies the
//! plugin only on that host, so in a fleet one host evaluates and sends.
//! It sees the deployments registered on that host.
//!
//! ## State
//!
//! Active and recently resolved alerts, acknowledgements and silences are one
//! JSON document (`app-lb-plugins.d/state/alerting.json`, or the fleet store's
//! `alerting-state` document), rewritten when they change. If it cannot be
//! read at start-up the plugin keeps evaluating and notifying from an empty
//! state but refuses acks and silences, and never overwrites the file, so an
//! operator can fix it without losing what it held. Check results, counter
//! samples and the delivery log are in memory.

pub mod config;
pub mod delivery;
pub mod engine;
mod routes;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use self::config::{AlertingConfig, Check, FleetConfig};
use self::delivery::{AlertPayload, Deliverer, Job};
use self::engine::{CheckResult, Counters, NsState, Observation, Samples};
use super::{Plugin, PluginMeta, SetError};
use crate::deployment::{Deployment, now_secs};
use crate::fleet_store::{Document, Expect, FileDocument, FileOptions};
use crate::metrics::Metrics;
use crate::registry::Registry;
use crate::secrets::SecretStore;

pub(crate) const PAGE_HTML: &str = include_str!("../../alerting_plugin.html");
pub const PLUGIN_ID: &str = "alerting";

// ---- persisted state ---------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct StateFile {
    version: u32,
    #[serde(default)]
    namespaces: BTreeMap<String, NsState>,
}

struct Store {
    file: Arc<dyn Document>,
    namespaces: Mutex<BTreeMap<String, NsState>>,
    /// Why the file could not be read at start-up; see the module docs.
    broken: Option<String>,
}

impl Store {
    fn from_document(file: Arc<dyn Document>) -> Self {
        let (namespaces, broken) = match file.read() {
            Ok(Some((bytes, _))) => match serde_json::from_slice::<StateFile>(&bytes) {
                Ok(f) if f.version == 1 => (f.namespaces, None),
                Ok(f) => (
                    BTreeMap::new(),
                    Some(format!("version {} was written by a newer app-lb", f.version)),
                ),
                Err(e) => (BTreeMap::new(), Some(format!("unreadable: {e}"))),
            },
            Ok(None) => (BTreeMap::new(), None),
            Err(e) => (BTreeMap::new(), Some(e.to_string())),
        };
        if let Some(e) = &broken {
            tracing::error!(path = %file.location(), error = %e,
                "the alerting plugin's state cannot be read; alerts still fire, but acks and silences are refused until it is fixed");
        }
        Self {
            file,
            namespaces: Mutex::new(namespaces),
            broken,
        }
    }

    /// Write `all` (the caller holds the lock it came from).
    fn persist(&self, all: &BTreeMap<String, NsState>) -> std::io::Result<()> {
        if self.broken.is_some() {
            return Ok(()); // never overwrite what could not be read
        }
        #[derive(Serialize)]
        struct Out<'a> {
            version: u32,
            namespaces: &'a BTreeMap<String, NsState>,
        }
        let json = serde_json::to_vec_pretty(&Out {
            version: 1,
            namespaces: all,
        })
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.file.write(&json, Expect::Any)?;
        Ok(())
    }
}

// ---- the plugin ----------------------------------------------------------------

#[derive(Default)]
struct Runtime {
    samples: Samples,
    /// Last result per namespace and check id.
    checks: HashMap<String, BTreeMap<String, CheckResult>>,
    /// When each `(namespace, check)` is next due.
    due: HashMap<(String, String), u64>,
    last_tick: Option<u64>,
}

pub struct AlertingPlugin {
    me: Weak<AlertingPlugin>,
    registry: Arc<Registry>,
    /// Handed over after start-up, once the metrics registry exists; until
    /// then the counter conditions read zero.
    metrics: OnceLock<Arc<Metrics>>,
    fleet: RwLock<Option<FleetConfig>>,
    /// The parsed install configuration of every namespace, as the host last
    /// handed it to [`Plugin::on_install`].
    installs: RwLock<BTreeMap<String, Arc<AlertingConfig>>>,
    store: Store,
    runtime: Mutex<Runtime>,
    /// Serialises evaluation with acks and silences around persistence.
    writes: tokio::sync::Mutex<()>,
    deliverer: Arc<Deliverer>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl AlertingPlugin {
    /// `state_dir` holds the state file, `alerting.json`.
    pub fn new(registry: Arc<Registry>, secrets: Arc<SecretStore>, state_dir: impl Into<PathBuf>) -> Arc<Self> {
        let path = state_dir.into().join("alerting.json");
        Self::with_state_document(registry, secrets, Arc::new(FileDocument::new(&path, FileOptions::PLAIN)))
    }

    /// The same plugin with its state in another backend (the fleet store).
    pub fn with_state_document(
        registry: Arc<Registry>,
        secrets: Arc<SecretStore>,
        file: Arc<dyn Document>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            registry,
            metrics: OnceLock::new(),
            fleet: RwLock::new(None),
            installs: RwLock::new(BTreeMap::new()),
            store: Store::from_document(file),
            runtime: Mutex::new(Runtime::default()),
            writes: tokio::sync::Mutex::new(()),
            deliverer: Deliverer::new(secrets),
            tasks: Mutex::new(Vec::new()),
        })
    }

    /// Hand the plugin the metrics registry, which is created after the
    /// plugin host. Later calls are ignored.
    pub fn attach(&self, metrics: Arc<Metrics>) {
        let _ = self.metrics.set(metrics);
    }

    fn policy(&self) -> crate::net_guard::Policy {
        self.fleet
            .read()
            .unwrap()
            .as_ref()
            .map(FleetConfig::policy)
            .unwrap_or_else(|| crate::net_guard::Policy::resolve(None, None))
    }

    fn install(&self, ns: &str) -> Option<Arc<AlertingConfig>> {
        self.installs.read().unwrap().get(ns).cloned()
    }

    fn stop_tasks(&self) {
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
    }

    // ---- observing ------------------------------------------------------------

    /// Why `deployment`'s rolling replacement is paused, if it is: the
    /// autoscaler pauses a rollout that made no progress within the policy's
    /// `progress_deadline_secs`.
    fn rollout_stall_reason(&self, deployment: &Deployment) -> Option<String> {
        deployment.rollout_stall_reason()
    }

    /// Every deployment of `ns` this host knows, as the conditions see it.
    /// The namespace wall is here: a deployment is observed only if its own
    /// spec says it is in `ns`.
    fn observe(&self, ns: &str) -> BTreeMap<String, Observation> {
        let metrics = self.metrics.get();
        self.registry
            .deployments()
            .values()
            .filter(|d| d.spec.namespace == ns)
            .map(|d| {
                let backends = d.backends();
                let available = backends.iter().filter(|b| b.is_available()).count() as u32;
                let wanted = if d.spec.is_managed() {
                    ((backends.len() + d.pending().len()) as u32).max(d.spec.scaling.min_replicas)
                } else {
                    backends.len() as u32
                };
                let unhealthy_upstreams = if d.spec.is_static() {
                    backends
                        .iter()
                        .filter(|b| !b.is_healthy())
                        .map(|b| b.peer.clone())
                        .collect()
                } else {
                    Vec::new()
                };
                let counters = metrics
                    .map(|m| {
                        let a = m.deployment_snapshot(&d.spec.id).autoscale;
                        Counters {
                            create_failures: a.create_failures,
                            boot_timeouts: a.boot_timeouts,
                            cold_start_timeouts: a.cold_start_timeouts,
                        }
                    })
                    .unwrap_or_default();
                (
                    d.spec.id.clone(),
                    Observation {
                        available,
                        wanted,
                        unhealthy_upstreams,
                        counters,
                        rollout_stall: self.rollout_stall_reason(d),
                    },
                )
            })
            .collect()
    }

    /// Run one check against every available replica of its deployment —
    /// which must be in `ns`.
    async fn run_check(&self, ns: &str, c: &Check, now: u64) -> CheckResult {
        let mut out = CheckResult {
            id: c.id.clone(),
            deployment: c.deployment.clone(),
            path: c.path.clone(),
            checked_at: now,
            ..Default::default()
        };
        let Some(d) = self.registry.get(&c.deployment).filter(|d| d.spec.namespace == ns) else {
            out.last_error = Some(format!("no deployment named {:?} in this namespace", c.deployment));
            return out;
        };
        if d.spec.gateway.is_some() {
            out.last_error = Some("checks do not support gateway deployments".into());
            return out;
        }
        let timeout = Duration::from_secs(c.timeout_secs);
        let backends: Vec<_> = d.backends().iter().filter(|b| b.is_available()).cloned().collect();
        let managed = d.spec.is_managed();
        let probes = backends.iter().map(|b| {
            let path = c.path.clone();
            async move {
                if b.tls {
                    crate::health::probe_https_status(&b.address, &b.sni, &path, timeout).await
                } else if managed {
                    match b.address.parse() {
                        Ok(addr) => crate::health::probe_status(addr, &path, timeout).await,
                        Err(_) => Err(format!("{} is not an address", b.address)),
                    }
                } else {
                    match tokio::net::lookup_host(&b.address).await.map(|mut a| a.next()) {
                        Ok(Some(addr)) => crate::health::probe_status(addr, &path, timeout).await,
                        Ok(None) => Err(format!("{} resolved to nothing", b.address)),
                        Err(e) => Err(format!("{} did not resolve: {e}", b.address)),
                    }
                }
            }
        });
        let results = futures::future::join_all(probes).await;
        out.total = results.len() as u32;
        for (b, r) in backends.iter().zip(results) {
            match r {
                Ok(s) if c.passes(s) => out.passing += 1,
                Ok(s) => out.last_error = Some(format!("{}: HTTP {s}", b.peer)),
                Err(e) => out.last_error = Some(format!("{}: {e}", b.peer)),
            }
        }
        if out.total == 0 {
            out.last_error = Some("no available replicas to probe".into());
        }
        out.ok = out.passing >= c.min_passing;
        if out.ok {
            out.last_error = None;
        }
        out
    }

    /// Run whichever checks are due.
    async fn run_due_checks(&self, installs: &BTreeMap<String, Arc<AlertingConfig>>, now: u64) {
        let due: Vec<(String, Check)> = {
            let rt = self.runtime.lock().unwrap();
            installs
                .iter()
                .flat_map(|(ns, cfg)| cfg.checks.iter().map(move |c| (ns, c)))
                .filter(|(ns, c)| {
                    rt.due
                        .get(&((*ns).clone(), c.id.clone()))
                        .is_none_or(|t| *t <= now)
                })
                .map(|(ns, c)| (ns.clone(), c.clone()))
                .collect()
        };
        let results = futures::future::join_all(
            due.iter().map(|(ns, c)| async move { (ns, c, self.run_check(ns, c, now).await) }),
        )
        .await;
        let mut rt = self.runtime.lock().unwrap();
        for (ns, c, r) in results {
            rt.due.insert((ns.clone(), c.id.clone()), now + c.interval_secs);
            rt.checks.entry(ns.clone()).or_default().insert(c.id.clone(), r);
        }
    }

    // ---- the tick -------------------------------------------------------------

    /// Evaluate every installed namespace once, at `now`.
    pub async fn tick_at(&self, now: u64) {
        let installs = self.installs.read().unwrap().clone();
        self.run_due_checks(&installs, now).await;

        let _held = self.writes.lock().await;
        let mut jobs = Vec::new();
        let changed = {
            let mut rt = self.runtime.lock().unwrap();
            let rt = &mut *rt;
            let mut all = self.store.namespaces.lock().unwrap();
            let mut changed = false;
            let mut live = std::collections::HashSet::new();
            // Results of checks no longer configured are dropped.
            rt.checks.retain(|ns, _| installs.contains_key(ns));
            for (ns, cfg) in &installs {
                if let Some(results) = rt.checks.get_mut(ns) {
                    results.retain(|id, _| cfg.checks.iter().any(|c| &c.id == id));
                }
                let observed = self.observe(ns);
                for (id, o) in &observed {
                    rt.samples.record(id, now, o.counters);
                    live.insert(id.clone());
                }
                let empty = BTreeMap::new();
                let checks = rt.checks.get(ns).unwrap_or(&empty);
                let mut active = Vec::new();
                for rule in &cfg.rules {
                    for d in engine::targets(rule, cfg, &observed) {
                        let summary = engine::evaluate(&rule.condition, d, &observed[d], checks, &rt.samples, now);
                        active.push((rule.id.clone(), d.to_string(), summary));
                    }
                }
                let state = all.entry(ns.clone()).or_default();
                let outcome = engine::step(state, ns, cfg, &active, now);
                changed |= outcome.changed;
                for n in outcome.notifications {
                    let payload = AlertPayload::from(&n.alert);
                    for rid in &n.receivers {
                        let Some(r) = cfg.receivers.iter().find(|r| &r.id == rid) else { continue };
                        let delivery_id = delivery::new_delivery_id();
                        jobs.push(Job {
                            namespace: ns.clone(),
                            receiver: r.clone(),
                            event: delivery::event_header(n.event.as_str()),
                            fingerprint: Some(n.alert.fingerprint.clone()),
                            body: delivery::body(r.format, ns, n.event.as_str(), &payload, &delivery_id),
                            delivery_id,
                        });
                    }
                }
            }
            rt.samples.retain(|d| live.contains(d));
            rt.due.retain(|(ns, id), _| {
                installs.get(ns).is_some_and(|c| c.checks.iter().any(|k| &k.id == id))
            });
            rt.last_tick = Some(now);
            if changed && let Err(e) = self.store.persist(&all) {
                tracing::warn!(error = %e, "could not save the alerting plugin's state");
            }
            changed
        };
        let _ = changed;
        for job in jobs {
            self.deliverer.enqueue(job);
        }
    }

    fn spawn_loop(&self, every: Duration) {
        let me = self.me.clone();
        let ticker = tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick is immediate; the first evaluation is one period
            // in, once the autoscaler has had a reconcile to fill the pools.
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(me) = me.upgrade() else { return };
                me.tick_at(now_secs()).await;
            }
        });
        let worker = tokio::spawn(self.deliverer.clone().run());
        let mut tasks = self.tasks.lock().unwrap();
        tasks.push(ticker);
        tasks.push(worker);
    }
}

#[async_trait]
impl Plugin for AlertingPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: PLUGIN_ID,
            name: "Alerting",
            description: "Alert rules over a namespace's own deployments — replica health, failed \
                 creates and boots, cold-start timeouts, upstream health, stalled rollouts and HTTP \
                 checks — with signed webhooks on firing and resolve, acknowledgements, silences and \
                 a delivery log. The operator enables it; each namespace installs it with its rules.",
            config_schema: json!({
                "type": "object",
                "properties": {
                    "allow_insecure": {"type": "boolean", "description": "Allow plain http:// receivers. Outranks APP_LB_ALERTING_ALLOW_INSECURE."},
                    "allow_private": {"type": "boolean", "description": "Allow receivers on private, loopback, link-local, CGNAT and ULA addresses. Outranks APP_LB_ALERTING_ALLOW_PRIVATE."},
                    "tick_secs": {"type": "integer", "minimum": 1, "maximum": 3600, "default": config::DEFAULT_TICK_SECS}
                }
            }),
        }
    }

    fn validate(&self, config: &Value) -> Result<(), String> {
        config::parse_fleet(config).map(|_| ())
    }

    async fn apply(&self, config: Option<Value>) -> Result<(), String> {
        self.stop_tasks();
        let Some(config) = config else {
            *self.fleet.write().unwrap() = None;
            return Ok(());
        };
        let cfg = config::parse_fleet(&config)?;
        self.deliverer.set_policy(cfg.policy());
        let every = Duration::from_secs(cfg.tick_secs);
        *self.fleet.write().unwrap() = Some(cfg);
        self.spawn_loop(every);
        Ok(())
    }

    async fn status(&self) -> Value {
        let Some(cfg) = self.fleet.read().unwrap().clone() else {
            return json!({});
        };
        let policy = cfg.policy();
        let (firing, pending) = {
            let all = self.store.namespaces.lock().unwrap();
            let alerts = all.values().flat_map(|s| s.alerts.values());
            alerts.fold((0, 0), |(f, p), a| match a.status {
                engine::AlertStatus::Firing => (f + 1, p),
                _ => (f, p + 1),
            })
        };
        json!({
            "tick_secs": cfg.tick_secs,
            "allow_insecure": policy.allow_insecure,
            "allow_private": policy.allow_private,
            "namespaces": self.installs.read().unwrap().len(),
            "firing": firing,
            "pending": pending,
            "last_tick": self.runtime.lock().unwrap().last_tick,
            "deliveries": self.deliverer.stats(),
            "state_error": self.store.broken,
        })
    }

    fn per_namespace(&self) -> bool {
        true
    }

    fn validate_install(&self, _namespace: &str, config: &Value) -> Result<(), String> {
        config::parse_install(config, self.policy()).map(|_| ())
    }

    async fn on_install(&self, namespace: &str, config: &Value, _fleet: &Value) -> Result<(), SetError> {
        // Re-run for every install on start-up: an install the current
        // policy would refuse is kept, and left out of evaluation, rather
        // than taking the others down with it.
        match config::parse_install(config, self.policy()) {
            Ok(cfg) => {
                self.installs
                    .write()
                    .unwrap()
                    .insert(namespace.to_string(), Arc::new(cfg));
                Ok(())
            }
            Err(e) => {
                self.installs.write().unwrap().remove(namespace);
                Err(SetError::Invalid(e))
            }
        }
    }

    async fn on_uninstall(&self, namespace: &str, _config: &Value) -> Result<(), SetError> {
        self.installs.write().unwrap().remove(namespace);
        {
            let mut rt = self.runtime.lock().unwrap();
            rt.checks.remove(namespace);
            rt.due.retain(|(ns, _), _| ns != namespace);
        }
        let _held = self.writes.lock().await;
        let mut all = self.store.namespaces.lock().unwrap();
        if all.remove(namespace).is_some() {
            self.store.persist(&all).map_err(SetError::Io)?;
        }
        drop(all);
        self.deliverer.forget(namespace);
        Ok(())
    }

    fn namespace_routes(self: Arc<Self>) -> Router {
        routes::router(self)
    }

    fn dashboard_path(&self) -> Option<&'static str> {
        Some("ui")
    }
}
