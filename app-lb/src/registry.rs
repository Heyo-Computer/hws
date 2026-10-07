//! The shared registry: the one piece of state the proxy, autoscaler, and admin
//! API all touch.
//!
//! Pingora fixes its service set at startup (`Server::run_forever(self)`
//! consumes the server), so "dynamic deployment registration" cannot mean adding
//! services at runtime. Instead every deployment lives in this registry behind
//! `ArcSwap`, and a single proxy service routes across whatever is currently in
//! it. Readers are lock-free; writers copy-on-write.

use crate::config::DeploymentSpec;
use crate::deployment::{Deployment, DeploymentState};
use arc_swap::ArcSwap;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteHandoffRecord {
    pub operation_id: String,
    pub predecessor_fingerprint: String,
    pub staged_fingerprint: String,
    pub staged_spec: DeploymentSpec,
    pub phase: RouteHandoffPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_version: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteHandoffPhase { Preparing, Prepared, Committed }

#[derive(Debug)]
pub enum HandoffError { NotFound, Conflict(String), Io(std::io::Error) }

/// Route rules pre-sorted most-specific-first, so the first match wins.
///
/// Split in two rather than held as one sorted list, because a fleet of agent
/// sandboxes is thousands of deployments each contributing one exact-host rule,
/// and a linear scan of that per request is the whole routing cost. The split is
/// sound because [`RouteRule::specificity`] tiers do not overlap: any rule with
/// a `host` scores at least `1_000_000`, and any rule without one scores at most
/// `100_000` plus the length of a hostname and a path. So if *any* exact-host
/// rule matches, it outranks everything in `rest` outright, and the two can be
/// consulted in order instead of merged.
///
/// [`RouteRule::specificity`]: crate::config::RouteRule::specificity
#[derive(Debug, Default)]
pub struct RouteTable {
    /// Rules that name an exact `host`, bucketed by that host (lowercased) so
    /// the common case is one hash lookup. Each bucket is sorted the same way
    /// the flat list was, so a `host`+`/api` rule still beats a bare `host` one.
    ///
    /// Buckets are `Arc`d so a copy-on-write update can share every bucket it
    /// does not touch. Registering one deployment then costs a table allocation
    /// and a refcount bump per bucket, instead of deep-copying and re-sorting
    /// every rule in the fleet.
    exact: HashMap<Arc<str>, Arc<Vec<RouteEntry>>>,
    /// Everything else — `host_suffix` and path-only rules — still scanned
    /// linearly. It stays short: these are the platform-level catch-alls, not
    /// the per-deployment routes. `Arc`d for the same reason, so a deployment
    /// with only exact hosts (which is every sandbox) never copies it at all.
    rest: Arc<Vec<RouteEntry>>,
}

/// One rule and the id of the deployment that declared it. The id is shared
/// rather than copied per rule — a fleet has one per deployment, and they are
/// cloned on every index update that touches the bucket.
type RouteEntry = (crate::config::RouteRule, Arc<str>);

/// Most specific first: a host+path rule must beat a bare path rule, and
/// `/api/v2` must beat `/api`. Ties broken by id for determinism.
fn by_specificity(
    (a, ai): &RouteEntry,
    (b, bi): &RouteEntry,
) -> std::cmp::Ordering {
    b.specificity()
        .cmp(&a.specificity())
        .then_with(|| ai.cmp(bi))
}

/// The bucket key for a rule's host: lowercased, since matching is
/// case-insensitive.
fn host_key(rule: &crate::config::RouteRule) -> Option<String> {
    rule.host.as_ref().map(|h| h.to_ascii_lowercase())
}

impl RouteTable {
    /// Build the whole index from scratch.
    ///
    /// Nothing in the running LB calls this any more — every write goes through
    /// [`updated`](Self::updated). It is kept as the reference implementation
    /// the incremental path is checked against: an index that drifts from a full
    /// rebuild is the failure mode of incremental updating, and it would show up
    /// as traffic routed to the wrong deployment rather than as a crash.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn build(deployments: &HashMap<Arc<str>, Arc<Deployment>>) -> Self {
        let mut exact: HashMap<Arc<str>, Vec<RouteEntry>> = HashMap::new();
        let mut rest = Vec::new();
        for d in deployments.values() {
            let id: Arc<str> = Arc::from(d.spec.id.as_str());
            for rule in &d.spec.routes {
                let entry = (rule.clone(), id.clone());
                match host_key(rule) {
                    Some(h) => exact.entry(Arc::from(h.as_str())).or_default().push(entry),
                    None => rest.push(entry),
                }
            }
        }
        for bucket in exact.values_mut() {
            bucket.sort_by(by_specificity);
        }
        rest.sort_by(by_specificity);
        Self {
            exact: exact.into_iter().map(|(k, v)| (k, Arc::new(v))).collect(),
            rest: Arc::new(rest),
        }
    }

    /// This table with one deployment's rules replaced.
    ///
    /// `previous` is what it declared before (`None` when registering),
    /// `next` what it declares now (`None` when deregistering). Only the buckets
    /// named by either are rebuilt; every other bucket is shared with `self`.
    ///
    /// This is what keeps registering the thousandth sandbox as cheap as the
    /// first. Rebuilding the whole index per write made a create storm quadratic
    /// — measurably so: the marginal cost of a create tracked the size of the
    /// fleet, which is exactly the thing a fleet cannot afford.
    fn updated(
        &self,
        id: &str,
        previous: Option<&[crate::config::RouteRule]>,
        next: Option<&[crate::config::RouteRule]>,
    ) -> Self {
        // The union of the hosts this deployment used to name and the ones it
        // names now. Anything outside it cannot have changed.
        let mut touched: HashSet<String> = HashSet::new();
        let mut touches_rest = false;
        for rules in [previous, next].into_iter().flatten() {
            for rule in rules {
                match host_key(rule) {
                    Some(h) => {
                        touched.insert(h);
                    }
                    None => touches_rest = true,
                }
            }
        }

        if touched.is_empty() && !touches_rest {
            // An unrouted deployment — the sandbox default — contributes no
            // rules either way, so the index is unchanged.
            return Self {
                exact: self.exact.clone(),
                rest: self.rest.clone(),
            };
        }

        let id: Arc<str> = Arc::from(id);
        let mut exact = self.exact.clone();
        for host in &touched {
            // Drop this deployment's old entries for the bucket, keeping every
            // other deployment's; then add whatever it declares now.
            let mut bucket: Vec<RouteEntry> = exact
                .get(host.as_str())
                .map(|b| b.iter().filter(|(_, i)| **i != *id).cloned().collect())
                .unwrap_or_default();
            if let Some(rules) = next {
                for rule in rules {
                    if host_key(rule).as_deref() == Some(host.as_str()) {
                        bucket.push((rule.clone(), id.clone()));
                    }
                }
            }
            // An empty bucket is removed rather than kept: `resolve` treats a
            // present-but-empty bucket as a miss anyway, and leaving them would
            // grow the map by one entry per hostname ever used.
            if bucket.is_empty() {
                exact.remove(host.as_str());
            } else {
                bucket.sort_by(by_specificity);
                exact.insert(Arc::from(host.as_str()), Arc::new(bucket));
            }
        }

        let rest = if touches_rest {
            let mut v: Vec<RouteEntry> = self
                .rest
                .iter()
                .filter(|(_, i)| **i != *id)
                .cloned()
                .collect();
            if let Some(rules) = next {
                for rule in rules.iter().filter(|r| r.host.is_none()) {
                    v.push((rule.clone(), id.clone()));
                }
            }
            v.sort_by(by_specificity);
            Arc::new(v)
        } else {
            self.rest.clone()
        };

        Self { exact, rest }
    }

    pub fn resolve(&self, host: Option<&str>, path: &str) -> Option<&str> {
        if let Some(host) = host {
            // `matches` compares hostnames case-insensitively, so the key has to
            // be folded too. Borrowed unless the request actually carries upper
            // case — the proxy already lowercases (`proxy::request_host`), so in
            // practice this is a scan and no allocation.
            let key = if host.bytes().any(|b| b.is_ascii_uppercase()) {
                Cow::Owned(host.to_ascii_lowercase())
            } else {
                Cow::Borrowed(host)
            };
            if let Some(bucket) = self.exact.get(key.as_ref())
                && let Some((_, id)) = bucket.iter().find(|(rule, _)| rule.matches(Some(host), path))
            {
                return Some(id);
            }
        }
        self.rest
            .iter()
            .find(|(rule, _)| rule.matches(host, path))
            .map(|(_, id)| &**id)
    }
}

#[derive(Debug)]
pub struct Registry {
    deployments: ArcSwap<HashMap<Arc<str>, Arc<Deployment>>>,
    routes: ArcSwap<RouteTable>,
    persist_path: PathBuf,
    /// Serializes compound admin mutations by deployment identity. Deployment
    /// objects are replaceable, so a mutex stored on one object cannot protect
    /// a drain from racing a spec replacement.
    change_lock: tokio::sync::Mutex<()>,
    /// Controller effects/read leases precede existing registry/rollout locks.
    /// Retirement takes the write side through durable freeze and inventory.
    pub(crate) retirement_gate: Arc<tokio::sync::RwLock<()>>,
    /// Every deployment uses a deterministic temporary filename. Serialize
    /// writes so concurrent background and admin persistence cannot clobber it.
    persist_lock: std::sync::Mutex<()>,
    /// Backend generations withdrawn by discovery but still observable while
    /// requests admitted before the withdrawal hold their Arcs. Runtime-only:
    /// a restart terminates those connections, so there is nothing to restore.
    retired_discovery: std::sync::Mutex<HashMap<String, Vec<Arc<crate::deployment::VmBackend>>>>,
    staged: std::sync::Mutex<HashMap<String, Arc<Deployment>>>,
    #[cfg(test)]
    pub(crate) fail_after_rename: std::sync::atomic::AtomicBool,
    /// Whether the last [`load`](Registry::load) left a file on disk that it
    /// could not turn into a deployment. Gates
    /// [`sweep_orphan_state`](Registry::sweep_orphan_state), which must not
    /// delete what it cannot account for.
    load_skipped: std::sync::atomic::AtomicBool,
}

impl Registry {
    pub fn new(persist_path: impl Into<PathBuf>) -> Self {
        Self {
            deployments: ArcSwap::from_pointee(HashMap::new()),
            routes: ArcSwap::from_pointee(RouteTable::default()),
            persist_path: persist_path.into(),
            change_lock: tokio::sync::Mutex::new(()),
            retirement_gate: Arc::new(tokio::sync::RwLock::new(())),
            persist_lock: std::sync::Mutex::new(()),
            retired_discovery: std::sync::Mutex::new(HashMap::new()),
            staged: std::sync::Mutex::new(HashMap::new()),
            #[cfg(test)]
            fail_after_rename: std::sync::atomic::AtomicBool::new(false),
            load_skipped: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Hold across fetch → mutation/replacement → persistence. Administrative
    /// writes are rare, so one registry-wide gate is simpler and safer than a
    /// replaceable per-deployment lock.
    pub async fn change_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.change_lock.lock().await
    }

    /// Autoscaling skips a busy registry instead of waiting while holding a
    /// create permit that a replacement may itself be draining.
    pub(crate) fn try_change_guard(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        self.change_lock.try_lock().ok()
    }

    pub fn deployments(&self) -> Arc<HashMap<Arc<str>, Arc<Deployment>>> {
        self.deployments.load_full()
    }

    pub fn get(&self, id: &str) -> Option<Arc<Deployment>> {
        self.deployments().get(id).cloned()
    }

    pub fn retirement_frozen(&self, id: &str) -> bool {
        self.get(id).is_some_and(|d| d.state().retirement.is_some())
    }

    /// Unknown receipt identity cannot be excluded from any cleanup inventory.
    /// Once recovered, retain only that allocation until its runtime is seen.
    pub fn allocation_protects(&self, sandbox: &str) -> bool {
        self.deployments().values().any(|d| d.state().create_attempts.iter().any(|a|
            a.allocation.is_some() && !a.runtime_observed
                && a.sandbox_id.as_deref().is_none_or(|id| id == sandbox)))
    }

    pub fn retirement_protects(&self, sandbox: &str, deployment: Option<&str>) -> bool {
        deployment.is_some_and(|id| self.retirement_frozen(id)) || self.deployments().values().any(|d|
            d.state().retirement.as_ref().is_some_and(|o|
                o.request.targets.iter().any(|t|t.backend_sandbox_id==sandbox)
                || o.inventory.iter().any(|id|id==sandbox)
                || d.state().create_attempts.iter().any(|a|a.sandbox_id.as_deref()==Some(sandbox))
                || crate::rollout::protected_ids(&d.state()).any(|id|id==sandbox)))
    }

    /// One controller process per state directory, including across restarts.
    /// Keep this descriptor for the daemon's whole lifetime; never unlink it.
    pub fn controller_lock(&self) -> std::io::Result<std::fs::File> {
        let dir=self.state_dir();
        let mut missing=Vec::new();
        let mut ancestor=dir.as_path();
        while !ancestor.as_os_str().is_empty() && !ancestor.exists() {
            missing.push(ancestor.to_path_buf());
            let Some(parent)=ancestor.parent() else {break};
            ancestor=parent;
        }
        std::fs::create_dir_all(&dir)?;
        for created in missing.iter().rev() {
            let parent=created.parent().filter(|p|!p.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
            std::fs::File::open(parent)?.sync_all()?;
        }
        let file=std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
            .open(dir.join("controller.lock"))?;
        file.try_lock().map_err(std::io::Error::other)?;
        Ok(file)
    }

    pub fn require_complete_load(&self) -> std::io::Result<()> {
        if self.load_skipped.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(std::io::Error::other("unreadable deployment state may contain retirement intent; controller startup refused"));
        }
        Ok(())
    }

    pub fn staged(&self, id: &str) -> Option<Arc<Deployment>> {
        self.staged.lock().unwrap_or_else(|e| e.into_inner()).get(id).cloned()
    }

    pub fn discovery_targets(&self) -> Vec<(String, String, bool)> {
        let mut out: Vec<_> = self.deployments().values().filter_map(|d| d.spec.discovery.as_ref()
            .map(|x| (d.spec.id.clone(), x.service_id.clone(), false))).collect();
        out.extend(self.staged.lock().unwrap_or_else(|e| e.into_inner()).values().filter_map(|d|
            d.spec.discovery.as_ref().map(|x| (d.spec.id.clone(), x.service_id.clone(), true))));
        out
    }

    pub fn prepare_handoff(&self, operation_id: &str, expected: &str, staged_spec: DeploymentSpec)
        -> Result<RouteHandoffRecord, HandoffError> {
        let current = self.get(&staged_spec.id).ok_or(HandoffError::NotFound)?;
        let current_fp = spec_fingerprint(&current.spec).map_err(HandoffError::Io)?;
        let staged_fp = spec_fingerprint(&staged_spec).map_err(HandoffError::Io)?;
        if let Some(existing) = current.state().route_handoff.clone() {
            if existing.operation_id == operation_id && existing.predecessor_fingerprint == expected
                && existing.staged_fingerprint == staged_fp { return Ok(existing); }
            return Err(HandoffError::Conflict("deployment already has a different route handoff intent".into()));
        }
        if current_fp != expected { return Err(HandoffError::Conflict("expected predecessor fingerprint does not match".into())); }
        validate_handoff(&current.spec, &staged_spec).map_err(HandoffError::Conflict)?;
        let record = RouteHandoffRecord { operation_id: operation_id.into(), predecessor_fingerprint: expected.into(),
            staged_fingerprint: staged_fp, staged_spec: staged_spec.clone(), phase: RouteHandoffPhase::Preparing,
            prepared_boot_id: None, prepared_version: None };
        let mut next = (*current.state()).clone();
        next.route_handoff = Some(record.clone());
        self.persist_snapshot(&current, &next).map_err(HandoffError::Io)?;
        current.set_state(next);
        self.staged.lock().unwrap_or_else(|e| e.into_inner()).insert(staged_spec.id.clone(), Arc::new(Deployment::new(staged_spec)));
        Ok(record)
    }

    pub fn inspect_handoff(&self, id: &str) -> Option<RouteHandoffRecord> {
        self.get(id)?.state().route_handoff.clone()
    }

    pub fn mark_handoff_prepared(&self, id: &str) -> Result<RouteHandoffRecord, HandoffError> {
        let current = self.get(id).ok_or(HandoffError::NotFound)?;
        let staged = self.staged(id).ok_or_else(|| HandoffError::Conflict("staged runtime unavailable".into()))?;
        let evidence = staged.regional.as_ref().and_then(|r| r.preparation(!staged.spec.maintenance))
            .filter(|p| p.prepared && p.adopted).ok_or_else(|| HandoffError::Conflict("regional runtime must be healthy and have adopted the active policy".into()))?;
        let mut record = current.state().route_handoff.clone().ok_or_else(|| HandoffError::Conflict("no route handoff".into()))?;
        if evidence.operation_id != record.operation_id {
            return Err(HandoffError::Conflict("regional snapshot operation does not match route handoff".into()));
        }
        record.phase = RouteHandoffPhase::Prepared;
        record.prepared_boot_id = Some(evidence.boot_id);
        record.prepared_version = Some(evidence.version);
        let mut next = (*current.state()).clone();
        next.route_handoff = Some(record.clone());
        self.persist_snapshot(&current, &next).map_err(HandoffError::Io)?;
        current.set_state(next);
        Ok(record)
    }

    pub fn commit_handoff(&self, id: &str, operation_id: &str) -> Result<RouteHandoffRecord, HandoffError> {
        let predecessor = self.get(id).ok_or(HandoffError::NotFound)?;
        let mut record = predecessor.state().route_handoff.clone().ok_or_else(|| HandoffError::Conflict("no route handoff".into()))?;
        if record.operation_id != operation_id { return Err(HandoffError::Conflict("operation identity does not match".into())); }
        if record.phase == RouteHandoffPhase::Committed { return Ok(record); }
        if record.phase != RouteHandoffPhase::Prepared { return Err(HandoffError::Conflict("route handoff is not prepared".into())); }
        if spec_fingerprint(&predecessor.spec).map_err(HandoffError::Io)? != record.predecessor_fingerprint {
            return Err(HandoffError::Conflict("predecessor spec changed after preparation".into()));
        }
        if self.deployments().values().any(|other| other.spec.id != id && record.staged_spec.routes.iter().any(|new| {
            let host = new.host.as_deref();
            let path = new.path_prefix.as_deref().unwrap_or("/");
            other.spec.routes.iter().any(|old| old.matches(host, path) || new.matches(old.host.as_deref(), old.path_prefix.as_deref().unwrap_or("/")))
        })) {
            return Err(HandoffError::Conflict("a competing deployment now overlaps the staged route".into()));
        }
        let staged = self.staged(id).ok_or_else(|| HandoffError::Conflict("staged runtime unavailable".into()))?;
        let evidence = staged.regional.as_ref().and_then(|r| r.preparation(!staged.spec.maintenance))
            .filter(|p| p.prepared && p.adopted).ok_or_else(|| HandoffError::Conflict("prepared evidence is stale or the active policy is not healthy".into()))?;
        if evidence.operation_id != record.operation_id {
            return Err(HandoffError::Conflict("regional snapshot operation does not match route handoff".into()));
        }
        if record.prepared_boot_id.as_deref() != Some(&evidence.boot_id) || record.prepared_version != Some(evidence.version) {
            return Err(HandoffError::Conflict("prepared evidence changed; inspect and prepare again".into()));
        }
        record.phase = RouteHandoffPhase::Committed;
        let mut next = (*staged.state()).clone();
        next.route_handoff = Some(record.clone());
        next.discovery_version = Some(evidence.version);
        // Persist switch intent before publishing. A crash after this point
        // reloads the regional spec (closed until a fresh matching snapshot).
        self.persist_snapshot(&staged, &next).map_err(HandoffError::Io)?;
        staged.set_state(next);
        // Fence even requests holding a predecessor Arc. Already-admitted
        // streams finish normally and remain visible in discovery status.
        self.fence_discovery_removals(&predecessor, &[]);
        self.install(Some(staged.clone()), id);
        self.staged.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
        Ok(record)
    }

    pub fn apply_staged_discovery(&self, old: &Arc<Deployment>, upstreams: Vec<String>) -> Option<Arc<Deployment>> {
        let mut stages = self.staged.lock().unwrap_or_else(|e| e.into_inner());
        if !stages.get(&old.spec.id).is_some_and(|d| Arc::ptr_eq(d, old)) { return None; }
        let mut spec = old.spec.clone(); spec.upstreams = upstreams;
        let mut next = Deployment::new(spec);
        next.regional = old.regional.clone();
        let next = Arc::new(next);
        next.set_state((*old.state()).clone());
        stages.insert(old.spec.id.clone(), next.clone());
        Some(next)
    }

    /// Resolve a request to a deployment.
    pub fn route(&self, host: Option<&str>, path: &str) -> Option<Arc<Deployment>> {
        let id = {
            let routes = self.routes.load();
            routes.resolve(host, path)?.to_string()
        };
        self.get(&id)
    }

    /// Register or replace a deployment.
    ///
    /// Replacing builds a fresh `Deployment`, so the old pool's VMs are dropped
    /// from routing immediately; the autoscaler reaps the orphaned sandboxes on
    /// its next tick by diffing against the daemon's list. A static deployment's
    /// operator drains are carried for upstream addresses still present in the
    /// replacement: replaying a deployment must not silently put a maintenance
    /// target back into service.
    pub fn upsert(&self, mut spec: DeploymentSpec) -> Arc<Deployment> {
        let previous = self.get(&spec.id);
        if let Some(old)=previous.as_ref().filter(|d|d.state().retirement.is_some()) {return old.clone();}
        if previous.as_ref().is_some_and(|old|
            old.spec.discovery.as_ref().and_then(|d| d.region.as_ref())
                != spec.discovery.as_ref().and_then(|d| d.region.as_ref()))
            && spec.discovery.is_some() {
            // A regional scope change cannot relabel cached endpoints from
            // another region. Wait for a validated snapshot of the new scope.
            spec.upstreams.clear();
        }
        if let Some(previous) = previous.as_ref().filter(|d| d.spec.discovery.is_some()) {
            self.fence_discovery_removals(previous, &spec.upstreams);
        }
        let previous_state = previous.as_ref().and_then(|previous| {
            (spec.is_static() && previous.spec.is_static()).then(|| {
                let mut state = (*previous.state()).clone();
                let same_discovery_service = previous
                    .spec
                    .discovery
                    .as_ref()
                    .map(|value| (&value.service_id, &value.region))
                    == spec.discovery.as_ref().map(|value| (&value.service_id, &value.region));
                if !same_discovery_service {
                    state.discovery_version = None;
                    state.discovery_source_url = None;
                }
                // Discovery can temporarily withdraw an address and later
                // return it. Do not turn that absence into an implicit operator
                // uncordon. Ordinary static spec edits retain the historical
                // behavior of forgetting intent for explicitly removed peers.
                if spec.discovery.is_none() || !same_discovery_service {
                    state
                        .upstream_drains
                        .retain(|drain| spec.upstreams.contains(&drain.upstream));
                }
                state
            })
        });
        let mut deployment = Deployment::new(spec);
        if let Some(previous) = &previous {
            if previous.spec.namespace == deployment.spec.namespace && previous.spec.discovery == deployment.spec.discovery {
                deployment.regional = previous.regional.clone();
            } else if let Some(router) = &previous.regional {
                router.fence();
            }
        }
        let deployment = Arc::new(deployment);
        if let Some(state) = previous_state {
            deployment.set_state(state);
        }
        if let Some(previous) = &previous {
            deployment.mutate_state(|s| {
                s.rollouts = previous.state().rollouts.clone();
                s.create_attempts = previous.state().create_attempts.clone();
                s.allocation_history_complete = previous.state().allocation_history_complete;
                s.rollout_revision = crate::rollout::revision();
            });
        }
        if deployment.spec.is_static()
            && let Some(previous) = previous.filter(|previous| previous.spec.is_static())
        {
            // Preserve the identity of every retained address. Requests already
            // admitted hold these Arcs, so reusing them preserves health and
            // in-flight accounting across an upstream-list edit or reorder.
            let old = previous.backends();
            let fresh = deployment.backends();
            let mut used = vec![false; old.len()];
            let backends = deployment
                .spec
                .upstreams
                .iter()
                .enumerate()
                .map(|(fresh_index, upstream)| {
                    if let Some((old_index, backend)) = old
                        .iter()
                        .enumerate()
                        .find(|(index, backend)| !used[*index] && backend.peer == *upstream)
                    {
                        used[old_index] = true;
                        backend.clone()
                    } else {
                        fresh[fresh_index].clone()
                    }
                })
                .collect();
            deployment.set_backends(backends);
        }
        self.install(Some(deployment.clone()), &deployment.spec.id.clone());
        deployment
    }

    /// Replace a discovery-owned upstream set while fencing every withdrawn
    /// backend generation. The caller holds [`change_guard`](Self::change_guard),
    /// making this transition coherent with persistence and status reads.
    pub fn apply_discovery_upstreams(
        &self,
        deployment: &Arc<Deployment>,
        upstreams: Vec<String>,
    ) -> Arc<Deployment> {
        let mut spec = deployment.spec.clone();
        spec.upstreams = upstreams;
        self.upsert(spec)
    }

    fn fence_discovery_removals(&self, deployment: &Arc<Deployment>, upstreams: &[String]) {
        let retained: HashSet<&str> = upstreams.iter().map(String::as_str).collect();
        let removed: Vec<_> = deployment
            .backends()
            .iter()
            .filter(|backend| !retained.contains(backend.peer.as_str()))
            .cloned()
            .collect();

        // This happens before publishing the replacement (and therefore before
        // snapshot acknowledgement). A request holding either the old
        // Deployment or backend Arc now fails its authoritative admission gate.
        for backend in &removed {
            backend.set_draining(true);
        }
        if !removed.is_empty() {
            let mut retired = self.retired_discovery.lock().unwrap_or_else(|e| e.into_inner());
            let generations = retired.entry(deployment.spec.id.clone()).or_default();
            generations.retain(|backend| backend.in_flight() != 0);
            generations.extend(removed);
        }
    }

    /// Current and not-yet-quiescent withdrawn discovery backend generations.
    /// Duplicate peers are intentionally left for the API layer to aggregate.
    pub fn discovery_backends(&self, id: &str) -> Vec<Arc<crate::deployment::VmBackend>> {
        let mut result: Vec<_> = self
            .get(id)
            .map(|d| d.backends().iter().cloned().collect())
            .unwrap_or_default();
        let mut retired = self
            .retired_discovery
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(backends) = retired.get_mut(id) {
            backends.retain(|backend| backend.in_flight() != 0);
            result.extend(backends.iter().cloned());
            if backends.is_empty() {
                retired.remove(id);
            }
        }
        result
    }

    /// Update a deployment's spec in place, **preserving its live VM pool**.
    ///
    /// Unlike `upsert` (which abandons the old pool for the autoscaler to reap),
    /// this carries the existing backends and pending VMs onto a fresh
    /// `Deployment` built from the new spec. The pool is a vec of shared
    /// `Arc<VmBackend>`, so the moved VMs keep their in-flight counters and
    /// drain flags, and requests in flight during the edit are unaffected.
    /// Returns `None` if the id is unknown.
    ///
    /// Only valid when the VM *template* is unchanged; a template change means
    /// the running VMs were built from a different spec and must be rebuilt,
    /// which is `upsert` plus a teardown of the old pool. The admin layer makes
    /// that decision.
    pub fn update(&self, spec: DeploymentSpec) -> Option<Arc<Deployment>> {
        let old = self.get(&spec.id)?;
        if old.state().retirement.is_some() {return None;}
        let new = Arc::new(Deployment::new(spec));
        // Runtime state is carried for the same reason the pool is: an edit is
        // not a reset. Dropping it here would strand every sandbox this
        // deployment had suspended — they are absent from the daemon's fleet
        // list, so nothing else remembers them.
        new.set_state((*old.state()).clone());
        new.mutate_state(|s| s.rollout_revision = crate::rollout::revision());
        new.set_backends((*old.backends()).clone());
        new.set_pending((*old.pending()).clone());
        self.install(Some(new.clone()), &new.spec.id.clone());
        Some(new)
    }

    pub fn remove(&self, id: &str) -> Option<Arc<Deployment>> {
        let removed = self.get(id)?;
        if removed.state().retirement.is_some() {return None;}
        if removed.state().create_attempts.iter().any(|a| a.allocation.is_some()) {return None;}
        if removed.spec.discovery.is_some() {
            self.fence_discovery_removals(&removed, &[]);
        }
        self.install(None, id);
        Some(removed)
    }

    /// Install or remove one deployment, updating the route index with it.
    ///
    /// Copy-on-write, so readers stay lock-free. The cost is one map allocation
    /// and a refcount bump per entry — *not* a deep copy of every deployment's
    /// routes and a re-sort of the whole index, which is what made the marginal
    /// cost of a create grow with the size of the fleet.
    ///
    /// Not atomic against a concurrent writer, which is fine: the admin API is
    /// the only writer of the deployment set, and it is a single service. The
    /// two `store`s are ordered deployments-then-routes so a request that
    /// resolves an id always finds it — the reverse order has a window where the
    /// index names a deployment the map does not yet hold.
    pub(crate) fn publish(&self, deployment: Arc<Deployment>) {
        if self.retirement_frozen(&deployment.spec.id) {return;}
        self.install(Some(deployment.clone()), &deployment.spec.id);
    }

    fn install(&self, deployment: Option<Arc<Deployment>>, id: &str) {
        let current = self.deployments.load();
        let previous = current.get(id).cloned();

        let mut next = (**current).clone();
        match &deployment {
            Some(d) => next.insert(Arc::from(id), d.clone()),
            None => next.remove(id),
        };

        let routes = self.routes.load().updated(
            id,
            previous.as_ref().map(|d| d.spec.routes.as_slice()),
            deployment.as_ref().map(|d| d.spec.routes.as_slice()),
        );

        self.deployments.store(Arc::new(next));
        self.routes.store(Arc::new(routes));
    }

    /// Where per-deployment state files live: `app-lb-state.json` →
    /// `app-lb-state.d/`. Derived rather than separately configured so there is
    /// still one knob to point at a data directory.
    pub fn state_dir(&self) -> PathBuf {
        let stem = self
            .persist_path
            .file_stem()
            .unwrap_or_else(|| std::ffi::OsStr::new("app-lb-state"));
        let mut name = stem.to_os_string();
        name.push(".d");
        match self.persist_path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.join(name),
            _ => PathBuf::from(name),
        }
    }

    /// Write one deployment's file. O(1) in fleet size, which is the point: a
    /// fleet of agent sandboxes registers and deregisters constantly, and
    /// rewriting every spec on each change made a create storm quadratic.
    pub fn persist_one(&self, id: &str) -> std::io::Result<()> {
        let _guard = self.persist_lock.lock().unwrap_or_else(|e| e.into_inner());
        let Some(d) = self.get(id) else {
            return self.forget(id);
        };
        self.persist_snapshot_inner(&d, &d.state())
    }

    /// Persist an explicit next state without publishing it to request routing.
    /// Used by uncordon so a failed disk write can never briefly admit traffic.
    pub fn persist_snapshot(
        &self,
        deployment: &Deployment,
        state: &DeploymentState,
    ) -> std::io::Result<()> {
        let _guard = self.persist_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.persist_snapshot_inner(deployment, state)
    }

    fn persist_snapshot_inner(
        &self,
        deployment: &Deployment,
        state: &DeploymentState,
    ) -> std::io::Result<()> {
        let dir = self.state_dir();
        let mut missing_dirs = Vec::new();
        let mut ancestor = dir.as_path();
        while !ancestor.as_os_str().is_empty() && !ancestor.exists() {
            missing_dirs.push(ancestor.to_path_buf());
            let Some(parent) = ancestor.parent() else {
                break;
            };
            ancestor = parent;
        }
        std::fs::create_dir_all(&dir)?;
        // create_dir_all makes each directory visible, but those entries are
        // not crash-durable until their parents are synced. Work from the
        // highest newly-created directory down toward the state directory.
        for created in missing_dirs.iter().rev() {
            let parent = created
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            std::fs::File::open(parent)?.sync_all()?;
        }
        let record = StoredDeployment {
            spec: deployment.spec.clone(),
            state: state.clone(),
        };
        let json = serde_json::to_vec_pretty(&record)?;
        // Write-then-rename so a crash mid-write can't truncate existing state.
        let path = dir.join(state_file_name(&deployment.spec.id));
        let tmp = path.with_extension("json.tmp");
        let mut file = std::fs::File::create(&tmp)?;
        std::io::Write::write_all(&mut file, &json)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, &path)?;
        #[cfg(test)]
        if self.fail_after_rename.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::other("injected failure after rename"));
        }
        // The rename is not durable until the directory entry is synced. A
        // successful drain must not disappear after a host crash and silently
        // reopen traffic on restart.
        std::fs::File::open(dir)?.sync_all()
    }

    /// Save the exact spec and completed history outside the startup registry.
    /// Content addressing makes retries idempotent without rewriting old reports.
    /// Caller holds the registry and lifecycle guards through record removal.
    pub fn archive_record(&self, deployment: &Deployment) -> std::io::Result<()> {
        let _guard = self.persist_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.persist_snapshot_inner(deployment, &deployment.state())?;
        let dir = self.state_dir();
        let source = dir.join(state_file_name(&deployment.spec.id));
        let bytes = std::fs::read(&source)?;
        let archive = dir.join("retired");
        std::fs::create_dir_all(&archive)?;
        std::fs::File::open(&dir)?.sync_all()?;
        let target = archive.join(format!("{:x}.json", Sha256::digest(&bytes)));
        match std::fs::hard_link(&source, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if std::fs::read(&target)? != bytes {
                    return Err(std::io::Error::other("retired record archive content mismatch"));
                }
            }
            Err(error) => return Err(error),
        }
        std::fs::File::open(archive)?.sync_all()
    }

    /// Drop one deployment's file. A missing file is success — deregistering
    /// something that was never persisted is not an error.
    pub fn forget(&self, id: &str) -> std::io::Result<()> {
        if self.retirement_frozen(id) {
            return Err(std::io::Error::other("retirement preserves the deployment record"));
        }
        match std::fs::remove_file(self.state_dir().join(state_file_name(id))) {
            Ok(()) => std::fs::File::open(self.state_dir())?.sync_all(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Delete state files that no live deployment claims, and report how many.
    ///
    /// The leak this closes is narrow: a deregistration whose [`forget`] failed
    /// leaves a file behind, and the next start reads it and resurrects the
    /// deployment. Sweeping at startup catches that.
    ///
    /// **Refuses to run if the preceding [`load`] skipped anything.** A file is
    /// skipped when its spec no longer validates — which a validation change can
    /// cause for a spec that was fine when written — and that file is the
    /// operator's only copy. Deleting it would turn a warning into data loss, so
    /// the sweep stands down and says so instead.
    ///
    /// [`forget`]: Self::forget
    /// [`load`]: Self::load
    pub fn sweep_orphan_state(&self) -> std::io::Result<usize> {
        if self.load_skipped.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                "not sweeping orphaned state files: the last load skipped at least one, \
                 and an unreadable file is still somebody's only copy of a spec",
            );
            return Ok(0);
        }
        let dir = self.state_dir();
        let wanted: std::collections::HashSet<String> = self
            .deployments()
            .keys()
            .map(|id| state_file_name(id))
            .collect();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let mut removed = 0;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.ends_with(".json") && !wanted.contains(name) {
                tracing::info!(file = %name, "removing orphaned deployment state file");
                std::fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Load persisted deployments. Nothing on disk is a normal first run.
    ///
    /// Reads the state directory, importing the legacy single file first if one
    /// is present. The filename is only a storage key — the id comes from the
    /// spec inside — so a file whose name was mangled by encoding still loads
    /// under the right id.
    pub fn load(&self) -> std::io::Result<usize> {
        self.migrate_legacy_file()?;

        let dir = self.state_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };

        let mut loaded = 0;
        let mut skipped = false;
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue; // a stray `.json.tmp` from an interrupted write
            }
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "unreadable state file");
                    skipped = true;
                    continue;
                }
            };
            let mut record: StoredDeployment = match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "unparseable state file");
                    skipped = true;
                    continue;
                }
            };
            // A file written before secret references carried a namespace
            // gets them bound to the deployment's, which is the only thing
            // they could ever have meant.
            record.spec.normalize();
            // Persisted state predates any validation change; skip bad entries
            // rather than refusing to start.
            if let Err(e) = record.spec.validate() {
                tracing::warn!(id = %record.spec.id, error = %e, "skipping invalid persisted deployment");
                skipped = true;
                continue;
            }
            // Reload cannot replace a local freeze with an older disk image.
            if self.retirement_frozen(&record.spec.id) {loaded += 1; continue;}
            let d = self.upsert(record.spec);
            d.set_state(record.state);
            if let Some(handoff) = d.state().route_handoff.clone()
                && handoff.phase != RouteHandoffPhase::Committed
            {
                // Preparation survives restart as intent only. The fresh Router
                // has a new boot id and must obtain a coherent fresh snapshot.
                self.staged.lock().unwrap_or_else(|e| e.into_inner()).insert(
                    d.spec.id.clone(), Arc::new(Deployment::new(handoff.staged_spec)));
            }
            loaded += 1;
        }
        self.load_skipped
            .store(skipped, std::sync::atomic::Ordering::Relaxed);
        Ok(loaded)
    }

    /// Import a pre-directory `app-lb-state.json`, then move it aside.
    ///
    /// Renamed rather than deleted so a downgrade still has the data, and so a
    /// second start cannot re-import specs that have since been edited or
    /// deregistered — which would resurrect deleted deployments.
    fn migrate_legacy_file(&self) -> std::io::Result<()> {
        let bytes = match std::fs::read(&self.persist_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let specs: Vec<DeploymentSpec> = serde_json::from_slice(&bytes)?;
        let dir = self.state_dir();
        std::fs::create_dir_all(&dir)?;
        for spec in &specs {
            let record = StoredDeployment {
                spec: spec.clone(),
                state: DeploymentState::default(),
            };
            let path = dir.join(state_file_name(&spec.id));
            // Never clobber: if the directory already has an entry it is newer
            // than this file, which is only here because an earlier rename
            // failed.
            if path.exists() {
                continue;
            }
            std::fs::write(&path, serde_json::to_vec_pretty(&record)?)?;
        }
        let aside = self.persist_path.with_extension("json.migrated");
        std::fs::rename(&self.persist_path, &aside)?;
        tracing::info!(
            count = specs.len(),
            from = %self.persist_path.display(),
            to = %dir.display(),
            "migrated deployment state to per-deployment files",
        );
        Ok(())
    }
}

pub fn spec_fingerprint(spec: &DeploymentSpec) -> std::io::Result<String> {
    let mut intent = spec.clone();
    intent.normalize();
    // Discovery refreshes membership independently of the operator's route
    // intent. They must not invalidate an otherwise identical handoff retry.
    if intent.discovery.is_some() { intent.upstreams.clear(); }
    let bytes = serde_json::to_vec(&intent).map_err(std::io::Error::other)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn validate_handoff(flat: &DeploymentSpec, regional: &DeploymentSpec) -> Result<(), String> {
    if regional.validate().is_err() { return Err("staged regional spec is invalid".into()); }
    let Some(predecessor) = flat.discovery.as_ref() else { return Err("predecessor must be discovery-backed".into()); };
    if predecessor.regional.is_some() || flat.gateway.is_some() {
        return Err("predecessor must use flat discovery routing".into());
    }
    let Some(discovery) = regional.discovery.as_ref() else { return Err("staged spec requires discovery".into()); };
    if discovery.region.is_none() || discovery.regional.is_none() || discovery.source.is_none() {
        return Err("staged spec requires explicit regional scope, authority and peer authentication".into());
    }
    let mut expected = flat.clone();
    expected.upstreams = regional.upstreams.clone();
    let allowed = expected.discovery.as_mut().unwrap();
    allowed.region = discovery.region.clone();
    allowed.regional = discovery.regional.clone();
    if expected != *regional {
        return Err("handoff must preserve authority, credentials, service identity and non-routing configuration".into());
    }
    Ok(())
}

/// One deployment's on-disk record: its spec, plus the runtime state that has
/// to outlive a restart but is not something the operator writes.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct StoredDeployment {
    spec: DeploymentSpec,
    #[serde(default)]
    state: DeploymentState,
}

/// A filename for a deployment id.
///
/// Ids are only required to be non-empty, so one may contain `/`, `..`, or a
/// leading dot — all of which would escape or hide the state directory.
/// Everything outside `[A-Za-z0-9_-]` is percent-escaped, including `.` and `%`
/// itself, which keeps the encoding injective: two different ids can never
/// collide on one file. It is deliberately not reversible — the id is read back
/// from the spec inside the file, so the name is a key and nothing more.
fn state_file_name(id: &str) -> String {
    let mut out = String::with_capacity(id.len() + 5);
    for b in id.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out.push_str(".json");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DiscoverySpec, HealthCheck, RouteRule, ScalingPolicy, VmSpec};
    use crate::config::Driver;
    use std::path::Path;

    fn spec(id: &str, routes: Vec<RouteRule>) -> DeploymentSpec {
        DeploymentSpec {
            ingress: None,
            account_id: None,
            user_id: None,
            namespace: "default".into(),
            feed: None,
            id: id.into(),
            routes,
            vm: Some(VmSpec {
                correlated_creates: false,
                env_from: vec![],
                workspace_archive: None,
                image_download_url: None,
                image_size_bytes: None,
                image_sha256: None,
                driver: Driver::Firecracker,
                image: None,
                rootfs: Default::default(),
                port: 8080,
                start_command: None,
                size_class: None,
                disk_size_gb: None,
                working_directory: None,
                env_vars: None,
                setup_hooks: None,
                open_ports: vec![],
                mounts: vec![],
                workspace: None,
                ttl_seconds: 3600,
            }),
            scaling: ScalingPolicy::default(),
            maintenance: false,
            health: HealthCheck::default(),
            upstreams: vec![],
            discovery: None,
            gateway: None,
            build: None,
            artifact: None,
            site: None,
            update: None,
            auth: None,
        }
    }

    fn static_spec(id: &str, routes: Vec<RouteRule>, upstreams: &[&str]) -> DeploymentSpec {
        DeploymentSpec {
            ingress: None,
            account_id: None,
            user_id: None,
            namespace: "default".into(),
            feed: None,
            id: id.into(),
            routes,
            vm: None,
            scaling: ScalingPolicy::default(),
            maintenance: false,
            health: HealthCheck::default(),
            upstreams: upstreams.iter().map(|s| s.to_string()).collect(),
            discovery: None,
            gateway: None,
            build: None,
            artifact: None,
            site: None,
            update: None,
            auth: None,
        }
    }

    fn regional_spec(flat: &DeploymentSpec, boot_id: &str) -> (DeploymentSpec, crate::regional::Snapshot) {
        let mut staged = flat.clone();
        staged.upstreams.clear();
        staged.discovery = Some(serde_json::from_value(serde_json::json!({
            "service_id":"svc", "region":"eu1",
            "source":{"url":"https://control.example/discovery","auth":{"secret":"discovery"}},
            "regional":{"gateway_id":"eu","backend_server_id":"host-eu","environment":"prod","auth":{"secret":"peer"}}
        })).unwrap());
        let snapshot = serde_json::from_value(serde_json::json!({
            "protocolVersion":1,"serviceId":"svc","environment":"prod","region":"eu1","gatewayId":"eu",
            "bootId":boot_id,"version":7,"operationId":"handoff-1","phase":"bake","proposalGeneration":1,
            "activeGeneration":1,"drainTarget":null,"closedThroughGeneration":0,
            "policies":[{"generation":1,"policy":{"version":1,"regions":[{"region":"eu1","weight":1,
                "gateways":[{"id":"eu","backendServerId":"host-eu","url":"https://eu.example"}]}]}}],
            "endpoints":[]
        })).unwrap();
        (staged, snapshot)
    }

    fn handoff_flat_spec() -> DeploymentSpec {
        let mut flat = static_spec("app", vec![host("app.example")], &["127.0.0.1:8000"]);
        let (regional, _) = regional_spec(&flat, "unused");
        flat.discovery = regional.discovery;
        let discovery = flat.discovery.as_mut().unwrap();
        discovery.region = None;
        discovery.regional = None;
        flat
    }

    #[test]
    fn staged_handoff_keeps_flat_selection_then_commits_without_invalidating_held_requests() {
        let state_file = scratch("route-handoff");
        let registry = Registry::new(&state_file);
        let flat = registry.upsert(handoff_flat_spec());
        let held = flat.backends()[0].try_hold().unwrap();
        let fingerprint = spec_fingerprint(&flat.spec).unwrap();
        let temporary = crate::regional::Router::new();
        let (staged_spec, _) = regional_spec(&flat.spec, &temporary.boot_id);
        let first = registry.prepare_handoff("handoff-1", &fingerprint, staged_spec.clone()).unwrap();
        assert_eq!(first.phase, RouteHandoffPhase::Preparing);
        assert!(Arc::ptr_eq(&registry.route(Some("app.example"), "/").unwrap(), &flat));
        assert_eq!(registry.prepare_handoff("handoff-1", &fingerprint, staged_spec.clone()).unwrap(), first);
        let mut conflict = staged_spec.clone(); conflict.maintenance = true;
        assert!(matches!(registry.prepare_handoff("handoff-1", &fingerprint, conflict), Err(HandoffError::Conflict(_))));

        let staged = registry.staged("app").unwrap();
        let router = staged.regional.as_ref().unwrap();
        let (_, snapshot) = regional_spec(&flat.spec, &router.boot_id);
        router.apply(snapshot, staged.spec.discovery.as_ref().unwrap().regional.as_ref().unwrap(), "svc", "eu1",
            vec![Arc::new(crate::deployment::VmBackend::for_upstream("127.0.0.1:9000".into()))]).unwrap();
        registry.mark_handoff_prepared("app").unwrap();
        registry.commit_handoff("app", "handoff-1").unwrap();
        let selected = registry.route(Some("app.example"), "/").unwrap();
        assert!(selected.regional.is_some());
        assert_eq!(flat.backends()[0].in_flight(), 1, "held predecessor keeps its own Arc and counter");
        assert!(!flat.backends()[0].try_acquire(), "a request holding the old route cannot start new work");
        assert!(registry.discovery_backends("app").iter().any(|b| b.peer == "127.0.0.1:8000" && b.in_flight() == 1));
        drop(held);
        assert_eq!(flat.backends()[0].in_flight(), 0);
        assert!(!registry.discovery_backends("app").iter().any(|b| b.peer == "127.0.0.1:8000"));

        let restarted = Registry::new(&state_file);
        assert_eq!(restarted.load().unwrap(), 1);
        let recovered = restarted.route(Some("app.example"), "/").unwrap();
        assert!(recovered.regional.is_some());
        assert!(recovered.regional.as_ref().unwrap().preparation(true).is_none(),
            "restart must not fabricate the old boot's preparation evidence");
        std::fs::remove_dir_all(state_file.parent().unwrap()).ok();
    }

    #[test]
    fn handoff_requires_healthy_active_policy_and_current_boot() {
        let path = scratch("handoff-policy");
        let registry = Registry::new(&path);
        let flat = registry.upsert(handoff_flat_spec());
        let (spec, _) = regional_spec(&flat.spec, "unused");
        registry.prepare_handoff("handoff-1", &spec_fingerprint(&flat.spec).unwrap(), spec).unwrap();
        let staged = registry.staged("app").unwrap();
        let router = staged.regional.as_ref().unwrap();
        let (_, mut snapshot) = regional_spec(&flat.spec, &router.boot_id);
        let regional = staged.spec.discovery.as_ref().unwrap().regional.as_ref().unwrap();
        let backend = Arc::new(crate::deployment::VmBackend::for_upstream("127.0.0.1:9000".into()));
        snapshot.active_generation = None;
        router.apply(snapshot.clone(), regional, "svc", "eu1", vec![backend.clone()]).unwrap();
        assert!(registry.mark_handoff_prepared("app").is_err(), "prepared alone does not permit cutover");
        snapshot.active_generation = Some(1);
        snapshot.version += 1;
        backend.set_healthy(false);
        router.apply(snapshot, regional, "svc", "eu1", vec![backend.clone()]).unwrap();
        assert!(registry.mark_handoff_prepared("app").is_err(), "adopted alone does not permit cutover");
        backend.set_healthy(true);
        registry.mark_handoff_prepared("app").unwrap();
        backend.set_healthy(false);
        assert!(registry.commit_handoff("app", "handoff-1").is_err(), "commit rechecks readiness");
        let restarted = Registry::new(&path);
        assert_eq!(restarted.load().unwrap(), 1);
        assert!(restarted.commit_handoff("app", "handoff-1").is_err());
        let recovered = restarted.staged("app").unwrap();
        let new_router = recovered.regional.as_ref().unwrap();
        assert_ne!(new_router.boot_id, router.boot_id);
        let (_, snapshot) = regional_spec(&flat.spec, &new_router.boot_id);
        backend.set_healthy(true);
        new_router.apply(snapshot, regional, "svc", "eu1", vec![backend]).unwrap();
        assert!(restarted.commit_handoff("app", "handoff-1").is_err(), "fresh snapshot cannot reuse an old boot receipt");
        restarted.mark_handoff_prepared("app").unwrap();
        restarted.commit_handoff("app", "handoff-1").unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn handoff_failed_persistence_is_not_acknowledged_by_retry() {
        let path = scratch("handoff-write-failure");
        let registry = Registry::new(&path);
        let flat = registry.upsert(handoff_flat_spec());
        let fingerprint = spec_fingerprint(&flat.spec).unwrap();
        let (spec, _) = regional_spec(&flat.spec, "unused");
        registry.fail_after_rename.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(registry.prepare_handoff("handoff-1", &fingerprint, spec.clone()), Err(HandoffError::Io(_))));
        assert!(registry.inspect_handoff("app").is_none());
        assert!(registry.staged("app").is_none());
        registry.prepare_handoff("handoff-1", &fingerprint, spec).unwrap();
        let staged = registry.staged("app").unwrap();
        let router = staged.regional.as_ref().unwrap();
        let (_, snapshot) = regional_spec(&flat.spec, &router.boot_id);
        router.apply(snapshot, staged.spec.discovery.as_ref().unwrap().regional.as_ref().unwrap(), "svc", "eu1",
            vec![Arc::new(crate::deployment::VmBackend::for_upstream("127.0.0.1:9000".into()))]).unwrap();
        registry.fail_after_rename.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(registry.mark_handoff_prepared("app"), Err(HandoffError::Io(_))));
        assert_eq!(registry.inspect_handoff("app").unwrap().phase, RouteHandoffPhase::Preparing);
        registry.mark_handoff_prepared("app").unwrap();
        registry.fail_after_rename.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(registry.commit_handoff("app", "handoff-1"), Err(HandoffError::Io(_))));
        assert!(Arc::ptr_eq(&registry.get("app").unwrap(), &flat));
        assert!(staged.state().route_handoff.is_none());
        assert_eq!(registry.inspect_handoff("app").unwrap().phase, RouteHandoffPhase::Prepared);
        // Rename may have happened before the I/O error. Restart recovers the
        // selected intent but cannot route from a prior boot's cached policy.
        let restarted = Registry::new(&path);
        restarted.load().unwrap();
        assert!(restarted.get("app").unwrap().regional.as_ref().unwrap().preparation(true).is_none());
        registry.commit_handoff("app", "handoff-1").unwrap();
        assert_eq!(registry.commit_handoff("app", "handoff-1").unwrap().phase, RouteHandoffPhase::Committed);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn handoff_preserves_authority_and_non_routing_intent_but_not_cached_membership() {
        let flat = handoff_flat_spec();
        let (regional, _) = regional_spec(&flat, "unused");
        validate_handoff(&flat, &regional).unwrap();
        let mut refreshed = flat.clone();
        refreshed.upstreams = vec!["127.0.0.1:8001".into()];
        assert_eq!(spec_fingerprint(&flat).unwrap(), spec_fingerprint(&refreshed).unwrap());
        for edit in 0..4 {
            let mut wrong = regional.clone();
            match edit {
                0 => wrong.discovery.as_mut().unwrap().source.as_mut().unwrap().url = "https://other.example/discovery".into(),
                1 => wrong.discovery.as_mut().unwrap().service_id = "other".into(),
                2 => wrong.maintenance = true,
                _ => wrong.user_id = Some("other-owner".into()),
            }
            assert!(validate_handoff(&flat, &wrong).is_err());
        }
        refreshed.discovery = None;
        assert!(validate_handoff(&refreshed, &regional).is_err());
        assert!(validate_handoff(&regional, &regional).is_err());
    }

    #[test]
    fn maintenance_update_preserves_managed_pool_and_route_identity() {
        let state_file = scratch("maintenance");
        let registry = Registry::new(&state_file);
        let original = registry.upsert(spec("demo", vec![RouteRule {
            host: Some("demo.local".into()),
            host_suffix: None,
            path_prefix: None,
            strip_prefix: false,
            redirect: None,
        }]));
        let backend = Arc::new(crate::deployment::VmBackend::new(
            "sb-1".into(),
            "127.0.0.1:8080".parse().unwrap(),
        ));
        original.set_backends(vec![backend.clone()]);

        let mut edited = original.spec.clone();
        edited.maintenance = true;
        let updated = registry.update(edited).unwrap();

        assert!(updated.spec.maintenance);
        assert!(Arc::ptr_eq(&backend, &updated.backends()[0]), "PUT-style update keeps the VM pool");
        assert!(Arc::ptr_eq(&updated, &registry.route(Some("demo.local"), "/").unwrap()));

        registry.persist_one("demo").unwrap();
        let reloaded = Registry::new(&state_file);
        assert_eq!(reloaded.load().unwrap(), 1);
        let persisted = reloaded.get("demo").unwrap();
        assert!(persisted.spec.maintenance);
        assert_eq!(persisted.spec.namespace, "default");
        assert_eq!(persisted.spec.routes, updated.spec.routes);
        assert_eq!(persisted.spec.auth, updated.spec.auth);
    }

    fn host(h: &str) -> RouteRule {
        RouteRule {
            host: Some(h.into()),
            host_suffix: None,
            path_prefix: None,
            strip_prefix: false,
            redirect: None,
        }
    }

    fn path(p: &str) -> RouteRule {
        RouteRule {
            host: None,
            host_suffix: None,
            path_prefix: Some(p.into()),
            strip_prefix: false,
            redirect: None,
        }
    }

    fn suffix(s: &str) -> RouteRule {
        RouteRule {
            host: None,
            host_suffix: Some(s.into()),
            path_prefix: None,
            strip_prefix: false,
            redirect: None,
        }
    }

    /// A spec write is how a fix ships, so it must be tried at once rather
    /// than after whatever is left of an hour-long boot-failure backoff. That
    /// holds because an upsert builds a fresh `Deployment`; this pins it, so
    /// carrying runtime state across an edit cannot quietly start carrying the
    /// embargo too.
    #[test]
    fn a_spec_write_clears_the_boot_failure_backoff() {
        let r = Registry::new("unused.json");
        let before = r.upsert(spec("web", vec![]));
        for _ in 0..12 {
            before.note_boot_failure(crate::deployment::now_secs());
        }
        assert_eq!(before.boot_failure_streak(), 12);
        assert!(before.boot_backoff_remaining(crate::deployment::now_secs()).is_some());

        let after = r.upsert(spec("web", vec![]));
        assert_eq!(after.boot_failure_streak(), 0);
        assert_eq!(after.boot_backoff_remaining(crate::deployment::now_secs()), None);
    }

    #[test]
    fn routes_by_subdomain() {
        let r = Registry::new("unused.json");
        r.upsert(spec("apps", vec![suffix("apps.example.com")]));
        assert_eq!(
            r.route(Some("foo.apps.example.com"), "/").unwrap().spec.id,
            "apps"
        );
        assert_eq!(
            r.route(Some("apps.example.com"), "/").unwrap().spec.id,
            "apps"
        );
        assert!(r.route(Some("foo.other.com"), "/").is_none());
    }

    #[test]
    fn exact_host_beats_subdomain_wildcard() {
        let r = Registry::new("unused.json");
        r.upsert(spec("wild", vec![suffix("example.com")]));
        r.upsert(spec("exact", vec![host("special.example.com")]));

        // A generic subdomain falls to the wildcard...
        assert_eq!(
            r.route(Some("other.example.com"), "/").unwrap().spec.id,
            "wild"
        );
        // ...but the exact host wins for its own name.
        assert_eq!(
            r.route(Some("special.example.com"), "/").unwrap().spec.id,
            "exact"
        );
    }

    #[test]
    fn routes_by_host() {
        let r = Registry::new("unused.json");
        r.upsert(spec("a", vec![host("a.local")]));
        r.upsert(spec("b", vec![host("b.local")]));

        assert_eq!(r.route(Some("a.local"), "/").unwrap().spec.id, "a");
        assert_eq!(r.route(Some("b.local"), "/").unwrap().spec.id, "b");
        assert!(r.route(Some("nope.local"), "/").is_none());
        assert!(r.route(None, "/").is_none());
    }

    #[test]
    fn routes_by_path_prefix() {
        let r = Registry::new("unused.json");
        r.upsert(spec("api", vec![path("/api")]));
        assert_eq!(r.route(None, "/api/v1").unwrap().spec.id, "api");
        assert!(r.route(None, "/web").is_none());
    }

    #[test]
    fn most_specific_route_wins() {
        let r = Registry::new("unused.json");
        r.upsert(spec("broad", vec![path("/api")]));
        r.upsert(spec("narrow", vec![path("/api/v2")]));
        r.upsert(spec("hosted", vec![host("a.local")]));

        assert_eq!(r.route(None, "/api/v1").unwrap().spec.id, "broad");
        assert_eq!(r.route(None, "/api/v2/x").unwrap().spec.id, "narrow");
        // Host beats a bare path prefix.
        assert_eq!(
            r.route(Some("a.local"), "/api/v1").unwrap().spec.id,
            "hosted"
        );
    }

    #[test]
    fn host_plus_path_beats_host_alone() {
        let r = Registry::new("unused.json");
        r.upsert(spec("site", vec![host("a.local")]));
        r.upsert(spec(
            "site-api",
            vec![RouteRule {
                host: Some("a.local".into()),
                host_suffix: None,
                path_prefix: Some("/api".into()),
                strip_prefix: false,
                redirect: None,
            }],
        ));
        assert_eq!(r.route(Some("a.local"), "/").unwrap().spec.id, "site");
        assert_eq!(
            r.route(Some("a.local"), "/api/x").unwrap().spec.id,
            "site-api"
        );
    }

    /// The exact-host bucket is keyed by a lowercased hostname, so a request
    /// carrying upper case has to be folded before the lookup or it misses the
    /// bucket entirely — a miss the flat scan could never have.
    #[test]
    fn exact_host_lookup_is_case_insensitive_in_both_directions() {
        let r = Registry::new("unused.json");
        r.upsert(spec("a", vec![host("MiXeD.Local")]));
        assert_eq!(r.route(Some("mixed.local"), "/").unwrap().spec.id, "a");
        assert_eq!(r.route(Some("MIXED.LOCAL"), "/").unwrap().spec.id, "a");
    }

    /// A populated host bucket whose rules all fail must fall through to the
    /// residual list. Returning `None` at the first bucket miss would be the
    /// natural bug in a split index, and it would silently 404 traffic that a
    /// wildcard rule is there to catch.
    #[test]
    fn a_host_bucket_that_does_not_match_falls_through_to_the_wildcard() {
        let r = Registry::new("unused.json");
        r.upsert(spec("wild", vec![suffix("local")]));
        r.upsert(spec(
            "api",
            vec![RouteRule {
                host: Some("a.local".into()),
                host_suffix: None,
                path_prefix: Some("/api".into()),
                strip_prefix: false,
                redirect: None,
            }],
        ));

        // The bucket for `a.local` exists and is consulted first...
        assert_eq!(r.route(Some("a.local"), "/api/x").unwrap().spec.id, "api");
        // ...but a path it doesn't cover still reaches the suffix rule.
        assert_eq!(r.route(Some("a.local"), "/other").unwrap().spec.id, "wild");
    }

    /// A rule may set `host` *and* `host_suffix`. It buckets by the exact host,
    /// and both conditions must still hold.
    #[test]
    fn a_rule_with_both_host_and_suffix_is_bucketed_but_still_fully_matched() {
        let r = Registry::new("unused.json");
        r.upsert(spec(
            "both",
            vec![RouteRule {
                host: Some("a.example.com".into()),
                host_suffix: Some("example.com".into()),
                path_prefix: None,
                strip_prefix: false,
                redirect: None,
            }],
        ));
        r.upsert(spec(
            "mismatch",
            vec![RouteRule {
                host: Some("a.other.com".into()),
                host_suffix: Some("example.com".into()),
                path_prefix: None,
                strip_prefix: false,
                redirect: None,
            }],
        ));

        assert_eq!(r.route(Some("a.example.com"), "/").unwrap().spec.id, "both");
        // The suffix contradicts the host, so nothing can ever satisfy it.
        assert!(r.route(Some("a.other.com"), "/").is_none());
    }

    /// The incremental index must agree with a full rebuild after *every*
    /// mutation, not just at the end.
    ///
    /// This is the test that matters for `RouteTable::updated`. Its failure mode
    /// is not a crash — it is a stale or missing bucket, which routes somebody's
    /// traffic to the wrong deployment or 404s a hostname that is registered.
    /// Comparing against `build` after each step is the only way to see that.
    #[test]
    fn the_incremental_index_never_drifts_from_a_full_rebuild() {
        // Route shapes chosen to cover every branch of `updated`: exact host,
        // host+path (two rules sharing one bucket), a suffix and a bare path
        // (both land in `rest`), several rules at once, and none at all.
        let shapes: Vec<Vec<RouteRule>> = vec![
            vec![host("a.local")],
            vec![host("b.local")],
            vec![RouteRule {
                host: Some("a.local".into()),
                host_suffix: None,
                path_prefix: Some("/api".into()),
                strip_prefix: false,
                redirect: None,
            }],
            vec![suffix("apps.example.com")],
            vec![path("/legacy")],
            vec![host("a.local"), suffix("example.com"), path("/x")],
            vec![host("A.LOCAL")], // same bucket, different case
            vec![],                // unrouted
        ];
        let probes: Vec<(Option<&str>, &str)> = vec![
            (Some("a.local"), "/"),
            (Some("a.local"), "/api/v1"),
            (Some("A.Local"), "/api"),
            (Some("b.local"), "/"),
            (Some("x.apps.example.com"), "/"),
            (Some("apps.example.com"), "/x"),
            (Some("other.example.com"), "/"),
            (None, "/legacy/thing"),
            (None, "/x"),
            (None, "/"),
        ];

        let r = Registry::new("unused.json");
        // A fixed LCG rather than a random source: a failure has to be
        // reproducible, and this is a correctness check, not a fuzz run.
        let mut seed: u64 = 0x5eed;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };

        for step in 0..400 {
            let id = format!("d{}", next() % 12);
            match next() % 4 {
                0 => {
                    r.remove(&id);
                }
                _ => {
                    let routes = shapes[next() % shapes.len()].clone();
                    // Exercise both write paths: `update` preserves the pool,
                    // `upsert` replaces the deployment outright.
                    if next() % 2 == 0 && r.get(&id).is_some() {
                        r.update(spec(&id, routes));
                    } else {
                        r.upsert(spec(&id, routes));
                    }
                }
            }

            let reference = RouteTable::build(&r.deployments());
            let live = r.routes.load();
            for (h, p) in &probes {
                assert_eq!(
                    live.resolve(*h, p),
                    reference.resolve(*h, p),
                    "step {step}: incremental index disagrees for host={h:?} path={p}",
                );
            }
        }
    }

    /// An unrouted deployment — the agent-sandbox shape — contributes nothing to
    /// either half of the index and is reachable only by id.
    #[test]
    fn an_unrouted_deployment_is_registered_but_never_routed() {
        let r = Registry::new("unused.json");
        r.upsert(spec("sandbox", vec![]));
        r.upsert(spec("web", vec![host("web.local")]));

        assert!(r.get("sandbox").is_some());
        assert!(r.route(Some("sandbox"), "/").is_none());
        assert!(r.route(None, "/").is_none());
        assert_eq!(r.route(Some("web.local"), "/").unwrap().spec.id, "web");
    }

    #[test]
    fn update_preserves_the_live_pool_and_swaps_routes() {
        use crate::deployment::VmBackend;
        use std::sync::Arc;

        let r = Registry::new("unused.json");
        r.upsert(spec("a", vec![host("old.local")]));
        let before = r.get("a").unwrap();
        let backend = Arc::new(VmBackend::new("sb-1".into(), "10.0.0.1:80".parse().unwrap()));
        backend.acquire(); // 1 in-flight, to prove the counter survives the edit
        before.set_backends(vec![backend.clone()]);

        // Edit the routes (not the VM template).
        let updated = r.update(spec("a", vec![host("new.local")])).unwrap();

        // The same backend Arc moved across, in-flight intact.
        let pool = updated.backends();
        assert_eq!(pool.len(), 1);
        assert!(Arc::ptr_eq(&pool[0], &backend), "the running VM must be carried over");
        assert_eq!(pool[0].in_flight(), 1, "in-flight counter preserved across the edit");

        // Routing follows the new spec.
        assert!(r.route(Some("old.local"), "/").is_none());
        assert_eq!(r.route(Some("new.local"), "/").unwrap().spec.id, "a");
    }

    #[test]
    fn update_of_unknown_deployment_is_none() {
        let r = Registry::new("unused.json");
        assert!(r.update(spec("ghost", vec![host("x.local")])).is_none());
    }

    #[test]
    fn upsert_replaces_and_reroutes() {
        let r = Registry::new("unused.json");
        r.upsert(spec("a", vec![host("old.local")]));
        r.upsert(spec("a", vec![host("new.local")]));
        assert!(r.route(Some("old.local"), "/").is_none());
        assert_eq!(r.route(Some("new.local"), "/").unwrap().spec.id, "a");
        assert_eq!(r.deployments().len(), 1);
    }

    #[test]
    fn remove_drops_routes() {
        let r = Registry::new("unused.json");
        r.upsert(spec("a", vec![host("a.local")]));
        assert!(r.remove("a").is_some());
        assert!(r.route(Some("a.local"), "/").is_none());
        assert!(r.remove("a").is_none());
    }

    #[test]
    fn persist_round_trips() {
        let dir = std::env::temp_dir().join(format!("app-lb-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state_file = dir.join("state.json");

        let r = Registry::new(&state_file);
        r.upsert(spec("a", vec![host("a.local")]));
        r.upsert(spec("b", vec![path("/b")]));
        persist_all(&r);

        let r2 = Registry::new(&state_file);
        assert_eq!(r2.load().unwrap(), 2);
        assert_eq!(r2.route(Some("a.local"), "/").unwrap().spec.id, "a");
        assert_eq!(r2.route(None, "/b/x").unwrap().spec.id, "b");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_missing_file_is_a_clean_first_run() {
        let r = Registry::new("/nonexistent/definitely/not/here.json");
        assert_eq!(r.load().unwrap(), 0);
    }

    /// A scratch state file under a name unique to this test, so the cases below
    /// can run in parallel without sharing a directory.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("app-lb-test-{}-{name}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("state.json")
    }

    /// Write every deployment's file. Production writes one at a time
    /// (`persist_one`); this is only for setting up a populated directory.
    fn persist_all(r: &Registry) {
        for id in r.deployments().keys() {
            r.persist_one(id).unwrap();
        }
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// The whole point of the directory layout: registering one deployment
    /// writes one file, not the whole fleet. A create storm was quadratic before.
    #[test]
    fn persist_one_touches_exactly_one_file() {
        let state_file = scratch("persist-one");
        let r = Registry::new(&state_file);
        r.upsert(spec("a", vec![host("a.local")]));
        r.upsert(spec("b", vec![host("b.local")]));

        r.persist_one("a").unwrap();
        assert_eq!(files_in(&r.state_dir()), vec!["a.json"]);

        r.persist_one("b").unwrap();
        assert_eq!(files_in(&r.state_dir()), vec!["a.json", "b.json"]);

        std::fs::remove_dir_all(state_file.parent().unwrap()).ok();
    }

    /// Runtime state rides along with the spec. Losing it across a restart would
    /// strand suspended sandboxes, which are invisible to the daemon's fleet
    /// list and so have no other record anywhere.
    #[test]
    fn runtime_state_round_trips_with_the_spec() {
        let state_file = scratch("runtime-state");
        let r = Registry::new(&state_file);
        let d = r.upsert(spec("a", vec![host("a.local")]));
        d.set_state(DeploymentState {
            suspended: vec!["sb-1".into()],
            ..Default::default()
        });
        r.persist_one("a").unwrap();

        let r2 = Registry::new(&state_file);
        assert_eq!(r2.load().unwrap(), 1);
        assert_eq!(r2.get("a").unwrap().state().suspended, vec!["sb-1"]);

        std::fs::remove_dir_all(state_file.parent().unwrap()).ok();
    }

    /// An edit is not a reset: `update` preserves the pool, and must preserve
    /// the runtime state for the same reason.
    #[test]
    fn update_carries_runtime_state_across_the_edit() {
        let r = Registry::new("unused.json");
        let d = r.upsert(spec("a", vec![host("old.local")]));
        d.set_state(DeploymentState {
            suspended: vec!["sb-1".into()],
            ..Default::default()
        });

        let updated = r.update(spec("a", vec![host("new.local")])).unwrap();
        assert_eq!(updated.state().suspended, vec!["sb-1"]);
    }

    #[test]
    fn static_upstream_drains_survive_restart_and_deployment_replay() {
        let state_file = scratch("static-upstream-drain");
        let r = Registry::new(&state_file);
        let d = r.upsert(static_spec(
            "stage",
            vec![host("stage.example.com")],
            &["eu1.example:443", "us1.example:443"],
        ));
        d.set_state(DeploymentState {
            upstream_drains: vec![
                crate::deployment::UpstreamDrain {
                    upstream: "eu1.example:443".into(),
                    reason: Some("old maintenance".into()),
                    started_at: 122,
                },
                crate::deployment::UpstreamDrain {
                    upstream: "us1.example:443".into(),
                    reason: Some("maintenance".into()),
                    started_at: 123,
                },
            ],
            discovery_version: Some(7),
            ..Default::default()
        });
        r.persist_one("stage").unwrap();

        let reloaded = Registry::new(&state_file);
        reloaded.load().unwrap();
        let loaded = reloaded.get("stage").unwrap();
        let us1 = loaded
            .backends()
            .iter()
            .find(|backend| backend.peer == "us1.example:443")
            .cloned()
            .unwrap();
        assert!(us1.is_draining(), "persisted drain must apply before routing");
        assert_eq!(loaded.state().discovery_version, Some(7));
        us1.acquire();

        let replayed = reloaded.upsert(static_spec(
            "stage",
            vec![host("stage.example.com")],
            &["us1.example:443", "ap1.example:443"],
        ));
        let replayed_us1 = replayed
            .backends()
            .iter()
            .find(|backend| backend.peer == "us1.example:443")
            .cloned()
            .unwrap();
        assert!(replayed_us1.is_draining(), "deployment replay must keep intent");
        assert_eq!(replayed.state().discovery_version, Some(7));
        assert!(
            Arc::ptr_eq(&us1, &replayed_us1),
            "a retained address must keep the object requests already reference",
        );
        assert_eq!(
            replayed_us1.in_flight(),
            1,
            "upstream-list edits must preserve admitted-request accounting",
        );
        assert!(
            replayed
                .state()
                .upstream_drains
                .iter()
                .all(|drain| drain.upstream != "eu1.example:443"),
            "drains for removed addresses must not survive",
        );
        replayed_us1.release();

        std::fs::remove_dir_all(state_file.parent().unwrap()).ok();
    }

    #[test]
    fn changing_discovery_service_resets_the_observed_version() {
        let r = Registry::new("unused.json");
        let mut cloud = static_spec("stage", vec![host("stage.example.com")], &[]);
        cloud.discovery = Some(DiscoverySpec {
            service_id: "cloud".into(),
            region: None,
            source: None,
            regional: None,
        });
        let deployment = r.upsert(cloud);
        deployment.mutate_state(|state| state.discovery_version = Some(7));

        let mut auth = static_spec("stage", vec![host("stage.example.com")], &[]);
        auth.discovery = Some(DiscoverySpec {
            service_id: "auth".into(),
            region: None,
            source: None,
            regional: None,
        });
        let deployment = r.upsert(auth);

        assert_eq!(deployment.state().discovery_version, None);
    }

    #[test]
    fn changing_discovery_region_fences_cached_membership_without_losing_in_flight_work() {
        let registry = Registry::new("unused.json");
        let mut spec = static_spec("stage", vec![host("stage.example.com")], &["eu.example:8081"]);
        spec.discovery = Some(DiscoverySpec { service_id: "stage".into(), region: Some("eu1".into()), source: None, regional: None });
        let original = registry.upsert(spec.clone());
        original.mutate_state(|state| {
            state.discovery_version = Some(17);
            state.discovery_source_url = Some("https://authority/discovery?region=eu1".into());
        });
        let backend = original.backends()[0].clone();
        assert!(backend.try_acquire());
        spec.discovery.as_mut().unwrap().region = Some("us3".into());
        let replacement = registry.upsert(spec);
        assert!(replacement.spec.upstreams.is_empty());
        assert_eq!(replacement.state().discovery_version, None);
        assert_eq!(replacement.state().discovery_source_url, None);
        assert!(!backend.try_acquire());
        assert_eq!(backend.in_flight(), 1);
        assert_eq!(registry.discovery_backends("stage").len(), 1);
        backend.release();
        assert!(registry.discovery_backends("stage").is_empty());
    }

    #[tokio::test]
    async fn discovery_replacement_fences_and_observes_retired_generations() {
        let r = Registry::new("unused.json");
        let mut first = static_spec(
            "stage",
            vec![host("stage.example.com")],
            &["a.example:80", "b.example:80"],
        );
        first.discovery = Some(DiscoverySpec { service_id: "stage".into(), region: None, source: None, regional: None });
        let deployment = r.upsert(first);
        deployment.mutate_state(|state| {
            state.discovery_version = Some(1);
            state.upstream_drains.push(crate::deployment::UpstreamDrain {
                upstream: "b.example:80".into(),
                reason: Some("maintenance".into()),
                started_at: 10,
            });
        });
        let old_a = deployment.backends().iter().find(|b| b.peer == "a.example:80").unwrap().clone();
        let old_b = deployment.backends().iter().find(|b| b.peer == "b.example:80").unwrap().clone();
        assert!(old_a.try_acquire(), "request is admitted before withdrawal");

        let _guard = r.change_guard().await;
        let second = r.apply_discovery_upstreams(
            &deployment,
            vec!["b.example:80".into(), "c.example:80".into()],
        );
        assert!(!old_a.try_acquire(), "a stale backend Arc must be fenced");
        assert_eq!(old_a.in_flight(), 1, "the held request remains observable");
        let second_backends = second.backends();
        let second_b = second_backends
            .iter()
            .find(|b| b.peer == "b.example:80")
            .unwrap();
        assert!(
            Arc::ptr_eq(&old_b, second_b),
            "unchanged backends keep their generation"
        );
        assert!(second_b.is_draining(), "operator drain intent survives discovery");

        let third = r.apply_discovery_upstreams(&second, vec!["c.example:80".into()]);
        assert!(!old_b.try_acquire(), "a second update fences its newly removed backend");
        let observed = r.discovery_backends("stage");
        assert!(observed.iter().any(|b| Arc::ptr_eq(b, &old_a)));
        assert!(observed.iter().any(|b| b.peer == "c.example:80" && !b.is_draining()));
        assert_eq!(third.backends().len(), 1);
        assert!(
            third.upstream_drain("b.example:80").is_some(),
            "temporary discovery absence must not erase operator intent"
        );

        old_a.release();
        assert!(
            r.discovery_backends("stage").iter().all(|b| !Arc::ptr_eq(b, &old_a)),
            "a quiescent retired generation is pruned",
        );
    }

    #[test]
    fn forget_drops_one_file_and_tolerates_a_missing_one() {
        let state_file = scratch("forget");
        let r = Registry::new(&state_file);
        r.upsert(spec("a", vec![host("a.local")]));
        r.upsert(spec("b", vec![host("b.local")]));
        persist_all(&r);

        r.forget("a").unwrap();
        assert_eq!(files_in(&r.state_dir()), vec!["b.json"]);
        // Deregistering something never persisted is not an error.
        r.forget("never-existed").unwrap();

        std::fs::remove_dir_all(state_file.parent().unwrap()).ok();
    }

    /// A file left behind by a deregistration whose `forget` failed must not
    /// resurrect the deployment on the next start.
    #[test]
    fn the_sweep_removes_files_no_deployment_claims() {
        let state_file = scratch("sweep");
        let r = Registry::new(&state_file);
        r.upsert(spec("a", vec![host("a.local")]));
        r.upsert(spec("b", vec![host("b.local")]));
        persist_all(&r);

        // Deregister without forgetting — the failed-unlink case.
        r.remove("b");
        assert_eq!(r.sweep_orphan_state().unwrap(), 1);
        assert_eq!(files_in(&r.state_dir()), vec!["a.json"]);

        std::fs::remove_dir_all(state_file.parent().unwrap()).ok();
    }

    /// The sweep must stand down when the load it follows could not account for
    /// every file. A spec that stopped validating is still the operator's only
    /// copy, and deleting it would turn a warning into data loss.
    #[test]
    fn the_sweep_refuses_to_run_after_a_load_that_skipped_a_file() {
        let state_file = scratch("sweep-guard");
        let r = Registry::new(&state_file);
        r.upsert(spec("good", vec![host("a.local")]));
        persist_all(&r);
        // A spec app-lb cannot parse — the shape of a forward/backward
        // incompatibility, not of a file that may be thrown away.
        std::fs::write(r.state_dir().join("mystery.json"), b"{\"spec\":{\"nope\":1}}").unwrap();

        let r2 = Registry::new(&state_file);
        assert_eq!(r2.load().unwrap(), 1, "the good one still loads");
        assert_eq!(r2.sweep_orphan_state().unwrap(), 0, "and nothing is deleted");
        assert!(r2.state_dir().join("mystery.json").is_file());

        std::fs::remove_dir_all(state_file.parent().unwrap()).ok();
    }

    /// An id is only required to be non-empty, so it can contain `/` or `..`.
    /// Those must neither escape the state directory nor collide with each
    /// other — the encoding is escaped, not stripped.
    #[test]
    fn ids_that_are_not_filename_safe_stay_inside_and_stay_distinct() {
        let state_file = scratch("unsafe-ids");
        let r = Registry::new(&state_file);
        r.upsert(spec("../escape", vec![host("a.local")]));
        r.upsert(spec("..%2Fescape", vec![host("b.local")]));
        r.upsert(spec("a/b", vec![host("c.local")]));
        persist_all(&r);

        let dir = r.state_dir();
        // Three distinct files, all of them directly inside the state directory.
        assert_eq!(files_in(&dir).len(), 3, "no two ids may share a file");
        assert!(dir.join(state_file_name("../escape")).is_file());

        // And they come back under their original ids.
        let r2 = Registry::new(&state_file);
        assert_eq!(r2.load().unwrap(), 3);
        assert!(r2.get("../escape").is_some());
        assert!(r2.get("..%2Fescape").is_some());
        assert!(r2.get("a/b").is_some());

        std::fs::remove_dir_all(state_file.parent().unwrap()).ok();
    }

    /// Upgrading from the single-file format imports it and moves it aside, so a
    /// second start cannot resurrect deployments deregistered in between.
    #[test]
    fn a_legacy_state_file_is_imported_once_and_moved_aside() {
        let state_file = scratch("legacy");
        let legacy = vec![spec("a", vec![host("a.local")]), spec("b", vec![path("/b")])];
        std::fs::write(&state_file, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

        let r = Registry::new(&state_file);
        assert_eq!(r.load().unwrap(), 2);
        assert_eq!(r.route(Some("a.local"), "/").unwrap().spec.id, "a");
        assert!(!state_file.exists(), "the legacy file must be moved aside");
        assert!(state_file.with_extension("json.migrated").is_file());

        // Deregister one, restart: the import must not bring it back.
        r.remove("b");
        r.forget("b").unwrap();
        let r2 = Registry::new(&state_file);
        assert_eq!(r2.load().unwrap(), 1);
        assert!(r2.get("b").is_none(), "a migrated file must not re-import");

        std::fs::remove_dir_all(state_file.parent().unwrap()).ok();
    }

    #[test]
    fn static_deployment_routes_and_is_prepopulated() {
        let r = Registry::new("unused.json");
        r.upsert(static_spec(
            "proxy",
            vec![path("/legacy")],
            &["10.0.0.9:8080", "backend.internal:8080"],
        ));
        let d = r.route(None, "/legacy/x").unwrap();
        assert_eq!(d.spec.id, "proxy");
        // Backends come straight from the spec — no autoscaler needed.
        assert_eq!(d.backends().len(), 2);
    }

    #[test]
    fn static_deployment_survives_persist_round_trip() {
        let dir = std::env::temp_dir().join(format!("app-lb-static-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state_file = dir.join("state.json");

        let r = Registry::new(&state_file);
        r.upsert(static_spec("proxy", vec![path("/legacy")], &["10.0.0.9:8080"]));
        persist_all(&r);

        let r2 = Registry::new(&state_file);
        assert_eq!(r2.load().unwrap(), 1);
        let d = r2.route(None, "/legacy").unwrap();
        assert!(d.spec.is_static());
        assert_eq!(d.backends().len(), 1, "backends rebuilt from upstreams on load");

        std::fs::remove_dir_all(&dir).ok();
    }
}
