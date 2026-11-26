//! Persistent GitHub runners: GitHub assigns jobs; this plugin supplies VM demand.
//! Webhooks only trigger reconciliation. Paginated REST snapshots, never event
//! ordering or lease expiry, decide whether a runner may sleep.

use super::{Installs, NamespaceScope, Plugin, PluginMeta, SetError};
use crate::{
    config::{Driver, IdleAction},
    deployment::{Deployment, now_secs},
    registry::Registry,
    secrets::{SecretRef, SecretStore},
};
use async_trait::async_trait;
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

const KEY: &str = "github-runners";
const POLL: u64 = 15;
const FRESH: u64 = 45;
const KEEPALIVE: u64 = 7 * 86400;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    id: String,
    repository: String,
    runner_id: u64,
    deployment: String,
    token: SecretRef,
    webhook_secret: SecretRef,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Install {
    bindings: Vec<Binding>,
}

fn segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        && s != "."
        && s != ".."
}

fn parse_install(ns: &str, value: &Value) -> Result<Install, String> {
    let mut install: Install = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    if install.bindings.is_empty() || install.bindings.len() > 20 {
        return Err("install requires 1–20 bindings".into());
    }
    let mut ids = BTreeSet::new();
    let mut deployments = BTreeSet::new();
    let mut runners = BTreeSet::new();
    for b in &mut install.bindings {
        let parts: Vec<_> = b.repository.split('/').collect();
        if !segment(&b.id)
            || parts.len() != 2
            || !parts.iter().all(|p| segment(p))
            || b.runner_id == 0
        {
            return Err("binding requires an id, owner/repository and numeric runner_id".into());
        }
        b.repository = b.repository.to_ascii_lowercase();
        if !ids.insert(b.id.clone())
            || !deployments.insert(b.deployment.clone())
            || !runners.insert((b.repository.clone(), b.runner_id))
        {
            return Err("binding ids, deployments and repository runners must be unique".into());
        }
        for r in [&mut b.token, &mut b.webhook_secret] {
            r.validate().map_err(|e| e.to_string())?;
            r.scope_to(ns);
        }
    }
    Ok(install)
}

#[derive(Deserialize)]
struct Label {
    name: String,
}
#[derive(Deserialize)]
struct Runner {
    id: u64,
    name: String,
    status: String,
    busy: bool,
    labels: Vec<Label>,
}
#[derive(Deserialize)]
struct Job {
    id: u64,
    status: String,
    labels: Vec<String>,
    runner_id: Option<u64>,
    runner_name: Option<String>,
}

fn needs_runner(r: &Runner, jobs: &[Job]) -> bool {
    r.busy
        || jobs.iter().any(|j| {
            if j.status == "completed" {
                return false;
            }
            j.runner_id == Some(r.id)
                || j.runner_name.as_deref() == Some(&r.name)
                || (j.status == "queued"
                    && !j.labels.is_empty()
                    && j.labels
                        .iter()
                        .all(|label| r.labels.iter().any(|l| l.name.eq_ignore_ascii_case(label))))
        })
}

#[derive(Default, Clone, Serialize)]
struct Observation {
    last_checked_at: u64,
    last_online_at: u64,
    awake: bool,
    seen_online: bool,
    sleep_allowed: bool,
    error: Option<String>,
}

pub struct GithubRunnersPlugin {
    me: Weak<Self>,
    registry: Arc<Registry>,
    secrets: Arc<SecretStore>,
    installs: RwLock<BTreeMap<String, Install>>,
    observations: Mutex<BTreeMap<(String, String), Observation>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    serial: tokio::sync::Mutex<()>,
    wake: tokio::sync::Notify,
    http: reqwest::Client,
    api: String,
}

impl GithubRunnersPlugin {
    pub fn new(registry: Arc<Registry>, secrets: Arc<SecretStore>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            registry,
            secrets,
            installs: RwLock::new(BTreeMap::new()),
            observations: Mutex::new(BTreeMap::new()),
            task: Mutex::new(None),
            serial: tokio::sync::Mutex::new(()),
            wake: tokio::sync::Notify::new(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .user_agent("Heyo-github-runners")
                .build()
                .unwrap(),
            api: "https://api.github.com".into(),
        })
    }

    fn deployment(&self, ns: &str, b: &Binding) -> Result<Arc<Deployment>, String> {
        let d = self
            .registry
            .get(&b.deployment)
            .filter(|d| d.spec.namespace == ns)
            .ok_or("binding deployment is not local to this namespace")?;
        if d.spec
            .vm
            .as_ref()
            .is_none_or(|v| v.driver != Driver::Libvirt || v.ttl_seconds != 0)
            || d.spec.scaling.idle_action != IdleAction::Suspend
            || d.spec.scaling.max_replicas != 1
            || d.spec.scaling.warm_pool != 0
            || d.spec.placement.is_some()
            || !d.state().adopted.is_empty()
        {
            return Err(
                "binding requires a host-local, single-replica owned Libvirt suspend deployment with ttl_seconds and warm_pool set to 0"
                    .into(),
            );
        }
        Ok(d)
    }

    fn permission(&self, d: &Deployment, until: u64) -> Result<(), String> {
        d.mutate_state(|s| {
            let was_blocked = s
                .sleep_permissions
                .get(KEY)
                .is_none_or(|t| *t <= now_secs());
            s.sleep_permissions.insert(KEY.into(), until);
            // Begin idle grace when actual work ends, not on every idle poll.
            if until == 0 || was_blocked {
                s.last_demand_at = now_secs();
            }
        });
        if self.registry.persist_one(&d.spec.id).is_err() {
            d.mutate_state(|s| {
                s.sleep_permissions.insert(KEY.into(), 0);
            });
            d.scale_signal.notify_one();
            return Err("could not persist sleep permission; keeping VM awake".into());
        }
        d.scale_signal.notify_one();
        Ok(())
    }

    async fn pages(&self, path: &str, key: &str, token: &str) -> Result<Vec<Value>, String> {
        let mut all = Vec::new();
        for page in 1..=100 {
            let sep = if path.contains('?') { '&' } else { '?' };
            let response = self
                .http
                .get(format!("{}{path}{sep}per_page=100&page={page}", self.api))
                .bearer_auth(token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
                .await
                .map_err(|_| "GitHub request failed")?;
            if !response.status().is_success() {
                return Err(format!(
                    "GitHub returned HTTP {}",
                    response.status().as_u16()
                ));
            }
            let body: Value = response
                .json()
                .await
                .map_err(|_| "invalid GitHub response")?;
            let rows = body[key].as_array().ok_or("incomplete GitHub collection")?;
            let total = body["total_count"]
                .as_u64()
                .ok_or("missing GitHub collection size")?;
            all.extend(rows.iter().cloned());
            // GitHub caps filtered workflow-run searches at 1,000 results.
            // Reaching that cap is uncertainty, not an idle repository.
            if key == "workflow_runs" && (total >= 1000 || all.len() >= 1000) {
                return Err("GitHub workflow search reached its result cap".into());
            }
            if rows.len() < 100 {
                if (all.len() as u64) < total {
                    return Err("GitHub collection was truncated".into());
                }
                return Ok(all);
            }
        }
        Err("GitHub pagination exceeded safety limit".into())
    }

    async fn snapshot(&self, b: &Binding) -> Result<(Runner, Vec<Job>), String> {
        let token = self
            .secrets
            .resolve(&b.token)
            .map_err(|_| "GitHub token unavailable")?;
        let prefix = format!("/repos/{}", b.repository);
        let runners = self
            .pages(&format!("{prefix}/actions/runners"), "runners", &token)
            .await?;
        let runners: Vec<Runner> =
            serde_json::from_value(json!(runners)).map_err(|_| "invalid runner response")?;
        let runner = runners
            .into_iter()
            .find(|r| r.id == b.runner_id)
            .ok_or("bound runner is missing")?;
        if runner.status != "online" && runner.status != "offline" {
            return Err("unknown runner status".into());
        }
        let mut runs = BTreeSet::new();
        for status in ["queued", "in_progress", "waiting", "pending", "requested"] {
            for run in self
                .pages(
                    &format!("{prefix}/actions/runs?status={status}"),
                    "workflow_runs",
                    &token,
                )
                .await?
            {
                runs.insert(run["id"].as_u64().ok_or("missing workflow run id")?);
            }
        }
        let mut jobs = BTreeMap::new();
        for run in runs {
            let rows = self
                .pages(
                    &format!("{prefix}/actions/runs/{run}/jobs?filter=latest"),
                    "jobs",
                    &token,
                )
                .await?;
            for row in rows {
                let job: Job = serde_json::from_value(row).map_err(|_| "invalid job response")?;
                if !["queued", "in_progress", "completed", "waiting", "pending"]
                    .contains(&job.status.as_str())
                {
                    return Err("unknown job status".into());
                }
                jobs.insert(job.id, job);
            }
        }
        Ok((runner, jobs.into_values().collect()))
    }

    async fn reconcile(&self) {
        let _serial = self.serial.lock().await;
        let installs = self.installs.read().unwrap().clone();
        for (ns, install) in installs {
            for b in install.bindings {
                let key = (ns.clone(), b.id.clone());
                let mut observation = self
                    .observations
                    .lock()
                    .unwrap()
                    .get(&key)
                    .cloned()
                    .unwrap_or_default();
                let started = Instant::now();
                let snapshot = tokio::time::timeout(Duration::from_secs(30), self.snapshot(&b))
                    .await
                    .unwrap_or_else(|_| Err("GitHub snapshot timed out".into()));
                let _change = self.registry.change_guard().await;
                let result = match self.deployment(&ns, &b) {
                    Err(e) => Err(e),
                    Ok(d) => {
                        let awake = !d.backends().is_empty() || !d.pending().is_empty();
                        if awake && !observation.awake {
                            observation.seen_online = false;
                        }
                        observation.awake = awake;
                        observation.last_checked_at = now_secs();
                        let allow = match &snapshot {
                            Ok((r, jobs)) if started.elapsed().as_secs() < 30 => {
                                if awake && r.status == "online" {
                                    observation.seen_online = true;
                                    observation.last_online_at = now_secs();
                                }
                                observation.seen_online
                                    && !needs_runner(r, jobs)
                                    && (!awake || r.status == "online")
                                    && now_secs().saturating_sub(observation.last_online_at)
                                        < KEEPALIVE
                            }
                            _ => false,
                        };
                        observation.sleep_allowed = allow;
                        let written =
                            self.permission(&d, if allow { now_secs() + FRESH } else { 0 });
                        written.and(snapshot.map(|_| ()))
                    }
                };
                observation.error = result.err();
                self.observations.lock().unwrap().insert(key, observation);
            }
        }
    }
}

#[async_trait]
impl Plugin for GithubRunnersPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: KEY,
            name: "GitHub runners",
            description: "Wake persistent GitHub runners on job demand; sleep only after fresh idle observations.",
            config_schema: json!({"type":"object","additionalProperties":false}),
        }
    }
    fn validate(&self, value: &Value) -> Result<(), String> {
        if value.as_object().is_none_or(|v| !v.is_empty()) {
            return Err("fleet configuration must be {}".into());
        }
        Ok(())
    }
    async fn apply(&self, config: Option<Value>) -> Result<(), String> {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
        // Permits expire even if disabled or the process dies. Existing VMs
        // wake and stay awake instead of treating a dead controller as idle.
        if let Some(config) = config {
            self.validate(&config)?;
            let me = self.me.clone();
            *self.task.lock().unwrap() = Some(tokio::spawn(async move {
                loop {
                    let Some(me) = me.upgrade() else { return };
                    me.reconcile().await;
                    tokio::select! { _ = tokio::time::sleep(Duration::from_secs(POLL)) => {}, _ = me.wake.notified() => {} }
                }
            }));
        }
        Ok(())
    }
    async fn status(&self) -> Value {
        json!({"namespaces": self.installs.read().unwrap().len(), "poll_secs":POLL,"freshness_secs":FRESH})
    }
    fn per_namespace(&self) -> bool {
        true
    }
    fn validate_install(&self, ns: &str, config: &Value) -> Result<(), String> {
        parse_install(ns, config).map(|_| ())
    }
    async fn on_install(&self, ns: &str, value: &Value, _: &Value) -> Result<(), SetError> {
        let install = parse_install(ns, value).map_err(SetError::Invalid)?;
        let _serial = self.serial.lock().await;
        let _change = self.registry.change_guard().await;
        let old = self.installs.read().unwrap().get(ns).cloned();
        if old.as_ref().is_some_and(|old| {
            old.bindings.iter().any(|b| {
                !install.bindings.iter().any(|n| {
                    n.deployment == b.deployment
                        && n.runner_id == b.runner_id
                        && n.repository == b.repository
                })
            })
        }) {
            return Err(SetError::Conflict("uninstall before removing or replacing bindings; first set their min_replicas to 1".into()));
        }
        let mut targets = Vec::new();
        for b in &install.bindings {
            for (other_ns, other) in self.installs.read().unwrap().iter() {
                if other_ns != ns
                    && other
                        .bindings
                        .iter()
                        .any(|o| o.repository == b.repository && o.runner_id == b.runner_id)
                {
                    return Err(SetError::Conflict("runner is already bound".into()));
                }
            }
            targets.push(self.deployment(ns, b).map_err(SetError::Invalid)?);
        }
        for d in targets {
            self.permission(&d, 0).map_err(SetError::Invalid)?;
        }
        self.observations
            .lock()
            .unwrap()
            .retain(|(n, _), _| n != ns);
        self.installs.write().unwrap().insert(ns.into(), install);
        self.wake.notify_one();
        Ok(())
    }
    async fn on_uninstall(&self, ns: &str, _: &Value) -> Result<(), SetError> {
        let _serial = self.serial.lock().await;
        let _change = self.registry.change_guard().await;
        let install = self.installs.read().unwrap().get(ns).cloned();
        if let Some(install) = install {
            let targets: Vec<_> = install
                .bindings
                .iter()
                .filter_map(|b| {
                    self.registry
                        .get(&b.deployment)
                        .filter(|d| d.spec.namespace == ns)
                })
                .collect();
            if targets.iter().any(|d| d.spec.scaling.min_replicas < 1) {
                return Err(SetError::Conflict(
                    "set min_replicas to 1 before removing runner control".into(),
                ));
            }
            for d in targets {
                d.mutate_state(|s| {
                    s.sleep_permissions.remove(KEY);
                });
                self.registry
                    .persist_one(&d.spec.id)
                    .map_err(SetError::Io)?;
            }
        }
        self.installs.write().unwrap().remove(ns);
        self.observations
            .lock()
            .unwrap()
            .retain(|(n, _), _| n != ns);
        Ok(())
    }
    fn namespace_routes(self: Arc<Self>) -> Router {
        Router::new().route("/status", get(|State(p): State<Arc<Self>>, Extension(ns): Extension<NamespaceScope>| async move {
            let rows: BTreeMap<_,_> = p.observations.lock().unwrap().iter().filter(|((n,_),_)| n == &ns.0).map(|((_,id),v)| (id.clone(),v.clone())).collect();
            Json(rows)
        })).with_state(self)
    }
    fn machine_routes(self: Arc<Self>) -> Router {
        Router::new()
            .route("/hooks/:namespace/:binding", post(hook))
            .layer(DefaultBodyLimit::max(128 * 1024))
            .with_state(self)
    }
}

fn valid_signature(secret: &[u8], body: &[u8], signature: &str) -> bool {
    let Some(hex) = signature.strip_prefix("sha256=") else {
        return false;
    };
    if hex.len() != 64 {
        return false;
    }
    let mut supplied = Vec::with_capacity(32);
    for pair in hex.as_bytes().chunks_exact(2) {
        let Ok(pair) = std::str::from_utf8(pair) else {
            return false;
        };
        let Ok(byte) = u8::from_str_radix(pair, 16) else {
            return false;
        };
        supplied.push(byte);
    }
    let Ok(key) = openssl::pkey::PKey::hmac(secret) else {
        return false;
    };
    let Ok(mut signer) = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key)
    else {
        return false;
    };
    if signer.update(body).is_err() {
        return false;
    }
    signer
        .sign_to_vec()
        .is_ok_and(|expected| openssl::memcmp::eq(&expected, &supplied))
}

async fn hook(
    State(p): State<Arc<GithubRunnersPlugin>>,
    Extension(installs): Extension<Installs>,
    Path((ns, id)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> StatusCode {
    if !installs.0.contains(&ns) {
        return StatusCode::NOT_FOUND;
    }
    let binding = p
        .installs
        .read()
        .unwrap()
        .get(&ns)
        .and_then(|i| i.bindings.iter().find(|b| b.id == id).cloned());
    let Some(b) = binding else {
        return StatusCode::NOT_FOUND;
    };
    let Ok(secret) = p.secrets.resolve(&b.webhook_secret) else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    if !valid_signature(
        secret.as_bytes(),
        &body,
        headers
            .get("x-hub-signature-256")
            .and_then(|h| h.to_str().ok())
            .unwrap_or(""),
    ) {
        return StatusCode::UNAUTHORIZED;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    if !value["repository"]["full_name"]
        .as_str()
        .is_some_and(|r| r.eq_ignore_ascii_case(&b.repository))
    {
        return StatusCode::FORBIDDEN;
    }
    match headers.get("x-github-event").and_then(|h| h.to_str().ok()) {
        Some("ping") => StatusCode::OK,
        Some("workflow_job") => {
            p.wake.notify_one();
            StatusCode::ACCEPTED
        }
        _ => StatusCode::BAD_REQUEST,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::VmBackend;
    use axum::{extract::Query, response::IntoResponse};

    #[derive(Clone)]
    struct Github {
        runner: Value,
        jobs: Vec<Value>,
        fail: bool,
        extra_runs: usize,
    }

    fn config() -> Value {
        json!({"bindings":[{"id":"ci","repository":"owner/repo","runner_id":42,"deployment":"ci", "token":{"secret":"github", "namespace":"other"},"webhook_secret":{"secret":"hook"}}]})
    }

    async fn fixture() -> (
        tempfile::TempDir,
        Arc<GithubRunnersPlugin>,
        Arc<Mutex<Github>>,
        tokio::task::JoinHandle<()>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(Registry::new(dir.path().join("state.json")));
        let secrets = Arc::new(SecretStore::new(dir.path().join("secrets.json"), None));
        for (id, token) in [("github", "namespace-token"), ("hook", "hook-secret")] {
            secrets.put(
                serde_json::from_value(json!({"id":id,"namespace":"team","data":{"token":token}}))
                    .unwrap(),
            );
        }
        let d = registry.upsert(serde_json::from_value(json!({"id":"ci","namespace":"team","routes":[],"vm":{"driver":"libvirt","port":22,"ttl_seconds":0},"scaling":{"min_replicas":0,"max_replicas":1,"scale_to_zero_after_secs":0,"idle_action":"suspend"}})).unwrap());
        d.set_backends(vec![Arc::new(VmBackend::new(
            "sb-test".into(),
            "127.0.0.1:22".parse().unwrap(),
        ))]);
        let github = Arc::new(Mutex::new(Github {
            runner: json!({"id":42,"name":"persistent-ci","status":"online","busy":false,"labels":[{"name":"self-hosted"},{"name":"heyo-ci"}]}),
            jobs: vec![],
            fail: false,
            extra_runs: 0,
        }));
        let state = github.clone();
        let router = Router::new().fallback(get(
            move |uri: axum::http::Uri,
                  Query(query): Query<BTreeMap<String, String>>,
                  headers: HeaderMap| {
                let state = state.clone();
                async move {
                    assert_eq!(
                        headers["authorization"], "Bearer namespace-token",
                        "secret is confined to the installing namespace"
                    );
                    let g = state.lock().unwrap();
                    if g.fail {
                        return StatusCode::FORBIDDEN.into_response();
                    }
                    let path = uri.path();
                    if path.ends_with("/runners") {
                        return Json(json!({"total_count":1,"runners":[g.runner]})).into_response();
                    }
                    if path.ends_with("/runs") {
                        let runs = if query.get("status").map(String::as_str) == Some("queued") {
                            vec![json!({"id":101})]
                        } else {
                            vec![]
                        };
                        return Json(
                            json!({"total_count":runs.len()+g.extra_runs,"workflow_runs":runs}),
                        )
                        .into_response();
                    }
                    if path.ends_with("/jobs") {
                        let page = query["page"].parse::<usize>().unwrap();
                        let jobs: Vec<_> = g.jobs.iter().skip((page - 1) * 100).take(100).collect();
                        return Json(json!({"total_count":g.jobs.len(),"jobs":jobs}))
                            .into_response();
                    }
                    StatusCode::NOT_FOUND.into_response()
                }
            },
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let plugin = Arc::new_cyclic(|me| GithubRunnersPlugin {
            me: me.clone(),
            registry,
            secrets,
            api: url,
            installs: RwLock::new(BTreeMap::new()),
            observations: Mutex::new(BTreeMap::new()),
            task: Mutex::new(None),
            serial: tokio::sync::Mutex::new(()),
            wake: tokio::sync::Notify::new(),
            http: reqwest::Client::new(),
        });
        plugin
            .on_install("team", &config(), &json!({}))
            .await
            .unwrap();
        (dir, plugin, github, task)
    }

    #[tokio::test]
    async fn queued_work_wakes_and_busy_errors_expiry_and_restart_fail_awake() {
        let (_dir, p, github, task) = fixture().await;
        let d = p.registry.get("ci").unwrap();
        assert_eq!(d.desired_replicas(), 1, "no GitHub observation yet");
        p.reconcile().await;
        assert_eq!(
            d.desired_replicas(),
            0,
            "confirmed online idle runner may sleep"
        );
        d.set_backends(vec![]);
        github.lock().unwrap().runner["status"] = json!("offline");
        p.reconcile().await;
        assert_eq!(
            d.desired_replicas(),
            0,
            "sleeping runner need not stay online"
        );
        // The only matching job is on page two, so a truncated snapshot fails.
        github.lock().unwrap().jobs = (0..100).map(|id| json!({"id":id,"status":"queued","labels":["another-runner"],"runner_id":null,"runner_name":null})).collect();
        p.reconcile().await;
        assert_eq!(
            d.desired_replicas(),
            0,
            "unrelated jobs must not wake this runner"
        );
        github.lock().unwrap().jobs.push(json!({"id":100,"status":"queued","labels":["heyo-ci"],"runner_id":null,"runner_name":null}));
        p.reconcile().await;
        assert_eq!(
            d.desired_replicas(),
            1,
            "polling alone recovers a missing webhook"
        );
        github.lock().unwrap().jobs.clear();
        d.set_backends(vec![Arc::new(VmBackend::new(
            "sb-test".into(),
            "127.0.0.1:22".parse().unwrap(),
        ))]);
        p.reconcile().await;
        assert_eq!(
            d.desired_replicas(),
            1,
            "restoring VM must reconnect its runner"
        );
        github.lock().unwrap().runner["status"] = json!("online");
        github.lock().unwrap().runner["busy"] = json!(true);
        p.reconcile().await;
        assert_eq!(
            d.desired_replicas(),
            1,
            "busy runner stays awake even without job rows"
        );
        github.lock().unwrap().runner["busy"] = json!(false);
        p.reconcile().await;
        assert_eq!(d.desired_replicas(), 0);
        github.lock().unwrap().jobs.push(json!({"id":102,"status":"in_progress","labels":["old-label"],"runner_id":42,"runner_name":"persistent-ci"}));
        p.reconcile().await;
        assert_eq!(
            d.desired_replicas(),
            1,
            "assigned jobs override stale busy and label metadata"
        );
        github.lock().unwrap().jobs.clear();
        for extra in [1, 1000] {
            github.lock().unwrap().extra_runs = extra;
            p.reconcile().await;
            assert_eq!(
                d.desired_replicas(),
                1,
                "truncated and capped inventories must fail awake"
            );
        }
        github.lock().unwrap().extra_runs = 0;
        github.lock().unwrap().fail = true;
        p.reconcile().await;
        assert_eq!(d.desired_replicas(), 1, "API errors are not idleness");
        github.lock().unwrap().fail = false;
        p.reconcile().await;
        d.mutate_state(|s| {
            s.sleep_permissions.insert(KEY.into(), now_secs());
        });
        assert_eq!(
            d.desired_replicas(),
            1,
            "dead controller's permission expires into demand"
        );
        p.registry.persist_one("ci").unwrap();
        let reloaded = Registry::new(_dir.path().join("state.json"));
        reloaded.load().unwrap();
        assert_eq!(
            reloaded.get("ci").unwrap().desired_replicas(),
            1,
            "expired guard survives process restart"
        );
        p.reconcile().await;
        assert_eq!(d.desired_replicas(), 0);
        p.on_install("team", &config(), &json!({})).await.unwrap();
        assert_eq!(
            d.desired_replicas(),
            1,
            "controller restart needs fresh observations"
        );
        assert!(
            p.on_uninstall("team", &json!({})).await.is_err(),
            "cannot remove busy-work safety"
        );
        task.abort();
    }

    #[tokio::test]
    async fn signed_webhooks_are_tenant_bound_hints_not_sleep_commands() {
        let (_dir, p, _github, task) = fixture().await;
        let router = p
            .clone()
            .machine_routes()
            .layer(Extension(Installs(BTreeSet::from(["team".into()]))));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hooks = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let body = r#"{"repository":{"full_name":"owner/repo"},"action":"completed"}"#;
        let sign = |body: &str| {
            let key = openssl::pkey::PKey::hmac(b"hook-secret").unwrap();
            let mut signer =
                openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
            signer.update(body.as_bytes()).unwrap();
            format!(
                "sha256={}",
                signer
                    .sign_to_vec()
                    .unwrap()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        };
        for (path, payload, signature, expected) in [
            (
                "/hooks/team/ci",
                body,
                String::new(),
                StatusCode::UNAUTHORIZED,
            ),
            (
                "/hooks/team/ci",
                body,
                format!("sha256={}", "00".repeat(32)),
                StatusCode::UNAUTHORIZED,
            ),
            ("/hooks/other/ci", body, sign(body), StatusCode::NOT_FOUND),
            (
                "/hooks/team/ci",
                "{\"repository\":{\"full_name\":\"owner/other\"}}",
                sign("{\"repository\":{\"full_name\":\"owner/other\"}}"),
                StatusCode::FORBIDDEN,
            ),
            ("/hooks/team/ci", body, sign(body), StatusCode::ACCEPTED),
            ("/hooks/team/ci", body, sign(body), StatusCode::ACCEPTED),
        ] {
            let response = p
                .http
                .post(format!("{url}{path}"))
                .header("x-hub-signature-256", signature)
                .header("x-github-event", "workflow_job")
                .body(payload)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            assert_eq!(
                p.registry.get("ci").unwrap().desired_replicas(),
                1,
                "even repeated completed events cannot release demand"
            );
        }
        assert!(p.on_install("other", &config(), &json!({})).await.is_err());
        hooks.abort();
        task.abort();
    }
}
