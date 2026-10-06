//! Polls app-lb's `GET /metrics` and flattens it into metric rows.
//!
//! app-lb already measures everything worth storing — host CPU/memory from the
//! daemon, per-VM CPU/RSS, pool occupancy, request counts and latency
//! percentiles — but keeps it only in memory, cumulative since process start and
//! gone on restart. This turns that live snapshot into history.
//!
//! Only the fields consumed here are declared; serde ignores the rest, so
//! app-lb can add to its response without breaking this.

use crate::ingest::Sink;
use crate::namespaces::{Directory, Gate};
use crate::sources::VmTarget;
use crate::store::schema::{LEGACY_NAMESPACE, MetricRecord, Record};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Reserved deployment id for whole-host samples, which belong to no
/// deployment. Chosen to be a legal partition name while being unlikely to
/// collide: app-lb ids in practice are slugs like `demo` or `vault-86a37f`.
pub const HOST_DEPLOYMENT: &str = "_host";

/// Reserved deployment id for sandboxes on the host that no deployment owns —
/// created through the heyvm CLI, the cloud API or the desktop rather than by
/// app-lb. Their logs and per-VM usage land here, keyed by `backend` (the
/// sandbox id), so a row in this partition always names its sandbox. One
/// partition rather than one per sandbox because sandboxes made by hand come
/// and go by the hundred, and a partition directory per short-lived VM is the
/// file-count problem compaction exists to avoid.
pub const UNMANAGED_DEPLOYMENT: &str = "_unmanaged";

#[derive(Debug, Clone, Deserialize)]
struct MetricsResponse {
    /// Unix seconds. Used as the timestamp for every row in the poll so a chart
    /// lines them up instead of smearing them across the collection latency.
    generated_at: u64,
    host: HostUsage,
    deployments: Vec<DeploymentView>,
    /// Sandboxes on the host outside every deployment. Absent from an app-lb
    /// that predates the field, which is then indistinguishable from a host
    /// with none — the honest reading, since such an app-lb never looked.
    #[serde(default)]
    host_sandboxes: Vec<HostSandboxView>,
}

/// One sandbox app-lb reports but does not manage. Everything but the id is
/// optional on the way in: this is decoration for a person, and a row missing
/// its image must not cost the poll.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct HostSandboxView {
    pub sandbox_id: String,
    #[serde(default)]
    pub name: String,
    /// The daemon's word: `running`, `stopped`, `provisioning`, …
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub size_class: Option<String>,
    #[serde(default)]
    pub guest_ip: Option<String>,
    #[serde(default)]
    pub uptime_secs: u64,
    #[serde(default)]
    pub cpu_percent: Option<f64>,
    #[serde(default)]
    pub memory_bytes: Option<u64>,
    /// The heyo account it is billed to, when the daemon knows.
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

impl HostSandboxView {
    /// Whether the guest has a console worth tailing. A stopped sandbox prints
    /// nothing, and asking the daemon to stream it would reconnect forever.
    fn is_live(&self) -> bool {
        matches!(self.status.as_deref(), Some("running" | "provisioning"))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct HostUsage {
    pub available: bool,
    pub cpu_percent: f64,
    pub memory_used_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct DeploymentView {
    pub id: String,
    /// The app-lb namespace the deployment lives in. Absent from an app-lb
    /// that predates reporting it, where every deployment was in `default`.
    #[serde(default)]
    pub namespace: Option<String>,
    /// `vm` or `static`. Optional because an older app-lb may not send it;
    /// see [`vm_targets`] for how that absence is handled.
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Older app-lb versions did not report this field. Absence means unknown,
    /// not routed: inventing a route would turn idle agent sandboxes into false
    /// outages during a mixed-version rollout.
    #[serde(default)]
    pub routed: Option<bool>,
    pub pool: PoolStatus,
    #[serde(default)]
    pub vms: Vec<VmView>,
    pub metrics: DeploymentMetrics,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct PoolStatus {
    #[serde(default)]
    pub desired_replicas: Option<u32>,
    pub ready: u32,
    pub draining: u32,
    pub pending: u32,
    #[serde(default)]
    pub min_replicas: Option<u32>,
    pub total_in_flight: u32,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct VmView {
    /// app-lb calls this `sandbox_id` for both kinds of backend, but for a
    /// static deployment it holds the upstream `host:port` rather than a
    /// sandbox. Stored as `backend` for that reason; the wire name is app-lb's.
    #[serde(rename(deserialize = "sandbox_id"))]
    pub backend: String,
    pub in_flight: u32,
    #[serde(default)]
    pub healthy: bool,
    #[serde(default)]
    pub draining: bool,
    #[serde(default)]
    pub uptime_secs: u64,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct DeploymentMetrics {
    pub requests: StatusCounts,
    pub latency_ms: Histogram,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct StatusCounts {
    pub total: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Histogram {
    pub count: u64,
    /// Total of every sample, in the histogram's base unit. Cumulative like
    /// `count`, so the two together give a per-interval mean once differenced —
    /// see `MetricRecord::latency_count`.
    pub sum: u64,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
}

/// The current topology and gauges behind the platform status API. Historical
/// storage remains the flattened parquet rows below.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct LiveStatus {
    pub schema_version: u8,
    pub source: String,
    pub observed_at_ms: i64,
    pub app_lb_generated_at_ms: i64,
    pub host: HostUsage,
    pub deployments: Vec<DeploymentView>,
    /// Sandboxes on the host outside every deployment, as app-lb last saw
    /// them. Empty from an app-lb that does not report them.
    pub host_sandboxes: Vec<HostSandboxView>,
}

pub struct Poller {
    client: reqwest::Client,
    url: String,
    auth: Option<(String, String)>,
    interval: Duration,
    sink: Sink,
    source: String,
    live: tokio::sync::watch::Sender<Option<LiveStatus>>,
    /// Where the current VM set goes after each successful poll, for the
    /// daemon log tailer. Deliberately never cleared on a failed poll: app-lb
    /// restarting must not stop log collection from sandboxes that are still
    /// running.
    targets: Option<tokio::sync::watch::Sender<Vec<VmTarget>>>,
    /// Where each deployment's namespace and the obs installs are published,
    /// for the sink's attribution and gate.
    directory: Arc<Directory>,
    installs_url: String,
    /// Set once an app-lb without the installs endpoint has been reported, so
    /// a fleet that is simply older says so once rather than every tick.
    warned_no_installs: AtomicBool,
}

/// The part of app-lb's `GET /api/plugins/obs/installs` this reads.
#[derive(Debug, Deserialize)]
struct InstallsResponse {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    namespaces: Vec<String>,
}

impl InstallsResponse {
    fn gate(self) -> Gate {
        if self.enabled {
            Gate::Installed(self.namespaces.into_iter().collect::<HashSet<_>>())
        } else {
            // The fleet plugin is off, so no install is in force; collect as
            // this collector always has. See `namespaces`.
            Gate::Open
        }
    }
}

impl Poller {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_url: &str,
        user: Option<String>,
        password: Option<String>,
        interval: Duration,
        sink: Sink,
        source: String,
        live: tokio::sync::watch::Sender<Option<LiveStatus>>,
        targets: Option<tokio::sync::watch::Sender<Vec<VmTarget>>>,
        directory: Arc<Directory>,
    ) -> Self {
        // app-lb's admin API is loopback and answers promptly or not at all; a
        // short timeout keeps a wedged connection from stalling the poll loop
        // past its own interval.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        // Only Basic auth, and only when a password is set — matching app-lb,
        // where the gate turns on with `APP_LB_DASHBOARD_PASSWORD` and the user
        // defaults to `admin`.
        let auth = password.map(|p| (user.unwrap_or_else(|| "admin".into()), p));

        let base = base_url.trim_end_matches('/');
        Self {
            client,
            url: format!("{base}/metrics"),
            auth,
            interval,
            sink,
            source,
            live,
            targets,
            directory,
            installs_url: format!("{base}/api/plugins/obs/installs"),
            warned_no_installs: AtomicBool::new(false),
        }
    }

    /// Ask app-lb which namespaces installed the obs plugin, and publish the
    /// answer as the gate. A failure leaves the previous gate in place: a
    /// blip in app-lb must neither open collection to every namespace nor
    /// close it on the ones that asked for it.
    async fn refresh_installs(&self) {
        if !self.directory.requires_install() {
            return;
        }
        let mut request = self.client.get(&self.installs_url);
        if let Some((user, password)) = &self.auth {
            request = request.basic_auth(user, Some(password));
        }
        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(url = %self.installs_url, error = %e, "obs installs poll failed; keeping the last answer");
                return;
            }
        };
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            if !self.warned_no_installs.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    url = %self.installs_url,
                    "app-lb has no obs installs endpoint (it predates per-namespace \
                     plugins); collecting every namespace",
                );
            }
            self.directory.set_gate(Gate::Open);
            return;
        }
        match response.error_for_status() {
            Ok(r) => match r.json::<InstallsResponse>().await {
                Ok(installs) => self.directory.set_gate(installs.gate()),
                Err(e) => {
                    tracing::warn!(url = %self.installs_url, error = %e, "unreadable obs installs; keeping the last answer")
                }
            },
            Err(e) => {
                tracing::warn!(url = %self.installs_url, error = %e, "obs installs poll failed; keeping the last answer")
            }
        }
    }

    /// Poll until the process ends.
    ///
    /// app-lb being unreachable is expected, not exceptional — it restarts, and
    /// it may well start after we do. Failures are logged and retried on the
    /// next tick rather than ending the loop.
    pub async fn run(self) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            match self.poll_once().await {
                Ok(count) => tracing::debug!(rows = count, "polled app-lb metrics"),
                Err(e) => tracing::warn!(url = %self.url, error = %e, "app-lb metrics poll failed"),
            }
        }
    }

    async fn poll_once(&self) -> Result<usize, reqwest::Error> {
        let mut request = self.client.get(&self.url);
        if let Some((user, password)) = &self.auth {
            request = request.basic_auth(user, Some(password));
        }
        let response = request.send().await?.error_for_status()?;
        let snapshot: MetricsResponse = response.json().await?;

        // Attribution and the gate before a single row is sent, so this poll's
        // rows are judged by this poll's answer.
        self.directory.set_namespaces(namespaces_of(&snapshot));
        self.refresh_installs().await;

        let live = LiveStatus {
            schema_version: 1,
            source: self.source.clone(),
            observed_at_ms: now_ms(),
            app_lb_generated_at_ms: (snapshot.generated_at as i64).saturating_mul(1000),
            host: snapshot.host.clone(),
            deployments: snapshot.deployments.clone(),
            host_sandboxes: snapshot.host_sandboxes.clone(),
        };
        self.live.send_replace(Some(live));

        if let Some(targets) = &self.targets {
            // send_if_modified so an unchanged fleet doesn't wake the tailer
            // manager every poll tick.
            // Only sandboxes whose logs would be kept: tailing a namespace
            // that has not installed obs would hold a stream open to drop
            // every line it carries.
            let mut current = vm_targets(&snapshot);
            current.retain(|t| self.directory.admit(&t.deployment).is_some());
            targets.send_if_modified(|previous| {
                if *previous == current {
                    false
                } else {
                    *previous = current;
                    true
                }
            });
        }

        let records = flatten(&snapshot);
        let count = records.len();
        for record in records {
            self.sink.send(record);
        }
        Ok(count)
    }
}

/// Deployment id → namespace, as `/metrics` reports it.
fn namespaces_of(snapshot: &MetricsResponse) -> HashMap<String, String> {
    snapshot
        .deployments
        .iter()
        .map(|d| {
            (
                d.id.clone(),
                d.namespace
                    .clone()
                    .unwrap_or_else(|| LEGACY_NAMESPACE.to_string()),
            )
        })
        .collect()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as i64)
}

/// The sandboxes worth tailing daemon logs from: every backend of a VM
/// deployment, plus every live sandbox on the host that belongs to none.
/// Static deployments are excluded — their "vms" entries hold `host:port`
/// upstreams, which the daemon has never heard of. When an older app-lb omits
/// `kind`, the backend's shape decides: a `host:port` always contains a
/// colon, a sandbox id never does.
///
/// The unowned sandboxes are attributed to [`UNMANAGED_DEPLOYMENT`]: app-lb
/// is still the authority on what is on the host, it has simply said "this
/// one is nobody's". They are tailed while live and dropped when they stop,
/// which is the same lifecycle a pool's VM gets.
fn vm_targets(snapshot: &MetricsResponse) -> Vec<VmTarget> {
    let mut targets = Vec::new();
    for deployment in &snapshot.deployments {
        for vm in &deployment.vms {
            let is_vm = match deployment.kind.as_deref() {
                Some("vm") => true,
                Some(_) => false,
                None => !vm.backend.contains(':'),
            };
            if is_vm {
                targets.push(VmTarget {
                    deployment: deployment.id.clone(),
                    backend: vm.backend.clone(),
                });
            }
        }
    }
    for sandbox in snapshot.host_sandboxes.iter().filter(|s| s.is_live()) {
        targets.push(VmTarget {
            deployment: UNMANAGED_DEPLOYMENT.into(),
            backend: sandbox.sandbox_id.clone(),
        });
    }
    targets
}

/// Turn one snapshot into rows: one for the host, one per deployment, one per VM.
fn flatten(snapshot: &MetricsResponse) -> Vec<Record> {
    // Seconds to millis. Every row in a poll shares this, so a chart joins them
    // on a single x value.
    let ts_millis = (snapshot.generated_at as i64).saturating_mul(1000);
    let mut records = Vec::new();

    // `available` is false until the daemon has produced a sample; writing zeros
    // then would draw a real-looking idle host.
    if snapshot.host.available {
        records.push(Record::Metric(MetricRecord {
            ts_millis,
            deployment: HOST_DEPLOYMENT.into(),
            cpu_percent: Some(snapshot.host.cpu_percent),
            memory_bytes: Some(snapshot.host.memory_used_bytes),
            ..Default::default()
        }));
    }

    for deployment in &snapshot.deployments {
        // Deployment-wide row: pool gauges plus traffic. Percentiles are
        // meaningless before any request has been measured, so they stay null
        // rather than reporting a confident 0ms.
        let measured = deployment.metrics.latency_ms.count > 0;
        records.push(Record::Metric(MetricRecord {
            ts_millis,
            deployment: deployment.id.clone(),
            backend: None,
            cpu_percent: deployment.pool.cpu_percent,
            memory_bytes: deployment.pool.memory_bytes,
            in_flight: Some(deployment.pool.total_in_flight),
            ready: Some(deployment.pool.ready),
            pending: Some(deployment.pool.pending),
            draining: Some(deployment.pool.draining),
            requests_total: Some(deployment.metrics.requests.total),
            errors_total: Some(deployment.metrics.requests.errors),
            p50_ms: measured.then_some(deployment.metrics.latency_ms.p50),
            p90_ms: measured.then_some(deployment.metrics.latency_ms.p90),
            p99_ms: measured.then_some(deployment.metrics.latency_ms.p99),
            // Unlike the percentiles, these are kept even at count = 0: a zero
            // count is a real measurement ("nothing has been timed yet"), and
            // the next sample's delta against it is the first honest interval.
            latency_count: Some(deployment.metrics.latency_ms.count),
            latency_sum: Some(deployment.metrics.latency_ms.sum),
            namespace: None,
        }));

        // Per-VM rows. Pool and traffic figures are deployment-wide and are left
        // null here rather than duplicated, so summing a column across VMs can't
        // silently multiply them.
        for vm in &deployment.vms {
            records.push(Record::Metric(MetricRecord {
                ts_millis,
                deployment: deployment.id.clone(),
                backend: Some(vm.backend.clone()),
                cpu_percent: vm.cpu_percent,
                memory_bytes: vm.memory_bytes,
                in_flight: Some(vm.in_flight),
                ..Default::default()
            }));
        }
    }

    // The sandboxes outside every deployment, under their reserved partition.
    // A rollup row first — `ready` is how many are live, and usage is the sum
    // of what the daemon sampled — because the fleet view reads the
    // deployment-wide series (rows with no `backend`), and without one this
    // partition would list on the overview as a blank. Then one row per
    // sandbox, exactly as a pool's VMs are recorded. Nothing at all when the
    // list is empty: an app-lb that does not report the field would otherwise
    // write a partition that says "none" every ten seconds forever.
    if !snapshot.host_sandboxes.is_empty() {
        let sampled: Vec<_> = snapshot
            .host_sandboxes
            .iter()
            .filter(|s| s.cpu_percent.is_some() || s.memory_bytes.is_some())
            .collect();
        records.push(Record::Metric(MetricRecord {
            ts_millis,
            deployment: UNMANAGED_DEPLOYMENT.into(),
            backend: None,
            cpu_percent: (!sampled.is_empty())
                .then(|| sampled.iter().filter_map(|s| s.cpu_percent).sum()),
            memory_bytes: (!sampled.is_empty())
                .then(|| sampled.iter().filter_map(|s| s.memory_bytes).sum()),
            ready: Some(
                snapshot
                    .host_sandboxes
                    .iter()
                    .filter(|s| s.is_live())
                    .count() as u32,
            ),
            ..Default::default()
        }));
        for sandbox in &snapshot.host_sandboxes {
            records.push(Record::Metric(MetricRecord {
                ts_millis,
                deployment: UNMANAGED_DEPLOYMENT.into(),
                backend: Some(sandbox.sandbox_id.clone()),
                cpu_percent: sandbox.cpu_percent,
                memory_bytes: sandbox.memory_bytes,
                ..Default::default()
            }));
        }
    }

    records
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response in the shape app-lb actually serves.
    const SNAPSHOT: &str = r#"{
        "generated_at": 1785260096,
        "uptime_secs": 3600,
        "host": {
            "available": true,
            "cpu_count": 8,
            "cpu_percent": 42.5,
            "memory_total_bytes": 16000000000,
            "memory_used_bytes": 8000000000,
            "sampled_at_ms": 1785260096000
        },
        "fleet": {"deployments": 1, "ready": 2, "draining": 0, "pending": 0, "total_in_flight": 3},
        "global": {
            "requests": {"total": 100, "c2xx": 95, "c3xx": 0, "c4xx": 4, "c5xx": 1, "errors": 5},
            "latency_ms": {"count": 100, "sum": 1000, "mean": 10.0, "p50": 8.0, "p90": 25.0, "p99": 90.0, "buckets": []},
            "cold_start_s": {"count": 0, "sum": 0, "mean": 0.0, "p50": 0.0, "p90": 0.0, "p99": 0.0, "buckets": []},
            "autoscale": {}
        },
        "deployments": [{
            "id": "demo",
            "kind": "vm",
            "upstreams": [],
            "routed": true,
            "pool": {
                "desired_replicas": 2, "ready": 2, "draining": 0, "pending": 1,
                "total_in_flight": 3, "target_concurrency": 10, "min_replicas": 1,
                "max_replicas": 4, "warm_pool": 0, "utilization": 0.15,
                "cpu_percent": 12.5, "memory_bytes": 500000000
            },
            "vms": [
                {"sandbox_id": "sb-aaa", "addr": "172.16.0.2:8080", "in_flight": 2,
                 "healthy": true, "draining": false, "uptime_secs": 120,
                 "cpu_percent": 7.5, "memory_bytes": 300000000},
                {"sandbox_id": "sb-bbb", "addr": "172.16.0.6:8080", "in_flight": 1,
                 "healthy": true, "draining": false, "uptime_secs": 60,
                 "cpu_percent": null, "memory_bytes": null}
            ],
            "metrics": {
                "requests": {"total": 100, "c2xx": 95, "c3xx": 0, "c4xx": 4, "c5xx": 1, "errors": 5},
                "latency_ms": {"count": 100, "sum": 1000, "mean": 10.0, "p50": 8.0, "p90": 25.0, "p99": 90.0, "buckets": []},
                "cold_start_s": {"count": 0, "sum": 0, "mean": 0.0, "p50": 0.0, "p90": 0.0, "p99": 0.0, "buckets": []},
                "autoscale": {}
            }
        }],
        "host_sandboxes": [
            {"sandbox_id": "sb-hand", "name": "sam-dev", "status": "running", "image": "ubuntu:24.04",
             "size_class": "medium", "guest_ip": "172.16.0.10", "uptime_secs": 5400,
             "cpu_percent": 3.5, "memory_bytes": 536870912, "account_id": "acc-team-a",
             "created_at": "2026-08-28T10:00:00+00:00"},
            {"sandbox_id": "sb-cold", "name": "scratch", "status": "stopped", "image": "ubuntu:24.04",
             "uptime_secs": 0, "cpu_percent": null, "memory_bytes": null}
        ]
    }"#;

    fn parse() -> MetricsResponse {
        serde_json::from_str(SNAPSHOT).expect("app-lb's real response shape must deserialize")
    }

    #[test]
    fn a_real_applb_response_deserializes() {
        let snapshot = parse();
        assert_eq!(snapshot.generated_at, 1_785_260_096);
        assert_eq!(snapshot.deployments.len(), 1);
        assert_eq!(snapshot.deployments[0].routed, Some(true));
        assert_eq!(snapshot.deployments[0].vms.len(), 2);
    }

    #[test]
    fn an_old_response_keeps_routing_unknown() {
        let old = SNAPSHOT.replace("\n            \"routed\": true,", "");
        let snapshot: MetricsResponse = serde_json::from_str(&old).unwrap();
        assert_eq!(snapshot.deployments[0].routed, None);
    }

    #[test]
    fn one_poll_yields_host_deployment_and_per_vm_rows() {
        let records = flatten(&parse());
        assert_eq!(
            records.len(),
            7,
            "1 host + 1 deployment + 2 VMs + 1 unmanaged rollup + 2 unmanaged sandboxes"
        );

        // Every row shares the snapshot's timestamp so a chart aligns them.
        for record in &records {
            assert_eq!(record.ts_millis(), 1_785_260_096_000);
        }
    }

    #[test]
    fn host_usage_lands_under_the_reserved_deployment() {
        let records = flatten(&parse());
        let Record::Metric(host) = &records[0] else {
            panic!("expected a metric");
        };
        assert_eq!(host.deployment, HOST_DEPLOYMENT);
        assert_eq!(host.backend, None);
        assert_eq!(host.cpu_percent, Some(42.5));
        assert_eq!(host.memory_bytes, Some(8_000_000_000));
    }

    #[test]
    fn unsampled_host_usage_is_omitted_rather_than_written_as_zero() {
        // app-lb reports available=false until the daemon's first sample;
        // storing zeros would draw a convincing idle host that never existed.
        let mut snapshot = parse();
        snapshot.host.available = false;
        let records = flatten(&snapshot);
        assert_eq!(records.len(), 6, "host row dropped, everything else stays");
        assert!(records.iter().all(|r| r.deployment() != HOST_DEPLOYMENT));
    }

    /// The sandboxes outside every deployment land under their reserved
    /// partition: a rollup row the fleet view can read, then one row per
    /// sandbox named by `backend`, so nothing there is ever anonymous.
    #[test]
    fn unmanaged_sandboxes_land_under_the_reserved_deployment() {
        let records = flatten(&parse());
        let rows: Vec<&MetricRecord> = records
            .iter()
            .filter_map(|r| match r {
                Record::Metric(m) if m.deployment == UNMANAGED_DEPLOYMENT => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(rows.len(), 3);
        let rollup = rows[0];
        assert_eq!(rollup.backend, None);
        assert_eq!(rollup.ready, Some(1), "one of the two is live");
        assert_eq!(rollup.cpu_percent, Some(3.5), "the sum of what was sampled");
        assert_eq!(rollup.memory_bytes, Some(536_870_912));
        assert_eq!(rollup.requests_total, None, "nothing is proxied to them");
        assert_eq!(rows[1].backend.as_deref(), Some("sb-hand"));
        assert_eq!(rows[1].cpu_percent, Some(3.5));
        assert_eq!(rows[2].backend.as_deref(), Some("sb-cold"));
        assert_eq!(rows[2].cpu_percent, None, "null, not 0.0");
    }

    /// An app-lb that does not report the field writes nothing under
    /// `_unmanaged` — not a rollup saying "none" every poll forever.
    #[test]
    fn an_app_lb_without_host_sandboxes_writes_no_unmanaged_rows() {
        let old = strip_host_sandboxes();
        let snapshot: MetricsResponse = serde_json::from_str(&old).unwrap();
        assert!(snapshot.host_sandboxes.is_empty());
        let records = flatten(&snapshot);
        assert_eq!(records.len(), 4);
        assert!(
            records
                .iter()
                .all(|r| r.deployment() != UNMANAGED_DEPLOYMENT)
        );
        assert!(
            vm_targets(&snapshot)
                .iter()
                .all(|t| t.deployment != UNMANAGED_DEPLOYMENT)
        );
    }

    /// `SNAPSHOT` with the `host_sandboxes` array removed, as an older app-lb
    /// would send it.
    fn strip_host_sandboxes() -> String {
        let start = SNAPSHOT.find(",\n        \"host_sandboxes\"").unwrap();
        let end = SNAPSHOT.rfind(']').unwrap() + 1;
        format!("{}{}", &SNAPSHOT[..start], &SNAPSHOT[end..])
    }

    #[test]
    fn deployment_rows_carry_pool_and_traffic() {
        let records = flatten(&parse());
        let Record::Metric(deployment) = &records[1] else {
            panic!("expected a metric");
        };
        assert_eq!(deployment.deployment, "demo");
        assert_eq!(deployment.backend, None);
        assert_eq!(deployment.ready, Some(2));
        assert_eq!(deployment.pending, Some(1));
        assert_eq!(deployment.in_flight, Some(3));
        assert_eq!(deployment.requests_total, Some(100));
        assert_eq!(deployment.errors_total, Some(5));
        assert_eq!(deployment.p50_ms, Some(8.0));
        assert_eq!(deployment.p90_ms, Some(25.0));
        assert_eq!(deployment.p99_ms, Some(90.0));
        assert_eq!(deployment.latency_count, Some(100));
        assert_eq!(deployment.latency_sum, Some(1000));
    }

    #[test]
    fn latency_totals_are_kept_even_when_nothing_has_been_timed() {
        // The percentiles go null at count = 0 because 0ms is not a measurement.
        // The totals are the opposite case: a zero count *is* one, and it is
        // what the next sample's delta is taken against. Dropping it would make
        // the first interval after a restart unchartable.
        let mut snapshot = parse();
        snapshot.deployments[0].metrics.latency_ms.count = 0;
        snapshot.deployments[0].metrics.latency_ms.sum = 0;
        let records = flatten(&snapshot);
        let Record::Metric(deployment) = &records[1] else {
            panic!("expected a metric");
        };
        assert_eq!(deployment.p50_ms, None);
        assert_eq!(deployment.latency_count, Some(0));
        assert_eq!(deployment.latency_sum, Some(0));
    }

    #[test]
    fn percentiles_are_null_until_a_request_has_been_measured() {
        // An empty histogram reports 0.0 for every percentile. Storing that
        // would put a flat 0ms line on the chart that reads as "very fast"
        // rather than "no data".
        let mut snapshot = parse();
        snapshot.deployments[0].metrics.latency_ms.count = 0;
        let records = flatten(&snapshot);
        let Record::Metric(deployment) = &records[1] else {
            panic!("expected a metric");
        };
        assert_eq!(deployment.p50_ms, None);
        assert_eq!(deployment.p90_ms, None);
        assert_eq!(deployment.p99_ms, None);
        assert_eq!(
            deployment.requests_total,
            Some(100),
            "counters are still real",
        );
    }

    #[test]
    fn per_vm_rows_do_not_duplicate_deployment_wide_figures() {
        // Summing `requests_total` across VMs must not multiply the
        // deployment's count by the number of replicas.
        let records = flatten(&parse());
        let Record::Metric(vm) = &records[2] else {
            panic!("expected a metric");
        };
        assert_eq!(vm.backend.as_deref(), Some("sb-aaa"));
        assert_eq!(vm.cpu_percent, Some(7.5));
        assert_eq!(vm.in_flight, Some(2), "in-flight is genuinely per-VM");
        assert_eq!(vm.requests_total, None);
        assert_eq!(vm.ready, None);
        assert_eq!(vm.p50_ms, None);
        // Latency is measured at the proxy per deployment, not per VM. Copying
        // the totals down would make a sum across replicas count every request
        // once per VM.
        assert_eq!(vm.latency_count, None);
        assert_eq!(vm.latency_sum, None);
    }

    #[test]
    fn a_vm_the_daemon_has_not_sampled_keeps_null_usage() {
        let records = flatten(&parse());
        let Record::Metric(vm) = &records[3] else {
            panic!("expected a metric");
        };
        assert_eq!(vm.backend.as_deref(), Some("sb-bbb"));
        assert_eq!(vm.cpu_percent, None, "null, not 0.0");
        assert_eq!(vm.memory_bytes, None);
    }

    #[test]
    fn unknown_fields_do_not_break_parsing() {
        // app-lb must be free to add to its response without breaking us.
        let extended = SNAPSHOT.replace(
            r#""generated_at": 1785260096,"#,
            r#""generated_at": 1785260096, "some_new_field": {"nested": true},"#,
        );
        assert!(serde_json::from_str::<MetricsResponse>(&extended).is_ok());
    }

    #[test]
    fn vm_deployments_yield_one_target_per_backend() {
        let targets = vm_targets(&parse());
        assert_eq!(
            targets,
            vec![
                VmTarget {
                    deployment: "demo".into(),
                    backend: "sb-aaa".into(),
                },
                VmTarget {
                    deployment: "demo".into(),
                    backend: "sb-bbb".into(),
                },
                // The running hand-made sandbox is tailed too, under the
                // reserved partition; the stopped one prints nothing.
                VmTarget {
                    deployment: UNMANAGED_DEPLOYMENT.into(),
                    backend: "sb-hand".into(),
                },
            ],
        );
    }

    /// A sandbox that stops leaves the tail set, exactly as a pool VM that is
    /// reaped does — the tailer manager then aborts its stream.
    #[test]
    fn a_stopped_unmanaged_sandbox_is_not_tailed() {
        let mut snapshot = parse();
        snapshot.host_sandboxes[0].status = Some("stopped".into());
        assert!(
            vm_targets(&snapshot)
                .iter()
                .all(|t| t.deployment != UNMANAGED_DEPLOYMENT)
        );
        // …and a status this build does not know is treated as not live rather
        // than guessed at.
        snapshot.host_sandboxes[0].status = Some("hibernating".into());
        assert!(
            vm_targets(&snapshot)
                .iter()
                .all(|t| t.deployment != UNMANAGED_DEPLOYMENT)
        );
        snapshot.host_sandboxes[0].status = None;
        assert!(
            vm_targets(&snapshot)
                .iter()
                .all(|t| t.deployment != UNMANAGED_DEPLOYMENT)
        );
    }

    #[test]
    fn static_deployments_are_not_tailed() {
        // A static deployment's "vms" hold host:port upstreams; asking the
        // daemon to stream logs for "10.0.0.5:3000" would 404 forever.
        let mut snapshot = parse();
        snapshot.deployments[0].kind = Some("static".into());
        snapshot.host_sandboxes.clear();
        assert!(vm_targets(&snapshot).is_empty());
    }

    #[test]
    fn a_missing_kind_falls_back_to_the_backend_shape() {
        // Older app-lb: no `kind`. Sandbox ids never contain a colon;
        // host:port upstreams always do.
        let mut snapshot = parse();
        snapshot.deployments[0].kind = None;
        snapshot.deployments[0].vms[1].backend = "10.0.0.5:3000".into();
        snapshot.host_sandboxes.clear();
        let targets = vm_targets(&snapshot);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].backend, "sb-aaa");
    }

    #[test]
    fn a_deployment_with_no_namespace_is_in_default() {
        // app-lb omits `namespace` for `default`, and an older one never sends it.
        let mut snapshot = parse();
        let mut tenant = snapshot.deployments[0].clone();
        tenant.id = "web".into();
        tenant.namespace = Some("team-a".into());
        snapshot.deployments.push(tenant);
        let map = namespaces_of(&snapshot);
        assert_eq!(map["demo"], "default");
        assert_eq!(map["web"], "team-a");
    }

    #[test]
    fn installs_gate_only_while_the_fleet_plugin_is_on() {
        let on: InstallsResponse = serde_json::from_str(
            r#"{"plugin":"obs","enabled":true,"namespaces":["a","b"],
                "installs":{"a":{"installed_at":1,"installed_by":null,"config":{}}}}"#,
        )
        .unwrap();
        assert_eq!(
            on.gate(),
            Gate::Installed(HashSet::from(["a".to_string(), "b".to_string()]))
        );
        let off: InstallsResponse =
            serde_json::from_str(r#"{"plugin":"obs","enabled":false,"namespaces":["a"]}"#).unwrap();
        assert_eq!(off.gate(), Gate::Open);
    }

    /// A fake app-lb: `/metrics` with `demo` in `default` and `web` in
    /// `team-a`, and `installs` as given (`None` = a 404, an older app-lb).
    async fn fake_applb(installs: Option<&'static str>) -> String {
        use axum::routing::get;
        let mut snapshot: serde_json::Value = serde_json::from_str(SNAPSHOT).unwrap();
        let mut web = snapshot["deployments"][0].clone();
        web["id"] = "web".into();
        web["namespace"] = "team-a".into();
        snapshot["deployments"].as_array_mut().unwrap().push(web);
        let mut app = axum::Router::new().route(
            "/metrics",
            get(move || {
                let s = snapshot.clone();
                async move { axum::Json(s) }
            }),
        );
        if let Some(body) = installs {
            app = app.route(
                "/api/plugins/obs/installs",
                get(move || async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                }),
            );
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    /// Poll once and return the deployments whose rows reached the queue.
    async fn collected(installs: Option<&'static str>) -> std::collections::BTreeSet<String> {
        let url = fake_applb(installs).await;
        let directory = Arc::new(Directory::new(true));
        let (sink, mut rx) = Sink::new(1024);
        let sink = sink.with_directory(directory.clone());
        let (live, _) = tokio::sync::watch::channel(None);
        let poller = Poller::new(
            &url,
            None,
            None,
            Duration::from_secs(10),
            sink,
            "test".into(),
            live,
            None,
            directory,
        );
        poller.poll_once().await.unwrap();
        let mut out = std::collections::BTreeSet::new();
        while let Ok(r) = rx.try_recv() {
            out.insert(r.deployment().to_string());
        }
        out
    }

    #[tokio::test]
    async fn the_poll_collects_only_installed_namespaces() {
        let got = collected(Some(
            r#"{"plugin":"obs","enabled":true,"namespaces":["team-a"]}"#,
        ))
        .await;
        assert!(got.contains("web"), "team-a installed obs");
        assert!(!got.contains("demo"), "default did not");
        assert!(
            got.contains(HOST_DEPLOYMENT),
            "the platform's rows are always kept"
        );
    }

    #[tokio::test]
    async fn an_app_lb_without_installs_is_collected_as_before() {
        let got = collected(None).await;
        assert!(got.contains("web") && got.contains("demo"));
    }
}
