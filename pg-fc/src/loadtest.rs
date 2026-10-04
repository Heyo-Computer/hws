//! Load harness for the cold-start path — reproduces, in one process, the
//! degradation a pooler host shows once it tracks thousands of sandboxes.
//!
//! WHY THIS EXISTS. A fresh host serves a brand-new schema in about a second.
//! A host that has been up for a while takes 30s+, and during most of that the
//! daemon shows no sign of having been asked for anything — while host CPU and
//! memory sit under 20%. That shape (latency scaling with *inventory* rather
//! than with load) is what this harness measures, and it can't be reproduced
//! against a real daemon without first provisioning thousands of real VMs.
//!
//! HOW. [`Daemon`] is an in-process heyvmd stand-in speaking the same wire
//! protocol the SDK expects, holding a synthetic fleet of arbitrary size. The
//! pooler is aimed at it with `PG_VM_POOL_DAEMON_URL` (see
//! [`crate::vm::daemon_base_url`]), so every code path under test is the real
//! one — the same `resolve_sandbox`, the same store, the same gates.
//!
//! WHAT IT ISOLATES. The stub answers instantly and does no VM work, so any
//! latency that grows with fleet size is the *pooler's own* bookkeeping, not
//! resource contention. It also counts every request and every byte it serves,
//! which is the direct measurement of the N+1 question: how much daemon work
//! does one new VM cost, and does that cost depend on how many VMs already
//! exist?
//!
//! RUNNING. The sweeps are `#[ignore]`d — they take a minute and print a table
//! rather than asserting:
//!
//! ```text
//! cargo test --release loadtest -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Cells share one process-wide stub and one process-wide environment, so
//! every test here takes [`exclusive`] for its duration — `--test-threads=1`
//! only keeps the interleaved output readable.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{Path as AxPath, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde_json::json;

use crate::config::Config;

// ---------------------------------------------------------------- the daemon

/// One synthetic sandbox. Only the fields the pooler actually reads.
#[derive(Clone)]
struct Vm {
    id: String,
    name: String,
    running: bool,
}

impl Vm {
    fn view(&self) -> serde_json::Value {
        json!({
            "id": self.id,
            "name": self.name,
            "status": if self.running { "running" } else { "stopped" },
            "status_changed_at": "2026-08-19T00:00:00Z",
            "image": "pg",
            "size_class": "micro",
            "is_deployed": true,
            "uptime_secs": 0,
            "urls": [],
            // A host-reachable address the pooler will dial for Postgres.
            // Port 5432 on loopback is (almost certainly) refused, which ends
            // the readiness wait quickly instead of burning the whole timeout.
            "guest_ip": "127.0.0.1",
        })
    }
}

/// Per-endpoint request and byte counters. Bytes are what makes the N+1
/// legible: a cold start that pulls a megabyte off the daemon is doing work
/// proportional to the fleet, whatever the clock says on any given run.
#[derive(Default)]
struct Metrics {
    calls: StdMutex<BTreeMap<&'static str, u64>>,
    bytes: AtomicU64,
}

impl Metrics {
    fn hit(&self, endpoint: &'static str, bytes: usize) {
        *self.calls.lock().unwrap().entry(endpoint).or_default() += 1;
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.calls.lock().unwrap().clear();
        self.bytes.store(0, Ordering::Relaxed);
    }

    fn total_calls(&self) -> u64 {
        self.calls.lock().unwrap().values().sum()
    }

    fn total_bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// `GET /deployed-sandboxes x8, POST /sandbox-deploy x8` — the per-cell
    /// breakdown, so a surprising byte count can be traced to an endpoint.
    fn breakdown(&self) -> String {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(ep, n)| format!("{ep} x{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

struct Daemon {
    vms: StdMutex<BTreeMap<String, Vm>>,
    metrics: Metrics,
    next_id: AtomicU64,
    /// What one full listing costs the real daemon, and whether those cost are
    /// paid concurrently.
    ///
    /// The stub's own answer is a `serde_json` encode, which is nothing like
    /// heyvmd: there, `GET /deployed-sandboxes` clones every VM's metadata
    /// under a lock and probes every live handle. That is the multiplier
    /// between "the pooler demands the whole inventory per cold start" (which
    /// the byte counters measure directly) and the wall-clock a client feels.
    /// Set it from a real host's measured listing time to model that host.
    list_delay: StdMutex<Duration>,
    /// Held across the delay when set, modelling a daemon that serves listings
    /// under one lock — the state heyvmd is in when its workers are parked on
    /// blocking VM work.
    list_serial: StdMutex<bool>,
    list_gate: tokio::sync::Mutex<()>,
    /// Whether the stub honors `GET /deployed-sandboxes?name=` (a current
    /// heyvmd) or ignores the query and serves the full inventory (an old
    /// one). Default true; flip off to model the fallback.
    supports_name_filter: StdMutex<bool>,
    /// `disk_size_gb` from the most recent deploy body. The pooler asking for
    /// the right data device is a wire-level fact, and the only place it can
    /// be observed is here.
    last_deploy_disk_gb: StdMutex<Option<u64>>,
}

impl Daemon {
    /// Replace the fleet with `n` stopped VMs named `pg-seed-<i>`, as a pooler
    /// host looks after `n` schemas have been served and idle-reaped.
    fn seed(&self, n: usize) {
        let mut vms = self.vms.lock().unwrap();
        vms.clear();
        for i in 0..n {
            let id = seed_id(i);
            vms.insert(
                id.clone(),
                Vm {
                    id,
                    name: format!("pg-{}", seed_schema(i)),
                    running: false,
                },
            );
        }
    }
}

fn seed_id(i: usize) -> String {
    format!("sb-seed-{i:06}")
}

fn seed_schema(i: usize) -> String {
    format!("seed-{i:06}")
}

async fn list(
    State(d): State<Arc<Daemon>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // A current heyvmd answers `?name=` with the one exact match (or an empty
    // array) straight off its name index — no fleet scan, no listing delay.
    // An old daemon's handler took only `State`, so with the filter off the
    // param is ignored and the full inventory goes over the wire.
    if *d.supports_name_filter.lock().unwrap()
        && let Some(name) = params.get("name")
    {
        let found: Vec<serde_json::Value> = d
            .vms
            .lock()
            .unwrap()
            .values()
            .filter(|vm| &vm.name == name)
            .map(Vm::view)
            .collect();
        let body = serde_json::to_string(&found).unwrap();
        d.metrics.hit("GET /deployed-sandboxes?name", body.len());
        return ([("content-type", "application/json")], body);
    }
    let all: Vec<serde_json::Value> = d.vms.lock().unwrap().values().map(Vm::view).collect();
    let body = serde_json::to_string(&all).unwrap();
    d.metrics.hit("GET /deployed-sandboxes", body.len());
    let delay = *d.list_delay.lock().unwrap();
    if !delay.is_zero() {
        let serial = *d.list_serial.lock().unwrap();
        if serial {
            let _one_at_a_time = d.list_gate.lock().await;
            tokio::time::sleep(delay).await;
        } else {
            tokio::time::sleep(delay).await;
        }
    }
    ([("content-type", "application/json")], body)
}

async fn get_one(State(d): State<Arc<Daemon>>, AxPath(id): AxPath<String>) -> impl IntoResponse {
    let found = d.vms.lock().unwrap().get(&id).map(Vm::view);
    match found {
        Some(v) => {
            let body = serde_json::to_string(&v).unwrap();
            d.metrics.hit("GET /deployed-sandboxes/{id}", body.len());
            ([("content-type", "application/json")], body).into_response()
        }
        None => {
            d.metrics.hit("GET /deployed-sandboxes/{id} (404)", 0);
            (StatusCode::NOT_FOUND, format!("Sandbox not found: {id}")).into_response()
        }
    }
}

/// The deploy. Answers like a current heyvmd — 202-equivalent, VM immediately
/// visible and `running` — so the harness measures the pooler's cost of asking,
/// with the daemon's own build cost set to zero.
async fn deploy(State(d): State<Arc<Daemon>>, body: String) -> impl IntoResponse {
    let parsed = serde_json::from_str::<serde_json::Value>(&body).ok();
    let name = parsed
        .as_ref()
        .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_string))
        .unwrap_or_default();
    *d.last_deploy_disk_gb.lock().unwrap() = parsed
        .as_ref()
        .and_then(|v| v.get("disk_size_gb").and_then(serde_json::Value::as_u64));
    let id = format!("sb-new-{:06}", d.next_id.fetch_add(1, Ordering::Relaxed));
    d.vms.lock().unwrap().insert(
        id.clone(),
        Vm {
            id: id.clone(),
            name,
            running: true,
        },
    );
    let out = json!({"id": id, "status": "running"}).to_string();
    d.metrics.hit("POST /sandbox-deploy", out.len());
    ([("content-type", "application/json")], out)
}

async fn start(State(d): State<Arc<Daemon>>, AxPath(id): AxPath<String>) -> impl IntoResponse {
    let known = match d.vms.lock().unwrap().get_mut(&id) {
        Some(vm) => {
            vm.running = true;
            true
        }
        None => false,
    };
    if known {
        d.metrics.hit("POST /sandbox/{id}/start", 2);
        ([("content-type", "application/json")], "{}").into_response()
    } else {
        d.metrics.hit("POST /sandbox/{id}/start (404)", 0);
        (StatusCode::NOT_FOUND, format!("Sandbox not found: {id}")).into_response()
    }
}

async fn stop(State(d): State<Arc<Daemon>>, AxPath(id): AxPath<String>) -> impl IntoResponse {
    if let Some(vm) = d.vms.lock().unwrap().get_mut(&id) {
        vm.running = false;
    }
    d.metrics.hit("POST /sandbox/{id}/stop", 2);
    ([("content-type", "application/json")], "{}")
}

async fn kill(State(d): State<Arc<Daemon>>, AxPath(id): AxPath<String>) -> impl IntoResponse {
    d.vms.lock().unwrap().remove(&id);
    d.metrics.hit("DELETE /deployed-sandboxes/{id}", 2);
    ([("content-type", "application/json")], "{}")
}

async fn ok_json(State(d): State<Arc<Daemon>>, AxPath(_id): AxPath<String>) -> impl IntoResponse {
    d.metrics.hit("POST /deployed-sandboxes/{id}/*", 2);
    ([("content-type", "application/json")], "{}")
}

/// The process-wide stub, started once on its own runtime.
///
/// Its own runtime and thread, deliberately: every `#[tokio::test]` builds and
/// drops a runtime of its own, and a server spawned onto one of those would
/// die with the first cell. Binding synchronously also means the port — and so
/// `PG_VM_POOL_DAEMON_URL` — is known before any pooler code runs, which
/// matters because `daemon_base_url()` caches its answer on first read.
fn daemon() -> &'static Arc<Daemon> {
    static STUB: OnceLock<Arc<Daemon>> = OnceLock::new();
    STUB.get_or_init(|| {
        let d = Arc::new(Daemon {
            vms: StdMutex::new(BTreeMap::new()),
            metrics: Metrics::default(),
            next_id: AtomicU64::new(0),
            list_delay: StdMutex::new(Duration::ZERO),
            list_serial: StdMutex::new(false),
            list_gate: tokio::sync::Mutex::const_new(()),
            supports_name_filter: StdMutex::new(true),
            last_deploy_disk_gb: StdMutex::new(None),
        });
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binding daemon stub");
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        // SAFETY: single-threaded setup — this runs inside a `OnceLock`
        // initializer, before any cell has spawned a task that reads the
        // environment.
        unsafe { std::env::set_var("PG_VM_POOL_DAEMON_URL", format!("http://{addr}")) };

        let app = axum::Router::new()
            .route("/deployed-sandboxes", get(list))
            .route(
                "/deployed-sandboxes/{id}",
                get(get_one).delete(kill),
            )
            .route("/deployed-sandboxes/{id}/ttl", post(ok_json))
            .route("/deployed-sandboxes/{id}/restart", post(ok_json))
            .route("/sandbox-deploy", post(deploy))
            .route("/sandbox/{id}/start", post(start))
            .route("/sandbox/{id}/stop", post(stop))
            .with_state(d.clone());

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("daemon stub runtime");
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        d
    })
}

// --------------------------------------------------------------- the harness

/// Guards the process environment while a `Config` is built from it.
static ENV_LOCK: StdMutex<()> = StdMutex::new(());

/// Exclusive use of the stub for the caller's whole test. Shared with every
/// other test that touches process-wide VM state — a bring-up here takes a
/// reclaim boot permit, so `reclaim`'s tests must not run alongside these.
async fn exclusive() -> tokio::sync::MutexGuard<'static, ()> {
    crate::vm::test_exclusive().await
}

/// A pooler configuration pointed at the stub, with a state file holding
/// `fleet` schema→VM rows — the durable inventory whose size is the
/// independent variable.
///
/// `ready_timeout` is deliberately short. The stub's VMs have no Postgres
/// behind them, so every bring-up ends in a readiness failure; a small budget
/// makes that tail a constant the cells share instead of the thing being
/// measured.
fn config_for(fleet: usize, warm_spares: usize) -> Config {
    let _env = ENV_LOCK.lock().unwrap();
    daemon(); // sets PG_VM_POOL_DAEMON_URL before anything reads it

    let dir = std::env::temp_dir().join(format!("pg-fc-loadtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("creating harness state dir");
    let state = dir.join(format!("registry-{fleet}.tsv"));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rows = String::new();
    for i in 0..fleet {
        rows.push_str(&format!("{}\t{}\t{now}\tlive\n", seed_schema(i), seed_id(i)));
    }
    std::fs::write(&state, rows).expect("seeding the state file");

    let set = |k: &str, v: &str| {
        // SAFETY: `ENV_LOCK` is held, and cells run single-threaded (see the
        // module docs on `--test-threads=1`).
        unsafe { std::env::set_var(k, v) }
    };
    set("PG_VM_POOL_STATE_FILE", state.to_str().unwrap());
    set("PG_VM_POOL_READY_TIMEOUT_SECS", "2");
    set("PG_VM_POOL_CONNECT_TIMEOUT_SECS", "2");
    set("PG_VM_POOL_ADMIT_TIMEOUT_SECS", "5");
    set("PG_VM_POOL_IDLE_TIMEOUT_SECS", "0");
    set("PG_VM_POOL_WARM_SPARES", &warm_spares.to_string());

    crate::pending::init(dir.join("pending.tsv"));
    // Process-wide state the cells would otherwise leak into each other: the
    // name→id cache warms as a side effect of every resolve, and the stub's
    // filter support is a per-cell scenario knob.
    crate::inventory::reset();
    *daemon().supports_name_filter.lock().unwrap() = true;
    Config::from_env().expect("building the harness config")
}

/// Latency distribution for one cell.
struct Stats {
    label: String,
    fleet: usize,
    conc: usize,
    p50: Duration,
    p95: Duration,
    max: Duration,
    calls_per_op: f64,
    bytes_per_op: f64,
    breakdown: String,
}

fn summarize(
    label: String,
    fleet: usize,
    conc: usize,
    mut samples: Vec<Duration>,
    ops: usize,
) -> Stats {
    samples.sort();
    let at = |q: f64| samples[((samples.len() as f64 * q) as usize).min(samples.len() - 1)];
    let m = &daemon().metrics;
    Stats {
        label,
        fleet,
        conc,
        p50: at(0.50),
        p95: at(0.95),
        max: *samples.last().unwrap(),
        calls_per_op: m.total_calls() as f64 / ops as f64,
        bytes_per_op: m.total_bytes() as f64 / ops as f64,
        breakdown: m.breakdown(),
    }
}

fn header() {
    println!(
        "\n{:<22} {:>7} {:>5} {:>9} {:>9} {:>9} {:>9} {:>12}",
        "scenario", "fleet", "conc", "p50", "p95", "max", "calls/op", "bytes/op"
    );
    println!("{}", "-".repeat(92));
}

impl Stats {
    fn print(&self) {
        println!(
            "{:<22} {:>7} {:>5} {:>9} {:>9} {:>9} {:>9.1} {:>12}",
            self.label,
            self.fleet,
            self.conc,
            format!("{:.0}ms", self.p50.as_secs_f64() * 1000.0),
            format!("{:.0}ms", self.p95.as_secs_f64() * 1000.0),
            format!("{:.0}ms", self.max.as_secs_f64() * 1000.0),
            self.calls_per_op,
            human(self.bytes_per_op),
        );
        println!("{:>22}   └ {}", "", self.breakdown);
    }
}

fn human(bytes: f64) -> String {
    match bytes {
        b if b >= 1_048_576.0 => format!("{:.1}MB", b / 1_048_576.0),
        b if b >= 1024.0 => format!("{:.1}KB", b / 1024.0),
        b => format!("{b:.0}B"),
    }
}

/// How the modelled daemon answers a full listing.
///
/// The stub's own encode cost is nothing like heyvmd's, so leaving it at
/// [`Listing::Instant`] measures the pooler's *demand* and nothing else. The
/// other two put a measured real-host listing time behind that demand, which
/// is what turns a shape into a wall-clock a client would feel.
#[derive(Clone, Copy)]
enum Listing {
    /// As fast as JSON can be encoded — isolates the pooler's own cost.
    Instant,
    /// `d` per listing, answered concurrently: a healthy daemon that is simply
    /// slow because the inventory is large.
    Concurrent(Duration),
    /// `d` per listing, one at a time: a daemon whose async workers are parked
    /// on blocking VM work (`mke2fs`, `debugfs`, rootfs clones), which is the
    /// state a bring-up burst puts it in.
    Serialized(Duration),
}

impl Listing {
    fn apply(self, d: &Daemon) {
        let (delay, serial) = match self {
            Listing::Instant => (Duration::ZERO, false),
            Listing::Concurrent(d) => (d, false),
            Listing::Serialized(d) => (d, true),
        };
        *d.list_delay.lock().unwrap() = delay;
        *d.list_serial.lock().unwrap() = serial;
    }
}

/// Whether the schemas a cell asks for are already bound to a VM in the store.
#[derive(Clone, Copy, PartialEq)]
enum Ask {
    /// A schema the pooler has never served: no stored id, so `resolve_sandbox`
    /// falls through to find-by-name. This is what a *new* customer hits.
    New,
    /// A schema whose VM the pooler already knows by id — the reattach path,
    /// which skips find-by-name entirely.
    Known,
}

/// Run `conc` concurrent cold resolves against a fleet of `fleet` VMs and
/// return the distribution.
///
/// Resolve rather than a full `checkout`: everything after it needs a real
/// Postgres inside the VM, and its failure against the stub would add a
/// constant that buries the signal. Resolve *is* the window in question — the
/// span between a client connecting and the daemon being asked to do anything
/// about its VM.
async fn resolve_cell(
    label: &str,
    fleet: usize,
    conc: usize,
    ask: Ask,
    listing: Listing,
) -> Stats {
    let cfg = config_for(fleet, 12);
    daemon().seed(fleet);
    daemon().metrics.reset();
    listing.apply(daemon());

    // Warm-spare pool present but empty, as it is on a host whose spares are
    // all claimed — so `bound_ids()` (an O(fleet) clone of the whole store) is
    // still computed per bring-up, exactly as in production.
    let spares = crate::spares::SparePool::new(12, 0);
    let bound: HashSet<String> = (0..fleet).map(seed_id).collect();

    let cfg = Arc::new(cfg);
    let spares = Arc::new(spares);
    let bound = Arc::new(bound);

    let started = Instant::now();
    let mut tasks = Vec::new();
    for i in 0..conc {
        let (cfg, spares, bound) = (cfg.clone(), spares.clone(), bound.clone());
        let (name, known_id) = match ask {
            // Spread the picks across the fleet so no cell is accidentally
            // measuring one hot map bucket.
            Ask::Known => {
                let idx = if fleet == 0 { 0 } else { i * (fleet / conc.max(1)).max(1) % fleet };
                (format!("pg-{}", seed_schema(idx)), Some(seed_id(idx)))
            }
            Ask::New => (format!("pg-fresh-{i}"), None),
        };
        tasks.push(tokio::spawn(async move {
            let t = Instant::now();
            let _ = crate::vm::resolve_sandbox(
                &cfg,
                &name,
                false,
                known_id.as_deref(),
                Some((&spares, &bound)),
                cfg.data_disk_gb,
            )
            .await;
            t.elapsed()
        }));
    }
    let mut samples = Vec::with_capacity(conc);
    for t in tasks {
        samples.push(t.await.expect("resolve task panicked"));
    }
    let wall = started.elapsed();
    let stats = summarize(label.to_string(), fleet, conc, samples, conc);
    println!("{:>22}   (wall {:.1}s)", "", wall.as_secs_f64());
    stats
}

// ----------------------------------------------------------------- the sweeps

/// Does the cost of bringing up ONE new VM depend on how many VMs the host
/// already tracks? Concurrency is fixed, so fleet size is the only variable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load sweep: run explicitly with --ignored --nocapture --test-threads=1"]
async fn cold_start_cost_versus_fleet_size() {
    let _exclusive = exclusive().await;
    header();
    let mut rows = Vec::new();
    for fleet in [0, 250, 1_000, 5_000] {
        rows.push(resolve_cell("new schema", fleet, 8, Ask::New, Listing::Instant).await);
        rows.last().unwrap().print();
    }
    // No fleet-0 cell here: with nothing seeded there is no known schema to
    // ask for, and the stored id would 404 into the new-schema path — a row
    // labelled "known" that measured the opposite.
    for fleet in [250, 1_000, 5_000] {
        rows.push(resolve_cell("known schema", fleet, 8, Ask::Known, Listing::Instant).await);
        rows.last().unwrap().print();
    }
    println!(
        "\nIf 'new schema' climbs with fleet and 'known schema' does not, the cost is \
         find-by-name: every first connect pulls the entire inventory.\n"
    );
}

/// Does it depend on how many clients arrive at once? Fleet is fixed, so
/// concurrency is the only variable — the control for the sweep above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load sweep: run explicitly with --ignored --nocapture --test-threads=1"]
async fn cold_start_cost_versus_concurrency() {
    let _exclusive = exclusive().await;
    header();
    for conc in [1, 4, 16, 64] {
        let s = resolve_cell("new schema", 2_000, conc, Ask::New, Listing::Instant).await;
        s.print();
    }
    println!(
        "\nPer-op cost that is flat in concurrency but high in absolute terms points at \
         per-request work; cost that climbs points at a shared lock or a gate.\n"
    );
}

/// What the demand above costs a client once a *real* daemon is behind it.
///
/// The sweeps hold the daemon at zero cost, which measures the pooler's demand
/// but understates the clock: heyvmd answers `GET /deployed-sandboxes` by
/// cloning every VM's metadata under a lock and probing every live handle, so
/// on a full host one listing is most of a second even when it is the only
/// thing happening. Feed that measured time back in — `curl -s -o /dev/null
/// -w '%{time_total}' localhost:34099/deployed-sandboxes` on the host in
/// question — and the arithmetic finishes itself: the cold path spends one
/// listing per new schema, so a burst of K spends K of them, and when the
/// daemon is serving them one at a time the last client in the burst waits for
/// all of them.
///
/// The default 800ms is a placeholder for a host with a few thousand VMs.
/// Override with `LOADTEST_LISTING_MS` to model a specific one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load sweep: run explicitly with --ignored --nocapture --test-threads=1"]
async fn cold_start_behind_a_realistic_daemon() {
    let _exclusive = exclusive().await;
    let ms: u64 = std::env::var("LOADTEST_LISTING_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(800);
    let d = Duration::from_millis(ms);
    println!("\nmodelling a daemon that answers one full listing in {ms}ms");
    header();
    for conc in [1, 8, 32] {
        resolve_cell("healthy daemon", 5_000, conc, Ask::New, Listing::Concurrent(d))
            .await
            .print();
    }
    for conc in [1, 8, 32] {
        resolve_cell("listings serialized", 5_000, conc, Ask::New, Listing::Serialized(d))
            .await
            .print();
    }
    println!(
        "\nThe 'known schema' rows of the fleet sweep pay none of this: reattach by id \
         never lists.\n"
    );
}

/// The regression guard, and the statement of what "fixed" means: the daemon
/// traffic one cold start generates must not scale with the size of the fleet.
///
/// A new schema currently resolves through find-by-name, which is
/// `GET /deployed-sandboxes` — the *whole* inventory — so the bytes one
/// bring-up pulls grow linearly with every VM the host has ever created. That
/// is the N+1: N is the fleet, and the +1 is the one VM anybody actually asked
/// for. It is invisible in a CPU graph because the pooler spends the time
/// waiting on the daemon to serialize a list it then throws away.
///
/// This was the acceptance criterion for removing the listing from the cold
/// path, and it holds now: a new schema resolves through the name→id cache
/// and the daemon's `?name=` lookup (`vm::find_by_name_with_retry`), so the
/// bytes one bring-up pulls are flat in fleet size. Runs in the normal suite
/// as the regression guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_cold_start_must_not_cost_the_whole_inventory() {
    let _exclusive = exclusive().await;
    let small = resolve_cell("guard/small", 100, 1, Ask::New, Listing::Instant).await;
    let large = resolve_cell("guard/large", 5_000, 1, Ask::New, Listing::Instant).await;
    header();
    small.print();
    large.print();
    // 50x the fleet must not mean meaningfully more daemon traffic per
    // bring-up. 2x leaves room for the id and name growing a few bytes.
    assert!(
        large.bytes_per_op < small.bytes_per_op * 2.0,
        "one cold start pulls {} from the daemon at a fleet of 5000 vs {} at 100 — \
         bring-up cost scales with inventory",
        human(large.bytes_per_op),
        human(small.bytes_per_op),
    );
}

/// The fixed cold path itself: resolving a schema whose VM exists on the
/// daemon but is unknown to the pooler (fresh cache, no registry row) must
/// cost one `?name=` lookup — not an inventory pull, and above all not a
/// deploy (a duplicate VM with an empty data disk is the data-loss case the
/// authoritative lookup exists to prevent).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn by_name_lookup_finds_without_pulling_inventory() {
    let _exclusive = exclusive().await;
    let cfg = config_for(500, 0);
    daemon().seed(500);
    daemon().metrics.reset();

    let name = format!("pg-{}", seed_schema(42));
    let (sb, provenance) = crate::vm::resolve_sandbox(&cfg, &name, false, None, None, cfg.data_disk_gb)
        .await
        .expect("resolving a daemon-known schema");
    assert_eq!(sb.sandbox_id(), seed_id(42));
    assert_eq!(provenance, crate::vm::Provenance::Existing);

    let calls = daemon().metrics.calls.lock().unwrap().clone();
    assert_eq!(
        calls.get("GET /deployed-sandboxes").copied().unwrap_or(0),
        0,
        "the cold path must not pull the inventory: {calls:?}"
    );
    assert_eq!(
        calls.get("GET /deployed-sandboxes?name").copied().unwrap_or(0),
        1,
        "exactly one by-name lookup: {calls:?}"
    );
    assert_eq!(
        calls.get("POST /sandbox-deploy").copied().unwrap_or(0),
        0,
        "an existing VM must be reattached, never recreated: {calls:?}"
    );
}

/// A bring-up that has to build a VM must ask for the data device the schema
/// actually needs, not the configured starting size.
///
/// The failure without it is silent and expensive: `PG_VM_POOL_DATA_DISK_GB`
/// is where a *new* schema starts, and device growth is offline-only, so a
/// schema that grew and was then dump-archived comes back into a device too
/// small to hold it. Its VM boots, Postgres starts, and `pg_restore` fills the
/// disk — `No space left on device`, a half-loaded cluster, and a broken VM
/// that looks like a daemon fault. The size travels in the deploy body, so
/// that body is what this asserts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_creates_its_vm_at_the_size_the_schema_needs() {
    let _exclusive = exclusive().await;
    let cfg = config_for(0, 0);
    daemon().seed(0);

    // The stub has no Postgres, so every create ends in a readiness failure —
    // irrelevant here. The deploy has already been sent by then, and the
    // request it carried is the whole question.
    *daemon().last_deploy_disk_gb.lock().unwrap() = None;
    let _ = crate::vm::resolve_sandbox(&cfg, "pg-grown", false, None, None, 16).await;
    assert_eq!(
        *daemon().last_deploy_disk_gb.lock().unwrap(),
        Some(16),
        "a restore that needs 16GiB must be built at 16GiB, not the {}GiB default",
        cfg.data_disk_gb
    );

    // ...and an ordinary bring-up still starts small: the point is a device
    // sized to the schema, in both directions.
    *daemon().last_deploy_disk_gb.lock().unwrap() = None;
    let _ = crate::vm::resolve_sandbox(&cfg, "pg-fresh", false, None, None, cfg.data_disk_gb).await;
    assert_eq!(
        *daemon().last_deploy_disk_gb.lock().unwrap(),
        Some(u64::from(cfg.data_disk_gb)),
        "a schema with no history must still start at the configured size"
    );
}

/// The duplicate-VM guard behind the positive-only cache design: a VM the
/// daemon knows about but the cache doesn't (pooler restarted, cache cold, no
/// registry row) must be found by the authoritative by-name call and
/// reattached — a cache miss is never treated as "doesn't exist".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn existing_vm_absent_from_cache_is_reattached_not_recreated() {
    let _exclusive = exclusive().await;
    let cfg = config_for(50, 0);
    daemon().seed(50);

    // Warm the cache with one resolve, then wipe it — the "restarted pooler"
    // state, with the VM still very much alive daemon-side.
    let name = format!("pg-{}", seed_schema(7));
    crate::vm::resolve_sandbox(&cfg, &name, false, None, None, cfg.data_disk_gb)
        .await
        .expect("first resolve");
    crate::inventory::reset();
    daemon().metrics.reset();

    let (sb, _) = crate::vm::resolve_sandbox(&cfg, &name, false, None, None, cfg.data_disk_gb)
        .await
        .expect("resolving after a cache wipe");
    assert_eq!(sb.sandbox_id(), seed_id(7), "the same VM, not a duplicate");

    let calls = daemon().metrics.calls.lock().unwrap().clone();
    assert_eq!(
        calls.get("POST /sandbox-deploy").copied().unwrap_or(0),
        0,
        "a cache miss must go to the daemon, never straight to create: {calls:?}"
    );
    assert_eq!(
        calls.get("GET /deployed-sandboxes?name").copied().unwrap_or(0),
        1,
        "the authoritative by-name lookup answers the miss: {calls:?}"
    );
}

/// Version skew: an old daemon ignores `?name=` and serves the full
/// inventory. Resolution must still land on the exact match (client-side
/// filter), the full list must warm the cache for free, and a second resolve
/// must be answered from the cache without another listing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn old_daemon_full_list_fallback_still_resolves() {
    let _exclusive = exclusive().await;
    let cfg = config_for(100, 0);
    daemon().seed(100);
    *daemon().supports_name_filter.lock().unwrap() = false;
    daemon().metrics.reset();

    let name = format!("pg-{}", seed_schema(3));
    let (sb, _) = crate::vm::resolve_sandbox(&cfg, &name, false, None, None, cfg.data_disk_gb)
        .await
        .expect("resolving against an old daemon");
    assert_eq!(sb.sandbox_id(), seed_id(3));

    let full_lists = |calls: &BTreeMap<&'static str, u64>| {
        calls.get("GET /deployed-sandboxes").copied().unwrap_or(0)
    };
    let calls = daemon().metrics.calls.lock().unwrap().clone();
    assert_eq!(full_lists(&calls), 1, "old daemon: one full-list fallback: {calls:?}");
    assert_eq!(calls.get("POST /sandbox-deploy").copied().unwrap_or(0), 0);

    // The absorbed full list covers every seeded name — the next cold resolve
    // is a cache hit and never lists.
    let other = format!("pg-{}", seed_schema(90));
    let (sb, _) = crate::vm::resolve_sandbox(&cfg, &other, false, None, None, cfg.data_disk_gb)
        .await
        .expect("second resolve");
    assert_eq!(sb.sandbox_id(), seed_id(90));
    let calls = daemon().metrics.calls.lock().unwrap().clone();
    assert_eq!(
        full_lists(&calls),
        1,
        "the second resolve must be served from the warmed cache: {calls:?}"
    );
}

// ------------------------------------------------------------- harness checks

/// The harness is only worth its output if the stub is really the daemon the
/// pooler talks to, and if the counters really count. Cheap enough to run in
/// the normal suite.
#[tokio::test]
async fn the_stub_stands_in_for_the_daemon_and_counts_what_it_serves() {
    let _exclusive = exclusive().await;
    let _cfg = config_for(3, 0);
    daemon().seed(3);
    daemon().metrics.reset();

    let all = crate::vm::list_with_retry()
        .await
        .expect("the pooler's own listing must reach the stub");
    assert_eq!(all.len(), 3, "the stub served the seeded fleet");
    assert_eq!(all[0].name, "pg-seed-000000");
    assert_eq!(all[0].guest_ip.as_deref(), Some("127.0.0.1"));

    assert_eq!(daemon().metrics.total_calls(), 1, "one listing, one request");
    assert!(
        daemon().metrics.total_bytes() > 0,
        "the byte counter is what the scaling assertions read"
    );
}

/// The measurement rests on the fleet actually reaching the wire, so pin that
/// a bigger fleet really does cost more bytes to list.
#[tokio::test]
async fn listing_cost_tracks_fleet_size() {
    let _exclusive = exclusive().await;
    let _cfg = config_for(0, 0);

    daemon().seed(10);
    daemon().metrics.reset();
    crate::vm::list_with_retry().await.unwrap();
    let small = daemon().metrics.total_bytes();

    daemon().seed(1_000);
    daemon().metrics.reset();
    crate::vm::list_with_retry().await.unwrap();
    let large = daemon().metrics.total_bytes();

    assert!(
        large > small * 50,
        "listing 1000 VMs ({large}B) must cost far more than listing 10 ({small}B)"
    );
}

/// Real PostgreSQL plus the existing daemon stand-in: exercises controller
/// recovery without giving the test permission to recreate a database VM.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL 18 on 127.0.0.1:5432 via PG_FC_FENCE_TEST_URL"]
async fn postgres_fence_controller_restart_recovers_without_tenant_bringup() {
    use crate::replication::{ReplRecord, Role, State as ReplState, orchestrate};
    let _exclusive = exclusive().await;
    let url = std::env::var("PG_FC_FENCE_TEST_URL").expect("disposable PostgreSQL URL required");
    let pg: tokio_postgres::Config = url.parse().unwrap();
    assert_eq!(pg.get_ports(), &[5432], "the daemon stand-in exposes guest PostgreSQL on port 5432");
    assert_eq!(pg.get_dbname(), Some("postgres"));
    let (maintenance, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(async move { let _ = connection.await; });
    let database = format!("fence_recovery_{}", std::process::id());
    maintenance.batch_execute(&format!("CREATE DATABASE {database}")).await.unwrap();

    let mut cfg = config_for(0, 0);
    cfg.pg_user = pg.get_user().unwrap().to_string();
    cfg.pg_password = pg.get_password().map(|p| String::from_utf8(p.to_vec()).unwrap());
    cfg.direct_connect = true;
    let vm_id = "sb-fenced-recovery";
    daemon().seed(0);
    daemon().vms.lock().unwrap().insert(vm_id.into(), Vm {
        id: vm_id.into(), name: format!("pg-{database}"), running: true,
    });
    crate::store::Store::load(cfg.state_file.clone()).put(&database, vm_id);
    let registry = Arc::new(crate::registry::SchemaRegistry::new(cfg.clone()).unwrap());
    registry.replication().create(ReplRecord::new(&database, Role::Primary, "test-peer", "test-password"), &|_| false).unwrap();
    registry.replication().set_state(&database, ReplState::Active, "test").unwrap();
    registry.replication().set_fence(&database, "intent", "simulate controller crash after admission close", vm_id, "").unwrap();
    maintenance.batch_execute(&crate::replication::sql::set_allow_connections(&database, false)).await.unwrap();
    drop(registry);

    // Fresh registry, no warm entries. Normal tenant bring-up would attempt
    // per-database grants and fail because that database refuses connections.
    daemon().metrics.reset();
    let registry = Arc::new(crate::registry::SchemaRegistry::new(cfg.clone()).unwrap());
    let result = orchestrate::fence(&registry, &database).await.unwrap();
    assert_eq!(result.vm_id, vm_id);
    let again = orchestrate::fence(&registry, &database).await.unwrap();
    assert_eq!(again.barrier_lsn, result.barrier_lsn, "retry moved the ready barrier");
    let _warm = registry.checkout(&database).await.unwrap();
    let rec = registry.replication().get(&database).unwrap();
    orchestrate::local_status(&registry, &rec).await.unwrap();
    assert!(registry.pin_reason(&database).unwrap().contains("fenced"));

    let operation = registry.replication_operation(&database).await.unwrap();
    let other = registry.clone();
    let name = database.clone();
    let mut unfence = tokio::spawn(async move { orchestrate::unfence(&other, &name).await });
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut unfence).await.is_err(), "unfence bypassed the operation lock");
    let closed: bool = maintenance.query_one("SELECT NOT datallowconn FROM pg_database WHERE datname=$1", &[&database]).await.unwrap().get(0);
    assert!(closed);
    drop(operation);
    unfence.await.unwrap().unwrap();
    assert!(!registry.replication().is_fenced(&database));
    let reopened: bool = maintenance.query_one("SELECT datallowconn FROM pg_database WHERE datname=$1", &[&database]).await.unwrap().get(0);
    assert!(reopened);
    assert_eq!(daemon().metrics.calls.lock().unwrap().get("POST /sandbox-deploy").copied().unwrap_or(0), 0, "recovery recreated its source VM");
    drop(_warm);
    drop(registry);
    maintenance.batch_execute(&format!("DROP DATABASE {database} WITH (FORCE)")).await.unwrap();
    std::fs::remove_file(cfg.state_file).unwrap();
    std::fs::remove_file(cfg.replication_file).unwrap();
}

/// Real libpq physical startup through the production password/route/splice
/// path. PostgreSQL ignores the claimed database, and so must this route.
/// The disposable server must allow physical replication from the test host
/// in pg_hba.conf, e.g. `host replication all all scram-sha-256`.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL18 on 127.0.0.1:5432 and psql on PATH"]
async fn physical_replication_startup_uses_authenticated_vm_and_its_fence() {
    use crate::replication::{ReplRecord, Role, State as ReplState};
    let _exclusive = exclusive().await;
    let url = std::env::var("PG_FC_FENCE_TEST_URL").expect("disposable PostgreSQL URL required");
    let pg: tokio_postgres::Config = url.parse().unwrap();
    assert_eq!(pg.get_ports(), &[5432]);
    assert_eq!(pg.get_dbname(), Some("postgres"));
    let (maintenance, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(async move { let _ = connection.await; });
    let database = format!("physical_route_{}", std::process::id());
    let rec = ReplRecord::new(&database, Role::Primary, "test-peer", "physical-test-password");
    maintenance.batch_execute(&format!("CREATE DATABASE {database}")).await.unwrap();
    maintenance.batch_execute(&format!("CREATE ROLE {} LOGIN REPLICATION PASSWORD 'physical-test-password'", rec.repl_role)).await.unwrap();
    let system: String = maintenance.query_one("SELECT system_identifier::text FROM pg_control_system()", &[]).await.unwrap().get(0);
    let mut cfg = config_for(0, 0);
    cfg.pg_user = pg.get_user().unwrap().to_string();
    cfg.pg_password = pg.get_password().map(|p| String::from_utf8(p.to_vec()).unwrap());
    cfg.direct_connect = true;
    let vm_id = "sb-physical-route";
    daemon().seed(0);
    daemon().vms.lock().unwrap().insert(vm_id.into(), Vm {
        id: vm_id.into(), name: format!("pg-{database}"), running: true,
    });
    // Seed synchronously: Store::put persists on a detached task, which can
    // race the independent Store loaded by SchemaRegistry::new below.
    std::fs::write(&cfg.state_file, format!("{database}\t{vm_id}\t0\tlive\n")).unwrap();
    let registry = Arc::new(crate::registry::SchemaRegistry::new(cfg.clone()).unwrap());
    registry.replication().create(rec.clone(), &|_| false).unwrap();
    registry.replication().set_state(&database, ReplState::Active, "test").unwrap();
    // Use the bound-VM maintenance path, without database provisioning/DDL.
    registry.replication().set_fence_payload(&database, "selective", "ready", "test admission", vm_id, "0/1", vec![]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let serving = registry.clone();
    let server = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let registry = serving.clone();
            tokio::spawn(async move {
                if let Err(error) = crate::handle_conn(socket, registry, None).await {
                    eprintln!("physical protocol test connection: {error:#}");
                }
            });
        }
    });
    let conninfo = format!("host=127.0.0.1 port={port} user={} dbname=unrelated_claim replication=true sslmode=disable connect_timeout=10", rec.repl_role);
    for (password, succeeds) in [("wrong-password", false), ("physical-test-password", true)] {
        let out = tokio::process::Command::new("psql").args(["-X", "-w", "-At", "-d", &conninfo, "-c", "IDENTIFY_SYSTEM"])
            .env("PGPASSWORD", password).output().await.unwrap();
        assert_eq!(out.status.success(), succeeds, "{}", String::from_utf8_lossy(&out.stderr));
        if succeeds {
            assert_eq!(String::from_utf8_lossy(&out.stdout).split('|').next(), Some(system.as_str()));
        } else {
            assert!(String::from_utf8_lossy(&out.stderr).contains("password authentication failed"));
        }
    }
    registry.replication().set_fence_payload(&database, "hard", "ready", "test closed", vm_id, "0/1", vec![]).unwrap();
    let out = tokio::process::Command::new("psql").args(["-X", "-w", "-At", "-d", &conninfo, "-c", "IDENTIFY_SYSTEM"])
        .env("PGPASSWORD", "physical-test-password").output().await.unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("database is fenced"), "fence lookup used claimed database instead of authenticated VM");
    // A later physical writer must authenticate and stream without the old
    // logical pairing, including while its own source fence closes tenants.
    registry.physical_sources().create(crate::replication::PhysicalSourceRecord {
        database: database.clone(), generation: "physical-auth-g1".into(), predecessor: None,
        source_vm_id: vm_id.into(), repl: Some(crate::replication::wire::Login { role: rec.repl_role.clone(), password: rec.repl_password.clone() }),
        fence: None, system_identifier: system.clone(), pg_major: 18, slot: "physical_auth_slot".into(),
        source_lsn: "0/1".into(), peer: "test-peer".into(), handoff_candidate: None, handoff_complete: false, handoff: None, last_error: None,
    }).unwrap();
    registry.physical_sources().set_fence(&database, "physical-auth-g1", "ready", Some("0/1")).unwrap();
    registry.replication().clear_fence(&database).unwrap();
    registry.replication().remove(&database).unwrap();
    for (password, succeeds) in [("wrong-password", false), ("physical-test-password", true)] {
        let out = tokio::process::Command::new("psql").args(["-X", "-w", "-At", "-d", &conninfo, "-c", "IDENTIFY_SYSTEM"])
            .env("PGPASSWORD", password).output().await.unwrap();
        assert_eq!(out.status.success(), succeeds, "{}", String::from_utf8_lossy(&out.stderr));
        if succeeds { assert_eq!(String::from_utf8_lossy(&out.stdout).split('|').next(), Some(system.as_str())); }
        else { assert!(String::from_utf8_lossy(&out.stderr).contains("password authentication failed")); }
    }
    server.abort();
    drop(registry);
    maintenance.batch_execute(&format!("DROP DATABASE {database} WITH (FORCE)")).await.unwrap();
    maintenance.batch_execute(&format!("DROP ROLE {}", rec.repl_role)).await.unwrap();
    std::fs::remove_file(cfg.state_file).unwrap();
    std::fs::remove_file(cfg.replication_file.with_extension("physical-sources.json")).unwrap();
    std::fs::remove_file(cfg.replication_file).unwrap();
}

#[tokio::test]
async fn physical_handoff_restart_admission_and_source_grant_are_fail_closed() {
    use crate::replication::{PhysicalRecord, PhysicalPhase as P, PhysicalSourceRecord, PhysicalHandoffGrant, ReplRecord, Role};
    let _exclusive = exclusive().await;
    let mut cfg = config_for(0, 0);
    let dir = cfg.state_file.parent().unwrap().join("handoff-admission");
    std::fs::create_dir_all(&dir).unwrap();
    cfg.state_file = dir.join("registry.tsv");
    cfg.replication_file = dir.join("replication.tsv");
    std::fs::write(&cfg.state_file, "acme\tsb-old\t0\tlive\nsource\tsb-source\t0\tlive\n").unwrap();
    let mut reg = Arc::new(crate::registry::SchemaRegistry::new(cfg.clone()).unwrap());
    reg.physical().create(PhysicalRecord { database: "acme".into(), generation: "g1".into(), predecessor: None,
        candidate_name: PhysicalRecord::candidate_name("g1"), repl: None, candidate_id: None,
        previous_vm_id: Some("sb-old".into()), source_node: "us3".into(), source_vm_id: "sb-source".into(),
        system_identifier: "123456".into(), pg_major: 18, slot: "physical_acme".into(),
        phase: P::Intent, handoff_barrier: None, standby_lsn: None, previous_retirement: None, last_error: None }).unwrap();
    for (from, to, id) in [(P::Intent, P::Creating, None), (P::Creating, P::Candidate, Some("sb-candidate".into())),
        (P::Candidate, P::Seeding, None), (P::Seeding, P::Verified, None)] {
        assert!(reg.physical_admission_ready("acme"), "preparation must preserve the old serving database");
        reg.physical().advance("acme", "g1", from, to, id).unwrap();
    }
    reg.physical().begin_handoff("acme", "g1", "0/ABC").unwrap();
    for (from, to) in [(P::Prepared, P::Promoting), (P::Promoting, P::Promoted), (P::Promoted, P::Binding)] {
        reg = Arc::new(crate::registry::SchemaRegistry::new(cfg.clone()).unwrap());
        assert!(!reg.physical_admission_ready("acme"));
        assert!(reg.checkout("acme").await.err().unwrap().to_string().contains("incomplete"));
        reg.physical().advance("acme", "g1", from, to, None).unwrap();
    }
    reg.commit_physical_binding("acme", "sb-old", "sb-candidate").await.unwrap();
    reg = Arc::new(crate::registry::SchemaRegistry::new(cfg.clone()).unwrap());
    assert!(!reg.physical_admission_ready("acme"), "a persisted binding alone must not open admission");
    reg.physical().advance("acme", "g1", P::Binding, P::Activated, None).unwrap();
    reg = Arc::new(crate::registry::SchemaRegistry::new(cfg.clone()).unwrap());
    assert!(reg.physical_admission_ready("acme"));
    reg.commit_physical_binding("acme", "sb-candidate", "sb-wrong").await.unwrap();
    assert!(!reg.physical_admission_ready("acme"));
    assert!(reg.checkout("acme").await.err().unwrap().to_string().contains("mismatch"));

    let logical = ReplRecord::new("source", Role::Primary, "eu1", "test-password");
    reg.replication().create(logical.clone(), &|_| false).unwrap();
    reg.physical_sources().create(PhysicalSourceRecord { database: "source".into(), generation: "g2".into(), predecessor: None,
        repl: None, fence: None,
        source_vm_id: "sb-source".into(), system_identifier: "123456".into(), pg_major: 18,
        slot: "physical_source".into(), source_lsn: "0/1".into(), peer: "eu1".into(), handoff_candidate: None, handoff_complete: false, handoff: None, last_error: None }).unwrap();
    assert!(!reg.physical_reconnect_allowed("source", &logical.repl_role));
    reg.physical_sources().grant_handoff("source", "g2", PhysicalHandoffGrant {
        candidate_id: "sb-destination".into(), peer: "eu1".into(), barrier_lsn: "0/ABC".into() }).unwrap();
    reg = Arc::new(crate::registry::SchemaRegistry::new(cfg.clone()).unwrap());
    assert!(!reg.physical_admission_ready("source"));
    assert!(reg.physical_reconnect_allowed("source", &logical.repl_role));
    assert!(!reg.physical_reconnect_allowed("source", "tenant"));
    assert!(!reg.physical_reconnect_allowed("acme", &logical.repl_role));
    assert!(crate::replication::orchestrate::unfence(&reg, "source").await.unwrap_err().to_string().contains("irrevocably"));
    assert!(reg.checkout("source").await.err().unwrap().to_string().contains("lost its fence"));
    drop(reg);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Exercise the production upgrade receiver and raw PG splice with libpq and
/// a disposable server. This isolates protocol framing from public TLS routing.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL18 on 127.0.0.1:5432 and psql on PATH"]
async fn writer_tunnel_preserves_postgres_auth_and_session() {
    use crate::replication::{PhysicalRecord, PhysicalPhase as P, wire};
    use tokio::io::copy_bidirectional;
    let _exclusive = exclusive().await;
    let pg: tokio_postgres::Config = std::env::var("PG_FC_FENCE_TEST_URL").unwrap().parse().unwrap();
    assert_eq!(pg.get_ports(), &[5432]);
    assert_eq!(pg.get_dbname(), Some("postgres"));
    let (admin, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap(); });
    let database = format!("writer_tunnel_{}", std::process::id());
    admin.batch_execute(&format!("CREATE ROLE {database} LOGIN PASSWORD 'writer-test-password';")).await.unwrap();
    admin.batch_execute(&format!("CREATE DATABASE {database} OWNER {database}")).await.unwrap();
    let system: String = admin.query_one("SELECT system_identifier::text FROM pg_control_system()", &[]).await.unwrap().get(0);
    let mut cfg = config_for(0, 0);
    let dir = cfg.state_file.parent().unwrap().join("writer-tunnel");
    std::fs::create_dir_all(&dir).unwrap();
    cfg.state_file = dir.join("registry.tsv"); cfg.replication_file = dir.join("replication.tsv");
    cfg.peers_file = dir.join("peers.tsv"); cfg.dedicated_file = dir.join("dedicated.tsv");
    cfg.pg_user = pg.get_user().unwrap().into();
    cfg.pg_password = pg.get_password().map(|p| String::from_utf8(p.to_vec()).unwrap());
    cfg.direct_connect = true;
    std::fs::write(&cfg.state_file, format!("{database}\tsb-previous\t0\tlive\n")).unwrap();
    let reg = Arc::new(crate::registry::SchemaRegistry::new(cfg.clone()).unwrap());
    reg.dedicated().create(&database, &database, "writer-test-password").unwrap();
    reg.peers().create("source", "https://source.invalid", "admin", "test-password", "127.0.0.1", 6432).unwrap();
    let vm = "sb-writer-tunnel";
    daemon().seed(0);
    daemon().vms.lock().unwrap().insert(vm.into(), Vm { id: vm.into(), name: "repl-seed-writer-test".into(), running: true });
    reg.physical().create(PhysicalRecord {
        database: database.clone(), generation: "writer-test".into(), predecessor: None,
        candidate_name: "repl-seed-writer-test".into(), repl: None, candidate_id: None,
        previous_vm_id: Some("sb-previous".into()), source_node: "source".into(), source_vm_id: "sb-source".into(),
        system_identifier: system.clone(), pg_major: 18, slot: "writer_slot".into(), phase: P::Intent,
        handoff_barrier: None, standby_lsn: None, previous_retirement: None, last_error: None,
    }).unwrap();
    for (from, to, id) in [(P::Intent, P::Creating, None), (P::Creating, P::Candidate, Some(vm.into())), (P::Candidate, P::Seeding, None), (P::Seeding, P::Verified, None)] {
        reg.physical().advance(&database, "writer-test", from, to, id).unwrap();
    }
    reg.physical().begin_handoff(&database, "writer-test", "0/105").unwrap();
    for (from, to) in [(P::Prepared, P::Promoting), (P::Promoting, P::Promoted), (P::Promoted, P::Binding)] {
        reg.physical().advance(&database, "writer-test", from, to, None).unwrap();
    }
    reg.commit_physical_binding(&database, "sb-previous", vm).await.unwrap();
    reg.physical().advance(&database, "writer-test", P::Binding, P::Activated, None).unwrap();
    let receiver = axum::Router::new().route("/tunnel", post(|State(reg): State<Arc<crate::registry::SchemaRegistry>>, mut req: axum::extract::Request| async move {
        crate::writer_routing::accept(&reg, true, &mut req).await
    })).with_state(reg.clone());
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/tunnel", http.local_addr().unwrap());
    let receiver_task = tokio::spawn(async move { axum::serve(http, receiver).await.unwrap(); });
    let frontend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = frontend.local_addr().unwrap().port();
    let claim = wire::WriterClaim { kind: wire::WriterClaimKind::Activation, database: database.clone(),
        generation: "writer-test".into(), candidate_id: vm.into(), source_vm_id: "sb-source".into(),
        system_identifier: system, pg_major: 18, sender_node: "source".into() };
    let frontend_task = tokio::spawn(async move {
        while let Ok((socket, _)) = frontend.accept().await {
            let endpoint = endpoint.clone(); let claim = claim.clone();
            tokio::spawn(async move {
                let crate::startup::Startup::Session(mut socket, info) = crate::startup::read_startup(socket, None).await.unwrap() else { return; };
                if crate::auth::require_password(&mut socket, "writer-test-password").await.is_err() { return; }
                let response = reqwest::Client::new().post(endpoint).header("Connection", "upgrade")
                    .header("Upgrade", "pg-fc-sql/1").json(&wire::WriterTunnelRequest { claim, startup: info.raw }).send().await.unwrap();
                assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
                let mut upgraded = response.upgrade().await.unwrap();
                copy_bidirectional(&mut socket, &mut upgraded).await.unwrap();
            });
        }
    });
    for (password, succeeds) in [("wrong-password", false), ("writer-test-password", true)] {
        let out = tokio::process::Command::new("psql").args(["-X", "-w", "-At", "-v", "ON_ERROR_STOP=1", "-d",
            &format!("host=127.0.0.1 port={port} user={database} dbname={database} sslmode=disable connect_timeout=20"),
            "-c", "CREATE TABLE proof (id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, value text); INSERT INTO proof(value) VALUES ('one-hop'); SELECT pg_sleep(11); SELECT id, value FROM proof;"])
            .env("PGPASSWORD", password).output().await.unwrap();
        assert_eq!(out.status.success(), succeeds, "{}", String::from_utf8_lossy(&out.stderr));
        if succeeds { assert!(String::from_utf8_lossy(&out.stdout).contains("1|one-hop"), "{}", String::from_utf8_lossy(&out.stdout)); }
    }
    frontend_task.abort(); receiver_task.abort();
    drop(reg);
    admin.batch_execute(&format!("DROP DATABASE {database} WITH (FORCE)")).await.unwrap();
    admin.batch_execute(&format!("DROP ROLE {database}")).await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn physical_three_transfers_preserve_revocation_and_replication_credentials() {
    use crate::replication::{PhysicalRecord, PhysicalPhase as P, PhysicalSourceRecord, PhysicalHandoffGrant, wire::Login};
    use crate::writer_routing::{route, Route, validate_destination};
    let _exclusive = exclusive().await;
    let base = config_for(0, 0);
    let dir = base.state_file.parent().unwrap().join("physical-three-transfers");
    std::fs::create_dir_all(&dir).unwrap();
    let mut configs = Vec::new();
    for (region, vm) in [("us3", "u0"), ("eu1", "e0")] {
        let mut cfg = base.clone();
        cfg.state_file = dir.join(format!("{region}.tsv"));
        cfg.replication_file = dir.join(format!("{region}-replication.tsv"));
        cfg.peers_file = dir.join(format!("{region}-peers.tsv"));
        cfg.replication = Some(crate::config::ReplicationConfig {
            node_name: region.into(), advertise_host: None, advertise_port: 6432,
            sslmode: "require".into(), allow_insecure: false, peer_timeout: Duration::from_secs(1),
            setup_deadline: Duration::from_secs(1), monitor_interval: None,
            slot_stale: Duration::from_secs(60), lag_warn_bytes: 1024, fix_sequences: true,
        });
        let peer = if region == "us3" { "eu1" } else { "us3" };
        crate::peers::PeerStore::load(cfg.peers_file.clone()).create(peer,
            &format!("https://{peer}.invalid"), "admin", "test-password", "127.0.0.1", 6432).unwrap();
        std::fs::write(&cfg.state_file, format!("acme\t{vm}\t0\tlive\n")).unwrap();
        configs.push(cfg);
    }
    let mut regions: Vec<_> = configs.iter().map(|cfg| Arc::new(crate::registry::SchemaRegistry::new(cfg.clone()).unwrap())).collect();
    let login = Login { role: "repl_acme".into(), password: "persisted-repl-password".into() };
    for (round, (source_idx, target_idx, candidate, barrier)) in [(0, 1, "e1", "0/101"), (1, 0, "u1", "0/202"), (0, 1, "e2", "0/303")].into_iter().enumerate() {
        let generation = format!("g{}", round + 1);
        let source_reg = &regions[source_idx];
        let target_reg = &regions[target_idx];
        let source_vm = source_reg.bound_vm_id("acme").unwrap();
        let previous_vm = target_reg.bound_vm_id("acme").unwrap();
        let active = source_reg.physical().get("acme");
        let predecessor = active.as_ref().map(|r| r.generation.clone());
        let source = PhysicalSourceRecord { database: "acme".into(), generation: generation.clone(), predecessor: predecessor.clone(),
            source_vm_id: source_vm.clone(), repl: Some(login.clone()), fence: None, system_identifier: "123456".into(), pg_major: 18,
            slot: format!("slot_{generation}"), source_lsn: "0/1".into(), peer: ["us3", "eu1"][target_idx].into(), handoff_candidate: None, handoff_complete: false, handoff: None, last_error: None };
        if let Some(active) = active { source_reg.physical_sources().create_successor(source.clone(), &active, &source_vm).unwrap(); }
        else { source_reg.physical_sources().create(source.clone()).unwrap(); }
        assert!(source_reg.physical_admission_ready("acme"));
        let intent = PhysicalRecord { database: "acme".into(), generation: generation.clone(), predecessor,
            candidate_name: PhysicalRecord::candidate_name(&generation), repl: Some(login.clone()), candidate_id: None,
            previous_vm_id: Some(previous_vm.clone()), source_node: ["us3", "eu1"][source_idx].into(), source_vm_id: source_vm.clone(),
            system_identifier: "123456".into(), pg_major: 18, slot: source.slot.clone(), phase: P::Intent, handoff_barrier: None, standby_lsn: None, previous_retirement: None, last_error: None };
        if round == 0 { target_reg.physical().create(intent).unwrap(); }
        else { target_reg.physical().create_successor(intent, &target_reg.physical_sources().get("acme").unwrap(), &previous_vm).unwrap(); }
        for (from, to, id) in [(P::Intent, P::Creating, None), (P::Creating, P::Candidate, Some(candidate.into())), (P::Candidate, P::Seeding, None), (P::Seeding, P::Verified, None)] {
            target_reg.physical().advance("acme", &generation, from, to, id).unwrap();
        }
        if round == 0 {
            let Route::Peer { claim, .. } = route(target_reg, "acme").unwrap() else { panic!("verified initial replica must route to source") };
            assert_eq!(claim.kind, crate::replication::wire::WriterClaimKind::InitialSource);
            assert_eq!(claim.source_vm_id, "u0");
            target_reg.physical().begin_standby_binding("acme", &generation, "0/100").unwrap();
            let check_route_after_restart = || {
                let restarted = crate::registry::SchemaRegistry::new(configs[target_idx].clone()).unwrap();
                let Route::Peer { claim, .. } = route(&restarted, "acme").unwrap() else { panic!("binding a standby must preserve the writer route") };
                assert_eq!(claim.source_vm_id, "u0");
                assert_eq!(claim.candidate_id, "e1");
                assert_eq!(claim.kind, crate::replication::wire::WriterClaimKind::InitialSource);
            };
            check_route_after_restart();
            target_reg.commit_physical_binding("acme", &previous_vm, candidate).await.unwrap();
            check_route_after_restart();
            target_reg.physical().advance("acme", &generation, P::StandbyBinding, P::Standby, None).unwrap();
            check_route_after_restart();
            target_reg.commit_physical_binding("acme", candidate, "wrong-binding").await.unwrap();
            assert!(matches!(route(target_reg, "acme").unwrap(), Route::Unavailable(_)));
            target_reg.commit_physical_binding("acme", "wrong-binding", candidate).await.unwrap();
        }
        source_reg.physical_sources().authorize_handoff("acme", &generation, candidate).unwrap();
        assert!(crate::replication::orchestrate::unfence(source_reg, "acme").await.is_err());
        source_reg.physical_sources().set_fence("acme", &generation, "ready", Some(barrier)).unwrap();
        assert!(!source_reg.physical_admission_ready("acme"), "a new fence must override an old activation");
        assert!(matches!(route(source_reg, "acme").unwrap(), Route::Unavailable(_)));
        assert!(source_reg.physical_reconnect_allowed("acme", &login.role));
        assert!(!source_reg.physical_reconnect_allowed("acme", "tenant"));
        source_reg.physical_sources().grant_handoff("acme", &generation, PhysicalHandoffGrant { candidate_id: candidate.into(), peer: source.peer, barrier_lsn: barrier.into() }).unwrap();
        let Route::Peer { claim, .. } = route(source_reg, "acme").unwrap() else { panic!("granted source must route to candidate") };
        assert_eq!(claim.generation, generation);
        assert_eq!(claim.candidate_id, candidate);
        // In the reverse-grant window both frontends can have old remote
        // routes. Local-only tunnel validation must refuse the second hop.
        assert!(validate_destination(target_reg, &claim, &previous_vm).is_err());
        target_reg.physical().begin_handoff("acme", &generation, barrier).unwrap();
        for (from, to) in [(P::Prepared, P::Promoting), (P::Promoting, P::Promoted), (P::Promoted, P::Binding)] {
            assert!(validate_destination(target_reg, &claim, &previous_vm).is_err());
            target_reg.physical().advance("acme", &generation, from, to, None).unwrap();
        }
        target_reg.commit_physical_binding("acme", &previous_vm, candidate).await.unwrap();
        assert!(!target_reg.physical_admission_ready("acme"));
        assert!(validate_destination(target_reg, &claim, candidate).is_err());
        target_reg.physical().advance("acme", &generation, P::Binding, P::Activated, None).unwrap();
        source_reg.physical_sources().complete_handoff("acme", &generation, candidate).unwrap();
        regions = configs.iter().map(|cfg| Arc::new(crate::registry::SchemaRegistry::new(cfg.clone()).unwrap())).collect();
        assert!(!regions[source_idx].physical_admission_ready("acme"));
        assert!(regions[target_idx].physical_admission_ready("acme"));
        assert!(matches!(route(&regions[target_idx], "acme").unwrap(), Route::Local));
        assert!(matches!(route(&regions[source_idx], "acme").unwrap(), Route::Peer { .. }));
        assert!(regions[source_idx].physical_sources().pending_handoffs().is_empty());
        validate_destination(&regions[target_idx], &claim, candidate).unwrap();
        for field in ["generation", "candidate_id", "source_vm_id", "system_identifier", "sender_node", "database", "pg_major"] {
            let mut value = serde_json::to_value(&claim).unwrap();
            value[field] = if field == "pg_major" { json!(17) } else { json!("wrong") };
            let wrong = serde_json::from_value(value).unwrap();
            assert!(validate_destination(&regions[target_idx], &wrong, candidate).is_err(), "accepted wrong {field}");
        }
        assert_eq!(regions[source_idx].physical_sources().by_repl_role(&login.role).unwrap().repl, Some(login.clone()));
        assert!(crate::replication::orchestrate::unfence(&regions[source_idx], "acme").await.is_err());
    }
    assert!(regions[0].physical_sources().has_grant_for_source_vm("acme", "u0"));
    assert!(regions[0].physical_sources().has_grant_for_source_vm("acme", "u1"));
    assert!(regions[1].physical_sources().has_grant_for_source_vm("acme", "e1"));
    assert!(!regions[1].physical_sources().has_grant_for_source_vm("acme", "e2"));
    drop(regions);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn physical_candidate_unknown_create_never_duplicates() {
    let _exclusive = exclusive().await;
    let cfg = config_for(0, 0);
    daemon().seed(0);
    daemon().metrics.reset();
    let owned = StdMutex::new(None);
    let own = |id: &str| { *owned.lock().unwrap() = Some(id.to_string()); Ok(()) };
    let name = "repl-seed-resume-test";
    let result = crate::vm::physical_candidate(&cfg, name, false, &own).await;
    assert!(result.err().unwrap().to_string().contains("refusing a second create"));
    assert!(owned.lock().unwrap().is_none());

    // The delayed daemon record becomes visible: resume that exact candidate.
    daemon().vms.lock().unwrap().insert("sb-candidate".into(), Vm {
        id: "sb-candidate".into(), name: name.into(), running: true,
    });
    let sb = crate::vm::physical_candidate(&cfg, name, false, &own).await.unwrap();
    assert_eq!(sb.sandbox_id(), "sb-candidate");
    assert_eq!(owned.lock().unwrap().as_deref(), Some("sb-candidate"));
    assert_eq!(daemon().metrics.calls.lock().unwrap().get("POST /sandbox-deploy").copied().unwrap_or(0), 0);
}
