//! Pushing app-lb's logs to app-obs.
//!
//! app-obs already polls this process for metrics. What it cannot get anywhere
//! else is the *log* side of what app-lb knows: the daemon's own log store only
//! ever holds the output of explicit `execute_command` calls, and a static
//! (`proxy_pass`) deployment has no guest to run a shipper inside at all — so for
//! those deployments the access log written here is the only log they will ever
//! have.
//!
//! Two sources feed one queue:
//!
//! * the **access log** — one record per request, attributed to the deployment
//!   that served it (see `proxy::logging`);
//! * app-lb's **own tracing events** at INFO and above, attributed to the
//!   deployment they name and to [`LB_DEPLOYMENT`] when they name none — so a
//!   scale-up, a failed health probe or an ACME error lands next to the traffic
//!   it concerns instead of only in supervisord's stdout file.
//!
//! Both are inert until `APP_LB_OBS_URL` is set; see [`from_env`].
//!
//! # This must never become a dependency of the data plane
//!
//! Recording is a `try_send` into a bounded queue and nothing else: no lock, no
//! await, no I/O on the request path. When the queue is full, records are dropped
//! and counted — the same trade app-obs makes on its own ingest queue. A
//! collector that has fallen behind must not become latency, and a collector that
//! is *down* must not become errors. A failed POST discards its batch rather than
//! retrying, because a retry queue is a memory leak with extra steps: the newest
//! records are the ones worth keeping, and they are still arriving.

use async_trait::async_trait;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Default deployment id app-lb's own events land under, for the ones that name
/// no deployment of their own. Underscore-prefixed to match app-obs's `_host`
/// convention for rows that belong to no deployment; it does appear in app-obs's
/// fleet list, which is the point — app-lb's own errors should be visible
/// somewhere.
///
/// Overridable with `APP_LB_OBS_DEPLOYMENT`, because one app-obs collects from
/// more than one app-lb: with every LB shipping to the same reserved id, two
/// hosts' events interleave under one name and "which LB logged this?" is only
/// answerable from the batch-level `host`. Naming them `lb-us2`, `lb-eu1` splits
/// them into partitions you can query separately.
pub const LB_DEPLOYMENT: &str = "_lb";

/// Longest id app-obs will store, from its `store::partition::check_deployment`.
const MAX_DEPLOYMENT_LEN: usize = 128;

/// `source` values, distinguishing the streams inside a deployment's log.
const ACCESS_SOURCE: &str = "access";
const EVENT_SOURCE: &str = "app-lb";
const JOB_SOURCE: &str = "job";

/// This module's tracing target, never shipped: a failed POST logs a warning,
/// and shipping that warning would generate another POST.
const SELF_TARGET: &str = module_path!();

/// Ceilings on the two unbounded strings in a record. A request path comes off
/// the wire and a Debug-formatted field can be arbitrarily large; app-obs's
/// ingest has a body limit, and one pathological record must not cost the whole
/// batch it travels in.
const MAX_PATH: usize = 512;
pub(crate) const MAX_MESSAGE: usize = 4096;

/// Ceiling on one POST. A collector that accepts the connection and then stalls
/// would otherwise hold the only shipping task forever, which shows up as a full
/// queue and dropped records rather than as the stall it is.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Much tighter ceiling on the *last* flush. `supervisorctl restart app-lb` must
/// not wait on a stalled collector — the records in hand are worth a moment, not
/// a delayed restart.
const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Shared with [`crate::siem`], which stamps its alerts on the same clock so an
/// alert and the access record that triggered it sort together in app-obs.
pub(crate) fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Truncate on a char boundary, marking that it happened.
pub(crate) fn truncate(mut s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s.push('…');
    s
}

/// Where app-lb ships, and how it batches. Process-level, so environment-only
/// like the rest of [`crate::config::LbConfig`] — except that the token is kept
/// out of anything derivable.
#[derive(Debug, Clone)]
pub struct ObsConfig {
    /// Full ingest URL, `<APP_LB_OBS_URL>/ingest`.
    pub endpoint: String,
    /// Bearer token matching app-obs's `APP_OBS_INGEST_TOKEN`. `None` is correct
    /// only when app-obs left its own ingest open.
    pub token: Option<String>,
    /// Batch-level `host`, identifying which machine these records came from.
    pub host: Option<String>,
    /// Deployment id for records that name no deployment of their own; see
    /// [`LB_DEPLOYMENT`]. `Arc<str>` because every such record clones it.
    pub deployment: Arc<str>,
    pub queue_capacity: usize,
    /// Records per POST. A batch is also flushed early when [`Self::flush`]
    /// elapses, so this is a ceiling, not a threshold to wait for.
    pub batch: usize,
    pub flush: Duration,
}

/// The pieces `main` wires up. Both sinks are clones of one queue: the split is
/// only about which sources are enabled.
pub struct Obs {
    /// Handed to the proxy. `None` when `APP_LB_OBS_ACCESS_LOG=0`.
    pub access: Option<LogSink>,
    /// Wrapped in an [`EventLayer`] at subscriber init. `None` when
    /// `APP_LB_OBS_EVENTS=0`.
    pub events: Option<LogSink>,
    /// Registered as a pingora background service.
    pub shipper: Shipper,
    /// Read by the admin API's `/metrics`, so a silently-dropping pipeline is
    /// visible without reading logs about the log shipper.
    pub stats: Arc<Stats>,
}

/// Shared with [`crate::siem`] rather than duplicated there, so the two cannot
/// drift on what counts as true or on whether a malformed number is fatal.
pub(crate) fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

pub(crate) fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(v) => match v.trim().parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => panic!("{name} must be a positive integer, got {v:?}"),
        },
        Err(_) => default,
    }
}

/// Turn `APP_LB_OBS_URL` into the full ingest endpoint, or say what is wrong
/// with it.
///
/// Two accommodations, because the value that gets typed here is almost always
/// copied from an *address* rather than written as a URL:
///
/// * **A missing scheme is filled in.** Every other address in this system is a
///   bare `host:port` (`APP_LB_ADMIN_ADDR`, `APP_OBS_INGEST_ADDR`), so that is
///   what people write. app-obs's ingest is plaintext HTTP and there is no second
///   reading of `127.0.0.1:9500`, so it is not a guess. Detected on `://` rather
///   than `:`, because `Url::parse` would otherwise read `127.0.0.1:9500` as the
///   *scheme* `127.0.0.1` and be perfectly happy about it.
/// * **A wildcard host becomes loopback.** `0.0.0.0` is what app-obs *binds*; as
///   a destination it can only have meant this host. Linux will connect to it,
///   which is worse than failing — it works until app-obs moves to another host.
///
/// Anything left over is a real error: a scheme that isn't HTTP, or no host at
/// all. Reported rather than repaired, since there is no defensible guess.
fn ingest_endpoint(raw: &str) -> Result<String, String> {
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };

    let mut url = reqwest::Url::parse(&with_scheme)
        .map_err(|e| format!("{raw:?} is not a URL ({e}); expected something like http://127.0.0.1:9500"))?;

    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "{raw:?} has scheme {:?}; app-obs ingest is http (or https behind a proxy)",
            url.scheme(),
        ));
    }
    match url.host_str() {
        Some("0.0.0.0") => set_host(&mut url, "127.0.0.1", raw)?,
        Some("::" | "[::]") => set_host(&mut url, "[::1]", raw)?,
        Some(_) => {}
        None => {
            return Err(format!(
                "{raw:?} names no host; expected something like http://127.0.0.1:9500",
            ));
        }
    }

    // `/ingest` on whatever path prefix was given, so app-obs behind a proxy at
    // `https://obs.example/collector` works as well as a bare host does.
    Ok(format!("{}/ingest", url.as_str().trim_end_matches('/')))
}

/// Read `APP_LB_OBS_DEPLOYMENT`, or fall back to [`LB_DEPLOYMENT`].
///
/// Validated here rather than left to app-obs, because app-obs's rejection is
/// invisible from this side: it 400s the *batch*, the shipper counts it as a
/// failed POST, and the reason ("bad deployment") never surfaces as anything
/// more specific than `HTTP 400` in a warning. Worse, the batch it kills also
/// carried other deployments' records — one bad label would silently cost every
/// log line that travelled with it.
///
/// The rule is app-obs's own (`store::partition::check_deployment`): the id
/// becomes a directory name, so it is letters, digits, dot, dash and underscore,
/// and not all dots.
fn lb_deployment(raw: Option<&str>) -> Result<Arc<str>, String> {
    let Some(id) = raw.map(str::trim).filter(|id| !id.is_empty()) else {
        return Ok(Arc::from(LB_DEPLOYMENT));
    };
    let legal = id.len() <= MAX_DEPLOYMENT_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && id.bytes().any(|b| b != b'.');
    if !legal {
        return Err(format!(
            "APP_LB_OBS_DEPLOYMENT={id:?} is not a deployment id app-obs can store; \
             use 1-{MAX_DEPLOYMENT_LEN} characters of [A-Za-z0-9._-] (it becomes a \
             directory name there)",
        ));
    }
    Ok(Arc::from(id))
}

fn set_host(url: &mut reqwest::Url, host: &str, raw: &str) -> Result<(), String> {
    url.set_host(Some(host))
        .map_err(|e| format!("cannot read {raw:?} as an address ({e})"))
}

/// Build the pipeline from the environment: `Ok(None)` leaves app-lb exactly as
/// it was, `Err` names a misconfiguration.
///
/// `APP_LB_OBS_URL` is the switch, in the same way `APP_LB_ACME_EMAIL` is the
/// switch for certificates: there is no default endpoint, because POSTing every
/// second to a port nobody is listening on is worse than shipping nothing.
///
/// A bad URL is returned as an error rather than panicking, and the caller
/// disables shipping and carries on. Panicking would make the observability
/// configuration able to take down the data plane, which is the one thing this
/// whole module is built not to do. A bad *numeric* setting still panics —
/// silently ignoring `APP_LB_OBS_QUEUE_CAPACITY=big` would leave a queue sized
/// nothing like what was asked for.
///
/// Note this runs *before* the tracing subscriber exists (installing the event
/// layer is why), so it cannot log a thing; everything it wants to say has to
/// come back through the return value.
pub fn from_env() -> Result<Option<Obs>, String> {
    let Some(url) = std::env::var("APP_LB_OBS_URL")
        .ok()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
    else {
        return Ok(None);
    };

    let config = ObsConfig {
        endpoint: ingest_endpoint(&url)?,
        token: std::env::var("APP_LB_OBS_TOKEN")
            .ok()
            .filter(|t| !t.trim().is_empty()),
        host: std::env::var("APP_LB_OBS_HOST")
            .ok()
            .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty()),
        deployment: lb_deployment(std::env::var("APP_LB_OBS_DEPLOYMENT").ok().as_deref())?,
        queue_capacity: env_usize("APP_LB_OBS_QUEUE_CAPACITY", 8192),
        batch: env_usize("APP_LB_OBS_BATCH", 500),
        flush: Duration::from_secs(env_usize("APP_LB_OBS_FLUSH_SECS", 2) as u64),
    };

    let (sink, rx) = LogSink::new(config.queue_capacity, config.deployment.clone());
    let stats = sink.stats.clone();
    Ok(Some(Obs {
        access: env_flag("APP_LB_OBS_ACCESS_LOG", true).then(|| sink.clone()),
        events: env_flag("APP_LB_OBS_EVENTS", true).then(|| sink.clone()),
        shipper: Shipper {
            config,
            rx: Mutex::new(Some(rx)),
            stats: stats.clone(),
        },
        stats,
    }))
}

/// One log line, in app-obs's ingest shape. `host` is set once per batch by the
/// shipper rather than repeated on every record.
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    /// Epoch milliseconds, stamped when the record is *made*. app-obs would
    /// default it to arrival time, but batching would then smear a burst across
    /// whenever the flush happened to land.
    pub ts: i64,
    pub deployment: String,
    /// The sandbox id for a managed VM, the `host:port` for a static upstream —
    /// `VmBackend::sandbox_id` already carries whichever applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    pub source: &'static str,
    pub level: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<serde_json::Value>,
}

/// Counters for the pipeline itself.
#[derive(Debug)]
pub struct Stats {
    queued: AtomicU64,
    dropped: AtomicU64,
    shipped: AtomicU64,
    failed: AtomicU64,
    healthy: AtomicBool,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            queued: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            shipped: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            // Optimistic until proven otherwise, so the first failure is a
            // transition worth logging.
            healthy: AtomicBool::new(true),
        }
    }
}

impl Stats {
    pub fn snapshot(&self) -> ObsSnapshot {
        ObsSnapshot {
            queued: self.queued.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            shipped: self.shipped.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            healthy: self.healthy.load(Ordering::Relaxed),
        }
    }
}

/// What `/metrics` reports about log shipping. `queued - shipped - failed` is
/// what is still in the queue; `dropped` never reached it.
#[derive(Debug, Clone, Serialize)]
pub struct ObsSnapshot {
    /// Records accepted into the queue.
    pub queued: u64,
    /// Records refused because the queue was full.
    pub dropped: u64,
    /// Records app-obs accepted.
    pub shipped: u64,
    /// Records lost to a failed POST.
    pub failed: u64,
    /// Whether the last POST succeeded.
    pub healthy: bool,
}

/// The write end, cloned to every source.
#[derive(Clone)]
pub struct LogSink {
    tx: mpsc::Sender<Record>,
    stats: Arc<Stats>,
    /// Where records that name no deployment go. Carried on the sink rather than
    /// read from a global, so every source attributes them the same way and the
    /// value is settable in a test.
    deployment: Arc<str>,
}

impl LogSink {
    fn new(capacity: usize, deployment: Arc<str>) -> (Self, mpsc::Receiver<Record>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self {
                tx,
                stats: Arc::new(Stats::default()),
                deployment,
            },
            rx,
        )
    }

    /// Queue a record, or drop it. Never blocks and never awaits — it is called
    /// from `logging` on the request path and from a tracing layer, which is
    /// synchronous and may not even be inside the runtime.
    pub fn send(&self, record: Record) {
        let counter = match self.tx.try_send(record) {
            Ok(()) => &self.stats.queued,
            Err(_) => &self.stats.dropped,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Queue one proxied request, attributing an unrouted one to this sink's
    /// deployment id. The proxy goes through this rather than building the record
    /// itself so it never has to know what that id is.
    pub fn send_access(&self, access: Access<'_>) {
        self.send(access.into_record(&self.deployment));
    }

    /// The id records that name no deployment are filed under.
    ///
    /// Shared with [`crate::siem`] so an alert raised against the LB itself lands
    /// beside the events that explain it, rather than under a second id derived
    /// by reading the environment twice.
    pub fn deployment(&self) -> Arc<str> {
        self.deployment.clone()
    }
}

/// Log level for a proxied request.
///
/// A 5xx and an upstream that never produced a response at all are both errors:
/// app-obs counts `error` lines per deployment, and those are exactly the two
/// outcomes worth counting. A 4xx is the caller's mistake rather than the
/// deployment's, so it is a warning — which keeps a scanner hammering unknown
/// paths from reading as an outage.
pub fn access_level(status: Option<u16>) -> &'static str {
    match status {
        Some(s) if s < 400 => "info",
        Some(s) if s < 500 => "warn",
        // Out-of-range codes join the 5xx side, as they do in `metrics`.
        Some(_) | None => "error",
    }
}

/// One proxied request, as the proxy sees it at the end.
pub struct Access<'a> {
    /// `None` for a request that matched no deployment. Those still ship, under
    /// [`LB_DEPLOYMENT`] with an `unrouted` marker — a wall of 404s for a
    /// hostname somebody expected to work is the single most common thing to have
    /// to diagnose, and it is invisible in a per-deployment view by definition.
    pub deployment: Option<&'a str>,
    pub backend: Option<String>,
    pub method: &'a str,
    pub path: &'a str,
    pub host: Option<&'a str>,
    /// `None` when nothing was ever written — all retries failed, or the cold
    /// start timed out.
    pub status: Option<u16>,
    pub duration: Duration,
    pub bytes: usize,
    pub client: Option<String>,
    pub error: Option<String>,
}

impl Access<'_> {
    /// `lb_deployment` attributes a request that matched nothing; see
    /// [`LogSink::send_access`], which supplies it.
    pub fn into_record(self, lb_deployment: &str) -> Record {
        // A transfer URL's path is its credential; never log it.
        let path = truncate(
            crate::transfers::redact(self.path).into_owned(),
            MAX_PATH,
        );
        let ms = self.duration.as_secs_f64() * 1000.0;
        let status = self.status;
        let message = match status {
            Some(s) => format!("{} {path} {s} {ms:.1}ms", self.method),
            // A dash rather than a 0, because no response was written at all.
            None => format!("{} {path} - {ms:.1}ms", self.method),
        };

        let mut fields = serde_json::Map::new();
        fields.insert("method".into(), self.method.into());
        fields.insert("path".into(), path.into());
        fields.insert(
            "status".into(),
            status.map_or(serde_json::Value::Null, |s| s.into()),
        );
        // Rounded to microseconds: enough to tell a tap-network hop from a cold
        // start, and it keeps the JSON short.
        fields.insert(
            "duration_ms".into(),
            serde_json::Number::from_f64((ms * 1000.0).round() / 1000.0)
                .map_or(serde_json::Value::Null, serde_json::Value::Number),
        );
        fields.insert("bytes".into(), self.bytes.into());
        if let Some(host) = self.host {
            fields.insert("host".into(), host.into());
        }
        if let Some(client) = self.client {
            fields.insert("client".into(), client.into());
        }
        if let Some(error) = self.error {
            fields.insert("error".into(), truncate(error, MAX_MESSAGE).into());
        }
        if self.deployment.is_none() {
            fields.insert("unrouted".into(), true.into());
        }

        Record {
            ts: now_millis(),
            deployment: self.deployment.unwrap_or(lb_deployment).to_string(),
            backend: self.backend,
            source: ACCESS_SOURCE,
            level: access_level(status),
            message,
            fields: Some(serde_json::Value::Object(fields)),
        }
    }
}

/// One line of a deploy job's output, attributed to the deployment it is for.
///
/// A job's output otherwise lives only in its in-memory [`JobRecord`], which is
/// capped at a few hundred lines, kept for a bounded history, and gone on restart.
/// That is fine for "why did this build fail?" asked within the hour and useless
/// for anything else — including the case that matters most, a build or update
/// that *hangs*, where the record shows `running` and the transcript that would
/// say where it stopped is only readable by polling the admin API at the time.
///
/// Attributed to the deployment rather than to app-lb itself, because "what
/// happened to this deployment lately" should have one answer: the build that
/// produced the image, the roll-out, and the traffic that followed all sit in one
/// stream, separable by `source`.
///
/// [`JobRecord`]: crate::jobs::JobRecord
pub fn job_line(deployment: &str, job_id: &str, line: String) -> Record {
    Record {
        ts: now_millis(),
        deployment: deployment.to_string(),
        // A build runs on the host, not in any VM; there is no backend to name.
        backend: None,
        source: JOB_SOURCE,
        // Step output is not levelled — a compiler warning and a fatal error
        // arrive on the same stream. The job's *outcome* is a separate event, and
        // that one is an error when it failed.
        level: "info",
        message: truncate(line, MAX_MESSAGE),
        fields: Some(serde_json::json!({ "job": job_id })),
    }
}

/// Forwards app-lb's own tracing events into the queue.
///
/// Only app-lb's own targets, and only INFO and above: DEBUG is where the
/// per-request routing chatter lives (the default filter is `app_lb=debug`), and
/// shipping it would bury the events that matter under a copy of the access log.
/// Everything else in the dependency graph is excluded outright — reqwest and
/// hyper log *inside* the POST this layer feeds, so forwarding them would be a
/// feedback loop.
pub struct EventLayer {
    sink: LogSink,
}

impl EventLayer {
    pub fn new(sink: LogSink) -> Self {
        Self { sink }
    }
}

/// Whether an event came from app-lb itself, and not from this module.
///
/// [`crate::siem`] is excluded for a second-order version of the same reason:
/// if app-obs is itself fronted by this app-lb, a shipped record becomes a
/// proxied request, which becomes an observation, which can raise an alert, which
/// ships another record. The SIEM's own alert-rate ceiling bounds that loop on
/// the alert side; this closes it on the tracing side.
fn ships_target(target: &str) -> bool {
    if target.starts_with(SELF_TARGET) || target.starts_with("app_lb::siem") {
        return false;
    }
    target == "app_lb" || target.starts_with("app_lb::")
}

fn level_name(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "error",
        Level::WARN => "warn",
        _ => "info",
    }
}

impl<S: Subscriber> Layer<S> for EventLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if !ships_target(meta.target()) {
            return;
        }
        // `Level` orders by verbosity, so TRACE is the *greatest*: this keeps
        // ERROR/WARN/INFO and drops DEBUG/TRACE.
        if *meta.level() > Level::INFO {
            return;
        }

        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        // The target says which subsystem spoke, which is most of what a bare
        // message leaves out.
        visitor
            .fields
            .insert("target".into(), meta.target().into());

        self.sink.send(Record {
            ts: now_millis(),
            deployment: visitor
                .deployment
                .unwrap_or_else(|| self.sink.deployment.to_string()),
            // An event names a deployment, never an individual backend; the
            // sandbox, where one is relevant, stays in `fields`.
            backend: None,
            source: EVENT_SOURCE,
            level: level_name(meta.level()),
            message: truncate(
                visitor
                    .message
                    .unwrap_or_else(|| meta.target().to_string()),
                MAX_MESSAGE,
            ),
            fields: Some(serde_json::Value::Object(visitor.fields)),
        });
    }
}

/// Splits an event's fields into the log line, the deployment it belongs to, and
/// everything else.
#[derive(Default)]
struct EventVisitor {
    message: Option<String>,
    deployment: Option<String>,
    fields: serde_json::Map<String, serde_json::Value>,
}

impl EventVisitor {
    fn insert(&mut self, field: &Field, value: serde_json::Value) {
        match field.name() {
            // The format-args message is the log line, not a field of it.
            "message" => {
                self.message = Some(match value {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                })
            }
            // Attribution: an event that names a deployment belongs in that
            // deployment's log rather than app-lb's. Taken out of `fields`
            // because app-obs stores it as the partition key, so leaving it in
            // would write the same string twice per record.
            "deployment" => match value {
                serde_json::Value::String(s) => self.deployment = Some(s),
                other => {
                    self.fields.insert("deployment".into(), other);
                }
            },
            name => {
                self.fields.insert(name.to_string(), value);
            }
        }
    }
}

impl Visit for EventVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, value.into());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, value.into());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        // JSON has no NaN or infinity; the string keeps the value visible
        // instead of turning it into a null.
        let value = serde_json::Number::from_f64(value)
            .map_or_else(|| value.to_string().into(), serde_json::Value::Number);
        self.insert(field, value);
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert(field, value.to_string().into());
    }

    /// Catches both `?x` (genuine `Debug`) and `%x` (`Display`, which tracing
    /// records as the `Debug` of a `format_args!`, so this yields the displayed
    /// text unquoted).
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.insert(field, format!("{value:?}").into());
    }
}

/// A batch, in app-obs's ingest shape. No batch-level `deployment`: every record
/// carries its own, and a default here would silently re-attribute anything that
/// somehow didn't.
#[derive(Serialize)]
struct Batch<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<&'a str>,
    records: &'a [Record],
}

/// Drains the queue into app-obs.
pub struct Shipper {
    config: ObsConfig,
    /// Taken by `start`. In a `Mutex<Option<_>>` because pingora hands a
    /// background service `&self`, so the receive end cannot simply be owned.
    rx: Mutex<Option<mpsc::Receiver<Record>>>,
    stats: Arc<Stats>,
}

impl Shipper {
    /// Record the outcome of a POST, logging only the *transitions*. A collector
    /// that stays down for an hour is one warning, not one per flush; the running
    /// count is in `/metrics`.
    fn mark(&self, ok: bool, records: usize, reason: &str) {
        let was_healthy = self.stats.healthy.swap(ok, Ordering::Relaxed);
        let counter = if ok {
            &self.stats.shipped
        } else {
            &self.stats.failed
        };
        counter.fetch_add(records as u64, Ordering::Relaxed);

        match (ok, was_healthy) {
            (true, false) => tracing::info!(
                endpoint = %self.config.endpoint,
                "app-obs ingest recovered",
            ),
            (false, true) => tracing::warn!(
                endpoint = %self.config.endpoint,
                error = reason,
                dropped = records,
                "app-obs ingest failed; discarding this batch rather than retrying \
                 (app-lb never waits on the collector)",
            ),
            _ => {}
        }
    }

    /// Flush, unless shutdown arrives first — in which case the batch is left
    /// intact for the final flush to retry. Returns whether it was interrupted.
    ///
    /// `select!` cannot preempt a future it is already awaiting, so without this
    /// a POST to a collector that accepted the connection and then went quiet
    /// would hold up a restart for the whole [`REQUEST_TIMEOUT`].
    async fn flush_or_stop(
        &self,
        client: &reqwest::Client,
        batch: &mut Vec<Record>,
        shutdown: &mut ShutdownWatch,
    ) -> bool {
        tokio::select! {
            _ = shutdown.changed() => true,
            () = self.flush(client, batch) => false,
        }
    }

    /// POST one batch and clear it, whatever happened to it.
    async fn flush(&self, client: &reqwest::Client, batch: &mut Vec<Record>) {
        if batch.is_empty() {
            return;
        }
        let count = batch.len();
        let body = Batch {
            host: self.config.host.as_deref(),
            records: batch,
        };

        let mut request = client.post(&self.config.endpoint).json(&body);
        if let Some(token) = &self.config.token {
            request = request.bearer_auth(token);
        }

        match request.send().await {
            // 202, in app-obs's case: queued, not yet on disk.
            Ok(response) if response.status().is_success() => self.mark(true, count, ""),
            Ok(response) => self.mark(false, count, &format!("HTTP {}", response.status())),
            Err(e) => self.mark(false, count, &error_chain(&e)),
        }
        batch.clear();
    }
}

/// Flatten an error and its causes into one line.
///
/// reqwest's own `Display` is frequently useless on its own — a bad URL reads
/// only as `builder error`, and the cause that actually names the problem
/// (`relative URL without a base`) is a level down. This is the difference
/// between a warning somebody can act on and one they have to go read the source
/// to interpret.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut message = e.to_string();
    let mut cause = e.source();
    while let Some(e) = cause {
        let text = e.to_string();
        // Skip a cause that only repeats what the outer layer already said.
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        cause = e.source();
    }
    message
}

#[async_trait]
impl BackgroundService for Shipper {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let Some(mut rx) = self.rx.lock().expect("obs receiver lock").take() else {
            // `start` runs once per service; a second call has nothing to drain.
            tracing::error!("log shipper started twice");
            return;
        };

        // Built here, not in `from_env`: `main` constructs the pipeline before
        // `run_forever`, which may fork to daemonize, and a client's connection
        // pool would not survive that.
        let client = match reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
        {
            Ok(client) => client,
            // Shipping is off, but the queue's senders keep dropping records on
            // the floor, which is exactly what they do when it is disabled.
            Err(e) => {
                tracing::error!(error = %e, "cannot build the app-obs HTTP client; logs will not ship");
                return;
            }
        };

        tracing::info!(
            endpoint = %self.config.endpoint,
            batch = self.config.batch,
            flush_secs = self.config.flush.as_secs(),
            authenticated = self.config.token.is_some(),
            // Which app-obs partition app-lb's own lines will appear under. Worth
            // one field at startup: the alternative is looking for a deployment id
            // in app-obs that you have to already know the value of.
            lb_deployment = %self.config.deployment,
            "shipping logs to app-obs",
        );

        let mut batch: Vec<Record> = Vec::with_capacity(self.config.batch);
        // Deliberately not `interval`, whose first tick fires *immediately*: that
        // POSTs in the first millisecond of the process, and when app-lb and
        // app-obs are started together by the same supervisor, app-obs has not
        // bound its listener yet. app-lb's startup events — the restored
        // deployments, the loaded certificates — are exactly the ones lost to
        // that race, and they are the ones most worth having after a host boot.
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + self.config.flush,
            self.config.flush,
        );
        // A flush that overruns the interval must not then fire back-to-back
        // ticks trying to catch up.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            // Set by a shutdown signal, including one that arrives while a POST
            // is in flight.
            let stopping = tokio::select! {
                _ = shutdown.changed() => true,
                _ = ticker.tick() => self.flush_or_stop(&client, &mut batch, &mut shutdown).await,
                record = rx.recv() => {
                    let Some(record) = record else {
                        // Every sender dropped, which in practice means the
                        // process is tearing down.
                        break;
                    };
                    batch.push(record);
                    // Sweep up whatever else is already waiting, so a burst
                    // becomes one POST instead of one per record.
                    while batch.len() < self.config.batch {
                        match rx.try_recv() {
                            Ok(record) => batch.push(record),
                            Err(_) => break,
                        }
                    }
                    if batch.len() >= self.config.batch {
                        self.flush_or_stop(&client, &mut batch, &mut shutdown).await
                    } else {
                        false
                    }
                }
            };
            if stopping {
                break;
            }
        }

        // Take whatever is already queued — but don't wait for more, because
        // shutdown is not the time to hold the process open for telemetry.
        while batch.len() < self.config.batch {
            match rx.try_recv() {
                Ok(record) => batch.push(record),
                Err(_) => break,
            }
        }
        let last = self.flush(&client, &mut batch);
        if tokio::time::timeout(SHUTDOWN_FLUSH_TIMEOUT, last).await.is_err() {
            tracing::warn!(
                records = batch.len(),
                "app-obs did not answer the final flush in time; abandoning it",
            );
        }
        tracing::info!("log shipper stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    fn sink() -> (LogSink, mpsc::Receiver<Record>) {
        LogSink::new(64, Arc::from(LB_DEPLOYMENT))
    }

    /// The value written here is nearly always copied from an *address*, so the
    /// forms people actually type have to work rather than fail at the first
    /// flush with reqwest's `builder error`.
    #[test]
    fn an_address_is_accepted_as_readily_as_a_url() {
        let cases = [
            // What a URL looks like.
            ("http://127.0.0.1:9500", "http://127.0.0.1:9500/ingest"),
            ("http://127.0.0.1:9500/", "http://127.0.0.1:9500/ingest"),
            ("https://obs.example.com", "https://obs.example.com/ingest"),
            // Bare host:port, matching every other address in this system. Note
            // `Url::parse` would read the host as a *scheme* here, which is why
            // the check is on `://`.
            ("127.0.0.1:9500", "http://127.0.0.1:9500/ingest"),
            ("localhost:9500", "http://localhost:9500/ingest"),
            // The wildcard app-obs binds. As a destination it can only mean this
            // host, and Linux would connect to it — working right up until
            // app-obs moves elsewhere.
            ("0.0.0.0:9500", "http://127.0.0.1:9500/ingest"),
            ("http://0.0.0.0:9500", "http://127.0.0.1:9500/ingest"),
            ("[::]:9500", "http://[::1]:9500/ingest"),
            // app-obs behind a proxy on a path prefix.
            ("https://obs.example.com/collector", "https://obs.example.com/collector/ingest"),
        ];
        for (raw, expected) in cases {
            assert_eq!(ingest_endpoint(raw).as_deref(), Ok(expected), "for {raw:?}");
        }
    }

    #[test]
    fn an_unusable_endpoint_says_what_is_wrong_with_it() {
        // Each message has to name the offending value, because it is read out of
        // a startup log by somebody who just edited a supervisor unit.
        for raw in ["", "http://", "ftp://obs:9500", "not a url at all"] {
            let err = ingest_endpoint(raw).expect_err("should be rejected: {raw:?}");
            assert!(err.contains(&format!("{raw:?}")), "{raw:?} -> {err}");
        }
    }

    /// The failure that prompted this: `0.0.0.0:9500/ingest` with no scheme
    /// reached reqwest, which said only "builder error".
    #[test]
    fn error_chain_reaches_the_cause_that_names_the_problem() {
        #[derive(Debug)]
        struct Outer(Inner);
        #[derive(Debug)]
        struct Inner;
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("builder error")
            }
        }
        impl std::fmt::Display for Inner {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("relative URL without a base")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        impl std::error::Error for Inner {}

        assert_eq!(
            error_chain(&Outer(Inner)),
            "builder error: relative URL without a base",
        );
        // A cause that merely repeats the outer text adds nothing.
        assert_eq!(error_chain(&Inner), "relative URL without a base");
    }

    #[test]
    fn request_outcomes_map_onto_the_levels_app_obs_counts() {
        assert_eq!(access_level(Some(200)), "info");
        assert_eq!(access_level(Some(302)), "info", "a sign-in redirect is not a fault");
        assert_eq!(access_level(Some(404)), "warn");
        assert_eq!(access_level(Some(499)), "warn");
        assert_eq!(access_level(Some(500)), "error");
        assert_eq!(access_level(Some(999)), "error", "out of range joins the 5xx side");
        // No response written at all: every upstream failed, or the cold start
        // timed out. The worst outcome there is, so it must not read as a 2xx.
        assert_eq!(access_level(None), "error");
    }

    #[tokio::test]
    async fn a_full_queue_drops_instead_of_blocking() {
        // The defining property: this is called from the request path, so it may
        // never await a free slot.
        let (sink, _rx) = LogSink::new(1, Arc::from(LB_DEPLOYMENT));
        sink.send_access(access(Some("demo"), Some(200)));
        sink.send_access(access(Some("demo"), Some(200)));

        assert_eq!(sink.stats.queued.load(Ordering::Relaxed), 1);
        assert_eq!(sink.stats.dropped.load(Ordering::Relaxed), 1);
        let snapshot = sink.stats.snapshot();
        assert_eq!((snapshot.queued, snapshot.dropped), (1, 1));
    }

    fn access(deployment: Option<&str>, status: Option<u16>) -> Access<'_> {
        Access {
            deployment,
            backend: Some("sb-abc123".into()),
            method: "GET",
            path: "/things",
            host: Some("demo.local"),
            status,
            duration: Duration::from_millis(12),
            bytes: 34,
            client: Some("10.1.2.3".into()),
            error: None,
        }
    }

    /// The wire shape has to match what app-obs's `Batch`/`IncomingRecord`
    /// deserialize, and nothing in this repo compiles against those types.
    #[test]
    fn an_access_record_serializes_into_app_obs_ingest_shape() {
        let record = access(Some("demo"), Some(200)).into_record(LB_DEPLOYMENT);
        let json = serde_json::to_value(&record).unwrap();

        assert_eq!(json["deployment"], "demo");
        assert_eq!(json["backend"], "sb-abc123");
        assert_eq!(json["source"], "access");
        assert_eq!(json["level"], "info");
        assert_eq!(json["message"], "GET /things 200 12.0ms");
        assert!(json["ts"].as_i64().is_some_and(|ts| ts > 1_700_000_000_000));
        assert_eq!(json["fields"]["method"], "GET");
        assert_eq!(json["fields"]["path"], "/things");
        assert_eq!(json["fields"]["status"], 200);
        assert_eq!(json["fields"]["duration_ms"], 12.0);
        assert_eq!(json["fields"]["bytes"], 34);
        assert_eq!(json["fields"]["host"], "demo.local");
        assert_eq!(json["fields"]["client"], "10.1.2.3");
        assert!(json["fields"].get("unrouted").is_none());

        let batch = serde_json::to_value(Batch {
            host: Some("us2"),
            records: std::slice::from_ref(&record),
        })
        .unwrap();
        assert_eq!(batch["host"], "us2");
        assert_eq!(batch["records"][0]["message"], record.message);
        assert!(
            batch.get("deployment").is_none(),
            "a batch-level default would re-attribute records",
        );
    }

    #[test]
    fn a_request_that_matched_no_deployment_is_still_attributable() {
        // app-obs rejects a record with no deployment outright, so these would
        // vanish rather than land somewhere useful.
        let record = access(None, Some(404)).into_record(LB_DEPLOYMENT);
        assert_eq!(record.deployment, LB_DEPLOYMENT);
        assert_eq!(record.level, "warn");
        let fields = serde_json::to_value(record.fields).unwrap();
        assert_eq!(fields["unrouted"], true);
    }

    /// Both streams have to honour `APP_LB_OBS_DEPLOYMENT`, or one app-lb's
    /// unrouted 404s would still land under `_lb` while its events moved.
    #[tokio::test]
    async fn a_configured_id_replaces_the_default_on_both_streams() {
        let (sink, mut rx) = LogSink::new(64, Arc::from("lb-us2"));
        sink.send_access(access(None, Some(404)));
        assert_eq!(rx.try_recv().unwrap().deployment, "lb-us2");

        let subscriber = tracing_subscriber::registry().with(EventLayer::new(sink));
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target: AS_IF_FROM, "cannot bind");
        });
        assert_eq!(rx.try_recv().unwrap().deployment, "lb-us2");

        // A record that names its own deployment is untouched by the override.
        let record = access(Some("demo"), Some(200)).into_record("lb-us2");
        assert_eq!(record.deployment, "demo");
    }

    /// app-obs 400s the whole *batch* for one illegal deployment id, taking every
    /// other deployment's records in it down too — so this has to be caught here,
    /// at startup, and not discovered as an opaque `HTTP 400` later.
    #[test]
    fn only_ids_app_obs_can_store_are_accepted() {
        assert_eq!(&*lb_deployment(None).unwrap(), LB_DEPLOYMENT);
        assert_eq!(&*lb_deployment(Some("")).unwrap(), LB_DEPLOYMENT);
        assert_eq!(&*lb_deployment(Some("  ")).unwrap(), LB_DEPLOYMENT);
        assert_eq!(&*lb_deployment(Some(" lb-us2 ")).unwrap(), "lb-us2");
        assert_eq!(&*lb_deployment(Some("_lb.eu1")).unwrap(), "_lb.eu1");

        for bad in [
            "lb/us2",     // a path separator: the id becomes a directory name
            "..",         // all dots: a relative path component
            "lb us2",     // a space
            "lb:us2",
            "lb\u{2019}", // non-ASCII
        ] {
            let err = lb_deployment(Some(bad)).expect_err("should be rejected: {bad:?}");
            assert!(err.contains(&format!("{bad:?}")), "{bad:?} -> {err}");
        }
        assert!(lb_deployment(Some(&"x".repeat(MAX_DEPLOYMENT_LEN + 1))).is_err());
        assert!(lb_deployment(Some(&"x".repeat(MAX_DEPLOYMENT_LEN))).is_ok());
    }

    #[test]
    fn a_failed_request_records_the_error_and_a_null_status() {
        let mut a = access(Some("demo"), None);
        a.error = Some("connect refused".into());
        let record = a.into_record(LB_DEPLOYMENT);
        assert_eq!(record.level, "error");
        assert_eq!(record.message, "GET /things - 12.0ms");
        let fields = serde_json::to_value(record.fields).unwrap();
        assert!(fields["status"].is_null(), "no response was written");
        assert_eq!(fields["error"], "connect refused");
    }

    /// A build's transcript has to land in the *deployment's* stream, separable
    /// from its traffic by `source` and from another build by `job`.
    #[test]
    fn a_job_line_is_attributed_to_the_deployment_it_builds() {
        let record = job_line("artifacts", "job-7", "Step 3/9 : RUN cargo build".into());
        let json = serde_json::to_value(&record).unwrap();

        assert_eq!(json["deployment"], "artifacts");
        assert_eq!(json["source"], "job");
        assert_eq!(json["level"], "info");
        assert_eq!(json["message"], "Step 3/9 : RUN cargo build");
        assert_eq!(json["fields"]["job"], "job-7");
        assert!(
            json.get("backend").is_none(),
            "a build runs on the host; there is no VM to name",
        );

        // `docker build` output can contain a single absurd line (a minified
        // bundle, a base64 blob); one must not decide the batch size.
        let long = job_line("artifacts", "job-7", "x".repeat(MAX_MESSAGE * 3));
        assert!(long.message.len() <= MAX_MESSAGE + 3, "got {}", long.message.len());
        assert!(long.message.ends_with('…'));
    }

    #[test]
    fn a_pathological_path_cannot_decide_the_batch_size() {
        let long = "/".to_string() + &"a".repeat(MAX_PATH * 4);
        let mut a = access(Some("demo"), Some(200));
        a.path = &long;
        let record = a.into_record(LB_DEPLOYMENT);
        let fields = serde_json::to_value(record.fields).unwrap();
        let path = fields["path"].as_str().unwrap();
        assert!(path.len() <= MAX_PATH + 3, "got {} bytes", path.len());
        assert!(path.ends_with('…'));
    }

    #[test]
    fn truncation_lands_on_char_boundaries() {
        // Splitting mid-codepoint would panic; a multi-byte tail is exactly what
        // a percent-decoded path or a Debug-formatted struct can end with.
        let s = "é".repeat(600);
        let cut = truncate(s, MAX_PATH);
        assert!(cut.len() <= MAX_PATH + 3);
        assert!(cut.ends_with('…'));
    }

    /// Only app-lb's own events, and never this module's — the shipper logs a
    /// warning when a POST fails, and shipping it would feed the next POST.
    #[test]
    fn event_targets_are_filtered_to_app_lb_itself() {
        assert!(ships_target("app_lb"));
        assert!(ships_target("app_lb::autoscale"));
        assert!(!ships_target(SELF_TARGET));
        assert!(!ships_target("app_lb::obs::inner"));
        assert!(!ships_target("reqwest::connect"));
        assert!(!ships_target("hyper_util::client::legacy"));
        assert!(!ships_target("pingora_core::server"));
    }

    /// Events here are emitted with an explicit `target:` from another app-lb
    /// module, because this module's *own* target is deliberately not shipped —
    /// `app_lb::obs::tests` would be filtered out like any other.
    const AS_IF_FROM: &str = "app_lb::autoscale";

    fn shipped(f: impl FnOnce()) -> Vec<Record> {
        let (sink, mut rx) = sink();
        let subscriber = tracing_subscriber::registry().with(EventLayer::new(sink));
        tracing::subscriber::with_default(subscriber, f);

        let mut records = Vec::new();
        while let Ok(record) = rx.try_recv() {
            records.push(record);
        }
        records
    }

    #[test]
    fn an_event_naming_a_deployment_lands_in_that_deployments_log() {
        let records = shipped(|| {
            tracing::info!(target: AS_IF_FROM, deployment = "demo", replicas = 3, "scaling up");
        });

        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.deployment, "demo");
        assert_eq!(record.source, "app-lb");
        assert_eq!(record.level, "info");
        assert_eq!(record.message, "scaling up");

        let fields = serde_json::to_value(&record.fields).unwrap();
        assert_eq!(fields["replicas"], 3);
        assert_eq!(fields["target"], AS_IF_FROM);
        assert!(
            fields.get("deployment").is_none(),
            "app-obs stores it as the partition key; twice is once too many",
        );
        assert!(fields.get("message").is_none(), "the message is the line");
    }

    #[test]
    fn an_event_naming_no_deployment_lands_under_the_lb_itself() {
        let records = shipped(|| tracing::warn!(target: AS_IF_FROM, port = 80, "cannot bind"));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].deployment, LB_DEPLOYMENT);
        assert_eq!(records[0].level, "warn");
        assert_eq!(records[0].message, "cannot bind");
    }

    #[test]
    fn this_modules_own_events_are_never_shipped() {
        // The shipper warns when a POST fails. Shipping that warning would queue
        // a record, which feeds the next POST, which fails, which warns…
        let records = shipped(|| tracing::warn!("app-obs ingest failed"));
        assert!(records.is_empty());
    }

    #[test]
    fn debug_and_trace_events_are_not_shipped() {
        // The default filter is `app_lb=debug`, and debug is where the
        // per-request routing chatter lives — a second, worse copy of the access
        // log.
        let records = shipped(|| {
            tracing::debug!(target: AS_IF_FROM, "no deployment matches request");
            tracing::trace!(target: AS_IF_FROM, "noise");
            tracing::error!(target: AS_IF_FROM, "kept");
        });
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, "kept");
        assert_eq!(records[0].level, "error");
    }

    /// `%x` reaches the visitor as the `Debug` of a `format_args!`, which is the
    /// displayed text; `?x` is genuine `Debug`. Both have to come out readable,
    /// because app-lb's events are written with `%` almost everywhere.
    #[test]
    fn display_and_debug_fields_both_survive() {
        let path = std::path::Path::new("/var/lib/app-lb");
        let records = shipped(|| {
            tracing::info!(target: AS_IF_FROM, dir = %path.display(), kind = ?Some(7u8), "loaded");
        });
        let fields = serde_json::to_value(&records[0].fields).unwrap();
        assert_eq!(fields["dir"], "/var/lib/app-lb");
        assert_eq!(fields["kind"], "Some(7)");
    }

    #[test]
    fn an_event_with_no_message_still_produces_a_line() {
        let records = shipped(|| tracing::info!(target: AS_IF_FROM, count = 1));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, AS_IF_FROM);
    }
}
