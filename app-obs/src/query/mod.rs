//! Reading stored parquet back out, for the API and the dashboard.
//!
//! # Pruning is the whole point
//!
//! Every query carries `date` (and, for logs, `hour`) predicates alongside its
//! `ts` range. Those are directory names, so DataFusion drops whole partitions
//! before opening a file — the difference between a "last 15 minutes" query
//! reading one directory and reading the entire retention window. A `ts` filter
//! on its own is *correct* and ruinous: it opens every file, then throws almost
//! all of it away.
//!
//! # No SQL text
//!
//! Everything here is built with the DataFrame API rather than assembled into a
//! SQL string. Some of these filters carry values that arrived from a customer
//! application — a `backend` id, a log search term — and the shortest way to be
//! sure none of it is ever parsed as SQL is for there to be no SQL to parse.
//!
//! # Cumulative counters
//!
//! `requests_total`, `errors_total`, `latency_count` and `latency_sum` are
//! cumulative since app-lb's process start and drop back to zero when it
//! restarts. Rates come from differencing consecutive buckets, and a *decrease*
//! means a restart, not negative traffic: it yields `None`, which the dashboard
//! draws as a gap. Clamping it to zero — as app-lb's live view reasonably does
//! for a two-second delta — would draw a convincing idle interval that never
//! happened.

use crate::store::partition::check_deployment;
use crate::store::schema::{LEGACY_NAMESPACE, Table, logs_schema, metrics_schema};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use datafusion::arrow::array::{
    Array, Float64Array, Int64Array, StringArray, TimestampMicrosecondArray,
    TimestampMillisecondArray, TimestampNanosecondArray, TimestampSecondArray, UInt32Array,
    UInt64Array,
};
use datafusion::arrow::datatypes::DataType;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::ScalarValue;
use datafusion::datasource::file_format::parquet::ParquetFormat;
use datafusion::datasource::listing::ListingOptions;
use datafusion::error::DataFusionError;
use datafusion::execution::cache::cache_manager::CacheManagerConfig;
use datafusion::execution::runtime_env::RuntimeEnvBuilder;
use datafusion::functions::expr_fn::{date_bin, lower};
use datafusion::functions_aggregate::expr_fn::{avg, count, last_value, max, sum};
use datafusion::prelude::{Expr, SessionConfig, SessionContext, col, lit, when};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Deployment id app-lb's whole-host samples land under. Not a deployment, so it
/// is reported separately rather than listed among them.
pub use crate::sources::applb::HOST_DEPLOYMENT;

/// Levels that count as an error on the overview.
///
/// The syslog path normalises severities down to `error`/`warning`/`info`/`debug`
/// (`ingest::syslog`), but the HTTP path stores whatever the application sent,
/// and structured loggers disagree freely: `ERROR`, `err`, `fatal`, `crit` all
/// turn up. Matched case-insensitively against the wider set, because a
/// dashboard that only counts the one canonical spelling reports a confident
/// zero errors for every logger that spells it differently.
const ERROR_LEVELS: &[&str] = &[
    "error",
    "err",
    "fatal",
    "critical",
    "crit",
    "emergency",
    "emerg",
    "alert",
    "panic",
];

/// Bucket widths the series may use, in seconds.
///
/// A fixed ladder rather than `window / target`, so a chart's x-axis lands on
/// round numbers and two windows of similar length don't produce subtly
/// different bucketing.
const STEP_LADDER: &[u32] = &[10, 30, 60, 300, 900, 3600, 21600, 86400];

/// Most log rows one request will return.
pub const MAX_LOG_LIMIT: usize = 1000;

#[derive(Debug)]
pub enum QueryError {
    /// Every query slot is taken. The caller should back off, not queue: ingest
    /// shares this runtime and must not wait behind a dashboard.
    Busy,
    /// The query outran its deadline.
    Timeout,
    /// The deployment id is not one that could ever have been stored.
    BadDeployment(String),
    Engine(DataFusionError),
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => write!(f, "too many queries in flight; retry shortly"),
            Self::Timeout => write!(f, "query exceeded its time limit"),
            Self::BadDeployment(d) => write!(f, "{d:?} is not a valid deployment id"),
            Self::Engine(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for QueryError {}

impl From<DataFusionError> for QueryError {
    fn from(e: DataFusionError) -> Self {
        Self::Engine(e)
    }
}

/// A resolved time range, always UTC.
#[derive(Debug, Clone, Copy)]
pub struct Window {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

impl Window {
    /// The last `seconds` up to `now`.
    pub fn trailing(now: DateTime<Utc>, seconds: i64) -> Self {
        Self {
            from: now - ChronoDuration::seconds(seconds.max(1)),
            to: now,
        }
    }

    pub fn seconds(&self) -> i64 {
        (self.to - self.from).num_seconds().max(1)
    }

    pub fn start_ms(self) -> i64 {
        self.from.timestamp_millis()
    }

    pub fn end_ms(self) -> i64 {
        self.to.timestamp_millis()
    }

    /// Bucket width giving roughly `target` points across the window.
    ///
    /// Floored at the ladder's smallest rung, which is app-lb's default poll
    /// interval: bucketing finer than samples arrive manufactures empty buckets,
    /// and an empty bucket reads as missing data rather than as spare
    /// resolution.
    pub fn step_secs(&self, target: u32) -> u32 {
        let ideal = self.seconds() / i64::from(target.max(1));
        *STEP_LADDER
            .iter()
            .find(|&&s| i64::from(s) >= ideal)
            .unwrap_or_else(|| STEP_LADDER.last().expect("ladder is never empty"))
    }

    /// The `date=` partition values this window can touch, inclusive.
    fn date_bounds(&self) -> (String, String) {
        (
            self.from.format("%Y-%m-%d").to_string(),
            self.to.format("%Y-%m-%d").to_string(),
        )
    }

    /// The `hour=` partition values this window can touch, or `None` when it is
    /// long enough to cover all of them.
    ///
    /// Deliberately an over-approximation. A window crossing midnight yields
    /// hours from both sides of it, which combined with the date range admits at
    /// most a couple of directories the window does not need — while never
    /// excluding one it does. The `ts` filter does the exact work.
    fn hour_bounds(&self) -> Option<Vec<String>> {
        if self.seconds() >= 86_400 {
            return None;
        }
        const HOUR_MS: i64 = 3_600_000;
        let mut hours = Vec::new();
        // Truncated to the hour first, so a window opening at 17:59 still asks
        // for hour 17 — where most of its rows are.
        let mut at = self.start_ms().div_euclid(HOUR_MS) * HOUR_MS;
        while at <= self.end_ms() {
            let label = format!("{:02}", at.div_euclid(HOUR_MS).rem_euclid(24));
            if !hours.contains(&label) {
                hours.push(label);
            }
            at += HOUR_MS;
        }
        Some(hours)
    }
}

/// One time bucket of a deployment's metrics.
///
/// Every measure is optional for the same reason it is in storage: a null means
/// "not reported", which is different from zero and has to stay different all
/// the way to the chart.
#[derive(Debug, Default, Clone, Serialize)]
pub struct MetricBucket {
    /// Bucket start, epoch milliseconds UTC.
    pub t: i64,
    pub requests_per_sec: Option<f64>,
    pub errors_per_sec: Option<f64>,
    /// Mean latency over this bucket alone, from Δsum/Δcount.
    pub mean_latency_ms: Option<f64>,
    /// Cumulative since app-lb started, *not* windowed. Shown as a figure, never
    /// on a time axis.
    pub p50_ms: Option<f64>,
    pub p90_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<f64>,
    pub in_flight: Option<f64>,
    pub ready: Option<f64>,
    pub pending: Option<f64>,
    pub draining: Option<f64>,
}

/// One time bucket of a deployment's log volume.
#[derive(Debug, Default, Clone, Serialize)]
pub struct LogBucket {
    pub t: i64,
    pub lines: u64,
    pub errors: u64,
}

/// A single stored log line.
#[derive(Debug, Clone, Serialize)]
pub struct LogRow {
    /// Epoch milliseconds UTC.
    pub ts: i64,
    pub level: Option<String>,
    pub source: String,
    pub message: String,
    pub backend: Option<String>,
    pub host: Option<String>,
    /// The structured payload, still a JSON string — parsed by whoever displays
    /// it, so an application emitting something unusual can't fail the query.
    pub fields: Option<String>,
}

/// Which log lines to return.
#[derive(Debug, Clone)]
pub struct LogFilter {
    pub deployment: String,
    /// Only rows attributed to this namespace. `None` is the operator's view:
    /// every row, whoever owns it.
    pub namespace: Option<String>,
    pub level: Option<String>,
    pub backend: Option<String>,
    /// Case-insensitive substring of the message.
    pub search: Option<String>,
    pub limit: usize,
    /// Page boundary: only lines at or before this instant, epoch millis.
    ///
    /// Inclusive on purpose. Log timestamps collide freely — a burst inside one
    /// millisecond is ordinary — and an exclusive boundary would silently drop
    /// every line sharing the last page's final millisecond. The caller
    /// de-duplicates instead.
    pub before_ms: Option<i64>,
}

pub struct Engine {
    ctx: SessionContext,
    data_dir: PathBuf,
    /// Bounds queries in flight. app-obs must never become a dependency of the
    /// data plane, and a month-wide query is CPU-bound parquet work on the same
    /// runtime that is accepting ingest.
    permits: Arc<Semaphore>,
    /// Every slot in `permits`, so `quiesce` knows what "all of them" means.
    permit_count: u32,
    timeout: Duration,
}

impl Engine {
    pub async fn new(
        data_dir: impl Into<PathBuf>,
        concurrency: usize,
        timeout: Duration,
    ) -> Result<Self, QueryError> {
        let data_dir = data_dir.into();

        let config = SessionConfig::new()
            // Leave cores for ingest. The default is one partition per core,
            // which lets a single dashboard refresh occupy the whole machine.
            .with_target_partitions(concurrency.clamp(1, 4))
            // Keep string columns as the `Utf8` the schema declares. Left on,
            // parquet reads come back as `StringView` arrays, and every accessor
            // below would have to know which one it got.
            .set_bool(
                "datafusion.execution.parquet.schema_force_view_types",
                false,
            );

        // No listing cache. DataFusion enables one by default — 1MiB, and with
        // an *infinite* TTL — which means a table registered at startup keeps
        // answering from the directory listing it took on its first query and
        // never sees another partition. For a collector whose whole job is to
        // show what just arrived, that is the one cache that cannot be allowed:
        // it makes the dashboard silently freeze in the past while ingest keeps
        // working. Listing a local directory is a syscall; correctness is worth
        // more.
        let runtime = RuntimeEnvBuilder::new()
            .with_cache_manager(CacheManagerConfig::default().with_list_files_cache_limit(0))
            .build_arc()?;
        let ctx = SessionContext::new_with_config_rt(config, runtime);

        for table in [Table::Logs, Table::Metrics] {
            // The directory has to exist before it can be registered as one: on
            // a fresh install nothing has been written yet, and a path that
            // isn't there is taken for a filename prefix rather than a table
            // root.
            let dir = data_dir.join(table.name());
            std::fs::create_dir_all(&dir).map_err(|e| {
                DataFusionError::Execution(format!("cannot create {}: {e}", dir.display()))
            })?;

            let mut partition_cols = vec![
                ("deployment".to_string(), DataType::Utf8),
                ("date".to_string(), DataType::Utf8),
            ];
            if table.hourly() {
                partition_cols.push(("hour".to_string(), DataType::Utf8));
            }

            let options = ListingOptions::new(Arc::new(ParquetFormat::default()))
                // Excludes the writer's in-progress `.<stem>.parquet.tmp` files,
                // the same guarantee `store::writer::parquet_files` gives every
                // other reader. A half-written footer is not a recoverable
                // parse error.
                .with_file_extension(".parquet")
                .with_table_partition_cols(partition_cols);

            let schema = match table {
                Table::Logs => logs_schema(),
                Table::Metrics => metrics_schema(),
            };

            // The schema is supplied rather than inferred: inference opens a
            // file, and at first boot there is no file to open, so an inferring
            // registration fails before anything has ever been written.
            //
            // Registering once is enough, given the listing cache is off above:
            // `ListingTable` re-lists its directories on every scan, so parquet
            // flushed a minute ago shows up without re-registration.
            let url = format!("{}/", dir.display());
            ctx.register_listing_table(table.name(), &url, options, Some(schema), None)
                .await?;
        }

        let permit_count = u32::try_from(concurrency.max(1)).unwrap_or(u32::MAX);
        Ok(Self {
            data_dir,
            ctx,
            permits: Arc::new(Semaphore::new(permit_count as usize)),
            permit_count,
            timeout,
        })
    }

    /// Hold every query slot until the returned permit drops.
    ///
    /// For the compactor, which swaps a partition's files and must not do so
    /// under a scan that has already listed the directory: with all slots held,
    /// no query is in flight, and one arriving meanwhile gets the same `Busy` a
    /// full pool produces. Waits for in-flight queries to finish rather than
    /// interrupting them, so hold this only across cheap work — renames, not
    /// reads.
    pub async fn quiesce(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.permits
            .clone()
            .acquire_many_owned(self.permit_count)
            .await
            .expect("the query semaphore is never closed")
    }

    /// Every deployment with data on disk, `_host` excluded, sorted.
    ///
    /// Directory names, not `SELECT DISTINCT`: reading them costs nothing, and
    /// it lists a deployment that has been quiet for the whole window instead of
    /// having it vanish from the overview exactly when someone wants to know why
    /// it went silent.
    pub fn deployments(&self) -> Vec<String> {
        let mut found = BTreeMap::new();
        for table in [Table::Logs, Table::Metrics] {
            for name in deployment_dirs(&self.data_dir.join(table.name())) {
                found.insert(name, ());
            }
        }
        found.into_keys().filter(|d| d != HOST_DEPLOYMENT).collect()
    }

    /// Whether any `_host` samples exist at all, so the overview can tell "the
    /// daemon reports no host usage" from "nothing has been collected yet".
    pub fn has_host_data(&self) -> bool {
        deployment_dirs(&self.data_dir.join(Table::Metrics.name()))
            .iter()
            .any(|d| d == HOST_DEPLOYMENT)
    }

    /// Bucketed metrics per deployment, already rate-differenced.
    ///
    /// `deployment` of `None` covers every one of them in a single scan, which
    /// is what the overview wants — one query for the whole fleet rather than
    /// one per row.
    pub async fn metrics(
        &self,
        window: Window,
        step_secs: u32,
        deployment: Option<&str>,
        namespace: Option<&str>,
    ) -> Result<BTreeMap<String, Vec<MetricBucket>>, QueryError> {
        if let Some(id) = deployment {
            check_deployment(id).map_err(|_| QueryError::BadDeployment(id.to_string()))?;
        }
        let _permit = self.permit()?;

        let batches = self
            .deadline(async {
                let mut df = self.ctx.table(Table::Metrics.name()).await?;
                df = df.filter(scan_filter(window, deployment, false))?;
                if let Some(ns) = namespace {
                    df = df.filter(namespace_filter(ns))?;
                }
                // Deployment-wide rows only. Per-VM rows leave the pool gauges
                // and traffic counters null on purpose, so mixing them in would
                // average real values against nothing.
                df = df.filter(col("backend").is_null())?;

                let ordered = vec![col("ts").sort(true, true)];
                df.aggregate(
                    vec![col("deployment"), bucket_expr(step_secs)],
                    vec![
                        // Counters: the value as the bucket ended. `max` would
                        // hide a restart inside the bucket by keeping the
                        // pre-restart peak.
                        last_value(col("requests_total"), ordered.clone()).alias("requests_total"),
                        last_value(col("errors_total"), ordered.clone()).alias("errors_total"),
                        last_value(col("latency_count"), ordered.clone()).alias("latency_count"),
                        last_value(col("latency_sum"), ordered.clone()).alias("latency_sum"),
                        // When that last sample was actually taken. A bucket is
                        // a container, not a measurement interval: the newest
                        // one is always partial, and dividing its delta by the
                        // full step width understates every live rate on the
                        // page. The real denominator is the time between the two
                        // samples being differenced.
                        last_value(col("ts"), ordered.clone()).alias("sample_ts"),
                        last_value(col("p50_ms"), ordered.clone()).alias("p50_ms"),
                        last_value(col("p90_ms"), ordered.clone()).alias("p90_ms"),
                        last_value(col("p99_ms"), ordered.clone()).alias("p99_ms"),
                        // Gauges: an average over the bucket is the honest
                        // summary, and `avg` already ignores nulls rather than
                        // counting them as zero.
                        avg(col("cpu_percent")).alias("cpu_percent"),
                        avg(col("memory_bytes")).alias("memory_bytes"),
                        avg(col("in_flight")).alias("in_flight"),
                        avg(col("ready")).alias("ready"),
                        avg(col("pending")).alias("pending"),
                        avg(col("draining")).alias("draining"),
                    ],
                )?
                .sort(vec![
                    col("deployment").sort(true, true),
                    col("bucket").sort(true, true),
                ])?
                .collect()
                .await
            })
            .await?;

        Ok(difference(&batches, step_secs))
    }

    /// Bucketed log volume per deployment.
    pub async fn log_volume(
        &self,
        window: Window,
        step_secs: u32,
        deployment: Option<&str>,
        namespace: Option<&str>,
    ) -> Result<BTreeMap<String, Vec<LogBucket>>, QueryError> {
        if let Some(id) = deployment {
            check_deployment(id).map_err(|_| QueryError::BadDeployment(id.to_string()))?;
        }
        let _permit = self.permit()?;

        let batches = self
            .deadline(async {
                let mut df = self
                    .ctx
                    .table(Table::Logs.name())
                    .await?
                    .filter(scan_filter(window, deployment, true))?;
                if let Some(ns) = namespace {
                    df = df.filter(namespace_filter(ns))?;
                }
                df.aggregate(
                    vec![col("deployment"), bucket_expr(step_secs)],
                    vec![
                        count(lit(1i64)).alias("lines"),
                        sum(when(is_error_level(), lit(1i64)).otherwise(lit(0i64))?)
                            .alias("errors"),
                    ],
                )?
                .sort(vec![
                    col("deployment").sort(true, true),
                    col("bucket").sort(true, true),
                ])?
                .collect()
                .await
            })
            .await?;

        let mut out: BTreeMap<String, Vec<LogBucket>> = BTreeMap::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                let Some(id) = string_at(batch, "deployment", row) else {
                    continue;
                };
                let Some(t) = millis_at(batch, "bucket", row) else {
                    continue;
                };
                out.entry(id.to_string()).or_default().push(LogBucket {
                    t,
                    lines: number_at(batch, "lines", row).unwrap_or(0.0).max(0.0) as u64,
                    errors: number_at(batch, "errors", row).unwrap_or(0.0).max(0.0) as u64,
                });
            }
        }
        Ok(out)
    }

    /// The most recent log lines matching a filter, newest first.
    pub async fn logs(
        &self,
        window: Window,
        filter: &LogFilter,
    ) -> Result<Vec<LogRow>, QueryError> {
        check_deployment(&filter.deployment)
            .map_err(|_| QueryError::BadDeployment(filter.deployment.clone()))?;
        let limit = filter.limit.clamp(1, MAX_LOG_LIMIT);
        let _permit = self.permit()?;

        // A page boundary can only narrow the window, never widen it past what
        // the caller asked for.
        let window = match filter.before_ms {
            Some(before) if before < window.end_ms() => Window {
                from: window.from,
                to: Utc
                    .timestamp_millis_opt(before)
                    .single()
                    .unwrap_or(window.to),
            },
            _ => window,
        };

        let batches = self
            .deadline(async {
                let mut df = self
                    .ctx
                    .table(Table::Logs.name())
                    .await?
                    .filter(scan_filter(window, Some(&filter.deployment), true))?;
                if let Some(ns) = &filter.namespace {
                    df = df.filter(namespace_filter(ns))?;
                }

                // Everything below is caller-supplied text. It goes in as an
                // `Expr` literal, so it is compared as a value and never parsed.
                if let Some(level) = &filter.level {
                    df = df.filter(lower(col("level")).eq(lit(level.to_lowercase())))?;
                }
                if let Some(backend) = &filter.backend {
                    df = df.filter(col("backend").eq(lit(backend.clone())))?;
                }
                if let Some(search) = &filter.search {
                    // `strpos` on lowered operands rather than `LIKE '%q%'`: no
                    // `%` or `_` in the search term needs escaping, so a message
                    // containing one is searchable as itself.
                    df = df.filter(
                        datafusion::functions::expr_fn::strpos(
                            lower(col("message")),
                            lit(search.to_lowercase()),
                        )
                        .gt(lit(0i64)),
                    )?;
                }

                df.sort(vec![col("ts").sort(false, true)])?
                    .limit(0, Some(limit))?
                    .collect()
                    .await
            })
            .await?;

        let mut rows = Vec::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                let Some(ts) = millis_at(batch, "ts", row) else {
                    continue;
                };
                rows.push(LogRow {
                    ts,
                    level: string_at(batch, "level", row).map(str::to_string),
                    source: string_at(batch, "source", row)
                        .unwrap_or("stdout")
                        .to_string(),
                    message: string_at(batch, "message", row).unwrap_or("").to_string(),
                    backend: string_at(batch, "backend", row).map(str::to_string),
                    host: string_at(batch, "host", row).map(str::to_string),
                    fields: string_at(batch, "fields", row).map(str::to_string),
                });
            }
        }
        Ok(rows)
    }

    /// Distinct backends that logged for a deployment in the window, for the
    /// log filter's dropdown.
    pub async fn backends(
        &self,
        window: Window,
        deployment: &str,
        namespace: Option<&str>,
    ) -> Result<Vec<String>, QueryError> {
        check_deployment(deployment)
            .map_err(|_| QueryError::BadDeployment(deployment.to_string()))?;
        let _permit = self.permit()?;

        let batches = self
            .deadline(async {
                let mut df = self
                    .ctx
                    .table(Table::Logs.name())
                    .await?
                    .filter(scan_filter(window, Some(deployment), true))?;
                if let Some(ns) = namespace {
                    df = df.filter(namespace_filter(ns))?;
                }
                df.filter(col("backend").is_not_null())?
                    .aggregate(vec![col("backend")], vec![max(col("ts")).alias("last_ts")])?
                    .sort(vec![col("backend").sort(true, true)])?
                    .collect()
                    .await
            })
            .await?;

        let mut out = Vec::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                if let Some(b) = string_at(batch, "backend", row) {
                    out.push(b.to_string());
                }
            }
        }
        Ok(out)
    }

    /// Take a query slot, or refuse.
    fn permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, QueryError> {
        self.permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| QueryError::Busy)
    }

    /// Impose the per-query deadline.
    async fn deadline<T>(
        &self,
        work: impl std::future::Future<Output = Result<T, DataFusionError>>,
    ) -> Result<T, QueryError> {
        match tokio::time::timeout(self.timeout, work).await {
            Ok(result) => Ok(result?),
            Err(_) => Err(QueryError::Timeout),
        }
    }
}

/// `date_bin` onto `step_secs`, anchored at the epoch.
///
/// Anchoring at a fixed origin rather than the window start means the same
/// instant always lands in the same bucket, so two overlapping requests agree
/// about where a spike was.
fn bucket_expr(step_secs: u32) -> Expr {
    let stride = ScalarValue::new_interval_dt(0, (i64::from(step_secs) * 1000) as i32);
    date_bin(lit(stride), col("ts"), lit(utc_millis(0))).alias("bucket")
}

/// A timestamp literal typed exactly like the `ts` column, so a comparison
/// needs no coercion and cannot be reinterpreted in another zone.
fn utc_millis(ms: i64) -> ScalarValue {
    ScalarValue::TimestampMillisecond(Some(ms), Some("UTC".into()))
}

/// The `ts` range plus the partition predicates that make it cheap.
///
/// The partition parts are what stop this reading the whole retention window;
/// the `ts` part is what makes the answer exact.
fn scan_filter(window: Window, deployment: Option<&str>, hourly: bool) -> Expr {
    let (from_date, to_date) = window.date_bounds();

    let mut filter = col("ts")
        .gt_eq(lit(utc_millis(window.start_ms())))
        .and(col("ts").lt_eq(lit(utc_millis(window.end_ms()))))
        // Lexical comparison on `YYYY-MM-DD` is chronological because the
        // fields are zero-padded and fixed-width — the same property that makes
        // the directories sort.
        .and(col("date").gt_eq(lit(from_date)))
        .and(col("date").lt_eq(lit(to_date)));

    if let Some(id) = deployment {
        filter = filter.and(col("deployment").eq(lit(id.to_string())));
    }
    if let Some(hours) = window.hour_bounds().filter(|_| hourly) {
        filter =
            filter.and(col("hour").in_list(hours.into_iter().map(lit).collect::<Vec<_>>(), false));
    }
    filter
}

/// Rows attributed to `ns`.
///
/// A null `namespace` is a row written before the column existed, and every
/// deployment then lived in [`LEGACY_NAMESPACE`] — so it belongs there and
/// nowhere else. The value is a literal, compared and never parsed, like every
/// other caller-supplied filter here.
fn namespace_filter(ns: &str) -> Expr {
    let exact = col("namespace").eq(lit(ns.to_string()));
    if ns == LEGACY_NAMESPACE {
        exact.or(col("namespace").is_null())
    } else {
        exact
    }
}

/// True when `level` names an error, however the sender spells it.
fn is_error_level() -> Expr {
    lower(col("level")).in_list(
        ERROR_LEVELS.iter().map(|l| lit(*l)).collect::<Vec<_>>(),
        false,
    )
}

/// Per-second rate between two cumulative samples.
///
/// `None` when the counter went backwards. app-lb's counters reset to zero on
/// restart, and a clamped zero would draw an idle interval that never happened —
/// the gap is the more informative answer, because it is the truth.
fn rate(prev: Option<f64>, curr: Option<f64>, seconds: f64) -> Option<f64> {
    let (prev, curr) = (prev?, curr?);
    if curr < prev || seconds <= 0.0 {
        return None;
    }
    Some((curr - prev) / seconds)
}

/// Mean latency across one interval, from cumulative (sum, count) pairs.
///
/// `None` when no request was measured in the interval: there is no mean of
/// nothing, and reporting 0ms would read as "very fast".
fn interval_mean(
    prev_sum: Option<f64>,
    curr_sum: Option<f64>,
    prev_count: Option<f64>,
    curr_count: Option<f64>,
) -> Option<f64> {
    let (prev_sum, curr_sum) = (prev_sum?, curr_sum?);
    let (prev_count, curr_count) = (prev_count?, curr_count?);
    let (delta_sum, delta_count) = (curr_sum - prev_sum, curr_count - prev_count);
    if delta_count <= 0.0 || delta_sum < 0.0 {
        return None;
    }
    Some(delta_sum / delta_count)
}

/// Turn the bucketed cumulative rows into per-bucket rates.
///
/// The first bucket of each deployment has nothing to difference against, so its
/// rates stay `None`. Callers ask for one extra bucket of lead-in when they care
/// about the left edge of a chart.
fn difference(batches: &[RecordBatch], step_secs: u32) -> BTreeMap<String, Vec<MetricBucket>> {
    let nominal = f64::from(step_secs.max(1));
    let mut out: BTreeMap<String, Vec<MetricBucket>> = BTreeMap::new();
    // Previous bucket per deployment. The rows arrive sorted by (deployment,
    // bucket), but keying it explicitly means a change to that ordering can't
    // silently start differencing one deployment against another.
    let mut previous: BTreeMap<String, Sample> = BTreeMap::new();

    for batch in batches {
        for row in 0..batch.num_rows() {
            let Some(id) = string_at(batch, "deployment", row) else {
                continue;
            };
            let Some(t) = millis_at(batch, "bucket", row) else {
                continue;
            };

            let current = Sample {
                sample_ts: millis_at(batch, "sample_ts", row),
                requests: number_at(batch, "requests_total", row),
                errors: number_at(batch, "errors_total", row),
                latency_count: number_at(batch, "latency_count", row),
                latency_sum: number_at(batch, "latency_sum", row),
            };
            let prior = previous.get(id).copied();
            let prev = prior.unwrap_or_default();
            // Between the two samples, not the nominal bucket width — see
            // `sample_ts`. Falls back to the width when either timestamp is
            // missing, which can only happen if a bucket somehow held no row.
            let seconds = match (prev.sample_ts, current.sample_ts) {
                (Some(a), Some(b)) if b > a => (b - a) as f64 / 1000.0,
                _ => nominal,
            };

            out.entry(id.to_string()).or_default().push(MetricBucket {
                t,
                requests_per_sec: prior
                    .and_then(|_| rate(prev.requests, current.requests, seconds)),
                errors_per_sec: prior.and_then(|_| rate(prev.errors, current.errors, seconds)),
                mean_latency_ms: prior.and_then(|_| {
                    interval_mean(
                        prev.latency_sum,
                        current.latency_sum,
                        prev.latency_count,
                        current.latency_count,
                    )
                }),
                p50_ms: number_at(batch, "p50_ms", row),
                p90_ms: number_at(batch, "p90_ms", row),
                p99_ms: number_at(batch, "p99_ms", row),
                cpu_percent: number_at(batch, "cpu_percent", row),
                memory_bytes: number_at(batch, "memory_bytes", row),
                in_flight: number_at(batch, "in_flight", row),
                ready: number_at(batch, "ready", row),
                pending: number_at(batch, "pending", row),
                draining: number_at(batch, "draining", row),
            });

            previous.insert(id.to_string(), current);
        }
    }
    out
}

/// The cumulative values a bucket ended on, and when that reading was taken.
#[derive(Debug, Default, Clone, Copy)]
struct Sample {
    sample_ts: Option<i64>,
    requests: Option<f64>,
    errors: Option<f64>,
    latency_count: Option<f64>,
    latency_sum: Option<f64>,
}

/// `deployment=` directory names under a table root.
fn deployment_dirs(table_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(table_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_prefix("deployment="))
                .map(str::to_string)
        })
        // Anything that isn't a partition directory is left out rather than
        // guessed at, the same way the retention sweeper treats it.
        .filter(|d| check_deployment(d).is_ok())
        .collect()
}

/// A numeric cell as `f64`, whatever width or signedness DataFusion chose.
///
/// Aggregates disagree: `avg` yields `Float64`, `sum` and `count` yield `Int64`,
/// `last_value` preserves the column's own `UInt64`. Handling them in one place
/// keeps the call sites from having to track which is which.
fn number_at(batch: &RecordBatch, name: &str, row: usize) -> Option<f64> {
    let column = batch.column_by_name(name)?;
    if column.is_null(row) {
        return None;
    }
    macro_rules! read {
        ($($array:ty),+) => {{
            $(if let Some(a) = column.as_any().downcast_ref::<$array>() {
                return Some(a.value(row) as f64);
            })+
        }};
    }
    read!(Float64Array, Int64Array, UInt64Array, UInt32Array);
    None
}

/// A timestamp cell as epoch milliseconds, whatever unit it carries.
fn millis_at(batch: &RecordBatch, name: &str, row: usize) -> Option<i64> {
    let column = batch.column_by_name(name)?;
    if column.is_null(row) {
        return None;
    }
    let any = column.as_any();
    if let Some(a) = any.downcast_ref::<TimestampMillisecondArray>() {
        return Some(a.value(row));
    }
    if let Some(a) = any.downcast_ref::<TimestampNanosecondArray>() {
        return Some(a.value(row) / 1_000_000);
    }
    if let Some(a) = any.downcast_ref::<TimestampMicrosecondArray>() {
        return Some(a.value(row) / 1_000);
    }
    if let Some(a) = any.downcast_ref::<TimestampSecondArray>() {
        return Some(a.value(row).saturating_mul(1_000));
    }
    None
}

fn string_at<'a>(batch: &'a RecordBatch, name: &str, row: usize) -> Option<&'a str> {
    let column = batch.column_by_name(name)?;
    if column.is_null(row) {
        return None;
    }
    column
        .as_any()
        .downcast_ref::<StringArray>()
        .map(|a| a.value(row))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::schema::{LogRecord, MetricRecord, Record};
    use crate::store::writer::Writer;

    /// 2026-07-28T17:34:56Z
    const TS: i64 = 1_785_260_096_000;

    fn at(ms: i64) -> DateTime<Utc> {
        Utc.timestamp_millis_opt(ms).single().unwrap()
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "app-obs-query-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_reset_counter_reads_as_a_gap_not_as_zero() {
        // app-lb restarting takes its counters back to zero. Reporting 0/s for
        // that interval would draw a convincing idle patch; the truth is that
        // the interval cannot be measured.
        assert_eq!(rate(Some(100.0), Some(160.0), 10.0), Some(6.0));
        assert_eq!(rate(Some(100.0), Some(3.0), 10.0), None, "restart");
        assert_eq!(rate(None, Some(160.0), 10.0), None, "no prior sample");
        assert_eq!(rate(Some(100.0), None, 10.0), None, "sample not reported");
        assert_eq!(
            rate(Some(100.0), Some(100.0), 10.0),
            Some(0.0),
            "genuinely idle"
        );
    }

    #[test]
    fn interval_latency_comes_from_the_deltas_not_the_totals() {
        // 40ms over 4 requests in this interval, whatever the lifetime mean is.
        assert_eq!(
            interval_mean(Some(1000.0), Some(1160.0), Some(100.0), Some(104.0)),
            Some(40.0),
        );
        // Nothing timed in the interval: there is no mean, and 0ms would read as
        // "very fast" rather than "no requests".
        assert_eq!(
            interval_mean(Some(1000.0), Some(1000.0), Some(100.0), Some(100.0)),
            None,
        );
        // A restart shows up here too.
        assert_eq!(
            interval_mean(Some(1000.0), Some(20.0), Some(100.0), Some(2.0)),
            None,
        );
    }

    #[test]
    fn a_short_window_prunes_to_hours_and_a_long_one_does_not() {
        // 15 minutes inside one hour: one date, one hour directory.
        let short = Window {
            from: at(TS),
            to: at(TS + 900_000),
        };
        assert_eq!(
            short.date_bounds(),
            ("2026-07-28".into(), "2026-07-28".into())
        );
        assert_eq!(short.hour_bounds(), Some(vec!["17".into()]));

        // Two hours spanning a boundary must admit both.
        let spanning = Window {
            from: at(TS),
            to: at(TS + 3_600_000),
        };
        assert_eq!(spanning.hour_bounds(), Some(vec!["17".into(), "18".into()]));

        // A day or more: every hour qualifies, so the list buys nothing and is
        // dropped rather than enumerated.
        let long = Window::trailing(at(TS), 86_400);
        assert_eq!(long.hour_bounds(), None);
    }

    #[test]
    fn a_window_crossing_midnight_admits_both_dates() {
        // 23:30 to 00:30. Two date directories, and hours from either side of
        // midnight — an over-approximation that never excludes a needed one.
        let from = at(1_785_281_400_000); // 2026-07-28T23:30:00Z
        let window = Window {
            from,
            to: from + ChronoDuration::hours(1),
        };
        assert_eq!(
            window.date_bounds(),
            ("2026-07-28".into(), "2026-07-29".into()),
        );
        let hours = window.hour_bounds().unwrap();
        assert!(hours.contains(&"23".to_string()));
        assert!(hours.contains(&"00".to_string()));
    }

    #[test]
    fn bucket_width_climbs_the_ladder_and_never_goes_below_the_poll_rate() {
        // An hour at ~120 points wants 30s; the ladder has that rung.
        assert_eq!(Window::trailing(at(TS), 3_600).step_secs(120), 30);
        // Asking for more points than there are samples floors at 10s rather
        // than manufacturing empty buckets.
        assert_eq!(Window::trailing(at(TS), 60).step_secs(600), 10);
        // A month coarsens instead of returning a quarter-million points.
        assert!(Window::trailing(at(TS), 30 * 86_400).step_secs(120) >= 21_600);
    }

    #[test]
    fn deployment_directories_are_read_without_a_scan() {
        let dir = tmpdir("dirs");
        for name in [
            "deployment=demo",
            "deployment=_host",
            "deployment=..",
            "notes",
        ] {
            std::fs::create_dir_all(dir.join("logs").join(name)).unwrap();
        }
        std::fs::write(dir.join("logs/deployment=file"), b"x").unwrap();

        let mut found = deployment_dirs(&dir.join("logs"));
        found.sort();
        assert_eq!(found, vec!["_host".to_string(), "demo".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn log(deployment: &str, ts: i64, level: &str, message: &str) -> Record {
        Record::Log(LogRecord {
            ts_millis: ts,
            deployment: deployment.into(),
            backend: Some("sb-abc".into()),
            source: "stdout".into(),
            level: Some(level.into()),
            message: message.into(),
            fields: None,
            host: None,
            namespace: None,
        })
    }

    /// Seed a data dir through the real writer, so the test exercises the same
    /// schema and partition layout the collector produces.
    fn seeded(tag: &str) -> PathBuf {
        let dir = tmpdir(tag);
        let mut writer = Writer::new(&dir, 10_000, Duration::from_secs(3600));
        writer.push(log("demo", TS, "info", "started")).unwrap();
        writer
            .push(log("demo", TS + 1000, "ERROR", "boom"))
            .unwrap();
        writer
            .push(log("demo", TS + 2000, "warning", "retrying %50"))
            .unwrap();
        writer.push(log("other", TS, "info", "elsewhere")).unwrap();

        for (i, requests) in [(0i64, 100u64), (1, 220), (2, 5)].iter().enumerate() {
            writer
                .push(Record::Metric(MetricRecord {
                    ts_millis: TS + requests.0 * 60_000,
                    deployment: "demo".into(),
                    requests_total: Some(requests.1),
                    errors_total: Some(requests.1 / 10),
                    latency_count: Some(requests.1),
                    latency_sum: Some(requests.1 * 8),
                    ready: Some(2),
                    p50_ms: Some(8.0),
                    ..Default::default()
                }))
                .unwrap();
            let _ = i;
        }
        writer.flush_all().unwrap();
        dir
    }

    async fn engine(dir: &Path) -> Engine {
        Engine::new(dir, 2, Duration::from_secs(30)).await.unwrap()
    }

    fn stamped(deployment: &str, namespace: Option<&str>, message: &str) -> Record {
        let Record::Log(mut r) = log(deployment, TS, "info", message) else {
            unreachable!()
        };
        r.namespace = namespace.map(str::to_string);
        Record::Log(r)
    }

    /// A logs file as app-obs wrote them before the `namespace` column: the
    /// current schema minus that column, placed where the writer would have.
    fn write_legacy_log(dir: &Path, deployment: &str, message: &str) {
        use datafusion::arrow::array::TimestampMillisecondArray;
        use datafusion::arrow::datatypes::Schema;
        use datafusion::parquet::arrow::ArrowWriter;

        let schema = Arc::new(Schema::new(
            logs_schema()
                .fields()
                .iter()
                .filter(|f| f.name() != "namespace")
                .cloned()
                .collect::<Vec<_>>(),
        ));
        let utf8 = |v: Option<&str>| Arc::new(StringArray::from(vec![v])) as _;
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(TimestampMillisecondArray::from(vec![TS]).with_timezone("UTC")) as _,
                utf8(Some("sb-old")),
                utf8(Some("stdout")),
                utf8(Some("info")),
                utf8(Some(message)),
                utf8(None),
                utf8(None),
            ],
        )
        .unwrap();
        let partition = crate::store::partition::PartitionKey::new(Table::Logs, deployment, TS)
            .unwrap()
            .dir(dir);
        std::fs::create_dir_all(&partition).unwrap();
        let file = std::fs::File::create(partition.join("0000000000001-000000.parquet")).unwrap();
        let mut w = ArrowWriter::try_new(file, schema, None).unwrap();
        w.write(&batch).unwrap();
        w.close().unwrap();
    }

    fn log_filter(deployment: &str, namespace: Option<&str>) -> LogFilter {
        LogFilter {
            deployment: deployment.into(),
            namespace: namespace.map(str::to_string),
            level: None,
            backend: None,
            search: None,
            limit: 100,
            before_ms: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_namespace_sees_only_rows_written_under_it() {
        let dir = tmpdir("ns-filter");
        let mut writer = Writer::new(&dir, 10_000, Duration::from_secs(3600));
        writer.push(stamped("web", Some("team-a"), "a's")).unwrap();
        writer.push(stamped("api", Some("team-b"), "b's")).unwrap();
        writer.push(stamped("_lb", Some("_"), "platform")).unwrap();
        // The same id under two namespaces over time: re-registered elsewhere.
        writer
            .push(stamped("moved", Some("team-a"), "before"))
            .unwrap();
        writer
            .push(stamped("moved", Some("team-b"), "after"))
            .unwrap();
        writer.flush_all().unwrap();
        let engine = engine(&dir).await;
        let window = Window::trailing(at(TS + 60_000), 3_600);

        let volume = engine
            .log_volume(window, 60, None, Some("team-a"))
            .await
            .unwrap();
        assert_eq!(
            volume.keys().collect::<Vec<_>>(),
            vec!["moved", "web"],
            "team-b's and the platform's rows stay out"
        );

        let rows = engine
            .logs(window, &log_filter("moved", Some("team-a")))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message, "before", "history follows its namespace");

        let rows = engine
            .logs(window, &log_filter("web", Some("team-b")))
            .await
            .unwrap();
        assert!(rows.is_empty());

        // The operator sees everything.
        let all = engine.log_volume(window, 60, None, None).await.unwrap();
        assert_eq!(all.len(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn parquet_from_before_namespaces_reads_as_default() {
        let dir = tmpdir("ns-legacy");
        write_legacy_log(&dir, "old", "from before namespaces");
        let mut writer = Writer::new(&dir, 10_000, Duration::from_secs(3600));
        writer
            .push(stamped("old", Some("default"), "after"))
            .unwrap();
        writer.flush_all().unwrap();
        let engine = engine(&dir).await;
        let window = Window::trailing(at(TS + 60_000), 3_600);

        let rows = engine
            .logs(window, &log_filter("old", Some("default")))
            .await
            .unwrap();
        let mut messages: Vec<_> = rows.iter().map(|r| r.message.as_str()).collect();
        messages.sort();
        assert_eq!(messages, vec!["after", "from before namespaces"]);

        assert!(
            engine
                .logs(window, &log_filter("old", Some("team-a")))
                .await
                .unwrap()
                .is_empty(),
            "a legacy row is default's, nobody else's"
        );
        assert_eq!(
            engine
                .logs(window, &log_filter("old", None))
                .await
                .unwrap()
                .len(),
            2,
            "and the operator's view reads both shapes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn written_rows_are_queryable_back_out() {
        // The one test that proves the schema, the partition layout and the
        // pruning predicates all agree: written by the real writer, read by the
        // real engine.
        let dir = seeded("roundtrip");
        let engine = engine(&dir).await;

        assert_eq!(
            engine.deployments(),
            vec!["demo".to_string(), "other".to_string()]
        );

        let window = Window {
            from: at(TS - 60_000),
            to: at(TS + 600_000),
        };
        let rows = engine
            .logs(
                window,
                &LogFilter {
                    deployment: "demo".into(),
                    namespace: None,
                    level: None,
                    backend: None,
                    search: None,
                    limit: 100,
                    before_ms: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(rows.len(), 3, "only demo's lines");
        assert_eq!(rows[0].message, "retrying %50", "newest first");
        assert_eq!(rows[0].backend.as_deref(), Some("sb-abc"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn search_is_case_insensitive_and_takes_wildcards_literally() {
        let dir = seeded("search");
        let engine = engine(&dir).await;
        let window = Window {
            from: at(TS - 60_000),
            to: at(TS + 600_000),
        };
        async fn matches(engine: &Engine, window: Window, search: &str) -> usize {
            let filter = LogFilter {
                deployment: "demo".into(),
                namespace: None,
                level: None,
                backend: None,
                search: Some(search.into()),
                limit: 100,
                before_ms: None,
            };
            engine.logs(window, &filter).await.unwrap().len()
        }

        assert_eq!(
            matches(&engine, window, "BOOM").await,
            1,
            "case-insensitive"
        );
        // `%` is a literal here, not a LIKE wildcard, so a message containing
        // one is searchable as itself.
        assert_eq!(matches(&engine, window, "%50").await, 1);
        assert_eq!(
            matches(&engine, window, "%").await,
            1,
            "matches only the line that has one",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn error_levels_are_counted_however_they_are_spelled() {
        // `ERROR` from a structured logger and `error` from syslog are the same
        // event; only one of them is the canonical spelling.
        let dir = seeded("levels");
        let engine = engine(&dir).await;
        let window = Window {
            from: at(TS - 60_000),
            to: at(TS + 600_000),
        };

        let volume = engine
            .log_volume(window, 3600, Some("demo"), None)
            .await
            .unwrap();
        let demo = volume.get("demo").expect("demo logged");
        assert_eq!(demo.iter().map(|b| b.lines).sum::<u64>(), 3);
        assert_eq!(demo.iter().map(|b| b.errors).sum::<u64>(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn counters_are_differenced_across_buckets_and_a_reset_is_a_gap() {
        let dir = seeded("rates");
        let engine = engine(&dir).await;
        let window = Window {
            from: at(TS - 60_000),
            to: at(TS + 600_000),
        };

        let series = engine
            .metrics(window, 60, Some("demo"), None)
            .await
            .unwrap();
        let demo = series.get("demo").expect("demo reported metrics");
        assert_eq!(demo.len(), 3);

        // Nothing to difference the first bucket against.
        assert_eq!(demo[0].requests_per_sec, None);
        // 100 -> 220 over 60s.
        assert_eq!(demo[1].requests_per_sec, Some(2.0));
        // 220 -> 5 is app-lb restarting, not negative traffic.
        assert_eq!(demo[2].requests_per_sec, None);
        // 100 -> 220 with samples 60s apart, so the divisor is the 60s between
        // the readings and not the bucket width. They coincide here; the
        // partial-bucket case is covered below.
        assert_eq!(demo[1].requests_per_sec, Some(2.0));
        // Cumulative percentiles pass through untouched.
        assert_eq!(demo[1].p50_ms, Some(8.0));
        // 8ms per request, from the deltas.
        assert_eq!(demo[1].mean_latency_ms, Some(8.0));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_partial_trailing_bucket_reports_the_real_rate() {
        // The newest bucket always holds less than a full step's worth of
        // samples, because now is somewhere in the middle of it. Dividing its
        // delta by the whole step width makes every live figure on the page read
        // low, and worse, makes steady traffic look like it is falling off a
        // cliff at the right-hand edge of every chart.
        let dir = tmpdir("partial");
        let mut writer = Writer::new(&dir, 10_000, Duration::from_secs(3600));
        // TS is at :56 past the minute, so these two samples — 14s apart, 140
        // requests between them, a true 10/s — straddle a 60s bucket boundary,
        // and the second bucket holds only 10s of its 60. Divided by the nominal
        // width it would read 2.33/s.
        for (offset, total) in [(0i64, 500u64), (14_000, 640)] {
            writer
                .push(Record::Metric(MetricRecord {
                    ts_millis: TS + offset,
                    deployment: "demo".into(),
                    requests_total: Some(total),
                    ..Default::default()
                }))
                .unwrap();
        }
        writer.flush_all().unwrap();

        let engine = engine(&dir).await;
        let series = engine
            .metrics(
                Window {
                    from: at(TS - 60_000),
                    to: at(TS + 120_000),
                },
                60,
                Some("demo"),
                None,
            )
            .await
            .unwrap();
        let demo = series.get("demo").unwrap();
        assert_eq!(demo.len(), 2, "the samples straddle a bucket boundary");
        assert_eq!(
            demo[1].requests_per_sec,
            Some(10.0),
            "140 requests in the 14s between the readings, not spread over a 60s bucket",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_partition_written_after_registration_is_visible() {
        // The tables are registered once at startup and then queried for the
        // life of the process, while the writer keeps adding files underneath
        // them. DataFusion ships a listing cache with an infinite TTL that turns
        // that into a dashboard frozen at whatever existed on the first query —
        // and it fails silently, because every query still succeeds.
        let dir = tmpdir("fresh");
        let mut writer = Writer::new(&dir, 1, Duration::from_secs(3600));
        writer.push(log("demo", TS, "info", "first")).unwrap();

        let engine = engine(&dir).await;
        let window = Window {
            from: at(TS - 60_000),
            to: at(TS + 600_000),
        };
        async fn count(engine: &Engine, window: Window) -> usize {
            let filter = LogFilter {
                deployment: "demo".into(),
                namespace: None,
                level: None,
                backend: None,
                search: None,
                limit: 100,
                before_ms: None,
            };
            engine.logs(window, &filter).await.unwrap().len()
        }
        assert_eq!(count(&engine, window).await, 1);

        // A second partition lands in the same directory, as the drain task does
        // every flush interval.
        writer
            .push(log("demo", TS + 1000, "info", "second"))
            .unwrap();
        assert_eq!(
            count(&engine, window).await,
            2,
            "the new partition must be visible",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_empty_data_directory_answers_rather_than_failing() {
        // Registration must not need a file to infer a schema from: the first
        // dashboard load can easily beat the first flush.
        let dir = tmpdir("empty");
        let engine = engine(&dir).await;
        assert!(engine.deployments().is_empty());

        let window = Window::trailing(at(TS), 3_600);
        assert!(
            engine
                .metrics(window, 60, None, None)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            engine
                .log_volume(window, 60, None, None)
                .await
                .unwrap()
                .is_empty()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unusable_deployment_id_is_refused_before_any_scan() {
        let dir = tmpdir("badid");
        let engine = engine(&dir).await;
        let window = Window::trailing(at(TS), 3_600);
        assert!(matches!(
            engine.metrics(window, 60, Some("../etc"), None).await,
            Err(QueryError::BadDeployment(_)),
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
