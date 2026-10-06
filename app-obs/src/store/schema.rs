//! Arrow schemas and the row types that feed them.
//!
//! Both tables are deliberately flat and columnar rather than a generic
//! name/value pair model: charting is then a `GROUP BY` over a real column
//! instead of a pivot, and parquet's per-column statistics let DataFusion skip
//! row groups on a predicate.
//!
//! The partition keys (`deployment`, `date`, `hour`) are *not* schema fields.
//! They live in directory names, so DataFusion recovers them from the path and
//! prunes whole directories before opening a file. Storing them again inside
//! the parquet would cost space and buy nothing.

use datafusion::arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use std::sync::Arc;

/// A single log line.
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// Milliseconds since the Unix epoch, UTC. Milliseconds rather than
    /// nanoseconds because log timestamps rarely carry more precision than
    /// that, and it keeps the column half the width.
    pub ts_millis: i64,
    pub deployment: String,
    /// `None` for a static (proxy_pass) upstream, which has no sandbox.
    pub backend: Option<String>,
    /// `stdout`, `stderr`, or `console` from the daemon tail; `syslog` from
    /// the syslog listener; whatever the sender said on the push path.
    pub source: String,
    pub level: Option<String>,
    pub message: String,
    /// Structured payload, as a JSON object string. A string rather than an
    /// Arrow map so that one application emitting unusual keys can't widen the
    /// schema for everybody; DataFusion can still reach into it with its JSON
    /// functions when a query needs to.
    pub fields: Option<String>,
    pub host: Option<String>,
    /// The app-lb namespace the deployment belonged to when the row was
    /// written, stamped by [`crate::ingest::Sink`] from the poller's
    /// directory — never by the sender. [`UNATTRIBUTED`] for platform rows and
    /// deployments app-lb has not reported; `None` only before stamping.
    pub namespace: Option<String>,
}

/// One sample of a deployment's or VM's resource and traffic state.
///
/// Every measure is optional because the sources genuinely disagree about what
/// they know: the daemon reports CPU and memory only for VMs it has sampled,
/// pool gauges exist per deployment but not per VM, and latency percentiles are
/// deployment-wide. A null means "not reported", which is different from zero
/// and must stay distinguishable in a chart.
#[derive(Debug, Clone, Default)]
pub struct MetricRecord {
    pub ts_millis: i64,
    pub deployment: String,
    pub backend: Option<String>,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
    pub in_flight: Option<u32>,
    pub ready: Option<u32>,
    pub pending: Option<u32>,
    pub draining: Option<u32>,
    pub requests_total: Option<u64>,
    pub errors_total: Option<u64>,
    pub p50_ms: Option<f64>,
    /// p90, not p95: app-lb's histogram reports p50/p90/p99
    /// (`app-lb/src/metrics.rs`), and inventing a p95 here would mean
    /// interpolating a number the source never measured.
    pub p90_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    /// Requests measured and their total latency, both cumulative since app-lb
    /// started.
    ///
    /// Stored because the percentiles above are cumulative too: app-lb's
    /// histogram never decays (`app-lb/src/metrics.rs`), so a stored p50 is a
    /// lifetime figure that barely moves and drops back on restart. Differencing
    /// these two between consecutive samples gives the mean latency *over that
    /// interval*, which is the only honest latency a chart can plot from a
    /// cumulative source.
    pub latency_count: Option<u64>,
    /// Milliseconds, matching `p50_ms` and friends.
    pub latency_sum: Option<u64>,
    /// See [`LogRecord::namespace`].
    pub namespace: Option<String>,
}

/// The `namespace` written for rows no tenant namespace owns: the platform's
/// reserved partitions (`_host`, `_lb`, `_unmanaged`, `syslog`) and any
/// deployment app-lb has not reported. Not a legal app-lb namespace (the
/// underscore), so no namespace route can ever be asked for it.
pub const UNATTRIBUTED: &str = "_";

/// The namespace a row written before the column existed belongs to. Every
/// deployment predating namespaces lived in app-lb's `default`, and that is
/// where app-lb still files a spec that names none.
pub const LEGACY_NAMESPACE: &str = "default";

/// Either kind of row. The writer is generic over this so ingest and polling
/// share one buffering, flushing, and partitioning path.
#[derive(Debug, Clone)]
pub enum Record {
    Log(LogRecord),
    Metric(MetricRecord),
}

impl Record {
    pub fn ts_millis(&self) -> i64 {
        match self {
            Self::Log(r) => r.ts_millis,
            Self::Metric(r) => r.ts_millis,
        }
    }

    pub fn deployment(&self) -> &str {
        match self {
            Self::Log(r) => &r.deployment,
            Self::Metric(r) => &r.deployment,
        }
    }

    pub fn set_namespace(&mut self, namespace: String) {
        match self {
            Self::Log(r) => r.namespace = Some(namespace),
            Self::Metric(r) => r.namespace = Some(namespace),
        }
    }

    pub fn table(&self) -> Table {
        match self {
            Self::Log(_) => Table::Logs,
            Self::Metric(_) => Table::Metrics,
        }
    }
}

/// The two tables, which differ in schema and in partition granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Table {
    Logs,
    Metrics,
}

impl Table {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Logs => "logs",
            Self::Metrics => "metrics",
        }
    }

    /// Logs partition by hour, metrics by day.
    ///
    /// Log volume is unbounded and bursty, so an hour bounds how much a single
    /// "tail the last few minutes" query has to open. Metrics arrive at a fixed
    /// poll rate — a day's worth is small, and hourly directories would just
    /// multiply tiny files for no pruning benefit.
    pub fn hourly(&self) -> bool {
        matches!(self, Self::Logs)
    }

    pub fn schema(&self) -> Arc<Schema> {
        match self {
            Self::Logs => logs_schema(),
            Self::Metrics => metrics_schema(),
        }
    }
}

fn ts_field() -> Field {
    // Timezone-aware so DataFusion renders and compares it as UTC rather than
    // silently reinterpreting it in the server's local zone.
    Field::new(
        "ts",
        DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
        false,
    )
}

pub fn logs_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        ts_field(),
        Field::new("backend", DataType::Utf8, true),
        Field::new("source", DataType::Utf8, false),
        Field::new("level", DataType::Utf8, true),
        Field::new("message", DataType::Utf8, false),
        Field::new("fields", DataType::Utf8, true),
        Field::new("host", DataType::Utf8, true),
        // Appended and nullable, like `latency_count` below: parquet written
        // before namespaces still reads, with a null the query layer takes as
        // [`LEGACY_NAMESPACE`].
        Field::new("namespace", DataType::Utf8, true),
    ]))
}

pub fn metrics_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        ts_field(),
        Field::new("backend", DataType::Utf8, true),
        Field::new("cpu_percent", DataType::Float64, true),
        Field::new("memory_bytes", DataType::UInt64, true),
        Field::new("in_flight", DataType::UInt32, true),
        Field::new("ready", DataType::UInt32, true),
        Field::new("pending", DataType::UInt32, true),
        Field::new("draining", DataType::UInt32, true),
        Field::new("requests_total", DataType::UInt64, true),
        Field::new("errors_total", DataType::UInt64, true),
        Field::new("p50_ms", DataType::Float64, true),
        Field::new("p90_ms", DataType::Float64, true),
        Field::new("p99_ms", DataType::Float64, true),
        // Appended, and nullable like everything else here, so parquet written
        // before these existed still reads: DataFusion fills a nullable column
        // missing from a file with nulls rather than failing the scan.
        Field::new("latency_count", DataType::UInt64, true),
        Field::new("latency_sum", DataType::UInt64, true),
        Field::new("namespace", DataType::Utf8, true),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_keys_are_not_schema_fields() {
        // They come from the directory path; duplicating them in the file would
        // cost space and let the two disagree.
        for schema in [logs_schema(), metrics_schema()] {
            for absent in ["deployment", "date", "hour"] {
                assert!(
                    schema.field_with_name(absent).is_err(),
                    "{absent} must live in the path, not the file",
                );
            }
        }
    }

    #[test]
    fn timestamps_carry_utc() {
        // Without a timezone, DataFusion would interpret these in the server's
        // local zone and a dashboard would silently shift by the UTC offset.
        for schema in [logs_schema(), metrics_schema()] {
            let ts = schema.field_with_name("ts").unwrap();
            assert_eq!(
                ts.data_type(),
                &DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
            );
            assert!(!ts.is_nullable(), "a row with no time is not a row");
        }
    }

    #[test]
    fn logs_partition_hourly_and_metrics_daily() {
        assert!(Table::Logs.hourly());
        assert!(!Table::Metrics.hourly());
    }
}
