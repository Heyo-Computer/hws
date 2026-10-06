//! Buffers records per partition and flushes them to parquet.
//!
//! Records arrive interleaved across deployments and, around an hour boundary,
//! across partitions. The writer keeps one buffer per partition and flushes a
//! buffer when it grows past `flush_rows` or has been open longer than
//! `flush_interval` — so a busy deployment produces reasonably sized files while
//! a quiet one still becomes queryable within a bounded delay.
//!
//! Files are written to a temporary name and renamed into place. A reader
//! listing the directory therefore only ever sees complete parquet files, which
//! matters because the query layer lists these directories concurrently with
//! writes and a half-written footer is not a recoverable parse error.

use super::partition::{PartitionError, PartitionKey};
use super::schema::{Record, Table};
use datafusion::arrow::array::{
    ArrayRef, Float64Builder, StringBuilder, TimestampMillisecondBuilder, UInt32Builder,
    UInt64Builder,
};
use datafusion::arrow::datatypes::DataType;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::parquet::arrow::ArrowWriter;
use datafusion::parquet::basic::Compression;
use datafusion::parquet::file::properties::WriterProperties;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// A partition's pending rows.
struct Buffer {
    records: Vec<Record>,
    /// When the first record landed, for the age-based flush.
    opened: Instant,
}

pub struct Writer {
    data_dir: PathBuf,
    buffers: HashMap<PartitionKey, Buffer>,
    flush_rows: usize,
    flush_interval: Duration,
    /// Monotonically increasing suffix, so two files flushed inside the same
    /// millisecond cannot collide.
    sequence: u64,
    /// Published for the API to read.
    ///
    /// An atomic rather than sharing the writer behind a lock: the writer runs
    /// alone in the drain task precisely so it never has to synchronise, and a
    /// dashboard poll must not be able to make a parquet flush wait.
    buffered: Arc<AtomicUsize>,
}

#[derive(Debug)]
pub enum WriteError {
    Partition(PartitionError),
    Arrow(datafusion::arrow::error::ArrowError),
    Parquet(datafusion::parquet::errors::ParquetError),
    Io(std::io::Error),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Partition(e) => write!(f, "{e}"),
            Self::Arrow(e) => write!(f, "{e}"),
            Self::Parquet(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WriteError {}

impl From<PartitionError> for WriteError {
    fn from(e: PartitionError) -> Self {
        Self::Partition(e)
    }
}
impl From<datafusion::arrow::error::ArrowError> for WriteError {
    fn from(e: datafusion::arrow::error::ArrowError) -> Self {
        Self::Arrow(e)
    }
}
impl From<datafusion::parquet::errors::ParquetError> for WriteError {
    fn from(e: datafusion::parquet::errors::ParquetError) -> Self {
        Self::Parquet(e)
    }
}
impl From<std::io::Error> for WriteError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl Writer {
    pub fn new(data_dir: impl Into<PathBuf>, flush_rows: usize, flush_interval: Duration) -> Self {
        Self {
            data_dir: data_dir.into(),
            buffers: HashMap::new(),
            // A zero threshold would flush every single row into its own file,
            // which is the small-files problem at its worst.
            flush_rows: flush_rows.max(1),
            flush_interval,
            sequence: 0,
            buffered: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// A handle on the buffered-row count, for whoever reports status.
    pub fn buffered_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.buffered)
    }

    /// Buffer one record, flushing its partition if that fills it.
    ///
    /// A record whose deployment id or timestamp is unusable is rejected here
    /// rather than at ingest, so every path into the writer gets the same
    /// validation.
    pub fn push(&mut self, record: Record) -> Result<(), WriteError> {
        let key = PartitionKey::new(record.table(), record.deployment(), record.ts_millis())?;

        let buffer = self.buffers.entry(key.clone()).or_insert_with(|| Buffer {
            records: Vec::new(),
            opened: Instant::now(),
        });
        buffer.records.push(record);

        if buffer.records.len() >= self.flush_rows {
            self.flush_partition(&key)?;
        }
        self.publish();
        Ok(())
    }

    /// Flush partitions whose buffer has been open longer than the interval.
    /// Called on a timer so a low-volume deployment doesn't sit unqueryable.
    pub fn flush_expired(&mut self) -> Result<usize, WriteError> {
        let now = Instant::now();
        let expired: Vec<PartitionKey> = self
            .buffers
            .iter()
            .filter(|(_, b)| now.duration_since(b.opened) >= self.flush_interval)
            .map(|(k, _)| k.clone())
            .collect();

        for key in &expired {
            self.flush_partition(key)?;
        }
        self.publish();
        Ok(expired.len())
    }

    /// Flush everything. Used on shutdown, where losing a partial buffer would
    /// mean losing logs that were already acknowledged to the sender.
    pub fn flush_all(&mut self) -> Result<usize, WriteError> {
        let keys: Vec<PartitionKey> = self.buffers.keys().cloned().collect();
        for key in &keys {
            self.flush_partition(key)?;
        }
        self.publish();
        Ok(keys.len())
    }

    /// Rows sitting in memory, not yet on disk.
    pub fn buffered_rows(&self) -> usize {
        self.buffers.values().map(|b| b.records.len()).sum()
    }

    /// Republish the buffered count.
    ///
    /// Recomputed rather than tracked incrementally: it is a sum over a handful
    /// of open partitions, and a count maintained by hand at every push, flush
    /// and rejection is exactly the kind of thing that drifts and then lies on a
    /// status page.
    fn publish(&self) {
        self.buffered.store(self.buffered_rows(), Ordering::Relaxed);
    }

    fn flush_partition(&mut self, key: &PartitionKey) -> Result<(), WriteError> {
        let Some(buffer) = self.buffers.remove(key) else {
            return Ok(());
        };
        if buffer.records.is_empty() {
            return Ok(());
        }

        let batch = build_batch(key.table, &buffer.records)?;
        let dir = key.dir(&self.data_dir);
        std::fs::create_dir_all(&dir)?;

        self.sequence += 1;
        let stem = format!("{:013x}-{:06x}", key_millis(&buffer), self.sequence);
        let final_path = dir.join(format!("{stem}.parquet"));
        let tmp_path = dir.join(format!(".{stem}.parquet.tmp"));

        // Zstd over the default snappy: log messages are highly repetitive and
        // this is cold-ish storage that gets scanned far less often than it is
        // written, so trading a little CPU for a much smaller footprint (and
        // fewer bytes to ship to S3 later) is the right side of that deal.
        let props = WriterProperties::builder()
            .set_compression(Compression::ZSTD(Default::default()))
            .build();

        {
            let file = std::fs::File::create(&tmp_path)?;
            let mut writer = ArrowWriter::try_new(file, key.table.schema(), Some(props))?;
            writer.write(&batch)?;
            // Explicit close so the footer is written and any error surfaces
            // here, while the file is still under its temporary name.
            writer.close()?;
        }

        std::fs::rename(&tmp_path, &final_path)?;
        tracing::debug!(
            path = %final_path.display(),
            rows = batch.num_rows(),
            "flushed partition",
        );
        Ok(())
    }
}

/// A stable, sortable prefix for the file name, taken from the oldest record.
/// Makes a directory listing roughly chronological, which helps when eyeballing
/// storage.
fn key_millis(buffer: &Buffer) -> i64 {
    buffer
        .records
        .iter()
        .map(Record::ts_millis)
        .min()
        .unwrap_or(0)
}

fn build_batch(table: Table, records: &[Record]) -> Result<RecordBatch, WriteError> {
    match table {
        Table::Logs => build_logs_batch(records),
        Table::Metrics => build_metrics_batch(records),
    }
}

fn build_logs_batch(records: &[Record]) -> Result<RecordBatch, WriteError> {
    let n = records.len();
    let mut ts = TimestampMillisecondBuilder::with_capacity(n);
    let mut backend = StringBuilder::new();
    let mut source = StringBuilder::new();
    let mut level = StringBuilder::new();
    let mut message = StringBuilder::new();
    let mut fields = StringBuilder::new();
    let mut host = StringBuilder::new();
    let mut namespace = StringBuilder::new();

    for record in records {
        let Record::Log(r) = record else {
            // The writer buckets by `Record::table()`, so a mismatch here means
            // that mapping and this one disagree — a bug, not bad input.
            unreachable!("metric record in a logs partition");
        };
        ts.append_value(r.ts_millis);
        backend.append_option(r.backend.as_deref());
        source.append_value(&r.source);
        level.append_option(r.level.as_deref());
        message.append_value(&r.message);
        fields.append_option(r.fields.as_deref());
        host.append_option(r.host.as_deref());
        namespace.append_option(r.namespace.as_deref());
    }

    let schema = Table::Logs.schema();
    let columns: Vec<ArrayRef> = vec![
        with_utc(ts, &schema),
        std::sync::Arc::new(backend.finish()),
        std::sync::Arc::new(source.finish()),
        std::sync::Arc::new(level.finish()),
        std::sync::Arc::new(message.finish()),
        std::sync::Arc::new(fields.finish()),
        std::sync::Arc::new(host.finish()),
        std::sync::Arc::new(namespace.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

fn build_metrics_batch(records: &[Record]) -> Result<RecordBatch, WriteError> {
    let n = records.len();
    let mut ts = TimestampMillisecondBuilder::with_capacity(n);
    let mut backend = StringBuilder::new();
    let mut cpu = Float64Builder::with_capacity(n);
    let mut memory = UInt64Builder::with_capacity(n);
    let mut in_flight = UInt32Builder::with_capacity(n);
    let mut ready = UInt32Builder::with_capacity(n);
    let mut pending = UInt32Builder::with_capacity(n);
    let mut draining = UInt32Builder::with_capacity(n);
    let mut requests = UInt64Builder::with_capacity(n);
    let mut errors = UInt64Builder::with_capacity(n);
    let mut p50 = Float64Builder::with_capacity(n);
    let mut p90 = Float64Builder::with_capacity(n);
    let mut p99 = Float64Builder::with_capacity(n);
    let mut latency_count = UInt64Builder::with_capacity(n);
    let mut latency_sum = UInt64Builder::with_capacity(n);
    let mut namespace = StringBuilder::new();

    for record in records {
        let Record::Metric(r) = record else {
            unreachable!("log record in a metrics partition");
        };
        ts.append_value(r.ts_millis);
        backend.append_option(r.backend.as_deref());
        cpu.append_option(r.cpu_percent);
        memory.append_option(r.memory_bytes);
        in_flight.append_option(r.in_flight);
        ready.append_option(r.ready);
        pending.append_option(r.pending);
        draining.append_option(r.draining);
        requests.append_option(r.requests_total);
        errors.append_option(r.errors_total);
        p50.append_option(r.p50_ms);
        p90.append_option(r.p90_ms);
        p99.append_option(r.p99_ms);
        latency_count.append_option(r.latency_count);
        latency_sum.append_option(r.latency_sum);
        namespace.append_option(r.namespace.as_deref());
    }

    let schema = Table::Metrics.schema();
    let columns: Vec<ArrayRef> = vec![
        with_utc(ts, &schema),
        std::sync::Arc::new(backend.finish()),
        std::sync::Arc::new(cpu.finish()),
        std::sync::Arc::new(memory.finish()),
        std::sync::Arc::new(in_flight.finish()),
        std::sync::Arc::new(ready.finish()),
        std::sync::Arc::new(pending.finish()),
        std::sync::Arc::new(draining.finish()),
        std::sync::Arc::new(requests.finish()),
        std::sync::Arc::new(errors.finish()),
        std::sync::Arc::new(p50.finish()),
        std::sync::Arc::new(p90.finish()),
        std::sync::Arc::new(p99.finish()),
        std::sync::Arc::new(latency_count.finish()),
        std::sync::Arc::new(latency_sum.finish()),
        std::sync::Arc::new(namespace.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

/// Stamp the timezone from the schema onto the timestamp array.
///
/// The builder produces a naive `Timestamp(Millisecond, None)`; the schema
/// declares `Some("UTC")`, and `RecordBatch::try_new` rejects the mismatch. The
/// underlying values are already UTC millis, so this is a metadata cast only.
fn with_utc(
    mut builder: TimestampMillisecondBuilder,
    schema: &datafusion::arrow::datatypes::Schema,
) -> ArrayRef {
    let array = builder.finish();
    match schema.field_with_name("ts").map(|f| f.data_type().clone()) {
        Ok(DataType::Timestamp(_, Some(tz))) => std::sync::Arc::new(array.with_timezone(tz)),
        _ => std::sync::Arc::new(array),
    }
}

/// List the parquet files in a directory, ignoring in-progress temporaries.
// The filtering here is what keeps a half-written file from reaching a reader,
// so the query layer and the compaction step both go through it.
pub fn parquet_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::schema::{LogRecord, MetricRecord};
    use datafusion::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    const TS: i64 = 1_785_260_096_000; // 2026-07-28T17:34:56Z

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("app-obs-writer-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn log(deployment: &str, ts: i64, message: &str) -> Record {
        Record::Log(LogRecord {
            ts_millis: ts,
            deployment: deployment.into(),
            backend: Some("sb-abc".into()),
            source: "stdout".into(),
            level: Some("info".into()),
            message: message.into(),
            fields: None,
            host: None,
            namespace: None,
        })
    }

    fn metric(deployment: &str, ts: i64, cpu: Option<f64>) -> Record {
        Record::Metric(MetricRecord {
            ts_millis: ts,
            deployment: deployment.into(),
            backend: Some("sb-abc".into()),
            cpu_percent: cpu,
            memory_bytes: Some(1024),
            ..Default::default()
        })
    }

    /// Read every row back out of a partition directory.
    fn read_rows(dir: &Path) -> usize {
        parquet_files(dir)
            .iter()
            .map(|path| {
                let file = std::fs::File::open(path).unwrap();
                ParquetRecordBatchReaderBuilder::try_new(file)
                    .unwrap()
                    .build()
                    .unwrap()
                    .map(|b| b.unwrap().num_rows())
                    .sum::<usize>()
            })
            .sum()
    }

    #[test]
    fn rows_round_trip_through_parquet() {
        let dir = tmpdir("roundtrip");
        let mut writer = Writer::new(&dir, 2, Duration::from_secs(3600));

        writer.push(log("demo", TS, "first")).unwrap();
        writer.push(log("demo", TS, "second")).unwrap();
        // Two rows hit flush_rows, so the partition is already on disk.

        let partition = PartitionKey::new(Table::Logs, "demo", TS)
            .unwrap()
            .dir(&dir);
        assert_eq!(read_rows(&partition), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn values_survive_the_round_trip() {
        let dir = tmpdir("values");
        let mut writer = Writer::new(&dir, 1, Duration::from_secs(3600));
        writer.push(log("demo", TS, "hello world")).unwrap();

        let partition = PartitionKey::new(Table::Logs, "demo", TS)
            .unwrap()
            .dir(&dir);
        let path = &parquet_files(&partition)[0];
        let file = std::fs::File::open(path).unwrap();
        let batch = ParquetRecordBatchReaderBuilder::try_new(file)
            .unwrap()
            .build()
            .unwrap()
            .next()
            .unwrap()
            .unwrap();

        use datafusion::arrow::array::StringArray;
        let messages = batch
            .column_by_name("message")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(messages.value(0), "hello world");

        // A UTC-stamped timestamp column, not a naive one.
        assert_eq!(
            batch.schema().field_with_name("ts").unwrap().data_type(),
            &DataType::Timestamp(
                datafusion::arrow::datatypes::TimeUnit::Millisecond,
                Some("UTC".into())
            ),
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn records_are_split_across_partitions() {
        let dir = tmpdir("split");
        let mut writer = Writer::new(&dir, 1000, Duration::from_secs(3600));

        // Same deployment, one hour apart, plus a second deployment.
        writer.push(log("demo", TS, "a")).unwrap();
        writer.push(log("demo", TS + 3_600_000, "b")).unwrap();
        writer.push(log("other", TS, "c")).unwrap();
        assert_eq!(writer.buffered_rows(), 3);
        writer.flush_all().unwrap();

        for (deployment, ts) in [("demo", TS), ("demo", TS + 3_600_000), ("other", TS)] {
            let partition = PartitionKey::new(Table::Logs, deployment, ts)
                .unwrap()
                .dir(&dir);
            assert_eq!(read_rows(&partition), 1, "{deployment} at {ts}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn metrics_keep_nulls_distinct_from_zero() {
        // "not reported" and "measured as zero" mean different things on a
        // chart, so an absent sample must stay null rather than becoming 0.0.
        let dir = tmpdir("nulls");
        let mut writer = Writer::new(&dir, 1, Duration::from_secs(3600));
        writer.push(metric("demo", TS, None)).unwrap();

        let partition = PartitionKey::new(Table::Metrics, "demo", TS)
            .unwrap()
            .dir(&dir);
        let file = std::fs::File::open(&parquet_files(&partition)[0]).unwrap();
        let batch = ParquetRecordBatchReaderBuilder::try_new(file)
            .unwrap()
            .build()
            .unwrap()
            .next()
            .unwrap()
            .unwrap();

        let cpu = batch.column_by_name("cpu_percent").unwrap();
        assert_eq!(cpu.null_count(), 1, "an unreported CPU sample must be null");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn age_based_flush_only_takes_expired_partitions() {
        let dir = tmpdir("expiry");
        let mut writer = Writer::new(&dir, 1000, Duration::ZERO);
        writer.push(log("demo", TS, "a")).unwrap();
        assert_eq!(writer.flush_expired().unwrap(), 1);
        assert_eq!(writer.buffered_rows(), 0);

        let mut patient = Writer::new(&dir, 1000, Duration::from_secs(3600));
        patient.push(log("demo", TS, "b")).unwrap();
        assert_eq!(patient.flush_expired().unwrap(), 0, "still young");
        assert_eq!(patient.buffered_rows(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_deployment_id_is_rejected_before_any_file_is_created() {
        let dir = tmpdir("badid");
        let mut writer = Writer::new(&dir, 1, Duration::from_secs(3600));
        assert!(writer.push(log("../escape", TS, "x")).is_err());
        assert!(
            !dir.join("logs").exists(),
            "a rejected record must not create directories",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn temporary_files_are_never_listed_as_parquet() {
        // The query layer lists these directories while writes are in flight;
        // a partial file surfacing as readable is an unrecoverable parse error.
        let dir = tmpdir("tmpfiles");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".x.parquet.tmp"), b"partial").unwrap();
        std::fs::write(dir.join("good.parquet"), b"").unwrap();

        let listed = parquet_files(&dir);
        assert_eq!(listed.len(), 1);
        assert!(listed[0].ends_with("good.parquet"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
