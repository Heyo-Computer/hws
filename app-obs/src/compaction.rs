//! Merges each partition's small parquet files into one.
//!
//! # The small-files problem
//!
//! The writer flushes a partition every `flush_interval` so fresh rows become
//! queryable quickly — which is right for freshness and ruinous for file count.
//! Metrics polled every ten seconds and flushed every minute make one tiny file
//! per deployment per minute, up to ~1,440 per daily partition; the default 24h
//! dashboard window then opens every one of them, and most of a query's budget
//! goes to parquet footers rather than rows. Compaction rewrites a partition's
//! files into a single one, so the steady state per partition is one compacted
//! file plus whatever the writer has flushed since the last pass.
//!
//! # Swapping files under a live reader
//!
//! The query layer lists these directories on every scan, and there is no
//! manifest to make a multi-file swap atomic. Instead the swap runs while the
//! engine is quiesced — the compactor holds every query slot for the few renames
//! involved — so no scan can observe the intermediate state, where the merged
//! file and its inputs are briefly both present or both absent. Queries arriving
//! in that instant get the same `Busy` a full pool produces, which the dashboard
//! already knows to retry.
//!
//! A crash can still land in the middle, so the sequence is ordered to be
//! recoverable from names alone:
//!
//! 1. write the merged rows to `.<stem>.compact.tmp` (invisible to readers);
//! 2. rename each input `x.parquet` → `x.parquet.merged` (now invisible too);
//! 3. rename the tmp to `<stem>.parquet` (the merge becomes visible, atomically);
//! 4. delete the `.merged` files.
//!
//! On the next pass: a leftover `.compact.tmp` means step 3 never happened, so
//! the `.merged` inputs are restored and the tmp discarded; `.merged` files with
//! no tmp mean the merge landed and only the cleanup was interrupted, so they
//! are deleted. Either way no row is lost and none is duplicated.
//!
//! The writer is never in the way: it only ever *adds* files, so anything it
//! flushes after the input list is taken is untouched by the swap and simply
//! survives alongside the merged file.

use crate::query::Engine;
use crate::store::partition::date_from_dir_name;
use crate::store::schema::Table;
use crate::store::writer::parquet_files;
use datafusion::parquet::arrow::ArrowWriter;
use datafusion::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use datafusion::parquet::basic::Compression;
use datafusion::parquet::file::properties::WriterProperties;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Fewest files worth merging. Two is already a win: a closed partition reaches
/// one file on its first pass and is skipped forever after.
const MIN_FILES: usize = 2;

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Compacted {
    pub partitions: usize,
    pub files_merged: usize,
    pub rows: usize,
}

pub struct Compaction {
    data_dir: PathBuf,
    interval: Duration,
    engine: Arc<Engine>,
    /// Distinguishes merged files created in the same millisecond, exactly as
    /// the writer's sequence does for flushes.
    sequence: AtomicU64,
}

#[derive(Debug)]
enum CompactError {
    Io(std::io::Error),
    Parquet(datafusion::parquet::errors::ParquetError),
    Arrow(datafusion::arrow::error::ArrowError),
}

impl std::fmt::Display for CompactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Parquet(e) => write!(f, "{e}"),
            Self::Arrow(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for CompactError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<datafusion::parquet::errors::ParquetError> for CompactError {
    fn from(e: datafusion::parquet::errors::ParquetError) -> Self {
        Self::Parquet(e)
    }
}
impl From<datafusion::arrow::error::ArrowError> for CompactError {
    fn from(e: datafusion::arrow::error::ArrowError) -> Self {
        Self::Arrow(e)
    }
}

impl Compaction {
    pub fn new(data_dir: impl Into<PathBuf>, interval: Duration, engine: Arc<Engine>) -> Self {
        Self {
            data_dir: data_dir.into(),
            interval,
            engine,
            sequence: AtomicU64::new(0),
        }
    }

    /// Compact on a timer until the process ends.
    ///
    /// The first tick fires immediately, which is also when crash recovery runs
    /// — so a partition left mid-swap by an unclean shutdown is put right before
    /// the dashboard has been up long enough for anyone to notice.
    pub async fn run(self) {
        if self.interval.is_zero() {
            tracing::info!("compaction disabled (APP_OBS_COMPACT_SECS=0)");
            return;
        }
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let done = self.pass().await;
            if done.partitions > 0 {
                tracing::info!(
                    partitions = done.partitions,
                    files_merged = done.files_merged,
                    rows = done.rows,
                    "compaction merged small parquet files",
                );
            } else {
                tracing::debug!("compaction found nothing to merge");
            }
        }
    }

    /// One sweep over every partition: recover, merge, then swap.
    ///
    /// All the expensive work — reading and rewriting parquet — happens before
    /// any query slot is taken. The engine is quiesced once, for the renames
    /// only, however many partitions were prepared.
    async fn pass(&self) -> Compacted {
        let mut done = Compacted::default();

        let prepared = tokio::task::block_in_place(|| {
            let mut swaps = Vec::new();
            for dir in partition_dirs(&self.data_dir) {
                if let Err(e) = recover_dir(&dir) {
                    tracing::warn!(dir = %dir.display(), error = %e, "compaction recovery failed");
                    continue;
                }
                match prepare(&dir, self.sequence.fetch_add(1, Ordering::Relaxed)) {
                    Ok(Some(swap)) => swaps.push(swap),
                    Ok(None) => {}
                    // A partition that cannot be merged is left exactly as it
                    // was; queries keep reading the original files.
                    Err(e) => {
                        tracing::warn!(dir = %dir.display(), error = %e, "compaction skipped a partition")
                    }
                }
            }
            swaps
        });
        if prepared.is_empty() {
            return done;
        }

        let quiesced = self.engine.quiesce().await;
        for swap in prepared {
            let (dir, files, rows) = (swap.dir.clone(), swap.inputs.len(), swap.rows);
            match swap.commit() {
                Ok(()) => {
                    done.partitions += 1;
                    done.files_merged += files;
                    done.rows += rows;
                }
                Err(e) => tracing::warn!(
                    dir = %dir.display(), error = %e,
                    "compaction swap failed; the partition was left as it was",
                ),
            }
        }
        drop(quiesced);
        done
    }
}

/// A merge that is written but not yet visible: the tmp file exists, the inputs
/// are still what readers see. `commit` performs the swap; dropping it without
/// committing leaves nothing but a tmp for recovery to sweep.
struct PendingSwap {
    dir: PathBuf,
    tmp: PathBuf,
    final_path: PathBuf,
    inputs: Vec<PathBuf>,
    rows: usize,
}

impl PendingSwap {
    /// Make the merged file the partition's contents. Runs while the engine is
    /// quiesced; on any failure the inputs are restored and the merge discarded,
    /// so the partition is never left half-swapped while the process lives.
    fn commit(self) -> std::io::Result<()> {
        let mut hidden: Vec<(PathBuf, PathBuf)> = Vec::new();
        let restore = |hidden: &[(PathBuf, PathBuf)], tmp: &Path| {
            // Originals first, tmp last: recovery treats a surviving tmp as "the
            // merge never landed", so the tmp must outlive any hidden input.
            for (aside, original) in hidden {
                let _ = std::fs::rename(aside, original);
            }
            let _ = std::fs::remove_file(tmp);
        };

        for input in &self.inputs {
            let aside = hidden_name(input);
            if let Err(e) = std::fs::rename(input, &aside) {
                restore(&hidden, &self.tmp);
                return Err(e);
            }
            hidden.push((aside, input.clone()));
        }

        if let Err(e) = std::fs::rename(&self.tmp, &self.final_path) {
            restore(&hidden, &self.tmp);
            return Err(e);
        }

        // Best-effort: a leftover `.merged` with the merge landed is exactly
        // what recovery deletes on the next pass.
        for (aside, _) in hidden {
            let _ = std::fs::remove_file(aside);
        }
        Ok(())
    }
}

/// Merge a partition's files into a tmp, or `None` when there are too few to
/// bother. Touches nothing a reader can see.
fn prepare(dir: &Path, sequence: u64) -> Result<Option<PendingSwap>, CompactError> {
    let mut inputs = parquet_files(dir);
    if inputs.len() < MIN_FILES {
        return Ok(None);
    }
    // The writer's `<millis hex>-<seq>` stems sort chronologically, so merging
    // in name order keeps rows roughly time-ordered in the merged file.
    inputs.sort();

    // Named like the writer's files but with a `-c` marker, so a merged file can
    // never collide with anything the writer produces.
    let min_ts = inputs
        .iter()
        .filter_map(|p| stem_millis(p))
        .min()
        .unwrap_or(0);
    let stem = format!("{min_ts:013x}-{sequence:06x}-c");
    let tmp = dir.join(format!(".{stem}.compact.tmp"));
    let final_path = dir.join(format!("{stem}.parquet"));

    match merge(&inputs, &tmp, table_of(dir)) {
        Ok(rows) => Ok(Some(PendingSwap {
            dir: dir.to_path_buf(),
            tmp,
            final_path,
            inputs,
            rows,
        })),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Stream every input's batches into one file at `tmp`.
///
/// For a partition under a known table the output schema is that table's
/// current one, and each batch is brought up to it: a column the schema has
/// gained since a file was written (`namespace`, `latency_count`) is filled
/// with nulls, exactly as the query layer reads it. Without that, the first
/// day after a column is appended holds files of two shapes and could never
/// be compacted. Anything else — a column the schema does not have, one
/// whose type changed — still aborts the merge with the partition untouched
/// rather than writing a file that mixes two shapes.
fn merge(inputs: &[PathBuf], tmp: &Path, table: Option<Table>) -> Result<usize, CompactError> {
    let target = table.map(|t| t.schema());
    // Same zstd choice as the writer, for the same reason: scanned far less
    // often than it is written, and smaller is the point.
    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(Default::default()))
        .build();

    let mut writer: Option<ArrowWriter<std::fs::File>> = None;
    let mut rows = 0;
    for input in inputs {
        let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(input)?)?;
        if writer.is_none() {
            let out = std::fs::File::create(tmp)?;
            writer = Some(ArrowWriter::try_new(
                out,
                target.clone().unwrap_or_else(|| reader.schema().clone()),
                Some(props.clone()),
            )?);
        }
        for batch in reader.build()? {
            let mut batch = batch?;
            if let Some(schema) = &target {
                batch = conform(batch, schema)?;
            }
            rows += batch.num_rows();
            writer
                .as_mut()
                .expect("created on the first input")
                .write(&batch)?;
        }
    }
    // Explicit close so the footer is written and any error surfaces while the
    // file is still under its temporary name — the writer's own bargain.
    writer.expect("inputs is never empty").close()?;
    Ok(rows)
}

/// `batch` in exactly `schema`'s shape, with nulls for the nullable columns it
/// predates.
fn conform(
    batch: datafusion::arrow::record_batch::RecordBatch,
    schema: &Arc<datafusion::arrow::datatypes::Schema>,
) -> Result<datafusion::arrow::record_batch::RecordBatch, CompactError> {
    use datafusion::arrow::array::new_null_array;
    use datafusion::arrow::error::ArrowError;

    if batch.schema() == *schema {
        return Ok(batch);
    }
    for field in batch.schema().fields() {
        if schema.field_with_name(field.name()).is_err() {
            return Err(CompactError::Arrow(ArrowError::SchemaError(format!(
                "column {:?} is not in the current schema",
                field.name()
            ))));
        }
    }
    let columns = schema
        .fields()
        .iter()
        .map(|field| match batch.column_by_name(field.name()) {
            Some(column) if column.data_type() == field.data_type() => Ok(column.clone()),
            Some(column) => Err(ArrowError::SchemaError(format!(
                "column {:?} is {} on disk but {} in the schema",
                field.name(),
                column.data_type(),
                field.data_type()
            ))),
            None if field.is_nullable() => Ok(new_null_array(field.data_type(), batch.num_rows())),
            None => Err(ArrowError::SchemaError(format!(
                "required column {:?} is missing",
                field.name()
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(datafusion::arrow::record_batch::RecordBatch::try_new(
        schema.clone(),
        columns,
    )?)
}

/// Which table a partition directory belongs to: the parent of its
/// `deployment=` ancestor. `None` for anything not shaped like the writer's
/// layout, which then merges in its own first file's schema as before.
fn table_of(dir: &Path) -> Option<Table> {
    let deployment = dir.ancestors().find(|a| {
        a.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("deployment="))
    })?;
    match deployment.parent()?.file_name()?.to_str()? {
        "logs" => Some(Table::Logs),
        "metrics" => Some(Table::Metrics),
        _ => None,
    }
}

/// Put a partition directory right after a crash, from names alone.
///
/// A surviving `.compact.tmp` means the merge never became visible, so any
/// hidden inputs are restored and the tmp discarded. Hidden inputs with no tmp
/// mean the merge landed and only the cleanup was cut short, so they go.
fn recover_dir(dir: &Path) -> std::io::Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    let mut tmps = Vec::new();
    let mut hidden = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with(".compact.tmp") {
            tmps.push(path);
        } else if name.ends_with(".parquet.merged") {
            hidden.push(path);
        }
    }

    if tmps.is_empty() {
        for path in hidden {
            std::fs::remove_file(&path)?;
        }
    } else {
        for path in hidden {
            restore_hidden(&path)?;
        }
        for path in tmps {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

/// Rename `x.parquet.merged` back to `x.parquet`, stepping aside if something
/// new already took the name — restoring must never overwrite data.
fn restore_hidden(path: &Path) -> std::io::Result<()> {
    let Some(original) = path
        .to_str()
        .and_then(|p| p.strip_suffix(".merged"))
        .map(PathBuf::from)
    else {
        return Ok(()); // not UTF-8; leave it rather than guess
    };
    let mut target = original.clone();
    let mut n = 0;
    while target.exists() {
        n += 1;
        target = original.with_extension(format!("r{n}.parquet"));
    }
    std::fs::rename(path, &target)
}

/// `x.parquet` → `x.parquet.merged`: invisible to every reader, because both the
/// listing table and `parquet_files` match on the `.parquet` extension.
fn hidden_name(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".merged");
    path.with_file_name(name)
}

/// The writer's `<millis hex>` filename prefix, for naming the merged file.
fn stem_millis(path: &Path) -> Option<i64> {
    let stem = path.file_stem()?.to_str()?;
    i64::from_str_radix(stem.split('-').next()?, 16).ok()
}

/// Every leaf partition directory under the data dir.
///
/// Walks only the names the writer produces — `deployment=`, `date=`, `hour=` —
/// so anything unrecognised is never rewritten, the same caution the retention
/// sweeper applies before deleting.
fn partition_dirs(data_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for table in [Table::Logs, Table::Metrics] {
        let table_dir = data_dir.join(table.name());
        for deployment in subdirs(&table_dir, |n| n.starts_with("deployment=")) {
            for date in subdirs(&deployment, |n| date_from_dir_name(n).is_some()) {
                if table.hourly() {
                    out.extend(subdirs(&date, |n| n.starts_with("hour=")));
                } else {
                    out.push(date);
                }
            }
        }
    }
    out.sort();
    out
}

fn subdirs(dir: &Path, keep: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter(|e| e.file_name().to_str().is_some_and(&keep))
        .map(|e| e.path())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::schema::{LogRecord, MetricRecord, Record};
    use crate::store::writer::Writer;
    use chrono::{TimeZone, Utc};

    /// 2026-07-28T17:34:56Z
    const TS: i64 = 1_785_260_096_000;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "app-obs-compact-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
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

    /// Seed a partition with one file per record, the small-files problem in
    /// miniature — flush_rows of 1 makes every push its own parquet.
    fn seeded(tag: &str, records: usize) -> (PathBuf, PathBuf) {
        let dir = tmpdir(tag);
        let mut writer = Writer::new(&dir, 1, Duration::from_secs(3600));
        for i in 0..records {
            writer
                .push(log("demo", TS + i as i64 * 1000, &format!("line {i}")))
                .unwrap();
        }
        let partition = crate::store::partition::PartitionKey::new(Table::Logs, "demo", TS)
            .unwrap()
            .dir(&dir);
        (dir, partition)
    }

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
    fn many_small_files_become_one_and_every_row_survives() {
        let (dir, partition) = seeded("merge", 5);
        assert_eq!(parquet_files(&partition).len(), 5, "one file per push");

        let swap = prepare(&partition, 1).unwrap().expect("worth merging");
        assert_eq!(swap.rows, 5);
        swap.commit().unwrap();

        let files = parquet_files(&partition);
        assert_eq!(files.len(), 1);
        assert_eq!(read_rows(&partition), 5, "no row lost, none duplicated");
        // Named like the writer's files plus the `-c` marker, so it sorts
        // chronologically and can never collide with a writer flush.
        let name = files[0].file_name().unwrap().to_str().unwrap();
        assert!(name.ends_with("-c.parquet"), "{name}");
        assert!(name.starts_with(&format!("{TS:013x}")), "{name}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A partition holding files written before `namespace` existed and files
    /// written after must still compact, the old rows reading as null.
    #[test]
    fn files_from_before_a_column_was_appended_merge_with_newer_ones() {
        use datafusion::arrow::array::{Array, StringArray, TimestampMillisecondArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema, TimeUnit};

        let (dir, partition) = seeded("legacy-merge", 2);
        // A legacy file: the logs schema as it was, without `namespace`.
        let legacy_schema = Arc::new(Schema::new(
            crate::store::schema::logs_schema()
                .fields()
                .iter()
                .filter(|f| f.name() != "namespace")
                .cloned()
                .collect::<Vec<_>>(),
        ));
        assert_eq!(
            legacy_schema.field(0),
            &Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
                false
            )
        );
        let n = 1;
        let utf8 = |v: Option<&str>| Arc::new(StringArray::from(vec![v; n])) as _;
        let batch = datafusion::arrow::record_batch::RecordBatch::try_new(
            legacy_schema.clone(),
            vec![
                Arc::new(TimestampMillisecondArray::from(vec![TS]).with_timezone("UTC")) as _,
                utf8(Some("sb-old")),
                utf8(Some("stdout")),
                utf8(None),
                utf8(Some("from before namespaces")),
                utf8(None),
                utf8(None),
            ],
        )
        .unwrap();
        let file = std::fs::File::create(partition.join("0000000000000-000000.parquet")).unwrap();
        let mut w = ArrowWriter::try_new(file, legacy_schema, None).unwrap();
        w.write(&batch).unwrap();
        w.close().unwrap();

        let swap = prepare(&partition, 7)
            .unwrap()
            .expect("mixed shapes still merge");
        swap.commit().unwrap();
        let files = parquet_files(&partition);
        assert_eq!(files.len(), 1);
        let reader =
            ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&files[0]).unwrap())
                .unwrap();
        assert!(reader.schema().field_with_name("namespace").is_ok());
        let mut rows = 0;
        let mut nulls = 0;
        for b in reader.build().unwrap() {
            let b = b.unwrap();
            rows += b.num_rows();
            nulls += b.column_by_name("namespace").unwrap().null_count();
        }
        assert_eq!(rows, 3);
        assert_eq!(nulls, 3, "neither seeded nor legacy rows were stamped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_lone_file_is_left_untouched() {
        // A partition already at one file has nothing to gain; rewriting it
        // every pass would be pure write amplification.
        let (dir, partition) = seeded("lone", 1);
        assert!(prepare(&partition, 1).unwrap().is_none());
        assert_eq!(parquet_files(&partition).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_flushed_after_the_input_list_is_taken_survives_the_swap() {
        // The writer keeps flushing while a merge is in flight. Anything it adds
        // after `prepare` is not in the input list and must come through intact.
        let (dir, partition) = seeded("racing", 3);
        let swap = prepare(&partition, 1).unwrap().unwrap();

        let mut writer = Writer::new(&dir, 1, Duration::from_secs(3600));
        writer
            .push(log("demo", TS + 60_000, "late arrival"))
            .unwrap();

        swap.commit().unwrap();
        assert_eq!(parquet_files(&partition).len(), 2, "merged + the late file");
        assert_eq!(read_rows(&partition), 4);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_interrupted_swap_restores_the_originals() {
        // Crash between hiding the inputs and the merge becoming visible: the
        // tmp survives, so recovery must put the inputs back — the merged rows
        // were never visible and the originals are the only copy that was.
        let (dir, partition) = seeded("interrupted", 3);
        let inputs = parquet_files(&partition);
        std::fs::rename(&inputs[0], hidden_name(&inputs[0])).unwrap();
        std::fs::write(partition.join(".0-c.compact.tmp"), b"half-written").unwrap();

        recover_dir(&partition).unwrap();

        assert_eq!(
            parquet_files(&partition).len(),
            3,
            "all inputs visible again"
        );
        assert_eq!(read_rows(&partition), 3);
        assert!(
            !partition.join(".0-c.compact.tmp").exists(),
            "the unfinished merge is discarded",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leftover_hidden_inputs_are_swept_once_the_merge_landed() {
        // Crash between the merge becoming visible and the cleanup: no tmp
        // remains, so the hidden inputs are duplicates of rows the merged file
        // already serves — they go.
        let (dir, partition) = seeded("landed", 3);
        let inputs = parquet_files(&partition);
        prepare(&partition, 1).unwrap().unwrap().commit().unwrap();
        std::fs::write(hidden_name(&inputs[0]), b"stale duplicate").unwrap();

        recover_dir(&partition).unwrap();

        assert_eq!(parquet_files(&partition).len(), 1);
        assert_eq!(read_rows(&partition), 3, "still exactly the merged rows");
        assert!(!hidden_name(&inputs[0]).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_writer_shaped_directories_are_walked() {
        // This code rewrites data, so it gets the retention sweeper's caution:
        // anything it cannot positively identify as a partition is not touched.
        let dir = tmpdir("walk");
        let mut writer = Writer::new(&dir, 1, Duration::from_secs(3600));
        writer.push(log("demo", TS, "a")).unwrap();
        writer
            .push(Record::Metric(MetricRecord {
                ts_millis: TS,
                deployment: "demo".into(),
                cpu_percent: Some(1.0),
                ..Default::default()
            }))
            .unwrap();
        let stray = dir.join("logs/deployment=demo/notes");
        std::fs::create_dir_all(&stray).unwrap();
        std::fs::write(stray.join("keep.parquet"), b"not ours").unwrap();

        let dirs = partition_dirs(&dir);
        assert_eq!(
            dirs,
            vec![
                dir.join("logs/deployment=demo/date=2026-07-28/hour=17"),
                dir.join("metrics/deployment=demo/date=2026-07-28"),
            ],
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn queries_see_the_same_rows_before_and_after_a_pass() {
        // The whole point: compaction changes the file layout and nothing else.
        let (dir, partition) = seeded("engine", 6);
        let engine = Arc::new(Engine::new(&dir, 2, Duration::from_secs(30)).await.unwrap());

        let window = crate::query::Window {
            from: Utc.timestamp_millis_opt(TS - 60_000).single().unwrap(),
            to: Utc.timestamp_millis_opt(TS + 600_000).single().unwrap(),
        };
        let count = |engine: Arc<Engine>| async move {
            let volume = engine
                .log_volume(window, 3600, Some("demo"), None)
                .await
                .unwrap();
            volume["demo"].iter().map(|b| b.lines).sum::<u64>()
        };
        assert_eq!(count(engine.clone()).await, 6);

        let compaction = Compaction::new(&dir, Duration::from_secs(3600), engine.clone());
        let done = compaction.pass().await;
        assert_eq!(done.partitions, 1);
        assert_eq!(done.files_merged, 6);

        assert_eq!(parquet_files(&partition).len(), 1);
        assert_eq!(count(engine).await, 6, "same answer from one file");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
