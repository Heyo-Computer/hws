//! Tiny persistent per-schema registry: `schema -> (sandbox-id, last-active,
//! state)`.
//!
//! When the pooler brings up a VM for a schema it records the sandbox id here
//! and flushes it to disk. On the next bring-up — including after a full pooler
//! restart — it reattaches to *that* VM by id instead of finding one by name.
//! That closes a data-loss race: a VM that was just stopped is briefly absent
//! from list-by-name, and reattaching by name in that window would create a
//! duplicate VM with a fresh, empty data disk. The schema (the client's db name)
//! is the key, so the file records both the db name and its VM.
//!
//! Two more fields drive the S3 eviction tier:
//!   - `last_active`: unix seconds of the last client checkout. This survives
//!     the VM leaving the warm map (idle-stop), so the hourly archive sweep can
//!     find schemas untouched for a week even though their VM is already
//!     stopped — the in-memory `SchemaEntry::last_active` is gone by then.
//!   - `state`: the storage tier — `live`, `frozen` (VM killed, data in a
//!     local dump file), or `archived` (data only in S3). Both offloaded tiers
//!     mean the next checkout must restore before serving.
//!
//! A fifth field, `disk_gb`, is what makes a dump-tier restore survivable for a
//! schema whose data device had grown: the VM that held it is deleted at
//! offload time, so without a durable note of how big that device was, the
//! restore builds the default-size one and `pg_restore` fills it (see
//! [`Store::set_disk_gb`]).
//!
//! The sixth and seventh, `bringup_ms` and `bringup_kind`, are diagnostics
//! only: how long this schema's last client bring-up took and what it was (a
//! fresh create, a spare claim, a reattach, or one of the restores — see
//! [`BringupKind`]). Nothing reads them back to make a decision; they are the
//! per-VM answer to "how long did this one take to come up", which the
//! aggregate timing charts can't give (see [`Store::set_bringup`]).
//!
//! Format: one
//! `schema\tsandbox_id\tlast_active_unix\tstate\tdisk_gb\tbringup_ms\tbringup_kind`
//! line per entry. Older 2-column files (`schema\tsandbox_id`) still parse: the
//! missing `last_active` defaults to *load time* (so an upgrade doesn't make
//! every pre-existing schema instantly eligible for eviction), state to `live`,
//! `disk_gb` to `0` ("unknown — use the configured default"), and the bring-up
//! fields to "never recorded". Trailing fields are ignored positionally, so an
//! older binary reads a 7-column file fine.
//! Schema names are validated upstream to contain no control chars (so never a
//! tab or newline), so this needs no escaping.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tracing::{info, warn};

/// `touch()`/`put()` bump `last_active` in memory on every client checkout;
/// the [`Store::flush_dirty`] loop persists the whole map at most this often
/// when anything changed. The sweep reads the in-memory value, so disk
/// freshness only matters across a pooler restart, where seconds of staleness
/// are harmless against hour-long thresholds. A **global** debounce, not
/// per-schema: at 20k+ registry rows a serialize is O(rows), and the old
/// per-schema debounce made a storm of *distinct* schemas serialize the whole
/// map once per schema — the exact load spike a storm shouldn't amplify.
/// Mapping changes (a new/changed schema→VM binding) still flush immediately:
/// losing one to a crash would strand a served schema, not just age a clock.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Where a schema's data currently lives — the storage tier ladder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    /// A VM (running or merely stopped) holds the data on its disk.
    Live,
    /// The VM (and its disk) was deleted; the data lives as a trimmed,
    /// zstd-compressed raw disk image under the pooler's compact dir — a
    /// stopped schema at a fraction of its ext4 footprint (~5-25x smaller),
    /// thawed by decompressing onto a fresh VM's disk: no boot at compact
    /// time, no pg_restore at thaw time. The next checkout materializes it.
    Compacted,
    /// The VM was killed; the data lives in a local dump file under the
    /// pooler's dump dir. The next checkout restores from it.
    Frozen,
    /// The data lives only in S3. The next checkout restores from there.
    Archived,
}

impl Tier {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Tier::Live => "live",
            Tier::Compacted => "compacted",
            Tier::Frozen => "frozen",
            Tier::Archived => "archived",
        }
    }

    // NOTE: an older binary reading a registry with "compacted" rows parses
    // them as Live (the historical default) — the schema then looks live with
    // no VM, and the next connect builds a fresh empty one while the compact
    // file still holds the data. Don't roll back across this without first
    // thawing (or manually decompressing) compacted schemas.
    fn parse(s: &str) -> Tier {
        match s {
            "archived" => Tier::Archived,
            "frozen" => Tier::Frozen,
            "compacted" => Tier::Compacted,
            _ => Tier::Live,
        }
    }
}

/// What a schema's last client bring-up had to do to get a serving Postgres.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BringupKind {
    /// A brand-new VM was created for the schema.
    Create,
    /// A warm spare was claimed off the pool.
    Spare,
    /// The schema's own VM was found (by id or name) and started or reused.
    Reattach,
    /// A fresh VM, then `pg_restore` of the schema's S3 dump into it.
    RestoreS3Dump,
    /// The schema's S3 disk image was downloaded and booted.
    RestoreS3Image,
    /// A fresh VM, then `pg_restore` of the local frozen dump into it.
    RestoreLocalDump,
    /// The local compacted image was decompressed and booted.
    ThawCompacted,
}

impl BringupKind {
    /// Stable on-disk token — part of the registry format, never rename.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            BringupKind::Create => "create",
            BringupKind::Spare => "spare",
            BringupKind::Reattach => "reattach",
            BringupKind::RestoreS3Dump => "restore_s3_dump",
            BringupKind::RestoreS3Image => "restore_s3_image",
            BringupKind::RestoreLocalDump => "restore_local_dump",
            BringupKind::ThawCompacted => "thaw_compacted",
        }
    }

    /// Unknown tokens (a newer binary's) parse to `None`: it's a diagnostic,
    /// never worth dropping the row over.
    fn parse(s: &str) -> Option<Self> {
        match s {
            "create" => Some(BringupKind::Create),
            "spare" => Some(BringupKind::Spare),
            "reattach" => Some(BringupKind::Reattach),
            "restore_s3_dump" => Some(BringupKind::RestoreS3Dump),
            "restore_s3_image" => Some(BringupKind::RestoreS3Image),
            "restore_local_dump" => Some(BringupKind::RestoreLocalDump),
            "thaw_compacted" => Some(BringupKind::ThawCompacted),
            _ => None,
        }
    }
}

/// How long one bring-up took to reach a serving Postgres, and what it was.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bringup {
    pub kind: BringupKind,
    /// Milliseconds from clearing the admission queue to a serving Postgres —
    /// the same span as `SchemaEntry`'s `bringup_took`, queue wait excluded.
    pub took_ms: u64,
}

/// A durable, owned view of one schema's registry entry.
#[derive(Clone)]
pub struct StoreRecord {
    pub sandbox_id: String,
    /// Unix seconds of the last client checkout for this schema.
    pub last_active: u64,
    /// Storage tier: whether a VM disk, a local dump, or S3 holds the data.
    pub tier: Tier,
    /// Size in GiB of the data device this schema last had, or `0` when it was
    /// never observed. Read when a restore has to *build* the VM: the data
    /// fitted in a device this big before it was offloaded, and the default
    /// (`PG_VM_POOL_DATA_DISK_GB`) is a starting size, not a promise that the
    /// schema still fits in one.
    pub disk_gb: u32,
    /// The schema's last client bring-up, `None` when none was recorded.
    pub bringup: Option<Bringup>,
}

impl StoreRecord {
    /// The VM is gone and a restore (local or S3) is needed before serving.
    pub fn offloaded(&self) -> bool {
        self.tier != Tier::Live
    }
}

/// Internal map value backing a [`StoreRecord`].
#[derive(Clone)]
struct Rec {
    sandbox_id: String,
    last_active: u64,
    tier: Tier,
    disk_gb: u32,
    bringup: Option<Bringup>,
}

impl Rec {
    fn view(&self) -> StoreRecord {
        StoreRecord {
            sandbox_id: self.sandbox_id.clone(),
            last_active: self.last_active,
            tier: self.tier,
            disk_gb: self.disk_gb,
            bringup: self.bringup,
        }
    }
}

pub struct Store {
    path: PathBuf,
    map: Mutex<HashMap<String, Rec>>,
    /// Monotone snapshot generation, assigned under the `map` lock when a
    /// snapshot is produced. The writer refuses to write a generation older
    /// than the newest already written, so out-of-order write tasks can never
    /// roll the file back to a stale snapshot.
    seq: AtomicU64,
    /// Serializes the actual file writes and remembers the newest generation
    /// written. Deliberately separate from `map`: the write path fsyncs, and
    /// on a saturated disk that stalls for seconds — it must never hold up
    /// readers or in-memory updates. `Arc` so write closures can own it.
    written: Arc<Mutex<u64>>,
    /// In-memory state is newer than the file — the [`Self::flush_dirty`] loop
    /// owes a write. Set by the activity-bump paths, which no longer serialize.
    dirty: AtomicBool,
    /// Cached set of every bound `sandbox_id`, rebuilt lazily after a mapping
    /// change. `bound_ids()` is on the cold-checkout hot path (the spare-claim
    /// safety check) — without the cache every checkout re-scanned all rows.
    bound_cache: Mutex<Option<Arc<HashSet<String>>>>,
}

impl Store {
    /// Load the store from `path`. A missing file starts empty; a partially
    /// corrupt file keeps whatever lines parse (never fatal — a lost mapping
    /// only costs us a find-by-name on next connect).
    pub fn load(path: PathBuf) -> Self {
        let now = now_unix();
        let map = match std::fs::read_to_string(&path) {
            Ok(s) => parse(&s, now),
            Err(_) => HashMap::new(),
        };
        if !map.is_empty() {
            info!(
                "loaded {} schema→VM mapping(s) from {}",
                map.len(),
                path.display()
            );
        }
        Store {
            path,
            map: Mutex::new(map),
            seq: AtomicU64::new(0),
            written: Arc::new(Mutex::new(0)),
            dirty: AtomicBool::new(false),
            bound_cache: Mutex::new(None),
        }
    }

    /// Stamp a freshly serialized snapshot with the next generation. Must be
    /// called while the `map` lock is held, so generation order matches
    /// snapshot content order.
    fn stamp(&self, snapshot: String) -> (u64, String) {
        (self.seq.fetch_add(1, Ordering::SeqCst) + 1, snapshot)
    }

    /// The full durable record for `schema`, if any.
    pub fn record(&self, schema: &str) -> Option<StoreRecord> {
        self.map.lock().unwrap().get(schema).map(Rec::view)
    }

    /// How many schemas are on the live tier — data on a VM disk rather than
    /// offloaded to a dump, a compacted image or S3.
    ///
    /// Counted under the lock without cloning, because the idle reaper reads
    /// it every pass to size its drain rate ([`crate::registry`]'s
    /// `drain_allowance`) and [`Self::records`] would clone the whole map for
    /// a number. Deliberately *not* "how many VMs are running": stopping a VM
    /// does not change its tier, so this stays constant while a cohort drains
    /// — which is exactly what makes the drain a constant slope instead of a
    /// decaying one.
    pub fn live_count(&self) -> usize {
        self.map
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.tier == Tier::Live)
            .count()
    }

    /// Every `(schema, record)` known to the store — the durable list of schemas
    /// the pooler has backed, including those whose VM is stopped or archived.
    pub fn records(&self) -> Vec<(String, StoreRecord)> {
        self.map
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.view()))
            .collect()
    }

    /// Record `schema -> id` (a fresh, live VM) and flush to disk. Refreshes
    /// `last_active` and resets the tier to [`Tier::Live`]. Best-effort: a
    /// write failure is logged, not fatal. Skips the write when the mapping is
    /// unchanged and still live (then it behaves like a debounced `touch`).
    pub fn put(&self, schema: &str, id: &str) {
        let now = now_unix();
        let snapshot = {
            let mut map = self.map.lock().unwrap();
            match map.get_mut(schema) {
                Some(r) if r.sandbox_id == id && r.tier == Tier::Live => {
                    // Unchanged live mapping: an activity bump. The flush loop
                    // persists it (see FLUSH_INTERVAL) — no O(rows) serialize
                    // on the checkout path.
                    r.last_active = now;
                    self.dirty.store(true, Ordering::Relaxed);
                    None
                }
                _ => {
                    // A new or changed binding flushes immediately: this is
                    // what makes a served schema findable after a crash.
                    // `disk_gb` is carried across the rebinding — a restore
                    // that just built a right-sized VM would otherwise forget
                    // the size on the very write that records it. A stale
                    // value only ever over-provisions the next restore, and
                    // the next idle-stop sample corrects it.
                    // The bring-up record is carried too, until the caller's
                    // `set_bringup` replaces it.
                    let prev = map.get(schema);
                    let disk_gb = prev.map(|r| r.disk_gb).unwrap_or(0);
                    let bringup = prev.and_then(|r| r.bringup);
                    map.insert(
                        schema.to_string(),
                        Rec {
                            sandbox_id: id.to_string(),
                            last_active: now,
                            tier: Tier::Live,
                            disk_gb,
                            bringup,
                        },
                    );
                    *self.bound_cache.lock().unwrap() = None;
                    Some(self.stamp(serialize(&map)))
                }
            }
        };
        self.write_detached(snapshot);
    }

    /// Commit a handoff binding, or fail without publishing it in memory.
    /// The caller must hold its database operation lock and keep admission
    /// closed until its handoff journal acknowledges this commit. Retrying an
    /// already-committed candidate is allowed; an unrelated binding is not.
    ///
    /// Unlike ordinary activity writes, this rare operation holds the map
    /// across fsync to prevent another snapshot from racing the binding. Run
    /// it on a blocking thread. Errors after rename have an unknown durable
    /// outcome, so they must retain the handoff fence and be retried.
    pub fn commit_handoff_binding(&self, schema: &str, expected: &str, candidate: &str) -> Result<()> {
        let mut map = self.map.lock().unwrap();
        let current = map.get(schema).context("handoff database has no serving binding")?;
        anyhow::ensure!(current.tier == Tier::Live, "handoff binding is not live");
        anyhow::ensure!(current.sandbox_id == expected || current.sandbox_id == candidate,
            "handoff serving binding changed");
        let mut next = map.clone();
        next.get_mut(schema).unwrap().sandbox_id = candidate.to_string();
        let (seq, contents) = self.stamp(serialize(&next));
        let mut newest = self.written.lock().unwrap();
        write_atomic(&self.path, &contents)?;
        let parent = self.path.parent().filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent)?.sync_all().context("fsync handoff binding directory")?;
        *newest = seq;
        *map = next;
        drop(newest);
        drop(map);
        *self.bound_cache.lock().unwrap() = None;
        Ok(())
    }

    /// Durably rekey a complete serving binding. A retry after the durable
    /// rename observes `new` and succeeds; two extant keys are a collision.
    pub fn rename_database(&self, old: &str, new: &str) -> Result<()> {
        let mut map = self.map.lock().unwrap();
        if map.contains_key(new) {
            anyhow::ensure!(
                !map.contains_key(old),
                "cannot rename database {old:?}: {new:?} already has a binding"
            );
            return Ok(());
        }
        let mut next = map.clone();
        let record = next
            .remove(old)
            .context("rename database has no serving binding")?;
        next.insert(new.to_string(), record);
        self.commit_maintenance_snapshot(&mut map, next, "fsync database rename directory")
    }

    /// Remove exactly the expected live serving binding. Missing is an
    /// idempotent success; a changed or offloaded binding is never retired.
    pub fn retire_database(&self, database: &str, expected_vm: &str) -> Result<()> {
        let mut map = self.map.lock().unwrap();
        let Some(current) = map.get(database) else {
            return Ok(());
        };
        anyhow::ensure!(current.tier == Tier::Live, "retirement binding is not live");
        anyhow::ensure!(
            current.sandbox_id == expected_vm,
            "retirement serving binding changed"
        );
        let mut next = map.clone();
        next.remove(database);
        self.commit_maintenance_snapshot(&mut map, next, "fsync database retirement directory")
    }

    fn commit_maintenance_snapshot(
        &self,
        map: &mut HashMap<String, Rec>,
        next: HashMap<String, Rec>,
        sync_context: &str,
    ) -> Result<()> {
        let (seq, contents) = self.stamp(serialize(&next));
        let mut newest = self.written.lock().unwrap();
        write_atomic(&self.path, &contents)?;
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent)?
            .sync_all()
            .context(sync_context.to_string())?;
        *newest = seq;
        *map = next;
        drop(newest);
        *self.bound_cache.lock().unwrap() = None;
        Ok(())
    }

    /// Bind `schema` to the archived tier so the next checkout restores it from
    /// S3, **creating the row when none exists**.
    ///
    /// The recovery case this exists for: a workbook whose archive is sitting
    /// in S3 but which this server has no record of at all — a registry lost
    /// to a rollback, a host rebuild, a row that never landed. Neither
    /// existing entry point covers it: [`Self::set_tier`] returns early on a
    /// missing row, and [`Self::put`] writes `Tier::Live` and demands a VM id.
    /// Without this the schema is unrecoverable through the pooler: every
    /// connect creates a fresh empty database beside an archive nothing reads.
    ///
    /// A newly created row carries a synthetic `sandbox_id`, and it matters
    /// that it is neither empty nor plausible. Empty is fatal: [`parse`] drops
    /// any line whose id field is blank, so a blank placeholder would work
    /// until the next pooler restart and then vanish without a trace.
    /// Plausible is worse: anything shaped like `sb-<hex>` invites some future
    /// sweep to go looking for a directory that was never there. The id is
    /// inert in every consumer — an archived row's id is never dialled,
    /// because the checkout path forces `known_id` to `None` whenever it
    /// chooses a restore source, and it matches no `sb-*` directory the orphan
    /// sweep scans.
    ///
    /// Returns the record it replaced, so the caller can tell an operator
    /// whether this repaired a row or invented one.
    pub async fn adopt_archived(&self, schema: &str) -> Option<StoreRecord> {
        let (prev, snapshot) = {
            let mut map = self.map.lock().unwrap();
            let prev = map.get(schema).map(Rec::view);
            // Keep the existing binding when repairing a row: it is the only
            // remaining pointer to whatever VM was serving this schema, and an
            // operator reading registry.tsv afterwards should still see it.
            let sandbox_id = prev
                .as_ref()
                .map(|r| r.sandbox_id.clone())
                .unwrap_or_else(|| format!("{ADOPTED_ID_PREFIX}{schema}"));
            let last_active = prev.as_ref().map(|r| r.last_active).unwrap_or_else(now_unix);
            let disk_gb = prev.as_ref().map(|r| r.disk_gb).unwrap_or(0);
            map.insert(
                schema.to_string(),
                Rec {
                    sandbox_id,
                    last_active,
                    tier: Tier::Archived,
                    disk_gb,
                    bringup: prev.as_ref().and_then(|r| r.bringup),
                },
            );
            *self.bound_cache.lock().unwrap() = None;
            (prev, self.stamp(serialize(&map)))
        };
        let (seq, contents) = snapshot;
        let path = self.path.clone();
        let written = self.written.clone();
        // Durable before returning, unlike the debounced `put`/`touch` path:
        // this is a hand-repaired row an operator is about to act on, and
        // losing it to a crash would silently undo the recovery.
        if let Err(e) =
            tokio::task::spawn_blocking(move || write_latest(&path, &written, seq, &contents)).await
        {
            warn!(
                "persisting the adopted archive row to {} did not complete: {e}",
                self.path.display()
            );
        }
        prev
    }

    /// The set of every `sandbox_id` bound to some schema, cached across calls
    /// and rebuilt only after a mapping change. Cheap enough for the checkout
    /// path (an `Arc` clone in the common case).
    pub fn bound_ids(&self) -> Arc<HashSet<String>> {
        let mut cache = self.bound_cache.lock().unwrap();
        if let Some(set) = cache.as_ref() {
            return set.clone();
        }
        let set = Arc::new(
            self.map
                .lock()
                .unwrap()
                .values()
                .map(|r| r.sandbox_id.clone())
                .collect::<HashSet<String>>(),
        );
        *cache = Some(set.clone());
        set
    }

    /// Persist the map if any activity bump landed since the last flush — the
    /// body of the global debounce loop (see [`FLUSH_INTERVAL`]). One O(rows)
    /// serialize per interval max, however many schemas were touched.
    pub fn flush_dirty(&self) {
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return;
        }
        let snapshot = {
            let map = self.map.lock().unwrap();
            Some(self.stamp(serialize(&map)))
        };
        self.write_detached(snapshot);
    }

    /// Bump `last_active` for `schema` to now (in memory); the flush loop
    /// persists it within [`FLUSH_INTERVAL`]. No-op if the schema isn't known.
    pub fn touch(&self, schema: &str) {
        let now = now_unix();
        let mut map = self.map.lock().unwrap();
        let Some(r) = map.get_mut(schema) else {
            return;
        };
        r.last_active = now;
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Record the size (GiB) of `schema`'s data device. No-op when the schema
    /// isn't known or the value is unchanged.
    ///
    /// This is the one fact about an offloaded schema that cannot be
    /// recovered after the fact: the dump tiers delete the VM, and a dump
    /// carries no record of the device it came off. Restoring one into a
    /// freshly created VM — which is sized `PG_VM_POOL_DATA_DISK_GB`, the
    /// *starting* size for a brand-new schema — is how a schema that had grown
    /// its device comes back into a device too small to hold it, fills it
    /// mid-`pg_restore`, and leaves a half-loaded cluster behind.
    ///
    /// Deliberately debounced (like [`Self::touch`]) rather than fsync'd: the
    /// offload paths call this immediately before [`Self::set_tier`], whose
    /// durable write serializes the same map — so the value that matters is on
    /// disk before the VM it describes is killed, without a second fsync on
    /// the idle-stop path that also records it.
    pub fn set_disk_gb(&self, schema: &str, disk_gb: u32) {
        let mut map = self.map.lock().unwrap();
        let Some(r) = map.get_mut(schema) else {
            return;
        };
        if r.disk_gb == disk_gb {
            return;
        }
        r.disk_gb = disk_gb;
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Record how long `schema`'s latest bring-up took and what kind it was.
    /// No-op when the schema isn't known or the value is unchanged.
    ///
    /// A lazy write, like [`Self::touch`]: it only marks the map dirty, and the
    /// [`Self::flush_dirty`] loop persists it within [`FLUSH_INTERVAL`]. This
    /// runs on the cold-checkout path right after [`Self::put`], and a
    /// diagnostic is not worth a second O(rows) serialize there; losing one to
    /// a crash costs nothing but the number.
    pub fn set_bringup(&self, schema: &str, bringup: Bringup) {
        let mut map = self.map.lock().unwrap();
        let Some(r) = map.get_mut(schema) else {
            return;
        };
        if r.bringup == Some(bringup) {
            return;
        }
        r.bringup = Some(bringup);
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Move `schema` to an offloaded tier ([`Tier::Frozen`] or
    /// [`Tier::Archived`]) and flush. The tier is *reset* to live by
    /// [`Self::put`] when a fresh VM id is recorded after a restore — that's
    /// the same event that makes the data live again.
    ///
    /// Unlike `put`/`touch` this **waits for the write to reach disk**: the
    /// caller kills the VM (or deletes the local dump) right after, and the
    /// tier must be durable *before* that — a crash in between with the tier
    /// unwritten would leave a "live" record pointing at a dead VM, and the
    /// next connect would build a fresh empty database instead of restoring.
    pub async fn set_tier(&self, schema: &str, tier: Tier) {
        let snapshot = {
            let mut map = self.map.lock().unwrap();
            let Some(r) = map.get_mut(schema) else {
                return;
            };
            r.tier = tier;
            self.stamp(serialize(&map))
        };
        let (seq, contents) = snapshot;
        let path = self.path.clone();
        let written = self.written.clone();
        let res =
            tokio::task::spawn_blocking(move || write_latest(&path, &written, seq, &contents))
                .await;
        if let Err(e) = res {
            warn!(
                "persisting archived flag to {} did not complete: {e}",
                self.path.display()
            );
        }
    }

    /// Queue a stamped snapshot for writing without blocking this thread on
    /// disk I/O. The write (create + fsync + rename) runs on the blocking
    /// pool — an fsync stalled behind heavy writeback must never pin an async
    /// worker thread, or enough of them starve the whole runtime (the
    /// "dashboard times out during sweeps" failure). Best-effort by design:
    /// `put`/`touch` losing their last write to a crash only costs a
    /// find-by-name or a slightly stale idle clock on the next boot.
    /// Generation stamping keeps concurrent writes from ever regressing the
    /// file. Outside a tokio runtime (unit tests, sync callers) it writes
    /// inline.
    fn write_detached(&self, snapshot: Option<(u64, String)>) {
        let Some((seq, contents)) = snapshot else {
            return;
        };
        let path = self.path.clone();
        let written = self.written.clone();
        let write = move || write_latest(&path, &written, seq, &contents);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(write);
            }
            Err(_) => write(),
        }
    }
}

/// Write `contents` (generation `seq`) unless a newer generation has already
/// been written. Holds the `written` lock across the write so writers
/// serialize; on success records the generation, on failure logs and leaves
/// the previous generation in place (a later snapshot will retry the state).
fn write_latest(path: &Path, written: &Mutex<u64>, seq: u64, contents: &str) {
    let mut newest = written.lock().unwrap();
    if seq <= *newest {
        return;
    }
    match write_atomic(path, contents) {
        Ok(()) => *newest = seq,
        Err(e) => warn!("failed to persist pooler registry to {}: {e:#}", path.display()),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse the TSV, tolerating the legacy 2-column format. `now` fills in a
/// missing `last_active` so upgraded entries start their eviction clock fresh.
/// Prefix for the synthetic `sandbox_id` on a row created by
/// [`Store::adopt_archived`]. Deliberately unlike a real sandbox id (`sb-…`)
/// so it reads as "no VM yet" to a human scanning registry.tsv, and so no
/// sweep keyed on the `sb-` shape ever mistakes it for a directory.
const ADOPTED_ID_PREFIX: &str = "pending-restore-";

fn parse(s: &str, now: u64) -> HashMap<String, Rec> {
    s.lines()
        .filter_map(|line| {
            let mut f = line.split('\t');
            let schema = f.next()?;
            let id = f.next()?;
            if schema.is_empty() || id.is_empty() {
                return None;
            }
            let last_active = f.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(now);
            let tier = Tier::parse(f.next().unwrap_or("live"));
            // Absent (pre-upgrade row) or unparseable ⇒ 0 ⇒ "unknown", which
            // every consumer reads as "use the configured default size".
            let disk_gb = f.next().and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
            // Both halves or neither: a duration without its kind can't be
            // read against anything.
            let took_ms = f.next().and_then(|v| v.parse::<u64>().ok());
            let kind = f.next().and_then(BringupKind::parse);
            let bringup = took_ms
                .zip(kind)
                .map(|(took_ms, kind)| Bringup { kind, took_ms });
            Some((
                schema.to_string(),
                Rec {
                    sandbox_id: id.to_string(),
                    last_active,
                    tier,
                    disk_gb,
                    bringup,
                },
            ))
        })
        .collect()
}

fn serialize(map: &HashMap<String, Rec>) -> String {
    let mut out = String::new();
    for (k, v) in map {
        let state = v.tier.as_str();
        out.push_str(k);
        out.push('\t');
        out.push_str(&v.sandbox_id);
        out.push('\t');
        out.push_str(&v.last_active.to_string());
        out.push('\t');
        out.push_str(state);
        out.push('\t');
        out.push_str(&v.disk_gb.to_string());
        // Omitted rather than written blank when never recorded, so such a
        // row stays byte-identical to the 5-column format.
        if let Some(b) = v.bringup {
            out.push('\t');
            out.push_str(&b.took_ms.to_string());
            out.push('\t');
            out.push_str(b.kind.as_str());
        }
        out.push('\n');
    }
    out
}

/// Write via a temp file + rename so a crash mid-write can't corrupt the store.
fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A row adopted by [`Store::adopt_archived`] must survive a write/read
    /// round-trip. This is the whole reason its placeholder id is a non-empty
    /// string: [`parse`] silently drops any line whose id field is blank, so a
    /// blank placeholder would look fine in memory and then disappear on the
    /// next pooler restart — taking the operator's recovery with it, and
    /// leaving a workbook that once again builds an empty database on connect.
    #[test]
    fn adopted_rows_survive_a_registry_round_trip() {
        let mut map = HashMap::new();
        map.insert(
            "wb1".to_string(),
            Rec {
                sandbox_id: format!("{ADOPTED_ID_PREFIX}wb1"),
                last_active: 1_700_000_000,
                tier: Tier::Archived,
                disk_gb: 8,
                bringup: None,
            },
        );
        let back = parse(&serialize(&map), 0);
        let r = back.get("wb1").expect("an adopted row must survive a round-trip");
        assert_eq!(r.tier, Tier::Archived, "the tier is the whole point of the row");
        assert_eq!(r.last_active, 1_700_000_000);
        assert_eq!(
            r.disk_gb, 8,
            "the device size must survive too — it is the only surviving record of how big a \
             restore's VM has to be"
        );

        // The failure this guards against, stated directly.
        let mut blank = HashMap::new();
        blank.insert(
            "wb2".to_string(),
            Rec {
                sandbox_id: String::new(),
                last_active: 0,
                tier: Tier::Archived,
                disk_gb: 0,
                bringup: None,
            },
        );
        assert!(
            parse(&serialize(&blank), 0).is_empty(),
            "parse drops a blank sandbox_id — an adopted row's placeholder must never be empty"
        );

        // And it must not be mistakable for a real VM directory.
        assert!(
            !ADOPTED_ID_PREFIX.starts_with("sb-"),
            "a placeholder shaped like a sandbox id invites a sweep to hunt for a directory \
             that never existed"
        );
    }

    fn tmp_store(tag: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("pg-fc-store-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Store::load(dir.join("registry.tsv"))
    }

    #[test]
    fn handoff_binding_is_durable_idempotent_and_rejects_stale_writes() {
        let store = tmp_store("handoff");
        store.put("a", "sb-old");
        store.put("other", "sb-unrelated");
        store.set_disk_gb("a", 13);
        let stale = store.stamp(serialize(&store.map.lock().unwrap()));
        assert!(store.bound_ids().contains("sb-old"));
        store.commit_handoff_binding("a", "sb-old", "sb-candidate").unwrap();
        write_latest(&store.path, &store.written, stale.0, &stale.1);
        store.commit_handoff_binding("a", "sb-old", "sb-candidate").unwrap();
        assert!(store.commit_handoff_binding("a", "sb-old", "sb-wrong").is_err());
        assert!(store.commit_handoff_binding("missing", "sb-old", "sb-candidate").is_err());
        let loaded = Store::load(store.path.clone());
        let record = loaded.record("a").unwrap();
        assert_eq!(record.sandbox_id, "sb-candidate");
        assert_eq!(record.disk_gb, 13);
        assert_eq!(loaded.record("other").unwrap().sandbox_id, "sb-unrelated");
        assert!(store.bound_ids().contains("sb-candidate"));
        assert!(!store.bound_ids().contains("sb-old"));
    }

    #[test]
    fn rename_and_retire_are_durable_exact_and_preserve_metadata() {
        let store = tmp_store("maintenance");
        store.put("old", "sb-1");
        store.set_disk_gb("old", 17);
        store.put("occupied", "sb-2");
        assert!(store.rename_database("old", "occupied").is_err());
        assert_eq!(store.record("old").unwrap().sandbox_id, "sb-1");
        store.rename_database("old", "new").unwrap();
        store.rename_database("old", "new").unwrap();
        let loaded = Store::load(store.path.clone());
        assert_eq!(loaded.record("new").unwrap().disk_gb, 17);
        assert_eq!(loaded.record("new").unwrap().sandbox_id, "sb-1");
        assert!(store.retire_database("new", "wrong").is_err());
        assert!(store.record("new").is_some());
        store.retire_database("new", "sb-1").unwrap();
        store.retire_database("new", "sb-1").unwrap();
        assert!(Store::load(store.path.clone()).record("new").is_none());
    }

    #[test]
    fn handoff_persistence_failure_does_not_publish_the_candidate() {
        let store = tmp_store("handoff-failure");
        store.put("a", "sb-old");
        let backup = store.path.with_extension("backup");
        std::fs::rename(&store.path, &backup).unwrap();
        std::fs::create_dir(&store.path).unwrap();
        assert!(store.commit_handoff_binding("a", "sb-old", "sb-candidate").is_err());
        assert_eq!(store.record("a").unwrap().sandbox_id, "sb-old");
        assert_eq!(Store::load(backup).record("a").unwrap().sandbox_id, "sb-old");
        std::fs::remove_dir(&store.path).unwrap();
        store.commit_handoff_binding("a", "sb-old", "sb-candidate").unwrap();
        assert_eq!(Store::load(store.path.clone()).record("a").unwrap().sandbox_id, "sb-candidate");
    }

    #[test]
    fn bound_ids_cache_tracks_mapping_changes() {
        let store = tmp_store("bound");
        assert!(store.bound_ids().is_empty());
        store.put("a", "sb-1");
        store.put("b", "sb-2");
        let set = store.bound_ids();
        assert!(set.contains("sb-1") && set.contains("sb-2"));
        // Rebinding a schema swaps its id out of the set.
        store.put("a", "sb-9");
        let set = store.bound_ids();
        assert!(set.contains("sb-9") && !set.contains("sb-1"));
        // An unchanged-mapping put (activity bump) must not clear the cache —
        // same Arc handed back.
        let before = store.bound_ids();
        store.put("a", "sb-9");
        assert!(Arc::ptr_eq(&before, &store.bound_ids()));
    }

    #[test]
    fn activity_bumps_flush_via_flush_dirty_not_inline() {
        let store = tmp_store("dirty");
        store.put("a", "sb-1"); // mapping change: writes inline (no runtime)
        assert!(store.path.exists());
        // Wipe the file; a pure activity bump must NOT rewrite it inline...
        std::fs::remove_file(&store.path).unwrap();
        store.touch("a");
        store.put("a", "sb-1"); // unchanged mapping = bump, not a write
        assert!(!store.path.exists(), "activity bump wrote inline");
        // ...but the flush loop's body persists it once, and only when dirty.
        store.flush_dirty();
        assert!(store.path.exists(), "flush_dirty did not write");
        std::fs::remove_file(&store.path).unwrap();
        store.flush_dirty(); // not dirty anymore: stays clean
        assert!(!store.path.exists(), "flush_dirty wrote while clean");
    }

    /// The device size is the one fact about an offloaded schema that cannot
    /// be recovered later — the VM that had it is deleted — so every path that
    /// rewrites a row has to carry it, and a pre-upgrade file has to read as
    /// "unknown" rather than as "zero GiB".
    #[test]
    fn the_recorded_device_size_survives_rebinding_and_upgrades() {
        let store = tmp_store("diskgb");
        store.put("wb", "sb-1");
        assert_eq!(store.record("wb").unwrap().disk_gb, 0, "unknown until observed");

        store.set_disk_gb("wb", 16);
        assert_eq!(store.record("wb").unwrap().disk_gb, 16);

        // A restore rebinds the schema to the VM it just built. That write
        // must not drop the size the same restore was sized from.
        store.put("wb", "sb-2");
        assert_eq!(
            store.record("wb").unwrap().disk_gb,
            16,
            "rebinding dropped the device size — the next restore would build the default"
        );

        // Unknown schemas are a no-op, not a panic or an invented row.
        store.set_disk_gb("never-seen", 8);
        assert!(store.record("never-seen").is_none());

        // A registry written by an older pooler carries no fifth column.
        let legacy = parse("wb1\tsb-1\t1700000000\tarchived\n", 999);
        assert_eq!(
            legacy.get("wb1").unwrap().disk_gb,
            0,
            "a pre-upgrade row must read as unknown, which every consumer floors at the default"
        );
    }

    /// The bring-up columns round-trip, and a row without them serializes to
    /// exactly the 5-column format an older binary wrote.
    #[test]
    fn bringup_columns_round_trip_and_stay_optional() {
        let mut map = HashMap::new();
        let bringup = Bringup {
            kind: BringupKind::RestoreS3Image,
            took_ms: 4_321,
        };
        map.insert(
            "wb1".to_string(),
            Rec {
                sandbox_id: "sb-1".to_string(),
                last_active: 1_700_000_000,
                tier: Tier::Live,
                disk_gb: 4,
                bringup: Some(bringup),
            },
        );
        let line = serialize(&map);
        assert_eq!(
            line,
            "wb1\tsb-1\t1700000000\tlive\t4\t4321\trestore_s3_image\n"
        );
        assert_eq!(parse(&line, 0).get("wb1").unwrap().bringup, Some(bringup));

        map.get_mut("wb1").unwrap().bringup = None;
        assert_eq!(serialize(&map), "wb1\tsb-1\t1700000000\tlive\t4\n");

        // A kind this binary doesn't know (a newer one's) drops the diagnostic,
        // never the row.
        let r = parse("wb1\tsb-1\t1700000000\tlive\t4\t99\tteleport\n", 0);
        let r = r
            .get("wb1")
            .expect("an unknown bring-up kind must not drop the row");
        assert_eq!(r.tier, Tier::Live);
        assert_eq!(r.bringup, None);

        for kind in [
            BringupKind::Create,
            BringupKind::Spare,
            BringupKind::Reattach,
            BringupKind::RestoreS3Dump,
            BringupKind::RestoreS3Image,
            BringupKind::RestoreLocalDump,
            BringupKind::ThawCompacted,
        ] {
            assert_eq!(BringupKind::parse(kind.as_str()), Some(kind));
        }
    }

    /// `set_bringup` is lazy: it marks the map dirty for the flush loop and
    /// survives the `put` that rebinds the schema.
    #[test]
    fn set_bringup_is_a_debounced_write() {
        let dir = std::env::temp_dir().join(format!("pgfc-bringup-{}", std::process::id()));
        let path = dir.join("registry.tsv");
        let _ = std::fs::remove_file(&path);
        let store = Store::load(path.clone());
        store.put("wb1", "sb-1");
        let bringup = Bringup {
            kind: BringupKind::Create,
            took_ms: 1_250,
        };
        store.set_bringup("wb1", bringup);
        assert!(
            !std::fs::read_to_string(&path).unwrap().contains("1250"),
            "set_bringup must not write on the checkout path"
        );
        store.flush_dirty();
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("\t1250\tcreate\n")
        );
        assert_eq!(store.record("wb1").unwrap().bringup, Some(bringup));

        // Rebinding carries it until the next set_bringup replaces it.
        store.put("wb1", "sb-2");
        assert_eq!(store.record("wb1").unwrap().bringup, Some(bringup));

        // Unknown schema: a no-op, not a phantom row.
        store.set_bringup("nope", bringup);
        assert!(store.record("nope").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_new_four_column_format() {
        let map = parse(
            "wb1\tsb-1\t1700000000\tlive\nwb2\tsb-2\t1700000500\tarchived\n\
             wb3\tsb-3\t1700000900\tfrozen\nwb4\tsb-4\t1700001000\tcompacted\n",
            999,
        );
        let wb1 = map.get("wb1").unwrap();
        assert_eq!(wb1.sandbox_id, "sb-1");
        assert_eq!(wb1.last_active, 1_700_000_000);
        assert_eq!(wb1.tier, Tier::Live);
        let wb2 = map.get("wb2").unwrap();
        assert_eq!(wb2.tier, Tier::Archived);
        assert_eq!(wb2.last_active, 1_700_000_500);
        assert_eq!(map.get("wb3").unwrap().tier, Tier::Frozen);
        assert_eq!(map.get("wb4").unwrap().tier, Tier::Compacted);
        assert_eq!(Tier::parse(Tier::Compacted.as_str()), Tier::Compacted);
    }

    #[test]
    fn legacy_two_column_format_defaults_to_now_and_live() {
        // The pre-eviction on-disk format. Missing last_active must default to
        // load time — NOT 0, or every upgraded schema would look week-stale and
        // get mass-archived on the first sweep after upgrade.
        let map = parse("wb\tsb-legacy\n", 12345);
        let r = map.get("wb").unwrap();
        assert_eq!(r.sandbox_id, "sb-legacy");
        assert_eq!(r.last_active, 12345);
        assert_eq!(r.tier, Tier::Live);
    }

    #[test]
    fn round_trips_through_serialize() {
        let map = parse("a\tsb-a\t100\tlive\nb\tsb-b\t200\tarchived\nc\tsb-c\t300\tfrozen\n", 0);
        let reparsed = parse(&serialize(&map), 0);
        assert_eq!(reparsed.get("a").unwrap().sandbox_id, "sb-a");
        assert_eq!(reparsed.get("a").unwrap().last_active, 100);
        assert_eq!(reparsed.get("a").unwrap().tier, Tier::Live);
        assert_eq!(reparsed.get("b").unwrap().tier, Tier::Archived);
        assert_eq!(reparsed.get("b").unwrap().last_active, 200);
        assert_eq!(reparsed.get("c").unwrap().tier, Tier::Frozen);
    }

    #[tokio::test]
    async fn put_touch_mark_clear_flow() {
        let dir = std::env::temp_dir().join(format!("pgvmpool-store-{}", std::process::id()));
        let path = dir.join("registry.tsv");
        let _ = std::fs::remove_file(&path);
        let store = Store::load(path.clone());

        store.put("wb", "sb-1");
        let r = store.record("wb").unwrap();
        assert_eq!(r.sandbox_id, "sb-1");
        assert_eq!(r.tier, Tier::Live);

        // Durable once it returns — the reload below must see it even if the
        // detached `put` write above hasn't landed (generation order covers it).
        store.set_tier("wb", Tier::Frozen).await;
        assert_eq!(store.record("wb").unwrap().tier, Tier::Frozen);
        store.set_tier("wb", Tier::Archived).await;

        // Reload from disk: the tier survives a restart.
        let reloaded = Store::load(path.clone());
        assert_eq!(reloaded.record("wb").unwrap().tier, Tier::Archived);

        // Recording a fresh VM id (a restore) resets the tier — the schema is
        // live again.
        reloaded.put("wb", "sb-2");
        let r = reloaded.record("wb").unwrap();
        assert_eq!(r.tier, Tier::Live);
        assert_eq!(r.sandbox_id, "sb-2");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stale_generations_never_regress_the_file() {
        let dir = std::env::temp_dir().join(format!("pgvmpool-seq-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("registry.tsv");
        let written = Mutex::new(0u64);
        write_latest(&path, &written, 2, "newer\tsb-2\t2\tlive\n");
        // A write task carrying an older snapshot finishes late: skipped.
        write_latest(&path, &written, 1, "older\tsb-1\t1\tlive\n");
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("newer"));
        assert!(!on_disk.contains("older"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
