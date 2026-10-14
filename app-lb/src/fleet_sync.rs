//! Fleet mode: the stores read and write the shared fleet store, and keep
//! their files as its local snapshot (`docs/design/fleet-shared-state.md` § 2).
//!
//! Off unless `APP_LB_FLEET_DATABASE_URL` is set. Then every store that is
//! fleet state is built over a [`FleetCollection`] or [`FleetDocument`]
//! instead of a bare file one:
//!
//! - **A write** goes to PostgreSQL first, as a compare-and-swap against the
//!   revision this host last saw. Only when it commits is the local file
//!   written, with the same bytes and the same code a single server uses.
//! - **A read** never touches the database. Stores keep serving from memory,
//!   loaded from the files, exactly as a single server does; the data plane
//!   has no database round trip anywhere.
//! - **Other hosts' writes** arrive through the change feed ([`FleetFeed`]):
//!   polled every second and woken by `LISTEN`, written into the files, then
//!   the store that owns the kind reloads.
//! - **Without the database** the host keeps serving from the files; writes
//!   fail with [`Unavailable`](crate::fleet_pg::Unavailable), which the admin
//!   API answers with 503. A host that starts with neither a database nor a
//!   snapshot refuses to start rather than invent an empty fleet.
//!
//! The files therefore stay exactly what a single server writes, so turning
//! fleet mode off again is a restart without the variable.
//!
//! **Seeding.** The first host to reach an empty fleet database writes its own
//! records into it, in one transaction, and marks it seeded. Every later host
//! takes the database's records instead, after copying its own state directory
//! aside (`app-lb-pre-fleet-<time>/`), since its local-only records are about
//! to be replaced.
//!
//! **Sealing.** Certificate private keys and the ACME account key are sealed
//! with `APP_LB_SECRET_KEY` (AES-256-GCM, bound to their kind and key) before
//! they reach the database, and unsealed into the `0600` files. Secrets are
//! already sealed by their own store. Fleet mode requires the key.

use crate::fleet_pg::{PgFailure, PgStore, Unavailable};
use crate::fleet_store::{
    Collection, Document, Entry, Expect, FileCollection, FileDocument, FileOptions, Revision,
    StoreError, Write,
};
use async_trait::async_trait;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use crate::fleet_store::DOC_KEY;

/// Leases: who renews certificates, sweeps expired tokens and collects
/// tombstones, fleet-wide.
pub const LEASE_ACME: &str = "acme";
pub const LEASE_TOKEN_SWEEP: &str = "token-sweep";
pub const LEASE_TOMBSTONES: &str = "tombstone-gc";
pub const LEASE_TTL: Duration = Duration::from_secs(15);
const LEASE_RENEW_EVERY: Duration = Duration::from_secs(5);
/// A holder stops acting this long before its lease would lapse, so it can
/// never act after another host may have taken over.
const LEASE_MARGIN: Duration = Duration::from_secs(3);

const FEED_POLL: Duration = Duration::from_secs(1);
const FEED_BATCH: usize = 500;
const LISTEN_RETRY: Duration = Duration::from_secs(10);
const TOMBSTONE_EVERY: Duration = Duration::from_secs(3600);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- where the snapshot lives ------------------------------------------------

/// `app-lb-state.json` → `app-lb-fleet-snapshot.json`, beside it: the cursor
/// and the revision of every record this host's files hold.
pub fn snapshot_meta_path(state_path: &str) -> PathBuf {
    let dir = crate::fleet_store::sibling_dir(state_path, "fleet");
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".d"))
        .map(|p| format!("{p}-snapshot.json"))
        .unwrap_or_else(|| "app-lb-fleet-snapshot.json".into());
    dir.with_file_name(name)
}

/// `app-lb-state.json` → `app-lb-fleet.d/deployments/`: the deployment
/// registry's fleet half. Its host half stays in `app-lb-state.d/`.
pub fn deployments_cache_dir(state_path: &str) -> PathBuf {
    crate::fleet_store::sibling_dir(state_path, "fleet").join("deployments")
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SnapshotMeta {
    version: u32,
    host: String,
    /// The feed resumes after this revision.
    cursor: Revision,
    /// When this host last heard from the database (unix seconds).
    synced_at: u64,
    /// kind → key → revision of the record the files hold.
    revisions: BTreeMap<String, BTreeMap<String, Revision>>,
}

// ---- what a failed write tells the admin API ---------------------------------

/// Why a fleet write failed, kept for the request that made it so the admin
/// API can answer 409 or 503 whatever the handler made of the error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteFailure {
    Conflict(String),
    Unavailable(String),
    Fenced(String),
}

tokio::task_local! {
    static WRITE_FAILURE: Arc<Mutex<Option<WriteFailure>>>;
}

/// Run `f` and report the first fleet write it saw fail.
pub async fn capture<F: std::future::Future>(f: F) -> (F::Output, Option<WriteFailure>) {
    let cell = Arc::new(Mutex::new(None));
    let out = WRITE_FAILURE.scope(cell.clone(), f).await;
    let failure = lock(&cell).take();
    (out, failure)
}

fn note(failure: WriteFailure) {
    let _ = WRITE_FAILURE.try_with(|cell| {
        lock(cell).get_or_insert(failure);
    });
}

// ---- the fleet ----------------------------------------------------------------

#[derive(Clone)]
enum Cache {
    Collection(Arc<FileCollection>),
    Document(Arc<FileDocument>),
}

impl Cache {
    fn read(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        match self {
            Cache::Collection(c) => Ok(c.get(key)?.map(|(b, _)| b)),
            Cache::Document(d) => Ok(d.read()?.map(|(b, _)| b)),
        }
    }

    fn write(&self, key: &str, body: &[u8]) -> io::Result<()> {
        match self {
            Cache::Collection(c) => c
                .put(key, body, Expect::Any)
                .map(|_| ())
                .map_err(Into::into),
            Cache::Document(d) => d.write(body, Expect::Any).map(|_| ()).map_err(Into::into),
        }
    }

    fn remove(&self, key: &str) -> io::Result<()> {
        match self {
            Cache::Collection(c) => c.delete(key, Expect::Any).map(|_| ()).map_err(Into::into),
            Cache::Document(d) => d.remove().map(|_| ()),
        }
    }

    /// Every record the files hold, unreadable ones left out.
    fn records(&self) -> io::Result<Vec<(String, Vec<u8>)>> {
        match self {
            Cache::Collection(c) => Ok(c
                .list()?
                .into_iter()
                .filter_map(|e| e.body.ok().map(|b| (e.key, b)))
                .collect()),
            Cache::Document(d) => Ok(d
                .read()?
                .map(|(b, _)| vec![(DOC_KEY.to_string(), b)])
                .unwrap_or_default()),
        }
    }

    /// The paths to copy aside before another host's records replace these.
    fn location(&self) -> PathBuf {
        match self {
            Cache::Collection(c) => c.dir().to_path_buf(),
            Cache::Document(d) => d.path().to_path_buf(),
        }
    }
}

pub type SeedFn = Box<dyn Fn() -> io::Result<Vec<(String, Vec<u8>)>> + Send + Sync>;
type Reload = Arc<dyn Fn() + Send + Sync>;

/// Work only the holder of a lease does, every so often.
struct Duty {
    lease: &'static str,
    every: Duration,
    last: Option<Instant>,
    run: Reload,
}

/// How a kind is kept.
#[derive(Debug, Clone, Copy, Default)]
pub struct KindOptions {
    /// Sealed with `APP_LB_SECRET_KEY` in the database.
    pub sealed: bool,
    /// Writes require this lease, at the epoch this host holds it under.
    pub fence: Option<&'static str>,
}

struct Kind {
    cache: Cache,
    opts: KindOptions,
    /// Where seeding reads this host's records from, when not the files
    /// themselves (the registry's fleet half is split out of its own files).
    seed: Option<SeedFn>,
}

/// How a start went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Started {
    /// This host seeded an empty database with its records.
    Seeded { records: usize },
    /// The files now match the database.
    Synced { records: usize, cursor: Revision },
    /// The database is out of reach; serving the snapshot from `synced_at`.
    Offline { synced_at: u64, error: String },
}

/// What `/whoami` and the logs report.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub available: bool,
    /// Seconds since this host last heard from the database. `None` before
    /// it ever has.
    pub snapshot_age_secs: Option<u64>,
    pub cursor: Revision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

pub struct Fleet {
    pg: Arc<PgStore>,
    meta: FileDocument,
    kinds: Mutex<BTreeMap<String, Arc<Kind>>>,
    snapshot: Mutex<SnapshotMeta>,
    dirty: Mutex<BTreeSet<String>>,
    reloads: Mutex<HashMap<String, Reload>>,
    seal_key: Vec<u8>,
    leases: Mutex<BTreeMap<String, Arc<Lease>>>,
    /// Set when the database cannot be trusted with this host's writes (an
    /// empty database under a host that already has a fleet snapshot). Writes
    /// are refused while it is set, reachable or not.
    blocked: Mutex<Option<String>>,
    /// One write at a time from this host, so it never conflicts with itself:
    /// a second write waits for the first's revision instead of racing it.
    write_lock: Mutex<()>,
    /// Kinds whose changes this host cannot apply live, already warned about.
    warned: Mutex<BTreeSet<String>>,
    duties: Mutex<Vec<Duty>>,
    synced_at: AtomicU64,
}

impl std::fmt::Debug for Fleet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fleet")
            .field("pg", &self.pg)
            .finish_non_exhaustive()
    }
}

impl Fleet {
    pub fn new(pg: Arc<PgStore>, meta_path: impl Into<PathBuf>, seal_key: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            pg,
            meta: FileDocument::new(meta_path, FileOptions::PLAIN),
            kinds: Mutex::new(BTreeMap::new()),
            snapshot: Mutex::new(SnapshotMeta::default()),
            dirty: Mutex::new(BTreeSet::new()),
            reloads: Mutex::new(HashMap::new()),
            seal_key,
            leases: Mutex::new(BTreeMap::new()),
            blocked: Mutex::new(None),
            write_lock: Mutex::new(()),
            warned: Mutex::new(BTreeSet::new()),
            duties: Mutex::new(Vec::new()),
            synced_at: AtomicU64::new(0),
        })
    }

    /// Run `f` every `every` on whichever host holds `lease`.
    pub fn duty(&self, lease: &'static str, every: Duration, f: impl Fn() + Send + Sync + 'static) {
        self.lease(lease);
        lock(&self.duties).push(Duty {
            lease,
            every,
            last: None,
            run: Arc::new(f),
        });
    }

    fn due_duties(&self) -> Vec<Reload> {
        let mut due = Vec::new();
        for duty in lock(&self.duties).iter_mut() {
            if self.lease(duty.lease).held().is_some()
                && duty.last.is_none_or(|t| t.elapsed() >= duty.every)
            {
                duty.last = Some(Instant::now());
                due.push(duty.run.clone());
            }
        }
        due
    }

    fn register(&self, kind: &str, cache: Cache, opts: KindOptions, seed: Option<SeedFn>) {
        let previous =
            lock(&self.kinds).insert(kind.to_string(), Arc::new(Kind { cache, opts, seed }));
        assert!(previous.is_none(), "fleet kind {kind:?} registered twice");
    }

    /// A fleet-backed collection whose snapshot is `cache`.
    pub fn collection(
        self: &Arc<Self>,
        kind: &str,
        cache: FileCollection,
        opts: KindOptions,
    ) -> Arc<FleetCollection> {
        let cache = Arc::new(cache);
        self.register(kind, Cache::Collection(cache.clone()), opts, None);
        Arc::new(FleetCollection {
            kind: kind.to_string(),
            fleet: self.clone(),
            cache,
        })
    }

    /// The same, seeded from `seed` rather than from `cache`'s own files.
    pub fn collection_seeded(
        self: &Arc<Self>,
        kind: &str,
        cache: FileCollection,
        opts: KindOptions,
        seed: SeedFn,
    ) -> Arc<FleetCollection> {
        let cache = Arc::new(cache);
        self.register(kind, Cache::Collection(cache.clone()), opts, Some(seed));
        Arc::new(FleetCollection {
            kind: kind.to_string(),
            fleet: self.clone(),
            cache,
        })
    }

    pub fn document(
        self: &Arc<Self>,
        kind: &str,
        cache: FileDocument,
        opts: KindOptions,
    ) -> Arc<FleetDocument> {
        let cache = Arc::new(cache);
        self.register(kind, Cache::Document(cache.clone()), opts, None);
        Arc::new(FleetDocument {
            kind: kind.to_string(),
            fleet: self.clone(),
            cache,
        })
    }

    /// Called after another host's change to `kind` lands in the files.
    pub fn on_reload(&self, kind: &str, f: impl Fn() + Send + Sync + 'static) {
        lock(&self.reloads).insert(kind.to_string(), Arc::new(f));
    }

    /// The lease named `name`, created on first ask. [`LeaseKeeper`] renews
    /// every lease asked for.
    pub fn lease(&self, name: &str) -> Arc<Lease> {
        lock(&self.leases)
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Lease::new(name)))
            .clone()
    }

    /// Whether writes would be attempted at all.
    pub fn writable(&self) -> bool {
        lock(&self.blocked).is_none() && self.pg.available()
    }

    pub fn status(&self) -> Status {
        let synced_at = self.synced_at.load(Ordering::Relaxed);
        Status {
            available: self.writable(),
            snapshot_age_secs: (synced_at > 0).then(|| now_secs().saturating_sub(synced_at)),
            cursor: lock(&self.snapshot).cursor,
            blocked: lock(&self.blocked).clone(),
            last_error: if self.pg.available() {
                None
            } else {
                self.pg.last_error()
            },
        }
    }

    fn revision(&self, kind: &str, key: &str) -> Option<Revision> {
        lock(&self.snapshot).revisions.get(kind)?.get(key).copied()
    }

    fn set_revision(&self, kind: &str, key: &str, revision: Option<Revision>) {
        let mut snap = lock(&self.snapshot);
        match revision {
            Some(r) => {
                snap.revisions
                    .entry(kind.to_string())
                    .or_default()
                    .insert(key.to_string(), r);
            }
            None => {
                if let Some(keys) = snap.revisions.get_mut(kind) {
                    keys.remove(key);
                }
            }
        }
    }

    fn save_meta(&self) {
        let json = {
            let snap = lock(&self.snapshot);
            serde_json::to_vec_pretty(&*snap)
        };
        match json {
            Ok(json) => {
                if let Err(e) = self.meta.write(&json, Expect::Any) {
                    tracing::warn!(path = %self.meta.location(), error = %e, "could not save the fleet snapshot's revisions");
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not encode the fleet snapshot's revisions"),
        }
    }

    fn kind(&self, kind: &str) -> Option<Arc<Kind>> {
        lock(&self.kinds).get(kind).cloned()
    }

    // -- sealing --

    fn seal(&self, kind: &str, key: &str, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        crate::fleet_seal::seal(&self.seal_key, kind, key, plaintext)
    }

    fn unseal(&self, kind: &str, key: &str, sealed: &[u8]) -> io::Result<Vec<u8>> {
        crate::fleet_seal::unseal(&self.seal_key, kind, key, sealed)
    }

    fn sealed_for_store(
        &self,
        k: &Kind,
        kind: &str,
        key: &str,
        body: &[u8],
    ) -> io::Result<Vec<u8>> {
        if k.opts.sealed {
            self.seal(kind, key, body)
        } else {
            Ok(body.to_vec())
        }
    }

    fn opened(&self, k: &Kind, kind: &str, key: &str, body: Vec<u8>) -> io::Result<Vec<u8>> {
        if k.opts.sealed {
            self.unseal(kind, key, &body)
        } else {
            Ok(body)
        }
    }

    // -- writes --

    fn write(
        &self,
        kind: &str,
        key: &str,
        body: Option<&[u8]>,
        expect: Expect,
    ) -> Result<Revision, StoreError> {
        let _one_at_a_time = lock(&self.write_lock);
        let k = self
            .kind(kind)
            .unwrap_or_else(|| panic!("fleet kind {kind:?} written before it was registered"));
        if let Some(reason) = lock(&self.blocked).clone() {
            note(WriteFailure::Unavailable(reason.clone()));
            return Err(StoreError::Io(io::Error::other(Unavailable(reason))));
        }
        // Known to be down: fail now rather than make the caller (a sign-in
        // on the data plane, say) wait out the timeout. The feed's next poll
        // is what notices the store is back.
        if !self.pg.available() {
            let reason = self
                .pg
                .last_error()
                .unwrap_or_else(|| "not reached yet".into());
            note(WriteFailure::Unavailable(reason.clone()));
            return Err(StoreError::Io(io::Error::other(Unavailable(reason))));
        }
        // `Any` means "whatever this host last saw", so a write based on a
        // view another host has since changed is refused, not merged.
        let expect = match expect {
            Expect::Any => match self.revision(kind, key) {
                Some(r) => Expect::Revision(r),
                None => Expect::Absent,
            },
            other => other,
        };
        let lease_epoch;
        let fence = match k.opts.fence {
            Some(name) => match self.lease(name).held() {
                Some(epoch) => {
                    lease_epoch = epoch;
                    Some((name, lease_epoch))
                }
                None => {
                    note(WriteFailure::Fenced(name.to_string()));
                    return Err(StoreError::Fenced {
                        lease: name.to_string(),
                    });
                }
            },
            None => None,
        };
        let result = match body {
            Some(body) => {
                let stored = self.sealed_for_store(&k, kind, key, body)?;
                self.pg.put(kind, key, &stored, expect, fence).map(Some)
            }
            None => self.pg.delete(kind, key, expect, fence),
        };
        match result {
            Ok(revision) => {
                self.synced_at.store(now_secs(), Ordering::Relaxed);
                // Committed. The files follow; a failure here is repaired by
                // the feed, which sees a revision newer than the files'.
                let local = match body {
                    Some(body) => k.cache.write(key, body),
                    None => k.cache.remove(key),
                };
                match local {
                    Ok(()) => {
                        self.set_revision(kind, key, if body.is_some() { revision } else { None });
                        self.save_meta();
                    }
                    Err(e) => {
                        tracing::warn!(kind, key, error = %e, "fleet write committed but the local snapshot was not updated; the feed will repair it")
                    }
                }
                Ok(revision.unwrap_or(0))
            }
            Err(PgFailure::Store(StoreError::Conflict { key: what, current })) => {
                note(WriteFailure::Conflict(format!(
                    "{what} was changed by another writer; reload it and try again"
                )));
                self.refresh(kind, key);
                Err(StoreError::Conflict { key: what, current })
            }
            Err(PgFailure::Store(StoreError::Fenced { lease })) => {
                note(WriteFailure::Fenced(lease.clone()));
                self.lease(&lease).lost();
                Err(StoreError::Fenced { lease })
            }
            Err(e @ PgFailure::Unavailable(_)) => {
                note(WriteFailure::Unavailable(e.to_string()));
                Err(e.into())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Re-read one record after a conflict, so the next attempt starts from
    /// what the database holds, and have its store reload.
    fn refresh(&self, kind: &str, key: &str) {
        let Some(k) = self.kind(kind) else { return };
        match self.pg.get(kind, key) {
            Ok(found) => {
                let local = match found {
                    Some((body, revision)) => self
                        .opened(&k, kind, key, body)
                        .and_then(|plain| k.cache.write(key, &plain))
                        .map(|()| Some(revision)),
                    None => k.cache.remove(key).map(|()| None),
                };
                match local {
                    Ok(revision) => {
                        self.set_revision(kind, key, revision);
                        self.save_meta();
                        lock(&self.dirty).insert(kind.to_string());
                    }
                    Err(e) => {
                        tracing::warn!(kind, key, error = %e, "could not refresh a conflicting record")
                    }
                }
            }
            Err(e) => {
                tracing::warn!(kind, key, error = %e, "could not re-read a conflicting record")
            }
        }
    }

    // -- startup --

    /// Bring the files in line with the database, or seed it. Call once,
    /// after every kind is registered and before any store loads.
    pub fn start(&self) -> Result<Started, String> {
        let previous = match self.meta.read() {
            Ok(Some((bytes, _))) => match serde_json::from_slice::<SnapshotMeta>(&bytes) {
                Ok(meta) => Some(meta),
                Err(e) => return Err(format!("{} is unreadable: {e}", self.meta.location())),
            },
            Ok(None) => None,
            Err(e) => return Err(format!("{} is unreadable: {e}", self.meta.location())),
        };

        let snapshot = self.pg.migrate().and_then(|()| self.pg.snapshot());
        let snapshot = match snapshot {
            Ok(s) => s,
            Err(PgFailure::Unavailable(error)) => {
                let Some(meta) = previous else {
                    return Err(format!(
                        "the fleet store is unreachable ({error}) and this host has no snapshot of it; \
                         refusing to start with no state rather than serve an empty fleet"
                    ));
                };
                let synced_at = meta.synced_at;
                self.synced_at.store(synced_at, Ordering::Relaxed);
                *lock(&self.snapshot) = meta;
                return Ok(Started::Offline { synced_at, error });
            }
            Err(e) => return Err(e.to_string()),
        };

        let mut seeded = 0;
        let snapshot = match (&snapshot.seeded, &previous) {
            (None, Some(_)) => {
                // This host has followed a fleet, and the database it points
                // at has never been seeded: it was replaced or emptied. Its
                // own snapshot is the best copy around, but whether to make it
                // the fleet's is an operator's decision, not a restart's.
                let reason = format!(
                    "the fleet database has never been seeded, but this host holds a snapshot of a fleet ({}); \
                     serving that snapshot read-only. To make this host's records the fleet's, stop app-lb, \
                     remove {} and start it again",
                    self.meta.location(),
                    self.meta.location()
                );
                *lock(&self.blocked) = Some(reason.clone());
                let meta = previous.unwrap_or_default();
                self.synced_at.store(meta.synced_at, Ordering::Relaxed);
                *lock(&self.snapshot) = meta;
                return Ok(Started::Offline {
                    synced_at: 0,
                    error: reason,
                });
            }
            (None, None) => {
                let writes = self.seed_writes()?;
                seeded = writes.len();
                let kinds = lock(&self.kinds).keys().cloned().collect();
                if self.pg.seed(writes, kinds).map_err(|e| e.to_string())? {
                    tracing::info!(
                        records = seeded,
                        "seeded the empty fleet store with this host's records"
                    );
                } else {
                    seeded = 0;
                    tracing::info!("another host seeded the fleet store first; taking its records");
                }
                self.pg.snapshot().map_err(|e| e.to_string())?
            }
            _ => snapshot,
        };

        // Kinds this binary keeps that the fleet has never been seeded with
        // (added by a newer app-lb than the one that seeded it) are seeded
        // from this host's own records, not replaced by an empty set.
        let unseeded: Vec<String> = lock(&self.kinds)
            .keys()
            .filter(|k| !snapshot.kinds.contains(*k))
            .cloned()
            .collect();
        let snapshot = if unseeded.is_empty() {
            snapshot
        } else {
            for kind in &unseeded {
                let records = self.seed_records(kind)?;
                match self
                    .pg
                    .seed_kind(kind, records)
                    .map_err(|e| e.to_string())?
                {
                    Some(n) => tracing::info!(
                        kind,
                        records = n,
                        "seeded a kind new to the fleet store from this host"
                    ),
                    None => tracing::info!(kind, "another host seeded this kind first"),
                }
            }
            self.pg.snapshot().map_err(|e| e.to_string())?
        };

        if previous.is_none() && seeded == 0 {
            self.set_aside()?;
        }
        let records = self.apply_snapshot(snapshot)?;
        self.synced_at.store(now_secs(), Ordering::Relaxed);
        {
            let mut snap = lock(&self.snapshot);
            snap.version = 1;
            snap.host = self.pg.host().to_string();
            snap.synced_at = now_secs();
        }
        self.save_meta();
        let cursor = lock(&self.snapshot).cursor;
        Ok(if seeded > 0 {
            Started::Seeded { records: seeded }
        } else {
            Started::Synced { records, cursor }
        })
    }

    /// One kind's records as this host would seed them: read from its
    /// files (or its seed source) and sealed where the kind is.
    fn seed_records(&self, kind: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
        let k = self
            .kind(kind)
            .ok_or_else(|| format!("unknown kind {kind}"))?;
        let records = match &k.seed {
            Some(seed) => seed(),
            None => k.cache.records(),
        }
        .map_err(|e| format!("could not read this host's {kind} to seed the fleet store: {e}"))?;
        records
            .into_iter()
            .map(|(key, body)| {
                let body = self
                    .sealed_for_store(&k, kind, &key, &body)
                    .map_err(|e| e.to_string())?;
                Ok((key, body))
            })
            .collect()
    }

    fn seed_writes(&self) -> Result<Vec<Write>, String> {
        let kinds: Vec<(String, Arc<Kind>)> = lock(&self.kinds)
            .iter()
            .map(|(n, k)| (n.clone(), k.clone()))
            .collect();
        let mut writes = Vec::new();
        for (kind, k) in kinds {
            let records = match &k.seed {
                Some(seed) => seed(),
                None => k.cache.records(),
            }
            .map_err(|e| {
                format!("could not read this host's {kind} to seed the fleet store: {e}")
            })?;
            for (key, body) in records {
                let body = self
                    .sealed_for_store(&k, &kind, &key, &body)
                    .map_err(|e| e.to_string())?;
                writes.push(Write::Put {
                    kind: kind.clone(),
                    key,
                    body,
                    expect: Expect::Absent,
                });
            }
        }
        Ok(writes)
    }

    /// Copy this host's state aside before another host's records replace it.
    fn set_aside(&self) -> Result<(), String> {
        let sources: Vec<PathBuf> = lock(&self.kinds)
            .values()
            .map(|k| k.cache.location())
            .collect();
        let Some(base) = self.meta.path().parent().map(Path::to_path_buf) else {
            return Ok(());
        };
        let aside = base.join(format!("app-lb-pre-fleet-{}", now_secs()));
        let mut copied = 0;
        for src in sources {
            if !src.exists() {
                continue;
            }
            let rel = src.strip_prefix(&base).unwrap_or(&src);
            let rel = rel.strip_prefix("/").unwrap_or(rel);
            copy_tree(&src, &aside.join(rel)).map_err(|e| {
                format!(
                    "could not copy {} aside before joining the fleet: {e}",
                    src.display()
                )
            })?;
            copied += 1;
        }
        if copied > 0 {
            tracing::warn!(to = %aside.display(), "joining an existing fleet: this host's own state was copied aside and is being replaced by the fleet's");
        }
        Ok(())
    }

    fn apply_snapshot(&self, snapshot: crate::fleet_pg::Snapshot) -> Result<usize, String> {
        let kinds: Vec<(String, Arc<Kind>)> = lock(&self.kinds)
            .iter()
            .map(|(n, k)| (n.clone(), k.clone()))
            .collect();
        let mut by_kind: BTreeMap<String, Vec<(String, Vec<u8>, Revision)>> = BTreeMap::new();
        for (kind, key, body, revision) in snapshot.records {
            by_kind.entry(kind).or_default().push((key, body, revision));
        }
        let mut revisions: BTreeMap<String, BTreeMap<String, Revision>> = BTreeMap::new();
        let mut total = 0;
        for (kind, k) in kinds {
            let wanted = by_kind.remove(&kind).unwrap_or_default();
            let mut keep = BTreeSet::new();
            for (key, body, revision) in wanted {
                let plain = self
                    .opened(&k, &kind, &key, body)
                    .map_err(|e| e.to_string())?;
                let current = k
                    .cache
                    .read(&key)
                    .map_err(|e| format!("{kind}/{key}: {e}"))?;
                if current.as_deref() != Some(plain.as_slice()) {
                    k.cache
                        .write(&key, &plain)
                        .map_err(|e| format!("{kind}/{key}: {e}"))?;
                }
                revisions
                    .entry(kind.clone())
                    .or_default()
                    .insert(key.clone(), revision);
                keep.insert(key);
                total += 1;
            }
            for (key, _) in k.cache.records().map_err(|e| format!("{kind}: {e}"))? {
                if !keep.contains(&key) {
                    k.cache
                        .remove(&key)
                        .map_err(|e| format!("{kind}/{key}: {e}"))?;
                }
            }
        }
        for kind in by_kind.keys() {
            tracing::info!(
                kind,
                "the fleet store holds a kind this app-lb does not know; ignoring it"
            );
        }
        let mut snap = lock(&self.snapshot);
        snap.revisions = revisions;
        snap.cursor = snapshot.cursor;
        Ok(total)
    }

    // -- the feed --

    /// Apply everything after the cursor. Returns how many changes were read.
    async fn poll(&self) -> Result<usize, PgFailure> {
        let mut read = 0;
        loop {
            let cursor = lock(&self.snapshot).cursor;
            let changes = self.pg.changes_after(cursor, FEED_BATCH).await?;
            self.synced_at.store(now_secs(), Ordering::Relaxed);
            let n = changes.len();
            read += n;
            if n == 0 {
                return Ok(read);
            }
            {
                let _one_at_a_time = lock(&self.write_lock);
                for change in changes {
                    let revision = change.revision;
                    self.apply_change(change);
                    lock(&self.snapshot).cursor = revision;
                }
            }
            self.save_meta();
            if n < FEED_BATCH {
                return Ok(read);
            }
        }
    }

    fn apply_change(&self, change: crate::fleet_store::Change) {
        let crate::fleet_store::Change {
            revision,
            kind,
            key,
            body,
        } = change;
        let Some(k) = self.kind(&kind) else { return };
        if self
            .revision(&kind, &key)
            .is_some_and(|seen| seen >= revision)
        {
            return; // this host's own write, already in its files
        }
        let local = match body {
            Some(body) => self
                .opened(&k, &kind, &key, body)
                .and_then(|plain| k.cache.write(&key, &plain))
                .map(|()| Some(revision)),
            None => {
                if self.revision(&kind, &key).is_none()
                    && !matches!(k.cache.read(&key), Ok(Some(_)))
                {
                    return; // a delete of something this host never had
                }
                k.cache.remove(&key).map(|()| None)
            }
        };
        match local {
            Ok(revision) => {
                self.set_revision(&kind, &key, revision);
                lock(&self.dirty).insert(kind);
            }
            Err(e) => {
                tracing::error!(kind, key, revision, error = %e, "could not apply a fleet change to the local snapshot")
            }
        }
    }

    /// Have every store whose files changed reload them.
    fn reload_dirty(&self) {
        let dirty = std::mem::take(&mut *lock(&self.dirty));
        for kind in dirty {
            let hook = lock(&self.reloads).get(&kind).cloned();
            match hook {
                Some(reload) => {
                    tracing::info!(kind, "applying fleet changes");
                    reload();
                }
                None => {
                    if lock(&self.warned).insert(kind.clone()) {
                        tracing::warn!(
                            kind,
                            "another writer changed fleet records of this kind; they are in the local snapshot and take effect at this host's next start"
                        );
                    }
                }
            }
        }
    }
}

fn copy_tree(src: &Path, dst: &Path) -> io::Result<()> {
    if src.is_dir() {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            copy_tree(&entry.path(), &dst.join(entry.file_name()))?;
        }
    } else {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dst)?;
    }
    Ok(())
}

// ---- every store's backend ---------------------------------------------------------

/// The backend of every store that holds fleet state, registered with the
/// fleet in one place so [`Fleet::start`] sees every kind before any store
/// loads. Each cache uses exactly the path and file options its store uses on
/// a single server, so the files are the same either way.
pub struct FleetStores {
    pub fleet: Arc<Fleet>,
    /// This host's fleet name (`APP_LB_FLEET_HOST`): what a deployment's
    /// `placement.home` names.
    pub host: String,
    pub deployments: Arc<FleetCollection>,
    pub namespaces: Arc<FleetCollection>,
    pub workflows: Arc<FleetCollection>,
    pub auth_providers: Arc<FleetCollection>,
    pub plugins: Arc<FleetCollection>,
    pub secrets: Arc<FleetDocument>,
    pub tokens: Arc<FleetDocument>,
    pub guard: Arc<FleetDocument>,
    pub pg_ownership: Arc<FleetDocument>,
    pub acme_account: Arc<FleetDocument>,
    pub acme_backoff: Arc<FleetDocument>,
    pub cert_chains: Arc<FleetCollection>,
    pub cert_keys: Arc<FleetCollection>,
    /// The data-plane session signing key (`APP_LB_AUTH_KEY`), so a sign-in
    /// on one host is a sign-in on every host. Sealed.
    pub auth_key: Arc<FleetDocument>,
}

impl FleetStores {
    pub fn register(
        fleet: &Arc<Fleet>,
        layout: &crate::fleet_store::Layout,
        host: &str,
        auth_key_path: &Path,
    ) -> Self {
        let plain = KindOptions::default();
        let acme = KindOptions {
            sealed: false,
            fence: Some(LEASE_ACME),
        };
        let acme_sealed = KindOptions {
            sealed: true,
            fence: Some(LEASE_ACME),
        };
        let private_dir = FileOptions::PRIVATE.private_dir(0o700);
        let state = layout.state_path.to_string_lossy().into_owned();
        let state_path = layout.state_path.clone();
        let certs = layout.acme_certs_dir();
        fleet.lease(LEASE_ACME);
        fleet.lease(LEASE_TOMBSTONES);
        Self {
            deployments: fleet.collection_seeded(
                "deployments",
                FileCollection::new(deployments_cache_dir(&state), ".json", FileOptions::SYNCED),
                plain,
                Box::new(move || crate::registry::fleet_seed(&state_path)),
            ),
            namespaces: fleet.collection(
                "namespaces",
                FileCollection::new(layout.namespace_dir(), ".json", FileOptions::PLAIN),
                plain,
            ),
            workflows: fleet.collection(
                "workflows",
                FileCollection::new(layout.workflow_dir(), ".json", FileOptions::PLAIN),
                plain,
            ),
            auth_providers: fleet.collection(
                "auth-providers",
                FileCollection::new(layout.auth_provider_dir(), ".json", FileOptions::PLAIN),
                plain,
            ),
            plugins: fleet.collection(
                "plugins",
                FileCollection::new(layout.plugin_dir(), ".json", FileOptions::PLAIN),
                plain,
            ),
            secrets: fleet.document(
                "secrets",
                FileDocument::new(&layout.secrets_path, FileOptions::PRIVATE),
                plain,
            ),
            tokens: fleet.document(
                "tokens",
                FileDocument::new(&layout.tokens_path, FileOptions::PRIVATE),
                plain,
            ),
            guard: fleet.document(
                "guard",
                FileDocument::new(&layout.guard_path, FileOptions::PLAIN),
                plain,
            ),
            pg_ownership: fleet.document(
                "pg-ownership",
                FileDocument::new(layout.postgres_ownership_path(), FileOptions::PLAIN),
                plain,
            ),
            acme_account: fleet.document(
                "acme-account",
                FileDocument::new(layout.acme_dir.join("account.json"), private_dir),
                acme_sealed,
            ),
            acme_backoff: fleet.document(
                "acme-backoff",
                FileDocument::new(
                    layout.acme_dir.join("backoff.json"),
                    FileOptions::PLAIN.private_dir(0o700),
                ),
                acme,
            ),
            cert_chains: fleet.collection(
                "cert-chains",
                FileCollection::new(&certs, ".crt.pem", private_dir),
                acme,
            ),
            cert_keys: fleet.collection(
                "cert-keys",
                FileCollection::new(&certs, ".key.pem", private_dir),
                acme_sealed,
            ),
            auth_key: fleet.document(
                "auth-key",
                FileDocument::new(auth_key_path, FileOptions::PRIVATE),
                KindOptions {
                    sealed: true,
                    fence: None,
                },
            ),
            host: host.to_string(),
            fleet: fleet.clone(),
        }
    }
}

// ---- the store-facing types ----------------------------------------------------

/// A [`Collection`] whose records are fleet state.
#[derive(Debug)]
pub struct FleetCollection {
    kind: String,
    fleet: Arc<Fleet>,
    cache: Arc<FileCollection>,
}

impl Collection for FleetCollection {
    fn get(&self, key: &str) -> io::Result<Option<(Vec<u8>, Revision)>> {
        Ok(self
            .cache
            .get(key)?
            .map(|(body, _)| (body, self.fleet.revision(&self.kind, key).unwrap_or(0))))
    }

    fn list(&self) -> io::Result<Vec<Entry>> {
        self.cache.list()
    }

    fn put(&self, key: &str, body: &[u8], expect: Expect) -> Result<Revision, StoreError> {
        self.fleet.write(&self.kind, key, Some(body), expect)
    }

    fn delete(&self, key: &str, expect: Expect) -> Result<bool, StoreError> {
        // Whether there was anything, as the files would answer.
        let existed =
            self.cache.get(key)?.is_some() || self.fleet.revision(&self.kind, key).is_some();
        self.fleet.write(&self.kind, key, None, expect)?;
        Ok(existed)
    }

    fn location(&self, key: &str) -> String {
        self.cache.location(key)
    }
}

/// A [`Document`] that is fleet state.
#[derive(Debug)]
pub struct FleetDocument {
    kind: String,
    fleet: Arc<Fleet>,
    cache: Arc<FileDocument>,
}

impl Document for FleetDocument {
    fn read(&self) -> io::Result<Option<(Vec<u8>, Revision)>> {
        Ok(self
            .cache
            .read()?
            .map(|(body, _)| (body, self.fleet.revision(&self.kind, DOC_KEY).unwrap_or(0))))
    }

    fn write(&self, body: &[u8], expect: Expect) -> Result<Revision, StoreError> {
        self.fleet.write(&self.kind, DOC_KEY, Some(body), expect)
    }

    fn location(&self) -> String {
        self.cache.location()
    }
}

// ---- leases ---------------------------------------------------------------------

/// A fleet-wide singleton's right to act. [`held`](Lease::held) answers from
/// memory, so it is cheap to ask on every tick; [`LeaseKeeper`] renews it.
#[derive(Debug)]
pub struct Lease {
    name: String,
    /// The epoch held, and the instant this host must stop acting by.
    state: Mutex<Option<(u64, Instant)>>,
}

impl Lease {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            state: Mutex::new(None),
        }
    }

    /// The epoch, while this host holds the lease with time to spare.
    pub fn held(&self) -> Option<u64> {
        match *lock(&self.state) {
            Some((epoch, deadline)) if Instant::now() < deadline => Some(epoch),
            _ => None,
        }
    }

    fn lost(&self) {
        if lock(&self.state).take().is_some() {
            tracing::warn!(lease = %self.name, "lease lost; this host stops acting on it");
        }
    }

    async fn tick(&self, pg: &PgStore) {
        // Measured from before the call, so the deadline errs early.
        let sent = Instant::now();
        let current = *lock(&self.state);
        let outcome = match current {
            Some((epoch, _)) => match pg.renew(&self.name, epoch, LEASE_TTL).await {
                Ok(true) => Ok(Some(epoch)),
                Ok(false) => pg.acquire(&self.name, LEASE_TTL).await,
                Err(e) => Err(e),
            },
            None => pg.acquire(&self.name, LEASE_TTL).await,
        };
        match outcome {
            Ok(Some(epoch)) => {
                let deadline = sent + LEASE_TTL - LEASE_MARGIN;
                let was = lock(&self.state).replace((epoch, deadline));
                if was.map(|(e, _)| e) != Some(epoch) {
                    tracing::info!(lease = %self.name, epoch, "lease acquired");
                }
            }
            Ok(None) => self.lost(),
            // Unreachable: keep acting only until the deadline already set,
            // which `held` enforces by itself.
            Err(e) => tracing::debug!(lease = %self.name, error = %e, "lease not renewed"),
        }
    }

    async fn release(&self, pg: &PgStore) {
        let current = lock(&self.state).take();
        if let Some((epoch, _)) = current {
            let _ = pg.release(&self.name, epoch).await;
        }
    }
}

// ---- background services ----------------------------------------------------------

/// Follows the change feed, renews leases, and collects tombstones while it
/// holds that lease.
pub struct FleetFeed {
    fleet: Arc<Fleet>,
}

impl FleetFeed {
    pub fn new(fleet: Arc<Fleet>) -> Self {
        Self { fleet }
    }
}

#[async_trait]
impl BackgroundService for FleetFeed {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let fleet = &self.fleet;
        let pg = fleet.pg.clone();
        let mut listener: Option<(
            tokio_postgres::Client,
            tokio::sync::mpsc::UnboundedReceiver<()>,
        )> = None;
        let mut last_listen = None::<Instant>;
        let mut last_renew = None::<Instant>;
        let mut last_gc = None::<Instant>;
        let mut was_writable = fleet.writable();
        loop {
            if listener.is_none() && last_listen.is_none_or(|t| t.elapsed() >= LISTEN_RETRY) {
                last_listen = Some(Instant::now());
                match pg.listen().await {
                    Ok(l) => listener = Some(l),
                    Err(e) => tracing::debug!(error = %e, "fleet LISTEN unavailable; polling only"),
                }
            }

            if last_renew.is_none_or(|t| t.elapsed() >= LEASE_RENEW_EVERY) {
                last_renew = Some(Instant::now());
                let leases: Vec<Arc<Lease>> = lock(&fleet.leases).values().cloned().collect();
                for lease in leases {
                    lease.tick(&pg).await;
                }
            }

            if lock(&fleet.blocked).is_none()
                && let Err(e) = fleet.poll().await
            {
                tracing::debug!(error = %e, "fleet feed poll failed");
            }
            fleet.reload_dirty();
            for duty in fleet.due_duties() {
                duty();
            }

            if fleet.lease(LEASE_TOMBSTONES).held().is_some()
                && last_gc.is_none_or(|t| t.elapsed() >= TOMBSTONE_EVERY)
            {
                last_gc = Some(Instant::now());
                match pg.collect_tombstones().await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(count = n, "collected fleet tombstones"),
                    Err(e) => tracing::warn!(error = %e, "could not collect fleet tombstones"),
                }
            }

            let writable = fleet.writable();
            if writable != was_writable {
                was_writable = writable;
                let status = fleet.status();
                if writable {
                    tracing::info!(cursor = status.cursor, "fleet store writable again");
                } else {
                    tracing::warn!(snapshot_age_secs = ?status.snapshot_age_secs, error = ?status.last_error, "fleet store not writable; mutations answer 503");
                }
            }

            let notified = async {
                match listener.as_mut() {
                    Some((_, rx)) => rx.recv().await.is_some(),
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                open = notified => {
                    if !open {
                        tracing::debug!("fleet LISTEN connection closed");
                        listener = None;
                    }
                }
                _ = tokio::time::sleep(FEED_POLL) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        let leases: Vec<Arc<Lease>> = lock(&fleet.leases).values().cloned().collect();
                        for lease in leases {
                            lease.release(&pg).await;
                        }
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_pg::tests::{TEST_URL_ENV, peer, test_store};

    struct Dir(PathBuf);
    impl Dir {
        fn new(name: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "fleet-sync-{name}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn state(&self) -> String {
            self.0
                .join("app-lb-state.json")
                .to_string_lossy()
                .into_owned()
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const KEY: [u8; 32] = [9; 32];

    /// One host: its fleet over `pg`, a namespace-like collection and a
    /// sealed document.
    fn host(pg: Arc<PgStore>, dir: &Dir) -> (Arc<Fleet>, Arc<FleetCollection>, Arc<FleetDocument>) {
        let fleet = Fleet::new(pg, snapshot_meta_path(&dir.state()), KEY.to_vec());
        let ns = fleet.collection(
            "namespaces",
            FileCollection::new(
                dir.0.join("app-lb-namespaces.d"),
                ".json",
                FileOptions::PLAIN,
            ),
            KindOptions::default(),
        );
        let account = fleet.document(
            "acme-account",
            FileDocument::new(dir.0.join("acme/account.json"), FileOptions::PRIVATE),
            KindOptions {
                sealed: true,
                fence: None,
            },
        );
        (fleet, ns, account)
    }

    macro_rules! pg_or_skip {
        ($name:expr, $host:expr) => {
            match test_store($name, $host) {
                Some(s) => s,
                None => {
                    eprintln!("skipped: {TEST_URL_ENV} is not set");
                    return;
                }
            }
        };
    }

    #[test]
    fn the_snapshot_paths_sit_beside_the_state() {
        assert_eq!(
            snapshot_meta_path("/var/lib/app-lb/app-lb-state.json"),
            Path::new("/var/lib/app-lb/app-lb-fleet-snapshot.json")
        );
        assert_eq!(
            deployments_cache_dir("/var/lib/app-lb/app-lb-state.json"),
            Path::new("/var/lib/app-lb/app-lb-fleet.d/deployments")
        );
    }

    #[test]
    fn sealing_round_trips_and_is_bound_to_the_record() {
        let pg = PgStore::open_in(
            "postgres://u@127.0.0.1:9/x",
            "h",
            Duration::from_secs(1),
            "fleet",
        )
        .unwrap();
        let fleet = Fleet::new(pg, "/nonexistent/meta.json", KEY.to_vec());
        let sealed = fleet.seal("acme-account", DOC_KEY, b"private").unwrap();
        assert!(!sealed.windows(7).any(|w| w == b"private"));
        assert_eq!(
            fleet.unseal("acme-account", DOC_KEY, &sealed).unwrap(),
            b"private"
        );
        assert!(
            fleet.unseal("cert-keys", DOC_KEY, &sealed).is_err(),
            "moved to another record"
        );
        let other = Fleet::new(fleet.pg.clone(), "/nonexistent/meta.json", vec![1; 32]);
        assert!(
            other.unseal("acme-account", DOC_KEY, &sealed).is_err(),
            "another key"
        );
    }

    #[test]
    fn the_first_host_seeds_and_the_second_takes_the_fleets_records() {
        let pg_a = pg_or_skip!("seed2", "host-a");
        let a_dir = Dir::new("a");
        std::fs::create_dir_all(a_dir.0.join("app-lb-namespaces.d")).unwrap();
        std::fs::write(
            a_dir.0.join("app-lb-namespaces.d/sam.json"),
            b"{\"name\":\"sam\"}",
        )
        .unwrap();
        let (a, _, a_account) = host(pg_a.clone(), &a_dir);
        std::fs::create_dir_all(a_dir.0.join("acme")).unwrap();
        std::fs::write(a_dir.0.join("acme/account.json"), b"secret-account").unwrap();
        assert_eq!(a.start().unwrap(), Started::Seeded { records: 2 });
        // Sealed in the database, plain in the file.
        let (stored, _) = pg_a.get("acme-account", DOC_KEY).unwrap().unwrap();
        assert!(stored.starts_with(crate::fleet_seal::MAGIC));
        assert_eq!(a_account.read().unwrap().unwrap().0, b"secret-account");

        let b_dir = Dir::new("b");
        std::fs::create_dir_all(b_dir.0.join("app-lb-namespaces.d")).unwrap();
        std::fs::write(b_dir.0.join("app-lb-namespaces.d/local.json"), b"{}").unwrap();
        let (b, b_ns, b_account) = host(peer(&pg_a, "host-b"), &b_dir);
        assert!(matches!(
            b.start().unwrap(),
            Started::Synced { records: 2, .. }
        ));
        let keys: Vec<_> = b_ns.list().unwrap().into_iter().map(|e| e.key).collect();
        assert_eq!(keys, ["sam"], "b's local-only record was replaced");
        assert_eq!(b_account.read().unwrap().unwrap().0, b"secret-account");
        let aside: Vec<_> = std::fs::read_dir(&b_dir.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("app-lb-pre-fleet-")
            })
            .collect();
        assert_eq!(aside.len(), 1);
        assert!(
            aside[0]
                .path()
                .join("app-lb-namespaces.d/local.json")
                .exists(),
            "but copied aside first"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_write_on_one_host_reaches_the_other_and_a_stale_one_conflicts() {
        let pg_a = pg_or_skip!("feed2", "host-a");
        let (a_dir, b_dir) = (Dir::new("fa"), Dir::new("fb"));
        let (a, a_ns, _) = host(pg_a.clone(), &a_dir);
        a.start().unwrap();
        let (b, b_ns, _) = host(peer(&pg_a, "host-b"), &b_dir);
        b.start().unwrap();
        let reloaded = Arc::new(AtomicU64::new(0));
        let r = reloaded.clone();
        b.on_reload("namespaces", move || {
            r.fetch_add(1, Ordering::Relaxed);
        });

        a_ns.put("sam", b"v1", Expect::Any).unwrap();
        b.poll().await.unwrap();
        b.reload_dirty();
        assert_eq!(b_ns.get("sam").unwrap().unwrap().0, b"v1");
        assert_eq!(reloaded.load(Ordering::Relaxed), 1);

        // a's own write coming back through its feed changes nothing.
        a.poll().await.unwrap();
        assert!(lock(&a.dirty).is_empty());

        // Both edit from v1; the second to commit is refused, then succeeds
        // once it has re-read.
        a_ns.put("sam", b"from-a", Expect::Any).unwrap();
        let (result, failure) = capture(async { b_ns.put("sam", b"from-b", Expect::Any) }).await;
        assert!(matches!(result, Err(StoreError::Conflict { .. })));
        assert!(matches!(failure, Some(WriteFailure::Conflict(_))));
        assert_eq!(b_ns.get("sam").unwrap().unwrap().0, b"from-a", "refreshed");
        b_ns.put("sam", b"from-b", Expect::Any).unwrap();

        // Deletes travel too.
        a.poll().await.unwrap();
        assert_eq!(a_ns.get("sam").unwrap().unwrap().0, b"from-b");
        b_ns.delete("sam", Expect::Any).unwrap();
        a.poll().await.unwrap();
        assert!(a_ns.get("sam").unwrap().is_none());
    }

    #[test]
    fn without_a_database_a_host_with_a_snapshot_serves_it_and_one_without_refuses() {
        let pg = pg_or_skip!("offline", "host-a");
        let dir = Dir::new("off");
        let (a, a_ns, _) = host(pg.clone(), &dir);
        a.start().unwrap();
        a_ns.put("sam", b"v1", Expect::Any).unwrap();

        let dead = || {
            PgStore::open_in(
                "postgres://u:p@127.0.0.1:9/x?connect_timeout=1",
                "host-a",
                Duration::from_secs(2),
                "fleet",
            )
            .unwrap()
        };
        let (again, again_ns, _) = host(dead(), &dir);
        assert!(matches!(again.start().unwrap(), Started::Offline { .. }));
        assert_eq!(
            again_ns.get("sam").unwrap().unwrap().0,
            b"v1",
            "the snapshot serves"
        );
        let err: io::Error = again_ns.put("sam", b"v2", Expect::Any).unwrap_err().into();
        assert!(crate::fleet_pg::is_unavailable(&err));
        assert_eq!(
            again_ns.get("sam").unwrap().unwrap().0,
            b"v1",
            "nothing written locally"
        );

        let empty = Dir::new("cold");
        let (cold, _, _) = host(dead(), &empty);
        assert!(cold.start().is_err(), "no snapshot and no database: refuse");
    }

    #[test]
    fn a_kind_added_after_seeding_is_seeded_from_the_host_not_wiped() {
        let pg = pg_or_skip!("newkind", "host-a");
        let dir = Dir::new("nk");
        let (a, _, _) = host(pg.clone(), &dir);
        a.start().unwrap();
        // The next binary keeps a new kind, and this host has a record of it.
        std::fs::write(dir.0.join("app-lb-auth-key"), [5u8; 32]).unwrap();
        let (again, _, _) = host(pg.clone(), &dir);
        let key = again.document(
            "auth-key",
            FileDocument::new(dir.0.join("app-lb-auth-key"), FileOptions::PRIVATE),
            KindOptions {
                sealed: true,
                fence: None,
            },
        );
        again.start().unwrap();
        assert_eq!(key.read().unwrap().unwrap().0, [5u8; 32], "kept, not wiped");
        let (stored, _) = pg.get("auth-key", DOC_KEY).unwrap().unwrap();
        assert!(
            stored.starts_with(crate::fleet_seal::MAGIC),
            "and sealed into the fleet"
        );
    }

    #[test]
    fn an_unseeded_database_under_a_fleet_snapshot_is_not_reseeded() {
        let pg = pg_or_skip!("reseed", "host-a");
        let dir = Dir::new("rs");
        let (a, a_ns, _) = host(pg, &dir);
        a.start().unwrap();
        a_ns.put("sam", b"v1", Expect::Any).unwrap();

        let fresh = pg_or_skip!("reseed2", "host-a");
        let (again, again_ns, _) = host(fresh.clone(), &dir);
        assert!(matches!(again.start().unwrap(), Started::Offline { .. }));
        assert!(!again.writable());
        assert!(again.status().blocked.is_some());
        assert!(again_ns.put("sam", b"v2", Expect::Any).is_err());
        assert!(fresh.snapshot().unwrap().seeded.is_none(), "nothing seeded");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_fenced_kind_is_written_only_under_its_lease() {
        let pg = pg_or_skip!("fence", "host-a");
        let dir = Dir::new("fe");
        let fleet = Fleet::new(pg.clone(), snapshot_meta_path(&dir.state()), KEY.to_vec());
        let certs = fleet.collection(
            "cert-chains",
            FileCollection::new(dir.0.join("acme/certs"), ".crt.pem", FileOptions::PRIVATE),
            KindOptions {
                sealed: false,
                fence: Some(LEASE_ACME),
            },
        );
        fleet.start().unwrap();
        let (result, failure) =
            capture(async { certs.put("a.example", b"chain", Expect::Any) }).await;
        assert!(matches!(result, Err(StoreError::Fenced { .. })));
        assert_eq!(failure, Some(WriteFailure::Fenced(LEASE_ACME.into())));
        fleet.lease(LEASE_ACME).tick(&pg).await;
        assert!(fleet.lease(LEASE_ACME).held().is_some());
        certs.put("a.example", b"chain", Expect::Any).unwrap();
    }
}
