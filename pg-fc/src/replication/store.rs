//! The durable record of what this node is replicating, and to or from whom.
//!
//! One row per database, eighteen tab-separated columns, `0600`, temp-file +
//! rename — the same shape as [`crate::dedicated`] and for the same reasons.
//! It holds a cleartext password (the replication login's) so it is no more
//! world-readable than `dedicated.tsv` is.
//!
//! Two properties of this file are load-bearing beyond "remember the pairing":
//!
//!   * **It is written before the thing it describes exists.** Every step of
//!     setup persists its record first and acts second, so a crash can leave
//!     a row describing work that never happened — recoverable, because every
//!     step is idempotent — but never work that happened with no row, which
//!     would be an orphaned replication slot pinning WAL with nothing to
//!     name it.
//!   * **[`ReplStore::is_pinned`] is the predicate every lifecycle exclusion
//!     asks.** The idle reaper, the offload pacer, pressure eviction and the
//!     dashboard's manual controls all defer to it, because stopping a
//!     replicated VM breaks the pairing in a way only a full re-seed fixes.
//!
//! The one field here that is not validated on the way in is `message`: it
//! carries Postgres error text. [`one_line`] is what preserves the module
//! invariant that no field can contain a tab or a newline, so nothing else
//! needs escaping.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use tracing::info;

use super::names;

/// Sanity cap, matching [`crate::dedicated::MAX_RECORDS`]: a pairing implies a
/// permanently pinned VM on both nodes, so the practical ceiling is far lower
/// than this anyway.
pub const MAX_RECORDS: usize = 512;

/// Which side of a pairing this node plays for one database.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Primary,
    Replica,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Primary => "primary",
            Role::Replica => "replica",
        }
    }
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "primary" => Some(Role::Primary),
            "replica" => Some(Role::Replica),
            _ => None,
        }
    }
}

/// Where a pairing has got to.
///
/// Only `Syncing` and `Active` pin the VM — see [`ReplStore::is_pinned`]. The
/// three terminal states exist so a finished or failed pairing stops holding
/// a VM hostage while its row is still readable on the dashboard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// Row written; nothing exists server-side yet. A crash here leaves
    /// exactly one visible row and zero Postgres objects, which is why the
    /// row is written first.
    Pending,
    /// Primary: publication and login exist, the peer has been asked to seed.
    /// Replica: subscription created, initial table copy in progress.
    Syncing,
    /// Streaming, every table ready.
    Active,
    /// A step failed; `message` says which. Never retried automatically —
    /// the data on both sides is intact and the decision (retry, detach,
    /// promote) is the operator's.
    Failed,
    /// Replica side: the subscription was dropped and this node is now
    /// authoritative. Kept for history; pins nothing.
    Promoted,
    /// Primary side: publication and slot dropped. Same.
    Detached,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Syncing => "syncing",
            State::Active => "active",
            State::Failed => "failed",
            State::Promoted => "promoted",
            State::Detached => "detached",
        }
    }
    pub fn parse(s: &str) -> Option<State> {
        Some(match s {
            "pending" => State::Pending,
            "syncing" => State::Syncing,
            "active" => State::Active,
            "failed" => State::Failed,
            "promoted" => State::Promoted,
            "detached" => State::Detached,
            _ => return None,
        })
    }
    /// Whether this state still depends on the VM staying up.
    pub fn pins(self) -> bool {
        matches!(self, State::Syncing | State::Active)
    }
    /// Whether a fresh pairing may replace a row in this state.
    pub fn is_terminal(self) -> bool {
        matches!(self, State::Failed | State::Promoted | State::Detached)
    }
}

/// One replication pairing, from this node's point of view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplRecord {
    /// The database name — also the schema key and the `pg-<database>` VM.
    pub database: String,
    pub role: Role,
    /// The other node, as named in [`crate::peers`].
    pub peer: String,
    pub publication: String,
    pub subscription: String,
    pub slot: String,
    /// The `REPLICATION` login the replica uses against the primary. Recorded
    /// on **both** sides: the primary owns it, and the replica needs it to
    /// rebuild the subscription's conninfo on a rotation.
    pub repl_role: String,
    /// Cleartext, for the same two reasons as
    /// [`crate::dedicated::Credential::password`]: it is re-applied to the
    /// guest role on every bring-up (a restore rebuilds the cluster from a
    /// dump that carries no roles), and `ALTER SUBSCRIPTION ... CONNECTION`
    /// needs it verbatim.
    pub repl_password: String,
    pub state: State,
    /// One line of human detail — normally a Postgres error. Sanitized by
    /// [`one_line`] on the way in.
    pub message: String,
    pub created_at: u64,
    pub updated_at: u64,
    /// Durable planned-switchover source fence. This is deliberately
    /// orthogonal to replication state: fencing never promotes either side.
    pub fence: Option<Fence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fence {
    /// `hard` closes the whole database; `selective` leaves only the private
    /// controller and this pairing's authenticated replication login usable.
    pub mode: String,
    pub phase: String,
    pub message: String,
    pub vm_id: String,
    pub barrier_lsn: String,
    pub requested_at: u64,
    pub updated_at: u64,
    /// Authoritative source values captured after the selective drain.
    pub sequences: Vec<SequenceSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SequenceSnapshot {
    pub schema: String,
    pub name: String,
    pub data_type: String,
    pub start_value: i64,
    pub min_value: i64,
    pub max_value: i64,
    pub increment_by: i64,
    pub cycle: bool,
    pub cache_size: i64,
    pub last_value: i64,
    pub is_called: bool,
}

impl ReplRecord {
    /// Build a record with every derived name filled in, so no caller has to
    /// remember which of the four naming helpers applies where.
    pub fn new(database: &str, role: Role, peer: &str, repl_password: &str) -> Self {
        let now = now_unix();
        Self {
            publication: names::publication_name(database),
            subscription: names::subscription_name(database),
            slot: names::slot_name(database, peer),
            repl_role: names::repl_role_name(database),
            database: database.to_string(),
            role,
            peer: peer.to_string(),
            repl_password: repl_password.to_string(),
            state: State::Pending,
            message: String::new(),
            created_at: now,
            updated_at: now,
            fence: None,
        }
    }
}

pub struct ReplStore {
    path: PathBuf,
    by_database: Mutex<HashMap<String, ReplRecord>>,
}

impl ReplStore {
    pub fn load(path: PathBuf) -> Self {
        let by_database = match std::fs::read_to_string(&path) {
            Ok(s) => parse(&s),
            Err(_) => HashMap::new(),
        };
        if !by_database.is_empty() {
            info!(
                "loaded {} replication record(s) from {}",
                by_database.len(),
                path.display()
            );
        }
        Self {
            path,
            by_database: Mutex::new(by_database),
        }
    }

    /// Every record, sorted by database for a stable render. Includes the
    /// replication password, so this is not the shape the API returns.
    pub fn list(&self) -> Vec<ReplRecord> {
        let mut out: Vec<_> = self.by_database.lock().unwrap().values().cloned().collect();
        out.sort_by(|a, b| a.database.cmp(&b.database));
        out
    }

    pub fn get(&self, database: &str) -> Option<ReplRecord> {
        self.by_database.lock().unwrap().get(database).cloned()
    }

    /// Rekey an optional logical-replication audit record while preserving all
    /// derived object names and credentials exactly as originally recorded.
    pub fn rename_database(&self, old: &str, new: &str) -> Result<()> {
        let mut map = self.by_database.lock().unwrap();
        if map.contains_key(new) {
            if !map.contains_key(old) {
                return Ok(());
            }
            bail!("cannot rename replication database {old:?}: {new:?} already exists");
        }
        let Some(mut record) = map.get(old).cloned() else {
            return Ok(());
        };
        record.database = new.to_string();
        let mut next = map.clone();
        next.remove(old);
        next.insert(new.to_string(), record);
        write_atomic(&self.path, &serialize(&next))?;
        *map = next;
        Ok(())
    }

    /// The record whose replication login is `role`. Logins are unique across
    /// records (enforced by [`Self::create`]) for the same reason dedicated
    /// roles are: the auth path's lookup must have exactly one answer.
    pub fn by_repl_role(&self, role: &str) -> Option<ReplRecord> {
        self.by_database
            .lock()
            .unwrap()
            .values()
            .find(|r| r.repl_role == role)
            .cloned()
    }

    /// The password to challenge a replication login with, or `None` if this
    /// role is not one.
    pub fn repl_password(&self, role: &str) -> Option<String> {
        self.by_repl_role(role).map(|r| r.repl_password)
    }

    /// **The predicate every lifecycle exclusion asks.** True while a pairing
    /// still depends on this database's VM being up.
    ///
    /// On a primary, stopping the VM drops the walsender and leaves an
    /// inactive slot pinning WAL; on a replica it stops consuming, so the
    /// primary's slot backs up instead. Both are recoverable only by a full
    /// re-seed, which is why this outranks every storage tier.
    pub fn is_pinned(&self, database: &str) -> bool {
        self.by_database
            .lock()
            .unwrap()
            .get(database)
            .is_some_and(|r| r.state.pins() || r.fence.is_some())
    }

    /// Every pinned database, so startup can warm them before the untracked
    /// reaper's first pass sees a running VM with no warm entry.
    pub fn pinned_databases(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .by_database
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.state.pins() || r.fence.is_some())
            .map(|r| r.database.clone())
            .collect();
        out.sort();
        out
    }

    /// Record a pairing and persist.
    ///
    /// `role_taken` is the caller's view of every *other* login this pooler
    /// knows — the dedicated credentials — so a replication login can never
    /// shadow a tenant's and make one password open the wrong thing. Passed
    /// as a closure for the same reason `pick_offload_job` takes its guards
    /// that way: it keeps this testable without standing up a registry.
    pub fn create(&self, rec: ReplRecord, role_taken: &dyn Fn(&str) -> bool) -> Result<ReplRecord> {
        if rec.database.is_empty() || rec.peer.is_empty() {
            bail!("database and peer are required");
        }
        crate::dedicated::validate_password(&rec.repl_password)?;
        if role_taken(&rec.repl_role) {
            bail!(
                "replication login {:?} collides with an existing role on this node",
                rec.repl_role
            );
        }
        {
            let mut map = self.by_database.lock().unwrap();
            // A finished or failed pairing may be replaced; a live one may not
            // — re-pairing a streaming database would silently orphan its slot.
            if let Some(old) = map.get(&rec.database)
                && (!old.state.is_terminal() || old.fence.is_some())
            {
                bail!(
                    "database {:?} is already replicating ({} with peer {:?}); \
                     detach or promote it first",
                    rec.database,
                    old.state.as_str(),
                    old.peer
                );
            }
            if !map.contains_key(&rec.database) && map.len() >= MAX_RECORDS {
                bail!("too many replication records (max {MAX_RECORDS})");
            }
            if let Some(other) = map
                .values()
                .find(|r| r.repl_role == rec.repl_role && r.database != rec.database)
            {
                bail!(
                    "replication login {:?} is already used by database {:?}",
                    rec.repl_role,
                    other.database
                );
            }
            let old = map.insert(rec.database.clone(), rec.clone());
            if let Err(e) = write_atomic(&self.path, &serialize(&map)) {
                if let Some(old) = old { map.insert(rec.database.clone(), old); } else { map.remove(&rec.database); }
                return Err(e).with_context(|| format!("persisting replication records to {}", self.path.display()));
            }
        }
        info!(
            "replication: recorded {} as {} with peer {}",
            rec.database,
            rec.role.as_str(),
            rec.peer
        );
        Ok(rec)
    }

    /// Advance a record's state and persist. `message` is sanitized to one
    /// printable line.
    pub fn set_state(&self, database: &str, state: State, message: &str) -> Result<()> {
        let mut map = self.by_database.lock().unwrap();
        let old = map.get(database).cloned().with_context(|| format!("no replication record for database {database:?}"))?;
        {
            let Some(rec) = map.get_mut(database) else {
                bail!("no replication record for database {database:?}");
            };
            if rec.state == state && rec.message == one_line(message) {
                return Ok(()); // no-op: don't rewrite the file on every poll
            }
            rec.state = state;
            rec.message = one_line(message);
            rec.updated_at = now_unix();
        }
        if let Err(e) = write_atomic(&self.path, &serialize(&map)) { map.insert(database.into(), old); return Err(e); }
        Ok(())
    }

    /// Persist fence intent/progress before the corresponding database side
    /// effect. Once present it remains until an explicit successful unfence.
    pub fn set_fence(
        &self,
        database: &str,
        phase: &str,
        message: &str,
        vm_id: &str,
        barrier_lsn: &str,
    ) -> Result<()> {
        let mut map = self.by_database.lock().unwrap();
        let old = map.get(database).cloned().with_context(|| format!("no replication record for database {database:?}"))?;
        {
            let Some(rec) = map.get_mut(database) else {
                bail!("no replication record for database {database:?}");
            };
            let now = now_unix();
            let requested_at = rec.fence.as_ref().map(|f| f.requested_at).unwrap_or(now);
            let mode = rec.fence.as_ref().map(|f| f.mode.clone()).unwrap_or_else(|| "hard".into());
            let sequences = rec.fence.as_ref().map(|f| f.sequences.clone()).unwrap_or_default();
            rec.fence = Some(Fence {
                mode,
                phase: one_line(phase),
                message: one_line(message),
                vm_id: one_line(vm_id),
                barrier_lsn: one_line(barrier_lsn),
                requested_at,
                updated_at: now,
                sequences,
            });
            rec.updated_at = now;
        }
        if let Err(e) = write_atomic(&self.path, &serialize(&map)) { map.insert(database.into(), old); return Err(e); }
        Ok(())
    }

    pub fn set_fence_payload(
        &self,
        database: &str,
        mode: &str,
        phase: &str,
        message: &str,
        vm_id: &str,
        barrier_lsn: &str,
        sequences: Vec<SequenceSnapshot>,
    ) -> Result<()> {
        let mut map = self.by_database.lock().unwrap();
        let old = map.get(database).cloned().context("replication record disappeared")?;
        let rec = map.get_mut(database).context("replication record disappeared")?;
        let now = now_unix();
        let requested_at = rec.fence.as_ref().map(|f| f.requested_at).unwrap_or(now);
        rec.fence = Some(Fence {
            mode: one_line(mode), phase: one_line(phase), message: one_line(message),
            vm_id: one_line(vm_id), barrier_lsn: one_line(barrier_lsn), requested_at,
            updated_at: now, sequences,
        });
        rec.updated_at = now;
        if let Err(e) = write_atomic(&self.path, &serialize(&map)) { map.insert(database.into(), old); return Err(e); }
        Ok(())
    }

    pub fn clear_fence(&self, database: &str) -> Result<()> {
        let mut map = self.by_database.lock().unwrap();
        let old = map.get(database).cloned().with_context(|| format!("no replication record for database {database:?}"))?;
        {
            let Some(rec) = map.get_mut(database) else {
                bail!("no replication record for database {database:?}");
            };
            rec.fence = None;
            rec.updated_at = now_unix();
        }
        if let Err(e) = write_atomic(&self.path, &serialize(&map)) { map.insert(database.into(), old); return Err(e); }
        Ok(())
    }

    pub fn is_fenced(&self, database: &str) -> bool {
        self.get(database).is_some_and(|r| r.fence.is_some())
    }

    /// Forget a pairing entirely. The Postgres objects are the caller's
    /// problem — this only drops the bookkeeping.
    pub fn remove(&self, database: &str) -> Result<bool> {
        let mut map = self.by_database.lock().unwrap();
        if map.get(database).is_some_and(|r| r.fence.is_some()) { bail!("{database} is fenced; explicitly unfence before removal"); }
        let Some(old) = map.remove(database) else { return Ok(false); };
        if let Err(e) = write_atomic(&self.path, &serialize(&map)) { map.insert(database.into(), old); return Err(e); }
        info!("replication: removed the record for {database}");
        Ok(true)
    }

    /// Whether any record still names `peer`, so a peer removal can be
    /// refused rather than silently orphaning a live pairing's control path.
    pub fn peer_in_use(&self, peer: &str) -> Option<String> {
        self.by_database
            .lock()
            .unwrap()
            .values()
            .find(|r| r.peer == peer && !r.state.is_terminal())
            .map(|r| r.database.clone())
    }
}

/// Collapse anything into one printable ASCII line, capped.
///
/// Postgres error text is the only unvalidated string that reaches this file,
/// and this is what preserves the module invariant that no field can contain
/// a tab or a newline — so nothing else has to escape anything.
fn one_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_MESSAGE));
    let mut last_space = false;
    for c in s.chars() {
        let c = if c.is_ascii_graphic() { c } else { ' ' };
        if c == ' ' {
            if last_space || out.is_empty() {
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }
        if out.len() + 1 > MAX_MESSAGE {
            break;
        }
        out.push(c);
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

const MAX_MESSAGE: usize = 200;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse(s: &str) -> HashMap<String, ReplRecord> {
    let mut map = HashMap::new();
    for line in s.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 10 {
            corrupt("too few fields");
            continue;
        }
        let (Some(role), Some(state)) = (Role::parse(f[1]), State::parse(f[8])) else {
            corrupt("unrecognized role or state");
            continue;
        };
        if f[0].is_empty() || f[2].is_empty() || f[6].is_empty() {
            corrupt("empty database, peer or login");
            continue;
        }
        map.insert(
            f[0].to_string(),
            ReplRecord {
                database: f[0].to_string(),
                role,
                peer: f[2].to_string(),
                publication: f[3].to_string(),
                subscription: f[4].to_string(),
                slot: f[5].to_string(),
                repl_role: f[6].to_string(),
                repl_password: f[7].to_string(),
                state,
                message: f[9].to_string(),
                created_at: f.get(10).and_then(|v| v.parse().ok()).unwrap_or(0),
                updated_at: f.get(11).and_then(|v| v.parse().ok()).unwrap_or(0),
                fence: f.get(12).filter(|v| !v.is_empty()).map(|phase| {
                    let mode = f.get(18).filter(|v| !v.is_empty()).unwrap_or(&"hard").to_string();
                    let sequences = f.get(19).and_then(|v| serde_json::from_str(v).ok());
                    let invalid = mode == "selective" && sequences.is_none();
                    Fence {
                    mode,
                    phase: if invalid { "error".into() } else { (*phase).to_string() },
                    message: if invalid { "invalid sequence snapshot; source fence retained".into() } else { f.get(13).unwrap_or(&"").to_string() },
                    vm_id: f.get(14).unwrap_or(&"").to_string(),
                    barrier_lsn: if invalid { String::new() } else { f.get(15).unwrap_or(&"").to_string() },
                    requested_at: f.get(16).and_then(|v| v.parse().ok()).unwrap_or(0),
                    updated_at: f.get(17).and_then(|v| v.parse().ok()).unwrap_or(0),
                    sequences: sequences.unwrap_or_default(),
                    }
                }),
            },
        );
    }
    map
}

/// Both warn and journal, for the same reason [`crate::peers`] does: a dropped
/// record un-pins a VM that is still replicating, which is silent until the
/// idle reaper stops it and the pairing breaks.
fn corrupt(why: &str) {
    tracing::warn!("skipping malformed replication line ({why})");
    crate::events::journal_error(
        "replication",
        format!(
            "skipped a malformed line in the replication file ({why}) — a live pairing may \
             now be unprotected from the idle reaper and the offload tiers"
        ),
    );
}

fn serialize(map: &HashMap<String, ReplRecord>) -> String {
    let mut records: Vec<_> = map.values().collect();
    records.sort_by(|a, b| a.database.cmp(&b.database));
    let mut out = String::new();
    for r in records {
        for field in [
            r.database.as_str(),
            r.role.as_str(),
            r.peer.as_str(),
            r.publication.as_str(),
            r.subscription.as_str(),
            r.slot.as_str(),
            r.repl_role.as_str(),
            r.repl_password.as_str(),
            r.state.as_str(),
            r.message.as_str(),
        ] {
            out.push_str(field);
            out.push('\t');
        }
        out.push_str(&r.created_at.to_string());
        out.push('\t');
        out.push_str(&r.updated_at.to_string());
        out.push('\t');
        if let Some(f) = &r.fence {
            for field in [&f.phase, &f.message, &f.vm_id, &f.barrier_lsn] {
                out.push_str(field);
                out.push('\t');
            }
            out.push_str(&f.requested_at.to_string());
            out.push('\t');
            out.push_str(&f.updated_at.to_string());
            out.push('\t');
            out.push_str(&f.mode);
            out.push('\t');
            out.push_str(&serde_json::to_string(&f.sequences).expect("sequence snapshots serialize"));
        }
        out.push('\n');
    }
    out
}

/// Temp file + rename at mode `0600`: this holds the replication login's
/// cleartext password.
fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .with_context(|| format!("tightening permissions on {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::File::open(parent)?.sync_all()
        .with_context(|| format!("syncing replication record directory {}", parent.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> ReplStore {
        let path = std::env::temp_dir().join(format!(
            "pgvmpool-replication-{}-{:?}.tsv",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        ReplStore::load(path)
    }

    fn free(_role: &str) -> bool {
        false
    }

    fn rec(db: &str, role: Role) -> ReplRecord {
        ReplRecord::new(db, role, "node_b", "hunter2hunter2")
    }

    #[test]
    fn create_advance_and_remove_round_trip_through_disk() {
        let s = store();
        let r = s.create(rec("acme", Role::Primary), &free).unwrap();
        assert_eq!(r.publication, "pgfc_pub_acme");
        assert_eq!(r.slot, "pgfc_acme_node_b");
        assert_eq!(r.repl_role, "acme_pgfcrepl");
        assert_eq!(r.state, State::Pending);

        s.set_state("acme", State::Active, "").unwrap();
        let reloaded = ReplStore::load(s.path.clone());
        let back = reloaded.get("acme").unwrap();
        assert_eq!(back.state, State::Active);
        assert_eq!(back.repl_password, "hunter2hunter2");
        assert_eq!(back.role, Role::Primary);

        assert!(s.remove("acme").unwrap());
        assert!(!s.remove("acme").unwrap());
        assert!(ReplStore::load(s.path.clone()).list().is_empty());
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn rename_preserves_replication_identity_and_is_durable() {
        let s = store();
        let original = s.create(rec("old_db", Role::Primary), &free).unwrap();
        s.rename_database("old_db", "new_db").unwrap();
        s.rename_database("old_db", "new_db").unwrap();
        let renamed = ReplStore::load(s.path.clone()).get("new_db").unwrap();
        assert_eq!(renamed.slot, original.slot);
        assert_eq!(renamed.repl_role, original.repl_role);
        assert_eq!(renamed.repl_password, original.repl_password);
        s.create(rec("occupied", Role::Replica), &free).unwrap();
        assert!(s.rename_database("new_db", "occupied").is_err());
        assert!(s.get("new_db").is_some());
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn fence_round_trips_and_pins_until_explicit_clear() {
        let s = store();
        s.create(rec("acme", Role::Primary), &free).unwrap();
        s.set_fence("acme", "intent", "requested", "vm-7", "").unwrap();
        assert!(s.is_fenced("acme"));
        assert!(s.is_pinned("acme"), "a pending fence survives lifecycle cleanup");
        let reloaded = ReplStore::load(s.path.clone());
        let f = reloaded.get("acme").unwrap().fence.unwrap();
        assert_eq!(f.phase, "intent");
        assert_eq!(f.vm_id, "vm-7");
        reloaded.set_fence("acme", "ready", "flushed", "vm-7", "0/CAFE").unwrap();
        assert_eq!(reloaded.get("acme").unwrap().fence.unwrap().barrier_lsn, "0/CAFE");
        reloaded.clear_fence("acme").unwrap();
        assert!(!reloaded.is_fenced("acme"));
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn selective_fence_payload_round_trips_without_moving_identity() {
        let s = store();
        s.create(rec("acme", Role::Primary), &free).unwrap();
        let sequence = SequenceSnapshot {
            schema: "odd schema".into(), name: "orders_seq".into(), data_type: "bigint".into(),
            start_value: 1, min_value: 1, max_value: i64::MAX, increment_by: 1,
            cycle: false, cache_size: 32, last_value: 96, is_called: true,
        };
        s.set_fence_payload("acme", "selective", "ready", "captured", "vm-7", "0/BEEF", vec![sequence.clone()]).unwrap();
        let fence = ReplStore::load(s.path.clone()).get("acme").unwrap().fence.unwrap();
        assert_eq!(fence.mode, "selective");
        assert_eq!(fence.vm_id, "vm-7");
        assert_eq!(fence.barrier_lsn, "0/BEEF");
        assert_eq!(fence.sequences, vec![sequence]);
        let content = std::fs::read_to_string(&s.path).unwrap();
        let malformed = content.replace("\"last_value\":96", "\"last_value\":null");
        assert_ne!(content, malformed);
        std::fs::write(&s.path, malformed).unwrap();
        let recovered = ReplStore::load(s.path.clone());
        let fence = recovered.get("acme").unwrap().fence.unwrap();
        assert!(recovered.is_fenced("acme"));
        assert_eq!(fence.phase, "error");
        assert!(fence.barrier_lsn.is_empty(), "corrupt sequence evidence must invalidate readiness");
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn failed_fence_clear_keeps_memory_and_disk_fenced() {
        let s = store();
        s.create(rec("acme", Role::Primary), &free).unwrap();
        s.set_fence("acme", "ready", "flushed", "vm-7", "0/CAFE").unwrap();
        let expected = s.get("acme").unwrap().fence;
        // Force the atomic replacement's temporary-file open to fail without
        // relying on permissions (which root test runners can bypass).
        let temporary = s.path.with_extension("tmp");
        std::fs::create_dir(&temporary).unwrap();
        assert!(s.clear_fence("acme").is_err());
        assert_eq!(s.get("acme").unwrap().fence, expected);
        assert_eq!(ReplStore::load(s.path.clone()).get("acme").unwrap().fence, expected);
        std::fs::remove_dir(temporary).unwrap();
        std::fs::remove_file(&s.path).unwrap();
    }

    #[test]
    fn a_fenced_terminal_record_cannot_be_recreated_or_removed() {
        let s = store();
        s.create(rec("acme", Role::Primary), &free).unwrap();
        s.set_state("acme", State::Detached, "done").unwrap();
        s.set_fence("acme", "error", "operator action required", "vm-7", "").unwrap();
        assert!(s.create(rec("acme", Role::Replica), &free).is_err());
        assert!(s.remove("acme").is_err());
        assert_eq!(s.get("acme").unwrap().role, Role::Primary);
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn replication_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let s = store();
        s.create(rec("acme", Role::Primary), &free).unwrap();
        let mode = std::fs::metadata(&s.path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "the replication login's password must not leak"
        );
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn is_pinned_only_for_syncing_and_active() {
        let s = store();
        s.create(rec("acme", Role::Primary), &free).unwrap();
        // The whole truth table, because every lifecycle exclusion trusts it.
        for (state, pinned) in [
            (State::Pending, false),
            (State::Syncing, true),
            (State::Active, true),
            (State::Failed, false),
            (State::Promoted, false),
            (State::Detached, false),
        ] {
            s.set_state("acme", state, "").unwrap();
            assert_eq!(s.is_pinned("acme"), pinned, "{state:?}");
            assert_eq!(s.pinned_databases().is_empty(), !pinned, "{state:?}");
        }
        // A database with no record is never pinned.
        assert!(!s.is_pinned("other"));
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn refuses_to_repair_a_live_pairing_but_allows_replacing_a_finished_one() {
        let s = store();
        s.create(rec("acme", Role::Primary), &free).unwrap();
        s.set_state("acme", State::Active, "").unwrap();
        let err = s
            .create(rec("acme", Role::Primary), &free)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already replicating"), "{err}");
        // ...but a detached or failed one may be re-paired.
        s.set_state("acme", State::Detached, "").unwrap();
        assert!(s.create(rec("acme", Role::Replica), &free).is_ok());
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn refuses_a_login_that_collides_with_an_existing_role() {
        let s = store();
        // A dedicated tenant already owns this name.
        let taken = |r: &str| r == "acme_pgfcrepl";
        let err = s
            .create(rec("acme", Role::Primary), &taken)
            .unwrap_err()
            .to_string();
        assert!(err.contains("collides"), "{err}");
        assert!(s.list().is_empty(), "nothing should have landed");
        // A short password is refused too — this one the pooler mints.
        let mut short = rec("acme", Role::Primary);
        short.repl_password = "short".into();
        assert!(s.create(short, &free).is_err());
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn message_is_sanitized_to_one_printable_line() {
        let s = store();
        s.create(rec("acme", Role::Primary), &free).unwrap();
        s.set_state("acme", State::Failed, "boom\tnope\nmore   spaces\u{0}x")
            .unwrap();
        let m = s.get("acme").unwrap().message;
        assert!(!m.contains('\t') && !m.contains('\n'), "{m:?}");
        assert_eq!(m, "boom nope more spaces x");
        // The file still reparses to exactly one record.
        assert_eq!(ReplStore::load(s.path.clone()).list().len(), 1);

        // And a pathological length can't blow the line out.
        s.set_state("acme", State::Failed, &"x".repeat(10_000))
            .unwrap();
        assert!(s.get("acme").unwrap().message.len() <= MAX_MESSAGE);
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn peer_in_use_reports_only_live_pairings() {
        let s = store();
        s.create(rec("acme", Role::Primary), &free).unwrap();
        s.set_state("acme", State::Syncing, "").unwrap();
        assert_eq!(s.peer_in_use("node_b").as_deref(), Some("acme"));
        assert_eq!(s.peer_in_use("node_c"), None);
        s.set_state("acme", State::Detached, "").unwrap();
        assert_eq!(s.peer_in_use("node_b"), None);
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn parse_skips_corrupt_lines() {
        let good = "acme\tprimary\tnode_b\tpub\tsub\tslot\tacme_pgfcrepl\tpw\tactive\t\t1\t2\n";
        let map = parse(&format!(
            "{good}garbage\n\
             b\tnotarole\tp\tpub\tsub\tslot\trole\tpw\tactive\t\t1\t2\n\
             c\tprimary\tp\tpub\tsub\tslot\trole\tpw\tnotastate\t\t1\t2\n\
             \tprimary\tp\tpub\tsub\tslot\trole\tpw\tactive\t\t1\t2\n"
        ));
        assert_eq!(map.len(), 1);
        assert_eq!(map["acme"].created_at, 1);
        assert_eq!(map["acme"].state, State::Active);
    }

    #[test]
    fn serialize_round_trips_sorted() {
        let s = store();
        s.create(rec("beta", Role::Replica), &free).unwrap();
        s.create(rec("acme", Role::Primary), &free).unwrap();
        let text = std::fs::read_to_string(&s.path).unwrap();
        assert!(text.starts_with("acme\t"), "{text}");
        let reparsed = parse(&text);
        assert_eq!(reparsed["beta"].role, Role::Replica);
        assert_eq!(reparsed["acme"].subscription, "pgfc_sub_acme");
        let _ = std::fs::remove_file(&s.path);
    }
}
