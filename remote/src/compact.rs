//! Compaction: merge a repo's small packs into one, without a lock service.
//!
//! Every push adds a pack to `state.json`, and nothing else ever removes one,
//! so a busy repo's state lists hundreds of small packs. Every cold cache
//! downloads all of them, and every fetch searches all of them. Compaction
//! follows the design of the size-tiered merges in Enroute and of `git repack
//! --geometric`:
//!
//! - **Which packs.** Packs fall into size classes, a factor `F` apart
//!   (`REMOTE_COMPACT_FACTOR`, 8) from 64 KiB. When `F` packs are at or below
//!   some class, the smallest such class, they merge. Each byte is rewritten
//!   about once per class, and no output is larger than
//!   `REMOTE_COMPACT_MAX_PACK_MB`.
//! - **How.** `git pack-objects --stdin-packs` writes every object of the
//!   inputs, reachable or not, into one pack. The result is checked to hold
//!   every input object before anything is uploaded. Since compaction drops
//!   nothing, a listed pack's objects are always in some listed pack.
//! - **The swap.** The new pack is uploaded, then a `retired/<pack>.json`
//!   marker is written for each input, then `state.json` is replaced under
//!   `If-Match`: the inputs leave the list and the new pack joins it. Pushes
//!   only add packs and move refs, so a push that lands first does not waste
//!   the work: the swap is reapplied to the newer state, as long as every
//!   input is still listed. Nothing holds a lock while git packs, and a push
//!   to the same repo never waits for one.
//! - **Deletion.** A reader in any region may have read the old state just
//!   before the swap and still be downloading its packs. A replaced pack is
//!   therefore deleted only once its marker is older than the grace period
//!   (`REMOTE_COMPACT_GRACE_SECS`, 6 hours). Its marker is kept for one more
//!   grace period afterwards. If a push ever re-lists a pack of the same name
//!   in that window, hydration finds the marker and passes over the missing
//!   pack, whose objects are in the pack that replaced it.
//!
//! Packs that no state ever listed, left by pushes that lost their race, are
//! not touched: nothing proves their names will not be pushed again.
//!
//! The state format is unchanged. An older instance reading a compacted state
//! downloads the merged pack like any other, and its pushes keep the swap.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::git::{self, GitError, GitService, RepoRef};
use crate::registry::{self, RepoState};
use crate::sigv4::now_unix;
use crate::store::{Cond, Put, Store, StoreError};

/// The smallest size class: packs below it count as this big.
const BASE_CLASS_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug)]
pub struct Policy {
    /// Run after writes (`REMOTE_COMPACT`, on unless `0`/`false`/`off`/`no`).
    /// The admin endpoint compacts either way.
    pub enabled: bool,
    pub factor: usize,
    pub max_pack_bytes: u64,
    pub grace_secs: u64,
    /// How long after a write the repo is looked at, so a burst of pushes is
    /// compacted once.
    pub delay_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            enabled: true,
            factor: 8,
            max_pack_bytes: 128 * 1024 * 1024,
            grace_secs: 6 * 3600,
            delay_secs: 30,
        }
    }
}

impl Policy {
    /// A compaction that has run this long gives up before its swap, so the
    /// output of a loser is never mistaken for a winner's (see [`run`]).
    fn deadline(&self) -> Duration {
        Duration::from_secs((self.grace_secs / 4).max(60))
    }
}

/// `retired/<pack>.json`: this pack was taken out of the state by a
/// compaction, or was the output of one that lost.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Retired {
    pub retired_at: u64,
    /// The pack holding its objects; `None` for a losing compaction's output.
    #[serde(default)]
    pub covered_by: Option<String>,
    /// When the pack itself was deleted from the store.
    #[serde(default)]
    pub deleted_at: Option<u64>,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    /// `compacted`, `nothing to do`, or why the swap did not happen.
    pub outcome: String,
    pub merged: Vec<String>,
    pub into: Option<String>,
    pub objects: usize,
    pub bytes_before: u64,
    pub bytes_after: u64,
    /// Listed packs already swept from the store, now dropped from the state.
    pub dropped: Vec<String>,
    pub packs_listed: usize,
    pub sweep: SweepReport,
}

#[derive(Debug, Default, Serialize)]
pub struct SweepReport {
    pub deleted_packs: usize,
    pub deleted_markers: usize,
    /// Markers still waiting out a grace period.
    pub pending: usize,
}

/// The size class of a pack of `bytes`.
fn class_of(bytes: u64, factor: usize) -> u32 {
    let mut x = bytes.max(BASE_CLASS_BYTES) / BASE_CLASS_BYTES;
    let mut c = 0;
    while x >= factor as u64 {
        x /= factor as u64;
        c += 1;
    }
    c
}

/// Which packs to merge, smallest first, or `None`. `packs` is
/// `(name, bytes)`.
pub fn plan(packs: &[(String, u64)], factor: usize, max_pack_bytes: u64) -> Option<Vec<String>> {
    let factor = factor.max(2);
    let mut small: Vec<&(String, u64)> = packs.iter().filter(|p| p.1 < max_pack_bytes).collect();
    small.sort_by_key(|p| (p.1, p.0.clone()));
    let top = small.last().map(|p| class_of(p.1, factor))?;
    for class in 0..=top {
        let k = small
            .iter()
            .take_while(|p| class_of(p.1, factor) <= class)
            .count();
        if k < factor {
            continue;
        }
        let mut take = &small[..k];
        while take.len() > 1 && take.iter().map(|p| p.1).sum::<u64>() > max_pack_bytes {
            take = &take[..take.len() - 1];
        }
        return (take.len() >= 2).then(|| take.iter().map(|p| p.0.clone()).collect());
    }
    None
}

fn internal(m: impl Into<String>) -> GitError {
    GitError::new(axum::http::StatusCode::INTERNAL_SERVER_ERROR, m)
}

fn store_err(e: StoreError) -> GitError {
    internal(e.to_string())
}

/// Compact `r` if its packs call for it, then sweep what earlier compactions
/// retired.
pub async fn run(git: &GitService, r: &RepoRef, policy: &Policy) -> Result<Report, GitError> {
    let _one = git.compact_gate.lock().await;
    let mut report = compact(git, r, policy).await?;
    report.sweep = sweep(&git.store, r, policy.grace_secs, now_unix())
        .await
        .map_err(store_err)?;
    Ok(report)
}

async fn compact(git: &GitService, r: &RepoRef, policy: &Policy) -> Result<Report, GitError> {
    let started = Instant::now();
    let label = format!("{}/{}", r.ns, r.name);
    let ex = git.exclusive(r).await?;
    let pack_dir = ex.path.join("objects/pack");
    let mut sizes = Vec::new();
    let mut dropped = Vec::new();
    for p in &ex.state.packs {
        match tokio::fs::metadata(pack_dir.join(format!("{p}.pack"))).await {
            Ok(m) if pack_dir.join(format!("{p}.idx")).exists() => sizes.push((p.clone(), m.len())),
            // Hydration passed over it: retired, swept, and covered.
            _ => dropped.push(p.clone()),
        }
    }
    let cache = ex.path.clone();
    let packs_listed = ex.state.packs.len();
    drop(ex);

    let merged = plan(&sizes, policy.factor, policy.max_pack_bytes).unwrap_or_default();
    let mut report = Report {
        packs_listed,
        dropped: dropped.clone(),
        ..Default::default()
    };
    if merged.is_empty() && dropped.is_empty() {
        report.outcome = "nothing to do".into();
        return Ok(report);
    }

    let built = if merged.is_empty() {
        None
    } else {
        report.bytes_before = sizes
            .iter()
            .filter(|(n, _)| merged.contains(n))
            .map(|p| p.1)
            .sum();
        Some(build(git, &cache, &merged).await?)
    };
    if started.elapsed() > policy.deadline() {
        report.outcome = "gave up: building the pack outlasted the deadline".into();
        if let Some(b) = &built {
            retire_orphan(&git.store, r, &b.name).await;
        }
        return Ok(report);
    }

    if let Some(b) = &built {
        for ext in ["pack", "idx"] {
            let file = format!("{}.{ext}", b.name);
            let bytes = tokio::fs::read(b.dir.path().join(&file))
                .await
                .map_err(|e| internal(format!("{file}: {e}")))?;
            git.store
                .put(
                    &r.bucket,
                    &registry::pack_key(&r.ns, &r.name, &file),
                    bytes,
                    Cond::None,
                )
                .await
                .map_err(store_err)?;
        }
        // Before the swap, so a crash after it cannot leave a replaced pack
        // that nothing will ever delete.
        let marker = serde_json::to_vec_pretty(&Retired {
            retired_at: now_unix(),
            covered_by: Some(b.name.clone()),
            deleted_at: None,
        })
        .expect("serializable");
        for p in &merged {
            git.store
                .put(
                    &r.bucket,
                    &registry::retired_key(&r.ns, &r.name, p),
                    marker.clone(),
                    Cond::None,
                )
                .await
                .map_err(store_err)?;
        }
    }

    let gone: HashSet<&String> = merged.iter().chain(&dropped).collect();
    let mut swapped = None;
    for _ in 0..8 {
        if started.elapsed() > policy.deadline() {
            report.outcome = "gave up: the swap outlasted the deadline".into();
            break;
        }
        let (cur, etag) = registry::state(&git.store, &r.bucket, &r.ns, &r.name).await?;
        let Some(etag) = etag else {
            report.outcome = "gave up: the repo was deleted".into();
            break;
        };
        if !merged.iter().all(|p| cur.packs.contains(p)) {
            report.outcome = "gave up: another compaction replaced these packs first".into();
            break;
        }
        let mut next: RepoState = cur.clone();
        next.packs.retain(|p| !gone.contains(p));
        if let Some(b) = &built
            && !next.packs.contains(&b.name)
        {
            next.packs.push(b.name.clone());
        }
        next.version = cur.version + 1;
        next.updated_at = now_unix();
        let body = serde_json::to_vec_pretty(&next).expect("serializable");
        match git
            .store
            .put(
                &r.bucket,
                &registry::state_key(&r.ns, &r.name),
                body,
                Cond::Matches(etag),
            )
            .await
            .map_err(store_err)?
        {
            Put::Written(_) => {
                swapped = Some(next);
                break;
            }
            // A push landed in between: reapply the swap to its state.
            Put::PreconditionFailed => continue,
        }
    }
    let Some(next) = swapped else {
        if report.outcome.is_empty() {
            report.outcome = "gave up: the repo kept changing".into();
        }
        if let Some(b) = &built {
            retire_orphan(&git.store, r, &b.name).await;
        }
        tracing::info!(repo = %label, outcome = %report.outcome, "compaction did not swap");
        return Ok(report);
    };

    // Swap the local files too, so this cache does not download its own
    // output. Held exclusively: no fetch is reading the inputs.
    {
        let _guard = git.lock_for(r).write_owned().await;
        if let Some(b) = &built {
            for ext in ["pack", "rev", "idx"] {
                let file = format!("{}.{ext}", b.name);
                let from = b.dir.path().join(&file);
                if from.exists() {
                    tokio::fs::rename(&from, pack_dir.join(&file))
                        .await
                        .map_err(|e| internal(e.to_string()))?;
                }
            }
        }
        let _ = git::prune_packs(&pack_dir, &next.packs).await;
    }
    report.outcome = "compacted".into();
    report.packs_listed = next.packs.len();
    if let Some(b) = built {
        report.objects = b.objects;
        report.bytes_after = b.bytes;
        report.into = Some(b.name);
    }
    report.merged = merged;
    tracing::info!(
        repo = %label,
        merged = report.merged.len(),
        dropped = report.dropped.len(),
        bytes_before = report.bytes_before,
        bytes_after = report.bytes_after,
        packs = report.packs_listed,
        "compacted",
    );
    Ok(report)
}

/// A merged pack waiting in a scratch directory.
struct Built {
    dir: tempfile::TempDir,
    name: String,
    objects: usize,
    bytes: u64,
}

/// Pack every object of `inputs` (in `cache`) into one new pack, and check
/// that none went missing.
async fn build(git: &GitService, cache: &Path, inputs: &[String]) -> Result<Built, GitError> {
    let tmp_root = git.cache_dir.join("tmp");
    tokio::fs::create_dir_all(&tmp_root)
        .await
        .map_err(|e| internal(e.to_string()))?;
    let dir = tempfile::Builder::new()
        .prefix("compact-")
        .tempdir_in(&tmp_root)
        .map_err(|e| internal(e.to_string()))?;
    let mut cmd = git.git();
    cmd.arg("--git-dir")
        .arg(cache)
        .args(["pack-objects", "--stdin-packs", "--delta-base-offset", "-q"])
        .arg(dir.path().join("pack"));
    let list: String = inputs.iter().map(|p| format!("{p}.pack\n")).collect();
    let out = piped(git, cmd, list.into_bytes()).await?;
    let hash = String::from_utf8_lossy(&out).trim().to_string();
    let name = format!("pack-{hash}");
    if !git::valid_pack_name(&name) {
        return Err(internal(format!(
            "pack-objects printed {hash:?}, not a pack name"
        )));
    }

    let mut want = HashSet::new();
    for p in inputs {
        want.extend(index_ids(git, &cache.join("objects/pack").join(format!("{p}.idx"))).await?);
    }
    let have = index_ids(git, &dir.path().join(format!("{name}.idx"))).await?;
    if let Some(missing) = want.iter().find(|id| !have.contains(*id)) {
        return Err(internal(format!(
            "compaction lost object {missing}; nothing was changed"
        )));
    }
    let bytes = tokio::fs::metadata(dir.path().join(format!("{name}.pack")))
        .await
        .map_err(|e| internal(e.to_string()))?
        .len();
    Ok(Built {
        dir,
        name,
        objects: have.len(),
        bytes,
    })
}

/// The object ids a pack index lists.
async fn index_ids(git: &GitService, idx: &Path) -> Result<HashSet<String>, GitError> {
    let bytes = tokio::fs::read(idx)
        .await
        .map_err(|e| internal(format!("{}: {e}", idx.display())))?;
    let mut cmd = git.git();
    cmd.arg("show-index");
    let out = piped(git, cmd, bytes).await?;
    Ok(String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1).map(String::from))
        .collect())
}

async fn piped(
    git: &GitService,
    mut cmd: tokio::process::Command,
    input: Vec<u8>,
) -> Result<Vec<u8>, GitError> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| internal(format!("cannot run {}: {e}", git.git_bin)))?;
    let mut stdin = child.stdin.take().expect("piped");
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(&input).await;
    });
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| internal(e.to_string()))?;
    let _ = writer.await;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(internal(format!(
            "git failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// The output of a compaction that did not swap is garbage, unless a winner
/// built a pack of the same name. A marker lets the sweep decide later.
async fn retire_orphan(store: &Store, r: &RepoRef, pack: &str) {
    let marker = serde_json::to_vec_pretty(&Retired {
        retired_at: now_unix(),
        covered_by: None,
        deleted_at: None,
    })
    .expect("serializable");
    if let Err(e) = store
        .put(
            &r.bucket,
            &registry::retired_key(&r.ns, &r.name, pack),
            marker,
            Cond::None,
        )
        .await
    {
        tracing::warn!(repo = %format!("{}/{}", r.ns, r.name), %pack, error = %e, "cannot mark an unused compaction output");
    }
}

/// Delete what compactions retired once nobody can still need it.
///
/// For each marker, against the state read after listing:
///
/// - listed and present: the swap never happened, or the name was pushed
///   again. The marker goes once it is a grace period old.
/// - listed and missing: kept. Hydration passes over the pack until the next
///   compaction drops it from the state.
/// - not listed, a grace period after retirement: the pack is deleted, and the
///   marker records when.
/// - not listed, a grace period after deletion: the marker goes.
pub async fn sweep(
    store: &Store,
    r: &RepoRef,
    grace_secs: u64,
    now: u64,
) -> Result<SweepReport, StoreError> {
    let prefix = registry::repo_prefix(&r.ns, &r.name);
    let retired_prefix = format!("{prefix}retired/");
    let markers: Vec<String> = store
        .list(&r.bucket, &retired_prefix)
        .await?
        .into_iter()
        .filter_map(|k| {
            k.strip_prefix(&retired_prefix)?
                .strip_suffix(".json")
                .filter(|p| git::valid_pack_name(p))
                .map(String::from)
        })
        .collect();
    let mut report = SweepReport::default();
    if markers.is_empty() {
        return Ok(report);
    }
    let packs_prefix = format!("{prefix}packs/");
    let mut present: HashMap<String, Vec<String>> = HashMap::new();
    for k in store.list(&r.bucket, &packs_prefix).await? {
        if let Some((base, _)) = k
            .strip_prefix(&packs_prefix)
            .and_then(|f| f.rsplit_once('.'))
        {
            present.entry(base.to_string()).or_default().push(k.clone());
        }
    }
    let (state, etag) = registry::state(store, &r.bucket, &r.ns, &r.name)
        .await
        .map_err(|e| StoreError {
            status: None,
            message: e.to_string(),
        })?;
    if etag.is_none() {
        return Ok(report);
    }
    let listed: HashSet<&String> = state.packs.iter().collect();

    for pack in markers {
        let key = registry::retired_key(&r.ns, &r.name, &pack);
        let Some(obj) = store.get(&r.bucket, &key).await? else {
            continue;
        };
        let Ok(mut m) = serde_json::from_slice::<Retired>(&obj.bytes) else {
            tracing::warn!(%key, "unreadable retirement marker; leaving it");
            report.pending += 1;
            continue;
        };
        let files = present.get(&pack);
        let aged = |t: u64| now >= t.saturating_add(grace_secs);
        match (listed.contains(&pack), files) {
            (true, Some(_)) if aged(m.retired_at) => {
                store.delete(&r.bucket, &key).await?;
                report.deleted_markers += 1;
            }
            (true, _) => report.pending += 1,
            (false, Some(files)) if m.deleted_at.is_none() && aged(m.retired_at) => {
                // The index first: a half-deleted pack is then one git
                // cannot find, not one it finds broken.
                let mut files = files.clone();
                files.sort_by_key(|f| !f.ends_with(".idx"));
                for f in files {
                    store.delete(&r.bucket, &f).await?;
                }
                m.deleted_at = Some(now);
                put_marker(store, r, &key, &m).await?;
                report.deleted_packs += 1;
                report.pending += 1;
            }
            (false, None) if m.deleted_at.is_none() => {
                m.deleted_at = Some(now);
                put_marker(store, r, &key, &m).await?;
                report.pending += 1;
            }
            (false, _) if m.deleted_at.is_some_and(aged) => {
                store.delete(&r.bucket, &key).await?;
                report.deleted_markers += 1;
            }
            _ => report.pending += 1,
        }
    }
    Ok(report)
}

async fn put_marker(store: &Store, r: &RepoRef, key: &str, m: &Retired) -> Result<(), StoreError> {
    let body = serde_json::to_vec_pretty(m).expect("serializable");
    store
        .put(&r.bucket, key, body, Cond::None)
        .await
        .map(|_| ())
}

/// Start the background compactor and connect `git`'s writes to it.
///
/// A write queues the repo `delay_secs` later, once however many writes
/// arrive meanwhile. One repo is compacted at a time. A repo whose sweep left
/// markers pending is looked at again a grace period later, so replaced packs
/// are deleted even if it is never pushed again, while this instance runs.
pub fn spawn(git: Arc<GitService>, policy: Policy) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<RepoRef>();
    let (queue_tx, mut queue) = tokio::sync::mpsc::unbounded_channel::<RepoRef>();
    git.set_compactor(tx.clone());
    let key = |r: &RepoRef| format!("{}/{}/{}", r.bucket, r.ns, r.name);
    let waiting: Arc<Mutex<HashSet<String>>> = Arc::default();
    let revisit: Arc<Mutex<HashSet<String>>> = Arc::default();

    let delay = Duration::from_secs(policy.delay_secs);
    let w = waiting.clone();
    tokio::spawn(async move {
        while let Some(r) = rx.recv().await {
            if !w.lock().unwrap_or_else(|e| e.into_inner()).insert(key(&r)) {
                continue;
            }
            let q = queue_tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = q.send(r);
            });
        }
    });

    tokio::spawn(async move {
        while let Some(r) = queue.recv().await {
            waiting
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key(&r));
            let label = format!("{}/{}", r.ns, r.name);
            match run(&git, &r, &policy).await {
                Ok(report) => {
                    if report.sweep.deleted_packs + report.sweep.deleted_markers > 0 {
                        tracing::info!(repo = %label, sweep = ?report.sweep, "swept retired packs");
                    }
                    if report.sweep.pending > 0
                        && revisit
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(key(&r))
                    {
                        let (tx, revisit, again) = (
                            tx.clone(),
                            revisit.clone(),
                            Duration::from_secs(policy.grace_secs + 60),
                        );
                        tokio::spawn(async move {
                            tokio::time::sleep(again).await;
                            revisit
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&key(&r));
                            let _ = tx.send(r);
                        });
                    }
                }
                Err(e) => tracing::warn!(repo = %label, error = %e.message, "compaction failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::FsStore;

    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;

    fn packs(sizes: &[u64]) -> Vec<(String, u64)> {
        sizes
            .iter()
            .enumerate()
            .map(|(i, s)| (format!("pack-{i:040x}"), *s))
            .collect()
    }

    #[test]
    fn size_classes_are_a_factor_apart() {
        assert_eq!(class_of(0, 8), 0);
        assert_eq!(class_of(64 * KIB, 8), 0);
        assert_eq!(class_of(511 * KIB, 8), 0);
        assert_eq!(class_of(512 * KIB, 8), 1);
        assert_eq!(class_of(4 * MIB, 8), 2);
    }

    #[test]
    fn plans_merge_the_smallest_full_class() {
        // Fewer than F packs: nothing to do.
        assert_eq!(plan(&packs(&[KIB; 7]), 8, 128 * MIB), None);
        // F small packs merge; the big one is left alone.
        let p = packs(&[KIB, KIB, KIB, KIB, KIB, KIB, KIB, KIB, 50 * MIB]);
        let got = plan(&p, 8, 128 * MIB).unwrap();
        assert_eq!(got.len(), 8);
        assert!(!got.contains(&p[8].0));
        // Seven small and one mid-sized: class 0 is not full, class 1 is.
        let p = packs(&[KIB, KIB, KIB, KIB, KIB, KIB, KIB, MIB]);
        assert_eq!(plan(&p, 8, 128 * MIB).unwrap().len(), 8);
        // A pack at the cap never merges, and the output stays under it.
        let p = packs(&[3 * MIB; 8]);
        assert_eq!(plan(&p, 8, 3 * MIB), None);
        let got = plan(&p, 8, 10 * MIB).unwrap();
        assert_eq!(got.len(), 3, "{got:?}");
    }

    async fn put(store: &Store, key: &str, body: &[u8]) {
        store
            .put("b", key, body.to_vec(), Cond::None)
            .await
            .unwrap();
    }

    fn marker(m: &Retired) -> Vec<u8> {
        serde_json::to_vec(m).unwrap()
    }

    #[tokio::test]
    async fn the_sweep_waits_a_grace_period_twice() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::Fs(FsStore::new(dir.path().into()));
        store.ensure_bucket("b").await.unwrap();
        let r = RepoRef {
            bucket: "b".into(),
            ns: "n".into(),
            name: "r".into(),
        };
        let (old, live, stale, moved) = (
            format!("pack-{}", "a".repeat(40)),
            format!("pack-{}", "b".repeat(40)),
            format!("pack-{}", "c".repeat(40)),
            format!("pack-{}", "d".repeat(40)),
        );
        for p in [&old, &live, &stale] {
            for ext in ["pack", "idx"] {
                put(
                    &store,
                    &registry::pack_key("n", "r", &format!("{p}.{ext}")),
                    b"x",
                )
                .await;
            }
        }
        let state = RepoState {
            head: "refs/heads/main".into(),
            packs: vec![live.clone(), stale.clone(), moved.clone()],
            ..Default::default()
        };
        put(
            &store,
            &registry::state_key("n", "r"),
            &serde_json::to_vec(&state).unwrap(),
        )
        .await;
        let at = |t| Retired {
            retired_at: t,
            covered_by: Some(live.clone()),
            deleted_at: None,
        };
        // `old` was replaced; `stale` lost its swap; `moved` is listed but gone.
        put(
            &store,
            &registry::retired_key("n", "r", &old),
            &marker(&at(1000)),
        )
        .await;
        put(
            &store,
            &registry::retired_key("n", "r", &stale),
            &marker(&at(1000)),
        )
        .await;
        put(
            &store,
            &registry::retired_key("n", "r", &moved),
            &marker(&at(1000)),
        )
        .await;
        let exists = |k: String| {
            let store = store.clone();
            async move { store.get("b", &k).await.unwrap().is_some() }
        };

        // Inside the grace period nothing moves.
        let s = sweep(&store, &r, 100, 1050).await.unwrap();
        assert_eq!((s.deleted_packs, s.deleted_markers, s.pending), (0, 0, 3));

        // After it: the replaced pack goes, the stale marker goes, and the
        // listed-but-gone pack keeps its marker.
        let s = sweep(&store, &r, 100, 1100).await.unwrap();
        assert_eq!((s.deleted_packs, s.deleted_markers, s.pending), (1, 1, 2));
        assert!(!exists(registry::pack_key("n", "r", &format!("{old}.pack"))).await);
        assert!(!exists(registry::pack_key("n", "r", &format!("{old}.idx"))).await);
        assert!(exists(registry::pack_key("n", "r", &format!("{stale}.pack"))).await);
        assert!(!exists(registry::retired_key("n", "r", &stale)).await);
        assert!(exists(registry::retired_key("n", "r", &moved)).await);

        // The replaced pack's marker outlives it by another grace period.
        let s = sweep(&store, &r, 100, 1150).await.unwrap();
        assert_eq!((s.deleted_packs, s.deleted_markers), (0, 0));
        assert!(exists(registry::retired_key("n", "r", &old)).await);
        let s = sweep(&store, &r, 100, 1200).await.unwrap();
        assert_eq!((s.deleted_packs, s.deleted_markers, s.pending), (0, 1, 1));
        assert!(!exists(registry::retired_key("n", "r", &old)).await);
        assert!(exists(registry::retired_key("n", "r", &moved)).await);
    }
}
