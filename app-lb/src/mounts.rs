//! Guest mount trees: where a mount's bytes live on this host, and what removes
//! them again.
//!
//! A [`MountSpec`] names a tarball in an artifact
//! store; a VM needs a *directory*. This module owns the ground between the two
//! — the layout of the trees under the mount root, the lookup the create
//! path makes on every replica, and the sweep that reclaims what no spec names
//! any more. The fetching and unpacking themselves are
//! [`crate::artifact::Puller::pull_mount`], because that is where a store
//! reference already turns into verified bytes.
//!
//! ## Content-addressed, and why that is the whole design
//!
//! A tree is named after the digest of the tarball it came from:
//!
//! ```text
//! /var/lib/app-lb/mounts/9f2c…e41a/        <- `tar czf corpus.tgz -C corpus .`
//! /var/lib/app-lb/mounts/4b70…09d3-s1/     <- rolled with a wrapper dir, strip 1
//! ```
//!
//! Three things follow from that and nothing else has to arrange them:
//!
//! * **A pull of bytes already here is free.** The directory existing *is* the
//!   proof, so a tag that has not moved costs one round trip to resolve and no
//!   transfer at all.
//! * **Deployments share.** Ten deployments mounting the same corpus hold one
//!   copy of it on the host, whatever they each call the mount or where in the
//!   guest they put it.
//! * **A rollback is a spec edit.** `digest` names a tree that is still here, so
//!   going back to it re-attaches rather than re-fetches.
//!
//! The `-s<n>` suffix is there because [`MountSpec::strip`] changes the *shape*
//! of the unpacked tree, not just its contents. Two deployments pulling one
//! tarball with different `strip_components` need two trees, and a name that
//! ignored the difference would hand the second one the first one's layout.
//!
//! ## Trees are read at boot, and only at boot
//!
//! heyvmd builds each VM its own ext4 image from the tree (`mke2fs -d`) when the
//! VM is created. Nothing reads the tree afterwards. That is what makes the
//! sweep below safe: a tree removed while VMs are running costs those VMs
//! nothing — they are already holding their copies — and only the *next* create
//! would have to fetch again. So the question the sweep asks is not "is anything
//! using this?" but the much easier "does any registered spec still name it?".

use crate::config::MountSpec;
use crate::registry::Registry;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// How long a tree nothing names survives.
///
/// A day, against the disk store's week, and the gap is deliberate: a tree is
/// re-fetchable from the store it came from, which is not true of the VM disks
/// [`crate::disks`] reclaims. Losing one costs a re-pull; losing a VM's disk
/// loses the VM's state.
///
/// **Measured from when the tree was unpacked**, not from when it stopped being
/// referenced — nothing records the latter, and a sidecar that did would be
/// state to keep correct for a question that is cheap to be conservative about.
/// So what the window actually protects is the tree a pull has just committed
/// and whose spec has not been written yet: between
/// [`crate::artifact::Puller::pull_mount`] returning and the digest reaching the
/// registry, the tree is referenced by nothing, and a sweep landing in that gap
/// would delete the bytes the job is about to point a pool at.
///
/// A tree that has been on the host for longer than the window is therefore
/// eligible as soon as the last spec stops naming it. In practice the gap
/// between sweeps ([`DEFAULT_SWEEP_SECS`]) is what makes an immediate rollback
/// free; past that, rolling back re-fetches.
pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

/// Gap between sweeps. The set being watched only changes when a pull lands or a
/// spec is edited, so this is slow on purpose.
pub const DEFAULT_SWEEP_SECS: u64 = 6 * 60 * 60;

/// Prefix of a tree being unpacked. Kept in the same directory as the finished
/// trees so the rename into place is within one filesystem, and prefixed with a
/// dot so it cannot collide with a digest.
const STAGING_PREFIX: &str = ".incoming-";

/// Where a deployment's mount trees live, and the questions asked of them.
///
/// Deliberately small: it holds a path and the retention window, and every
/// method is a pure function of the filesystem under that path. There is no
/// in-memory index of what has been pulled, because the directory listing is
/// that index and it survives a restart without being persisted.
#[derive(Debug, Clone)]
pub struct MountStore {
    root: PathBuf,
    ttl_secs: u64,
}

impl MountStore {
    pub fn new(root: PathBuf, ttl_secs: u64) -> Self {
        Self { root, ttl_secs }
    }

    /// The directory a given blob unpacks to under this store.
    ///
    /// A pure function of the two things that decide the tree's contents, which
    /// is what makes "already pulled" answerable by [`Path::exists`].
    pub fn tree_path(&self, digest: &str, strip: usize) -> PathBuf {
        self.root.join(tree_name(digest, strip))
    }

    /// Where an in-progress unpack goes, given a name unique to this attempt.
    ///
    /// Beside the finished trees rather than in `/tmp`: the move into place must
    /// be a rename within one filesystem, and a `/tmp` on tmpfs would also mean
    /// unpacking a multi-gigabyte corpus into RAM.
    pub fn staging_path(&self, token: &str) -> PathBuf {
        self.root.join(format!("{STAGING_PREFIX}{token}"))
    }

    /// The tree this mount is pinned to, or `None` if there is nothing to mount
    /// yet.
    ///
    /// Two ways to get `None`, and the caller does not need to tell them apart:
    /// no `digest` (nothing has been pulled) and a `digest` whose tree is not on
    /// this host (pulled somewhere else, or reclaimed). Both mean the same thing
    /// to a create — this VM cannot be given its data — and both are fixed by
    /// the same pull.
    pub fn resolve(&self, mount: &MountSpec) -> Option<PathBuf> {
        let digest = mount.digest.as_deref()?;
        let path = self.tree_path(digest, mount.strip());
        path.is_dir().then_some(path)
    }

    /// Create the root, so a pull does not have to and a misconfigured path is
    /// reported once at startup rather than once per job.
    ///
    /// `0755` rather than app-lb's umask: heyvmd reads these trees, and it does
    /// not necessarily run as the same user.
    pub fn ensure_root(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.root).map_err(|e| {
            format!("cannot create the mount directory {}: {e}", self.root.display())
        })?;
        set_readable(&self.root)
    }

    /// Move a finished staging directory into place under its content-addressed
    /// name, and report where it landed.
    ///
    /// Losing the race is a success, not an error: two pulls of one digest are
    /// two copies of identical bytes, so if the destination appeared while this
    /// one was unpacking, the staged copy is dropped and the winner is used. The
    /// alternative — replacing it — would swap the tree out from under a create
    /// that is reading it right now for no gain at all.
    pub fn commit(&self, staged: &Path, digest: &str, strip: usize) -> Result<PathBuf, String> {
        let dest = self.tree_path(digest, strip);
        if dest.is_dir() {
            let _ = std::fs::remove_dir_all(staged);
            return Ok(dest);
        }
        set_readable(staged)?;
        match std::fs::rename(staged, &dest) {
            Ok(()) => Ok(dest),
            Err(_) if dest.is_dir() => {
                let _ = std::fs::remove_dir_all(staged);
                Ok(dest)
            }
            Err(e) => Err(format!(
                "could not move the unpacked mount into {}: {e}",
                dest.display()
            )),
        }
    }

    /// Remove trees no registered spec names, plus any staging directory left by
    /// a crashed pull.
    ///
    /// Returns `(trees removed, bytes freed)`. Blocking; call it from
    /// `spawn_blocking`.
    ///
    /// The age check is on the *directory's* mtime, which the unpack sets — so
    /// the window starts when the tree became usable, not when the tarball it
    /// came from was rolled. See [`DEFAULT_TTL_SECS`] for what that window is
    /// really protecting, which is narrower than "trees get a day to come back".
    #[cfg(test)]
    fn sweep(&self, referenced: &HashSet<String>) -> (usize, u64) {
        let (removed, freed) = self.sweep_named(referenced, crate::deployment::now_secs());
        (removed.len(), freed)
    }

    /// [`sweep`](Self::sweep) against a given clock, which is what makes the
    /// retention window testable without waiting a day or rewriting mtimes.
    #[cfg(test)]
    fn sweep_at(&self, referenced: &HashSet<String>, now: u64) -> (usize, u64) {
        let (removed, freed) = self.sweep_named(referenced, now);
        (removed.len(), freed)
    }

    /// As [`sweep`](Self::sweep), naming the trees that went — so the same
    /// trees can be reclaimed on the daemon, which holds an uploaded copy of
    /// each. A stale staging directory is named too; the daemon never had
    /// it, and a delete of what is not there is a no-op.
    pub fn sweep_named(&self, referenced: &HashSet<String>, now: u64) -> (Vec<String>, u64) {
        if self.ttl_secs == 0 {
            return (Vec::new(), 0);
        }
        let mut removed = Vec::new();
        let mut freed = 0u64;

        let entries = match std::fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Vec::new(), 0),
            Err(e) => {
                tracing::warn!(
                    dir = %self.root.display(),
                    error = %e,
                    "cannot read the mount directory; nothing reclaimed this sweep",
                );
                return (Vec::new(), 0);
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let age = age_secs(&path, now);

            // A staging directory is nobody's tree: the pull that owned it
            // either finished (and renamed it away) or died. Given the same
            // grace period as everything else so a sweep cannot delete one out
            // from under a pull that is running right now.
            let stale_staging = name.starts_with(STAGING_PREFIX) && age >= self.ttl_secs;
            let unreferenced = !name.starts_with(STAGING_PREFIX)
                && !referenced.contains(name)
                && age >= self.ttl_secs;
            if !(stale_staging || unreferenced) {
                continue;
            }

            let bytes = dir_bytes(&path);
            match std::fs::remove_dir_all(&path) {
                Ok(()) => {
                    removed.push(name.to_string());
                    freed += bytes;
                    tracing::info!(
                        tree = %name,
                        bytes,
                        staging = stale_staging,
                        "reclaimed a mount tree no deployment names",
                    );
                }
                Err(e) => tracing::warn!(
                    tree = %name,
                    error = %e,
                    "cannot remove an unreferenced mount tree",
                ),
            }
        }
        (removed, freed)
    }
}

/// Every tree name the registry currently depends on.
///
/// Built from the *specs*, not from the running VMs, for the reason in the
/// module note: a VM holds its own copy from the moment it is created, so what
/// a tree is still needed for is the next create — and that is what a spec says.
pub fn referenced_trees(registry: &Registry) -> HashSet<String> {
    let mut referenced = HashSet::new();
    for d in registry.deployments().values() {
        let state = d.state();
        for spec in std::iter::once(&d.spec).chain(state.rollouts.iter().map(|o| &o.spec)) {
            if let Some(vm) = &spec.vm {
                referenced.extend(vm.mounts.iter().filter_map(|m| Some(tree_name(m.digest.as_deref()?, m.strip()))));
            }
        }
    }
    referenced
}

/// The directory name for a blob unpacked with a given strip. See the module
/// note for why `strip` is part of it.
fn tree_name(digest: &str, strip: usize) -> String {
    if strip == 0 {
        digest.to_string()
    } else {
        format!("{digest}-s{strip}")
    }
}

/// `0755`, so heyvmd can read the tree when it runs as another user.
///
/// Files inside are normalized by [`crate::unpack`] to safe read permissions
/// plus their archived executable bits. An archive cannot ship something
/// setuid or group-writable, but release entry points remain runnable.
fn set_readable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("cannot set permissions on {}: {e}", path.display()))?;
    }
    let _ = path;
    Ok(())
}

/// Seconds since a directory was last modified, saturating at 0 for a clock that
/// has moved backwards.
fn age_secs(path: &Path, now: u64) -> u64 {
    let modified = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(modified)
}

/// Apparent size of a tree, for the reclaimed-bytes line. Best-effort: a
/// directory that cannot be walked contributes what was readable of it, because
/// this number exists to be logged, not to be reconciled against anything.
fn dir_bytes(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(t) if t.is_dir() => stack.push(entry.path()),
                Ok(t) if t.is_file() => {
                    total += entry.metadata().map(|m| m.len()).unwrap_or(0);
                }
                _ => {}
            }
        }
    }
    total
}

/// The periodic reclamation, on the same terms as [`crate::disks::DiskSweeper`]:
/// never a dependency of the proxy, and never a reason traffic waits.
pub struct MountSweeper {
    store: MountStore,
    registry: Arc<Registry>,
    period: Duration,
    /// The daemon holds an uploaded copy of every tree a replica was built
    /// from; a tree reclaimed here is reclaimed there too.
    vms: crate::vm::VmManager,
}

impl MountSweeper {
    pub fn new(
        store: MountStore,
        registry: Arc<Registry>,
        sweep_secs: u64,
        vms: crate::vm::VmManager,
    ) -> Self {
        Self {
            store,
            registry,
            period: Duration::from_secs(sweep_secs.max(60)),
            vms,
        }
    }
}

#[async_trait::async_trait]
impl pingora_core::services::background::BackgroundService for MountSweeper {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        let mut tick = tokio::time::interval(self.period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; skip it. At startup the registry has
        // been loaded but a pull job kicked off by adoption may not have written
        // its digest back yet, and a sweep in that window would reclaim the tree
        // that job is about to reuse.
        tick.tick().await;
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let referenced = referenced_trees(&self.registry);
                    let store = self.store.clone();
                    let now = crate::deployment::now_secs();
                    // Walks a directory tree and unlinks gigabytes: not work for
                    // the runtime's async threads.
                    let swept = tokio::task::spawn_blocking(move || store.sweep_named(&referenced, now)).await;
                    match swept {
                        Ok((removed, _)) if removed.is_empty() => {}
                        Ok((removed, bytes)) => {
                            tracing::info!(
                                trees = removed.len(),
                                bytes,
                                "reclaimed mount trees no deployment names",
                            );
                            // The daemon holds an uploaded copy of each; a
                            // staging dir it never had is skipped.
                            for tree in removed.iter().filter(|t| !t.starts_with(STAGING_PREFIX)) {
                                if let Err(e) = self.vms.delete_tree(tree).await {
                                    tracing::warn!(
                                        tree = %tree,
                                        error = %e,
                                        "reclaimed here but not on the daemon; it stays there until an operator removes it",
                                    );
                                }
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "the mount sweep did not finish"),
                    }
                }
                _ = shutdown.changed() => {
                    tracing::info!("mount sweeper shutting down");
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MountSpec;

    const DIGEST: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const OTHER: &str = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "app-lb-mounts-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mount(path: &str, digest: Option<&str>, strip: Option<usize>) -> MountSpec {
        MountSpec {
            path: path.into(),
            store: "/srv/artifacts".into(),
            artifact_ref: "corpus".into(),
            auth: None,
            strip_components: strip,
            read_only: true,
            digest: digest.map(Into::into),
        }
    }

    /// Two deployments pulling one tarball with different `strip_components`
    /// need two trees: the strip changes the *shape* of what is unpacked, so a
    /// name that ignored it would hand the second one the first one's layout.
    #[test]
    fn the_tree_name_covers_the_strip_as_well_as_the_digest() {
        let store = MountStore::new(PathBuf::from("/var/lib/app-lb/mounts"), 0);
        assert_eq!(
            store.tree_path(DIGEST, 0),
            PathBuf::from(format!("/var/lib/app-lb/mounts/{DIGEST}")),
        );
        assert_eq!(
            store.tree_path(DIGEST, 1),
            PathBuf::from(format!("/var/lib/app-lb/mounts/{DIGEST}-s1")),
        );
        assert_ne!(store.tree_path(DIGEST, 1), store.tree_path(DIGEST, 2));
    }

    /// Both ways a mount can have nothing to attach, and the caller cannot tell
    /// them apart because both are fixed by the same pull.
    #[test]
    fn a_mount_resolves_only_when_its_tree_is_actually_there() {
        let root = scratch("resolve");
        let store = MountStore::new(root.clone(), 0);

        assert_eq!(store.resolve(&mount("/data", None, None)), None, "never pulled");
        assert_eq!(
            store.resolve(&mount("/data", Some(DIGEST), None)),
            None,
            "pinned to a tree this host does not hold",
        );

        std::fs::create_dir_all(root.join(DIGEST)).unwrap();
        assert_eq!(
            store.resolve(&mount("/data", Some(DIGEST), None)),
            Some(root.join(DIGEST)),
        );
        // The same digest with a strip is a different tree, and it is not there.
        assert_eq!(store.resolve(&mount("/data", Some(DIGEST), Some(1))), None);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_staged_tree_lands_under_its_digest() {
        let root = scratch("commit");
        let store = MountStore::new(root.clone(), 0);
        let staged = root.join("staging");
        std::fs::create_dir_all(&staged).unwrap();
        std::fs::write(staged.join("data.bin"), b"hello").unwrap();

        let landed = store.commit(&staged, DIGEST, 0).unwrap();
        assert_eq!(landed, root.join(DIGEST));
        assert_eq!(std::fs::read(landed.join("data.bin")).unwrap(), b"hello");
        assert!(!staged.exists(), "the staging directory is consumed by the move");

        std::fs::remove_dir_all(&root).ok();
    }

    /// Two pulls of one digest are two copies of identical bytes, so the loser
    /// takes the winner's tree rather than replacing it — a create reading the
    /// tree right now must not have it swapped underneath.
    #[test]
    fn losing_the_race_to_commit_keeps_the_tree_that_won() {
        let root = scratch("race");
        let store = MountStore::new(root.clone(), 0);

        let winner = root.join(DIGEST);
        std::fs::create_dir_all(&winner).unwrap();
        std::fs::write(winner.join("data.bin"), b"first").unwrap();

        let staged = root.join("staging");
        std::fs::create_dir_all(&staged).unwrap();
        std::fs::write(staged.join("data.bin"), b"second").unwrap();

        let landed = store.commit(&staged, DIGEST, 0).unwrap();
        assert_eq!(landed, winner);
        assert_eq!(std::fs::read(winner.join("data.bin")).unwrap(), b"first");
        assert!(!staged.exists(), "the losing copy is dropped, not left behind");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn the_sweep_removes_only_trees_nothing_names() {
        let root = scratch("sweep");
        let store = MountStore::new(root.clone(), 1);
        let now = crate::deployment::now_secs();

        for name in [DIGEST, OTHER, &format!("{DIGEST}-s1")] {
            std::fs::create_dir_all(root.join(name)).unwrap();
            std::fs::write(root.join(name).join("f"), b"x").unwrap();
        }
        let staging = root.join(format!("{STAGING_PREFIX}123"));
        std::fs::create_dir_all(&staging).unwrap();
        // A file at the root is not a tree and must be left alone.
        std::fs::write(root.join("README"), b"x").unwrap();

        // Use the captured clock so setup crossing a second cannot expire trees.
        assert_eq!(store.sweep_at(&HashSet::from([DIGEST.to_string()]), now).0, 0);

        // An hour later, everything here is past a one-second window.
        let later = crate::deployment::now_secs() + 3600;
        let (removed, _) = store.sweep_at(&HashSet::from([DIGEST.to_string()]), later);
        assert_eq!(removed, 3, "the other tree, the stripped tree and the staging dir");
        assert!(root.join(DIGEST).is_dir(), "the referenced tree stays");
        assert!(!root.join(OTHER).exists());
        assert!(!root.join(format!("{DIGEST}-s1")).exists());
        assert!(!staging.exists());
        assert!(root.join("README").is_file(), "loose files are not this sweep's");

        std::fs::remove_dir_all(&root).ok();
    }

    /// `APP_LB_MOUNT_TTL_SECS=0` is the switch for a host where the operator
    /// wants to reclaim by hand. It must not be a *shorter* window.
    #[test]
    fn a_zero_ttl_reclaims_nothing() {
        let root = scratch("ttl-zero");
        let store = MountStore::new(root.clone(), 0);
        std::fs::create_dir_all(root.join(OTHER)).unwrap();

        assert_eq!(store.sweep(&HashSet::new()), (0, 0));
        assert!(root.join(OTHER).is_dir());

        std::fs::remove_dir_all(&root).ok();
    }

    /// A sweep with no directory to sweep is a no-op, not a warning storm: the
    /// root is created at startup, but an operator can still remove it.
    #[test]
    fn a_missing_root_is_not_an_error() {
        let store = MountStore::new(PathBuf::from("/nonexistent/app-lb-mounts"), 60);
        assert_eq!(store.sweep(&HashSet::new()), (0, 0));
    }
}
