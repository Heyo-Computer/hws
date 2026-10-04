//! Whole-store operations against the remote tier, for `art s3 …`.
//!
//! - **backfill** publishes a local store into the remote: the one-time move
//!   of an existing store into the global one, and the repair for anything a
//!   region holds that the remote does not. Idempotent, and ordered so the
//!   remote never holds a pointer to nothing: blobs, then manifests, then the
//!   metadata that describes them, then tags last.
//! - **verify** walks every tag in the remote down to its blobs and reports
//!   anything missing — the check that the backup is whole.
//! - **gc** is the only thing that deletes content from the remote. It runs
//!   under a lease in the bucket, so two regions can never sweep at once, and
//!   it only takes what no tag reaches and is older than a grace window, which
//!   covers another region that has uploaded blobs and not yet written the
//!   manifest naming them.

use crate::digest::Digest;
use crate::error::{Error, Result};
use crate::manifest::Manifest;
use crate::remote::{Cond, Fetched, Remote, keys};
use crate::store::Store;
use serde::Serialize;
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, Clone, Default, Serialize)]
pub struct BackfillReport {
    pub blobs_uploaded: u64,
    pub blobs_present: u64,
    pub bytes_uploaded: u64,
    pub manifests_uploaded: u64,
    pub manifests_skipped: Vec<String>,
    pub labels: u64,
    pub public_markers: u64,
    pub repos: u64,
    pub tags_uploaded: u64,
    pub tags_present: u64,
    /// Tags the remote already has pointing elsewhere: `name: local → remote`.
    pub tag_conflicts: Vec<String>,
    pub tags_skipped: Vec<String>,
    pub dry_run: bool,
}

/// Publish everything in `store` to `remote`.
pub async fn backfill(
    store: &Store,
    remote: &Remote,
    dry_run: bool,
    overwrite_tags: bool,
) -> Result<BackfillReport> {
    let mut r = BackfillReport {
        dry_run,
        ..Default::default()
    };
    let mut in_remote: HashSet<Digest> = remote
        .list(keys::BLOBS)
        .await?
        .iter()
        .filter_map(|o| keys::digest_of(&o.key))
        .collect();

    for b in store.list_blobs().await? {
        if in_remote.contains(&b.digest) {
            r.blobs_present += 1;
            continue;
        }
        if !dry_run {
            let enc = store.encode_blob(&b.digest).await?;
            let len = enc.len();
            remote
                .upload(&keys::blob(&b.digest), Box::new(enc), len)
                .await?;
            r.bytes_uploaded += len;
            tracing::info!(digest = %b.digest, bytes = len, "uploaded blob");
        } else {
            r.bytes_uploaded += b.allocated;
        }
        in_remote.insert(b.digest);
        r.blobs_uploaded += 1;
    }

    let mut manifests_in_remote: HashSet<Digest> = remote
        .list(keys::MANIFESTS)
        .await?
        .iter()
        .filter_map(|o| keys::digest_of(&o.key))
        .collect();
    for d in store.list_manifests().await? {
        if manifests_in_remote.contains(&d) {
            continue;
        }
        let m = match store.get_manifest(&d).await {
            Ok(m) => m,
            Err(e) => {
                r.manifests_skipped.push(format!("{d}: unreadable ({e})"));
                continue;
            }
        };
        if let Some(e) = m.entries.iter().find(|e| !in_remote.contains(&e.digest)) {
            r.manifests_skipped.push(format!(
                "{d}: entry {} ({}) is in neither store",
                e.name, e.digest
            ));
            continue;
        }
        if !dry_run {
            let bytes = std::fs::read(store.inner().manifest_path_of(&d))
                .map_err(|e| Error::Remote(format!("read manifest {d}: {e}")))?;
            match remote.put(&keys::manifest(&d), bytes, Cond::IfAbsent).await {
                Ok(_) | Err(Error::PreconditionFailed(_)) => {}
                Err(e) => return Err(e),
            }
        }
        manifests_in_remote.insert(d);
        r.manifests_uploaded += 1;
    }

    let exists = |d: &Digest| in_remote.contains(d) || manifests_in_remote.contains(d);

    for l in store.list_labels().await? {
        if !exists(&l.digest) {
            continue;
        }
        if !dry_run {
            remote
                .put(&keys::label(&l.digest), l.label.to_json(), Cond::Always)
                .await?;
        }
        r.labels += 1;
    }
    for d in store.inner().public_digests()? {
        if !in_remote.contains(&d) {
            continue;
        }
        if !dry_run {
            remote
                .put(&keys::public(&d), Vec::new(), Cond::Always)
                .await?;
        }
        r.public_markers += 1;
    }
    for (repo, meta) in store.list_repos().await? {
        if !dry_run {
            // A repository the remote already describes keeps the remote's
            // description: it may have been edited from another region.
            match remote
                .put(&keys::repo(&repo), meta.to_json(), Cond::IfAbsent)
                .await
            {
                Ok(_) | Err(Error::PreconditionFailed(_)) => {}
                Err(e) => return Err(e),
            }
        }
        r.repos += 1;
    }

    for (t, d) in store.list_tags().await? {
        if !exists(&d) {
            r.tags_skipped
                .push(format!("{t}: {d} is not in the remote"));
            continue;
        }
        let key = keys::tag(&t);
        match remote.get(&key, None).await? {
            Fetched::Found { body, etag } => {
                let theirs = crate::remote::parse_tag_body(&body)?;
                if theirs == d {
                    r.tags_present += 1;
                    continue;
                }
                if !overwrite_tags {
                    r.tag_conflicts
                        .push(format!("{t}: local {d} → remote {theirs}"));
                    continue;
                }
                if !dry_run {
                    remote
                        .put(&key, format!("{d}\n").into_bytes(), Cond::IfMatch(etag))
                        .await?;
                }
            }
            _ => {
                if !dry_run {
                    match remote
                        .put(&key, format!("{d}\n").into_bytes(), Cond::IfAbsent)
                        .await
                    {
                        Ok(_) => {}
                        Err(Error::PreconditionFailed(_)) => {
                            r.tag_conflicts
                                .push(format!("{t}: created remotely during backfill"));
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        r.tags_uploaded += 1;
    }
    Ok(r)
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct VerifyReport {
    pub tags: u64,
    pub manifests: u64,
    pub blobs: u64,
    /// `tag → what is missing or wrong`.
    pub problems: Vec<String>,
}

/// Check that every tag in the remote resolves to content the remote holds.
/// With `deep`, download and re-hash every blob a tag reaches.
pub async fn verify(store: &Store, remote: &Remote, deep: bool) -> Result<VerifyReport> {
    let mut r = VerifyReport::default();
    let blobs: HashSet<Digest> = remote
        .list(keys::BLOBS)
        .await?
        .iter()
        .filter_map(|o| keys::digest_of(&o.key))
        .collect();
    let mut checked: HashSet<Digest> = HashSet::new();
    for obj in remote.list(keys::TAGS).await? {
        let Some(t) = keys::tag_of(&obj.key) else {
            r.problems
                .push(format!("{}: not a valid tag name", obj.key));
            continue;
        };
        r.tags += 1;
        let d = match remote.get(&obj.key, None).await? {
            Fetched::Found { body, .. } => match crate::remote::parse_tag_body(&body) {
                Ok(d) => d,
                Err(e) => {
                    r.problems.push(format!("{t}: {e}"));
                    continue;
                }
            },
            _ => continue,
        };
        let mut wanted = vec![];
        match remote.get(&keys::manifest(&d), None).await? {
            Fetched::Found { body, .. } => {
                r.manifests += 1;
                match Manifest::from_json(&body) {
                    Ok(m) => wanted.extend(m.entries.into_iter().map(|e| e.digest)),
                    Err(e) => r
                        .problems
                        .push(format!("{t}: manifest {d} unreadable: {e}")),
                }
            }
            _ => wanted.push(d.clone()),
        }
        for b in wanted {
            if !blobs.contains(&b) {
                r.problems.push(format!("{t}: blob {b} is missing"));
                continue;
            }
            if !checked.insert(b.clone()) {
                continue;
            }
            r.blobs += 1;
            if deep && let Err(e) = rehash(store, remote, &b).await {
                r.problems.push(format!("{t}: blob {b}: {e}"));
            }
        }
    }
    Ok(r)
}

/// Download one blob into scratch space, decode it and compare its hash. The
/// scratch file is unlinked either way; nothing is cached.
async fn rehash(store: &Store, remote: &Remote, d: &Digest) -> Result<()> {
    let reader = remote
        .open(&keys::blob(d))
        .await?
        .ok_or_else(|| Error::NotFound(d.clone()))?;
    let sync =
        tokio_util::io::SyncIoBridge::new_with_handle(reader, tokio::runtime::Handle::current());
    let dir = store.tmp_dir();
    let d = d.clone();
    crate::store::run_blocking(move || {
        use sha2::Digest as _;
        // An unnamed file: it vanishes when dropped, whatever happens here.
        let f = crate::sys::tmpfile::Incoming::create(&dir)?;
        let mut h = sha2::Sha256::new();
        crate::asp::decode_into(sync, f.as_raw_fd(), |b| h.update(b))
            .map_err(|e| Error::Remote(format!("decode: {e}")))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        let actual = Digest::from_bytes(&out);
        if actual != d {
            return Err(Error::DigestMismatch {
                expected: d,
                actual,
            });
        }
        Ok(())
    })
    .await
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RemoteGcReport {
    pub blobs_removed: u64,
    pub bytes_freed: u64,
    pub manifests_removed: u64,
    pub metadata_removed: u64,
    pub kept_reachable: u64,
    pub kept_young: u64,
    pub dry_run: bool,
}

#[derive(Serialize, serde::Deserialize)]
struct Lease {
    holder: String,
    expires: u64,
}

const LEASE_TTL: Duration = Duration::from_secs(3600);

/// Take the GC lease, or say who holds it.
async fn acquire_lease(remote: &Remote, holder: &str) -> Result<()> {
    let now = crate::repos::now_unix();
    let body = serde_json::to_vec(&Lease {
        holder: holder.to_string(),
        expires: now + LEASE_TTL.as_secs(),
    })
    .expect("lease serializes");
    match remote
        .put(keys::GC_LEASE, body.clone(), Cond::IfAbsent)
        .await
    {
        Ok(_) => return Ok(()),
        Err(Error::PreconditionFailed(_)) => {}
        Err(e) => return Err(e),
    }
    let Fetched::Found { body: held, etag } = remote.get(keys::GC_LEASE, None).await? else {
        // Released between the two calls; try once more from the top.
        return remote
            .put(keys::GC_LEASE, body, Cond::IfAbsent)
            .await
            .map(|_| ());
    };
    let lease: Lease = serde_json::from_slice(&held).unwrap_or(Lease {
        holder: "unreadable lease".into(),
        expires: 0,
    });
    if lease.expires > now {
        return Err(Error::PreconditionFailed(format!(
            "garbage collection is already running ({}, lease expires in {}s)",
            lease.holder,
            lease.expires - now
        )));
    }
    tracing::warn!(previous = %lease.holder, "taking over an expired GC lease");
    remote
        .put(keys::GC_LEASE, body, Cond::IfMatch(etag))
        .await
        .map(|_| ())
}

/// Sweep the remote: delete content no tag reaches, older than `min_age`.
pub async fn gc(remote: &Remote, min_age: Duration, dry_run: bool) -> Result<RemoteGcReport> {
    let holder = format!(
        "{}:{}",
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown-host".into()),
        std::process::id()
    );
    acquire_lease(remote, &holder).await?;
    let result = sweep(remote, min_age, dry_run).await;
    if let Err(e) = remote.delete(keys::GC_LEASE).await {
        tracing::warn!(error = %e, "releasing the GC lease failed; it expires on its own");
    }
    result
}

async fn sweep(remote: &Remote, min_age: Duration, dry_run: bool) -> Result<RemoteGcReport> {
    let mut r = RemoteGcReport {
        dry_run,
        ..Default::default()
    };
    // Mark.
    let mut live: HashSet<Digest> = HashSet::new();
    for obj in remote.list(keys::TAGS).await? {
        let Fetched::Found { body, .. } = remote.get(&obj.key, None).await? else {
            continue;
        };
        let Ok(d) = crate::remote::parse_tag_body(&body) else {
            continue;
        };
        live.insert(d.clone());
        if let Fetched::Found { body, .. } = remote.get(&keys::manifest(&d), None).await? {
            match Manifest::from_json(&body) {
                Ok(m) => live.extend(m.entries.into_iter().map(|e| e.digest)),
                // Same call as the local collector: a tagged manifest that
                // cannot be read keeps itself, and stops nothing being swept.
                Err(e) => tracing::warn!(digest = %d, error = %e, "tagged manifest is unreadable"),
            }
        }
    }
    let now = crate::repos::now_unix();
    let young = |modified: Option<u64>| {
        // Unknown age is young: never delete what cannot be dated.
        modified.is_none_or(|m| now.saturating_sub(m) < min_age.as_secs())
    };

    // Sweep content.
    let mut gone: HashSet<Digest> = HashSet::new();
    for (prefix, is_blob) in [(keys::BLOBS, true), (keys::MANIFESTS, false)] {
        for obj in remote.list(prefix).await? {
            let Some(d) = keys::digest_of(&obj.key) else {
                continue;
            };
            if live.contains(&d) {
                r.kept_reachable += 1;
                continue;
            }
            if young(obj.modified) {
                r.kept_young += 1;
                continue;
            }
            if !dry_run {
                remote.delete(&obj.key).await?;
            }
            if is_blob {
                r.blobs_removed += 1;
                r.bytes_freed += obj.size;
            } else {
                r.manifests_removed += 1;
            }
            gone.insert(d);
        }
    }
    // Metadata whose subject went with this sweep.
    for prefix in [keys::LABELS, keys::PUBLIC] {
        for obj in remote.list(prefix).await? {
            if keys::digest_of(&obj.key).is_some_and(|d| gone.contains(&d)) {
                if !dry_run {
                    remote.delete(&obj.key).await?;
                }
                r.metadata_removed += 1;
            }
        }
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::registry::{Registry, RegistryOptions};
    use crate::tags::TagName;

    fn store_in(d: &tempfile::TempDir, name: &str) -> Store {
        Store::open(&Config {
            root: d.path().join(name),
            min_free_bytes: 0,
            gc_min_age: Duration::ZERO,
            heyvm_images_dir: d.path().join("images"),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn backfill_publishes_a_whole_store_that_another_region_can_rebuild_from() {
        let d = tempfile::tempdir().unwrap();
        let old = store_in(&d, "old");
        let remote = Remote::fs(d.path().join("bucket")).unwrap();
        let blob = old
            .insert_bytes(b"legacy image".to_vec())
            .await
            .unwrap()
            .digest;
        let m = Manifest::new(crate::KIND_ROOTFS).with_entry("rootfs.ext4", blob.clone(), 12);
        let md = old.put_manifest(&m).await.unwrap();
        old.set_tag(&TagName::parse("debian-hermes").unwrap(), &md)
            .await
            .unwrap();
        old.set_label(
            &md,
            &crate::Label::new(Some("hermes".into()), None).unwrap(),
        )
        .await
        .unwrap();

        let dry = backfill(&old, &remote, true, false).await.unwrap();
        assert_eq!((dry.blobs_uploaded, dry.tags_uploaded), (1, 1));
        assert!(remote.list("").await.unwrap().is_empty(), "dry run wrote");

        let r = backfill(&old, &remote, false, false).await.unwrap();
        assert_eq!(
            (
                r.blobs_uploaded,
                r.manifests_uploaded,
                r.labels,
                r.tags_uploaded
            ),
            (1, 1, 1, 1)
        );
        // Again: nothing to do.
        let again = backfill(&old, &remote, false, false).await.unwrap();
        assert_eq!(
            (
                again.blobs_uploaded,
                again.blobs_present,
                again.tags_present
            ),
            (0, 1, 1)
        );

        let v = verify(&old, &remote, true).await.unwrap();
        assert!(v.problems.is_empty(), "{:?}", v.problems);
        assert_eq!((v.tags, v.blobs), (1, 1));

        // A brand-new region rebuilds from the remote alone.
        let fresh = Registry::new(
            store_in(&d, "fresh"),
            Some(remote.clone()),
            RegistryOptions::default(),
        );
        fresh.sync().await.unwrap();
        let (got, _) = fresh
            .get_tag(&TagName::parse("debian-hermes").unwrap())
            .await
            .unwrap();
        assert_eq!(got, md);
        fresh.ensure_blob(&blob).await.unwrap();
        fresh.store().verify(&blob).await.unwrap();
    }

    #[tokio::test]
    async fn backfill_reports_rather_than_overwrites_a_diverged_tag() {
        let d = tempfile::tempdir().unwrap();
        let a = store_in(&d, "a");
        let remote = Remote::fs(d.path().join("bucket")).unwrap();
        let x = a.insert_bytes(b"x".to_vec()).await.unwrap().digest;
        let y = a.insert_bytes(b"y".to_vec()).await.unwrap().digest;
        let t = TagName::parse("live").unwrap();
        a.set_tag(&t, &x).await.unwrap();
        backfill(&a, &remote, false, false).await.unwrap();
        a.set_tag(&t, &y).await.unwrap();
        let r = backfill(&a, &remote, false, false).await.unwrap();
        assert_eq!(r.tag_conflicts.len(), 1);
        let r = backfill(&a, &remote, false, true).await.unwrap();
        assert_eq!(r.tags_uploaded, 1);
    }

    #[tokio::test]
    async fn verify_finds_a_missing_blob() {
        let d = tempfile::tempdir().unwrap();
        let s = store_in(&d, "s");
        let remote = Remote::fs(d.path().join("bucket")).unwrap();
        let x = s.insert_bytes(b"x".to_vec()).await.unwrap().digest;
        s.set_tag(&TagName::parse("t").unwrap(), &x).await.unwrap();
        backfill(&s, &remote, false, false).await.unwrap();
        remote.delete(&keys::blob(&x)).await.unwrap();
        let v = verify(&s, &remote, false).await.unwrap();
        assert_eq!(v.problems.len(), 1, "{:?}", v.problems);
    }

    #[tokio::test]
    async fn gc_sweeps_only_the_unreachable_and_only_one_at_a_time() {
        let d = tempfile::tempdir().unwrap();
        let s = store_in(&d, "s");
        let remote = Remote::fs(d.path().join("bucket")).unwrap();
        let kept = s.insert_bytes(b"kept".to_vec()).await.unwrap().digest;
        let dropped = s.insert_bytes(b"dropped".to_vec()).await.unwrap().digest;
        s.set_tag(&TagName::parse("t").unwrap(), &kept)
            .await
            .unwrap();
        s.set_label(
            &dropped,
            &crate::Label::new(Some("old".into()), None).unwrap(),
        )
        .await
        .unwrap();
        backfill(&s, &remote, false, false).await.unwrap();

        // Young: nothing goes.
        let r = gc(&remote, Duration::from_secs(3600), false).await.unwrap();
        assert_eq!((r.blobs_removed, r.kept_young), (0, 1));

        // Somebody else holds the lease.
        remote
            .put(
                keys::GC_LEASE,
                serde_json::to_vec(&Lease {
                    holder: "eu1".into(),
                    expires: u64::MAX,
                })
                .unwrap(),
                Cond::Always,
            )
            .await
            .unwrap();
        assert!(matches!(
            gc(&remote, Duration::ZERO, false).await,
            Err(Error::PreconditionFailed(_))
        ));
        // An expired lease is taken over.
        remote
            .put(
                keys::GC_LEASE,
                serde_json::to_vec(&Lease {
                    holder: "eu1".into(),
                    expires: 1,
                })
                .unwrap(),
                Cond::Always,
            )
            .await
            .unwrap();
        let r = gc(&remote, Duration::ZERO, false).await.unwrap();
        assert_eq!(
            (r.blobs_removed, r.metadata_removed, r.kept_reachable),
            (1, 1, 1)
        );
        assert!(remote.head(&keys::blob(&kept)).await.unwrap().is_some());
        assert!(remote.head(&keys::blob(&dropped)).await.unwrap().is_none());
        assert!(
            remote.head(keys::GC_LEASE).await.unwrap().is_none(),
            "lease released"
        );
    }
}
