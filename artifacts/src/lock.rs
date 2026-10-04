//! Exactly one `.store.lock` open file description per [`crate::store::Store`].
//!
//! `flock` is a property of the *open file description*, not the descriptor or
//! the process, so two locks taken through the same `File` do not stack — the
//! second silently converts the first. A `std::sync::Mutex` around the handle
//! makes in-process access strictly sequential, which is what turns that from a
//! hazard into a guarantee. Never lock recursively.
//!
//! The lock protects the *commit*, not the streaming. A writer holds it while
//! linking already-synced blobs and writing the manifest that names them —
//! milliseconds — while a 20 GB import runs entirely outside it. That is why
//! [`crate::store::Store`] separates staging from committing at all: if the
//! lock covered the whole import, garbage collection would be blocked for the
//! length of the longest copy on the machine.
//!
//! Same pattern as `lock_store()` at heyo/mvm-ctrl/src/bundles.rs:93-106.

use crate::error::{IoContext, Result};
use fs2::FileExt;
use std::fs::File;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

pub const LOCK_FILENAME: &str = ".store.lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Taken by writers around a commit. Many writers may hold it at once;
    /// none may while a sweep is running.
    Shared,
    /// Taken by garbage collection across mark and sweep, so no blob can be
    /// linked into the store between the two phases.
    Exclusive,
}

pub struct StoreLock {
    file: Mutex<File>,
}

impl StoreLock {
    pub fn open(root: &Path) -> Result<StoreLock> {
        let path = root.join(LOCK_FILENAME);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .ctx(format!("open {}", path.display()))?;
        Ok(StoreLock {
            file: Mutex::new(file),
        })
    }

    /// Acquire the lock, blocking until it is available.
    ///
    /// Call only from a blocking context — this parks the calling thread.
    pub fn acquire(&self, mode: LockMode) -> Result<LockGuard<'_>> {
        let file = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match mode {
            LockMode::Shared => file.lock_shared(),
            LockMode::Exclusive => file.lock_exclusive(),
        }
        .ctx("acquire store lock")?;
        Ok(LockGuard { file })
    }
}

/// Releases the `flock` and the in-process mutex on drop.
pub struct LockGuard<'a> {
    file: MutexGuard<'a, File>,
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        // Unlocking is a single fast syscall, so doing it in `Drop` costs
        // nothing. A failure here means the descriptor is already gone, which
        // releases the lock anyway.
        let _ = fs2::FileExt::unlock(&*self.file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn tmpdir() -> tempfile::TempDir {
        match std::env::var_os("ART_TEST_DIR").map(std::path::PathBuf::from) {
            Some(b) => tempfile::tempdir_in(b).unwrap(),
            None => tempfile::tempdir().unwrap(),
        }
    }

    #[test]
    fn creates_the_lock_file() {
        let d = tmpdir();
        let _l = StoreLock::open(d.path()).unwrap();
        assert!(d.path().join(LOCK_FILENAME).exists());
    }

    #[test]
    fn opening_twice_does_not_truncate() {
        let d = tmpdir();
        {
            let _l = StoreLock::open(d.path()).unwrap();
        }
        std::fs::write(d.path().join(LOCK_FILENAME), b"marker").unwrap();
        let _l = StoreLock::open(d.path()).unwrap();
        assert_eq!(
            std::fs::read(d.path().join(LOCK_FILENAME)).unwrap(),
            b"marker"
        );
    }

    #[test]
    fn shared_and_exclusive_both_acquire_and_release() {
        let d = tmpdir();
        let l = StoreLock::open(d.path()).unwrap();
        for _ in 0..3 {
            {
                let _g = l.acquire(LockMode::Shared).unwrap();
            }
            {
                let _g = l.acquire(LockMode::Exclusive).unwrap();
            }
        }
    }

    #[test]
    fn in_process_access_is_serialized() {
        // The mutex, not flock, is what prevents two threads sharing one open
        // file description from converting each other's lock.
        let d = tmpdir();
        let l = Arc::new(StoreLock::open(d.path()).unwrap());
        let concurrent = Arc::new(AtomicUsize::new(0));
        let max = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let l = l.clone();
                let concurrent = concurrent.clone();
                let max = max.clone();
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        let _g = l.acquire(LockMode::Exclusive).unwrap();
                        let n = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
                        max.fetch_max(n, Ordering::SeqCst);
                        concurrent.fetch_sub(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            max.load(Ordering::SeqCst),
            1,
            "lock allowed concurrent entry"
        );
    }

    #[test]
    fn a_poisoned_mutex_still_yields_the_lock() {
        // A panic while holding the store lock must not wedge the store for
        // every later caller.
        let d = tmpdir();
        let l = Arc::new(StoreLock::open(d.path()).unwrap());
        let l2 = l.clone();
        let _ = std::thread::spawn(move || {
            let _g = l2.acquire(LockMode::Exclusive).unwrap();
            panic!("boom");
        })
        .join();
        let _g = l.acquire(LockMode::Exclusive).unwrap();
    }
}
