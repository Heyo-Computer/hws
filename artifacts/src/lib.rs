//! The digest of a blob's bytes is its only name; everything else in the store
//! is a pointer to a digest.
//!
//! A content-addressed artifact store built for ext4, and wired into heyvm.
//!
//! ext4 cannot reflink, so the usual copy-on-write tricks are unavailable and
//! the design leans on what ext4 *does* offer:
//!
//! - **`st_nlink` is the refcount.** A read-only materialization is a hardlink,
//!   so the kernel maintains the reference count in the same journal
//!   transaction as the link itself. The store keeps no counter of its own and
//!   therefore has no window in which its count and reality disagree.
//! - **Zero runs, not holes.** heyvm's base images are fully allocated on disk
//!   yet mostly zero inside, so reclaiming space means scanning for zeros and
//!   calling `FALLOC_FL_PUNCH_HOLE` — `SEEK_HOLE` alone finds nothing. See
//!   [`sys::sparse`].
//! - **`O_TMPFILE` + `link`.** A blob's final name is not known until its bytes
//!   have been hashed, and `link`'s `EEXIST` is exactly the dedup hit. See
//!   [`sys::tmpfile`].
//!
//! The filesystem is the only source of truth. There is no database to
//! reconcile with it and nothing to replay after a crash.

#[cfg(not(target_os = "linux"))]
compile_error!(
    "artifacts targets Linux: it is built on O_TMPFILE, FALLOC_FL_PUNCH_HOLE, \
     copy_file_range and statx, none of which have portable equivalents."
);

#[cfg(feature = "daemon")]
pub mod admin;
pub mod asp;
// The platform UI kit — tokens, the theme cookie and forwarded identity —
// shared with app-lb, app-obs, ci and heyosecret. Included by path rather than
// depended on as a crate, because those apps sit on three axum versions and two
// Rust editions; the shared module names no framework type. See `ui/README.md`.
pub mod cli;
pub mod config;
pub mod digest;
pub mod dockerfile;
pub mod error;
pub mod gc;
#[path = "../../ui/ui.rs"]
pub mod heyo_ui;
pub mod heyvm;
#[cfg(feature = "daemon")]
pub mod http;
#[cfg(feature = "daemon")]
pub mod hub;
pub mod labels;
pub mod lock;
pub mod manifest;
#[cfg(feature = "daemon")]
pub mod registry;
#[cfg(feature = "daemon")]
pub mod remote;
pub mod repos;
#[cfg(feature = "daemon")]
pub mod s3ops;
pub mod store;
pub mod sys;
pub mod tags;
#[cfg(feature = "daemon")]
pub mod web;

pub use config::Config;
pub use digest::Digest;
pub use error::{Error, Result};
pub use labels::{Label, Labelled};
pub use manifest::{BlobRef, Entry, Manifest};
pub use manifest::{KIND_BUNDLE, KIND_DOCKERFILE, KIND_GENERIC, KIND_ROOTFS};
pub use repos::RepoMeta;
pub use store::{BlobInfo, Materialize, Materialized, Method, Repository, Store, Usage};
pub use sys::sparse::Shape;
pub use tags::{Ref, RepoName, TagName};
