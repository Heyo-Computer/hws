//! Cross-host logical replication of one database to a peer pg-fc node.
//!
//! # The shape of it
//!
//! Two hosts each run a pooler. An operator provisions a dedicated database on
//! node A as usual, then wires replication to node B. What that means
//! concretely:
//!
//! ```text
//! node A (primary)                          node B (replica)
//!   pg-acme VM, wal_level=logical             pg-acme VM
//!   CREATE PUBLICATION pgfc_pub_acme          CREATE SUBSCRIPTION pgfc_sub_acme
//!   role acme_pgfcrepl (REPLICATION)              |
//!            ^                                    |
//!            +--- A's pooler :6432 <--- walreceiver+
//! ```
//!
//! The replication stream is an **ordinary client connection** to node A's
//! pooler. Nothing in the proxy path needed changing for that:
//! [`crate::startup`] parses only `user` and `database` and replays the raw
//! StartupMessage verbatim, so the extra `replication=database` parameter
//! passes through untouched; the `dbname` routes to the right VM exactly as it
//! does for a client; and logical replication connections match the guest's
//! ordinary `host all all` `pg_hba` line, because only *physical* replication
//! is excluded from `all`.
//!
//! # Why logical rather than physical
//!
//! A physical standby would replicate DDL and sequences too, but it needs
//! `$PGDATA` prepared from a base backup while Postgres is not running — a
//! whole standby boot mode in `init.sh` plus a cross-host base-backup
//! transport. Logical replication needs a WAL level, a publication and a
//! subscription, all of which are reachable over connections the pooler
//! already has. The cost is the limitation list in the README: no DDL, no
//! sequence values, and tables need a replica identity.
//!
//! # What lives where
//!
//! * [`names`] — deriving publication/subscription/slot/role names, fitted to
//!   Postgres' 63-byte identifier limit. Deterministic, because teardown
//!   re-derives what setup created.
//! * [`sql`] — every statement and connection string, as pure functions. This
//!   is the part worth testing exhaustively and the only part that can be.
//! * [`store`] — the durable per-database record, and
//!   [`store::ReplStore::is_pinned`], the predicate every lifecycle exclusion
//!   asks before stopping or offloading a VM.
//!
//! # The hazard to keep in mind
//!
//! A replication slot on the primary pins WAL until its subscriber consumes
//! it. A subscriber that goes away leaves an *inactive* slot pinning WAL
//! forever, and on these VMs a full data disk is a cluster-wide PANIC with no
//! way back in. Three things guard it, in order of who acts:
//! `max_slot_wal_keep_size` in the guest (Postgres invalidates the slot rather
//! than filling the disk — losing a replica beats losing a primary), the
//! monitor's warning before that fires, and the fact that a pinned VM is never
//! stopped in the first place.

pub mod names;
pub mod orchestrate;
pub mod peer;
pub mod physical;
pub mod physical_store;
pub mod retirement;
pub mod sql;
pub mod store;
pub mod wire;

pub use store::{ReplRecord, ReplStore, Role, SequenceSnapshot, State};
pub use physical_store::{PhysicalHandoffGrant, PhysicalPhase, PhysicalRecord, PhysicalSourceRecord, PhysicalSourceStore, PhysicalStore};
