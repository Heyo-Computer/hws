//! Durable, per-database maintenance admission. A failed operation never
//! releases either name: recovery must finish the same recorded operation.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::Mutex,
};

pub mod execute;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub created_at: String,
    pub system_identifier: String,
    pub database_oid: u32,
    /// Durable delete intent. A daemon 404 is conclusive only after this bit
    /// was persisted and the local disk is also absent.
    #[serde(default)]
    pub deletion_started: bool,
    pub deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: String,
    pub database: String,
    /// None means retire; Some means rename. Both names are reserved.
    pub destination: Option<String>,
    pub bound_vm: String,
    pub complete: bool,
    #[serde(default)]
    pub identities: BTreeMap<String, Identity>,
    #[serde(default)]
    pub metadata_committed: bool,
    /// Durable executor cursor. Only the executor may advance it.
    #[serde(default)]
    pub stage: Stage,
    /// Replication ownership captured from the local stores at begin time.
    #[serde(default)]
    pub peer: String,
    #[serde(default)]
    pub generation: String,
    #[serde(default)]
    pub role: Role,
    #[serde(default)]
    pub barrier_lsn: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    #[default]
    Begun,
    Captured,
    Prepared,
    Applied,
    Verified,
    MetadataCommitted,
    Finished,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    #[default]
    Source,
    Replica,
}

pub struct Store {
    path: PathBuf,
    operations: Mutex<BTreeMap<String, Operation>>,
}

impl Store {
    pub fn load(path: PathBuf) -> Result<Self> {
        let operations: BTreeMap<String, Operation> = match fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).context("reading database maintenance journal")?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        let mut names = std::collections::HashSet::new();
        for (id, op) in &operations {
            validate(op)?;
            ensure!(id == &op.id, "maintenance operation key mismatch");
            for name in std::iter::once(&op.database).chain(op.destination.iter()) {
                ensure!(names.insert(name), "overlapping maintenance database names");
            }
        }
        Ok(Self {
            path,
            operations: Mutex::new(operations),
        })
    }

    pub fn get(&self, id: &str) -> Option<Operation> {
        self.operations.lock().unwrap().get(id).cloned()
    }

    pub fn list(&self) -> Vec<Operation> {
        self.operations.lock().unwrap().values().cloned().collect()
    }

    pub fn rename_for(&self, database: &str) -> Option<Operation> {
        self.operations
            .lock()
            .unwrap()
            .values()
            .find(|op| {
                !op.complete
                    && op.destination.is_some()
                    && (op.database == database || op.destination.as_deref() == Some(database))
            })
            .cloned()
    }

    pub fn update(
        &self,
        id: &str,
        change: impl FnOnce(&mut Operation) -> Result<()>,
    ) -> Result<Operation> {
        let mut current = self.operations.lock().unwrap();
        let mut next = current.clone();
        let op = next
            .get_mut(id)
            .context("unknown database maintenance operation")?;
        change(op)?;
        validate(op)?;
        let before = current.get(id).unwrap();
        ensure!(
            op.id == before.id
                && op.database == before.database
                && op.destination == before.destination
                && op.bound_vm == before.bound_vm
                && op.peer == before.peer
                && op.generation == before.generation
                && op.role == before.role,
            "maintenance operation topology changed"
        );
        ensure!(
            op.stage as u8 >= before.stage as u8,
            "maintenance stage regressed"
        );
        ensure!(
            op.stage as u8 <= before.stage as u8 + 1,
            "maintenance stage skipped"
        );
        for (vm, identity) in &before.identities {
            let next_identity = op.identities.get(vm).context("captured identity removed")?;
            ensure!(
                identity.created_at == next_identity.created_at
                    && identity.system_identifier == next_identity.system_identifier
                    && identity.database_oid == next_identity.database_oid
                    && (!identity.deletion_started || next_identity.deletion_started)
                    && (!identity.deleted || next_identity.deleted),
                "captured identity/progress changed"
            );
        }
        let result = op.clone();
        self.persist(&next)?;
        *current = next;
        Ok(result)
    }

    pub fn check(&self, database: &str) -> Result<()> {
        for op in self.operations.lock().unwrap().values() {
            if op.database == database
                || (!op.complete && op.destination.as_deref() == Some(database))
            {
                bail!(
                    "database {database} is reserved by maintenance operation {}",
                    op.id
                );
            }
        }
        Ok(())
    }

    pub fn begin(&self, op: Operation) -> Result<()> {
        validate(&op)?;
        ensure!(!op.complete, "cannot begin a completed operation");
        let mut current = self.operations.lock().unwrap();
        if let Some(existing) = current.get(&op.id) {
            ensure!(
                existing.database == op.database
                    && existing.destination == op.destination
                    && existing.bound_vm == op.bound_vm
                    && existing.peer == op.peer
                    && existing.generation == op.generation
                    && existing.role == op.role,
                "maintenance operation identity changed"
            );
            return Ok(());
        }
        ensure!(
            op.identities.is_empty() && !op.metadata_committed && op.stage == Stage::Begun,
            "cannot inject maintenance progress"
        );
        for existing in current.values() {
            for name in std::iter::once(&op.database).chain(op.destination.iter()) {
                ensure!(
                    name != &existing.database && existing.destination.as_ref() != Some(name),
                    "database name belongs to another maintenance operation"
                );
            }
        }
        let mut next = current.clone();
        next.insert(op.id.clone(), op);
        self.persist(&next)?;
        *current = next;
        Ok(())
    }

    fn persist(&self, next: &BTreeMap<String, Operation>) -> Result<()> {
        let tmp = self.path.with_extension("maintenance.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(next)?)?;
        file.sync_all()?;
        fs::rename(&tmp, &self.path)?;
        // An ambiguous durable write must not leave the running pooler serving
        // names which its next boot will consider fenced.
        if let Err(error) = fs::File::open(
            self.path
                .parent()
                .context("maintenance journal has no parent")?,
        )
        .and_then(|dir| dir.sync_all())
        {
            tracing::error!(%error, "maintenance journal durability uncertain; stopping admission");
            std::process::abort();
        }
        Ok(())
    }
}

fn validate(op: &Operation) -> Result<()> {
    for value in [&op.id, &op.bound_vm] {
        ensure!(
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid maintenance identity"
        );
    }
    crate::dedicated::validate_identifier(&op.database, "database")?;
    if let Some(destination) = &op.destination {
        crate::dedicated::validate_identifier(destination, "database")?;
    }
    for name in std::iter::once(&op.database).chain(op.destination.iter()) {
        ensure!(
            !matches!(name.as_str(), "postgres" | "template0" | "template1"),
            "system database cannot be maintained"
        );
    }
    ensure!(
        op.destination.as_ref() != Some(&op.database),
        "rename requires different names"
    );
    ensure!(
        !op.peer.is_empty() && !op.generation.is_empty(),
        "maintenance topology is incomplete"
    );
    ensure!(
        !op.complete || op.stage == Stage::Finished,
        "completed operation has not finished"
    );
    ensure!(
        !op.metadata_committed || op.stage as u8 >= Stage::MetadataCommitted as u8,
        "metadata receipt precedes its stage"
    );
    ensure!(
        op.identities
            .values()
            .all(|i| !i.deleted || i.deletion_started),
        "deletion receipt has no durable intent"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_keeps_both_names_closed_and_rejects_different_identity() {
        let dir = std::env::temp_dir().join(format!(
            "pgfc-maintenance-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("maintenance.json");
        let store = Store::load(path.clone()).unwrap();
        let op = Operation {
            id: "rename-1".into(),
            database: "old_us3".into(),
            destination: Some("canonical".into()),
            bound_vm: "sb-123".into(),
            complete: false,
            identities: BTreeMap::new(),
            metadata_committed: false,
            stage: Stage::Begun,
            peer: "eu1".into(),
            generation: "g1".into(),
            role: Role::Source,
            barrier_lsn: None,
        };
        store.begin(op.clone()).unwrap();
        drop(store);
        let store = Store::load(path).unwrap();
        assert!(store.check("old_us3").is_err());
        assert!(store.check("canonical").is_err());
        assert!(store.check("unrelated").is_ok());
        store.begin(op.clone()).unwrap();
        let mut wrong = op.clone();
        wrong.bound_vm = "sb-other".into();
        assert!(store.begin(wrong).is_err());
        let mut overlap = op;
        overlap.id = "another".into();
        overlap.database = "canonical".into();
        overlap.destination = Some("third".into());
        assert!(store.begin(overlap).is_err());
        assert!(
            store
                .update("rename-1", |op| {
                    op.stage = Stage::Prepared;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(store.get("rename-1").unwrap().stage, Stage::Begun);
        for stage in [
            Stage::Captured,
            Stage::Prepared,
            Stage::Applied,
            Stage::Verified,
            Stage::MetadataCommitted,
        ] {
            store
                .update("rename-1", |op| {
                    op.stage = stage;
                    op.metadata_committed = stage == Stage::MetadataCommitted;
                    Ok(())
                })
                .unwrap();
            assert!(store.check("canonical").is_err());
            assert!(store.check("unrelated").is_ok());
        }
        store
            .update("rename-1", |op| {
                op.stage = Stage::Finished;
                op.complete = true;
                Ok(())
            })
            .unwrap();
        let reloaded = Store::load(store.path.clone()).unwrap();
        assert!(reloaded.check("canonical").is_ok());
        assert!(reloaded.check("old_us3").is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn journal_identity_and_delete_progress_are_immutable() {
        let dir = std::env::temp_dir().join(format!(
            "pgfc-maintenance-progress-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let store = Store::load(dir.join("maintenance.json")).unwrap();
        let op = Operation {
            id: "retire_1".into(),
            database: "tenant".into(),
            destination: None,
            bound_vm: "sb-1".into(),
            complete: false,
            identities: BTreeMap::new(),
            metadata_committed: false,
            stage: Stage::Begun,
            peer: "eu1".into(),
            generation: "g1".into(),
            role: Role::Source,
            barrier_lsn: None,
        };
        store.begin(op).unwrap();
        store
            .update("retire_1", |op| {
                op.identities.insert(
                    "sb-1".into(),
                    Identity {
                        created_at: "incarnation".into(),
                        system_identifier: "123".into(),
                        database_oid: 42,
                        deletion_started: true,
                        deleted: true,
                    },
                );
                op.stage = Stage::Captured;
                Ok(())
            })
            .unwrap();
        assert!(
            store
                .update("retire_1", |op| {
                    op.identities.get_mut("sb-1").unwrap().system_identifier = "456".into();
                    Ok(())
                })
                .is_err()
        );
        assert!(
            store
                .update("retire_1", |op| {
                    op.identities.get_mut("sb-1").unwrap().deleted = false;
                    Ok(())
                })
                .is_err()
        );
        assert!(
            store
                .update("retire_1", |op| {
                    op.generation = "g2".into();
                    Ok(())
                })
                .is_err()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
