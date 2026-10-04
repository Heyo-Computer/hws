//! Bounded, operator-stepped database retirement and rename executor.
use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result, bail, ensure};
use heyo_sdk::{HeyoClient, HeyoError, RequestOptions, Sandbox};
use serde_json::Value;

use super::{Identity, Operation, Role, Stage};
use crate::{registry::SchemaRegistry, replication::peer::PeerClient, vm};

pub async fn begin(
    reg: &Arc<SchemaRegistry>,
    id: String,
    database: String,
    destination: Option<String>,
    bound_vm: String,
) -> Result<Operation> {
    crate::dedicated::validate_identifier(&database, "database")?;
    if let Some(new) = &destination {
        crate::dedicated::validate_identifier(new, "database")?;
    }
    if let Some(existing) = reg.database_maintenance().get(&id) {
        ensure!(
            existing.database == database
                && existing.destination == destination
                && existing.bound_vm == bound_vm,
            "maintenance retry changed identity"
        );
        return Ok(existing);
    }
    let rename = destination.is_some();
    let (role, peer, generation) = if let Some(s) = reg.physical_sources().get(&database) {
        ensure!(
            s.source_vm_id == bound_vm
                && s.fence.is_none()
                && s.handoff.is_none()
                && s.handoff_candidate.is_none(),
            "unsupported source topology"
        );
        ensure!(
            reg.bound_vm_id(&database).as_deref() == Some(&bound_vm),
            "maintenance binding changed"
        );
        // Retirement supports the bootstrap source and its same-source reseed.
        // A deeper history cannot be proven complete from the current records.
        ensure!(
            rename || s.predecessor.is_none(),
            "retirement supports only bootstrap ownership"
        );
        (Role::Source, s.peer, s.generation)
    } else if let Some(r) = reg.physical().get(&database) {
        ensure!(!r.handoff_started(), "unsupported replica topology");
        ensure!(
            reg.bound_vm_id(&database).as_deref() == Some(&bound_vm),
            "maintenance binding changed"
        );
        ensure!(
            rename || r.predecessor.is_none(),
            "retirement supports only bootstrap ownership"
        );
        ensure!(r.candidate_id.is_some(), "physical candidate is not bound");
        ensure!(
            !rename || r.candidate_id.as_deref() == Some(&bound_vm),
            "rename requires the physical standby to be bound"
        );
        (Role::Replica, r.source_node, r.generation)
    } else {
        bail!("maintenance requires a physical topology")
    };
    ensure!(
        reg.peers().get(&peer).is_some(),
        "configured maintenance peer is missing"
    );
    let op = Operation {
        id,
        database,
        destination,
        bound_vm,
        complete: false,
        identities: BTreeMap::new(),
        metadata_committed: false,
        stage: Stage::Begun,
        peer,
        generation,
        role,
        barrier_lsn: None,
    };
    reg.begin_database_maintenance(op.clone()).await?;
    Ok(reg.database_maintenance().get(&op.id).unwrap())
}

pub async fn step(reg: &Arc<SchemaRegistry>, id: &str, requested: Stage) -> Result<Operation> {
    let initial = reg
        .database_maintenance()
        .get(id)
        .context("unknown maintenance operation")?;
    let _serial = reg.raw_replication_operation(&initial.database).await;
    let op = reg
        .database_maintenance()
        .get(id)
        .context("unknown maintenance operation")?;
    if requested as u8 <= op.stage as u8 {
        return Ok(op);
    }
    ensure!(!op.complete, "maintenance operation already finished");
    if op.stage != Stage::Begun && (op.stage as u8) < Stage::Verified as u8 {
        let current: std::collections::BTreeSet<_> =
            owned_ids(reg, &op)?.into_iter().map(|x| x.0).collect();
        ensure!(
            current == op.identities.keys().cloned().collect(),
            "maintenance ownership topology changed"
        );
        ensure!(
            reg.bound_vm_id(&op.database).as_deref() == Some(&op.bound_vm),
            "maintenance binding changed"
        );
    }
    ensure!(
        requested == next(op.stage),
        "next permitted stage is {:?}",
        next(op.stage)
    );
    match requested {
        Stage::Captured => capture(reg, &op).await?,
        Stage::Prepared => prepare(reg, &op).await?,
        Stage::Applied => apply(reg, &op).await?,
        Stage::Verified => verify(reg, &op).await?,
        Stage::MetadataCommitted => metadata(reg, &op).await?,
        Stage::Finished => finish(reg, &op).await?,
        Stage::Begun => unreachable!(),
    }
    Ok(reg.database_maintenance().get(id).unwrap())
}

fn next(stage: Stage) -> Stage {
    match stage {
        Stage::Begun => Stage::Captured,
        Stage::Captured => Stage::Prepared,
        Stage::Prepared => Stage::Applied,
        Stage::Applied => Stage::Verified,
        Stage::Verified => Stage::MetadataCommitted,
        Stage::MetadataCommitted | Stage::Finished => Stage::Finished,
    }
}

fn owned_ids(reg: &SchemaRegistry, op: &Operation) -> Result<Vec<(String, Option<String>)>> {
    let mut ids = vec![(op.bound_vm.clone(), None)];
    match op.role {
        Role::Source => {
            let r = reg
                .physical_sources()
                .get(&op.database)
                .context("physical source disappeared")?;
            ensure!(
                r.generation == op.generation && r.peer == op.peer,
                "source topology changed"
            );
            ids.push((r.source_vm_id, Some(r.system_identifier)));
        }
        Role::Replica => {
            let r = reg
                .physical()
                .get(&op.database)
                .context("physical replica disappeared")?;
            ensure!(
                r.generation == op.generation && r.source_node == op.peer,
                "replica topology changed"
            );
            ids.push((
                r.candidate_id.context("physical candidate disappeared")?,
                Some(r.system_identifier),
            ));
        }
    }
    let mut unique = BTreeMap::new();
    for (id, sid) in ids {
        let entry = unique.entry(id).or_insert(None);
        if sid.is_some() {
            *entry = sid;
        }
    }
    Ok(unique.into_iter().collect())
}

async fn capture(reg: &Arc<SchemaRegistry>, op: &Operation) -> Result<()> {
    let ids = owned_ids(reg, op)?;
    let mut identities = BTreeMap::new();
    for (id, journal_sid) in ids {
        let identity = live_identity(reg, &id, &op.database).await?;
        if let Some(sid) = journal_sid {
            ensure!(
                identity.system_identifier == sid,
                "physical journal/runtime identity mismatch"
            );
        }
        identities.insert(id, identity);
    }
    if op.destination.is_none() && identities.len() > 1 {
        let bound = &identities[&op.bound_vm].system_identifier;
        ensure!(
            identities
                .iter()
                .any(|(id, x)| id != &op.bound_vm && x.system_identifier != *bound),
            "old logical VM is not distinct from physical candidate"
        );
    }
    reg.database_maintenance().update(&op.id, |o| {
        o.identities = identities;
        o.stage = Stage::Captured;
        Ok(())
    })?;
    Ok(())
}

async fn live_identity(reg: &SchemaRegistry, id: &str, database: &str) -> Result<Identity> {
    let raw = daemon_info(id)
        .await?
        .context("maintenance VM is absent before delete intent")?;
    ensure!(
        raw.get("id").and_then(Value::as_str) == Some(id),
        "daemon VM identity mismatch"
    );
    let created_at = raw
        .get("created_at")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .context("daemon omitted VM incarnation")?
        .to_owned();
    let sb = Sandbox::connect(id.to_owned(), vm::local_opts())?;
    let mut env = std::collections::HashMap::new();
    env.insert("PGFC_DB".into(), database.into());
    let proof = vm::physical_exec(
        reg.cfg(),
        &sb,
        IDENTITY_SQL,
        env,
        "capturing maintenance identity",
    )
    .await?;
    ensure!(proof.exit_code == 0, "cannot read VM identity");
    let mut fields = proof.stdout.trim().split('|');
    let sid = fields
        .next()
        .context("identity omitted system identifier")?
        .to_owned();
    let oid = fields
        .next()
        .context("identity omitted database OID")?
        .parse()?;
    ensure!(
        fields.next().is_none() && !sid.is_empty(),
        "malformed runtime identity"
    );
    Ok(Identity {
        created_at,
        system_identifier: sid,
        database_oid: oid,
        deletion_started: false,
        deleted: false,
    })
}

async fn prepare(reg: &Arc<SchemaRegistry>, op: &Operation) -> Result<()> {
    require_peer(reg, op, Stage::Captured, false).await?;
    for id in op.identities.keys() {
        assert_live(reg, op, id).await?;
    }
    if op.role == Role::Source {
        let guard = reg.checkout_database_maintenance_exact(&op.id).await?;
        let db = guard.entry().pool.get().await?;
        db.batch_execute("SET synchronous_commit = on").await?;
        let prepared: i64 = db
            .query_one("SELECT count(*) FROM pg_prepared_xacts", &[])
            .await?
            .get(0);
        ensure!(prepared == 0, "VM has prepared transactions");
        let clients: i64 = db.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid() AND backend_type='client backend'", &[&op.database]).await?.get(0);
        ensure!(
            op.destination.is_some() || clients == 0,
            "database has application clients; drain them first"
        );
        db.batch_execute(&crate::replication::sql::set_allow_connections(
            &op.database,
            false,
        ))
        .await?;
        // Rename is explicitly approved to disconnect tenant sessions; retirement
        // never silently terminates an unexpected application session.
        if op.destination.is_some() {
            db.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid() AND backend_type='client backend'", &[&op.database]).await?;
        }
    } else {
        let physical = owned_ids(reg, op)?
            .into_iter()
            .find(|(id, journal)| journal.is_some() && id != &op.bound_vm);
        if physical.is_some() {
            // This is the replaced logical VM, not the read-only physical
            // standby. Stop its subscriptions and close its tenant database.
            let sb = Sandbox::connect(op.bound_vm.clone(), vm::local_opts())?;
            let mut env = std::collections::HashMap::new();
            env.insert("PGFC_DB".into(), op.database.clone());
            let result = vm::physical_exec(
                reg.cfg(),
                &sb,
                DRAIN_LOGICAL,
                env,
                "draining logical maintenance VM",
            )
            .await?;
            ensure!(
                result.exit_code == 0 && result.stdout.trim() == "t",
                "logical VM has application clients or could not be drained"
            );
        }
    }
    reg.database_maintenance().update(&op.id, |o| {
        o.stage = Stage::Prepared;
        Ok(())
    })?;
    Ok(())
}

async fn apply(reg: &Arc<SchemaRegistry>, op: &Operation) -> Result<()> {
    require_peer(reg, op, Stage::Prepared, false).await?;
    if let Some(new) = &op.destination {
        if op.role == Role::Source {
            // SQL may have committed even when the preceding request lost its
            // reply. Accept only the same captured OID under either name.
            if assert_live(reg, op, &op.bound_vm).await.is_err() {
                assert_database_identity(reg, op, &op.bound_vm, new).await?;
            }
            let guard = reg.checkout_database_maintenance_exact(&op.id).await?;
            let db = guard.entry().pool.get().await?;
            db.batch_execute("SET synchronous_commit = on").await?;
            let identity = &op.identities[&op.bound_vm];
            let rows = db
                .query(
                    "SELECT datname, oid::int8 FROM pg_database WHERE datname=$1 OR datname=$2",
                    &[&op.database, new],
                )
                .await?;
            let old = rows
                .iter()
                .find(|r| r.get::<_, String>(0) == op.database)
                .map(|r| r.get::<_, i64>(1));
            let after = rows
                .iter()
                .find(|r| r.get::<_, String>(0) == *new)
                .map(|r| r.get::<_, i64>(1));
            if old == Some(identity.database_oid.into()) && after.is_none() {
                db.batch_execute(&format!(
                    "ALTER DATABASE \"{}\" RENAME TO \"{}\"",
                    op.database, new
                ))
                .await?;
            } else {
                ensure!(
                    old.is_none() && after == Some(identity.database_oid.into()),
                    "rename catalog is neither before nor after state"
                );
            }
            let barrier: String = db
                .query_one("SELECT pg_current_wal_flush_lsn()::text", &[])
                .await?
                .get(0);
            reg.database_maintenance().update(&op.id, |o| {
                o.barrier_lsn = Some(barrier);
                o.stage = Stage::Applied;
                Ok(())
            })?;
            return Ok(());
        }
    } else {
        if op.role == Role::Source {
            require_peer(reg, op, Stage::Applied, true).await?;
        }
        for id in op.identities.keys() {
            delete_exact(reg, op, id).await?;
        }
    }
    reg.database_maintenance().update(&op.id, |o| {
        o.stage = Stage::Applied;
        Ok(())
    })?;
    Ok(())
}

async fn verify(reg: &Arc<SchemaRegistry>, op: &Operation) -> Result<()> {
    if let Some(new) = &op.destination {
        if op.role == Role::Replica {
            let source = peer_operation(reg, op).await?;
            ensure!(
                source.stage as u8 >= Stage::Applied as u8,
                "source has not renamed"
            );
            let barrier = source
                .barrier_lsn
                .context("source omitted post-rename barrier")?;
            let id = op
                .identities
                .keys()
                .find(|id| id.as_str() != op.bound_vm.as_str())
                .unwrap_or(&op.bound_vm);
            let expected = &op.identities[id];
            verify_standby(reg, id, new, expected, &barrier).await?;
            reg.database_maintenance().update(&op.id, |o| {
                o.barrier_lsn = Some(barrier);
                o.stage = Stage::Verified;
                Ok(())
            })?;
            return Ok(());
        }
        assert_database_identity(reg, op, &op.bound_vm, new).await?;
        require_peer(reg, op, Stage::Verified, false).await?;
    } else {
        for (id, identity) in &op.identities {
            ensure!(identity.deleted, "local deletion receipt is incomplete");
            ensure!(
                daemon_info(id).await?.is_none(),
                "daemon still reports retired VM"
            );
            ensure!(
                !tokio::fs::try_exists(
                    reg.cfg()
                        .run_dir
                        .as_ref()
                        .context("PG_VM_POOL_RUN_DIR is required")?
                        .join(id)
                )
                .await?,
                "retired VM disk remains"
            );
        }
    }
    reg.database_maintenance().update(&op.id, |o| {
        o.stage = Stage::Verified;
        Ok(())
    })?;
    Ok(())
}

async fn metadata(reg: &Arc<SchemaRegistry>, op: &Operation) -> Result<()> {
    require_peer(reg, op, Stage::Verified, op.destination.is_none()).await?;
    if let Some(new) = &op.destination {
        if op.role == Role::Source {
            let guard = reg.checkout_database_maintenance_exact(&op.id).await?;
            let db = guard.entry().pool.get().await?;
            db.batch_execute("SET synchronous_commit = on").await?;
            db.batch_execute(&crate::replication::sql::set_allow_connections(new, true))
                .await?;
            let barrier: String = db
                .query_one("SELECT pg_current_wal_flush_lsn()::text", &[])
                .await?
                .get(0);
            reg.database_maintenance().update(&op.id, |o| {
                o.barrier_lsn = Some(barrier);
                Ok(())
            })?;
        }
    } else {
        ensure!(
            op.identities.values().all(|i| i.deleted),
            "local resource receipts incomplete"
        );
    }
    reg.commit_database_maintenance(op).await?;
    reg.database_maintenance().update(&op.id, |o| {
        o.metadata_committed = true;
        o.stage = Stage::MetadataCommitted;
        Ok(())
    })?;
    Ok(())
}

async fn finish(reg: &Arc<SchemaRegistry>, op: &Operation) -> Result<()> {
    require_peer(reg, op, Stage::MetadataCommitted, false).await?;
    if let Some(new) = &op.destination {
        if op.role == Role::Replica {
            let source = peer_operation(reg, op).await?;
            let barrier = source
                .barrier_lsn
                .context("source omitted reopening barrier")?;
            verify_standby(
                reg,
                &op.bound_vm,
                new,
                &op.identities[&op.bound_vm],
                &barrier,
            )
            .await?;
        }
    }
    reg.database_maintenance().update(&op.id, |o| {
        o.complete = true;
        o.stage = Stage::Finished;
        Ok(())
    })?;
    Ok(())
}

async fn delete_exact(reg: &Arc<SchemaRegistry>, op: &Operation, id: &str) -> Result<()> {
    let expected = op.identities.get(id).context("missing captured identity")?;
    if expected.deleted {
        return Ok(());
    }
    if !expected.deletion_started {
        assert_live(reg, op, id).await?;
        reg.database_maintenance().update(&op.id, |o| {
            o.identities.get_mut(id).unwrap().deletion_started = true;
            Ok(())
        })?;
    }
    let disk = reg
        .cfg()
        .run_dir
        .as_ref()
        .context("PG_VM_POOL_RUN_DIR is required")?
        .join(id);
    let sb = Sandbox::connect(id.to_owned(), vm::local_opts())?;
    match daemon_info(id).await? {
        Some(_) => {
            assert_live(reg, op, id).await?;
            let mut env = std::collections::HashMap::new();
            env.insert("PGFC_DB".into(), op.database.clone());
            let proof = vm::physical_exec(
                reg.cfg(),
                &sb,
                SAFE_TO_DELETE,
                env,
                "checking retirement contents and clients",
            )
            .await?;
            ensure!(
                proof.exit_code == 0 && proof.stdout.trim() == "t",
                "retirement VM has clients, extra databases or prepared transactions"
            );
            vm::kill_and_reclaim(reg.cfg(), &sb, &op.database, "database retired").await?;
        }
        None => {}
    }
    ensure!(
        daemon_info(id).await?.is_none(),
        "VM deletion is not confirmed"
    );
    ensure!(
        !tokio::fs::try_exists(&disk).await?,
        "VM disk remains after deletion"
    );
    reg.database_maintenance().update(&op.id, |o| {
        o.identities.get_mut(id).unwrap().deleted = true;
        Ok(())
    })?;
    Ok(())
}

async fn assert_live(reg: &SchemaRegistry, op: &Operation, id: &str) -> Result<()> {
    let expected = &op.identities[id];
    let current = live_identity(reg, id, &op.database).await?;
    ensure!(
        current.created_at == expected.created_at
            && current.system_identifier == expected.system_identifier
            && current.database_oid == expected.database_oid,
        "VM identity changed immediately before destructive action"
    );
    Ok(())
}

async fn assert_database_identity(
    reg: &SchemaRegistry,
    op: &Operation,
    id: &str,
    database: &str,
) -> Result<()> {
    let actual = live_identity(reg, id, database).await?;
    let expected = &op.identities[id];
    ensure!(
        actual.created_at == expected.created_at
            && actual.system_identifier == expected.system_identifier
            && actual.database_oid == expected.database_oid,
        "renamed runtime identity changed"
    );
    Ok(())
}

async fn verify_standby(
    reg: &SchemaRegistry,
    id: &str,
    database: &str,
    expected: &Identity,
    barrier: &str,
) -> Result<()> {
    let raw = daemon_info(id).await?.context("standby disappeared")?;
    ensure!(
        raw.get("created_at").and_then(Value::as_str) == Some(&expected.created_at),
        "standby incarnation changed"
    );
    let sb = Sandbox::connect(id.to_owned(), vm::local_opts())?;
    let mut env = std::collections::HashMap::new();
    env.insert("PGFC_DB".into(), database.into());
    env.insert("PGFC_SID".into(), expected.system_identifier.clone());
    env.insert("PGFC_OID".into(), expected.database_oid.to_string());
    env.insert("PGFC_LSN".into(), barrier.into());
    let p = vm::physical_exec(
        reg.cfg(),
        &sb,
        VERIFY_STANDBY,
        env,
        "verifying renamed standby",
    )
    .await?;
    ensure!(
        p.exit_code == 0 && p.stdout.trim() == "t",
        "standby is not streaming, in recovery, and freshly replayed through rename barrier"
    );
    Ok(())
}

async fn daemon_info(id: &str) -> Result<Option<Value>> {
    match HeyoClient::new(vm::local_opts())?
        .request::<Value>(
            reqwest::Method::GET,
            &format!("/deployed-sandboxes/{id}"),
            None::<&()>,
            RequestOptions::default(),
        )
        .await
    {
        Ok(v) => Ok(Some(v)),
        Err(HeyoError::NotFound(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

async fn peer_operation(reg: &SchemaRegistry, op: &Operation) -> Result<Operation> {
    let peer = reg
        .peers()
        .get(&op.peer)
        .context("configured peer disappeared")?;
    PeerClient::new(
        peer,
        reg.replication_cfg()
            .context("replication disabled")?
            .peer_timeout,
    )?
    .maintenance_status(&op.id)
    .await
}

async fn require_peer(
    reg: &SchemaRegistry,
    op: &Operation,
    stage: Stage,
    deletion_receipts: bool,
) -> Result<()> {
    let p = peer_operation(reg, op).await?;
    let expected_role = if op.role == Role::Source {
        Role::Replica
    } else {
        Role::Source
    };
    ensure!(
        p.id == op.id
            && p.database == op.database
            && p.destination == op.destination
            && p.generation == op.generation
            && p.peer == reg.replication_cfg().unwrap().node_name
            && p.role == expected_role
            && p.stage as u8 >= stage as u8,
        "peer durable maintenance gate/progress does not match"
    );
    let (source, replica) = if op.role == Role::Source {
        (op, &p)
    } else {
        (&p, op)
    };
    let identity = source
        .identities
        .get(&source.bound_vm)
        .context("source has no captured identity")?;
    ensure!(
        replica
            .identities
            .values()
            .any(|i| i.system_identifier == identity.system_identifier
                && i.database_oid == identity.database_oid),
        "peer does not contain the same physical database"
    );
    if deletion_receipts {
        ensure!(
            p.identities.values().all(|i| i.deleted) && !p.identities.is_empty(),
            "peer exact deletion receipts are incomplete"
        );
    }
    Ok(())
}

const IDENTITY_SQL: &str = r#"set -eu
gosu postgres psql -XAt -v ON_ERROR_STOP=1 -d postgres -v db="$PGFC_DB" -F '|' <<'SQL'
SELECT (pg_control_system()).system_identifier::text, oid::int8 FROM pg_database WHERE datname=:'db';
SQL
"#;
const SAFE_TO_DELETE: &str = r#"set -eu
gosu postgres psql -XAt -v ON_ERROR_STOP=1 -d postgres -v db="$PGFC_DB" <<'SQL'
SELECT NOT EXISTS(SELECT FROM pg_database WHERE NOT datistemplate AND datname NOT IN ('postgres', :'db'))
AND NOT EXISTS(SELECT FROM pg_prepared_xacts)
AND NOT EXISTS(SELECT FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND backend_type='client backend' AND datname <> 'postgres');
SQL
"#;
const VERIFY_STANDBY: &str = r#"set -eu
gosu postgres psql -XAt -v ON_ERROR_STOP=1 -d postgres -v db="$PGFC_DB" -v sid="$PGFC_SID" -v oid="$PGFC_OID" -v lsn="$PGFC_LSN" <<'SQL'
SELECT pg_is_in_recovery() AND (pg_control_system()).system_identifier::text=:'sid'
AND EXISTS(SELECT FROM pg_database WHERE datname=:'db' AND oid=:'oid'::oid)
AND EXISTS(SELECT FROM pg_stat_wal_receiver WHERE status='streaming')
AND COALESCE(pg_last_wal_replay_lsn() >= :'lsn'::pg_lsn,false);
SQL
"#;
const DRAIN_LOGICAL: &str = r#"set -eu
export PGOPTIONS='-c synchronous_commit=on'
clients=$(gosu postgres psql -XAt -v ON_ERROR_STOP=1 -d postgres -v db="$PGFC_DB" <<'SQL'
SELECT count(*) FROM pg_stat_activity WHERE datname=:'db' AND pid<>pg_backend_pid() AND backend_type='client backend';
SQL
)
[ "$clients" = 0 ]
allowed=$(gosu postgres psql -XAt -v ON_ERROR_STOP=1 -d postgres -v db="$PGFC_DB" <<'SQL'
SELECT datallowconn FROM pg_database WHERE datname=:'db';
SQL
)
if [ "$allowed" = t ]; then
    gosu postgres psql -XqAt -v ON_ERROR_STOP=1 -d "$PGFC_DB" <<'SQL'
SELECT format('ALTER SUBSCRIPTION %I DISABLE', subname) FROM pg_subscription
WHERE subdbid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND subenabled \gexec
SQL
fi
gosu postgres psql -XqAt -v ON_ERROR_STOP=1 -d postgres -v db="$PGFC_DB" <<'SQL'
SELECT format('ALTER DATABASE %I ALLOW_CONNECTIONS false', :'db') \gexec
SELECT NOT EXISTS(SELECT FROM pg_subscription
WHERE subdbid=(SELECT oid FROM pg_database WHERE datname=:'db') AND subenabled);
SQL
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standby_proof_requires_recovery_streaming_identity_and_fresh_replay() {
        for predicate in [
            "pg_is_in_recovery()",
            "datname=:'db'",
            "status='streaming'",
            "pg_last_wal_replay_lsn() >= :'lsn'",
        ] {
            assert!(VERIFY_STANDBY.contains(predicate), "missing {predicate}");
        }
    }
}
