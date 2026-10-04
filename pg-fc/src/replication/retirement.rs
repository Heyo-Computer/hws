//! Explicit retirement of a replaced bootstrap logical replica, not a writer
//! decommission or a generic override of physical ownership protections.
use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result, bail};
use heyo_sdk::{HeyoError, Sandbox};

use super::{PhysicalPhase, Role, peer::PeerClient, physical_store::PreviousRetirement, wire};
use crate::{registry::SchemaRegistry, vm};

pub async fn retire_previous(
    reg: &Arc<SchemaRegistry>,
    database: &str,
    req: wire::RetirePreviousRequest,
) -> Result<wire::PhysicalRecordJson> {
    let _operation = reg.replication_operation(database).await;
    let source = reg
        .physical_sources()
        .get(database)
        .context("no physical source")?;
    if source.generation != req.generation
        || source.predecessor.is_some()
        || source.fence.is_some()
        || source.handoff.is_some()
        || source.handoff_candidate.is_some()
        || reg.bound_vm_id(database).as_deref() != Some(source.source_vm_id.as_str())
    {
        bail!("retirement requires the exact unfenced bootstrap writer");
    }
    let logical = reg
        .replication()
        .get(database)
        .context("missing logical slot ownership")?;
    if logical.role != Role::Primary || logical.peer != source.peer || logical.slot == source.slot {
        bail!("logical slot ownership does not match the physical source");
    }
    let cfg = reg.replication_cfg().context("replication disabled")?;
    let peer = reg
        .peers()
        .get(&source.peer)
        .context("source peer missing")?;
    let client = PeerClient::new(peer, cfg.peer_timeout)?;
    let info = client.node_info().await?;
    if info.node != source.peer || !info.physical_standby_writer_routing {
        bail!("peer does not support writer-preserving retirement");
    }
    let (_guard, db) = reg.db_client(database).await?;
    let row = db.query_one("SELECT NOT pg_is_in_recovery(), (pg_control_system()).system_identifier::text, current_setting('server_version_num')::int / 10000, pg_current_wal_flush_lsn()::text", &[]).await?;
    if !row.get::<_, bool>(0)
        || row.get::<_, String>(1) != source.system_identifier
        || row.get::<_, i32>(2) as u32 != source.pg_major
    {
        bail!("writer runtime identity changed");
    }
    let request = wire::RetirePreviousPeerRequest {
        previous_vm_id: req.previous_vm_id.clone(),
        standby: wire::PhysicalStandbyBindRequest {
            database: database.into(),
            generation: req.generation.clone(),
            candidate_id: req.candidate_id.clone(),
            source_node: cfg.node_name.clone(),
            source_vm_id: source.source_vm_id.clone(),
            system_identifier: source.system_identifier.clone(),
            pg_major: source.pg_major,
            source_lsn: row.get(3),
        },
    };
    let result = client.retire_previous(&request).await?;
    if result.generation != req.generation
        || result.candidate_id.as_deref() != Some(req.candidate_id.as_str())
        || !result
            .previous_retirement
            .as_ref()
            .is_some_and(|r| r.vm_id == req.previous_vm_id && r.deleted)
    {
        bail!("peer did not confirm the exact previous replica retirement");
    }
    // The physical stream shares the replication login. Never use logical
    // detach here: that would drop its role and break the retained standby.
    if let Some(slot) = db
        .query_opt(
            "SELECT slot_type, database, active FROM pg_replication_slots WHERE slot_name=$1",
            &[&logical.slot],
        )
        .await?
    {
        if slot.get::<_, String>(0) != "logical"
            || slot.get::<_, Option<String>>(1).as_deref() != Some(database)
            || slot.get::<_, bool>(2)
        {
            bail!(
                "previous replica deleted; logical slot is not inactive and exclusively owned, retry cleanup later"
            );
        }
        db.query_one("SELECT pg_drop_replication_slot($1)", &[&logical.slot])
            .await?;
    }
    Ok(result)
}

pub async fn accept_retirement(
    reg: &Arc<SchemaRegistry>,
    req: wire::RetirePreviousPeerRequest,
) -> Result<wire::PhysicalRecordJson> {
    let s = &req.standby;
    let _operation = reg.replication_operation(&s.database).await;
    let rec = reg
        .physical()
        .get(&s.database)
        .context("no retained physical replica")?;
    if rec.predecessor.is_some()
        || rec.phase != PhysicalPhase::Standby
        || rec.generation != s.generation
        || rec.candidate_id.as_deref() != Some(s.candidate_id.as_str())
        || rec.previous_vm_id.as_deref() != Some(req.previous_vm_id.as_str())
        || rec.source_node != s.source_node
        || rec.source_vm_id != s.source_vm_id
        || rec.system_identifier != s.system_identifier
        || rec.pg_major != s.pg_major
        || reg.bound_vm_id(&s.database).as_deref() != Some(s.candidate_id.as_str())
    {
        bail!("retirement does not identify the exact replaced bootstrap replica");
    }
    if reg.physical_sources().owns_vm(&req.previous_vm_id)
        || reg.physical().is_candidate_vm(&req.previous_vm_id)
        || reg
            .store_records()
            .iter()
            .any(|(_, r)| r.sandbox_id == req.previous_vm_id)
    {
        bail!("retirement target still has serving or physical source/candidate ownership");
    }
    if rec.previous_retirement.as_ref().is_some_and(|r| r.deleted) {
        return Ok((&rec).into());
    }
    let peer = reg
        .peers()
        .get(&s.source_node)
        .context("source peer missing")?;
    let info = PeerClient::new(
        peer,
        reg.replication_cfg()
            .context("replication disabled")?
            .peer_timeout,
    )?
    .node_info()
    .await?;
    if info.node != s.source_node || !info.physical_standby_writer_routing {
        bail!("source routing capability changed");
    }
    let candidate =
        vm::connect_physical_candidate(reg.cfg(), &rec.candidate_name, &s.candidate_id).await?;
    let mut env = HashMap::new();
    env.insert("PGFC_SYSTEM_ID".into(), s.system_identifier.clone());
    env.insert("PGFC_SLOT".into(), rec.slot.clone());
    env.insert("PGFC_LSN".into(), s.source_lsn.clone());
    let proof = vm::physical_exec(
        reg.cfg(),
        &candidate,
        VERIFY_RETAINED,
        env,
        "verifying retained replica",
    )
    .await?;
    if proof.exit_code != 0 || proof.stdout.trim() != "t" {
        bail!("retained replica is not streaming and caught up");
    }
    let old = Sandbox::connect(req.previous_vm_id.clone(), vm::local_opts())?;
    let info = match old.get().await {
        Ok(info) => Some(serde_json::to_value(info)?),
        Err(HeyoError::NotFound(_)) if rec.previous_retirement.is_some() => None,
        Err(error) => return Err(error.into()),
    };
    let mut retirement = if let Some(info) = info {
        let created = info
            .get("created_at")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .context("old VM has no incarnation timestamp; refusing deletion")?;
        let identity = vm::physical_exec(reg.cfg(), &old,
            "gosu postgres psql -XAt -v ON_ERROR_STOP=1 -d postgres -c 'SELECT system_identifier FROM pg_control_system()'",
            HashMap::new(), "identifying previous replica").await?;
        let system = identity.stdout.trim();
        if identity.exit_code != 0
            || system.is_empty()
            || !system.bytes().all(|b| b.is_ascii_digit())
            || system == s.system_identifier
        {
            bail!("old VM is not a distinct logical-replica cluster");
        }
        let intent = PreviousRetirement {
            vm_id: req.previous_vm_id.clone(),
            created_at: created.into(),
            system_identifier: system.into(),
            deleted: false,
        };
        reg.physical()
            .record_previous_retirement(&s.database, &s.generation, intent.clone())?;
        let mut env = HashMap::new();
        env.insert("PGFC_DB".into(), s.database.clone());
        let drained = vm::physical_exec(
            reg.cfg(),
            &old,
            DRAIN_PREVIOUS,
            env,
            "draining previous replica",
        )
        .await?;
        if drained.exit_code != 0 || drained.stdout.trim() != "t" {
            bail!("previous replica still has clients or other databases; retry after they finish");
        }
        old.kill().await?;
        match old.get().await {
            Err(HeyoError::NotFound(_)) => {}
            _ => bail!("previous VM deletion is not confirmed; retry the same retirement"),
        }
        intent
    } else {
        rec.previous_retirement
            .clone()
            .context("missing retirement intent")?
    };
    retirement.deleted = true;
    reg.physical()
        .record_previous_retirement(&s.database, &s.generation, retirement)?;
    crate::inventory::remove_id(&req.previous_vm_id);
    Ok((&reg
        .physical()
        .get(&s.database)
        .context("retirement record disappeared")?)
        .into())
}

const VERIFY_RETAINED: &str = r#"set -eu
gosu postgres psql -XAt -v ON_ERROR_STOP=1 -d postgres -v identity="$PGFC_SYSTEM_ID" -v slot="$PGFC_SLOT" -v lsn="$PGFC_LSN" <<'SQL'
SELECT pg_is_in_recovery() AND current_setting('transaction_read_only')='on'
AND (pg_control_system()).system_identifier::text=:'identity'
AND EXISTS(SELECT FROM pg_stat_wal_receiver WHERE status='streaming' AND slot_name=:'slot')
AND COALESCE(pg_last_wal_replay_lsn() >= :'lsn'::pg_lsn,false);
SQL
"#;

const DRAIN_PREVIOUS: &str = r#"set -eu
gosu postgres psql -XqAt -v ON_ERROR_STOP=1 -d postgres -v db="$PGFC_DB" <<'SQL'
SELECT format('ALTER DATABASE %I ALLOW_CONNECTIONS false', :'db') \gexec
SELECT NOT EXISTS(SELECT FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND backend_type='client backend')
AND NOT EXISTS(SELECT FROM pg_locks WHERE locktype='object' AND classid='pg_database'::regclass
    AND objid=(SELECT oid FROM pg_database WHERE datname=:'db') AND granted AND pid IS NOT NULL)
AND NOT EXISTS(SELECT FROM pg_database WHERE NOT datistemplate AND datname NOT IN ('postgres', :'db'))
AND NOT EXISTS(SELECT FROM pg_prepared_xacts);
SQL
"#;
