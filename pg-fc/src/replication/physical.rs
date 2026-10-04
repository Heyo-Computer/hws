//! Bounded physical migration preparation.
//!
//! `POST /api/replication/{db}/physical-prepare` creates durable source slot
//! ownership and asks the existing logical peer to seed a distinct candidate.
//! `POST /api/replication/peer/physical-replicas` durably records that
//! candidate before VM creation. Both endpoints are generation-idempotent and
//! return a sanitized [`wire::PhysicalRecordJson`]. The preparation worker may
//! advance only through `verified`: it never changes the ordinary database
//! binding, promotes either VM, or tears down logical replication.
//! A separate recovery worker resumes only explicitly authorized handoffs.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Context, Result, bail};
use tracing::warn;

use crate::registry::SchemaRegistry;
use super::{PhysicalHandoffGrant, PhysicalPhase, PhysicalRecord, PhysicalSourceRecord, Role, State, peer::PeerClient, wire};

const SETTINGS: [&str; 5] = ["max_connections", "max_prepared_transactions", "max_locks_per_transaction", "max_wal_senders", "max_worker_processes"];

pub async fn prepare_source(reg: &Arc<SchemaRegistry>, database: &str, generation: &str) -> Result<wire::PhysicalRecordJson> {
    prepare_source_inner(reg, database, generation, None).await
}

pub async fn reseed_source(reg: &Arc<SchemaRegistry>, database: &str, req: wire::PhysicalReseedRequest) -> Result<wire::PhysicalRecordJson> {
    prepare_source_inner(reg, database, &req.generation, Some(&req.prior_generation)).await
}

async fn prepare_source_inner(reg: &Arc<SchemaRegistry>, database: &str, generation: &str, reseed_from: Option<&str>) -> Result<wire::PhysicalRecordJson> {
    let _guard = reg.replication_operation(database).await?;
    let incoming = reg.physical().get(database).filter(|r| r.phase == PhysicalPhase::Activated);
    let source_vm_id = reg.bound_vm_id(database).context("source database has no durable VM binding")?;
    if !reg.physical_admission_ready(database) { bail!("physical source is fenced or not the current writer"); }
    let (peer_name, repl, predecessor) = if let Some(active) = &incoming {
        if active.candidate_id.as_deref() != Some(&source_vm_id) { bail!("incoming activation does not match current writer"); }
        (active.source_node.clone(), active.repl.clone().context("activated physical writer lost replication credential")?, Some(active.generation.clone()))
    } else {
        let logical = reg.replication().get(database).context("bootstrap physical preparation requires a logical pairing")?;
        let state_ok = matches!(logical.state, State::Active | State::Syncing)
            || reseed_from.is_some() && logical.state == State::Failed;
        if logical.role != Role::Primary || !state_ok { bail!("physical preparation must run on the logical primary"); }
        if logical.fence.is_some() { bail!("prepare the physical candidate before fencing the source"); }
        (logical.peer, wire::Login { role: logical.repl_role, password: logical.repl_password }, None)
    };
    let predecessor = reseed_from.map(str::to_owned).or(predecessor);
    let rcfg = reg.replication_cfg().context("replication disabled")?;
    if !reg.tls_enabled() && !rcfg.allow_insecure { bail!("physical preparation requires pooler TLS or explicitly allowed insecure transport"); }
    let peer = reg.peers().get(&peer_name).context("physical peer record is missing")?;
    let client = PeerClient::new(peer, rcfg.peer_timeout)?;
    let info = client.node_info().await?;
    if !info.physical_prepare || reseed_from.is_some() && !info.physical_reseed || info.node != peer_name || !info.replication_enabled
        || predecessor.is_some() && !info.physical_successor {
        bail!("peer identity/capability does not support this physical preparation");
    }
    if let Some(existing) = reg.physical_sources().get(database) {
        if existing.generation == generation {
            if existing.source_vm_id != source_vm_id || existing.handoff_candidate.is_some() || existing.handoff.is_some() || existing.fence.is_some() {
                bail!("source preparation is stale or already fenced");
            }
            reg.physical_sources().set_repl(database, generation, repl.clone())?;
        } else if reseed_from.is_some() && (reseed_from != Some(existing.generation.as_str()) || incoming.is_some())
            || reseed_from.is_none() && incoming.is_none() {
            bail!("a different physical generation already owns this source");
        }
    }
    let tenant = reg.dedicated().by_database(database).context("physical preparation requires the dedicated tenant credential")?;
    let (_conn_guard, db) = reg.db_client(database).await?;
    let row = db.query_one("SELECT NOT pg_is_in_recovery(), (pg_control_system()).system_identifier::text, current_setting('server_version_num')::int / 10000, pg_current_wal_flush_lsn()::text", &[]).await?;
    let primary: bool = row.get(0); if !primary { bail!("bound source VM is in recovery"); }
    if reg.bound_vm_id(database).as_deref() != Some(&source_vm_id) { bail!("source VM binding changed during validation"); }
    let extra: i64 = db.query_one("SELECT count(*) FROM pg_database WHERE datallowconn AND NOT datistemplate AND datname NOT IN ('postgres',$1)", &[&database]).await?.get(0);
    let tablespaces: i64 = db.query_one("SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')", &[]).await?.get(0);
    if extra != 0 || tablespaces != 0 { bail!("physical seed does not support extra user databases or tablespaces"); }
    let system_identifier: String = row.get(1); let pg_major: i32 = row.get(2); let source_lsn: String = row.get(3);
    if let Some(prior) = reseed_from {
        let owned = reg.physical_sources().get(database).context("physical reseed requires prior source ownership")?;
        let retry = owned.generation == generation && owned.predecessor.as_deref() == Some(prior);
        if (!retry && owned.generation != prior) || owned.source_vm_id != source_vm_id || owned.fence.is_some()
            || owned.handoff.is_some() || owned.handoff_candidate.is_some() { bail!("prior source is not safe to reseed"); }
        let logical = reg.replication().get(database).context("physical reseed requires the failed logical pairing")?;
        if logical.role != Role::Primary || logical.state != State::Failed || logical.peer != peer_name
            || logical.repl_role != repl.role || logical.repl_password != repl.password { bail!("failed logical pairing identity changed"); }
        let prior_slot = format!("pgfc_phys_{}", prior.replace('-', "_"));
        let checks = db.query_one("SELECT current_setting('wal_level')='logical', EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1 AND rolcanlogin), COALESCE((SELECT wal_status='lost' FROM pg_replication_slots WHERE slot_name=$2), false), COALESCE((SELECT wal_status='lost' FROM pg_replication_slots WHERE slot_name=$3), false)", &[&logical.repl_role, &logical.slot, &prior_slot]).await?;
        if !checks.get::<_, bool>(0) || !checks.get::<_, bool>(1) || !checks.get::<_, bool>(2) || !checks.get::<_, bool>(3) {
            bail!("physical reseed requires runtime logical WAL/login and both prior slots in lost state");
        }
    }
    let mut settings = BTreeMap::new();
    for key in SETTINGS { let value: i32 = db.query_one("SELECT current_setting($1)::int", &[&key]).await?.get(0); settings.insert(key.into(), value); }
    let slot = format!("pgfc_phys_{}", generation.replace('-', "_"));
    let intent = PhysicalSourceRecord { database: database.into(), generation: generation.into(), predecessor: predecessor.clone(), source_vm_id: source_vm_id.clone(), repl: Some(repl.clone()), fence: None, system_identifier: system_identifier.clone(), pg_major: pg_major as u32, slot: slot.clone(), source_lsn: source_lsn.clone(), peer: peer_name.clone(), handoff_candidate: None, handoff_complete: false, handoff: None, last_error: None };
    let source = if let Some(prior) = reseed_from {
        reg.physical_sources().create_reseed(intent, prior)?
    } else if let Some(active) = &incoming {
        reg.physical_sources().create_successor(intent, active, &source_vm_id)?
    } else { reg.physical_sources().create(intent)? };
    if source.source_vm_id != source_vm_id || source.system_identifier != system_identifier || source.pg_major != pg_major as u32 || source.slot != slot || source.peer != peer_name {
        bail!("durable physical source identity no longer matches the bound logical primary");
    }
    let existing_type: Option<String> = db.query_opt("SELECT slot_type FROM pg_replication_slots WHERE slot_name=$1", &[&slot]).await?.map(|r| r.get(0));
    if existing_type.as_deref().is_some_and(|kind| kind != "physical") { bail!("owned physical slot name collides with a non-physical slot"); }
    if existing_type.is_none() { db.query_one("SELECT pg_create_physical_replication_slot($1, true)", &[&slot]).await.context("creating owned physical slot")?; }
    let mut hba_env = HashMap::new(); hba_env.insert("PGFC_REPL_ROLE".into(), repl.role.clone());
    // TLS terminates at the pooler; its upstream connection is plaintext.
    hba_env.insert("PGFC_HBA_KIND".into(), "host".into());
    reg.exec_bound(database, &source_vm_id, "set -eu; f=/workspace/pgdata/pg_hba.conf; line=\"$PGFC_HBA_KIND replication $PGFC_REPL_ROLE 0.0.0.0/0 scram-sha-256\"; grep -Fqx \"$line\" $f || printf '%s\\n' \"$line\" >>$f; gosu postgres pg_ctl -D /workspace/pgdata reload", hba_env).await?;
    let host = rcfg.advertise_host.as_ref().context("PG_VM_POOL_ADVERTISE_PG_HOST is required")?;
    let host = super::orchestrate::resolve_v4(host, rcfg.advertise_port).await?.to_string();
    let request = wire::PhysicalReplicaRequest { database: database.into(), generation: generation.into(), predecessor, source_node: rcfg.node_name.clone(), source_vm_id: source.source_vm_id.clone(), system_identifier: source.system_identifier.clone(), pg_major: source.pg_major, source_lsn: source.source_lsn.clone(), settings, tenant: wire::Login { role: tenant.role, password: tenant.password }, repl, primary: wire::PrimaryEndpoint { hostaddr: host, port: rcfg.advertise_port, sslmode: rcfg.sslmode.clone() }, slot: source.slot.clone(), reseed_from: reseed_from.map(str::to_owned) };
    let answer = client.provision_physical_replica(&request).await?;
    Ok(answer)
}

pub async fn accept_candidate(reg: &Arc<SchemaRegistry>, req: wire::PhysicalReplicaRequest) -> Result<PhysicalRecord> {
    let _operation = reg.replication_operation(&req.database).await?;
    let rcfg = reg.replication_cfg().context("replication disabled")?;
    let _: std::net::Ipv4Addr = req.primary.hostaddr.parse().context("physical source must advertise IPv4")?;
    if req.primary.port == 0 || !matches!(req.primary.sslmode.as_str(), "require" | "disable")
        || (req.primary.sslmode == "disable" && !rcfg.allow_insecure) {
        bail!("invalid or insecure physical source endpoint");
    }
    if req.settings.values().any(|value| *value < 0) { bail!("physical source settings cannot be negative"); }
    let preceding = if req.reseed_from.is_some() {
        let logical = reg.replication().get(&req.database).context("physical reseed requires the failed logical replica")?;
        if logical.role != Role::Replica || logical.state != State::Failed || logical.peer != req.source_node
            || logical.repl_role != req.repl.role || logical.repl_password != req.repl.password {
            bail!("physical reseed source does not match the failed logical pairing");
        }
        None
    } else if req.predecessor.is_some() {
        let source = reg.physical_sources().get(&req.database).context("physical rejoin requires a preceding source grant")?;
        if source.repl.as_ref() != Some(&req.repl) { bail!("physical successor changed the replication credential"); }
        Some(source)
    } else {
        let logical = reg.replication().get(&req.database).context("physical candidate requires the existing logical replica")?;
        if logical.role != Role::Replica || logical.peer != req.source_node { bail!("physical source does not match the logical pairing"); }
        if logical.repl_role != req.repl.role || logical.repl_password != req.repl.password { bail!("physical replication credential does not match the logical pairing"); }
        None
    };
    let tenant = reg.dedicated().by_database(&req.database).context("logical replica lost its tenant credential")?;
    if tenant.role != req.tenant.role || tenant.password != req.tenant.password { bail!("physical tenant credential does not match the logical replica"); }
    if SETTINGS.iter().any(|key| !req.settings.contains_key(*key)) || req.settings.len() != SETTINGS.len() { bail!("physical source settings are incomplete"); }
    let previous = reg.bound_vm_id(&req.database).context("logical replica has no durable serving VM")?;
    if reg.physical().get(&req.database).is_some_and(|r| r.generation == req.generation) {
        reg.physical().set_repl(&req.database, &req.generation, req.repl.clone())?;
    }
    let intent = PhysicalRecord { database: req.database.clone(), generation: req.generation.clone(), predecessor: req.predecessor.clone(), candidate_name: PhysicalRecord::candidate_name(&req.generation), repl: Some(req.repl.clone()), candidate_id: None, previous_vm_id: Some(previous.clone()), source_node: req.source_node.clone(), source_vm_id: req.source_vm_id.clone(), system_identifier: req.system_identifier.clone(), pg_major: req.pg_major, slot: req.slot.clone(), phase: PhysicalPhase::Intent, handoff_barrier: None, standby_lsn: None, previous_retirement: None, last_error: None };
    let rec = if let Some(prior) = &req.reseed_from {
        if req.predecessor.as_deref() != Some(prior) { bail!("physical reseed ancestry mismatch"); }
        let old = reg.physical().get(&req.database).context("physical reseed requires prior candidate ownership")?;
        let retry = old.generation == req.generation && old.predecessor.as_deref() == Some(prior);
        if (!retry && old.generation != *prior) || old.source_node != req.source_node || old.source_vm_id != req.source_vm_id
            || old.system_identifier != req.system_identifier || old.pg_major != req.pg_major || old.handoff_started()
            || old.phase == PhysicalPhase::Standby { bail!("prior physical candidate is not safe to reseed"); }
        reg.physical().create_reseed(intent, prior, &previous)?
    } else if let Some(source) = preceding {
        reg.physical().create_successor(intent, &source, &previous)?
    } else { reg.physical().create(intent)? };
    let background = rec.clone();
    let reg2 = reg.clone(); tokio::spawn(async move { if let Err(e) = seed(reg2.clone(), req).await { let _ = reg2.physical().set_error(&background.database, &background.generation, Some(format!("{e:#}").chars().take(500).collect())); warn!("physical candidate prepare failed: {e:#}"); } });
    Ok(rec)
}

pub async fn source_grant(reg: &Arc<SchemaRegistry>, database: &str) -> Result<wire::PhysicalHandoffGrantJson> {
    let _operation = reg.replication_operation(database).await?;
    let source = reg.physical_sources().get(database).context("no physical source operation")?;
    let grant = source.handoff.context("physical handoff has not been authorized")?;
    if reg.bound_vm_id(database).as_deref() != Some(&source.source_vm_id) { bail!("physical grant no longer describes the bound source"); }
    let fence = source.fence.context("physical grant lost source fence")?;
    if fence.phase != "ready" || fence.barrier_lsn.as_deref() != Some(&grant.barrier_lsn) { bail!("physical grant source fence no longer matches"); }
    let (_guard, maintenance) = reg.maintenance_client(database).await?;
    let closed: bool = maintenance.query_one("SELECT NOT datallowconn FROM pg_database WHERE datname=$1", &[&database]).await?.get(0);
    if !closed { bail!("physical grant source admission is open"); }
    Ok(wire::PhysicalHandoffGrantJson { database: source.database, generation: source.generation,
        candidate_id: grant.candidate_id, source_vm_id: source.source_vm_id,
        system_identifier: source.system_identifier, pg_major: source.pg_major,
        barrier_lsn: grant.barrier_lsn, peer: grant.peer })
}

/// Explicitly authorize binding a verified remote candidate as a read-only
/// standby.  This path never fences the source and never creates a handoff.
pub async fn bind_standby_source(reg: &Arc<SchemaRegistry>, database: &str, generation: &str) -> Result<wire::PhysicalRecordJson> {
    let _operation = reg.replication_operation(database).await?;
    let source = reg.physical_sources().get(database).context("no physical source preparation")?;
    if source.generation != generation || source.fence.is_some() || source.handoff.is_some()
        || source.handoff_candidate.is_some() || reg.bound_vm_id(database).as_deref() != Some(&source.source_vm_id) {
        bail!("standby bind requires the exact unfenced source generation");
    }
    let peer = reg.peers().get(&source.peer).context("physical source peer is missing")?;
    let client = PeerClient::new(peer, reg.replication_cfg().context("replication disabled")?.peer_timeout)?;
    let info = client.node_info().await?;
    if info.node != source.peer || !info.physical_standby_bind { bail!("peer does not support physical standby binding"); }
    if source.predecessor.is_none() && !info.physical_standby_writer_routing {
        bail!("upgrade peer writer routing before binding a bootstrap standby");
    }
    let target = client.physical_status(database).await?;
    if target.generation != generation || !matches!(target.phase.as_str(), "verified" | "standbybinding" | "standby_binding" | "standby") || target.source_vm_id != source.source_vm_id
        || target.source_node != reg.replication_cfg().unwrap().node_name || target.system_identifier != source.system_identifier
        || target.pg_major != source.pg_major { bail!("peer does not own the exact verified standby candidate"); }
    if target.phase != "verified" { return Ok(target); }
    let candidate = target.candidate_id.context("verified peer candidate lost identity")?;
    let (_guard, db) = reg.db_client(database).await?;
    let row = db.query_one("SELECT NOT pg_is_in_recovery(), (pg_control_system()).system_identifier::text, pg_current_wal_flush_lsn()::text", &[]).await?;
    if !row.get::<_, bool>(0) || row.get::<_, String>(1) != source.system_identifier { bail!("source runtime is no longer the writer identity"); }
    let req = wire::PhysicalStandbyBindRequest { database: database.into(), generation: generation.into(), candidate_id: candidate,
        source_node: reg.replication_cfg().unwrap().node_name.clone(), source_vm_id: source.source_vm_id,
        system_identifier: source.system_identifier, pg_major: source.pg_major, source_lsn: row.get(2) };
    client.physical_standby_bind(&req).await
}

pub async fn accept_standby_bind(reg: &Arc<SchemaRegistry>, req: wire::PhysicalStandbyBindRequest) -> Result<wire::PhysicalRecordJson> {
    let _operation = reg.replication_operation(&req.database).await?;
    let mut rec = reg.physical().get(&req.database).context("no physical candidate preparation")?;
    let candidate = rec.candidate_id.clone().context("physical candidate has no durable VM identity")?;
    let previous = rec.previous_vm_id.clone().context("physical candidate lost old binding")?;
    if rec.generation != req.generation || candidate != req.candidate_id || rec.source_node != req.source_node
        || rec.source_vm_id != req.source_vm_id || rec.system_identifier != req.system_identifier || rec.pg_major != req.pg_major
        || rec.handoff_started() { bail!("stale or unauthorized physical standby bind"); }
    if rec.phase == PhysicalPhase::Standby { return Ok((&rec).into()); }
    if !matches!(rec.phase, PhysicalPhase::Verified | PhysicalPhase::StandbyBinding)
        || rec.phase == PhysicalPhase::StandbyBinding && rec.standby_lsn.as_deref() != Some(&req.source_lsn) {
        bail!("physical candidate is not authorized for standby binding");
    }
    let peer = reg.peers().get(&rec.source_node).context("physical source peer is missing")?;
    let info = PeerClient::new(peer, reg.replication_cfg().context("replication disabled")?.peer_timeout)?.node_info().await?;
    if info.node != rec.source_node || !info.physical_standby_bind { bail!("source identity/capability changed"); }
    if rec.predecessor.is_none() && !info.physical_standby_writer_routing {
        bail!("upgrade source writer routing before binding a bootstrap standby");
    }
    // Persist authorization before guest I/O: replay lag or a restart must
    // resume this candidate and this LSN, not require a new bind request.
    reg.physical().begin_standby_binding(&req.database, &req.generation, &req.source_lsn)?;
    let sandbox = crate::vm::connect_physical_candidate(reg.cfg(), &rec.candidate_name, &candidate).await?;
    let mut env = HashMap::new(); env.insert("PGFC_DB".into(), req.database.clone());
    let tenant = reg.dedicated().by_database(&req.database).context("standby lost tenant credential")?;
    env.insert("PGFC_ROLE".into(), tenant.role); env.insert("PGFC_ROLE_PASSWORD".into(), tenant.password);
    env.insert("PGFC_SYSTEM_ID".into(), req.system_identifier.clone()); env.insert("PGFC_SLOT".into(), rec.slot.clone());
    env.insert("PGFC_LSN".into(), req.source_lsn.clone()); env.insert("PGFC_HOST".into(), "127.0.0.1".into()); env.insert("PGFC_PORT".into(), "1".into());
    let verify = crate::vm::physical_exec(reg.cfg(), &sandbox, VERIFY_STANDBY_BIND, env, "verifying standby replay").await?;
    if verify.exit_code != 0 || (if verify.stdout.is_empty() { verify.output.trim() } else { verify.stdout.trim() }) != "t" {
        bail!("standby has not replayed the authorized source LSN or is not read-only");
    }
    // Always repeat the idempotent CAS, including after a crash following the
    // durable rename: it also invalidates any old warm entry.
    reg.commit_physical_binding(&req.database, &previous, &candidate).await?;
    let guard = reg.checkout_physical_exact(&req.database, &candidate).await?;
    if guard.entry().sandbox_id() != candidate { bail!("standby exact-ID checkout changed identity"); }
    rec = reg.physical().advance(&req.database, &req.generation, PhysicalPhase::StandbyBinding, PhysicalPhase::Standby, None)?;
    Ok((&rec).into())
}

const VERIFY_STANDBY_BIND: &str = r#"set -eu
gosu postgres psql -XAt -v ON_ERROR_STOP=1 -d postgres -v identity="$PGFC_SYSTEM_ID" -v slot="$PGFC_SLOT" -v lsn="$PGFC_LSN" <<'SQL'
SELECT pg_is_in_recovery()
AND current_setting('transaction_read_only')='on'
AND (pg_control_system()).system_identifier::text=:'identity'
AND EXISTS(SELECT FROM pg_stat_wal_receiver WHERE status='streaming' AND slot_name=:'slot')
AND COALESCE(pg_last_wal_replay_lsn() >= :'lsn'::pg_lsn,false) AS valid \gset
\if :valid
\else
\quit 1
\endif
SQL
export PGPASSWORD="$PGFC_ROLE_PASSWORD"
psql -X -w -At -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$PGFC_ROLE" -d "$PGFC_DB" -c "SELECT pg_is_in_recovery() AND current_setting('transaction_read_only')='on'"
"#;

pub async fn handoff_source(reg: &Arc<SchemaRegistry>, req: wire::PhysicalHandoffRequest) -> Result<wire::PhysicalRecordJson> {
    let operation = reg.replication_operation(&req.database).await?;
    let source = reg.physical_sources().get(&req.database).context("no physical source preparation")?;
    if source.generation != req.generation || source.source_vm_id != req.source_vm_id
        || reg.bound_vm_id(&req.database).as_deref() != Some(&source.source_vm_id)
        || source.system_identifier != req.system_identifier || source.pg_major != req.pg_major
        || reg.replication_cfg().context("replication disabled")?.node_name != req.source_node { bail!("handoff request does not match durable source ownership"); }
    let peer = reg.peers().get(&source.peer).context("physical source peer is missing")?;
    let client = PeerClient::new(peer, reg.replication_cfg().context("replication disabled")?.peer_timeout)?;
    let info = client.node_info().await?;
    if info.node != source.peer || !info.physical_handoff { bail!("peer does not support physical handoff"); }
    let target = client.physical_status(&req.database).await?;
    let already_granted = source.handoff.as_ref().is_some_and(|g| g.candidate_id == req.candidate_id && g.peer == source.peer);
    if target.generation != req.generation || target.candidate_id.as_deref() != Some(&req.candidate_id)
        || target.source_vm_id != req.source_vm_id || target.source_node != req.source_node
        || target.system_identifier != req.system_identifier || target.pg_major != req.pg_major
        || (!already_granted && !matches!(target.phase.as_str(), "verified" | "standby")) {
        bail!("peer candidate is not the exact verified physical preparation");
    }
    if reg.replication().get(&req.database).and_then(|r| r.fence).is_some_and(|f| f.mode == "selective") {
        bail!("clear the selective fence before authorizing a physical handoff");
    }
    if source.repl.is_none() {
        let logical = reg.replication().get(&req.database).context("physical source lost replication credential")?;
        reg.physical_sources().set_repl(&req.database, &req.generation, wire::Login { role: logical.repl_role, password: logical.repl_password })?;
    }
    // From this fsynced authorization onward, request loss or controller restart
    // must resume this exact candidate. Merely preparing a standby never arms it.
    reg.physical_sources().authorize_handoff(&req.database, &req.generation, &req.candidate_id)?;
    let barrier = fence_source(reg, &source).await?;
    let mut authorized = req.clone(); authorized.barrier_lsn = barrier.clone();
    reg.physical_sources().grant_handoff(&req.database, &req.generation, PhysicalHandoffGrant {
        candidate_id: req.candidate_id.clone(), peer: source.peer.clone(), barrier_lsn: barrier,
    })?;
    drop(operation);
    let answer = client.physical_handoff(&authorized).await?;
    if answer.database != req.database || answer.generation != req.generation
        || answer.candidate_id.as_deref() != Some(&req.candidate_id)
        || answer.source_vm_id != req.source_vm_id || answer.system_identifier != req.system_identifier
        || answer.pg_major != req.pg_major || answer.phase != "activated" {
        bail!("peer did not confirm the exact activated handoff");
    }
    reg.physical_sources().complete_handoff(&req.database, &req.generation, &req.candidate_id)?;
    Ok(answer)
}

/// Resume only explicit source authorization or destination Prepared-and-later
/// phases. No orchestrator database or request connection is needed. Each DB has
/// its own task so an unavailable peer/guest cannot block another handoff.
pub fn spawn_handoff_recovery(reg: Arc<SchemaRegistry>) {
    if reg.replication_cfg().is_none() { return; }
    tokio::spawn(async move {
        let mut workers = HashMap::<String, tokio::task::JoinHandle<()>>::new();
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            let finished: Vec<_> = workers.iter().filter(|(_, task)| task.is_finished()).map(|(db, _)| db.clone()).collect();
            for database in finished {
                if let Err(error) = workers.remove(&database).unwrap().await {
                    warn!(%database, %error, "physical handoff recovery task failed");
                }
            }
            let mut requests = Vec::new();
            for rec in reg.physical().list().into_iter().filter(|r| r.phase == PhysicalPhase::StandbyBinding) {
                if workers.contains_key(&rec.database) { continue; }
                let req = wire::PhysicalStandbyBindRequest { database: rec.database.clone(), generation: rec.generation.clone(),
                    candidate_id: rec.candidate_id.clone().unwrap(), source_node: rec.source_node.clone(), source_vm_id: rec.source_vm_id.clone(),
                    system_identifier: rec.system_identifier.clone(), pg_major: rec.pg_major, source_lsn: rec.standby_lsn.clone().unwrap() };
                let database = rec.database.clone(); let registry = reg.clone();
                workers.insert(database.clone(), tokio::spawn(async move {
                    if let Err(error) = accept_standby_bind(&registry, req).await { warn!(%database, %error, "physical standby bind recovery will retry"); }
                }));
            }
            for rec in reg.physical().list().into_iter().filter(|r| r.handoff_started() && r.phase != PhysicalPhase::Activated) {
                requests.push((false, wire::PhysicalHandoffRequest {
                    database: rec.database, generation: rec.generation, candidate_id: rec.candidate_id.unwrap(),
                    source_vm_id: rec.source_vm_id, system_identifier: rec.system_identifier, pg_major: rec.pg_major,
                    barrier_lsn: rec.handoff_barrier.unwrap(), source_node: rec.source_node,
                }));
            }
            for rec in reg.physical_sources().pending_handoffs() {
                // An old source can remain current in its source journal after
                // a fresh incoming activation. It no longer has work to drive.
                if reg.bound_vm_id(&rec.database).as_deref() != Some(&rec.source_vm_id) { continue; }
                requests.push((true, wire::PhysicalHandoffRequest {
                    database: rec.database, generation: rec.generation, candidate_id: rec.handoff_candidate.unwrap(),
                    source_vm_id: rec.source_vm_id, system_identifier: rec.system_identifier, pg_major: rec.pg_major,
                    barrier_lsn: String::new(), source_node: reg.replication_cfg().unwrap().node_name.clone(),
                }));
            }
            for (source, req) in requests {
                if workers.contains_key(&req.database) { continue; }
                let database = req.database.clone();
                let registry = reg.clone();
                workers.insert(database.clone(), tokio::spawn(async move {
                    let result = if source { handoff_source(&registry, req).await } else { accept_handoff(&registry, req).await };
                    if let Err(error) = result { warn!(%database, %error, "physical handoff recovery will retry"); }
                }));
            }
        }
    });
}

/// The operation lock is held throughout source fencing and grant creation.
async fn fence_source(reg: &Arc<SchemaRegistry>, source: &PhysicalSourceRecord) -> Result<String> {
    let database = source.database.as_str();
    if reg.bound_vm_id(database).as_deref() != Some(&source.source_vm_id) { bail!("stale physical source binding"); }
    if reg.replication().get(database).and_then(|r| r.fence).is_some_and(|f| f.mode == "selective") {
        bail!("clear the selective fence before a physical handoff");
    }
    let (guard, mut maintenance) = if source.fence.is_some() || reg.replication().is_fenced(database) {
        reg.maintenance_client(database).await?
    } else {
        let guard = reg.checkout(database).await?;
        let maintenance = guard.entry().pool.get().await?;
        (guard, maintenance)
    };
    if guard.entry().sandbox_id() != source.source_vm_id { bail!("physical source resolved to another VM"); }
    let identity: bool = maintenance.query_one(
        "SELECT NOT pg_is_in_recovery() AND (pg_control_system()).system_identifier::text=$1 AND current_setting('server_version_num')::int / 10000=$2",
        &[&source.system_identifier, &(source.pg_major as i32)]).await?.get(0);
    if !identity { bail!("physical source runtime identity changed"); }
    if let Some(fence) = &source.fence && fence.phase == "ready" {
        let closed: bool = maintenance.query_one("SELECT NOT datallowconn FROM pg_database WHERE datname=$1", &[&database]).await?.get(0);
        if !closed { bail!("ready physical fence has open database admission"); }
        return fence.barrier_lsn.clone().context("ready physical fence lacks a barrier");
    }
    reg.physical_sources().set_fence(database, &source.generation, "intent", None)?;
    let logical_slot = reg.replication().get(database).map(|r| r.slot).unwrap_or_else(|| source.slot.clone());
    let barrier = super::orchestrate::fence_postgres(&mut maintenance, database, &logical_slot, |phase, _| {
        reg.physical_sources().set_fence(database, &source.generation, phase, None)
    }).await?;
    reg.physical_sources().set_fence(database, &source.generation, "ready", Some(&barrier))?;
    Ok(barrier)
}

pub async fn accept_handoff(reg: &Arc<SchemaRegistry>, req: wire::PhysicalHandoffRequest) -> Result<wire::PhysicalRecordJson> {
    let _operation = reg.replication_operation(&req.database).await?;
    let mut rec = reg.physical().get(&req.database).context("no physical candidate preparation")?;
    let candidate = rec.candidate_id.clone().context("physical candidate has no durable VM identity")?;
    let previous = rec.previous_vm_id.clone().context("physical candidate lost previous VM ownership")?;
    if rec.generation != req.generation || candidate != req.candidate_id || rec.source_node != req.source_node
        || rec.source_vm_id != req.source_vm_id || rec.system_identifier != req.system_identifier || rec.pg_major != req.pg_major {
        bail!("stale or identity-mismatched physical handoff request");
    }
    if rec.repl.is_none() {
        let logical = reg.replication().get(&req.database).context("physical candidate lost replication credential")?;
        if logical.role != Role::Replica || logical.peer != rec.source_node { bail!("legacy candidate credential ancestry mismatch"); }
        reg.physical().set_repl(&req.database, &req.generation, wire::Login { role: logical.repl_role, password: logical.repl_password })?;
        rec = reg.physical().get(&req.database).context("physical candidate disappeared")?;
    }
    if matches!(rec.phase, PhysicalPhase::Verified | PhysicalPhase::Standby) {
        let peer = reg.peers().get(&rec.source_node).context("physical source peer is missing")?;
        let client = PeerClient::new(peer, reg.replication_cfg().context("replication disabled")?.peer_timeout)?;
        let grant = client.physical_grant(&req.database).await?;
        if grant.database != req.database || grant.generation != req.generation || grant.candidate_id != candidate
            || grant.source_vm_id != req.source_vm_id || grant.system_identifier != req.system_identifier
            || grant.pg_major != req.pg_major || grant.barrier_lsn != req.barrier_lsn || grant.peer != reg.replication_cfg().unwrap().node_name {
            bail!("source authorization does not exactly match this candidate and barrier");
        }
        rec = reg.physical().begin_handoff(&req.database, &req.generation, &req.barrier_lsn)?;
    } else if !rec.handoff_started() || rec.handoff_barrier.as_deref() != Some(&req.barrier_lsn) {
        bail!("physical candidate is not ready or its durable barrier differs");
    }
    if rec.phase == PhysicalPhase::Activated {
        if reg.bound_vm_id(&req.database).as_deref() != Some(&candidate) { bail!("activated handoff binding changed"); }
        return Ok((&rec).into());
    }
    let mut env = promotion_env(&rec, &req.barrier_lsn);
    if rec.phase == PhysicalPhase::Prepared {
        run_guest(reg, &rec.candidate_name, &candidate, "prepare-promotion", env.clone()).await?;
        rec = reg.physical().advance(&req.database, &req.generation, PhysicalPhase::Prepared, PhysicalPhase::Promoting, None)?;
    }
    if rec.phase == PhysicalPhase::Promoting {
        env.insert("PG_FC_ADMIN_ROLE".into(), reg.cfg().pg_user.clone());
        env.insert("PG_FC_ADMIN_PASSWORD".into(), reg.cfg().pg_password.clone().context("physical promotion requires configured admin password")?);
        run_guest(reg, &rec.candidate_name, &candidate, "promote", env).await?;
        rec = reg.physical().advance(&req.database, &req.generation, PhysicalPhase::Promoting, PhysicalPhase::Promoted, None)?;
    }
    if rec.phase == PhysicalPhase::Promoted { rec = reg.physical().advance(&req.database, &req.generation, PhysicalPhase::Promoted, PhysicalPhase::Binding, None)?; }
    if rec.phase == PhysicalPhase::Binding {
        reg.commit_physical_binding(&req.database, &previous, &candidate).await?;
        // The old logical VM remains owned by PhysicalRecord; only stale local
        // logical routing metadata is retired.
        if let Some(fence) = reg.replication().get(&req.database).and_then(|r| r.fence) {
            if fence.vm_id != previous { bail!("logical fence does not belong to the retired VM"); }
            // This changes bookkeeping only, after the replacement binding is
            // durable. Never issue ALTER DATABASE against the retired writer.
            reg.replication().clear_fence(&req.database)?;
        }
        reg.replication().remove(&req.database)?;
        let mut open_env = promotion_env(&rec, &req.barrier_lsn);
        open_env.insert("PG_FC_ADMIN_ROLE".into(), reg.cfg().pg_user.clone());
        open_env.insert("PG_FC_ADMIN_PASSWORD".into(), reg.cfg().pg_password.clone().context("physical admission requires configured admin password")?);
        run_guest(reg, &rec.candidate_name, &candidate, "open-admission", open_env).await?;
        rec = reg.physical().advance(&req.database, &req.generation, PhysicalPhase::Binding, PhysicalPhase::Activated, None)?;
    }
    Ok((&rec).into())
}

fn promotion_env(rec: &PhysicalRecord, barrier: &str) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("PG_FC_GENERATION".into(), rec.generation.clone()); env.insert("PG_FC_SYSTEM_IDENTIFIER".into(), rec.system_identifier.clone());
    env.insert("PG_FC_PG_MAJOR".into(), rec.pg_major.to_string()); env.insert("PG_FC_TENANT_DATABASE".into(), rec.database.clone());
    env.insert("PG_FC_BARRIER_LSN".into(), barrier.into());
    env
}

async fn run_guest(reg: &SchemaRegistry, name: &str, id: &str, action: &str, env: HashMap<String, String>) -> Result<()> {
    let sandbox = crate::vm::connect_physical_candidate(reg.cfg(), name, id).await?;
    let command = if action == "open-admission" {
        OPEN_ADMISSION
    } else { if action == "promote" { "/usr/local/bin/pg-fc-physical promote" } else { "/usr/local/bin/pg-fc-physical prepare-promotion" } };
    let out = crate::vm::physical_exec(reg.cfg(), &sandbox, command, env, "physical handoff guest transition").await?;
    if out.exit_code != 0 { bail!("guest physical handoff {action} failed (exit {})", out.exit_code); }
    Ok(())
}

const OPEN_ADMISSION: &str = r#"set -eu
/usr/local/bin/pg-fc-physical prepare-promotion
test "$(/usr/local/bin/pg-fc-physical status | jq -r .phase)" = promoted-but-fenced
export PGPASSWORD="$PG_FC_ADMIN_PASSWORD"
psql -X -w -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$PG_FC_ADMIN_ROLE" -d template1 <<'SQL'
\getenv database PG_FC_TENANT_DATABASE
\getenv identity PG_FC_SYSTEM_IDENTIFIER
SELECT NOT pg_is_in_recovery() AND (pg_control_system()).system_identifier::text = :'identity' AS valid \gset
\if :valid
SET synchronous_commit = on;
SELECT format('ALTER DATABASE %I ALLOW_CONNECTIONS true', :'database') \gexec
\else
\quit 1
\endif
SQL
"#;

async fn seed(reg: Arc<SchemaRegistry>, req: wire::PhysicalReplicaRequest) -> Result<()> {
    let _guard = reg.replication_operation(&req.database).await?;
    let mut rec = reg.physical().get(&req.database).context("physical intent disappeared")?;
    if rec.generation != req.generation || rec.source_vm_id != req.source_vm_id
        || rec.predecessor != req.predecessor || rec.handoff_started()
        || !matches!(rec.phase, PhysicalPhase::Intent | PhysicalPhase::Creating | PhysicalPhase::Candidate | PhysicalPhase::Seeding | PhysicalPhase::Verified) {
        bail!("stale physical seed worker");
    }
    let sandbox = if let Some(id) = &rec.candidate_id { crate::vm::connect_physical_candidate(reg.cfg(), &rec.candidate_name, id).await? } else {
        let allow_create = rec.phase == PhysicalPhase::Intent;
        if allow_create {
            reg.physical().advance(&req.database, &req.generation, PhysicalPhase::Intent, PhysicalPhase::Creating, None)?;
        }
        let own = |id: &str| { reg.physical().advance(&req.database, &req.generation, PhysicalPhase::Creating, PhysicalPhase::Candidate, Some(id.into())).map(|_| ()) };
        let sb = crate::vm::physical_candidate(reg.cfg(), &rec.candidate_name, allow_create, &own).await?;
        rec = reg.physical().get(&req.database).context("physical candidate ownership disappeared")?; sb
    };
    if rec.phase == PhysicalPhase::Candidate { rec = reg.physical().advance(&req.database, &req.generation, PhysicalPhase::Candidate, PhysicalPhase::Seeding, None)?; }
    if rec.phase == PhysicalPhase::Verified { return Ok(()); }
    let mut connection = super::sql::primary_conninfo(req.primary.hostaddr.parse()?, req.primary.port, &req.database, &req.primary.sslmode, &req.generation);
    connection.user = req.repl.role.clone();
    connection.password = req.repl.password.clone();
    let conninfo = connection.to_libpq();
    let plan = serde_json::json!({"generation":req.generation,"system_identifier":req.system_identifier,"pg_major":req.pg_major,"conninfo":conninfo,"slot":req.slot,"settings":req.settings});
    let mut env = HashMap::new(); env.insert("PGFC_PLAN".into(), serde_json::to_string(&plan)?);
    let launched = crate::vm::physical_exec(reg.cfg(), &sandbox, INSTALL_SEED_PLAN, env, "starting physical seed").await?;
    if launched.exit_code != 0 { bail!("physical seed plan installation failed; existing plan was not replaced"); }
    let deadline = tokio::time::Instant::now() + reg.replication_cfg().context("replication disabled")?.setup_deadline;
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let status = crate::vm::physical_exec(reg.cfg(), &sandbox, READ_STATUS, HashMap::new(), "probing physical seed").await?;
        if status.exit_code != 0 { bail!("physical seed status probe failed"); }
        let value: serde_json::Value = serde_json::from_str(if status.stdout.is_empty() { status.output.trim() } else { status.stdout.trim() })?;
        match value["phase"].as_str() { Some("active") => break, Some("failed") => bail!("guest seed failed: {}", value["error"].as_str().unwrap_or("unknown error")), _ if tokio::time::Instant::now() >= deadline => bail!("physical seed still running after setup deadline; retry will resume under guest lock"), _ => {} }
    }
    let mut verify_env = HashMap::new();
    verify_env.insert("PGFC_DB".into(), req.database.clone()); verify_env.insert("PGFC_ROLE".into(), req.tenant.role.clone());
    verify_env.insert("PGFC_SYSTEM_ID".into(), req.system_identifier.clone()); verify_env.insert("PGFC_SLOT".into(), req.slot.clone()); verify_env.insert("PGFC_LSN".into(), req.source_lsn.clone());
    verify_env.insert("PGFC_HOST".into(), req.primary.hostaddr.clone());
    verify_env.insert("PGFC_PORT".into(), req.primary.port.to_string());
    // Guest activation starts Postgres; it does not wait for the WAL receiver
    // to connect and replay the source barrier. Only a true probe verifies it.
    wait_for_runtime(deadline, || async {
        let verify = crate::vm::physical_exec(reg.cfg(), &sandbox, VERIFY_RUNTIME, verify_env.clone(), "verifying physical candidate runtime").await?;
        if verify.exit_code != 0 { bail!("physical candidate runtime probe failed"); }
        let result = if verify.stdout.is_empty() { verify.output.trim() } else { verify.stdout.trim() };
        match result {
            "t" => Ok(true),
            "f" => Ok(false),
            _ => bail!("physical candidate runtime probe returned an invalid result"),
        }
    }).await?;
    reg.physical().advance(&req.database, &req.generation, PhysicalPhase::Seeding, PhysicalPhase::Verified, None)?;
    Ok(())
}

async fn wait_for_runtime<F, Fut>(deadline: tokio::time::Instant, mut probe: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    loop {
        if probe().await? { return Ok(()); }
        if tokio::time::Instant::now() >= deadline {
            bail!("physical candidate runtime identity/streaming verification did not become ready before setup deadline");
        }
        tokio::time::sleep_until(std::cmp::min(deadline, tokio::time::Instant::now() + Duration::from_secs(5))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runtime_wait_requires_a_true_probe_after_startup() {
        let mut probes = 0;
        wait_for_runtime(tokio::time::Instant::now() + Duration::from_secs(10), || {
            probes += 1;
            std::future::ready(Ok(probes == 2))
        }).await.unwrap();
        assert_eq!(probes, 2);
    }

    #[tokio::test]
    async fn runtime_wait_preserves_deadline_and_probe_errors() {
        let mut probes = 0;
        let error = wait_for_runtime(tokio::time::Instant::now(), || {
            probes += 1;
            std::future::ready(Ok(false))
        }).await.unwrap_err();
        assert!(error.to_string().contains("setup deadline"));
        assert_eq!(probes, 1);
        let error = wait_for_runtime(tokio::time::Instant::now() + Duration::from_secs(10), || {
            std::future::ready(Err(anyhow::anyhow!("capture failed")))
        }).await.unwrap_err();
        assert_eq!(error.to_string(), "capture failed");
    }
}

// Command substitution gives jq a pipe instead of the serial TTY, disabling
// ANSI colors even in already-created guests. Preserve a failed probe's exit.
const READ_STATUS: &str = r#"set -e
status=$(/usr/local/bin/pg-fc-physical status)
printf '%s\n' "$status"
"#;

const INSTALL_SEED_PLAN: &str = r#"set -eu
umask 077
test -x /usr/local/bin/pg-fc-physical
mountpoint -q /workspace
install -d -o postgres -g postgres -m 700 /workspace/pg-fc-physical
if test -f /workspace/pg-fc-physical/plan.json; then
    printf '%s' "$PGFC_PLAN" | cmp -s - /workspace/pg-fc-physical/plan.json
else
    # Initial HEYVM_READY precedes postmaster readiness; do not race its first start.
    gosu postgres pg_isready -q -d postgres
    printf '%s' "$PGFC_PLAN" > /workspace/pg-fc-physical/plan.json.tmp
    chown postgres:postgres /workspace/pg-fc-physical/plan.json.tmp
    chmod 600 /workspace/pg-fc-physical/plan.json.tmp
    mv /workspace/pg-fc-physical/plan.json.tmp /workspace/pg-fc-physical/plan.json
fi
touch /etc/pg-fc-physical-persistent-required
sync
setsid nohup /usr/local/bin/pg-fc-physical seed >>/workspace/pg-fc-physical/controller.log 2>&1 </dev/null &
echo launched
"#;

// psql expands variables in input scripts, not the argument to -c.
const VERIFY_RUNTIME: &str = r#"set -eu
gosu postgres psql -AtX postgres -v ON_ERROR_STOP=1 -v db="$PGFC_DB" -v role="$PGFC_ROLE" -v sid="$PGFC_SYSTEM_ID" -v slot="$PGFC_SLOT" -v lsn="$PGFC_LSN" -v host="$PGFC_HOST" -v port="$PGFC_PORT" <<'SQL'
SELECT pg_is_in_recovery()
AND current_setting('transaction_read_only') = 'on'
AND (pg_control_system()).system_identifier::text = :'sid'
AND EXISTS(SELECT FROM pg_database WHERE datname = :'db')
AND EXISTS(SELECT FROM pg_roles WHERE rolname = :'role' AND rolcanlogin)
AND EXISTS(SELECT FROM pg_stat_wal_receiver WHERE status = 'streaming' AND slot_name = :'slot' AND sender_host = :'host' AND sender_port = :'port'::int)
AND pg_last_wal_replay_lsn() >= :'lsn'::pg_lsn;
SQL
"#;
