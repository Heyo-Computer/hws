//! Setting up, promoting and tearing down a pairing.
//!
//! Every flow here obeys one rule: **the durable record is written before the
//! thing it describes exists**, and every step is idempotent. A crash can
//! therefore leave a row describing work that never happened — which the
//! operator can retry or abandon — but never work that happened with no row,
//! which would be an orphaned replication slot pinning WAL on a primary with
//! nothing naming it.
//!
//! The ordering of the two sides matters for the same reason. The primary
//! creates its publication and login, but **not** the slot: `CREATE
//! SUBSCRIPTION ... create_slot = true` on the replica is what creates it. So
//! a setup that dies after the primary's half leaves nothing pinning WAL — the
//! publication and the login are inert on their own.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tracing::{info, warn};

use crate::config::ReplicationConfig;
use crate::registry::SchemaRegistry;

use super::{ReplRecord, Role, State, peer::PeerClient, sql, wire};

const FENCE_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(test)]
#[path = "fence_tests.rs"]
mod fence_tests;

/// Length of a generated replication password. Same 144 bits of entropy as a
/// dedicated database's, and generated the same way.
const PASSWORD_LEN: usize = 24;

/// The replication settings, or a message saying how to turn the feature on.
fn cfg(reg: &Arc<SchemaRegistry>) -> Result<&ReplicationConfig> {
    reg.replication_cfg()
        .context("replication is not enabled on this node (set PG_VM_POOL_REPLICATION=1)")
}

/// Resolve a peer's advertised host to an IPv4 address **on this host**.
///
/// The guest microVMs ship with an empty `/etc/resolv.conf`, so a hostname
/// handed to one simply never resolves — the same constraint that makes the S3
/// path pin IPs with `curl --resolve`. IPv4 only, because the guest tap/NAT is.
pub(crate) async fn resolve_v4(host: &str, port: u16) -> Result<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let addrs = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .with_context(|| format!("resolving {host} timed out"))?
    .with_context(|| format!("resolving {host}"))?;
    addrs
        .filter_map(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        })
        .find(|ip| !ip.is_loopback())
        .with_context(|| {
            format!(
                "{host} has no non-loopback IPv4 address — a guest VM reaches a peer over the \
                 host's IPv4 NAT, and cannot use a hostname or a loopback address"
            )
        })
}

fn generate_password() -> Result<String> {
    // Reuse the dedicated store's generator: same alphabet, same entropy, same
    // guarantee that the result passes the shared password validation.
    let p = crate::dedicated::generate_password()?;
    debug_assert_eq!(p.chars().count(), PASSWORD_LEN);
    Ok(p)
}

// ---------------------------------------------------------------------------
// Primary side
// ---------------------------------------------------------------------------

/// Wire `database` on this node up as the primary of a pairing with `peer`.
///
/// Synchronous through the peer call, so an operator gets a real answer rather
/// than a spinner: everything that can be refused is refused before anything
/// is created, and the only long step (the replica's schema copy) happens in
/// the *peer's* background.
pub async fn enable_primary(
    reg: &Arc<SchemaRegistry>,
    database: &str,
    peer_name: &str,
) -> Result<ReplRecord> {
    let _operation = reg.replication_operation(database).await?;
    if reg.physical().reserves_database(database) || reg.physical_sources().get(database).is_some() {
        bail!("logical replication changes are blocked while physical ownership exists");
    }
    let rcfg = cfg(reg)?;

    // The tenant credential has to be mirrored onto the replica so the same
    // connection string works against either node after a promote — which is
    // what makes failover a DNS change. Without one there is nothing to
    // mirror, so this is a dedicated-database-only feature.
    let tenant = reg.dedicated().by_database(database).with_context(|| {
        format!(
            "{database:?} is not a dedicated database — replication mirrors its role and \
             password onto the replica, so provision it on /dedicated first"
        )
    })?;

    let peer = reg
        .peers()
        .get(peer_name)
        .with_context(|| format!("no peer named {peer_name:?} — add it on /peers first"))?;

    let host = rcfg.advertise_host.as_deref().context(
        "PG_VM_POOL_ADVERTISE_PG_HOST is not set — a replica's guest needs an address to \
         dial this node's pooler, and it cannot be derived from PG_VM_POOL_LISTEN",
    )?;
    // Refuse rather than silently ship a cleartext credential across the
    // network. `sslmode=require` on the replica is only meaningful if this
    // side actually terminates TLS.
    if !reg.tls_enabled() && !rcfg.allow_insecure {
        bail!(
            "this node has no TLS configured (PG_VM_POOL_TLS_CERT/KEY), so the replica's \
             connection would carry the replication password in cleartext; configure TLS \
             or set PG_VM_POOL_REPL_ALLOW_INSECURE=1 if both nodes share a trusted link"
        );
    }
    let hostaddr = resolve_v4(host, rcfg.advertise_port).await?;

    // Handshake before anything is created on either side.
    let client = PeerClient::new(peer.clone(), rcfg.peer_timeout)?;
    let info = client
        .node_info()
        .await
        .with_context(|| format!("reaching peer {peer_name}"))?;
    if info.node == rcfg.node_name {
        bail!(
            "peer {peer_name:?} reports its node name as {:?}, which is this node — a database \
             cannot replicate to itself",
            info.node
        );
    }
    if !info.replication_enabled {
        bail!("peer {peer_name:?} does not have replication enabled (PG_VM_POOL_REPLICATION)");
    }

    // Durable first. From here a crash leaves a visible, retryable row.
    let repl_password = generate_password()?;
    let rec = ReplRecord::new(database, Role::Primary, peer_name, &repl_password);
    let rec = reg
        .replication()
        .create(rec, &|role| reg.dedicated().by_role(role).is_some())?;

    // `Syncing` before touching the VM, not after: it is `State::pins` that
    // keeps the idle reaper and the offload ladder off this VM, and the very
    // next step restarts its Postgres. `Pending` exists only to mark the
    // window between the row landing and this line.
    reg.replication()
        .set_state(database, State::Syncing, "preparing the primary")?;

    match prepare_primary(reg, &rec, &tenant, hostaddr, rcfg, &client).await {
        Ok(()) => {
            info!("replication: {database} is now a primary replicating to {peer_name}");
            Ok(reg.replication().get(database).unwrap_or(rec))
        }
        Err(e) => {
            // Deliberately not rolled back. The peer call may have succeeded
            // with only its *response* lost, and tearing the publication down
            // would then break a live subscriber. The record is left `Failed`
            // for the operator to reconcile, retry (every step is idempotent)
            // or abandon via detach.
            let _ = reg
                .replication()
                .set_state(database, State::Failed, &format!("{e:#}"));
            crate::events::journal_error(
                "replication",
                format!("enabling replication for {database} to {peer_name} failed: {e:#}"),
            );
            Err(e)
        }
    }
}

/// The steps that actually change something, split out so the caller's error
/// path is one place.
async fn prepare_primary(
    reg: &Arc<SchemaRegistry>,
    rec: &ReplRecord,
    tenant: &crate::dedicated::Credential,
    hostaddr: Ipv4Addr,
    rcfg: &ReplicationConfig,
    client: &PeerClient,
) -> Result<()> {
    let database = &rec.database;

    // Marker + Postgres restart, so the cluster is actually at
    // `wal_level = logical`. This also mints the REPLICATION login, because
    // the record now pins and `bring_up_for` picks it up.
    reg.apply_replication_mode(database)
        .await
        .context("switching the primary to wal_level=logical")?;

    let (_guard, db) = reg.db_client(database).await?;

    // Pre-flight, reported rather than enforced: a table with no primary key
    // and no REPLICA IDENTITY replicates INSERTs but errors on UPDATE/DELETE
    // at the publisher. Choosing an identity is the tenant's call, not ours.
    let offenders: Vec<String> = db
        .query(sql::NO_REPLICA_IDENTITY_SQL, &[])
        .await
        .context("checking replica identities")?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect();
    if !offenders.is_empty() {
        let msg = format!(
            "{database}: {} table(s) have no primary key and no REPLICA IDENTITY, so their \
             UPDATEs and DELETEs will error at the publisher: {}",
            offenders.len(),
            offenders.join(", ")
        );
        warn!("{msg}");
        crate::events::journal_error("replication", msg);
    }

    // `CREATE PUBLICATION` has no IF NOT EXISTS.
    let exists = db
        .query_opt(
            "SELECT 1 FROM pg_publication WHERE pubname = $1",
            &[&rec.publication],
        )
        .await
        .context("checking pg_publication")?
        .is_some();
    if !exists {
        db.batch_execute(&sql::create_publication(&rec.publication))
            .await
            .with_context(|| format!("creating publication {}", rec.publication))?;
        info!("{database}: created publication {}", rec.publication);
    }

    let server_version_num: Option<i32> = db
        .query_one("SELECT current_setting('server_version_num')::int4", &[])
        .await
        .ok()
        .map(|r| r.get(0));
    drop(db);

    let req = wire::ProvisionReplica {
        database: database.clone(),
        peer: rcfg.node_name.clone(),
        tenant: wire::Login {
            role: tenant.role.clone(),
            password: tenant.password.clone(),
        },
        repl: wire::Login {
            role: rec.repl_role.clone(),
            password: rec.repl_password.clone(),
        },
        primary: wire::PrimaryEndpoint {
            hostaddr: hostaddr.to_string(),
            port: rcfg.advertise_port,
            sslmode: rcfg.sslmode.clone(),
        },
        publication: rec.publication.clone(),
        subscription: rec.subscription.clone(),
        slot: rec.slot.clone(),
        copy_data: true,
        streaming: true,
        primary_server_version_num: server_version_num,
    };
    client
        .provision_replica(&req)
        .await
        .with_context(|| format!("asking peer {} to build the replica", client.name()))?;
    reg.replication()
        .set_state(database, State::Syncing, "the replica is seeding")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Replica side
// ---------------------------------------------------------------------------

/// Validate a peer's provisioning request and record it. Returns as soon as
/// the record is durable; the VM work runs in the background, exactly like
/// `SchemaRegistry::spawn_provision`.
pub fn accept_replica(
    reg: &Arc<SchemaRegistry>,
    req: wire::ProvisionReplica,
) -> Result<ReplRecord> {
    if reg.physical().reserves_database(&req.database) || reg.physical_sources().get(&req.database).is_some() {
        bail!("logical replication changes are blocked while physical ownership exists");
    }
    let rcfg = cfg(reg)?;
    if req.peer == rcfg.node_name {
        bail!("refusing to replicate from a peer reporting this node's own name");
    }
    // The publisher-newer-than-subscriber check needs this node's guest
    // version, which needs a warm VM — so it happens in `build_replica`, not
    // here. This path stays synchronous and cheap on purpose: it is what the
    // peer waits on.
    let database = crate::dedicated::validate_identifier(&req.database, "database")?;

    // The name must be free, or already be exactly this credential. Refusing
    // here is the whole protection against a replica landing on top of a
    // database that holds someone else's data.
    match reg.dedicated().by_database(&database) {
        Some(existing) if existing.role != req.tenant.role => bail!(
            "database {database:?} already exists on this node with a different role \
             ({:?}) — refusing to overwrite it",
            existing.role
        ),
        Some(_) => {}
        None => {
            reg.create_dedicated(&database, &req.tenant.role, &req.tenant.password)
                .with_context(|| format!("mirroring the tenant credential for {database}"))?;
        }
    }

    // Names come from the request, not re-derived: both sides must agree on
    // the slot and publication even if the two nodes run different builds
    // whose naming rules have drifted.
    let mut rec = ReplRecord::new(&database, Role::Replica, &req.peer, &req.repl.password);
    rec.publication = req.publication.clone();
    rec.subscription = req.subscription.clone();
    rec.slot = req.slot.clone();
    rec.repl_role = req.repl.role.clone();
    let rec = reg.replication().create(rec, &|role| {
        // The replication login lives on the *primary*; only a local
        // collision matters here.
        reg.dedicated().by_role(role).is_some()
    })?;
    reg.replication()
        .set_state(&database, State::Syncing, "seeding from the primary")?;

    let registry = reg.clone();
    let request = req;
    tokio::spawn(async move {
        let db = request.database.clone();
        if let Err(e) = build_replica(&registry, &request).await {
            warn!("replication: building the replica for {db} failed: {e:#}");
            let _ = registry
                .replication()
                .set_state(&db, State::Failed, &format!("{e:#}"));
            crate::events::journal_error(
                "replication",
                format!("building the replica for {db} failed: {e:#}"),
            );
        }
    });
    Ok(rec)
}

/// The replica's background half: bring the VM up in replica mode, seed the
/// schema, subscribe.
///
/// Every step is idempotent so a resumed or retried run converges: the marker
/// write is a no-op when it matches, the schema copy runs in one transaction
/// against an empty database, and the subscription is skipped when it exists.
async fn build_replica(reg: &Arc<SchemaRegistry>, req: &wire::ProvisionReplica) -> Result<()> {
    let _operation = reg.replication_operation(&req.database).await?;
    let rcfg = cfg(reg)?;
    let database = &req.database;

    // Marker + (for a replica) the worker budget its next boot needs.
    reg.apply_replication_mode(database)
        .await
        .context("putting the replica's VM into replica mode")?;

    let guard = reg.checkout(database).await?;
    let entry = guard.entry();

    let hostaddr: Ipv4Addr = req.primary.hostaddr.parse().with_context(|| {
        format!(
            "the primary sent {:?}, which is not an IPv4 address",
            req.primary.hostaddr
        )
    })?;
    let mut conninfo = sql::primary_conninfo(
        hostaddr,
        req.primary.port,
        database,
        &req.primary.sslmode,
        &rcfg.node_name,
    );
    conninfo.user = req.repl.role.clone();
    conninfo.password = req.repl.password.clone();

    let db = crate::vm::db_client(reg.cfg(), &entry.target, database).await?;

    // A publisher newer than its subscriber can emit protocol messages and
    // types the subscriber cannot apply, and the failure surfaces much later
    // as an apply error nobody connects to the version gap. The reverse
    // (subscriber newer) is fine and common. Checked here rather than in
    // `accept_replica` because it needs this node's guest version, which needs
    // a VM; an unreadable version skips the check rather than blocking.
    if let Some(theirs) = req.primary_server_version_num
        && let Ok(row) = db
            .query_one("SELECT current_setting('server_version_num')::int4", &[])
            .await
    {
        let ours: i32 = row.get(0);
        if theirs / 10_000 > ours / 10_000 {
            bail!(
                "the primary runs Postgres {} but this node's image is {} — a subscriber must \
                 not be older than its publisher; rebuild this node's guest image first",
                theirs / 10_000,
                ours / 10_000
            );
        }
    }

    let already = db
        .query_opt(
            "SELECT 1 FROM pg_subscription WHERE subname = $1",
            &[&req.subscription],
        )
        .await
        .context("checking pg_subscription")?
        .is_some();
    if already {
        info!(
            "{database}: subscription {} already exists",
            req.subscription
        );
        reg.replication()
            .set_state(database, State::Syncing, "subscription already present")?;
        return Ok(());
    }

    // Logical replication carries no DDL, so the tables have to exist before
    // the subscription's initial copy can land anything.
    // pg-fc grants this role schema USAGE on the publisher. Preserve that ACL
    // during schema copy without creating a second replication login here.
    let role_exists = db
        .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&req.repl.role])
        .await
        .context("checking the schema-copy ACL role")?
        .is_some();
    if !role_exists {
        db.batch_execute(&sql::create_replica_acl_role(&req.repl.role))
            .await
            .context("creating the schema-copy ACL role")?;
    }
    crate::vm::copy_schema_from_primary(
        reg.cfg(),
        &entry.sandbox,
        database,
        &conninfo,
        rcfg.setup_deadline,
    )
    .await
    .context("copying the primary's schema")?;

    // `create_slot = true` cannot run inside a transaction block, so it goes
    // through `batch_execute` as a lone statement — the same reason
    // `vm::ensure_database` issues `CREATE DATABASE` that way. It also blocks
    // on a round trip to the primary, hence the statement timeout.
    db.batch_execute(&format!(
        "SET statement_timeout = {}",
        rcfg.setup_deadline.as_millis().min(i32::MAX as u128)
    ))
    .await
    .ok();
    db.batch_execute(&sql::create_subscription(
        &req.subscription,
        &conninfo,
        &req.publication,
        &req.slot,
        req.copy_data,
        req.streaming,
    ))
    .await
    .with_context(|| {
        format!(
            "creating subscription {} against {}",
            req.subscription,
            conninfo.redacted()
        )
    })?;
    info!(
        "{database}: subscribed to {} on the primary via slot {}",
        req.publication, req.slot
    );
    reg.replication()
        .set_state(database, State::Syncing, "initial copy in progress")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Promote / detach
// ---------------------------------------------------------------------------

/// Close a primary database to new sessions and establish a fixed, locally
/// flushed WAL barrier. This does not alter the subscription or either
/// replication role and therefore is not promotion/failover.
pub async fn fence(reg: &Arc<SchemaRegistry>, database: &str) -> Result<wire::FenceResponse> {
    let _operation = reg.replication_operation(database).await?;
    fence_locked(reg, database).await
}

/// Caller holds the database operation lock through any subsequent grant.
pub(super) async fn fence_locked(reg: &Arc<SchemaRegistry>, database: &str) -> Result<wire::FenceResponse> {
    let rec = reg.replication().get(database)
        .with_context(|| format!("{database} is not replicating"))?;
    if rec.role != Role::Primary {
        bail!("{database} is a replication replica on this node; only the source may be fenced");
    }
    if let Some(f) = &rec.fence && f.phase == "ready" {
        let bound = reg.schema_record(database).context("ready fence lost its VM binding")?;
        if bound.sandbox_id != f.vm_id || f.barrier_lsn.is_empty() { bail!("ready fence identity/barrier mismatch"); }
        let (_guard, maintenance) = reg.maintenance_client(database).await?;
        let closed: bool = maintenance.query_one(
            "SELECT NOT datallowconn FROM pg_database WHERE datname = $1", &[&database]
        ).await?.get(0);
        if !closed { bail!("ready fence database admission is open; barrier is not valid"); }
        return Ok(wire::FenceResponse { record: (&rec).into(), database: database.into(), vm_id: f.vm_id.clone(), barrier_lsn: f.barrier_lsn.clone() });
    }
    let (guard, mut maintenance) = if rec.fence.is_some() {
        reg.maintenance_client(database).await?
    } else {
        let guard = reg.checkout(database).await?;
        let client = guard.entry().pool.get().await?;
        (guard, client)
    };
    let vm_id = guard.entry().sandbox.sandbox_id().to_string();
    if let Some(f) = &rec.fence && !f.vm_id.is_empty() && f.vm_id != vm_id {
        bail!("fence retry reached a different VM; refusing moving barrier");
    }
    reg.replication().set_fence(database, "intent", "fence requested; database state not yet verified", &vm_id, "")?;

    let result = fence_postgres(&mut maintenance, database, &rec.slot, |phase, message| {
        reg.replication().set_fence(database, phase, message, &vm_id, "")
    }).await;

    match result {
        Ok(barrier) => {
            reg.replication().set_fence(database, "ready", "source fenced and fixed WAL barrier flushed", &vm_id, &barrier)?;
            let rec = reg.replication().get(database).unwrap_or(rec);
            Ok(wire::FenceResponse { record: (&rec).into(), database: database.into(), vm_id, barrier_lsn: barrier })
        }
        Err(e) => {
            let msg = format!("{e:#}");
            let current = reg.replication().get(database).and_then(|r| r.fence);
            let vm = current.as_ref().map(|f| f.vm_id.as_str()).unwrap_or("");
            let barrier = current.as_ref().map(|f| f.barrier_lsn.as_str()).unwrap_or("");
            let _ = reg.replication().set_fence(database, "error", &msg, vm, barrier);
            Err(e)
        }
    }
}

/// Fence tenant writes while retaining the exact database-bound replication
/// login. Unlike [`fence`], this is an explicit coordinated-handoff boundary:
/// it never converts or silently reopens a pre-existing hard fence.
pub async fn fence_selective(
    reg: &Arc<SchemaRegistry>,
    database: &str,
) -> Result<wire::FenceResponse> {
    let _operation = reg.replication_operation(database).await?;
    let rec = reg.replication().get(database).with_context(|| format!("{database} is not replicating"))?;
    if rec.role != Role::Primary { bail!("{database} is not a replication primary"); }
    let tenant = reg.dedicated().by_database(database)
        .context("selective fencing requires a dedicated tenant credential")?;
    if let Some(f) = &rec.fence {
        if f.mode != "selective" { bail!("{database} already has a hard fence; explicitly unfence before requesting selective admission"); }
        if f.phase == "ready" {
            let bound = reg.schema_record(database).context("ready fence lost its VM binding")?;
            if bound.sandbox_id != f.vm_id || f.barrier_lsn.is_empty() { bail!("ready selective fence identity/barrier mismatch"); }
            let (_guard, maintenance) = reg.maintenance_client(database).await?;
            validate_selective_roles(&**maintenance, &tenant.role, &rec.repl_role).await?;
            let state = maintenance.query_one(
                "SELECT d.datallowconn, NOT o.rolcanlogin, has_database_privilege(r.oid, d.oid, 'CONNECT') \
                 FROM pg_database d JOIN pg_roles o ON o.rolname=$2 JOIN pg_roles r ON r.rolname=$3 \
                 WHERE d.datname=$1", &[&database, &tenant.role, &rec.repl_role]
            ).await.context("verifying durable selective admission")?;
            if !state.get::<_, bool>(0) || !state.get::<_, bool>(1) || !state.get::<_, bool>(2) {
                bail!("ready selective fence no longer matches PostgreSQL admission state");
            }
            return Ok(wire::FenceResponse { record: (&rec).into(), database: database.into(), vm_id: f.vm_id.clone(), barrier_lsn: f.barrier_lsn.clone() });
        }
    }
    let (guard, maintenance) = if rec.fence.is_some() {
        reg.maintenance_client(database).await?
    } else {
        let guard = reg.checkout(database).await?;
        let client = guard.entry().pool.get().await?;
        (guard, client)
    };
    let vm_id = guard.entry().sandbox_id();
    if let Some(f) = &rec.fence && !f.vm_id.is_empty() && f.vm_id != vm_id {
        bail!("selective fence retry reached a different VM; refusing moving barrier");
    }
    let mut database_client = crate::vm::db_client(reg.cfg(), &guard.entry().target, database).await?;
    let controller_pid: i32 = database_client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);

    validate_selective_roles(&**maintenance, &tenant.role, &rec.repl_role).await?;
    reg.replication().set_fence_payload(database, "selective", "intent",
        "selective fence requested; tenant admission not yet closed", &vm_id, "", vec![])?;
    let result = fence_postgres_selective(
        &**maintenance, &mut database_client, database, &tenant.role, &rec.repl_role,
        &rec.slot, controller_pid,
        |phase, message| reg.replication().set_fence(database, phase, message, &vm_id, ""),
    ).await;
    match result {
        Ok((barrier, sequences)) => {
            reg.replication().set_fence_payload(database, "selective", "ready",
                "tenant drained; source sequences and fixed WAL barrier captured", &vm_id,
                &barrier, sequences)?;
            let rec = reg.replication().get(database).unwrap_or(rec);
            Ok(wire::FenceResponse { record: (&rec).into(), database: database.into(), vm_id, barrier_lsn: barrier })
        }
        Err(e) => {
            let msg = format!("{e:#}");
            let _ = reg.replication().set_fence(database, "error", &msg, &vm_id, "");
            Err(e)
        }
    }
}

async fn validate_selective_roles<M: tokio_postgres::GenericClient + Sync>(
    maintenance: &M,
    owner: &str,
    repl_role: &str,
) -> Result<()> {
    let escapes: Vec<String> = maintenance.query(sql::TENANT_ROLE_ESCAPE_SQL, &[&owner]).await?
        .iter().map(|r| r.get(0)).collect();
    if !escapes.is_empty() {
        bail!("tenant owner {owner} has alternative LOGIN roles with inherited/SET ROLE access: {}; selective fencing is unsupported", escapes.join(", "));
    }
    let unsupported: Vec<String> = maintenance.query(sql::UNSUPPORTED_FENCE_ROLES_SQL, &[&owner, &repl_role]).await?
        .iter().map(|r| r.get(0)).collect();
    if !unsupported.is_empty() {
        bail!("selective fencing requires an isolated unprivileged tenant; unsupported roles: {}", unsupported.join(", "));
    }
    Ok(())
}

async fn fence_postgres_selective<M: tokio_postgres::GenericClient + Sync>(
    maintenance: &M,
    database_client: &mut tokio_postgres::Client,
    database: &str,
    owner: &str,
    repl_role: &str,
    slot: &str,
    controller_pid: i32,
    progress: impl Fn(&str, &str) -> Result<()>,
) -> Result<(String, Vec<super::SequenceSnapshot>)> {
    validate_selective_roles(maintenance, owner, repl_role).await?;
    progress("closing_admission", "disabling tenant owner and CONNECT inheritance")?;
    maintenance.batch_execute("SET synchronous_commit = on").await?;
    maintenance.batch_execute(&sql::selective_admission(database, owner, repl_role)).await?;
    progress("draining_startups", "waiting for pre-existing startup locks")?;
    let deadline = tokio::time::Instant::now() + FENCE_DRAIN_TIMEOUT;
    loop {
        let holders = maintenance.query(sql::DATABASE_OBJECT_LOCKS_SQL, &[&database]).await?;
        if holders.iter().all(|r| r.get::<_, i32>(0) == controller_pid) { break; }
        if tokio::time::Instant::now() >= deadline { bail!("startup lock holders did not drain; selective fence retained"); }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let prepared: i64 = maintenance.query_one(sql::PREPARED_XACTS_SQL, &[&database]).await?.get(0);
    if prepared != 0 { bail!("database has {prepared} prepared transaction(s); selective fence retained"); }
    let rows = maintenance.query(sql::FENCE_ACTIVITY_SQL, &[&database, &slot]).await?;
    for row in &rows {
        let pid: i32 = row.get("pid");
        let backend: &str = row.get("backend_type");
        let expected: bool = row.get("is_expected_sender");
        if pid != controller_pid && backend != "client backend" && !expected {
            bail!("unexpected database worker pid {pid} ({backend}); selective fence retained");
        }
    }
    maintenance.query("SELECT pg_terminate_backend(a.pid) FROM pg_stat_activity a LEFT JOIN pg_replication_slots s ON s.slot_name=$2 WHERE (a.datname=$1 OR a.usename=$4) AND a.pid <> $3 AND a.backend_type='client backend' AND a.pid <> COALESCE(s.active_pid,-1)", &[&database, &slot, &controller_pid, &owner]).await?;
    let deadline = tokio::time::Instant::now() + FENCE_DRAIN_TIMEOUT;
    loop {
        let rows = maintenance.query(sql::FENCE_ACTIVITY_SQL, &[&database, &slot]).await?;
        let remaining = rows.iter().filter(|r| r.get::<_, i32>("pid") != controller_pid && !r.get::<_, bool>("is_expected_sender")).count();
        let owner_sessions: i64 = maintenance.query_one("SELECT count(*) FROM pg_stat_activity WHERE usename=$1", &[&owner]).await?.get(0);
        if remaining == 0 && owner_sessions == 0 { break; }
        if tokio::time::Instant::now() >= deadline { bail!("{remaining} tenant session(s) did not exit; selective fence retained"); }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let prepared: i64 = maintenance.query_one(sql::PREPARED_XACTS_SQL, &[&database]).await?.get(0);
    if prepared != 0 { bail!("database has {prepared} prepared transaction(s) after drain; selective fence retained"); }

    let mut sequences = Vec::new();
    for row in database_client.query(sql::SEQUENCES_SQL, &[]).await? {
        let schema: String = row.get(0);
        let name: String = row.get(1);
        let value = database_client.query_one(&sql::sequence_value(&schema, &name), &[]).await?;
        sequences.push(super::SequenceSnapshot {
            schema, name, data_type: row.get(2), start_value: row.get(3), min_value: row.get(4),
            max_value: row.get(5), increment_by: row.get(6), cycle: row.get(7), cache_size: row.get(8),
            last_value: value.get(0), is_called: value.get(1),
        });
    }
    progress("barrier", "tenant drained; authoritative sequences captured")?;
    database_client.batch_execute("SET synchronous_commit = on").await?;
    let barrier: String = database_client.query_one("SELECT pg_current_wal_insert_lsn()::text", &[]).await?.get(0);
    maintenance.batch_execute("CHECKPOINT").await?;
    let flushed: bool = maintenance.query_one("SELECT pg_current_wal_flush_lsn() >= $1::text::pg_lsn", &[&barrier]).await?.get(0);
    if !flushed { bail!("WAL flush did not reach fixed barrier {barrier}; selective fence retained"); }
    Ok((barrier, sequences))
}

/// PostgreSQL's admission/drain/barrier protocol, separate from VM resolution
/// so the production protocol can be exercised against a disposable server.
pub(super) async fn fence_postgres(
    maintenance: &mut tokio_postgres::Client,
    database: &str,
    slot: &str,
    progress: impl Fn(&str, &str) -> Result<()>,
) -> Result<String> {
        progress("closing_admission", "durably closing admission")?;

        // synchronous_commit=on overrides the guest's source tuning. ALTER
        // DATABASE takes no target database-object lock; the explicit holder
        // wait below supplies the startup admission barrier.
        let tx = maintenance.transaction().await.context("starting durable fence transaction")?;
        tx.batch_execute("SET LOCAL synchronous_commit = on").await?;
        tx.batch_execute(&sql::set_allow_connections(database, false)).await?;
        tx.commit().await.context("durably committing ALLOW_CONNECTIONS false")?;
        progress("draining_startups", "waiting for pre-existing startup locks")?;
        let deadline = tokio::time::Instant::now() + FENCE_DRAIN_TIMEOUT;
        loop {
            let holders = maintenance.query(sql::DATABASE_OBJECT_LOCKS_SQL, &[&database]).await?;
            if holders.is_empty() { break; }
            if tokio::time::Instant::now() >= deadline { bail!("{} startup lock holder(s) did not finish within 30s; fence retained", holders.len()); }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        progress("draining", "startup admission quiesced; draining fresh activity snapshot")?;

        let prepared: i64 = maintenance.query_one(sql::PREPARED_XACTS_SQL, &[&database]).await?.get(0);
        if prepared != 0 {
            bail!("database has {prepared} prepared transaction(s); fence retained; resolve them explicitly before retrying");
        }

        // Reject background workers rather than killing something whose write
        // semantics are unknown. Client backends are application sessions and
        // are terminated; the exact slot's active logical walsender survives.
        let rows = maintenance.query(sql::FENCE_ACTIVITY_SQL, &[&database, &slot]).await?;
        for row in &rows {
            let backend: &str = row.get("backend_type");
            let expected: bool = row.get("is_expected_sender");
            if backend != "client backend" && !expected {
                bail!("unexpected database worker pid {} ({backend}); fence retained", row.get::<_, i32>("pid"));
            }
        }
        maintenance.query(sql::TERMINATE_APP_SESSIONS_SQL, &[&database, &slot]).await?;
        let deadline = tokio::time::Instant::now() + FENCE_DRAIN_TIMEOUT;
        loop {
            let rows = maintenance.query(sql::FENCE_ACTIVITY_SQL, &[&database, &slot]).await?;
            let remaining = rows.iter().filter(|r| !r.get::<_, bool>("is_expected_sender")).count();
            if remaining == 0 { break; }
            if tokio::time::Instant::now() >= deadline {
                bail!("{remaining} application session(s) did not exit within 30s; fence retained");
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // A transaction may have prepared after the first check but before
        // termination. Prepared transactions survive the originating backend.
        let prepared: i64 = maintenance.query_one(sql::PREPARED_XACTS_SQL, &[&database]).await?.get(0);
        if prepared != 0 { bail!("database has {prepared} prepared transaction(s) after drain; fence retained"); }
        progress("barrier", "sessions drained; capturing fixed WAL insert barrier")?;
        maintenance.batch_execute("SET synchronous_commit = on").await?;
        let barrier: String = maintenance.query_one("SELECT pg_current_wal_insert_lsn()::text", &[]).await?.get(0);
        maintenance.batch_execute("CHECKPOINT").await.context("checkpointing fixed WAL barrier")?;
        let flushed: bool = maintenance.query_one(
            "SELECT pg_current_wal_flush_lsn() >= $1::text::pg_lsn", &[&barrier]
        ).await?.get(0);
        if !flushed { bail!("WAL flush did not reach fixed barrier {barrier}; fence retained"); }
        Ok(barrier)
}

pub async fn unfence(reg: &Arc<SchemaRegistry>, database: &str) -> Result<()> {
    let _operation = reg.replication_operation(database).await?;
    if reg.physical_sources().get(database).is_some_and(|r| r.handoff_candidate.is_some()
        && reg.bound_vm_id(database).as_deref() == Some(&r.source_vm_id)) {
        bail!("physical handoff is authorized and will resume; source cannot be unfenced");
    }
    if reg.bound_vm_id(database).as_deref().is_some_and(|id| reg.physical_sources().has_grant_for_source_vm(database, id)) {
        bail!("physical handoff was irrevocably authorized; source admission can never be reopened");
    }
    if let Some(source) = reg.physical_sources().get(database).filter(|r| r.fence.is_some()) {
        if reg.bound_vm_id(database).as_deref() != Some(&source.source_vm_id) {
            bail!("physical fence does not describe the bound source");
        }
        let (_guard, maintenance) = reg.maintenance_client(database).await?;
        reg.physical_sources().set_fence(database, &source.generation, "unfencing", None)?;
        maintenance.batch_execute("SET synchronous_commit = on").await?;
        maintenance.batch_execute(&sql::set_allow_connections(database, true)).await
            .context("durably restoring physical source admission")?;
        if reg.replication().is_fenced(database) { reg.replication().clear_fence(database)?; }
        reg.physical_sources().clear_fence(database, &source.generation)?;
        return Ok(());
    }
    let rec = reg.replication().get(database).with_context(|| format!("{database} is not replicating"))?;
    if rec.fence.is_none() { bail!("{database} is not fenced"); }
    let (_guard, maintenance) = reg.maintenance_client(database).await?;
    let f = rec.fence.as_ref().unwrap();
    // Invalidate a ready barrier durably before reopening admission. A crash
    // or failed clear must never leave an open database marked ready-fenced.
    reg.replication().set_fence(database, "unfencing", "operator requested admission reopen; prior barrier invalid", &f.vm_id, "")?;
    maintenance.batch_execute("SET synchronous_commit = on").await?;
    if f.mode == "selective" {
        let tenant = reg.dedicated().by_database(database).context("selective fence lost tenant credential")?;
        maintenance.batch_execute(&sql::restore_selective_admission(database, &tenant.role)).await
            .context("restoring selective tenant admission")?;
    } else {
        maintenance.batch_execute(&sql::set_allow_connections(database, true)).await
            .context("durably restoring database admission")?;
    }
    reg.replication().clear_fence(database)?;
    Ok(())
}

/// Cut a replica loose: stop applying, drop the subscription, and re-seed the
/// sequences logical replication never carried.
pub async fn promote(reg: &Arc<SchemaRegistry>, database: &str) -> Result<wire::PromoteResponse> {
    let _operation = reg.replication_operation(database).await?;
    if reg.physical().reserves_database(database) || reg.physical_sources().get(database).is_some() {
        bail!("physical migration owns this database; logical promotion is disabled");
    }
    let rcfg = cfg(reg)?;
    let rec = reg
        .replication()
        .get(database)
        .with_context(|| format!("{database} is not replicating"))?;
    if rec.role != Role::Replica {
        bail!("{database} is a replication primary on this node, not a replica");
    }
    if rec.fence.is_some() {
        bail!("{database} is fenced; explicitly unfence it before promotion");
    }

    let (_guard, db) = reg.db_client(database).await?;
    for stmt in sql::promote_statements(&rec.subscription) {
        db.batch_execute(&stmt)
            .await
            .with_context(|| format!("promoting {database}: {stmt}"))?;
    }

    // Logical replication does not replicate sequence values, so every
    // serial/identity column here is still at its initial value and the first
    // insert would collide with a replicated row.
    let mut sequences_fixed = 0i64;
    if rcfg.fix_sequences {
        sequences_fixed = db
            .query_one(sql::COUNT_SEQUENCES_SQL, &[])
            .await
            .map(|r| r.get::<_, i64>(0))
            .unwrap_or(0);
        db.batch_execute(sql::FIX_SEQUENCES_SQL)
            .await
            .context("re-seeding sequences after the promote")?;
        info!("{database}: re-seeded {sequences_fixed} sequence(s) after promote");
    }
    drop(db);

    reg.replication()
        .set_state(database, State::Promoted, "promoted by an operator")?;
    // The record no longer pins, so this clears the marker and returns the VM
    // to the cheap WAL profile on its next start.
    if let Err(e) = reg.apply_replication_mode(database).await {
        warn!("{database}: promoted, but clearing the replication marker failed: {e:#}");
    }
    let rec = reg.replication().get(database).unwrap_or(rec);
    Ok(wire::PromoteResponse {
        record: (&rec).into(),
        sequences_fixed,
    })
}

/// Tear this node's half of a pairing down.
///
/// On a primary that means dropping the publication and the slot — the slot
/// especially, because an orphaned one pins WAL until
/// `max_slot_wal_keep_size` invalidates it. On a replica it is the same work
/// as a promote minus the sequence re-seed.
pub async fn detach(reg: &Arc<SchemaRegistry>, database: &str) -> Result<wire::DetachResponse> {
    let _operation = reg.replication_operation(database).await?;
    if reg.physical().reserves_database(database) || reg.physical_sources().get(database).is_some() {
        bail!("physical migration owns this database; logical detach is disabled");
    }
    let rcfg = cfg(reg)?;
    let rec = reg
        .replication()
        .get(database)
        .with_context(|| format!("{database} is not replicating"))?;
    if rec.fence.is_some() {
        bail!("{database} is fenced; explicitly unfence it before detach");
    }

    // Best-effort: tell the peer first, so its subscriber lets go of the slot
    // and the drop below finds it inactive. A peer that cannot be reached is
    // not a reason to leave this side pinned.
    if let Some(peer) = reg.peers().get(&rec.peer)
        && let Ok(client) = PeerClient::new(peer, rcfg.peer_timeout)
        && let Err(e) = client.teardown(database).await
    {
        warn!(
            "{database}: peer {} did not confirm teardown ({e:#}); continuing with this side",
            rec.peer
        );
    }

    let (_guard, db) = reg.db_client(database).await?;
    let mut slot_dropped = false;
    let mut publication_dropped = false;
    if rec.role == Role::Primary {
        // Order matters: drop the slot before the publication, so a subscriber
        // that is still attached fails to stream rather than silently
        // reconnecting to a publication that no longer publishes anything.
        match db
            .execute(&sql::drop_slot_if_inactive(&rec.slot), &[])
            .await
        {
            Ok(n) => slot_dropped = n > 0,
            Err(e) => warn!("{database}: dropping slot {} failed: {e}", rec.slot),
        }
        db.batch_execute(&sql::drop_publication(&rec.publication))
            .await
            .with_context(|| format!("dropping publication {}", rec.publication))?;
        publication_dropped = true;
        for stmt in sql::drop_repl_role(&rec.repl_role) {
            if let Err(e) = db.batch_execute(&stmt).await {
                warn!("{database}: cleaning up {}: {e}", rec.repl_role);
            }
        }
    } else {
        for stmt in sql::promote_statements(&rec.subscription) {
            if let Err(e) = db.batch_execute(&stmt).await {
                warn!("{database}: dropping subscription: {e}");
            }
        }
    }
    drop(db);

    reg.replication()
        .set_state(database, State::Detached, "detached by an operator")?;
    if let Err(e) = reg.apply_replication_mode(database).await {
        warn!("{database}: detached, but clearing the replication marker failed: {e:#}");
    }
    if !slot_dropped && rec.role == Role::Primary {
        warn!(
            "{database}: slot {} was not dropped (still active, or already gone) — if a \
             subscriber is still attached it will keep pinning WAL",
            rec.slot
        );
    }
    let rec = reg.replication().get(database).unwrap_or(rec);
    Ok(wire::DetachResponse {
        record: (&rec).into(),
        slot_dropped,
        publication_dropped,
    })
}

/// Pick up tables added to the publication since the subscription was created.
/// Logical replication publishes new tables automatically but the subscriber
/// only notices on a refresh — and the table still has to exist here.
pub async fn refresh(reg: &Arc<SchemaRegistry>, database: &str) -> Result<()> {
    let _operation = reg.replication_operation(database).await?;
    let rec = reg
        .replication()
        .get(database)
        .with_context(|| format!("{database} is not replicating"))?;
    if rec.role != Role::Replica {
        bail!("only a replica has a subscription to refresh");
    }
    let (_guard, db) = reg.db_client(database).await?;
    db.batch_execute(&sql::refresh_subscription(&rec.subscription))
        .await
        .with_context(|| format!("refreshing subscription {}", rec.subscription))
}

/// Read whichever side of the link this node can see.
pub async fn local_status(
    reg: &Arc<SchemaRegistry>,
    rec: &ReplRecord,
) -> Result<(Option<wire::PrimaryStatus>, Option<wire::ReplicaStatus>)> {
    let (_guard, db) = if rec.fence.is_some() && rec.role == Role::Primary {
        // Slot feedback is cluster-wide; tenant admission is deliberately shut.
        reg.maintenance_client(&rec.database).await?
    } else {
        reg.db_client(&rec.database).await?
    };
    match rec.role {
        Role::Primary => {
            let row = db
                .query_opt(sql::PRIMARY_STATUS_SQL, &[&rec.slot])
                .await
                .context("reading pg_replication_slots")?;
            Ok((
                row.map(|r| wire::PrimaryStatus {
                    slot_active: r.get("active"),
                    wal_status: r.get("wal_status"),
                    behind_bytes: r.get("behind_bytes"),
                    current_lsn: r.get("current_lsn"),
                    confirmed_flush_lsn: r.get("confirmed_flush_lsn"),
                    sender_state: r.get("sender_state"),
                    write_lag_s: r.get("write_lag_s"),
                    flush_lag_s: r.get("flush_lag_s"),
                    replay_lag_s: r.get("replay_lag_s"),
                }),
                None,
            ))
        }
        Role::Replica => {
            let row = db
                .query_opt(sql::REPLICA_STATUS_SQL, &[&rec.subscription])
                .await
                .context("reading pg_stat_subscription")?;
            Ok((
                None,
                row.map(|r| wire::ReplicaStatus {
                    enabled: r.get("subenabled"),
                    worker_running: r.get::<_, Option<bool>>("worker_running").unwrap_or(false),
                    received_lsn: r.get("received_lsn"),
                    latest_end_lsn: r.get("latest_end_lsn"),
                    last_msg_age_s: r.get("last_msg_age_s"),
                    tables_total: r.get::<_, Option<i64>>("tables_total").unwrap_or(0),
                    tables_ready: r.get::<_, Option<i64>>("tables_ready").unwrap_or(0),
                }),
            ))
        }
    }
}
