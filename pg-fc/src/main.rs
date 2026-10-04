//! pg-vm-pool — a per-schema Postgres pooler over Heyo microVMs.
//!
//! Listens on one Postgres endpoint. The database name in each client's startup
//! packet selects a schema; the pooler lazily boots (or restarts/reuses) the
//! `pg-<schema>` Firecracker VM, tunnels to its Postgres, and splices the
//! connection through. One isolated VM per schema, behind a single URL.

mod auth;
mod cancel;
mod config;
mod dashboard;
mod database_maintenance;
mod dedicated;
mod dumpsrv;
mod events;
mod imgarchive;
mod inventory;
/// Cold-start load harness. Test-only: it aims the whole pooler at an
/// in-process daemon stub, which is not something a running pooler should be
/// able to do by accident.
#[cfg(test)]
mod loadtest;
mod orphans;
mod peers;
mod pending;
mod proxy;
mod reclaim;
mod registry;
mod replication;
mod runtime_config;
mod s3;
mod spares;
mod startup;
mod store;
mod tls;
mod vm;
mod writer_routing;

use std::sync::Arc;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use config::Config;
use registry::SchemaRegistry;
use tls::TlsReloader;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,pg_vm_pool=info")),
        )
        .init();

    let cfg = Config::from_env()?;
    // Fail startup, loudly and with the fix in the message, if any configured
    // offload tier's output directory can't be created or written — an
    // unwritable dir otherwise degrades every offload into its most expensive
    // fallback path at job time (see the method's docs for the full story).
    cfg.preflight_offload_dirs()?;
    let listen_addr = cfg.listen_addr;
    // File-backed event metrics (daily partitions) for the monitoring charts;
    // memory-only if the dir can't be created.
    events::init(cfg.metrics_dir.clone());
    // Client-facing TLS: certbot (or any external renewer) owns the PEM files;
    // the reloader picks up rotations without a restart. Built before the
    // registry so a bad cert fails startup fast.
    let tls = match (cfg.tls_cert.clone(), cfg.tls_key.clone()) {
        (Some(cert), Some(key)) => {
            info!(
                "TLS enabled (cert={}, hot-reload on change)",
                cert.display()
            );
            Some(Arc::new(TlsReloader::new(cert, key)?))
        }
        _ => {
            info!("TLS disabled (set PG_VM_POOL_TLS_CERT/KEY to enable)");
            None
        }
    };
    if cfg.pg_password.is_some() && tls.is_none() && !listen_addr.ip().is_loopback() {
        warn!(
            "PG_VM_POOL_PASSWORD is set but TLS is not and PG_VM_POOL_LISTEN \
             ({listen_addr}) is not loopback — client passwords will cross \
             the network in cleartext; set PG_VM_POOL_TLS_CERT/KEY"
        );
    }
    // Pull the dashboard settings out before `cfg` is moved into the registry.
    let dashboard_cfg = cfg.dashboard.clone();
    // Pending-bring-up ledger (in-flight creates awaiting their registry
    // binding) lives beside the registry file; load any crash leftovers before
    // the first connection can race them.
    pending::init(
        cfg.state_file
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("pending-bringups.tsv"),
    );
    let registry = Arc::new(SchemaRegistry::new(cfg)?);
    registry.spawn_reaper();
    // Stops running VMs nothing tracks (left over from a pooler restart, a
    // failed idle-stop, or a daemon-side boot) so the ladder can reclaim them.
    registry.spawn_untracked_reaper();
    // Offload pacer: trickles cold schemas down the storage ladder (compact →
    // freeze → S3), one schema at a time and only while no client is waiting
    // on a bring-up, instead of waking on a timer and running a long batch.
    // No-op unless at least one of COMPACT/FREEZE/ARCHIVE_AFTER_SECS is set.
    registry.spawn_offloader();
    // Emergency disk-pressure eviction: when the VM-disk filesystem crosses the
    // high-water mark, archive oldest-idle schemas (TTL overridden) until it
    // recovers. No-op unless PG_VM_POOL_PRESSURE_PATH is configured.
    registry.spawn_pressure_reaper();
    // Urgent device growth: the only path that grows a *warm* VM's data
    // device. The idle-stop grow can't help a schema whose write load never
    // pauses, and once the guest's filesystem spans its device that schema
    // wedges on ENOSPC. No-op unless PG_VM_POOL_DISK_GROW_PCT is set (and
    // PG_VM_POOL_DISK_GROW_URGENT_PCT is not 0).
    registry.spawn_disk_grower();
    // Warm-spare pool: pre-booted empty VMs that cold bring-ups (notably S3
    // restores) claim instead of paying create + boot + initdb. No-op unless
    // PG_VM_POOL_WARM_SPARES > 0.
    registry.spawn_spare_replenisher();
    // Persists debounced activity bumps to the registry file (mapping changes
    // flush immediately inside the store; this loop only owes idle clocks).
    registry.spawn_store_flusher();
    // Carries the frozen tier's dump bytes both ways (and the S3 tier's
    // streamed dumps). No-op unless one of those tiers is configured.
    registry.spawn_dump_server();
    // Offline-trim stopped VMs' data disks so freed guest blocks return to the
    // host (Firecracker has no discard passthrough). No-op unless
    // PG_VM_POOL_RECLAIM_CMD is configured.
    registry.spawn_reclaimer();
    // Orphan-disk sweep: delete sb-<id>/ directories heyvmd has forgotten (a
    // kill it acked but didn't act on), reclaiming the stranded disk. No-op
    // unless PG_VM_POOL_ORPHAN_SWEEP_SECS (and PG_VM_POOL_RUN_DIR) are set.
    registry.spawn_orphan_reaper();
    // Bring up every VM a replication pairing depends on. Must run before the
    // untracked reaper's first pass, which classifies a running VM with no
    // warm entry as untracked. No-op when nothing is replicating.
    registry.spawn_replication_pinner();
    // Samples each pairing's lag and slot health for the dashboard, and warns
    // when an inactive slot starts pinning WAL. No-op when nothing is
    // replicating.
    registry.spawn_replication_monitor();
    // Continue explicitly authorized physical handoffs after request loss or
    // process restart, including when orchestrator's own database is moving.
    replication::physical::spawn_handoff_recovery(registry.clone());
    // Delete VMs whose bring-up handed out an id but never reached a registry
    // binding — the "stuck in provisioning, bound to nothing" leak no other
    // sweep covers. Always on; idle when the pending ledger is empty.
    registry.spawn_pending_janitor();
    // A pooler that died mid-image-restore left up to a full raw image in the
    // run dir's dot-named scratch (invisible to the sb-* sweep). Clean that
    // up-front — this startup is the first moment we know no restore is
    // running — and let the sweep keep it clean from here.
    if let Some(run_dir) = registry.run_dir() {
        check_run_dir(&run_dir);
        crate::imgarchive::gc_restore_scratch(&run_dir);
    }

    // Optional admin dashboard: enabled only when PG_VM_POOL_DASHBOARD_LISTEN is
    // set. Runs in its own task sharing the registry, so it never blocks the PG
    // accept loop below.
    if let Some(dash) = dashboard_cfg {
        if !dash.listen.ip().is_loopback() && dash.basic_auth.is_none() {
            warn!(
                "dashboard bound to non-loopback {} without basic auth — anyone who \
                 can reach it can stop/resize every VM; set PG_VM_POOL_DASHBOARD_USER/\
                 PASSWORD or bind a loopback address",
                dash.listen
            );
        }
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) = dashboard::serve(dash, registry).await {
                warn!("dashboard exited: {e:#}");
            }
        });
    }

    raise_open_files_limit();
    let listener = TcpListener::bind(listen_addr).await?;
    info!("pg-vm-pool listening on {listen_addr}");

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Never fatal. Returning here ended the process, and a restart
                // drops every connected client with it — the 2026-09-15 mia3
                // crash was exactly this, `accept` failing with EMFILE once
                // parked clients had used up the open-files limit. EMFILE and
                // ENFILE clear as connections close; the rest (ECONNABORTED
                // and the like) concern a single connection.
                warn!("accepting a client connection failed: {e}; retrying");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        // Disable Nagle on the client->pooler leg (mirrors the pooler->VM leg in
        // proxy::splice). The Postgres wire protocol is request/response, so
        // Nagle + delayed-ACK adds per-round-trip latency on the many small
        // statements a chatty client sends; a direct libpq connection sets
        // TCP_NODELAY itself, so the pooler must too to match it. Best-effort:
        // set on the raw socket before TLS wrapping (the option rides the fd).
        if let Err(e) = sock.set_nodelay(true) {
            warn!("could not set TCP_NODELAY on client connection {peer}: {e}");
        }
        // Arm keepalive on the same raw socket, for the same reason it has to
        // happen here: the option rides the fd, so it survives the TLS wrap.
        // Without it a client that vanishes without a FIN parks this task —
        // and the connection slot it is about to take — forever. See
        // `proxy::arm_keepalive`.
        proxy::arm_keepalive(&sock, "client->pooler");
        let registry = registry.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(sock, registry, tls).await {
                warn!("connection {peer} closed: {e:#}");
            }
        });
    }
}

async fn handle_conn(
    client: TcpStream,
    registry: Arc<SchemaRegistry>,
    tls: Option<Arc<TlsReloader>>,
) -> Result<()> {
    let (mut client, info) = match startup::read_startup(client, tls.as_deref()).await? {
        startup::Startup::Session(client, info) => (client, info),
        // A cancel for another connection's query. Routed by its key alone,
        // ahead of auth (the secret *is* the credential, as in Postgres) and
        // of any registry checkout, so it never takes a client slot or wakes
        // a VM. The secret is never logged.
        startup::Startup::Cancel(key) => {
            if !cancel::forward(cancel::global(), &key).await? {
                debug!("dropped a cancel for unknown backend pid {}", key.pid());
            }
            return Ok(());
        }
    };
    // Which password this client must prove, decided from its *role* alone: a
    // replication or dedicated login is challenged with its own, everyone else
    // with the shared `PG_VM_POOL_PASSWORD`. Keeping the requested database
    // out of this step means the handshake looks the same either way, so the
    // challenge can't be used to enumerate which database names are dedicated.
    if let Some(password) = registry.challenge_password_for(&info.user) {
        auth::require_password(&mut client, &password).await?;
    }
    // Authenticated — now, may this client route where it asked? A dedicated
    // credential may open only its own database (so it can never provision a
    // second VM), a shared-password client may not open a dedicated one, and a
    // replication login may open only the database it replicates.
    let schema =
        match registry.authorize_route(&info.user, &info.database, info.physical_replication) {
        Ok(schema) => schema,
        Err(reason) => {
                auth::send_fatal(&mut client, auth::SQLSTATE_INSUFFICIENT_PRIVILEGE, &reason)
                    .await?;
            anyhow::bail!("refused {}@{}: {reason}", info.user, info.database);
        }
    };
    // The bytes replayed upstream: the client's own StartupMessage plus the
    // pooler's session defaults. Built before writer routing so a session
    // forwarded to a peer carries the same defaults as a local one.
    let startup_raw = client_startup(&registry, &info);
    if info.physical_replication
        && let Some(operation) = registry.database_maintenance().rename_for(&schema)
    {
        // Authentication resolved an exact physical source. Keep WAL flowing
        // across a name change without running tenant database bootstrap.
        let guard = registry
            .checkout_database_maintenance_exact(&operation.id)
            .await?;
        return proxy::splice(client, guard.entry(), &startup_raw).await;
    }
    if writer_routing::is_routable_tenant(&registry, &info, &schema) {
        match writer_routing::route(&registry, &schema)? {
            writer_routing::Route::Local => {}
            writer_routing::Route::Peer { peer, claim } => {
                return writer_routing::forward(client, &startup_raw, peer, claim).await;
            }
            writer_routing::Route::Unavailable(reason) => {
                auth::send_fatal(&mut client, auth::SQLSTATE_INSUFFICIENT_PRIVILEGE, reason).await?;
                anyhow::bail!("writer unavailable for {schema}: {reason}");
            }
        }
    }
    if !info.physical_replication && !registry.physical_admission_ready(&schema) {
        auth::send_fatal(&mut client, auth::SQLSTATE_INSUFFICIENT_PRIVILEGE, "physical handoff is incomplete; admission remains closed").await?;
        anyhow::bail!("refused connection during incomplete physical handoff for {schema}");
    }
    if let Some(fence) = registry.replication().get(&schema).and_then(|r| r.fence)
        && (fence.mode != "selective"
            || registry.replication().by_repl_role(&info.user).is_none())
        && !(info.physical_replication && registry.physical_reconnect_allowed(&schema, &info.user))
    {
        auth::send_fatal(
            &mut client,
            auth::SQLSTATE_INSUFFICIENT_PRIVILEGE,
            "database is fenced for a planned switchover; operator unfence is required",
        )
        .await?;
        anyhow::bail!("refused connection to fenced database {schema}");
    }
    if !is_valid_schema(&schema) {
        anyhow::bail!("rejecting invalid schema name {schema:?}");
    }
    info!("client requested schema {schema}");

    // Hold the guard for the whole connection: it keeps the VM off the idle
    // reaper's radar until the client disconnects.
    let guard = match registry.checkout(&schema).await {
        Ok(guard) => guard,
        Err(e) => {
            // Say why before hanging up. A bare dropped socket reaches a libpq
            // client as "SSL SYSCALL error: EOF detected", which reads as a
            // network fault and says nothing about a pooler at capacity or a
            // schema being held off. Best-effort: the client may be gone.
            let sqlstate = if vm::is_shed(&e) {
                auth::SQLSTATE_TOO_MANY_CONNECTIONS
            } else {
                auth::SQLSTATE_CANNOT_CONNECT_NOW
            };
            let message = auth::client_message(&format!("pg-vm-pool: {e:#}"));
            let _ = auth::send_fatal(&mut client, sqlstate, &message).await;
            return Err(e);
        }
    };
    proxy::splice(client, guard.entry(), &startup_raw).await
}

/// The StartupMessage to replay to the guest for this client: verbatim, plus
/// the session-default `statement_timeout` (see
/// [`config::Config::client_statement_timeout`]) for ordinary client sessions.
///
/// Why here and not in the guest's `postgresql.conf`: clients and the pooler
/// log in as the same role (`PG_VM_POOL_USER`, `postgres` by default), so
/// neither the server config nor `ALTER ROLE … SET` can tell them apart, and a
/// cluster-wide default would cap every maintenance path (CREATE DATABASE,
/// CHECKPOINT before a stop, restores, `pg_dump` for freeze/archive, schema
/// copy, subscription setup) unless each remembered to opt out. Only client
/// sessions pass through this function, so nothing internal can inherit it,
/// and it takes effect on every VM at the next connection rather than the next
/// boot.
///
/// Replication sessions are left alone: a subscription's initial table sync
/// is a long `COPY` on a `replication=database` connection, and a replication
/// login's other sessions (the replica's schema-copy `pg_dump`) belong to the
/// pooler's own machinery. Best-effort: a packet that cannot be rewritten is
/// replayed as-is rather than refused.
fn client_startup<'a>(
    registry: &SchemaRegistry,
    info: &'a startup::StartupInfo,
) -> std::borrow::Cow<'a, [u8]> {
    let Some(timeout) = registry.cfg().client_statement_timeout else {
        return info.raw.as_slice().into();
    };
    if info.replication_requested
        || registry.replication().by_repl_role(&info.user).is_some()
        || registry
            .physical_sources()
            .by_repl_role(&info.user)
            .is_some()
    {
        return info.raw.as_slice().into();
    }
    let setting = format!(
        "statement_timeout={}",
        timeout.as_millis().min(i32::MAX as u128)
    );
    match startup::with_default_option(&info.raw, &setting) {
        Ok(raw) => raw.into(),
        Err(e) => {
            warn!(
                "replaying {}@{}'s startup without session defaults: {e:#}",
                info.user, info.database
            );
            info.raw.as_slice().into()
        }
    }
}

/// Raise this process's open-files soft limit to its hard limit.
///
/// Every parked client, spliced session and daemon call holds a descriptor,
/// and the soft limit a supervised service inherits is usually 1024 — which a
/// busy host outgrows: on 2026-09-15 all three hosts logged EMFILE, and mia3's
/// pooler died of it when `accept` failed. The hard limit there was 524288, so
/// the fix is only ever this call. Best-effort: a host that won't allow it
/// keeps the old limit and says so.
fn raise_open_files_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit and setrlimit only read and write the struct passed in.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        warn!(
            "could not read the open-files limit: {}",
            std::io::Error::last_os_error()
        );
        return;
    }
    if limit.rlim_cur >= limit.rlim_max {
        return;
    }
    let raised = libc::rlimit {
        rlim_cur: limit.rlim_max,
        rlim_max: limit.rlim_max,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
        info!(
            "raised the open-files limit from {} to {}",
            limit.rlim_cur, limit.rlim_max
        );
    } else {
        warn!(
            "could not raise the open-files limit from {}: {}",
            limit.rlim_cur,
            std::io::Error::last_os_error()
        );
    }
}

/// Sanity-check `PG_VM_POOL_RUN_DIR` at startup: it must be *heyvmd's* run dir
/// (the one holding `sb-<id>/`), not merely a directory that exists.
///
/// Everything that returns disk — the orphan sweep, the rootfs prune, the
/// reclaim command, compaction, image archiving, pressure eviction — resolves
/// paths under it, and every one of them treats "nothing there" as "nothing to
/// do". So a run dir pointed at the wrong path (the default `~/.heyo/run` on a
/// host whose daemon actually runs out of, say, a mounted array) doesn't fail:
/// it silently turns off disk reclamation while every log line still reads
/// normal. That is worth a loud line at startup.
fn check_run_dir(run_dir: &std::path::Path) {
    let sandboxes = std::fs::read_dir(run_dir).map(|entries| {
        entries
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("sb-"))
            .count()
    });
    match sandboxes {
        Ok(0) => warn!(
            "PG_VM_POOL_RUN_DIR={} holds no sb-<id>/ directories — if heyvmd's run dir is \
             elsewhere, every disk-reclaiming feature (orphan sweep, rootfs prune, reclaim \
             command, compaction, image archive, pressure eviction) is silently doing nothing. \
             Check the daemon's data dir and PG_VM_POOL_RECLAIM_CMD's argument too",
            run_dir.display()
        ),
        Ok(n) => info!("run dir {} holds {n} VM directories", run_dir.display()),
        Err(e) => warn!(
            "PG_VM_POOL_RUN_DIR={} is not readable ({e}) — disk verification, the orphan \
             sweep and the local offload tiers all need it",
            run_dir.display()
        ),
    }
}

/// Conservative guard on the client-supplied schema name: it becomes both a
/// Postgres database identifier and part of the VM name, so cap length (PG's
/// 63-byte identifier limit) and reject control characters.
pub(crate) fn is_valid_schema(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| !c.is_control())
}
