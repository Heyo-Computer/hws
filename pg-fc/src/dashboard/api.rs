//! The JSON admin API: everything the HTML dashboard shows and does, for
//! programs — app-lb's pg-fc plugin first among them.
//!
//! Same listener and same Basic-auth layer as the pages (see `router`), and
//! the same code paths behind them: an action here is the button on the VM
//! page with a JSON answer instead of a redirect. The wire types are in the
//! `pg-fc-api` crate so the plugin reads exactly what this writes.
//!
//! The API is keyed by **schema** (the database name a client connects with),
//! not by sandbox id. A schema outlives its VMs — an offload deletes the VM and
//! a restore creates another — so the schema is the only name a caller can
//! hold onto.

use std::collections::{BTreeSet, HashMap, HashSet};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use pg_fc_api::{
    ActionResult, ApiError, ConfigView, EventCounts, EventEntry, Health, HostDisk, HostInfo,
    LogTail, Metrics, ResizeRequest, RuntimeKnobs, SchemaAction, SchemaDetail, SchemaInfo,
    TierCounts, TimingSummary,
};
use serde::Deserialize;

use crate::registry::EntrySnapshot;
use crate::store::Tier;

use super::handlers::{Lifecycle, run_lifecycle};
use super::state::DashState;
use super::{host, logs, model};

fn fail(code: StatusCode, error: impl Into<String>) -> Response {
    (
        code,
        Json(ApiError {
            error: error.into(),
        }),
    )
        .into_response()
}

fn started(message: impl Into<String>) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(ActionResult {
            done: false,
            message: message.into(),
        }),
    )
        .into_response()
}

fn finished(message: impl Into<String>) -> Response {
    Json(ActionResult {
        done: true,
        message: message.into(),
    })
    .into_response()
}

// ---- health ----------------------------------------------------------------

/// `GET /api/health` — in-memory only, so it is cheap enough to poll. Behind
/// Basic auth like everything else, so it describes the pooler rather than
/// serving as an unauthenticated liveness probe.
pub async fn health(State(st): State<DashState>) -> Json<Health> {
    Json(health_view(&st).await)
}

/// What `/api/health` serves, for in-process callers (the fleet rollup).
pub(super) async fn health_view(st: &DashState) -> Health {
    let cfg = st.registry.cfg();
    let mut tiers = Vec::new();
    if cfg.compact.is_some() {
        tiers.push("compacted".into());
    }
    if cfg.freeze.is_some() {
        tiers.push("frozen".into());
    }
    if cfg.archive.is_some() {
        tiers.push("archived".into());
    }
    Health {
        version: env!("CARGO_PKG_VERSION").into(),
        uptime_secs: st.started_at.elapsed().as_secs(),
        listen: cfg.listen_addr.to_string(),
        warm_schemas: st.registry.snapshot().await.len(),
        known_schemas: st.registry.store_records().len(),
        tiers,
        tls: st.registry.tls_enabled(),
        replication: st.registry.replication_cfg().is_some(),
    }
}

// ---- metrics ---------------------------------------------------------------

#[derive(Deserialize)]
pub struct WindowQuery {
    /// Trailing window in hours (default 1, clamped to 1..=24).
    pub hours: Option<u64>,
}

impl WindowQuery {
    pub(super) fn hours(&self) -> u64 {
        self.hours.unwrap_or(1).clamp(1, 24)
    }
}

/// `GET /api/metrics` — activity counts, journalled errors and bring-up
/// latency over a trailing window. In-memory only, like `/api/health`.
pub async fn metrics(Query(q): Query<WindowQuery>) -> Json<Metrics> {
    Json(metrics_view(q.hours()))
}

/// What `/api/metrics` serves, for in-process callers (the fleet rollup).
pub(super) fn metrics_view(hours: u64) -> Metrics {
    use crate::events::{Event, Timing};
    // Whole clock-hour buckets, matching the monitoring charts: the current
    // (partial) hour plus `hours - 1` before it.
    let count = |e: Event| -> u64 {
        crate::events::hourly_counts(e, hours as usize)
            .iter()
            .map(|(_, n)| u64::from(*n))
            .sum()
    };
    let cutoff = crate::events::now_unix().saturating_sub(hours * 3600);
    let recent: Vec<_> = crate::events::journal_recent(crate::events::JOURNAL_CAPACITY)
        .into_iter()
        .filter(|e| e.t >= cutoff && e.level == crate::events::Level::Error)
        .collect();
    let timings = [
        Timing::VmCreate,
        Timing::RestoreS3Image,
        Timing::RestoreS3Dump,
        Timing::RestoreLocalImage,
        Timing::RestoreLocalDump,
        Timing::RestoreS3Download,
        Timing::RestoreImageAdopt,
        Timing::RestoreImageDecompress,
        Timing::RestoreImageFsck,
        Timing::RestoreImageBoot,
        Timing::RestoreDumpDownload,
        Timing::RestoreDumpLoad,
        Timing::RestoreDumpFinalize,
    ]
    .into_iter()
    .filter_map(|t| {
        crate::events::timing_stats(t, hours).map(|s| TimingSummary {
            kind: t.as_str().into(),
            count: s.count,
            p50_ms: s.p50_ms,
            p95_ms: s.p95_ms,
            p99_ms: s.p99_ms,
            max_ms: s.max_ms,
        })
    })
    .collect();
    Metrics {
        window_hours: hours,
        events: EventCounts {
            vms_created: count(Event::VmCreated),
            restores_s3: count(Event::RestoreS3),
            restores_local: count(Event::RestoreLocal),
            offloads_done: count(Event::OffloadDone),
            vms_deleted: count(Event::VmDeleted),
            spares_claimed: count(Event::SpareClaimed),
        },
        bringup_errors: recent.iter().filter(|e| e.kind == "bring-up").count(),
        errors: recent.len(),
        timings,
    }
}

// ---- schemas ---------------------------------------------------------------

/// One schema's row from the three places the pooler knows about it: the
/// durable record, the warm map and the dedicated-credential store.
fn schema_info(
    st: &DashState,
    schema: &str,
    warm: Option<&EntrySnapshot>,
    dedicated: bool,
    offloading: bool,
) -> SchemaInfo {
    let record = st.registry.store_record(schema);
    SchemaInfo {
        schema: schema.to_string(),
        // A dedicated database provisioned but never brought up has no record
        // yet; "pending" says that rather than claiming a tier.
        tier: record
            .as_ref()
            .map_or("pending", |r| r.tier.as_str())
            .to_string(),
        sandbox_id: warm
            .map(|w| w.sandbox_id.clone())
            .or_else(|| record.as_ref().map(|r| r.sandbox_id.clone()))
            .filter(|id| !id.is_empty()),
        last_active: record.as_ref().map_or(0, |r| r.last_active),
        disk_gb: record.as_ref().map(|r| r.disk_gb).filter(|&g| g > 0),
        warm: warm.is_some(),
        sessions: warm.map(|w| w.active),
        free_slots: warm.map(|w| w.free_slots),
        slot_limit: warm.map(|w| w.slot_limit),
        idle_secs: warm.map(|w| w.idle_secs),
        idle_budget_secs: warm.and_then(|w| w.idle_budget_secs),
        bringup_ms: warm.map(|w| w.bringup_ms as u64),
        keepalive: warm.is_some_and(|w| w.keepalive) || st.registry.cfg().is_keepalive(schema),
        dedicated,
        pinned: st.registry.pin_reason(schema),
        offloading,
    }
}

async fn all_schemas(st: &DashState) -> Vec<SchemaInfo> {
    let warm: HashMap<String, EntrySnapshot> = st
        .registry
        .snapshot()
        .await
        .into_iter()
        .map(|e| (e.schema.clone(), e))
        .collect();
    let dedicated: HashSet<String> = st
        .registry
        .dedicated()
        .list()
        .into_iter()
        .map(|c| c.database)
        .collect();
    let offloading: HashSet<String> = st.registry.archiving_schemas().into_iter().collect();
    let names: BTreeSet<String> = st
        .registry
        .store_records()
        .into_iter()
        .map(|(name, _)| name)
        .chain(warm.keys().cloned())
        .chain(dedicated.iter().cloned())
        .collect();
    names
        .iter()
        .map(|name| {
            schema_info(
                st,
                name,
                warm.get(name),
                dedicated.contains(name),
                offloading.contains(name),
            )
        })
        .collect()
}

#[derive(Deserialize)]
pub struct SchemaFilter {
    /// Only schemas on this tier (`live`, `compacted`, `frozen`, `archived`,
    /// `pending`), or `warm` for those with a VM checked in right now.
    pub tier: Option<String>,
    /// Substring match on the schema name.
    #[serde(default)]
    pub q: String,
}

/// `GET /api/schemas` — every schema the pooler knows, whatever its tier.
pub async fn schemas(
    State(st): State<DashState>,
    Query(f): Query<SchemaFilter>,
) -> Json<Vec<SchemaInfo>> {
    let mut rows = all_schemas(&st).await;
    if let Some(t) = f.tier.as_deref().filter(|t| !t.is_empty()) {
        rows.retain(|r| if t == "warm" { r.warm } else { r.tier == t });
    }
    if !f.q.is_empty() {
        rows.retain(|r| r.schema.contains(&f.q));
    }
    Json(rows)
}

/// `GET /api/schemas/{schema}` — one schema, with live size and backends when
/// it is warm. Those are read over the pooler's own warm pool (the liveness
/// path), never the guest console.
pub async fn schema(State(st): State<DashState>, Path(schema): Path<String>) -> Response {
    let Some(info) = all_schemas(&st)
        .await
        .into_iter()
        .find(|r| r.schema == schema)
    else {
        return fail(StatusCode::NOT_FOUND, format!("no schema named {schema:?}"));
    };
    let stats = match (&info.sandbox_id, info.warm) {
        (Some(id), true) => st.registry.db_stats(id, &schema).await,
        _ => None,
    };
    Json(SchemaDetail {
        db_size_bytes: stats.as_ref().map(|s| s.db_size_bytes),
        backends: stats.as_ref().map(|s| s.backends),
        info,
    })
    .into_response()
}

/// Read-only session identity on the currently bound, already-warm guest.
pub async fn sessions(State(st): State<DashState>, Path(schema): Path<String>) -> Response {
    match st.registry.database_sessions(&schema).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => fail(StatusCode::CONFLICT, format!("{error:#}")),
    }
}

/// `POST /api/schemas/{schema}/{action}`.
///
/// Refusals are 409 (the schema's state forbids it, and the caller can change
/// that state) or 501 (the pooler is not configured for it). Short actions
/// answer 200 when done; the long ones (reap, restore, image archive) answer
/// 202 and report in `/api/events`.
pub async fn schema_action(
    State(st): State<DashState>,
    Path((schema, action)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let Some(action) = SchemaAction::parse(&action) else {
        return fail(StatusCode::NOT_FOUND, format!("no action named {action:?}"));
    };
    let Some(record) = st.registry.store_record(&schema) else {
        return fail(
            StatusCode::NOT_FOUND,
            format!("the pooler has never backed a schema named {schema:?}"),
        );
    };
    // Everything but a restore touches the VM a replication pairing may
    // depend on; the pages refuse those one by one, and so does this.
    if action != SchemaAction::Restore
        && let Some(why) = st.registry.pin_reason(&schema)
    {
        return fail(StatusCode::CONFLICT, why);
    }
    let offloaded = record.tier != Tier::Live;
    let vm = record.sandbox_id.clone();
    match action {
        SchemaAction::Start | SchemaAction::Stop | SchemaAction::Reboot | SchemaAction::Resize
            if offloaded =>
        {
            fail(
                StatusCode::CONFLICT,
                format!(
                    "{schema} is {} — its VM was deleted when it was offloaded; restore it first",
                    record.tier.as_str()
                ),
            )
        }
        SchemaAction::Start => lifecycle(&vm, Lifecycle::Start, "started").await,
        SchemaAction::Stop => lifecycle(&vm, Lifecycle::Stop, "stopped").await,
        SchemaAction::Reboot => lifecycle(&vm, Lifecycle::Reboot, "rebooted").await,
        SchemaAction::Resize => {
            let req: ResizeRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => {
                    return fail(
                        StatusCode::BAD_REQUEST,
                        format!("resize needs {{\"size_class\": …}}: {e}"),
                    );
                }
            };
            let size = match crate::config::parse_size_class(&req.size_class) {
                Ok(s) => s,
                Err(_) => {
                    return fail(
                        StatusCode::BAD_REQUEST,
                        format!("unknown size class {:?}", req.size_class),
                    );
                }
            };
            let result = async {
                use anyhow::Context;
                let sb = heyo_sdk::Sandbox::connect(vm.clone(), crate::vm::local_opts())
                    .context("connecting to VM")?;
                tokio::time::timeout(super::handlers::ACTION_TIMEOUT, sb.resize(size))
                    .await
                    .context("resize timed out")??;
                anyhow::Ok(())
            }
            .await;
            match result {
                Ok(()) => finished(format!("resized to {}", size.as_str())),
                Err(e) => fail(StatusCode::BAD_GATEWAY, format!("{e:#}")),
            }
        }
        SchemaAction::Reap => {
            if offloaded {
                return fail(
                    StatusCode::CONFLICT,
                    format!("{schema} is already {}", record.tier.as_str()),
                );
            }
            if !st.registry.archive_enabled() {
                return fail(
                    StatusCode::NOT_IMPLEMENTED,
                    "the S3 tier is not configured (PG_VM_POOL_ARCHIVE_AFTER_SECS + PG_VM_POOL_S3_*)",
                );
            }
            let registry = st.registry.clone();
            let name = schema.clone();
            tokio::spawn(async move {
                if let Err(e) = registry.archive_schema(&name).await {
                    tracing::warn!("API reap of schema {name} to S3 failed: {e:#}");
                }
            });
            started(format!("reaping {schema} to S3"))
        }
        SchemaAction::ArchiveImage => {
            if offloaded {
                return fail(
                    StatusCode::CONFLICT,
                    format!("{schema} is already {}", record.tier.as_str()),
                );
            }
            if !st.registry.image_archive_enabled() {
                return fail(
                    StatusCode::NOT_IMPLEMENTED,
                    "image archiving is not enabled (PG_VM_POOL_IMAGE_ARCHIVE=1 + PG_VM_POOL_RUN_DIR)",
                );
            }
            let registry = st.registry.clone();
            let name = schema.clone();
            tokio::spawn(async move {
                if let Err(e) = registry.archive_schema_as_image(&name, Some(&vm)).await {
                    tracing::warn!("API image archive of schema {name} failed: {e:#}");
                }
            });
            started(format!("archiving {schema}'s disk image"))
        }
        SchemaAction::Restore => {
            if !offloaded {
                return fail(
                    StatusCode::CONFLICT,
                    format!("{schema} is live — there is nothing to restore"),
                );
            }
            // A checkout is exactly what a client connection would drive; the
            // guard drops as soon as the bring-up resolves, leaving the VM to
            // the idle reaper.
            let registry = st.registry.clone();
            let name = schema.clone();
            tokio::spawn(async move {
                match registry.checkout(&name).await {
                    Ok(guard) => {
                        let vm = guard.entry().sandbox_id();
                        drop(guard);
                        crate::events::journal_info(
                            "restore",
                            format!("schema {name} restored into VM {vm}"),
                        );
                    }
                    Err(e) => crate::events::journal_error(
                        "restore",
                        format!("restoring schema {name} failed: {e:#}"),
                    ),
                }
            });
            started(format!("restoring {schema}"))
        }
    }
}

async fn lifecycle(vm: &str, act: Lifecycle, done: &str) -> Response {
    match run_lifecycle(vm, act).await {
        Ok(()) => finished(done),
        Err(e) => fail(StatusCode::BAD_GATEWAY, format!("{e:#}")),
    }
}

// ---- host ------------------------------------------------------------------

/// `GET /api/host` — what `/monitoring` shows at the top, each part
/// best-effort: a stale daemon sampler or a `df` hiccup blanks its own fields.
pub async fn host(State(st): State<DashState>) -> Json<HostInfo> {
    Json(host_view(&st).await)
}

/// What `/api/host` serves, for in-process callers (the fleet rollup).
pub(super) async fn host_view(st: &DashState) -> HostInfo {
    let (usage, disks) = tokio::join!(model::fetch_host_usage(st), host::host_disks());
    let usage = usage.unwrap_or_default();
    let mut tiers = TierCounts::default();
    for (_, r) in st.registry.store_records() {
        match r.tier {
            Tier::Live => tiers.live += 1,
            Tier::Compacted => tiers.compacted += 1,
            Tier::Frozen => tiers.frozen += 1,
            Tier::Archived => tiers.archived += 1,
        }
    }
    let spares = st.registry.spare_pool_depth();
    HostInfo {
        cpu_percent: usage.cpu_percent,
        cpu_count: usage.cpu_count,
        memory_total_bytes: usage.memory_total_bytes,
        memory_used_bytes: usage.memory_used_bytes,
        disks: disks
            .unwrap_or_default()
            .into_iter()
            .map(|d| HostDisk {
                source: d.source,
                mount: d.mount,
                total: d.total,
                used: d.used,
                avail: d.avail,
            })
            .collect(),
        spares_ready: spares.map(|s| s.0),
        spares_target: spares.map(|s| s.1),
        tiers,
    }
}

// ---- events and logs -------------------------------------------------------

#[derive(Deserialize)]
pub struct EventQuery {
    /// At most this many (default 100, cap 1000).
    pub limit: Option<usize>,
    /// Only entries at or after this unix second.
    pub since: Option<u64>,
}

/// `GET /api/events` — the journal, newest first.
pub async fn events(Query(q): Query<EventQuery>) -> Json<Vec<EventEntry>> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    Json(
        crate::events::journal_recent(limit)
            .into_iter()
            .filter(|e| q.since.is_none_or(|s| e.t >= s))
            .map(|e| EventEntry {
                t: e.t,
                level: e.level.as_str().into(),
                kind: e.kind,
                msg: e.msg,
            })
            .collect(),
    )
}

#[derive(Deserialize)]
pub struct LogQuery {
    pub lines: Option<usize>,
}

fn log_tail(source: String, text: String) -> Response {
    Json(LogTail {
        source,
        lines: text.lines().map(str::to_string).collect(),
    })
    .into_response()
}

/// `GET /api/logs/{pooler|heyvmd}`.
pub async fn host_log(
    State(st): State<DashState>,
    Path(which): Path<String>,
    Query(q): Query<LogQuery>,
) -> Response {
    let path = match which.as_str() {
        "pooler" => &st.cfg.pooler_log,
        "heyvmd" => &st.cfg.heyvmd_log,
        _ => {
            return fail(
                StatusCode::NOT_FOUND,
                "logs are `pooler`, `heyvmd` or `schema/{name}`",
            );
        }
    };
    let lines = q.lines.unwrap_or(st.cfg.log_lines).clamp(1, 5000);
    match logs::tail_file(path, lines).await {
        Ok(text) => log_tail(path.display().to_string(), text),
        Err(e) => fail(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
    }
}

/// `GET /api/logs/schema/{schema}` — the schema's Postgres log, read from
/// inside its VM. The one guest exec in this API, so it is its own route and
/// never part of a listing.
pub async fn schema_log(
    State(st): State<DashState>,
    Path(schema): Path<String>,
    Query(q): Query<LogQuery>,
) -> Response {
    let Some(record) = st.registry.store_record(&schema) else {
        return fail(StatusCode::NOT_FOUND, format!("no schema named {schema:?}"));
    };
    if record.tier != Tier::Live {
        return fail(
            StatusCode::CONFLICT,
            format!("{schema} is {}; it has no VM to read", record.tier.as_str()),
        );
    }
    let lines = q.lines.unwrap_or(st.cfg.log_lines).clamp(1, 5000);
    match logs::tail_vm_log(&record.sandbox_id, lines).await {
        Ok(text) => log_tail(
            format!(
                "{}:/workspace/pgdata/log/postgresql-*.log",
                record.sandbox_id
            ),
            text,
        ),
        Err(e) => fail(StatusCode::BAD_GATEWAY, format!("{e:#}")),
    }
}

// ---- maintenance -----------------------------------------------------------

#[derive(Deserialize)]
struct TtlBody {
    ttl_secs: u64,
}

/// `POST /api/maintenance/{sweep|ttl-sweep|reclaim|stop-idle|purge}` — the
/// monitoring page's buttons. All run in the background; a pass that is
/// already running is a 409.
pub async fn maintenance(
    State(st): State<DashState>,
    Path(op): Path<String>,
    body: Bytes,
) -> Response {
    let busy = |e: anyhow::Error| fail(StatusCode::CONFLICT, format!("{e:#}"));
    match op.as_str() {
        "sweep" => match st.registry.spawn_sweep_now() {
            Ok(()) => started("S3 eviction sweep started"),
            Err(e) => busy(e),
        },
        "ttl-sweep" => {
            let Ok(TtlBody { ttl_secs }) = serde_json::from_slice(&body) else {
                return fail(StatusCode::BAD_REQUEST, "ttl-sweep needs {\"ttl_secs\": N}");
            };
            match st.registry.spawn_ttl_sweep_now(ttl_secs) {
                Ok(()) => started(format!("offloading every schema idle > {ttl_secs}s")),
                Err(e) => busy(e),
            }
        }
        "reclaim" => match st.registry.spawn_reclaim_now() {
            Ok(()) => started("disk reclaim started"),
            Err(e) => busy(e),
        },
        "purge" => match st.registry.spawn_purge_now() {
            Ok(()) => started("purge started"),
            Err(e) => busy(e),
        },
        "stop-idle" => {
            // The page's handler does the work in the background and answers
            // with a redirect; the redirect is what we drop.
            let _ = super::handlers::action_stop_idle(State(st)).await;
            started("stopping every session-less running VM")
        }
        _ => fail(
            StatusCode::NOT_FOUND,
            format!("no maintenance operation named {op:?}"),
        ),
    }
}

// ---- runtime configuration -------------------------------------------------

/// `GET /api/config`.
pub async fn config(State(st): State<DashState>) -> Json<ConfigView> {
    Json(st.registry.runtime().view())
}

/// `PUT /api/config` — a partial `RuntimeKnobs`; absent fields are unchanged.
pub async fn put_config(State(st): State<DashState>, Json(patch): Json<RuntimeKnobs>) -> Response {
    match st.registry.apply_runtime(patch) {
        Ok(_) => Json(st.registry.runtime().view()).into_response(),
        Err(e) => fail(StatusCode::BAD_REQUEST, e),
    }
}
