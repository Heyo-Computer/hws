//! The replication surface: a JSON admin API plus the dashboard's HTML forms,
//! and the node-to-node endpoints a peer calls.
//!
//! Structured exactly like [`super::dedicated`]: both surfaces share one
//! funnel per action, and both sit behind the dashboard's Basic-auth layer.
//! The node-to-node routes are namespaced under `/api/replication/peer/` so
//! what a peer is allowed to drive reads off the route table in one place.

use axum::Json;
use axum::extract::{Form, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use maud::Markup;
use serde::{Deserialize, Serialize};

use crate::replication::{orchestrate, wire};

use super::dedicated::ApiError;
use super::error::AppError;
use super::handlers::{Banner, qenc};
use super::state::DashState;
use super::views::{self, ReplRow};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Map an orchestration failure onto a status code.
///
/// Almost everything here is something the caller can fix — a name already
/// taken, a peer that is not reachable, replication not enabled on the far
/// side — so the default is `400` with the reason, not an opaque `500`. The
/// message is the fix, which is why it is always passed through verbatim.
fn api_err(e: &anyhow::Error) -> (StatusCode, Json<ApiError>) {
    let msg = format!("{e:#}");
    let code = if msg.contains("already replicating") || msg.contains("already exists") {
        StatusCode::CONFLICT
    } else if msg.contains("timed out") || msg.contains("reaching peer") {
        StatusCode::GATEWAY_TIMEOUT
    } else if msg.contains("peer ") && msg.contains("answered") {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::BAD_REQUEST
    };
    (code, Json(ApiError { error: msg }))
}

fn back(query: String) -> Redirect {
    Redirect::to(&format!("/replication?{query}"))
}

fn ok_or_err<T>(r: anyhow::Result<T>, done: &str) -> Redirect {
    match r {
        Ok(_) => back(format!("msg={}", qenc(done))),
        Err(e) => back(format!("err={}", qenc(&format!("{e:#}")))),
    }
}

// ---------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------

pub async fn page(
    State(st): State<DashState>,
    Query(b): Query<Banner>,
) -> Result<Markup, AppError> {
    let records = st.registry.replication().list();
    // Read the monitor's cache rather than querying each VM: a page render
    // must never disturb what it is showing, and one wedged VM must not hang
    // the request.
    let rows: Vec<ReplRow> = records
        .iter()
        .map(|rec| {
            let s = st.registry.replication_status_cached(&rec.database);
            ReplRow {
                rec: rec.clone(),
                primary: s.as_ref().and_then(|s| s.primary.clone()),
                replica: s.as_ref().and_then(|s| s.replica.clone()),
                error: s.and_then(|s| s.peer_error),
            }
        })
        .collect();
    let peers = st.registry.peers().list();
    // Only dedicated databases with no live pairing can be replicated.
    let candidates: Vec<String> = st
        .registry
        .dedicated()
        .list()
        .into_iter()
        .map(|c| c.database)
        .filter(|d| !st.registry.replication().is_pinned(d))
        .collect();
    Ok(views::replication_page(&st, &rows, &peers, &candidates, &b))
}

// ---------------------------------------------------------------------------
// Peers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PeerForm {
    pub name: String,
    pub base_url: String,
    pub user: String,
    pub password: String,
    pub pg_host: String,
    pub pg_port: u16,
}

#[derive(Serialize)]
pub struct PeerJson {
    pub name: String,
    pub base_url: String,
    pub pg_host: String,
    pub pg_port: u16,
    pub created_at: u64,
}

fn add_peer(st: &DashState, f: &PeerForm) -> anyhow::Result<()> {
    st.registry.peers().create(
        &f.name,
        &f.base_url,
        &f.user,
        &f.password,
        &f.pg_host,
        f.pg_port,
    )?;
    Ok(())
}

/// Removing a peer that a live pairing still names would leave that pairing
/// with no control path — status would go dark and detach would have nothing
/// to call. Refuse rather than orphan it.
fn remove_peer(st: &DashState, name: &str) -> anyhow::Result<bool> {
    if let Some(db) = st.registry.replication().peer_in_use(name) {
        anyhow::bail!("peer {name:?} is still used by the pairing for database {db:?}");
    }
    st.registry.peers().remove(name)
}

pub async fn peer_create_form(State(st): State<DashState>, Form(f): Form<PeerForm>) -> Redirect {
    ok_or_err(add_peer(&st, &f), "peer added")
}

pub async fn peer_delete_form(State(st): State<DashState>, Path(name): Path<String>) -> Redirect {
    match remove_peer(&st, &name) {
        Ok(true) => back(format!("msg={}", qenc("peer removed"))),
        Ok(false) => back(format!("err={}", qenc("no such peer"))),
        Err(e) => back(format!("err={}", qenc(&format!("{e:#}")))),
    }
}

pub async fn api_peers_list(State(st): State<DashState>) -> Json<Vec<PeerJson>> {
    Json(
        st.registry
            .peers()
            .list()
            .into_iter()
            .map(|p| PeerJson {
                name: p.name,
                base_url: p.base_url,
                pg_host: p.pg_host,
                pg_port: p.pg_port,
                created_at: p.created_at,
            })
            .collect(),
    )
}

pub async fn api_peer_create(State(st): State<DashState>, Json(f): Json<PeerForm>) -> Response {
    match add_peer(&st, &f) {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_peer_delete(State(st): State<DashState>, Path(name): Path<String>) -> Response {
    match remove_peer(&st, &name) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: format!("no peer named {name:?}"),
            }),
        )
            .into_response(),
        Err(e) => api_err(&e).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Pairings
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EnableForm {
    pub database: String,
    pub peer: String,
}

pub async fn enable_form(State(st): State<DashState>, Form(f): Form<EnableForm>) -> Redirect {
    let r = orchestrate::enable_primary(&st.registry, f.database.trim(), f.peer.trim()).await;
    ok_or_err(
        r,
        "replication started — the replica is seeding; watch the state column",
    )
}

pub async fn promote_form(State(st): State<DashState>, Path(db): Path<String>) -> Redirect {
    let r = orchestrate::promote(&st.registry, &db).await;
    match r {
        Ok(p) => back(format!(
            "msg={}",
            qenc(&format!(
                "{db} promoted — it no longer follows the primary; {} sequence(s) re-seeded",
                p.sequences_fixed
            ))
        )),
        Err(e) => back(format!("err={}", qenc(&format!("{e:#}")))),
    }
}

pub async fn refresh_form(State(st): State<DashState>, Path(db): Path<String>) -> Redirect {
    ok_or_err(
        orchestrate::refresh(&st.registry, &db).await,
        "subscription refreshed",
    )
}

pub async fn detach_form(State(st): State<DashState>, Path(db): Path<String>) -> Redirect {
    match orchestrate::detach(&st.registry, &db).await {
        Ok(d) => back(format!(
            "msg={}",
            qenc(&format!(
                "{db} detached (slot dropped: {}, publication dropped: {})",
                d.slot_dropped, d.publication_dropped
            ))
        )),
        Err(e) => back(format!("err={}", qenc(&format!("{e:#}")))),
    }
}

/// Forget a finished or failed record. Refuses a live one — that is what
/// detach and promote are for, and dropping the row would strand the Postgres
/// objects it names.
fn forget(st: &DashState, db: &str) -> anyhow::Result<bool> {
    if st.registry.physical().reserves_database(db) || st.registry.physical_sources().get(db).is_some() {
        anyhow::bail!("{db} has physical ownership; its logical record must remain unchanged");
    }
    if st.registry.replication().is_pinned(db) {
        anyhow::bail!(
            "{db} is still replicating — detach or promote it first, or its publication, \
             slot or subscription would be left behind with nothing naming them"
        );
    }
    st.registry.replication().remove(db)
}

pub async fn delete_form(State(st): State<DashState>, Path(db): Path<String>) -> Redirect {
    match forget(&st, &db) {
        Ok(true) => back(format!("msg={}", qenc("record removed"))),
        Ok(false) => back(format!("err={}", qenc("no such record"))),
        Err(e) => back(format!("err={}", qenc(&format!("{e:#}")))),
    }
}

// --- JSON ------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EnableRequest {
    pub database: String,
    pub peer: String,
}

pub async fn api_list(State(st): State<DashState>) -> Json<Vec<wire::RecordJson>> {
    Json(
        st.registry
            .replication()
            .list()
            .iter()
            .map(wire::RecordJson::from)
            .collect(),
    )
}

pub async fn api_enable(State(st): State<DashState>, Json(r): Json<EnableRequest>) -> Response {
    match orchestrate::enable_primary(&st.registry, r.database.trim(), r.peer.trim()).await {
        Ok(rec) => (StatusCode::CREATED, Json(wire::RecordJson::from(&rec))).into_response(),
        Err(e) => api_err(&e).into_response(),
    }
}

#[derive(Deserialize)]
pub struct StatusQuery {
    /// Sample the VMs now instead of reading the monitor's cache. Costs a
    /// round trip to each side, so it is opt-in.
    #[serde(default)]
    pub fresh: Option<u8>,
}

pub async fn api_get(
    State(st): State<DashState>,
    Path(db): Path<String>,
    Query(q): Query<StatusQuery>,
) -> Response {
    let Some(rec) = st.registry.replication().get(&db) else {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: format!("{db} is not replicating"),
            }),
        )
            .into_response();
    };
    let status = if q.fresh.unwrap_or(0) == 1 {
        st.registry.sample_replication(&rec).await
    } else {
        st.registry
            .replication_status_cached(&db)
            .unwrap_or_else(|| wire::StatusJson {
                record: (&rec).into(),
                primary: None,
                replica: None,
                peer_error: Some("not sampled yet".into()),
            })
    };
    Json(status).into_response()
}

pub async fn api_promote(State(st): State<DashState>, Path(db): Path<String>) -> Response {
    match orchestrate::promote(&st.registry, &db).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_fence(State(st): State<DashState>, Path(db): Path<String>) -> Response {
    match orchestrate::fence(&st.registry, &db).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_fence_selective(State(st): State<DashState>, Path(db): Path<String>) -> Response {
    match orchestrate::fence_selective(&st.registry, &db).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_unfence(State(st): State<DashState>, Path(db): Path<String>) -> Response {
    match orchestrate::unfence(&st.registry, &db).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_refresh(State(st): State<DashState>, Path(db): Path<String>) -> Response {
    match orchestrate::refresh(&st.registry, &db).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_detach(State(st): State<DashState>, Path(db): Path<String>) -> Response {
    match orchestrate::detach(&st.registry, &db).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_forget(State(st): State<DashState>, Path(db): Path<String>) -> Response {
    match forget(&st, &db) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: format!("{db} is not replicating"),
            }),
        )
            .into_response(),
        Err(e) => api_err(&e).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Node-to-node
// ---------------------------------------------------------------------------

pub async fn api_writer_tunnel(State(st): State<DashState>, mut request: axum::extract::Request) -> Response {
    crate::writer_routing::accept(&st.registry, st.cfg.basic_auth.is_some(), &mut request).await
}

/// The handshake a peer performs before creating anything. Deliberately says
/// nothing about which databases exist here — a peer is trusted to drive this
/// node, but the handshake itself is the least it needs.
pub async fn api_node_info(State(st): State<DashState>) -> Json<wire::NodeInfo> {
    let cfg = st.registry.replication_cfg();
    Json(wire::NodeInfo {
        node: cfg.map(|c| c.node_name.clone()).unwrap_or_default(),
        replication_enabled: cfg.is_some(),
        server_version_num: None,
        tls: st.registry.tls_enabled(),
        pg_listen_port: Some(st.registry.listen_port()),
        physical_prepare: true,
        physical_handoff: true,
        physical_successor: true,
        physical_reseed: true,
        physical_standby_bind: true,
        physical_standby_writer_routing: true,
    })
}

pub async fn api_physical_prepare(State(st): State<DashState>, Path(db): Path<String>, Json(req): Json<wire::PhysicalPrepareRequest>) -> Response {
    match crate::replication::physical::prepare_source(&st.registry, &db, &req.generation).await {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)).into_response(), Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_physical_reseed(State(st): State<DashState>, Path(db): Path<String>, Json(req): Json<wire::PhysicalReseedRequest>) -> Response {
    match crate::replication::physical::reseed_source(&st.registry, &db, req).await {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)).into_response(), Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_physical_standby_bind(State(st): State<DashState>, Path(db): Path<String>, Json(req): Json<wire::PhysicalPrepareRequest>) -> Response {
    match crate::replication::physical::bind_standby_source(&st.registry, &db, &req.generation).await {
        Ok(record) => Json(record).into_response(), Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_accept_physical_standby_bind(State(st): State<DashState>, Json(req): Json<wire::PhysicalStandbyBindRequest>) -> Response {
    match crate::replication::physical::accept_standby_bind(&st.registry, req).await {
        Ok(record) => Json(record).into_response(), Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_retire_previous(State(st): State<DashState>, Path(db): Path<String>, Json(req): Json<wire::RetirePreviousRequest>) -> Response {
    match crate::replication::retirement::retire_previous(&st.registry, &db, req).await {
        Ok(record) => Json(record).into_response(), Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_accept_retirement(State(st): State<DashState>, Json(req): Json<wire::RetirePreviousPeerRequest>) -> Response {
    match crate::replication::retirement::accept_retirement(&st.registry, req).await {
        Ok(record) => Json(record).into_response(), Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_physical_handoff(State(st): State<DashState>, Path(db): Path<String>, Json(mut req): Json<wire::PhysicalHandoffRequest>) -> Response {
    if req.database != db { return api_err(&anyhow::anyhow!("path database does not match handoff request")).into_response(); }
    req.database = db;
    match crate::replication::physical::handoff_source(&st.registry, req).await {
        Ok(record) => Json(record).into_response(), Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_accept_physical_handoff(State(st): State<DashState>, Json(req): Json<wire::PhysicalHandoffRequest>) -> Response {
    match crate::replication::physical::accept_handoff(&st.registry, req).await {
        Ok(record) => Json(record).into_response(), Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_physical_grant(State(st): State<DashState>, Path(db): Path<String>) -> Response {
    match crate::replication::physical::source_grant(&st.registry, &db).await {
        Ok(grant) => Json(grant).into_response(), Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_accept_physical_replica(State(st): State<DashState>, Json(req): Json<wire::PhysicalReplicaRequest>) -> Response {
    match crate::replication::physical::accept_candidate(&st.registry, req).await {
        Ok(record) => (StatusCode::ACCEPTED, Json(wire::PhysicalRecordJson::from(&record))).into_response(), Err(e) => api_err(&e).into_response(),
    }
}

pub async fn api_physical_get(State(st): State<DashState>, Path(db): Path<String>) -> Response {
    match st.registry.physical().get(&db) {
        Some(record) => Json(wire::PhysicalRecordJson::from(&record)).into_response(),
        None => (StatusCode::NOT_FOUND, Json(ApiError { error: format!("no physical preparation for {db}") })).into_response(),
    }
}

/// A primary asking this node to build the replica. Validates synchronously
/// and answers; the VM work runs in the background, so the primary is not held
/// open across a schema copy.
pub async fn api_accept_replica(
    State(st): State<DashState>,
    Json(req): Json<wire::ProvisionReplica>,
) -> Response {
    match orchestrate::accept_replica(&st.registry, req) {
        Ok(rec) => (StatusCode::CREATED, Json(wire::RecordJson::from(&rec))).into_response(),
        Err(e) => api_err(&e).into_response(),
    }
}
