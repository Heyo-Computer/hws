//! Stable, one-hop writer routing during explicit physical handoffs.

use std::{sync::Arc, time::Duration};
use anyhow::{Context, Result, bail};
use axum::{body::to_bytes, extract::Request, http::{StatusCode, header}, response::{IntoResponse, Response}};
use hyper_util::rt::TokioIo;

use crate::{peers::Peer, registry::SchemaRegistry, replication::{PhysicalPhase, Role, peer::PeerClient, wire}, startup::{ClientStream, StartupInfo}};

// JSON represents startup bytes as decimal integers, up to four bytes each.
const MAX_TUNNEL_JSON: usize = 64 * 1024;

pub(crate) enum Route { Local, Peer { peer: Peer, claim: wire::WriterClaim }, Unavailable(&'static str) }

pub(crate) fn is_routable_tenant(reg: &SchemaRegistry, info: &StartupInfo, db: &str) -> bool {
    !info.replication_requested
        && reg.dedicated().by_database(db).is_some_and(|d| d.role == info.user)
        && reg.replication().by_repl_role(&info.user).is_none()
        && reg.physical_sources().by_repl_role(&info.user).is_none()
}

pub(crate) fn route(reg: &SchemaRegistry, db: &str) -> Result<Route> {
    reg.database_maintenance().check(db)?;
    let bound = reg.bound_vm_id(db);
    if let Some(source) = reg.physical_sources().get(db) {
        if bound.as_deref() == Some(source.source_vm_id.as_str()) {
            if let Some(grant) = source.handoff {
                let peer = reg.peers().get(&grant.peer).context("writer grant names an unknown peer")?;
                return Ok(Route::Peer { peer, claim: wire::WriterClaim {
                    kind: wire::WriterClaimKind::Activation, database: db.into(), generation: source.generation,
                    candidate_id: grant.candidate_id, source_vm_id: source.source_vm_id,
                    system_identifier: source.system_identifier, pg_major: source.pg_major,
                    sender_node: local_node(reg)?,
                }});
            }
            if source.fence.is_some() { return Ok(Route::Unavailable("physical source is fenced without a writer grant")); }
        }
    }
    if let Some(candidate) = reg.physical().get(db) {
        if candidate.phase == PhysicalPhase::Standby && candidate.predecessor.is_some() {
            return Ok(if candidate.candidate_id.as_deref() == bound.as_deref() { Route::Local }
                else { Route::Unavailable("physical standby binding mismatch") });
        }
        if candidate.handoff_started() {
            return Ok(if candidate.phase == PhysicalPhase::Activated
                && candidate.candidate_id.as_deref() == bound.as_deref()
                && reg.physical_admission_ready(db) { Route::Local }
                else { Route::Unavailable("physical handoff is not activated on this binding") });
        }
        if candidate.predecessor.is_none() && matches!(candidate.phase,
            PhysicalPhase::Verified | PhysicalPhase::StandbyBinding | PhysicalPhase::Standby) {
            let expected_binding = match candidate.phase {
                PhysicalPhase::Verified => candidate.previous_vm_id == bound,
                PhysicalPhase::StandbyBinding => candidate.previous_vm_id == bound || candidate.candidate_id == bound,
                PhysicalPhase::Standby => candidate.candidate_id == bound,
                _ => unreachable!(),
            };
            if bound.is_none() || !expected_binding { return Ok(Route::Unavailable("initial replica binding changed")); }
            let peer = reg.peers().get(&candidate.source_node).context("initial physical source names an unknown peer")?;
            return Ok(Route::Peer { peer, claim: wire::WriterClaim {
                kind: wire::WriterClaimKind::InitialSource, database: db.into(), generation: candidate.generation,
                candidate_id: candidate.candidate_id.context("verified candidate lost identity")?,
                source_vm_id: candidate.source_vm_id, system_identifier: candidate.system_identifier,
                pg_major: candidate.pg_major, sender_node: local_node(reg)?,
            }});
        }
        return Ok(Route::Unavailable("physical candidate is not verified for writer routing"));
    }
    Ok(Route::Local)
}

fn local_node(reg: &SchemaRegistry) -> Result<String> {
    reg.replication_cfg().map(|c| c.node_name.clone()).context("writer routing requires a configured node identity")
}

pub(crate) async fn forward(mut client: ClientStream, startup: &[u8], peer: Peer, claim: wire::WriterClaim) -> Result<()> {
    if startup.len() > 10 * 1024 { bail!("startup packet too large for writer tunnel"); }
    let cancel_target = crate::cancel::CancelTarget::Host(peer.pg_host.clone(), peer.pg_port);
    let peer_client = PeerClient::new(peer, Duration::from_secs(10))?;
    if peer_client.verified_node_info().await?.node != peer_client.name() { bail!("writer peer identity mismatch"); }
    let upgraded = peer_client.writer_tunnel(&wire::WriterTunnelRequest { claim, startup: startup.to_vec() }).await?;
    let mut upgraded = crate::cancel::KeyCapture::new(upgraded, crate::cancel::global().clone(), cancel_target); // cancels relay one hop, to the splicing peer
    tokio::io::copy_bidirectional(&mut client, &mut upgraded).await.context("proxying writer tunnel")?;
    Ok(())
}

pub(crate) async fn accept(reg: &Arc<SchemaRegistry>, authenticated_admin: bool, request: &mut Request) -> Response {
    // Unlike ordinary dashboard pages, this transport is never available in
    // the dashboard's explicitly-open mode.
    if !authenticated_admin { return StatusCode::UNAUTHORIZED.into_response(); }
    match tokio::time::timeout(Duration::from_secs(15), accept_inner(reg, request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::GATEWAY_TIMEOUT.into_response(),
    }
}

async fn accept_inner(reg: &Arc<SchemaRegistry>, request: &mut Request) -> Response {
    if request.headers().get(header::UPGRADE).and_then(|v| v.to_str().ok()) != Some("pg-fc-sql/1")
        || !request.headers().get(header::CONNECTION).and_then(|v| v.to_str().ok()).is_some_and(|v| v.split(',').any(|x| x.trim().eq_ignore_ascii_case("upgrade"))) {
        return (StatusCode::BAD_REQUEST, "writer tunnel requires pg-fc-sql/1 upgrade").into_response();
    }
    let on_upgrade = hyper::upgrade::on(&mut *request);
    let body = std::mem::take(request.body_mut());
    let bytes = match to_bytes(body, MAX_TUNNEL_JSON).await { Ok(v) => v, Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response() };
    let req: wire::WriterTunnelRequest = match serde_json::from_slice(&bytes) { Ok(v) => v, Err(_) => return (StatusCode::BAD_REQUEST, "invalid writer tunnel request").into_response() };
    let info = match crate::startup::parse_forwarded(&req.startup) { Ok(v) => v, Err(_) => return (StatusCode::BAD_REQUEST, "invalid PostgreSQL startup").into_response() };
    if info.database != req.claim.database || !is_routable_tenant(reg, &info, &info.database)
        || reg.authorize_route(&info.user, &info.database, false).as_deref() != Ok(info.database.as_str()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let bound = match reg.bound_vm_id(&info.database) { Some(id) => id, None => return StatusCode::CONFLICT.into_response() };
    if validate_destination(reg, &req.claim, &bound).is_err() { return StatusCode::CONFLICT.into_response(); }
    if validate_sender(reg, &req.claim).await.is_err() { return StatusCode::FORBIDDEN.into_response(); }
    let guard = match reg.checkout(&info.database).await { Ok(g) => g, Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    if validate_destination(reg, &req.claim, &guard.entry().sandbox_id()).is_err() {
        return StatusCode::CONFLICT.into_response();
    }
    tokio::spawn(async move {
        match tokio::time::timeout(Duration::from_secs(10), on_upgrade).await {
            Ok(Ok(upgraded)) => {
                if let Err(error) = crate::proxy::splice(TokioIo::new(upgraded), guard.entry(), &req.startup).await {
                    tracing::warn!(%error, "peer SQL tunnel closed with an error");
                }
            }
            _ => tracing::warn!("peer SQL tunnel upgrade failed or timed out"),
        }
    });
    Response::builder().status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "upgrade").header(header::UPGRADE, "pg-fc-sql/1")
        .body(axum::body::Body::empty()).unwrap()
}

async fn validate_sender(reg: &SchemaRegistry, claim: &wire::WriterClaim) -> Result<()> {
    let peer = reg.peers().get(&claim.sender_node).context("unknown forwarding peer")?;
    // Activation already durably verified the source's identity-bound grant.
    // Do not require the retired source guest to be running for SQL routing.
    if claim.kind == wire::WriterClaimKind::Activation { return Ok(()); }
    let client = PeerClient::new(peer, Duration::from_secs(5))?;
    let info = client.verified_node_info().await?;
    if info.node != claim.sender_node { bail!("forwarding peer identity mismatch"); }
    match claim.kind {
        wire::WriterClaimKind::InitialSource => {
            let rec = client.physical_status(&claim.database).await?;
            if !matches!(rec.phase.as_str(), "verified" | "standbybinding" | "standby") || rec.generation != claim.generation
                || rec.candidate_id.as_deref() != Some(claim.candidate_id.as_str())
                || rec.source_node != local_node(reg)? || rec.source_vm_id != claim.source_vm_id
                || rec.system_identifier != claim.system_identifier || rec.pg_major != claim.pg_major {
                bail!("sender no longer owns the initial-source preparation");
            }
        }
        wire::WriterClaimKind::Activation => unreachable!("activation validated locally"),
    }
    Ok(())
}

pub(crate) fn validate_destination(reg: &SchemaRegistry, claim: &wire::WriterClaim, checked_out: &str) -> Result<()> {
    reg.database_maintenance().check(&claim.database)?;
    if reg.bound_vm_id(&claim.database).as_deref() != Some(checked_out) || !reg.physical_admission_ready(&claim.database)
        || reg.replication().is_fenced(&claim.database) {
        bail!("writer binding changed or admission closed");
    }
    match claim.kind {
        wire::WriterClaimKind::Activation => {
            let rec = reg.physical().get(&claim.database).context("no activated candidate")?;
            if rec.phase != PhysicalPhase::Activated || rec.generation != claim.generation
                || rec.candidate_id.as_deref() != Some(claim.candidate_id.as_str()) || checked_out != claim.candidate_id
                || rec.source_node != claim.sender_node || rec.source_vm_id != claim.source_vm_id
                || rec.system_identifier != claim.system_identifier || rec.pg_major != claim.pg_major
                || reg.physical_sources().get(&claim.database).is_some_and(|s| s.source_vm_id == checked_out && (s.handoff.is_some() || s.fence.is_some())) {
                bail!("activation writer claim mismatch");
            }
        }
        wire::WriterClaimKind::InitialSource => {
            let source = reg.physical_sources().get(&claim.database).context("no matching physical source preparation")?;
            let logical = reg.replication().get(&claim.database).context("initial source lost logical pairing")?;
            // Physical ownership is authoritative after preparation. Retiring
            // the logical subscriber/slot must not revoke the physical writer.
            if source.generation != claim.generation || source.predecessor.is_some()
                || source.source_vm_id != claim.source_vm_id || checked_out != claim.source_vm_id
                || source.system_identifier != claim.system_identifier || source.pg_major != claim.pg_major
                || source.peer != claim.sender_node || source.handoff.is_some() || source.fence.is_some()
                || logical.role != Role::Primary || logical.peer != source.peer {
                bail!("initial source writer claim mismatch");
            }
        }
    }
    Ok(())
}
