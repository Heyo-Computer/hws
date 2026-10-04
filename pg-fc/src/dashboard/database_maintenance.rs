//! Authenticated, operator-driven database maintenance API.
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use super::{dedicated::ApiError, state::DashState};
use crate::database_maintenance::{Operation, Stage, execute};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Begin {
    pub id: String,
    pub database: String,
    pub destination: Option<String>,
    pub bound_vm: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advance {
    pub stage: Stage,
}

fn auth_required(st: &DashState) -> anyhow::Result<()> {
    anyhow::ensure!(
        st.cfg.basic_auth.is_some(),
        "database maintenance is disabled when dashboard Basic auth is not configured"
    );
    Ok(())
}
fn answer(result: anyhow::Result<Operation>) -> Response {
    match result {
        Ok(op) => Json(op).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: format!("{e:#}"),
            }),
        )
            .into_response(),
    }
}

pub async fn begin(State(st): State<DashState>, Json(req): Json<Begin>) -> Response {
    if let Err(e) = auth_required(&st) {
        return answer(Err(e));
    }
    answer(
        execute::begin(
            &st.registry,
            req.id,
            req.database,
            req.destination,
            req.bound_vm,
        )
        .await,
    )
}
pub async fn advance(
    State(st): State<DashState>,
    Path(id): Path<String>,
    Json(req): Json<Advance>,
) -> Response {
    if let Err(e) = auth_required(&st) {
        return answer(Err(e));
    }
    answer(execute::step(&st.registry, &id, req.stage).await)
}
pub async fn get(State(st): State<DashState>, Path(id): Path<String>) -> Response {
    if let Err(e) = auth_required(&st) {
        return answer(Err(e));
    }
    match st.registry.database_maintenance().get(&id) {
        Some(op) => Json(op).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "unknown database maintenance operation".into(),
            }),
        )
            .into_response(),
    }
}
pub async fn list(State(st): State<DashState>) -> Response {
    if let Err(e) = auth_required(&st) {
        return answer(Err(e));
    }
    Json(st.registry.database_maintenance().list()).into_response()
}
