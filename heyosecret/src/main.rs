use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Query, State};
use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

// The platform UI kit — tokens, the theme cookie and forwarded identity —
// shared with app-lb, app-obs, ci and artifacts. Included by path rather than
// depended on as a crate: this crate is edition 2021 and two of the others are
// 2024, and the shared module is written to compile as both. See `ui/README.md`.
#[path = "../../ui/ui.rs"]
pub mod heyo_ui;
mod auth;
mod config;
mod crypto;
mod dashboard;
mod models;
mod store;

use config::Config;
use crypto::random_secret_bytes;
use models::{
    ErrorResponse, ListSecretsResponse, PutSecretRequest, ReadSecretRequest, RevokeSecretRequest,
    RotateRandomRequest,
};
use store::{PutSecretInput, SecretStore};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    store: SecretStore,
    /// Where the theme cookie is written and under what name — resolved once at
    /// startup from `HEYOSECRET_UI_COOKIE_*`, else the fleet-wide `HEYO_UI_*`.
    /// Set the same parent domain here as in app-lb's `auth.cookie_domain` and
    /// one choice of light or dark covers every app in the fleet.
    ui_cookies: Arc<crate::heyo_ui::CookieConfig>,
}

#[derive(Debug, Deserialize)]
struct PathQuery {
    path: String,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    prefix: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let config = Arc::new(Config::load()?);
    let store = SecretStore::connect(&config).await?;
    let port = config.server_port;

    let dashboard_enabled = config.dashboard_enabled();
    let state = AppState {
        config,
        store,
        ui_cookies: Arc::new(crate::heyo_ui::CookieConfig::from_env("HEYOSECRET")),
    };

    // Machine-facing JSON API, authenticated by the shared internal API key.
    // The permissive CORS policy applies only to these routes.
    let api = Router::new()
        .route("/health", get(health_check))
        .route("/v1/secrets/read", post(read_secret))
        .route("/v1/secrets/write", post(write_secret))
        .route("/v1/secrets/rotate-random", post(rotate_random))
        .route("/v1/secrets/revoke", post(revoke_secret))
        .route("/v1/secrets/metadata", get(secret_metadata))
        .route("/v1/secrets/history", get(secret_history))
        .route("/v1/secrets", get(list_secrets))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any),
        );

    // Browser-facing dashboard, authenticated by an admin-password session
    // cookie. Kept same-origin (no permissive CORS) and mounted separately.
    let app = api.merge(dashboard::routes()).with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    info!("HeyoSecret listening on {}", listener.local_addr()?);
    if dashboard_enabled {
        info!("Dashboard enabled at / (admin-password login)");
    } else {
        info!("Dashboard disabled (set HEYOSECRET_ADMIN_PASSWORD to enable)");
    }
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> impl IntoResponse {
    health_response(std::env::var("HEYOSECRET_REVISION").ok())
}

fn health_response(revision: Option<String>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    if let Some(value) = revision.and_then(|value| HeaderValue::from_str(&value).ok()) {
        headers.insert("x-heyo-revision", value);
    }
    (headers, Json(json!({ "status": "ok" })))
}

async fn read_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ReadSecretRequest>,
) -> impl IntoResponse {
    if let Err(status) = require_internal_api_key(&state, &headers) {
        return error(status, "Unauthorized");
    }
    match state.store.read_secret(&request.path, request.version).await {
        Ok(value) => (StatusCode::OK, Json(json!(value))).into_response(),
        Err(err) => error(StatusCode::NOT_FOUND, err.to_string()),
    }
}

async fn write_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PutSecretRequest>,
) -> impl IntoResponse {
    if let Err(status) = require_internal_api_key(&state, &headers) {
        return error(status, "Unauthorized");
    }
    let value = match base64::engine::general_purpose::STANDARD.decode(&request.value_base64) {
        Ok(value) => value,
        Err(_) => return error(StatusCode::BAD_REQUEST, "valueBase64 is not valid base64"),
    };
    let input = PutSecretInput {
        path: request.path,
        value,
        owner: request.owner,
        description: request.description,
        tags: Some(request.tags),
        read_access: Some(request.read_access),
        write_access: Some(request.write_access),
        metadata: request.metadata,
        actor: request.actor,
    };
    match state.store.put_secret(input).await {
        Ok(value) => (StatusCode::OK, Json(json!(value))).into_response(),
        Err(err) => error(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

async fn rotate_random(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RotateRandomRequest>,
) -> impl IntoResponse {
    if let Err(status) = require_internal_api_key(&state, &headers) {
        return error(status, "Unauthorized");
    }
    if request.bytes == 0 || request.bytes > 4096 {
        return error(StatusCode::BAD_REQUEST, "bytes must be between 1 and 4096");
    }
    match state
        .store
        .rotate_random(
            &request.path,
            random_secret_bytes(request.bytes),
            request.actor,
            request.metadata,
        )
        .await
    {
        Ok(value) => (StatusCode::OK, Json(json!(value))).into_response(),
        Err(err) => error(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

async fn revoke_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevokeSecretRequest>,
) -> impl IntoResponse {
    if let Err(status) = require_internal_api_key(&state, &headers) {
        return error(status, "Unauthorized");
    }
    match state
        .store
        .revoke(&request.path, request.version, request.actor)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "revoked" }))).into_response(),
        Err(err) => error(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

async fn secret_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PathQuery>,
) -> impl IntoResponse {
    if let Err(status) = require_internal_api_key(&state, &headers) {
        return error(status, "Unauthorized");
    }
    match state.store.metadata(&query.path).await {
        Ok(value) => (StatusCode::OK, Json(json!(value))).into_response(),
        Err(err) => error(StatusCode::NOT_FOUND, err.to_string()),
    }
}

async fn secret_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PathQuery>,
) -> impl IntoResponse {
    if let Err(status) = require_internal_api_key(&state, &headers) {
        return error(status, "Unauthorized");
    }
    match state.store.history(&query.path).await {
        Ok(value) => (StatusCode::OK, Json(json!(value))).into_response(),
        Err(err) => error(StatusCode::NOT_FOUND, err.to_string()),
    }
}

async fn list_secrets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    if let Err(status) = require_internal_api_key(&state, &headers) {
        return error(status, "Unauthorized");
    }
    match state.store.list(query.prefix.as_deref()).await {
        Ok(secrets) => (StatusCode::OK, Json(json!(ListSecretsResponse { secrets }))).into_response(),
        Err(err) => error(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

fn require_internal_api_key(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let expected = state.config.internal_api_key.trim();
    let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    if token.as_bytes().ct_eq(expected.as_bytes()).into() {
        Ok(())
    } else {
        warn!("Invalid HeyoSecret internal API key");
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn error(status: StatusCode, message: impl Into<String>) -> axum::response::Response {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_reports_the_managed_release_revision() {
        let response = health_response(Some("release-sha".into())).into_response();
        assert_eq!(response.headers()["x-heyo-revision"], "release-sha");
    }
}
