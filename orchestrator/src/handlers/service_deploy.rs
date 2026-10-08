use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use heyosecret_client::{HeyoSecretClient, HeyoSecretClientOptions};
use sea_orm::{ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, Statement, TransactionTrait, Value as SeaValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth;
use crate::cloud_client::{self, CreateDeploymentRequest, MountConfig, PortMapping};
use crate::db;
use crate::handlers::service_discovery;
use crate::AppState;

const DEFAULT_HEALTH_TIMEOUT_SECONDS: u64 = 180;
const DEFAULT_DRAIN_SECONDS: u64 = 10;
const SERVICE_CANDIDATE_CREATE_TIMEOUT_SECONDS: u64 = 900;
const SERVICE_ROUTE_WRITE_TIMEOUT_SECONDS: u64 = 30;
const CANDIDATE_CLEANUP_TIMEOUT_SECONDS: u64 = 60;
const CANDIDATE_DIAGNOSTIC_TIMEOUT_SECONDS: u64 = 20;
const CANDIDATE_DIAGNOSTIC_MAX_BYTES: usize = 12 * 1024;
const SERVICE_CANDIDATE_EVENT_SUBSCRIBE_TIMEOUT_SECONDS: u64 = 10;
const SERVICE_CANDIDATE_STATUS_POLL_INTERVAL_SECONDS: u64 = 5;
const SERVICE_HEALTH_REQUEST_TIMEOUT_SECONDS: u64 = 5;
const SERVICE_HEALTH_MAX_BACKOFF_SECONDS: u64 = 10;
pub(super) const SERVICE_HEALTH_STABILIZATION_SECONDS: u64 = 10;
const SERVICE_REVISION_CHECK_TIMEOUT_SECONDS: u64 = 30;
const SERVICE_RETIREMENT_RECONCILE_INTERVAL_SECONDS: u64 = 15;
const MAX_SERVICE_REPLICAS: u16 = 16;
const DEFAULT_GIT_AUTH_TOKEN_SECRET_PATH: &str = "cicd/git-auth-token";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDeployRequest {
    pub service_id: String,
    pub user_id: String,
    #[serde(default, alias = "async")]
    pub async_deploy: bool,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub deployment_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub archive_id: Option<String>,
    #[serde(default)]
    pub archive_name: Option<String>,
    #[serde(default)]
    pub archive_bytes_base64: Option<String>,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_environment: Option<String>,
    /// Optional Cloud placement pool within `deploymentEnvironment`.
    #[serde(default)]
    pub placement_pool: Option<String>,
    #[serde(default = "default_driver")]
    pub driver: String,
    #[serde(default = "default_image")]
    pub image: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub port_mappings: Vec<PortMapping>,
    #[serde(default)]
    pub mounts: Vec<MountConfig>,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    #[serde(default)]
    pub env_refs: Vec<String>,
    #[serde(default)]
    pub start_command: Option<String>,
    #[serde(default)]
    pub working_directory: Option<String>,
    #[serde(default)]
    pub setup_hooks: Option<Vec<String>>,
    #[serde(default = "default_size_class")]
    pub size_class: String,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    #[serde(default = "default_health_path")]
    pub health_path: String,
    #[serde(default = "default_health_timeout_seconds")]
    pub health_timeout_seconds: u64,
    #[serde(default = "default_health_probe_timeout_seconds")]
    pub health_probe_timeout_seconds: u64,
    /// Desired healthy endpoint count. Omitting this field preserves the
    /// legacy single-candidate deploy behavior; setting it enables convergent
    /// rolling replacement.
    #[serde(default)]
    pub desired_replicas: Option<u16>,
    /// Optional region for each desired replica. When populated its length
    /// must equal `desiredReplicas`; rolling replacement preserves each slot.
    #[serde(default)]
    pub replica_regions: Vec<String>,
    #[serde(default = "default_true")]
    pub retire_previous: bool,
    #[serde(default)]
    pub retire_previous_async: bool,
    #[serde(default)]
    pub delete_previous: bool,
    #[serde(default = "default_drain_seconds")]
    pub drain_seconds: u64,
    #[serde(default)]
    pub route: Option<ServiceRouteRequest>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub revision_guard: Option<ServiceRevisionGuard>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceArchivePresignRequest {
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceArchiveFinalizeRequest {
    pub archive_id: String,
    pub user_id: String,
    pub deployment_id: String,
    #[serde(default)]
    pub archive_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRevisionGuard {
    pub repository_url: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub expected_sha: String,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRouteRequest {
    pub host: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub backend_url: Option<String>,
    #[serde(default)]
    pub entry_points: Option<Vec<String>>,
    #[serde(default)]
    pub cert_resolver: Option<String>,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default = "default_true")]
    pub strip_prefix: bool,
    #[serde(default)]
    pub pass_host_header: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDeploymentState {
    pub service_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_environment: Option<String>,
    pub active_deployment_id: Option<String>,
    pub active_archive_id: Option<String>,
    pub active_backend_url: Option<String>,
    pub previous_deployment_id: Option<String>,
    pub previous_archive_id: Option<String>,
    #[serde(default)]
    pub active_metadata: serde_json::Value,
    #[serde(default)]
    pub previous_metadata: Option<serde_json::Value>,
    #[serde(default = "default_desired_replicas")]
    pub desired_replicas: u16,
    #[serde(default)]
    pub replica_regions: Vec<String>,
    pub route: Option<ServiceRouteRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_backend_url: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
    /// Versioned endpoint membership consumed by app-lb. This is assembled from
    /// the normalized discovery tables when state is read; legacy scalar fields
    /// remain for existing service-route and maintenance consumers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<service_discovery::ServiceDiscoverySnapshot>,
}

#[derive(Debug, Clone)]
struct DiscoveryRoutedServiceRoute {
    service_id: String,
    route: ServiceRouteRequest,
    previous_route: ServiceRouteRequest,
    previous_backend_url: String,
    health_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceDeployResponse {
    service_id: String,
    deployment_id: String,
    traffic_management: &'static str,
    archive_id: Option<String>,
    backend_url: String,
    health_url: String,
    previous_deployment_id: Option<String>,
    previous_retired: bool,
    route_updated: bool,
    state: ServiceDeploymentState,
}

#[derive(Debug, Deserialize)]
struct SandboxLifecycleEnvelope {
    event_type: String,
    payload: SandboxLifecyclePayload,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SandboxLifecyclePayload {
    deployment_id: String,
    status: String,
    #[serde(default)]
    error: Option<String>,
}

pub async fn presign_service_archive(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<ServiceArchivePresignRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(status) = auth::require_internal_api_key(&headers, &state.config.internal_api_key) {
        return (status, Json(json!({ "error": "Unauthorized" })));
    }
    if request.user_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "userId is required" })),
        );
    }

    match cloud_client::presign_archive_upload(&state, &request.user_id, None).await {
        Ok(slot) => (
            StatusCode::OK,
            Json(json!({
                "archiveId": slot.archive_id,
                "uploadUrl": slot.upload_url,
            })),
        ),
        Err(error) => {
            warn!("failed to prepare service archive upload: {error:#}");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": error.to_string() })),
            )
        }
    }
}

pub async fn finalize_service_archive(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<ServiceArchiveFinalizeRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(status) = auth::require_internal_api_key(&headers, &state.config.internal_api_key) {
        return (status, Json(json!({ "error": "Unauthorized" })));
    }
    if request.archive_id.trim().is_empty()
        || request.user_id.trim().is_empty()
        || request.deployment_id.trim().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "archiveId, userId, and deploymentId are required"
            })),
        );
    }

    match cloud_client::finalize_archive_upload(
        &state,
        &request.archive_id,
        &request.user_id,
        &request.deployment_id,
        request.archive_name,
        None,
    )
    .await
    {
        Ok(archive) => (
            StatusCode::CREATED,
            Json(json!({
                "archiveId": archive.id,
                "sizeBytes": archive.size_bytes,
            })),
        ),
        Err(error) => {
            warn!(archive_id = request.archive_id, "failed to finalize service archive upload: {error:#}");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": error.to_string() })),
            )
        }
    }
}

pub async fn deploy_service(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(spec): Json<super::service_spec::ServiceSpecRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(status) = auth::require_internal_api_key(&headers, &state.config.internal_api_key) {
        return (status, Json(json!({ "error": "Unauthorized" })));
    }

    let mut request = match spec.into_internal() {
        Ok(request) => request,
        Err(message) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))),
    };

    if let Err((status, message)) = validate_service_deployment_request(&state, &request).await {
        return (status, Json(json!({ "error": message })));
    }
    let traffic_management = if request.desired_replicas.is_some() {
        "discovery-membership"
    } else {
        "direct-route"
    };

    if request.async_deploy {
        let service_id = match sanitize_service_id(&request.service_id) {
            Ok(service_id) => service_id,
            Err(error) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": error.to_string() }))),
        };
        let database = match db::get_db() {
            Ok(database) => database,
            Err(error) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error":error.to_string()}))),
        };
        let admission = match try_service_lifecycle_lock(database, &service_id).await {
            Ok(Some(tx)) => tx,
            _ => return (StatusCode::CONFLICT, Json(json!({"error":"Service lifecycle is busy"}))),
        };
        if let Err(error) = super::service_adoption::ensure_managed(&admission, &service_id).await {
            return (StatusCode::CONFLICT, Json(json!({"error":error.to_string()})));
        }
        let deployment_id = request
            .deployment_id
            .clone()
            .unwrap_or_else(|| format!("svc-{service_id}-{}", Uuid::new_v4()));
        request.deployment_id = Some(deployment_id.clone());
        let request_payload = service_deployment_request_metadata(&request);
        if let Err(error) = record_service_deployment_event(
            &state,
            &deployment_id,
            &service_id,
            "accepted",
            "running",
            "Service deployment accepted for asynchronous execution.",
            Some(request_payload),
            None,
            None,
        )
        .await
        {
            warn!(service_id, deployment_id, "failed to persist service deployment acceptance: {error:#}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to persist service deployment run" })),
            );
        }
        if let Err(error) = admission.commit().await {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error":error.to_string()})));
        }

        let async_state = state.clone();
        let async_service_id = service_id.clone();
        let async_deployment_id = deployment_id.clone();
        tokio::spawn(async move {
            if let Err(error) = deploy_service_inner(async_state.clone(), request).await {
                let message = format!("Service deployment failed: {error:#}");
                warn!(
                    service_id = %async_service_id,
                    deployment_id = %async_deployment_id,
                    "async service deployment failed: {error:#}"
                );
                let _ = record_service_deployment_event(
                    &async_state,
                    &async_deployment_id,
                    &async_service_id,
                    "failed",
                    "failed",
                    &message,
                    None,
                    None,
                    Some(error.to_string()),
                )
                .await;
            }
        });

        return (
            StatusCode::ACCEPTED,
            Json(json!({
                "serviceId": service_id,
                "deploymentId": deployment_id,
                "trafficManagement": traffic_management,
                "status": "running",
                "phase": "accepted",
                "statusUrl": format!("/orchestration/services/deployments/{deployment_id}"),
            })),
        );
    }

    match deploy_service_inner(state, request).await {
        Ok(response) => (StatusCode::OK, Json(json!(response))),
        Err(error) => {
            warn!("service deploy failed: {error:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": error.to_string() })),
            )
        }
    }
}

pub async fn get_service_deployment_run(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(deployment_id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(status) = auth::require_internal_api_key(&headers, &state.config.internal_api_key) {
        return (status, Json(json!({ "error": "Unauthorized" })));
    }

    match read_service_deployment_run(&state, &deployment_id).await {
        Ok(Some(run)) => (StatusCode::OK, Json(run)),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Service deployment run not found" })),
        ),
        Err(error) => {
            warn!(deployment_id, "failed to read service deployment run: {error:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": error.to_string() })),
            )
        }
    }
}

pub async fn get_service_deployment(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(service_id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(status) = auth::require_internal_api_key(&headers, &state.config.internal_api_key) {
        return (status, Json(json!({ "error": "Unauthorized" })));
    }

    match read_service_state(&state, &service_id).await {
        Ok(state) => (StatusCode::OK, Json(json!(state))),
        Err(error) => {
            warn!("failed to read service deployment state: {error:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": error.to_string() })),
            )
        }
    }
}

async fn deploy_service_inner(
    state: AppState,
    mut request: ServiceDeployRequest,
) -> Result<ServiceDeployResponse> {
    request.deployment_environment = request.deployment_environment.as_deref().map(str::trim).map(str::to_owned);
    validate_service_deployment_request(&state, &request)
        .await
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    let service_id = sanitize_service_id(&request.service_id)?;
    // Keep retirement and deployment mutually exclusive across Orchestrator instances.
    // This transaction only owns the advisory lock; rollout progress remains durable
    // through the ordinary connections even if this process exits.
    let _guard = try_service_lifecycle_lock(db::get_db()?, &service_id)
        .await?
        .with_context(|| format!("service {service_id} has a deployment or retirement in progress"))?;
    super::service_adoption::ensure_managed(&_guard, &service_id).await?;
    super::regional_rollout::ensure_no_regional_rollout(db::get_db()?, &service_id).await?;
    super::regional_policy::require_legacy_topology(db::get_db()?, &service_id).await?;
    let baseline = read_service_state(&state,&service_id).await?;
    anyhow::ensure!(!request.retire_previous
        || super::instance_http::Contract::from_metadata(&baseline.active_metadata["source"])?.is_none(),
        "application lifecycle replacement requires a managed regional operation");
    bind_deployment_environment_identity(
        &state,
        &service_id,
        request.deployment_environment.as_deref(),
    )
    .await?;
    if request.desired_replicas.is_none() {
        return deploy_service_candidate(state, request, None).await;
    }
    let rollout_id = request
        .deployment_id
        .clone()
        .unwrap_or_else(|| format!("svc-{service_id}-{}", Uuid::new_v4()));
    request.deployment_id = Some(rollout_id.clone());
    claim_service_rollout(
        &service_id,
        &rollout_id,
        request.desired_replicas.unwrap_or(1),
    )
    .await?;

    let result = deploy_service_rollout(state, request).await;
    let (status, error_message) = match &result {
        Ok(_) => ("passed", None),
        Err(error) => ("failed", Some(format!("{error:#}"))),
    };
    if let Err(error) = finish_service_rollout(&rollout_id, status, error_message).await {
        warn!(rollout_id, "failed to persist terminal service rollout state: {error:#}");
    }
    result
}

pub(super) async fn validate_service_deployment_request(
    state: &AppState,
    request: &ServiceDeployRequest,
) -> std::result::Result<(), (StatusCode, String)> {
    let service_id = sanitize_service_id(&request.service_id)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let discovery_routed = state.config.service_uses_discovery_routing(&service_id);

    if request.deployment_environment.as_deref().is_some_and(|value| value.trim().is_empty()) {
        return Err((StatusCode::BAD_REQUEST, "deploymentEnvironment must not be empty".to_string()));
    }
    if request.deployment_environment.as_deref().is_some_and(|value| value.trim().chars().count() > 64) {
        return Err((StatusCode::BAD_REQUEST, "deploymentEnvironment must be at most 64 characters".to_string()));
    }
    if request.placement_pool.is_some() && request.deployment_environment.is_none() {
        return Err((StatusCode::BAD_REQUEST, "placementPool requires deploymentEnvironment".to_string()));
    }

    if request
        .placement_pool
        .as_deref()
        .is_some_and(|pool| pool.trim().is_empty())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "placementPool must not be empty".to_string(),
        ));
    }
    if request
        .placement_pool
        .as_deref()
        .is_some_and(|pool| pool.trim().chars().count() > 64)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "placementPool must be at most 64 characters".to_string(),
        ));
    }

    validate_service_traffic_mode(
        &service_id,
        request.desired_replicas,
        request.route.is_some(),
        discovery_routed,
    )?;

    if let Some(desired_replicas) = request.desired_replicas {
        if !request.replica_regions.is_empty()
            && request.replica_regions.len() != usize::from(desired_replicas)
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "replicaRegions must contain exactly {desired_replicas} entries when provided"
                ),
            ));
        }
        if request
            .replica_regions
            .iter()
            .any(|region| region.trim().is_empty())
        {
            return Err((
                StatusCode::BAD_REQUEST,
                "replicaRegions entries must not be empty".to_string(),
            ));
        }
        let route = request.route.as_ref().expect("traffic mode requires route");
        if super::host_ingress::enabled(state, &service_id) {
            super::host_ingress::validate(state, &service_id, route)
                .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
            if request.replica_regions.is_empty() {
                super::regional_observers::validate_ingress_observers(state, &service_id)
                    .map(drop)
            } else {
                validate_regional_observers(state, &service_id, &request.replica_regions).await
            }
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
        }
        if route.path_prefix.as_deref().is_none_or(str::is_empty) {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "discovery-routed service ingress requires route.pathPrefix".to_string(),
            ));
        }
        if route.strip_prefix {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "discovery-routed service ingress must preserve its prefix for app-lb"
                    .to_string(),
            ));
        }
    } else if !request.replica_regions.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "replicaRegions requires desiredReplicas".to_string(),
        ));
    }

    Ok(())
}

pub(super) fn validate_service_traffic_mode(
    service_id: &str,
    desired_replicas: Option<u16>,
    has_ingress_route: bool,
    discovery_routed: bool,
) -> std::result::Result<(), (StatusCode, String)> {
    match desired_replicas {
        Some(desired_replicas)
            if desired_replicas == 0 || desired_replicas > MAX_SERVICE_REPLICAS =>
        {
            Err((
                StatusCode::BAD_REQUEST,
                format!("desiredReplicas must be between 1 and {MAX_SERVICE_REPLICAS}"),
            ))
        }
        Some(_) if service_id == "app-lb" => Err((
            StatusCode::CONFLICT,
            "app-lb cannot use its own discovery membership for traffic management".to_string(),
        )),
        Some(_) if !discovery_routed => Err((
            StatusCode::CONFLICT,
            format!(
                "service {service_id} is not configured in ORCHESTRATOR_DISCOVERY_ROUTED_SERVICES"
            ),
        )),
        Some(_) if !has_ingress_route => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "desiredReplicas requires the stable ingress route that Orchestrator will move to app-lb"
                .to_string(),
        )),
        None if discovery_routed => Err((
            StatusCode::CONFLICT,
            format!("service {service_id} is discovery-routed and requires desiredReplicas"),
        )),
        _ => Ok(()),
    }
}

async fn claim_service_rollout(
    service_id: &str,
    rollout_id: &str,
    desired_replicas: u16,
) -> Result<()> {
    if desired_replicas == 0 || desired_replicas > MAX_SERVICE_REPLICAS {
        anyhow::bail!(
            "desiredReplicas must be between 1 and {MAX_SERVICE_REPLICAS}"
        );
    }
    let db = db::get_db()?;
    let claimed = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO service_rollouts (
                service_id, rollout_id, desired_replicas, status, stage, lease_expires_at
             ) VALUES ($1, $2, $3, 'running', 'accepted', NOW() + INTERVAL '1 hour')
             ON CONFLICT (service_id) DO UPDATE SET
                rollout_id = EXCLUDED.rollout_id,
                desired_replicas = EXCLUDED.desired_replicas,
                target_revision = NULL,
                status = 'running',
                stage = 'accepted',
                error_message = NULL,
                lease_expires_at = NOW() + INTERVAL '1 hour',
                created_at = NOW(),
                updated_at = NOW(),
                completed_at = NULL
             WHERE service_rollouts.status IN ('passed', 'failed')
                OR service_rollouts.lease_expires_at <= NOW()
             RETURNING rollout_id",
            vec![
                service_id.into(),
                rollout_id.into(),
                i32::from(desired_replicas).into(),
            ],
        ))
        .await
        .context("failed to claim service rollout")?;
    if claimed.is_none() {
        let active = db
            .query_one(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT rollout_id, stage FROM service_rollouts
                 WHERE service_id = $1 AND status = 'running' AND lease_expires_at > NOW()",
                [service_id.into()],
            ))
            .await?;
        if let Some(active) = active {
            let active_rollout: String = active.try_get("", "rollout_id")?;
            let active_stage: String = active.try_get("", "stage")?;
            anyhow::bail!(
                "service {service_id} already has rollout {active_rollout} in stage {active_stage}"
            );
        }
        anyhow::bail!("service {service_id} rollout could not be claimed");
    }
    Ok(())
}

async fn finish_service_rollout(
    rollout_id: &str,
    status: &str,
    error_message: Option<String>,
) -> Result<()> {
    let db = db::get_db()?;
    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE service_rollouts
         SET status = $2,
             stage = CASE WHEN $2 = 'passed' THEN 'completed' ELSE 'failed' END,
             error_message = $3,
             completed_at = NOW(),
             updated_at = NOW()
         WHERE rollout_id = $1",
        vec![rollout_id.into(), status.into(), error_message.into()],
    ))
    .await
    .context("failed to finish service rollout")?;
    Ok(())
}

async fn deploy_service_rollout(
    state: AppState,
    mut request: ServiceDeployRequest,
) -> Result<ServiceDeployResponse> {
    let service_id = sanitize_service_id(&request.service_id)?;
    let desired_replicas = request.desired_replicas.unwrap_or(1);
    if desired_replicas == 0 || desired_replicas > MAX_SERVICE_REPLICAS {
        anyhow::bail!(
            "desiredReplicas must be between 1 and {MAX_SERVICE_REPLICAS}"
        );
    }
    let rollout_id = request
        .deployment_id
        .clone()
        .unwrap_or_else(|| format!("svc-{service_id}-{}", Uuid::new_v4()));
    request.deployment_id = Some(rollout_id.clone());

    let archive_bytes = load_archive_bytes(&state, &request).await?;
    let target_revision = format!("{:x}", Sha256::digest(&archive_bytes));
    drop(archive_bytes);

    let rollout_state = read_service_state(&state, &service_id).await?;
    if let (Some(deployment_id), Some(region)) = (
        rollout_state.active_deployment_id.as_deref(),
        rollout_state
            .active_metadata
            .pointer("/runtime/region")
            .and_then(serde_json::Value::as_str),
    ) {
        service_discovery::set_endpoint_region(&service_id, deployment_id, region).await?;
    }
    let initial_snapshot = service_discovery::read_snapshot(&service_id).await?;
    let initial_previous_ids = rollout_old_endpoints(
        initial_snapshot.as_ref(),
        &target_revision,
    )
    .into_iter()
    .map(|endpoint| endpoint.deployment_id.clone())
    .collect::<Vec<_>>();
    let previous_deployment_id = initial_previous_ids.first().cloned();

    record_service_deployment_event(
        &state,
        &rollout_id,
        &service_id,
        "rollout-started",
        "running",
        "Reconciling service replicas to the requested revision.",
        Some(service_deployment_request_metadata(&request)),
        Some(json!({
            "desiredReplicas": desired_replicas,
            "trafficManagement": "discovery-membership",
            "targetRevision": target_revision,
            "observedReplicas": active_endpoint_count(initial_snapshot.as_ref()),
            "replicaRegions": request.replica_regions,
            "placementPool": request.placement_pool,
        })),
        None,
    )
    .await?;

    let candidate_regions = if request.replica_regions.is_empty() {
        vec![
            request.region.clone();
            rollout_candidates_needed(
                initial_snapshot.as_ref(),
                &target_revision,
                desired_replicas,
                request.retire_previous,
            )
        ]
    } else {
        rollout_candidate_regions(
            initial_snapshot.as_ref(),
            &target_revision,
            &request.replica_regions,
            request.retire_previous,
        )
    };
    let candidates_needed = candidate_regions.len();
    let mut route_updated = false;
    let mut ingress_backend_url = rollout_state.ingress_backend_url.clone();
    if active_endpoint_count(initial_snapshot.as_ref()) > 0 {
        ingress_backend_url = Some(cutover_service_ingress_to_app_lb(
            &state,
            &service_id,
            &rollout_id,
            request.route.as_ref().expect("validated discovery route"),
            &request.health_path,
            request.health_timeout_seconds,
        )
        .await?);
        route_updated = true;
    }
    let mut last_candidate = None;
    let mut retirement_started = HashSet::new();

    for (candidate_index, candidate_region) in candidate_regions.into_iter().enumerate() {
        let snapshot = service_discovery::read_snapshot(&service_id).await?;
        let replacement = if request.retire_previous
            && active_endpoint_count(snapshot.as_ref()) >= usize::from(desired_replicas)
        {
            if request.replica_regions.is_empty() {
                rollout_old_endpoints(snapshot.as_ref(), &target_revision)
                    .into_iter()
                    .find(|endpoint| {
                        endpoint.health_status == "healthy" && !endpoint.draining
                    })
                    .cloned()
            } else {
                rollout_replacement(
                    snapshot.as_ref(),
                    &target_revision,
                    &candidate_region,
                    &request.replica_regions,
                    desired_replicas,
                )
            }
        } else {
            None
        };
        let placement_exclusions = rolling_placement_exclusions(
            snapshot.as_ref(),
            replacement.as_ref().map(|endpoint| endpoint.deployment_id.as_str()),
        );
        let candidate_id = rollout_candidate_id(&rollout_id, candidate_index + 1);
        record_service_deployment_event(
            &state,
            &rollout_id,
            &service_id,
            "rollout-candidate",
            "running",
            "Creating the next rolling service candidate.",
            None,
            Some(json!({
                "candidateDeploymentId": candidate_id,
                "candidateNumber": candidate_index + 1,
                "candidateCount": candidates_needed,
                "candidateRegion": candidate_region,
                "replacementDeploymentId": replacement.as_ref().map(|endpoint| &endpoint.deployment_id),
                "excludedBackendServerIds": placement_exclusions.clone(),
            })),
            None,
        )
        .await?;

        let archive_bytes_base64 = request.archive_bytes_base64.take();
        let mut candidate_request = request.clone();
        candidate_request.deployment_id = Some(candidate_id.clone());
        candidate_request.archive_bytes_base64 = archive_bytes_base64;
        candidate_request.region = candidate_region;
        candidate_request.retire_previous = false;
        candidate_request.retire_previous_async = false;
        candidate_request.route = None;
        let mut candidate = deploy_service_candidate(
            state.clone(),
            candidate_request,
            Some(placement_exclusions),
        )
        .await
        .with_context(|| {
            format!(
                "rolling candidate {candidate_id} failed; existing healthy replicas remain active"
            )
        })?;
        request.archive_id = candidate.archive_id.clone().or(request.archive_id);
        candidate.state.desired_replicas = desired_replicas;
        candidate.state.replica_regions = request.replica_regions.clone();
        candidate.state.route = request.route.clone();
        candidate.state.ingress_backend_url = ingress_backend_url.clone();
        write_service_state(&state, &candidate.state).await?;
        record_service_deployment_event(
            &state,
            &rollout_id,
            &service_id,
            "rollout-candidate-healthy",
            "running",
            "Rolling service candidate is healthy and published.",
            None,
            Some(json!({
                "candidateDeploymentId": candidate_id,
                "readyReplicas": active_endpoint_count(
                    service_discovery::read_snapshot(&service_id).await?.as_ref()
                ),
            })),
            None,
        )
        .await?;
        last_candidate = Some(candidate);

        if let Some(replacement) = replacement {
            retire_rollout_endpoint(
                &state,
                &service_id,
                &rollout_id,
                &replacement.deployment_id,
                request.drain_seconds,
                request.delete_previous,
                request.retire_previous_async,
            )
            .await?;
            retirement_started.insert(replacement.deployment_id);
        }
    }

    let candidate_snapshot = service_discovery::read_snapshot(&service_id).await?;
    if !request.replica_regions.is_empty()
        && !target_regions_covered(
            candidate_snapshot.as_ref(),
            &target_revision,
            &request.replica_regions,
        )
    {
        anyhow::bail!(
            "service rollout did not establish the requested regional replica placement"
        );
    }
    if !route_updated {
        ingress_backend_url = Some(cutover_service_ingress_to_app_lb(
            &state,
            &service_id,
            &rollout_id,
            request.route.as_ref().expect("validated discovery route"),
            &request.health_path,
            request.health_timeout_seconds,
        )
        .await?);
        route_updated = true;
    }

    if request.retire_previous {
        for endpoint in rollout_old_endpoints(
            service_discovery::read_snapshot(&service_id).await?.as_ref(),
            &target_revision,
        ) {
            if retirement_started.contains(&endpoint.deployment_id) {
                continue;
            }
            retire_rollout_endpoint(
                &state,
                &service_id,
                &rollout_id,
                &endpoint.deployment_id,
                request.drain_seconds,
                request.delete_previous,
                request.retire_previous_async,
            )
            .await?;
        }

        let current_state = read_service_state(&state, &service_id).await?;
        let snapshot = service_discovery::read_snapshot(&service_id).await?;
        let excess_targets = if request.replica_regions.is_empty() {
            let mut endpoints = rollout_target_endpoints(snapshot.as_ref(), &target_revision);
            endpoints.sort_by_key(|endpoint| {
                (
                    current_state.active_deployment_id.as_deref()
                        == Some(endpoint.deployment_id.as_str()),
                    endpoint.deployment_id.clone(),
                )
            });
            let excess = endpoints
                .len()
                .saturating_sub(usize::from(desired_replicas));
            endpoints
                .into_iter()
                .take(excess)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            excess_target_endpoints(
                snapshot.as_ref(),
                &target_revision,
                &request.replica_regions,
                current_state.active_deployment_id.as_deref(),
            )
        };
        for endpoint in excess_targets {
            retire_rollout_endpoint(
                &state,
                &service_id,
                &rollout_id,
                &endpoint.deployment_id,
                request.drain_seconds,
                request.delete_previous,
                request.retire_previous_async,
            )
            .await?;
        }
    }

    let final_snapshot = service_discovery::read_snapshot(&service_id).await?;
    let ready_replicas = active_endpoint_count(final_snapshot.as_ref());
    let target_replicas = target_endpoint_count(final_snapshot.as_ref(), &target_revision);
    if ready_replicas < usize::from(desired_replicas)
        || (request.retire_previous && target_replicas != usize::from(desired_replicas))
        || (!request.replica_regions.is_empty()
            && !target_regions_ready(
                final_snapshot.as_ref(),
                &target_revision,
                &request.replica_regions,
            ))
    {
        anyhow::bail!(
            "service rollout ended with {ready_replicas} ready replicas ({target_replicas} at the target revision); {desired_replicas} required"
        );
    }
    let mut current_state = read_service_state(&state, &service_id).await?;
    if !final_snapshot.as_ref().is_some_and(|snapshot| {
        snapshot.endpoints.iter().any(|endpoint| {
            endpoint.deployment_id == current_state.active_deployment_id.as_deref().unwrap_or("")
                && endpoint.health_status == "healthy"
                && !endpoint.draining
        })
    }) {
        let retained = final_snapshot
            .as_ref()
            .and_then(|snapshot| {
                snapshot.endpoints.iter().find(|endpoint| {
                    endpoint.health_status == "healthy"
                        && !endpoint.draining
                        && (!request.retire_previous
                            || endpoint.revision.as_deref() == Some(target_revision.as_str()))
                })
            })
            .context("service has no retained healthy endpoint after rollout convergence")?;
        current_state.active_deployment_id = Some(retained.deployment_id.clone());
        current_state.active_backend_url = Some(retained.url.clone());
    }
    current_state.desired_replicas = desired_replicas;
    current_state.deployment_environment = request.deployment_environment.clone();
    current_state.replica_regions = request.replica_regions.clone();
    current_state.route = request.route.clone();
    current_state.ingress_backend_url = ingress_backend_url;
    current_state.discovery = final_snapshot;
    write_service_state(&state, &current_state).await?;

    let (archive_id, backend_url, health_url) = match last_candidate {
        Some(candidate) => (
            candidate.archive_id,
            candidate.backend_url,
            candidate.health_url,
        ),
        None => {
            let backend_url = current_state
                .active_backend_url
                .clone()
                .context("service has no active backend after rollout convergence")?;
            (
                current_state.active_archive_id.clone(),
                backend_url.clone(),
                join_url_path(&backend_url, &request.health_path),
            )
        }
    };
    let response = ServiceDeployResponse {
        service_id: service_id.clone(),
        deployment_id: rollout_id.clone(),
        traffic_management: "discovery-membership",
        archive_id,
        backend_url,
        health_url,
        previous_deployment_id,
        previous_retired: request.retire_previous
            && !request.retire_previous_async
            && !initial_previous_ids.is_empty(),
        route_updated,
        state: current_state,
    };
    record_service_deployment_event(
        &state,
        &rollout_id,
        &service_id,
        "completed",
        "passed",
        "Service rollout converged to the requested healthy replica count.",
        None,
        Some(serde_json::to_value(&response).unwrap_or_else(|_| json!({}))),
        None,
    )
    .await?;
    Ok(response)
}

async fn retire_rollout_endpoint(
    state: &AppState,
    service_id: &str,
    rollout_id: &str,
    deployment_id: &str,
    drain_seconds: u64,
    delete_previous: bool,
    retire_async: bool,
) -> Result<()> {
    record_service_deployment_event(
        state,
        rollout_id,
        service_id,
        "rollout-drain",
        "running",
        "Draining one previous service replica.",
        None,
        Some(json!({ "previousDeploymentId": deployment_id })),
        None,
    )
    .await?;
    let retired = if retire_async {
        begin_previous_service_deployment_retirement(
            state,
            service_id,
            rollout_id,
            deployment_id,
            drain_seconds,
            delete_previous,
        )
        .await
    } else {
        retire_previous_service_deployment(
            state,
            service_id,
            rollout_id,
            deployment_id,
            drain_seconds,
            delete_previous,
        )
        .await
    };
    if !retired {
        anyhow::bail!(
            "failed to schedule retirement of previous service replica {deployment_id}; rollout stopped with healthy replacements still serving"
        );
    }
    Ok(())
}

fn rollout_candidate_id(rollout_id: &str, candidate_number: usize) -> String {
    format!("{rollout_id}-r{candidate_number}")
}

fn active_endpoint_count(
    snapshot: Option<&service_discovery::ServiceDiscoverySnapshot>,
) -> usize {
    snapshot
        .map(|snapshot| {
            snapshot
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.health_status == "healthy" && !endpoint.draining)
                .count()
        })
        .unwrap_or_default()
}

fn target_endpoint_count(
    snapshot: Option<&service_discovery::ServiceDiscoverySnapshot>,
    target_revision: &str,
) -> usize {
    rollout_target_endpoints(snapshot, target_revision).len()
}

fn rollout_candidates_needed(
    snapshot: Option<&service_discovery::ServiceDiscoverySnapshot>,
    target_revision: &str,
    desired_replicas: u16,
    replace_previous: bool,
) -> usize {
    let observed = if replace_previous {
        target_endpoint_count(snapshot, target_revision)
    } else {
        active_endpoint_count(snapshot)
    };
    usize::from(desired_replicas).saturating_sub(observed)
}

fn rollout_candidate_regions(
    snapshot: Option<&service_discovery::ServiceDiscoverySnapshot>,
    target_revision: &str,
    desired_regions: &[String],
    replace_previous: bool,
) -> Vec<String> {
    let mut desired_counts = HashMap::<&str, usize>::new();
    let mut region_order = Vec::<&str>::new();
    for region in desired_regions {
        if !desired_counts.contains_key(region.as_str()) {
            region_order.push(region);
        }
        *desired_counts.entry(region).or_default() += 1;
    }

    let mut active_counts = HashMap::<&str, usize>::new();
    let mut target_counts = HashMap::<&str, usize>::new();
    if let Some(snapshot) = snapshot {
        for endpoint in snapshot.endpoints.iter().filter(|endpoint| {
            endpoint.health_status == "healthy" && !endpoint.draining
        }) {
            let Some(region) = endpoint.region.as_deref() else {
                continue;
            };
            *active_counts.entry(region).or_default() += 1;
            if endpoint.revision.as_deref() == Some(target_revision) {
                *target_counts.entry(region).or_default() += 1;
            }
        }
    }

    let mut candidates = Vec::new();
    for region in &region_order {
        let region = *region;
        let desired = desired_counts[region];
        let active = active_counts.get(region).copied().unwrap_or_default();
        for _ in 0..desired.saturating_sub(active) {
            candidates.push(region.to_string());
        }
    }
    if replace_previous {
        for region in region_order {
            let desired = desired_counts[region];
            let active = active_counts.get(region).copied().unwrap_or_default();
            let target = target_counts.get(region).copied().unwrap_or_default();
            let capacity_candidates = desired.saturating_sub(active);
            for _ in 0..desired
                .saturating_sub(target)
                .saturating_sub(capacity_candidates)
            {
                candidates.push(region.to_string());
            }
        }
    }
    candidates
}

fn rollout_target_endpoints<'a>(
    snapshot: Option<&'a service_discovery::ServiceDiscoverySnapshot>,
    target_revision: &str,
) -> Vec<&'a service_discovery::ServiceDiscoveryEndpoint> {
    snapshot
        .map(|snapshot| {
            snapshot
                .endpoints
                .iter()
                .filter(|endpoint| {
                    endpoint.health_status == "healthy"
                        && !endpoint.draining
                        && endpoint.revision.as_deref() == Some(target_revision)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn rollout_old_endpoints<'a>(
    snapshot: Option<&'a service_discovery::ServiceDiscoverySnapshot>,
    target_revision: &str,
) -> Vec<&'a service_discovery::ServiceDiscoveryEndpoint> {
    let mut endpoints = snapshot
        .map(|snapshot| {
            snapshot
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.revision.as_deref() != Some(target_revision))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    endpoints.sort_by(|left, right| left.deployment_id.cmp(&right.deployment_id));
    endpoints
}

fn rolling_placement_exclusions(
    snapshot: Option<&service_discovery::ServiceDiscoverySnapshot>,
    replacement_deployment_id: Option<&str>,
) -> Vec<String> {
    let mut exclusions = snapshot
        .map(|snapshot| {
            snapshot
                .endpoints
                .iter()
                .filter(|endpoint| {
                    endpoint.health_status == "healthy"
                        && !endpoint.draining
                        && replacement_deployment_id != Some(endpoint.deployment_id.as_str())
                })
                .filter_map(|endpoint| endpoint.backend_server_id.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    exclusions.sort();
    exclusions.dedup();
    exclusions
}

fn rollout_replacement(
    snapshot: Option<&service_discovery::ServiceDiscoverySnapshot>,
    target_revision: &str,
    candidate_region: &str,
    desired_regions: &[String],
    desired_replicas: u16,
) -> Option<service_discovery::ServiceDiscoveryEndpoint> {
    let snapshot = snapshot?;
    let mut active = snapshot
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.health_status == "healthy" && !endpoint.draining)
        .collect::<Vec<_>>();
    if active.len() < usize::from(desired_replicas) {
        return None;
    }
    active.sort_by(|left, right| left.deployment_id.cmp(&right.deployment_id));

    if let Some(endpoint) = active.iter().find(|endpoint| {
        endpoint.region.as_deref() == Some(candidate_region)
            && endpoint.revision.as_deref() != Some(target_revision)
    }) {
        return Some((**endpoint).clone());
    }

    let mut desired_counts = HashMap::<&str, usize>::new();
    for region in desired_regions {
        *desired_counts.entry(region).or_default() += 1;
    }
    let mut active_counts = HashMap::<&str, usize>::new();
    for endpoint in &active {
        if let Some(region) = endpoint.region.as_deref() {
            *active_counts.entry(region).or_default() += 1;
        }
    }
    if let Some(endpoint) = active.iter().find(|endpoint| {
        endpoint.region.as_deref().is_some_and(|region| {
            active_counts.get(region).copied().unwrap_or_default()
                > desired_counts.get(region).copied().unwrap_or_default()
        })
    }) {
        return Some((**endpoint).clone());
    }

    active
        .into_iter()
        .find(|endpoint| endpoint.region.is_none())
        .cloned()
}

fn target_regions_ready(
    snapshot: Option<&service_discovery::ServiceDiscoverySnapshot>,
    target_revision: &str,
    desired_regions: &[String],
) -> bool {
    target_regions_covered(snapshot, target_revision, desired_regions)
        && target_endpoint_count(snapshot, target_revision) == desired_regions.len()
}

fn target_regions_covered(
    snapshot: Option<&service_discovery::ServiceDiscoverySnapshot>,
    target_revision: &str,
    desired_regions: &[String],
) -> bool {
    rollout_candidate_regions(snapshot, target_revision, desired_regions, true).is_empty()
}

fn excess_target_endpoints(
    snapshot: Option<&service_discovery::ServiceDiscoverySnapshot>,
    target_revision: &str,
    desired_regions: &[String],
    active_deployment_id: Option<&str>,
) -> Vec<service_discovery::ServiceDiscoveryEndpoint> {
    let mut desired_counts = HashMap::<&str, usize>::new();
    for region in desired_regions {
        *desired_counts.entry(region).or_default() += 1;
    }
    let mut retained_counts = HashMap::<String, usize>::new();
    let mut endpoints = rollout_target_endpoints(snapshot, target_revision);
    endpoints.sort_by_key(|endpoint| {
        (
            active_deployment_id == Some(endpoint.deployment_id.as_str()),
            endpoint.deployment_id.clone(),
        )
    });
    endpoints
        .into_iter()
        .filter_map(|endpoint| {
            let region = endpoint.region.as_deref()?;
            let retained = retained_counts.entry(region.to_string()).or_default();
            let desired = desired_counts.get(region).copied().unwrap_or_default();
            if *retained < desired {
                *retained += 1;
                None
            } else {
                Some(endpoint.clone())
            }
        })
        .chain(
            rollout_target_endpoints(snapshot, target_revision)
                .into_iter()
                .filter(|endpoint| endpoint.region.is_none())
                .cloned(),
        )
        .collect()
}

/// Resolve one immutable candidate request without creating VMs or changing routes.
/// Callers may persist its fingerprint before the first Cloud request.
pub(super) async fn prepare_cloud_candidate(
    state: &AppState,
    request: &mut ServiceDeployRequest,
    deployment_id: &str,
    excluded_backend_server_ids: Vec<String>,
) -> Result<(CreateDeploymentRequest, String, Vec<ResolvedSecretRef>, super::service_recipe::Recipe)> {
    let service_id = sanitize_service_id(&request.service_id)?;
    let mut source = request.clone();
    let archive_bytes = load_archive_bytes(state, request).await?;
    let archive_sha256 = format!("{:x}", Sha256::digest(&archive_bytes));
    let archive_bytes = if request.archive_id.is_some() && request.archive_bytes_base64.is_none() {
        Vec::new()
    } else {
        archive_bytes
    };
    let account_id = request.account_id.clone().unwrap_or_else(|| request.user_id.clone());
    let ports = if request.ports.is_empty() && request.port_mappings.is_empty() {
        vec![8080]
    } else {
        request.ports.clone()
    };
    let resolved_secrets = resolve_env_refs(state, request).await?;
    source.env_refs = resolved_secrets.iter().map(|s| format!("{}=heyosecret://{}@{}",s.env,s.path,s.version)).collect();
    // The bound archive ID, not a mutable name or duplicated archive payload,
    // supplies bytes on a future fresh-boot rollback.
    source.archive_bytes_base64 = None;
    if super::instance_http::Contract::from_metadata(request.metadata.as_ref().unwrap_or(&serde_json::Value::Null))?.is_some() {
        let env = request.env.get_or_insert_with(HashMap::new);
        env.insert("HEYO_SERVICE_ID".into(), service_id.clone());
        env.insert("HEYO_DEPLOYMENT_ID".into(), deployment_id.into());
        env.insert("HEYO_REGION".into(), request.region.clone());
        env.entry("HEYO_REVISION".into()).or_insert_with(||archive_sha256.clone());
    }
    let cloud_request = CreateDeploymentRequest {
        deployment_id: deployment_id.into(),
        user_id: request.user_id.clone(),
        account_id,
        name: request.name.clone().unwrap_or_else(|| format!("service-{service_id}")),
        slug: Some(format!("{service_id}-candidate")),
        target: "service".to_string(),
        archive_id: request.archive_id.clone(),
        archive_name: request.archive_name.clone(),
        archive_bytes,
        region: request.region.clone(),
        backend_type: request.driver.clone(),
        image: request.image.clone(),
        ports,
        port_mappings: request.port_mappings.clone(),
        mounts: request.mounts.clone(),
        env: request.env.clone(),
        env_refs: request.env_refs.clone(),
        start_command: request.start_command.clone(),
        working_directory: request.working_directory.clone(),
        setup_hooks: request.setup_hooks.clone(),
        size_class: request.size_class.clone(),
        ttl_seconds: Some(request.ttl_seconds.unwrap_or(0)),
        deployment_environment: request.deployment_environment.clone(),
        placement_pool: request.placement_pool.clone(),
        excluded_backend_server_ids,
        allowed_backend_server_ids: None,
        metadata: request.metadata.clone(),
    };
    let guest_port = super::instance_http::Contract::from_metadata(source.metadata.as_ref().unwrap_or(&serde_json::Value::Null))?
        .map(|c|c.port).or_else(||cloud_request.ports.first().copied())
        .or_else(||cloud_request.port_mappings.first().map(|p|p.container)).context("creation recipe has no guest port")?;
    let recipe = super::service_recipe::Recipe {request:source,archive_sha256:archive_sha256.clone(),guest_port};
    Ok((cloud_request, archive_sha256, resolved_secrets, recipe))
}

async fn deploy_service_candidate(
    state: AppState,
    mut request: ServiceDeployRequest,
    placement_exclusions: Option<Vec<String>>,
) -> Result<ServiceDeployResponse> {
    let service_id = sanitize_service_id(&request.service_id)?;
    let mut current_state = read_service_state(&state, &service_id).await?;
    anyhow::ensure!(!request.retire_previous
        || super::instance_http::Contract::from_metadata(&current_state.active_metadata["source"])?.is_none(),
        "application lifecycle retirement requires the regional rollout barrier");
    let previous_discovery = service_discovery::read_stored_snapshot(&service_id).await?;
    let excluded_backend_server_ids = match placement_exclusions {
        Some(exclusions) => exclusions,
        None if request.retire_previous => Vec::new(),
        None => service_discovery::active_backend_server_ids(&service_id).await?,
    };
    let deployment_id = request
        .deployment_id
        .clone()
        .unwrap_or_else(|| format!("svc-{service_id}-{}", Uuid::new_v4()));

    let (cloud_request, archive_sha256, resolved_secrets, recipe) = prepare_cloud_candidate(
        &state, &mut request, &deployment_id, excluded_backend_server_ids,
    ).await?;
    super::service_recipe::record(db::get_db()?, &recipe, &cloud_request).await?;
    let creation_digest = cloud_client::deployment_request_digest(&cloud_request)?;

    record_service_deployment_event(
        &state,
        &deployment_id,
        &service_id,
        "started",
        "running",
        "Service deployment started.",
        Some(service_deployment_request_metadata(&request)),
        None,
        None,
    )
    .await?;

    let mut lifecycle_events = subscribe_to_candidate_lifecycle_events(
        &state,
        &service_id,
        &deployment_id,
    )
    .await;

    info!(service_id, deployment_id, "creating service deployment candidate");
    record_service_deployment_event(
        &state,
        &deployment_id,
        &service_id,
        "candidate-create",
        "running",
        "Creating service deployment candidate.",
        None,
        None,
        None,
    )
    .await?;
    let create_response = match timeout(
        Duration::from_secs(SERVICE_CANDIDATE_CREATE_TIMEOUT_SECONDS),
        cloud_client::create_deployment(&state, &cloud_request),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            let error_message = format!(
                "timed out after {SERVICE_CANDIDATE_CREATE_TIMEOUT_SECONDS}s creating service deployment candidate {deployment_id}"
            );
            schedule_failed_candidate_cleanup(
                state.clone(),
                service_id.clone(),
                deployment_id.clone(),
            );
            let _ = record_service_deployment_event(
                &state,
                &deployment_id,
                &service_id,
                "candidate-create",
                "failed",
                &error_message,
                None,
                None,
                Some(error_message.clone()),
            )
            .await;
            anyhow::bail!(error_message);
        }
    };
    drop(cloud_request);
    record_service_deployment_event(
        &state,
        &deployment_id,
        &service_id,
        "candidate-created",
        "running",
        "Service deployment candidate create request accepted.",
        None,
        Some(json!({
            "cloudStatus": create_response.status,
            "archiveId": create_response.archive_id,
            "backendServerId": create_response.backend_server_id,
            "backendSandboxId": create_response.backend_sandbox_id,
        })),
        None,
    )
    .await?;

    let previous_state = current_state.clone();
    let mut route_updated = false;
    let mut discovery_updated = false;
    let mut dependent_routes_updated = Vec::new();
    let mut ingress_backend_url = current_state.ingress_backend_url.clone();

    let deployment_result = async {
        verify_applied_placement(
            request.deployment_environment.as_deref(),
            request.placement_pool.as_deref(),
            &request.region,
            &create_response,
        )?;
        if create_response.status == "failed" {
            anyhow::bail!("service deployment candidate {deployment_id} failed during creation");
        }
        if create_response.status != "running" {
            if let Some(subscriber) = lifecycle_events.as_mut() {
                record_service_deployment_event(
                    &state,
                    &deployment_id,
                    &service_id,
                    "candidate-ready-wait",
                    "running",
                    "Waiting for service deployment candidate lifecycle readiness.",
                    None,
                    None,
                    None,
                )
                .await?;
                wait_for_candidate_lifecycle_ready(
                    subscriber,
                    &deployment_id,
                    request.health_timeout_seconds,
                )
                .await
                .with_context(|| {
                    format!(
                        "service deployment candidate {deployment_id} did not become ready"
                    )
                })?;
                record_service_deployment_event(
                    &state,
                    &deployment_id,
                    &service_id,
                    "candidate-ready",
                    "running",
                    "Service deployment candidate reported ready.",
                    None,
                    None,
                    None,
                )
                .await?;
            } else {
                info!(
                    service_id,
                    deployment_id,
                    status = %create_response.status,
                    "service deployment candidate is provisioning without NATS lifecycle events; falling back to backend URL polling"
                );
            }
        }

        record_service_deployment_event(
            &state,
            &deployment_id,
            &service_id,
            "backend-url",
            "running",
            "Resolving service deployment candidate backend URL.",
            None,
            None,
            None,
        )
        .await?;
        record_service_deployment_event(
            &state,
            &deployment_id,
            &service_id,
            "health-check",
            "running",
            "Checking service deployment candidate health.",
            None,
            None,
            None,
        )
        .await?;
        let health_deadline = tokio::time::Instant::now()
            + Duration::from_secs(request.health_timeout_seconds.max(1));
        let (backend_url, route_backend_url, health_url) = wait_for_candidate_health(
            &state,
            &service_id,
            &deployment_id,
            &request.health_path,
            request.health_probe_timeout_seconds,
            health_deadline,
        )
        .await?;
        record_service_deployment_event(
            &state,
            &deployment_id,
            &service_id,
            "healthy",
            "running",
            "Service deployment candidate health check passed.",
            None,
            Some(json!({
                "backendUrl": backend_url,
                "routeBackendUrl": route_backend_url,
                "healthUrl": health_url,
            })),
            None,
        )
        .await?;

        verify_service_revision_guard(
            &state,
            &service_id,
            &deployment_id,
            request.revision_guard.as_ref(),
        )
        .await?;

        let receipt = cloud_client::recover_deployment(&state,&deployment_id,&creation_digest,Some(recipe.guest_port)).await?;
        verify_applied_placement(request.deployment_environment.as_deref(),request.placement_pool.as_deref(),
            &request.region,&receipt.deployment)?;
        super::service_recipe::bind(db::get_db()?,&deployment_id,serde_json::to_value(&receipt.deployment)?).await?;

        let previous_deployment_id = current_state.active_deployment_id.clone();
        let previous_archive_id = current_state.active_archive_id.clone();
        let previous_metadata = Some(current_state.active_metadata.clone());
        let mut previous_deployment_ids: Vec<String> = previous_discovery
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .endpoints
                    .iter()
                    .filter(|endpoint| endpoint.deployment_id != deployment_id)
                    .map(|endpoint| endpoint.deployment_id.clone())
                    .collect()
            })
            .unwrap_or_default();
        if previous_deployment_ids.is_empty() {
            if let Some(previous) = previous_deployment_id
                .as_ref()
                .filter(|previous| *previous != &deployment_id)
            {
                previous_deployment_ids.push(previous.clone());
            }
        }
        previous_deployment_ids.sort();
        previous_deployment_ids.dedup();

        if let Some(route) = request.route.clone() {
            let effective_backend_url = route
                .backend_url
                .clone()
                .unwrap_or_else(|| route_backend_url.clone());
            route_updated = true;
            record_service_deployment_event(
                &state,
                &deployment_id,
                &service_id,
                "route-write",
                "running",
                "Updating service route to candidate backend.",
                None,
                Some(json!({ "backendUrl": effective_backend_url, "route": route })),
                None,
            )
            .await?;
            write_traefik_service_route(&state, &service_id, &route, &effective_backend_url)
                .await?;
            ingress_backend_url = Some(effective_backend_url.clone());
            record_service_deployment_event(
                &state,
                &deployment_id,
                &service_id,
                "route-updated",
                "running",
                "Service route updated to candidate backend.",
                None,
                Some(json!({ "backendUrl": effective_backend_url })),
                None,
            )
            .await?;

            if service_id == "app-lb" {
                rewire_discovery_routes_to_app_lb_candidate(
                    &state,
                    &deployment_id,
                    &route_backend_url,
                    request.health_timeout_seconds,
                    &mut dependent_routes_updated,
                )
                .await?;
            }
        }

        record_service_deployment_event(
            &state,
            &deployment_id,
            &service_id,
            "discovery-publish",
            "running",
            "Publishing the healthy service endpoint set.",
            None,
            None,
            None,
        )
        .await?;
        let discovery = service_discovery::publish_healthy_endpoint(
            &service_id,
            &deployment_id,
            create_response.backend_server_id.as_deref(),
            Some(&request.region),
            Some(if super::instance_http::Contract::from_metadata(request.metadata.as_ref().unwrap_or(&serde_json::Value::Null))?.is_some() {
                request.env.as_ref().and_then(|e|e.get("HEYO_REVISION")).map(String::as_str).unwrap_or(&archive_sha256)
            } else { &archive_sha256 }),
            &backend_url,
            request.retire_previous,
        )
        .await?;
        discovery_updated = true;
        record_service_deployment_event(
            &state,
            &deployment_id,
            &service_id,
            "discovery-published",
            "running",
            "Healthy service endpoint set published.",
            None,
            Some(json!({
                "version": discovery.version,
                "endpointCount": discovery.endpoints.len(),
            })),
            None,
        )
        .await?;

        current_state = ServiceDeploymentState {
            service_id: service_id.clone(),
            deployment_environment: request.deployment_environment.clone(),
            active_deployment_id: Some(deployment_id.clone()),
            active_archive_id: create_response.archive_id.clone(),
            active_backend_url: Some(backend_url.clone()),
            previous_deployment_id: previous_deployment_id.clone(),
            previous_archive_id,
            active_metadata: build_deployment_metadata(
                &request,
                &deployment_id,
                &archive_sha256,
                &resolved_secrets,
            ),
            previous_metadata,
            desired_replicas: request.desired_replicas.unwrap_or(1),
            replica_regions: request.replica_regions.clone(),
            route: request.route.clone().or_else(|| previous_state.route.clone()),
            ingress_backend_url,
            updated_at: Some(Utc::now()),
            discovery: Some(discovery),
        };
        record_service_deployment_event(
            &state,
            &deployment_id,
            &service_id,
            "state-write",
            "running",
            "Persisting active service deployment state.",
            None,
            None,
            None,
        )
        .await?;
        write_service_state(&state, &current_state).await?;
        record_service_deployment_event(
            &state,
            &deployment_id,
            &service_id,
            "state-written",
            "running",
            "Active service deployment state persisted.",
            None,
            None,
            None,
        )
        .await?;

        let previous_retired = if request.retire_previous && request.retire_previous_async {
            for previous in previous_deployment_ids {
                schedule_previous_service_deployment_retirement(
                    &state,
                    &service_id,
                    &deployment_id,
                    &previous,
                    request.drain_seconds,
                    request.delete_previous,
                )
                .await;
            }
            false
        } else if request.retire_previous {
            let mut retired = !previous_deployment_ids.is_empty();
            for previous in previous_deployment_ids {
                retired &= retire_previous_service_deployment(
                    &state,
                    &service_id,
                    &deployment_id,
                    &previous,
                    request.drain_seconds,
                    request.delete_previous,
                )
                .await;
            }
            retired
        } else {
            false
        };

        let response = ServiceDeployResponse {
            service_id: service_id.clone(),
            deployment_id: deployment_id.clone(),
            traffic_management: if request.desired_replicas.is_some() {
                "discovery-membership"
            } else {
                "direct-route"
            },
            archive_id: create_response.archive_id.clone(),
            backend_url,
            health_url,
            previous_deployment_id,
            previous_retired,
            route_updated,
            state: current_state,
        };
        record_service_deployment_event(
            &state,
            &deployment_id,
            &service_id,
            "completed",
            "passed",
            "Service deployment completed and is active.",
            None,
            Some(serde_json::to_value(&response).unwrap_or_else(|_| json!({}))),
            None,
        )
        .await?;
        Ok(response)
    }
    .await;

    match deployment_result {
        Ok(response) => Ok(response),
        Err(error) => {
            let _ = record_service_deployment_event(
                &state,
                &deployment_id,
                &service_id,
                "failed",
                "failed",
                &format!("Service deployment failed: {error:#}"),
                None,
                None,
                Some(error.to_string()),
            )
            .await;
            let diagnostics =
                collect_failed_candidate_diagnostics(&state, &service_id, &deployment_id).await;
            compensate_failed_candidate(
                &state,
                &service_id,
                &deployment_id,
                &request,
                &previous_state,
                route_updated,
                discovery_updated,
                &dependent_routes_updated,
                previous_discovery.as_ref(),
            )
            .await;
            match diagnostics {
                Some(diagnostics) if !diagnostics.trim().is_empty() => {
                    anyhow::bail!("{error:#}\n\ncandidate diagnostics for {deployment_id}:\n{diagnostics}")
                }
                _ => Err(error),
            }
        }
    }
}

fn verify_applied_placement(
    requested_environment: Option<&str>,
    requested_pool: Option<&str>,
    requested_region: &str,
    response: &cloud_client::CreateDeploymentResponse,
) -> Result<()> {
    let Some(requested_environment) = requested_environment.map(str::trim) else {
        return Ok(());
    };
    let placement = response.placement.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Cloud did not confirm requested deployment environment {requested_environment}; refusing an unscoped deployment"
        )
    })?;
    if placement.deployment_environment != requested_environment
        || placement.region != requested_region
        || requested_pool.is_some_and(|pool| placement.placement_pool.as_deref() != Some(pool))
    {
        anyhow::bail!(
            "Cloud applied environment {} pool {:?} in region {}, but the deployment requested environment {} pool {:?} in region {}",
            placement.deployment_environment,
            placement.placement_pool,
            placement.region,
            requested_environment,
            requested_pool,
            requested_region,
        );
    }
    Ok(())
}

fn service_deployment_request_metadata(request: &ServiceDeployRequest) -> serde_json::Value {
    let env_keys: Vec<String> = request
        .env
        .as_ref()
        .map(|env| {
            let mut keys: Vec<String> = env.keys().cloned().collect();
            keys.sort();
            keys
        })
        .unwrap_or_default();

    json!({
        "serviceId": request.service_id,
        "userId": request.user_id,
        "accountId": request.account_id,
        "deploymentId": request.deployment_id,
        "name": request.name,
        "archiveId": request.archive_id,
        "archiveName": request.archive_name,
        "archiveBytesBase64Length": request.archive_bytes_base64.as_ref().map(|value| value.len()),
        "region": request.region,
        "deploymentEnvironment": request.deployment_environment,
        "placementPool": request.placement_pool,
        "driver": request.driver,
        "image": request.image,
        "ports": request.ports,
        "portMappings": request.port_mappings,
        "mounts": request.mounts,
        "envKeys": env_keys,
        "envRefCount": request.env_refs.len(),
        "startCommand": request.start_command,
        "workingDirectory": request.working_directory,
        "setupHookCount": request.setup_hooks.as_ref().map(|hooks| hooks.len()).unwrap_or(0),
        "sizeClass": request.size_class,
        "ttlSeconds": request.ttl_seconds,
        "healthPath": request.health_path,
        "healthTimeoutSeconds": request.health_timeout_seconds,
        "desiredReplicas": request.desired_replicas,
        "replicaRegions": request.replica_regions,
        "trafficManagement": if request.desired_replicas.is_some() {
            "discovery-membership"
        } else {
            "direct-route"
        },
        "retirePrevious": request.retire_previous,
        "retirePreviousAsync": request.retire_previous_async,
        "deletePrevious": request.delete_previous,
        "drainSeconds": request.drain_seconds,
        "route": request.route,
        "metadata": request.metadata,
        "revisionGuard": request.revision_guard,
    })
}

async fn verify_service_revision_guard(
    state: &AppState,
    service_id: &str,
    deployment_id: &str,
    guard: Option<&ServiceRevisionGuard>,
) -> Result<()> {
    let Some(guard) = guard else {
        return Ok(());
    };
    let repository_url = validate_revision_repository_url(&guard.repository_url)?;
    validate_revision_ref(&guard.git_ref)?;
    let expected_sha = validate_revision_sha(&guard.expected_sha)?;

    if guard.force {
        record_service_deployment_event(
            state,
            deployment_id,
            service_id,
            "revision-verified",
            "running",
            "Service revision freshness check was explicitly overridden.",
            None,
            Some(json!({
                "repositoryUrl": repository_url,
                "ref": guard.git_ref,
                "expectedSha": expected_sha,
                "forced": true,
            })),
            None,
        )
        .await?;
        return Ok(());
    }

    record_service_deployment_event(
        state,
        deployment_id,
        service_id,
        "revision-check",
        "running",
        "Verifying the service revision immediately before cutover.",
        None,
        Some(json!({
            "repositoryUrl": repository_url,
            "ref": guard.git_ref,
            "expectedSha": expected_sha,
        })),
        None,
    )
    .await?;

    let token = service_revision_git_token(state).await?;
    let temp_dir = std::env::temp_dir().join(format!(
        "heyo-service-revision-{}",
        Uuid::new_v4().simple()
    ));
    tokio::fs::create_dir_all(&temp_dir).await?;
    let askpass_path = temp_dir.join("git-askpass.sh");
    let username = std::env::var("ORCHESTRATOR_GIT_AUTH_USERNAME")
        .or_else(|_| std::env::var("CI_GIT_USERNAME"))
        .unwrap_or_else(|_| "x-access-token".to_string());
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\n*Username*) printf '%s\\n' {} ;;\n*Password*) printf '%s\\n' {} ;;\n*) printf '\\n' ;;\nesac\n",
        shell_single_quote(&username),
        shell_single_quote(&token),
    );
    write_secret_file(&askpass_path, &script, 0o700).await?;

    let result = timeout(
        Duration::from_secs(SERVICE_REVISION_CHECK_TIMEOUT_SECONDS),
        Command::new("git")
            .env("GIT_ASKPASS", &askpass_path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(["ls-remote", "--exit-code", "--refs"])
            .arg(&repository_url)
            .arg(&guard.git_ref)
            .output(),
    )
    .await;
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    let output = result
        .with_context(|| {
            format!(
                "timed out after {SERVICE_REVISION_CHECK_TIMEOUT_SECONDS}s verifying current service revision"
            )
        })?
        .context("failed to execute git ls-remote for service revision guard")?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to resolve guarded service ref {} (git exited with {})",
            guard.git_ref,
            output.status
        );
    }
    let current_sha = parse_ls_remote_revision(&output.stdout, &guard.git_ref)?;
    if current_sha != expected_sha {
        anyhow::bail!(
            "refusing stale service cutover: expected {} at {}, but current revision is {}",
            expected_sha,
            guard.git_ref,
            current_sha
        );
    }

    record_service_deployment_event(
        state,
        deployment_id,
        service_id,
        "revision-verified",
        "running",
        "Service revision is current immediately before cutover.",
        None,
        Some(json!({
            "repositoryUrl": repository_url,
            "ref": guard.git_ref,
            "expectedSha": expected_sha,
            "currentSha": current_sha,
            "forced": false,
        })),
        None,
    )
    .await?;
    Ok(())
}

fn validate_revision_repository_url(repository_url: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(repository_url.trim())
        .context("revisionGuard.repositoryUrl must be a valid URL")?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some("github.com")
        || parsed.port().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("revisionGuard.repositoryUrl must be a canonical https://github.com URL");
    }
    let segments: Vec<_> = parsed
        .path_segments()
        .map(|segments| segments.filter(|segment| !segment.is_empty()).collect())
        .unwrap_or_default();
    if segments.len() != 2 {
        anyhow::bail!("revisionGuard.repositoryUrl must identify one GitHub owner and repository");
    }
    Ok(format!(
        "https://github.com/{}/{}",
        segments[0], segments[1]
    ))
}

fn validate_revision_ref(git_ref: &str) -> Result<()> {
    let branch = git_ref
        .strip_prefix("refs/heads/")
        .filter(|branch| !branch.is_empty())
        .ok_or_else(|| anyhow::anyhow!("revisionGuard.ref must be a full branch ref"))?;
    if branch.starts_with('-')
        || branch.contains("..")
        || branch.contains("@{")
        || branch.contains('\\')
        || branch.chars().any(|character| character.is_control() || character.is_whitespace())
    {
        anyhow::bail!("revisionGuard.ref is not a valid branch ref");
    }
    Ok(())
}

fn validate_revision_sha(expected_sha: &str) -> Result<String> {
    let expected_sha = expected_sha.trim().to_ascii_lowercase();
    if expected_sha.len() != 40 || !expected_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("revisionGuard.expectedSha must be a full 40-character Git SHA");
    }
    Ok(expected_sha)
}

fn parse_ls_remote_revision(output: &[u8], expected_ref: &str) -> Result<String> {
    let output = std::str::from_utf8(output).context("git ls-remote returned non-UTF-8 output")?;
    let mut matches = output.lines().filter_map(|line| {
        let (sha, git_ref) = line.split_once('\t')?;
        (git_ref == expected_ref).then_some(sha)
    });
    let sha = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("guarded service ref {expected_ref} did not resolve"))?;
    if matches.next().is_some() {
        anyhow::bail!("guarded service ref {expected_ref} resolved ambiguously");
    }
    validate_revision_sha(sha)
}

async fn service_revision_git_token(state: &AppState) -> Result<String> {
    for name in ["ORCHESTRATOR_GIT_AUTH_TOKEN", "CI_GIT_AUTH_TOKEN", "GITHUB_TOKEN"] {
        if let Ok(value) = std::env::var(name) {
            if !value.trim().is_empty() {
                return Ok(value);
            }
        }
    }
    if state.config.heyosecret_url.trim().is_empty() {
        anyhow::bail!("Git authentication is required to verify the service revision");
    }
    let secret_path = std::env::var("ORCHESTRATOR_GIT_AUTH_TOKEN_SECRET_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_GIT_AUTH_TOKEN_SECRET_PATH.to_string());
    let token = if state.config.heyosecret_internal_api_key.trim().is_empty() {
        state.config.internal_api_key.clone()
    } else {
        state.config.heyosecret_internal_api_key.clone()
    };
    let client = HeyoSecretClient::new(HeyoSecretClientOptions {
        base_url: state.config.heyosecret_url.clone(),
        token,
        timeout: Some(Duration::from_secs(10)),
    })
    .context("failed to create HeyoSecret client for Git authentication")?;
    let secret = client
        .read_active(&secret_path)
        .await
        .with_context(|| format!("failed to read Git authentication from HeyoSecret path {secret_path}"))?;
    let value = String::from_utf8(secret.value).context("Git authentication token is not valid UTF-8")?;
    if value.trim().is_empty() {
        anyhow::bail!("Git authentication token is empty");
    }
    Ok(value.trim().to_string())
}

async fn write_secret_file(path: &Path, contents: &str, mode: u32) -> Result<()> {
    tokio::fs::write(path, contents).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
    }
    let _ = mode;
    Ok(())
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

async fn record_service_deployment_event(
    _state: &AppState,
    deployment_id: &str,
    service_id: &str,
    phase: &str,
    status: &str,
    message: &str,
    request: Option<serde_json::Value>,
    response: Option<serde_json::Value>,
    error_message: Option<String>,
) -> Result<()> {
    let db = db::get_db()?;
    let run_status = deployment_run_status(phase, status);
    let target_revision = response
        .as_ref()
        .and_then(|value| value.get("targetRevision"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    let metadata = json!({
        "request": request,
        "response": response,
    });
    let request_value = match request {
        Some(value) => SeaValue::Json(Some(Box::new(value))),
        None => SeaValue::Json(None),
    };
    let response_value = match response {
        Some(value) => SeaValue::Json(Some(Box::new(value))),
        None => SeaValue::Json(None),
    };
    let metadata_value = SeaValue::Json(Some(Box::new(metadata)));

    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO service_deployment_runs (
            deployment_id, service_id, status, phase, message, error_message, request, response,
            completed_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
            CASE WHEN $3 IN ('passed', 'failed') THEN NOW() ELSE NULL END,
            NOW()
        )
        ON CONFLICT (deployment_id) DO UPDATE SET
            service_id = EXCLUDED.service_id,
            status = CASE
                WHEN service_deployment_runs.status IN ('passed', 'failed')
                    AND EXCLUDED.status NOT IN ('passed', 'failed')
                THEN service_deployment_runs.status
                ELSE EXCLUDED.status
            END,
            phase = EXCLUDED.phase,
            message = EXCLUDED.message,
            error_message = EXCLUDED.error_message,
            request = COALESCE(EXCLUDED.request, service_deployment_runs.request),
            response = COALESCE(EXCLUDED.response, service_deployment_runs.response),
            completed_at = CASE
                WHEN EXCLUDED.status IN ('passed', 'failed') THEN NOW()
                ELSE service_deployment_runs.completed_at
            END,
            updated_at = NOW()",
        vec![
            deployment_id.into(),
            service_id.into(),
            run_status.into(),
            phase.into(),
            message.into(),
            error_message.clone().into(),
            request_value,
            response_value,
        ],
    ))
    .await
    .context("failed to upsert service deployment run")?;

    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO service_deployment_events (
            deployment_id, service_id, phase, status, message, metadata, error_message
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        vec![
            deployment_id.into(),
            service_id.into(),
            phase.into(),
            status.into(),
            message.into(),
            metadata_value,
            error_message.into(),
        ],
    ))
    .await
    .context("failed to insert service deployment event")?;

    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE service_rollouts
         SET stage = $2,
             target_revision = COALESCE($3, target_revision),
             lease_expires_at = NOW() + INTERVAL '1 hour',
             updated_at = NOW()
         WHERE rollout_id = $1 AND status = 'running'",
        vec![deployment_id.into(), phase.into(), target_revision.into()],
    ))
    .await
    .context("failed to update durable service rollout stage")?;

    Ok(())
}

fn deployment_run_status(phase: &str, event_status: &str) -> &'static str {
    if event_status == "failed" {
        "failed"
    } else if phase == "completed" {
        "passed"
    } else {
        "running"
    }
}

#[derive(Debug)]
struct PendingServiceRetirement {
    deployment_id: String,
    service_id: String,
    previous_deployment_id: String,
    delete_previous: bool,
}

pub async fn run_retirement_reconciler(state: AppState) {
    let mut ticker = interval(Duration::from_secs(
        SERVICE_RETIREMENT_RECONCILE_INTERVAL_SECONDS,
    ));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        if let Err(error) = reconcile_pending_service_retirements(&state).await {
            warn!("failed to reconcile pending service retirements: {error:#}");
        }
    }
}

pub(super) async fn try_service_lifecycle_lock(
    db: &DatabaseConnection,
    service_id: &str,
) -> Result<Option<DatabaseTransaction>> {
    let transaction = db.begin().await?;
    let row = transaction.query_one(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT pg_try_advisory_xact_lock(hashtextextended('service-lifecycle:' || $1, 0)) AS acquired",
        [service_id.into()],
    )).await?.context("service lifecycle lock returned no result")?;
    if !row.try_get::<bool>("", "acquired")? {
        transaction.rollback().await?;
        return Ok(None);
    }
    Ok(Some(transaction))
}

#[cfg(test)]
pub(super) async fn wait_for_test_lifecycle_rollback(db: &DatabaseConnection, service_id: &str) -> Result<()> {
    // Transaction drop queues rollback. Another pooled connection can observe
    // its lock until that rollback completes; do not retry the tested mutation.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(transaction) = try_service_lifecycle_lock(db, service_id).await? {
                transaction.rollback().await?;
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.context("test lifecycle rollback did not release its lock")?
}

async fn reconcile_pending_service_retirements(state: &AppState) -> Result<()> {
    let db = db::get_db()?;
    for retirement in list_pending_service_retirements(db).await? {
        let Some(guard) = try_service_lifecycle_lock(db, &retirement.service_id).await? else {
            continue;
        };
        if super::service_adoption::ensure_managed(&guard, &retirement.service_id).await.is_err() {
            continue;
        }
        if super::regional_rollout::ensure_no_regional_rollout(&guard, &retirement.service_id).await.is_err() {
            continue;
        }
        // The initial scan is only a hint. A rollout or another reconciler may have
        // changed eligibility since then. Recheck while holding the lifecycle lock
        // and retain that lock until the external stop/delete has finished.
        if !list_pending_service_retirements(&guard).await?.iter().any(|current| {
            current.deployment_id == retirement.deployment_id
                && current.previous_deployment_id == retirement.previous_deployment_id
        }) {
            continue;
        }
        let retired = if retirement.delete_previous {
            // A previous instance can stop itself before it records the stop.
            // Retrying delete is the durable operation: Cloud treats an absent
            // deployment as success and destroys a still-running sandbox.
            finish_previous_service_deployment_retirement(
                state,
                &retirement.service_id,
                &retirement.deployment_id,
                &retirement.previous_deployment_id,
                true,
            )
            .await
        } else {
            stop_previous_service_deployment(
                state,
                &retirement.service_id,
                &retirement.deployment_id,
                &retirement.previous_deployment_id,
                retirement.delete_previous,
            )
            .await
        };
        if !retired {
            warn!(
                service_id = retirement.service_id,
                deployment_id = retirement.deployment_id,
                previous = retirement.previous_deployment_id,
                "pending service retirement did not complete successfully"
            );
        }
    }

    Ok(())
}

async fn list_pending_service_retirements(db: &impl ConnectionTrait) -> Result<Vec<PendingServiceRetirement>> {
    let rows = db
        .query_all(Statement::from_string(
            DbBackend::Postgres,
            "WITH retirement_intents AS (
                SELECT DISTINCT ON (
                    deployment_id,
                    metadata->'response'->>'previousDeploymentId'
                )
                    deployment_id,
                    service_id,
                    metadata->'response'->>'previousDeploymentId' AS previous_deployment_id,
                    COALESCE(
                        (metadata->'response'->>'deletePrevious')::BOOLEAN,
                        FALSE
                    ) AS delete_previous,
                    created_at,
                    COALESCE(
                        NULLIF(metadata->'response'->>'drainSeconds', '')::BIGINT,
                        0
                    ) AS drain_seconds
                FROM service_deployment_events
                WHERE phase = 'previous-retire-wait'
                    AND metadata->'response'->>'previousDeploymentId' IS NOT NULL
                ORDER BY
                    deployment_id,
                    metadata->'response'->>'previousDeploymentId',
                    created_at DESC,
                    id DESC
            )
            SELECT
                intent.deployment_id,
                intent.service_id,
                intent.previous_deployment_id,
                intent.delete_previous
            FROM retirement_intents intent
            WHERE intent.created_at
                    + GREATEST(intent.drain_seconds, 0) * INTERVAL '1 second' <= NOW()
                AND EXISTS (
                    SELECT 1
                    FROM service_deployment_events rollout_completed
                    WHERE rollout_completed.deployment_id = intent.deployment_id
                        AND rollout_completed.phase = 'completed'
                        AND rollout_completed.status = 'passed'
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM service_rollouts rollout
                    WHERE rollout.service_id = intent.service_id
                        AND (rollout.rollout_id <> intent.deployment_id
                            OR rollout.status <> 'passed')
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM service_deployment_states state
                    WHERE state.active_deployment_id = intent.previous_deployment_id
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM service_deployment_events completed
                    WHERE completed.deployment_id = intent.deployment_id
                        AND completed.status = 'passed'
                        AND completed.metadata->'response'->>'previousDeploymentId'
                            = intent.previous_deployment_id
                        AND (
                            completed.phase = 'previous-retire-cancelled'
                            OR
                            (
                                intent.delete_previous
                                AND completed.phase = 'previous-deleted'
                            )
                            OR (
                                NOT intent.delete_previous
                                AND completed.phase IN ('previous-stopped', 'previous-retained')
                            )
                        )
                )
            ORDER BY intent.created_at ASC
            LIMIT 20"
                .to_string(),
        ))
        .await
        .context("failed to list pending service deployment retirements")?;

    rows.into_iter()
        .map(|row| {
            Ok(PendingServiceRetirement {
                deployment_id: row.try_get("", "deployment_id")?,
                service_id: row.try_get("", "service_id")?,
                previous_deployment_id: row.try_get("", "previous_deployment_id")?,
                delete_previous: row.try_get("", "delete_previous")?,
            })
        })
        .collect()
}

async fn schedule_previous_service_deployment_retirement(
    state: &AppState,
    service_id: &str,
    deployment_id: &str,
    previous_deployment_id: &str,
    drain_seconds: u64,
    delete_previous: bool,
) {
    if !begin_previous_service_deployment_retirement(
        state,
        service_id,
        deployment_id,
        previous_deployment_id,
        drain_seconds,
        delete_previous,
    )
    .await
    {
        warn!(
            service_id,
            deployment_id,
            previous = previous_deployment_id,
            "async previous service deployment retirement could not be scheduled"
        );
    }
}

async fn retire_previous_service_deployment(
    state: &AppState,
    service_id: &str,
    deployment_id: &str,
    previous_deployment_id: &str,
    drain_seconds: u64,
    delete_previous: bool,
) -> bool {
    if !begin_previous_service_deployment_retirement(
        state,
        service_id,
        deployment_id,
        previous_deployment_id,
        drain_seconds,
        delete_previous,
    )
    .await
    {
        return false;
    }

    if drain_seconds > 0 {
        sleep(Duration::from_secs(drain_seconds)).await;
    }

    stop_previous_service_deployment(
        state,
        service_id,
        deployment_id,
        previous_deployment_id,
        delete_previous,
    )
    .await
}

async fn begin_previous_service_deployment_retirement(
    state: &AppState,
    service_id: &str,
    deployment_id: &str,
    previous_deployment_id: &str,
    drain_seconds: u64,
    delete_previous: bool,
) -> bool {
    if let Err(error) =
        service_discovery::mark_endpoint_draining(service_id, previous_deployment_id).await
    {
        warn!(
            service_id,
            previous = previous_deployment_id,
            "failed to persist service endpoint drain intent: {error:#}"
        );
        return false;
    }
    let metadata = json!({
        "previousDeploymentId": previous_deployment_id,
        "drainSeconds": drain_seconds,
        "deletePrevious": delete_previous,
    });
    if let Err(error) = record_service_deployment_event(
        state,
        deployment_id,
        service_id,
        "previous-retire-wait",
        "running",
        "Waiting before retiring previous service deployment.",
        None,
        Some(metadata),
        None,
    )
    .await
    {
        warn!(
            service_id,
            deployment_id,
            previous = previous_deployment_id,
            "failed to persist service retirement intent: {error:#}"
        );
        if let Err(restore_error) =
            service_discovery::mark_endpoint_active(service_id, previous_deployment_id).await
        {
            warn!(
                service_id,
                deployment_id,
                previous = previous_deployment_id,
                "failed to restore endpoint after retirement intent persistence failed: {restore_error:#}"
            );
        }
        return false;
    }
    true
}

async fn stop_previous_service_deployment(
    state: &AppState,
    service_id: &str,
    deployment_id: &str,
    previous_deployment_id: &str,
    delete_previous: bool,
) -> bool {
    let stop_metadata = json!({ "previousDeploymentId": previous_deployment_id });
    let _ = record_service_deployment_event(
        state,
        deployment_id,
        service_id,
        "previous-stop",
        "running",
        "Stopping previous service deployment.",
        None,
        Some(stop_metadata.clone()),
        None,
    )
    .await;
    if let Err(error) = cloud_client::stop_deployment(state, previous_deployment_id).await {
        let error_message = error.to_string();
        warn!(
            service_id,
            deployment_id,
            previous = previous_deployment_id,
            "failed to stop previous service deployment: {error:#}"
        );
        let _ = record_service_deployment_event(
            state,
            deployment_id,
            service_id,
            "previous-stop",
            "failed",
            "Failed to stop previous service deployment.",
            None,
            Some(stop_metadata),
            Some(error_message),
        )
        .await;
        return false;
    }
    let _ = record_service_deployment_event(
        state,
        deployment_id,
        service_id,
        "previous-stopped",
        "passed",
        "Previous service deployment stopped.",
        None,
        Some(json!({ "previousDeploymentId": previous_deployment_id })),
        None,
    )
    .await;

    finish_previous_service_deployment_retirement(
        state,
        service_id,
        deployment_id,
        previous_deployment_id,
        delete_previous,
    )
    .await
}

async fn finish_previous_service_deployment_retirement(
    state: &AppState,
    service_id: &str,
    deployment_id: &str,
    previous_deployment_id: &str,
    delete_previous: bool,
) -> bool {
    if !delete_previous {
        if let Err(error) = service_discovery::remove_endpoint(service_id, previous_deployment_id).await {
            warn!(
                service_id,
                previous = previous_deployment_id,
                "previous deployment stopped but its discovery membership could not be removed: {error:#}"
            );
            return false;
        }
        let _ = record_service_deployment_event(
            state,
            deployment_id,
            service_id,
            "previous-retained",
            "passed",
            "Previous service deployment retained after stop.",
            None,
            Some(json!({ "previousDeploymentId": previous_deployment_id })),
            None,
        )
        .await;
        return true;
    }

    let delete_metadata = json!({ "previousDeploymentId": previous_deployment_id });
    let _ = record_service_deployment_event(
        state,
        deployment_id,
        service_id,
        "previous-delete",
        "running",
        "Deleting previous service deployment.",
        None,
        Some(delete_metadata.clone()),
        None,
    )
    .await;
    if let Err(error) = cloud_client::delete_deployment(state, previous_deployment_id).await {
        let error_message = error.to_string();
        warn!(
            service_id,
            deployment_id,
            previous = previous_deployment_id,
            "failed to delete previous service deployment: {error:#}"
        );
        let _ = record_service_deployment_event(
            state,
            deployment_id,
            service_id,
            "previous-delete",
            "failed",
            "Failed to delete previous service deployment.",
            None,
            Some(delete_metadata),
            Some(error_message),
        )
        .await;
        return false;
    }
    if let Err(error) = service_discovery::remove_endpoint(service_id, previous_deployment_id).await {
        warn!(
            service_id,
            previous = previous_deployment_id,
            "previous deployment deleted but its discovery membership could not be removed: {error:#}"
        );
        return false;
    }
    let _ = record_service_deployment_event(
        state,
        deployment_id,
        service_id,
        "previous-deleted",
        "passed",
        "Previous service deployment deleted.",
        None,
        Some(json!({ "previousDeploymentId": previous_deployment_id })),
        None,
    )
    .await;

    true
}

async fn read_service_deployment_run(
    _state: &AppState,
    deployment_id: &str,
) -> Result<Option<serde_json::Value>> {
    let db = db::get_db()?;
    let row = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT deployment_id, service_id, status, phase, message, error_message,
                    request, response, created_at, updated_at, completed_at
             FROM service_deployment_runs WHERE deployment_id = $1 LIMIT 1",
            [deployment_id.into()],
        ))
        .await
        .context("failed to query service deployment run")?;

    let Some(row) = row else {
        return Ok(None);
    };

    let events = db
        .query_all(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id, phase, status, message, metadata, error_message, created_at
             FROM service_deployment_events
             WHERE deployment_id = $1
             ORDER BY created_at ASC, id ASC",
            [deployment_id.into()],
        ))
        .await
        .context("failed to query service deployment events")?;

    let created_at: chrono::DateTime<chrono::FixedOffset> = row
        .try_get("", "created_at")
        .context("failed to read service deployment created_at")?;
    let updated_at: chrono::DateTime<chrono::FixedOffset> = row
        .try_get("", "updated_at")
        .context("failed to read service deployment updated_at")?;
    let completed_at: Option<chrono::DateTime<chrono::FixedOffset>> = row
        .try_get("", "completed_at")
        .context("failed to read service deployment completed_at")?;

    let mut event_values = Vec::with_capacity(events.len());
    for event in events {
        let created_at: chrono::DateTime<chrono::FixedOffset> = event
            .try_get("", "created_at")
            .context("failed to read service deployment event created_at")?;
        event_values.push(json!({
            "id": event.try_get::<i64>("", "id").context("failed to read service deployment event id")?,
            "phase": event.try_get::<String>("", "phase").context("failed to read service deployment event phase")?,
            "status": event.try_get::<String>("", "status").context("failed to read service deployment event status")?,
            "message": event.try_get::<String>("", "message").context("failed to read service deployment event message")?,
            "metadata": event.try_get::<serde_json::Value>("", "metadata").unwrap_or_else(|_| json!({})),
            "errorMessage": event.try_get::<Option<String>>("", "error_message").context("failed to read service deployment event error_message")?,
            "createdAt": created_at.with_timezone(&Utc),
        }));
    }

    Ok(Some(json!({
        "deploymentId": row.try_get::<String>("", "deployment_id").context("failed to read deployment_id")?,
        "serviceId": row.try_get::<String>("", "service_id").context("failed to read service_id")?,
        "status": row.try_get::<String>("", "status").context("failed to read status")?,
        "phase": row.try_get::<String>("", "phase").context("failed to read phase")?,
        "message": row.try_get::<Option<String>>("", "message").context("failed to read message")?,
        "errorMessage": row.try_get::<Option<String>>("", "error_message").context("failed to read error_message")?,
        "request": row.try_get::<Option<serde_json::Value>>("", "request").context("failed to read request")?,
        "response": row.try_get::<Option<serde_json::Value>>("", "response").context("failed to read response")?,
        "createdAt": created_at.with_timezone(&Utc),
        "updatedAt": updated_at.with_timezone(&Utc),
        "completedAt": completed_at.map(|value| value.with_timezone(&Utc)),
        "events": event_values,
    })))
}

async fn subscribe_to_candidate_lifecycle_events(
    state: &AppState,
    service_id: &str,
    deployment_id: &str,
) -> Option<async_nats::Subscriber> {
    if !state.config.nats.enabled {
        return None;
    }

    info!(
        service_id,
        deployment_id,
        "subscribing to service candidate lifecycle events"
    );

    let subscribe = async {
        let client = async_nats::connect(&state.config.nats.url)
            .await
            .context("failed to connect to NATS")?;
        client
            .subscribe("sandbox.evt.>")
            .await
            .context("failed to subscribe to sandbox lifecycle events")
    };

    match timeout(
        Duration::from_secs(SERVICE_CANDIDATE_EVENT_SUBSCRIBE_TIMEOUT_SECONDS),
        subscribe,
    )
    .await
    {
        Ok(Ok(subscriber)) => Some(subscriber),
        Ok(Err(error)) => {
            warn!(
                service_id,
                deployment_id,
                "service deploy could not subscribe to NATS lifecycle events; falling back to polling: {error:#}"
            );
            None
        }
        Err(_) => {
            warn!(
                service_id,
                deployment_id,
                "timed out subscribing to NATS lifecycle events; falling back to polling"
            );
            None
        }
    }
}

async fn wait_for_candidate_lifecycle_ready(
    subscriber: &mut async_nats::Subscriber,
    deployment_id: &str,
    timeout_seconds: u64,
) -> Result<()> {
    if candidate_deployment_status_is_ready(deployment_id).await? {
        return Ok(());
    }

    let wait = async {
        let status_poll = tokio::time::sleep(Duration::from_secs(
            SERVICE_CANDIDATE_STATUS_POLL_INTERVAL_SECONDS,
        ));
        tokio::pin!(status_poll);

        loop {
            tokio::select! {
                _ = &mut status_poll => {
                    if candidate_deployment_status_is_ready(deployment_id).await? {
                        return Ok(());
                    }
                    status_poll.as_mut().reset(
                        tokio::time::Instant::now()
                            + Duration::from_secs(SERVICE_CANDIDATE_STATUS_POLL_INTERVAL_SECONDS),
                    );
                }
                message = subscriber.next() => {
                    let Some(message) = message else {
                        anyhow::bail!(
                            "NATS subscription closed before deployment {deployment_id} reported ready"
                        );
                    };

                    let envelope = match serde_json::from_slice::<SandboxLifecycleEnvelope>(&message.payload) {
                        Ok(envelope) => envelope,
                        Err(_) => continue,
                    };
                    if envelope.payload.deployment_id != deployment_id {
                        continue;
                    }

                    info!(
                        deployment_id,
                        event_type = %envelope.event_type,
                        status = %envelope.payload.status,
                        "service candidate lifecycle event received"
                    );

                    match envelope.payload.status.as_str() {
                        "running" => return Ok(()),
                        "failed" => {
                            anyhow::bail!(
                                "sandbox lifecycle event `{}` reported failure for deployment {}: {}",
                                envelope.event_type,
                                deployment_id,
                                envelope
                                    .payload
                                    .error
                                    .unwrap_or_else(|| "candidate failed without an error message".to_string())
                            );
                        }
                        _ => continue,
                    }
                }
            }
        }
    };

    timeout(Duration::from_secs(timeout_seconds.max(1)), wait)
        .await
        .with_context(|| {
            format!(
                "timed out after {}s waiting for service candidate {deployment_id} lifecycle readiness",
                timeout_seconds.max(1)
            )
        })?
}

async fn candidate_deployment_status_is_ready(deployment_id: &str) -> Result<bool> {
    match current_candidate_deployment_status(deployment_id).await? {
        Some((status, _)) if status == "running" => Ok(true),
        Some((status, error_message)) if status == "failed" => {
            anyhow::bail!(
                "deployment {deployment_id} is marked failed: {}",
                error_message.unwrap_or_else(|| "no error message recorded".to_string())
            );
        }
        _ => Ok(false),
    }
}

async fn current_candidate_deployment_status(
    deployment_id: &str,
) -> Result<Option<(String, Option<String>)>> {
    let db = db::get_db()?;
    let row = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT status, error_message FROM deployed_sandboxes WHERE id = $1 LIMIT 1",
            [deployment_id.into()],
        ))
        .await
        .context("failed to query candidate deployment status")?;

    let Some(row) = row else {
        return Ok(None);
    };

    let status: String = row
        .try_get("", "status")
        .context("failed to read candidate deployment status")?;
    let error_message: Option<String> = row
        .try_get("", "error_message")
        .context("failed to read candidate deployment error message")?;

    Ok(Some((status, error_message)))
}

async fn collect_failed_candidate_diagnostics(
    state: &AppState,
    service_id: &str,
    deployment_id: &str,
) -> Option<String> {
    let command = r#"set +e
echo "=== service candidate ==="
echo "hostname: $(hostname 2>/dev/null || true)"
echo "pwd: $(pwd 2>/dev/null || true)"
echo
echo "=== processes ==="
ps -eo pid,ppid,stat,etime,comm 2>/dev/null | tail -n 80
echo
echo "=== workspace files ==="
ls -la /workspace 2>/dev/null | tail -n 80
echo
echo "=== service log ==="
if [ -f /workspace/service.log ]; then
  tail -n 400 /workspace/service.log
else
  echo "/workspace/service.log not found"
fi
"#;

    let result = timeout(
        Duration::from_secs(CANDIDATE_DIAGNOSTIC_TIMEOUT_SECONDS),
        cloud_client::exec_in_deployment(state, deployment_id, command),
    )
    .await;

    let output = match result {
        Ok(Ok(response)) => {
            let mut parts = Vec::new();
            if !response.stdout.trim().is_empty() {
                parts.push(format!("stdout:\n{}", response.stdout.trim()));
            }
            if !response.stderr.trim().is_empty() {
                parts.push(format!("stderr:\n{}", response.stderr.trim()));
            }
            if !response.output.trim().is_empty() {
                parts.push(format!("output:\n{}", response.output.trim()));
            }
            if parts.is_empty() {
                format!("diagnostic command exited with {:?}", response.exit_code)
            } else {
                parts.join("\n\n")
            }
        }
        Ok(Err(error)) => {
            warn!(
                service_id,
                deployment_id,
                "failed to collect failed service deployment diagnostics: {error:#}"
            );
            return Some(format!("failed to collect diagnostics: {error:#}"));
        }
        Err(_) => {
            warn!(
                service_id,
                deployment_id,
                "timed out collecting failed service deployment diagnostics"
            );
            return Some(format!(
                "timed out after {CANDIDATE_DIAGNOSTIC_TIMEOUT_SECONDS}s collecting diagnostics"
            ));
        }
    };

    Some(truncate_diagnostic_output(&output, CANDIDATE_DIAGNOSTIC_MAX_BYTES))
}

fn truncate_diagnostic_output(output: &str, max_bytes: usize) -> String {
    if output.len() <= max_bytes {
        return output.to_string();
    }
    let mut start = output.len().saturating_sub(max_bytes);
    while start < output.len() && !output.is_char_boundary(start) {
        start += 1;
    }
    format!(
        "[truncated to last {max_bytes} bytes]\n{}",
        output.get(start..).unwrap_or("")
    )
}

async fn compensate_failed_candidate(
    state: &AppState,
    service_id: &str,
    deployment_id: &str,
    request: &ServiceDeployRequest,
    previous_state: &ServiceDeploymentState,
    route_updated: bool,
    discovery_updated: bool,
    dependent_routes_updated: &[DiscoveryRoutedServiceRoute],
    previous_discovery: Option<&service_discovery::ServiceDiscoverySnapshot>,
) {
    warn!(
        service_id,
        deployment_id,
        route_updated,
        "service deployment failed after candidate creation; attempting compensation"
    );

    if discovery_updated {
        if let Err(error) =
            service_discovery::restore_snapshot(service_id, previous_discovery).await
        {
            warn!(
                service_id,
                deployment_id,
                "failed to restore previous service discovery membership; leaving candidate running for manual recovery: {error:#}"
            );
            return;
        }
    }

    if !dependent_routes_updated.is_empty() {
        for dependent in dependent_routes_updated {
            if let Err(error) = write_traefik_service_route(
                state,
                &dependent.service_id,
                &dependent.previous_route,
                &dependent.previous_backend_url,
            )
            .await
            {
                warn!(
                    service_id,
                    deployment_id,
                    dependent_service_id = dependent.service_id,
                    previous_backend_url = dependent.previous_backend_url,
                    "failed to restore dependent service route; leaving candidate running for manual recovery: {error:#}"
                );
                return;
            }
            if let Err(error) = persist_service_ingress_target(
                &dependent.service_id,
                &dependent.previous_route,
                &dependent.previous_backend_url,
            )
            .await
            {
                warn!(
                    service_id,
                    deployment_id,
                    dependent_service_id = dependent.service_id,
                    "restored dependent service route but failed to persist its previous target; leaving candidate running for manual recovery: {error:#}"
                );
                return;
            }
        }
    }

    if route_updated {
        match (
            previous_state.route.as_ref().or(request.route.as_ref()),
            previous_state.active_backend_url.as_deref(),
        ) {
            (Some(previous_route), Some(previous_backend_url)) => {
                if let Err(error) = write_traefik_service_route(
                    state,
                    service_id,
                    previous_route,
                    previous_backend_url,
                )
                .await
                {
                    warn!(
                        service_id,
                        deployment_id,
                        previous_backend_url,
                        "failed to restore previous service route; leaving candidate running for manual recovery: {error:#}"
                    );
                    return;
                }
            }
            _ => {
                warn!(
                    service_id,
                    deployment_id,
                    "route may have moved to failed candidate and no previous route/backend is known; leaving candidate running for manual recovery"
                );
                return;
            }
        }
    }

    let cleanup = async {
        if let Err(error) = cloud_client::stop_deployment(state, deployment_id).await {
            warn!(
                service_id,
                deployment_id,
                "failed to stop failed service deployment candidate: {error:#}"
            );
        }
        if let Err(error) = cloud_client::delete_deployment(state, deployment_id).await {
            warn!(
                service_id,
                deployment_id,
                "failed to delete failed service deployment candidate: {error:#}"
            );
        }
    };

    if timeout(
        Duration::from_secs(CANDIDATE_CLEANUP_TIMEOUT_SECONDS),
        cleanup,
    )
    .await
    .is_err()
    {
        warn!(
            service_id,
            deployment_id,
            "timed out cleaning up failed service deployment candidate"
        );
    }
}

fn schedule_failed_candidate_cleanup(state: AppState, service_id: String, deployment_id: String) {
    tokio::spawn(async move {
        for delay_seconds in [0, 30, 120] {
            if delay_seconds > 0 {
                sleep(Duration::from_secs(delay_seconds)).await;
            }
            cleanup_failed_candidate_once(&state, &service_id, &deployment_id).await;
        }
    });
}

async fn cleanup_failed_candidate_once(state: &AppState, service_id: &str, deployment_id: &str) {
    let cleanup = async {
        if let Err(error) = cloud_client::stop_deployment(state, deployment_id).await {
            warn!(
                service_id,
                deployment_id,
                "failed to stop failed service deployment candidate: {error:#}"
            );
        }
        if let Err(error) = cloud_client::delete_deployment(state, deployment_id).await {
            warn!(
                service_id,
                deployment_id,
                "failed to delete failed service deployment candidate: {error:#}"
            );
        }
    };

    if timeout(
        Duration::from_secs(CANDIDATE_CLEANUP_TIMEOUT_SECONDS),
        cleanup,
    )
    .await
    .is_err()
    {
        warn!(
            service_id,
            deployment_id,
            "timed out cleaning up failed service deployment candidate"
        );
    }
}

pub(super) use super::regional_observers::{regional_observe, validate_regional_observers};

pub(super) async fn regional_baseline(state: &AppState, request: &ServiceDeployRequest) -> Result<ServiceDeploymentState> {
    let baseline = bind_deployment_environment_identity(
        state,
        &request.service_id,
        request.deployment_environment.as_deref(),
    )
    .await?;
    if baseline.ingress_backend_url.as_deref().is_none_or(str::is_empty)
        || baseline.route.is_none()
        || serde_json::to_value(&baseline.route)? != serde_json::to_value(&request.route)?
    {
        anyhow::bail!("regional rollout requires an already established discovery ingress and its unchanged route");
    }
    Ok(baseline)
}

fn enforce_deployment_environment_identity(
    state: &ServiceDeploymentState,
    requested: Option<&str>,
) -> Result<()> {
    let occupied = state.active_deployment_id.is_some()
        || state.previous_deployment_id.is_some()
        || state.active_backend_url.is_some()
        || state.discovery.as_ref().is_some_and(|snapshot| !snapshot.endpoints.is_empty());
    match (state.deployment_environment.as_deref(), requested) {
        (None, Some(environment)) if occupied => anyhow::bail!(
            "service {} is an occupied legacy identity and cannot be adopted into deployment environment {environment}",
            state.service_id
        ),
        (Some(existing), Some(requested)) if existing != requested => anyhow::bail!(
            "service {} is bound to deployment environment {existing}, not {requested}",
            state.service_id
        ),
        (Some(existing), None) => anyhow::bail!(
            "service {} is bound to deployment environment {existing}; deploymentEnvironment is required",
            state.service_id
        ),
        _ => Ok(()),
    }
}

async fn bind_deployment_environment_identity(
    state: &AppState,
    service_id: &str,
    requested: Option<&str>,
) -> Result<ServiceDeploymentState> {
    let mut service_state = read_service_state(state, service_id).await?;
    enforce_deployment_environment_identity(&service_state, requested)?;
    if service_state.deployment_environment.is_none() {
        if let Some(environment) = requested {
            service_state.deployment_environment = Some(environment.to_owned());
            // The caller owns the service lifecycle lock. Persist the identity before
            // archive loading, rollout admission, or any Cloud request can occur.
            write_service_state(state, &service_state).await?;
        }
    }
    Ok(service_state)
}

pub(super) async fn restore_regional_baseline(state: &AppState, baseline: &ServiceDeploymentState) -> Result<()> {
    write_service_state(state, baseline).await
}

pub(super) async fn regional_revision(state: &AppState, request: &ServiceDeployRequest) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(load_archive_bytes(state, request).await?)))
}

/// The regional controller owns the lifecycle lock and journals the create
/// intent before calling this non-idempotent operation.
pub(super) async fn regional_create_candidate(
    state: &AppState, request: &ServiceDeployRequest, candidate_id: &str, region: &str,
) -> Result<()> {
    let mut candidate = request.clone();
    candidate.deployment_id = Some(candidate_id.to_string());
    candidate.region = region.to_string();
    candidate.retire_previous = false;
    candidate.retire_previous_async = false;
    candidate.delete_previous = false;
    candidate.route = None;
    deploy_service_candidate(state.clone(), candidate, Some(Vec::new())).await?;
    Ok(())
}

pub(super) async fn regional_probe(
    _state: &AppState, request: &ServiceDeployRequest,
    endpoint: &service_discovery::ServiceDiscoveryEndpoint,
) -> Result<()> {
    service_discovery::validate_endpoint_url(&endpoint.url)?;
    if !request.health_path.starts_with('/') || request.health_path.starts_with("//") {
        anyhow::bail!("healthPath must be an absolute path, not an authority");
    }
    let mut url = reqwest::Url::parse(&endpoint.url)?;
    url.set_path(&request.health_path);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(request.health_probe_timeout_seconds.clamp(1, 30)))
        .build()?;
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("regional health probe for {} returned {}", endpoint.deployment_id, response.status());
    }
    Ok(())
}

async fn load_archive_bytes(state: &AppState, request: &ServiceDeployRequest) -> Result<Vec<u8>> {
    match (&request.archive_bytes_base64, &request.archive_id) {
        (Some(encoded), _) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("archiveBytesBase64 is not valid base64"),
        (None, Some(archive_id)) => {
            cloud_client::download_archive(state, archive_id, &request.user_id).await
        }
        (None, None) => anyhow::bail!("archiveId or archiveBytesBase64 is required"),
    }
}

async fn wait_for_candidate_health(
    state: &AppState,
    service_id: &str,
    deployment_id: &str,
    health_path: &str,
    probe_timeout_seconds: u64,
    deadline: tokio::time::Instant,
) -> Result<(String, String, String)> {
    let mut backend_urls = Vec::new();
    let mut discovery_backend_url = None;
    let mut route_backend_url = None;
    let mut attempts: u64 = 0;
    let mut retry_delay = Duration::from_secs(1);
    let mut last_error = "candidate endpoint is not available yet".to_string();
    let mut healthy_since = None;

    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for healthy deployment {deployment_id}: {last_error}");
        }

        match current_candidate_deployment_status(deployment_id).await {
            Ok(Some((status, error_message))) if status == "failed" => {
                anyhow::bail!(
                    "deployment {deployment_id} is marked failed: {}",
                    error_message.unwrap_or_else(|| "no error message recorded".to_string())
                );
            }
            Ok(_) => {}
            Err(error) => {
                last_error = format!("candidate status is temporarily unavailable: {error:#}");
                warn!(deployment_id, "{last_error}");
            }
        }

        let previous_url_count = backend_urls.len();
        match cloud_client::deployment_healthcheck_urls(state, deployment_id).await {
            Ok(urls) => {
                if let Some(url) = urls.probe_url() {
                    route_backend_url = Some(url.clone());
                    backend_urls.clear();
                    backend_urls.push(url);
                }
                match urls.internal_url() {
                    Some(url) => match service_discovery::validate_endpoint_url(&url) {
                        Ok(()) => {
                            discovery_backend_url = Some(url);
                        }
                        Err(error) => {
                            discovery_backend_url = None;
                            last_error = format!(
                                "candidate internal endpoint is not suitable for service discovery: {error}"
                            );
                        }
                    },
                    None => {
                        discovery_backend_url = None;
                        last_error =
                            "candidate internal service endpoint is not available yet".to_string();
                    }
                }
            }
            Err(error) => {
                last_error =
                    format!("candidate health endpoints are temporarily unavailable: {error:#}");
                warn!(deployment_id, "{last_error}");
            }
        }

        attempts += 1;
        let mut probe_succeeded = false;
        for backend_url in &backend_urls {
            let health_url = join_url_path(backend_url, health_path);
            let request = state
                .http_client
                .get(&health_url)
                .header(reqwest::header::ACCEPT, "application/json")
                .timeout(Duration::from_secs(probe_timeout_seconds));

            match request.send().await {
                Ok(response) => {
                    let booting = response
                        .headers()
                        .get("x-heyo-boot")
                        .and_then(|value| value.to_str().ok())
                        == Some("starting");
                    if response.status().is_success() && !booting {
                        let Some(discovery_backend_url) = discovery_backend_url.as_deref() else {
                            healthy_since = None;
                            last_error =
                                "candidate is healthy but its internal service endpoint is not available yet"
                                    .to_string();
                            continue;
                        };
                        let now = tokio::time::Instant::now();
                        probe_succeeded = true;
                        if !health_observation_is_stable(
                            &mut healthy_since,
                            &health_url,
                            now,
                        ) {
                            last_error = format!(
                                "{health_url} is healthy but has not remained healthy for {SERVICE_HEALTH_STABILIZATION_SECONDS}s"
                            );
                            continue;
                        }
                        let (discovery_url, route_url) = candidate_endpoint_urls(
                            discovery_backend_url,
                            route_backend_url.as_deref(),
                        );
                        return Ok((discovery_url, route_url, health_url));
                    }
                    healthy_since = None;
                    if booting {
                        last_error =
                            format!("{health_url} reported that the sandbox is still starting");
                    } else {
                        last_error = format!("{} returned HTTP {}", health_url, response.status());
                    }
                    warn!(health_url, status = %response.status(), booting, "candidate health check returned non-success");
                }
                Err(error) => {
                    healthy_since = None;
                    last_error = format!("{health_url} could not be reached: {error}");
                    warn!(health_url, "candidate health check failed: {error}");
                }
            }
        }

        if attempts == 1 || attempts % 15 == 0 {
            let _ = record_service_deployment_event(
                state,
                deployment_id,
                service_id,
                "health-check",
                "running",
                "Waiting for service deployment candidate health.",
                None,
                Some(json!({
                    "attempt": attempts,
                    "backendUrls": backend_urls,
                    "lastError": last_error,
                })),
                None,
            )
            .await;
        }

        if probe_succeeded || backend_urls.len() > previous_url_count {
            retry_delay = Duration::from_secs(1);
        } else {
            retry_delay =
                (retry_delay * 2).min(Duration::from_secs(SERVICE_HEALTH_MAX_BACKOFF_SECONDS));
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        sleep(retry_delay.min(remaining)).await;
    }
}

fn health_observation_is_stable(
    healthy_since: &mut Option<(String, tokio::time::Instant)>,
    health_url: &str,
    now: tokio::time::Instant,
) -> bool {
    let since = match healthy_since {
        Some((observed_url, since)) if observed_url == health_url => *since,
        _ => {
            *healthy_since = Some((health_url.to_string(), now));
            now
        }
    };
    now.duration_since(since) >= Duration::from_secs(SERVICE_HEALTH_STABILIZATION_SECONDS)
}

fn candidate_endpoint_urls(
    healthy_backend_url: &str,
    preferred_route_url: Option<&str>,
) -> (String, String) {
    (
        healthy_backend_url.to_string(),
        preferred_route_url
            .unwrap_or(healthy_backend_url)
            .to_string(),
    )
}

fn service_backend_api_url(state: &AppState) -> String {
    let configured = state.config.backend_api_url.trim();
    if !configured.is_empty() {
        return configured.to_string();
    }
    std::env::var("ORCHESTRATOR_BACKEND_API_URL")
        .or_else(|_| std::env::var("BACKEND_API_URL"))
        .unwrap_or_default()
}

fn app_lb_route_health_url(
    app_lb_url: &str,
    route: &ServiceRouteRequest,
    health_path: &str,
) -> Result<String> {
    let prefix = route
        .path_prefix
        .as_deref()
        .filter(|prefix| !prefix.is_empty())
        .context("discovery-routed service ingress requires route.pathPrefix")?;
    Ok(join_url_path(
        &join_url_path(app_lb_url, prefix),
        health_path,
    ))
}

async fn wait_for_app_lb_route_health(
    state: &AppState,
    app_lb_url: &str,
    route: &ServiceRouteRequest,
    health_path: &str,
    timeout_seconds: u64,
) -> Result<String> {
    let health_url = app_lb_route_health_url(app_lb_url, route, health_path)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_seconds.max(1));
    let mut last_error = "app-lb discovery route has not been checked".to_string();
    let mut retry_delay = Duration::from_secs(1);
    let mut healthy_since = None;
    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for app-lb route {health_url}: {last_error}");
        }
        match state
            .http_client
            .get(&health_url)
            .timeout(Duration::from_secs(SERVICE_HEALTH_REQUEST_TIMEOUT_SECONDS))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                if health_observation_is_stable(
                    &mut healthy_since,
                    &health_url,
                    tokio::time::Instant::now(),
                ) {
                    return Ok(health_url);
                }
                last_error = format!(
                    "route is healthy but has not remained healthy for {SERVICE_HEALTH_STABILIZATION_SECONDS}s"
                );
                retry_delay = Duration::from_secs(1);
            }
            Ok(response) => {
                healthy_since = None;
                last_error = format!("received HTTP {}", response.status());
            }
            Err(error) => {
                healthy_since = None;
                last_error = error.to_string();
            }
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        sleep(retry_delay.min(remaining)).await;
        if healthy_since.is_none() {
            retry_delay =
                (retry_delay * 2).min(Duration::from_secs(SERVICE_HEALTH_MAX_BACKOFF_SECONDS));
        }
    }
}

async fn list_discovery_routed_service_routes(
    state: &AppState,
) -> Result<Vec<DiscoveryRoutedServiceRoute>> {
    let db = db::get_db()?;
    let rows = db
        .query_all(Statement::from_string(
            DbBackend::Postgres,
            "SELECT service_id, active_backend_url, active_metadata, route, ingress_backend_url
             FROM service_deployment_states
             WHERE service_id <> 'app-lb' AND route IS NOT NULL
             ORDER BY service_id"
                .to_string(),
        ))
        .await
        .context("failed to list discovery-routed service routes")?;

    rows.into_iter()
        .filter_map(|row| {
            let service_id = match row.try_get::<String>("", "service_id") {
                Ok(service_id) if state.config.service_uses_discovery_routing(&service_id) => {
                    service_id
                }
                Ok(_) => return None,
                Err(error) => return Some(Err(error.into())),
            };
            Some((|| {
                let active_metadata: serde_json::Value = row
                    .try_get("", "active_metadata")
                    .context("failed to read active service deployment metadata")?;
                let health_path = active_metadata
                    .pointer("/runtime/healthPath")
                    .and_then(serde_json::Value::as_str)
                    .filter(|path| !path.is_empty())
                    .with_context(|| {
                        format!("service {service_id} has no persisted runtime health path")
                    })?
                    .to_string();
                let previous_route: ServiceRouteRequest = serde_json::from_value(
                    row.try_get("", "route")
                        .context("failed to read service deployment route")?,
                )
                .with_context(|| format!("failed to parse route for service {service_id}"))?;
                let previous_backend_url = row
                    .try_get::<Option<String>>("", "ingress_backend_url")
                    .context("failed to read service ingress backend")?
                    .or(row
                        .try_get::<Option<String>>("", "active_backend_url")
                        .context("failed to read active service backend")?)
                    .with_context(|| {
                        format!("service {service_id} has no previous ingress backend")
                    })?;
                let mut route = previous_route.clone();
                route.strip_prefix = false;
                Ok(DiscoveryRoutedServiceRoute {
                    service_id,
                    route,
                    previous_route,
                    previous_backend_url,
                    health_path,
                })
            })())
        })
        .collect()
}

async fn rewire_discovery_routes_to_app_lb_candidate(
    state: &AppState,
    deployment_id: &str,
    candidate_backend_url: &str,
    timeout_seconds: u64,
    updated_routes: &mut Vec<DiscoveryRoutedServiceRoute>,
) -> Result<()> {
    let routes = list_discovery_routed_service_routes(state).await?;
    if routes.is_empty() {
        return Ok(());
    }

    record_service_deployment_event(
        state,
        deployment_id,
        "app-lb",
        "dependent-routes-check",
        "running",
        "Verifying discovery-routed services through the new app-lb candidate.",
        None,
        Some(json!({
            "dependentServices": routes
                .iter()
                .map(|route| route.service_id.as_str())
                .collect::<Vec<_>>(),
        })),
        None,
    )
    .await?;

    for dependent in &routes {
        wait_for_app_lb_route_health(
            state,
            candidate_backend_url,
            &dependent.route,
            &dependent.health_path,
            timeout_seconds,
        )
        .await
        .with_context(|| {
            format!(
                "service {} was not healthy through the new app-lb candidate",
                dependent.service_id
            )
        })?;
    }

    for dependent in routes {
        write_traefik_service_route(
            state,
            &dependent.service_id,
            &dependent.route,
            candidate_backend_url,
        )
        .await
        .with_context(|| {
            format!(
                "failed to move service {} ingress to the new app-lb candidate",
                dependent.service_id
            )
        })?;
        updated_routes.push(dependent);
        let updated = updated_routes.last().expect("just pushed dependent route");
        persist_service_ingress_target(
            &updated.service_id,
            &updated.route,
            candidate_backend_url,
        )
        .await?;
    }

    record_service_deployment_event(
        state,
        deployment_id,
        "app-lb",
        "dependent-routes-updated",
        "running",
        "Discovery-routed service ingress now targets the new app-lb candidate.",
        None,
        Some(json!({
            "appLbBackendUrl": candidate_backend_url,
            "dependentServices": updated_routes
                .iter()
                .map(|route| route.service_id.as_str())
                .collect::<Vec<_>>(),
        })),
        None,
    )
    .await?;
    Ok(())
}

async fn persist_service_ingress_target(
    service_id: &str,
    route: &ServiceRouteRequest,
    backend_url: &str,
) -> Result<()> {
    let db = db::get_db()?;
    let route = serde_json::to_value(route).context("failed to serialize service route")?;
    let result = db
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE service_deployment_states
             SET route = $2, ingress_backend_url = $3, updated_at = NOW()
             WHERE service_id = $1",
            vec![
                service_id.into(),
                SeaValue::Json(Some(Box::new(route))),
                backend_url.into(),
            ],
        ))
        .await
        .with_context(|| format!("failed to persist ingress target for service {service_id}"))?;
    if result.rows_affected() != 1 {
        anyhow::bail!("service {service_id} has no deployment state for its ingress target");
    }
    Ok(())
}

async fn cutover_service_ingress_to_app_lb(
    state: &AppState,
    service_id: &str,
    rollout_id: &str,
    route: &ServiceRouteRequest,
    health_path: &str,
    timeout_seconds: u64,
) -> Result<String> {
    if super::host_ingress::enabled(state, service_id) {
        let snapshot = service_discovery::read_snapshot(service_id).await?.context("no service discovery baseline")?;
        let ingress = super::host_ingress::establish(state, service_id, route, health_path, timeout_seconds, &snapshot).await?;
        persist_service_ingress_target(service_id, route, &ingress).await?;
        record_service_deployment_event(state, rollout_id, service_id,
            "app-lb-ingress-active", "running",
            "Host-managed ingress instances adopted discovery and passed routed health checks.",
            None, Some(json!({"route": route, "ingressBackendUrl": ingress})), None).await?;
        return Ok(ingress);
    }
    let app_lb_state = read_service_state(state, "app-lb").await?;
    let app_lb_backend_url = app_lb_state
        .active_backend_url
        .as_deref()
        .context("app-lb has no active backend for discovery-routed ingress")?;
    let previous_state = read_service_state(state, service_id).await?;
    let previous_route = previous_state.route.as_ref().unwrap_or(route);
    let previous_backend_url = previous_state
        .ingress_backend_url
        .as_deref()
        .or(previous_state.active_backend_url.as_deref())
        .context("service has no existing ingress backend to restore if cutover fails")?;
    record_service_deployment_event(
        state,
        rollout_id,
        service_id,
        "app-lb-ingress-check",
        "running",
        "Verifying service health through app-lb before ingress cutover.",
        None,
        None,
        None,
    )
    .await?;
    let health_url = wait_for_app_lb_route_health(
        state,
        app_lb_backend_url,
        route,
        health_path,
        timeout_seconds,
    )
    .await?;
    write_traefik_service_route(state, service_id, route, app_lb_backend_url).await?;
    if let Err(persist_error) =
        persist_service_ingress_target(service_id, route, app_lb_backend_url).await
    {
        if let Err(restore_error) = write_traefik_service_route(
            state,
            service_id,
            previous_route,
            previous_backend_url,
        )
        .await
        {
            anyhow::bail!(
                "failed to persist app-lb ingress cutover: {persist_error:#}; also failed to restore the previous ingress route: {restore_error:#}"
            );
        }
        return Err(persist_error).context("failed to persist app-lb ingress cutover; restored previous ingress route");
    }
    record_service_deployment_event(
        state,
        rollout_id,
        service_id,
        "app-lb-ingress-active",
        "running",
        "Stable service ingress now targets the healthy app-lb backend.",
        None,
        Some(json!({
            "appLbBackendUrl": app_lb_backend_url,
            "healthUrl": health_url,
            "route": route,
        })),
        None,
    )
    .await?;
    Ok(app_lb_backend_url.to_string())
}

async fn write_traefik_service_route(
    state: &AppState,
    service_id: &str,
    route: &ServiceRouteRequest,
    backend_url: &str,
) -> Result<()> {
    let proxy_backend_url = if proxy_subdomain_and_path(
        backend_url,
        &state.config.proxy_base_domains,
    )
    .is_some()
    {
        let proxy_url = service_backend_api_url(state)
            .trim()
            .trim_end_matches('/')
            .to_string();
        if proxy_url.is_empty() {
            anyhow::bail!(
                "ORCHESTRATOR_BACKEND_API_URL must be set to route service proxy subdomains"
            );
        }
        Some(proxy_url)
    } else {
        None
    };

    timeout(
        Duration::from_secs(SERVICE_ROUTE_WRITE_TIMEOUT_SECONDS),
        cloud_client::upsert_service_route(
            state,
            &cloud_client::UpsertServiceRouteRequest {
                service_id: service_id.to_string(),
                backend_url: backend_url.to_string(),
                proxy_backend_url,
                route: cloud_client::ServiceRouteRequest {
                    host: route.host.clone(),
                    path_prefix: route.path_prefix.clone(),
                    entry_points: route.entry_points.clone(),
                    cert_resolver: route.cert_resolver.clone(),
                    priority: route.priority,
                    strip_prefix: route.strip_prefix,
                    pass_host_header: route.pass_host_header,
                },
            },
        ),
    )
    .await
    .with_context(|| {
        format!(
            "timed out after {SERVICE_ROUTE_WRITE_TIMEOUT_SECONDS}s writing service route for {service_id}"
        )
    })??;

    Ok(())
}

async fn read_service_state(state: &AppState, service_id: &str) -> Result<ServiceDeploymentState> {
    let service_id = sanitize_service_id(service_id)?;

    if let Some(mut service_state) = read_service_state_from_db(&service_id).await? {
        service_state.discovery = service_discovery::read_snapshot(&service_id).await?;
        return Ok(service_state);
    }

    let path = service_state_path(state, &service_id)?;
    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let mut service_state: ServiceDeploymentState = serde_json::from_slice(&bytes)
                .with_context(|| format!("failed to parse service state {}", path.display()))?;
            service_state.discovery = service_discovery::read_snapshot(&service_id).await?;
            Ok(service_state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ServiceDeploymentState {
            service_id,
            active_metadata: json!({}),
            desired_replicas: default_desired_replicas(),
            ..Default::default()
        }),
        Err(error) => Err(error).with_context(|| format!("failed to read service state {}", path.display())),
    }
}

async fn write_service_state(_state: &AppState, service_state: &ServiceDeploymentState) -> Result<()> {
    write_service_state_to_db(service_state).await?;
    Ok(())
}

async fn read_service_state_from_db(service_id: &str) -> Result<Option<ServiceDeploymentState>> {
    let db = db::get_db()?;
    read_service_state_in(db,service_id).await
}

pub(super) async fn read_service_state_in(db: &impl ConnectionTrait, service_id: &str) -> Result<Option<ServiceDeploymentState>> {
    let row = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT service_id, active_deployment_id, active_archive_id, active_backend_url, \
             previous_deployment_id, previous_archive_id, active_metadata, previous_metadata, \
             deployment_environment, desired_replicas, replica_regions, route, ingress_backend_url, updated_at \
             FROM service_deployment_states WHERE service_id = $1 LIMIT 1",
            [service_id.into()],
        ))
        .await
        .context("failed to query service deployment state")?;

    let Some(row) = row else {
        return Ok(None);
    };

    let route_value: Option<serde_json::Value> = row
        .try_get("", "route")
        .context("failed to read service deployment route")?;
    let active_metadata: Option<serde_json::Value> = row
        .try_get("", "active_metadata")
        .context("failed to read active service deployment metadata")?;
    let previous_metadata: Option<serde_json::Value> = row
        .try_get("", "previous_metadata")
        .context("failed to read previous service deployment metadata")?;
    let updated_at: chrono::DateTime<chrono::FixedOffset> = row
        .try_get("", "updated_at")
        .context("failed to read service deployment updated_at")?;

    Ok(Some(ServiceDeploymentState {
        service_id: row
            .try_get("", "service_id")
            .context("failed to read service_id")?,
        deployment_environment: row
            .try_get("", "deployment_environment")
            .context("failed to read deployment_environment")?,
        active_deployment_id: row
            .try_get("", "active_deployment_id")
            .context("failed to read active_deployment_id")?,
        active_archive_id: row
            .try_get("", "active_archive_id")
            .context("failed to read active_archive_id")?,
        active_backend_url: row
            .try_get("", "active_backend_url")
            .context("failed to read active_backend_url")?,
        previous_deployment_id: row
            .try_get("", "previous_deployment_id")
            .context("failed to read previous_deployment_id")?,
        previous_archive_id: row
            .try_get("", "previous_archive_id")
            .context("failed to read previous_archive_id")?,
        active_metadata: active_metadata.unwrap_or_else(|| json!({})),
        previous_metadata,
        desired_replicas: u16::try_from(
            row.try_get::<i32>("", "desired_replicas")
                .context("failed to read desired_replicas")?,
        )
        .context("desired_replicas is outside the supported range")?,
        replica_regions: serde_json::from_value(
            row.try_get("", "replica_regions")
                .context("failed to read replica_regions")?,
        )
        .context("failed to parse replica_regions")?,
        route: route_value
            .map(serde_json::from_value)
            .transpose()
            .context("failed to parse service deployment route")?,
        ingress_backend_url: row
            .try_get("", "ingress_backend_url")
            .context("failed to read ingress_backend_url")?,
        updated_at: Some(updated_at.with_timezone(&Utc)),
        discovery: None,
    }))
}

async fn write_service_state_to_db(service_state: &ServiceDeploymentState) -> Result<()> {
    let db = db::get_db()?;
    write_service_state_in(db,service_state).await
}

pub(super) async fn write_service_state_in(db: &impl ConnectionTrait, service_state: &ServiceDeploymentState) -> Result<()> {
    let route = service_state
        .route
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .context("failed to serialize service route")?;
    let route_value = match route {
        Some(value) => SeaValue::Json(Some(Box::new(value))),
        None => SeaValue::Json(None),
    };
    let active_metadata = SeaValue::Json(Some(Box::new(service_state.active_metadata.clone())));
    let previous_metadata = match service_state.previous_metadata.clone() {
        Some(value) => SeaValue::Json(Some(Box::new(value))),
        None => SeaValue::Json(None),
    };
    let replica_regions = SeaValue::Json(Some(Box::new(json!(service_state.replica_regions))));

    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO service_deployment_states (
            service_id, active_deployment_id, active_archive_id, active_backend_url,
            previous_deployment_id, previous_archive_id, active_metadata, previous_metadata,
            deployment_environment, desired_replicas, replica_regions, route, ingress_backend_url, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
        ON CONFLICT (service_id) DO UPDATE SET
            active_deployment_id = EXCLUDED.active_deployment_id,
            active_archive_id = EXCLUDED.active_archive_id,
            active_backend_url = EXCLUDED.active_backend_url,
            previous_deployment_id = EXCLUDED.previous_deployment_id,
            previous_archive_id = EXCLUDED.previous_archive_id,
            active_metadata = EXCLUDED.active_metadata,
            previous_metadata = EXCLUDED.previous_metadata,
            deployment_environment = COALESCE(service_deployment_states.deployment_environment, EXCLUDED.deployment_environment),
            desired_replicas = EXCLUDED.desired_replicas,
            replica_regions = EXCLUDED.replica_regions,
            route = EXCLUDED.route,
            ingress_backend_url = EXCLUDED.ingress_backend_url,
            updated_at = NOW()",
        vec![
            service_state.service_id.clone().into(),
            service_state.active_deployment_id.clone().into(),
            service_state.active_archive_id.clone().into(),
            service_state.active_backend_url.clone().into(),
            service_state.previous_deployment_id.clone().into(),
            service_state.previous_archive_id.clone().into(),
            active_metadata,
            previous_metadata,
            service_state.deployment_environment.clone().into(),
            i32::from(service_state.desired_replicas).into(),
            replica_regions,
            route_value,
            service_state.ingress_backend_url.clone().into(),
        ],
    ))
    .await
    .context("failed to write service deployment state")?;

    Ok(())
}

fn build_deployment_metadata(
    request: &ServiceDeployRequest,
    deployment_id: &str,
    archive_sha256: &str,
    resolved_secrets: &[ResolvedSecretRef],
) -> serde_json::Value {
    let mut env_keys = request
        .env
        .as_ref()
        .map(|env| env.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    env_keys.sort();
    env_keys.dedup();

    let mut env_refs = request.env_refs.clone();
    env_refs.sort();
    env_refs.dedup();

    json!({
        "deploymentId": deployment_id,
        "archiveId": request.archive_id,
        "archiveName": request.archive_name,
        "archiveSha256": archive_sha256,
        "requestedAt": Utc::now(),
        "source": request.metadata,
        "runtime": {
            "driver": request.driver,
            "image": request.image,
            "region": request.region,
            "deploymentEnvironment": request.deployment_environment,
            "sizeClass": request.size_class,
            "ports": request.ports,
            "portMappings": request.port_mappings,
            "mounts": request.mounts,
            "workingDirectory": request.working_directory,
            "startCommand": request.start_command,
            "healthPath": request.health_path,
            "replicaRegions": request.replica_regions,
            "placementPool": request.placement_pool,
        },
        "environment": {
            "envKeys": env_keys,
            "envRefs": env_refs,
            "resolvedSecrets": resolved_secrets,
            "valuesRedacted": true,
        }
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ResolvedSecretRef {
    env: String,
    path: String,
    version: i32,
    status: String,
}

async fn resolve_env_refs(
    state: &AppState,
    request: &mut ServiceDeployRequest,
) -> Result<Vec<ResolvedSecretRef>> {
    if request.env_refs.is_empty() {
        return Ok(Vec::new());
    }
    if state.config.heyosecret_url.trim().is_empty() {
        anyhow::bail!("ORCHESTRATOR_HEYOSECRET_URL or HEYOSECRET_URL is required when envRefs are present");
    }

    let heyosecret_token = if state.config.heyosecret_internal_api_key.trim().is_empty() {
        state.config.internal_api_key.clone()
    } else {
        state.config.heyosecret_internal_api_key.clone()
    };

    let client = HeyoSecretClient::new(HeyoSecretClientOptions {
        base_url: state.config.heyosecret_url.clone(),
        token: heyosecret_token,
        timeout: Some(Duration::from_secs(10)),
    })
    .context("failed to create HeyoSecret client")?;

    let mut env = request.env.clone().unwrap_or_default();
    let mut resolved = Vec::with_capacity(request.env_refs.len());
    for reference in &request.env_refs {
        let (env_key, secret_ref) = parse_env_ref(reference)?;
        let (secret_path, version_selector) = parse_secret_ref(&secret_ref)?;
        let secret = read_heyosecret_ref_with_retry(&client, &secret_path, version_selector)
            .await
            .with_context(|| format!("failed to read HeyoSecret ref {secret_ref}"))?;
        let value = String::from_utf8(secret.value)
            .with_context(|| format!("secret {secret_path} is not valid UTF-8 for env injection"))?;
        env.insert(env_key.clone(), value);
        resolved.push(ResolvedSecretRef {
            env: env_key,
            path: secret.path,
            version: secret.version,
            status: format!("{:?}", secret.status).to_ascii_lowercase(),
        });
    }
    request.env = Some(env);
    Ok(resolved)
}

async fn read_heyosecret_ref_with_retry(
    client: &HeyoSecretClient,
    secret_path: &str,
    version_selector: SecretVersionSelector,
) -> Result<heyosecret_client::SecretValue> {
    let mut last_error = None;
    for attempt in 1..=12 {
        let result = match version_selector {
            SecretVersionSelector::Active => client.read_active(secret_path).await,
            SecretVersionSelector::Version(version) => client.read(secret_path, Some(version)).await,
        };
        match result {
            Ok(secret) => return Ok(secret),
            Err(error) => {
                warn!(
                    secret_path,
                    attempt,
                    "failed to read HeyoSecret ref; retrying: {error:#}"
                );
                last_error = Some(error);
                if attempt < 12 {
                    sleep(Duration::from_secs(attempt)).await;
                }
            }
        }
    }
    Err(last_error
        .expect("retry loop should record at least one HeyoSecret error")
        .into())
}

#[derive(Debug, Clone, Copy)]
enum SecretVersionSelector {
    Active,
    Version(i32),
}

fn parse_env_ref(reference: &str) -> Result<(String, String)> {
    let (key, value) = reference
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("envRef must be KEY=heyosecret://path[@active|@version]"))?;
    let key = key.trim();
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        || key.chars().next().is_some_and(|ch| ch.is_ascii_digit())
    {
        anyhow::bail!("envRef key must be an uppercase environment variable name: {key}");
    }
    Ok((key.to_string(), value.trim().to_string()))
}

fn parse_secret_ref(reference: &str) -> Result<(String, SecretVersionSelector)> {
    let rest = reference
        .strip_prefix("heyosecret://")
        .ok_or_else(|| anyhow::anyhow!("envRef value must start with heyosecret://"))?;
    let (path, selector) = match rest.rsplit_once('@') {
        Some((path, "active")) => (path, SecretVersionSelector::Active),
        Some((path, version)) => {
            let version = version
                .parse::<i32>()
                .with_context(|| format!("invalid HeyoSecret version selector @{version}"))?;
            (path, SecretVersionSelector::Version(version))
        }
        None => (rest, SecretVersionSelector::Active),
    };
    if path.trim().is_empty() {
        anyhow::bail!("HeyoSecret ref path cannot be empty");
    }
    Ok((path.to_string(), selector))
}

fn service_state_path(state: &AppState, service_id: &str) -> Result<PathBuf> {
    let service_id = sanitize_service_id(service_id)?;
    let base = state.config.service_state_dir.trim();
    if base.is_empty() {
        anyhow::bail!("ORCHESTRATOR_SERVICE_STATE_DIR must not be empty");
    }
    Ok(Path::new(base).join(format!("{service_id}.json")))
}

pub(super) fn sanitize_service_id(service_id: &str) -> Result<String> {
    let trimmed = service_id.trim();
    if trimmed.is_empty() {
        anyhow::bail!("serviceId is required");
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        anyhow::bail!("serviceId must contain only lowercase letters, digits, and '-' characters");
    }
    Ok(trimmed.to_string())
}

fn join_url_path(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim();
    if path.is_empty() || path == "/" {
        base.to_string()
    } else if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

fn proxy_subdomain_and_path(url: &str, base_domains: &str) -> Option<(String, String)> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (host, path) = match without_scheme.split_once('/') {
        Some((host, path)) => (host, format!("/{path}")),
        None => (without_scheme, "/".to_string()),
    };
    let host = host.split(':').next().unwrap_or(host);
    let subdomain = proxy_subdomain_for_host(host, base_domains)?;
    if subdomain.is_empty() || subdomain.contains('.') {
        return None;
    }
    Some((subdomain, path))
}

fn proxy_subdomain_for_host(host: &str, base_domains: &str) -> Option<String> {
    for base_domain in base_domains.split(',').map(str::trim) {
        let base_domain = base_domain.trim_matches('.');
        if base_domain.is_empty() {
            continue;
        }
        let suffix = format!(".{base_domain}");
        if let Some(subdomain) = host.strip_suffix(&suffix) {
            if subdomain.is_empty() || subdomain.contains('.') {
                return None;
            }
            return Some(subdomain.to_string());
        }
    }
    None
}

fn default_region() -> String {
    "local".to_string()
}

fn default_driver() -> String {
    "firecracker_containerd".to_string()
}

fn default_image() -> String {
    "ubuntu:24.04".to_string()
}

fn default_size_class() -> String {
    "small".to_string()
}

fn default_health_probe_timeout_seconds() -> u64 {
    SERVICE_HEALTH_REQUEST_TIMEOUT_SECONDS
}

fn default_health_path() -> String {
    "/health".to_string()
}

fn default_health_timeout_seconds() -> u64 {
    DEFAULT_HEALTH_TIMEOUT_SECONDS
}

fn default_desired_replicas() -> u16 {
    1
}

fn default_drain_seconds() -> u64 {
    DEFAULT_DRAIN_SECONDS
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::{
        active_endpoint_count, app_lb_route_health_url, candidate_endpoint_urls,
        deployment_run_status, health_observation_is_stable, parse_env_ref,
        parse_ls_remote_revision, parse_secret_ref, proxy_subdomain_and_path,
        rolling_placement_exclusions, rollout_candidate_regions, rollout_candidates_needed,
        rollout_old_endpoints, rollout_replacement, target_endpoint_count,
        target_regions_covered, target_regions_ready, validate_revision_ref,
        validate_revision_repository_url, validate_revision_sha, validate_service_traffic_mode,
        verify_applied_placement, enforce_deployment_environment_identity,
        SecretVersionSelector, ServiceDeploymentState, ServiceDeployRequest, ServiceRouteRequest,
        list_pending_service_retirements, try_service_lifecycle_lock,
    };
    use crate::cloud_client::CreateDeploymentResponse;
    use crate::handlers::service_discovery::{
        ServiceDiscoveryEndpoint, ServiceDiscoverySnapshot,
    };
    use anyhow::Result;
    use chrono::Utc;
    use sea_orm::{ConnectionTrait, DbBackend, Statement, TransactionTrait};
    use uuid::Uuid;

    fn discovery_snapshot() -> ServiceDiscoverySnapshot {
        ServiceDiscoverySnapshot {
            service_id: "cloud".to_string(),
            version: 7,
            regional_policy: None,
            endpoints: vec![
                ServiceDiscoveryEndpoint {
                    deployment_id: "old-us2".to_string(),
                    backend_server_id: Some("us2".to_string()),
                    region: Some("EU".to_string()),
                    revision: Some("old".to_string()),
                    url: "http://us2.internal:24001".to_string(),
                    health_status: "healthy".to_string(),
                    draining: false,
                },
                ServiceDiscoveryEndpoint {
                    deployment_id: "new-us3".to_string(),
                    backend_server_id: Some("us3".to_string()),
                    region: Some("US".to_string()),
                    revision: Some("new".to_string()),
                    url: "http://us3.internal:24002".to_string(),
                    health_status: "healthy".to_string(),
                    draining: false,
                },
                ServiceDiscoveryEndpoint {
                    deployment_id: "draining-us4".to_string(),
                    backend_server_id: Some("us4".to_string()),
                    region: Some("US".to_string()),
                    revision: Some("old".to_string()),
                    url: "http://us4.internal:24003".to_string(),
                    health_status: "healthy".to_string(),
                    draining: true,
                },
            ],
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn keeps_discovery_internal_and_routes_public() {
        assert_eq!(
            candidate_endpoint_urls(
                "http://eu1.internal:2238",
                Some("https://aqorah.stage.heyo.computer"),
            ),
            (
                "http://eu1.internal:2238".to_string(),
                "https://aqorah.stage.heyo.computer".to_string(),
            )
        );
    }

    #[test]
    fn builds_health_url_against_the_selected_app_lb() {
        let route = ServiceRouteRequest {
            host: "stage.example.com".to_string(),
            path_prefix: Some("/orchestrator".to_string()),
            backend_url: None,
            entry_points: None,
            cert_resolver: None,
            priority: None,
            strip_prefix: false,
            pass_host_header: false,
        };
        assert_eq!(
            app_lb_route_health_url("http://candidate.internal:8080", &route, "/health")
                .unwrap(),
            "http://candidate.internal:8080/orchestrator/health"
        );
    }

    #[test]
    fn health_must_remain_stable_before_cutover() {
        let start = tokio::time::Instant::now();
        let mut healthy_since = None;
        assert!(!health_observation_is_stable(
            &mut healthy_since,
            "http://candidate/health",
            start,
        ));
        assert!(!health_observation_is_stable(
            &mut healthy_since,
            "http://candidate/health",
            start + std::time::Duration::from_secs(9),
        ));
        assert!(health_observation_is_stable(
            &mut healthy_since,
            "http://candidate/health",
            start + std::time::Duration::from_secs(10),
        ));
        assert!(!health_observation_is_stable(
            &mut healthy_since,
            "http://replacement/health",
            start + std::time::Duration::from_secs(11),
        ));
    }

    #[test]
    fn plans_rollout_from_observed_revision_membership() {
        let snapshot = discovery_snapshot();
        assert_eq!(active_endpoint_count(Some(&snapshot)), 2);
        assert_eq!(target_endpoint_count(Some(&snapshot), "new"), 1);
        assert_eq!(
            rollout_old_endpoints(Some(&snapshot), "new")
                .into_iter()
                .map(|endpoint| endpoint.deployment_id.as_str())
                .collect::<Vec<_>>(),
            ["draining-us4", "old-us2"]
        );
    }

    #[test]
    fn replacement_allows_candidate_on_replaced_host_only() {
        let snapshot = discovery_snapshot();
        assert_eq!(
            rolling_placement_exclusions(Some(&snapshot), Some("old-us2")),
            ["us3"]
        );
        assert_eq!(
            rolling_placement_exclusions(Some(&snapshot), None),
            ["us2", "us3"]
        );
    }

    #[test]
    fn converges_from_observed_target_and_total_counts() {
        let snapshot = discovery_snapshot();
        assert_eq!(rollout_candidates_needed(Some(&snapshot), "new", 2, true), 1);
        assert_eq!(rollout_candidates_needed(Some(&snapshot), "new", 2, false), 0);
        assert_eq!(rollout_candidates_needed(None, "new", 2, true), 2);
    }

    #[test]
    fn regional_rollout_adds_missing_capacity_before_replacing_a_region() {
        let mut snapshot = discovery_snapshot();
        snapshot.endpoints.truncate(1);
        let regions = vec!["EU".to_string(), "US".to_string()];
        assert_eq!(
            rollout_candidate_regions(Some(&snapshot), "new", &regions, true),
            ["US", "EU"]
        );

        snapshot.endpoints.push(ServiceDiscoveryEndpoint {
            deployment_id: "new-us3".to_string(),
            backend_server_id: Some("us3".to_string()),
            region: Some("US".to_string()),
            revision: Some("new".to_string()),
            url: "http://us3.internal:24002".to_string(),
            health_status: "healthy".to_string(),
            draining: false,
        });
        assert_eq!(
            rollout_replacement(Some(&snapshot), "new", "EU", &regions, 2)
                .map(|endpoint| endpoint.deployment_id),
            Some("old-us2".to_string())
        );
        snapshot.endpoints[0].revision = Some("new".to_string());
        assert!(target_regions_ready(Some(&snapshot), "new", &regions));

        snapshot.endpoints.push(ServiceDiscoveryEndpoint {
            deployment_id: "extra-eu".to_string(),
            backend_server_id: Some("eu2".to_string()),
            region: Some("EU".to_string()),
            revision: Some("new".to_string()),
            url: "http://eu2.internal:24003".to_string(),
            health_status: "healthy".to_string(),
            draining: false,
        });
        assert!(target_regions_covered(Some(&snapshot), "new", &regions));
        assert!(!target_regions_ready(Some(&snapshot), "new", &regions));
    }

    #[test]
    fn retirement_events_do_not_complete_the_parent_rollout() {
        assert_eq!(deployment_run_status("previous-deleted", "passed"), "running");
        assert_eq!(deployment_run_status("rollout-candidate-healthy", "running"), "running");
        assert_eq!(deployment_run_status("completed", "passed"), "passed");
        assert_eq!(deployment_run_status("candidate-create", "failed"), "failed");
    }

    #[test]
    fn keeps_direct_and_discovery_traffic_modes_distinct() {
        assert!(validate_service_traffic_mode("cloud", None, true, false).is_ok());
        assert!(validate_service_traffic_mode("cloud", Some(2), true, true).is_ok());

        assert!(validate_service_traffic_mode("cloud", None, false, true).is_err());
        assert!(validate_service_traffic_mode("cloud", Some(2), false, false).is_err());
        assert!(validate_service_traffic_mode("cloud", Some(2), false, true).is_err());
        assert!(validate_service_traffic_mode("app-lb", Some(2), true, true).is_err());
        assert!(validate_service_traffic_mode("cloud", Some(0), false, true).is_err());
        assert!(validate_service_traffic_mode("cloud", Some(17), false, true).is_err());
    }

    #[test]
    fn requires_cloud_to_confirm_scoped_placement() {
        let confirmed: CreateDeploymentResponse = serde_json::from_value(serde_json::json!({
            "deploymentId": "dep-1",
            "placement": {
                "deploymentEnvironment": "staging",
                "nodeId": "eu1",
                "placementPool": "platform",
                "region": "EU"
            },
            "status": "running"
        }))
        .unwrap();
        assert!(verify_applied_placement(Some("staging"), Some("platform"), "EU", &confirmed).is_ok());
        assert!(verify_applied_placement(Some("production"), Some("platform"), "EU", &confirmed).is_err());
        assert!(verify_applied_placement(Some("staging"), Some("platform"), "US", &confirmed).is_err());

        let production: CreateDeploymentResponse = serde_json::from_value(serde_json::json!({
            "deploymentId": "dep-production",
            "placement": {
                "deploymentEnvironment": "production",
                "nodeId": "eu2",
                "placementPool": "platform",
                "region": "EU"
            },
            "status": "running"
        })).unwrap();
        assert!(verify_applied_placement(Some("production"), Some("platform"), "EU", &production).is_ok());
        assert!(verify_applied_placement(Some("staging"), Some("platform"), "EU", &production).is_err());
        assert!(verify_applied_placement(Some("production"), Some("other"), "EU", &production).is_err());

        let environment_only: CreateDeploymentResponse = serde_json::from_value(serde_json::json!({
            "deploymentId": "dep-env",
            "placement": {
                "deploymentEnvironment": "staging",
                "nodeId": "eu1",
                "region": "EU"
            },
            "status": "running"
        })).unwrap();
        assert!(verify_applied_placement(Some("staging"), None, "EU", &environment_only).is_ok());

        let legacy: CreateDeploymentResponse = serde_json::from_value(serde_json::json!({
            "deploymentId": "dep-2",
            "status": "running"
        }))
        .unwrap();
        assert!(verify_applied_placement(None, None, "US", &legacy).is_ok());
        assert!(verify_applied_placement(Some("staging"), None, "US", &legacy).is_err());
        assert!(verify_applied_placement(Some("staging"), Some("platform"), "US", &legacy).is_err());
    }

    #[test]
    fn deployment_environment_is_immutable_for_occupied_service_identity() {
        let mut state = ServiceDeploymentState {
            service_id: "api".into(),
            active_deployment_id: Some("dep-1".into()),
            ..Default::default()
        };
        assert!(enforce_deployment_environment_identity(&state, Some("production")).is_err());
        state.deployment_environment = Some("staging".into());
        assert!(enforce_deployment_environment_identity(&state, Some("staging")).is_ok());
        assert!(enforce_deployment_environment_identity(&state, Some("production")).is_err());
        assert!(enforce_deployment_environment_identity(&state, None).is_err());

        state.active_deployment_id = None;
        assert!(enforce_deployment_environment_identity(&state, Some("production")).is_err());
    }

    #[test]
    fn parses_env_secret_refs() {
        let (key, reference) = parse_env_ref("JWT_SECRET=heyosecret://platform/jwt/key@active").unwrap();
        assert_eq!(key, "JWT_SECRET");
        let (path, selector) = parse_secret_ref(&reference).unwrap();
        assert_eq!(path, "platform/jwt/key");
        assert!(matches!(selector, SecretVersionSelector::Active));

        let (path, selector) = parse_secret_ref("heyosecret://cicd/runner-token@3").unwrap();
        assert_eq!(path, "cicd/runner-token");
        assert!(matches!(selector, SecretVersionSelector::Version(3)));
    }

    #[test]
    fn rejects_invalid_env_secret_refs() {
        assert!(parse_env_ref("jwt=heyosecret://platform/jwt/key").is_err());
        assert!(parse_secret_ref("env://platform/jwt/key").is_err());
        assert!(parse_secret_ref("heyosecret://platform/jwt/key@nope").is_err());
    }

    #[test]
    fn parses_configured_proxy_health_urls() {
        assert_eq!(
            proxy_subdomain_and_path(
                "https://oj8wf6.stage.example.com/health",
                "stage.example.com,example.com"
            ),
            Some(("oj8wf6".to_string(), "/health".to_string()))
        );
        assert_eq!(
            proxy_subdomain_and_path(
                "https://oj8wf6.example.com/health",
                "stage.example.com,example.com"
            ),
            Some(("oj8wf6".to_string(), "/health".to_string()))
        );
        assert_eq!(
            proxy_subdomain_and_path(
                "https://foo.oj8wf6.stage.example.com/health",
                "stage.example.com,example.com"
            ),
            None
        );
        assert_eq!(
            proxy_subdomain_and_path("https://oj8wf6.example.com/health", ""),
            None
        );
    }

    #[test]
    fn parses_service_revision_guard_contract() {
        let request: ServiceDeployRequest = serde_json::from_value(serde_json::json!({
            "serviceId": "cloud",
            "userId": "heyo-system",
            "placementPool": "platform",
            "revisionGuard": {
                "repositoryUrl": "https://github.com/example/acme-service.git",
                "ref": "refs/heads/main",
                "expectedSha": "8265558143fa2da97be77aecb93a584575c919d1"
            }
        }))
        .unwrap();
        assert_eq!(request.placement_pool.as_deref(), Some("platform"));
        let guard = request.revision_guard.unwrap();
        assert_eq!(guard.git_ref, "refs/heads/main");
        assert!(!guard.force);
    }

    #[tokio::test]
    async fn host_ingress_deploy_without_replica_regions_stays_single_region() {
        let config: crate::config::Config = serde_json::from_value(serde_json::json!({
            "server_port":0,"database_url":"unused","agent_provider":"test","agent_model":"test","agent_api_key":"",
            "agent_timeout_seconds":1,"agent_max_iterations":1,"jwt_secret":"test","cloud_internal_url":"http://cloud",
            "internal_api_key":"test","heyosecret_url":"http://secrets","discovery_routed_services":"smoke",
            "discovery_observers":[{"service_id":"smoke","region":"us3","deployment_id":"smoke",
                "base_url":"http://lb","ingress_url":"http://lb",
                "discovery_url":"http://orch/orchestration/services/smoke/discovery","token_secret_path":"test/observer"}]
        })).unwrap();
        let state = crate::AppState { config: std::sync::Arc::new(config), http_client: reqwest::Client::new(),
            worker_id: std::sync::Arc::new("test".into()), ci_workspace_cache: Default::default() };
        let request = |regions: serde_json::Value| -> ServiceDeployRequest {
            serde_json::from_value(serde_json::json!({
                "serviceId":"smoke","userId":"u","desiredReplicas":1,"replicaRegions":regions,
                "route":{"host":"smoke.example","pathPrefix":"/smoke","stripPrefix":false}
            })).unwrap()
        };
        super::validate_service_deployment_request(&state, &request(serde_json::json!([]))).await.unwrap();
        super::validate_service_deployment_request(&state, &request(serde_json::json!(["us3"]))).await.unwrap();
        let (_, error) = super::validate_service_deployment_request(&state, &request(serde_json::json!(["eu1"])))
            .await.unwrap_err();
        assert!(error.contains("each rollout region"), "{error}");
    }

    #[test]
    fn validates_service_revision_guard_inputs() {
        assert_eq!(
            validate_revision_repository_url("https://github.com/example/acme-service.git").unwrap(),
            "https://github.com/example/acme-service.git"
        );
        for invalid in [
            "http://github.com/example/acme-service.git",
            "https://token@github.com/example/acme-service.git",
            "https://github.com.attacker.example/example/acme-service.git",
            "https://github.com:8443/example/acme-service.git",
            "https://github.com/example/acme-service.git?token=secret",
        ] {
            assert!(validate_revision_repository_url(invalid).is_err(), "{invalid}");
        }
        assert!(validate_revision_ref("refs/heads/main").is_ok());
        assert!(validate_revision_ref("main").is_err());
        assert!(validate_revision_ref("refs/heads/bad..branch").is_err());
        assert_eq!(
            validate_revision_sha("8265558143FA2DA97BE77AECB93A584575C919D1").unwrap(),
            "8265558143fa2da97be77aecb93a584575c919d1"
        );
        assert!(validate_revision_sha("82655581").is_err());
    }

    #[test]
    fn parses_exact_service_revision_from_ls_remote() {
        let output = b"8265558143fa2da97be77aecb93a584575c919d1\trefs/heads/main\n";
        assert_eq!(
            parse_ls_remote_revision(output, "refs/heads/main").unwrap(),
            "8265558143fa2da97be77aecb93a584575c919d1"
        );
        assert!(parse_ls_remote_revision(output, "refs/heads/release").is_err());
        let ambiguous = [output.as_slice(), output.as_slice()].concat();
        assert!(parse_ls_remote_revision(&ambiguous, "refs/heads/main").is_err());
    }

    #[tokio::test]
    #[ignore = "requires ORCHESTRATOR_TEST_DATABASE_URL (disposable PostgreSQL)"]
    async fn retirement_reactivation_and_supersession_postgres() -> Result<()> {
        let db = sea_orm::Database::connect(std::env::var("ORCHESTRATOR_TEST_DATABASE_URL")?).await?;
        let tx = db.begin().await?;
        let schema = format!("retirement_test_{}", Uuid::new_v4().simple());
        tx.execute_unprepared(&format!("CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema};")).await?;
        for migration in [
            include_str!("../../migrations/028_add_service_deployment_state.sql"),
            include_str!("../../migrations/030_add_service_deployment_runs.sql"),
            include_str!("../../migrations/031_add_service_discovery.sql"),
            include_str!("../../migrations/032_add_service_rollout_state.sql"),
            include_str!("../../migrations/034_cancel_reactivated_service_retirements.sql"),
            // Startup applies migrations repeatedly; cancellation must be idempotent.
            include_str!("../../migrations/034_cancel_reactivated_service_retirements.sql"),
        ] {
            tx.execute_unprepared(migration).await?;
        }
        tx.execute_unprepared("INSERT INTO service_deployment_states(service_id,active_deployment_id) VALUES ('orchestrator','replacement');
            INSERT INTO service_deployment_runs(deployment_id,service_id,status,phase) VALUES ('sept4','orchestrator','passed','completed'), ('today','orchestrator','running','rollout-drain');
            INSERT INTO service_deployment_events(deployment_id,service_id,phase,status,message,metadata,created_at) VALUES
            ('sept4','orchestrator','previous-retire-wait','running','drain','{\"response\":{\"previousDeploymentId\":\"old\",\"deletePrevious\":true,\"drainSeconds\":30}}',NOW()-INTERVAL '5 days'),
            ('sept4','orchestrator','completed','passed','done','{}',NOW()-INTERVAL '5 days');").await?;
        let eligible = list_pending_service_retirements(&tx).await?;
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].deployment_id, "sept4");
        assert_eq!(eligible[0].previous_deployment_id, "old");

        // The incident's direct recovery SQL: restoring old must permanently
        // revoke sept4's authority, not merely hide it while old is active.
        tx.execute_unprepared("UPDATE service_deployment_states SET active_deployment_id='old' WHERE service_id='orchestrator';").await?;
        assert!(list_pending_service_retirements(&tx).await?.is_empty());
        tx.execute_unprepared("UPDATE service_deployment_states SET active_deployment_id='replacement' WHERE service_id='orchestrator';").await?;
        assert!(list_pending_service_retirements(&tx).await?.is_empty());
        let row = tx.query_one(Statement::from_string(DbBackend::Postgres,
            "SELECT COUNT(*) AS count FROM service_deployment_events WHERE phase='previous-retire-cancelled'".to_string())).await?.unwrap();
        assert_eq!(row.try_get::<i64>("", "count")?, 1);

        // Upgrade after a recovery performed by the old binary: backfill must
        // cancel the existing active target, not only future state transitions.
        tx.execute_unprepared("ALTER TABLE service_deployment_states DISABLE TRIGGER cancel_reactivated_service_retirements;
            UPDATE service_deployment_states SET active_deployment_id='old';
            DELETE FROM service_deployment_events WHERE phase='previous-retire-cancelled';").await?;
        for _ in 0..2 {
            tx.execute_unprepared(include_str!("../../migrations/034_cancel_reactivated_service_retirements.sql")).await?;
        }
        tx.execute_unprepared("UPDATE service_deployment_states SET active_deployment_id='replacement';").await?;
        assert!(list_pending_service_retirements(&tx).await?.is_empty());
        let row = tx.query_one(Statement::from_string(DbBackend::Postgres,
            "SELECT COUNT(*) AS count FROM service_deployment_events WHERE phase='previous-retire-cancelled'".to_string())).await?.unwrap();
        assert_eq!(row.try_get::<i64>("", "count")?, 1);

        // Simulate an uncancelled legacy intent predating the migration. The
        // service's newer rollout blocks it even after its lease expires.
        tx.execute_unprepared("DELETE FROM service_deployment_events WHERE phase='previous-retire-cancelled';
            INSERT INTO service_rollouts(service_id,rollout_id,desired_replicas,status,stage,lease_expires_at) VALUES ('orchestrator','today',1,'running','rollout-drain',NOW()-INTERVAL '1 hour');").await?;
        assert!(list_pending_service_retirements(&tx).await?.is_empty());
        tx.execute_unprepared("UPDATE service_rollouts SET status='passed';").await?;
        assert!(list_pending_service_retirements(&tx).await?.is_empty());

        // Only today's own completed rollout and expired drain can retire old.
        tx.execute_unprepared("INSERT INTO service_deployment_events(deployment_id,service_id,phase,status,message,metadata,created_at) VALUES
            ('today','orchestrator','previous-retire-wait','running','drain','{\"response\":{\"previousDeploymentId\":\"old\",\"deletePrevious\":false,\"drainSeconds\":30}}',NOW());").await?;
        assert!(list_pending_service_retirements(&tx).await?.is_empty());
        tx.execute_unprepared("INSERT INTO service_deployment_events(deployment_id,service_id,phase,status,message) VALUES ('today','orchestrator','completed','passed','done');").await?;
        assert!(list_pending_service_retirements(&tx).await?.is_empty());
        tx.execute_unprepared("UPDATE service_deployment_events SET created_at=NOW()-INTERVAL '31 seconds' WHERE deployment_id='today' AND phase='previous-retire-wait';").await?;
        let eligible = list_pending_service_retirements(&tx).await?;
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].deployment_id, "today");
        assert!(!eligible[0].delete_previous);
        tx.execute_unprepared("UPDATE service_rollouts SET status='running';").await?;
        assert!(list_pending_service_retirements(&tx).await?.is_empty());
        tx.execute_unprepared("UPDATE service_rollouts SET status='passed';
            INSERT INTO service_deployment_events(deployment_id,service_id,phase,status,message,metadata) VALUES ('today','orchestrator','previous-retained','passed','done','{\"response\":{\"previousDeploymentId\":\"old\"}}');").await?;
        assert!(list_pending_service_retirements(&tx).await?.is_empty());
        tx.rollback().await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires ORCHESTRATOR_TEST_DATABASE_URL (disposable PostgreSQL)"]
    async fn retirement_lifecycle_lock_postgres() -> Result<()> {
        let url = std::env::var("ORCHESTRATOR_TEST_DATABASE_URL")?;
        let first = sea_orm::Database::connect(url.clone()).await?;
        let second = sea_orm::Database::connect(url).await?;
        let service = format!("lock-test-{}", Uuid::new_v4());
        let deployment = try_service_lifecycle_lock(&first, &service).await?.unwrap();
        assert!(try_service_lifecycle_lock(&second, &service).await?.is_none());
        let unrelated = try_service_lifecycle_lock(&second, &format!("{service}-other")).await?.unwrap();
        unrelated.rollback().await?;
        deployment.rollback().await?;
        let retirement = try_service_lifecycle_lock(&second, &service).await?.unwrap();
        assert!(try_service_lifecycle_lock(&first, &service).await?.is_none());
        retirement.rollback().await?;
        assert!(try_service_lifecycle_lock(&first, &service).await?.is_some());
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires ORCHESTRATOR_TEST_DATABASE_URL (disposable PostgreSQL)"]
    async fn deployment_environment_binding_survives_failure_and_restart_postgres() -> Result<()> {
        let url = std::env::var("ORCHESTRATOR_TEST_DATABASE_URL")?;
        let first = sea_orm::Database::connect(url.clone()).await?;
        let schema = format!("environment_test_{}", Uuid::new_v4().simple());
        let setup = first.begin().await?;
        setup.execute_unprepared(&format!("CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema};")).await?;
        setup.execute_unprepared(include_str!("../../migrations/028_add_service_deployment_state.sql")).await?;
        setup.execute_unprepared(include_str!("../../migrations/031_add_service_discovery.sql")).await?;
        setup.execute_unprepared(include_str!("../../migrations/033_add_service_replica_placement.sql")).await?;
        setup.execute_unprepared(include_str!("../../migrations/036_add_service_deployment_environment.sql")).await?;
        // Startup migration replay must also be safe.
        setup.execute_unprepared(include_str!("../../migrations/036_add_service_deployment_environment.sql")).await?;
        setup.execute_unprepared("INSERT INTO service_deployment_states(service_id,deployment_environment) VALUES ('api','production')").await?;
        setup.commit().await?;

        // A fresh pool represents a process restart after candidate failure. The
        // identity row has no active endpoint, but its binding remains authoritative.
        let restarted = sea_orm::Database::connect(url).await?;
        let read = restarted.begin().await?;
        read.execute_unprepared(&format!("SET LOCAL search_path TO {schema}")).await?;
        let row = read.query_one(Statement::from_string(DbBackend::Postgres,
            "SELECT service_id,deployment_environment,active_deployment_id FROM service_deployment_states WHERE service_id='api'")).await?.unwrap();
        let state = ServiceDeploymentState {
            service_id: row.try_get("", "service_id")?,
            deployment_environment: row.try_get("", "deployment_environment")?,
            active_deployment_id: row.try_get("", "active_deployment_id")?,
            ..Default::default()
        };
        assert_eq!(state.deployment_environment.as_deref(), Some("production"));
        assert!(enforce_deployment_environment_identity(&state, Some("staging")).is_err(),
            "wrong environment must fail before candidate creation or a Cloud request");
        assert!(enforce_deployment_environment_identity(&state, None).is_err());
        assert!(read.execute_unprepared("UPDATE service_deployment_states SET deployment_environment='staging' WHERE service_id='api'").await.is_err());
        read.rollback().await?;

        let cleanup = first.begin().await?;
        cleanup.execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE")).await?;
        cleanup.commit().await?;
        Ok(())
    }
}
