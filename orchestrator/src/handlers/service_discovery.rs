use anyhow::{Context, Result};
use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use sea_orm::{AccessMode, ConnectionTrait, DbBackend, IsolationLevel, Statement, TransactionTrait, Value as SeaValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{auth, db, AppState};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDiscoveryEndpoint {
    pub deployment_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_server_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    pub url: String,
    pub health_status: String,
    pub draining: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDiscoverySnapshot {
    pub service_id: String,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regional_policy: Option<super::regional_policy::RegionalPolicy>,
    pub endpoints: Vec<ServiceDiscoveryEndpoint>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryQuery {
    pub region: Option<String>,
    pub protocol: Option<String>,
    pub gateway_id: Option<String>,
    pub boot_id: Option<String>,
}

#[derive(Default, Deserialize)]
pub struct InventoryQuery {
    pub after: Option<String>,
}

/// Global inventory comes only from shared durable state, never this API
/// instance's local deployment files. Each page is one committed snapshot.
pub async fn list_services(
    headers: HeaderMap, State(state): State<AppState>, Query(query): Query<InventoryQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(status) = auth::require_internal_api_key(&headers, &state.config.internal_api_key) {
        return (status, Json(json!({"error":"Unauthorized"})));
    }
    let result = async { read_inventory(db::get_db()?, query.after.as_deref()).await }.await;
    match result {
        Ok(inventory) => (StatusCode::OK, Json(inventory)),
        Err(error) => {
            tracing::warn!(%error, "shared service inventory unavailable");
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"Shared service inventory unavailable"})))
        }
    }
}

pub(super) async fn read_inventory(db: &sea_orm::DatabaseConnection, after: Option<&str>) -> Result<serde_json::Value> {
    let tx = db.begin_with_config(Some(IsolationLevel::RepeatableRead), Some(AccessMode::ReadOnly)).await?;
    let rows = tx.query_all(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT ids.service_id,s.desired_replicas,s.replica_regions,
                (SELECT jsonb_agg(jsonb_build_object('deploymentId',e.deployment_id,'region',e.region,
                    'observedAt',e.observed_at,'lifecycleOwner',e.lifecycle_owner,'capabilities',e.capabilities)
                    ORDER BY e.region,e.deployment_id) FROM external_service_bindings e WHERE e.service_id=ids.service_id) AS external_bindings
         FROM (SELECT service_id FROM service_discovery_sets UNION SELECT service_id FROM service_deployment_states UNION SELECT service_id FROM external_service_bindings) ids
         LEFT JOIN service_deployment_states s USING(service_id)
         WHERE ($1::text IS NULL OR ids.service_id > $1) ORDER BY ids.service_id LIMIT 101",
        [after.map(str::to_owned).into()])).await?;
    let mut services = Vec::new();
    for row in rows.iter().take(100) {
        let id: String = row.try_get("", "service_id")?;
        let snapshot = read_snapshot_in(&tx, &id, true).await?;
        let operation = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT operation_id,status,phase,target_revision FROM regional_service_rollouts
             WHERE service_id=$1 ORDER BY created_at DESC,operation_id DESC LIMIT 1", [id.clone().into()])).await?;
        let rollout = operation.map(|r| -> Result<_> { Ok(json!({
            "operationId":r.try_get::<String>("","operation_id")?,"status":r.try_get::<String>("","status")?,
            "phase":r.try_get::<String>("","phase")?,"targetRevision":r.try_get::<String>("","target_revision")?
        })) }).transpose()?;
        let external_bindings: Option<Value> = row.try_get("","external_bindings")?;
        let external = external_bindings.as_ref().and_then(Value::as_array).filter(|v|v.len()==1).map(|v| {
            let mut singleton=v[0].clone(); singleton["externallyManaged"]=json!(false); singleton
        });
        let update = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT operation_id,status,intent,observation,observed_at,error FROM application_updates WHERE service_id=$1 ORDER BY created_at DESC,operation_id DESC LIMIT 1",[id.clone().into()])).await?
            .map(|r| -> Result<Value> {
                let intent: Value = r.try_get("","intent")?;
                let observation: Option<Value> = r.try_get("","observation")?;
                Ok(json!({"operationId":r.try_get::<String>("","operation_id")?,
                    "status":r.try_get::<String>("","status")?,"targetRevision":intent["targetRevision"],
                    "runId":intent["runId"],"phase":observation.as_ref().and_then(|o|o.get("phase")),
                    "observedAt":r.try_get::<Option<DateTime<Utc>>>("","observed_at")?,
                    "error":r.try_get::<Option<String>>("","error")?}))
            }).transpose()?;
        services.push(json!({"serviceId":id,
            "desiredReplicas":row.try_get::<Option<i32>>("","desired_replicas")?,
            "replicaRegions":row.try_get::<Option<serde_json::Value>>("","replica_regions")?,
            "discoveryVersion":snapshot.as_ref().map(|s|s.version),
            "endpoints":snapshot.as_ref().map(|s| &s.endpoints), "rollout":rollout,"external":external,
            "externalBindings":external_bindings,"update":update}));
    }
    let next = if rows.len() > 100 { services.last().map(|s| s["serviceId"].clone()) } else { None };
    tx.commit().await?;
    Ok(json!({"services":services,"nextCursor":next}))
}

fn scoped_response(mut snapshot: ServiceDiscoverySnapshot, region: Option<&str>) -> serde_json::Value {
    if let Some(region) = region {
        snapshot.endpoints.retain(|endpoint| endpoint.region.as_deref() == Some(region));
    }
    // Preserve the authoritative generation even for an empty regional set.
    // Echoing scope lets consumers distinguish a scoped empty response from
    // an older server silently ignoring the query parameter.
    let mut response = json!(snapshot);
    response["region"] = json!(region);
    response
}

pub async fn get_service_discovery(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(service_id): AxumPath<String>,
    Query(query): Query<DiscoveryQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(status) = auth::require_internal_api_key(&headers, &state.config.internal_api_key) {
        return (status, Json(json!({ "error": "Unauthorized" })));
    }

    if let Some(protocol) = &query.protocol {
        if protocol != "regional-v1" || query.region.is_none() || query.gateway_id.is_none() || query.boot_id.is_none() {
            return (StatusCode::BAD_REQUEST, Json(json!({"error":"regional-v1 requires region, gatewayId and bootId"})));
        }
        let result = async {
            read_regional_snapshot(db::get_db()?, &service_id, query.region.as_deref().unwrap(),
                query.gateway_id.as_deref().unwrap(), query.boot_id.as_deref().unwrap()).await
        }.await;
        return match result {
            Ok(value) => (StatusCode::OK, Json(value)),
            Err(error) => {
                tracing::warn!(%service_id, %error, "regional snapshot unavailable");
                (StatusCode::CONFLICT, Json(json!({"error":"regional snapshot is not authorized or ready"})))
            }
        };
    }
    match read_snapshot(&service_id).await {
        Ok(Some(snapshot)) => (StatusCode::OK, Json(scoped_response(snapshot, query.region.as_deref()))),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Service discovery set not found" })),
        ),
        Err(error) => {
            tracing::warn!(service_id, "failed to read service discovery set: {error:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to read service discovery set" })),
            )
        }
    }
}

pub async fn read_snapshot(service_id: &str) -> Result<Option<ServiceDiscoverySnapshot>> {
    read_snapshot_with_region_drains(service_id, true).await
}

/// One committed view of policy history, active reference, admission fences and
/// region-scoped membership. Draft regional_policy is never an active policy.
pub(super) async fn read_regional_snapshot(
    db: &sea_orm::DatabaseConnection, service: &str, region: &str, gateway: &str, boot: &str,
) -> Result<serde_json::Value> {
    let tx = db.begin_with_config(Some(IsolationLevel::RepeatableRead), Some(AccessMode::ReadOnly)).await?;
    let mut snapshot = read_snapshot_in(&tx, service, true).await?.context("discovery set is missing")?;
    let rows = tx.query_all(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT p.generation,p.policy,p.step_id,r.operation_id,r.phase,r.plan,r.observer_topology,r.deployment_request
         FROM regional_policy_proposals p JOIN regional_service_rollouts r USING(service_id,operation_id)
         WHERE p.service_id=$1 ORDER BY p.generation", [service.into()])).await?;
    let latest = rows.last().context("no published policy proposal")?;
    let participants: Vec<super::regional_reports::Participant> = serde_json::from_str(
        &latest.try_get::<String>("", "observer_topology")?)?;
    anyhow::ensure!(participants.iter().any(|p| p.gateway_id == gateway && p.region == region && p.boot_id == boot),
        "gateway boot is not pinned by current operation");
    anyhow::ensure!(tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT 1 FROM regional_gateway_reports WHERE service_id=$1 AND gateway_id=$2 AND boot_id=$3 AND invalidated",
        [service.into(), gateway.into(), boot.into()])).await?.is_none(), "gateway boot was invalidated");
    let request: serde_json::Value = latest.try_get("", "deployment_request")?;
    let environment = request.get("deploymentEnvironment").and_then(|v| v.as_str())
        .filter(|s| !s.is_empty()).context("regional operation must pin deploymentEnvironment")?;
    let plan: super::regional_plan::Plan = serde_json::from_value(latest.try_get("", "plan")?)?;
    let target = plan.publication(&latest.try_get::<String>("", "step_id")?)?.region.as_deref();
    let active = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT generation FROM service_active_regional_policies WHERE service_id=$1", [service.into()])).await?
        .map(|r| r.try_get::<i64>("", "generation")).transpose()?;
    let fence = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT closed_through_generation FROM service_regional_admission_fences WHERE service_id=$1 AND region=$2",
        [service.into(), region.into()])).await?.map(|r| r.try_get::<i64>("", "closed_through_generation")).transpose()?.unwrap_or(0);
    let policies = rows.iter().map(|r| -> Result<_> {
        Ok(json!({"generation":r.try_get::<i64>("", "generation")?,"policy":r.try_get::<serde_json::Value>("", "policy")?}))
    }).collect::<Result<Vec<_>>>()?;
    snapshot.endpoints.retain(|e| e.region.as_deref() == Some(region));
    let response = json!({"protocolVersion":1,"serviceId":service,"environment":environment,
        "region":region,"gatewayId":gateway,"bootId":boot,"version":snapshot.version,
        "operationId":latest.try_get::<String>("", "operation_id")?,"phase":latest.try_get::<String>("", "phase")?,
        "proposalGeneration":latest.try_get::<i64>("", "generation")?,"activeGeneration":active,
        "drainTarget":target,"closedThroughGeneration":fence,"policies":policies,"endpoints":snapshot.endpoints});
    tx.commit().await?;
    Ok(response)
}

/// Compensation must save individual drain intent, not materialize temporary
/// region exclusions as permanent replica drains.
pub(super) async fn read_stored_snapshot(service_id: &str) -> Result<Option<ServiceDiscoverySnapshot>> {
    read_snapshot_with_region_drains(service_id, false).await
}

async fn read_snapshot_with_region_drains(service_id: &str, effective: bool) -> Result<Option<ServiceDiscoverySnapshot>> {
    let db = db::get_db()?;
    // Version and membership must come from the same committed snapshot. A
    // watcher must never acknowledge a new version with an older endpoint set.
    let transaction = db.begin_with_config(
        Some(IsolationLevel::RepeatableRead), Some(AccessMode::ReadOnly),
    ).await?;
    let snapshot = read_snapshot_in(&transaction, service_id, effective).await?;
    transaction.commit().await?;
    Ok(snapshot)
}

pub(super) async fn read_snapshot_in(
    transaction: &impl ConnectionTrait, service_id: &str, effective: bool,
) -> Result<Option<ServiceDiscoverySnapshot>> {
    let set = transaction
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT version, updated_at, regional_policy FROM service_discovery_sets WHERE service_id = $1",
            [service_id.into()],
        ))
        .await
        .context("failed to query service discovery set")?;
    let Some(set) = set else {
        return Ok(None);
    };

    let version: i64 = set.try_get("", "version")?;
    let regional_policy: Option<serde_json::Value> = set.try_get("", "regional_policy")?;
    let regional_policy = regional_policy.map(serde_json::from_value).transpose()
        .context("invalid stored regional routing policy")?;
    let updated_at: DateTime<chrono::FixedOffset> = set.try_get("", "updated_at")?;
    let rows = transaction
        .query_all(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT deployment_id, backend_server_id, region, revision, backend_url, health_status,
                (draining OR ($2 AND EXISTS (
                    SELECT 1 FROM service_region_drains r
                    WHERE r.service_id = e.service_id AND r.region = e.region
                ))) AS draining
             FROM service_discovery_endpoints e
             WHERE e.service_id = $1
             ORDER BY deployment_id ASC",
            vec![service_id.into(), effective.into()],
        ))
        .await
        .context("failed to query service discovery endpoints")?;
    let endpoints = rows
        .into_iter()
        .map(|row| {
            Ok(ServiceDiscoveryEndpoint {
                deployment_id: row.try_get("", "deployment_id")?,
                backend_server_id: row.try_get("", "backend_server_id")?,
                region: row.try_get("", "region")?,
                revision: row.try_get("", "revision")?,
                url: row.try_get("", "backend_url")?,
                health_status: row.try_get("", "health_status")?,
                draining: row.try_get("", "draining")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Some(ServiceDiscoverySnapshot {
        service_id: service_id.to_string(),
        version: u64::try_from(version).context("service discovery version was negative")?,
        regional_policy,
        endpoints,
        updated_at: updated_at.with_timezone(&Utc),
    }))
}

pub async fn active_backend_server_ids(service_id: &str) -> Result<Vec<String>> {
    Ok(read_snapshot(service_id)
        .await?
        .map(|snapshot| {
            snapshot
                .endpoints
                .into_iter()
                .filter(|endpoint| !endpoint.draining)
                .filter_map(|endpoint| endpoint.backend_server_id)
                .collect()
        })
        .unwrap_or_default())
}

/// Publish a healthy candidate. Replacing a service marks old members draining;
/// adding capacity leaves existing members eligible. Membership and operator
/// drain intent stay durable even when a later health observation changes.
pub async fn publish_healthy_endpoint(
    service_id: &str,
    deployment_id: &str,
    backend_server_id: Option<&str>,
    region: Option<&str>,
    revision: Option<&str>,
    backend_url: &str,
    replace_existing: bool,
) -> Result<ServiceDiscoverySnapshot> {
    validate_endpoint_url(backend_url)?;
    let db = db::get_db()?;
    let transaction = db.begin().await?;
    ensure_set(&transaction, service_id).await?;
    if replace_existing {
        transaction
            .execute(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE service_discovery_endpoints
                 SET draining = TRUE, updated_at = NOW()
                 WHERE service_id = $1 AND deployment_id <> $2 AND draining = FALSE",
                [service_id.into(), deployment_id.into()],
            ))
            .await?;
    }
    transaction
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO service_discovery_endpoints (
                service_id, deployment_id, backend_server_id, region, revision,
                backend_url, health_status, draining, observed_at, updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6, 'healthy', FALSE, NOW(), NOW())
             ON CONFLICT (service_id, deployment_id) DO UPDATE SET
                backend_server_id = EXCLUDED.backend_server_id,
                region = EXCLUDED.region,
                revision = EXCLUDED.revision,
                backend_url = EXCLUDED.backend_url,
                health_status = 'healthy',
                draining = FALSE,
                observed_at = NOW(),
                updated_at = NOW()",
            vec![
                service_id.into(),
                deployment_id.into(),
                backend_server_id.map(str::to_string).into(),
                region.map(str::to_string).into(),
                revision.map(str::to_string).into(),
                backend_url.into(),
            ],
        ))
        .await?;
    bump_version(&transaction, service_id).await?;
    transaction.commit().await?;
    read_snapshot(service_id)
        .await?
        .context("published service discovery set disappeared")
}

pub async fn set_endpoint_region(
    service_id: &str,
    deployment_id: &str,
    region: &str,
) -> Result<()> {
    let db = db::get_db()?;
    let transaction = db.begin().await?;
    let result = transaction
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE service_discovery_endpoints
             SET region = $3, updated_at = NOW()
             WHERE service_id = $1 AND deployment_id = $2 AND region IS NULL",
            [service_id.into(), deployment_id.into(), region.into()],
        ))
        .await?;
    if result.rows_affected() > 0 {
        bump_version(&transaction, service_id).await?;
    }
    transaction.commit().await?;
    Ok(())
}

/// Region exclusion applies even to candidates published after the drain.
/// Clearing it never clears a replica's independent retirement/operator drain.
pub async fn set_region_draining(service_id: &str, region: &str, draining: bool) -> Result<()> {
    let db = db::get_db()?;
    let transaction = db.begin().await?;
    ensure_set(&transaction, service_id).await?;
    let sql = if draining {
        "INSERT INTO service_region_drains (service_id, region) VALUES ($1, $2)
         ON CONFLICT (service_id, region) DO NOTHING"
    } else {
        "DELETE FROM service_region_drains WHERE service_id = $1 AND region = $2"
    };
    let result = transaction.execute(Statement::from_sql_and_values(
        DbBackend::Postgres, sql, [service_id.into(), region.into()],
    )).await?;
    if result.rows_affected() > 0 {
        bump_version(&transaction, service_id).await?;
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn mark_endpoint_draining(service_id: &str, deployment_id: &str) -> Result<()> {
    let db = db::get_db()?;
    let transaction = db.begin().await?;
    let result = transaction
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE service_discovery_endpoints
             SET draining = TRUE, updated_at = NOW()
             WHERE service_id = $1 AND deployment_id = $2 AND draining = FALSE",
            [service_id.into(), deployment_id.into()],
        ))
        .await?;
    if result.rows_affected() > 0 {
        bump_version(&transaction, service_id).await?;
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn mark_endpoint_active(service_id: &str, deployment_id: &str) -> Result<()> {
    let db = db::get_db()?;
    let transaction = db.begin().await?;
    cancel_endpoint_retirement(&transaction,service_id,deployment_id).await?;
    let result = transaction
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE service_discovery_endpoints
             SET draining = FALSE, updated_at = NOW()
             WHERE service_id = $1 AND deployment_id = $2 AND draining = TRUE",
            [service_id.into(), deployment_id.into()],
        ))
        .await?;
    if result.rows_affected() > 0 {
        bump_version(&transaction, service_id).await?;
    }
    transaction.commit().await?;
    Ok(())
}

pub(super) async fn cancel_endpoint_retirement(db: &impl ConnectionTrait, service_id: &str, deployment_id: &str) -> Result<()> {
    // Membership is authoritative for multi-replica rollback. Reactivating a
    // non-scalar replica must revoke historical retirement authority too.
    db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO service_deployment_events(deployment_id,service_id,phase,status,message,metadata)
         SELECT DISTINCT intent.deployment_id,intent.service_id,'previous-retire-cancelled','passed',
             'Retirement cancelled to protect retained or active discovery capacity.',
             jsonb_build_object('response',jsonb_build_object('previousDeploymentId',$2::TEXT))
         FROM service_deployment_events intent
         WHERE intent.service_id=$1 AND intent.phase='previous-retire-wait'
             AND intent.metadata->'response'->>'previousDeploymentId'=$2
             AND NOT EXISTS (SELECT 1 FROM service_deployment_events cancelled
                 WHERE cancelled.deployment_id=intent.deployment_id
                     AND cancelled.phase='previous-retire-cancelled'
                     AND cancelled.metadata->'response'->>'previousDeploymentId'=$2)",
        [service_id.into(),deployment_id.into()])).await?;
    Ok(())
}

pub async fn remove_endpoint(service_id: &str, deployment_id: &str) -> Result<()> {
    let db = db::get_db()?;
    let transaction = db.begin().await?;
    let result = transaction
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM service_discovery_endpoints WHERE service_id = $1 AND deployment_id = $2",
            [service_id.into(), deployment_id.into()],
        ))
        .await?;
    if result.rows_affected() > 0 {
        bump_version(&transaction, service_id).await?;
    }
    transaction.commit().await?;
    Ok(())
}

/// Restore the membership observed before a failed cutover. The set remains and
/// its version advances even when the old snapshot was absent, so watchers that
/// already saw the failed candidate receive an authoritative empty snapshot
/// rather than keeping that candidate forever after a 404.
pub async fn restore_snapshot(
    service_id: &str,
    snapshot: Option<&ServiceDiscoverySnapshot>,
) -> Result<()> {
    let db = db::get_db()?;
    let transaction = db.begin().await?;
    ensure_set(&transaction, service_id).await?;
    transaction
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM service_discovery_endpoints WHERE service_id = $1",
            [service_id.into()],
        ))
        .await?;
    if let Some(snapshot) = snapshot {
        for endpoint in &snapshot.endpoints {
            transaction
                .execute(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "INSERT INTO service_discovery_endpoints (
                        service_id, deployment_id, backend_server_id, region, revision,
                        backend_url, health_status, draining, observed_at, updated_at
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())",
                    vec![
                        service_id.into(),
                        endpoint.deployment_id.clone().into(),
                        endpoint.backend_server_id.clone().into(),
                        endpoint.region.clone().into(),
                        endpoint.revision.clone().into(),
                        endpoint.url.clone().into(),
                        endpoint.health_status.clone().into(),
                        endpoint.draining.into(),
                    ],
                ))
                .await?;
        }
    }
    bump_version(&transaction, service_id).await?;
    transaction.commit().await?;
    Ok(())
}

async fn ensure_set<C: ConnectionTrait>(connection: &C, service_id: &str) -> Result<()> {
    connection
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO service_discovery_sets (service_id) VALUES ($1)
             ON CONFLICT (service_id) DO NOTHING",
            [service_id.into()],
        ))
        .await?;
    Ok(())
}

async fn bump_version<C: ConnectionTrait>(connection: &C, service_id: &str) -> Result<()> {
    connection
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE service_discovery_sets
             SET version = version + 1, updated_at = NOW()
             WHERE service_id = $1",
            [SeaValue::String(Some(Box::new(service_id.to_string())))],
        ))
        .await?;
    Ok(())
}

pub(crate) fn validate_endpoint_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value).context("service discovery endpoint must be a URL")?;
    // `Url::port()` normalizes an explicit default `:80` to `None`, so inspect
    // the original authority to distinguish it from an omitted port.
    let authority = value
        .split_once("//")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .unwrap_or("");
    let has_explicit_port = if authority.starts_with('[') {
        authority.rfind("]:").is_some()
    } else {
        authority.rsplit_once(':').is_some()
    };
    if url.scheme() != "http"
        || url.host_str().is_none()
        || !has_explicit_port
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        anyhow::bail!(
            "service discovery endpoint must be a plaintext, credential-free, pathless URL with an explicit non-default port"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires ORCHESTRATOR_TEST_DATABASE_URL (disposable PostgreSQL)"]
    async fn global_inventory_is_shared_paginated_and_preserves_missing_discovery() -> Result<()> {
        let url = std::env::var("ORCHESTRATOR_TEST_DATABASE_URL")?;
        let root = sea_orm::Database::connect(url.clone()).await?;
        let schema = format!("inventory_{}", uuid::Uuid::new_v4().simple());
        root.execute_unprepared(&format!("CREATE SCHEMA {schema}")).await?;
        let mut options = sea_orm::ConnectOptions::new(url);
        options.set_schema_search_path(schema.clone());
        let first = sea_orm::Database::connect(options.clone()).await?;
        let second = sea_orm::Database::connect(options).await?;
        for migration in [include_str!("../../migrations/028_add_service_deployment_state.sql"),
            include_str!("../../migrations/031_add_service_discovery.sql"),
            include_str!("../../migrations/032_add_service_rollout_state.sql"),
            include_str!("../../migrations/033_add_service_replica_placement.sql"),
            include_str!("../../migrations/035_add_regional_service_rollouts.sql"),
            include_str!("../../migrations/037_add_regional_routing_policy.sql")] {
            first.execute_unprepared(migration).await?;
        }
        first.execute_unprepared("INSERT INTO service_deployment_states(service_id,desired_replicas,replica_regions,active_metadata)
            VALUES('a-service',2,'[\"US\",\"eu1\"]','{\"secret\":\"never-forward\"}');
            INSERT INTO service_discovery_sets(service_id,version) VALUES('a-service',9),('b-discovery-only',3);
            INSERT INTO service_discovery_endpoints(service_id,deployment_id,region,revision,backend_url,health_status)
            VALUES('a-service','one','US','rev-a','http://us:2222','healthy'),
                  ('a-service','two','eu1','rev-b','http://eu:3333','healthy');
            INSERT INTO service_region_drains(service_id,region) VALUES('a-service','eu1');
            INSERT INTO service_deployment_states(service_id)
            SELECT 'z-' || lpad(i::text,3,'0') FROM generate_series(1,100) i;").await?;
        let page = read_inventory(&first, None).await?;
        assert_eq!(page, read_inventory(&second, None).await?);
        assert_eq!(page["services"].as_array().unwrap().len(),100);
        assert_eq!(page["nextCursor"],"z-098");
        let service = &page["services"][0];
        assert_eq!(service["desiredReplicas"],2);
        assert_eq!(service["discoveryVersion"],9);
        assert_eq!(service["endpoints"][0]["draining"],false);
        assert_eq!(service["endpoints"][1]["draining"],true);
        assert_eq!(service["endpoints"][1]["revision"],"rev-b");
        assert!(page["services"][1]["desiredReplicas"].is_null());
        assert!(page["services"][2]["endpoints"].is_null());
        assert!(!page.to_string().contains("never-forward"));
        let tail = read_inventory(&second, Some("z-098")).await?;
        assert_eq!(tail["services"].as_array().unwrap().len(),2);
        assert_eq!(tail["services"][0]["serviceId"],"z-099");
        assert!(tail["nextCursor"].is_null());
        first.close().await?;
        second.close().await?;
        root.execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE")).await?;
        Ok(())
    }

    #[test]
    fn regional_response_preserves_generation_and_excludes_other_or_unplaced_endpoints() {
        let snapshot: ServiceDiscoverySnapshot = serde_json::from_value(json!({
            "serviceId":"svc", "version":17, "updatedAt":"2026-09-22T00:00:00Z",
            "regionalPolicy":{"version":1,"regions":[
                {"region":"us3","weight":2,"gateways":[{"id":"us-a","backendServerId":"host-us","url":"https://us.example"}]},
                {"region":"eu1","weight":1,"gateways":[{"id":"eu-a","backendServerId":"host-eu","url":"https://eu.example"}]}
            ]},
            "endpoints":[
                {"deploymentId":"us-a","region":"us3","url":"http://us:24001","healthStatus":"healthy","draining":false},
                {"deploymentId":"eu-a","region":"eu1","url":"http://eu:24002","healthStatus":"healthy","draining":false},
                {"deploymentId":"eu-b","region":"eu1","url":"http://eu:24003","healthStatus":"unhealthy","draining":true},
                {"deploymentId":"unknown","url":"http://old:24004","healthStatus":"healthy","draining":false}
            ]
        })).unwrap();
        let eu = scoped_response(snapshot.clone(), Some("eu1"));
        let us = scoped_response(snapshot.clone(), Some("us3"));
        assert_eq!(eu["regionalPolicy"], us["regionalPolicy"]);
        assert_eq!(eu["regionalPolicy"]["regions"].as_array().unwrap().len(), 2);
        assert_eq!(eu["region"], "eu1");
        assert_eq!(eu["version"], 17);
        assert_eq!(eu["endpoints"].as_array().unwrap().len(), 2);
        assert_eq!(eu["endpoints"][0]["deploymentId"], "eu-a");
        assert_eq!(eu["endpoints"][1]["draining"], true);
        let empty = scoped_response(snapshot.clone(), Some("absent"));
        assert_eq!(empty["region"], "absent");
        assert_eq!(empty["version"], 17);
        assert_eq!(empty["endpoints"], json!([]));
        assert_eq!(scoped_response(snapshot, None)["endpoints"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn discovery_endpoint_requires_cross_host_proxy_shape() {
        assert!(validate_endpoint_url("http://us3.internal:24001").is_ok());
        assert!(validate_endpoint_url("http://[::1]:80").is_ok());
        for invalid in [
            "https://us3.internal:443",
            "http://us3.internal",
            "http://user@us3.internal:24001",
            "http://us3.internal:24001/health",
        ] {
            assert!(validate_endpoint_url(invalid).is_err(), "accepted {invalid}");
        }
    }
}
