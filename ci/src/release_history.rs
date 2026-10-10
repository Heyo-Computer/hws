//! Service deployment evidence, not permission to execute a promotion.
//! Operator-declared obligations are frozen before jobs become schedulable.
use crate::{plan::Plan, release_policy::ServiceDeploymentScope, store::Store};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeSet;

pub(crate) fn scopes(plan: &Plan) -> Result<Vec<ServiceDeploymentScope>> {
    let mut scopes = None;
    for snapshot in plan.jobs.iter().filter_map(|j| j.release_policy.as_ref()) {
        if let Some(previous) = &scopes {
            ensure!(
                previous == &snapshot.service_deployments,
                "inconsistent frozen service scopes"
            );
        } else {
            scopes = Some(snapshot.service_deployments.clone());
        }
    }
    Ok(scopes.unwrap_or_default())
}

pub(crate) async fn enroll(
    tx: &mut Transaction<'_, Postgres>,
    run: &str,
    repository: &str,
    scopes: &[ServiceDeploymentScope],
    source: &str,
    bundle: Option<&str>,
    automatic: bool,
) -> Result<()> {
    // Lock only for this short history transaction, never for CI execution.
    // Stable ordering also permits concurrent multi-service admissions.
    let mut scopes: Vec<_> = scopes.iter().collect();
    scopes.sort_by_key(|s| (&s.environment, &s.service));
    for scope in scopes {
        ensure!(
            !scope.obligations.is_empty(),
            "service history requires obligations"
        );
        let obligations = serde_json::to_value(&scope.obligations)?;
        let id = format!(
            "service-{:x}",
            Sha256::digest(serde_json::to_vec(&json!([
                run,
                scope.environment,
                scope.service
            ]))?)
        );
        sqlx::query(
            "INSERT INTO ci_release_service_environment(name,service,repository) VALUES($1,$2,$3)
            ON CONFLICT(name,service) DO NOTHING",
        )
        .bind(&scope.environment)
        .bind(&scope.service)
        .bind(repository)
        .execute(&mut **tx)
        .await?;
        let env = sqlx::query(
            "SELECT repository,active_run FROM ci_release_service_environment
            WHERE name=$1 AND service=$2 FOR UPDATE",
        )
        .bind(&scope.environment)
        .bind(&scope.service)
        .fetch_one(&mut **tx)
        .await?;
        ensure!(
            crate::repos::same_repo(env.get("repository"), repository),
            "service repository changed"
        );
        if let Some(existing) = sqlx::query(
            "SELECT obligations,source,bundle_id FROM ci_release_service_deployment WHERE id=$1",
        )
        .bind(&id)
        .fetch_optional(&mut **tx)
        .await?
        {
            ensure!(
                existing.get::<Value, _>("obligations") == obligations
                    && existing.get::<&str, _>("source") == source
                    && (source != "promotion"
                        || existing.get::<Option<String>, _>("bundle_id").as_deref() == bundle),
                "service deployment replay differs"
            );
            continue;
        }
        for obligation in &scope.obligations {
            let valid: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM ci_job WHERE run_id=$1 AND job_key=$2
                AND jsonb_array_length(plan->'steps')>$3)",
            )
            .bind(run)
            .bind(&obligation.job)
            .bind(i32::try_from(obligation.step)?)
            .fetch_one(&mut **tx)
            .await?;
            ensure!(
                valid,
                "unknown persisted service obligation {}:{}",
                obligation.job,
                obligation.step
            );
        }
        sqlx::query("INSERT INTO ci_release_service_deployment(id,run_id,environment,service,source,automatic,obligations,bundle_id,created_at)
            SELECT $1,id,$3,$4,$5,$6,$7,$8,created_at FROM ci_run WHERE id=$2")
            .bind(&id).bind(run).bind(&scope.environment).bind(&scope.service).bind(source)
            .bind(automatic).bind(&obligations).bind(bundle).execute(&mut **tx).await?;
    }
    Ok(())
}

pub(crate) async fn enroll_retry(tx: &mut Transaction<'_, Postgres>, run: &str) -> Result<()> {
    let snapshots: Vec<Value> = sqlx::query_scalar("SELECT DISTINCT plan->'release_policy'->'service_deployments'
        FROM ci_job WHERE run_id=$1 AND jsonb_typeof(plan->'release_policy'->'service_deployments')='array'")
        .bind(run).fetch_all(&mut **tx).await?;
    ensure!(
        snapshots.len() <= 1,
        "inconsistent frozen retry service scopes"
    );
    if let Some(snapshot) = snapshots.first() {
        let scopes: Vec<ServiceDeploymentScope> = serde_json::from_value(snapshot.clone())?;
        let repository: String = sqlx::query_scalar("SELECT repo_url FROM ci_run WHERE id=$1")
            .bind(run)
            .fetch_one(&mut **tx)
            .await?;
        enroll(tx, run, &repository, &scopes, "ordinary", None, false).await?;
    }
    Ok(())
}

// All identities come from immutable effect intents, not job names or region
// suffixes. Legacy receipts without an artifact stay visible, but cannot prove
// equivalence to a retained candidate.
const EFFECTIVE_STEPS: &str = "WITH RECURSIVE lineage AS (
    SELECT j.id,j.job_key,j.carried_from,j.status,j.plan,j.finished_at FROM ci_job j WHERE j.run_id=$1
    UNION
    SELECT p.id,p.job_key,p.carried_from,p.status,p.plan,p.finished_at FROM lineage j
        JOIN ci_job p ON p.run_id=j.carried_from AND p.job_key=j.job_key
), obligations AS (
    SELECT j.id AS job_id,j.status AS job_status,j.finished_at AS job_finished_at,
        s.id AS step_id,s.status AS step_status,s.finished_at,
        j.plan->'steps'->((o->>'step')::int)->>'uses' AS action,c.deployment_id
    FROM jsonb_array_elements($2::jsonb) o JOIN lineage j ON j.job_key=o->>'job'
    LEFT JOIN ci_step s ON s.job_id=j.id AND s.idx=(o->>'step')::int
    LEFT JOIN ci_release_carried_deployment c ON c.job_id=j.id AND c.step_index=(o->>'step')::int
    WHERE j.carried_from IS NULL
) ";

const RECEIPTS: &str =
    "SELECT DISTINCT d.id,d.request_hash,d.service_id,d.sha,d.status,d.created_at,d.updated_at,
    COALESCE(s.intent->>'artifact',h.intent->'request'->>'artifact_sha256',
        u.request->'release'->>'artifactDigest',f.intent->>'artifact',
        m.request->>'archive_sha256',b.request->'artifact'->>'artifact_sha256',
        c.request->>'artifact') AS artifact
    FROM ci_service_deployment d
    LEFT JOIN ci_service_rollout s ON s.id=d.id
    LEFT JOIN ci_host_app_lb h ON h.id=d.id
    LEFT JOIN ci_regional_update u ON u.id=d.id
    LEFT JOIN ci_stateful_release_rollout f ON f.id=d.id
    LEFT JOIN ci_host_maintenance m ON m.id=d.id
    LEFT JOIN ci_host_heyvm_bootstrap b ON b.id=d.id
    LEFT JOIN ci_controller_rollout c ON c.id=d.id
    WHERE EXISTS(SELECT 1 FROM obligations o WHERE d.step_id=o.step_id OR d.id=o.deployment_id)
    ORDER BY d.id";

pub(crate) async fn settle(store: &Store) -> Result<()> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM ci_release_service_deployment
        WHERE status='running' ORDER BY created_at,id",
    )
    .fetch_all(store.pool())
    .await?;
    for id in ids {
        if let Err(error) = settle_one(store, &id).await {
            // Keep this service's uncertainty visible without preventing unrelated
            // services from settling or being promoted by the same reconciler.
            tracing::error!(deployment = %id, %error, "service history settlement blocked");
            sqlx::query("UPDATE ci_release_service_deployment SET error=$2 WHERE id=$1 AND status='running'")
                .bind(&id).bind(error.to_string()).execute(store.pool()).await?;
        }
    }
    Ok(())
}

async fn settle_one(store: &Store, id: &str) -> Result<()> {
    settle_in(store.pool().begin().await?, id).await
}

async fn settle_in(mut tx: Transaction<'_, Postgres>, id: &str) -> Result<()> {
    // Lock environment first, consistently with admission.
    let Some(env) = sqlx::query(
        "SELECT e.* FROM ci_release_service_environment e
        JOIN ci_release_service_deployment h ON h.environment=e.name AND h.service=e.service
        WHERE h.id=$1 FOR UPDATE OF e SKIP LOCKED",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    else {
        return Ok(());
    };
    let attempt = sqlx::query("SELECT * FROM ci_release_service_deployment WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if attempt.get::<&str, _>("status") != "running" {
        return Ok(());
    }
    let run: &str = attempt.get("run_id");
    let promotion = attempt.get::<&str, _>("source") == "promotion";
    if promotion {
        ensure!(
            env.get::<Option<String>, _>("active_run").as_deref() == Some(run),
            "promotion history lost its active-run fence"
        );
    }
    let obligations: Value = attempt.get("obligations");
    let steps = sqlx::query(&format!("{EFFECTIVE_STEPS} SELECT o.*,
        EXISTS(SELECT 1 FROM ci_service_deployment d WHERE d.step_id=o.step_id OR d.id=o.deployment_id) AS has_receipt
        FROM obligations o"))
        .bind(run).bind(&obligations).fetch_all(&mut *tx).await?;
    ensure!(
        steps.len() == obligations.as_array().map_or(0, Vec::len),
        "service obligation disappeared"
    );
    let receipts = sqlx::query(&format!("{EFFECTIVE_STEPS}{RECEIPTS}"))
        .bind(run)
        .bind(&obligations)
        .fetch_all(&mut *tx)
        .await?;
    if receipts
        .iter()
        .any(|r| !matches!(r.get::<&str, _>("status"), "passed" | "failed"))
    {
        return Ok(());
    }
    if steps.iter().any(|s| {
        s.get::<Option<&str>, _>("step_status")
            .is_none_or(|status| !matches!(status, "success" | "failure" | "cancelled" | "skipped"))
            && !matches!(
                s.get::<&str, _>("job_status"),
                "success" | "failure" | "cancelled" | "skipped"
            )
    }) {
        return Ok(());
    }
    let skipped = receipts.is_empty()
        && steps.iter().all(|s| {
            s.get::<Option<&str>, _>("step_status") == Some("skipped")
                || s.get::<&str, _>("job_status") == "skipped"
        });
    let success = !receipts.is_empty()
        && steps.iter().all(|s| {
            s.get::<Option<&str>, _>("step_status") == Some("success")
                && (!s.get::<Option<&str>, _>("action").is_some_and(|a| {
                    matches!(
                        a,
                        "ci/rollout-service"
                            | "ci/rollout-stateful-service"
                            | "ci/rollout-host-app-lb"
                            | "ci/deploy-controller"
                            | "ci/rollout-pooler"
                            | "ci/rollout-site"
                            | "ci/deploy-service"
                            | "ci/deploy-app-lb"
                            | "ci/host-heyvm-maintenance"
                            | "ci/bootstrap-host-heyvm"
                            | "ci/rollout-host-heyvmd"
                    )
                }) || s.get::<bool, _>("has_receipt"))
        })
        && receipts
            .iter()
            .all(|r| r.get::<&str, _>("status") == "passed");
    let revisions: BTreeSet<String> = receipts.iter().map(|r| r.get("sha")).collect();
    let artifacts: BTreeSet<String> = receipts.iter().filter_map(|r| r.get("artifact")).collect();
    let unknown: Vec<String> = receipts
        .iter()
        .filter(|r| r.get::<Option<String>, _>("artifact").is_none())
        .map(|r| r.get("id"))
        .collect();
    let revision = (revisions.len() == 1).then(|| revisions.first().unwrap().clone());
    let success = success && revision.is_some();
    let status = if skipped {
        "skipped"
    } else if success {
        "success"
    } else {
        "failure"
    };
    let mut identity =
        json!({"revision":revision,"artifacts":artifacts,"unverified_receipts":unknown});
    let mut bundle: Option<String> = attempt.get("bundle_id");
    if success {
        // Candidate identity includes bytes, not just a Git SHA. Only ready,
        // singleton retained builds are currently accepted by promotion APIs.
        let candidates = sqlx::query(
            "SELECT c.id,c.manifest,c.manifest_sha256 FROM ci_release_bundle c
            JOIN ci_release_build b ON b.id=c.build_id WHERE b.status='ready'
            AND c.repository=$1 AND c.manifest->>'revision'=$2 AND c.manifest->>'retained'='true'
            AND c.manifest->>'version'='2' ORDER BY c.created_at,c.id",
        )
        .bind(env.get::<&str, _>("repository"))
        .bind(&revision)
        .fetch_all(&mut *tx)
        .await?;
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter(|c| {
                let manifest: Value = c.get("manifest");
                manifest["repository"].as_str() == Some(env.get::<&str, _>("repository"))
                    && serde_json::to_vec(&manifest).is_ok_and(|bytes| {
                        hex::encode(Sha256::digest(bytes)) == c.get::<String, _>("manifest_sha256")
                    })
            })
            .collect();
        let matching = candidates
            .iter()
            .find(|c| {
                let manifest: Value = c.get("manifest");
                manifest["components"]
                    .as_object()
                    .is_some_and(|components| {
                        components.len() == 1
                            && components
                                .get(attempt.get::<&str, _>("service"))
                                .is_some_and(|a| {
                                    unknown.is_empty()
                                        && artifacts.len() == 1
                                        && a["sha256"].as_str()
                                            == artifacts.first().map(String::as_str)
                                })
                    })
            })
            .map(|c| c.get::<String, _>("id"));
        if bundle.is_some() {
            ensure!(
                candidates
                    .iter()
                    .any(|c| Some(c.get::<&str, _>("id")) == bundle.as_deref()),
                "promotion candidate is no longer retained"
            );
            // Successful promotion receipts must agree with the selected artifact.
            let manifest: Value = candidates
                .iter()
                .find(|c| Some(c.get::<&str, _>("id")) == bundle.as_deref())
                .unwrap()
                .get("manifest");
            let digest =
                manifest["components"][attempt.get::<&str, _>("service")]["sha256"].as_str();
            ensure!(
                digest.is_some() && artifacts.iter().all(|a| Some(a.as_str()) == digest),
                "promotion receipt artifact mismatch"
            );
            // Promotion execution already binds every artifact selection to
            // this immutable singleton manifest, including older action types
            // whose receipt does not retain the digest separately.
            identity =
                json!({"revision":revision,"artifacts":[digest.unwrap()],"unverified_receipts":[]});
        } else {
            bundle = matching;
        }
    }
    let error = (!success && !skipped).then_some(
        "Not every declared service obligation completed successfully with one verified revision",
    );
    // Carried effects retain their original order, even when a retry reruns a
    // verification step later. This is observation time, not remote wall time.
    let effect_completed: Option<chrono::DateTime<chrono::Utc>> =
        receipts.iter().map(|r| r.get("updated_at")).max();
    let completed = effect_completed.or_else(|| {
        steps
            .iter()
            .filter_map(|s| {
                s.get::<Option<chrono::DateTime<chrono::Utc>>, _>("finished_at")
                    .or_else(|| s.get("job_finished_at"))
            })
            .max()
    });
    let effect_key = serde_json::to_string(
        &receipts
            .iter()
            .map(|r| r.get::<&str, _>("id"))
            .collect::<Vec<_>>(),
    )?;
    sqlx::query("UPDATE ci_release_service_deployment SET status=$2,revision=$3,release_identity=$4,bundle_id=$5,
        error=$6,completed_at=COALESCE($7,now()),effect_key=$8 WHERE id=$1")
        .bind(id).bind(status).bind(&revision).bind(&identity).bind(&bundle).bind(error).bind(completed).bind(effect_key).execute(&mut *tx).await?;
    // Recompute both positions. A late older completion can fill in previous
    // without displacing current. Duplicate carried evidence prefers its first
    // attempt rather than presenting a retry as another deployment.
    sqlx::query("WITH current AS (
        SELECT id,bundle_id,release_identity FROM ci_release_service_deployment
        WHERE environment=$1 AND service=$2 AND status='success'
        ORDER BY completed_at DESC,effect_key DESC,created_at,id LIMIT 1
    ), previous AS (
        SELECT h.id,h.bundle_id FROM ci_release_service_deployment h,current c
        WHERE h.environment=$1 AND h.service=$2 AND h.status='success'
        AND h.release_identity IS DISTINCT FROM c.release_identity
        ORDER BY h.completed_at DESC,h.effect_key DESC,h.created_at,h.id LIMIT 1
    ) UPDATE ci_release_service_environment SET
        current_deployment=(SELECT id FROM current),current_bundle=(SELECT bundle_id FROM current),
        previous_deployment=(SELECT id FROM previous),previous_bundle=(SELECT bundle_id FROM previous),
        active_run=CASE WHEN $3 AND active_run=$4 THEN NULL ELSE active_run END,
        automation_held=automation_held OR $5,updated_at=now() WHERE name=$1 AND service=$2")
        .bind(attempt.get::<&str,_>("environment")).bind(attempt.get::<&str,_>("service"))
        .bind(promotion).bind(run).bind(status == "failure").execute(&mut *tx).await?;
    if promotion {
        sqlx::query("UPDATE ci_release_service_promotion SET completed_at=now() WHERE run_id=$1")
            .bind(run)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn view(store: &Store, environment: &str, service: &str) -> Result<Option<Value>> {
    let found: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_release_service_deployment WHERE environment=$1 AND service=$2)")
        .bind(environment).bind(service).fetch_one(store.pool()).await?;
    if !found {
        return Ok(None);
    }
    let state: Value = sqlx::query_scalar(
        "SELECT to_jsonb(e) FROM ci_release_service_environment e WHERE name=$1 AND service=$2",
    )
    .bind(environment)
    .bind(service)
    .fetch_one(store.pool())
    .await?;
    let mut result = json!({"state":state,"current_deployment":null,"previous_deployment":null});
    for key in ["current_deployment", "previous_deployment"] {
        if let Some(id) = state[key].as_str() {
            result[key] = sqlx::query_scalar("SELECT to_jsonb(h)-'obligations'-'release_identity' FROM ci_release_service_deployment h WHERE id=$1")
                .bind(id).fetch_one(store.pool()).await?;
        }
    }
    let mut history: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(h)-'release_identity'
        FROM ci_release_service_deployment h WHERE environment=$1 AND service=$2
        ORDER BY (status='running') DESC,completed_at DESC NULLS LAST,effect_key DESC,created_at,id LIMIT 20")
        .bind(environment).bind(service).fetch_all(store.pool()).await?;
    for entry in &mut history {
        let receipts = sqlx::query(&format!("{EFFECTIVE_STEPS}{RECEIPTS}"))
            .bind(entry["run_id"].as_str())
            .bind(&entry["obligations"])
            .fetch_all(store.pool())
            .await?;
        entry["deployments"] = json!(
            receipts
                .iter()
                .map(|r| json!({"service":r.get::<&str,_>("service_id"),
            "revision":r.get::<&str,_>("sha"),"status":r.get::<&str,_>("status")}))
                .collect::<Vec<_>>()
        );
        entry.as_object_mut().unwrap().remove("obligations");
    }
    let recovery: bool = sqlx::query_scalar("SELECT COALESCE((SELECT status IN ('failure','cancelled')
        FROM ci_release_service_deployment WHERE environment=$1 AND service=$2 AND completed_at IS NOT NULL
        AND status<>'skipped' ORDER BY completed_at DESC,effect_key DESC,created_at,id LIMIT 1),false)")
        .bind(environment).bind(service).fetch_one(store.pool()).await?;
    result["history"] = json!(history);
    result["recovery_required"] = json!(recovery);
    result["recovery_bundle"] = if recovery {
        state["current_bundle"].clone()
    } else {
        Value::Null
    };
    Ok(Some(result))
}

/// Explicit operator attribution for old receipts. Never inferred from today's
/// policy, service names, Git repositories, or former environment-wide bundles.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Import {
    run_id: String,
    scope: ServiceDeploymentScope,
    expected_receipts: std::collections::BTreeMap<String, String>,
}

pub(crate) async fn import(store: &Store, entries: Vec<Import>) -> Result<()> {
    for entry in entries {
        let mut tx = store.pool().begin().await?;
        let run = sqlx::query("SELECT repo_url,status FROM ci_run WHERE id=$1")
            .bind(&entry.run_id)
            .fetch_one(&mut *tx)
            .await?;
        ensure!(
            matches!(
                run.get::<&str, _>("status"),
                "success" | "failure" | "cancelled"
            ),
            "history import requires a terminal run"
        );
        ensure!(
            !entry.scope.environment.trim().is_empty() && !entry.scope.service.trim().is_empty(),
            "history import requires explicit environment and service"
        );
        ensure!(
            entry
                .scope
                .obligations
                .iter()
                .map(|o| (&o.job, o.step))
                .collect::<BTreeSet<_>>()
                .len()
                == entry.scope.obligations.len(),
            "duplicate imported obligation"
        );
        let receipts = sqlx::query(&format!("{EFFECTIVE_STEPS}{RECEIPTS}"))
            .bind(&entry.run_id)
            .bind(serde_json::to_value(&entry.scope.obligations)?)
            .fetch_all(&mut *tx)
            .await?;
        let actual: std::collections::BTreeMap<String, String> = receipts
            .iter()
            .map(|r| (r.get("id"), r.get("request_hash")))
            .collect();
        ensure!(
            !actual.is_empty() && actual == entry.expected_receipts,
            "import receipt IDs and immutable request hashes must match exactly"
        );
        ensure!(
            receipts
                .iter()
                .all(|r| matches!(r.get::<&str, _>("status"), "passed" | "failed")),
            "unsettled receipt cannot be imported"
        );
        enroll(
            &mut tx,
            &entry.run_id,
            run.get("repo_url"),
            std::slice::from_ref(&entry.scope),
            "legacy_import",
            None,
            false,
        )
        .await?;
        let id: String = sqlx::query_scalar(
            "SELECT id FROM ci_release_service_deployment
            WHERE run_id=$1 AND environment=$2 AND service=$3",
        )
        .bind(&entry.run_id)
        .bind(&entry.scope.environment)
        .bind(&entry.scope.service)
        .fetch_one(&mut *tx)
        .await?;
        let done: bool = sqlx::query_scalar(
            "SELECT completed_at IS NOT NULL FROM ci_release_service_deployment WHERE id=$1",
        )
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
        if done {
            continue;
        } // Exact replay: enrollment already checked attribution.
        let active: bool = sqlx::query_scalar("SELECT active_run IS NOT NULL FROM ci_release_service_environment WHERE name=$1 AND service=$2")
            .bind(&entry.scope.environment).bind(&entry.scope.service).fetch_one(&mut *tx).await?;
        ensure!(!active, "cannot import while a service promotion is active");
        let live: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ci_release_service_deployment
            WHERE environment=$1 AND service=$2 AND source<>'legacy_import') OR
            EXISTS(SELECT 1 FROM ci_release_service_promotion WHERE environment=$1 AND service=$2)",
        )
        .bind(&entry.scope.environment)
        .bind(&entry.scope.service)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(!live, "import history before activating scoped deployments");
        let first: chrono::DateTime<chrono::Utc> =
            receipts.iter().map(|r| r.get("created_at")).min().unwrap();
        let last: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT max(completed_at)
            FROM ci_release_service_deployment WHERE environment=$1 AND service=$2 AND id<>$3",
        )
        .bind(&entry.scope.environment)
        .bind(&entry.scope.service)
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(
            last.is_none_or(|last| last <= first),
            "import receipts in deployment order; overlapping history needs operator reconciliation"
        );
        sqlx::query("UPDATE ci_release_service_deployment SET created_at=$2 WHERE id=$1")
            .bind(&id)
            .bind(first)
            .execute(&mut *tx)
            .await?;
        settle_in(tx, &id).await?;
        let complete: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_release_service_deployment WHERE id=$1 AND completed_at IS NOT NULL)")
            .bind(&id).fetch_one(store.pool()).await?;
        ensure!(
            complete,
            "import obligations have not settled; entry was not imported"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_policy::ServiceDeploymentObligation;

    fn cloud() -> ServiceDeploymentScope {
        ServiceDeploymentScope {
            environment: "stage".into(),
            service: "cloud".into(),
            obligations: ["west", "east"]
                .into_iter()
                .map(|job| ServiceDeploymentObligation {
                    job: job.into(),
                    step: 0,
                })
                .collect(),
        }
    }

    async fn seed(store: &Store, run: &str, revision: &str, digest: &str) {
        // The unrelated job fails the run, while both service obligations pass.
        sqlx::query(
            "INSERT INTO ci_run(id,workflow_id,workflow_path,repo_url,sha,status)
            VALUES($1,'release','release.yml','repo',$2,'failure')",
        )
        .bind(run)
        .bind(revision)
        .execute(store.pool())
        .await
        .unwrap();
        for job in ["west", "east", "unrelated"] {
            let id = format!("{run}.{job}");
            let status = if job == "unrelated" {
                "failure"
            } else {
                "success"
            };
            let plan = json!({"steps":[{"uses":"ci/rollout-service"}],
                "release_policy":{"service_deployments":[cloud()]}});
            sqlx::query(
                "INSERT INTO ci_job(id,run_id,job_key,base_id,display,status,plan,finished_at)
                VALUES($1,$2,$3,$3,$3,$4,$5,now())",
            )
            .bind(&id)
            .bind(run)
            .bind(job)
            .bind(status)
            .bind(plan)
            .execute(store.pool())
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO ci_step(id,job_id,idx,name,uses,status,finished_at)
                VALUES($1,$1,0,'deploy','ci/rollout-service',$2,now())",
            )
            .bind(&id)
            .bind(status)
            .execute(store.pool())
            .await
            .unwrap();
            if job != "unrelated" {
                sqlx::query("INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,sha,git_ref)
                    VALUES($1,$1,$2,$1,$3,'immutable-request','passed',$4,'main')")
                    .bind(&id).bind(run).bind(format!("cloud-{job}")).bind(revision).execute(store.pool()).await.unwrap();
                sqlx::query(
                    "INSERT INTO ci_service_rollout(id,intent,deadline) VALUES($1,$2,now())",
                )
                .bind(&id)
                .bind(json!({"artifact":digest}))
                .execute(store.pool())
                .await
                .unwrap();
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires disposable CI_TEST_DATABASE_URL"]
    async fn history_preserves_real_revisions_across_import_deployment_and_retry() {
        let base = std::env::var("CI_TEST_DATABASE_URL").unwrap();
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        let schema = format!("service_history_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = reqwest::Url::parse(&base).unwrap();
        url.query_pairs_mut()
            .append_pair("options", &format!("-c search_path={schema}"));
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(
            url.as_str(),
            dir.path().join("logs"),
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();
        store.migrate().await.unwrap();
        store.migrate().await.unwrap();

        seed(&store, "old", &"a".repeat(40), &"d".repeat(64)).await;
        let entry = || Import {
            run_id: "old".into(),
            scope: cloud(),
            expected_receipts: ["old.west", "old.east"]
                .into_iter()
                .map(|id| (id.into(), "immutable-request".into()))
                .collect(),
        };
        let mut wrong = entry();
        wrong.expected_receipts.remove("old.east");
        assert!(import(&store, vec![wrong]).await.is_err());
        assert!(view(&store, "stage", "cloud").await.unwrap().is_none());
        import(&store, vec![entry()]).await.unwrap();
        import(&store, vec![entry()]).await.unwrap();
        let old = view(&store, "stage", "cloud").await.unwrap().unwrap();
        assert_eq!(old["current_deployment"]["revision"], "a".repeat(40));
        assert!(old["previous_deployment"].is_null());
        assert!(old["current_deployment"]["bundle_id"].is_null());
        assert_eq!(old["history"].as_array().unwrap().len(), 1);
        assert!(view(&store, "stage", "auth").await.unwrap().is_none());
        assert!(
            crate::release_environment::bundle_for_run(&store, "old")
                .await
                .unwrap()
                .is_none()
        );

        seed(&store, "new", &"b".repeat(40), &"e".repeat(64)).await;
        let mut tx = store.pool().begin().await.unwrap();
        enroll_retry(&mut tx, "new").await.unwrap();
        tx.commit().await.unwrap();
        sqlx::query("UPDATE ci_service_deployment SET status='running' WHERE id='new.east'")
            .execute(store.pool())
            .await
            .unwrap();
        settle(&store).await.unwrap();
        let pending = view(&store, "stage", "cloud").await.unwrap().unwrap();
        assert_eq!(pending["current_deployment"]["revision"], "a".repeat(40));
        assert!(pending["state"]["active_run"].is_null());
        sqlx::query("UPDATE ci_service_deployment SET status='passed' WHERE id='new.east'")
            .execute(store.pool())
            .await
            .unwrap();
        settle(&store).await.unwrap();
        settle(&store).await.unwrap();
        let deployed = view(&store, "stage", "cloud").await.unwrap().unwrap();
        assert_eq!(deployed["current_deployment"]["revision"], "b".repeat(40));
        assert_eq!(deployed["previous_deployment"]["revision"], "a".repeat(40));
        assert_eq!(deployed["recovery_required"], false);
        assert!(deployed["state"]["active_run"].is_null());

        // Failed-only retry carries successful jobs without copying their steps.
        sqlx::query(
            "INSERT INTO ci_run(id,workflow_id,workflow_path,repo_url,sha,status)
            VALUES('retry','release','release.yml','repo',$1,'success')",
        )
        .bind("b".repeat(40))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query("INSERT INTO ci_job(id,run_id,job_key,base_id,display,status,plan,carried_from,finished_at)
            SELECT 'retry.'||job_key,'retry',job_key,base_id,display,'success',plan,'new',now()
            FROM ci_job WHERE run_id='new' AND job_key IN ('west','east')")
            .execute(store.pool()).await.unwrap();
        let mut tx = store.pool().begin().await.unwrap();
        enroll_retry(&mut tx, "retry").await.unwrap();
        tx.commit().await.unwrap();
        settle(&store).await.unwrap();
        let retried = view(&store, "stage", "cloud").await.unwrap().unwrap();
        assert_eq!(retried["current_deployment"]["run_id"], "new");
        assert_eq!(retried["previous_deployment"]["revision"], "a".repeat(40));
        assert_eq!(
            retried["history"][0]["deployments"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(
            crate::release_environment::bundle_for_run(&store, "retry")
                .await
                .unwrap()
                .is_none()
        );

        // Admission and reconciliation order must not become deployment order.
        // A separate promotion owner is not released by ordinary observations.
        seed(&store, "earlier", &"c".repeat(40), &"f".repeat(64)).await;
        seed(&store, "later", &"d".repeat(40), &"1".repeat(64)).await;
        sqlx::query("UPDATE ci_service_deployment SET updated_at=now()+interval '1 minute' WHERE run_id='earlier'")
            .execute(store.pool()).await.unwrap();
        sqlx::query("UPDATE ci_service_deployment SET updated_at=now()+interval '2 minutes' WHERE run_id='later'")
            .execute(store.pool()).await.unwrap();
        sqlx::query("UPDATE ci_release_service_environment SET active_run='old' WHERE name='stage' AND service='cloud'")
            .execute(store.pool()).await.unwrap();
        let mut tx = store.pool().begin().await.unwrap();
        enroll_retry(&mut tx, "later").await.unwrap();
        enroll_retry(&mut tx, "earlier").await.unwrap();
        tx.commit().await.unwrap();
        for run in ["later", "earlier"] {
            let id: String =
                sqlx::query_scalar("SELECT id FROM ci_release_service_deployment WHERE run_id=$1")
                    .bind(run)
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            settle_one(&store, &id).await.unwrap();
        }
        let ordered = view(&store, "stage", "cloud").await.unwrap().unwrap();
        assert_eq!(ordered["current_deployment"]["run_id"], "later");
        assert_eq!(ordered["previous_deployment"]["run_id"], "earlier");
        assert_eq!(ordered["state"]["active_run"], "old");

        // A retry of an older successful deployment adds evidence, not a new
        // rollout that would overwrite the latest version or its predecessor.
        sqlx::query("INSERT INTO ci_run(id,workflow_id,workflow_path,repo_url,sha,status)
            SELECT 'late-retry',workflow_id,workflow_path,repo_url,sha,'success' FROM ci_run WHERE id='new'")
            .execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO ci_job(id,run_id,job_key,base_id,display,status,plan,carried_from,finished_at)
            SELECT 'late-retry.'||job_key,'late-retry',job_key,base_id,display,'success',plan,'new',now()+interval '3 minutes'
            FROM ci_job WHERE run_id='new' AND job_key IN ('west','east')")
            .execute(store.pool()).await.unwrap();
        let mut tx = store.pool().begin().await.unwrap();
        enroll_retry(&mut tx, "late-retry").await.unwrap();
        tx.commit().await.unwrap();
        settle(&store).await.unwrap();
        let final_state = view(&store, "stage", "cloud").await.unwrap().unwrap();
        assert_eq!(final_state["current_deployment"]["run_id"], "later");
        assert_eq!(final_state["previous_deployment"]["run_id"], "earlier");
        assert_eq!(final_state["state"]["active_run"], "old");

        store.pool().close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
