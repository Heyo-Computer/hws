//! Environment policy selects an existing release. CI's ordinary persisted DAG
//! and managed rollout actions execute it; there is no second rollout engine.
use crate::{dispatch::Dispatcher, plan::Plan, store::Store};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Manual,
    Automatic,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Legacy default; new environments put source ownership on each service.
    #[serde(default)]
    pub repository: String,
    #[serde(default)]
    pub workflow_id: String,
    /// The same bundle must have completed successfully in these environments.
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub mode: Mode,
    pub network: Option<String>,
    #[serde(default)]
    pub workflow: String,
    #[serde(default)]
    pub services: BTreeMap<String, Rollout>,
    #[serde(default)]
    pub service_targets: BTreeMap<String, crate::service_rollout::Target>,
    #[serde(default)]
    pub pooler_targets: BTreeMap<String, crate::pooler_rollout::Target>,
    #[serde(default)]
    pub site_targets: BTreeMap<String, crate::site_rollout::Target>,
    #[serde(default)]
    pub stateful_targets: BTreeMap<String, crate::stateful_rollout::Target>,
    #[serde(default)]
    pub placements: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rollout {
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub mode: Option<Mode>,
    #[serde(default)]
    pub requires: Option<Vec<String>>,
    /// Existing CI secrets scope; inherits the environment's legacy scope.
    #[serde(default)]
    pub workflow_id: String,
    pub workflow: String,
    #[serde(default)]
    pub service_targets: BTreeMap<String, crate::service_rollout::Target>,
    #[serde(default)]
    pub pooler_targets: BTreeMap<String, crate::pooler_rollout::Target>,
    #[serde(default)]
    pub site_targets: BTreeMap<String, crate::site_rollout::Target>,
    #[serde(default)]
    pub stateful_targets: BTreeMap<String, crate::stateful_rollout::Target>,
    #[serde(default)]
    pub placements: BTreeMap<String, String>,
}

fn select(policy: &Policy, service: Option<&str>) -> Result<(String, Policy)> {
    if policy.services.is_empty() {
        // Legacy workflows are safe only if every deployment consumes the same
        // artifact. The manifest supplies its actual component name at admission.
        let p = plan("legacy", policy)?;
        let mut inputs = std::collections::BTreeSet::new();
        for step in p.jobs.iter().flat_map(|j| &j.steps) {
            if step.uses.as_deref() != Some("ci/host-heyvm-maintenance") {
                inputs.insert((
                    step.with.get("workflow"),
                    step.with.get("artifact"),
                    step.with.get("job"),
                ));
            }
        }
        ensure!(
            inputs.len() == 1,
            "legacy policy must select one service artifact"
        );
        return Ok((service.unwrap_or("").to_owned(), policy.clone()));
    }
    let service = match service {
        Some(s) => s,
        None if policy.services.len() == 1 => policy.services.keys().next().unwrap(),
        None => anyhow::bail!("service is required for a multi-service environment"),
    };
    let rollout = policy
        .services
        .get(service)
        .ok_or_else(|| anyhow::anyhow!("unknown environment service"))?;
    let mut resolved = policy.clone();
    resolved.services.clear();
    if let Some(repository) = &rollout.repository {
        resolved.repository = repository.clone();
    }
    if let Some(mode) = rollout.mode {
        resolved.mode = mode;
    }
    if let Some(requires) = &rollout.requires {
        resolved.requires = requires.clone();
    }
    if !rollout.workflow_id.is_empty() {
        resolved.workflow_id = rollout.workflow_id.clone();
    }
    resolved.workflow = rollout.workflow.clone();
    resolved.service_targets = rollout.service_targets.clone();
    resolved.pooler_targets = rollout.pooler_targets.clone();
    resolved.site_targets = rollout.site_targets.clone();
    resolved.stateful_targets = rollout.stateful_targets.clone();
    resolved.placements = rollout.placements.clone();
    Ok((service.to_owned(), resolved))
}

fn candidate_service(manifest: &Value, selected: Option<&str>) -> Result<String> {
    let components = manifest["components"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("release has no components"))?;
    ensure!(
        components.len() == 1,
        "promotion requires a singleton service release"
    );
    let service = components.keys().next().unwrap();
    ensure!(!service.is_empty(), "release service is empty");
    ensure!(
        manifest
            .get("service")
            .is_none_or(|s| s.as_str() == Some(service.as_str())),
        "release service identity mismatch"
    );
    ensure!(
        selected.is_none_or(|s| s == service),
        "release belongs to another service"
    );
    Ok(service.clone())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub environment: String,
    #[serde(default)]
    pub service: Option<String>,
    pub bundle_id: String,
    pub request_id: String,
    #[serde(default)]
    pub recover: bool,
}

pub fn policies(raw: Option<&str>) -> Result<BTreeMap<String, Policy>> {
    let policies: BTreeMap<String, Policy> = match raw {
        Some(raw) => serde_yaml::from_str(raw)?,
        None => BTreeMap::new(),
    };
    for (name, policy) in &policies {
        ensure!(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
            "environment name requires ASCII letters, digits, '-' or '_'"
        );
        if policy.services.is_empty() {
            ensure!(
                !policy.repository.is_empty(),
                "environment requires repository"
            );
            ensure!(
                !policy.workflow_id.is_empty(),
                "environment requires workflow scope"
            );
            // Historical workflows may deploy several components. Singleton
            // selection is an admission rule, not a startup/history rule.
            plan(name, policy)?;
        } else {
            ensure!(
                policy.workflow.is_empty()
                    && policy.service_targets.is_empty()
                    && policy.pooler_targets.is_empty()
                    && policy.site_targets.is_empty()
                    && policy.stateful_targets.is_empty()
                    && policy.placements.is_empty(),
                "do not mix legacy rollout and services"
            );
            for service in policy.services.keys() {
                ensure!(
                    !service.is_empty() && service.len() <= 128,
                    "invalid service name"
                );
                let (_, resolved) = select(policy, Some(service))?;
                ensure!(
                    !resolved.repository.is_empty(),
                    "service requires repository"
                );
                ensure!(
                    !resolved.workflow_id.is_empty(),
                    "service requires workflow scope"
                );
                plan(name, &resolved)?;
            }
        }
        let services: Vec<Option<&str>> = if policy.services.is_empty() {
            vec![None]
        } else {
            policy.services.keys().map(|s| Some(s.as_str())).collect()
        };
        for service in services {
            let resolved = match service {
                Some(service) => select(policy, Some(service))?.1,
                None => policy.clone(),
            };
            let mut pending = resolved.requires.clone();
            let mut visited = std::collections::BTreeSet::new();
            while let Some(dependency) = pending.pop() {
                ensure!(dependency != *name, "environment prerequisite cycle");
                if !visited.insert(dependency.clone()) {
                    continue;
                }
                let prerequisite = policies
                    .get(&dependency)
                    .ok_or_else(|| anyhow::anyhow!("unknown prerequisite {dependency}"))?;
                let prerequisite = if prerequisite.services.is_empty() {
                    prerequisite.clone()
                } else {
                    select(prerequisite, service)?.1
                };
                ensure!(
                    crate::repos::same_repo(&resolved.repository, &prerequisite.repository),
                    "prerequisite must use the same repository"
                );
                pending.extend(prerequisite.requires.clone());
            }
        }
    }
    Ok(policies)
}

fn plan(name: &str, policy: &Policy) -> Result<Plan> {
    let wf = crate::workflow::Workflow::parse(&format!("@environment/{name}"), &policy.workflow)?;
    ensure!(
        wf.on == ["promotion"],
        "environment workflow must use only on: promotion"
    );
    let plan = Plan::build(&wf)?;
    ensure!(!plan.jobs.is_empty(), "promotion needs deployment jobs");
    let mut previous = None;
    for job in &plan.jobs {
        ensure!(
            job.key == job.base_id
                && job.condition.is_none()
                && !job.continue_on_error
                && !job.steps.is_empty(),
            "promotion jobs must be unconditional, non-matrix and must not tolerate errors"
        );
        ensure!(
            job.needs == previous.into_iter().collect::<Vec<_>>(),
            "promotion jobs must form one sequential chain; finish a region before changing the next"
        );
        previous = Some(job.base_id.clone());
        for step in &job.steps {
            ensure!(
                step.condition.is_none() && !step.continue_on_error && step.run.is_none(),
                "promotion steps must be unconditional rollout actions, not shell builds"
            );
            ensure!(
                matches!(
                    step.uses.as_deref(),
                    Some(
                        "ci/rollout-service"
                            | "ci/rollout-pooler"
                            | "ci/rollout-site"
                            | "ci/rollout-stateful-service"
                            | "ci/rollout-host-app-lb"
                            | "ci/rollout-host-heyvmd"
                            | "ci/promote-service-archive"
                            | "ci/host-heyvm-maintenance"
                            | "ci/deploy-controller"
                    )
                ),
                "promotion action must consume an existing bundle; merge, build and bootstrap are not allowed"
            );
        }
    }
    ensure!(
        policy
            .placements
            .keys()
            .all(|id| plan.jobs.iter().any(|j| &j.base_id == id)),
        "unknown promotion placement job"
    );
    Ok(plan)
}

async fn bundle(store: &Store, id: &str) -> Result<Value> {
    let row = sqlx::query("SELECT c.manifest,c.manifest_sha256,c.repository,b.git_ref,b.status FROM ci_release_bundle c
        JOIN ci_release_build b ON b.id=c.build_id WHERE c.id=$1").bind(id).fetch_optional(store.pool()).await?
        .ok_or_else(|| anyhow::anyhow!("release is not a retained build bundle"))?;
    let manifest: Value = row.get("manifest");
    ensure!(
        row.get::<&str, _>("status") == "ready"
            && manifest["version"] == 2
            && manifest["retained"] == true,
        "release build is not ready and retained"
    );
    ensure!(
        hex::encode(Sha256::digest(serde_json::to_vec(&manifest)?))
            == row.get::<String, _>("manifest_sha256"),
        "release manifest integrity mismatch"
    );
    ensure!(
        manifest["repository"].as_str() == Some(row.get::<&str, _>("repository")),
        "release repository mismatch"
    );
    Ok(json!({"manifest":manifest,"git_ref":row.get::<String,_>("git_ref")}))
}

/// An admitted promotion is its own provenance, never a fabricated Git receipt.
pub async fn bundle_for_run(store: &Store, run_id: &str) -> Result<Option<Value>> {
    let promotion =
        sqlx::query("SELECT bundle_id,service FROM ci_release_service_promotion WHERE run_id=$1")
            .bind(run_id)
            .fetch_optional(store.pool())
            .await?;
    let Some(promotion) = promotion else {
        let historical: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ci_release_promotion WHERE run_id=$1)",
        )
        .bind(run_id)
        .fetch_one(store.pool())
        .await?;
        ensure!(!historical, "legacy bundled deployments are archived and cannot execute; select a service release");
        return Ok(None);
    };
    let id: String = promotion.get("bundle_id");
    let value = bundle(store, &id).await?;
    let service: &str = promotion.get("service");
    candidate_service(&value["manifest"], Some(service))?;
    let run = store
        .get_run(run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing promotion run"))?;
    ensure!(
        value["manifest"]["revision"].as_str() == Some(&run.sha)
            && value["manifest"]["repository"].as_str() == Some(&run.repo_url),
        "promotion source differs from its release"
    );
    Ok(Some(value))
}

pub fn artifact(
    manifest: &Value,
    workflow: &str,
    name: &str,
    producer: Option<&str>,
) -> Result<crate::artifacts::StoredArtifact> {
    let components = manifest["components"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("release has no components"))?;
    let matches = components
        .values()
        .filter(|a| {
            a["workflow"] == workflow
                && a["name"] == name
                && producer.is_none_or(|job| a["job"] == job)
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "release component is missing or ambiguous: {workflow}:{name}"
    );
    let a: crate::release_catalog::Artifact = serde_json::from_value(matches[0].clone())?;
    ensure!(
        a.sink == "artifacts"
            && a.size_bytes > 0
            && a.sha256.len() == 64
            && a.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
        "release artifact identity is invalid"
    );
    Ok(crate::artifacts::StoredArtifact {
        sink: "artifacts",
        digest: Some(a.sha256),
        size_bytes: a.size_bytes,
        uri: a.uri,
        public_url: None,
    })
}

pub async fn admit(
    d: &Dispatcher,
    mut request: Request,
    actor: &str,
    automatic: bool,
) -> Result<Value> {
    ensure!(
        d.config.release_service_environments_enabled,
        "service promotions are disabled until all original executors are retired"
    );
    ensure!(
        request.service.is_some(),
        "service is required; environment-wide deployments are no longer supported"
    );
    let _admission = d
        .executor
        .admission_permit()
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(
        !request.request_id.is_empty() && request.request_id.len() <= 128,
        "promotion request_id requires 1..128 characters"
    );
    let configured = policies(d.config.release_environments.as_deref())?;
    let policy = configured
        .get(&request.environment)
        .ok_or_else(|| anyhow::anyhow!("unknown environment"))?;
    let (selected, policy) = select(policy, request.service.as_deref())?;
    ensure!(
        !automatic || policy.mode == Mode::Automatic,
        "environment requires manual promotion"
    );
    let selected = if configured[&request.environment].services.is_empty() {
        let names = service_names(d, &policy)?;
        ensure!(
            selected.is_empty() || selected == names[0],
            "unknown legacy environment service"
        );
        names[0].clone()
    } else {
        selected
    };
    let bundle = bundle(&d.store, &request.bundle_id).await?;
    request.service = Some(candidate_service(
        &bundle["manifest"],
        (!selected.is_empty()).then_some(selected.as_str()),
    )?);
    ensure!(
        crate::repos::same_repo(
            &policy.repository,
            bundle["manifest"]["repository"].as_str().unwrap_or("")
        ),
        "release repository does not own this environment"
    );
    let mut plan = plan(&request.environment, &policy)?;
    // Prove every input exists before admitting any deployment job.
    for job in &plan.jobs {
        for step in &job.steps {
            if step.uses.as_deref() != Some("ci/host-heyvm-maintenance") {
                let field = |key: &str| {
                    step.with
                        .get(key)
                        .filter(|v| !v.is_empty() && !v.contains("${{"))
                        .ok_or_else(|| anyhow::anyhow!("promotion requires literal with.{key}"))
                };
                artifact(
                    &bundle["manifest"],
                    field("workflow")?,
                    field("artifact")?,
                    if step.uses.as_deref() == Some("ci/promote-service-archive") {
                        step.with.get("job").map(String::as_str)
                    } else {
                        None
                    },
                )?;
            }
        }
    }
    let target_policy = crate::release_policy::Policy {
        workflow_path: plan.workflow_path.clone(),
        workflow: policy.workflow.clone(),
        submission_mode: Default::default(),
        service_targets: policy.service_targets.clone(),
        pooler_targets: policy.pooler_targets.clone(),
        site_targets: policy.site_targets.clone(),
        stateful_targets: policy.stateful_targets.clone(),
        placements: policy.placements.clone(),
    };
    plan = crate::release_policy::prepare_plan(d, &policy.repository, &target_policy, plan).await?;
    d.assign_network(&mut plan, policy.network.as_deref(), &mut Vec::new())?;
    let source: Vec<u8> = sqlx::query_scalar(
        "SELECT s.descriptor FROM ci_release_build_run m JOIN ci_run_source s ON s.run_id=m.run_id
        WHERE m.build_id=$1 ORDER BY m.workflow_path LIMIT 1",
    )
    .bind(bundle["manifest"]["build_id"].as_str())
    .fetch_one(d.store.pool())
    .await?;
    let value = persist(
        &d.store, &request, &policy, &bundle, &plan, &source, actor, automatic,
    )
    .await?;
    if let Err(error) = d.advance_run(value["run_id"].as_str().unwrap()).await {
        tracing::warn!(%error, "promotion scheduling deferred to existing run recovery");
    }
    Ok(value)
}

async fn persist(
    store: &Store,
    request: &Request,
    policy: &Policy,
    bundle: &Value,
    plan: &Plan,
    source: &[u8],
    actor: &str,
    automatic: bool,
) -> Result<Value> {
    ensure!(
        request.service.is_some(),
        "service is required; refusing an unscoped legacy retry"
    );
    let service = candidate_service(&bundle["manifest"], request.service.as_deref())?;
    let mut tx = store.pool().begin().await?;
    let repository = bundle["manifest"]["repository"].as_str().unwrap();
    sqlx::query("INSERT INTO ci_release_service_environment(name,repository,service) VALUES($1,$2,$3) ON CONFLICT(name,service) DO NOTHING")
        .bind(&request.environment).bind(repository).bind(&service).execute(&mut *tx).await?;
    // Serialize changes to one environment, not CI execution across regions.
    let env = sqlx::query(
        "SELECT * FROM ci_release_service_environment WHERE name=$1 AND service=$2 FOR UPDATE",
    )
    .bind(&request.environment)
    .bind(&service)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        env.get::<&str, _>("repository") == repository,
        "environment repository changed"
    );
    if let Some(saved) = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(p) FROM ci_release_service_promotion p WHERE environment=$1 AND request_id=$2 AND service=$3",
    )
    .bind(&request.environment)
    .bind(&request.request_id)
    .bind(&service)
    .fetch_optional(&mut *tx)
    .await?
    {
        ensure!(
            saved["bundle_id"] == request.bundle_id,
            "request_id already selects another release"
        );
        return Ok(json!({"run_id":saved["run_id"],"environment":request.environment,
            "service":service,"bundle_id":request.bundle_id,"request_id":request.request_id}));
    }
    // Historical unscoped work must settle before a new service-scoped run
    // can safely begin. Do not attribute its current/previous/hold to a service.
    let legacy_active: Option<Option<String>> = sqlx::query_scalar(
        "SELECT active_run FROM ci_release_environment WHERE name=$1 FOR UPDATE",
    )
    .bind(&request.environment)
    .fetch_optional(&mut *tx)
    .await?;
    ensure!(
        legacy_active.flatten().is_none(),
        "legacy environment deployment must settle first"
    );
    ensure!(
        env.get::<Option<String>, _>("active_run").is_none(),
        "environment already has a deployment in progress"
    );
    ensure!(
        !automatic || !env.get::<bool, _>("automation_held"),
        "environment automation is held"
    );
    if request.recover {
        ensure!(!automatic, "recovery must be requested manually");
        ensure!(
            env.get::<Option<String>, _>("current_bundle").as_deref()
                == Some(request.bundle_id.as_str()),
            "recovery must restore the last complete successful release"
        );
        let failed: bool = sqlx::query_scalar("SELECT coalesce((SELECT r.status IN ('failure','cancelled') FROM ci_release_service_promotion p JOIN ci_run r ON r.id=p.run_id WHERE p.environment=$1 AND p.service=$2 AND p.completed_at IS NOT NULL ORDER BY p.created_at DESC,p.run_id DESC LIMIT 1),false)")
            .bind(&request.environment).bind(&service).fetch_one(&mut *tx).await?;
        ensure!(failed, "recovery requires a settled failed promotion");
    } else {
        for prerequisite in &policy.requires {
            let passed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_release_service_promotion p JOIN ci_run r ON r.id=p.run_id WHERE p.environment=$1 AND p.bundle_id=$2 AND p.service=$3 AND p.completed_at IS NOT NULL AND r.status='success')")
                .bind(prerequisite).bind(&request.bundle_id).bind(&service).fetch_one(&mut *tx).await?;
            ensure!(
                passed,
                "release must first succeed in prerequisite {prerequisite}"
            );
        }
    }
    let run_id = crate::vm::new_id();
    let run = crate::store::RunRequest {
        workflow_id: policy.workflow_id.clone(),
        repo_url: repository.into(),
        git_ref: bundle["git_ref"].as_str().unwrap().into(),
        sha: bundle["manifest"]["revision"].as_str().unwrap().into(),
        actor_subject: Some(actor.into()),
        source: "release-promotion".into(),
        changes: crate::paths::Changes::unknown("deploy the complete selected release"),
        ..Default::default()
    };
    Store::create_run_in(&mut tx, &run_id, &run, plan).await?;
    Store::record_source_in(&mut tx, &run_id, source).await?;
    sqlx::query(
        "INSERT INTO ci_release_service_promotion(run_id,environment,request_id,bundle_id,automatic,policy,service)
        VALUES($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&run_id)
    .bind(&request.environment)
    .bind(&request.request_id)
    .bind(&request.bundle_id)
    .bind(automatic)
    .bind(serde_json::to_value(policy)?)
    .bind(&service)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE ci_release_service_environment SET active_run=$2,automation_held=automation_held OR $3,updated_at=now() WHERE name=$1 AND service=$4")
        .bind(&request.environment).bind(&run_id).bind(!automatic).bind(&service).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(
        json!({"run_id":run_id,"environment":request.environment,"service":service,"bundle_id":request.bundle_id,"request_id":request.request_id}),
    )
}

fn service_names(d: &Dispatcher, policy: &Policy) -> Result<Vec<String>> {
    if !policy.services.is_empty() {
        return Ok(policy.services.keys().cloned().collect());
    }
    let (_, resolved) = select(policy, None)?;
    let p = plan("legacy", &resolved)?;
    let builds = crate::release_build::policies(d.config.release_builds.as_deref())?;
    let mut names = std::collections::BTreeSet::new();
    for (repository, build) in builds {
        if !crate::repos::same_repo(&repository, &policy.repository) {
            continue;
        }
        for (name, component) in build.components {
            if p.jobs
                .iter()
                .flat_map(|j| &j.steps)
                .filter(|s| s.uses.as_deref() != Some("ci/host-heyvm-maintenance"))
                .all(|s| {
                    s.with.get("workflow") == Some(&component.workflow)
                        && s.with.get("artifact") == Some(&component.artifact)
                        && s.with.get("job").is_none_or(|job| job == &component.job)
                })
            {
                names.insert(name);
            }
        }
    }
    ensure!(
        names.len() == 1,
        "legacy environment needs one configured service build selection"
    );
    Ok(names.into_iter().collect())
}

async fn service_view(store: &Store, name: &str, service: &str) -> Result<Value> {
    let (environment_table, promotion_table, predicate) = if service.is_empty() {
        (
            "ci_release_environment",
            "ci_release_promotion",
            "$2::text=''",
        )
    } else {
        (
            "ci_release_service_environment",
            "ci_release_service_promotion",
            "service=$2",
        )
    };
    let state_sql =
        format!("SELECT to_jsonb(e) FROM {environment_table} e WHERE name=$1 AND {predicate}");
    let state: Option<Value> = sqlx::query_scalar(&state_sql)
        .bind(name)
        .bind(service)
        .fetch_optional(store.pool())
        .await?;
    let history_sql = format!("SELECT to_jsonb(p) || jsonb_build_object('status',r.status,'error',r.error,
            'deployments',(SELECT coalesce(jsonb_agg(jsonb_build_object('service',d.service_id,'revision',d.sha,'status',d.status)),'[]')
            FROM ci_service_deployment d WHERE d.run_id=p.run_id)) FROM {promotion_table} p JOIN ci_run r ON r.id=p.run_id
            WHERE p.environment=$1 AND {predicate} ORDER BY p.created_at DESC,p.run_id DESC LIMIT 20");
    let history: Vec<Value> = sqlx::query_scalar(&history_sql)
        .bind(name)
        .bind(service)
        .fetch_all(store.pool())
        .await?;
    let recovery_required = history.first().is_some_and(|p| {
        !p["completed_at"].is_null()
            && matches!(p["status"].as_str(), Some("failure" | "cancelled"))
    });
    let recovery_bundle = if recovery_required {
        state.as_ref().and_then(|s| s["current_bundle"].as_str())
    } else {
        None
    };
    Ok(
        json!({"service":service,"state":state,"history":history,"recovery_required":recovery_required,"recovery_bundle":recovery_bundle}),
    )
}

pub async fn list(d: &Dispatcher) -> Result<Value> {
    let configured = policies(d.config.release_environments.as_deref())?;
    let mut environments = Vec::new();
    for (name, policy) in configured {
        let mut services = Vec::new();
        let mut names: std::collections::BTreeSet<String> =
            policy.services.keys().cloned().collect();
        // Also show already admitted scoped state for a legacy singleton policy,
        // without requiring historical multi-component policies to be singleton.
        names.extend(
            sqlx::query_scalar::<_, String>(
                "SELECT service FROM ci_release_service_environment WHERE name=$1",
            )
            .bind(&name)
            .fetch_all(d.store.pool())
            .await?,
        );
        for service in names {
            let mut view = service_view(&d.store, &name, &service).await?;
            let configured = policy.services.is_empty() || policy.services.contains_key(&service);
            view["configured"] = json!(configured);
            if configured {
                let resolved = if policy.services.is_empty() {
                    policy.clone()
                } else {
                    select(&policy, Some(&service))?.1
                };
                view["repository"] = json!(resolved.repository);
                view["mode"] = json!(resolved.mode);
                view["requires"] = json!(resolved.requires);
            }
            services.push(view);
        }
        environments.push(json!({"name":name,"mode":policy.mode,"repository":policy.repository,"requires":policy.requires,
            "services":services}));
    }
    Ok(json!({"environments":environments}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationRequest {
    pub environment: String,
    #[serde(default)]
    pub service: Option<String>,
    pub held: bool,
}

pub async fn automation(d: &Dispatcher, mut request: AutomationRequest) -> Result<Value> {
    ensure!(
        d.config.release_service_environments_enabled,
        "service automation is disabled until all original executors are retired"
    );
    ensure!(
        request.service.is_some(),
        "service is required for automation mutation"
    );
    let configured = policies(d.config.release_environments.as_deref())?;
    let policy = configured
        .get(&request.environment)
        .ok_or_else(|| anyhow::anyhow!("unknown environment"))?;
    if policy.services.is_empty() {
        let names = service_names(d, policy)?;
        ensure!(
            request.service.as_deref().is_none_or(|s| s == names[0]),
            "unknown legacy environment service"
        );
        request.service = Some(names[0].clone());
    }
    set_automation(&d.store, policy, request).await
}

async fn set_automation(
    store: &Store,
    policy: &Policy,
    request: AutomationRequest,
) -> Result<Value> {
    ensure!(
        request.service.is_some(),
        "service is required for automation mutation"
    );
    let (service, policy) = select(policy, request.service.as_deref())?;
    ensure!(
        !service.is_empty(),
        "service is required for automation mutation"
    );
    ensure!(
        request.held || policy.mode == Mode::Automatic,
        "environment policy is manual"
    );
    let mut tx = store.pool().begin().await?;
    sqlx::query("INSERT INTO ci_release_service_environment(name,repository,service) VALUES($1,$2,$3) ON CONFLICT(name,service) DO NOTHING")
        .bind(&request.environment).bind(&policy.repository).bind(&service).execute(&mut *tx).await?;
    let row = sqlx::query(
        "SELECT repository,active_run FROM ci_release_service_environment WHERE name=$1 AND service=$2 FOR UPDATE",
    )
    .bind(&request.environment)
    .bind(&service)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        crate::repos::same_repo(row.get("repository"), &policy.repository),
        "environment repository changed"
    );
    ensure!(
        request.held || row.get::<Option<String>, _>("active_run").is_none(),
        "wait for the active promotion before resuming automation"
    );
    sqlx::query(
        "UPDATE ci_release_service_environment SET automation_held=$2,updated_at=now() WHERE name=$1 AND service=$3",
    )
    .bind(&request.environment)
    .bind(request.held)
    .bind(&service)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(json!({"environment":request.environment,"service":service,"automation_held":request.held}))
}

async fn finish(store: &Store) -> Result<()> {
    let mut tx = store.pool().begin().await?;
    // Both formats settle in their own original state; no inferred attribution.
    for (environment_table, promotion_table, service_column, service_join, service_filter) in [
        (
            "ci_release_environment",
            "ci_release_promotion",
            "''::text",
            "",
            "$4::text=''",
        ),
        (
            "ci_release_service_environment",
            "ci_release_service_promotion",
            "e.service",
            "AND p.service=e.service",
            "service=$4",
        ),
    ] {
        let rows_sql = format!("SELECT e.name,{service_column} AS service,p.run_id,p.bundle_id,r.status FROM {environment_table} e
        JOIN {promotion_table} p ON p.run_id=e.active_run AND p.environment=e.name {service_join}
        JOIN ci_run r ON r.id=p.run_id
        WHERE r.status IN ('success','failure','cancelled')
        AND NOT EXISTS(SELECT 1 FROM ci_service_deployment d WHERE d.run_id=r.id AND d.status NOT IN ('passed','failed'))
        FOR UPDATE OF e SKIP LOCKED");
        let rows = sqlx::query(&rows_sql).fetch_all(&mut *tx).await?;
        for row in rows {
            let success = row.get::<&str, _>("status") == "success";
            let update_sql = format!("UPDATE {environment_table} SET previous_bundle=CASE WHEN $2 AND current_bundle IS DISTINCT FROM $3 THEN current_bundle ELSE previous_bundle END,
            current_bundle=CASE WHEN $2 THEN $3 ELSE current_bundle END,active_run=NULL,
            automation_held=automation_held OR NOT $2,updated_at=now() WHERE name=$1 AND {service_filter}");
            sqlx::query(&update_sql)
                .bind(row.get::<&str, _>("name"))
                .bind(success)
                .bind(row.get::<&str, _>("bundle_id"))
                .bind(row.get::<&str, _>("service"))
                .execute(&mut *tx)
                .await?;
            sqlx::query(&format!(
                "UPDATE {promotion_table} SET completed_at=now() WHERE run_id=$1"
            ))
            .bind(row.get::<&str, _>("run_id"))
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

pub fn spawn(d: Arc<Dispatcher>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let Ok(_effect) = d.executor.effect_permit().await else {
                continue;
            };
            if let Err(error) = reconcile(&d).await {
                tracing::warn!(%error,"environment promotion reconciliation deferred");
            }
        }
    });
}

async fn latest_ready(store: &Store, repository: &str, service: &str) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT c.id FROM ci_release_bundle c JOIN ci_release_build b ON b.id=c.build_id
        WHERE c.repository=$1 AND b.status='ready' AND c.manifest->>'retained'='true'
        AND c.manifest->>'version'='2'
        AND jsonb_typeof(c.manifest->'components')='object'
        AND (SELECT count(*) FROM jsonb_object_keys(CASE WHEN jsonb_typeof(c.manifest->'components')='object' THEN c.manifest->'components' ELSE '{}'::jsonb END))=1
        AND c.manifest->'components' ? $2
        AND (NOT c.manifest ? 'service' OR c.manifest->>'service'=$2)
        ORDER BY b.created_at DESC,b.id DESC LIMIT 1",
    )
    .bind(repository)
    .bind(service)
    .fetch_optional(store.pool())
    .await?)
}

async fn reconcile(d: &Dispatcher) -> Result<()> {
    finish(&d.store).await?;
    if !d.config.release_service_environments_enabled {
        return Ok(());
    }
    for (environment, policy) in policies(d.config.release_environments.as_deref())? {
        if policy.services.is_empty() && policy.mode != Mode::Automatic {
            continue;
        }
        for service in service_names(d, &policy)? {
            let resolved = if policy.services.is_empty() {
                policy.clone()
            } else {
                select(&policy, Some(&service))?.1
            };
            if resolved.mode != Mode::Automatic {
                continue;
            }
            let held: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_release_service_environment WHERE name=$1 AND service=$2 AND (automation_held OR active_run IS NOT NULL))")
            .bind(&environment).bind(&service).fetch_one(d.store.pool()).await?;
            if held {
                continue;
            }
            let id = latest_ready(&d.store, &resolved.repository, &service).await?;
            let Some(id) = id else { continue };
            let attempted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_release_service_promotion WHERE environment=$1 AND bundle_id=$2 AND service=$3)")
            .bind(&environment).bind(&id).bind(&service).fetch_one(d.store.pool()).await?;
            if attempted {
                continue;
            }
            if let Err(error) = admit(
                d,
                Request {
                    environment: environment.clone(),
                    service: Some(service),
                    bundle_id: id.clone(),
                    request_id: format!("auto-{id}"),
                    recover: false,
                },
                "environment-policy",
                true,
            )
            .await
            {
                tracing::warn!(%error,"automatic promotion deferred");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environments_resolve_repository_and_policy_per_service() {
        let rollout = |repository: &str| -> Rollout {
            serde_json::from_value(json!({"repository":repository,"workflow":policy().workflow}))
                .unwrap()
        };
        let mut stage = policy();
        stage.repository.clear();
        stage.workflow.clear();
        stage.mode = Mode::Automatic;
        stage.services = BTreeMap::from([
            ("auth".into(), rollout("private-repo")),
            ("ci".into(), rollout("public-repo")),
        ]);
        stage.services.get_mut("auth").unwrap().mode = Some(Mode::Manual);
        let mut production = stage.clone();
        production.mode = Mode::Manual;
        production.requires = vec!["stage".into()];
        let mut config = BTreeMap::from([("stage", stage), ("production", production)]);
        let validate = |config: &BTreeMap<&str, Policy>| {
            policies(Some(&serde_yaml::to_string(config).unwrap()))
        };
        assert!(validate(&config).is_ok());
        let (_, auth) = select(&config["stage"], Some("auth")).unwrap();
        let (_, ci) = select(&config["stage"], Some("ci")).unwrap();
        assert_eq!(auth.repository, "private-repo");
        assert_eq!(auth.mode, Mode::Manual);
        assert_eq!(ci.repository, "public-repo");
        assert_eq!(ci.mode, Mode::Automatic);
        assert_eq!(
            select(&config["production"], Some("ci"))
                .unwrap()
                .1
                .requires,
            ["stage"]
        );
        config
            .get_mut("production")
            .unwrap()
            .services
            .get_mut("auth")
            .unwrap()
            .repository = Some("wrong-repo".into());
        assert!(
            validate(&config)
                .unwrap_err()
                .to_string()
                .contains("same repository")
        );
        config
            .get_mut("production")
            .unwrap()
            .services
            .get_mut("auth")
            .unwrap()
            .repository = Some("private-repo".into());
        config
            .get_mut("stage")
            .unwrap()
            .services
            .get_mut("ci")
            .unwrap()
            .requires = Some(vec!["production".into()]);
        assert!(validate(&config).unwrap_err().to_string().contains("cycle"));
        config
            .get_mut("stage")
            .unwrap()
            .services
            .get_mut("ci")
            .unwrap()
            .requires = Some(vec![]);
        assert!(validate(&config).is_ok());
        config.get_mut("stage").unwrap().services.remove("auth");
        assert!(
            validate(&config)
                .unwrap_err()
                .to_string()
                .contains("unknown environment service")
        );
    }

    #[test]
    fn service_selection_is_explicit_and_rejects_cross_service_bundles() {
        let rollout = Rollout {
            repository: None,
            mode: None,
            requires: None,
            workflow_id: "scope".into(),
            workflow: policy().workflow,
            service_targets: BTreeMap::new(),
            pooler_targets: BTreeMap::new(),
            site_targets: BTreeMap::new(),
            stateful_targets: BTreeMap::new(),
            placements: BTreeMap::new(),
        };
        let mut configured = policy();
        configured.workflow.clear();
        configured.services = BTreeMap::from([("api".into(), rollout.clone())]);
        assert_eq!(select(&configured, None).unwrap().0, "api");
        configured.services.insert("worker".into(), rollout);
        assert!(select(&configured, None).is_err());
        assert!(select(&configured, Some("missing")).is_err());
        assert_eq!(
            select(&configured, Some("worker")).unwrap().1.workflow_id,
            "scope"
        );
        assert!(
            policies(Some(
                &serde_yaml::to_string(&BTreeMap::from([("stage", configured)])).unwrap()
            ))
            .is_ok()
        );
        let singleton = json!({"components":{"api":{}}});
        assert_eq!(candidate_service(&singleton, None).unwrap(), "api");
        assert!(candidate_service(&singleton, Some("worker")).is_err());
        assert!(candidate_service(&singleton, Some("")).is_err());
        assert!(
            candidate_service(
                &json!({"service":"worker","components":{"api":{}}}),
                Some("api")
            )
            .is_err()
        );
        assert!(
            candidate_service(&json!({"components":{"api":{},"worker":{}}}), Some("api")).is_err()
        );
        assert!(candidate_service(&json!({"components":{}}), None).is_err());
        let mut legacy = policy();
        legacy.workflow = legacy.workflow.replace(
            "uses: ci/rollout-service",
            "uses: ci/rollout-service, with: {workflow: api.yml, artifact: api}",
        );
        assert!(select(&legacy, None).is_ok());
        legacy.workflow = legacy
            .workflow
            .replacen("artifact: api", "artifact: worker", 1);
        assert!(select(&legacy, None).is_err());
        assert!(
            policies(Some(
                &serde_yaml::to_string(&BTreeMap::from([("historical", legacy)])).unwrap()
            ))
            .is_ok(),
            "multi-component historical policy must not prevent startup or settlement"
        );
    }

    #[test]
    fn example_separates_submission_build_and_environment_policy() {
        let config: BTreeMap<String, serde_yaml::Value> =
            serde_yaml::from_str(include_str!("../deploy/releases.example.yml")).unwrap();
        let raw = |name: &str| serde_yaml::to_string(&config[name]).unwrap();
        let repository = "https://github.com/Heyo-Computer/hws.git";
        let submission =
            crate::release_policy::select(Some(&raw("CI_RELEASE_POLICIES")), repository)
                .unwrap()
                .unwrap();
        assert_eq!(
            submission.submission_mode,
            crate::release_policy::SubmissionMode::MergeOnly
        );
        let builds = crate::release_build::policies(Some(&raw("CI_RELEASE_BUILDS"))).unwrap();
        assert_eq!(builds[repository].daily_utc_minute, Some(120));
        let environments = policies(Some(&raw("CI_RELEASE_ENVIRONMENTS"))).unwrap();
        assert_eq!(environments["hws-stage"].mode, Mode::Automatic);
        assert_eq!(environments["hws-production"].mode, Mode::Manual);
        assert_eq!(environments["hws-production"].requires, ["hws-stage"]);
        for (name, policy) in environments {
            let selections: Vec<Option<&str>> = if policy.services.is_empty() {
                vec![None]
            } else {
                policy.services.keys().map(|s| Some(s.as_str())).collect()
            };
            for service in selections {
                let (_, policy) = select(&policy, service).unwrap();
                let plan = plan(&name, &policy).unwrap();
                assert_eq!(plan.jobs[1].needs, [plan.jobs[0].base_id.clone()]);
                for target in policy.service_targets.values() {
                    crate::service_rollout::validate_target(target).unwrap();
                }
                for job in plan.jobs {
                    assert!(
                        job.vm.build.is_some(),
                        "promotion must not depend on an unregistered default image"
                    );
                    let step = &job.steps[0];
                    assert!(policy.service_targets.contains_key(&step.with["target"]));
                    assert!(
                        builds[repository]
                            .components
                            .values()
                            .any(|selection| selection.workflow == step.with["workflow"]
                                && selection.artifact == step.with["artifact"])
                    );
                }
            }
        }
    }

    fn policy() -> Policy {
        Policy {
            repository: "repo".into(),
            services: BTreeMap::new(),
            workflow_id: "platform".into(),
            requires: Vec::new(),
            mode: Mode::Manual,
            network: None,
            workflow: "on: promotion\njobs:\n  first:\n    steps: [{uses: ci/rollout-service}]\n  second:\n    needs: [first]\n    steps: [{uses: ci/rollout-service}]\n".into(),
            service_targets: BTreeMap::new(),
            pooler_targets: BTreeMap::new(),
            site_targets: BTreeMap::new(),
            stateful_targets: BTreeMap::new(),
            placements: BTreeMap::new(),
        }
    }

    #[test]
    fn prerequisite_graph_rejects_missing_cross_repository_and_cycles() {
        let mut configured = BTreeMap::from([
            ("stage", policy()),
            (
                "production",
                Policy {
                    requires: vec!["stage".into()],
                    ..policy()
                },
            ),
        ]);
        let validate = |config: &BTreeMap<&str, Policy>| {
            policies(Some(&serde_yaml::to_string(config).unwrap()))
        };
        assert!(validate(&configured).is_ok());
        configured.get_mut("stage").unwrap().requires = vec!["production".into()];
        assert!(
            validate(&configured)
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );
        configured.get_mut("stage").unwrap().requires = vec!["missing".into()];
        assert!(
            validate(&configured)
                .unwrap_err()
                .to_string()
                .contains("unknown prerequisite")
        );
        configured.get_mut("stage").unwrap().requires.clear();
        configured.get_mut("stage").unwrap().repository = "other-repo".into();
        assert!(
            validate(&configured)
                .unwrap_err()
                .to_string()
                .contains("same repository")
        );
    }

    #[test]
    fn promotion_policy_requires_sequential_deployment_only() {
        let valid = policy();
        assert_eq!(plan("any-region", &valid).unwrap().jobs.len(), 2);
        let daemon = Policy {
            workflow: valid.workflow.replace("uses: ci/rollout-service", "uses: ci/rollout-host-heyvmd, with: {target: daemon, token: '${{ secrets.HOST_TOKEN }}', workflow: .ci/workflows/mvm-ctrl.yml, artifact: heyvm}"),
            ..valid.clone()
        };
        assert_eq!(plan("stage", &daemon).unwrap().jobs.len(), 2);
        let bootstrap = Policy {
            workflow: daemon
                .workflow
                .replace("ci/rollout-host-heyvmd", "ci/bootstrap-host-heyvm"),
            ..valid.clone()
        };
        assert!(
            plan("stage", &bootstrap)
                .unwrap_err()
                .to_string()
                .contains("merge, build and bootstrap are not allowed")
        );
        for workflow in [
            valid.workflow.replace("    needs: [first]\n", ""),
            valid
                .workflow
                .replace("ci/rollout-service", "ci/merge-release"),
            valid
                .workflow
                .replace("ci/rollout-service", "ci/upload-artifact"),
            valid
                .workflow
                .replace("uses: ci/rollout-service", "run: echo build"),
            valid
                .workflow
                .replace("  second:\n", "  second:\n    if: false\n"),
        ] {
            assert!(
                plan(
                    "stage",
                    &Policy {
                        workflow,
                        ..valid.clone()
                    }
                )
                .is_err()
            );
        }
        assert!(policies(None).unwrap().is_empty());
        let mut unknown = valid;
        unknown.placements.insert("missing".into(), "host".into());
        assert!(plan("stage", &unknown).is_err());
    }

    #[test]
    fn artifact_selection_rejects_ambiguity_and_preserves_identity() {
        let component = json!({"id":"a","run_id":"build-run","workflow":"api.yml",
            "job":"linux","name":"binary","sink":"artifacts","uri":"retained-a",
            "sha256":"a".repeat(64),"size_bytes":37});
        let mut other = component.clone();
        other["job"] = json!("arm");
        other["sha256"] = json!("b".repeat(64));
        other["size_bytes"] = json!(91);
        other["uri"] = json!("retained-b");
        let manifest = json!({"components":{"linux":component,"arm":other}});
        assert!(artifact(&manifest, "api.yml", "binary", None).is_err());
        assert!(artifact(&manifest, "other.yml", "binary", Some("arm")).is_err());
        let selected = artifact(&manifest, "api.yml", "binary", Some("arm")).unwrap();
        assert_eq!(selected.digest.as_deref(), Some("b".repeat(64).as_str()));
        assert_eq!(selected.uri, "retained-b");
        assert_eq!(selected.size_bytes, 91);
    }

    #[tokio::test]
    #[ignore = "requires disposable CI_TEST_DATABASE_URL"]
    async fn promotion_persistence_is_idempotent_scoped_and_tracks_completion() {
        let base = std::env::var("CI_TEST_DATABASE_URL").unwrap();
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        let schema = format!("promotion_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
        let mut url = reqwest::Url::parse(&base).unwrap();
        url.query_pairs_mut()
            .append_pair("options", &format!("-c search_path={schema}"));
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(
            url.as_str(),
            dir.path().join("logs"),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        // Exercise an upgrade from the original environment schema, not only a
        // fresh database. Historical rows remain explicitly unattributed.
        for migration in crate::store::embedded_migrations()
            .into_iter()
            .filter(|m| m.name.as_str() < "052")
        {
            sqlx::raw_sql(&migration.sql)
                .execute(store.pool())
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO ci_release_environment(name,repository,automation_held) VALUES('legacy','repo',true)")
            .execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO ci_release_bundle(id,repository,name,manifest,manifest_sha256,created_by) VALUES('legacy-bundle','repo','legacy','{}','legacy-digest','test')")
            .execute(store.pool()).await.unwrap();
        let legacy_policy = policy();
        let legacy_plan = plan("legacy", &legacy_policy).unwrap();
        let mut tx = store.pool().begin().await.unwrap();
        Store::create_run_in(
            &mut tx,
            "legacy-run",
            &crate::store::RunRequest {
                workflow_id: "platform".into(),
                repo_url: "repo".into(),
                git_ref: "refs/heads/main".into(),
                sha: "a".repeat(40),
                ..Default::default()
            },
            &legacy_plan,
        )
        .await
        .unwrap();
        sqlx::query("INSERT INTO ci_release_promotion(run_id,environment,request_id,bundle_id,automatic,policy) VALUES('legacy-run','legacy','legacy-request','legacy-bundle',false,'{}')")
            .execute(&mut *tx).await.unwrap();
        sqlx::query("UPDATE ci_release_environment SET current_bundle='legacy-bundle',previous_bundle='legacy-bundle',active_run='legacy-run' WHERE name='legacy'")
            .execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        store.migrate().await.unwrap();
        store.migrate().await.unwrap();
        let old_retry = sqlx::query("INSERT INTO ci_release_promotion(run_id,environment,request_id,bundle_id,automatic,policy) VALUES('legacy-run','legacy','legacy-request','legacy-bundle',false,'{}') ON CONFLICT(environment,request_id) DO NOTHING")
            .execute(store.pool()).await.unwrap();
        assert_eq!(old_retry.rows_affected(), 0);
        let legacy: Value = sqlx::query_scalar(
            "SELECT to_jsonb(e) FROM ci_release_environment e WHERE name='legacy'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert!(legacy.get("service").is_none());
        assert_eq!(legacy["automation_held"], true);
        assert_eq!(legacy["current_bundle"], "legacy-bundle");
        assert_eq!(legacy["previous_bundle"], "legacy-bundle");
        assert_eq!(legacy["active_run"], "legacy-run");
        let legacy_history = service_view(&store, "legacy", "").await.unwrap();
        assert!(legacy_history["history"][0].get("service").is_none());
        assert_eq!(legacy_history["history"][0]["request_id"], "legacy-request");
        assert!(service_view(&store, "legacy", "api").await.unwrap()["state"].is_null());
        let policy = policy();
        let plan = plan("stage", &policy).unwrap();
        for id in ["old", "new", "candidate"] {
            let revision = match id {
                "old" => "a",
                "new" => "b",
                _ => "c",
            }
            .repeat(40);
            let manifest = json!({"version":2,"retained":true,"build_id":id,"repository":"repo","revision":revision,
                "components":{"api":{"id":"artifact","run_id":"build","workflow":"api.yml","job":"linux",
                "name":"binary","sink":"artifacts","uri":"retained-api","sha256":"d".repeat(64),"size_bytes":73}}});
            sqlx::query("INSERT INTO ci_release_build(id,repository,name,revision,git_ref,policy,created_by,status) VALUES($1,'repo',$1,$2,'refs/heads/main','{}','test','ready')")
                .bind(id).bind(&revision).execute(store.pool()).await.unwrap();
            sqlx::query("INSERT INTO ci_release_bundle(id,repository,name,manifest,manifest_sha256,created_by,build_id) VALUES($1,'repo',$1,$2,$3,'test',$1)")
                .bind(id).bind(&manifest).bind(hex::encode(Sha256::digest(serde_json::to_vec(&manifest).unwrap())))
                .execute(store.pool()).await.unwrap();
        }
        sqlx::query("UPDATE ci_release_build SET created_at=CASE WHEN id='new' THEN now()-interval '1 hour' ELSE now()-interval '2 hours' END")
            .execute(store.pool()).await.unwrap();
        sqlx::query("UPDATE ci_release_bundle SET created_at=CASE WHEN id='old' THEN now() ELSE now()-interval '30 minutes' END")
            .execute(store.pool()).await.unwrap();
        assert_eq!(
            latest_ready(&store, "repo", "api")
                .await
                .unwrap()
                .as_deref(),
            Some("new"),
            "a slow old build must not displace a newer build"
        );
        let mut bundle = super::bundle(&store, "old").await.unwrap();
        let mut request = Request {
            environment: "stage".into(),
            service: Some("api".into()),
            bundle_id: "old".into(),
            request_id: "first".into(),
            recover: false,
        };
        let source = serde_json::to_vec(&crate::trigger::GitPatchSource {
            base_revision: "a".repeat(40),
            target_tree: "b".repeat(40),
            patch_base64: String::new(),
            workflows: BTreeMap::new(),
            changes: crate::paths::Changes::unknown("retained release"),
        })
        .unwrap();
        request.recover = true;
        assert!(
            persist(
                &store, &request, &policy, &bundle, &plan, &source, "alice", false
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("last complete")
        );
        request.recover = false;
        let (a, b) = tokio::join!(
            persist(
                &store, &request, &policy, &bundle, &plan, &source, "alice", false
            ),
            persist(
                &store, &request, &policy, &bundle, &plan, &source, "bob", false
            )
        );
        let run = a.unwrap()["run_id"].as_str().unwrap().to_owned();
        assert_eq!(b.unwrap()["run_id"], run);
        let conflicting = Request {
            environment: request.environment.clone(),
            service: request.service.clone(),
            bundle_id: "new".into(),
            request_id: request.request_id.clone(),
            recover: false,
        };
        let different = super::bundle(&store, "new").await.unwrap();
        assert!(
            persist(
                &store,
                &conflicting,
                &policy,
                &different,
                &plan,
                &source,
                "operator",
                false
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("request_id already selects another release")
        );
        assert_eq!(
            crate::release::deployment_source(&store, &run)
                .await
                .unwrap()
                .0,
            "a".repeat(40)
        );
        let artifact = crate::submission::artifact(&store, &run, "api.yml", "binary", None)
            .await
            .unwrap();
        assert_eq!(artifact.size_bytes, 73);
        assert_eq!(artifact.digest.as_deref(), Some("d".repeat(64).as_str()));
        assert!(
            crate::release::get(&store, &run).await.unwrap().is_none(),
            "promotion must not fabricate a Git receipt"
        );
        sqlx::query("UPDATE ci_release_bundle SET manifest=jsonb_set(manifest,'{revision}','\"tampered\"') WHERE id='old'")
            .execute(store.pool()).await.unwrap();
        assert!(
            crate::release::deployment_source(&store, &run)
                .await
                .is_err()
        );
        sqlx::query("UPDATE ci_release_bundle SET manifest=$1 WHERE id='old'")
            .bind(&bundle["manifest"])
            .execute(store.pool())
            .await
            .unwrap();
        request.request_id = "second".into();
        assert!(
            persist(
                &store, &request, &policy, &bundle, &plan, &source, "alice", false
            )
            .await
            .is_err()
        );
        // A busy stage does not block a different environment.
        request.environment = "production".into();
        persist(
            &store, &request, &policy, &bundle, &plan, &source, "alice", false,
        )
        .await
        .unwrap();
        sqlx::query("UPDATE ci_run SET status='success' WHERE id=$1")
            .bind(&run)
            .execute(store.pool())
            .await
            .unwrap();
        let job: String =
            sqlx::query_scalar("SELECT id FROM ci_job WHERE run_id=$1 AND base_id='first'")
                .bind(&run)
                .fetch_one(store.pool())
                .await
                .unwrap();
        store
            .create_step(
                "rollout-step",
                &job,
                0,
                "rollout",
                Some("ci/rollout-service"),
            )
            .await
            .unwrap();
        sqlx::query("INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,sha,git_ref) VALUES('rollout','rollout-step',$1,$2,'api','hash','running','revision','refs/heads/main')")
            .bind(&run).bind(&job).execute(store.pool()).await.unwrap();
        finish(&store).await.unwrap();
        let active: Option<String> =
            sqlx::query_scalar("SELECT active_run FROM ci_release_service_environment WHERE name='stage' AND service='api'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(
            active.as_deref(),
            Some(run.as_str()),
            "run completion must not hide an unresolved rollout"
        );
        let waiting_policy = Policy {
            requires: vec!["stage".into()],
            ..policy.clone()
        };
        let waiting_request = Request {
            environment: "waiting-production".into(),
            service: Some("api".into()),
            bundle_id: "old".into(),
            request_id: "waiting".into(),
            recover: false,
        };
        assert!(
            persist(
                &store,
                &waiting_request,
                &waiting_policy,
                &bundle,
                &plan,
                &source,
                "alice",
                false
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("prerequisite stage")
        );
        sqlx::query("UPDATE ci_service_deployment SET status='passed' WHERE id='rollout'")
            .execute(store.pool())
            .await
            .unwrap();
        finish(&store).await.unwrap();
        let state = sqlx::query(
            "SELECT * FROM ci_release_service_environment WHERE name='stage' AND service='api'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(state.get::<String, _>("current_bundle"), "old");
        assert!(state.get::<Option<String>, _>("previous_bundle").is_none());
        assert!(state.get::<bool, _>("automation_held"));
        request.environment = "stage".into();
        request.bundle_id = "new".into();
        bundle = super::bundle(&store, "new").await.unwrap();
        assert!(
            persist(
                &store, &request, &policy, &bundle, &plan, &source, "policy", true
            )
            .await
            .is_err()
        );
        let next = persist(
            &store, &request, &policy, &bundle, &plan, &source, "alice", false,
        )
        .await
        .unwrap();
        sqlx::query("UPDATE ci_run SET status='failure' WHERE id=$1")
            .bind(next["run_id"].as_str())
            .execute(store.pool())
            .await
            .unwrap();
        finish(&store).await.unwrap();
        let current: String = sqlx::query_scalar(
            "SELECT current_bundle FROM ci_release_service_environment WHERE name='stage' AND service='api'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            current, "old",
            "failed promotion must not advance the environment"
        );
        request.request_id = "retry".into();
        let next = persist(
            &store, &request, &policy, &bundle, &plan, &source, "alice", false,
        )
        .await
        .unwrap();
        sqlx::query("UPDATE ci_run SET status='success' WHERE id=$1")
            .bind(next["run_id"].as_str())
            .execute(store.pool())
            .await
            .unwrap();
        finish(&store).await.unwrap();
        let state = sqlx::query(
            "SELECT * FROM ci_release_service_environment WHERE name='stage' AND service='api'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(state.get::<String, _>("current_bundle"), "new");
        assert_eq!(state.get::<String, _>("previous_bundle"), "old");
        let toggle = |held| AutomationRequest {
            environment: "stage".into(),
            service: Some("api".into()),
            held,
        };
        assert!(
            set_automation(&store, &policy, toggle(false))
                .await
                .is_err()
        );
        let automatic = Policy {
            mode: Mode::Automatic,
            ..policy.clone()
        };
        set_automation(&store, &automatic, toggle(false))
            .await
            .unwrap();
        let mut scoped = automatic.clone();
        scoped.repository = "unrelated-environment-default".into();
        scoped.mode = Mode::Manual;
        scoped.workflow.clear();
        scoped.services.insert(
            "api".into(),
            serde_json::from_value(json!({
                "repository":policy.repository,"mode":"automatic","workflow":policy.workflow
            }))
            .unwrap(),
        );
        set_automation(&store, &scoped, toggle(true)).await.unwrap();
        set_automation(&store, &scoped, toggle(false))
            .await
            .unwrap();
        scoped.services.get_mut("api").unwrap().mode = Some(Mode::Manual);
        scoped.mode = Mode::Automatic;
        assert!(
            set_automation(&store, &scoped, toggle(false))
                .await
                .is_err()
        );
        request.request_id = "repeat-current".into();
        let repeated = persist(
            &store, &request, &automatic, &bundle, &plan, &source, "policy", true,
        )
        .await
        .unwrap();
        // Hold may stop future admissions while the admitted rollout finishes.
        set_automation(&store, &automatic, toggle(true))
            .await
            .unwrap();
        assert!(
            set_automation(&store, &automatic, toggle(false))
                .await
                .is_err()
        );
        sqlx::query("UPDATE ci_run SET status='success' WHERE id=$1")
            .bind(repeated["run_id"].as_str())
            .execute(store.pool())
            .await
            .unwrap();
        finish(&store).await.unwrap();
        let previous: String = sqlx::query_scalar(
            "SELECT previous_bundle FROM ci_release_service_environment WHERE name='stage' AND service='api'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            previous, "old",
            "redeploying current must preserve rollback target"
        );
        set_automation(&store, &automatic, toggle(false))
            .await
            .unwrap();
        // A passed different bundle is not sufficient, for either admission mode.
        let gated = Policy {
            requires: vec!["stage".into()],
            ..automatic.clone()
        };
        let mut gated_request = Request {
            environment: "gated-production".into(),
            service: Some("api".into()),
            bundle_id: "candidate".into(),
            request_id: "gated".into(),
            recover: false,
        };
        let candidate = super::bundle(&store, "candidate").await.unwrap();
        for auto in [false, true] {
            let error = persist(
                &store,
                &gated_request,
                &gated,
                &candidate,
                &plan,
                &source,
                "operator",
                auto,
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("prerequisite stage"));
        }
        gated_request.bundle_id = "new".into();
        persist(
            &store,
            &gated_request,
            &gated,
            &bundle,
            &plan,
            &source,
            "operator",
            false,
        )
        .await
        .unwrap();

        // A -> B succeeded; C fails. Recovery must restore B, never A.
        request.bundle_id = "candidate".into();
        request.request_id = "partial-failure".into();
        let failed = persist(
            &store, &request, &policy, &candidate, &plan, &source, "operator", false,
        )
        .await
        .unwrap();
        sqlx::query("UPDATE ci_run SET status='failure' WHERE id=$1")
            .bind(failed["run_id"].as_str())
            .execute(store.pool())
            .await
            .unwrap();
        request.recover = true;
        request.request_id = "recovery".into();
        request.bundle_id = "new".into();
        assert!(
            persist(
                &store, &request, &policy, &bundle, &plan, &source, "operator", false
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("in progress")
        );
        finish(&store).await.unwrap();
        request.bundle_id = "old".into();
        let old = super::bundle(&store, "old").await.unwrap();
        assert!(
            persist(
                &store, &request, &policy, &old, &plan, &source, "operator", false
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("last complete")
        );
        request.bundle_id = "new".into();
        // Policy changes must not block recovery to the known-good release.
        let changed_policy = Policy {
            requires: vec!["new-prerequisite".into()],
            ..policy.clone()
        };
        let recovered = persist(
            &store,
            &request,
            &changed_policy,
            &bundle,
            &plan,
            &source,
            "operator",
            false,
        )
        .await
        .unwrap();
        sqlx::query("UPDATE ci_run SET status='success' WHERE id=$1")
            .bind(recovered["run_id"].as_str())
            .execute(store.pool())
            .await
            .unwrap();
        finish(&store).await.unwrap();
        let state = sqlx::query(
            "SELECT * FROM ci_release_service_environment WHERE name='stage' AND service='api'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(state.get::<String, _>("current_bundle"), "new");
        assert_eq!(state.get::<String, _>("previous_bundle"), "old");
        assert!(state.get::<bool, _>("automation_held"));
        request.request_id = "not-a-failure".into();
        assert!(
            persist(
                &store, &request, &policy, &bundle, &plan, &source, "operator", false
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("settled failed")
        );

        let api_before = service_view(&store, "stage", "api").await.unwrap();
        let mut worker_manifest = candidate["manifest"].clone();
        let component = worker_manifest["components"]["api"].clone();
        worker_manifest["components"] = json!({"worker":component});
        worker_manifest["build_id"] = json!("worker");
        sqlx::query("INSERT INTO ci_release_build(id,repository,name,revision,git_ref,policy,created_by,status) VALUES('worker','repo','worker',$1,'refs/heads/main','{}','test','ready')")
            .bind(worker_manifest["revision"].as_str()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO ci_release_bundle(id,repository,name,manifest,manifest_sha256,created_by,build_id) VALUES('worker','repo','worker',$1,$2,'test','worker')")
            .bind(&worker_manifest).bind(hex::encode(Sha256::digest(serde_json::to_vec(&worker_manifest).unwrap())))
            .execute(store.pool()).await.unwrap();
        let worker = super::bundle(&store, "worker").await.unwrap();
        let mut worker_request = Request {
            environment: "stage".into(),
            service: Some("worker".into()),
            bundle_id: "worker".into(),
            request_id: "first".into(),
            recover: false,
        };
        // Same request ID is independent across services. Cross-service input
        // is rejected before a database identity or run can be created.
        assert!(
            persist(
                &store,
                &worker_request,
                &policy,
                &bundle,
                &plan,
                &source,
                "operator",
                false
            )
            .await
            .is_err()
        );
        let admitted = persist(
            &store,
            &worker_request,
            &policy,
            &worker,
            &plan,
            &source,
            "operator",
            false,
        )
        .await
        .unwrap();
        let duplicate = persist(
            &store,
            &worker_request,
            &policy,
            &worker,
            &plan,
            &source,
            "operator",
            false,
        )
        .await
        .unwrap();
        assert_eq!(admitted["run_id"], duplicate["run_id"]);
        assert_eq!(admitted, duplicate);
        assert_eq!(
            api_before,
            service_view(&store, "stage", "api").await.unwrap()
        );
        assert_eq!(
            latest_ready(&store, "repo", "api")
                .await
                .unwrap()
                .as_deref(),
            Some("new")
        );
        assert_eq!(
            latest_ready(&store, "repo", "worker")
                .await
                .unwrap()
                .as_deref(),
            Some("worker")
        );
        // Worker is active while API admits and settles a failed candidate.
        request.recover = false;
        request.bundle_id = "candidate".into();
        request.request_id = "isolated-failure".into();
        let api_failed = persist(
            &store, &request, &policy, &candidate, &plan, &source, "operator", false,
        )
        .await
        .unwrap();
        let worker_before = service_view(&store, "stage", "worker").await.unwrap();
        set_automation(
            &store,
            &automatic,
            AutomationRequest {
                environment: "stage".into(),
                service: Some("api".into()),
                held: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            worker_before,
            service_view(&store, "stage", "worker").await.unwrap()
        );
        sqlx::query("UPDATE ci_run SET status='failure' WHERE id=$1")
            .bind(api_failed["run_id"].as_str())
            .execute(store.pool())
            .await
            .unwrap();
        finish(&store).await.unwrap();
        assert_eq!(
            worker_before,
            service_view(&store, "stage", "worker").await.unwrap()
        );
        request.recover = true;
        request.bundle_id = "new".into();
        request.request_id = "isolated-recovery".into();
        let rollback = persist(
            &store, &request, &policy, &bundle, &plan, &source, "operator", false,
        )
        .await
        .unwrap();
        sqlx::query("UPDATE ci_run SET status='success' WHERE id=$1")
            .bind(rollback["run_id"].as_str())
            .execute(store.pool())
            .await
            .unwrap();
        finish(&store).await.unwrap();
        assert_eq!(
            worker_before,
            service_view(&store, "stage", "worker").await.unwrap()
        );
        sqlx::query("UPDATE ci_run SET status='failure' WHERE id=$1")
            .bind(admitted["run_id"].as_str())
            .execute(store.pool())
            .await
            .unwrap();
        finish(&store).await.unwrap();
        let api_after = service_view(&store, "stage", "api").await.unwrap();
        worker_request.request_id = "retry-worker".into();
        let retried = persist(
            &store,
            &worker_request,
            &policy,
            &worker,
            &plan,
            &source,
            "operator",
            false,
        )
        .await
        .unwrap();
        sqlx::query("UPDATE ci_run SET status='success' WHERE id=$1")
            .bind(retried["run_id"].as_str())
            .execute(store.pool())
            .await
            .unwrap();
        finish(&store).await.unwrap();
        assert_eq!(
            api_after,
            service_view(&store, "stage", "api").await.unwrap()
        );
        // Re-running the whole embedded migration set preserves both histories
        // and the legacy namespace without fabricating service state.
        let worker_after = service_view(&store, "stage", "worker").await.unwrap();
        store.migrate().await.unwrap();
        assert_eq!(
            api_after,
            service_view(&store, "stage", "api").await.unwrap()
        );
        assert_eq!(
            worker_after,
            service_view(&store, "stage", "worker").await.unwrap()
        );
        let legacy_view = service_view(&store, "legacy", "").await.unwrap();
        assert_eq!(legacy_view["state"], legacy);
        // Old admission/upsert and name-only updates remain usable even when
        // two scoped services already occupy the same environment name.
        let old_insert = sqlx::query(
            "INSERT INTO ci_release_environment(name,repository) VALUES('stage','repo') ON CONFLICT(name) DO NOTHING",
        );
        old_insert.execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO ci_release_environment(name,repository) VALUES('stage','repo') ON CONFLICT(name) DO NOTHING")
            .execute(store.pool()).await.unwrap();
        let updated = sqlx::query(
            "UPDATE ci_release_environment SET automation_held=true WHERE name='stage'",
        )
        .execute(store.pool())
        .await
        .unwrap();
        assert_eq!(updated.rows_affected(), 1);
        assert_eq!(
            api_after,
            service_view(&store, "stage", "api").await.unwrap()
        );
        assert_eq!(
            worker_after,
            service_view(&store, "stage", "worker").await.unwrap()
        );

        // Historical manifests remain intact but cannot authorize execution,
        // even if a caller retries an old run rather than admitting a new one.
        let mut historical_manifest =
            super::bundle(&store, "old").await.unwrap()["manifest"].clone();
        historical_manifest["build_id"] = json!("legacy-build");
        historical_manifest["components"]["worker"] =
            historical_manifest["components"]["api"].clone();
        sqlx::query("INSERT INTO ci_release_build(id,repository,name,revision,git_ref,policy,created_by,status) SELECT 'legacy-build',repository,'legacy-build',revision,git_ref,policy,created_by,status FROM ci_release_build WHERE id='old'")
            .execute(store.pool()).await.unwrap();
        sqlx::query("UPDATE ci_release_bundle SET manifest=$1,manifest_sha256=$2,build_id='legacy-build' WHERE id='legacy-bundle'")
            .bind(&historical_manifest)
            .bind(hex::encode(Sha256::digest(serde_json::to_vec(&historical_manifest).unwrap())))
            .execute(store.pool()).await.unwrap();
        assert!(bundle_for_run(&store, "legacy-run").await.unwrap_err()
            .to_string().contains("archived and cannot execute"));
        assert_eq!(super::bundle(&store, "legacy-bundle").await.unwrap()["manifest"], historical_manifest);
        let visible = crate::release_catalog::list(&store, None).await.unwrap();
        assert!(visible.iter().any(|r| r["id"] == "old"));
        assert!(!visible.iter().any(|r| r["id"] == "legacy-bundle"));
        let legacy_request = Request {
            environment: "legacy".into(),
            service: Some("api".into()),
            bundle_id: "old".into(),
            request_id: "scoped".into(),
            recover: false,
        };
        let old_bundle = super::bundle(&store, "old").await.unwrap();
        assert!(
            persist(
                &store,
                &legacy_request,
                &policy,
                &old_bundle,
                &plan,
                &source,
                "operator",
                false
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("legacy environment deployment must settle first")
        );
        sqlx::query("UPDATE ci_run SET status='success' WHERE id='legacy-run'")
            .execute(store.pool())
            .await
            .unwrap();
        finish(&store).await.unwrap();
        let settled = service_view(&store, "legacy", "").await.unwrap();
        assert!(settled["state"]["active_run"].is_null());
        assert!(!settled["history"][0]["completed_at"].is_null());
        assert!(service_view(&store, "legacy", "api").await.unwrap()["state"].is_null());
        store.pool().close().await;
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
