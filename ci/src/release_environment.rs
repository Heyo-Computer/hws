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
    pub repository: String,
    pub workflow_id: String,
    #[serde(default)]
    pub mode: Mode,
    pub network: Option<String>,
    pub workflow: String,
    #[serde(default)]
    pub service_targets: BTreeMap<String, crate::service_rollout::Target>,
    #[serde(default)]
    pub placements: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub environment: String,
    pub bundle_id: String,
    pub request_id: String,
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
        ensure!(
            !policy.repository.is_empty() && !policy.workflow_id.is_empty(),
            "environment requires repository and workflow scope"
        );
        plan(name, policy)?;
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
                            | "ci/rollout-host-app-lb"
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
    let id: Option<String> =
        sqlx::query_scalar("SELECT bundle_id FROM ci_release_promotion WHERE run_id=$1")
            .bind(run_id)
            .fetch_optional(store.pool())
            .await?;
    let Some(id) = id else { return Ok(None) };
    let value = bundle(store, &id).await?;
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
    request: Request,
    actor: &str,
    automatic: bool,
) -> Result<Value> {
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
    ensure!(
        !automatic || policy.mode == Mode::Automatic,
        "environment requires manual promotion"
    );
    let bundle = bundle(&d.store, &request.bundle_id).await?;
    ensure!(
        crate::repos::same_repo(
            &policy.repository,
            bundle["manifest"]["repository"].as_str().unwrap_or("")
        ),
        "release repository does not own this environment"
    );
    let mut plan = plan(&request.environment, policy)?;
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
        &d.store, &request, policy, &bundle, &plan, &source, actor, automatic,
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
    let mut tx = store.pool().begin().await?;
    let repository = bundle["manifest"]["repository"].as_str().unwrap();
    sqlx::query("INSERT INTO ci_release_environment(name,repository) VALUES($1,$2) ON CONFLICT(name) DO NOTHING")
        .bind(&request.environment).bind(repository).execute(&mut *tx).await?;
    // Serialize changes to one environment, not CI execution across regions.
    let env = sqlx::query("SELECT * FROM ci_release_environment WHERE name=$1 FOR UPDATE")
        .bind(&request.environment)
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        env.get::<&str, _>("repository") == repository,
        "environment repository changed"
    );
    if let Some(saved) = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(p) FROM ci_release_promotion p WHERE environment=$1 AND request_id=$2",
    )
    .bind(&request.environment)
    .bind(&request.request_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        ensure!(
            saved["bundle_id"] == request.bundle_id,
            "request_id already selects another release"
        );
        return Ok(saved);
    }
    ensure!(
        env.get::<Option<String>, _>("active_run").is_none(),
        "environment already has a deployment in progress"
    );
    ensure!(
        !automatic || !env.get::<bool, _>("automation_held"),
        "environment automation is held"
    );
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
        "INSERT INTO ci_release_promotion(run_id,environment,request_id,bundle_id,automatic,policy)
        VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(&run_id)
    .bind(&request.environment)
    .bind(&request.request_id)
    .bind(&request.bundle_id)
    .bind(automatic)
    .bind(serde_json::to_value(policy)?)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE ci_release_environment SET active_run=$2,automation_held=automation_held OR $3,updated_at=now() WHERE name=$1")
        .bind(&request.environment).bind(&run_id).bind(!automatic).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(
        json!({"run_id":run_id,"environment":request.environment,"bundle_id":request.bundle_id,"request_id":request.request_id}),
    )
}

pub async fn list(d: &Dispatcher) -> Result<Value> {
    let configured = policies(d.config.release_environments.as_deref())?;
    let mut environments = Vec::new();
    for (name, policy) in configured {
        let state: Option<Value> =
            sqlx::query_scalar("SELECT to_jsonb(e) FROM ci_release_environment e WHERE name=$1")
                .bind(&name)
                .fetch_optional(d.store.pool())
                .await?;
        let history: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(p) || jsonb_build_object('status',r.status,'error',r.error,
            'deployments',(SELECT coalesce(jsonb_agg(jsonb_build_object('service',d.service_id,'revision',d.sha,'status',d.status)),'[]')
            FROM ci_service_deployment d WHERE d.run_id=p.run_id)) FROM ci_release_promotion p JOIN ci_run r ON r.id=p.run_id
            WHERE p.environment=$1 ORDER BY p.created_at DESC LIMIT 20").bind(&name).fetch_all(d.store.pool()).await?;
        environments.push(json!({"name":name,"mode":policy.mode,"repository":policy.repository,"state":state,"history":history}));
    }
    Ok(json!({"environments":environments}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationRequest {
    pub environment: String,
    pub held: bool,
}

pub async fn automation(d: &Dispatcher, request: AutomationRequest) -> Result<Value> {
    let configured = policies(d.config.release_environments.as_deref())?;
    let policy = configured
        .get(&request.environment)
        .ok_or_else(|| anyhow::anyhow!("unknown environment"))?;
    set_automation(&d.store, policy, request).await
}

async fn set_automation(
    store: &Store,
    policy: &Policy,
    request: AutomationRequest,
) -> Result<Value> {
    ensure!(
        request.held || policy.mode == Mode::Automatic,
        "environment policy is manual"
    );
    let mut tx = store.pool().begin().await?;
    sqlx::query("INSERT INTO ci_release_environment(name,repository) VALUES($1,$2) ON CONFLICT(name) DO NOTHING")
        .bind(&request.environment).bind(&policy.repository).execute(&mut *tx).await?;
    let row = sqlx::query(
        "SELECT repository,active_run FROM ci_release_environment WHERE name=$1 FOR UPDATE",
    )
    .bind(&request.environment)
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
        "UPDATE ci_release_environment SET automation_held=$2,updated_at=now() WHERE name=$1",
    )
    .bind(&request.environment)
    .bind(request.held)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(json!({"environment":request.environment,"automation_held":request.held}))
}

async fn finish(store: &Store) -> Result<()> {
    let mut tx = store.pool().begin().await?;
    let rows = sqlx::query("SELECT e.name,p.run_id,p.bundle_id,r.status FROM ci_release_environment e
        JOIN ci_release_promotion p ON p.run_id=e.active_run JOIN ci_run r ON r.id=p.run_id
        WHERE r.status IN ('success','failure','cancelled')
        AND NOT EXISTS(SELECT 1 FROM ci_service_deployment d WHERE d.run_id=r.id AND d.status NOT IN ('passed','failed'))
        FOR UPDATE OF e SKIP LOCKED").fetch_all(&mut *tx).await?;
    for row in rows {
        let success = row.get::<&str, _>("status") == "success";
        sqlx::query("UPDATE ci_release_environment SET previous_bundle=CASE WHEN $2 AND current_bundle IS DISTINCT FROM $3 THEN current_bundle ELSE previous_bundle END,
            current_bundle=CASE WHEN $2 THEN $3 ELSE current_bundle END,active_run=NULL,
            automation_held=automation_held OR NOT $2,updated_at=now() WHERE name=$1")
            .bind(row.get::<&str,_>("name")).bind(success).bind(row.get::<&str,_>("bundle_id")).execute(&mut *tx).await?;
        sqlx::query("UPDATE ci_release_promotion SET completed_at=now() WHERE run_id=$1")
            .bind(row.get::<&str, _>("run_id"))
            .execute(&mut *tx)
            .await?;
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

async fn latest_ready(store: &Store, repository: &str) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT c.id FROM ci_release_bundle c JOIN ci_release_build b ON b.id=c.build_id
        WHERE c.repository=$1 AND b.status='ready' AND c.manifest->>'retained'='true'
        ORDER BY b.created_at DESC,b.id DESC LIMIT 1",
    )
    .bind(repository)
    .fetch_optional(store.pool())
    .await?)
}

async fn reconcile(d: &Dispatcher) -> Result<()> {
    finish(&d.store).await?;
    for (environment, policy) in policies(d.config.release_environments.as_deref())? {
        if policy.mode != Mode::Automatic {
            continue;
        }
        let held: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_release_environment WHERE name=$1 AND (automation_held OR active_run IS NOT NULL))")
            .bind(&environment).fetch_one(d.store.pool()).await?;
        if held {
            continue;
        }
        let id = latest_ready(&d.store, &policy.repository).await?;
        let Some(id) = id else { continue };
        let attempted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_release_promotion WHERE environment=$1 AND bundle_id=$2)")
            .bind(&environment).bind(&id).fetch_one(d.store.pool()).await?;
        if attempted {
            continue;
        }
        if let Err(error) = admit(
            d,
            Request {
                environment,
                bundle_id: id.clone(),
                request_id: format!("auto-{id}"),
            },
            "environment-policy",
            true,
        )
        .await
        {
            tracing::warn!(%error,"automatic promotion deferred");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for (name, policy) in environments {
            let plan = plan(&name, &policy).unwrap();
            assert_eq!(plan.jobs[1].needs, [plan.jobs[0].base_id.clone()]);
            for target in policy.service_targets.values() {
                crate::service_rollout::validate_target(target).unwrap();
            }
            for job in plan.jobs {
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

    fn policy() -> Policy {
        Policy {
            repository: "repo".into(),
            workflow_id: "platform".into(),
            mode: Mode::Manual,
            network: None,
            workflow: "on: promotion\njobs:\n  first:\n    steps: [{uses: ci/rollout-service}]\n  second:\n    needs: [first]\n    steps: [{uses: ci/rollout-service}]\n".into(),
            service_targets: BTreeMap::new(),
            placements: BTreeMap::new(),
        }
    }

    #[test]
    fn promotion_policy_requires_sequential_deployment_only() {
        let valid = policy();
        assert_eq!(plan("any-region", &valid).unwrap().jobs.len(), 2);
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
        store.migrate().await.unwrap();
        store.migrate().await.unwrap();
        let policy = policy();
        let plan = plan("stage", &policy).unwrap();
        for id in ["old", "new"] {
            let revision = if id == "old" { "a" } else { "b" }.repeat(40);
            let manifest = json!({"version":2,"retained":true,"build_id":id,"repository":"repo","revision":revision,
                "components":{"api":{"id":"artifact","run_id":"build","workflow":"api.yml","job":"linux",
                "name":"binary","sink":"artifacts","uri":"retained-api","sha256":"d".repeat(64),"size_bytes":73}}});
            sqlx::query("INSERT INTO ci_release_build(id,repository,name,revision,git_ref,policy,created_by,status) VALUES($1,'repo',$1,$2,'refs/heads/main','{}','test','ready')")
                .bind(id).bind(&revision).execute(store.pool()).await.unwrap();
            sqlx::query("INSERT INTO ci_release_bundle(id,repository,name,manifest,manifest_sha256,created_by,build_id) VALUES($1,'repo',$1,$2,$3,'test',$1)")
                .bind(id).bind(&manifest).bind(hex::encode(Sha256::digest(serde_json::to_vec(&manifest).unwrap())))
                .execute(store.pool()).await.unwrap();
        }
        sqlx::query("UPDATE ci_release_build SET created_at=CASE WHEN id='old' THEN now()-interval '2 hours' ELSE now()-interval '1 hour' END")
            .execute(store.pool()).await.unwrap();
        sqlx::query("UPDATE ci_release_bundle SET created_at=CASE WHEN id='old' THEN now() ELSE now()-interval '30 minutes' END")
            .execute(store.pool()).await.unwrap();
        assert_eq!(
            latest_ready(&store, "repo").await.unwrap().as_deref(),
            Some("new"),
            "a slow old build must not displace a newer build"
        );
        let mut bundle = super::bundle(&store, "old").await.unwrap();
        let mut request = Request {
            environment: "stage".into(),
            bundle_id: "old".into(),
            request_id: "first".into(),
        };
        let source = serde_json::to_vec(&crate::trigger::GitPatchSource {
            base_revision: "a".repeat(40),
            target_tree: "b".repeat(40),
            patch_base64: String::new(),
            workflows: BTreeMap::new(),
            changes: crate::paths::Changes::unknown("retained release"),
        })
        .unwrap();
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
            sqlx::query_scalar("SELECT active_run FROM ci_release_environment WHERE name='stage'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(
            active.as_deref(),
            Some(run.as_str()),
            "run completion must not hide an unresolved rollout"
        );
        sqlx::query("UPDATE ci_service_deployment SET status='passed' WHERE id='rollout'")
            .execute(store.pool())
            .await
            .unwrap();
        finish(&store).await.unwrap();
        let state = sqlx::query("SELECT * FROM ci_release_environment WHERE name='stage'")
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
            "SELECT current_bundle FROM ci_release_environment WHERE name='stage'",
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
        let state = sqlx::query("SELECT * FROM ci_release_environment WHERE name='stage'")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(state.get::<String, _>("current_bundle"), "new");
        assert_eq!(state.get::<String, _>("previous_bundle"), "old");
        let toggle = |held| AutomationRequest {
            environment: "stage".into(),
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
            "SELECT previous_bundle FROM ci_release_environment WHERE name='stage'",
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
    }
}
