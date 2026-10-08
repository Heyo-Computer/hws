//! Service-scoped build admission. Existing CI jobs do the work; this module
//! freezes their membership and publishes a retained bundle after they succeed.
use crate::{
    dispatch::Dispatcher, plan::Plan, release_catalog::Selection, store::Store,
    trigger::GitPatchSource,
};
use anyhow::{Result, ensure};
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Existing workflow/secrets scope, not a new credential namespace.
    pub workflow_id: String,
    pub git_ref: String,
    pub components: BTreeMap<String, Selection>,
    pub network: Option<String>,
    /// Minutes after midnight UTC. None means manual builds only.
    pub daily_utc_minute: Option<u16>,
    /// Frozen at admission, never trusted from operator configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_identity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub repository: String,
    pub name: String,
    /// Full merged SHA. None freezes the configured branch tip at admission.
    pub revision: Option<String>,
    /// May be omitted only for a repository configured with one service.
    pub service: Option<String>,
}

fn select(policy: &Policy, service: Option<&str>) -> Result<Policy> {
    let service = match service {
        Some(service) => service,
        None if policy.components.len() == 1 => policy.components.keys().next().unwrap(),
        None => anyhow::bail!("service is required for a multi-service repository"),
    };
    let selection = policy
        .components
        .get(service)
        .ok_or_else(|| anyhow::anyhow!("service has no release build policy"))?;
    let mut selected = policy.clone();
    selected.components = BTreeMap::from([(service.to_string(), selection.clone())]);
    selected.input_identity = None;
    Ok(selected)
}

fn check_service(value: &Value, policy: &Policy) -> Result<()> {
    let mut saved: Policy = serde_json::from_value(value["policy"].clone())?;
    ensure!(
        saved.components.keys().eq(policy.components.keys()),
        "release build name already identifies another service"
    );
    let mut requested = policy.clone();
    saved.input_identity = None;
    requested.input_identity = None;
    ensure!(
        serde_json::to_value(saved)? == serde_json::to_value(requested)?,
        "release build name already identifies another selected policy"
    );
    Ok(())
}

fn service_daily_name(service: &str, day: &str) -> String {
    // The maximum service name plus a date exceeds the admission limit.
    // Hashing the full name also avoids truncation collisions.
    let digest = hex::encode(Sha256::digest(service.as_bytes()));
    format!("{day}-{digest}")
}

pub fn policies(raw: Option<&str>) -> Result<BTreeMap<String, Policy>> {
    let policies: BTreeMap<String, Policy> = match raw {
        Some(raw) => serde_yaml::from_str(raw)?,
        None => return Ok(BTreeMap::new()),
    };
    let mut seen = Vec::new();
    for (repository, policy) in &policies {
        ensure!(
            policy.input_identity.is_none(),
            "input_identity is admission-owned evidence"
        );
        ensure!(
            !seen
                .iter()
                .any(|other: &&str| crate::repos::same_repo(other, repository)),
            "duplicate release build repository"
        );
        seen.push(repository.as_str());
        ensure!(
            !policy.workflow_id.trim().is_empty() && policy.git_ref.starts_with("refs/heads/"),
            "release builds require a workflow scope and full branch ref"
        );
        ensure!(
            policy.daily_utc_minute.is_none_or(|minute| minute < 1440),
            "daily_utc_minute must be 0..1439"
        );
        ensure!(
            !policy.components.is_empty() && policy.components.len() <= 256,
            "select 1..256 release components"
        );
        for (component, selection) in &policy.components {
            ensure!(
                valid_name(component)
                    && !selection.workflow.trim().is_empty()
                    && !selection.job.trim().is_empty()
                    && !selection.artifact.trim().is_empty(),
                "each component needs a name, workflow, producer job and artifact"
            );
        }
    }
    Ok(policies)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Build every selected workflow, regardless of submit path filters. Keep job
/// and step conditions: changed() sees unknown/all, while genuine test failures
/// and optional matrix cells retain their normal semantics.
fn plans(policy: &Policy, source: &GitPatchSource) -> Result<Vec<Plan>> {
    let paths: BTreeSet<_> = policy.components.values().map(|s| &s.workflow).collect();
    let mut result = Vec::new();
    for path in paths {
        let text = source
            .workflows
            .get(path)
            .ok_or_else(|| anyhow::anyhow!("missing build workflow {path}"))?;
        let workflow = crate::workflow::Workflow::parse(path, text)?;
        ensure!(
            !workflow.on.iter().any(|on| on == "release"),
            "release publication workflows cannot build a bundle"
        );
        let mut plan = Plan::build(&workflow)?;
        for job in &mut plan.jobs {
            ensure!(
                !job.continue_on_error,
                "release build jobs must not tolerate failure"
            );
            for step in &mut job.steps {
                ensure!(
                    !step.continue_on_error,
                    "release build steps must not tolerate failure"
                );
                // These are build-only builtins. Arbitrary shell is still trusted
                // repository code, just as it is in ordinary validation jobs.
                ensure!(
                    matches!(step.uses.as_deref(), None | Some("ci/upload-artifact")),
                    "release build workflow contains a non-build action"
                );
                if step.uses.as_deref() == Some("ci/upload-artifact") {
                    // A build is not a deployment or a publication of 'latest'.
                    step.with.remove("alias");
                    // Preserve explicit public downloads: host self-update
                    // consumes digest URLs without artifact-store credentials.
                }
            }
        }
        for selection in policy.components.values().filter(|s| &s.workflow == path) {
            ensure!(
                plan.jobs.iter().any(|j| j.key == selection.job),
                "component producer {} is not an exact expanded job in {path}",
                selection.job
            );
        }
        result.push(plan);
    }
    Ok(result)
}

pub async fn list(store: &Store) -> Result<Vec<Value>> {
    Ok(sqlx::query_scalar("SELECT to_jsonb(b) || jsonb_build_object('runs',
        (SELECT coalesce(jsonb_object_agg(workflow_path,run_id),'{}') FROM ci_release_build_run WHERE build_id=b.id))
        FROM ci_release_build b ORDER BY created_at DESC,id DESC LIMIT 100")
        .fetch_all(store.pool()).await?)
}

async fn existing(
    store: &Store,
    repository: &str,
    name: &str,
    revision: Option<&str>,
) -> Result<Option<Value>> {
    let value: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(b) FROM ci_release_build b WHERE repository=$1 AND name=$2",
    )
    .bind(repository)
    .bind(name)
    .fetch_optional(store.pool())
    .await?;
    if let Some(value) = &value {
        ensure!(
            revision.is_none_or(|sha| value["revision"]
                .as_str()
                .is_some_and(|saved| saved.eq_ignore_ascii_case(sha))),
            "release build name already identifies another revision"
        );
    }
    Ok(value)
}

async fn reusable(store: &Store, repository: &str, policy: &Policy) -> Result<Option<Value>> {
    if policy.input_identity.is_none() {
        return Ok(None);
    }
    Ok(sqlx::query_scalar(
        "SELECT to_jsonb(b) FROM ci_release_build b JOIN ci_release_bundle c ON c.build_id=b.id
         WHERE b.repository=$1 AND b.status='ready' AND b.policy=$2
         AND c.manifest->>'retained'='true' ORDER BY b.created_at DESC LIMIT 1",
    )
    .bind(repository)
    .bind(serde_json::to_value(policy)?)
    .fetch_optional(store.pool())
    .await?)
}

pub async fn admit(d: &Dispatcher, request: Request, actor: &str) -> Result<Value> {
    let _admission = d
        .executor
        .admission_permit()
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(valid_name(&request.name), "invalid release build name");
    ensure!(
        d.artifacts.kind() == "artifacts",
        "release builds require the artifacts sink with retained GC roots"
    );
    let configured = policies(d.config.release_builds.as_deref())?;
    let (repository, policy) = configured
        .iter()
        .find(|(repo, _)| crate::repos::same_repo(repo, &request.repository))
        .ok_or_else(|| anyhow::anyhow!("repository has no operator release build policy"))?;
    let mut policy = select(policy, request.service.as_deref())?;
    if let Some(value) = existing(
        &d.store,
        repository,
        &request.name,
        request.revision.as_deref(),
    )
    .await?
    {
        check_service(&value, &policy)?;
        return Ok(value);
    }
    let resolved = d
        .secrets
        .resolve(&crate::secrets::Secrets::prefix(
            &policy.workflow_id,
            "default",
        ))
        .await?;
    let token = resolved
        .secrets
        .get("CI_GIT_AUTH_TOKEN")
        .or_else(|| resolved.secrets.get("GITHUB_TOKEN"))
        .map(String::as_str)
        .unwrap_or("");
    let paths = policy
        .components
        .values()
        .map(|s| s.workflow.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let (source, identity, commit_message) = crate::release_git::build_source_scoped(
        repository,
        &policy.git_ref,
        request.revision.as_deref(),
        &paths,
        token,
        d.config.max_source_bytes,
    )
    .await
    .map_err(anyhow::Error::msg)?;
    policy.input_identity = Some(identity);
    // Only retained catalog candidates with exactly the frozen selected policy
    // and verified input identity can be reused. Old builds lack this evidence.
    let reused = reusable(&d.store, repository, &policy).await?;
    if let Some(mut value) = reused {
        value["reused"] = json!(true);
        value["requested_revision"] = json!(source.base_revision);
        value["requested_name"] = json!(request.name);
        return Ok(value);
    }
    let mut plans = plans(&policy, &source)?;
    for plan in &mut plans {
        d.assign_network(plan, policy.network.as_deref(), &mut Vec::new())?;
    }
    let value = persist(
        &d.store,
        repository,
        &request.name,
        &policy,
        &source,
        &plans,
        actor,
        &commit_message,
    )
    .await?;
    // Scheduling is deliberately after commit. Existing stalled-run recovery
    // replays this if the instance stops or queue publication fails here.
    let runs: Vec<String> =
        sqlx::query_scalar("SELECT run_id FROM ci_release_build_run WHERE build_id=$1")
            .bind(value["id"].as_str())
            .fetch_all(d.store.pool())
            .await?;
    for run in runs {
        if let Err(error) = d.advance_run(&run).await {
            tracing::warn!(%run, %error, "release build scheduling deferred");
        }
    }
    Ok(value)
}

async fn persist(
    store: &Store,
    repository: &str,
    name: &str,
    policy: &Policy,
    source: &GitPatchSource,
    plans: &[Plan],
    actor: &str,
    commit_message: &str,
) -> Result<Value> {
    let mut tx = store.pool().begin().await?;
    let id = uuid::Uuid::new_v4().to_string();
    let inserted = sqlx::query(
        "INSERT INTO ci_release_build(id,repository,name,revision,git_ref,policy,created_by,commit_message)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(repository,name) DO NOTHING",
    )
    .bind(&id)
    .bind(repository)
    .bind(name)
    .bind(&source.base_revision)
    .bind(&policy.git_ref)
    .bind(serde_json::to_value(policy)?)
    .bind(actor)
    .bind(commit_message)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    let saved: Value = sqlx::query_scalar(
        "SELECT to_jsonb(b) FROM ci_release_build b WHERE repository=$1 AND name=$2",
    )
    .bind(repository)
    .bind(name)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        saved["revision"].as_str() == Some(&source.base_revision),
        "release build name already identifies another revision"
    );
    check_service(&saved, policy)?;
    if inserted {
        let bytes = serde_json::to_vec(source)?;
        for plan in plans {
            let run = crate::vm::new_id();
            let request = crate::store::RunRequest {
                workflow_id: policy.workflow_id.clone(),
                repo_url: repository.into(),
                git_ref: policy.git_ref.clone(),
                sha: source.base_revision.clone(),
                source: "release-build".into(),
                actor_subject: Some(actor.into()),
                changes: source.changes.clone(),
                // Always the fleet: a release build is admitted from an
                // operator policy on the fleet API, never from a namespace,
                // and its secrets are read under the fleet prefix above.
                namespace: String::new(),
                ..Default::default()
            };
            Store::create_run_in(&mut tx, &run, &request, plan).await?;
            Store::record_source_in(&mut tx, &run, &bytes).await?;
            sqlx::query(
                "INSERT INTO ci_release_build_run(build_id,workflow_path,run_id) VALUES($1,$2,$3)",
            )
            .bind(&id)
            .bind(&plan.workflow_path)
            .bind(&run)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(saved)
}

/// Return None while work is active. Terminal failures never become a bundle.
async fn collect(store: &Store, build: &Value) -> Result<Option<Value>> {
    let id = build["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("build has no id"))?;
    let policy: Policy = serde_json::from_value(build["policy"].clone())?;
    let runs = sqlx::query(
        "SELECT m.workflow_path,r.id,r.status,r.sha FROM ci_release_build_run m
        JOIN ci_run r ON r.id=m.run_id WHERE m.build_id=$1",
    )
    .bind(id)
    .fetch_all(store.pool())
    .await?;
    ensure!(
        runs.len()
            == policy
                .components
                .values()
                .map(|s| &s.workflow)
                .collect::<BTreeSet<_>>()
                .len(),
        "build membership is incomplete"
    );
    ensure!(
        !runs
            .iter()
            .any(|r| matches!(r.get::<&str, _>("status"), "failure" | "cancelled")),
        "a release build workflow failed or was cancelled"
    );
    if runs.iter().any(|r| r.get::<&str, _>("status") != "success") {
        return Ok(None);
    }
    let mut components = BTreeMap::new();
    for (component, selection) in &policy.components {
        let run = runs
            .iter()
            .find(|r| r.get::<&str, _>("workflow_path") == selection.workflow)
            .ok_or_else(|| anyhow::anyhow!("missing component workflow"))?;
        ensure!(
            Some(run.get::<&str, _>("sha")) == build["revision"].as_str(),
            "build revision mismatch"
        );
        let artifacts = sqlx::query("SELECT a.* FROM ci_artifact a JOIN ci_job j ON j.id=a.job_id
            WHERE a.run_id=$1 AND a.name=$2 AND j.job_key=$3 AND j.status='success' AND j.carried_from IS NULL
            AND NOT EXISTS(SELECT 1 FROM ci_step s WHERE s.job_id=j.id AND s.status IN ('failure','cancelled'))")
            .bind(run.get::<&str,_>("id")).bind(&selection.artifact).bind(&selection.job).fetch_all(store.pool()).await?;
        ensure!(
            artifacts.len() == 1,
            "component {component} needs exactly one successful artifact producer"
        );
        let a = &artifacts[0];
        let digest: Option<String> = a.get("digest");
        let digest =
            digest.ok_or_else(|| anyhow::anyhow!("component {component} has no digest"))?;
        ensure!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid component digest"
        );
        let size: i64 = a.get("size_bytes");
        ensure!(
            size >= 0 && a.get::<&str, _>("sink") == "artifacts",
            "component must use retained artifact storage"
        );
        components.insert(
            component.clone(),
            crate::release_catalog::Artifact {
                id: a.get("id"),
                run_id: run.get("id"),
                workflow: selection.workflow.clone(),
                job: selection.job.clone(),
                name: selection.artifact.clone(),
                sink: a.get("sink"),
                uri: a.get("uri"),
                sha256: digest.to_lowercase(),
                size_bytes: size as u64,
            },
        );
    }
    Ok(Some(
        json!({"version":2,"repository":build["repository"],"revision":build["revision"],
        "build_id":id,"retained":true,"components":components}),
    ))
}

async fn finalize(
    store: &Store,
    sink: &dyn crate::artifacts::ArtifactSink,
    build: &Value,
    mut manifest: Value,
) -> Result<()> {
    let id = build["id"].as_str().unwrap();
    for (component, artifact) in manifest["components"].as_object_mut().unwrap() {
        let stored = crate::artifacts::StoredArtifact {
            sink: "artifacts",
            digest: Some(artifact["sha256"].as_str().unwrap().into()),
            uri: artifact["uri"].as_str().unwrap().into(),
            size_bytes: artifact["size_bytes"].as_u64().unwrap(),
            public_url: None,
        };
        // Content belongs in the key too: reusing a release name may never
        // repoint an already-retained blob even before the DB commit.
        let key = format!("{id}:{component}:{}", stored.digest.as_deref().unwrap());
        let retained = sink.retain(&stored, &key).await?;
        artifact["uri"] = json!(retained.uri);
    }
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&manifest)?));
    let mut tx = store.pool().begin().await?;
    // One build's finalization, never a global execution lock. The state change
    // and bundle insertion commit together; external pin retries are idempotent.
    let changed = sqlx::query(
        "UPDATE ci_release_build SET status='ready',error=NULL WHERE id=$1 AND status='building'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        tx.rollback().await?;
        return Ok(());
    }
    sqlx::query("INSERT INTO ci_release_bundle(id,repository,name,build_id,manifest,manifest_sha256,created_by)
        VALUES($1,$2,$3,$1,$4,$5,$6)")
        .bind(id).bind(build["repository"].as_str()).bind(build["name"].as_str())
        .bind(&manifest).bind(digest).bind(build["created_by"].as_str()).execute(&mut *tx).await?;
    for (component, artifact) in manifest["components"].as_object().unwrap() {
        sqlx::query("INSERT INTO ci_release_bundle_artifact(bundle_id,component,artifact_id) VALUES($1,$2,$3)")
            .bind(id).bind(component).bind(artifact["id"].as_str()).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

fn daily_name(policy: &Policy, now: DateTime<Utc>) -> Option<String> {
    policy
        .daily_utc_minute
        .filter(|minute| now.hour() * 60 + now.minute() >= u32::from(*minute))
        .map(|_| format!("daily-{}", now.format("%Y-%m-%d")))
}

pub fn spawn(d: Arc<Dispatcher>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let Ok(_effect) = d.executor.effect_permit().await else {
                continue;
            };
            if let Err(error) = reconcile(&d).await {
                tracing::warn!(%error, "release build reconciliation deferred");
            }
        }
    });
}

async fn reconcile(d: &Dispatcher) -> Result<()> {
    let builds: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(b) FROM ci_release_build b WHERE status='building' ORDER BY created_at LIMIT 100")
        .fetch_all(d.store.pool()).await?;
    for build in builds {
        let manifest = match collect(&d.store, &build).await {
            Ok(Some(manifest)) => manifest,
            Ok(None) => continue,
            Err(error) => {
                // A DB outage is retryable; invalid completed build evidence is
                // terminal and must not fill the pending reconciliation batch.
                if error.downcast_ref::<sqlx::Error>().is_some() {
                    return Err(error);
                }
                sqlx::query("UPDATE ci_release_build SET status='failure',error=$2 WHERE id=$1 AND status='building'")
                    .bind(build["id"].as_str()).bind(error.to_string()).execute(d.store.pool()).await?;
                continue;
            }
        };
        if let Err(error) = finalize(&d.store, d.artifacts.as_ref(), &build, manifest).await {
            // Pin/storage failures retry without rebuilding or republishing Git.
            sqlx::query("UPDATE ci_release_build SET error=$2 WHERE id=$1 AND status='building'")
                .bind(build["id"].as_str())
                .bind(error.to_string())
                .execute(d.store.pool())
                .await?;
        }
    }
    for (repository, policy) in policies(d.config.release_builds.as_deref())? {
        let Some(name) = daily_name(&policy, Utc::now()) else {
            continue;
        };
        for service in policy.components.keys() {
            if let Err(error) = admit(
                d,
                Request {
                    repository: repository.clone(),
                    name: service_daily_name(service, &name),
                    revision: None,
                    service: Some(service.clone()),
                },
                "daily-scheduler",
            )
            .await
            {
                tracing::warn!(%error, "daily release build admission deferred");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_selection_policy_identity_and_daily_names_are_independent() {
        let configured = policy();
        assert!(select(&configured, None).is_err());
        assert!(select(&configured, Some("absent")).is_err());
        let api = select(&configured, Some("api")).unwrap();
        let worker = select(&configured, Some("worker")).unwrap();
        assert_eq!(api.components.len(), 1);
        assert_eq!(plans(&api, &source()).unwrap().len(), 1);
        assert!(select(&api, None).is_ok());
        let saved = json!({"policy":api});
        assert!(check_service(&saved, &worker).is_err());
        assert!(check_service(&saved, &api).is_ok());
        let mut changed = api.clone();
        changed.components.get_mut("api").unwrap().artifact = "other".into();
        assert!(check_service(&saved, &changed).is_err());
        assert_ne!(
            serde_json::to_value(&api).unwrap(),
            serde_json::to_value(&changed).unwrap()
        );
        let day = daily_name(&configured, "2026-10-05T02:00:00Z".parse().unwrap()).unwrap();
        assert_ne!(
            service_daily_name("api", &day),
            service_daily_name("worker", &day)
        );
        assert!(valid_name(&service_daily_name(&"s".repeat(128), &day)));
        let request: Request =
            serde_json::from_value(json!({"repository":"repo","name":"build"})).unwrap();
        assert!(request.service.is_none());
    }

    fn policy() -> Policy {
        Policy {
            workflow_id: "platform".into(),
            git_ref: "refs/heads/main".into(),
            network: None,
            daily_utc_minute: Some(90),
            input_identity: None,
            components: BTreeMap::from([
                (
                    "api".into(),
                    Selection {
                        workflow: "api.yml".into(),
                        job: "build".into(),
                        artifact: "binary".into(),
                    },
                ),
                (
                    "worker".into(),
                    Selection {
                        workflow: "worker.yml".into(),
                        job: "build".into(),
                        artifact: "binary".into(),
                    },
                ),
            ]),
        }
    }

    fn source() -> GitPatchSource {
        let yaml = "on:\n  submit:\n    paths: ['never/**']\njobs:\n  build:\n    if: changed('never/**')\n    steps:\n      - run: echo build\n      - uses: ci/upload-artifact\n        with:\n          name: binary\n          path: out\n          alias: latest\n          public: 'true'\n";
        GitPatchSource {
            base_revision: "a".repeat(40),
            target_tree: "b".repeat(40),
            patch_base64: String::new(),
            workflows: BTreeMap::from([
                ("api.yml".into(), yaml.into()),
                ("worker.yml".into(), yaml.into()),
            ]),
            changes: crate::paths::Changes::unknown("full build"),
        }
    }

    #[test]
    fn release_build_is_complete_and_cannot_move_aliases_or_deploy() {
        let policy = policy();
        let mut source = source();
        let plans = super::plans(&policy, &source).unwrap();
        assert_eq!(plans.len(), 2);
        for plan in plans {
            assert_eq!(plan.jobs.len(), 1);
            assert!(plan.jobs[0].condition.as_ref().unwrap().contains("changed"));
            assert_eq!(plan.jobs[0].steps[1].with.get("public").unwrap(), "true");
            assert!(!plan.jobs[0].steps[1].with.contains_key("alias"));
        }
        source
            .workflows
            .get_mut("api.yml")
            .unwrap()
            .push_str("      - uses: ci/merge-release\n");
        assert!(super::plans(&policy, &source).is_err());
        let mut wrong_job = policy.clone();
        wrong_job.components.get_mut("worker").unwrap().job = "another".into();
        assert!(super::plans(&wrong_job, &self::source()).is_err());
    }

    #[test]
    fn release_daily_cutoff_is_utc_and_opt_in() {
        let mut policy = policy();
        let before: DateTime<Utc> = "2026-10-05T01:29:59Z".parse().unwrap();
        let at: DateTime<Utc> = "2026-10-05T01:30:00Z".parse().unwrap();
        assert_eq!(daily_name(&policy, before), None);
        assert_eq!(daily_name(&policy, at).as_deref(), Some("daily-2026-10-05"));
        assert_eq!(
            daily_name(&policy, at + chrono::Duration::hours(12)).as_deref(),
            Some("daily-2026-10-05")
        );
        policy.daily_utc_minute = None;
        assert_eq!(daily_name(&policy, at), None);
        assert!(policies(None).unwrap().is_empty());
        policy.daily_utc_minute = Some(1440);
        assert!(
            policies(Some(
                &serde_yaml::to_string(&BTreeMap::from([("repo", policy)])).unwrap()
            ))
            .is_err()
        );
    }

    async fn database() -> (Store, tempfile::TempDir) {
        let base = std::env::var("CI_TEST_DATABASE_URL").expect("disposable database");
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        let schema = format!("release_build_{}", uuid::Uuid::new_v4().simple());
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
        (store, dir)
    }

    struct Retention {
        fail: bool,
    }
    #[async_trait::async_trait]
    impl crate::artifacts::ArtifactSink for Retention {
        fn kind(&self) -> &'static str {
            "artifacts"
        }
        async fn put(
            &self,
            _: &crate::artifacts::ArtifactRef,
            _: Vec<u8>,
        ) -> Result<crate::artifacts::StoredArtifact, crate::artifacts::ArtifactError> {
            unreachable!()
        }
        async fn get(
            &self,
            _: &crate::artifacts::StoredArtifact,
        ) -> Result<Vec<u8>, crate::artifacts::ArtifactError> {
            unreachable!()
        }
        async fn retain(
            &self,
            stored: &crate::artifacts::StoredArtifact,
            _: &str,
        ) -> Result<crate::artifacts::StoredArtifact, crate::artifacts::ArtifactError> {
            if self.fail {
                return Err(crate::artifacts::ArtifactError::Transport(
                    "store unavailable".into(),
                ));
            }
            Ok(crate::artifacts::StoredArtifact {
                uri: format!("retained-{}", stored.digest.as_deref().unwrap()),
                ..stored.clone()
            })
        }
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL"]
    async fn services_build_independently_and_reuse_only_verified_retained_policy() {
        let (store, _dir) = database().await;
        let configured = policy();
        let mut api = select(&configured, Some("api")).unwrap();
        api.input_identity = Some("a".repeat(64));
        let mut worker = select(&configured, Some("worker")).unwrap();
        worker.input_identity = Some("b".repeat(64));
        let source = source();
        let api_plans = plans(&api, &source).unwrap();
        let worker_plans = plans(&worker, &source).unwrap();
        let day = "daily-2026-10-05";
        let a = persist(
            &store,
            "repo",
            &service_daily_name("api", day),
            &api,
            &source,
            &api_plans,
            "scheduler",
            "API change",
        )
        .await
        .unwrap();
        let w = persist(
            &store,
            "repo",
            &service_daily_name("worker", day),
            &worker,
            &source,
            &worker_plans,
            "scheduler",
            "Worker change",
        )
        .await
        .unwrap();
        assert_ne!(a["id"], w["id"]);
        assert!(
            persist(
                &store,
                "repo",
                &service_daily_name("api", day),
                &worker,
                &source,
                &worker_plans,
                "scheduler",
                "Worker change"
            )
            .await
            .is_err()
        );
        sqlx::query("UPDATE ci_run SET status='failure' WHERE id IN (SELECT run_id FROM ci_release_build_run WHERE build_id=$1)")
            .bind(a["id"].as_str()).execute(store.pool()).await.unwrap();
        assert!(collect(&store, &a).await.is_err());
        let run: String =
            sqlx::query_scalar("SELECT run_id FROM ci_release_build_run WHERE build_id=$1")
                .bind(w["id"].as_str())
                .fetch_one(store.pool())
                .await
                .unwrap();
        sqlx::query("UPDATE ci_run SET status='success' WHERE id=$1")
            .bind(&run)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE ci_job SET status='success' WHERE run_id=$1")
            .bind(&run)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO ci_artifact(id,run_id,job_id,name,sink,digest,size_bytes,uri) VALUES($1,$1,$2,'binary','artifacts',$3,5,'build-tag')")
            .bind(&run).bind(crate::store::job_id(&run, "build")).bind("d".repeat(64)).execute(store.pool()).await.unwrap();
        let manifest = collect(&store, &w).await.unwrap().unwrap();
        assert_eq!(manifest["components"].as_object().unwrap().len(), 1);
        assert!(manifest["components"].get("worker").is_some());
        assert!(reusable(&store, "repo", &worker).await.unwrap().is_none());
        finalize(&store, &Retention { fail: false }, &w, manifest)
            .await
            .unwrap();
        let reused = reusable(&store, "repo", &worker).await.unwrap().unwrap();
        assert_eq!(reused["revision"], source.base_revision);
        assert_eq!(reused["id"], w["id"]);
        assert_eq!(reused["commit_message"], "Worker change");
        let catalog = crate::release_catalog::list(&store, None).await.unwrap();
        let candidate = catalog.iter().find(|r| r["id"] == w["id"]).unwrap();
        assert_eq!(candidate["commit_message"], "Worker change");
        for field in ["inputs", "artifact", "network", "evidence"] {
            let mut different = worker.clone();
            match field {
                "inputs" => different.input_identity = Some("c".repeat(64)),
                "artifact" => {
                    different.components.get_mut("worker").unwrap().artifact = "new".into()
                }
                "network" => different.network = Some("new-network".into()),
                _ => different.input_identity = None,
            }
            assert!(
                reusable(&store, "repo", &different)
                    .await
                    .unwrap()
                    .is_none(),
                "{field}"
            );
        }
        assert!(reusable(&store, "repo", &api).await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL"]
    async fn release_build_atomic_duplicate_admission_and_retained_completion() {
        let (store, _dir) = database().await;
        let policy = policy();
        let source = source();
        let plans = plans(&policy, &source).unwrap();
        let (a, b) = tokio::join!(
            persist(&store, "repo", "daily", &policy, &source, &plans, "a", "Source commit"),
            persist(&store, "repo", "daily", &policy, &source, &plans, "b", "Source commit")
        );
        let build = a.unwrap();
        assert_eq!(build["id"], b.unwrap()["id"]);
        assert_eq!(build["commit_message"], "Source commit");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM ci_run")
                .fetch_one(store.pool())
                .await
                .unwrap(),
            2
        );
        let mut changed = source.clone();
        changed.base_revision = "c".repeat(40);
        assert!(
            persist(&store, "repo", "daily", &policy, &changed, &plans, "a", "Different commit")
                .await
                .is_err()
        );
        assert!(collect(&store, &build).await.unwrap().is_none());
        let runs = sqlx::query(
            "SELECT run_id,workflow_path FROM ci_release_build_run ORDER BY workflow_path",
        )
        .fetch_all(store.pool())
        .await
        .unwrap();
        for (index, row) in runs.iter().enumerate() {
            let run = row.get::<&str, _>("run_id");
            let descriptor = store.source_descriptor(run).await.unwrap();
            assert_eq!(descriptor.base_revision, "a".repeat(40));
            assert!(descriptor.patch().unwrap().is_empty());
            assert_eq!(descriptor.workflows.len(), 2);
            sqlx::query("UPDATE ci_run SET status='success' WHERE id=$1")
                .bind(run)
                .execute(store.pool())
                .await
                .unwrap();
            sqlx::query("UPDATE ci_job SET status='success' WHERE run_id=$1")
                .bind(run)
                .execute(store.pool())
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO ci_artifact(id,run_id,job_id,name,sink,digest,size_bytes,uri)
                VALUES($1,$1,$2,'binary','artifacts',$3,$4,'build-tag')",
            )
            .bind(run)
            .bind(crate::store::job_id(run, "build"))
            .bind(if index == 0 {
                "d".repeat(64)
            } else {
                "e".repeat(64)
            })
            .bind(if index == 0 { 37i64 } else { 59i64 })
            .execute(store.pool())
            .await
            .unwrap();
        }
        sqlx::query("UPDATE ci_artifact SET name='missing' WHERE id=$1")
            .bind(runs[1].get::<&str, _>("run_id"))
            .execute(store.pool())
            .await
            .unwrap();
        assert!(
            collect(&store, &build)
                .await
                .unwrap_err()
                .to_string()
                .contains("exactly one")
        );
        sqlx::query("UPDATE ci_artifact SET name='binary'")
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO ci_artifact(id,run_id,job_id,name,sink,digest,size_bytes,uri)
            SELECT 'duplicate',run_id,job_id,name,sink,digest,size_bytes,uri FROM ci_artifact WHERE id=$1")
            .bind(runs[0].get::<&str,_>("run_id")).execute(store.pool()).await.unwrap();
        assert!(
            collect(&store, &build)
                .await
                .unwrap_err()
                .to_string()
                .contains("exactly one")
        );
        sqlx::query("DELETE FROM ci_artifact WHERE id='duplicate'")
            .execute(store.pool())
            .await
            .unwrap();
        let manifest = collect(&store, &build).await.unwrap().unwrap();
        assert_eq!(manifest["components"]["api"]["sha256"], "d".repeat(64));
        assert_eq!(manifest["components"]["worker"]["size_bytes"], 59);
        assert!(
            finalize(&store, &Retention { fail: true }, &build, manifest.clone())
                .await
                .is_err()
        );
        assert!(
            crate::release_catalog::list(&store, None)
                .await
                .unwrap()
                .is_empty()
        );
        let (a, b) = tokio::join!(
            finalize(&store, &Retention { fail: false }, &build, manifest.clone()),
            finalize(&store, &Retention { fail: false }, &build, manifest)
        );
        a.unwrap();
        b.unwrap();
        let catalog = crate::release_catalog::list(&store, None).await.unwrap();
        assert!(catalog.is_empty(), "historical multi-service builds must not be deployable candidates");
        let retained: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(b) FROM ci_release_bundle b")
            .fetch_all(store.pool()).await.unwrap();
        assert_eq!(retained.len(), 1, "concurrent completion must retain one historical record");
        assert_eq!(
            retained[0]["manifest"]["components"]["api"]["uri"],
            format!("retained-{}", "d".repeat(64))
        );
        assert_eq!(retained[0]["manifest"]["retained"], true);
        assert!(retained[0]["publication_run_id"].is_null());
        assert_eq!(
            existing(&store, "repo", "daily", None)
                .await
                .unwrap()
                .unwrap()["status"],
            "ready"
        );
        assert!(
            sqlx::query("DELETE FROM ci_artifact")
                .execute(store.pool())
                .await
                .is_err()
        );
        // A successful run label alone must not disguise a different source.
        sqlx::query("UPDATE ci_run SET sha='wrong'")
            .execute(store.pool())
            .await
            .unwrap();
        assert!(
            collect(&store, &build)
                .await
                .unwrap_err()
                .to_string()
                .contains("revision")
        );
        sqlx::query("UPDATE ci_run SET sha=$1,status='failure'")
            .bind("a".repeat(40))
            .execute(store.pool())
            .await
            .unwrap();
        assert!(
            collect(&store, &build)
                .await
                .unwrap_err()
                .to_string()
                .contains("failed")
        );
    }
}
