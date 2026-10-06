//! Durable admission and validation gate for multi-workflow submissions.
//!
//! Membership is written in the same transaction as the runs.  There is no
//! mutable coordinator state here: every gate check reconstructs its answer
//! from the frozen membership and persisted run/job/step evidence.

use crate::plan::{JobPlan, Plan};
use crate::store::Store;
use serde_json::Value;
use sqlx::Row;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    Unmanaged,
    Waiting,
    Ready,
    Rejected(String),
}

pub fn validate_validation_plan(plan: &Plan) -> Result<(), String> {
    for job in &plan.jobs {
        if job.continue_on_error || job.steps.iter().any(|s| s.continue_on_error) {
            return Err(format!("{}: release validation may not tolerate errors", plan.workflow_path));
        }
        if job.steps.iter().any(|s| matches!(s.uses.as_deref(),
            Some("ci/merge-release" | "ci/checkout-release" | "ci/deploy-service" |
                 "ci/deploy-app-lb" | "ci/deploy-controller" | "ci/host-heyvm-maintenance" | "ci/bootstrap-host-heyvm" | "ci/rollout-host-heyvmd" | "ci/rollout-service" | "ci/rollout-host-app-lb" | "ci/rollout-pooler" | "ci/rollout-site" | "ci/rollout-stateful-service"))) {
            return Err(format!("{}: move publication/deployment into the on: release workflow", plan.workflow_path));
        }
    }
    Ok(())
}

/// Exactly one unconditional merge, with every other job depending on it.
/// The validated source cannot be rewritten by post-validation version bumps.
pub fn validate_release_plan(plan: &Plan) -> Result<(), String> {
    let merges: Vec<_> = plan.jobs.iter().flat_map(|job| job.steps.iter()
        .filter(|step| step.uses.as_deref() == Some("ci/merge-release"))
        .map(move |step| (job, step))).collect();
    let [(merge, step)] = merges.as_slice() else {
        return Err("release workflow requires exactly one ci/merge-release step".into());
    };
    if merge.condition.is_some() || step.condition.is_some() || !merge.needs.is_empty()
        || merge.steps.len() != 1
        || step.with.get("manifests").and_then(|v| serde_json::from_str::<Vec<String>>(v).ok()) != Some(vec![])
        || step.with.contains_key("tags")
    {
        return Err("submission merge must be its job's only step, unconditional, with no needs, manifests: '[]', and no tags".into());
    }
    let mut after_merge = HashSet::from([merge.base_id.as_str()]);
    for job in &plan.jobs {
        if job.continue_on_error || job.steps.iter().any(|s| s.continue_on_error) {
            return Err("release jobs may not tolerate errors".into());
        }
        if job.key != merge.key {
            if !job.needs.iter().any(|n| after_merge.contains(n.as_str())) {
                return Err(format!("release job {:?} must depend on the merge", job.base_id));
            }
            after_merge.insert(job.base_id.as_str());
        }
        if let Some(index) = job.steps.iter().position(|s| s.uses.as_deref() == Some("ci/deploy-controller")) {
            let mut ancestors = HashSet::new();
            let mut pending = job.needs.clone();
            while let Some(id) = pending.pop() {
                if ancestors.insert(id.clone()) {
                    for ancestor in plan.jobs.iter().filter(|j| j.base_id == id) {
                        pending.extend(ancestor.needs.iter().cloned());
                    }
                }
            }
            if index + 1 != job.steps.len() || plan.jobs.iter()
                .any(|j| j.key != job.key && !ancestors.contains(&j.base_id)) {
                return Err("controller replacement must be the last step and depend on all other release jobs".into());
            }
        }
    }
    Ok(())
}

/// Freeze submission membership.  The caller owns the transaction so run
/// creation and admission become visible (or roll back) together.
pub async fn record(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    release_run_id: &str,
    validation_run_ids: &[String],
) -> Result<(), String> {
    if validation_run_ids.is_empty() {
        return Err("submission requires at least one validation run".into());
    }
    let mut unique = HashSet::with_capacity(validation_run_ids.len());
    for id in validation_run_ids {
        if id == release_run_id {
            return Err("release run cannot validate itself".into());
        }
        if !unique.insert(id.as_str()) {
            return Err(format!("duplicate validation run {id:?}"));
        }
    }
    let count = i32::try_from(validation_run_ids.len())
        .map_err(|_| "too many validation runs".to_string())?;
    sqlx::query("INSERT INTO ci_submission(release_run_id,validation_count) VALUES($1,$2)")
        .bind(release_run_id)
        .bind(count)
        .execute(&mut **tx)
        .await
        .map_err(|e| format!("record submission: {e}"))?;
    for (ordinal, id) in validation_run_ids.iter().enumerate() {
        sqlx::query("INSERT INTO ci_submission_validation(release_run_id,validation_run_id,ordinal) VALUES($1,$2,$3)")
            .bind(release_run_id)
            .bind(id)
            .bind(ordinal as i32)
            .execute(&mut **tx)
            .await
            .map_err(|e| format!("record validation membership: {e}"))?;
    }
    Ok(())
}

pub async fn is_member(store: &Store, run_id: &str) -> Result<bool, String> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ci_submission_validation WHERE validation_run_id=$1)",
    )
    .bind(run_id)
    .fetch_one(store.pool())
    .await
    .map_err(|e| format!("read submission membership: {e}"))
}

pub async fn authorize_publication(store: &Store, run_id: &str) -> Result<(), String> {
    let blocked: bool = sqlx::query_scalar(
        "SELECT validation_only OR EXISTS(SELECT 1 FROM ci_submission_validation WHERE validation_run_id=$1)
         FROM ci_run WHERE id=$1",
    ).bind(run_id).fetch_one(store.pool()).await.map_err(|e| e.to_string())?;
    if blocked {
        return Err("validation-only runs cannot merge or deploy; submit the complete revision".into());
    }
    Ok(())
}

pub async fn validations(store: &Store, release_run_id: &str) -> Result<Vec<String>, String> {
    sqlx::query_scalar("SELECT validation_run_id FROM ci_submission_validation WHERE release_run_id=$1 ORDER BY ordinal")
        .bind(release_run_id)
        .fetch_all(store.pool())
        .await
        .map_err(|e| format!("read submission validations: {e}"))
}

#[derive(Debug)]
struct EvidenceJob {
    status: String,
    carried: bool,
    plan: JobPlan,
    steps: Vec<(i32, String)>,
}

fn strict_validation(jobs: &[EvidenceJob]) -> Result<(), String> {
    if jobs.is_empty() {
        return Err("validation has no jobs".into());
    }
    for job in jobs {
        if job.status == "skipped" {
            return Err(format!("validation job {:?} was skipped", job.plan.base_id));
        }
        if job.status != "success" {
            return Err(format!(
                "validation job {:?} did not succeed",
                job.plan.base_id
            ));
        }
        if job.carried {
            return Err(format!(
                "validation job {:?} was carried from another run",
                job.plan.base_id
            ));
        }
        if job.plan.continue_on_error || job.plan.steps.iter().any(|s| s.continue_on_error) {
            return Err(format!(
                "validation job {:?} tolerates errors",
                job.plan.base_id
            ));
        }
        if job.plan.steps.is_empty() {
            return Err(format!(
                "validation job {:?} has no planned steps",
                job.plan.base_id
            ));
        }
        if job.steps.len() != job.plan.steps.len()
            || job
                .steps
                .iter()
                .enumerate()
                .any(|(expected, (idx, status))| {
                    *idx < 0 || *idx != expected as i32 || status != "success"
                })
        {
            return Err(format!(
                "validation job {:?} lacks complete contiguous successful step evidence",
                job.plan.base_id
            ));
        }
    }
    Ok(())
}

async fn evidence(store: &Store, run_id: &str) -> Result<Vec<EvidenceJob>, String> {
    let rows = sqlx::query(
        "SELECT j.status,j.carried_from IS NOT NULL AS carried,j.plan,
                COALESCE(jsonb_agg(jsonb_build_array(s.idx,s.status) ORDER BY s.idx)
                         FILTER (WHERE s.id IS NOT NULL AND s.idx >= 0),'[]'::jsonb) AS steps
           FROM ci_job j LEFT JOIN ci_step s ON s.job_id=j.id
          WHERE j.run_id=$1 GROUP BY j.id ORDER BY j.created_at,j.id",
    )
    .bind(run_id)
    .fetch_all(store.pool())
    .await
    .map_err(|e| format!("read validation evidence: {e}"))?;
    rows.into_iter()
        .map(|row| {
            Ok(EvidenceJob {
                status: row.get("status"),
                carried: row.get("carried"),
                plan: serde_json::from_value(row.get("plan"))
                    .map_err(|e| format!("decode validation job plan: {e}"))?,
                steps: serde_json::from_value(row.get("steps"))
                    .map_err(|e| format!("decode validation steps: {e}"))?,
            })
        })
        .collect()
}

pub async fn gate(store: &Store, release_run_id: &str) -> Result<Gate, String> {
    let submission = sqlx::query(
        "SELECT s.validation_count,r.repo_url,r.repo_id,r.git_ref,r.default_branch,r.sha,r.release_base_sha,r.changes
           FROM ci_submission s JOIN ci_run r ON r.id=s.release_run_id
          WHERE s.release_run_id=$1",
    )
    .bind(release_run_id)
    .fetch_optional(store.pool())
    .await
    .map_err(|e| format!("read submission: {e}"))?;
    let Some(release) = submission else {
        return Ok(Gate::Unmanaged);
    };
    let expected: i32 = release.get("validation_count");
    let repo: String = release.get("repo_url");
    let repo_id: Option<String> = release.get("repo_id");
    let git_ref: String = release.get("git_ref");
    let default_branch: Option<String> = release.get("default_branch");
    let source: String = release.get("sha");
    let target: Option<String> = release.get("release_base_sha");
    let changes: Value = release.get("changes");
    let members = sqlx::query(
        "SELECT r.id,r.status,r.repo_url,r.repo_id,r.git_ref,r.default_branch,r.sha,r.release_base_sha,r.changes
           FROM ci_submission_validation m JOIN ci_run r ON r.id=m.validation_run_id
          WHERE m.release_run_id=$1 ORDER BY m.ordinal",
    )
    .bind(release_run_id)
    .fetch_all(store.pool())
    .await
    .map_err(|e| format!("read frozen submission membership: {e}"))?;
    if members.len() != expected as usize {
        return Ok(Gate::Rejected(format!(
            "submission membership is incomplete: expected {expected}, found {}",
            members.len()
        )));
    }

    let mut waiting = false;
    for member in members {
        let id: String = member.get("id");
        if member.get::<String, _>("repo_url") != repo
            || member.get::<Option<String>, _>("repo_id") != repo_id
            || member.get::<String, _>("git_ref") != git_ref
            || member.get::<Option<String>, _>("default_branch") != default_branch
            || member.get::<String, _>("sha") != source
            || member.get::<Option<String>, _>("release_base_sha") != target
            || member.get::<Value, _>("changes") != changes
        {
            return Ok(Gate::Rejected(format!(
                "validation run {id} does not match the release source identity"
            )));
        }
        let status: String = member.get("status");
        let jobs = evidence(store, &id).await?;
        if jobs
            .iter()
            .any(|j| matches!(j.status.as_str(), "failure" | "cancelled" | "skipped"))
        {
            let reason = strict_validation(&jobs)
                .err()
                .unwrap_or_else(|| "validation contains failed evidence".to_string());
            return Ok(Gate::Rejected(reason));
        }
        match status.as_str() {
            "queued" | "running" => {
                // Policy violations are already knowable and must not wait for
                // a misleading successful rollup.
                if let Some(job) = jobs.iter().find(|j| {
                    j.carried
                        || j.plan.continue_on_error
                        || j.plan.steps.iter().any(|s| s.continue_on_error)
                }) {
                    return Ok(Gate::Rejected(format!(
                        "validation job {:?} is not strict fresh evidence",
                        job.plan.base_id
                    )));
                }
                waiting = true;
            }
            "success" => {
                if let Err(reason) = strict_validation(&jobs) {
                    return Ok(Gate::Rejected(reason));
                }
            }
            "failure" | "cancelled" => {
                return Ok(Gate::Rejected(format!(
                    "validation run {id} ended {status}"
                )));
            }
            other => {
                return Ok(Gate::Rejected(format!(
                    "validation run {id} has unknown status {other:?}"
                )));
            }
        }
    }
    Ok(if waiting { Gate::Waiting } else { Gate::Ready })
}

/// Select the one frozen validation run that produced a workflow's artifacts.
pub async fn artifact_run(
    store: &Store,
    release_run_id: &str,
    workflow_path: &str,
) -> Result<String, String> {
    match gate(store, release_run_id).await? {
        Gate::Ready => {}
        Gate::Unmanaged => return Err("release run is not an admitted submission".into()),
        Gate::Waiting => return Err("submission validations are not complete".into()),
        Gate::Rejected(reason) => return Err(format!("submission validation rejected: {reason}")),
    }
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT r.id FROM ci_submission_validation m JOIN ci_run r ON r.id=m.validation_run_id
          WHERE m.release_run_id=$1 AND r.workflow_path=$2 ORDER BY m.ordinal",
    )
    .bind(release_run_id)
    .bind(workflow_path)
    .fetch_all(store.pool())
    .await
    .map_err(|e| format!("resolve submission artifact run: {e}"))?;
    match rows.as_slice() {
        [id] => Ok(id.clone()),
        [] => Err(format!(
            "workflow {workflow_path:?} is not in the frozen submission"
        )),
        _ => Err(format!(
            "workflow {workflow_path:?} is ambiguous in the frozen submission"
        )),
    }
}

/// Resolve immutable artifact provenance, never a caller-supplied run or URL.
pub async fn artifact(
    store: &Store, release_run_id: &str, workflow: &str, name: &str,
    producer: Option<&str>,
) -> Result<crate::artifacts::StoredArtifact, String> {
    if let Some(bundle) = crate::release_environment::bundle_for_run(store, release_run_id).await.map_err(|e| e.to_string())? {
        return crate::release_environment::artifact(&bundle["manifest"], workflow, name, producer).map_err(|e| e.to_string());
    }
    let run = artifact_run(store, release_run_id, workflow).await?;
    let rows = sqlx::query(
        "SELECT a.* FROM ci_artifact a JOIN ci_job j ON j.id=a.job_id
         WHERE a.run_id=$1 AND a.name=$2 AND j.status='success'
           AND ($3::text IS NULL OR j.job_key=$3)",
    ).bind(&run).bind(name).bind(producer).fetch_all(store.pool()).await
        .map_err(|e| format!("read validated artifact: {e}"))?;
    let [row] = rows.as_slice() else {
        return Err(format!("validated artifact {workflow}:{name} is missing or ambiguous"));
    };
    let digest: String = row.get::<Option<String>, _>("digest")
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("validated artifact has no SHA256 digest")?;
    let size: i64 = row.get("size_bytes");
    if size <= 0 { return Err("validated artifact is empty".into()); }
    Ok(crate::artifacts::StoredArtifact {
        sink: match row.get::<String, _>("sink").as_str() {
            "disk" => "disk", "s3" => "s3", "artifacts" => "artifacts",
            _ => return Err("validated artifact uses an unknown sink".into()),
        },
        digest: Some(digest), size_bytes: size as u64,
        uri: row.get("uri"), public_url: row.get("public_url"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release_plan() -> Plan {
        let workflow = crate::workflow::Workflow::parse("release.yml", r#"
on: release
jobs:
  merge:
    vm: {driver: firecracker}
    steps:
      - uses: ci/merge-release
        with: {manifests: '[]', token: '${{ secrets.GIT_AUTH_TOKEN }}'}
  us3:
    needs: [merge]
    vm: {driver: firecracker}
    steps: [{uses: ci/deploy-service}]
  eu1:
    needs: [us3]
    vm: {driver: firecracker}
    steps: [{uses: ci/deploy-service}]
  controller:
    needs: [eu1]
    vm: {driver: firecracker}
    steps: [{uses: ci/deploy-controller}]
"#).unwrap();
        Plan::build(&workflow).unwrap()
    }

    #[test]
    fn release_policy_requires_a_single_exact_merge_and_controller_last() {
        let plan = release_plan();
        assert!(validate_release_plan(&plan).is_ok());
        assert!(validate_validation_plan(&plan).is_err());
        let rollout = crate::workflow::Workflow::parse("rollout.yml", "jobs:\n  deploy:\n    steps: [{uses: ci/rollout-service}]\n").unwrap();
        assert!(validate_validation_plan(&Plan::build(&rollout).unwrap()).is_err());
        let mut conditional = plan.clone();
        conditional.jobs[0].condition = Some("false".into());
        assert!(validate_release_plan(&conditional).is_err());
        let mut bump = plan.clone();
        bump.jobs[0].steps[0].with.insert("manifests".into(), "[\"Cargo.toml\"]".into());
        assert!(validate_release_plan(&bump).is_err());
        let mut parallel = plan.clone();
        parallel.jobs[3].needs = vec!["merge".into()];
        assert!(validate_release_plan(&parallel).is_err());
        let mut ungated = plan.clone();
        ungated.jobs[1].needs.clear();
        assert!(validate_release_plan(&ungated).is_err());
        let mut duplicate = plan.clone();
        duplicate.jobs[0].steps.push(plan.jobs[0].steps[0].clone());
        assert!(validate_release_plan(&duplicate).is_err());
        let filtered = "on:\n  release:\n    paths: ['ci/**']\njobs:\n  build:\n    vm: {driver: firecracker}\n    steps: [{run: 'true'}]";
        assert!(crate::workflow::Workflow::parse("release.yml", filtered).is_err());
    }

    fn job(status: &str, steps: &[(i32, &str)]) -> EvidenceJob {
        let workflow = crate::workflow::Workflow::parse("validate.yml", "jobs:\n  check:\n    vm: { driver: firecracker }\n    steps:\n      - run: cargo test\n      - run: cargo check\n").unwrap();
        EvidenceJob {
            status: status.into(),
            carried: false,
            plan: crate::plan::Plan::build(&workflow).unwrap().jobs.remove(0),
            steps: steps.iter().map(|(i, s)| (*i, (*s).into())).collect(),
        }
    }

    #[test]
    fn strict_evidence_requires_fresh_contiguous_unskipped_success() {
        assert!(strict_validation(&[job("success", &[(0, "success"), (1, "success")])]).is_ok());
        assert!(strict_validation(&[]).is_err());
        for bad in [
            job("failure", &[(0, "success"), (1, "success")]),
            job("skipped", &[(0, "success"), (1, "success")]),
            job("success", &[(0, "success")]),
            job("success", &[(0, "success"), (2, "success")]),
            job("success", &[(-1, "success"), (0, "success")]),
            job("success", &[(0, "success"), (1, "skipped")]),
        ] {
            assert!(strict_validation(&[bad]).is_err());
        }
        let mut carried = job("success", &[(0, "success"), (1, "success")]);
        carried.carried = true;
        assert!(strict_validation(&[carried]).is_err());
        let mut tolerant = job("success", &[(0, "success"), (1, "success")]);
        tolerant.plan.continue_on_error = true;
        assert!(strict_validation(&[tolerant]).is_err());
    }

    async fn fixture() -> (Store, String, tempfile::TempDir) {
        let base = std::env::var("CI_TEST_DATABASE_URL").expect("disposable CI_TEST_DATABASE_URL");
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        let schema = format!("submission_{}", uuid::Uuid::new_v4().simple());
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
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();
        store.migrate().await.unwrap();
        (store, url.into(), dir)
    }

    async fn add_run(store: &Store, id: &str, path: &str, status: &str) {
        sqlx::query("INSERT INTO ci_run(id,workflow_id,workflow_path,repo_url,sha,release_base_sha,changes,status) VALUES($1,$2,$2,'repo','source','base','{\"kind\":\"known\",\"paths\":[\"x\"]}'::jsonb,$3)")
            .bind(id).bind(path).bind(status).execute(store.pool()).await.unwrap();
        let plan = job("success", &[]).plan;
        sqlx::query("INSERT INTO ci_job(id,run_id,job_key,base_id,display,status,plan) VALUES($1,$2,'check','check','check',$3,$4)")
            .bind(format!("{id}.check")).bind(id).bind(if status == "success" { "success" } else { "pending" })
            .bind(serde_json::to_value(plan).unwrap()).execute(store.pool()).await.unwrap();
        if status == "success" {
            for idx in 0..2 {
                sqlx::query("INSERT INTO ci_step(id,job_id,idx,name,status) VALUES($1,$2,$3,'step','success')")
                    .bind(format!("{id}.check.{idx}")).bind(format!("{id}.check")).bind(idx)
                    .execute(store.pool()).await.unwrap();
            }
        }
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL"]
    async fn frozen_gate_handles_reverse_completion_restart_and_artifact_scope() {
        let (store, url, dir) = fixture().await;
        add_run(&store, "release", "release.yml", "running").await;
        add_run(&store, "a", "a.yml", "running").await;
        add_run(&store, "b", "b.yml", "success").await;
        let mut tx = store.pool().begin().await.unwrap();
        record(&mut tx, "release", &["a".into(), "b".into()])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(validations(&store, "release").await.unwrap(), ["a", "b"]);
        assert!(is_member(&store, "a").await.unwrap());
        assert_eq!(gate(&store, "release").await.unwrap(), Gate::Waiting);
        sqlx::raw_sql("UPDATE ci_run SET status='success' WHERE id='a'; UPDATE ci_job SET status='success' WHERE run_id='a'").execute(store.pool()).await.unwrap();
        for idx in 0..2 {
            sqlx::query("INSERT INTO ci_step(id,job_id,idx,name,status) VALUES($1,'a.check',$2,'step','success')").bind(format!("a.check.{idx}")).bind(idx).execute(store.pool()).await.unwrap();
        }
        drop(store);
        let restarted = Store::connect(
            &url,
            dir.path().join("restart"),
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(gate(&restarted, "release").await.unwrap(), Gate::Ready);
        assert_eq!(
            artifact_run(&restarted, "release", "a.yml").await.unwrap(),
            "a"
        );
        assert!(
            artifact_run(&restarted, "release", "release.yml")
                .await
                .is_err()
        );
        sqlx::query("UPDATE ci_run SET workflow_path='a.yml' WHERE id='b'")
            .execute(restarted.pool())
            .await
            .unwrap();
        assert!(
            artifact_run(&restarted, "release", "a.yml")
                .await
                .unwrap_err()
                .contains("ambiguous")
        );
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL"]
    async fn publication_and_artifacts_are_scoped_to_complete_submissions() {
        let (store, _, _dir) = fixture().await;
        add_run(&store, "release", "release.yml", "running").await;
        add_run(&store, "validation", "auth.yml", "success").await;
        add_run(&store, "unrelated", "auth.yml", "success").await;
        let mut tx = store.pool().begin().await.unwrap();
        record(&mut tx, "release", &["validation".into()]).await.unwrap();
        tx.commit().await.unwrap();

        assert!(authorize_publication(&store, "release").await.is_ok());
        assert!(authorize_publication(&store, "validation").await.is_err());
        assert!(authorize_publication(&store, "unrelated").await.is_ok());
        sqlx::query("UPDATE ci_run SET validation_only=true WHERE id='unrelated'")
            .execute(store.pool()).await.unwrap();
        assert!(authorize_publication(&store, "unrelated").await.is_err());
        assert!(authorize_publication(&store, "missing").await.is_err());

        for run in ["validation", "unrelated"] {
            sqlx::query("INSERT INTO ci_artifact(id,run_id,job_id,name,sink,digest,size_bytes,uri) VALUES($1,$1,$2,'auth','disk',$3,17,$4)")
                .bind(run).bind(format!("{run}.check")).bind("a".repeat(64))
                .bind(format!("/{run}/auth.tar.gz")).execute(store.pool()).await.unwrap();
        }
        let selected = artifact(&store, "release", "auth.yml", "auth", Some("check")).await.unwrap();
        assert_eq!(selected.uri, "/validation/auth.tar.gz");
        assert_eq!(selected.digest.as_deref(), Some("a".repeat(64).as_str()));
        assert!(artifact(&store, "release", "auth.yml", "auth", Some("other")).await.is_err());
        assert!(artifact(&store, "release", "cloud.yml", "auth", None).await.is_err());
        sqlx::query("UPDATE ci_artifact SET digest=NULL WHERE id='validation'")
            .execute(store.pool()).await.unwrap();
        assert!(artifact(&store, "release", "auth.yml", "auth", None).await.unwrap_err().contains("SHA256"));
        sqlx::query("UPDATE ci_artifact SET digest=$1 WHERE id='validation'")
            .bind("b".repeat(64)).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO ci_artifact(id,run_id,job_id,name,sink,digest,size_bytes,uri) SELECT 'duplicate',run_id,job_id,name,sink,digest,size_bytes,uri FROM ci_artifact WHERE id='validation'")
            .execute(store.pool()).await.unwrap();
        assert!(artifact(&store, "release", "auth.yml", "auth", None).await.unwrap_err().contains("ambiguous"));
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL"]
    async fn release_catalog_pins_provenance_and_rejects_replacement() {
        use crate::release_catalog::{self, Request, Selection};
        let (store, _, _dir) = fixture().await;
        add_run(&store, "release", "release.yml", "success").await;
        add_run(&store, "build", "cloud.yml", "success").await;
        add_run(&store, "unrelated", "cloud.yml", "success").await;
        let mut tx = store.pool().begin().await.unwrap();
        record(&mut tx, "release", &["build".into()]).await.unwrap();
        tx.commit().await.unwrap();
        for (id, digest) in [("build", "a"), ("unrelated", "b")] {
            sqlx::query("INSERT INTO ci_artifact(id,run_id,job_id,name,sink,digest,size_bytes,uri)
                VALUES($1,$1,$2,'cloud','s3',$3,37,$4)")
                .bind(id).bind(format!("{id}.check")).bind(digest.repeat(64))
                .bind(format!("s3://builds/{id}/cloud")).execute(store.pool()).await.unwrap();
        }
        let request = Request { name: "daily-1".into(), publication_run_id: "release".into(),
            components: std::collections::BTreeMap::from([("cloud".into(), Selection {
                workflow: "cloud.yml".into(), artifact: "cloud".into(), job: "check".into(),
            })]) };
        assert!(release_catalog::register(&store, request.clone(), "admin").await.is_err());
        sqlx::query("INSERT INTO ci_release(run_id,request_hash,source_sha,base_sha,git_ref,versions,candidate_sha,prepared,status)
            VALUES('release','hash','source','base','refs/heads/main','{}','source','{}','published')")
            .execute(store.pool()).await.unwrap();
        let (a,b) = tokio::join!(release_catalog::register(&store, request.clone(), "admin-a"),
            release_catalog::register(&store, request.clone(), "admin-b"));
        let a = a.unwrap();
        assert_eq!(a, b.unwrap());
        assert_eq!(a["manifest"]["components"]["cloud"]["sha256"], "a".repeat(64));
        assert_eq!(a["manifest"]["components"]["cloud"]["run_id"], "build");
        assert_eq!(release_catalog::list(&store, None).await.unwrap().len(), 1);
        assert!(sqlx::query("DELETE FROM ci_artifact WHERE id='build'").execute(store.pool()).await.is_err());
        sqlx::query("UPDATE ci_artifact SET digest=$1 WHERE id='build'").bind("c".repeat(64))
            .execute(store.pool()).await.unwrap();
        assert!(release_catalog::register(&store, request.clone(), "admin").await.unwrap_err()
            .to_string().contains("different immutable contents"));
        let saved = release_catalog::list(&store, None).await.unwrap();
        assert_eq!(saved[0]["manifest"]["components"]["cloud"]["sha256"], "a".repeat(64));
        sqlx::query("UPDATE ci_artifact SET sink='disk' WHERE id='build'").execute(store.pool()).await.unwrap();
        let mut other = request.clone(); other.name = "daily-2".into();
        assert!(release_catalog::register(&store, other, "admin").await.unwrap_err().to_string().contains("shared storage"));
        sqlx::query("UPDATE ci_job SET status='failure' WHERE run_id='build'").execute(store.pool()).await.unwrap();
        assert!(release_catalog::register(&store, request, "admin").await.is_err());
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL"]
    async fn admission_is_atomic_and_bad_persisted_evidence_is_rejected() {
        let (store, _, _dir) = fixture().await;
        add_run(&store, "release", "release.yml", "running").await;
        add_run(&store, "good", "good.yml", "success").await;
        let mut empty = store.pool().begin().await.unwrap();
        assert!(record(&mut empty, "release", &[]).await.is_err());
        empty.rollback().await.unwrap();
        let mut duplicate = store.pool().begin().await.unwrap();
        assert!(
            record(&mut duplicate, "release", &["good".into(), "good".into()])
                .await
                .is_err()
        );
        duplicate.rollback().await.unwrap();
        let mut rolled = store.pool().begin().await.unwrap();
        record(&mut rolled, "release", &["good".into()])
            .await
            .unwrap();
        rolled.rollback().await.unwrap();
        assert_eq!(gate(&store, "release").await.unwrap(), Gate::Unmanaged);
        let mut tx = store.pool().begin().await.unwrap();
        record(&mut tx, "release", &["good".into()]).await.unwrap();
        tx.commit().await.unwrap();
        sqlx::query("UPDATE ci_job SET carried_from='old' WHERE run_id='good'")
            .execute(store.pool())
            .await
            .unwrap();
        assert!(
            matches!(gate(&store,"release").await.unwrap(),Gate::Rejected(r) if r.contains("carried"))
        );
        sqlx::raw_sql(
            "UPDATE ci_job SET carried_from=NULL; DELETE FROM ci_step WHERE job_id='good.check'",
        )
        .execute(store.pool())
        .await
        .unwrap();
        assert!(
            matches!(gate(&store,"release").await.unwrap(),Gate::Rejected(r) if r.contains("evidence"))
        );
        sqlx::query("UPDATE ci_run SET repo_url='other' WHERE id='good'")
            .execute(store.pool())
            .await
            .unwrap();
        assert!(
            matches!(gate(&store,"release").await.unwrap(),Gate::Rejected(r) if r.contains("source identity"))
        );
    }
}
