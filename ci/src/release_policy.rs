//! Operator-owned release instructions compiled into the existing persisted DAG.
//! This is admission-time configuration, not another coordinator or CI lock.
use crate::{dispatch::Dispatcher, host_maintenance, host_heyvm_bootstrap_coordinator, plan::Plan, service_rollout, workflow::Workflow};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionMode {
    #[default]
    MergeAndDeploy,
    MergeOnly,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub workflow_path: String,
    pub workflow: String,
    /// Opt-in separation of submission publication from environment deployment.
    #[serde(default)]
    pub submission_mode: SubmissionMode,
    #[serde(default)]
    pub service_targets: BTreeMap<String, service_rollout::Target>,
    #[serde(default)]
    pub pooler_targets: BTreeMap<String, crate::pooler_rollout::Target>,
    #[serde(default)]
    pub site_targets: BTreeMap<String, crate::site_rollout::Target>,
    #[serde(default)]
    pub stateful_targets: BTreeMap<String, crate::stateful_rollout::Target>,
    /// Job ID -> existing maintenance target alias of its coordinator host.
    #[serde(default)]
    pub placements: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Snapshot {
    pub digest: String,
    pub maintenance: BTreeMap<String, host_maintenance::Target>,
    pub hosts: BTreeMap<String, host_heyvm_bootstrap_coordinator::Target>,
    #[serde(default)]
    pub app_lbs: BTreeMap<String, crate::host_app_lb::Target>,
    /// Expressions only; credential values are never persisted here.
    pub token_expressions: Vec<String>,
}

pub fn select(raw: Option<&str>, repository: &str) -> Result<Option<Policy>> {
    let Some(raw) = raw else { return Ok(None) };
    let policies: BTreeMap<String, Policy> = serde_yaml::from_str(raw)?;
    let mut selected = None;
    for (repo, policy) in policies {
        if crate::repos::same_repo(&repo, repository) {
            ensure!(selected.is_none(), "multiple release policies match this repository");
            let workflow = Workflow::parse(&policy.workflow_path, &policy.workflow)?;
            ensure!(workflow.on == ["release"], "operator policy must use only on: release");
            ensure!(!policy.workflow_path.trim().is_empty(), "operator policy needs a workflow path");
            crate::submission::validate_release_plan(&Plan::build(&workflow)?).map_err(anyhow::Error::msg)?;
            selected = Some(policy);
        }
    }
    Ok(selected)
}

/// Ignore candidate release YAML even if it was renamed or deleted. Inject the
/// operator workflow exactly once across all registered workflow globs.
pub fn workflows(files: Vec<(String, String)>, policy: &Policy, inject: bool) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (path, text) in files {
        if path == policy.workflow_path { continue; }
        if Workflow::parse(&path, &text)?.on.iter().any(|on| on == "release") { continue; }
        out.push((path, text));
    }
    if inject { out.push((policy.workflow_path.clone(), policy.workflow.clone())); }
    Ok(out)
}

fn input(step: &crate::workflow::Step, key: &str) -> Result<String> {
    step.with.get(key).filter(|s| !s.trim().is_empty() && !s.contains("${{"))
        .cloned().ok_or_else(|| anyhow::anyhow!("operator release action requires a literal with.{key}"))
}

fn exclusive(step: &crate::workflow::Step, keys: &[&str]) -> Result<()> {
    ensure!(keys.iter().all(|key| !step.with.contains_key(*key)),
        "operator release actions must use target aliases, not duplicated infrastructure fields");
    Ok(())
}

pub async fn prepare(d: &Dispatcher, repository: &str, policy: &Policy) -> Result<Plan> {
    let plan = submission_plan(policy)?;
    let plan = prepare_plan(d, repository, policy, plan).await?;
    crate::submission::validate_release_plan(&plan).map_err(anyhow::Error::msg)?;
    Ok(plan)
}

/// Resolve the same operator targets for either submission or promotion jobs.
/// The caller validates its own lifecycle (merge-first vs retained-bundle).
pub(crate) async fn prepare_plan(d: &Dispatcher, repository: &str, policy: &Policy, mut plan: Plan) -> Result<Plan> {
    let mut effective = policy.clone();
    effective.placements.retain(|id, _| plan.jobs.iter().any(|job| &job.base_id == id));
    let mut snapshot = Snapshot { digest: String::new(), maintenance: BTreeMap::new(), hosts: BTreeMap::new(), app_lbs: BTreeMap::new(), token_expressions: Vec::new() };
    let mut aliases: Vec<String> = effective.placements.values().cloned().collect();
    for job in &plan.jobs {
        for step in &job.steps {
            if let Some(token) = step.with.get("token") {
                ensure!(token.starts_with("${{ secrets.") && token.ends_with(" }}"), "operator release tokens must be secret expressions");
                if !snapshot.token_expressions.contains(token) { snapshot.token_expressions.push(token.clone()); }
            }
            match step.uses.as_deref() {
                Some("ci/rollout-host-app-lb") => {
                    let alias = input(step, "target")?;
                    let target = crate::host_app_lb::trusted(d, &alias).await?;
                    ensure!(crate::repos::same_repo(repository, &target.repository), "app-lb target is not authorized for this repository");
                    snapshot.app_lbs.insert(alias, target);
                }
                Some("ci/host-heyvm-maintenance" | "ci/promote-service-archive") => aliases.push(input(step, "target")?),
                Some("ci/bootstrap-host-heyvm" | "ci/rollout-host-heyvmd") => {
                    let alias = input(step, "target")?;
                    ensure!(d.config.heyvm.local_runner.is_none(), "host rollout requires a real runner tunnel");
                    if !snapshot.hosts.contains_key(&alias) {
                        snapshot.hosts.insert(alias.clone(), host_heyvm_bootstrap_coordinator::trusted(d, &alias).await?);
                    }
                }
                _ => {}
            }
        }
    }
    for alias in aliases {
        if !snapshot.maintenance.contains_key(&alias) {
            let target = host_maintenance::trusted_target(d, &alias).await?;
            ensure!(crate::repos::same_repo(repository, &target.repository), "maintenance target is not authorized for this repository");
            snapshot.maintenance.insert(alias, target);
        }
    }
    bind(&mut plan, repository, &effective, &snapshot)?;
    snapshot.digest = hex::encode(Sha256::digest(serde_json::to_vec(&(policy, &snapshot))?));
    for job in &mut plan.jobs { job.release_policy = Some(snapshot.clone()); }
    Ok(plan)
}

fn submission_plan(policy: &Policy) -> Result<Plan> {
    let mut plan = Plan::build(&Workflow::parse(&policy.workflow_path, &policy.workflow)?)?;
    crate::submission::validate_release_plan(&plan).map_err(anyhow::Error::msg)?;
    // Validate placements before filtering so typos still fail admission.
    ensure!(policy.placements.keys().all(|id| plan.jobs.iter().any(|j| &j.base_id == id)),
        "release placement names an unknown job");
    if policy.submission_mode == SubmissionMode::MergeOnly {
        // validate_release_plan proves this is one unconditional, single-step
        // job. Existing submission membership still gates its publication.
        plan.jobs.retain(|job| job.steps.iter().any(|s| s.uses.as_deref() == Some("ci/merge-release")));
    }
    Ok(plan)
}

pub async fn check_targets(d: &Dispatcher, snapshot: &Snapshot) -> Result<()> {
    for (alias, expected) in &snapshot.app_lbs {
        ensure!(&crate::host_app_lb::trusted(d, alias).await? == expected,
            "app-lb mapping changed since admission; resubmit before merging");
    }
    for (alias, expected) in &snapshot.maintenance {
        ensure!(&host_maintenance::trusted_target(d, alias).await? == expected,
            "maintenance mapping changed since admission; resubmit before merging");
    }
    for (alias, expected) in &snapshot.hosts {
        ensure!(&host_heyvm_bootstrap_coordinator::trusted(d, alias).await? == expected,
            "host mapping changed since admission; resubmit before merging");
    }
    Ok(())
}

fn bind(plan: &mut Plan, repository: &str, policy: &Policy, snapshot: &Snapshot) -> Result<()> {
    for id in policy.placements.keys() {
        ensure!(plan.jobs.iter().any(|job| &job.base_id == id), "release placement names an unknown job");
    }
    for job in &mut plan.jobs {
        ensure!(job.target.node.is_none() && !job.target.local && !job.target.is_existing_vm(),
            "operator release placement must use mapped aliases, not workflow host pins");
        if let Some(alias) = policy.placements.get(&job.base_id) {
            job.target.node = Some(snapshot.maintenance.get(alias)
                .ok_or_else(|| anyhow::anyhow!("missing placement target"))?.runner_hd_id.clone());
        }
        for step in &mut job.steps {
            match step.uses.as_deref() {
                Some("ci/rollout-service") => {
                    exclusive(step, &["url", "deployment", "namespace", "mount-path", "revision-env"])?;
                    let alias = input(step, "target")?;
                    let target = policy.service_targets.get(&alias).ok_or_else(|| anyhow::anyhow!("unknown service target"))?;
                    crate::cd::app_lb_endpoint(&target.url).map_err(anyhow::Error::msg)?;
                    ensure!(!target.deployment.trim().is_empty() && !target.namespace.trim().is_empty(), "service target has an empty identity");
                    crate::service_rollout::validate_target(target)?;
                    host_maintenance::token_secret(step.with.get("token").map(String::as_str).unwrap_or(""))?;
                    step.with.remove("target");
                    for (key, value) in [("url", &target.url), ("deployment", &target.deployment),
                        ("namespace", &target.namespace), ("mount-path", &target.mount_path), ("revision-env", &target.revision_env)] {
                        step.with.insert(key.into(), value.clone());
                    }
                }
                Some("ci/rollout-pooler") => {
                    exclusive(step, &["resolved-target", "url", "name", "namespace", "pooler"])?;
                    let alias = input(step, "target")?;
                    let target = policy.pooler_targets.get(&alias).ok_or_else(|| anyhow::anyhow!("unknown pooler target"))?;
                    crate::pooler_rollout::validate_target(target)?;
                    host_maintenance::token_secret(step.with.get("token").map(String::as_str).unwrap_or(""))?;
                    step.with.remove("target");
                    step.with.insert("resolved-target".into(), serde_json::to_string(target)?);
                }
                Some("ci/rollout-site" | "ci/rollout-stateful-service") => {
                    exclusive(step, &["resolved-target", "url", "deployment", "namespace"])?;
                    let alias = input(step, "target")?;
                    let target = if step.uses.as_deref() == Some("ci/rollout-site") {
                        let target = policy.site_targets.get(&alias).ok_or_else(|| anyhow::anyhow!("unknown site target"))?;
                        crate::site_rollout::validate_target(target)?;
                        serde_json::to_string(target)?
                    } else {
                        let target = policy.stateful_targets.get(&alias).ok_or_else(|| anyhow::anyhow!("unknown stateful target"))?;
                        crate::stateful_rollout::validate_target(target)?;
                        serde_json::to_string(target)?
                    };
                    host_maintenance::token_secret(step.with.get("token").map(String::as_str).unwrap_or(""))?;
                    step.with.remove("target");
                    step.with.insert("resolved-target".into(), target);
                }
                Some("ci/host-heyvm-maintenance" | "ci/promote-service-archive") => {
                    exclusive(step, &["url", "user-id", "runner"])?;
                    let alias = input(step, "target")?;
                    let target = snapshot.maintenance.get(&alias).ok_or_else(|| anyhow::anyhow!("unknown maintenance target"))?;
                    step.with.remove("target");
                    if step.uses.as_deref() == Some("ci/host-heyvm-maintenance") {
                        host_maintenance::token_secret(step.with.get("token").map(String::as_str).unwrap_or(""))?;
                        step.with.insert("runner".into(), alias);
                        step.with.insert("url".into(), target.cloud_url.clone());
                    } else {
                        step.with.insert("url".into(), target.orchestrator_url.clone());
                        step.with.insert("user-id".into(), target.artifact_user_id.clone());
                    }
                }
                Some("ci/bootstrap-host-heyvm" | "ci/rollout-host-heyvmd") => {
                    let alias = input(step, "target")?;
                    let target = snapshot.hosts.get(&alias).ok_or_else(|| anyhow::anyhow!("unknown host target"))?;
                    target.validate_admission(repository, job.target.node.as_deref(), step.uses.as_deref() == Some("ci/rollout-host-heyvmd"))?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPO: &str = "https://github.com/example/platform.git";
    const RELEASE: &str = "on: release\njobs:\n  merge:\n    steps:\n      - uses: ci/merge-release\n        with: {manifests: '[]'}\n  us:\n    needs: [merge]\n    steps:\n      - uses: ci/promote-service-archive\n        with: {target: us3}\n      - uses: ci/host-heyvm-maintenance\n        with: {target: us3, token: '${{ secrets.CLOUD_TOKEN }}'}\n  eu:\n    needs: [us]\n    steps:\n      - run: echo eu\n";

    fn policy() -> Policy {
        Policy { workflow_path: ".ci/workflows/regional-release.yml".into(), workflow: RELEASE.into(),
            submission_mode: SubmissionMode::MergeAndDeploy,
            service_targets: BTreeMap::new(), pooler_targets: BTreeMap::new(),
            site_targets: BTreeMap::new(), stateful_targets: BTreeMap::new(), placements: BTreeMap::new() }
    }

    #[test]
    fn merge_only_excludes_deployment_but_preserves_publication_validation() {
        let mut policy = policy();
        assert_eq!(submission_plan(&policy).unwrap().jobs.len(), 3);
        policy.submission_mode = SubmissionMode::MergeOnly;
        let plan = submission_plan(&policy).unwrap();
        assert_eq!(plan.jobs.len(), 1);
        assert_eq!(plan.jobs[0].steps[0].uses.as_deref(), Some("ci/merge-release"));
        assert!(crate::submission::validate_release_plan(&plan).is_ok());
        policy.workflow = policy.workflow.replace("manifests: '[]'", "manifests: '[\"Cargo.toml\"]'");
        assert!(submission_plan(&policy).is_err());
    }

    #[test]
    fn old_policies_keep_deploying_and_unknown_modes_are_rejected() {
        let mut value = serde_json::to_value(policy()).unwrap();
        value.as_object_mut().unwrap().remove("submission_mode");
        assert_eq!(serde_json::from_value::<Policy>(value.clone()).unwrap().submission_mode,
            SubmissionMode::MergeAndDeploy);
        value["submission_mode"] = serde_json::json!("merge_onyl");
        assert!(serde_json::from_value::<Policy>(value).is_err());
    }

    fn snapshot() -> Snapshot {
        Snapshot { digest: "frozen-policy".into(), token_expressions: Vec::new(), hosts: BTreeMap::new(), app_lbs: BTreeMap::new(), maintenance: BTreeMap::from([
            ("us3".into(), host_maintenance::Target { repository: REPO.into(), runner_hd_id: "us-runner".into(),
                backend_server_id: "us-backend".into(), cloud_url: "https://cloud.eu.example".into(),
                orchestrator_url: "https://archive.eu.example".into(), artifact_user_id: "archive-owner".into(),
                target: "us-layout".into(), region: Some("US".into()) })]) }
    }

    #[test]
    fn release_source_is_operator_owned_even_if_candidate_removes_or_renames_it() {
        let policy = policy();
        let validation = (".ci/workflows/build.yml".into(), "jobs:\n  build:\n    steps: [{run: echo build}]".into());
        let files = workflows(vec![validation.clone(), ("renamed-release.yml".into(), RELEASE.replace("needs: [us]", "needs: [merge]")),
            (policy.workflow_path.clone(), "broken candidate yaml".into())], &policy, true).unwrap();
        assert_eq!(files, vec![validation, (policy.workflow_path.clone(), RELEASE.into())]);
        assert_eq!(workflows(vec![], &policy, true).unwrap(), vec![(policy.workflow_path.clone(), RELEASE.into())]);
        assert!(workflows(vec![("renamed.yml".into(), RELEASE.into())], &policy, false).unwrap().is_empty());
    }

    #[test]
    fn policy_selection_is_repository_scoped_and_rejects_ambiguous_configuration() {
        let raw = serde_json::to_string(&BTreeMap::from([(REPO, policy())])).unwrap();
        assert!(select(Some(&raw), "https://github.com/example/platform").unwrap().is_some());
        assert!(select(Some(&raw), "https://github.com/example/other.git").unwrap().is_none());
        assert!(select(None, REPO).unwrap().is_none());
        assert!(select(Some("not a mapping"), REPO).is_err());
        let duplicate = serde_json::to_string(&BTreeMap::from([(REPO, policy()), ("https://github.com/example/platform", policy())])).unwrap();
        assert!(select(Some(&duplicate), REPO).is_err());
    }

    #[test]
    fn us_maintenance_and_publication_use_the_same_eu_authority() {
        let policy = policy();
        let mut plan = Plan::build(&Workflow::parse(&policy.workflow_path, RELEASE).unwrap()).unwrap();
        bind(&mut plan, REPO, &policy, &snapshot()).unwrap();
        let us = &plan.jobs[1];
        assert_eq!(us.steps[0].with["url"], "https://archive.eu.example");
        assert_eq!(us.steps[0].with["user-id"], "archive-owner");
        assert_eq!(us.steps[1].with["url"], "https://cloud.eu.example");
        assert_eq!(us.steps[1].with["runner"], "us3");
        assert!(!us.steps[1].with.contains_key("target"));
        assert_eq!(plan.jobs[2].needs, vec!["us"]);
        let mut duplicated = Plan::build(&Workflow::parse("release.yml", RELEASE).unwrap()).unwrap();
        duplicated.jobs[1].steps[1].with.insert("url".into(), "https://cloud.us.example".into());
        assert!(bind(&mut duplicated, REPO, &policy, &snapshot()).is_err());
        let mut unknown = Plan::build(&Workflow::parse("release.yml", RELEASE).unwrap()).unwrap();
        unknown.jobs[1].steps[1].with.insert("target".into(), "missing".into());
        assert!(bind(&mut unknown, REPO, &policy, &snapshot()).is_err());
    }

    #[test]
    fn persisted_jobs_keep_targets_and_legacy_jobs_still_decode() {
        let mut job = Plan::build(&Workflow::parse("release.yml", RELEASE).unwrap()).unwrap().jobs.remove(0);
        let legacy = serde_json::to_value(&job).unwrap();
        assert!(legacy.get("release_policy").is_none());
        assert!(serde_json::from_value::<crate::plan::JobPlan>(legacy).unwrap().release_policy.is_none());
        let mut frozen = snapshot();
        frozen.app_lbs.insert("ingress".into(), crate::host_app_lb::Target {
            repository: REPO.into(), url: "https://admin.first.example".into(),
            deployment: "host-ingress".into(), namespace: "default".into(),
            health_url: "https://admin.first.example/healthz".into(),
        });
        job.release_policy = Some(frozen);
        let stored = serde_json::to_vec(&job).unwrap();
        let restored: crate::plan::JobPlan = serde_json::from_slice(&stored).unwrap();
        assert_eq!(restored, job);
        let frozen = restored.release_policy.unwrap();
        assert_eq!(frozen.maintenance["us3"].cloud_url, "https://cloud.eu.example");
        assert_eq!(frozen.app_lbs["ingress"].url, "https://admin.first.example");
        let mut old = serde_json::to_value(frozen).unwrap();
        old.as_object_mut().unwrap().remove("app_lbs");
        assert!(serde_json::from_value::<Snapshot>(old).unwrap().app_lbs.is_empty());
    }

    #[test]
    fn regional_example_allows_a_third_region_without_engine_changes() {
        let repo = "https://github.com/Heyo-Computer/heyo.git";
        let mut policy = select(Some(include_str!("../deploy/regional-release-policy.example.yml")), repo).unwrap().unwrap();
        let mut china = policy.service_targets["cloud-region-a"].clone();
        china.url = "https://admin.china.example".into();
        china.deployment = "cloud-china".into();
        policy.service_targets.insert("cloud-china".into(), china);
        policy.workflow.push_str("  cloud-china:\n    needs: [verify-region-b]\n    steps:\n      - uses: ci/rollout-service\n        with:\n          target: cloud-china\n          token: ${{ secrets.APP_LB_CHINA_TOKEN }}\n          workflow: .ci/workflows/cloud.yml\n          artifact: cloud\n");
        let mut snap = snapshot();
        let mut first = snap.maintenance.remove("us3").unwrap();
        first.repository = repo.into();
        first.runner_hd_id = "first-runner".into();
        let mut second = first.clone();
        second.runner_hd_id = "second-runner".into();
        second.backend_server_id = "second-backend".into();
        snap.maintenance.insert("region-a".into(), first);
        snap.maintenance.insert("region-b".into(), second);
        for (alias, runner) in [("heyvmd-region-a", "first-runner"), ("heyvmd-region-b", "second-runner")] {
            snap.hosts.insert(alias.into(), serde_json::from_value(serde_json::json!({
                "repository":repo, "app_lb_admin_url":"https://admin.example", "app_lb_deployment":"daemon",
                "app_lb_namespace":"default", "runner_hd_id":runner, "backend_server_id":runner,
                "executable":"/usr/local/bin/heyvmd", "unit":"heyvmd", "state_dir":"/var/lib/heyvm",
                "config_json_path":"/etc/heyvm/update.json", "systemd_drop_in_path":"/etc/systemd/system/heyvmd.service.d/update.conf",
                "local_health_url":"http://127.0.0.1:34099/health", "target_alias":alias, "region":alias,
                "process_manager":"supervisor"
            })).unwrap());
        }
        let original = Plan::build(&Workflow::parse(&policy.workflow_path, &policy.workflow).unwrap()).unwrap();
        let mut plan = original.clone();
        bind(&mut plan, repo, &policy, &snap).unwrap();
        let job = |id: &str| plan.jobs.iter().find(|j| j.base_id == id).unwrap();
        assert_eq!(job("cloud-region-b").needs, ["verify-region-a"]);
        assert_eq!(job("verify-region-a").needs, ["heyvmd-region-a"]);
        assert!(job("verify-region-a").condition.is_none());
        assert!(job("verify-region-a").steps[0].condition.is_none());
        assert_eq!(job("heyvmd-region-a").target.node.as_deref(), Some("second-runner"));
        assert_eq!(job("heyvmd-region-b").target.node.as_deref(), Some("first-runner"));
        assert_eq!(job("cloud-region-a").steps[0].with["deployment"], "cloud-region-a");
        assert_eq!(job("cloud-region-b").steps[0].with["url"], "https://admin.region-b.example");
        assert_eq!(job("heyvm-region-a").steps[2].with["url"], "https://cloud.eu.example");
        assert_eq!(job("cloud-china").needs, ["verify-region-b"]);
        assert_eq!(job("cloud-china").steps[0].with["url"], "https://admin.china.example");

        let mut wrong = policy.clone();
        wrong.placements.insert("heyvmd-region-a".into(), "region-a".into());
        assert!(bind(&mut original.clone(), repo, &wrong, &snap).is_err());
        let mut missing = policy.clone();
        missing.placements.remove("heyvmd-region-a");
        assert!(bind(&mut original.clone(), repo, &missing, &snap).is_err());
        let mut missing_service = policy.clone();
        missing_service.service_targets.remove("cloud-region-a");
        assert!(bind(&mut original.clone(), repo, &missing_service, &snap).is_err());
        let mut unsafe_service = policy.clone();
        unsafe_service.service_targets.get_mut("cloud-region-a").unwrap().url = "https://credential@admin.example".into();
        assert!(bind(&mut original.clone(), repo, &unsafe_service, &snap).is_err());
    }
}
