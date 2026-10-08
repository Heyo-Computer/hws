//! What a namespace's builds may do on the shared fleet.
//!
//! A tenant namespace gets its own repositories, tokens and runs on this
//! installation's runners, and nothing else. The fleet's workflows deploy
//! services, merge releases and maintain hosts with operator credentials; a
//! tenant's must not be able to reach any of that, by asking for it in a
//! workflow file or by naming itself after something that can.
//!
//! So a tenant submit is planned under a narrower policy than a fleet one, and
//! every rule is enforced at submit time, where the refusal reaches the person
//! who ran `git submit`:
//!
//! - **One network.** Builds run in the network app-lb's plugin config names
//!   for the namespace (`namespace_networks[ns]`, else `tenant_network`). It
//!   must be a network this instance serves and must not be the fleet default,
//!   which is where the fleet's own builds — and their warm caches — live. A
//!   workflow may pin a host in that network; it may not name another network,
//!   `uses: default` (this orchestrator's own host), or an existing VM.
//! - **No native runners.** `runs-on` runs on a fleet machine outside any VM.
//! - **No release.** `on: release` is the coordinator trigger that merges and
//!   publishes.
//! - **Two actions.** `ci/upload-artifact` and `ci/download-artifact`; every
//!   other built-in deploys, publishes or touches a host.
//! - **No release policy and no workflow objects.** Both are matched by
//!   repository URL and are operator statements about the fleet's own
//!   repositories; a tenant registering the same URL does not inherit them.
//! - **Secrets under the namespace**, at `ci/ns/<ns>/<workflow>/<env>` — see
//!   [`crate::secrets::Secrets::prefix_for`].
//!
//! Each rule also has a second door at execution time — the action check in
//! `run_steps`, the native enqueue, and [`refuse_tenant_run`] in front of every
//! publication flow — so a plan that reached the queue some other way still
//! stops.

use crate::plan::Plan;
use crate::runners::{Pool, RunnerSet};
use crate::store::Store;
use crate::workflow::{Target, Workflow};
use std::fmt;

/// The built-in actions a namespace run may use. Everything else merges,
/// publishes, deploys or maintains hosts with fleet credentials.
pub const TENANT_ACTIONS: &[&str] = &["ci/upload-artifact", "ci/download-artifact"];

/// Whether a step's `uses:` is one a namespace run may execute.
pub fn action_allowed(action: &str) -> bool {
    TENANT_ACTIONS.contains(&action.trim())
}

/// A namespace name as app-lb accepts one (`config::is_valid_namespace`
/// there): it appears in a URL path and a secret path unescaped, so the
/// alphabet is narrow and the two dot-only names are refused outright.
pub fn valid_namespace(ns: &str) -> bool {
    !ns.is_empty()
        && ns != "."
        && ns != ".."
        && ns
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenancyError(pub String);

impl fmt::Display for TenancyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TenancyError {}

fn refuse(message: impl Into<String>) -> TenancyError {
    TenancyError(message.into())
}

/// The served network a namespace's builds run in.
///
/// `configured` is what app-lb's plugin config says
/// ([`crate::tenants::TenantSet::network_for`]). It is checked against the live
/// pool here rather than trusted, because the config is written in app-lb and
/// the pool is this instance's: a network this instance does not serve would
/// queue jobs nobody consumes, and the fleet default would put tenant code next
/// to the fleet's own builds.
pub fn resolve_network<'a>(
    pool: &'a Pool,
    namespace: &str,
    configured: Option<&str>,
) -> Result<&'a RunnerSet, TenancyError> {
    let Some(wanted) = configured else {
        return Err(refuse(format!(
            "no network is configured for namespace {namespace}; an operator sets \
             tenant_network (or namespace_networks) on app-lb's ci plugin"
        )));
    };
    let set = match pool.find(wanted) {
        Some(set) if set.served => set,
        _ => {
            return Err(refuse(format!(
                "namespace {namespace} is configured to build in {wanted}, which this \
                 orchestrator does not serve"
            )));
        }
    };
    if pool
        .default_set()
        .is_some_and(|d| d.network_id == set.network_id)
    {
        return Err(refuse(format!(
            "namespace {namespace} is configured to build in {}, the fleet's default \
             network; tenant builds need a network of their own",
            set.network_name
        )));
    }
    Ok(set)
}

/// Refuse a workflow a namespace may not run, naming the first rule it breaks.
pub fn check_workflow(wf: &Workflow, network: &RunnerSet) -> Result<(), TenancyError> {
    let path = &wf.path;
    if wf.on.iter().any(|t| t == "release") {
        return Err(refuse(format!(
            "{path}: `on: release` merges and publishes, and is not available to namespace runs"
        )));
    }
    for (key, job) in &wf.jobs {
        if !job.runs_on.is_empty() {
            return Err(refuse(format!(
                "{path}: job {key} uses `runs-on`; native runners are not available to \
                 namespace runs — remove it to build in a VM"
            )));
        }
        let target = match &job.uses {
            Some(u) => Target::parse(u).map_err(|e| refuse(format!("{path}: job {key}: {e}")))?,
            None => Target::any(),
        };
        check_target(path, key, &target, network)?;
        for step in &job.steps {
            if let Some(action) = &step.uses
                && !action_allowed(action)
            {
                return Err(refuse(format!(
                    "{path}: job {key} uses {action}; namespace runs may only use {}",
                    TENANT_ACTIONS.join(" and ")
                )));
            }
        }
    }
    Ok(())
}

fn check_target(
    path: &str,
    key: &str,
    target: &Target,
    network: &RunnerSet,
) -> Result<(), TenancyError> {
    if target.local {
        return Err(refuse(format!(
            "{path}: job {key} uses `default`, this orchestrator's own host, which is \
             not available to namespace runs"
        )));
    }
    if let Some(net) = &target.network
        && !network.matches(net)
    {
        return Err(refuse(format!(
            "{path}: job {key} names network {net}; this namespace builds in {}",
            network.network_name
        )));
    }
    // A VM somebody else created — another tenant's, or a service's — is not
    // a build machine this namespace owns.
    if target.vm.is_some() {
        return Err(refuse(format!(
            "{path}: job {key} names an existing VM; namespace runs build in a fresh one"
        )));
    }
    Ok(())
}

/// Re-check a plan after placement, and take the pool's reuse away.
///
/// The workflow was checked before planning; this checks what planning made of
/// it, so a matrix or a default that resolved somewhere unexpected is caught
/// before anything is stored. And a tenant VM is never handed to the next job
/// with the same fingerprint: that job could be another namespace's.
pub fn seal_plan(plan: &mut Plan, network: &RunnerSet) -> Result<(), TenancyError> {
    for job in &mut plan.jobs {
        if !job.native_labels.is_empty() {
            return Err(refuse(format!(
                "job {} would run on a native runner",
                job.key
            )));
        }
        check_target(&plan.workflow_path, &job.key, &job.target, network)?;
        if job.target.network.as_deref() != Some(network.network_name.as_str()) {
            return Err(refuse(format!(
                "job {} was placed outside {}",
                job.key, network.network_name
            )));
        }
        if let Some(action) = job
            .steps
            .iter()
            .filter_map(|s| s.uses.as_deref())
            .find(|a| !action_allowed(a))
        {
            return Err(refuse(format!("job {} uses {action}", job.key)));
        }
        job.vm.reuse = false;
    }
    Ok(())
}

/// Refuse a fleet-only flow — merge, publish, deploy, rollout, host
/// maintenance — for a namespace run. A missing run passes, so the caller's
/// own lookup reports it the way it always has.
pub async fn refuse_tenant_run(store: &Store, run_id: &str) -> Result<(), String> {
    let namespace: Option<String> = sqlx::query_scalar("SELECT namespace FROM ci_run WHERE id=$1")
        .bind(run_id)
        .fetch_optional(store.pool())
        .await
        .map_err(|e| e.to_string())?;
    match namespace {
        Some(ns) if !ns.is_empty() => Err(format!(
            "run {run_id} belongs to namespace {ns}; namespace runs cannot merge, publish, \
             deploy or maintain hosts"
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(id: &str, name: &str, served: bool) -> RunnerSet {
        RunnerSet {
            network_id: id.into(),
            network_name: name.into(),
            served,
            ..RunnerSet::default()
        }
    }

    fn pool() -> Pool {
        Pool {
            networks: vec![
                set("n-fleet", "fleet", true),
                set("n-ten", "tenants", true),
                set("n-off", "elsewhere", false),
            ],
            default_network_id: "n-fleet".into(),
            ..Pool::default()
        }
    }

    fn wf(yaml: &str) -> Workflow {
        Workflow::parse(".ci/workflows/build.yml", yaml).expect("parses")
    }

    fn tenants() -> RunnerSet {
        set("n-ten", "tenants", true)
    }

    const OK: &str = "on: [submit]\njobs:\n  build:\n    steps:\n      - run: make\n      - uses: ci/upload-artifact\n        with: { name: out, path: out }\n";

    #[test]
    fn the_tenant_network_must_be_served_and_not_the_fleet_default() {
        let p = pool();
        assert_eq!(
            resolve_network(&p, "team-a", Some("tenants"))
                .unwrap()
                .network_id,
            "n-ten"
        );
        assert_eq!(
            resolve_network(&p, "team-a", Some("n-ten"))
                .unwrap()
                .network_name,
            "tenants"
        );
        assert!(
            resolve_network(&p, "team-a", None)
                .unwrap_err()
                .0
                .contains("no network is configured")
        );
        assert!(
            resolve_network(&p, "team-a", Some("elsewhere"))
                .unwrap_err()
                .0
                .contains("does not serve")
        );
        assert!(
            resolve_network(&p, "team-a", Some("missing"))
                .unwrap_err()
                .0
                .contains("does not serve")
        );
        assert!(
            resolve_network(&p, "team-a", Some("fleet"))
                .unwrap_err()
                .0
                .contains("fleet's default")
        );
    }

    #[test]
    fn an_ordinary_build_passes() {
        check_workflow(&wf(OK), &tenants()).unwrap();
        check_workflow(
            &wf("on: [submit]\njobs:\n  b:\n    uses: tenants/host-1\n    steps: [{run: x}]\n"),
            &tenants(),
        )
        .unwrap();
        check_workflow(
            &wf("on: [submit]\njobs:\n  b:\n    uses: n-ten\n    steps: [{run: x}]\n"),
            &tenants(),
        )
        .unwrap();
    }

    #[test]
    fn every_tenant_refusal_names_its_rule() {
        let cases = [
            (
                "on: [release]\njobs:\n  b:\n    steps: [{run: x}]\n",
                "on: release",
            ),
            (
                "on: [submit]\njobs:\n  b:\n    runs-on: [linux, x86_64]\n    steps: [{run: x}]\n",
                "runs-on",
            ),
            (
                "on: [submit]\njobs:\n  b:\n    uses: default\n    steps: [{run: x}]\n",
                "uses `default`",
            ),
            (
                "on: [submit]\njobs:\n  b:\n    uses: fleet\n    steps: [{run: x}]\n",
                "names network fleet",
            ),
            (
                "on: [submit]\njobs:\n  b:\n    uses: fleet/host-1\n    steps: [{run: x}]\n",
                "names network fleet",
            ),
            (
                "on: [submit]\njobs:\n  b:\n    uses: tenants/host-1/vm-9\n    steps: [{run: x}]\n",
                "existing VM",
            ),
            (
                "on: [submit]\njobs:\n  b:\n    steps: [{uses: ci/deploy-service}]\n",
                "ci/deploy-service",
            ),
            (
                "on: [submit]\njobs:\n  b:\n    steps: [{uses: ci/merge-release}]\n",
                "ci/merge-release",
            ),
            (
                "on: [submit]\njobs:\n  b:\n    steps: [{uses: ci/rollout-host-app-lb}]\n",
                "ci/rollout-host-app-lb",
            ),
        ];
        for (yaml, why) in cases {
            let Ok(w) = Workflow::parse(".ci/workflows/build.yml", yaml) else {
                // A workflow the parser refuses is refused anyway; the policy
                // only has to cover what parses.
                continue;
            };
            let err = check_workflow(&w, &tenants()).expect_err(yaml);
            assert!(err.0.contains(why), "{yaml}: {err}");
        }
    }

    #[test]
    fn only_the_artifact_actions_are_allowed() {
        assert!(action_allowed("ci/upload-artifact"));
        assert!(action_allowed(" ci/download-artifact "));
        for a in [
            "ci/deploy-service",
            "ci/merge-release",
            "ci/host-heyvm-maintenance",
            "",
            "ci/upload-artifact2",
        ] {
            assert!(!action_allowed(a), "{a}");
        }
    }

    #[test]
    fn a_sealed_plan_stays_in_the_tenant_network_and_never_reuses_a_vm() {
        let mut plan = Plan::build(&wf(OK)).unwrap();
        plan.jobs[0].target.network = Some("tenants".into());
        assert!(plan.jobs[0].vm.reuse, "the pool reuses by default");
        seal_plan(&mut plan, &tenants()).unwrap();
        assert!(!plan.jobs[0].vm.reuse);

        let mut stray = Plan::build(&wf(OK)).unwrap();
        stray.jobs[0].target.network = Some("fleet".into());
        assert!(seal_plan(&mut stray, &tenants()).is_err());
        let mut unplaced = Plan::build(&wf(OK)).unwrap();
        assert!(
            seal_plan(&mut unplaced, &tenants()).is_err(),
            "an unplaced job is not trusted"
        );
    }

    #[test]
    fn namespace_names_follow_app_lb() {
        for ok in ["team-a", "v1.2", "a_b", "X"] {
            assert!(valid_namespace(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "a b", "a%2f", "ü"] {
            assert!(!valid_namespace(bad), "{bad}");
        }
    }
}
