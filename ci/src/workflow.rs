//! The workflow file: `.ci/workflows/*.yml`.
//!
//! GitHub Actions' shape, with two deliberate departures.
//!
//! **`uses:` on a job places it**, where GitHub has `runs-on:` selecting a
//! label. That is the point of the whole system: a job names the heyvm network
//! and the machine it wants, and membership of that network is what makes a host
//! eligible. The grammar is `default`, `<network>`, `<network>/<node>` or
//! `<network>/<node>/<vm>` — see [`Target`].
//!
//! **`vm:` on a job describes the machine to build.** GitHub gives you an opaque
//! runner image; here the workflow author declares the driver, image, size and
//! setup hooks, and — via `cache_key_files` — says what should invalidate the
//! warm VM the next run would otherwise reuse.
//!
//! Parsing is two-stage on purpose. The document is read as a
//! `serde_yaml::Value` first so that `jobs:` keeps the order the author wrote
//! (a `BTreeMap` would sort them, and a workflow reads top to bottom) and so
//! that a malformed job reports *which* job rather than a line number inside a
//! merged error.

use crate::paths::Changes;
use crate::vm::VmSpec;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The literal `uses:` value meaning "the host this orchestrator runs on".
pub const DEFAULT_NODE: &str = "default";

/// Where a job runs, as `uses:` spells it.
///
/// **`uses:` carries everything needed to place the job**, which is what makes
/// the third form worth having: a sandbox does not record which host it is on
/// (`SandboxInfo` has no daemon field, and there is no cloud-proxied exec), so
/// without the node in the path the orchestrator would have to interrogate every
/// host in the network to find one VM.
///
/// ```text
/// default                     the host this orchestrator runs on
/// <network>                   any online host in that network
/// <network>/*                 the same, written explicitly
/// <network>/<node>            that host; the `vm:` block builds a VM on it
/// <network>/<node>/<vm>       that existing VM on that host; `vm:` is unused
///                             and every step is an exec into it
/// absent                      the repository's assigned network, any host
/// ```
///
/// Kept as a struct with defaulted fields rather than an enum, because a
/// `JobPlan` — this included — is persisted as JSONB on `ci_job` and replayed on
/// a JetStream redelivery. An enum would change that shape and strand every job
/// queued across the deploy that introduced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// `None` means the repository's assigned network — or, with `local`, no
    /// network at all.
    pub network: Option<String>,
    /// The host machine, by daemon id or name. `None` means any online host in
    /// the network.
    ///
    /// Aliased to `runner` so a plan written by an older build still
    /// deserializes: that is the field name jobs queued before this change
    /// carry, and a redelivery has to route them the same way.
    #[serde(alias = "runner")]
    pub node: Option<String>,
    /// An existing sandbox on that node. When set, the `vm:` block is unused and
    /// every step execs into this VM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm: Option<String>,
    /// `uses: default` — resolve to the orchestrator's own host, whatever
    /// network it is in.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub local: bool,
}

impl Target {
    /// Parse the `uses:` value.
    pub fn parse(raw: &str) -> Result<Self, WorkflowError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(WorkflowError::EmptyUses);
        }
        if raw.eq_ignore_ascii_case(DEFAULT_NODE) {
            return Ok(Self {
                network: None,
                node: None,
                vm: None,
                local: true,
            });
        }

        let parts: Vec<&str> = raw.split('/').map(str::trim).collect();
        if parts.len() > 3 {
            return Err(WorkflowError::UsesTooDeep(raw.to_string()));
        }
        let network = parts[0];
        if network.is_empty() {
            return Err(WorkflowError::EmptyUses);
        }

        // `*` means "unspecified" only in the node position. A `*` network would
        // be "any network at all", which is not a placement anybody means, and a
        // `*` VM cannot be exec'd into.
        let node = match parts.get(1).copied() {
            None | Some("*") => None,
            Some("") => return Err(WorkflowError::EmptyRunner(raw.to_string())),
            Some(n) => Some(n.to_string()),
        };
        let vm = match parts.get(2).copied() {
            None => None,
            Some("") | Some("*") => return Err(WorkflowError::EmptyRunner(raw.to_string())),
            Some(v) => Some(v.to_string()),
        };
        // `<network>/*/<vm>` names a VM without saying which host holds it,
        // which is precisely the lookup this grammar exists to avoid.
        if vm.is_some() && node.is_none() {
            return Err(WorkflowError::VmWithoutNode(raw.to_string()));
        }

        Ok(Self {
            network: Some(network.to_string()),
            node,
            vm,
            local: false,
        })
    }

    pub fn any() -> Self {
        Self {
            network: None,
            node: None,
            vm: None,
            local: false,
        }
    }

    /// Whether steps exec into an existing VM rather than one built from the
    /// `vm:` block.
    pub fn is_existing_vm(&self) -> bool {
        self.vm.is_some()
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.local {
            return write!(f, "{DEFAULT_NODE}");
        }
        let network = self.network.as_deref().unwrap_or("*");
        match (&self.node, &self.vm) {
            (Some(n), Some(v)) => write!(f, "{network}/{n}/{v}"),
            (Some(n), None) => write!(f, "{network}/{n}"),
            (None, _) => write!(f, "{network}/*"),
        }
    }
}

/// What to do when the named runner cannot take the job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fallback {
    /// Wait for that host, then fail. The default, because a warm VM pool is
    /// host-local: silently moving the job to another host throws away the cache
    /// the author asked for by pinning it, and turns a fast build into a slow
    /// one for reasons nothing reports.
    #[default]
    None,
    /// Any online host in the network will do.
    Any,
}

/// `with:` values as text, whatever scalar the author wrote them as. A bare
/// `true`, `3` or `1.5` becomes its YAML spelling; `~`/null becomes the empty
/// string, which every consumer already treats as unset; a list or a mapping
/// is refused, since there is no one string it could mean.
fn with_scalars<'de, D>(d: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: BTreeMap<String, serde_yaml::Value> = Deserialize::deserialize(d)?;
    raw.into_iter()
        .map(|(k, v)| {
            let text = match v {
                serde_yaml::Value::String(s) => s,
                serde_yaml::Value::Bool(b) => b.to_string(),
                serde_yaml::Value::Number(n) => n.to_string(),
                serde_yaml::Value::Null => String::new(),
                other => {
                    return Err(serde::de::Error::custom(format!(
                        "`with.{k}` must be a scalar, not {}",
                        match other {
                            serde_yaml::Value::Sequence(_) => "a list",
                            serde_yaml::Value::Mapping(_) => "a mapping",
                            _ => "a tagged value",
                        }
                    )));
                }
            };
            Ok((k, text))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "if", default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses: Option<String>,
    /// Inputs to `uses:`. Strings, so they can be substituted — but taken
    /// from any YAML scalar, because an author writes `public: true` and
    /// `retries: 3` as the bare values they are, not `"true"` and `"3"`.
    #[serde(
        default,
        deserialize_with = "with_scalars",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub with: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    #[serde(
        rename = "working-directory",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub working_directory: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(
        rename = "timeout-minutes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub timeout_minutes: Option<u64>,
    #[serde(rename = "continue-on-error", default)]
    pub continue_on_error: bool,
}

impl Step {
    pub fn label(&self, index: usize) -> String {
        if let Some(n) = &self.name {
            return n.clone();
        }
        if let Some(u) = &self.uses {
            return u.clone();
        }
        if let Some(r) = &self.run {
            // First line only — a `run:` block is often a whole script, and a
            // step list is unreadable if one entry is forty lines.
            let first = r
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("")
                .trim();
            return truncate(first, 60);
        }
        format!("step {}", index + 1)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Strategy {
    /// Axes, or an explicit `include:` list. Values are free-form YAML so a
    /// numeric axis stays numeric for `${{ }}` comparisons.
    #[serde(default)]
    pub matrix: Option<serde_yaml::Value>,
    #[serde(rename = "max-parallel", default)]
    pub max_parallel: Option<usize>,
    #[serde(rename = "fail-fast", default = "default_true")]
    pub fail_fast: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `<network>/<runner>`. Absent means the workflow object's network and any
    /// online host in it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses: Option<String>,
    /// Native runner labels. Every label must be advertised by one runner.
    /// Mutually exclusive with `uses:` and `vm:` placement.
    #[serde(rename = "runs-on", default, skip_serializing_if = "Vec::is_empty")]
    pub runs_on: Vec<String>,
    #[serde(default)]
    pub vm: VmSpec,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needs: Vec<String>,
    #[serde(rename = "if", default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Strategy>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub outputs: BTreeMap<String, String>,
    #[serde(rename = "continue-on-error", default)]
    pub continue_on_error: bool,
    #[serde(
        rename = "timeout-minutes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub timeout_minutes: Option<u64>,
    #[serde(default)]
    pub fallback: Fallback,
    pub steps: Vec<Step>,
}

impl Job {
    pub fn target(&self) -> Result<Target, WorkflowError> {
        if !self.runs_on.is_empty() {
            if self.uses.is_some() {
                return Err(WorkflowError::NativePlacement("`runs-on` and `uses` are mutually exclusive".into()));
            }
            if self.vm != VmSpec::default() {
                return Err(WorkflowError::NativePlacement("native `runs-on` jobs cannot have a `vm` block".into()));
            }
            if self.runs_on.iter().any(|label| label.trim().is_empty()) {
                return Err(WorkflowError::NativePlacement("`runs-on` labels cannot be empty".into()));
            }
        }
        match &self.uses {
            Some(u) => Target::parse(u),
            None => Ok(Target::any()),
        }
    }
}

/// The filters on `on: submit:` — which branches, and which paths.
///
/// **This block used to be read and thrown away.** `on: { submit: { branches:
/// [main] } }` parsed, because only the *keys* of the `on:` mapping were looked
/// at, and then built every branch anyway. A filter that silently does nothing
/// is the same class of bug as a misspelled `stpes:`, which this file makes a
/// hard parse error — so `deny_unknown_fields` is on here for the same reason.
///
/// `paths` and `paths-ignore` are mutually exclusive, as are `branches` and
/// `branches-ignore`. GitHub allows a mixture and resolves it by pattern order
/// within the list, which is behaviour nobody can read off the file; refusing
/// the combination costs a workflow nothing and removes the question.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitFilter {
    /// Build only these branches. Empty means every branch.
    #[serde(default)]
    pub branches: Vec<String>,
    #[serde(rename = "branches-ignore", default)]
    pub branches_ignore: Vec<String>,
    /// Build only when a changed path matches. Empty means any change.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Skip when *every* changed path matches.
    #[serde(rename = "paths-ignore", default)]
    pub paths_ignore: Vec<String>,
}

impl SubmitFilter {
    fn validate(&self, path: &str) -> Result<(), WorkflowError> {
        if !self.paths.is_empty() && !self.paths_ignore.is_empty() {
            return Err(WorkflowError::ConflictingFilter {
                path: path.to_string(),
                a: "paths",
                b: "paths-ignore",
            });
        }
        if !self.branches.is_empty() && !self.branches_ignore.is_empty() {
            return Err(WorkflowError::ConflictingFilter {
                path: path.to_string(),
                a: "branches",
                b: "branches-ignore",
            });
        }
        for (field, patterns) in [
            ("branches", &self.branches),
            ("branches-ignore", &self.branches_ignore),
            ("paths", &self.paths),
            ("paths-ignore", &self.paths_ignore),
        ] {
            for pattern in patterns {
                crate::paths::validate(pattern).map_err(|detail| WorkflowError::BadFilter {
                    path: path.to_string(),
                    field,
                    detail,
                })?;
            }
        }
        Ok(())
    }

    /// Whether a submit on `branch` that changed `changes` should produce a run.
    ///
    /// `Err` carries the reason, which is reported to the submitter: a workflow
    /// that decided not to build must say so at the terminal that asked, or the
    /// answer to "why did nothing happen" is a log line on a server.
    pub fn admits(&self, branch: &str, changes: &Changes) -> Result<(), String> {
        if !self.branches.is_empty()
            && !self
                .branches
                .iter()
                .any(|p| crate::paths::matches(p, branch))
        {
            return Err(format!(
                "branch {branch:?} is not in `branches: [{}]`",
                self.branches.join(", ")
            ));
        }
        if let Some(hit) = self
            .branches_ignore
            .iter()
            .find(|p| crate::paths::matches(p, branch))
        {
            return Err(format!(
                "branch {branch:?} matches `branches-ignore: {hit}`"
            ));
        }
        if !self.paths.is_empty() && !changes.matches_any(&self.paths) {
            return Err(format!(
                "nothing under `paths: [{}]` changed ({changes})",
                self.paths.join(", ")
            ));
        }
        if changes.all_match(&self.paths_ignore) {
            return Err(format!(
                "every changed path matches `paths-ignore: [{}]`",
                self.paths_ignore.join(", ")
            ));
        }
        Ok(())
    }
}

/// A parsed workflow file. `jobs` keeps the author's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workflow {
    pub path: String,
    pub name: Option<String>,
    /// `submit` starts validation; `release` is coordinator-only and waits for
    /// the complete frozen submission's validation evidence.
    pub on: Vec<String>,
    /// The filters written under `on: submit:`. Default — no filters, build
    /// everything — when `on:` is absent or names `submit` without a block.
    pub on_submit: SubmitFilter,
    pub env: BTreeMap<String, String>,
    pub jobs: Vec<(String, Job)>,
}

/// The top level, minus `jobs`, which is handled separately to keep its order.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowHeader {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    on: Option<serde_yaml::Value>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    jobs: serde_yaml::Value,
}

impl Workflow {
    pub fn parse(path: &str, yaml: &str) -> Result<Self, WorkflowError> {
        let header: WorkflowHeader =
            serde_yaml::from_str(yaml).map_err(|e| WorkflowError::Yaml {
                path: path.to_string(),
                detail: e.to_string(),
            })?;

        let Some(mapping) = header.jobs.as_mapping() else {
            return Err(WorkflowError::NoJobs(path.to_string()));
        };
        if mapping.is_empty() {
            return Err(WorkflowError::NoJobs(path.to_string()));
        }

        let mut jobs = Vec::with_capacity(mapping.len());
        for (key, value) in mapping {
            let id = key
                .as_str()
                .ok_or_else(|| WorkflowError::BadJobId(format!("{key:?}")))?
                .to_string();
            // Deserialized one at a time so the error names the job. A single
            // `BTreeMap<String, Job>` deserialize reports a path into the merged
            // document, which is far harder to act on.
            let job: Job =
                serde_yaml::from_value(value.clone()).map_err(|e| WorkflowError::BadJob {
                    path: path.to_string(),
                    job: id.clone(),
                    detail: e.to_string(),
                })?;
            jobs.push((id, job));
        }

        let (on, on_submit) = match header.on {
            None => (vec!["submit".to_string()], SubmitFilter::default()),
            Some(v) => {
                if v.as_mapping().and_then(|m| m.get("release")).is_some_and(|v| !v.is_null()) {
                    return Err(WorkflowError::Yaml {
                        path: path.to_string(),
                        detail: "release trigger does not accept filters; it coordinates all selected validations".into(),
                    });
                }
                (trigger_names(&v), submit_filter(path, &v)?)
            }
        };
        on_submit.validate(path)?;

        let wf = Self {
            path: path.to_string(),
            name: header.name,
            on,
            on_submit,
            env: header.env,
            jobs,
        };
        wf.validate()?;
        Ok(wf)
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        let ids: BTreeSet<&str> = self.jobs.iter().map(|(id, _)| id.as_str()).collect();
        if ids.len() != self.jobs.len() {
            return Err(WorkflowError::DuplicateJob(self.path.clone()));
        }

        for (id, job) in &self.jobs {
            if !is_job_id(id) {
                return Err(WorkflowError::BadJobId(id.clone()));
            }
            job.vm.validate().map_err(|e| WorkflowError::BadVm {
                job: id.clone(),
                detail: e.to_string(),
            })?;
            job.target().map_err(|e| match e {
                WorkflowError::EmptyUses => WorkflowError::BadUses {
                    job: id.clone(),
                    detail: "`uses:` is empty".to_string(),
                },
                other => WorkflowError::BadUses {
                    job: id.clone(),
                    detail: other.to_string(),
                },
            })?;

            for need in &job.needs {
                if !ids.contains(need.as_str()) {
                    return Err(WorkflowError::UnknownNeed {
                        job: id.clone(),
                        need: need.clone(),
                    });
                }
                if need == id {
                    return Err(WorkflowError::SelfNeed(id.clone()));
                }
            }

            if job.steps.is_empty() {
                return Err(WorkflowError::NoSteps(id.clone()));
            }
            for (i, step) in job.steps.iter().enumerate() {
                match (&step.run, &step.uses) {
                    (Some(_), Some(_)) => {
                        return Err(WorkflowError::StepRunAndUses {
                            job: id.clone(),
                            step: step.label(i),
                        });
                    }
                    (None, None) => {
                        return Err(WorkflowError::StepNeitherRunNorUses {
                            job: id.clone(),
                            step: step.label(i),
                        });
                    }
                    _ => {}
                }
            }
        }

        // A cycle would otherwise surface as jobs that simply never start, with
        // nothing saying why.
        if let Some(cycle) = self.find_cycle() {
            return Err(WorkflowError::Cycle(cycle));
        }
        Ok(())
    }

    /// Depth-first search for a `needs` cycle, returning the path if there is one.
    fn find_cycle(&self) -> Option<Vec<String>> {
        #[derive(Clone, Copy, PartialEq)]
        enum Mark {
            Open,
            Done,
        }
        let deps: BTreeMap<&str, &Vec<String>> = self
            .jobs
            .iter()
            .map(|(id, j)| (id.as_str(), &j.needs))
            .collect();
        let mut marks: BTreeMap<&str, Mark> = BTreeMap::new();
        let mut stack: Vec<&str> = Vec::new();

        fn visit<'a>(
            node: &'a str,
            deps: &BTreeMap<&'a str, &'a Vec<String>>,
            marks: &mut BTreeMap<&'a str, Mark>,
            stack: &mut Vec<&'a str>,
        ) -> Option<Vec<String>> {
            match marks.get(node) {
                Some(Mark::Done) => return None,
                Some(Mark::Open) => {
                    let start = stack.iter().position(|n| *n == node).unwrap_or(0);
                    let mut cycle: Vec<String> =
                        stack[start..].iter().map(|s| s.to_string()).collect();
                    cycle.push(node.to_string());
                    return Some(cycle);
                }
                None => {}
            }
            marks.insert(node, Mark::Open);
            stack.push(node);
            if let Some(needs) = deps.get(node) {
                for n in needs.iter() {
                    if let Some((key, _)) = deps.get_key_value(n.as_str())
                        && let Some(c) = visit(key, deps, marks, stack)
                    {
                        return Some(c);
                    }
                }
            }
            stack.pop();
            marks.insert(node, Mark::Done);
            None
        }

        for (id, _) in &self.jobs {
            if let Some((key, _)) = deps.get_key_value(id.as_str())
                && let Some(c) = visit(key, &deps, &mut marks, &mut stack)
            {
                return Some(c);
            }
        }
        None
    }

    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.path)
    }
}

/// The block under `on: submit:`, when `on:` is written as a mapping.
///
/// The other two spellings — a bare string and a sequence — carry no block, so
/// they get the default. Only `submit`'s block is read: an unsupported trigger
/// is already reported as unsupported, and parsing filters for a trigger that
/// never fires would be inventing a contract this build does not honour.
fn submit_filter(path: &str, v: &serde_yaml::Value) -> Result<SubmitFilter, WorkflowError> {
    let Some(map) = v.as_mapping() else {
        return Ok(SubmitFilter::default());
    };
    let Some(block) = map
        .iter()
        .find(|(k, _)| k.as_str() == Some("submit"))
        .map(|(_, v)| v)
    else {
        return Ok(SubmitFilter::default());
    };
    // `on: { submit: }` is a mapping whose value is null, and means the trigger
    // with no filters — not a malformed block.
    if block.is_null() {
        return Ok(SubmitFilter::default());
    }
    serde_yaml::from_value(block.clone()).map_err(|e| WorkflowError::BadTriggerBlock {
        path: path.to_string(),
        detail: e.to_string(),
    })
}

/// `on: submit`, `on: [submit, schedule]`, or `on: {submit: {...}}`.
fn trigger_names(v: &serde_yaml::Value) -> Vec<String> {
    match v {
        serde_yaml::Value::String(s) => vec![s.clone()],
        serde_yaml::Value::Sequence(items) => items
            .iter()
            .filter_map(|i| i.as_str().map(str::to_string))
            .collect(),
        serde_yaml::Value::Mapping(m) => m
            .keys()
            .filter_map(|k| k.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Job ids become NATS subject tokens and appear in sandbox names, so the
/// alphabet is restricted rather than escaped — the same rule queue-fn applies
/// to function ids.
pub fn is_job_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

#[derive(Debug, PartialEq, Eq)]
pub enum WorkflowError {
    NativePlacement(String),
    Yaml {
        path: String,
        detail: String,
    },
    NoJobs(String),
    DuplicateJob(String),
    BadJobId(String),
    /// The block under `on: submit:` did not deserialize — a misspelled filter
    /// name, or a scalar where a list belongs.
    BadTriggerBlock {
        path: String,
        detail: String,
    },
    /// A filter pattern this dialect cannot represent.
    BadFilter {
        path: String,
        field: &'static str,
        detail: String,
    },
    /// Two filters that would need an ordering rule to combine.
    ConflictingFilter {
        path: String,
        a: &'static str,
        b: &'static str,
    },
    BadJob {
        path: String,
        job: String,
        detail: String,
    },
    BadVm {
        job: String,
        detail: String,
    },
    BadUses {
        job: String,
        detail: String,
    },
    EmptyUses,
    EmptyRunner(String),
    /// `uses:` had more than the three segments the grammar defines.
    UsesTooDeep(String),
    /// A VM named without the host that holds it.
    VmWithoutNode(String),
    UnknownNeed {
        job: String,
        need: String,
    },
    SelfNeed(String),
    Cycle(Vec<String>),
    NoSteps(String),
    StepRunAndUses {
        job: String,
        step: String,
    },
    StepNeitherRunNorUses {
        job: String,
        step: String,
    },
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativePlacement(detail) => write!(f, "invalid native runner placement: {detail}"),
            Self::Yaml { path, detail } => write!(f, "{path} is not valid workflow YAML: {detail}"),
            Self::NoJobs(path) => write!(f, "{path} declares no jobs"),
            Self::DuplicateJob(path) => write!(f, "{path} declares the same job id twice"),
            Self::BadTriggerBlock { path, detail } => write!(
                f,
                "the `on: submit:` block in {path} is malformed: {detail}. \
                 The filters are `branches`, `branches-ignore`, `paths` and \
                 `paths-ignore`, each a list of glob patterns."
            ),
            Self::BadFilter {
                path,
                field,
                detail,
            } => write!(f, "`on: submit: {field}:` in {path} — {detail}"),
            Self::ConflictingFilter { path, a, b } => write!(
                f,
                "{path} sets both `{a}:` and `{b}:` under `on: submit:`. Which \
                 wins would depend on the order the patterns happen to be \
                 written in, so write one or the other."
            ),
            Self::BadJobId(id) => write!(
                f,
                "job id {id:?} must be 1-64 characters of letters, digits, '_' or '-'; \
                 it becomes a NATS subject token and part of a VM name"
            ),
            Self::BadJob { path, job, detail } => {
                write!(f, "job {job:?} in {path} is malformed: {detail}")
            }
            Self::BadVm { job, detail } => write!(f, "job {job:?} has an invalid `vm:` — {detail}"),
            Self::BadUses { job, detail } => {
                write!(f, "job {job:?} has an invalid `uses:` — {detail}")
            }
            Self::EmptyUses => write!(
                f,
                "`uses:` must name a network, as `<network>` or `<network>/<runner>`"
            ),
            Self::EmptyRunner(raw) => write!(
                f,
                "`uses: {raw}` has an empty segment; write `<network>`, \
                 `<network>/<node>`, or `<network>/<node>/<vm>`"
            ),
            Self::UsesTooDeep(raw) => write!(
                f,
                "`uses: {raw}` has more than three segments. The deepest form is \
                 `<network>/<node>/<vm>`, which names an existing VM on a host; \
                 `default` names the host this CI runs on."
            ),
            Self::VmWithoutNode(raw) => write!(
                f,
                "`uses: {raw}` names a VM but not the host holding it. A sandbox \
                 does not record its host, so write `<network>/<node>/<vm>` — \
                 otherwise every host in the network has to be interrogated to \
                 find it."
            ),
            Self::UnknownNeed { job, need } => write!(
                f,
                "job {job:?} needs {need:?}, which no job in this workflow declares"
            ),
            Self::SelfNeed(job) => write!(f, "job {job:?} needs itself"),
            Self::Cycle(path) => write!(f, "jobs form a `needs` cycle: {}", path.join(" -> ")),
            Self::NoSteps(job) => write!(f, "job {job:?} has no steps"),
            Self::StepRunAndUses { job, step } => write!(
                f,
                "step {step:?} in job {job:?} sets both `run:` and `uses:`; a step is one \
                 or the other"
            ),
            Self::StepNeitherRunNorUses { job, step } => write!(
                f,
                "step {step:?} in job {job:?} sets neither `run:` nor `uses:`"
            ),
        }
    }
}

impl std::error::Error for WorkflowError {}

#[cfg(test)]
mod repo_workflow_files {
    /// The workflows this repository actually runs must stay parseable by the
    /// `with:` values are strings so they can be substituted, and a YAML
    /// author writes `public: true` as a bare boolean. serde_yaml hands a
    /// plain scalar to a `String` field as its text — this pins that, because
    /// the alternative is every upload step having to quote `"true"`.
    #[test]
    fn a_bare_yaml_boolean_in_with_arrives_as_its_text() {
        fn with_block(extra: &str) -> String {
            format!(
                "name: w\njobs:\n  build:\n    vm:\n      driver: kvm\n      image: ubuntu:24.04\n    steps:\n      - uses: ci/upload-artifact\n        with:\n          name: dist\n          {extra}\n"
            )
        }
        let wf = super::Workflow::parse("w.yml", &with_block("path: dist\n          public: true"))
            .unwrap();
        let step = &wf.jobs[0].1.steps[0];
        assert_eq!(step.with.get("public").map(String::as_str), Some("true"));

        // Numbers and nulls likewise; a list is the one thing with no text.
        let wf = super::Workflow::parse(
            "w.yml",
            &with_block("path: dist\n          retries: 3\n          description: ~"),
        )
        .unwrap();
        let with = &wf.jobs[0].1.steps[0].with;
        assert_eq!(with.get("retries").map(String::as_str), Some("3"));
        assert_eq!(with.get("description").map(String::as_str), Some(""));
        let err = super::Workflow::parse("w.yml", &with_block("path: [a, b]")).unwrap_err();
        assert!(
            err.to_string()
                .contains("`with.path` must be a scalar, not a list"),
            "{err}"
        );
    }

    /// parser that runs them. A syntax slip in `.ci/workflows/*.yml` otherwise
    /// surfaces as a run that never starts, on the server, after the push.
    #[test]
    fn the_repos_own_workflows_parse() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../.ci/workflows");
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return, // crate used outside the monorepo
        };
        let mut seen = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yml") {
                continue;
            }
            let yaml = std::fs::read_to_string(&path).unwrap();
            let name = path.display().to_string();
            let wf = super::Workflow::parse(&name, &yaml)
                .unwrap_or_else(|e| panic!("{name} does not parse: {e}"));
            assert!(!wf.jobs.is_empty(), "{name} has no jobs");
            // Planning is where `uses:` targets and job graphs are validated;
            // a workflow that parses but cannot plan still never runs.
            crate::plan::Plan::build(&wf).unwrap_or_else(|e| panic!("{name} does not plan: {e}"));
            seen += 1;
        }
        assert!(
            seen >= 3,
            "expected the repo's workflow files, found {seen}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
name: build
on: [submit]
env:
  CARGO_TERM_COLOR: never

jobs:
  build:
    uses: prod-runners/bigbox
    vm:
      driver: firecracker
      image: ubuntu:24.04
      size_class: medium
      cache_key_files:
        - Cargo.lock
    strategy:
      matrix:
        target: [x86_64, aarch64]
      max-parallel: 2
    steps:
      - name: Build
        run: cargo build --release --target ${{ matrix.target }}
        timeout-minutes: 30
      - uses: ci/upload-artifact
        with:
          name: bin
          path: target/release/app

  deploy:
    uses: prod-runners
    needs: [build]
    if: ${{ needs.build.result == 'success' }}
    vm:
      driver: kvm
      image: ubuntu:24.04
    steps:
      - run: ./deploy.sh
"#;

    fn parse(yaml: &str) -> Result<Workflow, WorkflowError> {
        Workflow::parse(".ci/workflows/build.yml", yaml)
    }

    /// This repository's own `.ci/workflows/*.yml`, parsed and planned from
    /// disk.
    ///
    /// Everywhere else a workflow is a string in a test. These files are the
    /// real thing: they are submitted to a live orchestrator, where a typo is a
    /// rejected submit somebody is waiting on rather than a compile error — and
    /// `deny_unknown_fields` means a misspelling like `stpes:` is a hard parse
    /// failure. This crate also builds itself, so its own workflow being wrong
    /// breaks its own CI. Reading them here moves that failure into
    /// `cargo test`, where it costs seconds.
    ///
    /// Resolved from `CARGO_MANIFEST_DIR` rather than the working directory,
    /// and one level up from it: since the subtree merge this crate is `ci/`
    /// inside the monorepo, while the workflows it must satisfy live at the
    /// repository root, which is the only place `ci` reads them from. So this
    /// now checks every workflow here — `app-lb.yml`, `app-obs.yml` and `codegraph.yml` as well
    /// as this crate's own — which is strictly more than it covered before.
    #[test]
    fn this_repositorys_own_workflows_parse_and_plan() {
        let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.ci/workflows"));
        let mut checked = 0;
        let mut releases = 0;
        for entry in std::fs::read_dir(dir)
            .expect(".ci/workflows exists")
            .flatten()
        {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yml") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("readable");
            let wf = Workflow::parse(&path.display().to_string(), &text)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let plan = crate::plan::Plan::build(&wf).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            if wf.on.iter().any(|t| t == "release") {
                assert_eq!(wf.on, ["release"]);
                crate::submission::validate_release_plan(&plan).unwrap();
                releases += 1;
            } else {
                assert!(wf.on.iter().any(|t| t == "submit"), "{} has no submission trigger", path.display());
                crate::submission::validate_validation_plan(&plan).unwrap();
            }
            checked += 1;
        }
        // Without this the test passes by finding nothing, which is exactly what
        // happens if the directory is ever renamed.
        assert!(checked > 0, "no workflow files found in {}", dir.display());
        assert_eq!(releases, 1, "exactly one coordinator must own publication");
    }

    #[test]
    fn the_sample_workflow_parses() {
        let wf = parse(SAMPLE).expect("parses");
        assert_eq!(wf.name.as_deref(), Some("build"));
        assert_eq!(wf.on, ["submit"]);
        assert_eq!(wf.env.get("CARGO_TERM_COLOR").unwrap(), "never");
        assert_eq!(wf.jobs.len(), 2);
    }

    /// A workflow reads top to bottom; a `BTreeMap` would render `deploy`
    /// before `build`.
    #[test]
    fn jobs_keep_the_order_the_author_wrote() {
        let wf = parse(SAMPLE).unwrap();
        let ids: Vec<&str> = wf.jobs.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["build", "deploy"]);
    }

    #[test]
    fn uses_names_a_network_a_node_and_optionally_a_vm() {
        assert_eq!(
            Target::parse("prod-runners/bigbox").unwrap(),
            Target {
                network: Some("prod-runners".into()),
                node: Some("bigbox".into()),
                vm: None,
                local: false,
            }
        );
        // Three segments: an existing VM on a named host. The `vm:` block is
        // unused and every step execs into it.
        let existing = Target::parse("prod-runners/bigbox/sb-1a34").unwrap();
        assert_eq!(
            existing,
            Target {
                network: Some("prod-runners".into()),
                node: Some("bigbox".into()),
                vm: Some("sb-1a34".into()),
                local: false,
            }
        );
        assert!(existing.is_existing_vm());
        assert!(
            !Target::parse("prod-runners/bigbox")
                .unwrap()
                .is_existing_vm()
        );

        // Both spellings of "any host in this network".
        for raw in ["prod-runners", "prod-runners/*"] {
            assert_eq!(
                Target::parse(raw).unwrap(),
                Target {
                    network: Some("prod-runners".into()),
                    node: None,
                    vm: None,
                    local: false,
                },
                "{raw}"
            );
        }

        assert_eq!(Target::parse("  ").unwrap_err(), WorkflowError::EmptyUses);
        assert!(matches!(
            Target::parse("net/").unwrap_err(),
            WorkflowError::EmptyRunner(_)
        ));
    }

    /// `default` is the one form that names no network: it is whatever host
    /// this orchestrator is running on.
    #[test]
    fn default_names_the_orchestrators_own_host() {
        for raw in ["default", "DEFAULT", "  default  "] {
            let t = Target::parse(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}"));
            assert!(t.local, "{raw}");
            assert_eq!(t.network, None);
            assert_eq!(t.node, None);
            assert_eq!(t.vm, None);
            assert_eq!(t.to_string(), "default");
        }
        // Absent `uses:` is a different thing: the repository's assigned
        // network, any host. Conflating the two would send every unpinned job
        // to the orchestrator's own machine.
        assert!(!Target::any().local);
    }

    /// The grammar exists so `uses:` alone can place a job. A VM without its
    /// host would put the lookup back, since a sandbox does not record one.
    #[test]
    fn a_vm_must_be_named_with_its_host() {
        assert!(matches!(
            Target::parse("prod-runners/*/sb-1").unwrap_err(),
            WorkflowError::VmWithoutNode(_)
        ));
        let e = Target::parse("prod-runners/*/sb-1")
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not record its host"), "{e}");

        assert!(matches!(
            Target::parse("a/b/c/d").unwrap_err(),
            WorkflowError::UsesTooDeep(_)
        ));
        // A `*` in the VM position cannot be exec'd into, so it is refused
        // rather than quietly meaning "build one".
        assert!(matches!(
            Target::parse("net/node/*").unwrap_err(),
            WorkflowError::EmptyRunner(_)
        ));
    }

    /// Every form has to survive the round trip through `ci_job.plan`, and a
    /// plan written before `node` existed still has to route.
    #[test]
    fn targets_round_trip_through_the_stored_plan() {
        for raw in [
            "default",
            "prod-runners",
            "prod-runners/bigbox",
            "prod-runners/bigbox/sb-1a34",
        ] {
            let t = Target::parse(raw).unwrap();
            let json = serde_json::to_string(&t).unwrap();
            let back: Target = serde_json::from_str(&json).unwrap();
            assert_eq!(t, back, "{raw} -> {json}");
        }

        // The compatibility that matters on deploy day: a job queued by an
        // older build spells the host `runner`.
        let old: Target =
            serde_json::from_str(r#"{"network":"prod-runners","runner":"bigbox"}"#).unwrap();
        assert_eq!(old.node.as_deref(), Some("bigbox"));
        assert_eq!(old.vm, None);
        assert!(!old.local);
    }

    /// An absent `uses:` inherits the workflow object's network.
    #[test]
    fn a_job_without_uses_targets_anything() {
        let wf = parse(
            r#"
jobs:
  a:
    vm: { driver: firecracker }
    steps: [{ run: "true" }]
"#,
        )
        .unwrap();
        assert_eq!(wf.jobs[0].1.target().unwrap(), Target::any());
    }

    #[test]
    fn pinning_does_not_silently_migrate_by_default() {
        let wf = parse(SAMPLE).unwrap();
        assert_eq!(wf.jobs[0].1.fallback, Fallback::None);
        let wf = parse(
            r#"
jobs:
  a:
    uses: net/host
    fallback: any
    vm: { driver: firecracker }
    steps: [{ run: "true" }]
"#,
        )
        .unwrap();
        assert_eq!(wf.jobs[0].1.fallback, Fallback::Any);
    }

    #[test]
    fn a_needs_cycle_is_reported_with_its_path() {
        let err = parse(
            r#"
jobs:
  a:
    needs: [c]
    vm: { driver: firecracker }
    steps: [{ run: "true" }]
  b:
    needs: [a]
    vm: { driver: firecracker }
    steps: [{ run: "true" }]
  c:
    needs: [b]
    vm: { driver: firecracker }
    steps: [{ run: "true" }]
"#,
        )
        .unwrap_err();
        match &err {
            WorkflowError::Cycle(path) => {
                assert!(path.len() >= 3, "{path:?}");
                assert!(err.to_string().contains("->"), "{err}");
            }
            other => panic!("expected a cycle, got {other:?}"),
        }
    }

    #[test]
    fn a_job_needing_itself_is_rejected() {
        let err = parse(
            r#"
jobs:
  a:
    needs: [a]
    vm: { driver: firecracker }
    steps: [{ run: "true" }]
"#,
        )
        .unwrap_err();
        assert_eq!(err, WorkflowError::SelfNeed("a".into()));
    }

    #[test]
    fn a_need_on_an_unknown_job_names_both() {
        let err = parse(
            r#"
jobs:
  a:
    needs: [nope]
    vm: { driver: firecracker }
    steps: [{ run: "true" }]
"#,
        )
        .unwrap_err();
        assert_eq!(
            err,
            WorkflowError::UnknownNeed {
                job: "a".into(),
                need: "nope".into()
            }
        );
        assert!(err.to_string().contains("nope"));
    }

    /// The error has to name the job, not a line offset into a merged document.
    #[test]
    fn a_malformed_job_names_the_job() {
        let err = parse(
            r#"
jobs:
  build:
    vm: { driver: firecracker }
    steps: [{ run: "true" }]
  broken:
    vm: { driver: nonsense }
    steps: [{ run: "true" }]
"#,
        )
        .unwrap_err();
        match &err {
            WorkflowError::BadJob { job, .. } => assert_eq!(job, "broken"),
            other => panic!("expected BadJob, got {other:?}"),
        }
        assert!(err.to_string().contains("broken"), "{err}");
    }

    #[test]
    fn a_step_must_be_run_or_uses_but_not_both() {
        let err = parse(
            r#"
jobs:
  a:
    vm: { driver: firecracker }
    steps:
      - run: "true"
        uses: ci/upload-artifact
"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, WorkflowError::StepRunAndUses { .. }),
            "{err:?}"
        );

        let err = parse(
            r#"
jobs:
  a:
    vm: { driver: firecracker }
    steps:
      - name: nothing
"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, WorkflowError::StepNeitherRunNorUses { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn libvirt_is_rejected_and_names_the_job() {
        let err = parse(
            r#"
jobs:
  a:
    vm: { driver: libvirt }
    steps: [{ run: "true" }]
"#,
        )
        .unwrap_err();
        match &err {
            WorkflowError::BadVm { job, detail } => {
                assert_eq!(job, "a");
                assert!(detail.contains("firecracker"), "{detail}");
            }
            other => panic!("expected BadVm, got {other:?}"),
        }
    }

    /// Job ids reach NATS subjects and VM names unescaped.
    #[test]
    fn job_ids_are_charset_restricted() {
        assert!(is_job_id("build"));
        assert!(is_job_id("build-x86_64"));
        assert!(!is_job_id(""));
        assert!(!is_job_id("build.release"));
        assert!(!is_job_id("build release"));
        assert!(!is_job_id(&"a".repeat(65)));

        let err = parse(
            r#"
jobs:
  "build.release":
    vm: { driver: firecracker }
    steps: [{ run: "true" }]
"#,
        )
        .unwrap_err();
        assert!(matches!(err, WorkflowError::BadJobId(_)), "{err:?}");
    }

    /// A typo in a field name silently doing nothing is the worst failure mode
    /// a workflow file has — `deny_unknown_fields` turns it into a parse error.
    #[test]
    fn an_unknown_field_is_a_parse_error_rather_than_ignored() {
        let err = parse(
            r#"
jobs:
  a:
    vm: { driver: firecracker }
    stpes: [{ run: "true" }]
"#,
        )
        .unwrap_err();
        assert!(matches!(err, WorkflowError::BadJob { .. }), "{err:?}");

        let err = parse(
            r#"
jobs:
  a:
    vm: { driver: firecracker }
    steps:
      - run: "true"
        timeout_minutes: 5
"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, WorkflowError::BadJob { .. }),
            "timeout_minutes is spelled timeout-minutes: {err:?}"
        );
    }

    #[test]
    fn a_workflow_with_no_jobs_is_rejected() {
        assert!(matches!(
            parse("name: empty\njobs: {}\n").unwrap_err(),
            WorkflowError::NoJobs(_)
        ));
    }

    #[test]
    fn a_job_with_no_steps_is_rejected() {
        let err = parse(
            r#"
jobs:
  a:
    vm: { driver: firecracker }
    steps: []
"#,
        )
        .unwrap_err();
        assert_eq!(err, WorkflowError::NoSteps("a".into()));
    }

    #[test]
    fn triggers_parse_in_all_three_spellings() {
        for (yaml, want) in [
            ("on: submit", vec!["submit"]),
            ("on: [submit, schedule]", vec!["submit", "schedule"]),
            ("on:\n  submit:\n    branches: [main]", vec!["submit"]),
        ] {
            let wf = parse(&format!(
                "{yaml}\njobs:\n  a:\n    vm: {{ driver: firecracker }}\n    steps: [{{ run: \"true\" }}]\n"
            ))
            .unwrap();
            assert_eq!(wf.on, want, "{yaml}");
        }
        // Absent `on:` defaults to submit, the only trigger there is.
        let wf =
            parse("jobs:\n  a:\n    vm: { driver: firecracker }\n    steps: [{ run: \"true\" }]\n")
                .unwrap();
        assert_eq!(wf.on, ["submit"]);
    }

    fn with_on(block: &str) -> Result<Workflow, WorkflowError> {
        parse(&format!(
            "{block}\njobs:\n  a:\n    vm: {{ driver: firecracker }}\n    steps: [{{ run: \"true\" }}]\n"
        ))
    }

    fn changed(paths: &[&str]) -> Changes {
        Changes::known(paths.iter().map(|s| s.to_string()).collect())
    }

    /// The regression this whole block exists for. `on: { submit: { branches:
    /// [main] } }` used to parse — only the mapping's *keys* were read — and
    /// then build every branch anyway, with nothing reporting that the filter
    /// had been dropped.
    #[test]
    fn a_filter_block_is_read_rather_than_discarded() {
        let wf = with_on("on:\n  submit:\n    branches: [main]\n    paths: ['api/**']").unwrap();
        assert_eq!(wf.on_submit.branches, ["main"]);
        assert_eq!(wf.on_submit.paths, ["api/**"]);

        // The three spellings that carry no block all mean "no filters".
        for block in ["on: submit", "on: [submit]", "on:\n  submit:"] {
            let wf = with_on(block).unwrap_or_else(|e| panic!("{block}: {e}"));
            assert_eq!(wf.on_submit, SubmitFilter::default(), "{block}");
            assert_eq!(wf.on_submit.admits("anything", &changed(&["x"])), Ok(()));
        }
    }

    /// The same rule the rest of this file applies to `stpes:`: a misspelled
    /// filter name is a parse error, not a filter that silently does nothing.
    #[test]
    fn a_misspelled_filter_is_a_parse_error() {
        for bad in ["path", "branch", "paths_ignore", "on-paths"] {
            let err = with_on(&format!("on:\n  submit:\n    {bad}: ['a/**']"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("paths-ignore"), "{bad}: {err}");
        }
        // A scalar where a list belongs is caught by the same route.
        assert!(with_on("on:\n  submit:\n    paths: 'api/**'").is_err());
    }

    #[test]
    fn conflicting_filters_are_refused_rather_than_ordered() {
        let err =
            with_on("on:\n  submit:\n    paths: ['a/**']\n    paths-ignore: ['b/**']").unwrap_err();
        assert!(
            matches!(err, WorkflowError::ConflictingFilter { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("order"), "{err}");

        let err = with_on("on:\n  submit:\n    branches: [main]\n    branches-ignore: [dev]")
            .unwrap_err();
        assert!(
            matches!(err, WorkflowError::ConflictingFilter { .. }),
            "{err:?}"
        );
    }

    /// `!` in a `paths:` list is GitHub's spelling and is order-dependent, so it
    /// is refused with the spelling that is not.
    #[test]
    fn a_negated_pattern_names_paths_ignore() {
        let err = with_on("on:\n  submit:\n    paths: ['!docs/**']")
            .unwrap_err()
            .to_string();
        assert!(err.contains("paths-ignore"), "{err}");
        assert!(err.contains("docs/**"), "{err}");
    }

    /// The monorepo decision, both ways.
    #[test]
    fn paths_admit_only_a_submit_that_touched_them() {
        let wf = with_on("on:\n  submit:\n    paths: ['packages/api/**', 'Cargo.lock']").unwrap();
        let f = &wf.on_submit;

        assert_eq!(
            f.admits("main", &changed(&["packages/api/src/main.rs"])),
            Ok(())
        );
        assert_eq!(f.admits("main", &changed(&["Cargo.lock"])), Ok(()));

        let why = f
            .admits("main", &changed(&["packages/web/index.html"]))
            .unwrap_err();
        assert!(why.contains("packages/api/**"), "{why}");
        assert!(why.contains("1 path(s) changed"), "{why}");
    }

    /// `paths-ignore` skips only when *nothing* in the commit is interesting.
    #[test]
    fn paths_ignore_needs_every_path_to_match() {
        let wf = with_on("on:\n  submit:\n    paths-ignore: ['docs/**', '*.md']").unwrap();
        let f = &wf.on_submit;

        assert!(
            f.admits("main", &changed(&["docs/a.txt", "README.md"]))
                .is_err()
        );
        // One interesting file is enough to build.
        assert_eq!(
            f.admits("main", &changed(&["docs/a.txt", "src/main.rs"])),
            Ok(())
        );
        // A commit that changed nothing is not a commit that changed only docs.
        assert_eq!(f.admits("main", &changed(&[])), Ok(()));
    }

    #[test]
    fn branch_filters_use_the_same_glob_dialect() {
        let wf = with_on("on:\n  submit:\n    branches: [main, 'release/*']").unwrap();
        let f = &wf.on_submit;
        assert_eq!(f.admits("main", &changed(&["x"])), Ok(()));
        assert_eq!(f.admits("release/1.2", &changed(&["x"])), Ok(()));
        // `*` does not cross a separator, so a nested branch is not a release.
        assert!(f.admits("release/1.2/rc", &changed(&["x"])).is_err());
        let why = f.admits("feature/x", &changed(&["x"])).unwrap_err();
        assert!(why.contains("feature/x"), "{why}");

        let wf = with_on("on:\n  submit:\n    branches-ignore: ['wip/**']").unwrap();
        assert!(wf.on_submit.admits("wip/a/b", &changed(&["x"])).is_err());
        assert_eq!(wf.on_submit.admits("main", &changed(&["x"])), Ok(()));
    }

    /// The safety property, at the level that decides whether a build happens:
    /// a submit whose diff could not be read must build, not skip.
    #[test]
    fn an_unknown_change_set_still_builds_a_path_filtered_workflow() {
        let unknown = Changes::unknown("a tarball carries no history");

        let wf = with_on("on:\n  submit:\n    paths: ['packages/api/**']").unwrap();
        assert_eq!(wf.on_submit.admits("main", &unknown), Ok(()));

        // And `paths-ignore` must not skip on no answer either — that is the
        // case a bare `.all()` gets wrong, because all-of-nothing is true.
        let wf = with_on("on:\n  submit:\n    paths-ignore: ['**']").unwrap();
        assert_eq!(wf.on_submit.admits("main", &unknown), Ok(()));
    }

    /// A branch filter is decided without reading the diff at all, so it holds
    /// for the submits that have no diff to read.
    #[test]
    fn branch_filters_do_not_depend_on_the_change_set() {
        let wf = with_on("on:\n  submit:\n    branches: [main]").unwrap();
        let unknown = Changes::unknown("no parent");
        assert!(wf.on_submit.admits("feature/x", &unknown).is_err());
        assert_eq!(wf.on_submit.admits("main", &unknown), Ok(()));
    }

    #[test]
    fn step_labels_fall_back_sensibly() {
        let wf = parse(SAMPLE).unwrap();
        let steps = &wf.jobs[0].1.steps;
        assert_eq!(steps[0].label(0), "Build");
        assert_eq!(steps[1].label(1), "ci/upload-artifact");

        let long = Step {
            name: None,
            id: None,
            condition: None,
            uses: None,
            with: BTreeMap::new(),
            run: Some(format!("echo {}", "x".repeat(200))),
            shell: None,
            working_directory: None,
            env: BTreeMap::new(),
            timeout_minutes: None,
            continue_on_error: false,
        };
        let label = long.label(0);
        assert!(label.chars().count() <= 60, "{label}");
        assert!(label.ends_with('…'));
    }
}

#[cfg(test)]
mod repo_workflow {
    use super::*;

    /// This crate's own `.ci/workflows/ci.yml` must parse and plan.
    ///
    /// It is the worked example the README points at, so a change that breaks
    /// it breaks the documentation too — and it is the workflow that builds
    /// this binary, so breaking it breaks the only route by which a fix for
    /// breaking it can ship.
    ///
    /// Named `ci.yml` at the repository root, not `build.yml` beside this
    /// crate: the subtree merge moved it there, because that is the one
    /// location `ci` looks for workflows in a submitted tree.
    #[test]
    fn this_repositorys_own_workflow_is_valid() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../.ci/workflows/ci.yml");
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("{path} must exist and be readable: {e}"));

        let wf =
            Workflow::parse(path, &text).unwrap_or_else(|e| panic!("{path} does not parse: {e}"));
        assert!(wf.on.iter().any(|t| t == "submit"));

        let plan =
            crate::plan::Plan::build(&wf).unwrap_or_else(|e| panic!("{path} does not plan: {e}"));
        assert_eq!(plan.jobs.len(), 1);
        crate::submission::validate_validation_plan(&plan).unwrap();
        let validate = plan.jobs.iter().find(|j| j.base_id == "release").unwrap();
        assert!(!validate.target.local, "CI builds must not pin the controller host");
        assert!(wf.on_submit.paths.iter().any(|p| p == "app-lb/src/host_bundle.rs"),
            "CI must rebuild when its shared archive validator changes");
        assert!(validate.condition.as_deref().unwrap().contains("'app-lb/src/host_bundle.rs'"),
            "the job filter must not skip a shared archive validator change");
        assert!(validate.steps.iter().any(|s| s.run.as_deref().is_some_and(|s|
            s == "cargo test --release --locked -- --test-threads=1")));

        // Every `uses:` step in it must name an action that exists, or the
        // build fails at the step rather than at parse time.
        for job in &plan.jobs {
            for step in &job.steps {
                if let Some(action) = &step.uses {
                    assert!(
                        matches!(action.as_str(), "ci/upload-artifact"),
                        "{path} uses {action:?}, which is not a built-in action"
                    );
                }
            }
        }
    }

    /// `app-lb.yml` is two jobs so a failed-only re-run carries a passed one
    /// over. `release` must keep its name (the artifact tag is
    /// `ci-app-lb-<run>-release-app-lb`) and must wait for `protocol`, and the
    /// two must share one VM definition so they share a warm pool.
    #[test]
    fn app_lb_release_waits_for_the_protocol_job_and_shares_its_vm() {
        let text = include_str!("../../.ci/workflows/app-lb.yml");
        let wf = Workflow::parse("app-lb.yml", text).unwrap();
        let plan = crate::plan::Plan::build(&wf).unwrap();
        let ids: Vec<_> = plan.jobs.iter().map(|j| j.base_id.as_str()).collect();
        assert_eq!(ids, ["protocol", "release"], "dependency order");
        assert_eq!(plan.jobs[1].needs, ["protocol"]);
        assert!(plan.jobs[0].needs.is_empty());
        let job = |name: &str| &wf.jobs.iter().find(|(n, _)| n == name).expect(name).1;
        assert_eq!(
            format!("{:?}", job("protocol").vm),
            format!("{:?}", job("release").vm),
            "one warm pool"
        );
        let names = |name: &str| -> Vec<String> {
            job(name).steps.iter().filter_map(|s| s.name.clone()).collect()
        };
        assert_eq!(names("protocol")[0], "Guard the cache disk");
        assert!(names("protocol").iter().any(|n| n == "Verify proxy protocol compatibility"));
        assert!(!names("release").iter().any(|n| n.contains("protocol")));
        assert!(!text.contains("apt-get install"), "tools are baked into the image");
    }

    #[test]
    fn regional_release_orders_regions_and_selects_exact_validation_artifacts() {
        let text = include_str!("../../.ci/workflows/regional-release.yml");
        let wf = Workflow::parse("regional-release.yml", text).unwrap();
        assert_eq!(wf.on, ["release"]);
        let plan = crate::plan::Plan::build(&wf).unwrap();
        crate::submission::validate_release_plan(&plan).unwrap();
        assert_eq!(plan.jobs.iter().map(|j| j.base_id.as_str()).collect::<Vec<_>>(),
            ["merge", "us3", "eu1", "poolers", "controller"]);
        for (i, predecessor) in [(1, "merge"), (2, "us3"), (3, "eu1"), (4, "poolers")] {
            assert_eq!(plan.jobs[i].needs, [predecessor]);
            assert!(plan.jobs[i].condition.is_none(), "do not skip a dependency stage");
        }
        let preflight = include_str!("../../.ci/diagnostics/regional-rollout-preflight.yml");
        for (i, region, deployment) in [(1, "us3", "orchestrator-us3"), (2, "eu1", "orchestrator-eu1")] {
            let steps = &plan.jobs[i].steps;
            assert_eq!(steps[0].uses.as_deref(), Some("ci/rollout-host-app-lb"));
            assert_eq!(steps[0].with["target"], format!("app-lb-{region}"));
            assert_eq!(steps[1].uses.as_deref(), Some("ci/rollout-service"));
            assert_eq!(steps[1].with["deployment"], deployment);
            assert!(preflight.contains(&format!("('{region}', '{deployment}')")),
                "preflight and release must use the canonical service identity, not a candidate alias");
            assert_eq!(steps[1].with["url"], format!("https://admin.{region}.heyo.work"));
            assert_eq!(steps[1].with["mount-path"], "/opt/orchestrator-release",
                "reuse the registered private release mount instead of adding an unauthenticated mount");
        }
        let poolers = &plan.jobs[3].steps;
        assert_eq!(poolers[0].uses.as_deref(), Some("ci/checkout-release"));
        assert_eq!(poolers[1].uses.as_deref(), Some("ci/download-artifact"));
        assert_eq!(poolers[1].with["workflow"], ".ci/workflows/pg-fc.yml");
        assert_eq!(poolers[1].with["name"], "pg-fc");
        assert!(poolers[2].run.as_deref().unwrap().contains("python3 pg-fc/deploy/rollout_poolers.py pg-fc-release.tar.gz"));
        assert_eq!(plan.jobs[4].steps.last().unwrap().uses.as_deref(), Some("ci/deploy-controller"));

        // Exercise asymmetric changes: a shared parser affects CI and app-lb,
        // release-mount extraction affects app-lb and its mounted service, while
        // a service-only edit must not silently demand an absent bundle.
        for (path, expected) in [
            ("app-lb/src/main.rs", vec!["app-lb"]),
            ("app-lb/src/host_bundle.rs", vec!["app-lb", "ci"]),
            ("app-lb/src/unpack.rs", vec!["app-lb", "orchestrator-linux"]),
            ("ci/src/main.rs", vec!["ci"]),
            ("orchestrator/src/main.rs", vec!["orchestrator-linux"]),
            ("heyosecret-client/src/lib.rs", vec!["orchestrator-linux"]),
            ("pg-fc/src/main.rs", vec!["pg-fc"]),
            (".ci/workflows/pg-fc.yml", vec!["pg-fc"]),
            (".ci/image/ci/Dockerfile", vec!["ci", "orchestrator-linux", "pg-fc"]),
            (".ci/image/apps/Dockerfile", vec!["app-lb"]),
            (".ci/workflows/regional-release.yml", vec!["app-lb", "ci", "orchestrator-linux", "pg-fc"]),
            ("README.md", vec![]),
        ] {
            let changes = crate::paths::Changes::known(vec![path.into()]);
            let mut ctx = crate::expr::Context::new();
            ctx.set("ci", serde_json::json!({"changes_known":true,"changed_files":[path]}));
            for step in poolers {
                assert_eq!(ctx.eval_condition(step.condition.as_deref().unwrap()).unwrap(),
                    expected.contains(&"pg-fc"), "{path}: pooler steps must select together");
            }
            for step in plan.jobs.iter().skip(1).flat_map(|j| &j.steps) {
                if !step.with.contains_key("workflow") {
                    continue;
                }
                let validation_path = &step.with["workflow"];
                let artifact = step.with.get("artifact").or_else(|| step.with.get("name")).unwrap();
                let yaml = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(validation_path)).unwrap();
                let validation = Workflow::parse(validation_path, &yaml).unwrap();
                let build = crate::plan::Plan::build(&validation).unwrap();
                crate::submission::validate_validation_plan(&build).unwrap();
                let selected = ctx.eval_condition(step.condition.as_deref().unwrap()).unwrap();
                assert_eq!(selected, expected.contains(&artifact.as_str()), "{path}: {validation_path}");
                assert_eq!(selected, validation.on_submit.admits("feature", &changes).is_ok(), "{path}: {validation_path}");
                if selected {
                    assert!(build.jobs.iter().all(|j| j.condition.as_deref().is_none_or(|c| ctx.eval_condition(c).unwrap())));
                    assert!(build.jobs.iter().flat_map(|j| &j.steps).any(|s|
                        s.uses.as_deref() == Some("ci/upload-artifact") && s.with.get("name") == Some(artifact)));
                }
            }
        }
    }
}
