//! CI workflow objects.
//!
//! app-lb stores these and serves them; the `ci` orchestrator polls
//! `GET /workflows` and does the building. They live here for the same reason
//! deployments and secrets do — one place holds what this fleet knows about, and
//! one CLI manages all of it.
//!
//! ## One file per object, like the registry
//!
//! Not a single `app-lb-workflows.json`, because the registry already learned
//! why: rewriting every object on each change makes a create storm quadratic
//! (`registry.rs:344`). Workflows change far less often than sandboxes, so the
//! argument is weaker here — but the shape is free, and the alternative has a
//! failure mode where one unparseable object loses the rest of the file.
//!
//! An unreadable file is skipped with a warning rather than failing the load.
//! It is still somebody's only copy of a spec, and refusing to start over one
//! bad object takes the whole load balancer down with it.

use crate::config::WorkflowSpec;
use crate::fleet_store::{Collection, Expect, FileCollection, FileOptions};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug)]
pub struct WorkflowStore {
    workflows: ArcSwap<HashMap<String, Arc<WorkflowSpec>>>,
    dir: PathBuf,
    records: Arc<dyn Collection>,
}

impl WorkflowStore {
    /// `dir` is where one JSON file per workflow lives, derived from the state
    /// path the same way the registry derives its own.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let records = Arc::new(FileCollection::new(&dir, ".json", FileOptions::PLAIN));
        Self::with_collection(dir, records)
    }

    /// The same store over another backend. `dir` is only reported in logs.
    pub fn with_collection(dir: impl Into<PathBuf>, records: Arc<dyn Collection>) -> Self {
        Self {
            workflows: ArcSwap::from_pointee(HashMap::new()),
            dir: dir.into(),
            records,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn list(&self) -> Vec<Arc<WorkflowSpec>> {
        let mut out: Vec<_> = self.workflows.load().values().cloned().collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub fn get(&self, id: &str) -> Option<Arc<WorkflowSpec>> {
        self.workflows.load().get(id).cloned()
    }

    /// Insert or replace, then persist. Validation is the caller's, so a handler
    /// can answer 400 before anything is stored.
    pub fn upsert(&self, spec: WorkflowSpec) -> Result<Arc<WorkflowSpec>, std::io::Error> {
        let spec = Arc::new(spec);
        let mut next = (**self.workflows.load()).clone();
        next.insert(spec.id.clone(), spec.clone());
        self.workflows.store(Arc::new(next));
        self.persist_one(&spec)?;
        Ok(spec)
    }

    /// Returns whether anything was removed, so a handler can answer 404.
    pub fn remove(&self, id: &str) -> Result<bool, std::io::Error> {
        let mut next = (**self.workflows.load()).clone();
        let existed = next.remove(id).is_some();
        self.workflows.store(Arc::new(next));
        if existed {
            // Already gone is the desired end state.
            self.records.delete(&key(id), Expect::Any)?;
        }
        Ok(existed)
    }

    /// Write-then-rename, so a reader never sees a half-written object and a
    /// crash mid-write leaves the previous version intact.
    fn persist_one(&self, spec: &WorkflowSpec) -> Result<(), std::io::Error> {
        let json = serde_json::to_vec_pretty(spec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.records.put(&key(&spec.id), &json, Expect::Any)?;
        Ok(())
    }

    /// Load every object from disk, skipping any that will not parse.
    ///
    /// Returns how many were skipped, so the caller can log it. A skipped object
    /// is not fatal but is not nothing either — it means somebody's workflow
    /// stopped running for a reason nothing else will mention.
    pub fn load(&self) -> (usize, usize) {
        let mut loaded = HashMap::new();
        let mut skipped = 0usize;

        let entries = match self.records.list() {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(dir = %self.dir.display(), error = %e, "could not list workflow objects");
                return (0, 0);
            }
        };
        for entry in entries {
            match entry
                .body
                .ok()
                .and_then(|b| serde_json::from_slice::<WorkflowSpec>(&b).ok())
            {
                Some(spec) if spec.validate().is_ok() => {
                    loaded.insert(spec.id.clone(), Arc::new(spec));
                }
                _ => {
                    tracing::warn!(
                        "skipping unreadable workflow object {}; it is still on disk",
                        entry.location
                    );
                    skipped += 1;
                }
            }
        }
        let count = loaded.len();
        self.workflows.store(Arc::new(loaded));
        (count, skipped)
    }
}

/// A filename that cannot escape the directory whatever the id contains.
///
/// Ids are already restricted by `WorkflowSpec::validate`, but a file on disk
/// may predate a validation change, so the encoding is applied unconditionally.
/// The store key: [`file_name`] without its `.json`.
fn key(id: &str) -> String {
    let mut name = file_name(id);
    name.truncate(name.len() - ".json".len());
    name
}

fn file_name(id: &str) -> String {
    let mut out = String::with_capacity(id.len() + 5);
    for b in id.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out.push_str(".json");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SpecError;

    fn spec(id: &str) -> WorkflowSpec {
        WorkflowSpec {
            id: id.to_string(),
            repo: "git@github.com:me/app.git".into(),
            git_ref: "main".into(),
            path: ".ci/workflows/*.yml".into(),
            network: "prod-runners".into(),
            auth: None,
            secrets_prefix: None,
            enabled: true,
        }
    }

    fn store() -> (WorkflowStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "app-lb-wf-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        (WorkflowStore::new(dir.clone()), dir)
    }

    #[test]
    fn a_workflow_round_trips_through_disk() {
        let (s, dir) = store();
        s.upsert(spec("build")).unwrap();
        assert_eq!(s.get("build").unwrap().network, "prod-runners");

        let reloaded = WorkflowStore::new(dir.clone());
        let (count, skipped) = reloaded.load();
        assert_eq!((count, skipped), (1, 0));
        assert_eq!(reloaded.get("build").unwrap().repo, "git@github.com:me/app.git");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn listing_is_sorted_so_a_ui_does_not_reshuffle() {
        let (s, dir) = store();
        for id in ["zeta", "alpha", "mid"] {
            s.upsert(spec(id)).unwrap();
        }
        let ids: Vec<String> = s.list().iter().map(|w| w.id.clone()).collect();
        assert_eq!(ids, ["alpha", "mid", "zeta"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn removing_is_idempotent_and_reports_whether_it_existed() {
        let (s, dir) = store();
        s.upsert(spec("build")).unwrap();
        assert!(s.remove("build").unwrap());
        assert!(!s.remove("build").unwrap(), "already gone is not an error");
        assert!(s.get("build").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// One bad object must not take the rest of the fleet's workflows with it —
    /// still less refuse to start the load balancer.
    #[test]
    fn an_unreadable_object_is_skipped_rather_than_failing_the_load() {
        let (s, dir) = store();
        s.upsert(spec("good")).unwrap();
        std::fs::write(dir.join("broken.json"), b"{not json").unwrap();
        // Parses, but fails validation: an id that would break a NATS subject.
        std::fs::write(
            dir.join("invalid.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": "has spaces", "repo": "r", "ref": "main",
                "path": ".ci/workflows/*.yml", "network": "n", "enabled": true
            }))
            .unwrap(),
        )
        .unwrap();

        let reloaded = WorkflowStore::new(dir.clone());
        let (count, skipped) = reloaded.load();
        assert_eq!(count, 1, "the good one still loads");
        assert_eq!(skipped, 2);
        assert!(reloaded.get("good").is_some());
        // And the bad files are left on disk rather than cleaned up.
        assert!(dir.join("broken.json").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_directory_is_the_empty_case() {
        let s = WorkflowStore::new(std::env::temp_dir().join("app-lb-wf-does-not-exist"));
        assert_eq!(s.load(), (0, 0));
        assert!(s.list().is_empty());
    }

    /// Ids are validated, but a file could predate that, so the encoding is
    /// unconditional.
    #[test]
    fn a_filename_cannot_escape_the_directory() {
        assert_eq!(file_name("build"), "build.json");
        assert_eq!(file_name("build-x_1"), "build-x_1.json");
        let evil = file_name("../../etc/passwd");
        assert!(!evil.contains('/'), "{evil}");
        assert!(Path::new("/tmp/wf").join(&evil).starts_with("/tmp/wf"));
    }

    #[test]
    fn validation_rejects_what_would_break_a_subject_or_a_path() {
        assert!(spec("build").validate().is_ok());

        let mut s = spec("has spaces");
        assert!(matches!(s.validate(), Err(SpecError::BadWorkflowId(_))));

        s = spec("build");
        s.path = "../../etc".into();
        assert!(matches!(s.validate(), Err(SpecError::BadWorkflowPath(_))));

        s = spec("build");
        s.path = "/absolute".into();
        assert!(matches!(s.validate(), Err(SpecError::BadWorkflowPath(_))));

        s = spec("build");
        s.network = "  ".into();
        assert!(matches!(s.validate(), Err(SpecError::EmptyWorkflowNetwork)));

        s = spec("build");
        s.repo = String::new();
        assert!(matches!(s.validate(), Err(SpecError::EmptyWorkflowRepo)));
    }

    /// Defaults exist so a minimal object is usable, and the wire form must keep
    /// `ref` spelled the way YAML and git spell it.
    #[test]
    fn a_minimal_object_gets_workable_defaults() {
        let w: WorkflowSpec = serde_json::from_str(
            r#"{"id":"build","repo":"git@example.com:me/app.git","network":"prod"}"#,
        )
        .unwrap();
        assert_eq!(w.git_ref, "main");
        assert_eq!(w.path, ".ci/workflows/*.yml");
        assert!(w.enabled);
        assert!(w.validate().is_ok());

        let json = serde_json::to_value(&w).unwrap();
        assert_eq!(json["ref"], "main", "not `git_ref` on the wire");
        assert!(json.get("auth").is_none(), "absent options stay absent");
    }
}

/// Where workflow objects live, derived from the deployment state path.
///
/// `app-lb-state.json` gives `app-lb-workflows.d/`, beside `app-lb-state.d/`.
/// Derived rather than separately configured so an operator who moves the state
/// path takes the workflows with it.
pub fn workflow_dir(state_path: &str) -> PathBuf {
    crate::fleet_store::sibling_dir(state_path, "workflows")
}

#[cfg(test)]
mod dir_tests {
    use super::*;

    /// Moving the state path has to take the workflows with it, or an operator
    /// who relocates one finds the other still in the old place.
    #[test]
    fn the_directory_follows_the_state_path() {
        assert_eq!(
            workflow_dir("app-lb-state.json"),
            PathBuf::from("app-lb-workflows.d")
        );
        assert_eq!(
            workflow_dir("/var/lib/app-lb/app-lb-state.json"),
            PathBuf::from("/var/lib/app-lb/app-lb-workflows.d")
        );
        // A non-standard stem still gets a distinct, adjacent directory.
        assert_eq!(
            workflow_dir("/srv/custom.json"),
            PathBuf::from("/srv/custom-workflows.d")
        );
    }
}
