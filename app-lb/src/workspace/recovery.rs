//! Explicit selection of one retained workspace lineage. This never resumes,
//! stops, deletes, or rewrites the seed of the selected source.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRequest {
    pub operation_id: String,
    pub source_sandbox_id: String,
    pub expected_snapshot: String,
    pub confirm_replace: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recovery {
    pub request: RecoveryRequest,
    pub deployment: String,
    pub namespace: String,
    pub spec_sha256: String,
    pub guest_path: String,
    pub status: String,
    pub snapshot: Option<String>,
    pub error: Option<String>,
}

fn spec_hash(spec: &DeploymentSpec) -> String {
    let mut value = serde_json::to_value(spec).expect("deployment serializes");
    value.sort_all_objects();
    hex(&Sha256::digest(serde_json::to_vec(&value).expect("JSON")))
}

impl Workspaces {
    pub fn attach_disk_store(&self, disks: &Arc<crate::disks::DiskStore>) {
        *self.disk_store.lock().unwrap() = Arc::downgrade(disks);
    }

    pub fn source_retained(&self, sandbox_id: &str) -> bool {
        self.recovery_pinned(sandbox_id) || self.disk_store.lock().unwrap().upgrade().is_some_and(|s| s.is_retained(sandbox_id))
    }

    pub async fn lifecycle_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.lifecycle.lock().await
    }

    pub fn recovery_active(&self, id: &str) -> bool {
        let record = self.record(id);
        record.recoveries.iter().any(|o| o.status != "succeeded")
            || !record.recoveries.is_empty() && self.persist_failed(id)
    }

    pub fn has_recovery(&self, id: &str) -> bool { !self.record(id).recoveries.is_empty() }

    pub fn recovery_pinned(&self, sandbox_id: &str) -> bool {
        self.records.lock().unwrap().values().any(|r| r.recoveries.iter().any(|o| o.request.source_sandbox_id == sandbox_id))
    }

    pub fn recovery_pins(&self) -> Vec<String> {
        self.records.lock().unwrap().values().flat_map(|r| r.recoveries.iter().map(|o| o.request.source_sandbox_id.clone())).collect()
    }

    pub fn recovery(&self, id: &str, operation: &str) -> Option<Recovery> {
        let mut o = self.record(id).recoveries.into_iter().find(|o| o.request.operation_id == operation)?;
        if self.persist_failed(id) {
            o.status = "running".into();
            o.error = Some("workspace record persistence pending; creation remains fenced".into());
        }
        Some(o)
    }

    /// Caller holds registry writer, every create permit, and lifecycle guard.
    pub async fn admit_recovery(&self, d: &Arc<Deployment>, request: RecoveryRequest) -> Result<Recovery, String> {
        let id = &d.spec.id;
        if let Some(old) = self.recovery(id, &request.operation_id) {
            return if old.request == request && old.namespace == d.spec.namespace { Ok(old) }
                else { Err("operation_id conflicts with an existing recovery".into()) };
        }
        if !request.confirm_replace || request.operation_id.is_empty() || request.operation_id.len() > 128
            || !request.operation_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || request.expected_snapshot.len() != 64 || !request.expected_snapshot.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !crate::disks::valid_sandbox_id(&request.source_sandbox_id) {
            return Err("explicit confirmation, safe operation/source IDs and exact lowercase snapshot SHA256 are required".into());
        }
        let workspace = d.spec.vm.as_ref().and_then(|v| v.workspace.as_ref()).ok_or("deployment has no workspace")?;
        let record = self.record(id);
        if self.recovery_active(id) || self.persist_failed(id) || record.digest.as_ref() != Some(&request.expected_snapshot)
            || record.replacement_captures_remaining != 1 || !record.pending.is_empty() || !record.initialized || self.runtime(id).1 {
            return Err("snapshot changed, another operation is pending, or replacement fence is not exactly one".into());
        }
        if !d.backends().is_empty() || !d.pending().is_empty() || !d.state().suspended.is_empty() {
            return Err("recovery requires an empty serving, pending and resumable pool".into());
        }
        let seed = record.seeds.get(&request.source_sandbox_id).ok_or("source has no durable workspace ownership record")?;
        if seed.mount_index.is_none() { return Err("source workspace mount identity was not recorded".into()); }
        if self.records.lock().unwrap().iter().any(|(owner, r)| owner != id && r.seeds.contains_key(&request.source_sandbox_id)) {
            return Err("source belongs to another deployment record".into());
        }
        // Legacy seeds carry no namespace; require the durable capture spec as
        // corroborating ownership, never infer it from a caller-supplied name.
        let saved = self.spec_for_orphan(id).ok_or("missing durable workspace capture spec")?;
        if saved.id != *id || saved.namespace != d.spec.namespace
            || saved.vm.as_ref().and_then(|v| v.workspace.as_ref()) != Some(workspace) {
            return Err("recorded workspace namespace/path/store differs from deployment".into());
        }
        let operation = Recovery { request, deployment: id.clone(), namespace: d.spec.namespace.clone(),
            spec_sha256: spec_hash(&d.spec), guest_path: workspace.guest_path().into(),
            status: "running".into(), snapshot: None, error: None };
        self.confirm_recovery_stopped(&operation).await?;
        // Pin and exclusive operation are one durable record. Failed writes
        // retain the in-memory fence; no capture starts before re-persistence.
        self.with_record(id, |r| r.recoveries.push(operation.clone()));
        if self.persist_failed(id) { return Err("could not persist recovery intent; creation remains fenced".into()); }
        self.wake.notify_one();
        Ok(operation)
    }

    async fn confirm_recovery_stopped(&self, operation: &Recovery) -> Result<(), String> {
        let fleet = self.vms.list().await.map_err(|e| format!("cannot verify active fleet: {e}"))?;
        let inactive = self.vms.list_inactive().await.map_err(|e| format!("cannot verify retained source: {e}"))?;
        let mut found = false;
        for info in fleet.iter().chain(inactive.iter()) {
            if info.id == operation.request.source_sandbox_id {
                if info.status != heyo_sdk::SandboxStatus::Stopped || crate::vm::owner_of(&info.name) != Some(operation.deployment.as_str()) {
                    return Err("exact recovery source is not confirmed stopped and owned by this deployment".into());
                }
                found = true;
            } else if crate::vm::owner_of(&info.name) == Some(operation.deployment.as_str())
                && !crate::vm::is_terminal(&info.status) {
                return Err("another workspace VM is active; recovery cannot proceed".into());
            }
        }
        if !found { return Err("retained source is missing; absence is not stopped-state confirmation".into()); }
        Ok(())
    }

    pub(super) async fn run_recovery(&self, d: &Arc<Deployment>) {
        let id = &d.spec.id;
        let Some(operation) = self.record(id).recoveries.into_iter().find(|o| o.status == "running") else { return; };
        let result = self.capture_recovery(d, &operation).await;
        if let Err(error) = result {
            self.with_record(id, |r| {
                if let Some(o) = r.recoveries.iter_mut().find(|o| o.request.operation_id == operation.request.operation_id) { o.error = Some(error.clone()); }
            });
            self.note_error(id, format!("workspace recovery retained its source and fence: {error}"));
        }
    }

    async fn capture_recovery(&self, d: &Arc<Deployment>, operation: &Recovery) -> Result<(), String> {
        let id = &d.spec.id;
        if spec_hash(&d.spec) != operation.spec_sha256 || self.record(id).digest.as_ref() != Some(&operation.request.expected_snapshot)
            || !self.registry.get(id).is_some_and(|live| Arc::ptr_eq(&live, d)) {
            return Err("deployment or snapshot changed after recovery admission".into());
        }
        self.confirm_recovery_stopped(operation).await?;
        // A timed-out blocking tar may still finish. Isolate every attempt so
        // it can never overwrite a committed snapshot or a later attempt.
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        let attempt = self.dir(id).join(format!("recovery-{}-{nonce}", operation.request.operation_id));
        let staging = attempt.join("extracting");
        let captured = tokio::time::timeout(self.cfg.timeout, self.capture_via_daemon(
            &self.cfg, &attempt, &operation.request.source_sandbox_id, &operation.guest_path, &staging))
            .await.map_err(|_| "recovery capture timed out")?.map_err(|e| match e { CaptureError::Stale(e) | CaptureError::Gone(e) | CaptureError::Retry(e) => e })?;
        self.confirm_recovery_stopped(operation).await?;
        let captured_bundle = attempt.join("bundles").join(format!("{}.tar.gz", captured.digest));
        if !verify_file(&captured_bundle, &captured.digest)? { return Err("captured bundle digest did not verify".into()); }
        let captured_tree = attempt.join("snapshots").join(&captured.digest);
        sync_tree(&captured_tree).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(self.dir(id).join("bundles")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(self.dir(id).join("snapshots")).map_err(|e| e.to_string())?;
        let bundle = self.bundle_path(id, &captured.digest);
        let tree = self.tree_path(id, Some(&captured.digest));
        if !tree.exists() { std::fs::rename(&captured_tree, &tree).map_err(|e| e.to_string())?; }
        std::fs::rename(&captured_bundle, &bundle).map_err(|e| e.to_string())?;
        // The tree and bundle must survive a crash before state releases the
        // fence. Do not follow symlinks out of a captured workspace.
        sync_tree(&self.tree_path(id, Some(&captured.digest))).map_err(|e| e.to_string())?;
        for path in [bundle, self.dir(id).join("bundles"), self.dir(id).join("snapshots"), self.dir(id)] {
            std::fs::File::open(path).and_then(|f| f.sync_all()).map_err(|e| e.to_string())?;
        }
        if self.record(id).digest.as_ref() != Some(&operation.request.expected_snapshot) { return Err("snapshot changed before commit".into()); }
        self.with_record(id, |r| {
            r.digest = Some(captured.digest.clone()); r.captured_from = Some(operation.request.source_sandbox_id.clone());
            r.captured_at = Some(now_secs()); r.files = captured.files; r.bytes = captured.bytes;
            r.initialized = true; r.push_pending = true; r.last_error = None;
            r.replacement_captures_remaining = 0;
            let o = r.recoveries.iter_mut().find(|o| o.request.operation_id == operation.request.operation_id).expect("durable recovery");
            o.snapshot = Some(captured.digest.clone()); o.status = "succeeded".into(); o.error = None;
            // Keep the original source seed unchanged and permanently pinned.
        });
        if !self.persist_failed(id) { d.scale_signal.notify_one(); }
        let _ = std::fs::remove_dir_all(attempt); // only this completed extraction, never VM data
        Ok(())
    }
}

fn sync_tree(path: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        for child in std::fs::read_dir(path)? { sync_tree(&child?.path())?; }
        std::fs::File::open(path)?.sync_all()?;
    } else if metadata.is_file() {
        std::fs::File::open(path)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get, extract::State, response::IntoResponse, http::StatusCode};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Daemon {
        active: AtomicBool,
        export_failure: AtomicBool,
        fail_commit: AtomicBool,
        exports: AtomicUsize,
        unexpected: AtomicUsize,
        tmp_state: PathBuf,
        bundle: Vec<u8>,
    }
    struct Fixture {
        ws: Arc<Workspaces>, d: Arc<Deployment>, daemon: Arc<Daemon>,
        root: PathBuf, server: tokio::task::JoinHandle<()>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) { self.server.abort(); let _ = std::fs::remove_dir_all(&self.root); }
    }
    fn request() -> RecoveryRequest {
        RecoveryRequest { operation_id: "repair-1".into(), source_sandbox_id: "sb-retained".into(), expected_snapshot: "a".repeat(64), confirm_replace: true }
    }
    async fn fixture() -> Fixture {
        static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!("workspace-recovery-{}-{}", std::process::id(), SEQUENCE.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&root);
        let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
        let body = b"retained-stream-state\n";
        let mut header = tar::Header::new_gnu(); header.set_size(body.len() as u64); header.set_mode(0o600); header.set_cksum();
        tar.append_data(&mut header, "jetstream/state", body.as_slice()).unwrap();
        let bundle = tar.into_inner().unwrap().finish().unwrap();
        let daemon = Arc::new(Daemon { active: AtomicBool::new(false), export_failure: AtomicBool::new(false), fail_commit: AtomicBool::new(false),
            exports: AtomicUsize::new(0), unexpected: AtomicUsize::new(0), tmp_state: root.join("workspaces/demo/.state.json.tmp"), bundle });
        let app = Router::new()
            .route("/deployed-sandboxes", get(|State(s): State<Arc<Daemon>>| async move {
                axum::Json(if s.active.load(Ordering::SeqCst) { serde_json::json!([{"id":"sb-retained","name":"applb-demo-0000deadbeef","status":"running","status_changed_at":""}]) } else { serde_json::json!([]) })
            }))
            .route("/sandboxes/inactive", get(|| async { axum::Json(serde_json::json!({"sandboxes":[{"id":"sb-retained","name":"applb-demo-0000deadbeef","status":"stopped"}],"next_cursor":null})) }))
            .route("/sandboxes/:id/mounts/export", get(|State(s): State<Arc<Daemon>>| async move {
                s.exports.fetch_add(1, Ordering::SeqCst);
                if s.export_failure.load(Ordering::SeqCst) { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); }
                if s.fail_commit.swap(false, Ordering::SeqCst) { std::fs::create_dir(&s.tmp_state).unwrap(); }
                s.bundle.clone().into_response()
            }))
            .fallback(|State(s): State<Arc<Daemon>>| async move { s.unexpected.fetch_add(1, Ordering::SeqCst); StatusCode::METHOD_NOT_ALLOWED })
            .with_state(daemon.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let registry = Arc::new(Registry::new(root.join("deployments.json")));
        let spec: DeploymentSpec = serde_json::from_value(serde_json::json!({"id":"demo","routes":[{"host":"demo.test"}],
            "vm":{"driver":"firecracker","port":4222,"workspace":{"store":"/unused-local-store"}},"scaling":{"min_replicas":1,"max_replicas":1}})).unwrap();
        let d = registry.upsert(spec);
        let ws = Arc::new(Workspaces::new(WorkspaceConfig { root: root.join("workspaces"), tar_bin:"tar".into(), aws_bin:"aws".into(),
            art_bin:"art".into(), s3_endpoint:None, home:None, timeout:Duration::from_secs(3) },
            VmManager::new(Some(url), None, crate::mounts::MountStore::new(root.join("mounts"), 0)).unwrap(), registry,
            Arc::new(SecretStore::new(root.join("secrets.json"), None))));
        ws.ensure_root().unwrap();
        ws.with_record("demo", |r| { r.digest = Some("a".repeat(64)); r.initialized = true; r.replacement_captures_remaining = 1;
            r.seeds.insert("sb-retained".into(), Seed { digest: None, dirty: true, mount_index: Some(0) }); });
        ws.remember_spec(&d.spec);
        Fixture { ws, d, daemon, root, server }
    }
    fn restart(f: &Fixture) -> Workspaces {
        let ws = Workspaces::new(f.ws.cfg.clone(), f.ws.vms.clone(), f.ws.registry.clone(), f.ws.secrets.clone());
        assert_eq!(ws.load(), 1); ws
    }

    #[tokio::test]
    async fn recovery_rejects_stale_foreign_namespace_and_active_sources() {
        let f = fixture().await;
        let mut stale = request(); stale.expected_snapshot = "b".repeat(64);
        assert!(f.ws.admit_recovery(&f.d, stale).await.is_err());
        f.ws.runtime.lock().unwrap().entry("demo".into()).or_default().restore_wanted = true;
        assert!(f.ws.admit_recovery(&f.d, request()).await.is_err(), "pending restore must not overwrite recovery");
        f.ws.runtime.lock().unwrap().get_mut("demo").unwrap().restore_wanted = false;
        let mut foreign = request(); foreign.source_sandbox_id = "sb-other".into();
        assert!(f.ws.admit_recovery(&f.d, foreign).await.unwrap_err().contains("ownership"));
        f.ws.with_record("other", |r| { r.seeds.insert("sb-retained".into(), Seed { digest:None, dirty:true, mount_index:Some(0) }); });
        assert!(f.ws.admit_recovery(&f.d, request()).await.unwrap_err().contains("another deployment"));
        f.ws.records.lock().unwrap().remove("other");
        let mut wrong_namespace = f.d.spec.clone(); wrong_namespace.namespace = "another-team".into();
        f.ws.remember_spec(&wrong_namespace);
        assert!(f.ws.admit_recovery(&f.d, request()).await.unwrap_err().contains("namespace"));
        f.ws.remember_spec(&f.d.spec);
        f.daemon.active.store(true, Ordering::SeqCst);
        assert!(f.ws.admit_recovery(&f.d, request()).await.unwrap_err().contains("not confirmed stopped"));
        assert!(!f.ws.has_recovery("demo")); assert_eq!(f.daemon.exports.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn recovery_exact_capture_unblocks_without_reseeding_resuming_or_deleting_source() {
        let f = fixture().await;
        let original_seed = f.ws.record("demo").seeds["sb-retained"].clone();
        let admit = || async { let _guard = f.ws.lifecycle_guard().await; f.ws.admit_recovery(&f.d, request()).await.unwrap() };
        let (one, two) = tokio::join!(admit(), admit());
        assert_eq!(one, two); assert_eq!(f.ws.record("demo").recoveries.len(), 1);
        let mut conflict = request(); conflict.source_sandbox_id = "sb-other".into();
        assert!(f.ws.admit_recovery(&f.d, conflict).await.is_err());
        assert!(f.ws.seed_for_create(&f.d).is_err());
        let ((), ()) = tokio::join!(f.ws.pass(), f.ws.pass());
        let op = f.ws.recovery("demo", "repair-1").unwrap(); assert_eq!(op.status, "succeeded");
        let digest = hex(&Sha256::digest(&f.daemon.bundle));
        assert_eq!(op.snapshot, Some(digest.clone()));
        assert_eq!(std::fs::read(f.ws.tree_path("demo", Some(&digest)).join("jetstream/state")).unwrap(), b"retained-stream-state\n");
        assert_eq!(f.ws.record("demo").seeds["sb-retained"], original_seed);
        assert_eq!(f.ws.record("demo").replacement_captures_remaining, 0);
        assert_eq!(f.ws.seed_for_create(&f.d).unwrap().unwrap().digest, Some(digest));
        assert!(f.ws.recovery_pinned("sb-retained")); assert!(f.ws.holds("demo", "sb-retained"));
        assert!(f.d.state().suspended.is_empty());
        assert_eq!(f.ws.admit_recovery(&f.d, request()).await.unwrap().status, "succeeded");
        assert_eq!(f.daemon.exports.load(Ordering::SeqCst), 1);
        assert_eq!(f.daemon.unexpected.load(Ordering::SeqCst), 0, "no stop/start/delete/storage mutation");
        let recovered = restart(&f);
        assert_eq!(recovered.recovery("demo", "repair-1").unwrap().status, "succeeded");
        assert!(recovered.recovery_pinned("sb-retained"));
    }

    #[tokio::test]
    async fn recovery_capture_and_commit_failure_keep_fence_and_restart_safely() {
        let f = fixture().await;
        f.ws.admit_recovery(&f.d, request()).await.unwrap();
        f.daemon.export_failure.store(true, Ordering::SeqCst); f.ws.pass().await;
        assert_eq!(f.ws.record("demo").digest, Some("a".repeat(64)));
        assert!(f.ws.blocked(&f.d).is_some()); assert!(f.ws.recovery_pinned("sb-retained"));
        let ws = restart(&f);
        f.daemon.export_failure.store(false, Ordering::SeqCst);
        f.daemon.fail_commit.store(true, Ordering::SeqCst); ws.pass().await;
        assert!(ws.persist_failed("demo")); assert!(ws.seed_for_create(&f.d).is_err());
        assert_eq!(ws.recovery("demo", "repair-1").unwrap().status, "running");
        let restarted = restart(&f);
        assert_eq!(restarted.record("demo").digest, Some("a".repeat(64)), "failed commit cannot release durable old fence");
        std::fs::remove_dir(&f.daemon.tmp_state).unwrap();
        restarted.pass().await;
        assert_eq!(restarted.recovery("demo", "repair-1").unwrap().status, "succeeded");
        assert!(restarted.recovery_pinned("sb-retained"));
        assert_eq!(f.daemon.unexpected.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn recovery_intent_write_failure_does_not_capture_or_clear_prior_fence() {
        let f = fixture().await;
        std::fs::create_dir(&f.daemon.tmp_state).unwrap();
        assert!(f.ws.admit_recovery(&f.d, request()).await.is_err());
        f.ws.pass().await;
        assert_eq!(f.daemon.exports.load(Ordering::SeqCst), 0);
        assert!(f.ws.seed_for_create(&f.d).is_err());
        let ws = restart(&f);
        assert!(!ws.has_recovery("demo")); assert_eq!(ws.record("demo").replacement_captures_remaining, 1);
        std::fs::remove_dir(&f.daemon.tmp_state).unwrap();
        ws.admit_recovery(&f.d, request()).await.unwrap(); ws.pass().await;
        assert_eq!(ws.recovery("demo", "repair-1").unwrap().status, "succeeded");
    }

    #[tokio::test]
    async fn recovery_ambiguous_commit_restarts_from_durable_success_without_recapture() {
        let f = fixture().await;
        f.ws.admit_recovery(&f.d, request()).await.unwrap();
        f.ws.fail_after_rename.store(true, Ordering::SeqCst);
        f.ws.pass().await;
        assert!(f.ws.persist_failed("demo"));
        assert_eq!(f.ws.recovery("demo", "repair-1").unwrap().status, "running");
        assert!(f.ws.seed_for_create(&f.d).is_err());
        let ws = restart(&f);
        assert_eq!(ws.recovery("demo", "repair-1").unwrap().status, "succeeded");
        assert!(ws.seed_for_create(&f.d).is_ok());
        assert!(ws.recovery_pinned("sb-retained"));
        assert_eq!(f.daemon.exports.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn replacement_capture_respects_disk_retention_even_when_then_kill() {
        let f = fixture().await;
        let disks = Arc::new(crate::disks::DiskStore::new(crate::disks::DiskConfig {
            state_path:f.root.join("disks.json"), ttl_secs:0, sweep_secs:60, aws_bin:"aws".into(), bucket:None,
            prefix:String::new(), endpoint:None, archive_on_expire:false, archive_timeout:Duration::from_secs(5), orphan_ttl_secs:0,
        }, f.ws.vms.clone(), f.ws.registry.clone()).with_workspaces(f.ws.clone()));
        disks.set_policy("sb-retained", Some(true), None).unwrap(); f.ws.attach_disk_store(&disks);
        let pending = PendingCapture { sandbox_id:"sb-retained".into(), then:Then::Kill, queued_at:0, attempts:0 };
        let _guard = f.ws.lifecycle_guard().await;
        f.ws.after_capture("demo", &pending).await;
        assert_eq!(f.ws.record("demo").replacement_captures_remaining, 0);
        assert!(f.ws.record("demo").seeds.contains_key("sb-retained"));
        assert!(f.ws.holds("demo", "sb-retained")); assert!(f.d.state().suspended.is_empty());
        assert_eq!(f.daemon.unexpected.load(Ordering::SeqCst), 0);
        drop(_guard);
        // The stronger recovery pin also defeats an explicit force-purge;
        // no daemon inventory or destructive request is needed to refuse it.
        f.ws.with_record("demo", |r| r.replacement_captures_remaining = 1);
        f.ws.admit_recovery(&f.d, request()).await.unwrap();
        disks.set_policy("sb-retained", Some(false), None).unwrap();
        assert!(matches!(disks.purge("sb-retained", true).await, Err(crate::disks::DiskError::Held { forceable:false, .. })));
        assert_eq!(f.daemon.unexpected.load(Ordering::SeqCst), 0);
    }
}
