//! The on-disk layout a single-server app-lb writes, pinned.
//!
//! Every durable store now writes through `fleet_store`. These tests drive each
//! of them over one temporary root, then compare the whole tree against what
//! the stores wrote before that seam existed: the same file names, the same
//! modes, pretty JSON byte-for-byte, and nothing else (no temp files, no new
//! directories). A change here is a change to what an older binary reads after
//! a rollback, so it should be deliberate.

use crate::config::{DeploymentSpec, NamespaceSpec, WorkflowSpec};
use crate::guard::Guard;
use crate::namespaces::NamespaceStore;
use crate::plugins::{PluginRecord, PluginStore};
use crate::registry::Registry;
use crate::secrets::{SecretSpec, SecretStore};
use crate::tls::CertStore;
use crate::tokens::TokenStore;
use crate::workflows::WorkflowStore;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

struct Root(PathBuf);

impl Root {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "app-lb-layout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }

    fn state(&self) -> String {
        self.path("app-lb-state.json")
            .to_string_lossy()
            .into_owned()
    }

    /// Every file under the root, relative, with its permission bits.
    fn tree(&self) -> BTreeMap<String, u32> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, u32>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let meta = entry.metadata().unwrap();
                if meta.is_dir() {
                    walk(base, &path, out);
                } else {
                    let rel = path
                        .strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    out.insert(rel, mode(&meta));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.0, &self.0, &mut out);
        out
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode(_meta: &std::fs::Metadata) -> u32 {
    0
}

fn pretty<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec_pretty(value).unwrap()
}

#[test]
fn every_store_writes_the_files_it_always_wrote() {
    let root = Root::new();
    let state = root.state();

    // Deployments: one synced file per deployment, id percent-encoded.
    let registry = Registry::new(&state);
    let spec: DeploymentSpec = serde_json::from_value(serde_json::json!({
        "id": "web/1",
        "routes": [{"host": "web.example.com"}],
        "upstreams": ["127.0.0.1:8080"]
    }))
    .unwrap();
    registry.upsert(spec);
    registry.persist_one("web/1").unwrap();

    // The four object stores: one pretty JSON file per object.
    let namespaces = NamespaceStore::new(crate::namespaces::namespace_dir(&state));
    let ns = NamespaceSpec {
        name: "sam".into(),
        description: Some("Sam's".into()),
        created_at: 1,
        hosts: vec![],
    };
    namespaces.upsert(ns.clone()).unwrap();

    let workflows = WorkflowStore::new(crate::workflows::workflow_dir(&state));
    let wf = WorkflowSpec {
        id: "build".into(),
        repo: "git@github.com:me/app.git".into(),
        git_ref: "main".into(),
        path: ".ci/workflows/*.yml".into(),
        network: "prod-runners".into(),
        auth: None,
        secrets_prefix: None,
        enabled: true,
    };
    workflows.upsert(wf.clone()).unwrap();

    let plugins = PluginStore::new(crate::plugins::plugin_dir(&state));
    let record = PluginRecord {
        enabled: true,
        updated_at: 7,
        ..Default::default()
    };
    plugins.put("obs", record.clone()).unwrap();

    // The whole-file stores.
    let secrets = SecretStore::new(root.path("app-lb-secrets.json"), None);
    secrets.put(SecretSpec {
        namespace: crate::config::DEFAULT_NAMESPACE.to_string(),
        id: "github".into(),
        description: None,
        data: BTreeMap::from([("token".to_string(), "t0ken".to_string())]),
        updated_at: 3,
    });
    secrets.persist().unwrap();

    let sealed = SecretStore::new(root.path("sealed/app-lb-secrets.json"), Some(vec![7u8; 32]));
    sealed.persist().unwrap();

    let tokens = TokenStore::new(root.path("app-lb-tokens.json"));
    let request: crate::tokens::NewToken =
        serde_json::from_value(serde_json::json!({"name": "ci"})).unwrap();
    tokens.mint(request, 100).unwrap();
    tokens.persist().unwrap();

    let guard = Guard::new(root.path("app-lb-guard.json"), true);
    let rule: crate::guard::RuleSpec =
        serde_json::from_value(serde_json::json!({"match": {"client": "203.0.113.7"}})).unwrap();
    guard.insert(rule, 100).unwrap();
    guard.persist().unwrap();

    // Certificates: a chain and a key per host, both private, in a private directory.
    let certs = CertStore::new(root.path("acme/certs"), None);
    let (chain, key) = crate::tls::tests::self_signed("app.example.com", 30);
    certs.insert("app.example.com", &chain, &key).unwrap();

    assert_eq!(
        root.tree(),
        BTreeMap::from([
            ("acme/certs/app.example.com.crt.pem".to_string(), 0o600),
            ("acme/certs/app.example.com.key.pem".to_string(), 0o600),
            ("app-lb-guard.json".to_string(), file_mode()),
            ("app-lb-namespaces.d/sam.json".to_string(), file_mode()),
            ("app-lb-plugins.d/obs.json".to_string(), file_mode()),
            ("app-lb-secrets.json".to_string(), 0o600),
            ("app-lb-state.d/web%2F1.json".to_string(), file_mode()),
            ("app-lb-tokens.json".to_string(), 0o600),
            ("app-lb-workflows.d/build.json".to_string(), file_mode()),
            ("sealed/app-lb-secrets.json".to_string(), 0o600),
        ]),
        "the set of files, and their modes, is exactly what app-lb has always written"
    );
    #[cfg(unix)]
    {
        let dir_mode = std::fs::metadata(root.path("acme/certs"))
            .map(|m| mode(&m))
            .unwrap();
        assert_eq!(dir_mode, 0o700);
    }

    // Byte-for-byte: the serializers did not move, and nothing wraps them.
    let read = |rel: &str| std::fs::read(root.path(rel)).unwrap();
    assert_eq!(read("app-lb-namespaces.d/sam.json"), pretty(&ns));
    assert_eq!(read("app-lb-workflows.d/build.json"), pretty(&wf));
    assert_eq!(read("app-lb-plugins.d/obs.json"), pretty(&record));
    assert_eq!(read("acme/certs/app.example.com.crt.pem"), chain);
    assert_eq!(read("acme/certs/app.example.com.key.pem"), key);

    let deployment: serde_json::Value =
        serde_json::from_slice(&read("app-lb-state.d/web%2F1.json")).unwrap();
    // `StoredDeployment` is private to the registry; check the shape it pretty-prints.
    assert!(
        read("app-lb-state.d/web%2F1.json")
            .starts_with(b"{\n  \"spec\": {\n    \"id\": \"web/1\",")
    );
    assert_eq!(deployment["spec"]["id"], "web/1");
    assert!(
        deployment.get("state").is_some(),
        "spec and state stay in one record"
    );

    let secrets_file: serde_json::Value =
        serde_json::from_slice(&read("app-lb-secrets.json")).unwrap();
    assert_eq!(secrets_file["encryption"], "none");
    assert_eq!(secrets_file["secrets"][0]["data"]["token"], "t0ken");
    let sealed_file: serde_json::Value =
        serde_json::from_slice(&read("sealed/app-lb-secrets.json")).unwrap();
    assert_eq!(sealed_file["encryption"], "aes-256-gcm");
    let tokens_file: serde_json::Value =
        serde_json::from_slice(&read("app-lb-tokens.json")).unwrap();
    assert_eq!(tokens_file["version"], 1);
    assert_eq!(tokens_file["tokens"][0]["name"], "ci");

    // And every store reads back what it wrote.
    assert_eq!(Registry::new(&state).load().unwrap(), 1);
    assert_eq!(
        NamespaceStore::new(crate::namespaces::namespace_dir(&state)).load(),
        (1, 0)
    );
    assert_eq!(
        WorkflowStore::new(crate::workflows::workflow_dir(&state)).load(),
        (1, 0)
    );
    assert_eq!(
        PluginStore::new(crate::plugins::plugin_dir(&state)).load(),
        (1, 0)
    );
    assert_eq!(
        SecretStore::new(root.path("app-lb-secrets.json"), None)
            .load()
            .unwrap(),
        1
    );
    assert_eq!(
        TokenStore::new(root.path("app-lb-tokens.json"))
            .load()
            .unwrap(),
        1
    );
    assert_eq!(
        Guard::new(root.path("app-lb-guard.json"), true)
            .load(200)
            .unwrap(),
        1
    );
    assert_eq!(
        CertStore::new(root.path("acme/certs"), None).load_from_disk(),
        1
    );
}

/// Files that are not credentials get whatever the umask leaves, as before.
fn file_mode() -> u32 {
    let probe = std::env::temp_dir().join(format!("app-lb-umask-{}", std::process::id()));
    std::fs::write(&probe, b"").unwrap();
    let m = mode(&std::fs::metadata(&probe).unwrap());
    let _ = std::fs::remove_file(&probe);
    m
}

#[test]
fn a_state_tree_left_by_an_older_binary_loads_unchanged() {
    // Written the way the stores wrote before the seam: plain std::fs, pretty JSON.
    let root = Root::new();
    let state = root.state();
    let ns = NamespaceSpec {
        name: "legacy".into(),
        description: None,
        created_at: 5,
        hosts: vec![],
    };
    std::fs::create_dir_all(root.path("app-lb-namespaces.d")).unwrap();
    std::fs::write(root.path("app-lb-namespaces.d/legacy.json"), pretty(&ns)).unwrap();
    // A stray temp file from an interrupted write, and an unreadable object.
    std::fs::write(root.path("app-lb-namespaces.d/half.json.tmp"), b"{").unwrap();
    std::fs::write(root.path("app-lb-namespaces.d/broken.json"), b"not json").unwrap();

    let before = root.tree();
    let store = NamespaceStore::new(crate::namespaces::namespace_dir(&state));
    assert_eq!(
        store.load(),
        (1, 1),
        "one loaded, the broken one skipped, the temp file ignored"
    );
    assert_eq!(store.get("legacy").unwrap().as_ref(), &ns);

    // Loading writes nothing.
    assert_eq!(root.tree(), before);
    let names: BTreeSet<_> = before.keys().cloned().collect();
    assert!(
        names.contains("app-lb-namespaces.d/broken.json"),
        "an unreadable object stays on disk"
    );
}
