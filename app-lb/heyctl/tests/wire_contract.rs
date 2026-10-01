//! The wire contract between app-lb and this crate.
//!
//! `src/types.rs` promises these tests exist; until now they did not, and the
//! `extra` maps were carried without anything asserting on them. The fixtures in
//! `../testdata/wire/*.json` are written by app-lb's *own* response types
//! (`app-lb/src/wire_golden.rs`), so parsing one here and finding `extra` empty
//! is the only check that this crate still understands every field the server
//! sends.
//!
//! Leniency is what makes the check necessary rather than redundant: to a
//! defaulting deserializer an unknown field and an absent one are identical, so
//! a field that disappears from this crate's structs breaks nothing and blanks a
//! column. `extra` turns that into a failing test.
//!
//! Regenerate the fixtures with:
//!   `UPDATE_GOLDEN=1 cargo test -p app-lb wire_golden`

use hws::types::{
    AuthProviderView, DeploymentSpec, DeploymentStatus, DiskInventory, DiskState, JobRecord, MetricsResponse, PluginView,
    UpstreamTrafficStatus, WorkflowList, WorkflowView,
};
use std::path::PathBuf;

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("heyctl lives inside the app-lb workspace")
        .join("testdata")
        .join("wire")
        .join(format!("{name}.json"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}\nrun `UPDATE_GOLDEN=1 cargo test -p app-lb wire_golden`",
            path.display()
        )
    })
}

/// The check that matters: every field app-lb sends has a name here.
#[test]
fn workflow_view_understands_every_field() {
    let w: WorkflowView = serde_json::from_str(&fixture("workflow")).expect("fixture parses");

    assert!(
        w.extra.is_empty(),
        "heyctl does not understand these fields app-lb sends: {:?}\n\
         Add them to WorkflowView in src/types.rs.",
        w.extra.keys().collect::<Vec<_>>()
    );

    // And the values actually landed, rather than defaulting past a rename.
    assert_eq!(w.id, "build");
    assert_eq!(w.git_ref, "main", "`ref` on the wire, `git_ref` in Rust");
    assert_eq!(w.path, ".ci/workflows/*.yml");
    assert_eq!(w.network, "prod-runners");
    assert!(w.auth.is_some(), "a SecretRef must survive as an opaque value");
    assert_eq!(w.secrets_prefix.as_deref(), Some("ci/app"));
    assert!(w.enabled);
}

/// The listing the `ci` orchestrator polls. Enveloped, so the envelope needs its
/// own check — a bare-array assumption here would fail at runtime, not compile
/// time.
#[test]
fn workflow_list_understands_every_field() {
    let list: WorkflowList = serde_json::from_str(&fixture("workflow-list")).expect("parses");
    assert!(
        list.extra.is_empty(),
        "unknown fields on the list envelope: {:?}",
        list.extra.keys().collect::<Vec<_>>()
    );
    assert_eq!(list.workflows.len(), 1);
    assert!(list.workflows[0].extra.is_empty());
    assert_eq!(list.workflows[0].id, "build");
}

/// A minimal object gets its defaults filled server-side, so the client must see
/// them rather than empty strings.
#[test]
fn a_minimal_workflow_arrives_with_its_defaults_filled() {
    let w: WorkflowView = serde_json::from_str(&fixture("workflow-minimal")).expect("parses");
    assert!(w.extra.is_empty(), "{:?}", w.extra.keys().collect::<Vec<_>>());
    assert_eq!(w.git_ref, "main");
    assert_eq!(w.path, ".ci/workflows/*.yml");
    assert!(w.enabled);
    assert!(w.auth.is_none());
}

/// Leniency itself: a *newer* server sending a field this build has no name for
/// must still parse, and the unknown field must be reachable rather than
/// discarded. That is the property the `extra` map buys.
#[test]
fn an_unknown_field_parses_and_is_reachable() {
    let mut value: serde_json::Value =
        serde_json::from_str(&fixture("workflow")).expect("fixture parses");
    value["concurrency_group"] = serde_json::json!("prod");

    let w: WorkflowView = serde_json::from_value(value).expect("a newer server still parses");
    assert_eq!(w.id, "build", "the known fields still land");
    assert_eq!(
        w.extra.get("concurrency_group").and_then(|v| v.as_str()),
        Some("prod"),
        "an unknown field must be reachable, not dropped"
    );
}

#[test]
fn upstream_traffic_status_understands_every_field() {
    let status: UpstreamTrafficStatus =
        serde_json::from_str(&fixture("upstream-traffic-status")).expect("fixture parses");
    assert!(
        status.extra.is_empty(),
        "unknown upstream traffic fields: {:?}",
        status.extra.keys().collect::<Vec<_>>()
    );
    assert_eq!(status.deployment_id, "stage");
    assert_eq!(status.upstream, "us1.example.com:443");
    assert_eq!(status.state, "draining");
    assert!(status.healthy);
    assert_eq!(status.in_flight, 3);
    assert_eq!(status.reason.as_deref(), Some("regional maintenance"));
    assert_eq!(status.started_at, Some(1_722_400_000));
}

/// The disk inventory `heyctl get disks` renders.
///
/// Checked field-by-field rather than only through `extra`, because this
/// response is the one an operator reads while deciding whether gigabytes are
/// safe to delete. A blanked column here is not a cosmetic regression: `held_by`
/// going missing turns "never reclaim this" into an empty cell, and the two size
/// fields disagreeing by design means silently rendering the wrong one
/// misreports how full the host actually is.
#[test]
fn disk_inventory_understands_every_field() {
    let inv: DiskInventory = serde_json::from_str(&fixture("disks")).expect("fixture parses");
    assert!(
        inv.extra.is_empty(),
        "unknown inventory fields: {:?}",
        inv.extra.keys().collect::<Vec<_>>()
    );
    assert!(inv.complete);
    assert_eq!(inv.data_dir, "/var/lib/heyo");
    assert_eq!(inv.ttl_secs, 604_800);
    assert_eq!(inv.totals.disks, 3);
    // The free-space block, which is what turns "here are the disks" into "and
    // that is why a create just failed". A fixture below the floor, so the
    // pressure path has a shape a client can render.
    assert_eq!(inv.free_bytes, Some(12_884_901_888));
    assert_eq!(inv.filesystem_bytes, Some(536_870_912_000));
    // The orphan clock is the policy that matters here, and it must survive the
    // wire: an orphan is the disk of a VM that never created, and retaining a
    // copy of that on the seven-day TTL is the leak this separates out.
    assert!(inv.orphan_ttl_secs > 0, "the orphan TTL must survive the wire");
    assert!(
        inv.orphan_ttl_secs < inv.ttl_secs,
        "an orphan must expire sooner than a recoverable disk, not later",
    );
    assert_eq!(inv.totals.reclaimable_bytes, 2_147_483_648);
    assert!(
        inv.totals.extra.is_empty(),
        "unknown totals fields: {:?}",
        inv.totals.extra.keys().collect::<Vec<_>>()
    );

    assert_eq!(inv.disks.len(), 3);
    for d in &inv.disks {
        assert!(
            d.extra.is_empty(),
            "unknown disk fields on {}: {:?}",
            d.sandbox_id,
            d.extra.keys().collect::<Vec<_>>()
        );
        for p in &d.parts {
            assert!(
                p.extra.is_empty(),
                "unknown disk-part fields: {:?}",
                p.extra.keys().collect::<Vec<_>>()
            );
        }
    }

    // The running disk: claimed, held, and sparse — the case where the two size
    // columns differ by 8x and reporting either alone would mislead.
    let running = &inv.disks[0];
    assert_eq!(running.sandbox_id, "sb-1a2b3c4d");
    assert_eq!(running.deployment.as_deref(), Some("web"));
    assert_eq!(running.state, DiskState::Running);
    assert!(running.claimed);
    assert_eq!(running.bytes, 1_073_741_824);
    assert_eq!(running.apparent_bytes, 8_589_934_592);
    assert_eq!(running.held_by.as_deref(), Some("in use by a running sandbox"));
    assert_eq!(running.parts.len(), 2);
    assert_eq!(running.roots, vec!["run/sb-1a2b3c4d".to_string()]);

    // The orphan: no daemon record, nothing holding it, and an expiry the sweep
    // will act on. `held_by: None` is what makes it reclaimable.
    let orphan = &inv.disks[1];
    assert_eq!(orphan.state, DiskState::Orphan);
    assert_eq!(orphan.deployment, None);
    assert_eq!(orphan.held_by, None);
    assert_eq!(orphan.expires_at, Some(1_759_604_800));

    // The pinned one: an operator said never, which outranks any age.
    let pinned = &inv.disks[2];
    assert_eq!(pinned.state, DiskState::Stopped);
    assert!(pinned.retain);
    assert_eq!(pinned.note.as_deref(), Some("keeping for the incident postmortem"));
    assert_eq!(pinned.expires_at, None);
}

/// A state this build has never heard of must degrade, not blank the listing.
#[test]
fn an_unknown_disk_state_degrades_to_unknown() {
    let mut value: serde_json::Value =
        serde_json::from_str(&fixture("disks")).expect("fixture parses");
    value["disks"][0]["state"] = serde_json::json!("quiescing");

    let inv: DiskInventory = serde_json::from_value(value).expect("a newer server still parses");
    assert_eq!(inv.disks[0].state, DiskState::Unknown);
    assert_eq!(inv.disks[1].state, DiskState::Orphan, "the other rows are unaffected");
}

/// `GET /metrics`, which had no contract test at all until now.
///
/// That gap was not theoretical. `AutoscaleCounts` was missing `boot_timeouts`
/// while app-lb had been sending it, so `heyctl describe` could not distinguish
/// the two ways a pool gets stuck at `ready: 0` — a guest that never becomes
/// healthy, and a VM that is never created. Both render as silence, and the
/// second one sends you to debug an image that never ran.
///
/// Asserting `extra` is empty at every level is what keeps that from recurring:
/// a lenient deserializer cannot tell an absent field from an unknown one, so
/// without this a field app-lb adds is simply never shown.
#[test]
fn metrics_response_understands_every_field() {
    let m: MetricsResponse =
        serde_json::from_str(&fixture("metrics-response")).expect("fixture parses");
    assert!(
        m.extra.is_empty(),
        "unknown metrics fields: {:?}",
        m.extra.keys().collect::<Vec<_>>()
    );
    assert!(
        m.global.extra.is_empty(),
        "unknown global-metrics fields: {:?}",
        m.global.extra.keys().collect::<Vec<_>>()
    );

    // The daemon block: the one field that says whether everything else here is
    // live or frozen. The fixture is the unreachable case on purpose.
    assert!(
        m.daemon.extra.is_empty(),
        "unknown daemon fields: {:?}",
        m.daemon.extra.keys().collect::<Vec<_>>()
    );
    assert!(!m.daemon.reachable, "the fixture records an unreachable daemon");
    assert!(
        m.daemon.last_error.as_deref().is_some_and(|e| e.contains("deployed-sandboxes")),
        "the reason must survive the wire, not just the boolean",
    );

    let a = &m.global.autoscale;
    assert!(
        a.extra.is_empty(),
        "unknown autoscale fields: {:?}",
        a.extra.keys().collect::<Vec<_>>()
    );
    assert_eq!(a.vms_created, 2);
    assert_eq!(a.boot_timeouts, 1, "the field that had gone missing");
    assert_eq!(a.create_failures, 1);
    assert_eq!(
        a.last_create_error.as_deref(),
        Some("api error (500): No space left on device"),
        "the reason a pool is stuck must survive the wire",
    );

    for d in &m.deployments {
        assert!(
            d.metrics.autoscale.extra.is_empty(),
            "unknown per-deployment autoscale fields: {:?}",
            d.metrics.autoscale.extra.keys().collect::<Vec<_>>()
        );
    }
}

/// Guest mounts, which are the one part of the VM template whose *absence* has a
/// consequence a client must be able to explain: a mount with no `digest` is a
/// deployment whose pool cannot start.
///
/// `VmSpec` carries no `extra` map — it is a spec mirror rather than a response
/// envelope — so this asserts the values landed instead. A rename or a dropped
/// field shows up as a default here, which is exactly the silent-blank-column
/// failure this file exists to catch.
#[test]
fn guest_mounts_survive_the_wire() {
    let d: DeploymentStatus =
        serde_json::from_str(&fixture("deployment-status-vm")).expect("fixture parses");
    let vm = d.spec.vm.expect("the vm fixture has a template");

    assert_eq!(vm.mounts.len(), 1, "the mount must not be dropped");
    let m = &vm.mounts[0];
    assert_eq!(m.path, "/data/corpus");
    assert_eq!(m.store, "http://127.0.0.1:8080");
    assert_eq!(m.artifact_ref, "corpus-2026-08", "`ref` on the wire");
    assert_eq!(m.strip_components, Some(1));
    assert!(m.read_only, "the fixture's mount is read-only");
    assert!(m.auth.is_some(), "a SecretRef must survive as an opaque value");
    assert!(
        m.digest.as_deref().is_some_and(|d| d.len() == 64),
        "the resolved digest is what says which bytes the guests hold",
    );
    assert!(m.summary().contains("/data/corpus"));
}

/// The third kind of pull, whose result lives in `mounts` rather than in
/// `image` — so a client that only understood the other two would render a mount
/// pull as a job that did nothing.
#[test]
fn a_mount_pull_reports_every_mount() {
    let j: JobRecord = serde_json::from_str(&fixture("job-mount-pull")).expect("fixture parses");

    assert!(j.is_mount_pull(), "kind is `mount-pull`, not `artifact-pull`");
    assert_eq!(j.mounts.len(), 2);

    let fetched = &j.mounts[0];
    assert_eq!(fetched.path, "/data/corpus");
    assert_eq!(fetched.artifact_ref, "corpus-2026-08", "`ref` on the wire");
    assert_eq!(fetched.files, Some(1_204));
    assert_eq!(fetched.bytes, Some(734_003_200));
    assert_eq!(fetched.unpacked, Some(2_147_483_648));
    assert!(fetched.changed, "this one moved the pool");
    assert!(fetched.tree.is_some());

    // The common case, and the one whose rendering must not read as an error:
    // the tree was already on this host, so nothing was fetched or unpacked.
    let reused = &j.mounts[1];
    assert!(reused.reused);
    assert!(!reused.changed);
    assert_eq!(reused.bytes, Some(0));
    assert_eq!(reused.files, None, "nothing was unpacked, which is not zero files");

    assert_eq!(j.result_summary(), "1/2 updated");
    assert_eq!(j.target_summary(), "/data/corpus,/opt/models");
}

/// A JWT gate's verification policy, which is the one part of a spec whose
/// *misreading* is a security question: a client that dropped `require` would
/// render a restricted deployment as open to anyone the issuer signs for.
#[test]
fn a_jwt_gate_survives_the_wire() {
    let d: DeploymentStatus =
        serde_json::from_str(&fixture("deployment-status-jwt")).expect("fixture parses");
    let gate = d.spec.auth.expect("the fixture is gated");

    assert!(gate.accepts_jwt(), "the provider list carries `jwt`");
    assert!(
        gate.providers().iter().any(|p| p == "google"),
        "the fixture is the mixed gate: a person signs in, a program presents a token",
    );

    let jwt = gate.jwt.expect("the verification policy must not be dropped");
    assert_eq!(jwt.issuer, "auth-service");
    assert_eq!(jwt.audience.as_deref(), Some("heyo-app"));
    assert_eq!(jwt.algorithms, vec!["HS256"]);
    assert_eq!(jwt.subject_claim, "userId", "the Heyo auth API's subject is not `sub`");
    assert_eq!(jwt.cookie.as_deref(), Some("heyo_access_token"));
    assert_eq!(jwt.leeway_secs, Some(30));
    assert!(jwt.secret.is_some(), "a SecretRef must survive as an opaque value");

    // The claim map is the gate's allow-list, and it renders as one.
    assert_eq!(jwt.require.len(), 2);
    let summary = jwt.require_summary();
    assert!(summary.contains("role=user|admin"), "{summary}");
    assert!(summary.contains("accountId=acct_7f3c"), "{summary}");
    assert!(jwt.key_summary().contains("heyo-auth"), "{}", jwt.key_summary());
}

/// The auth provider object, in both shapes app-lb serialises it in.
#[test]
fn auth_provider_view_understands_every_field() {
    let heyo: AuthProviderView =
        serde_json::from_str(&fixture("auth-provider-heyo")).expect("fixture parses");
    assert!(
        heyo.extra.is_empty(),
        "heyctl does not understand these fields app-lb sends: {:?}\n\
         Add them to AuthProviderView in src/types.rs.",
        heyo.extra.keys().collect::<Vec<_>>()
    );
    assert_eq!(heyo.name, "heyo");
    assert_eq!(heyo.namespace, "team-a");
    assert_eq!(heyo.providers(), vec!["jwt".to_string()]);
    let jwt = heyo.jwt.as_ref().expect("a jwt provider carries its policy");
    assert_eq!(jwt.issuer, "auth-service");
    assert_eq!(jwt.subject_claim, "userId", "the Heyo auth API's subject is not `sub`");
    assert_eq!(heyo.admits(), "role=user|admin");
    assert_eq!(heyo.trust_summary(), "auth-service");

    let google: AuthProviderView =
        serde_json::from_str(&fixture("auth-provider-google")).expect("fixture parses");
    assert!(
        google.extra.is_empty(),
        "unknown fields on the google provider: {:?}",
        google.extra.keys().collect::<Vec<_>>()
    );
    assert_eq!(google.providers(), vec!["google".to_string()]);
    assert!(google.client_secret.is_some(), "a SecretRef must survive as a reference");
    assert_eq!(google.admits(), "@example.com");
    assert_eq!(google.cookie_domain.as_deref(), Some(".example.com"));
}

/// A gate that inherits its identity carries `provider_ref` and nothing else —
/// which only reads correctly if this crate knows the field exists.
#[test]
fn an_inherited_gate_names_the_provider_it_came_from() {
    // This fixture is a bare spec, not the status envelope a listing returns.
    let spec: DeploymentSpec =
        serde_json::from_str(&fixture("deployment-inherited-gate")).expect("fixture parses");
    let gate = spec.auth.as_ref().expect("the fixture has a gate");
    assert_eq!(gate.provider_ref.as_deref(), Some("corp-google"));
    assert_eq!(spec.namespace(), "team-a", "the provider is looked up in this namespace");
    assert!(gate.client_id.is_none(), "an inheriting gate carries no identity of its own");
}

/// The plugin list `heyctl plugins` renders.
#[test]
fn plugin_view_understands_every_field() {
    let plugins: Vec<PluginView> = serde_json::from_str(&fixture("plugins")).expect("fixture parses");
    for p in &plugins {
        assert!(
            p.extra.is_empty(),
            "heyctl does not understand these fields app-lb sends: {:?}\n\
             Add them to PluginView in src/types.rs.",
            p.extra.keys().collect::<Vec<_>>()
        );
    }
    let on = &plugins[0];
    assert_eq!(on.id, "example");
    assert!(on.enabled);
    assert_eq!(on.last_error.as_deref(), Some("connection refused"), "enabled and failing is a state");
    assert_eq!(on.config["url"], "http://127.0.0.1:34199");
    assert!(!plugins[1].enabled);
}
