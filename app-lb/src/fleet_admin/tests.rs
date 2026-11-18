use super::*;

fn row(host: &str, state: &str, facts: Option<HostFacts>) -> HostRow {
    HostRow {
        host: host.into(),
        address: Some(format!("{host}.example")),
        state: state.into(),
        boot_id: "b".into(),
        age_secs: 0.0,
        facts,
    }
}

fn facts(drivers: &[&str], free: u64) -> Option<HostFacts> {
    Some(HostFacts {
        drivers: Some(drivers.iter().map(|d| d.to_string()).collect()),
        memory_free_bytes: Some(free),
        ..Default::default()
    })
}

#[test]
fn calls_are_classified_by_what_they_act_on() {
    let get = Method::GET;
    let post = Method::POST;
    assert_eq!(classify(&get, "/deployments", None), Route::List);
    assert_eq!(classify(&post, "/deployments", None), Route::Register);
    assert_eq!(classify(&get, "/metrics", Some("summary=true")), Route::Metrics);
    assert_eq!(
        classify(&get, "/deployments/web", None),
        Route::Deployment { id: "web".into(), vm: None, owner: None, body_vm: false }
    );
    assert_eq!(
        classify(&Method::DELETE, "/deployments/web/vms/sb-1", None),
        Route::Deployment { id: "web".into(), vm: Some("sb-1".into()), owner: None, body_vm: false }
    );
    assert_eq!(
        classify(&get, "/deployments/web/shell", Some("cols=80&sandbox_id=sb-2")),
        Route::Deployment { id: "web".into(), vm: Some("sb-2".into()), owner: None, body_vm: false }
    );
    assert_eq!(
        classify(&post, "/deployments/web/exec", None),
        Route::Deployment { id: "web".into(), vm: None, owner: None, body_vm: true }
    );
    assert_eq!(
        classify(&get, "/deployments/web/operations/us5~op_1", None),
        Route::Deployment { id: "web".into(), vm: None, owner: Some("us5".into()), body_vm: false }
    );
    assert_eq!(classify(&get, "/jobs/us4~job-1", None), Route::Owned(Some("us4".into())));
    assert_eq!(classify(&get, "/jobs/job-1", None), Route::Owned(None), "an old id is local");
    assert_eq!(classify(&Method::PUT, "/transfers/us5~abc", None), Route::Owned(Some("us5".into())));
    assert_eq!(classify(&get, "/api/plugins/ci/runs", None), Route::Plugin("ci".into()));
    assert_eq!(classify(&get, "/api/plugins/ci/machine/x", None), Route::Plugin("ci".into()));
    assert_eq!(classify(&Method::PUT, "/namespaces/a/plugins/pg", None), Route::Plugin("pg".into()));
    assert_eq!(classify(&get, "/namespaces/a/plugins/pg", None), Route::Local, "the record is fleet state");
    assert_eq!(classify(&get, "/namespaces/a/plugins/pg/dbs", None), Route::Plugin("pg".into()));
    for local in ["/namespaces", "/secrets", "/tokens", "/fleet-hosts", "/healthz", "/api/plugins"] {
        assert_eq!(classify(&get, local, None), Route::Local, "{local}");
    }
}

#[test]
fn scoped_ids_name_their_host_and_old_ones_name_none() {
    assert_eq!(owner_of("us5~op_00ff"), Some("us5"));
    assert_eq!(owner_of("us-5.a_b~x"), Some("us-5.a_b"));
    assert_eq!(owner_of("op_00ff"), None);
    assert_eq!(owner_of("us5~"), None);
    assert_eq!(owner_of("bad host~x"), None);
    // `scoped` is unchanged until a host is named, which a test never does:
    // the id formats every other test pins stay as they are.
    assert_eq!(scoped("op_1".into()), "op_1");
}

#[test]
fn placement_picks_the_capable_host_with_most_room_and_never_an_incapable_one() {
    let members = vec![
        row("us1", "active", facts(&["libvirt"], 900)),
        row("us4", "active", facts(&["firecracker", "kvm"], 10)),
        row("us5", "active", facts(&["firecracker", "kvm"], 50)),
        row("us6", "active", None),
    ];
    assert_eq!(choose_home("us4", &members, "firecracker").unwrap(), "us5");
    assert_eq!(choose_home("us4", &members, "libvirt").unwrap(), "us1");
    // A draining host is never chosen, however roomy.
    let mut draining = members.clone();
    draining[2].state = "draining".into();
    assert_eq!(choose_home("us4", &draining, "firecracker").unwrap(), "us4");
    // Nobody says lxc; the receiving host says it cannot either.
    assert!(choose_home("us4", &members, "lxc").is_err());
    // A host with no facts keeps today's rule: it takes what nobody claims.
    assert_eq!(choose_home("us6", &members, "lxc").unwrap(), "us6");
    // A member with no address takes no hops, so is not chosen for others.
    let mut unreachable = members.clone();
    unreachable[2].address = None;
    assert_eq!(choose_home("us4", &unreachable, "firecracker").unwrap(), "us4");
}

#[test]
fn an_explicit_placement_is_checked_against_what_members_boot() {
    let members = vec![
        row("us1", "active", facts(&["libvirt"], 1)),
        row("us4", "active", facts(&["firecracker"], 1)),
        row("us6", "active", None),
    ];
    let pinned = |home: &str| json!({"mode": "pinned", "home": home});
    assert_eq!(check_explicit("us4", &members, &pinned("us1"), "libvirt").unwrap(), "us1");
    assert!(check_explicit("us4", &members, &pinned("us4"), "libvirt").unwrap_err().contains("us4"));
    assert_eq!(check_explicit("us4", &members, &pinned("us6"), "libvirt").unwrap(), "us6", "unknown is not no");
    let spread = json!({"mode": "spread"});
    let e = check_explicit("us4", &members, &spread, "firecracker").unwrap_err();
    assert!(e.contains("us1") && !e.contains("us6"), "{e}");
    let subset = json!({"mode": "spread", "hosts": ["us4", "us6"]});
    assert_eq!(check_explicit("us4", &members, &subset, "firecracker").unwrap(), "us4");
}

#[test]
fn lists_merge_by_deployment_and_fold_a_spread_ones_vms() {
    let mine = json!([
        {"spec": {"id": "a"}, "ready": 1, "vms": [{"sandbox_id": "x"}]},
        {"spec": {"id": "s", "placement": {"mode": "spread"}}, "ready": 1, "pending": 0, "total_in_flight": 2,
         "desired_replicas": 1, "vms": [{"sandbox_id": "s1"}]},
    ]);
    let theirs = vec![(
        "us5".to_string(),
        json!([
            {"spec": {"id": "b"}, "ready": 0, "vms": []},
            {"spec": {"id": "s", "placement": {"mode": "spread"}}, "ready": 2, "pending": 1, "total_in_flight": 3,
             "desired_replicas": 2, "vms": [{"sandbox_id": "s2"}, {"sandbox_id": "s3"}]},
        ]),
    )];
    let merged = merge_lists("us4", mine, theirs);
    let list = merged.as_array().unwrap();
    assert_eq!(list.iter().map(|d| d["spec"]["id"].as_str().unwrap()).collect::<Vec<_>>(), ["a", "b", "s"]);
    assert_eq!(list[0]["host"], "us4");
    assert_eq!(list[1]["host"], "us5");
    let s = &list[2];
    assert_eq!(s["hosts"], json!(["us4", "us5"]));
    assert_eq!(s["ready"], 3);
    assert_eq!(s["pending"], 1);
    assert_eq!(s["desired_replicas"], 3);
    let vms: Vec<(&str, &str)> = s["vms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["sandbox_id"].as_str().unwrap(), v["host"].as_str().unwrap()))
        .collect();
    assert_eq!(vms, [("s1", "us4"), ("s2", "us5"), ("s3", "us5")]);
}

#[test]
fn metrics_merge_counts_and_say_what_is_missing() {
    let mine = json!({"host": {"cpu_count": 8}, "fleet": {"deployments": 1, "ready": 2}, "matched": 1,
        "tracked_deployments": 1, "deployments": [{"id": "a"}], "host_sandboxes": [{"sandbox_id": "h1"}]});
    let theirs = vec![("us5".to_string(), json!({"host": {"cpu_count": 4}, "fleet": {"deployments": 2, "ready": 1},
        "matched": 2, "tracked_deployments": 2, "deployments": [{"id": "b"}, {"id": "a"}], "host_sandboxes": []}))];
    let m = merge_metrics("us4", mine, theirs, &["us6".to_string()]);
    assert_eq!(m["fleet"]["deployments"], 3);
    assert_eq!(m["fleet"]["ready"], 3);
    assert_eq!(m["matched"], 2, "b added; a is listed once");
    assert_eq!(m["deployments"][1], json!({"id": "b", "host": "us5"}));
    assert_eq!(m["deployments"][0]["hosts"], json!(["us4", "us5"]));
    assert_eq!(m["host_sandboxes"][0]["host"], "us4");
    assert_eq!(m["members"][1]["usage"]["cpu_count"], 4);
    assert_eq!(m["partial"], true);
    assert_eq!(m["hosts_unreachable"], json!(["us6"]));
}

#[test]
fn facts_list_spread_vms_and_room() {
    let registry = Registry::new(std::env::temp_dir().join(format!("fleet-admin-facts-{}.json", std::process::id())));
    registry.upsert(
        serde_json::from_value(json!({"id": "s", "routes": [], "vm": {"driver": "firecracker", "port": 8080},
            "placement": {"mode": "spread"}}))
        .unwrap(),
    );
    registry.get("s").unwrap().mutate_state(|st| st.suspended.push("sb-9".into()));
    registry.upsert(
        serde_json::from_value(json!({"id": "p", "routes": [], "vm": {"driver": "firecracker", "port": 8080}})).unwrap(),
    );
    registry.get("p").unwrap().mutate_state(|st| st.suspended.push("sb-1".into()));
    let usage = crate::metrics::HostUsageSnapshot {
        available: true,
        cpu_count: 8,
        cpu_percent: 25.0,
        memory_total_bytes: 100,
        memory_used_bytes: 40,
        sampled_at_ms: 1,
    };
    let f = super::facts(&registry, &usage, Some(vec!["firecracker".into()]));
    assert_eq!(f.memory_free_bytes, Some(60));
    assert_eq!(f.vcpus_free, Some(6.0));
    assert_eq!(f.vms.get("sb-9").map(String::as_str), Some("s"));
    assert!(!f.vms.contains_key("sb-1"), "a pinned deployment's VMs are at its home");
}
