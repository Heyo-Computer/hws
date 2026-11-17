//! The plugin end to end: a registry with real deployments, a local webhook
//! receiver, and the namespace surface through the plugin host.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use serde_json::{Value, json};

use super::delivery::{Backoff, DeliveryStatus};
use super::*;
use crate::config::DeploymentSpec;
use crate::plugins::ns_proxy::NamespaceActor;
use crate::plugins::{PluginHost, PluginStore};
use crate::secrets::SecretSpec;

struct Fixture {
    _dir: tempfile::TempDir,
    registry: Arc<Registry>,
    secrets: Arc<SecretStore>,
    plugin: Arc<AlertingPlugin>,
    host: PluginHost,
    state_dir: std::path::PathBuf,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let registry = Arc::new(Registry::new(dir.path().join("state.json")));
    let secrets = Arc::new(SecretStore::new(dir.path().join("secrets.json"), None));
    let state_dir = dir.path().join("plugins").join("state");
    let plugin = AlertingPlugin::new(registry.clone(), secrets.clone(), &state_dir);
    plugin.deliverer.set_backoff(Backoff {
        base: Duration::from_millis(10),
        cap: Duration::from_millis(40),
    });
    let host = PluginHost::new(vec![plugin.clone()], PluginStore::new(dir.path().join("plugins")));
    // Long ticks: the tests drive evaluation themselves.
    host.set(
        PLUGIN_ID,
        true,
        Some(json!({"allow_insecure": true, "allow_private": true, "tick_secs": 3600})),
    )
    .await
    .unwrap();
    Fixture {
        _dir: dir,
        registry,
        secrets,
        plugin,
        host,
        state_dir,
    }
}

fn static_deployment(id: &str, ns: &str, upstream: &str) -> DeploymentSpec {
    serde_json::from_value(json!({
        "id": id, "namespace": ns,
        "routes": [{"host": format!("{id}.{ns}.example")}],
        "upstreams": [upstream],
    }))
    .unwrap()
}

/// A webhook receiver that answers with the queued statuses, then 200.
#[derive(Clone, Default)]
struct Receiver {
    seen: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
    raw: Arc<Mutex<Vec<Vec<u8>>>>,
    statuses: Arc<Mutex<Vec<u16>>>,
}

async fn receiver(statuses: Vec<u16>) -> (Receiver, String) {
    let r = Receiver {
        statuses: Arc::new(Mutex::new(statuses)),
        ..Default::default()
    };
    let state = r.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let state = state.clone();
            async move {
                let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                state.seen.lock().unwrap().push((headers, v));
                state.raw.lock().unwrap().push(body.to_vec());
                let mut s = state.statuses.lock().unwrap();
                let code = if s.is_empty() { 200 } else { s.remove(0) };
                StatusCode::from_u16(code).unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (r, format!("http://{addr}/hook"))
}

/// A plain HTTP upstream answering every request with `status`.
async fn upstream(status: u16) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n").as_bytes())
                    .await;
            });
        }
    });
    addr.to_string()
}

async fn wait_for(mut f: impl FnMut() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting");
}

fn req(method: &str, uri: &str, body: Value, principal: Option<&str>) -> Request<Body> {
    let mut r = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(if body.is_null() { Body::empty() } else { Body::from(body.to_string()) })
        .unwrap();
    r.extensions_mut().insert(NamespaceActor {
        principal: principal.map(str::to_string),
        email: None,
        admin: true,
    });
    r
}

async fn call(f: &Fixture, ns: &str, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
    let resp = f
        .host
        .dispatch_namespace(PLUGIN_ID, ns, req(method, uri, body, Some("user:alice")))
        .await;
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_down_deployment_fires_a_signed_webhook_and_resolves() {
    let f = fixture().await;
    let (rx, url) = receiver(vec![]).await;
    f.secrets.put(SecretSpec {
        id: "hook".into(),
        namespace: "team-a".into(),
        description: None,
        data: [("key".to_string(), "s3cret".to_string())].into(),
        updated_at: 0,
    });
    let d = f.registry.upsert(static_deployment("web", "team-a", "127.0.0.1:9"));
    // The same id cannot exist twice, so another namespace's down deployment
    // is a different id — and must never be seen by team-a's `*` rule.
    let other = f.registry.upsert(static_deployment("api", "team-b", "127.0.0.1:9"));
    other.backends()[0].set_healthy(false);
    f.host
        .install(
            PLUGIN_ID,
            "team-a",
            json!({
                "receivers": [{"id": "ops", "url": url, "secret": {"secret": "hook", "key": "key", "namespace": "team-b"}}],
                "rules": [{"id": "down", "deployment": "*", "condition": {"type": "no_healthy_replicas"},
                           "severity": "critical", "receivers": ["ops"]}],
            }),
            Some("user:alice".into()),
        )
        .await
        .unwrap();

    let now = now_secs();
    f.plugin.tick_at(now).await;
    let (_, v) = call(&f, "team-a", "GET", "/api/alerts", Value::Null).await;
    assert_eq!(v["active"], json!([]), "web is healthy: {v}");

    d.backends()[0].set_healthy(false);
    f.plugin.tick_at(now + 15).await;
    wait_for(|| rx.seen.lock().unwrap().len() == 1).await;
    let (headers, body) = rx.seen.lock().unwrap()[0].clone();
    assert_eq!(headers["x-heyo-event"], "alert.firing");
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(body["version"], 1);
    assert_eq!(body["namespace"], "team-a");
    assert_eq!(body["status"], "firing");
    assert_eq!(body["alert"]["deployment"], "web", "only team-a's deployment");
    assert_eq!(body["alert"]["severity"], "critical");
    assert_eq!(headers["x-heyo-delivery"], body["delivery_id"].as_str().unwrap());
    // Signed with team-a's secret, whatever namespace the reference named.
    let sig = headers["x-heyo-signature"].to_str().unwrap();
    let (t, _) = sig.split_once(',').unwrap();
    let t: u64 = t.strip_prefix("t=").unwrap().parse().unwrap();
    let raw = rx.raw.lock().unwrap()[0].clone();
    assert_eq!(sig, delivery::signature(b"s3cret", t, &raw).unwrap());

    let (status, v) = call(&f, "team-a", "GET", "/api/alerts", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["active"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["active"][0]["status"], "firing");
    let fp = v["active"][0]["fingerprint"].as_str().unwrap().to_string();
    assert_eq!(fp, engine::fingerprint("team-a", "down", "web"));

    // Another namespace sees nothing of it and cannot ack it.
    f.host.install(PLUGIN_ID, "team-b", json!({}), None).await.unwrap();
    let (_, v) = call(&f, "team-b", "GET", "/api/alerts", Value::Null).await;
    assert_eq!(v["active"], json!([]));
    let (status, _) = call(&f, "team-b", "POST", &format!("/api/alerts/{fp}/ack"), Value::Null).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, v) = call(&f, "team-a", "POST", &format!("/api/alerts/{fp}/ack"), json!({"comment": "on it"})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["acked_by"], "user:alice");

    d.backends()[0].set_healthy(true);
    f.plugin.tick_at(now + 30).await;
    wait_for(|| rx.seen.lock().unwrap().len() == 2).await;
    let (headers, body) = rx.seen.lock().unwrap()[1].clone();
    assert_eq!(headers["x-heyo-event"], "alert.resolved");
    assert_eq!(body["status"], "resolved");
    assert_eq!(body["alert"]["resolved_at"], now + 30);
    let (_, v) = call(&f, "team-a", "GET", "/api/alerts", Value::Null).await;
    assert_eq!(v["active"], json!([]));
    assert_eq!(v["resolved"][0]["fingerprint"], fp.as_str());
    assert!(v["resolved"][0].get("acked_by").is_none(), "an ack clears on resolve");

    let (_, v) = call(&f, "team-a", "GET", "/api/deliveries", Value::Null).await;
    let list = v["deliveries"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert!(list.iter().all(|d| d["status"] == "delivered" && d["attempts"] == 1), "{v}");
    let (_, v) = call(&f, "team-b", "GET", "/api/deliveries", Value::Null).await;
    assert_eq!(v["deliveries"], json!([]));
}

#[tokio::test]
async fn deliveries_retry_with_backoff_and_give_up_after_five_attempts() {
    let f = fixture().await;
    let (rx, url) = receiver(vec![500, 503]).await;
    f.host
        .install(PLUGIN_ID, "team-a", json!({"receivers": [{"id": "ops", "url": url}]}), None)
        .await
        .unwrap();
    let (status, v) = call(&f, "team-a", "POST", "/api/receivers/ops/test", Value::Null).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{v}");
    let id = v["delivery_id"].as_str().unwrap().to_string();
    wait_for(|| {
        f.plugin.deliverer.log("team-a").first().is_some_and(|d| d.status == DeliveryStatus::Delivered)
    })
    .await;
    let log = f.plugin.deliverer.log("team-a");
    assert_eq!(log[0].delivery_id, id);
    assert_eq!(log[0].attempts, 3);
    assert_eq!(log[0].response_status, Some(200));
    let seen = rx.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3);
    assert!(seen.iter().all(|(h, _)| h["x-heyo-event"] == "alert.test" && h.get("x-heyo-signature").is_none()));
    assert!(seen.iter().all(|(h, _)| h["x-heyo-delivery"] == id.as_str()), "one id across retries");

    // A receiver that never succeeds is given up on.
    *rx.statuses.lock().unwrap() = vec![500; 10];
    call(&f, "team-a", "POST", "/api/receivers/ops/test", Value::Null).await;
    wait_for(|| f.plugin.deliverer.log("team-a").first().is_some_and(|d| d.status == DeliveryStatus::Failed)).await;
    assert_eq!(f.plugin.deliverer.log("team-a")[0].attempts, delivery::ATTEMPTS);
    assert_eq!(rx.seen.lock().unwrap().len(), 3 + 5);

    let (status, _) = call(&f, "team-a", "POST", "/api/receivers/nope/test", Value::Null).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_private_receiver_is_refused_at_send_without_the_override() {
    let f = fixture().await;
    let (rx, url) = receiver(vec![]).await;
    f.host
        .install(PLUGIN_ID, "team-a", json!({"receivers": [{"id": "ops", "url": url}]}), None)
        .await
        .unwrap();
    // The operator tightens the policy after the install was accepted.
    f.plugin.deliverer.set_policy(crate::net_guard::Policy::default());
    call(&f, "team-a", "POST", "/api/receivers/ops/test", Value::Null).await;
    wait_for(|| f.plugin.deliverer.log("team-a").first().is_some_and(|d| d.status == DeliveryStatus::Failed)).await;
    let rec = &f.plugin.deliverer.log("team-a")[0];
    assert!(rec.last_error.as_deref().unwrap().contains("https"), "{rec:?}");
    assert!(rx.seen.lock().unwrap().is_empty(), "nothing was sent");
}

#[tokio::test]
async fn checks_probe_only_the_namespaces_own_replicas() {
    let f = fixture().await;
    let good = upstream(200).await;
    let bad = upstream(503).await;
    f.registry.upsert(static_deployment("web", "team-a", &good));
    f.registry.upsert(static_deployment("flaky", "team-a", &bad));
    f.registry.upsert(static_deployment("theirs", "team-b", &good));
    f.host
        .install(
            PLUGIN_ID,
            "team-a",
            json!({
                "checks": [
                    {"id": "web", "deployment": "web", "path": "/healthz"},
                    {"id": "flaky", "deployment": "flaky", "path": "/"},
                    {"id": "teapot", "deployment": "web", "path": "/", "expect_status": 418},
                    {"id": "theirs", "deployment": "theirs", "path": "/"}
                ],
                "rules": [{"id": "flaky", "deployment": "*", "condition": {"type": "check_failing", "check": "flaky"}}],
            }),
            None,
        )
        .await
        .unwrap();
    let now = now_secs();
    f.plugin.tick_at(now).await;
    let (status, v) = call(&f, "team-a", "GET", "/api/checks", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    let by_id = |id: &str| {
        v["checks"].as_array().unwrap().iter().find(|c| c["id"] == id).unwrap()["result"].clone()
    };
    assert_eq!(by_id("web")["ok"], true, "{v}");
    assert_eq!(by_id("web")["passing"], 1);
    assert_eq!(by_id("flaky")["ok"], false);
    assert!(by_id("flaky")["last_error"].as_str().unwrap().contains("503"));
    assert_eq!(by_id("teapot")["ok"], false, "200 is not the expected 418");
    let theirs = by_id("theirs");
    assert_eq!(theirs["ok"], false);
    assert_eq!(theirs["total"], 0, "another namespace's deployment is never probed");
    assert!(theirs["last_error"].as_str().unwrap().contains("no deployment named"));

    let (_, v) = call(&f, "team-a", "GET", "/api/alerts", Value::Null).await;
    assert_eq!(v["active"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["active"][0]["deployment"], "flaky");
    assert_eq!(v["active"][0]["condition"], "check_failing");

    // Not due again until its interval has passed: the result keeps its time.
    f.plugin.tick_at(now + 15).await;
    let (_, v) = call(&f, "team-a", "GET", "/api/checks", Value::Null).await;
    let web = v["checks"].as_array().unwrap().iter().find(|c| c["id"] == "web").unwrap().clone();
    assert_eq!(web["result"]["checked_at"], now);
    f.plugin.tick_at(now + 30).await;
    let (_, v) = call(&f, "team-a", "GET", "/api/checks", Value::Null).await;
    let web = v["checks"].as_array().unwrap().iter().find(|c| c["id"] == "web").unwrap().clone();
    assert_eq!(web["result"]["checked_at"], now + 30);
}

#[tokio::test]
async fn silences_are_namespaced_validated_and_survive_a_restart() {
    let f = fixture().await;
    f.host.install(PLUGIN_ID, "team-a", json!({}), None).await.unwrap();
    f.host.install(PLUGIN_ID, "team-b", json!({}), None).await.unwrap();
    let until = now_secs() + 3600;
    let (status, v) = call(
        &f,
        "team-a",
        "POST",
        "/api/silences",
        json!({"matchers": {"deployment": "web", "severity": "critical"}, "until": until, "comment": "deploy"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["created_by"], "user:alice");
    let id = v["id"].as_str().unwrap().to_string();

    let rfc = chrono::DateTime::from_timestamp((now_secs() + 60) as i64, 0).unwrap().to_rfc3339();
    let (status, v) = call(&f, "team-a", "POST", "/api/silences", json!({"until": rfc})).await;
    assert_eq!(status, StatusCode::CREATED, "rfc3339 until: {v}");
    for bad in [
        json!({"until": 1}),
        json!({"until": "yesterday"}),
        json!({"until": until, "matchers": {"nope": 1}}),
        json!({"until": until, "extra": true}),
        json!({"until": now_secs() + 365 * 86_400}),
    ] {
        let (status, v) = call(&f, "team-a", "POST", "/api/silences", bad.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
    let huge = json!({"until": until, "comment": "x".repeat(20_000)});
    let (status, _) = call(&f, "team-a", "POST", "/api/silences", huge).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let (_, v) = call(&f, "team-b", "GET", "/api/silences", Value::Null).await;
    assert_eq!(v["silences"], json!([]));
    let (status, _) = call(&f, "team-b", "DELETE", &format!("/api/silences/{id}"), Value::Null).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "another namespace cannot remove it");

    // A new process reads the same file.
    let again = AlertingPlugin::new(f.registry.clone(), f.secrets.clone(), &f.state_dir);
    let restored = again.store.namespaces.lock().unwrap()["team-a"].silences.clone();
    assert_eq!(restored.len(), 2);
    assert!(restored.iter().any(|s| s.id == id && s.comment == "deploy"));

    let (status, _) = call(&f, "team-a", "DELETE", &format!("/api/silences/{id}"), Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    let (_, v) = call(&f, "team-a", "GET", "/api/silences", Value::Null).await;
    assert_eq!(v["silences"].as_array().unwrap().len(), 1);

    // Uninstalling forgets the namespace's state.
    f.host.uninstall(PLUGIN_ID, "team-a").await.unwrap();
    assert!(!f.plugin.store.namespaces.lock().unwrap().contains_key("team-a"));
}

#[tokio::test]
async fn an_unreadable_state_file_refuses_changes_and_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("alerting.json"), b"{ not json").unwrap();
    let registry = Arc::new(Registry::new(dir.path().join("state.json")));
    let secrets = Arc::new(SecretStore::new(dir.path().join("secrets.json"), None));
    let plugin = AlertingPlugin::new(registry, secrets, &state_dir);
    let host = PluginHost::new(vec![plugin.clone()], PluginStore::new(dir.path().join("plugins")));
    host.set(PLUGIN_ID, true, Some(json!({"tick_secs": 3600}))).await.unwrap();
    host.install(PLUGIN_ID, "team-a", json!({}), None).await.unwrap();
    let resp = host
        .dispatch_namespace(
            PLUGIN_ID,
            "team-a",
            req("POST", "/api/silences", json!({"until": now_secs() + 60}), None),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    plugin.tick_at(now_secs()).await;
    assert_eq!(std::fs::read(state_dir.join("alerting.json")).unwrap(), b"{ not json");
    assert!(plugin.status().await["state_error"].is_string());
}

#[tokio::test]
async fn the_page_and_the_install_gate() {
    let f = fixture().await;
    let resp = f
        .host
        .dispatch_namespace(PLUGIN_ID, "team-a", req("GET", "/ui", Value::Null, None))
        .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT, "not installed");
    let e = f
        .host
        .install(PLUGIN_ID, "team-a", json!({"receivers": [{"id": "x", "url": "ftp://x"}]}), None)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("scheme"), "{e}");
    f.host.install(PLUGIN_ID, "team-a", json!({}), None).await.unwrap();
    let resp = f
        .host
        .dispatch_namespace(PLUGIN_ID, "team-a", req("GET", "/ui", Value::Null, None))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains(r#"<meta name="plugin-namespace" content="team-a">"#));
    assert!(!html.contains("{{"), "an unfilled placeholder shipped");
    assert!(!html.contains("<script src=\"http"), "self-contained");
    let (status, v) = call(&f, "team-a", "GET", "/api/status", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["namespace"], "team-a");
    let (status, _) = call(&f, "team-a", "GET", "/api/nope", Value::Null).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(f.plugin.meta().id, "alerting");
    assert!(!f.plugin.auto_install(&json!({})));
}

/// The namespace surface's answers, recorded for the clients' wire contract
/// tests (`testdata/wire/alerting-*.json`). Volatile values — ids, ports,
/// wall-clock times — are pinned after the fact.
#[tokio::test]
async fn wire_fixtures_are_recorded() {
    let f = fixture().await;
    let (rx, url) = receiver(vec![]).await;
    let web = f.registry.upsert(static_deployment("web", "team-a", "127.0.0.1:9"));
    let api = f.registry.upsert(static_deployment("api", "team-a", "127.0.0.1:9"));
    web.backends()[0].set_healthy(false);
    api.backends()[0].set_healthy(false);
    f.host
        .install(
            PLUGIN_ID,
            "team-a",
            json!({
                "receivers": [{"id": "ops", "url": url, "secret": {"secret": "hook", "key": "key"}}],
                "rules": [{"id": "down", "deployment": "*", "condition": {"type": "no_healthy_replicas"},
                           "severity": "critical", "receivers": ["ops"]},
                          {"id": "home", "deployment": "web", "condition": {"type": "check_failing", "check": "home"},
                           "for_secs": 60}],
                "checks": [{"id": "home", "deployment": "web", "path": "/healthz", "expect_status": 200}],
            }),
            None,
        )
        .await
        .unwrap();
    f.secrets.put(SecretSpec {
        id: "hook".into(),
        namespace: "team-a".into(),
        description: None,
        data: [("key".to_string(), "k".to_string())].into(),
        updated_at: 0,
    });
    let t0 = 1_760_000_000;
    f.plugin.tick_at(t0).await;
    api.backends()[0].set_healthy(true);
    f.plugin.tick_at(t0 + 15).await;
    for _ in 0..300 {
        if rx.seen.lock().unwrap().len() >= 3 { break; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(rx.seen.lock().unwrap().len(), 3, "{:#?}", f.plugin.deliverer.log("team-a"));
    let web_fp = engine::fingerprint("team-a", "down", "web");
    let (status, _) = call(&f, "team-a", "POST", &format!("/api/alerts/{web_fp}/ack"), json!({"comment": "on it"})).await;
    assert_eq!(status, StatusCode::OK);
    let (status, mut silence) = call(
        &f,
        "team-a",
        "POST",
        "/api/silences",
        json!({"matchers": {"deployment": "web", "severity": "critical"}, "until": now_secs() + 86_400, "comment": "deploy"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    silence["id"] = json!("sil_0123456789abcdef");
    silence["created_at"] = json!(t0 + 20);
    silence["until"] = json!(t0 + 86_400);
    crate::admin::wire_golden::golden("alerting-silence", &silence);

    let (_, mut alerts) = call(&f, "team-a", "GET", "/api/alerts", Value::Null).await;
    for a in alerts["active"].as_array_mut().unwrap() {
        if a.get("acked_at").is_some() {
            a["acked_at"] = json!(t0 + 18);
        }
    }
    assert_eq!(alerts["active"].as_array().unwrap().len(), 2, "{alerts}");
    assert_eq!(alerts["resolved"].as_array().unwrap().len(), 1, "{alerts}");
    crate::admin::wire_golden::golden("alerting-alerts", &alerts);

    let (_, checks) = call(&f, "team-a", "GET", "/api/checks", Value::Null).await;
    crate::admin::wire_golden::golden("alerting-checks", &checks);

    let (_, mut status) = call(&f, "team-a", "GET", "/api/status", Value::Null).await;
    status["receivers"][0]["endpoint"] = json!("https://hooks.example.com");
    crate::admin::wire_golden::golden("alerting-status", &status);

    let (_, mut deliveries) = call(&f, "team-a", "GET", "/api/deliveries", Value::Null).await;
    let list = deliveries["deliveries"].as_array_mut().unwrap();
    list.retain(|d| d["event"] == "alert.resolved");
    for d in list.iter_mut() {
        d["delivery_id"] = json!("dlv_0123456789abcdef01234567");
        d["created_at"] = json!(t0 + 15);
        d["updated_at"] = json!(t0 + 15);
    }
    crate::admin::wire_golden::golden("alerting-deliveries", &deliveries);

    let (status, mut test) = call(&f, "team-a", "POST", "/api/receivers/ops/test", Value::Null).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    test["delivery_id"] = json!("dlv_0123456789abcdef01234567");
    crate::admin::wire_golden::golden("alerting-test-delivery", &test);
}

#[tokio::test]
async fn a_paused_rollout_fires_rollout_stalled_and_resolves_when_it_moves_on() {
    use crate::deployment::{DeploymentState, RolloutPhase, RolloutProgress};
    let f = fixture().await;
    let (rx, url) = receiver(vec![]).await;
    let d = f.registry.upsert(static_deployment("web", "team-a", "127.0.0.1:9"));
    f.host
        .install(
            PLUGIN_ID,
            "team-a",
            json!({
                "receivers": [{"id": "ops", "url": url}],
                "rules": [{"id": "stuck", "deployment": "web", "condition": {"type": "rollout_stalled"},
                           "severity": "warning", "receivers": ["ops"]}],
            }),
            Some("user:alice".into()),
        )
        .await
        .unwrap();
    let set_phase = |phase: RolloutPhase| {
        let mut progress =
            RolloutProgress::new("rev-2".into(), crate::config::RolloutStrategy::Rolling, 0);
        progress.phase = phase;
        let mut state: DeploymentState = (*d.state()).clone();
        state.rollout_progress = Some(progress);
        d.set_state(state);
    };

    let now = now_secs();
    set_phase(RolloutPhase::Progressing);
    f.plugin.tick_at(now).await;
    let (_, v) = call(&f, "team-a", "GET", "/api/alerts", Value::Null).await;
    assert_eq!(v["active"], json!([]), "a progressing rollout is not stalled: {v}");

    set_phase(RolloutPhase::Paused { reason: "new replicas never became healthy".into() });
    f.plugin.tick_at(now + 15).await;
    wait_for(|| rx.seen.lock().unwrap().len() == 1).await;
    let (headers, body) = rx.seen.lock().unwrap()[0].clone();
    assert_eq!(headers["x-heyo-event"], "alert.firing");
    assert_eq!(body["alert"]["rule"], "stuck");
    assert_eq!(body["alert"]["deployment"], "web");

    set_phase(RolloutPhase::Complete);
    f.plugin.tick_at(now + 30).await;
    wait_for(|| rx.seen.lock().unwrap().len() == 2).await;
    assert_eq!(rx.seen.lock().unwrap()[1].0["x-heyo-event"], "alert.resolved");
}
