//! Live end-to-end: five firecracker VMs on a real app-lb, through `hws`.
//!
//! Ignored by default; it creates real VMs. Run it against an app-lb with a
//! namespace token:
//!
//! ```sh
//! HWS_E2E_URL=https://admin.us5.heyo.work \
//! HWS_E2E_TOKEN=applb_… HWS_E2E_NAMESPACE=e2e HWS_E2E_DOMAIN=us5.heyo.work \
//!   cargo test -p hws --test e2e_live -- --ignored --nocapture
//! ```
//!
//! | Variable | Default | |
//! | --- | --- | --- |
//! | `HWS_E2E_URL` | — | app-lb admin API |
//! | `HWS_E2E_TOKEN` | — | an admin token for the namespace |
//! | `HWS_E2E_NAMESPACE` | `e2e` | where the deployments go |
//! | `HWS_E2E_DOMAIN` | — | base domain the last VM is routed under (`<id>.<domain>`); omitted skips the public fetch |
//! | `HWS_E2E_STORE` | `https://hub.heyo.work` | where the image is pulled from |
//! | `HWS_E2E_IMAGE` | `heyo/alpine:3.24` | the public alpine image |
//! | `HWS_E2E_REPORT` | — | write the latency report here as JSON |
//!
//! What it does, timing each step:
//!
//! 1. Registers five deployments from the public alpine image at zero
//!    replicas, concurrently, pulls the image into each, then scales each to
//!    one VM. Creation latency is register → pull done → first healthy VM.
//!    The image runs only sshd, so readiness is a TCP check on port 22.
//! 2. Runs the same exec commands in every VM, timing each call.
//! 3. In the last VM, writes a "Heyo World" page and serves it on port 8080
//!    with busybox `nc -lk -e`, then adds a public route to the deployment and
//!    fetches the page through app-lb. The route is added to the live spec so
//!    the pool (and the server in it) is kept.
//! 4. Deletes all five, whatever happened.

use std::time::{Duration, Instant};

use hws::{Client, ExecRequest};
use serde_json::{Value, json};

const VMS: usize = 5;
const PORT: u16 = 8080;
const HTML: &str = "<!doctype html><title>Heyo World</title><h1>Heyo World</h1>";

/// One connection: read the request head, answer with the page. `nc -lk -e`
/// runs it per connection with the socket on stdin/stdout.
const SERVE_SH: &str = "#!/bin/sh\n\
while IFS= read -r line; do line=$(printf '%s' \"$line\" | tr -d '\\r'); [ -z \"$line\" ] && break; done\n\
body=$(cat /srv/heyo/index.html)\n\
printf 'HTTP/1.1 200 OK\\r\\nContent-Type: text/html; charset=utf-8\\r\\nContent-Length: %s\\r\\nConnection: close\\r\\n\\r\\n%s' \"${#body}\" \"$body\"\n";

/// Commands run in every VM, with what their output must contain.
const COMMANDS: &[(&str, &str)] = &[
    ("true", ""),
    ("echo heyo", "heyo"),
    ("cat /etc/alpine-release", "3."),
    ("uname -s", "Linux"),
    ("ls /", "etc"),
];

struct Env {
    url: String,
    token: String,
    namespace: String,
    domain: Option<String>,
    store: String,
    image: String,
    report: Option<String>,
}

impl Env {
    fn load() -> Option<Self> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Some(Self {
            url: var("HWS_E2E_URL")?,
            token: var("HWS_E2E_TOKEN")?,
            namespace: var("HWS_E2E_NAMESPACE").unwrap_or_else(|| "e2e".into()),
            domain: var("HWS_E2E_DOMAIN"),
            store: var("HWS_E2E_STORE").unwrap_or_else(|| "https://hub.heyo.work".into()),
            image: var("HWS_E2E_IMAGE").unwrap_or_else(|| "heyo/alpine:3.24".into()),
            report: var("HWS_E2E_REPORT"),
        })
    }
}

fn spec(env: &Env, id: &str) -> Value {
    json!({
        "id": id,
        "namespace": env.namespace,
        "routes": [],
        "vm": { "driver": "firecracker", "port": PORT, "size_class": "small" },
        "artifact": { "store": env.store, "ref": env.image },
        "health": { "path": null, "port": 22 },
        "scaling": {
            // Zero until the image is pulled: a pool asked for a VM before
            // then boots the default image instead, fails, and backs off.
            "min_replicas": 0, "max_replicas": 1, "warm_pool": 0,
            "boot_timeout_secs": 180, "scale_to_zero_after_secs": 900
        }
    })
}

fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1000.0 * 10.0).round() / 10.0
}

#[derive(Debug, Default, serde::Serialize)]
struct Creation {
    id: String,
    register_ms: f64,
    pull_ms: f64,
    boot_ms: f64,
    total_ms: f64,
    sandbox_id: String,
}

/// Register, pull, and wait for the first healthy VM, timing each.
async fn create(lb: &Client, env: &Env, id: &str) -> Result<Creation, String> {
    let t0 = Instant::now();
    lb.create_deployment(&spec(env, id))
        .await
        .map_err(|e| format!("{id}: register: {e}"))?;
    let registered = t0.elapsed();

    // An artifact deployment boots nothing until its image is pulled.
    let job = lb
        .start_pull(id, None, false)
        .await
        .map_err(|e| format!("{id}: pull: {e}"))?;
    let done = lb
        .wait_for_job(&job.id)
        .in_deployment(id)
        .timeout(Duration::from_secs(300))
        .await_done()
        .await
        .map_err(|e| format!("{id}: pull job: {e}"))?;
    if done.status != "succeeded" {
        return Err(format!("{id}: pull {}: {:?}", done.status, done.error));
    }
    let pulled = t0.elapsed();

    lb.patch_scaling(id, &json!({ "min_replicas": 1 }))
        .await
        .map_err(|e| format!("{id}: scale to 1: {e}"))?;
    let status = lb
        .wait_for_ready(id)
        .timeout(Duration::from_secs(240))
        .await_ready()
        .await
        .map_err(|e| format!("{id}: ready: {e}"))?;
    let total = t0.elapsed();
    let sandbox_id = status
        .vms
        .first()
        .map(|v| v.sandbox_id.clone())
        .unwrap_or_default();
    Ok(Creation {
        id: id.to_string(),
        register_ms: ms(registered),
        pull_ms: ms(pulled - registered),
        boot_ms: ms(total - pulled),
        total_ms: ms(total),
        sandbox_id,
    })
}

#[derive(Debug, serde::Serialize)]
struct ExecTiming {
    id: String,
    command: String,
    ms: f64,
}

#[derive(Debug, Default, serde::Serialize)]
struct Report {
    app_lb: String,
    image: String,
    creations: Vec<Creation>,
    execs: Vec<ExecTiming>,
    heyo_world_url: Option<String>,
    heyo_world_first_200_ms: Option<f64>,
}

fn summary(label: &str, mut v: Vec<f64>) {
    if v.is_empty() {
        return;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = v[v.len() / 2];
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    println!(
        "{label:<22} n={:<3} min={:>9.1}ms p50={:>9.1}ms mean={:>9.1}ms max={:>9.1}ms",
        v.len(),
        v[0],
        p50,
        mean,
        v[v.len() - 1]
    );
}

/// Steps 2 and 3. Separate from the test body so cleanup runs on any failure.
async fn exercise(
    lb: &Client,
    env: &Env,
    ids: &[String],
    report: &mut Report,
) -> Result<(), String> {
    // Step 1: create all five at once, each timed on its own.
    let created = futures::future::join_all(ids.iter().map(|id| create(lb, env, id))).await;
    for c in created {
        report.creations.push(c?);
    }

    // Step 2: exec latency, every command in every VM.
    for id in ids {
        for (command, want) in COMMANDS {
            let t = Instant::now();
            let out = lb
                .exec(id, &ExecRequest::new(*command).timeout_secs(20))
                .await
                .map_err(|e| format!("{id}: exec {command:?}: {e}"))?;
            let took = t.elapsed();
            if out.exit_code != 0 || !out.stdout.contains(want) {
                return Err(format!(
                    "{id}: {command:?} exited {} with {:?}",
                    out.exit_code, out.stdout
                ));
            }
            report.execs.push(ExecTiming {
                id: id.clone(),
                command: command.to_string(),
                ms: ms(took),
            });
        }
    }

    // Step 3: serve "Heyo World" from the last VM.
    let last = ids.last().expect("five ids");
    let start = format!(
        "mkdir -p /srv/heyo && printf '%s' \"$SERVE\" > /srv/heyo/serve.sh && chmod +x /srv/heyo/serve.sh \
         && printf '%s' \"$HTML\" > /srv/heyo/index.html \
         && (setsid nohup nc -lk -p {PORT} -e /srv/heyo/serve.sh </dev/null >/dev/null 2>&1 &) \
         && sleep 1 && curl -s http://127.0.0.1:{PORT}/"
    );
    let out = lb
        .exec(
            last,
            &ExecRequest::new(start)
                .env("SERVE", SERVE_SH)
                .env("HTML", HTML)
                .timeout_secs(20),
        )
        .await
        .map_err(|e| format!("{last}: start server: {e}"))?;
    if !out.stdout.contains("Heyo World") {
        return Err(format!(
            "{last}: the server did not answer in the guest: {out:?}"
        ));
    }

    let Some(domain) = &env.domain else {
        println!("HWS_E2E_DOMAIN unset: served in the guest, public fetch skipped");
        return Ok(());
    };
    let host = format!("{last}.{domain}");
    // The live spec, not the one registered: the pull filled in `vm.image`,
    // and a `vm` that differs would recycle the pool and the server with it.
    let current = lb
        .deployment(last)
        .await
        .map_err(|e| format!("{last}: get: {e}"))?;
    let before = current.vms.first().map(|v| v.sandbox_id.clone());
    // Raw, so every field of the live spec round-trips, including ones this
    // client has no type for.
    let listed = lb
        .raw()
        .deployments_in(&env.namespace)
        .await
        .map_err(|e| format!("{last}: list: {e}"))?;
    let mut live = listed
        .as_array()
        .and_then(|rows| rows.iter().find(|d| d["spec"]["id"] == json!(last)))
        .map(|d| d["spec"].clone())
        .ok_or_else(|| format!("{last}: not in the namespace listing"))?;
    live["routes"] = json!([{ "host": host }]);
    let replaced = lb
        .replace_deployment(last, &live)
        .await
        .map_err(|e| format!("{last}: add route: {e}"))?;
    let after = replaced.vms.first().map(|v| v.sandbox_id.clone());
    if before != after {
        return Err(format!(
            "{last}: adding a route recycled the pool ({before:?} -> {after:?})"
        ));
    }

    let url = format!("https://{host}/");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let t = Instant::now();
    let mut last_err = String::new();
    // A new exact host gets its certificate within seconds; allow two minutes.
    while t.elapsed() < Duration::from_secs(120) {
        match http.get(&url).send().await {
            Ok(r) if r.status().is_success() => {
                let body = r.text().await.unwrap_or_default();
                if body.contains("Heyo World") {
                    report.heyo_world_url = Some(url.clone());
                    report.heyo_world_first_200_ms = Some(ms(t.elapsed()));
                    return Ok(());
                }
                last_err = format!("200 without the page: {body:?}");
            }
            Ok(r) => last_err = format!("HTTP {}", r.status()),
            Err(e) => last_err = e.to_string(),
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    Err(format!("{url}: never served Heyo World: {last_err}"))
}

#[tokio::test]
#[ignore = "creates five live VMs; set HWS_E2E_* and pass --ignored"]
async fn five_alpine_vms_exec_and_heyo_world() {
    let Some(env) = Env::load() else {
        eprintln!("HWS_E2E_URL / HWS_E2E_TOKEN unset; skipping");
        return;
    };
    let lb = Client::builder(&env.url)
        .token(&env.token)
        .timeout(Duration::from_secs(60))
        .build()
        .expect("client builds");

    let run = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 0xff_ffff
    );
    let ids: Vec<String> = (1..=VMS).map(|i| format!("e2e-rs-{run}-{i}")).collect();
    let mut report = Report {
        app_lb: env.url.clone(),
        image: format!("{}/{}", env.store, env.image),
        ..Default::default()
    };

    let result = exercise(&lb, &env, &ids, &mut report).await;

    // Step 4, unconditionally.
    for id in &ids {
        if let Err(e) = lb.delete_deployment(id).await {
            eprintln!("cleanup: {id}: {e}");
        }
    }

    println!("\n== hws e2e against {} ({})", report.app_lb, report.image);
    for c in &report.creations {
        println!(
            "create {:<22} register={:>7.1}ms pull={:>8.1}ms boot={:>8.1}ms total={:>8.1}ms {}",
            c.id, c.register_ms, c.pull_ms, c.boot_ms, c.total_ms, c.sandbox_id
        );
    }
    summary(
        "create total",
        report.creations.iter().map(|c| c.total_ms).collect(),
    );
    summary(
        "create boot",
        report.creations.iter().map(|c| c.boot_ms).collect(),
    );
    summary("exec", report.execs.iter().map(|e| e.ms).collect());
    if let (Some(url), Some(t)) = (&report.heyo_world_url, report.heyo_world_first_200_ms) {
        println!("heyo world             {url} first 200 after {t:.1}ms");
    }
    if let Some(path) = &env.report {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).expect("report written");
    }

    if let Err(e) = result {
        panic!("{e}");
    }
    assert_eq!(report.creations.len(), VMS);
    assert_eq!(report.execs.len(), VMS * COMMANDS.len());
}
