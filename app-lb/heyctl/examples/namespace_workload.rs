//! Create a workload in your namespace, collect its telemetry, read its logs,
//! roll it to a new image and delete it — with nothing but a namespace token.
//!
//! ```sh
//! HEYCTL_SERVER=https://admin.example.com HEYCTL_TOKEN=applb_… \
//!     cargo run --example namespace_workload
//! ```
//!
//! Kept identical to the quick start in the README.

use hws::{Client, LogQuery};
use serde_json::json;
use std::time::Duration;

#[tokio::main]
async fn main() -> hws::Result<()> {
    let lb = Client::builder(
        std::env::var("HEYCTL_SERVER").unwrap_or_else(|_| "http://127.0.0.1:9090".into()),
    )
    .token(std::env::var("HEYCTL_TOKEN").expect("set HEYCTL_TOKEN"))
    .build()?;

    // Who am I, and where can I deploy?
    let me = lb.whoami().await?;
    let ns = me.sole_namespace().unwrap_or("default").to_string();

    // Create a workload: a managed microVM pool behind a hostname.
    lb.create_deployment(&json!({
        "id": "web",
        "namespace": ns,
        "routes": [{"host": "web.example.com"}],
        "vm": {"image": "nginx-fc", "port": 80},
        "scaling": {"min_replicas": 1, "max_replicas": 4},
    }))
    .await?;
    lb.wait_for_ready("web")
        .timeout(Duration::from_secs(300))
        .await?;

    // Collect its telemetry — once per namespace — and read it back.
    lb.install_plugin(&ns, "obs", None).await?;
    let obs = lb.obs(&ns);
    for d in obs.fleet(Some("1h")).await?.deployments {
        println!(
            "{}: {} log lines, {} errors",
            d.id, d.log_lines, d.error_logs
        );
    }
    for line in obs
        .logs("web", &LogQuery::new().level("error").limit(20))
        .await?
        .rows
    {
        println!("{} {}", line.ts, line.message);
    }

    // Change it: whole-spec replace, or a rollout that verifies the new pool
    // before draining the old one.
    let current = lb.deployment("web").await?;
    let mut spec = lb.raw().spec("web").await?;
    spec["vm"]["image"] = json!("nginx-fc:1.27");
    let op = lb
        .start_rollout("web", "web-1-27", &current.rollout_revision, &spec)
        .await?;
    println!("rollout {} is {}", op.operation_id, op.status);

    lb.delete_deployment("web").await?;
    Ok(())
}
