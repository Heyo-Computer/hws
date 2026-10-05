//! CI orchestration and dashboard for heyvm networks.
//!
//! A machine becomes a runner by running `heyvmd` and joining a heyvm network —
//! there is no agent to install. This process discovers those hosts, opens an
//! iroh tunnel to each, and drives workflow jobs on them: claiming or creating a
//! VM from a fingerprinted pool, running each step through the daemon's async
//! exec-operation API, and streaming the output back.
//!
//! Startup order is deliberate. Config is resolved and *fully* validated before
//! anything binds a port or dials NATS, so a misconfiguration is a non-zero exit
//! with a message naming the variable — not a process that supervisord reports
//! as `RUNNING` while every job fails.

mod application_lifecycle;
mod artifacts;
mod bus;
mod cd;
// The platform UI kit — tokens, the theme cookie and forwarded identity —
// shared with app-lb, app-obs, heyosecret and artifacts. Included by path
// rather than depended on as a crate: those five apps sit on three different
// axum versions, so the shared module deliberately names no framework type and
// each one wires its own routes. See `ui/README.md`.
mod config;
mod controller_rollout;
mod debug_report;
mod dispatch;
mod executor;
mod expr;
mod host_app_lb;
mod host_bootstrap;
mod host_bootstrap_delivery;
mod host_heyvm_bootstrap;
mod host_heyvm_bootstrap_coordinator;
mod host_maintenance;
#[path = "../../ui/ui.rs"]
mod heyo_ui;
mod image;
mod managed_update;
mod nats_auth;
mod native;
mod objects;
mod paths;
mod plan;
mod pool;
mod regional_update;
mod release;
mod release_build;
mod release_catalog;
mod release_git;
mod release_policy;
mod repos;
mod runners;
mod secrets;
mod service_archive;
mod service_rollout;
mod store;
mod submission;
mod trigger;
mod vm;
mod vm_cleanup;
mod web;
mod workflow;

use bus::Bus;
use config::Config;
use dispatch::Dispatcher;
use pool::Pool;
use runners::{RunnerError, Runners};
use std::sync::Arc;
use std::time::Duration;
use store::Store;
use vm::Vms;

#[tokio::main]
async fn main() {
    // WSS client setup cannot infer a provider when the dependency graph
    // enables both ring and AWS-LC. Select it before any TLS client is built.
    if rustls::crypto::aws_lc_rs::default_provider().install_default().is_err() {
        eprintln!("ci: rustls crypto provider was already installed");
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        if matches!(args[0].as_str(), "--hold-executor-recovery" | "--transfer-executor-recovery") {
            eprintln!("{} is no longer supported; executor ownership is scoped to each process boot", args[0]);
            std::process::exit(2);
        }
        if args[0] == "--inspect-executor" && args.len() == 1 {
            let result: anyhow::Result<serde_json::Value> = async {
                let config = Config::from_env()?;
                let store = Store::connect(&config.database_url, config.log_dir.clone(), config.db_statement_timeout).await?;
                let boots: Vec<serde_json::Value> = sqlx::query_scalar("SELECT jsonb_build_object('bootId',boot_id,'deployment',deployment_id,'registeredAt',registered_at,'readyAt',ready_at,'retired',retired) FROM ci_executor_boot ORDER BY registered_at DESC,boot_id")
                    .fetch_all(store.pool()).await?;
                Ok(serde_json::json!({"boots":boots}))
            }.await;
            match result {
                Ok(value) => println!("{value}"),
                Err(error) => { eprintln!("executor inspection failed: {error}"); std::process::exit(1); }
            }
            return;
        }
        if args[0] == "--reconcile-service-rollout" && args.len() == 3 {
            let result: anyhow::Result<()> = async {
                let config = Config::from_env()?;
                let store = Store::connect(&config.database_url, config.log_dir.clone(), config.db_statement_timeout).await?;
                service_rollout::recover(&store, &secrets::Secrets::new(&config), &args[1], &args[2]).await
            }.await;
            match result {
                Ok(()) => println!("Service rollout receipt checked; original run and job history preserved."),
                Err(_) => {
                    eprintln!("Service rollout recovery unresolved; drain fence retained.");
                    std::process::exit(1);
                }
            }
            return;
        }
        if args[0] == "--deliver-host-bootstrap" && matches!(args.len(), 6 | 7) {
            let targets = std::env::var("CI_HOST_APP_LB_TARGETS").ok();
            let token = std::env::var("CI_HOST_APP_LB_TOKEN").unwrap_or_default();
            match host_bootstrap_delivery::run(&args[1], &args[2], args[3].as_ref(), args[4].as_ref(), args[5].as_ref(), args.get(6).map(String::as_str), targets.as_deref(), &token).await {
                Ok(status) => println!("{status}"),
                Err(error) => {
                    eprintln!("bootstrap delivery incomplete: {error}");
                    std::process::exit(1);
                }
            }
            return;
        }
        if args[0] == "--prepare-host-bootstrap" && args.len() == 5 {
            match host_bootstrap::run(args[1].as_ref(), args[2].as_ref(), args[3].as_ref(), args[4].as_ref()) {
                Ok(status) => println!("{status}"),
                Err(error) => {
                    eprintln!("bootstrap preparation refused: {error}");
                    std::process::exit(1);
                }
            }
            return;
        }
        if args[0] == "--check-host-bootstrap" && args.len() == 4 {
            let targets = std::env::var("CI_HOST_APP_LB_TARGETS").ok();
            let token = std::env::var("CI_HOST_APP_LB_TOKEN").unwrap_or_default();
            match host_bootstrap::check(args[2].as_ref(), &args[3], &args[1], targets.as_deref(), &token).await {
                Ok(status) => println!("{status}"),
                Err(error) => {
                    eprintln!("bootstrap remains unverified: {error}");
                    std::process::exit(1);
                }
            }
            return;
        }
        if args[0] != "--check-workflows" || args.len() < 2 {
            eprintln!("usage: ci [--inspect-executor | --check-workflows FILE ... | --prepare-host-bootstrap PLAN_JSON INSPECTION_JSON BUNDLE OUTPUT_JSON | --deliver-host-bootstrap TARGET inspect|admit INPUT_JSON BUNDLE JOURNAL_JSON | --check-host-bootstrap TARGET MANIFEST_JSON INTENT_SHA256]");
            std::process::exit(2);
        }
        let mut failed = false;
        for path in &args[1..] {
            let result = std::fs::read_to_string(path)
                .map_err(|e| format!("{path}: {e}"))
                .and_then(|yaml| workflow::Workflow::parse(path, &yaml).map_err(|e| e.to_string()))
                .and_then(|workflow| plan::Plan::build(&workflow).map_err(|e| e.to_string()));
            match result {
                Ok(plan) => println!("{path}: valid plan ({} jobs)", plan.jobs.len()),
                Err(error) => {
                    eprintln!("{path}: {error}");
                    failed = true;
                }
            }
        }
        // Offline: no configuration, database, broker or runner connections.
        std::process::exit(if failed { 1 } else { 0 });
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,ci=debug".into()),
        )
        .init();

    let config = match Config::from_env() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            // stderr as well as the log: a startup failure has to be visible in
            // `supervisorctl tail` even when the log filter is set to `error`.
            eprintln!("ci: refusing to start — {e}");
            tracing::error!("refusing to start: {e}");
            std::process::exit(1);
        }
    };

    if config.nats.credential_from_url {
        tracing::warn!(
            "the NATS credential arrived inside CI_NATS_URL, which is visible in \
             shell history and process listings; prefer CI_NATS_TOKEN, \
             CI_NATS_USER/CI_NATS_PASSWORD, CI_NATS_CREDS or CI_NATS_NKEY"
        );
    }

    tracing::info!("{} starting — {}", config.name, config.summary());

    let secrets_client = secrets::Secrets::new(&config);
    let objects = Arc::new(objects::Workflows::new(&config));
    let runners = Arc::new(Runners::new(config.clone()));
    // The first read of the pool is awaited so a network that does not exist is
    // reported now rather than by the first job. Which failures are fatal is the
    // distinction that matters: naming a network wrongly is a configuration
    // error and behaves like one, while a cloud that is merely unreachable
    // right now must not stop the dashboard from serving — the refresh loop
    // will pick the pool up when it recovers.
    match runners.refresh().await {
        Ok(()) => {
            let pool = runners.snapshot();
            for set in pool.served() {
                tracing::info!(
                    "serving network {} ({}): {} runner(s), {} online{}",
                    set.network_name,
                    set.network_id,
                    set.runners.len(),
                    set.dispatchable().count(),
                    if set.network_id == pool.default_network_id {
                        " — the default for a repository that names none"
                    } else {
                        ""
                    },
                );
            }
            // Named, because "I assigned that network and nothing built" is
            // otherwise answered only by reading a page nobody thought to open.
            let unserved: Vec<&str> = pool
                .networks
                .iter()
                .filter(|n| !n.served)
                .map(|n| n.network_name.as_str())
                .collect();
            if !unserved.is_empty() {
                tracing::info!(
                    "not serving {} other network(s) on this account: {}. Add one to \
                     CI_NETWORK, or set CI_NETWORK=*, to build for it.",
                    unserved.len(),
                    unserved.join(", ")
                );
            }
        }
        Err(e @ (RunnerError::UnknownNetwork { .. } | RunnerError::AmbiguousNetwork { .. })) => {
            eprintln!("ci: refusing to start — {e}");
            tracing::error!("refusing to start: {e}");
            std::process::exit(1);
        }
        Err(e) => {
            tracing::warn!("could not read the runner pool at startup, will retry: {e}");
        }
    }
    runners.clone().spawn_refresh_loop();

    // Postgres before NATS: a bad connection string is far more common than a
    // bad NATS one, and failing on the likelier cause first makes the message
    // people actually see the useful one.
    let store = match Store::connect(
        &config.database_url,
        config.log_dir.clone(),
        config.db_statement_timeout,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ci: refusing to start — {e}");
            std::process::exit(1);
        }
    };
    // The embedded set always, first: the binary's own schema is not
    // optional. A directory, if one is named, runs *after* it — so a stale
    // CI_MIGRATIONS_DIR left in a supervisor conf from before the migrations
    // were compiled in cannot shadow the binary, only add to it.
    if let Err(e) = store.migrate().await {
        eprintln!("ci: refusing to start — {e}");
        std::process::exit(1);
    }
    if let Some(dir) = &config.migrations_dir {
        tracing::warn!(
            "CI_MIGRATIONS_DIR is set: also running SQL from {} after the {} migrations \
             compiled into this binary",
            dir.display(),
            store::EMBEDDED_MIGRATIONS.len()
        );
        if let Err(e) = store.migrate_from_dir(dir).await {
            eprintln!("ci: refusing to start — {e}");
            std::process::exit(1);
        }
    }
    tracing::info!(
        "database ready ({} migrations applied)",
        store::EMBEDDED_MIGRATIONS.len()
    );
    match store.import_sources(&config.workspace_dir, config.max_source_bytes).await {
        Ok(count) => tracing::info!(count, "retained source descriptors verified in shared storage"),
        Err(e) => {
            eprintln!("ci: refusing to start — {e}");
            std::process::exit(1);
        }
    }
    match store.import_logs().await {
        Ok(count) => tracing::info!(count, "retained logs imported into shared storage"),
        Err(e) => {
            eprintln!("ci: refusing to start — {e}");
            std::process::exit(1);
        }
    }

    let bus = match Bus::connect(&config.nats, &config.nats_prefix).await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            eprintln!("ci: refusing to start — {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(
        "jetstream ready: {} / {}",
        bus.jobs_stream(),
        bus.events_stream()
    );
    let artifacts = match artifacts::sink_for(&config) {
        Ok(s) => Arc::from(s),
        Err(e) => {
            eprintln!("ci: refusing to start — {e}");
            std::process::exit(1);
        }
    };
    // Said once, at startup, because it is the one configuration where the
    // repositories page has no gate of its own — and minting a submit token is
    // minting the right to run code on a runner.
    if config.admin_emails.is_empty() {
        tracing::warn!(
            "CI_ADMIN_EMAILS is empty, so /repos accepts a request that carries no app-lb \
             identity: on a deployment reachable by anyone, anyone can register a \
             repository and mint a submit token. Set CI_ADMIN_EMAILS."
        );
    }

    if !secrets_client.is_configured() {
        tracing::warn!(
            "heyosecret is not configured, so `${{{{ secrets.* }}}}` will resolve empty. \
             Set CI_HEYOSECRET_URL and CI_HEYOSECRET_TOKEN."
        );
    }

    // Register only after binding so failed listeners do not advertise a boot.
    let listener = match tokio::net::TcpListener::bind(config.listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ci: cannot bind CI_LISTEN_ADDR={} — {e}", config.listen_addr);
            std::process::exit(1);
        }
    };
    // Deployment IDs are scoped to their regional authority; both regions may
    // legitimately use the same ID for instances of the one CI application.
    let executor_identity = executor::identity(&config);
    let executor = executor::ExecutorInstance::register(store.pool().clone(), &executor_identity).await;
    let dispatcher = Arc::new(Dispatcher {
        executor: Arc::new(match executor {
            Ok(owner) => owner,
            Err(e) => { eprintln!("ci: refusing to start — {e}"); std::process::exit(1); }
        }),
        config: config.clone(),
        store: store.clone(),
        pool: Pool::new(store.pool().clone()),
        images: image::Catalog::new(store.pool().clone()),
        bus: bus.clone(),
        runners: runners.clone(),
        vms: Arc::new(Vms::new()),
        secrets: secrets_client,
        artifacts,
        objects: objects.clone(),
    });

    // One eager read so a misconfigured CI_APP_LB_URL is visible at startup
    // rather than at the first submit.
    if objects.is_configured() {
        match objects.refresh().await {
            Ok(()) => tracing::info!(
                "{} workflow object(s) registered in app-lb",
                objects.snapshot().workflows.len()
            ),
            Err(e) => tracing::warn!("could not read workflow objects at startup: {e}"),
        }
    }
    objects.clone().spawn_refresh_loop();

    start_execution(dispatcher.clone()).await;

    let app = web::router(
        config.clone(),
        runners.clone(),
        store.clone(),
        dispatcher.clone(),
    );
    tracing::info!("listening on http://{}", config.listen_addr);

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!("server stopped: {e}");
        std::process::exit(1);
    }
    tracing::info!("shut down cleanly");
}

async fn start_execution(dispatcher: Arc<Dispatcher>) {
    dispatcher.bus.clone().spawn_outbox_publisher(dispatcher.store.clone());
    spawn_log_sweeper(dispatcher.config.clone(), dispatcher.store.clone());
    if let Ok(_effect) = dispatcher.executor.effect_permit().await {
        if let Err(e) = dispatcher.reclaim_pool().await {
            tracing::warn!("could not reclaim the VM pool: {e}");
        }
    }
    dispatcher.clone().spawn_lease_loop();
    dispatcher.clone().spawn_consumers();
    application_lifecycle::spawn(dispatcher.clone());
    controller_rollout::spawn(dispatcher.clone());
    regional_update::spawn(dispatcher.clone());
    service_rollout::spawn(dispatcher.clone());
    managed_update::spawn(dispatcher.clone());
    host_maintenance::spawn(dispatcher.clone());
    host_heyvm_bootstrap_coordinator::spawn(dispatcher.clone());
    vm_cleanup::spawn(dispatcher.clone());
    debug_report::spawn(dispatcher.clone());
    release_build::spawn(dispatcher.clone());

    if let Err(e) = dispatcher.executor.mark_ready().await {
        eprintln!("ci: refusing to announce readiness — {e}");
        std::process::exit(1);
    }
    let executor = dispatcher.executor.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if let Err(error) = executor.mark_ready().await {
                tracing::warn!(%error, "could not refresh CI instance readiness");
            }
        }
    });

}

/// Delete step and VM logs older than `CI_LOG_RETENTION_DAYS`.
///
/// Logs are the bulk of what this process writes and nothing else prunes them.
/// The rows stay: a step that ran and its exit code are the
/// run's history, and losing those with the bytes would make an old run look as
/// though it never happened.
///
/// Bounded per pass to avoid expiring months of shared history in one transaction.
fn spawn_log_sweeper(config: Arc<Config>, store: Store) {
    let Some(retention) = config.log_retention else {
        tracing::info!("CI_LOG_RETENTION_DAYS=0, so shared logs are kept forever; watch database storage");
        return;
    };
    /// How often to look. Logs age in days; checking hourly is prompt enough and
    /// keeps each pass small.
    const EVERY: Duration = Duration::from_secs(3600);
    /// Runs per pass.
    const BATCH: i64 = 200;

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Ok(cutoff) = chrono::Duration::from_std(retention) else {
                tracing::error!("CI_LOG_RETENTION_DAYS is out of range; not sweeping");
                return;
            };
            let cutoff = chrono::Utc::now() - cutoff;

            let runs = match store.runs_with_logs_before(cutoff, BATCH).await {
                Ok(runs) => runs,
                Err(e) => {
                    tracing::warn!("could not list runs to sweep: {e}");
                    continue;
                }
            };
            if runs.is_empty() {
                continue;
            }

            let mut swept = 0u64;
            for run_id in &runs {
                match store.forget_logs_of(run_id).await {
                    Ok(n) => swept += n,
                    Err(e) => tracing::warn!("could not expire shared logs for {run_id}: {e}"),
                }
            }
            tracing::info!(
                "log sweep: {} run(s) older than {} day(s), {swept} step log(s) discarded",
                runs.len(),
                retention.as_secs() / 86_400
            );
        }
    });
}

/// SIGTERM as well as ctrl-c: supervisord stops a program with `TERM`, and a
/// process that only handles ctrl-c gets killed after `stopwaitsecs` instead of
/// draining.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            // Nothing useful to do if the handler cannot be installed; fall
            // back to ctrl-c alone rather than refusing to serve.
            Err(e) => {
                tracing::warn!("could not install a SIGTERM handler: {e}");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        _ = ctrl_c => tracing::info!("received ctrl-c, draining"),
        _ = terminate => tracing::info!("received SIGTERM, draining"),
    }
}
