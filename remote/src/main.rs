//! remote: git repositories on S3, one bucket per Heyo account, for agents.
//!
//! Agents that generate a project have files and, often, no git repo and no
//! place to push one. This service gives each namespace git remotes they can
//! reach three ways:
//!
//! - **git over smart HTTP**: `git push https://remote.…/<ns>/<repo>.git`,
//!   with no helper to install.
//! - **a JSON or tarball commit**: `POST /api/repos/<ns>/<repo>/commits`, for
//!   an agent with no git at all.
//! - **an app-lb build**: `build.repo` set to the clone URL, with an `hrm_`
//!   read token as `build.auth`.
//!
//! People browse them in a server-rendered web UI on the same host (see
//! `web.rs`), which sees exactly the namespaces app-lb grants the signed-in
//! account.
//!
//! The object store is the authority (see `git.rs` for the push protocol), so
//! one instance per region can serve the same repos. Authentication follows
//! app-lb's provider model (see `auth.rs`).
//!
//! `remote hook pre-receive` is the same binary, run by git as the push hook.

mod api;
mod auth;
mod browse;
mod commit;
mod config;
mod git;
// The shared look, theme cookie and top bar, included rather than depended on
// as the other apps do. See `ui/README.md`.
#[path = "../../ui/ui.rs"]
mod heyo_ui;
mod registry;
mod sigv4;
mod store;
mod web;

use std::sync::Arc;

use config::Config;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("hook") {
        std::process::exit(hook(args.get(1).map(String::as_str)).await);
    }
    if matches!(args.first().map(String::as_str), Some("--version" | "-V")) {
        println!("remote {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,remote=debug".into()),
        )
        .init();

    let cfg = Config::from_env();
    if let Err(e) = cfg.validate() {
        tracing::error!("{e}");
        std::process::exit(2);
    }
    let resolved = match cfg.store.resolve().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("{e}");
            std::process::exit(2);
        }
    };
    let registry = Arc::new(registry::Registry::new(
        resolved.store.clone(),
        cfg.bucket_prefix.clone(),
        cfg.control_bucket.clone(),
    ));
    // The control bucket holds namespace bindings and tokens; nothing works
    // without it, so fail now rather than on the first request.
    if let Err(e) = registry.ensure_bucket(&cfg.control_bucket).await {
        tracing::error!(bucket = %cfg.control_bucket, error = %e, "cannot create or reach the control bucket");
        std::process::exit(1);
    }
    let auth = Arc::new(auth::Authenticator::new(
        cfg.admin_token.clone(),
        cfg.auth_url.clone(),
        cfg.applb_url.clone(),
        cfg.default_account.clone(),
        cfg.auth_cache_secs,
        cfg.auth_timeout_secs,
        resolved.store.clone(),
        cfg.control_bucket.clone(),
    ));
    let hook_bin = std::env::current_exe().unwrap_or_else(|_| "remote".into());
    let git = Arc::new(git::GitService::new(
        cfg.git_bin.clone(),
        cfg.cache_dir.clone(),
        cfg.max_push_bytes,
        cfg.allow_force_push,
        hook_bin,
        resolved.store.clone(),
        resolved.hook_env().to_vec(),
    ));
    if auth.providers().len() == 1 {
        tracing::warn!(
            "no REMOTE_AUTH_URL, REMOTE_APPLB_URL or REMOTE_ADMIN_TOKEN: only hrm_ tokens are \
             accepted, and nothing can mint one"
        );
    }
    tracing::info!(
        listen = %cfg.listen,
        public_url = %cfg.public_url,
        control_bucket = %cfg.control_bucket,
        providers = ?auth.providers(),
        "starting remote",
    );

    let listener = match tokio::net::TcpListener::bind(&cfg.listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr = %cfg.listen, error = %e, "cannot bind");
            std::process::exit(1);
        }
    };
    let state = api::AppState {
        cfg: Arc::new(cfg),
        registry,
        auth,
        git,
        ui: Arc::new(heyo_ui::CookieConfig::from_env("REMOTE")),
    };
    if let Err(e) = axum::serve(listener, api::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!(error = %e, "server stopped");
    }
}

/// `remote hook <name>`: run by git inside a cache repo. Exit status is the
/// verdict, and stderr goes to the pushing client.
async fn hook(name: Option<&str>) -> i32 {
    if name != Some("pre-receive") {
        eprintln!("unknown hook {name:?}");
        return 2;
    }
    let resolved = match Config::from_env().store.resolve().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("heyo: {e}");
            return 1;
        }
    };
    match git::run_pre_receive(resolved.store).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("heyo: push refused: {e}");
            1
        }
    }
}

/// Resolve on SIGTERM (what a supervisor sends) or Ctrl-C (what a terminal
/// does).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
