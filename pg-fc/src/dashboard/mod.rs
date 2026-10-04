//! Optional server-side-rendered admin dashboard for the pooler.
//!
//! Runs in-process (a `tokio::spawn` in `main`) so it can read the pooler's
//! live in-memory session counts (`SchemaRegistry::snapshot`) alongside the
//! daemon's VM inventory (`Sandbox::list`). Enabled only when
//! `PG_VM_POOL_DASHBOARD_LISTEN` is set; gated behind HTTP Basic auth when
//! `PG_VM_POOL_DASHBOARD_USER`/`PASSWORD` are configured.
//!
//! The main "Databases" view (`/`) is a paged, searchable, state-filtered
//! list of every heyvmd sandbox — power state, allocated size (vCPU/RAM),
//! uptime, and live pooler sessions. The daemon's list endpoints have no
//! server-side paging, so the filter/page slice happens in-process and only
//! the visible page is joined and rendered. On the detail page it also shows
//! live DB size/backends read over the pooler's own warm PG pool. It drives
//! stop/start/reboot/resize on any VM, and tails the pooler / heyvmd / per-VM
//! Postgres logs.
//!
//! A `/monitoring` view adds whole-host health — total CPU % and memory % from
//! heyvmd's `/system/usage` sampler, plus per-filesystem disk saturation read
//! directly on the host with `df` (the pooler shares the host with heyvmd) — and
//! pooler-fleet aggregates rolled up from the same inventory. It also configures
//! webhook alerts on those host metrics: a background evaluator (see `alerts`)
//! samples them on an interval and POSTs a webhook when a rule crosses its
//! threshold.
//!
//! Guest-console access (SDK `commands()` exec) goes through the VM's PID-1
//! serial-console shell on this image and can halt the VM, so the browsable
//! pages (index + detail) perform **no** guest access — only daemon reads and
//! safe PG-pool queries. The one guest exec, the per-VM Postgres log tail, is
//! confined to its own explicitly-navigated `/logs/vm/{id}` page. Every daemon
//! and guest call is timeout-bounded so one wedged VM can't hang a request.

mod alerts;
mod api;
mod archives;
mod auth;
mod database_maintenance;
mod dedicated;
mod error;
mod fleet;
mod handlers;
mod history;
mod host;
mod logs;
mod model;
mod replication;
mod router;
mod state;
mod views;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing::info;

use crate::config::DashboardConfig;
use crate::registry::SchemaRegistry;
use state::DashState;

/// Bind the dashboard's HTTP listener and serve until the process exits. Shares
/// the pooler's `Arc<SchemaRegistry>` for live session data.
pub async fn serve(cfg: DashboardConfig, registry: Arc<SchemaRegistry>) -> Result<()> {
    let addr = cfg.listen;
    let alert_interval = cfg.alert_interval;
    if !cfg.fleet.is_empty() {
        let names: Vec<&str> = cfg.fleet.iter().map(|m| m.name.as_str()).collect();
        info!(
            "dashboard fleet rollup: this instance is {:?}, reading {}",
            cfg.fleet_name,
            names.join(", ")
        );
        // Basic auth over plain HTTP crosses the network in the clear. A
        // loopback or private-link URL is the operator's call; say so once.
        for m in cfg.fleet.iter().filter(|m| {
            m.basic_auth.is_some()
                && m.base_url.starts_with("http://")
                && !m.base_url.starts_with("http://127.")
                && !m.base_url.starts_with("http://localhost")
        }) {
            tracing::warn!(
                "dashboard fleet member {} is plain http ({}): its dashboard credentials \
                 are sent unencrypted on every /fleet load",
                m.name,
                m.base_url
            );
        }
    }
    let alerts = Arc::new(alerts::AlertStore::load(cfg.alerts_file.clone()));
    let state = DashState {
        registry,
        cfg: Arc::new(cfg),
        alerts,
        history: Arc::new(history::VmHistory::new(history::CAPACITY)),
        inventory: Arc::new(model::InventoryCache::new()),
        started_at: std::time::Instant::now(),
    };
    // Background webhook-alert evaluator: samples host metrics on an interval and
    // fires any crossed rules. Shares the same `AlertStore` the pages mutate.
    alerts::spawn_evaluator(state.clone(), alert_interval);
    // Background sampler: records the live-VM count on an interval for the
    // monitoring page's chart.
    history::spawn_sampler(state.clone());
    let app = router::build(state);
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding dashboard on {addr}"))?;
    info!("dashboard listening on {addr}");
    axum::serve(listener, app)
        .await
        .context("dashboard server error")?;
    Ok(())
}
