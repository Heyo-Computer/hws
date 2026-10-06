//! `logs` and `top -n` — a namespace's telemetry, read through app-lb's `obs`
//! plugin.
//!
//! Both need the plugin installed in the namespace (`heyctl plugins install obs
//! -n <ns>`). Neither talks to app-obs directly: app-lb checks the credential
//! reaches the namespace and asks app-obs on its behalf, so a namespace token
//! is all a tenant needs.

use super::Ctx;
use crate::LogQuery;
use crate::output::{self, Table};
use crate::types::ObsLogRow;
use anyhow::{Result, bail};
use clap::Args;
use std::time::Duration;

#[derive(Args, Debug)]
pub struct LogsArgs {
    /// The deployment whose logs to show.
    #[arg(value_name = "DEPLOYMENT")]
    pub deployment: String,

    /// The deployment's namespace. Defaults to the namespace this credential
    /// is confined to.
    #[arg(long, short = 'n', value_name = "NAMESPACE")]
    pub namespace: Option<String>,

    /// How far back to look: 15m, 1h, 6h, 1d, 7d, …
    #[arg(long, value_name = "WINDOW", default_value = "1h")]
    pub since: String,

    /// Only lines at this level (error, warn, info, …).
    #[arg(long)]
    pub level: Option<String>,

    /// Only lines whose message contains this text (case-insensitive).
    #[arg(long, value_name = "TEXT")]
    pub grep: Option<String>,

    /// Only lines from this VM (sandbox id) or upstream.
    #[arg(long, value_name = "BACKEND")]
    pub backend: Option<String>,

    /// At most this many lines (newest kept).
    #[arg(long, default_value_t = 200)]
    pub limit: usize,
}

pub fn logs(ctx: &Ctx, args: &LogsArgs) -> Result<()> {
    let ns = ctx.namespace(args.namespace.as_deref())?;
    let id = super::deployment_name(&args.deployment)?;
    let mut query = LogQuery::new().window(&args.since).limit(args.limit.max(1));
    if let Some(l) = &args.level {
        query = query.level(l);
    }
    if let Some(g) = &args.grep {
        query = query.search(g);
    }
    if let Some(b) = &args.backend {
        query = query.backend(b);
    }
    if ctx.out.is_machine() {
        let raw = ctx.client.raw().obs_logs(&ns, &id, &query)?;
        return output::emit(&raw, ctx.out, &[]);
    }
    let page = ctx.client.obs(ns.as_str()).logs(&id, &query)?;
    if page.rows.is_empty() {
        eprintln!("No log lines for {id} in the last {}.", args.since);
        return Ok(());
    }
    // The server answers newest first, which is the right order to *cut* at a
    // limit and the wrong one to read; print the way `tail` would.
    for row in page.rows.iter().rev() {
        println!("{}", line(row));
    }
    if page.next_before_ms.is_some() {
        eprintln!(
            "(showing the newest {}; raise --limit or narrow --since for more)",
            page.rows.len()
        );
    }
    Ok(())
}

fn line(row: &ObsLogRow) -> String {
    let ts = output::timestamp((row.ts.max(0) / 1000) as u64);
    let level = row.level.as_deref().unwrap_or("-");
    match row.backend.as_deref() {
        Some(b) => format!("{ts} {level:<5} [{b}] {}", row.message),
        None => format!("{ts} {level:<5} {}", row.message),
    }
}

/// `top -n <ns>`: every deployment in a namespace with its traffic, errors and
/// usage over a window, from app-obs rather than the LB's live counters.
pub fn top(ctx: &Ctx, ns: &str, window: &str, watch: Option<Duration>) -> Result<()> {
    if let Some(every) = watch {
        if ctx.out.is_machine() {
            bail!(
                "--watch renders a table; drop `-o {}`",
                super::read::format_name(ctx.out)
            );
        }
        return super::read::watch(every, || top_once(ctx, ns, window));
    }
    top_once(ctx, ns, window)
}

fn top_once(ctx: &Ctx, ns: &str, window: &str) -> Result<()> {
    if ctx.out.is_machine() {
        let raw = ctx.client.raw().obs_fleet(ns, Some(window))?;
        return output::emit(&raw, ctx.out, &[]);
    }
    let fleet = ctx.client.obs(ns).fleet(Some(window))?;
    if fleet.deployments.is_empty() {
        println!(
            "No telemetry for namespace {ns:?} in the last {}.",
            fleet.window
        );
        return Ok(());
    }
    let mut table = Table::new([
        "NAME",
        "REQ/S",
        "ERR/S",
        "P50",
        "P99",
        "CPU%",
        "MEMORY",
        "READY",
        "LOG LINES",
        "ERROR LOGS",
    ]);
    let rate = |v: Option<f64>| v.map(|v| format!("{v:.2}")).unwrap_or_else(|| "-".into());
    let ms = |v: Option<f64>| v.map(output::millis).unwrap_or_else(|| "-".into());
    for d in &fleet.deployments {
        let l = &d.latest;
        table.row([
            d.id.clone(),
            rate(l.requests_per_sec),
            rate(l.errors_per_sec),
            ms(l.p50_ms),
            ms(l.p99_ms),
            output::opt_percent(l.cpu_percent),
            output::opt_bytes(l.memory_bytes.map(|b| b as u64)),
            l.ready
                .map(|r| format!("{r:.0}"))
                .unwrap_or_else(|| "-".into()),
            d.log_lines.to_string(),
            d.error_logs.to_string(),
        ]);
    }
    table.print();
    if fleet.freshness.buffered_rows > 0 {
        eprintln!(
            "({} recent rows not yet queryable; app-obs flushes every {}s)",
            fleet.freshness.buffered_rows, fleet.freshness.flush_secs
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_log_line_reads_like_tail() {
        let row = ObsLogRow {
            ts: 86_400_000 + 1_500,
            level: Some("error".into()),
            backend: Some("sb-1".into()),
            message: "disk full".into(),
            ..Default::default()
        };
        assert_eq!(line(&row), "1970-01-02 00:00:01 UTC error [sb-1] disk full");
        let bare = ObsLogRow {
            message: "hi".into(),
            ..Default::default()
        };
        assert_eq!(line(&bare), "1970-01-01 00:00:00 UTC -     hi");
    }
}
