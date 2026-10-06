//! `top` and `status` — the `/metrics` views.
//!
//! `/metrics` is gated by `APP_LB_DASHBOARD_PASSWORD` alone, independently of
//! the CRUD API, so these commands can need credentials even where `get` does
//! not (and vice versa).

use super::{Ctx, Resource};
use crate::output::{self, Table};
use crate::types::MetricsResponse;
use anyhow::{Context, Result, bail};
use clap::Args;
use std::time::Duration;

#[derive(Args, Debug)]
pub struct TopArgs {
    /// What to rank: deployments (the default), vms, or host.
    #[arg(value_name = "RESOURCE", default_value = "deployments")]
    pub resource: String,

    /// Re-render every --interval seconds until interrupted.
    #[arg(long, short = 'w')]
    pub watch: bool,

    #[arg(long, value_name = "SECS", default_value_t = 2, requires = "watch")]
    pub interval: u64,

    /// Rank a namespace's deployments by their telemetry over --window instead
    /// of the LB's live counters. Needs the obs plugin installed there.
    #[arg(long, short = 'n', value_name = "NAMESPACE")]
    pub namespace: Option<String>,

    /// With -n: the window to summarise (15m, 1h, 6h, 1d, 7d, …).
    #[arg(long, value_name = "WINDOW", default_value = "1h", requires = "namespace")]
    pub window: String,
}

/// `top host` has no [`Resource`] of its own — it is the whole-machine view the
/// daemon reports, which is neither a deployment nor a VM.
enum TopKind {
    Deployments,
    Vms,
    Host,
}

fn top_kind(word: &str) -> Result<TopKind> {
    match word.to_ascii_lowercase().trim_end_matches('s') {
        "host" | "node" | "machine" => Ok(TopKind::Host),
        other => match Resource::parse(other) {
            Some(Resource::Deployment) => Ok(TopKind::Deployments),
            Some(Resource::Vm) => Ok(TopKind::Vms),
            _ => bail!("`top` understands deployments, vms or host — not {word:?}"),
        },
    }
}

pub fn top(ctx: &Ctx, args: &TopArgs) -> Result<()> {
    if let Some(ns) = &args.namespace {
        if !matches!(top_kind(&args.resource)?, TopKind::Deployments) {
            bail!("`top -n` ranks deployments only");
        }
        let every = args.watch.then(|| Duration::from_secs(args.interval.max(1)));
        return super::telemetry::top(ctx, ns, &args.window, every);
    }
    let kind = top_kind(&args.resource)?;
    if args.watch {
        if ctx.out.is_machine() {
            bail!(
                "--watch renders a table; drop `-o {}`",
                super::read::format_name(ctx.out)
            );
        }
        return super::read::watch(Duration::from_secs(args.interval.max(1)), || {
            top_once(ctx, &kind)
        });
    }
    top_once(ctx, &kind)
}

fn fetch(ctx: &Ctx) -> Result<(serde_json::Value, MetricsResponse)> {
    let raw = ctx.client.raw().metrics(&crate::MetricsQuery::new()).context(
        "reading /metrics — it is gated by APP_LB_DASHBOARD_PASSWORD even when the CRUD API is open",
    )?;
    let parsed = serde_json::from_value(raw.clone()).context("parsing /metrics")?;
    Ok((raw, parsed))
}

fn top_once(ctx: &Ctx, kind: &TopKind) -> Result<()> {
    let (raw, m) = fetch(ctx)?;
    if ctx.out.is_machine() {
        return output::emit(&raw, ctx.out, &[]);
    }
    match kind {
        TopKind::Deployments => top_deployments(&m),
        TopKind::Vms => top_vms(&m),
        TopKind::Host => top_host(&m),
    }
    Ok(())
}

fn top_deployments(m: &MetricsResponse) {
    if m.deployments.is_empty() {
        println!("No deployments registered.");
        return;
    }
    let mut table = Table::new([
        "NAME", "READY", "IN-FLIGHT", "UTIL", "CPU%", "MEMORY", "REQUESTS", "5XX", "P50", "P99",
    ]);
    for d in &m.deployments {
        let met = &d.metrics;
        table.row([
            d.id.clone(),
            // A static deployment has no desired count to compare against — its
            // backends are whatever `upstreams` lists.
            if d.kind == "static" {
                d.pool.ready.to_string()
            } else {
                format!("{}/{}", d.pool.ready, d.pool.desired_replicas)
            },
            d.pool.total_in_flight.to_string(),
            output::ratio_percent(d.pool.utilization),
            output::opt_percent(d.pool.cpu_percent),
            output::opt_bytes(d.pool.memory_bytes),
            met.requests.total.to_string(),
            met.requests.c5xx.to_string(),
            output::millis(met.latency_ms.p50),
            output::millis(met.latency_ms.p99),
        ]);
    }
    table.print();
}

fn top_vms(m: &MetricsResponse) {
    let mut table = Table::new([
        "DEPLOYMENT", "SANDBOX", "STATUS", "CPU%", "MEMORY", "IN-FLIGHT", "UPTIME", "ADDRESS",
    ]);
    for d in &m.deployments {
        for vm in &d.vms {
            table.row([
                d.id.clone(),
                vm.sandbox_id.clone(),
                vm.status().to_string(),
                output::opt_percent(vm.cpu_percent),
                output::opt_bytes(vm.memory_bytes),
                vm.in_flight.to_string(),
                output::duration(vm.uptime_secs),
                vm.addr.clone(),
            ]);
        }
    }
    if table.is_empty() {
        println!("No VMs running.");
        return;
    }
    table.print();
}

fn top_host(m: &MetricsResponse) {
    if !m.host.available {
        println!(
            "No host usage yet — app-lb polls the heyvm daemon's /system/usage each reconcile \
             tick; if this persists, check APP_LB_DAEMON_URL."
        );
        return;
    }
    let free = m.host.memory_total_bytes.saturating_sub(m.host.memory_used_bytes);
    let mem_pct = if m.host.memory_total_bytes > 0 {
        m.host.memory_used_bytes as f64 / m.host.memory_total_bytes as f64
    } else {
        0.0
    };
    let mut table = Table::new(["CORES", "CPU%", "MEMORY USED", "MEMORY FREE", "MEMORY TOTAL", "MEM%"]);
    table.row([
        m.host.cpu_count.to_string(),
        output::percent(m.host.cpu_percent),
        output::bytes(m.host.memory_used_bytes),
        output::bytes(free),
        output::bytes(m.host.memory_total_bytes),
        output::ratio_percent(Some(mem_pct)),
    ]);
    table.print();
}

// -- status ----------------------------------------------------------------

/// A whole-LB overview: how long it has been up, what the host looks like, what
/// the fleet is doing, and how traffic has gone since start.
pub fn status(ctx: &Ctx) -> Result<()> {
    let (raw, m) = fetch(ctx)?;
    if ctx.out.is_machine() {
        return output::emit(&raw, ctx.out, &[]);
    }

    output::section("Load balancer");
    output::field("Server", &ctx.endpoint.server);
    output::field("Context", &ctx.endpoint.name);
    output::field("Uptime", output::duration(m.uptime_secs));

    // Before the host and fleet numbers, because when this is false every one of
    // them is stale: app-lb abandons the reconcile tick when it cannot list the
    // daemon's sandboxes, so nothing scales, nothing boots, and the counters sit
    // exactly where they were. Reading "0 ready" as an idle fleet is the mistake
    // this line exists to prevent.
    if !m.daemon.reachable {
        output::section("VM daemon");
        output::field("Reachable", "NO — the autoscaler is not running");
        if let Some(err) = m.daemon.last_error.as_deref() {
            output::field("Error", err);
        }
        output::field(
            "Effect",
            "no VM is created, promoted or reaped for any deployment while this persists",
        );
    }

    output::section("Host");
    if m.host.available {
        output::field(
            "CPU",
            format!("{} ({} cores)", output::percent(m.host.cpu_percent), m.host.cpu_count),
        );
        output::field(
            "Memory",
            format!(
                "{} / {} used",
                output::bytes(m.host.memory_used_bytes),
                output::bytes(m.host.memory_total_bytes)
            ),
        );
    } else {
        output::field("Usage", "not reported yet by the heyvm daemon");
    }

    output::section("Fleet");
    output::field("Deployments", m.fleet.deployments.to_string());
    output::field(
        "Backends",
        format!(
            "{} ready, {} draining, {} pending",
            m.fleet.ready, m.fleet.draining, m.fleet.pending
        ),
    );
    output::field("In flight", m.fleet.total_in_flight.to_string());

    let g = &m.global;
    output::section("Traffic (since start, all deployments)");
    output::field(
        "Requests",
        format!(
            "{} — {} 2xx, {} 3xx, {} 4xx, {} 5xx, {} errors",
            g.requests.total,
            g.requests.c2xx,
            g.requests.c3xx,
            g.requests.c4xx,
            g.requests.c5xx,
            g.requests.errors
        ),
    );
    output::field(
        "Latency",
        format!(
            "p50 {}  p90 {}  p99 {}",
            output::millis(g.latency_ms.p50),
            output::millis(g.latency_ms.p90),
            output::millis(g.latency_ms.p99)
        ),
    );
    let a = &g.autoscale;
    output::field(
        "Autoscaler",
        format!(
            "{} created, {} drained, {} reaped",
            a.vms_created, a.vms_drained, a.vms_reaped
        ),
    );
    output::field(
        "Cold starts",
        format!(
            "{} waits — {} served, {} timed out",
            a.cold_start_waits, a.cold_start_hits, a.cold_start_timeouts
        ),
    );

    // Only when the LB is shipping logs. `dropped` leads because it is the one
    // number nothing else records: those lines never reached app-obs, so its
    // dashboard cannot tell them from a deployment that had nothing to say.
    if let Some(o) = &m.obs {
        output::section("Log shipping (app-obs)");
        output::field(
            "Records",
            format!(
                "{} shipped, {} dropped (queue full), {} lost (ingest failed)",
                o.shipped, o.dropped, o.failed
            ),
        );
        output::field(
            "Ingest",
            if o.healthy {
                "reachable"
            } else {
                "not answering — records are being discarded, traffic is unaffected"
            },
        );
    }

    // Certificates share the CRUD gate, not the metrics one, so this can fail
    // on its own; a missing section is better than a failed `status`.
    if let Ok(certs) = ctx.client.raw().certs()
        && let Some(list) = certs.as_array()
    {
        let due = list
            .iter()
            .filter(|c| c.get("needs_renewal").and_then(serde_json::Value::as_bool) == Some(true))
            .count();
        output::section("Certificates");
        output::field(
            "Issued",
            format!("{} ({due} due for renewal)", list.len()),
        );
    }
    Ok(())
}
