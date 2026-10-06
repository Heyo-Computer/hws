//! `get` and `describe` — the read-only views of the control plane.

use super::{Ctx, Resource, now_secs, parse_ref};
use crate::output::{self, OutputFormat, Table};
use crate::types::{
    AuthProviderView, CertStatus, DeploymentStatus, DiskInfo, DiskInventory, JobRecord,
    MetricsResponse, NamespaceEntry, SecretSummary, WorkflowList, WorkflowView,
};
use anyhow::{Context, Result, bail};
use clap::Args;
use serde_json::Value;
use std::time::Duration;

#[derive(Args, Debug)]
pub struct GetArgs {
    /// What to list: deployments, vms, certs, secrets, jobs, disks, or all.
    /// Accepts `deployment/web` and trailing names, e.g. `get deploy web api`.
    #[arg(value_name = "RESOURCE", required = true)]
    pub args: Vec<String>,

    /// Only show VMs, jobs or disks belonging to this deployment.
    #[arg(long, short = 'd', value_name = "NAME")]
    pub deployment: Option<String>,

    /// Only show deployments, secrets or auth providers in this namespace.
    /// Applied by app-lb, not here, so the listing is narrowed before it is
    /// sent — and for the walled kinds it is the only way to name one, since a
    /// secret in `team-a` and a secret in `default` may share an id.
    #[arg(long, short = 'n', value_name = "NAMESPACE")]
    pub namespace: Option<String>,

    /// List deployments across configured gateways, without changing local write targets.
    #[arg(long)]
    pub fleet: bool,

    /// Re-render every --interval seconds until interrupted.
    #[arg(long, short = 'w')]
    pub watch: bool,

    #[arg(long, value_name = "SECS", default_value_t = 2, requires = "watch")]
    pub interval: u64,
}

pub fn get(ctx: &Ctx, args: &GetArgs) -> Result<()> {
    let (kind, names) = parse_ref(&args.args, None)?;
    if args.watch {
        if ctx.out.is_machine() {
            bail!("--watch renders a table; drop `-o {}`", format_name(ctx.out));
        }
        return watch(Duration::from_secs(args.interval.max(1)), || {
            get_once(ctx, kind, &names, args)
        });
    }
    get_once(ctx, kind, &names, args)
}

fn get_once(ctx: &Ctx, kind: Resource, names: &[String], args: &GetArgs) -> Result<()> {
    if args.fleet {
        if !matches!(kind, Resource::Deployment) || !names.is_empty() || args.deployment.is_some() {
            bail!("--fleet supports `get deployments` without names or --deployment; use --namespace to narrow it");
        }
        return get_fleet_deployments(ctx, args.namespace.as_deref());
    }
    match kind {
        Resource::Deployment => get_deployments(ctx, names, args.namespace.as_deref()),
        Resource::Vm => get_vms(ctx, names, args.deployment.as_deref()),
        Resource::Cert => get_certs(ctx),
        Resource::Secret => get_secrets(ctx, names, args.namespace.as_deref()),
        Resource::Workflow => get_workflows(ctx, names),
        Resource::Job => get_jobs(ctx, names, args.deployment.as_deref()),
        Resource::Disk => get_disks(ctx, names, args.deployment.as_deref()),
        Resource::Namespace => get_namespaces(ctx),
        Resource::AuthProvider => get_auth_providers(ctx, names, args.namespace.as_deref()),
        Resource::All => {
            get_deployments(ctx, &[], args.namespace.as_deref())?;
            println!();
            get_vms(ctx, &[], None)
        }
    }
}

fn get_fleet_deployments(ctx: &Ctx, namespace: Option<&str>) -> Result<()> {
    let raw = ctx.client.raw().fleet_deployments(namespace)?;
    if raw.get("configured").and_then(Value::as_bool) != Some(true) {
        bail!("this gateway has no fleet configured; use a regional context without --fleet");
    }
    let rows = raw["rows"].as_array().context("fleet response has no rows")?;
    if ctx.out.is_machine() {
        let names = rows.iter().map(|r| format!("deployment/{}/{}",
            r["namespace"].as_str().unwrap_or("?"), r["id"].as_str().unwrap_or("?"))).collect::<Vec<_>>();
        return output::emit(&raw, ctx.out, &names);
    }
    let mut table = Table::new(["NAMESPACE", "NAME", "GATEWAY", "REGION", "READY", "PENDING", "HEALTH", "ERROR"]);
    for row in rows {
        for cell in row["cells"].as_array().context("fleet row has no cells")? {
            let text = |v: &Value| match v { Value::Null => "—".to_owned(), Value::String(s) => s.clone(), v => v.to_string() };
            table.row([text(&row["namespace"]), text(&row["id"]), text(&cell["gateway"]),
                text(&cell["region"]), text(&cell["ready"]), text(&cell["pending"]),
                text(&cell["health"]), text(&cell["error"])]);
        }
    }
    table.print();
    for gateway in raw["gateways"].as_array().context("fleet response has no gateways")? {
        if let Some(error) = gateway["error"].as_str() {
            eprintln!("Warning: gateway {} unavailable: {error}; its inventory is unknown", gateway["id"]);
        }
        if gateway["truncated"].as_bool() == Some(true) {
            eprintln!("Warning: gateway {} inventory is truncated", gateway["id"]);
        }
    }
    Ok(())
}

/// Fetch either the whole list or the named subset, as raw JSON plus the parsed
/// view. Both are kept: `-o json` must print the server's own bytes.
fn fetch_deployments(
    ctx: &Ctx,
    names: &[String],
    namespace: Option<&str>,
) -> Result<(Value, Vec<DeploymentStatus>)> {
    let raw = if names.is_empty() {
        match namespace {
            // Server-side: app-lb filters before it serialises, which on a fleet
            // of thousands of sandboxes is the difference the query parameter
            // exists to make.
            Some(ns) => ctx.client.raw().deployments_in(ns)?,
            None => ctx.client.raw().deployments()?,
        }
    } else {
        let mut out = Vec::new();
        for name in names {
            out.push(
                ctx.client
                    .raw()
                    .deployment(name)
                    .with_context(|| format!("getting deployment {name:?}"))?,
            );
        }
        // A single name prints as one object, several as a list — the shape
        // `-o json` consumers expect from the equivalent API calls.
        if out.len() == 1 {
            out.into_iter().next().expect("len == 1")
        } else {
            Value::Array(out)
        }
    };

    let parsed: Vec<DeploymentStatus> = match &raw {
        Value::Array(items) => items
            .iter()
            .map(|v| serde_json::from_value(v.clone()))
            .collect::<Result<_, _>>()
            .context("parsing the deployment list")?,
        other => vec![serde_json::from_value(other.clone()).context("parsing the deployment")?],
    };
    Ok((raw, parsed))
}

fn get_deployments(ctx: &Ctx, names: &[String], namespace: Option<&str>) -> Result<()> {
    let (raw, deployments) = fetch_deployments(ctx, names, namespace)?;

    if ctx.out.is_machine() {
        let names: Vec<String> = deployments
            .iter()
            .map(|d| format!("deployment/{}", d.spec.id))
            .collect();
        return output::emit(&raw, ctx.out, &names);
    }

    if deployments.is_empty() {
        match namespace {
            // Naming the filter matters: an empty list and a namespace nothing
            // is in are the same output otherwise, and the second one is the
            // answer to a question the reader actually asked.
            Some(ns) => println!("No deployments in namespace {ns:?}."),
            None => println!("No deployments registered."),
        }
        return Ok(());
    }

    let mut table = if ctx.out.is_wide() {
        Table::new([
            "NAME", "KIND", "ROUTES", "DESIRED", "READY", "PENDING", "IN-FLIGHT", "MIN", "MAX",
            "WARM", "TARGET", "BACKEND", "SOURCE", "AUTH",
        ])
    } else {
        Table::new(["NAME", "KIND", "ROUTES", "DESIRED", "READY", "PENDING", "IN-FLIGHT"])
    };

    for d in &deployments {
        let mut row = vec![
            d.spec.id.clone(),
            d.kind.clone(),
            d.spec.routes_summary(),
            // Neither a static deployment nor a site has an autoscaler, so
            // "desired" is a number nobody set — a dash beats a misleading 0.
            if d.spec.is_static() || d.spec.is_site() {
                "—".to_string()
            } else {
                d.desired_replicas.to_string()
            },
            d.ready.to_string(),
            d.pending.to_string(),
            d.total_in_flight.to_string(),
        ];
        if ctx.out.is_wide() {
            let s = &d.spec.scaling;
            if d.spec.is_static() || d.spec.is_site() {
                row.extend(["—".to_string(), "—".to_string(), "—".to_string(), "—".to_string()]);
            } else {
                row.extend([
                    s.min_replicas.to_string(),
                    s.max_replicas.to_string(),
                    s.warm_pool.to_string(),
                    s.target_concurrency.to_string(),
                ]);
            }
            row.push(d.spec.backend_summary());
            // How this deployment is updated, which the BACKEND column (what is
            // running now) deliberately does not say. A managed deployment
            // builds from a repo or pulls from an artifact store — never both,
            // which is what lets one column carry either; a static one runs
            // commands on the host.
            row.push(match (&d.spec.build, &d.spec.artifact, &d.spec.update) {
                (Some(b), _, _) => b.summary(),
                (None, Some(a), _) => a.summary(),
                (None, None, Some(u)) => u.summary(),
                (None, None, None) => "—".into(),
            });
            // Whether anything stands in front of this deployment at all — the
            // one property you want to be able to scan a whole fleet for.
            row.push(match &d.spec.auth {
                Some(a) => a.providers().join("+"),
                None => "—".into(),
            });
        }
        table.row(row);
    }
    table.print();
    Ok(())
}

fn get_vms(ctx: &Ctx, names: &[String], filter: Option<&str>) -> Result<()> {
    let scope: Vec<String> = filter.into_iter().map(str::to_string).collect();
    // No namespace here: `get vms` is already scoped by deployment, and a VM
    // listing narrowed twice would need both filters to agree to show anything.
    let (_, deployments) = fetch_deployments(ctx, &scope, None)?;

    let wanted = |id: &str| names.is_empty() || names.iter().any(|n| n == id);

    if ctx.out.is_machine() {
        let mut rows = Vec::new();
        let mut refs = Vec::new();
        for d in &deployments {
            for vm in d.vms.iter().filter(|v| wanted(&v.sandbox_id)) {
                refs.push(format!("vm/{}", vm.sandbox_id));
                rows.push(serde_json::json!({
                    "deployment": d.spec.id,
                    "sandbox_id": vm.sandbox_id,
                    "addr": vm.addr,
                    "in_flight": vm.in_flight,
                    "healthy": vm.healthy,
                    "draining": vm.draining,
                }));
            }
        }
        return output::emit(&Value::Array(rows), ctx.out, &refs);
    }

    let mut table = Table::new(["DEPLOYMENT", "SANDBOX", "ADDRESS", "STATUS", "IN-FLIGHT"]);
    for d in &deployments {
        for vm in d.vms.iter().filter(|v| wanted(&v.sandbox_id)) {
            table.row([
                d.spec.id.clone(),
                vm.sandbox_id.clone(),
                vm.addr.clone(),
                vm.status().to_string(),
                vm.in_flight.to_string(),
            ]);
        }
    }
    if table.is_empty() {
        println!("No VMs in the pool. (`heyctl top vms` shows resource usage for running VMs.)");
        return Ok(());
    }
    table.print();
    Ok(())
}

/// `heyctl get namespaces` — which namespaces exist, and how much is in each.
///
/// "Exist" is doing real work in that sentence: a namespace is not an object,
/// so this is the set of names the deployments currently mention, narrowed to
/// the ones this credential can see. Nothing here can be created or deleted —
/// a namespace begins when a deployment declares it and ends when the last one
/// stops.
fn get_namespaces(ctx: &Ctx) -> Result<()> {
    let raw = ctx.client.raw().namespaces()?;
    let namespaces: Vec<NamespaceEntry> =
        serde_json::from_value(raw.clone()).context("parsing the namespace list")?;

    if ctx.out.is_machine() {
        let names: Vec<String> = namespaces
            .iter()
            .map(|n| format!("namespace/{}", n.namespace))
            .collect();
        return output::emit(&raw, ctx.out, &names);
    }

    if namespaces.is_empty() {
        println!(
            "No namespaces. Every deployment is in \"default\" until one says \
             otherwise — put a deployment in a namespace with \
             `heyctl create deployment <NAME> --namespace <NS>`, or a \
             `\"namespace\"` field in a spec passed to `heyctl apply`."
        );
        return Ok(());
    }

    // DECLARED is the column that earns its place: a namespace with zero
    // deployments and no object is a name nothing mentions any more, while one
    // with an object is somewhere waiting to be used. Same row, opposite
    // meanings, and only this column separates them.
    let mut table = if ctx.out.is_wide() {
        Table::new(["NAMESPACE", "DEPLOYMENTS", "DECLARED", "CREATED", "DESCRIPTION"])
    } else {
        Table::new(["NAMESPACE", "DEPLOYMENTS", "DECLARED"])
    };
    let now = now_secs();
    for n in &namespaces {
        let mut row = vec![
            n.namespace.clone(),
            n.deployments.to_string(),
            if n.declared { "yes".into() } else { "—".to_string() },
        ];
        if ctx.out.is_wide() {
            row.push(match n.created_at {
                Some(t) => format!("{} ago", output::duration(now.saturating_sub(t))),
                None => "—".into(),
            });
            row.push(n.description.clone().unwrap_or_else(|| "—".into()));
        }
        table.row(row);
    }
    table.print();
    if !namespaces.iter().any(|n| n.declared) {
        println!(
            "\nNone of these are declared — they exist because deployments name them. \
             `heyctl create namespace <NAME>` makes one that stands on its own."
        );
    }
    Ok(())
}

fn get_certs(ctx: &Ctx) -> Result<()> {
    let raw = ctx.client.raw().certs()?;
    let certs: Vec<CertStatus> =
        serde_json::from_value(raw.clone()).context("parsing the certificate list")?;

    if ctx.out.is_machine() {
        let names: Vec<String> = certs.iter().map(|c| format!("cert/{}", c.host)).collect();
        return output::emit(&raw, ctx.out, &names);
    }

    if certs.is_empty() {
        println!(
            "No certificates issued. (ACME is off unless APP_LB_ACME_EMAIL is set; \
             `host_suffix` routes cannot be covered by ACME.)"
        );
        return Ok(());
    }

    let mut table = Table::new(["HOST", "ISSUER", "NOT-AFTER", "RENEWAL"]);
    for c in &certs {
        table.row([
            c.host.clone(),
            c.issuer.clone(),
            c.not_after.clone(),
            if c.needs_renewal { "due".into() } else { "ok".to_string() },
        ]);
    }
    table.print();
    Ok(())
}

/// `get disks` — what each sandbox occupies on the app-lb host, and what holds
/// it there.
///
/// The question this answers is "why is the host full", and before it existed
/// the only place to ask was the `/storage` console in a browser. That gap is
/// not cosmetic: a deployment whose VMs fail to boot leaves a data disk per
/// attempt, and at a `disk_size_gb` of any size those add up long before anyone
/// thinks to open a dashboard.
///
/// Two size columns because they routinely disagree by an order of magnitude: a
/// data disk is created sparse at its full nominal size, so ON-DISK is what the
/// host has actually lost and APPARENT is what the guest believes it has. Sorted
/// by ON-DISK, because the reason for looking is almost always "what is big".
///
/// HELD is the reclaim story in one column — the phrase app-lb uses for why the
/// sweep will not take a disk, or when it will.
fn get_disks(ctx: &Ctx, names: &[String], deployment: Option<&str>) -> Result<()> {
    let raw = ctx.client.raw().disks()?;
    let inv: DiskInventory =
        serde_json::from_value(raw.clone()).context("parsing the disk inventory")?;

    let mut disks: Vec<&DiskInfo> = inv
        .disks
        .iter()
        .filter(|d| names.is_empty() || names.iter().any(|n| n == &d.sandbox_id))
        .filter(|d| deployment.is_none_or(|want| d.deployment.as_deref() == Some(want)))
        .collect();
    disks.sort_by_key(|d| std::cmp::Reverse(d.bytes));

    if ctx.out.is_machine() {
        // The whole document, not just the rows: `complete` and the totals are
        // what make the list interpretable, and a filtered `-o json` that
        // dropped them would be a worse answer than the server's own.
        let ids: Vec<String> = disks.iter().map(|d| format!("disk/{}", d.sandbox_id)).collect();
        return output::emit(&raw, ctx.out, &ids);
    }

    // Said before the table rather than after: every row below is unclassified
    // when this is false, and an operator who reads "orphan" as "safe to delete"
    // on an incomplete listing deletes a running VM's disk.
    if !inv.complete {
        println!(
            "warning: the daemon did not answer both listings{}; nothing is classified as an \
             orphan and the sweep will not run.",
            inv.incomplete_reason
                .as_deref()
                .map(|r| format!(" ({r})"))
                .unwrap_or_default(),
        );
    }

    if disks.is_empty() {
        match (names.is_empty(), deployment) {
            (true, None) => println!("No per-sandbox disks on this host ({}).", inv.data_dir),
            (_, Some(d)) => println!("No disks belong to deployment {d:?}."),
            _ => println!("No disks match."),
        }
        return Ok(());
    }

    let now = now_secs();
    let mut table = Table::new([
        "SANDBOX",
        "DEPLOYMENT",
        "STATE",
        "ON-DISK",
        "APPARENT",
        "AGE",
        "HELD",
    ]);
    for d in &disks {
        table.row([
            d.sandbox_id.clone(),
            d.deployment.clone().unwrap_or_else(|| "—".into()),
            d.state.label().to_string(),
            output::bytes(d.bytes),
            output::bytes(d.apparent_bytes),
            output::duration(now.saturating_sub(d.modified_at)),
            held_reason(d, now),
        ]);
    }
    table.print();

    let t = &inv.totals;
    println!();
    println!(
        "{} disks, {} on disk ({} apparent) — {} running, {} stopped, {} orphan, {} retained.",
        t.disks,
        output::bytes(t.bytes),
        output::bytes(t.apparent_bytes),
        t.running,
        t.stopped,
        t.orphan,
        t.retained,
    );

    // The number the table cannot show: whether the sum above is a problem.
    // "Why can't this host create a VM" is answered here and nowhere else — a
    // create fails on ENOSPC long before any single disk looks suspicious.
    if let Some(free) = inv.free_bytes {
        let capacity = match inv.filesystem_bytes {
            Some(total) if total > 0 => format!(" of {}", output::bytes(total)),
            _ => String::new(),
        };
        println!("Host filesystem: {} free{capacity}.", output::bytes(free));
    }
    if inv.totals.orphan > 0 && inv.orphan_ttl_secs > 0 {
        // Orphans are the category worth calling out separately: they are disks
        // whose sandbox the daemon has no record of, so nothing will resume
        // them, and they are on a much shorter clock than the rest.
        println!(
            "{} orphaned (no daemon record) — reclaimed after {}, not the {} TTL.",
            inv.totals.orphan,
            output::duration(inv.orphan_ttl_secs),
            output::duration(inv.ttl_secs),
        );
    }
    if inv.ttl_secs == 0 {
        println!("Expiry is off, so nothing is reclaimed automatically.");
    } else if t.expiring_now > 0 {
        println!(
            "The sweep would reclaim {} now, freeing {}.",
            t.expiring_now,
            output::bytes(t.reclaimable_bytes),
        );
    }
    Ok(())
}

/// The one-phrase answer to "will this be reclaimed, and if not why not".
///
/// `held_by` is app-lb's own wording and is preferred verbatim so the CLI and
/// the console cannot drift into describing the same rule two ways.
fn held_reason(d: &DiskInfo, now: u64) -> String {
    if let Some(reason) = d.held_by.as_deref() {
        return reason.to_string();
    }
    match d.expires_at {
        // Already due: the sweep simply has not run yet, which is a different
        // state from "will expire" and the one worth naming.
        Some(at) if at <= now => "expiring".into(),
        Some(at) => format!("in {}", output::duration(at.saturating_sub(now))),
        None => "—".into(),
    }
}

/// `get secrets` — names and key names. There is no flag that prints a value:
/// app-lb has no endpoint that returns one.
fn get_workflows(ctx: &Ctx, names: &[String]) -> Result<()> {
    let raw = if names.is_empty() {
        ctx.client.raw().workflows()?
    } else {
        let mut out = Vec::new();
        for name in names {
            out.push(
                ctx.client
                    .raw()
                    .workflow(name)
                    .with_context(|| format!("getting workflow {name:?}"))?,
            );
        }
        Value::Array(out)
    };

    // `GET /workflows` is enveloped; a by-name fetch is a bare array. Both
    // shapes reach this function, so both are unwrapped here rather than at two
    // call sites.
    let workflows: Vec<WorkflowView> = match &raw {
        Value::Array(items) => items
            .iter()
            .map(|v| serde_json::from_value(v.clone()))
            .collect::<Result<_, _>>()
            .context("parsing the workflow list")?,
        Value::Object(map) if map.contains_key("workflows") => {
            serde_json::from_value::<WorkflowList>(raw.clone())
                .context("parsing the workflow list")?
                .workflows
        }
        other => vec![serde_json::from_value(other.clone()).context("parsing the workflow")?],
    };

    if ctx.out.is_machine() {
        let refs: Vec<String> = workflows
            .iter()
            .map(|w| format!("workflow/{}", w.id))
            .collect();
        return output::emit(&raw, ctx.out, &refs);
    }

    if workflows.is_empty() {
        println!(
            "No CI workflows. (`heyctl create workflow build --repo <url> \
             --network <net>` registers one.)"
        );
        return Ok(());
    }

    let mut table = if ctx.out.is_wide() {
        Table::new(["NAME", "REPO", "REF", "PATH", "NETWORK", "ENABLED"])
    } else {
        Table::new(["NAME", "REPO", "REF", "NETWORK"])
    };
    for w in &workflows {
        let mut row = vec![w.id.clone(), w.repo.clone(), w.git_ref.clone()];
        if ctx.out.is_wide() {
            row.push(w.path.clone());
        }
        row.push(w.network.clone());
        if ctx.out.is_wide() {
            row.push(if w.enabled { "yes" } else { "no" }.to_string());
        }
        table.row(row);
    }
    table.print();
    Ok(())
}

fn get_secrets(ctx: &Ctx, names: &[String], namespace: Option<&str>) -> Result<()> {
    let raw = if names.is_empty() {
        ctx.client.raw().secrets_in(namespace)?
    } else {
        let mut out = Vec::new();
        for name in names {
            out.push(
                ctx.client
                    .raw()
                    .secret_in(namespace, name)
                    .with_context(|| format!("getting secret {name:?}"))?,
            );
        }
        Value::Array(out)
    };

    let secrets: Vec<SecretSummary> = match &raw {
        Value::Array(items) => items
            .iter()
            .map(|v| serde_json::from_value(v.clone()))
            .collect::<Result<_, _>>()
            .context("parsing the secret list")?,
        other => vec![serde_json::from_value(other.clone()).context("parsing the secret")?],
    };

    if ctx.out.is_machine() {
        let refs: Vec<String> = secrets.iter().map(|s| format!("secret/{}", s.id)).collect();
        return output::emit(&raw, ctx.out, &refs);
    }

    if secrets.is_empty() {
        println!(
            "No secrets stored. (`heyctl create secret github --from-stdin token` \
             stores one; values are never readable back.)"
        );
        return Ok(());
    }

    let mut table = if ctx.out.is_wide() {
        Table::new(["NAME", "KEYS", "AT-REST", "UPDATED", "DESCRIPTION"])
    } else {
        Table::new(["NAME", "KEYS", "UPDATED"])
    };
    for s in &secrets {
        let mut row = vec![
            s.id.clone(),
            if s.keys.is_empty() {
                "<none>".into()
            } else {
                s.keys.join(",")
            },
        ];
        if ctx.out.is_wide() {
            row.push(if s.encrypted_at_rest {
                "encrypted".into()
            } else {
                "plaintext".into()
            });
        }
        row.push(if s.updated_at == 0 {
            "—".into()
        } else {
            format!("{} (server clock)", s.updated_at)
        });
        if ctx.out.is_wide() {
            row.push(output::opt_str(s.description.as_deref()));
        }
        table.row(row);
    }
    table.print();
    Ok(())
}

/// `get auth-providers [-n NAMESPACE] [NAME...]` — the declared identity
/// objects a gate can inherit with `auth.provider_ref`.
///
/// Names are resolved inside one namespace, because that is the only place a
/// provider is unique: `-n` when it is not `default`.
fn get_auth_providers(ctx: &Ctx, names: &[String], namespace: Option<&str>) -> Result<()> {
    let ns = namespace.unwrap_or(crate::DEFAULT_NAMESPACE);
    let raw = if names.is_empty() {
        ctx.client.raw().auth_providers(namespace)?
    } else {
        let mut out = Vec::new();
        for name in names {
            out.push(
                ctx.client
                    .raw()
                    .auth_provider(ns, name)
                    .with_context(|| format!("getting auth provider {name:?} in namespace {ns:?}"))?,
            );
        }
        Value::Array(out)
    };

    let providers: Vec<AuthProviderView> = match &raw {
        Value::Array(items) => items
            .iter()
            .map(|v| serde_json::from_value(v.clone()))
            .collect::<Result<_, _>>()
            .context("parsing the auth provider list")?,
        other => vec![serde_json::from_value(other.clone()).context("parsing the auth provider")?],
    };

    if ctx.out.is_machine() {
        let refs: Vec<String> = providers
            .iter()
            .map(|p| format!("auth-provider/{}/{}", p.namespace, p.name))
            .collect();
        return output::emit(&raw, ctx.out, &refs);
    }

    if providers.is_empty() {
        println!(
            "No auth providers declared{}. (`heyctl create auth-provider heyo --preset heyo \
             --secret heyo-auth/jwt_secret` declares one; deployments inherit it with \
             `heyctl set auth <deployment> --provider-ref heyo`.)",
            match namespace {
                Some(ns) => format!(" in namespace {ns}"),
                None => String::new(),
            }
        );
        return Ok(());
    }

    let mut table = if ctx.out.is_wide() {
        Table::new(["NAME", "NAMESPACE", "PROVIDER", "TRUST", "ADMITS", "DESCRIPTION"])
    } else {
        Table::new(["NAME", "NAMESPACE", "PROVIDER", "TRUST", "ADMITS"])
    };
    for p in &providers {
        let mut row = vec![
            p.name.clone(),
            p.namespace.clone(),
            p.providers().join("+"),
            p.trust_summary(),
            p.admits(),
        ];
        if ctx.out.is_wide() {
            row.push(output::opt_str(p.description.as_deref()));
        }
        table.row(row);
    }
    table.print();
    Ok(())
}

/// `get jobs [-d DEPLOYMENT] [ID...]` — the image builds and host updates this
/// LB has run, newest first.
fn get_jobs(ctx: &Ctx, names: &[String], deployment: Option<&str>) -> Result<()> {
    let raw = match (names, deployment) {
        // A named job is looked up directly, so `get job job-abc` works without
        // knowing which deployment it belonged to.
        ([id], _) => ctx.client.raw().job(id)?,
        ([], Some(d)) => ctx.client.raw().deployment_jobs(d)?,
        ([], None) => ctx.client.raw().jobs()?,
        _ => bail!("get job takes at most one job id; use -d to scope by deployment"),
    };

    let jobs: Vec<JobRecord> = match &raw {
        Value::Array(items) => items
            .iter()
            .map(|v| serde_json::from_value(v.clone()))
            .collect::<Result<_, _>>()
            .context("parsing the job list")?,
        other => vec![serde_json::from_value(other.clone()).context("parsing the job")?],
    };

    if ctx.out.is_machine() {
        let refs: Vec<String> = jobs.iter().map(|j| format!("job/{}", j.id)).collect();
        return output::emit(&raw, ctx.out, &refs);
    }

    if jobs.is_empty() {
        println!(
            "No jobs yet. (`heyctl set build <deployment> --repo <url>` records where an \
             image comes from; `heyctl set update <deployment> --workdir <dir> --command \
             '<cmd>'` records how a static one is updated.)"
        );
        return Ok(());
    }

    // A single named job is worth spelling out — its log is the reason somebody
    // asked for it by id.
    if let ([_], Some(record)) = (names, jobs.first())
        && jobs.len() == 1
    {
        return describe_job(record);
    }

    // TARGET and RESULT mean different things per kind (a ref and an image for a
    // build; a directory and a command count for an update), which is why the
    // KIND column is there.
    let mut table = Table::new([
        "JOB", "DEPLOYMENT", "KIND", "STATUS", "TARGET", "RESULT", "TOOK",
    ]);
    // Jobs are timestamped on the server's clock, so measure elapsed time
    // against the newest record rather than this machine's idea of now.
    let now = jobs
        .iter()
        .map(|j| j.finished_at.unwrap_or(j.started_at))
        .max()
        .unwrap_or(0);
    for j in &jobs {
        table.row([
            j.id.clone(),
            j.deployment.clone(),
            j.kind.clone(),
            j.status.clone(),
            j.target_summary(),
            j.result_summary(),
            output::duration(j.elapsed_secs(now)),
        ]);
    }
    table.print();
    Ok(())
}

fn describe_job(j: &JobRecord) -> Result<()> {
    output::top_field("Job", &j.id);
    output::top_field("Deployment", &j.deployment);
    output::top_field("Kind", &j.kind);

    output::section("Source");
    if j.is_update() {
        output::field("Working dir", output::opt_str(j.working_dir.as_deref()));
        output::field(
            "Commands",
            match (j.commands_run, j.commands_total) {
                (Some(run), Some(total)) => format!("{run} of {total} completed"),
                (_, Some(total)) => format!("{total}"),
                _ => "—".into(),
            },
        );
    } else if j.is_mount_pull() {
        // One row per mount rather than the single Store/Ref/Digest triple a
        // rootfs pull gets: this job covers all of a deployment's mounts, and
        // which one moved is the whole question.
        for m in &j.mounts {
            let digest = m
                .digest
                .as_ref()
                .map(|d| d.chars().take(12).collect::<String>())
                .unwrap_or_else(|| "—".into());
            let moved = match (m.bytes, m.reused) {
                (_, true) => "already on this host".to_string(),
                (Some(0), false) => "hardlinked from a local store".to_string(),
                (Some(n), false) => output::bytes(n),
                (None, false) => "—".into(),
            };
            output::field(
                &m.path,
                format!(
                    "{} — {digest}, {moved}{}",
                    m.summary(),
                    if m.changed { " (changed)" } else { "" }
                ),
            );
        }
        if j.mounts.is_empty() {
            output::field("Mounts", "—");
        }
    } else if j.is_pull() {
        output::field("Store", output::opt_str(j.store.as_deref()));
        output::field("Ref", output::opt_str(j.artifact_ref.as_deref()));
        // The whole point of a pull: a tag can move, so the digest is what
        // actually says which bytes the pool is running.
        output::field("Digest", output::opt_str(j.digest.as_deref()));
        output::field(
            "Transferred",
            match (j.bytes, j.reused) {
                (Some(0), true) => "nothing — the image was already on the host".to_string(),
                (Some(n), _) => output::bytes(n),
                (None, _) => "—".into(),
            },
        );
    } else {
        output::field("Repo", &j.repo);
        output::field("Ref", j.git_ref.as_deref().unwrap_or("(default branch)"));
        output::field("Commit", output::opt_str(j.commit.as_deref()));
        output::field("Dockerfile", output::opt_str(j.dockerfile.as_deref()));
    }

    output::section("Result");
    output::field("Status", &j.status);
    if j.is_update() {
        output::field(
            "Upstreams",
            match j.verified {
                Some(true) => "healthy after the update",
                Some(false) => "did NOT come back — the host has already been changed",
                None if j.is_running() => "not checked yet",
                // No verdict on a finished job means it never got that far —
                // except when it succeeded, which can only mean the check is off.
                None if j.succeeded() => "not checked (verify_timeout_secs is 0)",
                None => "not checked — the job failed before that point",
            },
        );
    } else if j.is_mount_pull() {
        output::field(
            "Trees",
            format!(
                "{} on this host ({})",
                j.mounts.len(),
                output::bytes(j.mounts.iter().filter_map(|m| m.unpacked).sum::<u64>()),
            ),
        );
        output::field(
            "Rolled out",
            if j.rolled_out {
                "yes — vm.mounts digests updated, pool recycled"
            } else if j.is_running() {
                "not yet"
            } else {
                // The ordinary outcome of a pull that found every tree already
                // pinned, which is what registering an unchanged spec does.
                "no — the pool already had these trees"
            },
        );
    } else {
        output::field("Image", output::opt_str(j.image.as_deref()));
        output::field(
            "Rolled out",
            if j.rolled_out {
                "yes — vm.image updated, pool recycled"
            } else if j.is_running() {
                "not yet"
            } else {
                "no"
            },
        );
    }
    output::field(
        "Took",
        output::duration(j.elapsed_secs(j.finished_at.unwrap_or(j.started_at))),
    );
    if let Some(e) = &j.error {
        output::field("Error", e);
    }

    output::section("Log");
    if j.log.is_empty() {
        println!("  (no output yet)");
    }
    for line in &j.log {
        println!("  {line}");
    }
    Ok(())
}

#[derive(Args, Debug)]
pub struct DescribeArgs {
    /// What to describe: `web`, `deployment/web`, or `auth-provider heyo`.
    #[arg(value_name = "RESOURCE", required = true)]
    pub args: Vec<String>,

    /// The namespace an auth provider lives in. Ignored for a deployment,
    /// whose namespace is part of the object.
    #[arg(long, short = 'n', value_name = "NAMESPACE")]
    pub namespace: Option<String>,
}

pub fn describe(ctx: &Ctx, args: &DescribeArgs) -> Result<()> {
    let (kind, names) = parse_ref(&args.args, Some(Resource::Deployment))?;
    if kind == Resource::AuthProvider {
        return describe_auth_providers(ctx, &names, args.namespace.as_deref());
    }
    if kind != Resource::Deployment {
        bail!("describe works on deployments and auth providers");
    }
    if names.is_empty() {
        bail!("describe needs a name, e.g. `heyctl describe deployment web`");
    }

    // Metrics are a separate, separately-gated endpoint. Fetch once, and carry
    // on without them if this user can only reach the CRUD API. Not needed at
    // all under -o json/yaml, which prints the deployment payload verbatim.
    let metrics: Option<MetricsResponse> = if ctx.out.is_machine() {
        None
    } else {
        ctx.client
            .raw()
            .metrics(&crate::MetricsQuery::new())
            .ok()
            .and_then(|v| serde_json::from_value(v).ok())
    };

    for (i, name) in names.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let raw = ctx.client.raw().deployment(name)?;
        if ctx.out.is_machine() {
            output::emit(&raw, ctx.out, &[format!("deployment/{name}")])?;
            continue;
        }
        let d: DeploymentStatus = serde_json::from_value(raw)?;
        describe_one(&d, metrics.as_ref());
    }
    Ok(())
}

/// `describe auth-provider <NAME> [-n NAMESPACE]` — everything an inheriting
/// gate will be given, plus what a deployment still has to supply itself.
fn describe_auth_providers(ctx: &Ctx, names: &[String], namespace: Option<&str>) -> Result<()> {
    if names.is_empty() {
        bail!(
            "describe needs a name, e.g. `heyctl describe auth-provider heyo` \
             (add -n <namespace> when it is not `default`)"
        );
    }
    let ns = namespace.unwrap_or(crate::DEFAULT_NAMESPACE);
    for (i, name) in names.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let raw = ctx
            .client
            .raw()
            .auth_provider(ns, name)
            .with_context(|| format!("getting auth provider {name:?} in namespace {ns:?}"))?;
        if ctx.out.is_machine() {
            output::emit(&raw, ctx.out, &[format!("auth-provider/{ns}/{name}")])?;
            continue;
        }
        let p: AuthProviderView = serde_json::from_value(raw)?;
        describe_provider(&p);
    }
    Ok(())
}

fn describe_provider(p: &AuthProviderView) {
    output::top_field("Name", &p.name);
    output::top_field("Namespace", &p.namespace);
    if let Some(d) = &p.description {
        output::top_field("Description", d);
    }
    if p.created_at > 0 {
        output::top_field("Declared", output::timestamp(p.created_at));
    }

    output::section("Identity");
    output::field("Provider", p.providers().join(" or "));
    if let Some(client_id) = &p.client_id {
        output::field("Client id", client_id);
    }
    if let Some(secret) = &p.client_secret {
        output::field("Client secret", format!("secret {}", secret.render_in(&p.namespace)));
    }
    if p.providers().iter().any(|q| q == "google") {
        output::field("Who may enter", p.admits());
    }
    if let Some(jwt) = &p.jwt {
        output::field("JWT issuer", &jwt.issuer);
        output::field("JWT audience", jwt.audience.as_deref().unwrap_or("(not checked)"));
        // Spelled out rather than summarised: which key verifies a token is the
        // whole of what this object is trusted for.
        output::field(
            "JWT key",
            match (&jwt.secret, &jwt.public_key, &jwt.jwks_url) {
                (Some(r), _, _) => format!("shared secret {}", r.render_in(&p.namespace)),
                (_, Some(_), _) => "an inline public key".to_string(),
                (_, _, Some(url)) => format!("the key set at {url}"),
                _ => "<none>".to_string(),
            },
        );
        output::field("JWT algorithms", jwt.algorithms.join(", "));
        output::field("JWT admits", jwt.require_summary());
        output::field(
            "JWT subject claim",
            format!("{} -> x-auth-request-user", jwt.subject_claim),
        );
        if let Some(cookie) = &jwt.cookie {
            output::field("JWT cookie", format!("{cookie} (when no Authorization header)"));
        }
        match (&jwt.login_url, &jwt.cookie) {
            _ if jwt.authorize_url.is_some() => output::field(
                "Browser sign-in",
                format!(
                    "scoped: {} asks for namespace access, then a host-only app-lb session",
                    jwt.authorize_url.as_deref().unwrap_or_default()
                ),
            ),
            (Some(url), Some(cookie)) => {
                output::field(
                    "Browser sign-in",
                    format!(
                        "{url}?{}=<the url they asked for> — that page sets {cookie}",
                        jwt.login_redirect_param.as_deref().unwrap_or("redirect_uri")
                    ),
                );
            }
            // Worth saying, because it is the difference between a person seeing
            // a sign-in page and a person seeing a 401 they cannot act on.
            (None, _) => output::field(
                "Browser sign-in",
                "none — a token-less browser gets 401. Set --login-url and --cookie \
                 to send it somewhere",
            ),
            _ => {}
        }
    }
    if let Some(domain) = &p.cookie_domain {
        output::field("Session realm", format!("{domain} (shared across the namespace's gates)"));
    }

    output::section("Inheriting it");
    output::field(
        "In a spec",
        format!("auth: {{ provider_ref: {} }}", p.name),
    );
    output::field(
        "With heyctl",
        format!("heyctl set auth <deployment> --provider-ref {}", p.name),
    );
    output::field(
        "The gate still owns",
        "public_paths, base_path, cookie_name, session_ttl_secs, forward_identity",
    );
}

fn describe_one(d: &DeploymentStatus, metrics: Option<&MetricsResponse>) {
    output::top_field("Name", &d.spec.id);
    output::top_field(
        "Kind",
        if d.spec.is_site() {
            "site (files served off disk)".to_string()
        } else if d.spec.is_static() {
            if d.spec.discovery.is_some() {
                "static (proxy_pass to discovered upstreams)".to_string()
            } else {
                "static (proxy_pass to fixed upstreams)".to_string()
            }
        } else {
            let driver = d.spec.vm.as_ref().map(|v| v.driver.clone()).unwrap_or_default();
            format!("vm (managed {driver} pool)")
        },
    );

    output::section("Routes");
    if d.spec.routes.is_empty() {
        println!("  <none>");
    }
    for r in &d.spec.routes {
        println!("  {}", r.render());
    }

    if let Some(site) = &d.spec.site {
        output::section("Site");
        output::field("Root", &site.root);
        output::field(
            "Index",
            if site.index.is_empty() { "none (directories 404)" } else { &site.index },
        );
        output::field("404 page", site.not_found.as_deref().unwrap_or("none (plain text)"));
        output::field(
            "Unmatched paths",
            if site.spa {
                "served the index (SPA mode)"
            } else {
                "404"
            },
        );
        output::field("Cache-Control", &site.cache_control);
    }

    if d.spec.is_static() {
        output::section("Upstreams");
        if let Some(discovery) = &d.spec.discovery {
            output::field("Discovery service", &discovery.service_id);
        }
        for u in &d.spec.upstreams {
            println!("  {u}");
        }

        // The static counterpart of a managed deployment's "Build source": what
        // `heyctl update` would run, and where.
        if let Some(update) = &d.spec.update {
            output::section("Update (on the app-lb host)");
            output::field("Working dir", &update.working_dir);
            output::field(
                "Verify",
                match update.verify_timeout_secs {
                    Some(0) => "off — a successful job only means the commands exited 0".into(),
                    Some(s) => format!("re-probe the upstreams, up to {}", output::duration(s)),
                    None => "re-probe the upstreams, up to 1m".into(),
                },
            );
            if let Some(t) = update.timeout_secs {
                output::field("Command timeout", output::duration(t));
            }
            if let Some(env) = &update.env {
                let keys: Vec<&str> = env.keys().map(String::as_str).collect();
                if !keys.is_empty() {
                    output::field("Env", keys.join(", "));
                }
            }
            if !update.env_from.is_empty() {
                let refs: Vec<String> = update.env_from.iter().map(|e| e.render()).collect();
                output::field("Env from secrets", refs.join(", "));
            }
            if let Some(auth) = &update.auth {
                output::field("Git credential", format!("secret {}", auth.render()));
            }
            println!("  Commands:");
            for (i, c) in update.commands.iter().enumerate() {
                println!("    {}. {c}", i + 1);
            }
        }
    } else if let Some(vm) = &d.spec.vm {
        output::section("VM template");
        output::field("Driver", &vm.driver);
        output::field("Image", output::opt_str(vm.image.as_deref()));
        output::field("Port", vm.port.to_string());
        output::field("Size class", output::opt_str(vm.size_class.as_deref()));
        if let Some(gb) = vm.disk_size_gb {
            output::field("Disk", format!("{gb} GB"));
        }
        if let Some(cmd) = &vm.start_command {
            output::field("Start command", cmd);
        }
        if let Some(dir) = &vm.working_directory {
            output::field("Working dir", dir);
        }
        if !vm.open_ports.is_empty() {
            let ports: Vec<String> = vm.open_ports.iter().map(u16::to_string).collect();
            output::field("Open ports", ports.join(","));
        }
        output::field("TTL", output::duration(vm.ttl_seconds));
        if let Some(env) = &vm.env_vars {
            // Values can be secrets (the API echoes the whole spec back), so
            // show the keys and let `-o json` be the deliberate way to see them.
            let keys: Vec<&str> = env.keys().map(String::as_str).collect();
            output::field(
                "Env",
                if keys.is_empty() {
                    "<none>".to_string()
                } else {
                    format!("{} ({})", keys.join(", "), "values hidden; use -o json")
                },
            );
        }
        if let Some(hooks) = &vm.setup_hooks
            && !hooks.is_empty()
        {
            output::field("Setup hooks", hooks.join(" ; "));
        }

        if !vm.mounts.is_empty() {
            output::section("Mounts");
            for m in &vm.mounts {
                // The digest is the answer to "which bytes are these guests
                // holding?", and its absence is the answer to "why is the pool
                // empty?" — so an unpulled mount says so here rather than
                // showing a blank column.
                let state = match &m.digest {
                    Some(d) => format!("digest {}", d.chars().take(12).collect::<String>()),
                    None => "NOT PULLED — the pool cannot start until it is".to_string(),
                };
                output::field(&m.path, format!("{} — {state}", m.summary()));
                if let Some(n) = m.strip_components {
                    output::field("  strip_components", n.to_string());
                }
                if let Some(auth) = &m.auth {
                    output::field("  Store credential", format!("secret {}", auth.render()));
                }
            }
        }

        if let Some(ws) = &d.workspace {
            output::section("Workspace");
            let short = |d: &Option<String>| match d {
                Some(d) => d.chars().take(12).collect::<String>(),
                None => "(empty)".to_string(),
            };
            output::field(&ws.path, format!("{} ({})", ws.store, ws.phase));
            output::field(
                "  Snapshot",
                match ws.captured_at {
                    Some(at) => format!(
                        "{} — {} files, {}, captured from {} at {}",
                        short(&ws.digest),
                        ws.files,
                        output::bytes(ws.bytes),
                        ws.captured_from.as_deref().unwrap_or("?"),
                        output::timestamp(at),
                    ),
                    None => short(&ws.digest),
                },
            );
            output::field(
                "  In store",
                if ws.push_pending {
                    format!("NOT YET — push pending (store holds {})", short(&ws.pushed))
                } else {
                    match ws.pushed_at {
                        Some(at) => format!("{} at {}", short(&ws.pushed), output::timestamp(at)),
                        None => short(&ws.pushed),
                    }
                },
            );
            let interval = d
                .spec
                .vm
                .as_ref()
                .and_then(|vm| vm.workspace.as_ref())
                .and_then(|w| w.snapshot_interval_secs);
            output::field(
                "  Snapshot every",
                match interval {
                    Some(n) => output::duration(n),
                    None => "only when the replica retires (snapshot_interval_secs unset)".to_string(),
                },
            );
            for p in &ws.pending {
                output::field(
                    "  Capture queued",
                    format!(
                        "{} (then {}{})",
                        p.sandbox_id,
                        p.then,
                        if p.attempts > 0 {
                            format!(", {} failed attempt(s)", p.attempts)
                        } else {
                            String::new()
                        }
                    ),
                );
            }
            if let Some(why) = &ws.blocked {
                output::field("  Pool held", why);
            }
            if let Some(e) = &ws.last_error {
                output::field("  Last error", e);
            }
        }

        if let Some(build) = &d.spec.build {
            output::section("Build source");
            output::field("Repo", &build.repo);
            output::field("Ref", build.git_ref.as_deref().unwrap_or("(default branch)"));
            output::field(
                "Dockerfile",
                build
                    .dockerfile
                    .as_deref()
                    .unwrap_or("(found in the checkout)"),
            );
            if let Some(c) = &build.context {
                output::field("Context", c);
            }
            output::field(
                "Image name",
                build
                    .image_name
                    .as_deref()
                    .unwrap_or("(the deployment id) + commit"),
            );
            if let Some(mb) = build.image_size_mb {
                output::field("Rootfs size", format!("{mb} MB"));
            }
            // A reference, not a value: the credential itself is only ever
            // resolved server-side, when a build runs.
            output::field(
                "Credential",
                match &build.auth {
                    Some(a) => format!("secret {}", a.render()),
                    None => "none (public repo, or host ssh keys)".to_string(),
                },
            );
        }

        // The other image source. Never both — app-lb refuses a spec holding
        // one of each — so these two sections cannot appear together.
        if let Some(artifact) = &d.spec.artifact {
            output::section("Artifact source");
            output::field("Store", &artifact.store);
            let remote = artifact.store.starts_with("http://")
                || artifact.store.starts_with("https://");
            output::field(
                "Transport",
                if remote {
                    "streamed over HTTP, digest verified on arrival"
                } else {
                    "materialized locally by `art` (hole-aware)"
                },
            );
            // Which of the two it is decides whether the deployment follows a
            // moving tag or is pinned, and that is the thing worth knowing.
            output::field(
                "Ref",
                match artifact.artifact_ref.len() == 64
                    && artifact.artifact_ref.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    true => format!("{} (a digest — pinned)", artifact.artifact_ref),
                    false => format!("{} (a tag — resolved at pull time)", artifact.artifact_ref),
                },
            );
            output::field(
                "Image name",
                artifact
                    .image_name
                    .as_deref()
                    .unwrap_or("(the deployment id) + digest"),
            );
            output::field(
                "Grow to",
                match artifact.grow_gb {
                    Some(gb) => format!("{gb} GiB (sparse)"),
                    None => "(the image's stored size)".to_string(),
                },
            );
            output::field(
                "Credential",
                match (&artifact.auth, remote) {
                    (Some(a), true) => format!("secret {}", a.render()),
                    // Said rather than shown as configured: the server logs it
                    // as unused on every pull, and this is where somebody would
                    // look first.
                    (Some(a), false) => {
                        format!("secret {} — UNUSED, a local store has no API key", a.render())
                    }
                    (None, _) => "none (an ungated store)".to_string(),
                },
            );
        }

        output::section("Scaling");
        let s = &d.spec.scaling;
        output::field("Desired", d.desired_replicas.to_string());
        output::field("Min / Max", format!("{} / {}", s.min_replicas, s.max_replicas));
        output::field("Warm pool", s.warm_pool.to_string());
        output::field("Target concurrency", s.target_concurrency.to_string());
        output::field(
            "Scale to zero after",
            output::duration(s.scale_to_zero_after_secs),
        );
        output::field("Cold start timeout", output::duration(s.cold_start_timeout_secs));
        output::field("Drain timeout", output::duration(s.drain_timeout_secs));
        output::field(
            "When idle",
            match s.idle_action.as_str() {
                "retain" => "retain — stop the VM, keeping its /workspace disk".to_string(),
                // Empty when talking to an app-lb that predates the field.
                "destroy" | "" => "destroy — kill the VM and its disks".to_string(),
                other => other.to_string(),
            },
        );
    }

    if let Some(auth) = &d.spec.auth {
        output::section("Sign-in gate");
        // An inheriting gate carries no identity of its own, so everything below
        // would print as absent. Say where it comes from instead, and name the
        // command that shows it.
        if let Some(provider_ref) = &auth.provider_ref {
            output::field(
                "Identity from",
                format!(
                    "auth provider {provider_ref} in namespace {} \
                     (`heyctl describe auth-provider {provider_ref} -n {}`)",
                    d.spec.namespace(),
                    d.spec.namespace(),
                ),
            );
        }
        // Every field from here to the JWT block is the *identity* half, which
        // an inheriting gate does not have: printing it would describe this
        // empty gate rather than the provider it borrows, and `providers()`
        // reads an absent list as Google, so "who may enter: <nobody>" is what
        // that looks like. The line above says where to look instead.
        if auth.provider_ref.is_none() {
            // Joined rather than listed, because they are alternatives: any one
            // of them admits a request.
            output::field("Provider", auth.providers().join(" or "));
            // Absent on a token-only gate, where neither describes anything.
            if let Some(client_id) = &auth.client_id {
                output::field("Client id", client_id);
            }
            if let Some(secret) = &auth.client_secret {
                output::field("Client secret", format!("secret {}", secret.render()));
            }
            // Only meaningful for Google, which is the only provider these two
            // describe — a JWT gate's allow-list is `jwt.require`, printed below.
            if auth.providers().iter().any(|p| p == "google") {
                output::field("Who may enter", auth.allow_summary());
            }
        }
        if let Some(jwt) = &auth.jwt {
            output::field("JWT issuer", &jwt.issuer);
            output::field(
                "JWT audience",
                jwt.audience.as_deref().unwrap_or("(not checked)"),
            );
            output::field("JWT key", jwt.key_summary());
            output::field("JWT algorithms", jwt.algorithms.join(", "));
            output::field("JWT admits", jwt.require_summary());
            output::field(
                "JWT subject claim",
                format!("{} -> x-auth-request-user", jwt.subject_claim),
            );
            if let Some(cookie) = &jwt.cookie {
                output::field("JWT cookie", format!("{cookie} (when no Authorization header)"));
            }
            // A block the gate will never consult is worth saying out loud: the
            // server refuses that spec, so seeing it here means the deployment
            // predates the check or was written by hand against an older LB.
            if !auth.accepts_jwt() {
                output::field(
                    "JWT",
                    "NOT IN USE — `jwt` is not among this gate's providers",
                );
            }
        }
        if !auth.public_paths.is_empty() {
            // Rendered with the scope, because the path alone no longer says
            // what reaching it takes — and "public" vs "admin" on the same path
            // is the whole difference between open and closed.
            output::field(
                "Public paths",
                auth.public_paths
                    .iter()
                    .map(|p| format!("{} ({})", p.path, p.scope))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        // The single most common reason a gate doesn't work is that this exact
        // URL is not registered with the provider, so print it rather than
        // leaving it to be assembled by hand.
        let host = d
            .spec
            .routes
            .iter()
            .find_map(|r| r.host.clone())
            .unwrap_or_else(|| "<this deployment's hostname>".into());
        output::field("Redirect URI", match &auth.redirect_url {
            Some(u) => format!("{u} (overridden)"),
            None => auth.callback_url(&host),
        });
        output::field("Session lifetime", output::duration(auth.session_ttl_secs));
        output::field(
            "Identity headers",
            if auth.forward_identity {
                "x-auth-request-email, -user, -name"
            } else {
                "not forwarded"
            },
        );
    }

    output::section("Health check");
    output::field(
        "Probe",
        match &d.spec.health.path {
            Some(p) => format!("GET {p}"),
            None => "TCP connect".to_string(),
        },
    );
    if let Some(port) = d.spec.health.port {
        output::field("Port", port.to_string());
    }
    output::field("Timeout", output::duration(d.spec.health.timeout_secs));

    output::section("Backends");
    output::field("Ready / Pending", format!("{} / {}", d.ready, d.pending));
    output::field("In flight", d.total_in_flight.to_string());
    if d.vms.is_empty() {
        println!("  (no backends)");
    } else if d.spec.is_static() {
        // A static deployment's "backends" are the configured upstreams — there
        // is no sandbox, and no resource usage to report for one.
        let mut table = Table::indented(["UPSTREAM", "STATUS", "IN-FLIGHT"], 2);
        for vm in &d.vms {
            table.row([
                vm.addr.clone(),
                vm.status().to_string(),
                vm.in_flight.to_string(),
            ]);
        }
        table.print();
    } else {
        let view = metrics.and_then(|m| m.deployments.iter().find(|v| v.id == d.spec.id));
        let mut table = Table::indented(
            ["SANDBOX", "ADDRESS", "STATUS", "IN-FLIGHT", "CPU%", "MEMORY", "UPTIME"],
            2,
        );
        for vm in &d.vms {
            let live = view.and_then(|v| v.vms.iter().find(|x| x.sandbox_id == vm.sandbox_id));
            table.row([
                vm.sandbox_id.clone(),
                vm.addr.clone(),
                vm.status().to_string(),
                vm.in_flight.to_string(),
                output::opt_percent(live.and_then(|l| l.cpu_percent)),
                output::opt_bytes(live.and_then(|l| l.memory_bytes)),
                live.map(|l| output::duration(l.uptime_secs))
                    .unwrap_or_else(|| "—".into()),
            ]);
        }
        table.print();
    }

    match metrics.and_then(|m| m.deployments.iter().find(|v| v.id == d.spec.id)) {
        None => {
            output::section("Traffic");
            println!("  (no metrics — /metrics is gated or unreachable for this user)");
        }
        Some(view) => {
            let m = &view.metrics;
            output::section("Traffic (since app-lb started)");
            output::field(
                "Requests",
                format!(
                    "{} total — {} 2xx, {} 3xx, {} 4xx, {} 5xx, {} errors",
                    m.requests.total,
                    m.requests.c2xx,
                    m.requests.c3xx,
                    m.requests.c4xx,
                    m.requests.c5xx,
                    m.requests.errors
                ),
            );
            output::field(
                "Latency",
                format!(
                    "p50 {}  p90 {}  p99 {}",
                    output::millis(m.latency_ms.p50),
                    output::millis(m.latency_ms.p90),
                    output::millis(m.latency_ms.p99)
                ),
            );
            output::field("Utilization", output::ratio_percent(view.pool.utilization));
            output::field(
                "Pool CPU / memory",
                format!(
                    "{} / {}",
                    output::opt_percent(view.pool.cpu_percent),
                    output::opt_bytes(view.pool.memory_bytes)
                ),
            );
            let a = &m.autoscale;
            output::field(
                "Autoscaler",
                format!(
                    "{} VMs created, {} drained, {} reaped ({} up / {} down events)",
                    a.vms_created, a.vms_drained, a.vms_reaped, a.scale_up_events, a.scale_down_events
                ),
            );
            output::field(
                "Cold starts",
                format!(
                    "{} waits — {} served, {} timed out (p50 {:.1}s)",
                    a.cold_start_waits, a.cold_start_hits, a.cold_start_timeouts, m.cold_start_s.p50
                ),
            );
            // The two failure counters, and only when non-zero: a healthy pool
            // should not carry two permanent zeroes, but a stuck one must say
            // which kind of stuck it is. They are the difference between "the
            // guest never became healthy" (boot timeouts — debug the image) and
            // "no VM was ever created" (create failures — debug the host), which
            // otherwise look identical from out here: `ready: 0`.
            if a.boot_timeouts > 0 {
                output::field(
                    "Boot failures",
                    format!(
                        "{} VMs never passed their health check inside the boot timeout",
                        a.boot_timeouts
                    ),
                );
            }
            if a.create_failures > 0 {
                output::field(
                    "Create failures",
                    match a.last_create_error.as_deref() {
                        Some(err) => format!(
                            "{} refused by the VM daemon — last error: {err}",
                            a.create_failures
                        ),
                        None => format!("{} refused by the VM daemon", a.create_failures),
                    },
                );
            }
        }
    }
}

/// Re-run a renderer on a timer, clearing the screen between passes.
pub fn watch(interval: Duration, mut render: impl FnMut() -> Result<()>) -> Result<()> {
    loop {
        // Home the cursor and clear, so successive frames don't scroll.
        print!("\x1b[2J\x1b[H");
        render()?;
        println!("\n(watching every {}s — Ctrl-C to stop)", interval.as_secs());
        std::thread::sleep(interval);
    }
}

/// Shared by `get`/`top`: how the output format was spelled, for error text.
pub fn format_name(f: OutputFormat) -> &'static str {
    match f {
        OutputFormat::Table => "table",
        OutputFormat::Wide => "wide",
        OutputFormat::Json => "json",
        OutputFormat::Yaml => "yaml",
        OutputFormat::Name => "name",
    }
}
