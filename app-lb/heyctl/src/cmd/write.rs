//! The commands that change something: create, apply, edit, set, scale,
//! restart and delete.
//!
//! Every in-place change is a read-modify-write against `PUT /deployments/:id`,
//! which replaces the whole spec. The one exception is `scale`, which has a
//! real partial endpoint (`PATCH .../scaling`) and so never has to read first.

use super::{Ctx, Resource, deployment_name, parse_ref};
use crate::output::{self, Table};
use crate::spec::{self, EnvChange};
use crate::types::{DeploymentStatus, JobRecord, SecretSummary, UpstreamTrafficStatus};
use anyhow::{Context, Result, bail};
use clap::Args;
use serde_json::{Map, Value};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

// -- create ----------------------------------------------------------------

/// The `build_source` group exists so the flags that merely *describe* a build
/// can require "one of the two sources", rather than naming `--repo`
/// specifically — which was true while a repo was the only source and silently
/// wrong the moment a second one existed.
#[derive(Args, Debug)]
#[command(group(clap::ArgGroup::new("build_source").args(["repo", "build_store"])))]
pub struct CreateDeploymentArgs {
    /// The deployment id, unique across the load balancer.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// The namespace this deployment belongs to. Omitted means "default".
    ///
    /// A namespace is not created first — naming one here is what brings it
    /// into existence. It is also the wall a namespace-scoped token is confined
    /// to: see `heyctl token mint --namespace`.
    #[arg(long, short = 'n', value_name = "NAMESPACE")]
    pub namespace: Option<String>,

    // Routing. The three shorthand flags describe one rule together; --route
    // adds further rules.
    /// Exact hostname to route, e.g. `secrets.local`.
    #[arg(long, value_name = "HOST", help_heading = "Routing")]
    pub host: Option<String>,
    /// Subdomain match: the apex and any subdomain of it, e.g. `apps.example.com`.
    #[arg(long, value_name = "DOMAIN", help_heading = "Routing")]
    pub host_suffix: Option<String>,
    /// Path prefix to route, e.g. `/api`. Forwarded unchanged — app-lb does not
    /// strip it.
    #[arg(long, value_name = "PATH", help_heading = "Routing")]
    pub path_prefix: Option<String>,
    /// An extra route rule: `host=a.example.com,path=/api`, `*.example.com`, or
    /// `/api`. Repeatable.
    #[arg(long = "route", value_name = "RULE", help_heading = "Routing")]
    pub routes: Vec<String>,
    /// Create with no ingress at all. The deployment takes no HTTP traffic and
    /// is reached only by `heyctl exec` and `heyctl shell` — the usual
    /// shape for an agent sandbox. Managed (VM) deployments only; add a route
    /// later with `heyctl set routes` to expose it.
    #[arg(
        long,
        conflicts_with_all = ["host", "host_suffix", "path_prefix", "routes"],
        help_heading = "Routing"
    )]
    pub no_route: bool,

    // Managed VM pool.
    /// Guest image for the VM pool (defaults to ubuntu:24.04 daemon-side).
    #[arg(long, value_name = "IMAGE", help_heading = "VM pool")]
    pub image: Option<String>,
    /// Guest port traffic is proxied to. Required for a managed deployment.
    #[arg(long, value_name = "PORT", help_heading = "VM pool")]
    pub port: Option<u16>,
    /// Hypervisor driver. libvirt is rejected: app-lb routes to the guest IP,
    /// which only tap-networked firecracker/kvm expose.
    #[arg(long, value_name = "DRIVER", default_value = "firecracker", help_heading = "VM pool")]
    pub driver: String,
    /// Command the guest runs at boot.
    #[arg(long, value_name = "CMD", help_heading = "VM pool")]
    pub start_command: Option<String>,
    /// Size class: micro, mini, small, medium, large, xlarge.
    #[arg(long, value_name = "CLASS", help_heading = "VM pool")]
    pub size: Option<String>,
    /// Size of the guest's persistent data disk, mounted at /workspace. This is
    /// the *only* storage that survives a stop — the root filesystem is recopied
    /// from the image on every boot — so a sandbox that keeps state needs it.
    #[arg(long, value_name = "GB", help_heading = "VM pool")]
    pub disk_gb: Option<u32>,
    #[arg(long, value_name = "DIR", help_heading = "VM pool")]
    pub workdir: Option<String>,
    /// Guest environment variable, `KEY=VALUE`. Repeatable.
    #[arg(long = "env", short = 'e', value_name = "KEY=VALUE", help_heading = "VM pool")]
    pub env: Vec<String>,
    /// Command run once while the VM is being prepared. Repeatable.
    #[arg(long = "setup-hook", value_name = "CMD", help_heading = "VM pool")]
    pub setup_hooks: Vec<String>,
    /// Extra guest port to open. Repeatable.
    #[arg(long = "open-port", value_name = "PORT", help_heading = "VM pool")]
    pub open_ports: Vec<u16>,
    /// Backstop TTL in seconds: VMs die on their own if app-lb stops renewing.
    #[arg(long, value_name = "SECS", help_heading = "VM pool")]
    pub ttl: Option<u64>,

    /// Serve files from this directory on the app-lb host instead of proxying
    /// anywhere — a static site, the way nginx's `root` or a CloudFront origin
    /// works. Absolute path.
    #[arg(long, value_name = "DIR", help_heading = "Static site")]
    pub site_root: Option<String>,
    /// File served for a directory. Pass "" to 404 those instead.
    #[arg(long, value_name = "FILE", help_heading = "Static site")]
    pub site_index: Option<String>,
    /// Page served with a 404, relative to the site root.
    #[arg(long, value_name = "FILE", help_heading = "Static site")]
    pub site_404: Option<String>,
    /// Serve the index for any unmatched path, so a client-side router owns the
    /// URL space. Turns every typo into a 200 — for single-page apps only.
    #[arg(long, help_heading = "Static site")]
    pub site_spa: bool,
    /// `Cache-Control` for served files.
    #[arg(long, value_name = "VALUE", help_heading = "Static site")]
    pub site_cache_control: Option<String>,

    /// A fixed upstream `host:port` to proxy_pass to, instead of a VM pool.
    /// Repeatable; mutually exclusive with the VM-pool flags.
    #[arg(long = "upstream", value_name = "ADDR", help_heading = "Static upstreams")]
    pub upstreams: Vec<String>,
    /// Orchestrator service whose healthy endpoint set supplies the upstreams.
    /// May be combined with --upstream to provide a last-known bootstrap set.
    #[arg(long, value_name = "SERVICE", help_heading = "Static upstreams")]
    pub discovery_service: Option<String>,

    // Build source. Recording it here does not build anything — `heyctl
    // build <name>` does that — so a deployment can be created against an
    // existing image and switched to built images later.
    /// Git remote the guest image is built from.
    #[arg(long, value_name = "URL", help_heading = "Build source", conflicts_with = "build_store")]
    pub repo: Option<String>,
    /// Artifact store holding a Dockerfile manifest to build, instead of a git
    /// remote: an `art serve` URL or an absolute store root on the app-lb host.
    /// Pair it with --ref.
    #[arg(
        long = "build-store",
        value_name = "URL|PATH",
        help_heading = "Build source",
        conflicts_with = "repo",
        requires = "git_ref"
    )]
    pub build_store: Option<String>,
    /// Which version of the source to build: a branch, tag or commit for --repo,
    /// or a Dockerfile manifest's tag or digest for --build-store.
    #[arg(long = "ref", value_name = "REF", help_heading = "Build source", requires = "build_source")]
    pub git_ref: Option<String>,
    /// Dockerfile path within the repo. Unset lets app-lb look for one.
    #[arg(long, value_name = "PATH", help_heading = "Build source", requires = "repo")]
    pub dockerfile: Option<String>,
    /// Build context within the repo. Defaults to the Dockerfile's directory.
    #[arg(long = "build-context", value_name = "PATH", help_heading = "Build source", requires = "repo")]
    pub build_context: Option<String>,
    /// Base name for built images; the source version is appended.
    #[arg(long, value_name = "NAME", help_heading = "Build source", requires = "build_source")]
    pub image_name: Option<String>,
    /// Rootfs size for the built image.
    #[arg(long = "size-mb", value_name = "MB", help_heading = "Build source", requires = "build_source")]
    pub image_size_mb: Option<u64>,
    /// Stored secret holding the credential, as `NAME` or `NAME/KEY`: a git
    /// token for --repo, or the store's API key for --build-store.
    #[arg(long = "secret", value_name = "NAME[/KEY]", help_heading = "Build source", requires = "build_source")]
    pub secret: Option<String>,

    #[command(flatten)]
    pub scaling: ScalingFlags,

    /// Health probe path. Defaults to `/`.
    #[arg(long, value_name = "PATH", help_heading = "Health")]
    pub health_path: Option<String>,
    /// Prove readiness with a bare TCP connect instead of an HTTP request.
    #[arg(long, conflicts_with = "health_path", help_heading = "Health")]
    pub health_tcp: bool,
    /// Health port, if the guest serves health somewhere other than --port.
    #[arg(long, value_name = "PORT", help_heading = "Health")]
    pub health_port: Option<u16>,
    #[arg(long, value_name = "SECS", help_heading = "Health")]
    pub health_timeout: Option<u64>,

    /// Print the spec that would be sent, and send nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// The scaling knobs, shared by `create` and `scale`.
#[derive(Args, Debug, Default)]
pub struct ScalingFlags {
    /// Floor for the pool: replicas kept even at zero traffic.
    #[arg(long, value_name = "N", help_heading = "Scaling")]
    pub min: Option<u64>,
    /// Ceiling for the pool.
    #[arg(long, value_name = "N", help_heading = "Scaling")]
    pub max: Option<u64>,
    /// Idle-but-ready spares kept above what load requires.
    #[arg(long, value_name = "N", help_heading = "Scaling")]
    pub warm: Option<u64>,
    /// In-flight requests per VM the autoscaler aims for.
    #[arg(long, value_name = "N", help_heading = "Scaling")]
    pub target_concurrency: Option<u64>,
    /// Idle time before the pool drops to min_replicas.
    #[arg(long, value_name = "SECS", help_heading = "Scaling")]
    pub scale_to_zero_after: Option<u64>,
    /// How long a request waits for a VM to boot before giving up with 503.
    #[arg(long, value_name = "SECS", help_heading = "Scaling")]
    pub cold_start_timeout: Option<u64>,
    /// How long a draining VM may keep serving before it is killed anyway.
    #[arg(long, value_name = "SECS", help_heading = "Scaling")]
    pub drain_timeout: Option<u64>,
    /// How long a booting VM has to pass its health check before the autoscaler
    /// gives up on it and replaces it. 0 waits indefinitely.
    #[arg(long, value_name = "SECS", help_heading = "Scaling")]
    pub boot_timeout: Option<u64>,
    /// What becomes of a VM the autoscaler retires. `destroy` (the default)
    /// frees the sandbox and its disks. `retain` stops it instead, keeping its
    /// /workspace data disk, and a later request or `exec` resumes that VM
    /// rather than booting a fresh one — the setting for an agent sandbox,
    /// whose working directory is the point.
    #[arg(
        long,
        value_name = "ACTION",
        value_parser = ["destroy", "retain"],
        help_heading = "Scaling"
    )]
    pub idle_action: Option<String>,
}

impl ScalingFlags {
    fn patch(&self) -> Map<String, Value> {
        let mut patch = spec::scaling_patch(&[
            ("min_replicas", self.min),
            ("max_replicas", self.max),
            ("warm_pool", self.warm),
            ("target_concurrency", self.target_concurrency),
            ("scale_to_zero_after_secs", self.scale_to_zero_after),
            ("cold_start_timeout_secs", self.cold_start_timeout),
            ("drain_timeout_secs", self.drain_timeout),
            ("boot_timeout_secs", self.boot_timeout),
        ]);
        if let Some(action) = &self.idle_action {
            patch.insert("idle_action".into(), Value::String(action.clone()));
        }
        patch
    }
}

#[derive(Args, Debug)]
pub struct CreateNamespaceArgs {
    /// The namespace's name. Letters, digits, `-`, `_` and `.` — it appears in
    /// URLs and filenames unescaped.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// What the namespace is for. A room with no label is fine until there are
    /// twenty of them.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,

    /// Print what would be sent, and send nothing.
    #[arg(long)]
    pub dry_run: bool,
}

pub fn create_namespace(ctx: &Ctx, args: &CreateNamespaceArgs) -> Result<()> {
    let mut spec = Map::new();
    spec.insert("name".into(), Value::String(args.name.clone()));
    if let Some(d) = &args.description {
        spec.insert("description".into(), Value::String(d.clone()));
    }
    let spec = Value::Object(spec);
    if args.dry_run {
        return print_spec(ctx, &spec);
    }
    let created = ctx.client.create_namespace(&spec)?;
    // Not `report_write`: that one emits `deployment/<id>` and parses a
    // DeploymentStatus, so a namespace would be announced as a deployment in
    // `-o json` and print nothing useful in a table.
    if ctx.out.is_machine() {
        return output::emit(&created, ctx.out, &[format!("namespace/{}", args.name)]);
    }
    println!("namespace/{} created", args.name);
    {
        println!(
            "\nNothing is in it yet. Put a deployment there with \
             `heyctl create deployment <NAME> --namespace {}`, or mint a token \
             confined to it with `heyctl token mint <NAME> --namespace {}`.",
            args.name, args.name,
        );
    }
    Ok(())
}

pub fn create(ctx: &Ctx, args: &CreateDeploymentArgs) -> Result<()> {
    let spec = build_spec(args)?;
    if args.dry_run {
        return print_spec(ctx, &spec);
    }
    let created = ctx.client.raw().create_deployment(&spec)?;
    report_write(ctx, &created, &args.name, "created")?;
    // Recording a build source does not build anything; say so, because the
    // deployment is otherwise sitting on whatever --image named.
    if args.repo.is_some() && !ctx.out.is_machine() {
        println!(
            "\nIts image is not built yet — run `heyctl build {}` to check out the repo, \
             build the Dockerfile and roll the pool onto the result.",
            args.name
        );
    }
    Ok(())
}

fn build_spec(args: &CreateDeploymentArgs) -> Result<Value> {
    let mut routes = Vec::new();
    if let Some(rule) = spec::route_from_parts(
        args.host.as_deref(),
        args.host_suffix.as_deref(),
        args.path_prefix.as_deref(),
    ) {
        routes.push(rule);
    }
    for r in &args.routes {
        routes.push(spec::parse_route(r)?);
    }
    if routes.is_empty() && !args.no_route {
        bail!(
            "a deployment needs at least one route — pass --host, --host-suffix, \
             --path-prefix or --route, or --no-route for a sandbox reached only \
             by exec/shell"
        );
    }
    let static_backend = !args.upstreams.is_empty() || args.discovery_service.is_some();
    if args.no_route && static_backend {
        bail!(
            "--no-route leaves nothing able to reach this deployment: a static \
             (proxy_pass) deployment has no exec/shell door, so the proxy is its \
             only way in"
        );
    }

    let mut spec = Map::new();
    spec.insert("id".into(), Value::String(args.name.clone()));
    // Omitted when unset rather than sent as "default": app-lb defaults it and
    // skips it on the way back out, so writing it explicitly would put a field
    // in every spec that means nothing.
    if let Some(ns) = &args.namespace {
        spec.insert("namespace".into(), Value::String(ns.clone()));
    }
    spec.insert("routes".into(), Value::Array(routes));

    let vm_flags_used = args.image.is_some()
        || args.port.is_some()
        || args.start_command.is_some()
        || args.size.is_some()
        || !args.env.is_empty();

    if let Some(root) = &args.site_root {
        if vm_flags_used || static_backend {
            bail!(
                "--site-root makes this a static site, which has no VM template and no \
                 upstreams — it serves files off disk. Drop the other backend flags."
            );
        }
        // Checked here because this branch returns early, and a scaling flag
        // quietly dropped would look like it had been applied.
        if !args.scaling.patch().is_empty() {
            bail!("a static site has no pool to scale, so the scaling flags do nothing");
        }
        let mut site = Map::new();
        site.insert("root".into(), Value::String(root.clone()));
        insert_opt_str(&mut site, "index", args.site_index.as_deref());
        insert_opt_str(&mut site, "not_found", args.site_404.as_deref());
        insert_opt_str(&mut site, "cache_control", args.site_cache_control.as_deref());
        if args.site_spa {
            site.insert("spa".into(), Value::Bool(true));
        }
        spec.insert("site".into(), Value::Object(site));
        return Ok(Value::Object(spec));
    }
    // The site flags only mean something with a root to apply them to; silently
    // ignoring them would look like they took effect.
    for (flag, set) in [
        ("--site-index", args.site_index.is_some()),
        ("--site-404", args.site_404.is_some()),
        ("--site-cache-control", args.site_cache_control.is_some()),
        ("--site-spa", args.site_spa),
    ] {
        if set {
            bail!("{flag} needs --site-root — it configures a static site");
        }
    }

    if static_backend {
        if vm_flags_used {
            bail!(
                "--upstream/--discovery-service makes this a static (proxy_pass) deployment, \
                 which has no VM template — drop the VM flags, or drop the static backend flags"
            );
        }
        spec.insert(
            "upstreams".into(),
            Value::Array(args.upstreams.iter().cloned().map(Value::String).collect()),
        );
        if let Some(service_id) = args.discovery_service.as_deref() {
            if service_id.trim().is_empty() {
                bail!("--discovery-service must not be empty");
            }
            spec.insert("discovery".into(), serde_json::json!({ "service_id": service_id }));
        }
    } else {
        let port = args.port.context(
            "a managed deployment needs --port (the guest port to proxy to); \
             use --upstream or --discovery-service instead for a static proxy_pass deployment",
        )?;
        let mut vm = Map::new();
        vm.insert("driver".into(), Value::String(args.driver.to_ascii_lowercase()));
        vm.insert("port".into(), Value::from(port));
        insert_opt_str(&mut vm, "image", args.image.as_deref());
        insert_opt_str(&mut vm, "start_command", args.start_command.as_deref());
        insert_opt_str(&mut vm, "size_class", args.size.as_deref().map(str::to_ascii_lowercase).as_deref());
        insert_opt_str(&mut vm, "working_directory", args.workdir.as_deref());
        if let Some(gb) = args.disk_gb {
            vm.insert("disk_size_gb".into(), Value::from(gb));
        }
        if let Some(ttl) = args.ttl {
            vm.insert("ttl_seconds".into(), Value::from(ttl));
        }
        if !args.env.is_empty() {
            let mut env = Map::new();
            for e in &args.env {
                match spec::parse_env(e)? {
                    EnvChange::Set(k, v) => {
                        env.insert(k, Value::String(v));
                    }
                    EnvChange::Remove(k) => {
                        bail!("--env {k}- removes a variable; there is nothing to remove on create")
                    }
                }
            }
            vm.insert("env_vars".into(), Value::Object(env));
        }
        if !args.setup_hooks.is_empty() {
            vm.insert(
                "setup_hooks".into(),
                Value::Array(args.setup_hooks.iter().cloned().map(Value::String).collect()),
            );
        }
        if !args.open_ports.is_empty() {
            vm.insert(
                "open_ports".into(),
                Value::Array(args.open_ports.iter().map(|p| Value::from(*p)).collect()),
            );
        }
        spec.insert("vm".into(), Value::Object(vm));
    }

    if args.repo.is_some() || args.build_store.is_some() {
        if static_backend {
            bail!(
                "--repo and --build-store build a guest image, which a static (proxy_pass) \
                 deployment does not have — drop the static backend flags, or drop the build flags"
            );
        }
        let mut build = Map::new();
        insert_opt_str(&mut build, "repo", args.repo.as_deref());
        insert_opt_str(&mut build, "store", args.build_store.as_deref());
        insert_opt_str(&mut build, "ref", args.git_ref.as_deref());
        insert_opt_str(&mut build, "dockerfile", args.dockerfile.as_deref());
        insert_opt_str(&mut build, "context", args.build_context.as_deref());
        insert_opt_str(&mut build, "image_name", args.image_name.as_deref());
        if let Some(mb) = args.image_size_mb {
            build.insert("image_size_mb".into(), Value::from(mb));
        }
        if let Some(s) = &args.secret {
            build.insert("auth".into(), spec::parse_secret_ref(s)?);
        }
        spec.insert("build".into(), Value::Object(build));
    }

    let scaling = args.scaling.patch();
    if !scaling.is_empty() {
        if static_backend {
            bail!("a static (proxy_pass) deployment is not autoscaled, so the scaling flags do nothing");
        }
        spec.insert("scaling".into(), Value::Object(scaling));
    }

    let mut health = Map::new();
    if args.health_tcp {
        // Explicit null is what selects a bare TCP connect; omitting the field
        // would get the server's default of `GET /`.
        health.insert("path".into(), Value::Null);
    } else if let Some(p) = &args.health_path {
        health.insert("path".into(), Value::String(p.clone()));
    }
    if let Some(port) = args.health_port {
        health.insert("port".into(), Value::from(port));
    }
    if let Some(t) = args.health_timeout {
        health.insert("timeout_secs".into(), Value::from(t));
    }
    if !health.is_empty() {
        spec.insert("health".into(), Value::Object(health));
    }

    Ok(Value::Object(spec))
}

fn insert_opt_str(map: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(v) = value {
        map.insert(key.to_string(), Value::String(v.to_string()));
    }
}

// -- create secret ---------------------------------------------------------

/// Where a secret's values come from.
///
/// Four sources rather than one because a credential on the command line is
/// visible in `ps` and lands in shell history — that is the convenient form, so
/// it stays, but the alternatives have to be just as easy to reach.
#[derive(Args, Debug, Default)]
pub struct SecretSourceFlags {
    /// Read the value from a file: `KEY=/path/to/token`. A single trailing
    /// newline is stripped, which is what `openssl rand … > file` leaves.
    #[arg(long = "from-file", value_name = "KEY=PATH", help_heading = "Sources")]
    pub from_file: Vec<String>,
    /// Take the value from this process's environment: `KEY=VAR`, or just `KEY`
    /// to use the key's own name as the variable.
    #[arg(long = "from-env", value_name = "KEY[=VAR]", help_heading = "Sources")]
    pub from_env: Vec<String>,
    /// Read one value from stdin: `--from-stdin KEY`. Everything up to EOF is
    /// the value, minus a trailing newline.
    #[arg(long = "from-stdin", value_name = "KEY", help_heading = "Sources")]
    pub from_stdin: Option<String>,
}

impl SecretSourceFlags {
    /// Collect every source into `KEY -> value`, in flag order.
    fn collect(&self, literals: &[String]) -> Result<Map<String, Value>> {
        let mut data = Map::new();
        for arg in literals {
            match spec::parse_env(arg)? {
                EnvChange::Set(k, v) => {
                    data.insert(k, Value::String(v));
                }
                EnvChange::Remove(k) => bail!(
                    "{k}- removes a key; there is nothing to remove while creating a secret"
                ),
            }
        }
        for arg in &self.from_file {
            let (key, path) = arg.split_once('=').with_context(|| {
                format!("--from-file {arg:?} is not KEY=PATH")
            })?;
            let value = std::fs::read_to_string(path)
                .with_context(|| format!("reading the value for {key:?} from {path}"))?;
            data.insert(key.to_string(), Value::String(trim_one_newline(&value)));
        }
        for arg in &self.from_env {
            let (key, var) = match arg.split_once('=') {
                Some((k, v)) => (k, v),
                None => (arg.as_str(), arg.as_str()),
            };
            let value = std::env::var(var).with_context(|| {
                format!("${var} is not set, so there is no value for {key:?}")
            })?;
            data.insert(key.to_string(), Value::String(value));
        }
        if let Some(key) = &self.from_stdin {
            let value = std::io::read_to_string(std::io::stdin())
                .with_context(|| format!("reading the value for {key:?} from stdin"))?;
            data.insert(key.clone(), Value::String(trim_one_newline(&value)));
        }
        Ok(data)
    }
}

fn trim_one_newline(s: &str) -> String {
    s.strip_suffix('\n')
        .map(|t| t.strip_suffix('\r').unwrap_or(t))
        .unwrap_or(s)
        .to_string()
}

#[derive(Args, Debug)]
pub struct CreateSecretArgs {
    /// The secret id, unique within its namespace.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// The namespace the secret lives behind. Omitted means `default`.
    ///
    /// A wall, not a label: only deployments and auth providers in the same
    /// namespace can resolve it, so a key stored in the wrong one is missing
    /// rather than merely misfiled.
    #[arg(long, short = 'n', value_name = "NAMESPACE")]
    pub namespace: Option<String>,

    /// `KEY=VALUE`, repeatable. Visible in `ps` and in shell history — prefer
    /// --from-file, --from-env or --from-stdin for anything real.
    #[arg(value_name = "KEY=VALUE")]
    pub literals: Vec<String>,

    #[command(flatten)]
    pub sources: SecretSourceFlags,

    /// What this secret is for. Shown by `heyctl get secrets`.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,

    /// Print what would be sent — with the values redacted — and send nothing.
    #[arg(long)]
    pub dry_run: bool,
}

pub fn create_secret(ctx: &Ctx, args: &CreateSecretArgs) -> Result<()> {
    let data = args.sources.collect(&args.literals)?;
    if data.is_empty() {
        bail!(
            "a secret needs at least one key — pass KEY=VALUE, --from-file, --from-env \
             or --from-stdin"
        );
    }

    let mut body = Map::new();
    body.insert("id".into(), Value::String(args.name.clone()));
    if let Some(ns) = &args.namespace {
        body.insert("namespace".into(), Value::String(ns.clone()));
    }
    if let Some(d) = &args.description {
        body.insert("description".into(), Value::String(d.clone()));
    }
    body.insert("data".into(), Value::Object(data.clone()));

    if args.dry_run {
        // Never print the values, not even here: a dry run is the command people
        // paste into a terminal that somebody else is watching.
        let mut shown = body.clone();
        shown.insert(
            "data".into(),
            Value::Object(
                data.keys()
                    .map(|k| (k.clone(), Value::String("<redacted>".into())))
                    .collect(),
            ),
        );
        return print_spec(ctx, &Value::Object(shown));
    }

    // POST upserts, so say which one actually happened.
    let existed = ctx
        .client
        .secret_exists_in(args.namespace.as_deref(), &args.name)
        .unwrap_or(false);
    let result = ctx.client.raw().put_secret(&Value::Object(body))?;
    report_secret(ctx, &result, &args.name, if existed { "replaced" } else { "created" })
}

#[derive(Args, Debug)]
pub struct SetSecretArgs {
    /// The secret, e.g. `github` or `secret/github`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,

    /// The namespace it lives in. Omitted means `default`.
    #[arg(long, short = 'n', value_name = "NAMESPACE")]
    pub namespace: Option<String>,

    /// `KEY=VALUE` to set, `KEY-` to remove. Repeatable. Keys not mentioned are
    /// left as they are — which matters here, because there is no way to read
    /// them back and resend them.
    #[arg(value_name = "KEY=VALUE")]
    pub changes: Vec<String>,

    #[command(flatten)]
    pub sources: SecretSourceFlags,

    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,

    #[arg(long)]
    pub dry_run: bool,
}

pub fn set_secret(ctx: &Ctx, args: &SetSecretArgs) -> Result<()> {
    let id = secret_name(&args.resource)?;

    // Sets and removals share one map: `null` is how the API spells "remove".
    let mut data = Map::new();
    let mut removed = Vec::new();
    for arg in &args.changes {
        match spec::parse_env(arg)? {
            EnvChange::Set(k, v) => {
                data.insert(k, Value::String(v));
            }
            EnvChange::Remove(k) => {
                data.insert(k.clone(), Value::Null);
                removed.push(k);
            }
        }
    }
    for (k, v) in args.sources.collect(&[])? {
        data.insert(k, v);
    }
    if data.is_empty() && args.description.is_none() {
        bail!(
            "nothing to change — pass KEY=VALUE, KEY-, --from-file, --from-env, \
             --from-stdin or --description"
        );
    }

    let mut body = Map::new();
    body.insert("data".into(), Value::Object(data.clone()));
    if let Some(d) = &args.description {
        body.insert("description".into(), Value::String(d.clone()));
    }

    if args.dry_run {
        let redacted: Map<String, Value> = data
            .iter()
            .map(|(k, v)| {
                let shown = if v.is_null() {
                    Value::Null
                } else {
                    Value::String("<redacted>".into())
                };
                (k.clone(), shown)
            })
            .collect();
        let mut shown = body.clone();
        shown.insert("data".into(), Value::Object(redacted));
        return print_spec(ctx, &Value::Object(shown));
    }

    let result = ctx
        .client
        .raw()
        .patch_secret_in(args.namespace.as_deref(), &id, &Value::Object(body))?;
    report_secret(ctx, &result, &id, "updated")
}

/// A single `secret/NAME` or bare-name argument.
fn secret_name(arg: &str) -> Result<String> {
    let (kind, names) = parse_ref(std::slice::from_ref(&arg.to_string()), Some(Resource::Secret))?;
    if kind != Resource::Secret {
        bail!("expected a secret, got {}", kind.singular());
    }
    match names.len() {
        1 => Ok(names.into_iter().next().expect("len == 1")),
        _ => bail!("expected a secret name, e.g. `github` or `secret/github`"),
    }
}

fn report_secret(ctx: &Ctx, result: &Value, id: &str, verb: &str) -> Result<()> {
    if ctx.out.is_machine() {
        return output::emit(result, ctx.out, &[format!("secret/{id}")]);
    }
    match serde_json::from_value::<SecretSummary>(result.clone()) {
        Ok(s) => println!(
            "secret/{id} {verb} — {} key(s): {}{}",
            s.keys.len(),
            s.keys.join(", "),
            if s.encrypted_at_rest {
                " (encrypted at rest)"
            } else {
                " (stored in plaintext; set APP_LB_SECRET_KEY on the server to encrypt)"
            }
        ),
        Err(_) => println!("secret/{id} {verb}"),
    }
    Ok(())
}

// -- set build -------------------------------------------------------------

#[derive(Args, Debug)]
pub struct SetBuildArgs {
    /// The deployment, e.g. `web` or `deployment/web`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,

    /// Git remote to build from: `https://…`, `git@host:path`, or a path on the
    /// app-lb host. Required the first time, unless --store is given.
    #[arg(long, value_name = "URL", conflicts_with = "store")]
    pub repo: Option<String>,
    /// Build from a Dockerfile manifest in an artifact store instead of a git
    /// checkout: an `art serve` URL (`http://host:8080`) or an absolute path to
    /// a store root on the app-lb host. Pair it with --ref.
    ///
    /// `heyctl artifact push-dockerfile` is what puts one there.
    #[arg(long, value_name = "URL|PATH", conflicts_with = "repo")]
    pub store: Option<String>,
    /// Which version of the source to build: a branch, tag or commit for --repo
    /// (unset follows the remote's default branch), or the tag or digest of a
    /// Dockerfile manifest for --store, where it is required.
    #[arg(long = "ref", value_name = "REF")]
    pub git_ref: Option<String>,
    /// Dockerfile path within the repo. Unset lets app-lb look for one. Git
    /// source only — a Dockerfile manifest already names its own recipe.
    #[arg(long, value_name = "PATH", conflicts_with = "store")]
    pub dockerfile: Option<String>,
    /// Build context within the repo. Defaults to the Dockerfile's directory.
    /// Git source only.
    #[arg(long = "build-context", value_name = "PATH", conflicts_with = "store")]
    pub build_context: Option<String>,
    /// Base name for built images; the commit is appended. Defaults to the
    /// deployment id.
    #[arg(long, value_name = "NAME")]
    pub image_name: Option<String>,
    /// Rootfs size for the built image. Unset lets heyvm size it from the image
    /// contents.
    #[arg(long = "size-mb", value_name = "MB")]
    pub image_size_mb: Option<u64>,
    /// Credential: a stored secret, as `NAME` or `NAME/KEY` (default key
    /// `token`). A git token for --repo, or the store's ART_API_KEY for --store.
    #[arg(long = "secret", value_name = "NAME[/KEY]")]
    pub secret: Option<String>,
    /// Username to pair with the token. Only needed by forges that reject a
    /// placeholder; GitHub, GitLab and Bitbucket do not.
    #[arg(long, value_name = "NAME", requires = "secret")]
    pub username: Option<String>,
    /// Build without credentials (drops `build.auth`).
    #[arg(long, conflicts_with_all = ["secret", "username"])]
    pub no_auth: bool,
    /// Remove the build source entirely; the deployment keeps its current image.
    #[arg(long, conflicts_with_all = [
        "repo", "store", "git_ref", "dockerfile", "build_context", "image_name",
        "image_size_mb", "secret", "username", "no_auth",
    ])]
    pub clear: bool,

    #[arg(long)]
    pub dry_run: bool,
}

pub fn set_build(ctx: &Ctx, args: &SetBuildArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;

    if args.clear {
        return edit_spec(ctx, &id, args.dry_run, "build source removed", |spec| {
            if let Some(map) = spec.as_object_mut() {
                map.remove("build");
            }
            Ok(())
        });
    }

    let touched = args.repo.is_some()
        || args.store.is_some()
        || args.git_ref.is_some()
        || args.dockerfile.is_some()
        || args.build_context.is_some()
        || args.image_name.is_some()
        || args.image_size_mb.is_some()
        || args.secret.is_some()
        || args.no_auth;
    if !touched {
        bail!(
            "nothing to set — pass --repo or --store, --ref, --dockerfile, --context, \
             --image-name, --size-mb, --secret or --no-auth (or --clear to remove the \
             build source)"
        );
    }

    let auth = match &args.secret {
        Some(s) => {
            let mut r = spec::parse_secret_ref(s)?;
            if let (Some(u), Some(map)) = (&args.username, r.as_object_mut()) {
                map.insert("username".into(), Value::String(u.clone()));
            }
            Some(r)
        }
        None => None,
    };

    edit_spec(ctx, &id, args.dry_run, "build source updated", |spec| {
        let build = spec::build_mut(spec, &id)?;
        let had = |key: &str| build.get(key).and_then(Value::as_str).is_some();
        if !had("repo") && !had("store") && args.repo.is_none() && args.store.is_none() {
            bail!(
                "deployment {id:?} has no build source yet, so --repo or --store is required \
                 (e.g. --repo https://github.com/acme/web.git, or --store \
                 http://art:8080 --ref web-rootfs)"
            );
        }
        // Switching sources drops the other one and the fields that only meant
        // something to it. Leaving them would produce a spec the server rejects
        // as having two sources, which is a confusing way to report a switch
        // that was expressed unambiguously.
        if args.repo.is_some() {
            build.remove("store");
        }
        if args.store.is_some() {
            for stale in ["repo", "dockerfile", "context"] {
                build.remove(stale);
            }
        }
        for (key, value) in [
            ("repo", args.repo.as_deref()),
            ("store", args.store.as_deref()),
            ("ref", args.git_ref.as_deref()),
            ("dockerfile", args.dockerfile.as_deref()),
            ("context", args.build_context.as_deref()),
            ("image_name", args.image_name.as_deref()),
        ] {
            if let Some(v) = value {
                build.insert(key.to_string(), Value::String(v.to_string()));
            }
        }
        if let Some(mb) = args.image_size_mb {
            build.insert("image_size_mb".into(), Value::from(mb));
        }
        if let Some(auth) = &auth {
            build.insert("auth".into(), auth.clone());
        }
        if args.no_auth {
            build.remove("auth");
        }
        Ok(())
    })
}

// -- set artifact ----------------------------------------------------------

#[derive(Args, Debug)]
pub struct SetArtifactArgs {
    /// The deployment, e.g. `web` or `deployment/web`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,

    /// The artifact store: an `art serve` URL (`http://host:8080`) or an
    /// absolute path to a store root on the app-lb host. Omit it to pull from
    /// app-lb's own global store — where `heyctl artifact push` puts images —
    /// which needs a ref under the deployment's namespace (`<ns>/web:v2`) or a
    /// digest, and no --secret. `--store ''` switches an existing deployment
    /// back to app-lb's store.
    #[arg(long, value_name = "URL|PATH")]
    pub store: Option<String>,
    /// Tag or digest naming the rootfs. A tag follows whatever it is moved to;
    /// a digest is immutable, and is what a rollback should name.
    #[arg(long = "ref", value_name = "REF")]
    pub artifact_ref: Option<String>,
    /// Base name for pulled images; the digest is appended. Defaults to the
    /// deployment id.
    #[arg(long, value_name = "NAME")]
    pub image_name: Option<String>,
    /// Grow the pulled rootfs to this many gigabytes. Sparse, so it costs no
    /// disk until the guest writes to it.
    #[arg(long = "grow-gb", value_name = "GB")]
    pub grow_gb: Option<u64>,
    /// API key for a gated store: a stored secret, as `NAME` or `NAME/KEY`
    /// (default key `token`). Only meaningful for the URL form.
    #[arg(long = "secret", value_name = "NAME[/KEY]")]
    pub secret: Option<String>,
    /// Pull without credentials (drops `artifact.auth`).
    #[arg(long, conflicts_with = "secret")]
    pub no_auth: bool,
    /// Remove the artifact source entirely; the deployment keeps its current
    /// image.
    #[arg(long, conflicts_with_all = [
        "store", "artifact_ref", "image_name", "grow_gb", "secret", "no_auth",
    ])]
    pub clear: bool,

    #[arg(long)]
    pub dry_run: bool,
}

pub fn set_artifact(ctx: &Ctx, args: &SetArtifactArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;

    if args.clear {
        return edit_spec(ctx, &id, args.dry_run, "artifact source removed", |spec| {
            if let Some(map) = spec.as_object_mut() {
                map.remove("artifact");
            }
            Ok(())
        });
    }

    let touched = args.store.is_some()
        || args.artifact_ref.is_some()
        || args.image_name.is_some()
        || args.grow_gb.is_some()
        || args.secret.is_some()
        || args.no_auth;
    if !touched {
        bail!(
            "nothing to set — pass --ref, --store, --image-name, --grow-gb, --secret or \
             --no-auth (or --clear to remove the artifact source)"
        );
    }

    let auth = match &args.secret {
        Some(s) => Some(spec::parse_secret_ref(s)?),
        None => None,
    };

    edit_spec(ctx, &id, args.dry_run, "artifact source updated", |spec| {
        apply_artifact_args(spec, &id, args, auth.as_ref())
    })
}

/// The edit `set artifact` makes, apart from the fetch and the `PUT` around it.
fn apply_artifact_args(
    spec: &mut Value,
    id: &str,
    args: &SetArtifactArgs,
    auth: Option<&Value>,
) -> Result<()> {
    let artifact = spec::artifact_mut(spec, id)?;
    // A ref is required to pull at all, and a block without one is a spec
    // app-lb would reject on `PUT` — so say so here, where the flag that
    // would fix it is still in view. The store is not: an absent one means
    // app-lb's own global store, and is left absent rather than written
    // out as an empty string.
    if artifact.get("ref").and_then(Value::as_str).is_none() && args.artifact_ref.is_none() {
        bail!(
            "deployment {id:?} has no artifact ref yet, so --ref is required \
             (a tag like `<namespace>/web:v2`, or a digest). \
             `heyctl artifact ls` lists the tags you can name"
        );
    }
    // `--store ''` switches back to app-lb's own store by dropping the key.
    if args.store.as_deref().is_some_and(|s| s.trim().is_empty()) {
        artifact.remove("store");
    }
    for (key, value) in [
        ("store", args.store.as_deref().filter(|s| !s.trim().is_empty())),
        ("ref", args.artifact_ref.as_deref()),
        ("image_name", args.image_name.as_deref()),
    ] {
        if let Some(v) = value {
            artifact.insert(key.to_string(), Value::String(v.to_string()));
        }
    }
    if let Some(gb) = args.grow_gb {
        artifact.insert("grow_gb".into(), Value::from(gb));
    }
    if let Some(auth) = auth {
        artifact.insert("auth".into(), auth.clone());
    }
    if args.no_auth {
        artifact.remove("auth");
    }
    Ok(())
}

// -- mount pull ------------------------------------------------------------

#[derive(Args, Debug)]
pub struct MountPullArgs {
    /// The deployment whose mounts to unpack, e.g. `search` or
    /// `deployment/search`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,

    /// Re-fetch trees already on the app-lb host. Rarely wanted: a tree's
    /// directory name is its digest, so its presence already proves what is in
    /// it.
    #[arg(long)]
    pub force: bool,

    /// Wait for the pull to finish and report the outcome.
    #[arg(long, short = 'w')]
    pub wait: bool,

    /// Print the pull's output when it finishes. Implies --wait.
    #[arg(long)]
    pub logs: bool,

    #[arg(long, value_name = "SECS", default_value_t = 1800)]
    pub timeout: u64,
}

/// `heyctl mounts pull <id>` — unpack every mount the spec declares.
///
/// Rarely needed by hand: registering or editing a deployment whose mounts have
/// no tree on the host starts one of these by itself. What is left for this
/// command is a tag that has moved, and `--force`.
///
/// No `--ref`, unlike `heyctl pull`. That flag rewrites one field for one job;
/// a deployment can declare eight mounts, and a single reference would have
/// nothing to attach itself to. Roll back by pinning `digest` or moving the tag.
pub fn pull_mounts(ctx: &Ctx, args: &MountPullArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;
    let started = ctx.client.raw().start_mount_pull(&id, args.force)?;

    if ctx.out.is_machine() && !(args.wait || args.logs) {
        let record: JobRecord = serde_json::from_value(started.clone()).unwrap_or_default();
        return output::emit(&started, ctx.out, &[format!("job/{}", record.id)]);
    }

    let record: JobRecord =
        serde_json::from_value(started).context("parsing the job the server started")?;
    if !ctx.out.is_machine() {
        let paths: Vec<&str> = record.mounts.iter().map(|m| m.path.as_str()).collect();
        println!(
            "job/{} started for deployment/{id} — {}",
            record.id,
            if paths.is_empty() {
                "no mounts listed yet".to_string()
            } else {
                paths.join(", ")
            },
        );
    }

    if !(args.wait || args.logs) {
        println!(
            "\nIt runs on the app-lb host, one mount at a time, and takes as long as the \
             transfers do — or no time at all for a tree that is already there. Follow it \
             with `heyctl get job {}`.",
            record.id
        );
        return Ok(());
    }
    wait_job(ctx, &record.id, Duration::from_secs(args.timeout), args.logs)
}

// -- pull ------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct PullArgs {
    /// The deployment to pull for, e.g. `web` or `deployment/web`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,

    /// Pull this reference instead of the one in the spec. A one-off: the
    /// stored `artifact.ref` is left alone, which is what makes
    /// `--ref <digest>` a rollback rather than a config change.
    #[arg(long = "ref", value_name = "REF")]
    pub artifact_ref: Option<String>,

    /// Re-fetch even when the image is already on the app-lb host. Rarely
    /// wanted: the image filename is its digest, so its presence already proves
    /// the bytes are right.
    #[arg(long)]
    pub force: bool,

    /// Wait for the pull to finish and report the outcome.
    #[arg(long, short = 'w')]
    pub wait: bool,

    /// Print the pull's output when it finishes. Implies --wait.
    #[arg(long)]
    pub logs: bool,

    #[arg(long, value_name = "SECS", default_value_t = 1800)]
    pub timeout: u64,
}

pub fn pull(ctx: &Ctx, args: &PullArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;

    let mut body = Map::new();
    if let Some(r) = &args.artifact_ref {
        body.insert("ref".into(), Value::String(r.clone()));
    }
    let started = ctx.client.raw().start_pull(
        &id,
        body.get("ref").and_then(Value::as_str),
        args.force,
    )?;

    if ctx.out.is_machine() && !(args.wait || args.logs) {
        let record: JobRecord = serde_json::from_value(started.clone()).unwrap_or_default();
        return output::emit(&started, ctx.out, &[format!("job/{}", record.id)]);
    }

    let record: JobRecord =
        serde_json::from_value(started).context("parsing the job the server started")?;
    if !ctx.out.is_machine() {
        println!(
            "job/{} started for deployment/{id} — {} from {}",
            record.id,
            record.artifact_ref.as_deref().unwrap_or("(spec ref)"),
            record.store.as_deref().unwrap_or("(spec store)"),
        );
    }

    if !(args.wait || args.logs) {
        println!(
            "\nIt runs on the app-lb host, and takes as long as the transfer does — or no \
             time at all if the image is already there. Follow it with \
             `heyctl get job {}`.",
            record.id
        );
        return Ok(());
    }
    wait_job(ctx, &record.id, Duration::from_secs(args.timeout), args.logs)
}

// -- set update ------------------------------------------------------------

#[derive(Args, Debug)]
pub struct SetUpdateArgs {
    /// The static deployment, e.g. `app-obs` or `deployment/app-obs`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,

    /// Working directory on the **app-lb host** — where the commands run.
    /// Required the first time. Must be absolute.
    #[arg(long = "workdir", visible_alias = "working-dir", value_name = "DIR")]
    pub working_dir: Option<String>,

    /// A command to run, in order. Repeatable; each is a shell line, so
    /// `--command 'git pull && cargo build --release'` is one step. Passing any
    /// replaces the whole list.
    #[arg(long = "command", short = 'c', value_name = "CMD")]
    pub commands: Vec<String>,

    /// Environment for the commands, `KEY=VALUE`. Repeatable; replaces the
    /// existing set.
    #[arg(long = "env", short = 'e', value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Environment from a stored secret: `NAME/KEY`, or `ENV=NAME/KEY` to choose
    /// the variable name. Repeatable; replaces the existing set.
    #[arg(long = "secret-env", value_name = "[ENV=]NAME/KEY")]
    pub secret_env: Vec<String>,

    /// Stored secret holding a git credential, for commands that fetch
    /// (`git pull`): `NAME` or `NAME/KEY`.
    #[arg(long = "secret", value_name = "NAME[/KEY]")]
    pub secret: Option<String>,

    /// Run without a git credential (drops `update.auth`).
    #[arg(long, conflicts_with = "secret")]
    pub no_auth: bool,

    /// Ceiling on a single command.
    #[arg(long = "command-timeout", value_name = "SECS")]
    pub timeout_secs: Option<u64>,

    /// How long to wait for the upstreams to answer afterwards. `0` skips the
    /// check — right only when the commands restart nothing.
    #[arg(long = "verify-timeout", value_name = "SECS")]
    pub verify_timeout_secs: Option<u64>,

    /// Remove the update block entirely.
    #[arg(long, conflicts_with_all = [
        "working_dir", "commands", "env", "secret_env", "secret", "no_auth",
        "timeout_secs", "verify_timeout_secs",
    ])]
    pub clear: bool,

    #[arg(long)]
    pub dry_run: bool,
}

pub fn set_update(ctx: &Ctx, args: &SetUpdateArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;

    if args.clear {
        return edit_spec(ctx, &id, args.dry_run, "update commands removed", |spec| {
            if let Some(map) = spec.as_object_mut() {
                map.remove("update");
            }
            Ok(())
        });
    }

    let touched = args.working_dir.is_some()
        || !args.commands.is_empty()
        || !args.env.is_empty()
        || !args.secret_env.is_empty()
        || args.secret.is_some()
        || args.no_auth
        || args.timeout_secs.is_some()
        || args.verify_timeout_secs.is_some();
    if !touched {
        bail!(
            "nothing to set — pass --workdir, --command, --env, --secret-env, --secret, \
             --command-timeout or --verify-timeout (or --clear to remove the update block)"
        );
    }

    // Parse everything before the read-modify-write, so a typo fails without
    // having touched the server.
    let auth = match &args.secret {
        Some(s) => Some(spec::parse_secret_ref(s)?),
        None => None,
    };
    let secret_env: Vec<Value> = args
        .secret_env
        .iter()
        .map(|s| spec::parse_secret_env(s))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut env = Map::new();
    for e in &args.env {
        match spec::parse_env(e)? {
            EnvChange::Set(k, v) => {
                env.insert(k, Value::String(v));
            }
            EnvChange::Remove(k) => bail!(
                "--env {k}- removes a variable, but --env replaces the whole set here; \
                 pass the variables you want to keep"
            ),
        }
    }

    edit_spec(ctx, &id, args.dry_run, "update commands set", |spec| {
        let update = spec::update_mut(spec, &id)?;
        if update.get("working_dir").and_then(Value::as_str).is_none()
            && args.working_dir.is_none()
        {
            bail!(
                "deployment {id:?} has no update block yet, so --workdir is required \
                 (the directory on the app-lb host where the commands run)"
            );
        }
        if update.get("commands").and_then(Value::as_array).is_none_or(|c| c.is_empty())
            && args.commands.is_empty()
        {
            bail!(
                "deployment {id:?} has no update commands yet, so at least one --command is \
                 required (e.g. -c 'git pull --ff-only' -c 'cargo build --release')"
            );
        }

        if let Some(dir) = &args.working_dir {
            update.insert("working_dir".into(), Value::String(dir.clone()));
        }
        if !args.commands.is_empty() {
            update.insert(
                "commands".into(),
                Value::Array(args.commands.iter().cloned().map(Value::String).collect()),
            );
        }
        if !args.env.is_empty() {
            update.insert("env".into(), Value::Object(env.clone()));
        }
        if !secret_env.is_empty() {
            update.insert("env_from".into(), Value::Array(secret_env.clone()));
        }
        if let Some(auth) = &auth {
            update.insert("auth".into(), auth.clone());
        }
        if args.no_auth {
            update.remove("auth");
        }
        if let Some(t) = args.timeout_secs {
            update.insert("timeout_secs".into(), Value::from(t));
        }
        if let Some(t) = args.verify_timeout_secs {
            update.insert("verify_timeout_secs".into(), Value::from(t));
        }
        Ok(())
    })
}

// -- set auth --------------------------------------------------------------

#[derive(Args, Debug)]
pub struct SetAuthArgs {
    /// The deployment to gate, e.g. `web` or `deployment/web`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,

    /// Inherit this deployment's identity from a namespace auth provider
    /// instead of writing it here: who may enter and how they are verified come
    /// from `heyctl get auth-providers`, and editing the provider reaches every
    /// deployment that names it.
    ///
    /// The provider must be declared in *this deployment's* namespace. Setting
    /// it clears any inline identity on the gate, because app-lb refuses a gate
    /// that carries both — everything route-scoped (public paths, base path,
    /// cookie name, session TTL) stays where it is.
    #[arg(long, value_name = "NAME", conflicts_with_all = [
        "client_id", "secret", "allow_domains", "allow_emails",
    ])]
    pub provider_ref: Option<String>,

    /// OAuth client id from the Google Cloud console. Required the first time.
    #[arg(long, value_name = "ID")]
    pub client_id: Option<String>,

    /// Stored secret holding the client secret: `NAME` or `NAME/KEY`.
    /// Required the first time.
    #[arg(long = "secret", value_name = "NAME[/KEY]")]
    pub secret: Option<String>,

    /// A Google Workspace domain whose accounts may enter. Repeatable; passing
    /// any replaces the list. `*` means any Google account.
    #[arg(long = "allow-domain", value_name = "DOMAIN")]
    pub allow_domains: Vec<String>,

    /// An individual address allowed regardless of domain. Repeatable; passing
    /// any replaces the list.
    #[arg(long = "allow-email", value_name = "EMAIL")]
    pub allow_emails: Vec<String>,

    /// A path prefix that bypasses sign-in, written with scope `admin` (an
    /// admin-tier app-token is still required). Use `heyctl edit` for scope
    /// `public`. Repeatable; passing any replaces the list.
    #[arg(long = "public-path", value_name = "PATH")]
    pub public_paths: Vec<String>,

    /// Where app-lb's sign-in endpoints live under this deployment's hostname.
    /// Defaults to `/__applb/auth`; set it under a path prefix if the deployment
    /// is routed by one.
    #[arg(long, value_name = "PATH")]
    pub base_path: Option<String>,

    /// How long a session lasts.
    #[arg(long = "session-ttl", value_name = "SECS")]
    pub session_ttl_secs: Option<u64>,

    /// Session cookie name.
    #[arg(long, value_name = "NAME")]
    pub cookie_name: Option<String>,

    /// Stop sending `x-auth-request-*` headers upstream.
    #[arg(long)]
    pub no_forward_identity: bool,

    /// Remove the gate; the deployment serves everyone again.
    #[arg(long, conflicts_with_all = [
        "provider_ref", "client_id", "secret", "allow_domains", "allow_emails",
        "public_paths", "base_path", "session_ttl_secs", "cookie_name",
        "no_forward_identity",
    ])]
    pub clear: bool,

    #[arg(long)]
    pub dry_run: bool,
}

pub fn set_auth(ctx: &Ctx, args: &SetAuthArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;

    if args.clear {
        return edit_spec(ctx, &id, args.dry_run, "sign-in gate removed", |spec| {
            if let Some(map) = spec.as_object_mut() {
                map.remove("auth");
            }
            Ok(())
        });
    }

    let touched = args.provider_ref.is_some()
        || args.client_id.is_some()
        || args.secret.is_some()
        || !args.allow_domains.is_empty()
        || !args.allow_emails.is_empty()
        || !args.public_paths.is_empty()
        || args.base_path.is_some()
        || args.session_ttl_secs.is_some()
        || args.cookie_name.is_some()
        || args.no_forward_identity;
    if !touched {
        bail!(
            "nothing to set — pass --provider-ref, --client-id, --secret, --allow-domain, \
             --allow-email, --public-path, --base-path, --session-ttl, --cookie-name or \
             --no-forward-identity (or --clear to remove the gate)"
        );
    }

    let secret = match &args.secret {
        Some(s) => Some(spec::parse_secret_ref(s)?),
        None => None,
    };

    edit_spec(ctx, &id, args.dry_run, "sign-in gate set", |spec| {
        let auth = spec::auth_mut(spec)?;
        let fresh = auth.is_empty();

        // Inheriting is the whole gate's identity, so it replaces whatever was
        // written inline rather than sitting beside it — app-lb refuses a gate
        // that carries both, and silently leaving a stale client id behind
        // would turn this command into a 400 nobody asked for.
        if let Some(name) = &args.provider_ref {
            auth.insert("provider_ref".into(), Value::String(name.clone()));
            for identity in [
                "provider",
                "client_id",
                "client_secret",
                "allowed_domains",
                "allowed_emails",
                "jwt",
                "cookie_domain",
            ] {
                auth.remove(identity);
            }
            // The route-scoped half below still applies, and a gate that
            // inherits needs none of the first-time identity checks.
            apply_route_scoped_auth(auth, args);
            return Ok(());
        }
        // Going the other way — writing identity onto a gate that inherited it —
        // has to drop the reference for the same reason.
        auth.remove("provider_ref");

        if fresh && (args.client_id.is_none() || secret.is_none()) {
            bail!(
                "deployment {id:?} has no sign-in gate yet, so --client-id and --secret are \
                 both required (store the client secret first: `heyctl create secret \
                 google --from-stdin client_secret`)"
            );
        }
        if fresh && args.allow_domains.is_empty() && args.allow_emails.is_empty() {
            bail!(
                "a new gate needs an allow-list: --allow-domain <workspace-domain> and/or \
                 --allow-email <address>. Use --allow-domain '*' to admit any Google account"
            );
        }

        if let Some(cid) = &args.client_id {
            auth.insert("client_id".into(), Value::String(cid.clone()));
        }
        if let Some(s) = &secret {
            auth.insert("client_secret".into(), s.clone());
        }
        for (key, values) in [
            ("allowed_domains", &args.allow_domains),
            ("allowed_emails", &args.allow_emails),
        ] {
            if !values.is_empty() {
                auth.insert(
                    key.to_string(),
                    Value::Array(values.iter().cloned().map(Value::String).collect()),
                );
            }
        }
        apply_route_scoped_auth(auth, args);
        Ok(())
    })
}

/// The half of a gate that is the deployment's own whether or not its identity
/// is inherited: which paths skip it, where its endpoints live, how long a
/// session lasts, and whether identity goes upstream.
fn apply_route_scoped_auth(auth: &mut Map<String, Value>, args: &SetAuthArgs) {
    if !args.public_paths.is_empty() {
        auth.insert(
            "public_paths".into(),
            Value::Array(args.public_paths.iter().cloned().map(Value::String).collect()),
        );
    }
    insert_opt_str(auth, "base_path", args.base_path.as_deref());
    insert_opt_str(auth, "cookie_name", args.cookie_name.as_deref());
    if let Some(ttl) = args.session_ttl_secs {
        auth.insert("session_ttl_secs".into(), Value::from(ttl));
    }
    if args.no_forward_identity {
        auth.insert("forward_identity".into(), Value::Bool(false));
    }
}

// -- auth providers --------------------------------------------------------

/// The identity half of a sign-in gate, declared once and inherited by name.
///
/// Three shapes, and the flags pick between them rather than a mode argument:
/// `--preset` materialises a known issuer's policy from a secret alone,
/// `--issuer` describes any other JWT issuer, and `--client-id` is Google.
#[derive(Args, Debug)]
#[command(group(
    clap::ArgGroup::new("identity")
        .args(["preset", "issuer", "client_id"])
        .required(true)
))]
pub struct CreateAuthProviderArgs {
    /// The provider's name, unique within its namespace. Deployments name it in
    /// `auth.provider_ref`, so keep it short: `heyo`, `corp-google`, `okta`.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// The namespace that owns it. A deployment may only inherit a provider in
    /// its own namespace. Omitted means `default`.
    #[arg(long, short = 'n', value_name = "NAMESPACE")]
    pub namespace: Option<String>,

    /// What this provider is for. Shown by `heyctl get auth-providers -o wide`.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,

    /// Build a known issuer's policy for you. Two exist:
    ///
    /// `heyo-jwks` — the Heyo auth API's gate tokens, verified `RS256` against
    /// its published key set. Needs no secret, and app-lb derives the key set
    /// URL from the auth service it federates to unless `--jwks-url` says
    /// otherwise. **Prefer this one**, and the more so the less you own of what
    /// the provider sits behind: nothing in it is secret, so it is safe in a
    /// namespace somebody else administers.
    ///
    /// `heyo` — the same service's `HS256` access tokens, from `--secret`. That
    /// key both verifies *and* mints, so whoever can read it can issue any
    /// identity the auth service can.
    ///
    /// The expansion happens on the server, so it is app-lb's idea of that
    /// issuer and not this build's. Any other flag here is applied on top of
    /// the result.
    #[arg(long, value_name = "NAME")]
    pub preset: Option<String>,

    /// The `iss` a token must carry, exactly. This is the bring-your-own form:
    /// with a key source it describes any issuer at all — your own service,
    /// Auth0, Okta, Cognito, Keycloak.
    #[arg(long, value_name = "ISSUER")]
    pub issuer: Option<String>,

    /// OAuth client id, for a Google provider.
    #[arg(long, value_name = "ID")]
    pub client_id: Option<String>,

    /// A stored secret, `NAME` or `NAME/KEY`: the HMAC signing key for an
    /// `HS*` JWT provider, or the OAuth client secret for Google. Resolved in
    /// this provider's namespace, never another's.
    #[arg(long = "secret", value_name = "NAME[/KEY]")]
    pub secret: Option<String>,

    /// The issuer's JWKS endpoint, usually `<issuer>/.well-known/jwks.json`.
    /// The right choice for any issuer that rotates keys — nothing has to be
    /// done here when it does.
    #[arg(long, value_name = "URL")]
    pub jwks_url: Option<String>,

    /// A PEM public key or certificate file, for an issuer that publishes one
    /// key rather than a set. Read here and sent inline: it is a public key, so
    /// it is not a secret and does not go in the store.
    #[arg(long, value_name = "PATH")]
    pub public_key_file: Option<PathBuf>,

    /// A signature algorithm this provider accepts. Repeatable. Defaults to
    /// `HS256` with `--secret` and `RS256` with a public key or JWKS — the
    /// token never chooses, because the token is attacker-controlled input.
    #[arg(long = "alg", value_name = "ALG")]
    pub algorithms: Vec<String>,

    /// The `aud` a token must carry. Omitted means the audience is not checked.
    #[arg(long, value_name = "AUDIENCE")]
    pub audience: Option<String>,

    /// A claim a token must satisfy: `CLAIM=VALUE`, or `CLAIM=A,B` for "any of
    /// these". Repeatable, and every one of them must hold. `true`/`false` are
    /// sent as booleans; everything else is a string, so an all-digits account
    /// id stays the id it is.
    ///
    /// This is a JWT provider's allow-list. With none, any unexpired token the
    /// issuer signed for this audience gets in — which for your own issuer
    /// means "a signed-in user", and is a reasonable thing to want.
    #[arg(long = "require", value_name = "CLAIM=VALUE")]
    pub require: Vec<String>,

    /// Which claim holds the stable user id forwarded as `x-auth-request-user`.
    /// `sub` unless the issuer says otherwise.
    #[arg(long, value_name = "CLAIM")]
    pub subject_claim: Option<String>,

    /// Which claim holds the address forwarded as `x-auth-request-email`.
    #[arg(long, value_name = "CLAIM")]
    pub email_claim: Option<String>,

    /// Which claim holds the display name.
    #[arg(long, value_name = "CLAIM")]
    pub name_claim: Option<String>,

    /// Clock skew allowed on `exp` and `nbf`.
    #[arg(long = "leeway", value_name = "SECS")]
    pub leeway_secs: Option<u64>,

    /// A cookie to read the token from when there is no `Authorization` header.
    /// What makes a JWT provider work for people in browsers at all — a
    /// navigation cannot carry a header.
    #[arg(long, value_name = "NAME")]
    pub cookie: Option<String>,

    /// Where to send a token-less browser to sign in. Your issuer's own page:
    /// app-lb redirects there with the URL the person wanted, that page sets
    /// the cookie above and sends them back. Requires --cookie.
    #[arg(long, value_name = "URL")]
    pub login_url: Option<String>,

    /// The query parameter that page reads the return URL from. `redirect_uri`
    /// unless set; `return_to`, `next` and `rd` are the other common spellings.
    #[arg(long, value_name = "NAME")]
    pub login_redirect_param: Option<String>,

    /// A Google Workspace domain whose accounts may enter. Repeatable. `*`
    /// means any Google account.
    #[arg(long = "allow-domain", value_name = "DOMAIN")]
    pub allow_domains: Vec<String>,

    /// An individual address allowed regardless of domain. Repeatable.
    #[arg(long = "allow-email", value_name = "EMAIL")]
    pub allow_emails: Vec<String>,

    /// Also admit app-tokens app-lb minted. The usual shape for a deployment
    /// with both a UI and a machine caller.
    #[arg(long)]
    pub app_token: bool,

    /// Share one sign-in across every gate that inherits this provider, by
    /// setting the session cookie on a parent domain, e.g. `.example.com`.
    #[arg(long, value_name = "DOMAIN")]
    pub cookie_domain: Option<String>,

    /// Print what would be sent, and send nothing. With `--preset` that is the
    /// first of two requests — the rest of the flags are applied to whatever
    /// the server expands, which only exists once it has answered.
    #[arg(long)]
    pub dry_run: bool,
}

/// `CLAIM=VALUE` / `CLAIM=A,B` into the `require` map's one entry.
fn parse_require(arg: &str) -> Result<(String, Value)> {
    let (claim, values) = arg
        .split_once('=')
        .with_context(|| format!("{arg:?} is not CLAIM=VALUE"))?;
    let claim = claim.trim();
    if claim.is_empty() {
        bail!("{arg:?} has an empty claim name");
    }
    let scalar = |v: &str| match v {
        // The two values a claim is genuinely likely to hold as a non-string.
        // Numbers are deliberately not converted: an account id that happens to
        // be all digits is a string in every token that carries one.
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        other => Value::String(other.to_string()),
    };
    let parts: Vec<&str> = values.split(',').map(str::trim).filter(|v| !v.is_empty()).collect();
    match parts.as_slice() {
        [] => bail!("{arg:?} has no value — write CLAIM=VALUE, or CLAIM=A,B for any of them"),
        [one] => Ok((claim.to_string(), scalar(one))),
        many => Ok((
            claim.to_string(),
            Value::Array(many.iter().map(|v| scalar(v)).collect()),
        )),
    }
}

impl CreateAuthProviderArgs {
    fn namespace(&self) -> &str {
        self.namespace.as_deref().unwrap_or(crate::DEFAULT_NAMESPACE)
    }

    /// The `jwt` block these flags describe, or `None` when they describe none.
    ///
    /// Not built for a `--preset`: the server owns that expansion, and the
    /// tweaks are applied to what it returns.
    fn jwt_block(&self) -> Result<Option<Map<String, Value>>> {
        let public_key = match &self.public_key_file {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading the public key {}", path.display()))?,
            ),
            None => None,
        };
        let key_sources = [
            ("--secret", self.secret.is_some()),
            ("--public-key-file", public_key.is_some()),
            ("--jwks-url", self.jwks_url.is_some()),
        ];
        let named: Vec<&str> = key_sources.iter().filter(|(_, set)| *set).map(|(n, _)| *n).collect();

        let Some(issuer) = &self.issuer else {
            return Ok(None);
        };
        match named.as_slice() {
            [] => bail!(
                "--issuer needs a key to verify with: --secret <NAME[/KEY]> for HS256, \
                 --jwks-url <URL> for an issuer that publishes a key set, or \
                 --public-key-file <PATH> for one static public key"
            ),
            [_] => {}
            many => bail!(
                "a JWT provider verifies with exactly one key — {} were given",
                many.join(", ")
            ),
        }
        if self.login_url.is_some() && self.cookie.is_none() {
            bail!(
                "--login-url needs --cookie: the trip back from a sign-in page is a \
                 navigation, and a navigation can only carry a token in a cookie"
            );
        }

        let mut jwt = Map::new();
        if let Some(s) = &self.secret {
            jwt.insert("secret".into(), spec::parse_secret_ref(s)?);
        }
        if let Some(pem) = public_key {
            jwt.insert("public_key".into(), Value::String(pem));
        }
        insert_opt_str(&mut jwt, "jwks_url", self.jwks_url.as_deref());
        // Defaulted by key kind rather than left to the server, which has no
        // default at all — an algorithm the spec did not choose is the
        // confusion attack this field exists to prevent.
        let algorithms: Vec<Value> = if self.algorithms.is_empty() {
            let default = if self.secret.is_some() { "HS256" } else { "RS256" };
            vec![Value::String(default.to_string())]
        } else {
            self.algorithms.iter().cloned().map(Value::String).collect()
        };
        jwt.insert("algorithms".into(), Value::Array(algorithms));
        jwt.insert("issuer".into(), Value::String(issuer.clone()));
        insert_opt_str(&mut jwt, "audience", self.audience.as_deref());
        self.apply_jwt_tweaks(&mut jwt)?;
        Ok(Some(jwt))
    }

    /// The fields that are the same whether the block was written by these
    /// flags or expanded from a preset. Applied to both, which is what lets
    /// `--preset heyo --require accountId=…` mean what it looks like.
    fn apply_jwt_tweaks(&self, jwt: &mut Map<String, Value>) -> Result<()> {
        if !self.require.is_empty() {
            let mut require = Map::new();
            for arg in &self.require {
                let (claim, value) = parse_require(arg)?;
                require.insert(claim, value);
            }
            jwt.insert("require".into(), Value::Object(require));
        }
        insert_opt_str(jwt, "subject_claim", self.subject_claim.as_deref());
        insert_opt_str(jwt, "email_claim", self.email_claim.as_deref());
        insert_opt_str(jwt, "name_claim", self.name_claim.as_deref());
        insert_opt_str(jwt, "cookie", self.cookie.as_deref());
        insert_opt_str(jwt, "login_url", self.login_url.as_deref());
        insert_opt_str(jwt, "login_redirect_param", self.login_redirect_param.as_deref());
        if let Some(secs) = self.leeway_secs {
            jwt.insert("leeway_secs".into(), Value::from(secs));
        }
        Ok(())
    }

    /// Whether a Google allow-list was written on a provider that will never
    /// run a Google flow. Refused rather than dropped: whoever wrote it
    /// believes the provider is restricted, and it would not be.
    fn misplaced_google_allow_list(&self) -> bool {
        (self.preset.is_some() || self.issuer.is_some())
            && self.client_id.is_none()
            && !(self.allow_domains.is_empty() && self.allow_emails.is_empty())
    }

    /// Whether any flag applies on top of a preset's expansion.
    fn tweaks_a_preset(&self) -> bool {
        !self.require.is_empty()
            || self.audience.is_some()
            || self.subject_claim.is_some()
            || self.email_claim.is_some()
            || self.name_claim.is_some()
            || self.cookie.is_some()
            || self.login_url.is_some()
            || self.login_redirect_param.is_some()
            || self.leeway_secs.is_some()
            || !self.algorithms.is_empty()
            || self.app_token
            || self.cookie_domain.is_some()
    }

    /// The providers this object admits, as the server spells them: a bare
    /// string for one, an array for several.
    fn providers(&self) -> Value {
        let mut kinds: Vec<&str> = Vec::new();
        if self.client_id.is_some() {
            kinds.push("google");
        }
        if self.issuer.is_some() || self.preset.is_some() {
            kinds.push("jwt");
        }
        if self.app_token {
            kinds.push("app-token");
        }
        match kinds.as_slice() {
            [one] => Value::String((*one).to_string()),
            many => Value::Array(many.iter().map(|k| Value::String((*k).to_string())).collect()),
        }
    }
}

pub fn create_auth_provider(ctx: &Ctx, args: &CreateAuthProviderArgs) -> Result<()> {
    let ns = args.namespace().to_string();

    let mut body = Map::new();
    body.insert("name".into(), Value::String(args.name.clone()));
    body.insert("namespace".into(), Value::String(ns.clone()));
    insert_opt_str(&mut body, "description", args.description.as_deref());
    insert_opt_str(&mut body, "cookie_domain", args.cookie_domain.as_deref());

    // These describe a *Google* identity and mean nothing to a JWT provider,
    // whose allow-list is `require`. app-lb refuses the combination; saying so
    // here names the flag to use instead, and stops a preset from quietly
    // dropping them.
    if args.misplaced_google_allow_list() {
        bail!(
            "--allow-domain/--allow-email describe a Google identity. A JWT provider's \
             allow-list is --require <claim>=<value>, e.g. --require accountId=acct_7f3c"
        );
    }

    if let Some(preset) = &args.preset {
        // The preset is the server's, so the body carries the request-only
        // `preset` plus whatever key material that preset takes, and nothing
        // that would collide with what it expands. Everything else is applied
        // in a second pass below.
        if args.public_key_file.is_some() {
            bail!("--preset brings its own key material; drop --public-key-file");
        }
        body.insert("preset".into(), Value::String(preset.clone()));
        match preset.as_str() {
            // Verifies against a published key set: no secret exists to name,
            // and the URL is optional because app-lb can derive it.
            "heyo-jwks" => {
                if args.secret.is_some() {
                    bail!(
                        "--preset heyo-jwks verifies against the issuer's published key set, \
                         so there is no secret to give it. (That is the point of it — use \
                         --preset heyo if you really want the HS256 shared-secret form.)"
                    );
                }
                if let Some(url) = &args.jwks_url {
                    body.insert("jwks_url".into(), Value::String(url.clone()));
                }
            }
            // Verifies with the issuer's own signing key, which has to be here.
            _ => {
                if args.jwks_url.is_some() {
                    bail!("--preset {preset} verifies with a shared secret; drop --jwks-url");
                }
                let Some(secret) = &args.secret else {
                    bail!(
                        "--preset {preset} needs the signing key it verifies with: \
                         --secret <NAME[/KEY]>, e.g. --secret heyo-auth/jwt_secret \
                         (store it first with `heyctl create secret heyo-auth --from-stdin \
                         jwt_secret`) — or use --preset heyo-jwks, which needs no secret"
                    );
                };
                body.insert("secret".into(), spec::parse_secret_ref(secret)?);
            }
        }
    } else {
        body.insert("provider".into(), args.providers());
        if let Some(jwt) = args.jwt_block()? {
            body.insert("jwt".into(), Value::Object(jwt));
        }
        if let Some(id) = &args.client_id {
            body.insert("client_id".into(), Value::String(id.clone()));
            let Some(secret) = &args.secret else {
                bail!(
                    "a Google provider needs its OAuth client secret: \
                     --secret <NAME[/KEY]> (store it first with \
                     `heyctl create secret google --from-stdin client_secret`)"
                );
            };
            body.insert("client_secret".into(), spec::parse_secret_ref(secret)?);
            if args.allow_domains.is_empty() && args.allow_emails.is_empty() {
                bail!(
                    "a Google provider needs an allow-list: --allow-domain <workspace-domain> \
                     and/or --allow-email <address>. Use --allow-domain '*' to admit any \
                     Google account"
                );
            }
        }
        for (key, values) in [
            ("allowed_domains", &args.allow_domains),
            ("allowed_emails", &args.allow_emails),
        ] {
            if !values.is_empty() {
                body.insert(
                    key.to_string(),
                    Value::Array(values.iter().cloned().map(Value::String).collect()),
                );
            }
        }
    }

    if args.dry_run {
        return print_spec(ctx, &Value::Object(body));
    }

    let existed = ctx.client.auth_provider_exists(&ns, &args.name).unwrap_or(false);
    let mut stored = ctx.client.create_auth_provider(&Value::Object(body))?;

    // A preset's tweaks are a second write against what the server expanded,
    // rather than a copy of the preset in this binary: the materialised object
    // comes back, the flags are applied to it, and it goes up again. `POST`
    // upserts and keeps the original `created_at`, so the result is one object
    // either way.
    if args.preset.is_some() && args.tweaks_a_preset() {
        // The server's own bytes, minus what these flags change — not a
        // re-serialised view, which would drop any field this build predates.
        let mut object = ctx
            .client
            .raw()
            .auth_provider(&ns, &args.name)?
            .as_object()
            .cloned()
            .context("app-lb returned an auth provider that is not an object")?;
        let mut jwt = object
            .get("jwt")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        args.apply_jwt_tweaks(&mut jwt)?;
        if !args.algorithms.is_empty() {
            jwt.insert(
                "algorithms".into(),
                Value::Array(args.algorithms.iter().cloned().map(Value::String).collect()),
            );
        }
        object.insert("jwt".into(), Value::Object(jwt));
        if args.app_token {
            object.insert("provider".into(), args.providers());
        }
        insert_opt_str(&mut object, "cookie_domain", args.cookie_domain.as_deref());
        stored = ctx.client.create_auth_provider(&Value::Object(object))?;
    }

    if ctx.out.is_machine() {
        let raw = ctx.client.raw().auth_provider(&ns, &args.name)?;
        return output::emit(&raw, ctx.out, &[format!("auth-provider/{ns}/{}", args.name)]);
    }
    println!(
        "auth-provider/{ns}/{} {} ({})",
        args.name,
        if existed { "replaced" } else { "created" },
        stored.providers().join(" or "),
    );
    println!(
        "\nInherit it: `heyctl set auth <deployment> --provider-ref {}` — the deployment \
         must be in namespace {ns}.",
        args.name
    );
    Ok(())
}

pub fn delete_auth_providers(ctx: &Ctx, names: &[String], namespace: Option<&str>) -> Result<()> {
    if names.is_empty() {
        bail!("delete needs a name, e.g. `heyctl delete auth-provider heyo -n team-a`");
    }
    let ns = namespace.unwrap_or(crate::DEFAULT_NAMESPACE);
    for name in names {
        ctx.client
            .delete_auth_provider(ns, name)
            .with_context(|| format!("deleting auth provider {name:?} in namespace {ns:?}"))?;
        println!("auth-provider/{ns}/{name} deleted");
    }
    Ok(())
}

// -- update ----------------------------------------------------------------

#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// The static deployment to update, e.g. `app-obs`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,

    /// Wait for the update to finish and report the outcome.
    #[arg(long, short = 'w')]
    pub wait: bool,

    /// Print the commands' output as it arrives. Implies --wait.
    #[arg(long)]
    pub logs: bool,

    #[arg(long, value_name = "SECS", default_value_t = 1800)]
    pub timeout: u64,
}

pub fn update(ctx: &Ctx, args: &UpdateArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;
    let started = ctx.client.raw().start_update(&id)?;

    if ctx.out.is_machine() && !(args.wait || args.logs) {
        let record: JobRecord = serde_json::from_value(started.clone()).unwrap_or_default();
        return output::emit(&started, ctx.out, &[format!("job/{}", record.id)]);
    }

    let record: JobRecord =
        serde_json::from_value(started).context("parsing the job the server started")?;
    if !ctx.out.is_machine() {
        println!(
            "job/{} started for deployment/{id} — {} command(s) in {}",
            record.id,
            record.commands_total.unwrap_or(0),
            record.working_dir.as_deref().unwrap_or("its working directory"),
        );
    }

    if !(args.wait || args.logs) {
        println!(
            "\nIt runs on the app-lb host. Follow it with `heyctl get job {}`.",
            record.id
        );
        return Ok(());
    }
    wait_job(ctx, &record.id, Duration::from_secs(args.timeout), args.logs)
}

// -- build -----------------------------------------------------------------

#[derive(Args, Debug)]
pub struct BuildArgs {
    /// The deployment to build, e.g. `web` or `deployment/web`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,

    /// Build this ref instead of the one in the spec. A one-off: the stored
    /// `build.ref` is left alone.
    #[arg(long = "ref", value_name = "REF")]
    pub git_ref: Option<String>,

    /// Wait for the build to finish and report the outcome.
    #[arg(long, short = 'w')]
    pub wait: bool,

    /// Print the build's output when it finishes. Implies --wait.
    #[arg(long)]
    pub logs: bool,

    #[arg(long, value_name = "SECS", default_value_t = 1800)]
    pub timeout: u64,
}

pub fn build(ctx: &Ctx, args: &BuildArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;

    let started = ctx.client.raw().start_build(&id, args.git_ref.as_deref())?;

    if ctx.out.is_machine() && !(args.wait || args.logs) {
        let record: JobRecord = serde_json::from_value(started.clone()).unwrap_or_default();
        return output::emit(&started, ctx.out, &[format!("job/{}", record.id)]);
    }

    let record: JobRecord =
        serde_json::from_value(started).context("parsing the job the server started")?;
    if !ctx.out.is_machine() {
        println!(
            "job/{} started for deployment/{id} — {}",
            record.id,
            record.git_ref.as_deref().unwrap_or("(default branch)")
        );
    }

    if !(args.wait || args.logs) {
        println!(
            "\nIt runs on the app-lb host and takes as long as `docker build` does. \
             Follow it with `heyctl get job {}`.",
            record.id
        );
        return Ok(());
    }
    wait_job(ctx, &record.id, Duration::from_secs(args.timeout), args.logs)
}

/// Poll one job — build or update — to completion.
fn wait_job(ctx: &Ctx, job_id: &str, timeout: Duration, show_logs: bool) -> Result<()> {
    let started = Instant::now();
    let mut last_lines = 0usize;
    loop {
        let raw = ctx.client.raw().job(job_id)?;
        let record: JobRecord =
            serde_json::from_value(raw.clone()).context("parsing the job record")?;

        // Stream whatever is new since the last poll, so a long `docker build`
        // or `cargo build` shows progress rather than a cursor.
        if show_logs && record.log.len() > last_lines {
            for line in &record.log[last_lines..] {
                println!("  {line}");
            }
            last_lines = record.log.len();
        }

        if !record.is_running() {
            if ctx.out.is_machine() {
                return output::emit(&raw, ctx.out, &[format!("job/{job_id}")]);
            }
            // With --logs the output is already on screen; reprinting the tail
            // would show every line twice for a job that failed fast.
            return report_job(&record, !show_logs);
        }
        if started.elapsed() >= timeout {
            bail!(
                "timed out after {}s waiting for job/{job_id}; it is still running on the \
                 server — check it with `heyctl get job {job_id}`",
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn report_job(record: &JobRecord, show_tail: bool) -> Result<()> {
    if record.succeeded() {
        if record.is_update() {
            println!(
                "job/{} succeeded — {} ran in {}{}",
                record.id,
                record.result_summary(),
                record.working_dir.as_deref().unwrap_or("its working directory"),
                match record.verified {
                    Some(true) => "; the upstreams are answering again",
                    // The server fails a job whose upstreams never came back, so
                    // this is the verification-disabled case.
                    _ => "; the upstreams were not re-checked",
                }
            );
            return Ok(());
        }
        let rolled = if record.rolled_out {
            "; the pool is recycling onto it"
        } else {
            "; the deployment was NOT updated"
        };
        if record.is_pull() {
            println!(
                "job/{} succeeded — image {} from digest {} ({}){}",
                record.id,
                record.image.as_deref().unwrap_or("?"),
                record.short_digest(),
                match (record.bytes, record.reused) {
                    (_, true) => "already on the host".to_string(),
                    (Some(n), false) => format!("{} transferred", output::bytes(n)),
                    (None, false) => "transferred".to_string(),
                },
                rolled,
            );
        } else {
            println!(
                "job/{} succeeded — image {} from commit {}{}",
                record.id,
                record.image.as_deref().unwrap_or("?"),
                record.short_commit(),
                rolled,
            );
        }
        println!(
            "\nWatch the replacements with `heyctl rollout status {}`.",
            record.deployment
        );
        return Ok(());
    }

    // A failure ends the command non-zero, and the last few log lines are what
    // says why, so print them even without --logs.
    if show_tail {
        for line in record.log.iter().rev().take(15).collect::<Vec<_>>().into_iter().rev() {
            eprintln!("  {line}");
        }
    }
    bail!(
        "job/{} failed: {}",
        record.id,
        record.error.as_deref().unwrap_or("no reason reported")
    )
}

// -- apply -----------------------------------------------------------------

#[derive(Args, Debug)]
pub struct ApplyArgs {
    /// A spec file (JSON or YAML), or `-` for stdin. Repeatable; a file may
    /// hold one spec, a JSON array, or a multi-document YAML stream.
    #[arg(long, short = 'f', value_name = "FILE", required = true)]
    pub filename: Vec<PathBuf>,

    /// Print what would be sent, and send nothing.
    #[arg(long)]
    pub dry_run: bool,
}

pub fn apply(ctx: &Ctx, args: &ApplyArgs) -> Result<()> {
    let mut specs = Vec::new();
    for path in &args.filename {
        specs.extend(spec::read_specs(path)?);
    }

    for s in &specs {
        // `kind` decides what an object is, and its absence means "deployment".
        // Defaulting that way rather than requiring the field is what keeps
        // every spec file written before namespaces existed working untouched —
        // there are a lot of them, and none of them say `kind: deployment`.
        let kind = s.get("kind").and_then(Value::as_str).unwrap_or("deployment");
        if kind == "namespace" || kind == "Namespace" {
            apply_namespace(ctx, s, args.dry_run)?;
            continue;
        }
        if kind == "auth-provider" || kind == "AuthProvider" || kind == "authProvider" {
            apply_auth_provider(ctx, s, args.dry_run)?;
            continue;
        }
        if kind != "deployment" && kind != "Deployment" {
            bail!(
                "unknown kind {kind:?} — `apply` understands \"deployment\", \"namespace\" \
                 and \"auth-provider\", and an object with no `kind` is a deployment"
            );
        }
        let id = spec::spec_id(s)
            .context("a spec in the input has no `id` field")?
            .to_string();
        if args.dry_run {
            print_spec(ctx, s)?;
            continue;
        }
        // Create-or-replace, decided by what is already registered. POST would
        // also work for both (it upserts), but it tears the pool down on every
        // apply; PUT keeps VMs alive when only scaling or routing changed.
        let existed = ctx.client.deployment_exists(&id)?;
        let result = if existed {
            ctx.client.raw().replace_deployment(&id, s)?
        } else {
            ctx.client.raw().create_deployment(s)?
        };
        report_write(ctx, &result, &id, if existed { "configured" } else { "created" })?;
    }
    Ok(())
}

/// One `kind: namespace` object from an `apply` input.
///
/// `POST /namespaces` is already an upsert that keeps the original `created_at`,
/// so unlike a deployment there is no create-or-replace decision to make here
/// and nothing to look up first.
fn apply_namespace(ctx: &Ctx, spec: &Value, dry_run: bool) -> Result<()> {
    let name = spec
        .get("name")
        .and_then(Value::as_str)
        .context("a `kind: namespace` object needs a `name`")?
        .to_string();
    if dry_run {
        return print_spec(ctx, spec);
    }
    // `kind` is heyctl's own dispatch key, not part of app-lb's object, so it
    // is stripped rather than sent — the server would reject the unknown field
    // or, worse, quietly keep it in the stored spec.
    let mut body = spec.clone();
    if let Some(o) = body.as_object_mut() {
        o.remove("kind");
    }
    let applied = ctx.client.create_namespace(&body)?;
    if ctx.out.is_machine() {
        return output::emit(&applied, ctx.out, &[format!("namespace/{name}")]);
    }
    println!("namespace/{name} configured");
    Ok(())
}

/// One `kind: auth-provider` object from an `apply` input.
///
/// Like a namespace and unlike a deployment, `POST` is already the upsert —
/// re-declaring keeps the original `created_at` — so there is nothing to look
/// up first. The body may carry the request-only `preset`/`secret` pair, which
/// the server expands and never stores, so a file can say "the Heyo auth API,
/// with this key" in three lines.
fn apply_auth_provider(ctx: &Ctx, spec: &Value, dry_run: bool) -> Result<()> {
    let name = spec
        .get("name")
        .and_then(Value::as_str)
        .context("a `kind: auth-provider` object needs a `name`")?
        .to_string();
    let ns = spec
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or(crate::DEFAULT_NAMESPACE)
        .to_string();
    if dry_run {
        return print_spec(ctx, spec);
    }
    // `kind` is heyctl's dispatch key, not part of app-lb's object.
    let mut body = spec.clone();
    if let Some(o) = body.as_object_mut() {
        o.remove("kind");
    }
    ctx.client.create_auth_provider(&body)?;
    if ctx.out.is_machine() {
        let raw = ctx.client.raw().auth_provider(&ns, &name)?;
        return output::emit(&raw, ctx.out, &[format!("auth-provider/{ns}/{name}")]);
    }
    println!("auth-provider/{ns}/{name} configured");
    Ok(())
}

// -- edit ------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct EditArgs {
    /// The deployment to edit, e.g. `web` or `deployment/web`.
    #[arg(value_name = "RESOURCE", required = true)]
    pub args: Vec<String>,
}

pub fn edit(ctx: &Ctx, args: &EditArgs) -> Result<()> {
    let (kind, names) = parse_ref(&args.args, Some(Resource::Deployment))?;
    if kind != Resource::Deployment {
        bail!("edit only works on deployments");
    }
    let [id] = names.as_slice() else {
        bail!("edit takes exactly one deployment");
    };

    let current = spec::spec_of(&ctx.client.raw().deployment(id)?)?;
    let header = format!(
        "# Editing deployment {id:?} on {}.\n\
         # Save an unchanged file (or an empty one) to cancel.\n\
         # The pool is preserved unless the `vm` block or `upstreams` change.\n",
        ctx.endpoint.server
    );
    let original = format!("{header}{}", serde_yaml::to_string(&current)?);

    let path = std::env::temp_dir().join(format!(
        "heyctl-{}-{}.yaml",
        sanitize(id),
        std::process::id()
    ));
    std::fs::write(&path, &original).with_context(|| format!("writing {}", path.display()))?;

    let edited = run_editor(&path).inspect_err(|_| {
        let _ = std::fs::remove_file(&path);
    })?;

    if edited == original || edited.lines().all(|l| l.trim().is_empty() || l.starts_with('#')) {
        std::fs::remove_file(&path).ok();
        println!("Edit cancelled, no changes made.");
        return Ok(());
    }

    let new_spec: Value = serde_yaml::from_str(&edited)
        .with_context(|| format!("the edited spec is not valid YAML/JSON; it is kept at {}", path.display()))?;

    match ctx.client.raw().replace_deployment(id, &new_spec) {
        Ok(result) => {
            std::fs::remove_file(&path).ok();
            report_write(ctx, &result, id, "edited")
        }
        // Keep the buffer on rejection: retyping a spec because the server said
        // "min_replicas exceeds max_replicas" would be a poor trade.
        Err(e) => Err(e).with_context(|| format!("your edit is kept at {}", path.display())),
    }
}

fn run_editor(path: &std::path::Path) -> Result<String> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());
    // Through a shell, so EDITOR="code -w" and friends keep working. The path
    // goes in as $1 rather than being interpolated, so a space in $TMPDIR
    // doesn't split into two filenames.
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(path)
        .status()
        .with_context(|| format!("launching the editor ({editor})"))?;
    if !status.success() {
        bail!("the editor ({editor}) exited with {status}");
    }
    std::fs::read_to_string(path).with_context(|| format!("reading back {}", path.display()))
}

fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
        .collect()
}

// -- set -------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct SetImageArgs {
    /// The deployment, e.g. `web` or `deployment/web`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,
    /// The new guest image.
    #[arg(value_name = "IMAGE")]
    pub image: String,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct SetEnvArgs {
    #[arg(value_name = "RESOURCE")]
    pub resource: String,
    /// `KEY=VALUE` to set, `KEY-` to remove. Repeatable.
    #[arg(value_name = "KEY=VALUE", required = true)]
    pub changes: Vec<String>,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct SetUpstreamsArgs {
    #[arg(value_name = "RESOURCE")]
    pub resource: String,
    /// The full new upstream list, as `host:port` addresses.
    #[arg(value_name = "ADDR", required = true)]
    pub upstreams: Vec<String>,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct SetRouteArgs {
    #[arg(value_name = "RESOURCE")]
    pub resource: String,
    /// Exact hostname to route.
    #[arg(long, value_name = "HOST")]
    pub host: Option<String>,
    /// Subdomain match: the apex and any subdomain of it.
    #[arg(long, value_name = "DOMAIN")]
    pub host_suffix: Option<String>,
    /// Path prefix to route.
    #[arg(long, value_name = "PATH")]
    pub path_prefix: Option<String>,
    /// A rule in `host=…,path=…` form. Repeatable.
    #[arg(long = "route", value_name = "RULE")]
    pub routes: Vec<String>,
    /// Keep the existing rules and add these, instead of replacing them.
    #[arg(long)]
    pub add: bool,
    /// Remove every route, withdrawing the deployment from the proxy. The
    /// counterpart to `create --no-route`: an exposed sandbox goes back to
    /// being reachable only by exec/shell, without being torn down. Managed
    /// (VM) deployments only.
    #[arg(long, conflicts_with_all = ["host", "host_suffix", "path_prefix", "routes", "add"])]
    pub none: bool,
    #[arg(long)]
    pub dry_run: bool,
}

pub fn set_image(ctx: &Ctx, args: &SetImageArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;
    // A new image means new VMs: app-lb rebuilds the pool when the `vm` block
    // changes, so this is the closest thing to a rolling deploy.
    edit_spec(ctx, &id, args.dry_run, "image updated", |spec| {
        let vm = spec::vm_mut(spec, &id)?;
        vm.insert("image".into(), Value::String(args.image.clone()));
        Ok(())
    })
}

pub fn set_env(ctx: &Ctx, args: &SetEnvArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;
    let changes: Vec<EnvChange> = args
        .changes
        .iter()
        .map(|c| spec::parse_env(c))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    edit_spec(ctx, &id, args.dry_run, "env updated", |spec| {
        spec::apply_env(spec, &id, &changes)?;
        Ok(())
    })
}

pub fn set_upstreams(ctx: &Ctx, args: &SetUpstreamsArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;
    edit_spec(ctx, &id, args.dry_run, "upstreams updated", |spec| {
        if !spec::is_static(spec) {
            let what = if spec::is_site(spec) {
                "a static site, which serves files off disk"
            } else {
                "a managed VM pool, whose backends come from the `vm` template"
            };
            bail!("deployment {id:?} is {what} — it has no upstream list to set");
        }
        spec["upstreams"] = Value::Array(args.upstreams.iter().cloned().map(Value::String).collect());
        Ok(())
    })
}

pub fn set_route(ctx: &Ctx, args: &SetRouteArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;
    let mut rules = Vec::new();
    if let Some(rule) = spec::route_from_parts(
        args.host.as_deref(),
        args.host_suffix.as_deref(),
        args.path_prefix.as_deref(),
    ) {
        rules.push(rule);
    }
    for r in &args.routes {
        rules.push(spec::parse_route(r)?);
    }
    if rules.is_empty() && !args.none {
        bail!(
            "nothing to set — pass --host, --host-suffix, --path-prefix or --route, \
             or --none to withdraw the deployment from the proxy"
        );
    }

    let message = if args.none { "routes cleared" } else { "routes updated" };
    edit_spec(ctx, &id, args.dry_run, message, |spec| {
        if args.none && (spec::is_static(spec) || spec::is_site(spec)) {
            let kind = if spec::is_site(spec) { "a static site" } else { "a static (proxy_pass) one" };
            bail!(
                "deployment {id:?} is {kind}, and the proxy is the only way to reach it \
                 — clearing its routes would leave it unreachable"
            );
        }
        let existing = spec
            .get("routes")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut next = if args.add { existing } else { Vec::new() };
        for rule in &rules {
            if !next.contains(rule) {
                next.push(rule.clone());
            }
        }
        spec["routes"] = Value::Array(next);
        Ok(())
    })
}

/// Read-modify-write one deployment's spec.
fn edit_spec(
    ctx: &Ctx,
    id: &str,
    dry_run: bool,
    verb: &str,
    mutate: impl FnOnce(&mut Value) -> Result<()>,
) -> Result<()> {
    let mut spec = spec::spec_of(&ctx.client.raw().deployment(id)?)?;
    mutate(&mut spec)?;
    if dry_run {
        return print_spec(ctx, &spec);
    }
    let result = ctx.client.raw().replace_deployment(id, &spec)?;
    report_write(ctx, &result, id, verb)
}

// -- scale -----------------------------------------------------------------

#[derive(Args, Debug)]
pub struct ScaleArgs {
    /// The deployment to scale, e.g. `web` or `deployment/web`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,

    /// Pin the pool to exactly N replicas (sets both min and max). Without it,
    /// the autoscaler keeps deciding within the min/max band.
    #[arg(long, short = 'r', value_name = "N", conflicts_with_all = ["min", "max"])]
    pub replicas: Option<u64>,

    #[command(flatten)]
    pub scaling: ScalingFlags,
}

pub fn scale(ctx: &Ctx, args: &ScaleArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;
    let mut patch = args.scaling.patch();
    if let Some(n) = args.replicas {
        patch.insert("min_replicas".into(), Value::from(n));
        patch.insert("max_replicas".into(), Value::from(n));
    }
    if patch.is_empty() {
        bail!(
            "nothing to change — pass --replicas, or one of --min/--max/--warm/\
             --target-concurrency/--scale-to-zero-after/--cold-start-timeout/--drain-timeout/\
             --boot-timeout/--idle-action"
        );
    }

    let result = ctx.client.raw().patch_scaling(&id, &Value::Object(patch))?;
    if ctx.out.is_machine() {
        return output::emit(&result, ctx.out, &[format!("deployment/{id}")]);
    }
    let status: DeploymentStatus = serde_json::from_value(result)?;
    println!(
        "deployment/{id} scaled — desired {} (min {}, max {}, warm {}, target {} in-flight/VM), \
         {} ready, {} pending",
        status.desired_replicas,
        status.spec.scaling.min_replicas,
        status.spec.scaling.max_replicas,
        status.spec.scaling.warm_pool,
        status.spec.scaling.target_concurrency,
        status.ready,
        status.pending,
    );
    Ok(())
}

// -- static-upstream traffic control --------------------------------------

#[derive(Args, Debug)]
pub struct CordonArgs {
    /// The static deployment, e.g. `stage` or `deployment/stage`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,
    /// The exact `host:port` entry to stop sending new requests to.
    #[arg(value_name = "UPSTREAM")]
    pub upstream: String,
    /// Allow cordoning when no other healthy, accepting upstream remains.
    #[arg(long)]
    pub force: bool,
    /// Why this upstream is being withdrawn. Stored with the durable drain.
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,
}

#[derive(Args, Debug)]
pub struct DrainArgs {
    #[command(flatten)]
    pub cordon: CordonArgs,
    /// Give up waiting after this long. The upstream remains cordoned on timeout.
    #[arg(long, value_name = "SECS", default_value_t = 300)]
    pub timeout: u64,
}

#[derive(Args, Debug)]
pub struct UncordonArgs {
    /// The static deployment, e.g. `stage` or `deployment/stage`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,
    /// The exact `host:port` entry to return to traffic when healthy.
    #[arg(value_name = "UPSTREAM")]
    pub upstream: String,
}

fn emit_upstream_status(ctx: &Ctx, status: &UpstreamTrafficStatus) -> Result<()> {
    output::emit(
        &serde_json::to_value(status)?,
        ctx.out,
        &[format!("upstream/{}", status.upstream)],
    )
}

pub fn cordon(ctx: &Ctx, args: &CordonArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;
    let status = ctx.client.cordon_upstream(
        &id,
        &args.upstream,
        args.force,
        args.reason.as_deref(),
    )?;
    if ctx.out.is_machine() {
        return emit_upstream_status(ctx, &status);
    }
    println!(
        "upstream/{} cordoned in deployment/{id} — {} request(s) still in flight{}",
        status.upstream,
        status.in_flight,
        status
            .reason
            .as_deref()
            .map(|reason| format!(" ({reason})"))
            .unwrap_or_default(),
    );
    if status.in_flight > 0 {
        println!(
            "Wait for completion with `heyctl drain {id} {}`.",
            status.upstream
        );
    }
    Ok(())
}

pub fn drain(ctx: &Ctx, args: &DrainArgs) -> Result<()> {
    let id = deployment_name(&args.cordon.resource)?;
    let mut outcome = ctx.client.cordon_upstream(
        &id,
        &args.cordon.upstream,
        args.cordon.force,
        args.cordon.reason.as_deref(),
    )?;
    if !ctx.out.is_machine() {
        println!(
            "upstream/{} cordoned in deployment/{id}; waiting for {} in-flight request(s).",
            outcome.upstream, outcome.in_flight
        );
    }

    let started = Instant::now();
    let timeout = Duration::from_secs(args.timeout);
    let mut last = outcome.in_flight;
    loop {
        if outcome.in_flight == 0 {
            outcome.state = "drained".into();
            if ctx.out.is_machine() {
                return emit_upstream_status(ctx, &outcome);
            }
            println!(
                "upstream/{} drained — no requests remain in flight.",
                outcome.upstream
            );
            return Ok(());
        }
        if started.elapsed() >= timeout {
            bail!(
                "timed out after {}s waiting for upstream {:?} to drain; it remains cordoned. \
                 Inspect it with `heyctl get vms -d {id}` or restore it with \
                 `heyctl uncordon {id} {}`",
                timeout.as_secs(),
                args.cordon.upstream,
                args.cordon.upstream,
            );
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        std::thread::sleep(Duration::from_secs(1).min(remaining));
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            bail!(
                "timed out after {}s waiting for upstream {:?} to drain; it remains cordoned. \
                 Restore it with `heyctl uncordon {id} {}`",
                timeout.as_secs(),
                args.cordon.upstream,
                args.cordon.upstream,
            );
        }

        let deployment = ctx.client.deployment_with_timeout(&id, remaining)?;
        let upstreams: Vec<_> = deployment
            .vms
            .iter()
            .filter(|backend| backend.addr == args.cordon.upstream)
            .collect();
        if upstreams.is_empty() {
            bail!(
                "upstream {:?} disappeared from deployment/{id} while draining",
                args.cordon.upstream,
            );
        }
        if upstreams.iter().any(|upstream| !upstream.draining) {
            bail!(
                "upstream {:?} became uncordoned before its drain completed",
                args.cordon.upstream,
            );
        }
        outcome.in_flight = upstreams.iter().map(|upstream| upstream.in_flight).sum();
        if !ctx.out.is_machine() && outcome.in_flight != last {
            println!("{} request(s) still in flight.", outcome.in_flight);
            last = outcome.in_flight;
        }
    }
}

pub fn uncordon(ctx: &Ctx, args: &UncordonArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;
    let status = ctx.client.uncordon_upstream(&id, &args.upstream)?;
    if ctx.out.is_machine() {
        return emit_upstream_status(ctx, &status);
    }
    println!(
        "upstream/{} uncordoned in deployment/{id} — {}",
        status.upstream,
        if status.healthy {
            "accepting traffic"
        } else {
            "administratively accepting, but still excluded by its health probe"
        },
    );
    Ok(())
}

// -- restart / rollout status ---------------------------------------------

#[derive(Args, Debug)]
pub struct RestartArgs {
    /// The deployment to recycle, e.g. `web` or `deployment/web`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,
    /// Kill VMs immediately, dropping in-flight requests, instead of draining.
    #[arg(long)]
    pub force: bool,
    /// Wait until the replacement pool is ready.
    #[arg(long)]
    pub wait: bool,
    #[arg(long, value_name = "SECS", default_value_t = 300)]
    pub timeout: u64,
}

pub fn restart(ctx: &Ctx, args: &RestartArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;
    let status: DeploymentStatus = serde_json::from_value(ctx.client.raw().deployment(&id)?)?;

    if status.spec.is_static() {
        bail!(
            "deployment {id:?} is static (proxy_pass) — it has no VMs to recycle. \
             Restart the upstream itself; app-lb re-probes it every tick and it rejoins."
        );
    }
    if status.vms.is_empty() {
        println!("deployment/{id} has no running VMs — nothing to restart.");
        return Ok(());
    }

    // Evicting is per-VM: there is no rollout object server-side. The autoscaler
    // boots replacements on its next tick, so this is a recycle, not a shrink.
    println!(
        "Recycling {} VM(s) of deployment/{id} ({}).",
        status.vms.len(),
        if args.force { "killing now" } else { "draining" }
    );
    let mut table = Table::new(["SANDBOX", "OUTCOME"]);
    for vm in &status.vms {
        let result = ctx.client.raw().evict_vm(&id, &vm.sandbox_id, args.force)?;
        let outcome = result
            .get("outcome")
            .and_then(Value::as_str)
            .unwrap_or("requested")
            .to_string();
        table.row([vm.sandbox_id.clone(), outcome]);
    }
    table.print();

    if args.wait {
        println!();
        return wait_ready(ctx, &id, Duration::from_secs(args.timeout));
    }
    println!("\nWatch the replacements with `heyctl rollout status {id}`.");
    Ok(())
}

#[derive(Args, Debug)]
pub struct RolloutStatusArgs {
    /// The deployment to watch, e.g. `web` or `deployment/web`.
    #[arg(value_name = "RESOURCE")]
    pub resource: String,
    /// Give up after this long.
    #[arg(long, value_name = "SECS", default_value_t = 300)]
    pub timeout: u64,
    /// Print the current state once and exit.
    #[arg(long)]
    pub no_wait: bool,
}

pub fn rollout_status(ctx: &Ctx, args: &RolloutStatusArgs) -> Result<()> {
    let id = deployment_name(&args.resource)?;
    if args.no_wait {
        let status: DeploymentStatus = serde_json::from_value(ctx.client.raw().deployment(&id)?)?;
        println!("{}", describe_progress(&status));
        return Ok(());
    }
    wait_ready(ctx, &id, Duration::from_secs(args.timeout))
}

/// Poll until the pool matches its desired size with every VM healthy.
fn wait_ready(ctx: &Ctx, id: &str, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    let mut last = String::new();
    loop {
        let status: DeploymentStatus = serde_json::from_value(ctx.client.raw().deployment(id)?)?;
        let line = describe_progress(&status);
        if line != last {
            println!("{line}");
            last = line;
        }

        let healthy = status.vms.iter().filter(|v| v.healthy && !v.draining).count();
        if status.pending == 0
            && healthy >= status.desired_replicas as usize
            && !status.vms.iter().any(|v| v.draining)
        {
            println!("deployment/{id} is ready.");
            return Ok(());
        }
        if started.elapsed() >= timeout {
            bail!(
                "timed out after {}s waiting for deployment/{id} — \
                 `heyctl describe deployment {id}` shows where it is stuck",
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn describe_progress(s: &DeploymentStatus) -> String {
    let healthy = s.vms.iter().filter(|v| v.healthy && !v.draining).count();
    let draining = s.vms.iter().filter(|v| v.draining).count();
    format!(
        "Waiting for deployment/{}: {healthy}/{} ready, {} pending, {draining} draining",
        s.spec.id, s.desired_replicas, s.pending
    )
}

// -- delete ----------------------------------------------------------------

#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// What to delete: `deployment web`, `deployment/web`, or
    /// `vm <sandbox-id> --deployment web`.
    #[arg(value_name = "RESOURCE", required = true)]
    pub args: Vec<String>,

    /// The deployment a VM belongs to (required when deleting VMs).
    #[arg(long, short = 'd', value_name = "NAME")]
    pub deployment: Option<String>,

    /// The namespace an auth provider lives in. A provider is unique within
    /// its namespace, not across the fleet, so this is how one is named.
    #[arg(long, short = 'n', value_name = "NAMESPACE")]
    pub namespace: Option<String>,

    /// Delete every deployment, or every VM of --deployment.
    #[arg(long)]
    pub all: bool,

    /// For VMs: kill immediately, dropping in-flight requests, instead of
    /// draining.
    #[arg(long)]
    pub force: bool,

    /// Skip the confirmation prompt for destructive bulk deletes.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

pub fn delete(ctx: &Ctx, args: &DeleteArgs) -> Result<()> {
    let (kind, names) = parse_ref(&args.args, None)?;
    match kind {
        Resource::Deployment => delete_deployments(ctx, &names, args),
        Resource::Vm => delete_vms(ctx, &names, args),
        Resource::Secret => delete_secrets(ctx, &names, args),
        Resource::Workflow => delete_workflows(ctx, &names, args),
        Resource::Cert => bail!(
            "certificates are managed by app-lb's ACME loop and cannot be deleted through \
             the API; remove them from APP_LB_ACME_DIR on the host instead"
        ),
        Resource::Job => bail!(
            "jobs are a record of something that already happened and cannot be deleted; \
             the server keeps the most recent ones and forgets the rest"
        ),
        // Reading the inventory is `get disks`; reclaiming from it is not wired
        // up here on purpose. `DELETE /disks/:id` removes gigabytes with no
        // undo — app-lb's own routing calls it the single most destructive route
        // it exposes — so it wants its own command with its own confirmation,
        // not a arm of the generic `delete` that `--all` also flows through.
        Resource::Disk => bail!(
            "disks are not deleted through `delete` — `get disks` shows what is on the host \
             and why each one is held; reclaiming is `DELETE /disks/<sandbox>` or \
             `POST /disks/sweep` on the admin API, which delete gigabytes with no undo"
        ),
        Resource::Namespace => delete_namespaces(ctx, &names),
        Resource::AuthProvider => delete_auth_providers(ctx, &names, args.namespace.as_deref()),
        Resource::All => bail!("`delete all` is not supported — name the deployments, or use --all"),
    }
}

#[derive(Args, Debug)]
pub struct CreateWorkflowArgs {
    /// Workflow id. Becomes a NATS subject token and part of a VM name, so it
    /// is restricted to letters, digits, `-` and `_`.
    pub id: String,

    /// Clone URL of the repository this workflow builds.
    #[arg(long)]
    pub repo: String,

    /// The heyvm network whose hosts may run it.
    #[arg(long)]
    pub network: String,

    /// Branch or ref.
    #[arg(long = "ref", default_value = "main")]
    pub git_ref: String,

    /// Glob for workflow files inside the repository.
    #[arg(long, default_value = ".ci/workflows/*.yml")]
    pub path: String,

    /// heyosecret prefix override. Defaults to `ci/<id>` in the orchestrator.
    #[arg(long)]
    pub secrets_prefix: Option<String>,

    /// Register it but do not run it yet.
    #[arg(long)]
    pub disabled: bool,
}

pub fn create_workflow(ctx: &Ctx, args: &CreateWorkflowArgs) -> Result<()> {
    let mut spec = serde_json::json!({
        "id": args.id,
        "repo": args.repo,
        "ref": args.git_ref,
        "path": args.path,
        "network": args.network,
        "enabled": !args.disabled,
    });
    // Only sent when given, so the server's own default is what fills it in —
    // one place decides the default rather than two that can disagree.
    if let Some(prefix) = &args.secrets_prefix {
        spec["secrets_prefix"] = Value::String(prefix.clone());
    }

    let created = ctx
        .client
        .create_workflow(&spec)
        .with_context(|| format!("creating workflow {:?}", args.id))?;

    println!(
        "workflow/{} created ({} on {}, {} → {})",
        created.id, created.git_ref, created.repo, created.path, created.network
    );
    if !created.enabled {
        println!("It is disabled; `heyctl set workflow {} --enabled` turns it on.", created.id);
    }
    Ok(())
}

fn delete_workflows(ctx: &Ctx, names: &[String], args: &DeleteArgs) -> Result<()> {
    let targets: Vec<String> = if args.all {
        ctx.client.workflows()?.into_iter().map(|w| w.id).collect()
    } else {
        if names.is_empty() {
            bail!("delete workflow needs a name, or --all");
        }
        names.to_vec()
    };
    if targets.is_empty() {
        println!("No CI workflows to delete.");
        return Ok(());
    }
    // Deleting a workflow stops a repository being built, which is the kind of
    // change somebody notices a week later. Same confirmation the other bulk
    // deletes use.
    if args.all && !args.yes {
        confirm(&format!("Delete {} workflow(s)?", targets.len()))?;
    }
    for id in &targets {
        ctx.client
            .delete_workflow(id)
            .with_context(|| format!("deleting workflow {id:?}"))?;
        println!("workflow/{id} deleted");
    }
    Ok(())
}

/// `heyctl delete namespace <NAME>` — undeclare it.
///
/// No `--all`, deliberately. The other bulk deletes remove things that can be
/// recreated from a spec file; a sweep over namespaces would be a sweep over
/// the walls other credentials are scoped against, and the blast radius is not
/// the objects it removes but every token that pointed at them.
fn delete_namespaces(ctx: &Ctx, names: &[String]) -> Result<()> {
    if names.is_empty() {
        bail!("delete namespace needs a name");
    }
    for name in names {
        ctx.client
            .delete_namespace(name)
            .with_context(|| format!("deleting namespace {name:?}"))?;
        println!("namespace/{name} deleted");
    }
    Ok(())
}

fn delete_secrets(ctx: &Ctx, names: &[String], args: &DeleteArgs) -> Result<()> {
    let ns = args.namespace.as_deref();
    let targets: Vec<String> = if args.all {
        // Narrowed to the namespace being deleted from, so `--all -n team-a`
        // cannot reach past its own wall.
        let list: Vec<SecretSummary> = serde_json::from_value(ctx.client.raw().secrets_in(ns)?)?;
        list.into_iter().map(|s| s.id).collect()
    } else {
        if names.is_empty() {
            bail!("delete secret needs a name, or --all");
        }
        names.to_vec()
    };

    if targets.is_empty() {
        println!("No secrets to delete.");
        return Ok(());
    }
    if args.all && !args.yes {
        confirm(&format!(
            "About to delete {} secret(s), permanently: {}",
            targets.len(),
            targets.join(", ")
        ))?;
    }

    for id in &targets {
        // The server refuses (409) while a deployment's build still references
        // the secret; --force is how you say you meant it.
        ctx.client.delete_secret_in(ns, id, args.force)?;
        match ns {
            Some(ns) => println!("secret/{id} deleted from namespace {ns}"),
            None => println!("secret/{id} deleted"),
        }
    }
    Ok(())
}

fn delete_deployments(ctx: &Ctx, names: &[String], args: &DeleteArgs) -> Result<()> {
    let targets: Vec<String> = if args.all {
        let list: Vec<DeploymentStatus> = serde_json::from_value(ctx.client.raw().deployments()?)?;
        list.into_iter().map(|d| d.spec.id).collect()
    } else {
        if names.is_empty() {
            bail!("delete needs a name, or --all");
        }
        names.to_vec()
    };

    if targets.is_empty() {
        println!("No deployments to delete.");
        return Ok(());
    }
    if args.all && !args.yes {
        confirm(&format!(
            "About to delete {} deployment(s) and tear down their VMs: {}",
            targets.len(),
            targets.join(", ")
        ))?;
    }

    for id in &targets {
        ctx.client.delete_deployment(id)?;
        println!("deployment/{id} deleted");
    }
    Ok(())
}

fn delete_vms(ctx: &Ctx, names: &[String], args: &DeleteArgs) -> Result<()> {
    let deployment = args
        .deployment
        .clone()
        .context("deleting a VM needs --deployment (VM ids are scoped to a deployment)")?;
    let id = deployment_name(&deployment)?;

    let targets: Vec<String> = if args.all {
        let status: DeploymentStatus = serde_json::from_value(ctx.client.raw().deployment(&id)?)?;
        status.vms.into_iter().map(|v| v.sandbox_id).collect()
    } else {
        if names.is_empty() {
            bail!("delete vm needs a sandbox id, or --all");
        }
        names.to_vec()
    };

    if targets.is_empty() {
        println!("No VMs to delete in deployment/{id}.");
        return Ok(());
    }

    for sandbox in &targets {
        let result = ctx.client.raw().evict_vm(&id, sandbox, args.force)?;
        let outcome = result
            .get("outcome")
            .and_then(Value::as_str)
            .unwrap_or("requested");
        println!("vm/{sandbox} {outcome}");
    }
    // Worth saying, because it is the difference between this and `scale`.
    println!(
        "\nThe autoscaler boots replacements on its next tick if the scaling policy still \
         wants the capacity. To shrink the pool, use `heyctl scale`."
    );
    Ok(())
}

pub fn confirm(prompt: &str) -> Result<()> {
    println!("{prompt}");
    print!("Type 'yes' to continue: ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("reading confirmation")?;
    if answer.trim() != "yes" {
        bail!("aborted");
    }
    Ok(())
}

// -- shared reporting ------------------------------------------------------

fn print_spec(ctx: &Ctx, spec: &Value) -> Result<()> {
    match ctx.out {
        crate::output::OutputFormat::Yaml => print!("{}", serde_yaml::to_string(spec)?),
        _ => println!("{}", serde_json::to_string_pretty(spec)?),
    }
    Ok(())
}

/// The one-line confirmation after a write, or the server's object under
/// `-o json`/`-o yaml`.
fn report_write(ctx: &Ctx, result: &Value, id: &str, verb: &str) -> Result<()> {
    if ctx.out.is_machine() {
        return output::emit(result, ctx.out, &[format!("deployment/{id}")]);
    }
    let status: Option<DeploymentStatus> = serde_json::from_value(result.clone()).ok();
    match status {
        Some(s) if !s.spec.is_static() => println!(
            "deployment/{id} {verb} — desired {}, {} ready, {} pending",
            s.desired_replicas, s.ready, s.pending
        ),
        Some(s) => println!(
            "deployment/{id} {verb} — {} upstream(s), {} healthy",
            s.spec.upstreams.len(),
            s.ready
        ),
        None => println!("deployment/{id} {verb}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct SetArtifactCmd {
        #[command(flatten)]
        args: SetArtifactArgs,
    }

    fn set_artifact_args(argv: &[&str]) -> SetArtifactArgs {
        let mut full = vec!["set-artifact", "web"];
        full.extend_from_slice(argv);
        SetArtifactCmd::try_parse_from(full).expect("flags parse").args
    }

    #[test]
    fn a_first_artifact_source_needs_only_a_ref() {
        // No --store: app-lb's own global store, left absent in the spec
        // rather than written as an empty string.
        let mut spec = serde_json::json!({"id": "web", "routes": []});
        let args = set_artifact_args(&["--ref", "acme/web:v2"]);
        apply_artifact_args(&mut spec, "web", &args, None).unwrap();
        assert_eq!(spec["artifact"], serde_json::json!({"ref": "acme/web:v2"}));

        // A ref is still required.
        let mut spec = serde_json::json!({"id": "web", "routes": []});
        let e = apply_artifact_args(&mut spec, "web", &set_artifact_args(&["--grow-gb", "4"]), None)
            .unwrap_err();
        assert!(e.to_string().contains("--ref is required"), "{e}");
        assert!(!e.to_string().contains("--store"), "{e}");
    }

    #[test]
    fn an_explicit_store_still_works_and_an_empty_one_switches_back() {
        let mut spec = serde_json::json!({"id": "web", "routes": []});
        let args = set_artifact_args(&["--store", "http://art:8080", "--ref", "debian"]);
        apply_artifact_args(&mut spec, "web", &args, None).unwrap();
        assert_eq!(spec["artifact"]["store"], "http://art:8080");

        let args = set_artifact_args(&["--store", "", "--ref", "acme/web:v3"]);
        apply_artifact_args(&mut spec, "web", &args, None).unwrap();
        assert!(spec["artifact"].get("store").is_none(), "{spec}");
        assert_eq!(spec["artifact"]["ref"], "acme/web:v3");
    }

    /// A `#[derive(Args)]` struct is parsed through a command that flattens it.
    #[derive(Parser, Debug)]
    struct ProviderCmd {
        #[command(flatten)]
        args: CreateAuthProviderArgs,
    }

    fn provider(argv: &[&str]) -> CreateAuthProviderArgs {
        let mut full = vec!["create-auth-provider"];
        full.extend_from_slice(argv);
        ProviderCmd::try_parse_from(full).expect("flags parse").args
    }

    #[test]
    fn a_claim_requirement_is_a_value_or_any_of_several() {
        assert_eq!(
            parse_require("accountId=acct_7f3c").unwrap(),
            ("accountId".to_string(), Value::String("acct_7f3c".into())),
        );
        assert_eq!(
            parse_require("role=user,admin").unwrap(),
            (
                "role".to_string(),
                Value::Array(vec![Value::String("user".into()), Value::String("admin".into())]),
            ),
        );
        // The one conversion, because a boolean claim is genuinely common.
        assert_eq!(
            parse_require("email_verified=true").unwrap(),
            ("email_verified".to_string(), Value::Bool(true)),
        );
        // And the one that is deliberately *not* converted: an id that happens
        // to be digits is a string in the token it came from.
        assert_eq!(
            parse_require("orgId=12345").unwrap(),
            ("orgId".to_string(), Value::String("12345".into())),
        );
        assert!(parse_require("role").is_err(), "no `=`");
        assert!(parse_require("=user").is_err(), "no claim");
        assert!(parse_require("role=").is_err(), "no value");
    }

    /// The bring-your-own-issuer path: any issuer, one key, and the algorithm
    /// chosen by the spec rather than by the token.
    #[test]
    fn a_jwt_provider_names_one_key_and_defaults_its_algorithm_by_key_kind() {
        let jwt = provider(&["okta", "--issuer", "https://example.okta.com", "--jwks-url", "https://example.okta.com/keys"])
            .jwt_block()
            .unwrap()
            .expect("an issuer means a jwt block");
        assert_eq!(jwt["algorithms"], serde_json::json!(["RS256"]));
        assert_eq!(jwt["issuer"], "https://example.okta.com");

        let jwt = provider(&["own", "--issuer", "my-service", "--secret", "signing/jwt"])
            .jwt_block()
            .unwrap()
            .expect("an issuer means a jwt block");
        assert_eq!(jwt["algorithms"], serde_json::json!(["HS256"]), "a shared secret is symmetric");
        assert_eq!(jwt["secret"], serde_json::json!({"secret": "signing", "key": "jwt"}));

        // Two keys is the question "which one verified this?" with no answer.
        let two = provider(&[
            "both", "--issuer", "x", "--secret", "s/k", "--jwks-url", "https://e/keys",
        ]);
        assert!(two.jwt_block().is_err());

        // No key at all.
        assert!(provider(&["none", "--issuer", "x"]).jwt_block().is_err());
    }

    /// The redirect and the cookie are one mechanism: without the cookie the
    /// browser comes back holding nothing and is redirected again, forever.
    #[test]
    fn a_login_redirect_without_a_cookie_is_refused_before_the_server_sees_it() {
        let args = provider(&[
            "own", "--issuer", "my-service", "--secret", "s/k",
            "--login-url", "https://auth.example.com/login",
        ]);
        let err = args.jwt_block().expect_err("login_url needs a cookie");
        assert!(err.to_string().contains("--cookie"), "{err}");

        let ok = provider(&[
            "own", "--issuer", "my-service", "--secret", "s/k",
            "--login-url", "https://auth.example.com/login",
            "--cookie", "heyo_token",
            "--login-redirect-param", "return_to",
        ])
        .jwt_block()
        .unwrap()
        .expect("a jwt block");
        assert_eq!(ok["login_url"], "https://auth.example.com/login");
        assert_eq!(ok["login_redirect_param"], "return_to");
        assert_eq!(ok["cookie"], "heyo_token");
    }

    /// A Google allow-list on a JWT provider is refused rather than dropped:
    /// whoever wrote it believes the provider is restricted, and it is not.
    #[test]
    fn a_google_allow_list_on_a_jwt_provider_is_refused_with_the_right_flag_named() {
        let misplaced = |argv: &[&str]| provider(argv).misplaced_google_allow_list();
        assert!(misplaced(&[
            "heyo", "--preset", "heyo", "--secret", "s/k", "--allow-domain", "example.com",
        ]));
        assert!(misplaced(&[
            "own", "--issuer", "x", "--secret", "s/k", "--allow-email", "a@example.com",
        ]));
        // Not misplaced: a Google provider is exactly where they belong.
        assert!(!misplaced(&[
            "corp", "--client-id", "1234.apps.googleusercontent.com", "--secret", "g/s",
            "--allow-domain", "example.com",
        ]));
        assert!(!misplaced(&["heyo", "--preset", "heyo", "--secret", "s/k"]));
    }

    /// The two Heyo presets take different key material, and each refuses the
    /// other's: naming a secret for the key-set preset means somebody thinks
    /// they are configuring something they are not.
    #[test]
    fn the_presets_refuse_each_others_key_material() {
        use clap::Parser as _;
        let parse = |argv: &[&str]| {
            let mut full = vec!["create-auth-provider"];
            full.extend_from_slice(argv);
            ProviderCmd::try_parse_from(full).map(|c| c.args)
        };
        // Both are accepted by the parser; the refusal is the handler's, and
        // these assert the flag combinations that reach it.
        let jwks = parse(&["heyo", "--preset", "heyo-jwks"]).expect("no secret needed");
        assert!(jwks.secret.is_none() && jwks.jwks_url.is_none());
        let with_url = parse(&[
            "heyo", "--preset", "heyo-jwks", "--jwks-url", "https://auth.example.com/.well-known/jwks.json",
        ])
        .expect("an explicit key set is allowed");
        assert_eq!(
            with_url.jwks_url.as_deref(),
            Some("https://auth.example.com/.well-known/jwks.json"),
        );
        // And the preset itself satisfies the "one identity shape" group, so
        // `--preset heyo-jwks` alone is a complete command.
        assert!(parse(&["heyo", "--preset", "heyo-jwks"]).is_ok());
    }

    /// One provider serialises as a bare string, several as an array — the
    /// shape app-lb's own `Providers` round-trips.
    #[test]
    fn the_provider_list_is_a_string_for_one_and_an_array_for_several() {
        assert_eq!(
            provider(&["heyo", "--preset", "heyo", "--secret", "s/k"]).providers(),
            Value::String("jwt".into()),
        );
        assert_eq!(
            provider(&["mixed", "--issuer", "x", "--secret", "s/k", "--app-token"]).providers(),
            serde_json::json!(["jwt", "app-token"]),
        );
    }
}
