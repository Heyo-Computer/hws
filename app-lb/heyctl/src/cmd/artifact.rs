//! `heyctl artifact` — authenticate against an artifact store and push guest
//! images to it.
//!
//! The store is a separate service from app-lb (`art serve`), so these commands
//! resolve a *registry* rather than a context and never touch `--server`. A
//! `login` here has nothing to do with a `login` there: one saves HTTP Basic
//! credentials for a load balancer, the other saves a shared key for a content
//! store, and conflating them would mean a `--context` switch silently
//! retargeted a push.
//!
//! The point of a push is the pull on the other end: an image in a store is what
//! a deployment's `artifact` block names, so `heyctl artifact push` and
//! `heyctl pull` are the two halves of shipping a rootfs to a fleet. That is
//! why a push writes a manifest and moves a tag rather than just uploading
//! bytes — see [`crate::artifact`].

use crate::cmd::GlobalOpts;
use crate::artifact::{self, RegistryClient};
use crate::config::{Config, PasswordSource, RegistryEntry, resolve_registry_endpoint};
use crate::output::{self, Table};
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Subcommand, Debug)]
pub enum ArtifactCmd {
    /// Verify an artifact store's API key and save it as a named registry.
    Login(LoginArgs),

    /// Forget a stored registry, or just its API key.
    Logout(LogoutArgs),

    /// List the stored registries.
    #[command(visible_alias = "contexts")]
    Registries,

    /// Choose which stored registry later commands use.
    #[command(visible_alias = "use-registry")]
    Use(UseArgs),

    /// Upload an ext4 rootfs and tag it, so deployments can pull it.
    Push(PushArgs),

    /// Upload a Dockerfile (and its build context) and tag it, so deployments
    /// can *build* it.
    ///
    /// The counterpart of `push`, one step earlier: `push` ships an image
    /// somebody already built, this ships the recipe and lets app-lb build it on
    /// the host that will run it. Point a deployment at it with
    /// `heyctl set build --store <url> --ref <tag>`.
    #[command(visible_alias = "push-df")]
    PushDockerfile(PushDockerfileArgs),

    /// Download a tag or digest — from the configured store, or from any store
    /// named by host, the hub included: `hub.heyo.work/heyo/postgres:16`.
    ///
    /// A public repository needs no login. Every byte is checked against its
    /// digest before the file appears.
    Pull(PullArgs),

    /// List the store's tags — the images a deployment can name.
    #[command(visible_alias = "tags")]
    Ls,

    /// Show what one tag or digest resolves to.
    Describe(DescribeArgs),

    /// Logical size, physical size and free space on the store.
    Usage,

    /// Remove a tag. The blob it named stays until the store's `art gc` runs.
    #[command(visible_alias = "rm-tag")]
    Untag(UntagArgs),
}

/// Flags shared by every command that has to reach a store.
#[derive(Args, Debug, Clone)]
pub struct RegistryOpts {
    /// Which stored registry to use.
    #[arg(long, global = true, env = "HEYCTL_REGISTRY", value_name = "NAME")]
    pub registry: Option<String>,

    /// Store URL, overriding the stored registry. `host:port` is accepted and
    /// assumed to be http.
    #[arg(long, global = true, env = "HEYCTL_ART_URL", value_name = "URL")]
    pub registry_url: Option<String>,

    /// API key, overriding the stored one. Prefer `heyctl artifact login` —
    /// an argument is visible in `ps`.
    #[arg(
        long,
        global = true,
        env = "HEYCTL_ART_API_KEY",
        value_name = "KEY",
        hide_env_values = true
    )]
    pub api_key: Option<String>,
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// The store, e.g. `http://127.0.0.1:8080`.
    #[arg(value_name = "URL")]
    pub url: String,

    /// The API key (`ART_API_KEY` on the store). Prefer --api-key-stdin or the
    /// prompt.
    #[arg(long, value_name = "KEY", hide_env_values = true)]
    pub api_key: Option<String>,

    /// Read the API key from stdin (the trailing newline is stripped).
    #[arg(long, conflicts_with = "api_key")]
    pub api_key_stdin: bool,

    /// Store this shell command instead of the key itself; it is run to fetch
    /// the key on each request that needs one.
    #[arg(long, value_name = "CMD", conflicts_with_all = ["api_key", "api_key_stdin"])]
    pub api_key_command: Option<String>,

    /// Verify the key but don't write it to disk — supply it per invocation via
    /// HEYCTL_ART_API_KEY.
    #[arg(long)]
    pub no_store_key: bool,

    /// Name for the stored registry. Defaults to the store's host.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Accept any TLS certificate. Only for a self-signed store you control.
    #[arg(long)]
    pub insecure_skip_tls_verify: bool,

    /// Store the registry without making it the current one.
    #[arg(long)]
    pub no_switch: bool,
}

#[derive(Args, Debug)]
pub struct LogoutArgs {
    /// Which registry. Defaults to the current one.
    #[arg(value_name = "NAME")]
    pub name: Option<String>,

    /// Drop the stored key but keep the registry.
    #[arg(long)]
    pub key_only: bool,
}

#[derive(Args, Debug)]
pub struct UseArgs {
    #[arg(value_name = "NAME")]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct PushArgs {
    /// Path to an ext4 rootfs. Mutually exclusive with --image.
    #[arg(value_name = "FILE", required_unless_present = "image")]
    pub file: Option<PathBuf>,

    /// A heyvm image name instead of a path — resolved to
    /// `~/.heyo/images/firecracker/<name>.ext4`, which is where
    /// `heyvm mvm build` puts one.
    #[arg(long, value_name = "NAME", conflicts_with = "file")]
    pub image: Option<String>,

    /// Tag to point at the uploaded image. Defaults to the filename without
    /// `.ext4`, which is what `art heyvm import` would have used.
    #[arg(long, value_name = "NAME")]
    pub tag: Option<String>,

    /// Upload and write a manifest, but move no tag. The manifest digest is
    /// printed, and a deployment can name it directly.
    #[arg(long, conflicts_with = "tag")]
    pub no_tag: bool,

    /// Upload even if the store already reports holding these bytes.
    #[arg(long)]
    pub force: bool,

    /// Make the tag's repository public afterwards: listed on the hub and
    /// pullable by anyone without a key. Needs a namespaced tag
    /// (`heyo/postgres:16`) and the store's API key.
    #[arg(long, requires = "tag")]
    pub public: bool,
}

#[derive(Args, Debug)]
pub struct PullArgs {
    /// `[host/]repo:tag`, a flat tag, or a digest.
    #[arg(value_name = "REF")]
    pub reference: String,

    /// Where to write it. For a single-file artifact, a file path (default:
    /// the entry's name in the current directory); for several entries, a
    /// directory.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct PushDockerfileArgs {
    /// Path to the Dockerfile.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Build context: a directory to pack, or an existing `.tar`/`.tar.gz`.
    /// Omit for a recipe that copies nothing in.
    ///
    /// Spelled `--build-context` rather than `--context` because `--context` is
    /// a global flag that selects the saved app-lb context. Same name `set
    /// build` uses, for the same collision. (`art dockerfile put` has no such
    /// clash and spells it `--context`.)
    #[arg(long = "build-context", value_name = "PATH")]
    pub build_context: Option<PathBuf>,

    /// Tag to point at the manifest. Defaults to the Dockerfile's directory
    /// name, which is usually the project.
    #[arg(long, value_name = "NAME")]
    pub tag: Option<String>,

    /// Upload and write a manifest, but move no tag. The manifest digest is
    /// printed, and a deployment can name it directly — which is what pinning a
    /// build to exact inputs looks like.
    #[arg(long, conflicts_with = "tag")]
    pub no_tag: bool,

    /// Default name for the image this builds. `build.image_name` on the
    /// deployment overrides it.
    #[arg(long, value_name = "NAME")]
    pub image_name: Option<String>,

    /// Default rootfs size in megabytes. `build.image_size_mb` on the deployment
    /// overrides it.
    #[arg(long = "size-mb", value_name = "MB")]
    pub image_size_mb: Option<u64>,

    /// Provenance note recorded on the manifest. Part of its address, so two
    /// pushes differing only here are two manifests.
    #[arg(long, value_name = "TEXT")]
    pub source: Option<String>,

    /// Upload even if the store already reports holding these bytes.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct DescribeArgs {
    /// A tag or a digest.
    #[arg(value_name = "REF")]
    pub reference: String,
}

#[derive(Args, Debug)]
pub struct UntagArgs {
    #[arg(value_name = "NAME")]
    pub name: String,
}

pub fn run(globals: &GlobalOpts, opts: &RegistryOpts, cmd: &ArtifactCmd) -> Result<()> {
    match cmd {
        // These touch the config file and must keep working against an
        // unreachable store.
        ArtifactCmd::Logout(args) => logout(globals, args),
        ArtifactCmd::Registries => registries(globals),
        ArtifactCmd::Use(args) => use_registry(globals, args),

        ArtifactCmd::Login(args) => login(globals, args),
        ArtifactCmd::Push(args) => push(globals, opts, args),
        ArtifactCmd::PushDockerfile(args) => push_dockerfile(globals, opts, args),
        ArtifactCmd::Pull(args) => pull(globals, opts, args),
        ArtifactCmd::Ls => ls(globals, opts),
        ArtifactCmd::Describe(args) => describe(globals, opts, args),
        ArtifactCmd::Usage => usage(globals, opts),
        ArtifactCmd::Untag(args) => untag(globals, opts, args),
    }
}

/// Build a client for whichever store this invocation resolves to.
fn client(globals: &GlobalOpts, opts: &RegistryOpts) -> Result<(RegistryClient, String, PasswordSource)> {
    let path = Config::path(globals.config.as_deref())?;
    let config = Config::load(&path)?;
    let ep = resolve_registry_endpoint(
        &config,
        opts.registry.as_deref(),
        opts.registry_url.as_deref(),
        opts.api_key.as_deref(),
        globals.insecure_skip_tls_verify,
    )?;
    let c = RegistryClient::new(
        &ep.url,
        ep.api_key.as_deref(),
        ep.insecure_skip_tls_verify,
        Duration::from_secs(globals.request_timeout),
    )?;
    Ok((c, ep.name, ep.api_key_source))
}

// -- auth ------------------------------------------------------------------

fn login(globals: &GlobalOpts, args: &LoginArgs) -> Result<()> {
    let path = Config::path(globals.config.as_deref())?;
    let mut config = Config::load(&path)?;
    let insecure = args.insecure_skip_tls_verify || globals.insecure_skip_tls_verify;
    let timeout = Duration::from_secs(globals.request_timeout);

    // Reachability before credentials, so a typo'd port does not look like a
    // bad key. `/healthz` is open on a store even when everything else is not,
    // which is exactly what makes it usable for this.
    let anon = RegistryClient::new(&args.url, None, insecure, timeout)?;
    anon.healthz()
        .with_context(|| format!("cannot reach an artifact store at {}", args.url))?;

    // Is it even gated? A store with no ART_API_KEY answers every route, and
    // saving a key for one would be storing a credential that does nothing.
    let open = anon.tags().is_ok();
    if open {
        println!(
            "{} has no API key configured — every route is open.\n\
             (Set ART_API_KEY on the store to gate it.)",
            anon.url()
        );
        return save_registry(
            &mut config,
            &path,
            args,
            RegistryEntry {
                url: anon.url().to_string(),
                api_key: None,
                api_key_command: None,
                insecure_skip_tls_verify: insecure,
            },
        );
    }

    let key = match (&args.api_key_command, &args.api_key, args.api_key_stdin) {
        (Some(cmd), _, _) => run_command(cmd)?,
        (None, Some(k), _) => k.clone(),
        (None, None, true) => {
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
                .context("reading the API key from stdin")?;
            buf.trim_end_matches(['\n', '\r']).to_string()
        }
        (None, None, false) => rpassword::prompt_password(format!("API key for {}: ", args.url))
            .context("reading the API key")?,
    };
    if key.is_empty() {
        bail!("an empty API key will not authenticate against the store");
    }

    // Verify against a gated route rather than /healthz, which is open either
    // way and would report success for any key at all.
    let c = RegistryClient::new(&args.url, Some(&key), insecure, timeout)?;
    c.tags().context("verifying the API key against GET /tags")?;

    println!("Logged in to {}.", c.url());
    if args.no_store_key {
        println!("  key not stored — set HEYCTL_ART_API_KEY for later commands");
    }

    save_registry(
        &mut config,
        &path,
        args,
        RegistryEntry {
            url: c.url().to_string(),
            api_key: (!args.no_store_key && args.api_key_command.is_none()).then(|| key.clone()),
            api_key_command: args.api_key_command.clone(),
            insecure_skip_tls_verify: insecure,
        },
    )
}

fn save_registry(
    config: &mut Config,
    path: &std::path::Path,
    args: &LoginArgs,
    entry: RegistryEntry,
) -> Result<()> {
    let name = args
        .name
        .clone()
        .unwrap_or_else(|| registry_name_for(&entry.url));
    config.registries.insert(name.clone(), entry);
    if !args.no_switch {
        config.current_registry = Some(name.clone());
    }
    config.save(path)?;
    println!("Registry {name:?} saved to {}.", path.display());
    Ok(())
}

/// `http://art.example.com:8080` becomes `art.example.com`; a loopback address
/// becomes `local`. Same shape as a context's name, so a config file holding
/// both reads consistently.
fn registry_name_for(url: &str) -> String {
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url);
    let bare = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    match bare {
        "127.0.0.1" | "localhost" | "::1" | "[::1]" => "local".to_string(),
        other => other.to_string(),
    }
}

fn logout(globals: &GlobalOpts, args: &LogoutArgs) -> Result<()> {
    let path = Config::path(globals.config.as_deref())?;
    let mut config = Config::load(&path)?;

    let name = match &args.name {
        Some(n) => n.clone(),
        None => config
            .resolve_registry(None)?
            .map(|(n, _)| n)
            .context("no registry to log out of")?,
    };
    if !config.registries.contains_key(&name) {
        bail!("no registry named {name:?}");
    }

    if args.key_only {
        if let Some(entry) = config.registries.get_mut(&name) {
            entry.api_key = None;
            entry.api_key_command = None;
        }
        config.save(&path)?;
        println!("Dropped the API key for registry {name:?}; the url is kept.");
        return Ok(());
    }

    config.registries.remove(&name);
    if config.current_registry.as_deref() == Some(name.as_str()) {
        config.current_registry = None;
    }
    config.save(&path)?;
    println!("Registry {name:?} removed.");
    Ok(())
}

fn registries(globals: &GlobalOpts) -> Result<()> {
    let path = Config::path(globals.config.as_deref())?;
    let config = Config::load(&path)?;

    if globals.output.is_machine() {
        let rows: Vec<Value> = config
            .registries
            .iter()
            .map(|(name, e)| {
                json!({
                    "name": name,
                    "url": e.url,
                    "current": config.current_registry.as_deref() == Some(name.as_str()),
                    // Never the key itself: `-o json` is a thing people pipe
                    // into files and paste into issues.
                    "has_key": e.api_key.is_some() || e.api_key_command.is_some(),
                })
            })
            .collect();
        return output::emit(&Value::Array(rows), globals.output, &[]);
    }

    if config.registries.is_empty() {
        println!("No artifact stores configured. `heyctl artifact login <url>` adds one.");
        return Ok(());
    }

    let mut table = Table::new(["CURRENT", "NAME", "URL", "KEY"]);
    for (name, e) in &config.registries {
        let current = config.current_registry.as_deref() == Some(name.as_str());
        table.row([
            if current { "*" } else { "" },
            name,
            &e.url,
            match (&e.api_key, &e.api_key_command) {
                (_, Some(_)) => "command",
                (Some(_), None) => "stored",
                (None, None) => "none",
            },
        ]);
    }
    table.print();
    Ok(())
}

fn use_registry(globals: &GlobalOpts, args: &UseArgs) -> Result<()> {
    let path = Config::path(globals.config.as_deref())?;
    let mut config = Config::load(&path)?;
    if !config.registries.contains_key(&args.name) {
        bail!(
            "no registry named {:?} — `heyctl artifact registries` lists them",
            args.name
        );
    }
    config.current_registry = Some(args.name.clone());
    config.save(&path)?;
    println!("Now using registry {:?}.", args.name);
    Ok(())
}

// -- push ------------------------------------------------------------------

fn push(globals: &GlobalOpts, opts: &RegistryOpts, args: &PushArgs) -> Result<()> {
    let path = match (&args.file, &args.image) {
        (Some(f), _) => f.clone(),
        (None, Some(name)) => artifact::heyvm_image_path(name)?,
        (None, None) => bail!("give a path to an .ext4 file, or --image <name>"),
    };
    let meta = std::fs::metadata(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a file", path.display());
    }

    // Resolve the tag before uploading anything. A name the store would refuse
    // should not cost a multi-gigabyte transfer first.
    let tag = if args.no_tag {
        None
    } else {
        let t = match &args.tag {
            Some(t) => t.clone(),
            None => artifact::default_tag_for(&path).with_context(|| {
                format!(
                    "cannot derive a tag from {} — pass --tag, or --no-tag to push \
                     without one",
                    path.display()
                )
            })?,
        };
        if !artifact::is_valid_tag(&t) {
            bail!(
                "{t:?} is not a usable tag: tags are [A-Za-z0-9._-] and may not start with \
                 `-` or `.`, or a repository and tag like `heyo/postgres:16`"
            );
        }
        Some(t)
    };
    if args.public && tag.as_deref().and_then(artifact::repo_of).is_none() {
        bail!("--public needs a namespaced tag (`team/name:tag`): only repositories are public");
    }

    let (c, registry, _) = client(globals, opts)?;
    let quiet = globals.output.is_machine();

    // 1. Hash. The digest is the blob's name, so it has to exist before the
    //    request that carries it does.
    if !quiet {
        eprintln!("Hashing {} ({})...", path.display(), output::bytes(meta.len()));
    }
    let (digest, size) = artifact::hash_file(&path, |done, total| {
        if !quiet {
            progress("hashing", done, total);
        }
    })?;
    if !quiet {
        clear_progress();
    }

    // 2. Ask before sending. A rootfs that has not changed is the common case.
    let already = if args.force { None } else { c.blob_exists(&digest)? };
    let uploaded = match already {
        Some(_) => {
            if !quiet {
                println!("{digest} is already in {registry}; skipping the upload");
            }
            false
        }
        None => {
            if !quiet {
                eprintln!("Uploading {} to {}...", output::bytes(size), c.url());
            }
            c.put_blob(&digest, &path, size)?
        }
    };

    // 3. Describe it as a rootfs, so a pull can find it. Cheap and idempotent:
    //    the manifest is content-addressed too, so re-pushing an unchanged
    //    image lands on the same digest instead of accumulating manifests.
    let image_name = tag.clone().unwrap_or_else(|| digest[..12].to_string());
    let manifest = artifact::rootfs_manifest(&digest, size, &image_name);
    let manifest_digest = c.put_manifest(&manifest)?;

    // 4. Move the tag onto the manifest, not the blob: that is what makes
    //    `art get <tag>` and app-lb's puller both resolve.
    if let Some(t) = &tag {
        c.put_tag(t, &manifest_digest)?;
    }
    let public_repo = match tag.as_deref().and_then(artifact::repo_of) {
        Some(repo) if args.public => {
            c.put_repo(repo, true, None)?;
            Some(repo.to_string())
        }
        _ => None,
    };

    let result = json!({
        "registry": registry,
        "store": c.url(),
        "public": public_repo,
        "path": path.display().to_string(),
        "digest": digest,
        "manifest": manifest_digest,
        "size": size,
        "tag": tag,
        "uploaded": uploaded,
    });
    if globals.output.is_machine() {
        return output::emit(&result, globals.output, &[]);
    }

    output::section("Pushed");
    if let Some(repo) = &public_repo {
        output::field("public", format!("{repo} is on the hub; anyone can pull it"));
    }
    output::field("store", c.url());
    output::field("digest", &digest);
    output::field("manifest", &manifest_digest);
    output::field("size", output::bytes(size));
    match &tag {
        Some(t) => output::field("tag", t),
        None => output::field("tag", "(none — name the manifest digest to pull it)"),
    }
    println!();
    let reference = tag.as_deref().unwrap_or(&manifest_digest);
    println!("Pull it with:");
    println!("  heyctl set artifact <deployment> --store {} --ref {reference}", c.url());
    println!("  heyctl pull <deployment> --wait");
    Ok(())
}

// -- pull ------------------------------------------------------------------

fn pull(globals: &GlobalOpts, opts: &RegistryOpts, args: &PullArgs) -> Result<()> {
    let (store, reference) = artifact::split_store_ref(&args.reference);
    if !(artifact::is_valid_tag(&reference) || artifact::is_digest(&reference)) {
        bail!("{reference:?} is neither a tag nor a digest");
    }
    let c = match &store {
        // Named by host: no stored registry is consulted, and the request is
        // anonymous unless a key was passed explicitly.
        Some(url) => RegistryClient::new(
            url,
            opts.api_key.as_deref(),
            globals.insecure_skip_tls_verify,
            Duration::from_secs(globals.request_timeout),
        )?,
        None => client(globals, opts)?.0,
    };
    let quiet = globals.output.is_machine();

    let Some(resolved) = c.resolve(&reference)? else {
        bail!("{reference} is not in {}", c.url());
    };
    // (entry name, digest) pairs to fetch.
    let entries: Vec<(String, String)> = match &resolved {
        artifact::Resolved::Manifest(m) => m
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|e| {
                Some((
                    e.get("name")?.as_str()?.to_string(),
                    e.get("digest")?.as_str()?.to_string(),
                ))
            })
            .collect(),
        artifact::Resolved::Blob(d) => {
            let name = reference
                .rsplit('/')
                .next()
                .unwrap_or(&reference)
                .replace(':', "-");
            vec![(name, d.clone())]
        }
    };
    if entries.is_empty() {
        bail!("{reference} names a manifest with no entries");
    }
    for (name, digest) in &entries {
        if !artifact::is_safe_entry_name(name) || !artifact::is_digest(digest) {
            bail!("the store described an entry {name:?} ({digest}) that is not safe to write");
        }
    }

    let targets: Vec<(PathBuf, &str)> = if entries.len() == 1 {
        let dest = match &args.output {
            Some(p) if p.is_dir() => p.join(&entries[0].0),
            Some(p) => p.clone(),
            None => PathBuf::from(&entries[0].0),
        };
        vec![(dest, entries[0].1.as_str())]
    } else {
        let dir = args.output.clone().unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        entries.iter().map(|(n, d)| (dir.join(n), d.as_str())).collect()
    };

    let mut pulled = Vec::new();
    for (dest, digest) in &targets {
        if !quiet {
            eprintln!("Pulling {} -> {}", &digest[..12], dest.display());
        }
        let size = c.get_blob(digest, dest, |done, total| {
            if !quiet {
                progress("pulling", done, total);
            }
        })?;
        if !quiet {
            clear_progress();
        }
        pulled.push(json!({"path": dest.display().to_string(), "digest": digest, "size": size}));
    }

    let result = json!({ "store": c.url(), "ref": reference, "files": pulled });
    if quiet {
        return output::emit(&result, globals.output, &[]);
    }
    output::section("Pulled");
    output::field("store", c.url());
    output::field("ref", &reference);
    for f in &pulled {
        output::field("file", f["path"].as_str().unwrap_or_default());
    }
    Ok(())
}

// -- push-dockerfile -------------------------------------------------------

fn push_dockerfile(
    globals: &GlobalOpts,
    opts: &RegistryOpts,
    args: &PushDockerfileArgs,
) -> Result<()> {
    let meta = std::fs::metadata(&args.file)
        .with_context(|| format!("reading {}", args.file.display()))?;
    if !meta.is_file() {
        bail!("{} is not a file", args.file.display());
    }
    artifact::check_dockerfile_size(&args.file, meta.len())?;

    // Resolved before anything is packed or uploaded. A name the store would
    // refuse should not cost a context pack first.
    let tag = if args.no_tag {
        None
    } else {
        let t = match &args.tag {
            Some(t) => t.clone(),
            None => default_recipe_tag(&args.file).with_context(|| {
                format!(
                    "cannot derive a tag from {} — pass --tag, or --no-tag to push without one",
                    args.file.display()
                )
            })?,
        };
        if !artifact::is_valid_tag(&t) {
            bail!(
                "{t:?} is not a usable tag: tags are [A-Za-z0-9._-] and may not start with \
                 `-` or `.`"
            );
        }
        Some(t)
    };

    let quiet = globals.output.is_machine();

    // A directory is packed into a temp file first; an archive is used as it is.
    // The `Scratch` is what removes the packed copy however this returns.
    let packed = match &args.build_context {
        Some(c) if c.is_dir() => {
            if !quiet {
                eprintln!("Packing {}...", c.display());
            }
            let dest = Scratch::new(std::env::temp_dir().join(format!(
                "heyctl-context-{}.tar.gz",
                std::process::id()
            )));
            let size = artifact::pack_context(c, dest.path())?;
            if !quiet {
                println!("packed {} into {}", c.display(), output::bytes(size));
            }
            Some(dest)
        }
        _ => None,
    };
    let archive: Option<&std::path::Path> = match (&packed, &args.build_context) {
        (Some(p), _) => Some(p.path()),
        (None, Some(c)) => Some(c.as_path()),
        (None, None) => None,
    };

    let (c, registry, _) = client(globals, opts)?;

    // Both blobs go up the same way `push` sends a rootfs: hash, ask, upload.
    // The recipe is kilobytes and the context is usually not, so the "ask" is
    // worth it for exactly one of them and costs one round trip for the other.
    let recipe = upload(&c, &args.file, args.force, quiet, "Dockerfile")?;
    let context = match archive {
        Some(p) => Some(upload(&c, p, args.force, quiet, "context")?),
        None => None,
    };

    let manifest = artifact::dockerfile_manifest(
        (&recipe.digest, recipe.size),
        context.as_ref().map(|c| (c.digest.as_str(), c.size)),
        args.image_name.as_deref(),
        args.image_size_mb,
        args.source.as_deref(),
    );
    let manifest_digest = c.put_manifest(&manifest)?;

    // The tag lands on the manifest, never on the recipe blob: the manifest is
    // what carries the context and the annotations, and a tag on the Dockerfile
    // alone would resolve to a recipe with neither.
    if let Some(t) = &tag {
        c.put_tag(t, &manifest_digest)?;
    }

    let result = json!({
        "registry": registry,
        "store": c.url(),
        "path": args.file.display().to_string(),
        "manifest": manifest_digest,
        "dockerfile": { "digest": recipe.digest, "size": recipe.size, "uploaded": recipe.uploaded },
        "context": context.as_ref().map(|c| json!({
            "digest": c.digest, "size": c.size, "uploaded": c.uploaded,
        })),
        "tag": tag,
    });
    if globals.output.is_machine() {
        return output::emit(&result, globals.output, &[]);
    }

    output::section("Pushed");
    output::field("store", c.url());
    output::field("manifest", &manifest_digest);
    output::field(
        "Dockerfile",
        format!("{} ({})", recipe.digest, output::bytes(recipe.size)),
    );
    match &context {
        Some(c) => output::field(
            "context",
            format!("{} ({})", c.digest, output::bytes(c.size)),
        ),
        None => output::field("context", "(none — this recipe copies nothing in)"),
    }
    match &tag {
        Some(t) => output::field("tag", t),
        None => output::field("tag", "(none — name the manifest digest to build it)"),
    }
    println!();
    let reference = tag.as_deref().unwrap_or(&manifest_digest);
    println!("Build it with:");
    println!(
        "  heyctl set build <deployment> --store {} --ref {reference}",
        c.url()
    );
    println!("  heyctl build <deployment> --wait");
    Ok(())
}

/// One blob's trip into the store: hash it, ask whether it is already there,
/// upload it if not.
struct Uploaded {
    digest: String,
    size: u64,
    uploaded: bool,
}

fn upload(
    c: &RegistryClient,
    path: &std::path::Path,
    force: bool,
    quiet: bool,
    what: &str,
) -> Result<Uploaded> {
    let (digest, size) = artifact::hash_file(path, |done, total| {
        if !quiet {
            progress(&format!("hashing {what}"), done, total);
        }
    })?;
    if !quiet {
        clear_progress();
    }

    let already = if force { None } else { c.blob_exists(&digest)? };
    let uploaded = match already {
        Some(_) => {
            if !quiet {
                println!("{what} {digest} is already in the store; skipping the upload");
            }
            false
        }
        None => {
            if !quiet {
                eprintln!("Uploading {what} ({})...", output::bytes(size));
            }
            c.put_blob(&digest, path, size)?
        }
    };
    Ok(Uploaded {
        digest,
        size,
        uploaded,
    })
}

/// The tag a Dockerfile gets when none is given: the name of the directory
/// holding it.
///
/// Not the filename, which is `Dockerfile` for almost every recipe there has
/// ever been and would collide across every project in a shared store. The
/// directory name is the closest thing to "which project is this".
fn default_recipe_tag(path: &std::path::Path) -> Option<String> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let name = match dir {
        Some(d) => d.canonicalize().ok()?.file_name()?.to_str()?.to_string(),
        None => return None,
    };
    artifact::is_valid_tag(&name).then_some(name)
}

/// A file removed on drop, for a context packed on the way to the store.
struct Scratch(PathBuf);

impl Scratch {
    fn new(path: PathBuf) -> Self {
        Scratch(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A one-line progress meter on stderr, so `-o json` on stdout stays clean.
fn progress(what: &str, done: u64, total: u64) {
    if total == 0 {
        return;
    }
    let pct = (done as f64 / total as f64 * 100.0).min(100.0);
    eprint!(
        "\r  {what} {:>6.1}%  {} / {}   ",
        pct,
        output::bytes(done),
        output::bytes(total)
    );
    let _ = std::io::stderr().flush();
}

fn clear_progress() {
    eprint!("\r{:60}\r", "");
    let _ = std::io::stderr().flush();
}

// -- reads -----------------------------------------------------------------

fn ls(globals: &GlobalOpts, opts: &RegistryOpts) -> Result<()> {
    let (c, _, _) = client(globals, opts)?;
    let tags = c.tags()?;
    if globals.output.is_machine() {
        return output::emit(&tags, globals.output, &[]);
    }

    let rows = tags.as_array().map(Vec::as_slice).unwrap_or_default();
    if rows.is_empty() {
        println!("No tags in {}.", c.url());
        return Ok(());
    }
    let mut table = Table::new(["TAG", "DIGEST"]);
    for r in rows {
        table.row([
            r.get("tag").and_then(Value::as_str).unwrap_or("?"),
            r.get("digest").and_then(Value::as_str).unwrap_or("?"),
        ]);
    }
    table.print();
    Ok(())
}

fn describe(globals: &GlobalOpts, opts: &RegistryOpts, args: &DescribeArgs) -> Result<()> {
    let (c, _, _) = client(globals, opts)?;
    let manifest = c.manifest(&args.reference)?;
    if globals.output.is_machine() {
        return output::emit(&manifest, globals.output, &[]);
    }

    output::section(&format!("Manifest {}", args.reference));
    output::field(
        "kind",
        manifest.get("kind").and_then(Value::as_str).unwrap_or("?"),
    );
    if let Some(entries) = manifest.get("entries").and_then(Value::as_array) {
        let mut table = Table::indented(["NAME", "DIGEST", "SIZE"], 2);
        for e in entries {
            table.row([
                e.get("name").and_then(Value::as_str).unwrap_or("?").to_string(),
                e.get("digest").and_then(Value::as_str).unwrap_or("?").to_string(),
                output::bytes(e.get("size").and_then(Value::as_u64).unwrap_or(0)),
            ]);
        }
        println!();
        table.print();
    }
    if let Some(ann) = manifest.get("annotations").and_then(Value::as_object)
        && !ann.is_empty()
    {
        println!();
        output::section("Annotations");
        for (k, v) in ann {
            output::field(k, v.as_str().unwrap_or_default());
        }
    }
    Ok(())
}

fn usage(globals: &GlobalOpts, opts: &RegistryOpts) -> Result<()> {
    let (c, _, _) = client(globals, opts)?;
    let u = c.usage()?;
    if globals.output.is_machine() {
        return output::emit(&u, globals.output, &[]);
    }

    let n = |key: &str| u.get(key).and_then(Value::as_u64);

    output::section(&format!("Store {}", c.url()));
    for (key, label) in [("blobs", "Blobs"), ("manifests", "Manifests"), ("tags", "Tags")] {
        if let Some(v) = n(key) {
            output::field(label, v.to_string());
        }
    }

    output::section("Space");
    if let Some(logical) = n("logical") {
        output::field("Logical", output::bytes(logical));
        // The saving is the whole reason this store exists — an ext4 image is
        // fully allocated on disk and mostly zero inside — so show it rather
        // than leaving two numbers to be divided by eye.
        if let Some(allocated) = n("allocated") {
            output::field(
                "Stored",
                match logical {
                    0 => output::bytes(allocated),
                    _ => format!(
                        "{} ({:.1}% of logical)",
                        output::bytes(allocated),
                        allocated as f64 / logical as f64 * 100.0
                    ),
                },
            );
        }
    } else if let Some(allocated) = n("allocated") {
        output::field("Stored", output::bytes(allocated));
    }
    if let (Some(avail), Some(total)) = (n("fsAvailable"), n("fsTotal")) {
        output::field(
            "Filesystem",
            format!("{} free of {}", output::bytes(avail), output::bytes(total)),
        );
    }
    Ok(())
}

fn untag(globals: &GlobalOpts, opts: &RegistryOpts, args: &UntagArgs) -> Result<()> {
    let (c, _, _) = client(globals, opts)?;
    c.delete_tag(&args.name)?;
    println!(
        "Tag {:?} removed from {}. The blob it named stays until the store's `art gc` runs.",
        args.name,
        c.url()
    );
    Ok(())
}

fn run_command(cmd: &str) -> Result<String> {
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .with_context(|| format!("running {cmd:?}"))?;
    if !out.status.success() {
        bail!("{cmd:?} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8(out.stdout)
        .context("the api key command produced non-UTF-8 output")?
        .trim_end_matches(['\n', '\r'])
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recipe_is_tagged_after_its_directory_not_its_filename() {
        // Every project's recipe is called `Dockerfile`, so a filename default
        // would have every push in a shared store fighting over one tag.
        let dir = std::env::temp_dir().join(format!("heyctl-tag-{}", std::process::id()));
        let project = dir.join("web-frontend");
        std::fs::create_dir_all(&project).unwrap();
        let df = project.join("Dockerfile");
        std::fs::write(&df, b"FROM debian\n").unwrap();
        assert_eq!(default_recipe_tag(&df).as_deref(), Some("web-frontend"));

        // A directory the store would refuse gets no default, so the push asks
        // for --tag rather than inventing something.
        let odd = dir.join(".hidden");
        std::fs::create_dir_all(&odd).unwrap();
        let df = odd.join("Dockerfile");
        std::fs::write(&df, b"FROM debian\n").unwrap();
        assert_eq!(default_recipe_tag(&df), None);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_registry_is_named_after_its_host() {
        assert_eq!(registry_name_for("http://art.example.com:8080"), "art.example.com");
        assert_eq!(registry_name_for("http://127.0.0.1:8080"), "local");
        assert_eq!(registry_name_for("https://art.example.com"), "art.example.com");
        assert_eq!(registry_name_for("localhost:8080"), "local");
    }
}
