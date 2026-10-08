//! `heyctl plugins` — list, switch on and configure app-lb's built-in plugins,
//! and install the per-namespace ones into a namespace.
//!
//! The set of plugins is compiled into app-lb; what these commands change is
//! whether each one runs and with what configuration. A plugin can be enabled
//! and failing at once (it could not reach what it needs), so every write
//! prints `last_error` when there is one rather than reporting bare success.
//!
//! Some plugins (`obs`, `ci`, `remote`) also install per namespace. `enable`/`disable` are the
//! operator's fleet-wide switch; `install`/`uninstall` are a namespace
//! administrator's, and a plugin serves a namespace only when both are on.

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use crate::{NamespacePlugin, PluginView};
use crate::cmd::Ctx;
use crate::output::{self, Table};

#[derive(Subcommand, Debug)]
pub enum PluginsCmd {
    /// List every plugin and whether it is enabled — or, with -n, the plugins
    /// a namespace can install and whether it has.
    #[command(alias = "ls")]
    List {
        /// List what this namespace can install, and what it has.
        #[arg(long, short = 'n', value_name = "NAMESPACE")]
        namespace: Option<String>,
    },
    /// Show one plugin: its configuration and live status.
    Describe { id: String },
    /// Switch a plugin on with its stored configuration.
    Enable { id: String },
    /// Switch a plugin off. Its configuration is kept.
    Disable { id: String },
    /// Replace a plugin's configuration.
    Set(SetArgs),
    /// Install a per-namespace plugin into a namespace. Needs admin over the
    /// namespace; the plugin must also be enabled for the fleet.
    Install(InstallArgs),
    /// Uninstall a per-namespace plugin from a namespace.
    Uninstall {
        id: String,
        /// Defaults to the namespace this credential is confined to.
        #[arg(long, short = 'n', value_name = "NAMESPACE")]
        namespace: Option<String>,
    },
    /// Every namespace a plugin is installed in. Fleet scope only.
    Installs { id: String },
}

#[derive(Args, Debug)]
pub struct InstallArgs {
    pub id: String,
    /// Defaults to the namespace this credential is confined to.
    #[arg(long, short = 'n', value_name = "NAMESPACE")]
    pub namespace: Option<String>,
    /// A JSON file holding the per-namespace configuration, or `-` for stdin.
    /// Most plugins need none.
    #[arg(long, short = 'f', value_name = "FILE")]
    pub file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct SetArgs {
    pub id: String,
    /// A JSON file holding the configuration object, or `-` for stdin.
    #[arg(long, short = 'f', value_name = "FILE")]
    pub file: PathBuf,
    /// Also enable the plugin. Without this the enabled state is unchanged.
    #[arg(long)]
    pub enable: bool,
}

pub fn run(ctx: &Ctx, cmd: &PluginsCmd) -> Result<()> {
    match cmd {
        PluginsCmd::List { namespace: None } => list(ctx),
        PluginsCmd::List { namespace: Some(ns) } => list_namespace(ctx, ns),
        PluginsCmd::Describe { id } => describe(ctx, id),
        PluginsCmd::Enable { id } => report(ctx.client.set_plugin(id, true, None)?),
        PluginsCmd::Disable { id } => report(ctx.client.set_plugin(id, false, None)?),
        PluginsCmd::Set(args) => set(ctx, args),
        PluginsCmd::Install(args) => install(ctx, args),
        PluginsCmd::Uninstall { id, namespace } => {
            let ns = ctx.namespace(namespace.as_deref())?;
            let p = ctx.client.uninstall_plugin(&ns, id)?;
            eprintln!("{} uninstalled from namespace {ns:?}.", p.id);
            Ok(())
        }
        PluginsCmd::Installs { id } => installs(ctx, id),
    }
}

fn read_json(file: &std::path::Path) -> Result<Value> {
    let text = if file.as_os_str() == "-" {
        std::io::read_to_string(std::io::stdin()).context("reading configuration from stdin")?
    } else {
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?
    };
    serde_json::from_str(&text).context("the configuration is not valid JSON")
}

fn namespace_state(p: &NamespacePlugin) -> &'static str {
    match (p.installed, p.enabled) {
        (true, true) => "installed",
        // Installed, but the operator has it off: nothing runs for anyone.
        (true, false) => "installed (disabled for the fleet)",
        (false, true) => "available",
        (false, false) => "disabled for the fleet",
    }
}

fn list_namespace(ctx: &Ctx, ns: &str) -> Result<()> {
    if ctx.out.is_machine() {
        let raw = ctx.client.raw().namespace_plugins(ns)?;
        let names: Vec<String> = raw
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| p.get("id").and_then(Value::as_str))
                    .map(|id| format!("plugin/{id}"))
                    .collect()
            })
            .unwrap_or_default();
        return output::emit(&raw, ctx.out, &names);
    }
    let plugins = ctx.client.namespace_plugins(ns)?;
    if plugins.is_empty() {
        println!("This app-lb has no plugins that install per namespace.");
        return Ok(());
    }
    let mut table = Table::new(["ID", "NAME", "STATE", "INSTALLED", "DASHBOARD", "DESCRIPTION"]);
    for p in &plugins {
        // Only where it would open: the page answers an uninstalled or
        // switched-off plugin with an explanation, not the dashboard.
        let dashboard = match (&p.dashboard, p.enabled && p.installed) {
            (Some(_), true) => format!("/namespaces/{ns}/plugin-console/{}", p.id),
            _ => "-".into(),
        };
        table.row([
            p.id.clone(),
            p.name.clone(),
            namespace_state(p).to_string(),
            p.installed_at.map(output::timestamp).unwrap_or_else(|| "-".into()),
            dashboard,
            p.description.clone(),
        ]);
    }
    table.print();
    Ok(())
}

fn install(ctx: &Ctx, args: &InstallArgs) -> Result<()> {
    let ns = ctx.namespace(args.namespace.as_deref())?;
    let config = args.file.as_deref().map(read_json).transpose()?;
    let p = ctx.client.install_plugin(&ns, &args.id, config.as_ref())?;
    eprintln!("{} installed in namespace {ns:?}.", p.id);
    if p.id == crate::OBS_PLUGIN {
        eprintln!(
            "Telemetry for every deployment in {ns:?} is collected from now on. \
             Read it with `heyctl top -n {ns}` and `heyctl logs <deployment> -n {ns}`."
        );
    }
    if p.dashboard.is_some() && p.enabled {
        eprintln!("Its dashboard is at /namespaces/{ns}/plugin-console/{} on app-lb.", p.id);
    }
    Ok(())
}

fn installs(ctx: &Ctx, id: &str) -> Result<()> {
    if ctx.out.is_machine() {
        let raw = ctx.client.raw().plugin_installs(id)?;
        let names: Vec<String> = raw
            .get("namespaces")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(|n| format!("namespace/{n}"))
                    .collect()
            })
            .unwrap_or_default();
        return output::emit(&raw, ctx.out, &names);
    }
    let i = ctx.client.plugin_installs(id)?;
    if !i.enabled {
        eprintln!("note: {id} is disabled for the fleet, so no namespace is served.");
    }
    if i.installs.is_empty() {
        println!("{id} is not installed in any namespace.");
        return Ok(());
    }
    let mut table = Table::new(["NAMESPACE", "INSTALLED", "BY"]);
    for (ns, install) in &i.installs {
        table.row([
            ns.clone(),
            output::timestamp(install.installed_at),
            install.installed_by.clone().unwrap_or_else(|| "operator".into()),
        ]);
    }
    table.print();
    Ok(())
}

fn state_cell(p: &PluginView) -> &'static str {
    match (p.enabled, p.last_error.is_some()) {
        (true, true) => "error",
        (true, false) => "enabled",
        (false, _) => "disabled",
    }
}

fn list(ctx: &Ctx) -> Result<()> {
    if ctx.out.is_machine() {
        let raw = ctx.client.raw().plugins()?;
        let names: Vec<String> = raw
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| p.get("id").and_then(Value::as_str))
                    .map(|id| format!("plugin/{id}"))
                    .collect()
            })
            .unwrap_or_default();
        return output::emit(&raw, ctx.out, &names);
    }
    let plugins = ctx.client.plugins()?;
    if plugins.is_empty() {
        println!("This app-lb has no plugins.");
        return Ok(());
    }
    let mut table = Table::new(["ID", "NAME", "STATE", "DESCRIPTION"]);
    for p in &plugins {
        table.row([
            p.id.clone(),
            p.name.clone(),
            state_cell(p).to_string(),
            p.description.clone(),
        ]);
    }
    table.print();
    Ok(())
}

fn describe(ctx: &Ctx, id: &str) -> Result<()> {
    if ctx.out.is_machine() {
        let raw = ctx.client.raw().plugins()?;
        let one = raw
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|p| p.get("id").and_then(Value::as_str) == Some(id))
            })
            .cloned();
        let Some(one) = one else {
            bail!("no plugin named {id:?}")
        };
        return output::emit(&one, ctx.out, &[format!("plugin/{id}")]);
    }
    print_plugin(&ctx.client.plugin(id)?);
    Ok(())
}

fn set(ctx: &Ctx, args: &SetArgs) -> Result<()> {
    let config = read_json(&args.file)?;
    let enabled = args.enable || ctx.client.plugin(&args.id)?.enabled;
    report(ctx.client.set_plugin(&args.id, enabled, Some(&config))?)
}

/// A write succeeded if the record was saved; say so, and say loudly if
/// applying it did not.
fn report(p: PluginView) -> Result<()> {
    match &p.last_error {
        Some(e) if p.enabled => {
            eprintln!("{} is enabled, but it failed to start: {e}", p.id);
        }
        _ => eprintln!(
            "{} {}.",
            p.id,
            if p.enabled { "enabled" } else { "disabled" }
        ),
    }
    Ok(())
}

fn print_plugin(p: &PluginView) {
    output::section("Plugin");
    output::field("ID", &p.id);
    output::field("Name", &p.name);
    output::field("State", state_cell(p));
    output::field("Description", &p.description);
    if let Some(e) = &p.last_error {
        output::field("Last error", e);
    }
    output::section("Configuration");
    println!(
        "{}",
        serde_json::to_string_pretty(&p.config).unwrap_or_default()
    );
    output::section("Status");
    println!(
        "{}",
        serde_json::to_string_pretty(&p.status).unwrap_or_default()
    );
}
