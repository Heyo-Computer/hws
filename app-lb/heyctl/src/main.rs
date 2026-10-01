//! heyctl — a kubectl-shaped CLI for the app-lb admin API.
//!
//! The verbs mirror kubectl because the mental model is the same: declarative
//! specs you `apply`, imperative helpers (`create`, `scale`, `set`) that write
//! those specs for you, and read commands (`get`, `describe`, `top`) that render
//! them back. What it drives is app-lb's admin API — deployments, their microVM
//! pools, and the certificates app-lb issues for their hostnames.
//!
//! Two shapes of deployment exist and the difference surfaces everywhere: a
//! *managed* one owns an autoscaled pool of Firecracker/KVM VMs, while a
//! *static* one proxy_passes to fixed upstreams and has neither a scaling policy
//! nor VMs to evict.

// The whole implementation is the library: this binary is argument parsing and
// dispatch. That is the point of the split — every command below runs through
// the same client an SDK caller gets, so a field the client stops understanding
// breaks the build here rather than blanking a column at somebody's terminal.
use hws::cmd;
use hws::cmd::GlobalOpts;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use cmd::Ctx;

#[derive(Parser, Debug)]
#[command(
    name = "heyctl",
    version,
    about = "Control an app-lb load balancer: deployments, scaling, VM pools and certificates",
    long_about = "heyctl drives app-lb's admin API.\n\n\
                  By default it talks to http://127.0.0.1:9090 — app-lb's admin listener binds \
                  loopback and speaks plaintext HTTP, so reach a remote one over an SSH tunnel \
                  (ssh -L 9090:127.0.0.1:9090 host) or through app-lb's own TLS listener, and \
                  save it with `heyctl login`.",
    propagate_version = true,
    max_term_width = 100
)]
struct Cli {
    #[command(flatten)]
    globals: GlobalOpts,

    #[command(subcommand)]
    command: Command,
}


#[derive(Subcommand, Debug)]
enum Command {
    /// Verify credentials against a server and save them as a context.
    Login(cmd::auth::LoginArgs),

    /// Forget a stored context, or just its password.
    Logout(cmd::auth::LogoutArgs),

    /// Show which server and identity the next command would use, and what it
    /// is allowed to do.
    Whoami,

    /// Mint, list and revoke app-tokens — the credential a program
    /// authenticates with.
    #[command(subcommand)]
    Token(cmd::token::TokenCmd),

    /// Read a namespace's event feed — the RSS of deployments that opted in.
    Feed(cmd::feed::FeedArgs),

    /// List, enable, disable and configure app-lb's built-in plugins.
    #[command(subcommand, visible_alias = "plugin")]
    Plugins(cmd::plugins::PluginsCmd),

    /// Manage stored contexts.
    Config {
        #[command(subcommand)]
        cmd: cmd::auth::ConfigCmd,
    },

    /// List deployments, VMs, certificates, secrets, auth providers, jobs or
    /// disks.
    #[command(visible_alias = "list")]
    Get(cmd::read::GetArgs),

    /// Show everything about a deployment — spec, pool, backends and traffic —
    /// or about an auth provider.
    Describe(cmd::read::DescribeArgs),

    /// Register a deployment, store a secret, or declare a namespace or auth
    /// provider.
    Create {
        #[command(subcommand)]
        cmd: CreateCmd,
    },

    /// Build a managed deployment's guest image from its Dockerfile — out of a
    /// git checkout or an artifact store — and roll the pool onto the result.
    Build(cmd::write::BuildArgs),

    /// Pull a managed deployment's guest rootfs from an artifact store, and
    /// roll the pool onto it. The alternative to `build` for a deployment whose
    /// image somebody else already made.
    Pull(cmd::write::PullArgs),

    /// Unpack a managed deployment's guest mounts from an artifact store.
    ///
    /// Usually unnecessary: registering or editing a deployment whose mounts
    /// have no tree on the app-lb host starts one of these automatically.
    #[command(subcommand)]
    Mounts(MountsCmd),

    /// Talk to an artifact store: log in, and push guest images others can pull.
    ///
    /// A store is a separate service from app-lb, so these commands use their
    /// own saved registries rather than the `--server` context.
    #[command(visible_aliases = ["art", "registry"])]
    Artifact {
        #[command(flatten)]
        opts: cmd::artifact::RegistryOpts,
        #[command(subcommand)]
        cmd: cmd::artifact::ArtifactCmd,
    },

    /// Update a static (proxy_pass) deployment: run its commands in its working
    /// directory on the app-lb host, then check that its upstreams came back.
    Update(cmd::write::UpdateArgs),

    /// Create or replace deployments from a spec file (JSON or YAML).
    Apply(cmd::write::ApplyArgs),

    /// Fetch a deployment's spec, open it in $EDITOR, and put it back.
    Edit(cmd::write::EditArgs),

    /// Change one part of a deployment in place.
    Set {
        #[command(subcommand)]
        cmd: SetCmd,
    },

    /// Change a deployment's scaling policy.
    #[command(visible_alias = "autoscale")]
    Scale(cmd::write::ScaleArgs),

    /// Recycle a deployment's VMs, one eviction at a time.
    Restart(cmd::write::RestartArgs),

    /// Stop new requests to one static upstream and return immediately.
    Cordon(cmd::write::CordonArgs),

    /// Cordon one static upstream and wait for its in-flight requests to finish.
    Drain(cmd::write::DrainArgs),

    /// Return a cordoned static upstream to traffic when it is healthy.
    Uncordon(cmd::write::UncordonArgs),

    /// Watch a pool converge on its desired size.
    Rollout {
        #[command(subcommand)]
        cmd: RolloutCmd,
    },

    /// Run one command inside a deployment's VM and print what it wrote.
    ///
    /// Goes through app-lb, not the heyvm daemon, so it works wherever the admin
    /// API does and starts a VM for a deployment that has none running. The
    /// guest's exit code becomes heyctl's.
    Exec(cmd::session::ExecArgs),

    /// Open an interactive shell in a deployment's VM.
    ///
    /// Together with `exec`, the only way into a deployment registered with no
    /// routes — an agent sandbox, which takes no HTTP traffic at all.
    #[command(visible_alias = "ssh")]
    Shell(cmd::session::ShellArgs),

    /// Deregister a deployment, or evict a VM from one.
    #[command(visible_alias = "rm")]
    Delete(cmd::write::DeleteArgs),

    /// Resource usage for deployments, VMs or the host.
    Top(cmd::observe::TopArgs),

    /// A whole-LB overview: uptime, host, fleet and traffic.
    #[command(visible_alias = "cluster-info")]
    Status,

    /// Print a shell completion script.
    Completion {
        /// bash, zsh, fish, elvish or powershell.
        #[arg(value_name = "SHELL")]
        shell: Shell,
    },
}

#[derive(Subcommand, Debug)]
enum CreateCmd {
    /// Register a deployment: a managed VM pool, or a static proxy_pass target.
    #[command(visible_aliases = ["deploy", "dep"])]
    Deployment(Box<cmd::write::CreateDeploymentArgs>),

    /// Store secret values — a git token, an API key. Values go in and are
    /// never readable back out; deployments refer to them by name.
    #[command(visible_alias = "sec")]
    Secret(cmd::write::CreateSecretArgs),

    /// Register a CI workflow: which repository the `ci` orchestrator builds,
    /// and on which heyvm network.
    #[command(visible_aliases = ["wf", "flow"])]
    Workflow(cmd::write::CreateWorkflowArgs),

    /// Declare a namespace, so it exists before anything is in it.
    ///
    /// Deployments may name a namespace that was never declared — that keeps
    /// working. Declaring one lets you make the room first and say what it is
    /// for. Fleet-scoped admin only.
    #[command(visible_alias = "ns")]
    Namespace(cmd::write::CreateNamespaceArgs),

    /// Declare an auth provider: who may enter and how they are verified,
    /// named once and inherited by any deployment in the namespace.
    ///
    /// The identity half of a sign-in gate on its own. Deployments inherit it
    /// with `heyctl set auth <deployment> --provider-ref <name>`, and app-lb
    /// resolves it on every gated request — so editing the provider reaches
    /// every deployment that names it, and rotating a key is one command.
    #[command(visible_aliases = ["provider", "idp"])]
    AuthProvider(Box<cmd::write::CreateAuthProviderArgs>),
}

#[derive(Subcommand, Debug)]
enum SetCmd {
    /// Point a managed deployment at a different guest image. The pool is
    /// rebuilt, because the running VMs were made from the old one.
    Image(cmd::write::SetImageArgs),

    /// Set or remove guest environment variables (`KEY=VALUE`, or `KEY-`).
    /// Rebuilds the pool for the same reason.
    Env(cmd::write::SetEnvArgs),

    /// Replace a static deployment's upstream addresses.
    Upstreams(cmd::write::SetUpstreamsArgs),

    /// Replace (or, with --add, extend) a deployment's route rules.
    #[command(visible_alias = "routes")]
    Route(cmd::write::SetRouteArgs),

    /// Set where a managed deployment's image is built from: a git repo and
    /// Dockerfile, or a Dockerfile manifest in an artifact store. Recording it
    /// changes nothing on its own — `heyctl build` runs it.
    Build(cmd::write::SetBuildArgs),

    /// Set where a managed deployment's image is *pulled* from: an artifact
    /// store and a reference. Recording it changes nothing on its own —
    /// `heyctl pull` runs it. Mutually exclusive with `set build`.
    #[command(visible_alias = "art")]
    Artifact(cmd::write::SetArtifactArgs),

    /// Set how a static deployment is updated: a working directory on the app-lb
    /// host and the commands to run in it. `heyctl update` runs them.
    Update(cmd::write::SetUpdateArgs),

    /// Put a deployment behind a sign-in gate, or change who may enter: Google
    /// inline with --client-id, or a namespace auth provider with
    /// --provider-ref. Applies to either kind of deployment; the application
    /// behind it is unchanged.
    Auth(cmd::write::SetAuthArgs),

    /// Rotate keys of a stored secret (`KEY=VALUE`, or `KEY-`). Keys you don't
    /// mention are left alone.
    #[command(visible_alias = "sec")]
    Secret(cmd::write::SetSecretArgs),
}

#[derive(Subcommand, Debug)]
enum MountsCmd {
    /// Unpack every mount the spec declares, then roll the pool onto the trees.
    Pull(cmd::write::MountPullArgs),
}

#[derive(Subcommand, Debug)]
enum RolloutCmd {
    /// Wait until a deployment's pool is at its desired size and healthy.
    Status(cmd::write::RolloutStatusArgs),

    /// Recycle a deployment's VMs (the same thing as `heyctl restart`).
    Restart(cmd::write::RestartArgs),
}

fn main() {
    // Rust ignores SIGPIPE, which turns `heyctl get deployments | head` into
    // a panic on the first write past the closed pipe. Restore the default
    // disposition so the process just ends, like every other CLI in a pipeline.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();
    if let Err(e) = run(&cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<()> {
    let g = &cli.globals;
    match &cli.command {
        // These touch the config file and build at most their own client, so
        // they must keep working against an unreachable server.
        Command::Login(args) => cmd::auth::login(g, args),
        Command::Logout(args) => cmd::auth::logout(g, args),
        Command::Config { cmd } => cmd::auth::config(g, cmd),
        Command::Whoami => cmd::auth::whoami(g),
        Command::Token(cmd) => cmd::token::run(&Ctx::new(g)?, cmd),
        Command::Feed(args) => cmd::feed::run(&Ctx::new(g)?, args),
        Command::Plugins(cmd) => cmd::plugins::run(&Ctx::new(g)?, cmd),
        Command::Completion { shell } => {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            clap_complete::generate(*shell, &mut command, name, &mut std::io::stdout());
            Ok(())
        }

        // An artifact store is not an app-lb, so these build their own client
        // from a saved registry and never touch `Ctx`.
        Command::Artifact { opts, cmd } => cmd::artifact::run(g, opts, cmd),

        Command::Get(args) => cmd::read::get(&Ctx::new(g)?, args),
        Command::Describe(args) => cmd::read::describe(&Ctx::new(g)?, args),
        Command::Create { cmd } => match cmd {
            CreateCmd::Deployment(args) => cmd::write::create(&Ctx::new(g)?, args),
            CreateCmd::Secret(args) => cmd::write::create_secret(&Ctx::new(g)?, args),
            CreateCmd::Workflow(args) => cmd::write::create_workflow(&Ctx::new(g)?, args),
            CreateCmd::Namespace(args) => cmd::write::create_namespace(&Ctx::new(g)?, args),
            CreateCmd::AuthProvider(args) => {
                cmd::write::create_auth_provider(&Ctx::new(g)?, args)
            }
        },
        Command::Build(args) => cmd::write::build(&Ctx::new(g)?, args),
        Command::Pull(args) => cmd::write::pull(&Ctx::new(g)?, args),
        Command::Mounts(MountsCmd::Pull(args)) => cmd::write::pull_mounts(&Ctx::new(g)?, args),
        Command::Update(args) => cmd::write::update(&Ctx::new(g)?, args),
        Command::Apply(args) => cmd::write::apply(&Ctx::new(g)?, args),
        Command::Edit(args) => cmd::write::edit(&Ctx::new(g)?, args),
        Command::Set { cmd } => {
            let ctx = Ctx::new(g)?;
            match cmd {
                SetCmd::Image(args) => cmd::write::set_image(&ctx, args),
                SetCmd::Env(args) => cmd::write::set_env(&ctx, args),
                SetCmd::Upstreams(args) => cmd::write::set_upstreams(&ctx, args),
                SetCmd::Route(args) => cmd::write::set_route(&ctx, args),
                SetCmd::Build(args) => cmd::write::set_build(&ctx, args),
                SetCmd::Artifact(args) => cmd::write::set_artifact(&ctx, args),
                SetCmd::Update(args) => cmd::write::set_update(&ctx, args),
                SetCmd::Auth(args) => cmd::write::set_auth(&ctx, args),
                SetCmd::Secret(args) => cmd::write::set_secret(&ctx, args),
            }
        }
        Command::Scale(args) => cmd::write::scale(&Ctx::new(g)?, args),
        Command::Restart(args) => cmd::write::restart(&Ctx::new(g)?, args),
        Command::Cordon(args) => cmd::write::cordon(&Ctx::new(g)?, args),
        Command::Drain(args) => cmd::write::drain(&Ctx::new(g)?, args),
        Command::Uncordon(args) => cmd::write::uncordon(&Ctx::new(g)?, args),
        Command::Rollout { cmd } => {
            let ctx = Ctx::new(g)?;
            match cmd {
                RolloutCmd::Status(args) => cmd::write::rollout_status(&ctx, args),
                RolloutCmd::Restart(args) => cmd::write::restart(&ctx, args),
            }
        }
        Command::Exec(args) => cmd::session::exec(&Ctx::new(g)?, args),
        Command::Shell(args) => cmd::session::shell(&Ctx::new(g)?, args),
        Command::Delete(args) => cmd::write::delete(&Ctx::new(g)?, args),
        Command::Top(args) => cmd::observe::top(&Ctx::new(g)?, args),
        Command::Status => cmd::observe::status(&Ctx::new(g)?),
    }
}

#[cfg(test)]
mod tests {
    use hws::output::OutputFormat;
    use super::*;

    #[test]
    fn the_cli_definition_is_well_formed() {
        // Catches duplicated flags, bad aliases and broken `requires`/
        // `conflicts_with` references, which clap only validates at runtime.
        Cli::command().debug_assert();
    }

    #[test]
    fn global_flags_are_accepted_after_the_subcommand() {
        let cli = Cli::try_parse_from([
            "heyctl",
            "get",
            "deployments",
            "-o",
            "json",
            "--server",
            "http://lb:9090",
        ])
        .unwrap();
        assert_eq!(cli.globals.output, OutputFormat::Json);
        assert_eq!(cli.globals.server.as_deref(), Some("http://lb:9090"));
    }

    #[test]
    fn scale_rejects_replicas_together_with_a_band() {
        assert!(
            Cli::try_parse_from(["heyctl", "scale", "web", "--replicas", "2", "--min", "1"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["heyctl", "scale", "web", "--replicas", "2"]).is_ok());
    }

    /// The three identity shapes are alternatives, and one of them is required:
    /// a provider with no identity at all would be a name and nothing else.
    #[test]
    fn creating_an_auth_provider_needs_exactly_one_identity_shape() {
        assert!(
            Cli::try_parse_from(["heyctl", "create", "auth-provider", "heyo"]).is_err(),
            "no identity given"
        );
        assert!(
            Cli::try_parse_from([
                "heyctl", "create", "auth-provider", "heyo",
                "--preset", "heyo", "--issuer", "auth-service",
            ])
            .is_err(),
            "a preset and a hand-written issuer are two answers to one question"
        );
        // The preset form: an issuer app-lb knows, from a stored key.
        assert!(
            Cli::try_parse_from([
                "heyctl", "create", "auth-provider", "heyo", "-n", "team-a",
                "--preset", "heyo", "--secret", "heyo-auth/jwt_secret",
            ])
            .is_ok()
        );
        // The bring-your-own form: any issuer, verified against its key set.
        assert!(
            Cli::try_parse_from([
                "heyctl", "create", "provider", "okta",
                "--issuer", "https://example.okta.com",
                "--jwks-url", "https://example.okta.com/oauth2/v1/keys",
                "--alg", "RS256",
                "--require", "groups=engineering,ops",
            ])
            .is_ok()
        );
    }

    /// Inheriting an identity and writing one inline are mutually exclusive —
    /// app-lb refuses a gate that carries both, so clap refuses it first.
    #[test]
    fn a_gate_either_inherits_an_identity_or_writes_one() {
        assert!(
            Cli::try_parse_from([
                "heyctl", "set", "auth", "web", "--provider-ref", "heyo",
                "--client-id", "1234.apps.googleusercontent.com",
            ])
            .is_err()
        );
        // Route-scoped flags still belong to the deployment.
        assert!(
            Cli::try_parse_from([
                "heyctl", "set", "auth", "web", "--provider-ref", "heyo",
                "--public-path", "/healthz",
            ])
            .is_ok()
        );
    }

    #[test]
    fn create_takes_the_shorthand_and_long_route_forms() {
        let cli = Cli::try_parse_from([
            "heyctl",
            "create",
            "deployment",
            "web",
            "--host",
            "web.local",
            "--port",
            "8080",
            "--route",
            "path=/api",
            "-e",
            "RUST_LOG=info",
        ])
        .unwrap();
        let Command::Create {
            cmd: CreateCmd::Deployment(args),
        } = &cli.command
        else {
            panic!("expected create deployment");
        };
        assert_eq!(args.host.as_deref(), Some("web.local"));
        assert_eq!(args.port, Some(8080));
        assert_eq!(args.routes, vec!["path=/api".to_string()]);
        assert_eq!(args.env, vec!["RUST_LOG=info".to_string()]);
    }

    #[test]
    fn create_accepts_an_orchestrator_discovery_service() {
        let cli = Cli::try_parse_from([
            "heyctl",
            "create",
            "deployment",
            "cloud",
            "--host",
            "cloud.example.com",
            "--discovery-service",
            "cloud",
        ])
        .unwrap();
        let Command::Create {
            cmd: CreateCmd::Deployment(args),
        } = &cli.command
        else {
            panic!("expected create deployment");
        };
        assert_eq!(args.discovery_service.as_deref(), Some("cloud"));
        assert_eq!(args.port, None);
    }

    #[test]
    fn create_takes_a_build_source() {
        let cli = Cli::try_parse_from([
            "heyctl",
            "create",
            "deployment",
            "web",
            "--host",
            "web.local",
            "--port",
            "8080",
            "--repo",
            "https://github.com/acme/web.git",
            "--ref",
            "main",
            "--secret",
            "github/token",
        ])
        .unwrap();
        let Command::Create {
            cmd: CreateCmd::Deployment(args),
        } = &cli.command
        else {
            panic!("expected create deployment");
        };
        assert_eq!(args.repo.as_deref(), Some("https://github.com/acme/web.git"));
        assert_eq!(args.git_ref.as_deref(), Some("main"));
        assert_eq!(args.secret.as_deref(), Some("github/token"));

        // The build knobs describe a repo, so they need one.
        assert!(
            Cli::try_parse_from([
                "heyctl", "create", "deployment", "web", "--host", "w.local", "--port", "80",
                "--ref", "main",
            ])
            .is_err(),
            "--ref without --repo should be refused"
        );
    }

    #[test]
    fn a_secret_can_be_created_without_putting_the_value_on_the_command_line() {
        let cli = Cli::try_parse_from([
            "heyctl",
            "create",
            "secret",
            "github",
            "--from-stdin",
            "token",
            "--description",
            "CI PAT",
        ])
        .unwrap();
        let Command::Create {
            cmd: CreateCmd::Secret(args),
        } = &cli.command
        else {
            panic!("expected create secret");
        };
        assert_eq!(args.name, "github");
        assert_eq!(args.sources.from_stdin.as_deref(), Some("token"));
        assert!(args.literals.is_empty());
        assert_eq!(args.description.as_deref(), Some("CI PAT"));
    }

    #[test]
    fn build_takes_a_one_off_ref_and_can_wait() {
        let cli =
            Cli::try_parse_from(["heyctl", "build", "web", "--ref", "v2.1", "--wait"]).unwrap();
        let Command::Build(args) = &cli.command else {
            panic!("expected build");
        };
        assert_eq!(args.resource, "web");
        assert_eq!(args.git_ref.as_deref(), Some("v2.1"));
        assert!(args.wait);
    }

    #[test]
    fn update_takes_a_working_directory_and_commands() {
        let cli = Cli::try_parse_from([
            "heyctl",
            "set",
            "update",
            "app-obs",
            "--workdir",
            "/srv/app-obs",
            "-c",
            "git pull --ff-only",
            "-c",
            "cargo build --release",
            "-c",
            "supervisorctl restart app-obs",
            "--secret-env",
            "APP_OBS_INGEST_TOKEN=obs/ingest_token",
            "--verify-timeout",
            "90",
        ])
        .unwrap();
        let Command::Set {
            cmd: SetCmd::Update(args),
        } = &cli.command
        else {
            panic!("expected set update");
        };
        assert_eq!(args.working_dir.as_deref(), Some("/srv/app-obs"));
        assert_eq!(args.commands.len(), 3);
        assert_eq!(args.commands[0], "git pull --ff-only");
        assert_eq!(args.secret_env, vec!["APP_OBS_INGEST_TOKEN=obs/ingest_token"]);
        assert_eq!(args.verify_timeout_secs, Some(90));
    }

    #[test]
    fn running_an_update_can_wait_and_stream() {
        let cli = Cli::try_parse_from(["heyctl", "update", "app-obs", "--logs"]).unwrap();
        let Command::Update(args) = &cli.command else {
            panic!("expected update");
        };
        assert_eq!(args.resource, "app-obs");
        assert!(args.logs);
        assert!(!args.wait, "--logs implies waiting without setting the flag");
    }

    #[test]
    fn a_gate_takes_a_client_id_a_secret_and_an_allow_list() {
        let cli = Cli::try_parse_from([
            "heyctl",
            "set",
            "auth",
            "web",
            "--client-id",
            "cid.apps.googleusercontent.com",
            "--secret",
            "google/client_secret",
            "--allow-domain",
            "example.com",
            "--allow-email",
            "contractor@gmail.com",
            "--public-path",
            "/healthz",
        ])
        .unwrap();
        let Command::Set {
            cmd: SetCmd::Auth(args),
        } = &cli.command
        else {
            panic!("expected set auth");
        };
        assert_eq!(args.client_id.as_deref(), Some("cid.apps.googleusercontent.com"));
        assert_eq!(args.secret.as_deref(), Some("google/client_secret"));
        assert_eq!(args.allow_domains, vec!["example.com".to_string()]);
        assert_eq!(args.allow_emails, vec!["contractor@gmail.com".to_string()]);
        assert_eq!(args.public_paths, vec!["/healthz".to_string()]);
        assert!(!args.clear);
    }

    #[test]
    fn clearing_a_gate_excludes_editing_it() {
        assert!(Cli::try_parse_from(["heyctl", "set", "auth", "web", "--clear"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "heyctl", "set", "auth", "web", "--clear", "--allow-domain", "example.com",
            ])
            .is_err(),
            "--clear and --allow-domain say opposite things"
        );
    }

    #[test]
    fn clearing_an_update_excludes_editing_it() {
        assert!(Cli::try_parse_from(["heyctl", "set", "update", "obs", "--clear"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "heyctl", "set", "update", "obs", "--clear", "-c", "make deploy",
            ])
            .is_err(),
            "--clear and --command say opposite things"
        );
    }

    #[test]
    fn a_pull_takes_a_one_off_ref_and_can_wait() {
        let cli = Cli::try_parse_from([
            "heyctl", "pull", "web", "--ref", "debian-hermes", "--wait",
        ])
        .unwrap();
        let Command::Pull(args) = &cli.command else {
            panic!("expected pull");
        };
        assert_eq!(args.resource, "web");
        assert_eq!(args.artifact_ref.as_deref(), Some("debian-hermes"));
        assert!(args.wait);
        assert!(!args.force);
    }

    #[test]
    fn an_artifact_source_takes_a_store_and_a_ref() {
        let cli = Cli::try_parse_from([
            "heyctl",
            "set",
            "artifact",
            "web",
            "--store",
            "http://127.0.0.1:8080",
            "--ref",
            "debian-hermes",
            "--grow-gb",
            "8",
            "--secret",
            "art/api_key",
        ])
        .unwrap();
        let Command::Set {
            cmd: SetCmd::Artifact(args),
        } = &cli.command
        else {
            panic!("expected set artifact");
        };
        assert_eq!(args.store.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(args.artifact_ref.as_deref(), Some("debian-hermes"));
        assert_eq!(args.grow_gb, Some(8));
        assert_eq!(args.secret.as_deref(), Some("art/api_key"));
    }

    #[test]
    fn clearing_an_artifact_source_excludes_editing_it() {
        assert!(Cli::try_parse_from(["heyctl", "set", "artifact", "web", "--clear"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "heyctl", "set", "artifact", "web", "--clear", "--ref", "debian-hermes",
            ])
            .is_err(),
            "--clear and --ref say opposite things"
        );
    }

    #[test]
    fn a_push_takes_a_file_or_an_image_but_not_both() {
        let cli = Cli::try_parse_from([
            "heyctl", "artifact", "push", "/tmp/rootfs.ext4", "--tag", "web-v2",
        ])
        .unwrap();
        let Command::Artifact {
            cmd: cmd::artifact::ArtifactCmd::Push(args),
            ..
        } = &cli.command
        else {
            panic!("expected artifact push");
        };
        assert_eq!(args.file.as_deref(), Some(std::path::Path::new("/tmp/rootfs.ext4")));
        assert_eq!(args.tag.as_deref(), Some("web-v2"));

        assert!(
            Cli::try_parse_from(["heyctl", "artifact", "push", "--image", "artifacts"]).is_ok(),
            "--image is the other way to name the source"
        );
        assert!(
            Cli::try_parse_from([
                "heyctl", "artifact", "push", "/tmp/a.ext4", "--image", "artifacts",
            ])
            .is_err(),
            "a path and an image name are two answers to one question"
        );
        // Something has to be pushed.
        assert!(Cli::try_parse_from(["heyctl", "artifact", "push"]).is_err());
        // And a tag cannot be both given and refused.
        assert!(
            Cli::try_parse_from([
                "heyctl", "artifact", "push", "/tmp/a.ext4", "--tag", "x", "--no-tag",
            ])
            .is_err()
        );
    }

    #[test]
    fn login_takes_a_token_instead_of_a_pair() {
        let cli = Cli::try_parse_from([
            "heyctl",
            "login",
            "--server",
            "https://server.heyo.computer/namespaces/team-a/lb",
            "--token-stdin",
            "--name",
            "team-a",
        ])
        .unwrap();
        let Command::Login(args) = &cli.command else {
            panic!("expected login");
        };
        assert!(args.token_stdin);
        assert_eq!(args.server.as_deref(), Some("https://server.heyo.computer/namespaces/team-a/lb"));
        assert_eq!(args.name.as_deref(), Some("team-a"));

        // A token and a Basic pair are alternatives on the same login.
        assert!(Cli::try_parse_from(["heyctl", "login", "--token", "heyo_api_x", "--user", "admin"]).is_err());
        assert!(Cli::try_parse_from(["heyctl", "login", "--token", "heyo_api_x", "--password-stdin"]).is_err());
        // The global flag exists for one-off commands.
        let cli = Cli::try_parse_from(["heyctl", "--token", "heyo_api_x", "get", "deployments"]).unwrap();
        assert_eq!(cli.globals.token.as_deref(), Some("heyo_api_x"));
    }

    #[test]
    fn artifact_login_takes_a_url_and_a_key_out_of_band() {
        let cli = Cli::try_parse_from([
            "heyctl",
            "artifact",
            "login",
            "http://art.example.com:8080",
            "--api-key-stdin",
            "--name",
            "prod-store",
        ])
        .unwrap();
        let Command::Artifact {
            cmd: cmd::artifact::ArtifactCmd::Login(args),
            ..
        } = &cli.command
        else {
            panic!("expected artifact login");
        };
        assert_eq!(args.url, "http://art.example.com:8080");
        assert!(args.api_key_stdin);
        assert_eq!(args.name.as_deref(), Some("prod-store"));

        // The three ways of supplying a key are alternatives, not a precedence
        // chain: two of them set would leave half the command a lie.
        assert!(
            Cli::try_parse_from([
                "heyctl", "artifact", "login", "http://art:8080", "--api-key", "k",
                "--api-key-stdin",
            ])
            .is_err()
        );
    }

    #[test]
    fn a_build_source_is_a_repo_or_a_store_and_never_both() {
        assert!(
            Cli::try_parse_from([
                "heyctl", "set", "build", "web", "--store", "http://art:8080", "--ref",
                "web-rootfs",
            ])
            .is_ok()
        );
        // The flags that only describe a checkout do not apply to a manifest,
        // which already names its recipe and its context.
        for conflicting in [
            vec!["--store", "http://art:8080", "--repo", "https://x/y.git"],
            vec!["--store", "http://art:8080", "--dockerfile", "deploy/Dockerfile"],
            vec!["--store", "http://art:8080", "--build-context", "."],
        ] {
            let mut argv = vec!["heyctl", "set", "build", "web"];
            argv.extend(conflicting.iter().copied());
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "{conflicting:?} should be refused"
            );
        }
    }

    #[test]
    fn create_takes_a_dockerfile_manifest_build_source() {
        let cli = Cli::try_parse_from([
            "heyctl",
            "create",
            "deployment",
            "web",
            "--host",
            "web.local",
            "--port",
            "8080",
            "--build-store",
            "http://art:8080",
            "--ref",
            "web-rootfs",
        ])
        .unwrap();
        let Command::Create {
            cmd: CreateCmd::Deployment(args),
        } = &cli.command
        else {
            panic!("expected create deployment");
        };
        assert_eq!(args.build_store.as_deref(), Some("http://art:8080"));
        assert_eq!(args.git_ref.as_deref(), Some("web-rootfs"));
        assert_eq!(args.repo, None);

        // A store has no default branch, so its ref is not optional.
        assert!(
            Cli::try_parse_from([
                "heyctl", "create", "deployment", "web", "--host", "w.local", "--port", "80",
                "--build-store", "http://art:8080",
            ])
            .is_err(),
            "--build-store without --ref should be refused"
        );
        // And the two sources stay alternatives.
        assert!(
            Cli::try_parse_from([
                "heyctl", "create", "deployment", "web", "--host", "w.local", "--port", "80",
                "--build-store", "http://art:8080", "--repo", "https://x/y.git", "--ref", "main",
            ])
            .is_err(),
            "--build-store and --repo say opposite things"
        );
    }

    #[test]
    fn pushing_a_dockerfile_takes_a_context_and_a_tag() {
        let cli = Cli::try_parse_from([
            "heyctl",
            "artifact",
            "push-dockerfile",
            "./Dockerfile",
            "--build-context",
            "./app",
            "--tag",
            "web-rootfs",
            "--size-mb",
            "4096",
        ])
        .unwrap();
        let Command::Artifact {
            cmd: cmd::artifact::ArtifactCmd::PushDockerfile(args),
            ..
        } = &cli.command
        else {
            panic!("expected artifact push-dockerfile");
        };
        assert_eq!(args.file, std::path::PathBuf::from("./Dockerfile"));
        assert_eq!(args.build_context.as_deref(), Some(std::path::Path::new("./app")));
        assert_eq!(args.tag.as_deref(), Some("web-rootfs"));
        assert_eq!(args.image_size_mb, Some(4096));

        // A tag and no-tag say opposite things.
        assert!(
            Cli::try_parse_from([
                "heyctl", "artifact", "push-dockerfile", "./Dockerfile", "--tag", "x",
                "--no-tag",
            ])
            .is_err()
        );
    }

    #[test]
    fn clearing_a_build_source_excludes_editing_it() {
        assert!(Cli::try_parse_from(["heyctl", "set", "build", "web", "--clear"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "heyctl", "set", "build", "web", "--clear", "--repo", "https://x/y.git",
            ])
            .is_err(),
            "--clear and --repo say opposite things"
        );
        // --username is only meaningful next to the secret it belongs to.
        assert!(
            Cli::try_parse_from(["heyctl", "set", "build", "web", "--username", "bot"]).is_err()
        );
    }
}
