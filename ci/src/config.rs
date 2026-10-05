//! Configuration, resolved from `CI_*` environment variables.
//!
//! There are no CLI arguments — the house convention (app-lb, queue-fn, app-obs)
//! is environment-only config, because the process is started by supervisord and
//! a flag that only exists in one unit file is a flag nobody finds.
//!
//! **A misconfiguration is a startup failure, not a degraded service.** Every
//! value is resolved and validated in [`Config::from_env`] before anything binds
//! a port or dials NATS, and every [`ConfigError`] names the variable to fix.
//! The alternative — discovering at the first job that `CI_NETWORK` was never
//! set — costs a run and reads as a heyvm outage.
//!
//! One thing deliberately *not* here: the NATS credential. It lives in
//! [`crate::nats_auth::NatsEndpoint`], which has no `Debug` that reveals it, so a
//! `{:?}` on `Config` cannot print a password.

use crate::nats_auth::{EnvCredentials, NatsAuthError, NatsEndpoint};
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Where build artifacts go. Chosen once at startup; a workflow object may
/// override it per workflow later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactSinkKind {
    /// A directory on the orchestrator host.
    Disk,
    /// An S3 bucket.
    S3,
    /// The `artifacts` content-addressed store, over HTTP.
    Artifacts,
}

impl ArtifactSinkKind {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "disk" | "file" | "local" => Some(Self::Disk),
            "s3" => Some(Self::S3),
            "artifacts" | "art" => Some(Self::Artifacts),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disk => "disk",
            Self::S3 => "s3",
            Self::Artifacts => "artifacts",
        }
    }
}

#[derive(Debug, Clone)]
pub struct S3Config {
    pub bucket: String,
    pub prefix: String,
    pub region: Option<String>,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ArtifactsConfig {
    /// HTTP endpoint of the logical artifact store. All release participants
    /// must use the same global bucket/prefix, via the hub or regional caches.
    /// `ART_S3_BUCKET` belongs to art, not CI's separate raw-S3 sink. A daemon
    /// without a remote tier remains a standalone local store.
    pub url: String,
    pub token: Option<String>,
    /// The base URL a *guest* uses to reach the same store, when it differs
    /// from `url` (`CI_ARTIFACT_GUEST_URL`).
    ///
    /// `ci/upload-artifact` has the guest `curl -T` its tarball straight to
    /// the store rather than reading it out over the exec channel — which on
    /// firecracker is the emulated serial console, tens of KiB/s, so a 40 MB
    /// artifact took a quarter of an hour to leave the VM. The guest needs a
    /// URL it can resolve and route to: `url` is usually that, but an
    /// orchestrator that reaches its store as `http://localhost:…` or by a
    /// name only its own host knows sets this to the public one. Unset means
    /// `url`. A guest that cannot reach the store falls back to the exec
    /// channel, so a wrong value here costs time, not the artifact.
    pub guest_url: Option<String>,
}

impl ArtifactsConfig {
    /// The base URL to hand a guest: `guest_url` when set, else `url`.
    pub fn url_for_guest(&self) -> &str {
        self.guest_url.as_deref().unwrap_or(&self.url)
    }
}

/// Which of the account's networks this instance takes work for.
///
/// Not "every network the account has", by default, and the reason is
/// JetStream: jobs are sharded onto one durable consumer per runner and per
/// network precisely so several orchestrators can run at once **as long as they
/// own disjoint sets**. An instance that silently served everything would steal
/// another's work, so what it serves is configuration rather than discovery.
///
/// `*` opts into serving everything, which is the right answer for the single
/// instance most installations run — and is a decision that has been made rather
/// than one that happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServedNetworks {
    /// Every network on the account, including ones created after startup.
    All,
    /// Only these, by name or id. The first is the default for a repository
    /// that names none.
    Named(Vec<String>),
}

impl ServedNetworks {
    fn parse(raw: &str) -> Self {
        if raw.trim() == "*" {
            return Self::All;
        }
        Self::Named(
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        )
    }

    /// Whether a network is one this instance takes work for.
    ///
    /// Matched on id *or* name, because `CI_NETWORK` is written by a person and
    /// the dashboard shows both.
    pub fn includes(&self, id: &str, name: &str) -> bool {
        match self {
            Self::All => true,
            Self::Named(names) => names
                .iter()
                .any(|n| n == id || n.eq_ignore_ascii_case(name)),
        }
    }

    /// The network a repository with no assignment falls back to, when the
    /// configuration names one. `All` defers to the account's own default.
    pub fn preferred(&self) -> Option<&str> {
        match self {
            Self::All => None,
            Self::Named(names) => names.first().map(String::as_str),
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            Self::All => "*".to_string(),
            Self::Named(names) => names.join(","),
        }
    }
}

/// The heyvm control-plane connection and the networks whose hosts are runners.
#[derive(Debug, Clone)]
pub struct HeyvmConfig {
    /// Cloud base URL. `None` uses the SDK default (`https://server.heyo.computer`).
    pub base_url: Option<String>,
    /// Bearer for the cloud *and* for each runner daemon.
    pub api_key: String,
    /// Which networks this instance takes work for. Their `host` members are the
    /// runner pool; every other network on the account is still listed on the
    /// dashboard, marked as one this instance does not serve.
    pub networks: ServedNetworks,
    /// Which daemon `uses: default` means, when it cannot be worked out.
    ///
    /// Resolution order is: this, then the local daemon's own `backend_id`,
    /// then its name matched against the account's daemons, then `hd-local`
    /// under `CI_LOCAL_RUNNER`. This exists because `backend_id` is populated
    /// from the daemon's environment (`BACKEND_SERVER_ID`/`HEYVM_BACKEND_ID`)
    /// and may simply be absent — and the answer has to be the *real* daemon id,
    /// since it becomes a NATS subject. Two orchestrators both inventing
    /// `hd-local` would eat each other's jobs.
    pub default_node: Option<String>,
    /// Where the co-located daemon listens, for the `uses: default` probe.
    pub local_daemon_url: String,
    /// `~/.heyo/daemon.json` — heyvmd's persisted identity, and the id it
    /// registers with the cloud under. The authority for `uses: default`;
    /// `None` when there is no home directory to resolve it from.
    pub daemon_state_path: Option<PathBuf>,
    /// Optional iroh relay override for NAT traversal.
    pub relay: Option<String>,
    /// How often the runner set is re-read from the control plane.
    pub refresh_interval: Duration,
    /// How long a job waits for a runner that is never going to take it —
    /// pinned to an offline host, or on a queue with no consumer — before it
    /// is failed. Not a cap on waiting behind a busy runner: see `queue_wait`.
    pub runner_wait: Duration,
    /// How long a job may wait *on capacity* — queued behind work a live,
    /// bound consumer is busy with — before it is failed. `None` (the default)
    /// means as long as it takes: a job's own timeouts start when it is picked
    /// up, never while it is queued, so a backlog on one host is a wait, not a
    /// failure. `CI_QUEUE_WAIT_SECS` sets a cap for deployments that want one.
    pub queue_wait: Option<Duration>,
    /// Backstop TTL on every VM we create, so a crashed orchestrator does not
    /// strand a fleet. Renewed on the lease loop while a job holds the VM.
    ///
    /// Only running VMs are subject to TTL; durable cleanup owns deletion.
    pub vm_ttl: Duration,
    /// Drive one local `heyvmd` directly instead of discovering hosts through
    /// the cloud.
    ///
    /// `CI_LOCAL_RUNNER=1` uses `http://127.0.0.1:34099`; any other value is
    /// taken as the daemon's base URL. The pool becomes a single runner named
    /// `local`, and no iroh tunnel or cloud account is involved.
    ///
    /// This exists because the development loop otherwise needs a registered
    /// daemon *and* a network membership before a single job can run — and
    /// because it is the only configuration a test can assert against without a
    /// second machine. queue-fn is local-daemon-only for the same reason.
    pub local_runner: Option<String>,
    /// Optional bearer for a protected direct daemon. Separate from the Cloud
    /// credential: the host may trust a different internal API key.
    pub local_runner_token: Option<String>,
}

/// Default for `CI_ALLOW_UNAUTHENTICATED_RUNNERS`.
///
/// Refusing is the default because an iroh ticket is bearer-equivalent — a
/// daemon with no `JWT_SECRET` hands a host shell to anyone who has seen its
/// ticket. Opting out is for a single-machine loop where the tunnel never
/// leaves localhost.
const ALLOW_UNAUTHENTICATED_RUNNERS: bool = false;

#[derive(Debug)]
pub struct Config {
    pub name: String,
    pub listen_addr: SocketAddr,
    /// Absolute base URL this app is reachable at, with no trailing slash. Used
    /// for links in the dashboard and for exec-operation callbacks.
    pub public_url: String,

    pub heyvm: HeyvmConfig,

    pub nats: NatsEndpoint,
    /// Subject and stream namespace. Interpolated into subjects unescaped, so it
    /// is charset-validated here.
    pub nats_prefix: String,

    /// Postgres connection string. Not dialed until the store is built.
    pub database_url: String,
    /// Bound on every statement, so a database that accepts a connection and
    /// then answers nothing cannot hang a consumer silently. `0` disables it.
    pub db_statement_timeout: Duration,
    /// Where step logs are appended. Postgres holds the path and byte length;
    /// multi-megabyte log blobs in a row would be a mistake.
    pub log_dir: PathBuf,
    /// Where a run's checkout is materialized. Read by the fingerprint to hash
    /// `cache_key_files`, and by nothing else — the guest gets the repository
    /// over git, not from here.
    pub workspace_dir: PathBuf,
    /// Also run `*.sql` from this directory, after the set compiled into the
    /// binary. Unset — the default, and the right setting for every deploy —
    /// means the embedded migrations alone, which cannot drift from the binary
    /// the way a directory on disk did. Additive rather than a replacement so
    /// a stale setting left in a conf cannot shadow the binary's own schema.
    pub migrations_dir: Option<PathBuf>,

    pub artifact_sink: ArtifactSinkKind,
    pub artifact_dir: PathBuf,
    pub s3: Option<S3Config>,
    pub artifacts: Option<ArtifactsConfig>,

    /// heyosecret base URL and its one all-powerful bearer. This process is the
    /// policy layer — heyosecret has no per-namespace authorization, so the
    /// token must never reach a build.
    pub heyosecret_url: Option<String>,
    pub heyosecret_token: Option<String>,

    /// The parent domain the *theme* cookie is written for, and the name it is
    /// written under.
    ///
    /// The theme half of what `auth.cookie_domain` does for the session in a
    /// deployment spec: set both to the same realm and one choice of light or
    /// dark covers every app in the fleet. Unset means a host-only cookie,
    /// which is right for a single instance and for a local run.
    ///
    /// `CI_UI_COOKIE_DOMAIN` first, then the fleet-wide `HEYO_UI_COOKIE_DOMAIN`
    /// — the same precedence `CI_HEYOSECRET_URL`/`HEYOSECRET_URL` uses, so an
    /// operator can set one variable for every Heyo app on a host and override
    /// it here if this one instance differs.
    pub ui_cookie_domain: Option<String>,
    pub ui_cookie_name: String,

    /// app-lb admin API, where `workflow` objects live.
    pub app_lb_url: Option<String>,
    pub app_lb_token: Option<String>,

    /// Opt-in self-deployment target and the only repository allowed to update it.
    pub controller_deployment: Option<String>,
    pub controller_repository: Option<String>,
    pub controller_app_lb_url: Option<String>,
    pub controller_app_lb_token: Option<String>,
    /// Shared app identity and its authenticated lifecycle authority.
    pub application_id: Option<String>,
    /// Platform-injected exact managed deployment identity, not an app-lb ID.
    pub managed_deployment: Option<String>,
    pub application_orchestrator_url: Option<String>,
    pub application_lifecycle_token: Option<String>,
    pub expected_sha: Option<String>,
    /// Operator-owned repository release policies, injected from HeyoSecret.
    pub release_policies: Option<String>,
    /// Opt-in build-only release cutoffs and component membership.
    pub release_builds: Option<String>,
    /// Named environment promotion policies; absent means no automatic promotion.
    pub release_environments: Option<String>,
    /// Operator-owned runner/backend/archive-database mapping; never workflow supplied.
    pub host_maintenance_targets: Option<String>,
    /// Repository-scoped managed systemd app-lb targets; never workflow supplied.
    pub host_app_lb_targets: Option<String>,
    /// Operator-owned native heyvm bootstrap targets; never workflow supplied.
    pub host_heyvm_bootstrap_targets: Option<String>,

    /// Shared secret the `git submit` client HMACs its payload with, when it
    /// has no repository token.
    ///
    /// Still required, because it is the credential that works before any
    /// repository has been registered — and the one that keeps an existing
    /// installation working across this upgrade.
    pub webhook_secret: String,
    /// Refuse the shared-secret path entirely, leaving only per-repository
    /// tokens.
    ///
    /// Off by default so registering repositories is something an installation
    /// migrates to rather than something an upgrade forces. Turn it on once
    /// every repository has a token: a shared secret cannot be revoked for one
    /// repository, cannot say which repository is submitting, and a leaked copy
    /// is a leak of the whole system.
    pub require_repo_token: bool,
    /// Dedicated bearer for native runner machine routes. Never inferred from
    /// app-lb forwarded identity or the submit credential.
    pub native_runner_secret: Option<String>,
    /// Glob for workflow files inside a submitted tree.
    ///
    /// A workflow object will override this per repository; until then it is the
    /// one place the convention lives.
    pub default_workflow_path: String,
    /// Ceiling on a submitted source archive, after base64 decoding.
    ///
    /// The whole tree arrives in one JSON body and is then written into a guest
    /// the same way, so this bounds both the request and the upload.
    pub max_source_bytes: usize,

    /// How many lines of a VM's own console to attach to a job.
    ///
    /// A whole boot log is long and nobody reads all of it; the tail is what
    /// answers "why did this VM not come up".
    pub vm_log_lines: usize,
    /// How long a run's step and VM logs are kept in shared storage.
    ///
    /// Logs are the bulk of what this app writes — a build log is megabytes and
    /// nothing prunes itself — so this defaults to something short rather than
    /// to forever. `CI_LOG_RETENTION_DAYS=0` disables the sweep, which is a
    /// choice about database storage somebody should make deliberately.
    pub log_retention: Option<Duration>,
    /// Emails seeded as admins on first sight. app-lb has no roles, so this app
    /// keeps its own.
    pub admin_emails: Vec<String>,

    /// Whether to accept a runner whose daemon serves its API with no auth. See
    /// [`ALLOW_UNAUTHENTICATED_RUNNERS`].
    pub allow_unauthenticated_runners: bool,

    /// Ceiling on any one job, enforced by the executor.
    ///
    /// No longer the basis for JetStream's `ack_wait`: a running job now extends
    /// its own ack window with `AckKind::Progress`, so the queue does not need
    /// to be told in advance how long a build might take. This is the wall clock
    /// a job is cut off at, and the only thing that bounds a runaway one.
    pub max_job_duration: Duration,

    /// Identifies this process among orchestrators sharing a database.
    ///
    /// **Random per process, and deliberately not configurable.** It is how a
    /// restarted instance recognises that a VM leased by "itself" was leased by
    /// a process that no longer exists — a stable id would make the new process
    /// inherit the dead one's leases and reclaim nothing.
    pub instance_id: String,
    /// How long a VM lease is good for without a renewal.
    ///
    /// The window between an instance dying and its VMs becoming reclaimable.
    /// Comfortably more than the renewal interval, so a slow database or a
    /// paused process does not drop a lease somebody is still using — losing a
    /// lease early means two instances on one VM, which is far worse than
    /// reclaiming a minute late.
    pub vm_lease: Duration,

    /// Signs short-TTL, run-scoped tokens for the SSE log stream.
    ///
    /// Random per process, like the artifacts dashboard's session token. A
    /// restart invalidating open log streams is correct — the browser
    /// reconnects and the page it reconnects from was itself re-fetched through
    /// app-lb's gate.
    pub stream_key: [u8; 32],
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let name = opt("CI_NAME").unwrap_or_else(|| "ci".to_string());

        let listen_raw = opt("CI_LISTEN_ADDR").unwrap_or_else(|| "127.0.0.1:9500".to_string());
        let listen_addr = listen_raw
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::BadValue {
                var: "CI_LISTEN_ADDR",
                value: listen_raw.clone(),
                reason: e.to_string(),
            })?;

        let public_url = opt("CI_PUBLIC_URL")
            .unwrap_or_else(|| format!("http://{listen_addr}"))
            .trim_end_matches('/')
            .to_string();

        // `HEYO_API_KEY` is the SDK's own fallback and what `heyvm login` writes
        // into the environment, so accept it rather than forcing a second name.
        let api_key = opt("CI_HEYO_API_KEY")
            .or_else(|| opt("HEYO_API_KEY"))
            .ok_or(ConfigError::Missing {
                var: "CI_HEYO_API_KEY",
                purpose: "the bearer for the heyvm cloud and for each runner daemon \
                          (HEYO_API_KEY is also accepted)",
            })?;

        let network_raw = opt("CI_NETWORK").ok_or(ConfigError::Missing {
            var: "CI_NETWORK",
            purpose: "the heyvm network (or comma-separated networks, or `*` for all) \
                      whose `host` members are the runner pool",
        })?;
        let networks = ServedNetworks::parse(&network_raw);
        if matches!(&networks, ServedNetworks::Named(n) if n.is_empty()) {
            return Err(ConfigError::BadValue {
                var: "CI_NETWORK",
                value: network_raw,
                reason: "names no network. Give one name or id, several separated by \
                         commas, or `*` to serve every network on the account"
                    .to_string(),
            });
        }

        let heyvm = HeyvmConfig {
            base_url: opt("CI_HEYO_BASE_URL"),
            api_key,
            networks,
            default_node: opt("CI_DEFAULT_NODE"),
            daemon_state_path: opt("CI_DAEMON_STATE_PATH")
                .map(PathBuf::from)
                .or_else(|| heyo_data_dir().map(|d| d.join("daemon.json"))),
            local_daemon_url: opt("CI_LOCAL_DAEMON_URL")
                .unwrap_or_else(|| heyo_sdk::DEFAULT_LOCAL_BASE_URL.to_string())
                .trim_end_matches('/')
                .to_string(),
            relay: opt("CI_IROH_RELAY"),
            refresh_interval: secs("CI_RUNNER_REFRESH_SECS", 30)?,
            // Longer than `bus::ladder_total()` (21 min), and checked
            // below so the two cannot drift apart again.
            runner_wait: secs("CI_RUNNER_WAIT_SECS", 1800)?,
            queue_wait: match opt("CI_QUEUE_WAIT_SECS") {
                None => None,
                Some(_) => Some(secs("CI_QUEUE_WAIT_SECS", 0)?),
            },
            vm_ttl: secs("CI_VM_TTL_SECONDS", 3600)?,
            local_runner: opt("CI_LOCAL_RUNNER").map(|v| match v.as_str() {
                "1" | "true" | "yes" | "on" => heyo_sdk::DEFAULT_LOCAL_BASE_URL.to_string(),
                other => other.trim_end_matches('/').to_string(),
            }),
            local_runner_token: opt("CI_LOCAL_RUNNER_TOKEN"),
        };

        let nats_url = opt("CI_NATS_URL").unwrap_or_else(|| "nats://127.0.0.1:4222".to_string());
        let nats = NatsEndpoint::resolve(
            &nats_url,
            &EnvCredentials {
                user: opt("CI_NATS_USER"),
                password: opt("CI_NATS_PASSWORD"),
                token: opt("CI_NATS_TOKEN"),
                creds_file: opt("CI_NATS_CREDS"),
                nkey_seed: opt("CI_NATS_NKEY"),
            },
        )?;

        // The reaper must outlast the queue's own retries.
        //
        // `fail_jobs_waiting_for_a_runner` fails jobs still sitting `queued`. A
        // delivery that fails *before* `claim_job` — picking a runner, say —
        // leaves the job exactly that, so a job being retried normally is
        // indistinguishable from one nothing ever took. Reaping first replaces
        // the real error with "no runner took this job", which blames the hosts
        // for something that never involved them.
        //
        // Checked rather than merely defaulted, because both sides are
        // configurable and a wrong pairing fails silently and intermittently —
        // only for jobs whose first delivery happens to fail.
        let ladder = crate::bus::ladder_total();
        if heyvm.runner_wait <= ladder {
            return Err(ConfigError::BadValue {
                var: "CI_RUNNER_WAIT_SECS",
                value: heyvm.runner_wait.as_secs().to_string(),
                reason: format!(
                    "must exceed the redelivery ladder ({}s), or a job still being \
                     retried is failed as though no runner ever took it",
                    ladder.as_secs()
                ),
            });
        }

        let nats_prefix = opt("CI_NATS_SUBJECT_PREFIX").unwrap_or_else(|| "ci".to_string());
        if !is_subject_token(&nats_prefix) {
            return Err(ConfigError::BadValue {
                var: "CI_NATS_SUBJECT_PREFIX",
                value: nats_prefix,
                // Interpolated into subjects and durable consumer names without
                // escaping, exactly as queue-fn does with function ids.
                reason: "must be one or more of [A-Za-z0-9_-]; it becomes a NATS \
                         subject token and a durable consumer name verbatim"
                    .to_string(),
            });
        }

        let database_url = opt("CI_DATABASE_URL").ok_or(ConfigError::Missing {
            var: "CI_DATABASE_URL",
            purpose: "the Postgres connection string holding runs, jobs, steps and the VM pool",
        })?;

        let log_dir = PathBuf::from(opt("CI_LOG_DIR").unwrap_or_else(|| "ci-logs".to_string()));
        let workspace_dir =
            PathBuf::from(opt("CI_WORKSPACE_DIR").unwrap_or_else(|| "ci-workspaces".to_string()));

        let sink_raw = opt("CI_ARTIFACT_SINK").unwrap_or_else(|| "disk".to_string());
        let artifact_sink = ArtifactSinkKind::parse(&sink_raw).ok_or(ConfigError::BadValue {
            var: "CI_ARTIFACT_SINK",
            value: sink_raw.clone(),
            reason: "must be one of: disk, s3, artifacts".to_string(),
        })?;
        let artifact_dir =
            PathBuf::from(opt("CI_ARTIFACT_DIR").unwrap_or_else(|| "ci-artifacts".to_string()));

        // S3 is also used for debug reports when another primary artifact sink
        // is selected, so resolve it whenever a bucket is present. Selecting S3
        // as the primary sink still makes the bucket mandatory at startup.
        let s3_bucket = opt("CI_S3_BUCKET");
        if matches!(artifact_sink, ArtifactSinkKind::S3) && s3_bucket.is_none() {
            return Err(ConfigError::Missing {
                var: "CI_S3_BUCKET",
                purpose: "the bucket artifacts go to, required by CI_ARTIFACT_SINK=s3",
            });
        }
        let s3 = s3_bucket.map(|bucket| S3Config {
            bucket,
            prefix: opt("CI_S3_PREFIX").unwrap_or_else(|| "ci".to_string()),
            region: opt("CI_S3_REGION"),
            endpoint: opt("CI_S3_ENDPOINT"),
        });
        let artifacts = match artifact_sink {
            ArtifactSinkKind::Artifacts => Some(ArtifactsConfig {
                url: opt("CI_ARTIFACT_URL")
                    .ok_or(ConfigError::Missing {
                        var: "CI_ARTIFACT_URL",
                        purpose: "the base URL of one central `art serve`, required by \
                                  CI_ARTIFACT_SINK=artifacts",
                    })?
                    .trim_end_matches('/')
                    .to_string(),
                token: opt("CI_ARTIFACT_TOKEN"),
                guest_url: opt("CI_ARTIFACT_GUEST_URL")
                    .map(|u| u.trim_end_matches('/').to_string())
                    .filter(|u| !u.is_empty()),
            }),
            _ => None,
        };

        let webhook_secret = opt("CI_WEBHOOK_SECRET").ok_or(ConfigError::Missing {
            var: "CI_WEBHOOK_SECRET",
            purpose: "the HMAC-SHA256 secret `git submit` signs its payload with when it \
                          has no per-repository token",
        })?;
        if webhook_secret.len() < 16 {
            return Err(ConfigError::BadValue {
                var: "CI_WEBHOOK_SECRET",
                // The value is a secret, so the error names its length, not itself.
                value: format!("<{} bytes>", webhook_secret.len()),
                reason: "must be at least 16 bytes; this is the only thing standing \
                         between the public submit endpoint and arbitrary code \
                         execution on a runner"
                    .to_string(),
            });
        }

        let admin_emails = opt("CI_ADMIN_EMAILS")
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let release_builds = opt("CI_RELEASE_BUILDS");
        crate::release_build::policies(release_builds.as_deref()).map_err(|error| ConfigError::BadValue {
            var: "CI_RELEASE_BUILDS", value: "<operator policy>".into(), reason: error.to_string(),
        })?;
        let release_environments = opt("CI_RELEASE_ENVIRONMENTS");
        crate::release_environment::policies(release_environments.as_deref()).map_err(|error| ConfigError::BadValue {
            var: "CI_RELEASE_ENVIRONMENTS", value: "<operator policy>".into(), reason: error.to_string(),
        })?;

        Ok(Self {
            name,
            listen_addr,
            public_url,
            heyvm,
            nats,
            nats_prefix,
            database_url,
            // 30s is far past any query this makes — the heaviest is the
            // `/vms` inventory join over a table with one row per pooled VM —
            // and far short of the ~5 minutes a suspended database instance
            // can take to wake, which is the stall this is here to cut.
            db_statement_timeout: secs("CI_DB_STATEMENT_TIMEOUT_SECS", 30)?,
            log_dir,
            workspace_dir,
            migrations_dir: opt("CI_MIGRATIONS_DIR").map(PathBuf::from),
            artifact_sink,
            artifact_dir,
            s3,
            artifacts,
            heyosecret_url: opt("CI_HEYOSECRET_URL")
                .or_else(|| opt("HEYOSECRET_URL"))
                .map(|u| u.trim_end_matches('/').to_string()),
            heyosecret_token: opt("CI_HEYOSECRET_TOKEN")
                .or_else(|| opt("HEYOSECRET_INTERNAL_API_KEY"))
                .or_else(|| opt("PLATFORM_INTERNAL_API_KEY")),
            // Validated here rather than at render time: a domain the browser
            // will silently discard is a toggle that appears to do nothing, and
            // finding that out from a user is worse than a startup line.
            ui_cookie_domain: opt("CI_UI_COOKIE_DOMAIN")
                .or_else(|| opt(crate::heyo_ui::COOKIE_DOMAIN_ENV))
                .and_then(|d| {
                    let normalized = crate::heyo_ui::normalize_cookie_domain(&d);
                    if normalized.is_none() {
                        tracing::warn!(
                            "CI_UI_COOKIE_DOMAIN={d:?} is not a domain a cookie can be \
                             scoped to; the theme will be remembered per host instead"
                        );
                    }
                    normalized
                }),
            ui_cookie_name: opt("CI_UI_COOKIE_NAME")
                .or_else(|| opt(crate::heyo_ui::COOKIE_NAME_ENV))
                .unwrap_or_else(|| crate::heyo_ui::THEME_COOKIE.to_string()),
            app_lb_url: opt("CI_APP_LB_URL").map(|u| u.trim_end_matches('/').to_string()),
            app_lb_token: opt("CI_APP_LB_TOKEN"),
            controller_deployment: opt("CI_CONTROLLER_DEPLOYMENT"),
            controller_repository: opt("CI_CONTROLLER_REPOSITORY"),
            controller_app_lb_url: opt("CI_CONTROLLER_APP_LB_URL").map(|u| u.trim_end_matches('/').to_string()),
            controller_app_lb_token: opt("CI_CONTROLLER_APP_LB_TOKEN"),
            application_id: opt("HEYO_SERVICE_ID").or_else(|| opt("CI_APPLICATION_ID")),
            managed_deployment: opt("HEYO_DEPLOYMENT_ID"),
            application_orchestrator_url: opt("CI_APPLICATION_ORCHESTRATOR_URL").map(|u| u.trim_end_matches('/').to_string()),
            application_lifecycle_token: opt("CI_APPLICATION_LIFECYCLE_TOKEN"),
            expected_sha: opt("HEYO_REVISION").or_else(||opt("CI_EXPECTED_SHA")),
            release_policies: opt("CI_RELEASE_POLICIES"),
            release_builds,
            release_environments,
            host_maintenance_targets: opt("CI_HOST_MAINTENANCE_TARGETS"),
            host_app_lb_targets: opt("CI_HOST_APP_LB_TARGETS"),
            host_heyvm_bootstrap_targets: opt("CI_HOST_HEYVM_BOOTSTRAP_TARGETS"),
            webhook_secret,
            require_repo_token: flag("CI_REQUIRE_REPO_TOKEN", false)?,
            native_runner_secret: opt("CI_NATIVE_RUNNER_SECRET"),
            default_workflow_path: opt("CI_WORKFLOW_PATH")
                .unwrap_or_else(|| ".ci/workflows/*.yml".to_string()),
            max_source_bytes: bytes("CI_MAX_SOURCE_BYTES", 64 * 1024 * 1024)?,
            admin_emails,
            vm_log_lines: bytes("CI_VM_LOG_LINES", 500)?,
            log_retention: days("CI_LOG_RETENTION_DAYS", 2)?,
            max_job_duration: secs("CI_MAX_JOB_SECONDS", 4 * 60 * 60)?,
            allow_unauthenticated_runners: flag(
                "CI_ALLOW_UNAUTHENTICATED_RUNNERS",
                ALLOW_UNAUTHENTICATED_RUNNERS,
            )?,
            instance_id: format!("ci-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]),
            vm_lease: secs("CI_VM_LEASE_SECS", 180)?,
            stream_key: random_key(),
        })
    }

    /// One line naming every resolved setting that is safe to print. Logged at
    /// startup so a misbehaving deployment can be diagnosed from its own output
    /// rather than from someone's memory of the unit file.
    pub fn summary(&self) -> String {
        format!(
            "instance={} listen={} public={} network={} nats={} prefix={} sink={} logs={} \
             heyosecret={} app-lb={} admins={} submit={}",
            self.instance_id,
            self.listen_addr,
            self.public_url,
            self.heyvm
                .local_runner
                .as_deref()
                .map(|u| format!("local:{u}"))
                .unwrap_or_else(|| self.heyvm.networks.as_str()),
            self.nats.redacted(),
            self.nats_prefix,
            self.artifact_sink.as_str(),
            self.log_dir.display(),
            self.heyosecret_url.as_deref().unwrap_or("unset"),
            self.app_lb_url.as_deref().unwrap_or("unset"),
            self.admin_emails.len(),
            if self.require_repo_token {
                "repo-token-only"
            } else {
                "repo-token-or-shared-secret"
            },
        )
    }
}

/// heyvm's data directory, resolved exactly as `mvm-ctrl` resolves it.
///
/// **`MVM_DATA_DIR` first, `~/.heyo` only as the fallback** — the same order as
/// `utils::get_heyo_data_dir`. A deployment that sets it (this one uses
/// `/var/lib/heyvm`) keeps `daemon.json` there, and assuming a home directory
/// would read a path that does not exist and silently fall through to a worse
/// source of the daemon's identity.
fn heyo_data_dir() -> Option<PathBuf> {
    if let Some(dir) = opt("MVM_DATA_DIR") {
        return Some(PathBuf::from(dir));
    }
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .map(|h| PathBuf::from(h).join(".heyo"))
}

fn opt(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        _ => None,
    }
}

/// A boolean env var.
///
/// Unparseable values are an error rather than falsey. `CI_ALLOW_UNAUTHENTICATED_RUNNERS=yes`
/// silently meaning `false` would be a security setting that reads as applied
/// and is not.
fn flag(var: &'static str, default: bool) -> Result<bool, ConfigError> {
    match opt(var) {
        None => Ok(default),
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(ConfigError::BadValue {
                var,
                value: raw,
                reason: "must be one of: true, false, 1, 0, yes, no, on, off".to_string(),
            }),
        },
    }
}

fn bytes(var: &'static str, default: usize) -> Result<usize, ConfigError> {
    match opt(var) {
        None => Ok(default),
        Some(raw) => {
            let n = raw.parse::<usize>().map_err(|e| ConfigError::BadValue {
                var,
                value: raw.clone(),
                reason: e.to_string(),
            })?;
            if n == 0 {
                return Err(ConfigError::BadValue {
                    var,
                    value: raw,
                    reason: "must be greater than zero".to_string(),
                });
            }
            Ok(n)
        }
    }
}

/// A retention period in whole days, where `0` means "never delete".
///
/// Zero is a legitimate value here, unlike every other duration in this file —
/// which is why it does not go through `secs`, whose whole job is to refuse a
/// zero that would become a busy loop.
fn days(var: &'static str, default: u64) -> Result<Option<Duration>, ConfigError> {
    let raw = match opt(var) {
        None => return Ok(Some(Duration::from_secs(default * 86_400))),
        Some(raw) => raw,
    };
    let n = raw.parse::<u64>().map_err(|e| ConfigError::BadValue {
        var,
        value: raw.clone(),
        reason: format!("{e}; whole days, or 0 to keep logs forever"),
    })?;
    Ok((n > 0).then(|| Duration::from_secs(n * 86_400)))
}

fn secs(var: &'static str, default: u64) -> Result<Duration, ConfigError> {
    match opt(var) {
        None => Ok(Duration::from_secs(default)),
        Some(raw) => {
            let n = raw.parse::<u64>().map_err(|e| ConfigError::BadValue {
                var,
                value: raw.clone(),
                reason: e.to_string(),
            })?;
            if n == 0 {
                return Err(ConfigError::BadValue {
                    var,
                    value: raw,
                    reason: "must be greater than zero".to_string(),
                });
            }
            Ok(Duration::from_secs(n))
        }
    }
}

/// Whether a string may be interpolated into a NATS subject and a durable
/// consumer name without escaping.
pub fn is_subject_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// 32 random bytes, from two v4 UUIDs.
///
/// `uuid` is already a dependency and its v4 generator is a CSPRNG, so this
/// avoids linking `rand` for one call. 122 bits of entropy each, 244 total —
/// well past what signing a 60-second stream token needs.
fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    key
}

#[derive(Debug)]
pub enum ConfigError {
    Missing {
        var: &'static str,
        purpose: &'static str,
    },
    BadValue {
        var: &'static str,
        value: String,
        reason: String,
    },
    Nats(NatsAuthError),
}

impl From<NatsAuthError> for ConfigError {
    fn from(e: NatsAuthError) -> Self {
        Self::Nats(e)
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { var, purpose } => {
                write!(f, "{var} is not set. It is {purpose}.")
            }
            Self::BadValue { var, value, reason } => {
                write!(f, "{var}={value:?} is not usable: {reason}")
            }
            Self::Nats(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_sink_kinds_parse_with_their_aliases() {
        assert_eq!(
            ArtifactSinkKind::parse("disk"),
            Some(ArtifactSinkKind::Disk)
        );
        assert_eq!(
            ArtifactSinkKind::parse("LOCAL"),
            Some(ArtifactSinkKind::Disk)
        );
        assert_eq!(ArtifactSinkKind::parse(" s3 "), Some(ArtifactSinkKind::S3));
        assert_eq!(
            ArtifactSinkKind::parse("art"),
            Some(ArtifactSinkKind::Artifacts)
        );
        assert_eq!(ArtifactSinkKind::parse("gcs"), None);
    }

    #[test]
    fn a_guest_reaches_the_store_by_its_own_url_when_one_is_set() {
        let mut c = ArtifactsConfig {
            url: "http://localhost:9000".into(),
            token: None,
            guest_url: None,
        };
        assert_eq!(c.url_for_guest(), "http://localhost:9000");
        c.guest_url = Some("https://art.example".into());
        assert_eq!(c.url_for_guest(), "https://art.example");
    }

    #[test]
    fn one_network_several_networks_and_all_of_them_all_parse() {
        assert_eq!(
            ServedNetworks::parse("prod-runners"),
            ServedNetworks::Named(vec!["prod-runners".into()])
        );
        assert_eq!(
            ServedNetworks::parse(" prod , lab ,, "),
            ServedNetworks::Named(vec!["prod".into(), "lab".into()]),
            "whitespace and empty entries are noise, not networks"
        );
        assert_eq!(ServedNetworks::parse("*"), ServedNetworks::All);
        assert_eq!(ServedNetworks::parse(" * "), ServedNetworks::All);
    }

    /// `CI_NETWORK` is written by a person, and the dashboard shows both a
    /// network's id and its name — so either spelling has to be accepted.
    #[test]
    fn a_served_network_is_matched_by_id_or_name() {
        let named = ServedNetworks::parse("prod-runners,net-9");
        assert!(named.includes("net-1", "prod-runners"));
        assert!(named.includes("net-1", "PROD-Runners"), "case-insensitive");
        assert!(named.includes("net-9", "whatever"), "by id");
        assert!(!named.includes("net-2", "lab"));

        assert!(ServedNetworks::All.includes("net-2", "lab"));
    }

    /// The first entry is the default, because it is the one somebody wrote
    /// first. `*` names none, and defers to the account's own default network.
    #[test]
    fn the_preferred_network_is_the_first_named_one() {
        assert_eq!(ServedNetworks::parse("prod,lab").preferred(), Some("prod"));
        assert_eq!(ServedNetworks::All.preferred(), None);
    }

    /// A `CI_NETWORK` of only separators names nothing, and an instance serving
    /// nothing would accept submits it can never run.
    #[tokio::test]
    async fn a_network_list_that_names_nothing_is_refused_at_startup() {
        unsafe {
            std::env::set_var("CI_HEYO_API_KEY", "k");
            std::env::set_var("CI_DATABASE_URL", "postgres://localhost/ci");
            std::env::set_var("CI_WEBHOOK_SECRET", "0123456789abcdef");
            std::env::set_var("CI_NETWORK", " , , ");
        }
        let err = Config::from_env().expect_err("must not start");
        assert!(err.to_string().contains("CI_NETWORK"), "{err}");
        assert!(err.to_string().contains("names no network"), "{err}");
        unsafe { std::env::set_var("CI_NETWORK", "test-net") };
        unsafe {
            std::env::set_var("CI_LOCAL_RUNNER", "https://runner.example.test");
            std::env::remove_var("CI_LOCAL_RUNNER_TOKEN");
        }
        let config = Config::from_env().unwrap();
        let runners = crate::runners::Runners::new(std::sync::Arc::new(config));
        assert!(runners.options_for("hd-local").await.unwrap().options.api_key.is_none());
        unsafe { std::env::set_var("CI_LOCAL_RUNNER_TOKEN", "distinct-daemon-key") };
        let config = Config::from_env().unwrap();
        let runners = crate::runners::Runners::new(std::sync::Arc::new(config));
        let options = runners.options_for("hd-local").await.unwrap();
        assert_eq!(options.options.api_key.as_deref(), Some("distinct-daemon-key"));
        assert_eq!(options.options.base_url.as_deref(), Some("https://runner.example.test"));
        unsafe {
            std::env::remove_var("CI_LOCAL_RUNNER");
            std::env::remove_var("CI_LOCAL_RUNNER_TOKEN");
        }
    }

    /// Retention is the one duration where zero is meaningful — it is how an
    /// operator says "keep everything" — so it must not go through the guard
    /// that refuses a zero elsewhere.
    #[test]
    fn a_retention_of_zero_means_forever_rather_than_being_refused() {
        unsafe { std::env::remove_var("CI_TEST_RETENTION") };
        assert_eq!(
            days("CI_TEST_RETENTION", 2).unwrap(),
            Some(Duration::from_secs(2 * 86_400)),
            "the default is two days"
        );

        unsafe { std::env::set_var("CI_TEST_RETENTION", "0") };
        assert_eq!(days("CI_TEST_RETENTION", 2).unwrap(), None);

        unsafe { std::env::set_var("CI_TEST_RETENTION", "30") };
        assert_eq!(
            days("CI_TEST_RETENTION", 2).unwrap(),
            Some(Duration::from_secs(30 * 86_400))
        );

        unsafe { std::env::set_var("CI_TEST_RETENTION", "two") };
        let err = days("CI_TEST_RETENTION", 2).unwrap_err();
        assert!(err.to_string().contains("whole days"), "{err}");
        unsafe { std::env::remove_var("CI_TEST_RETENTION") };
    }

    /// The prefix reaches a subject and a durable consumer name verbatim, so a
    /// dot or a wildcard in it would silently reshape the subject space.
    #[test]
    fn subject_tokens_reject_anything_that_would_reshape_a_subject() {
        assert!(is_subject_token("ci"));
        assert!(is_subject_token("ci-prod_2"));
        assert!(!is_subject_token(""));
        assert!(!is_subject_token("ci.prod"));
        assert!(!is_subject_token("ci.>"));
        assert!(!is_subject_token("ci *"));
    }

    #[test]
    fn a_zero_duration_is_rejected_rather_than_becoming_a_busy_loop() {
        unsafe { std::env::set_var("CI_TEST_ZERO_SECS", "0") };
        let err = secs("CI_TEST_ZERO_SECS", 30).unwrap_err();
        assert!(err.to_string().contains("greater than zero"), "{err}");
        unsafe { std::env::remove_var("CI_TEST_ZERO_SECS") };
    }

    /// Every error must name the variable to fix — that is the whole reason
    /// config is validated up front instead of at first use.
    #[test]
    fn errors_name_the_variable_to_fix() {
        let e = ConfigError::Missing {
            var: "CI_NETWORK",
            purpose: "the heyvm network",
        };
        assert!(e.to_string().starts_with("CI_NETWORK is not set"));

        let e = ConfigError::BadValue {
            var: "CI_LISTEN_ADDR",
            value: "nope".into(),
            reason: "invalid socket address".into(),
        };
        assert!(e.to_string().contains("CI_LISTEN_ADDR"));
        assert!(e.to_string().contains("invalid socket address"));
    }

    /// Regression guard for the one error that must not echo its value: the
    /// webhook secret's length is diagnostic enough.
    #[test]
    fn a_short_webhook_secret_is_reported_by_length_not_by_value() {
        let e = ConfigError::BadValue {
            var: "CI_WEBHOOK_SECRET",
            value: format!("<{} bytes>", "hunter2".len()),
            reason: "must be at least 16 bytes".into(),
        };
        assert!(!e.to_string().contains("hunter2"));
        assert!(e.to_string().contains("<7 bytes>"));
    }

    #[test]
    fn the_stream_key_is_not_all_zeroes() {
        let a = random_key();
        let b = random_key();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b, "two calls must not return the same key");
    }
}
