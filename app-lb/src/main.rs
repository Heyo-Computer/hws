//! app-lb: an application load balancer for heyvm Firecracker/KVM microVMs.
//!
//! Register a deployment (VM template + routes + scaling policy) against the
//! admin API and the proxy routes traffic to a pool of VMs, booting and reaping
//! them to match load.

// The platform UI kit — tokens, the theme cookie and forwarded identity —
// shared with app-obs, ci, heyosecret and artifacts. Included by path rather
// than depended on as a crate: this crate is on axum 0.7 and three of the
// others are on 0.8, and the shared module names no framework type. See
// `ui/README.md`.
#[path = "../../ui/ui.rs"]
mod heyo_ui;

mod acme;
mod admin;
mod artifact;
mod auth;
mod auth_providers;
mod autoscale;
mod cli;
mod config;
mod deployment;
mod discovery;
mod disks;
mod dns;
mod federated;
mod fleet;
mod fleet_store;
mod fleet_hop;
mod fleet_placement;
mod fleet_pg;
mod fleet_seal;
mod fleet_split;
mod secrets_seal;
mod fleet_sync;
#[cfg(test)]
mod fleet_store_layout_tests;
mod feed;
mod gateway;
mod guest_files;
mod regional;
mod guard;
mod health;
mod host_bundle;
mod host_update;
mod images;
mod incus;
mod instance_lock;
mod jobs;
mod jwt;
mod metrics;
mod mounts;
mod namespaces;
mod obs;
mod operations;
mod onboarding;
mod plugins;
mod proxy;
mod request_control;
mod registry;
mod allocation;
mod retirement;
mod rollout;
mod runtime;
mod secrets;
mod siem;
mod site;
mod store_gateway;
mod tls;
mod tokens;
mod transfers;
mod unpack;
mod tunnel_dialer;
mod vm;
mod worker;
mod worker_rpc;
mod workspace;
mod workflows;

use crate::acme::{AcmeConfig, AcmeManager, ChallengeTable};
use crate::admin::AdminApi;
use crate::auth::Authenticator;
use crate::autoscale::Autoscaler;
use crate::config::LbConfig;
use crate::jobs::{JobConfig, Jobs};
use crate::metrics::Metrics;
use crate::registry::Registry;
use crate::secrets::SecretStore;
use crate::tls::CertStore;
use crate::vm::VmManager;
use pingora_core::server::Server;
use pingora_core::services::background::background_service;
use std::sync::Arc;

fn config_from_env() -> LbConfig {
    let mut cfg = LbConfig::default();
    if let Ok(v) = std::env::var("APP_LB_PROXY_ADDR") {
        cfg.proxy_addr = v;
    }
    if let Ok(v) = std::env::var("APP_LB_ADMIN_ADDR") {
        cfg.admin_addr = v;
    }
    if let Ok(v) = std::env::var("APP_LB_STATE_PATH") {
        cfg.state_path = v;
    }
    if let Ok(v) = std::env::var("APP_LB_SECRETS_PATH") {
        cfg.secrets_path = v;
    }
    if let Ok(v) = std::env::var("APP_LB_TOKENS_PATH") {
        cfg.tokens_path = v;
    }
    if let Ok(v) = std::env::var("APP_LB_GUARD_PATH") {
        cfg.guard_path = v;
    }
    if let Ok(v) = std::env::var("APP_LB_NAME") {
        cfg.name = v;
    }
    if let Ok(v) = std::env::var("APP_LB_DAEMON_URL") {
        cfg.daemon_url = Some(v);
    }
    if let Ok(v) = std::env::var("APP_LB_DASHBOARD_USER") {
        cfg.dashboard_user = Some(v);
    }
    if let Ok(v) = std::env::var("APP_LB_DASHBOARD_PASSWORD") {
        cfg.dashboard_password = Some(v);
    }
    if let Ok(v) = std::env::var("APP_LB_ADMIN_AUTH") {
        cfg.admin_auth = matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    if let Ok(v) = std::env::var("APP_LB_AUTH_URL") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            cfg.auth_url = Some(v);
        }
    }
    if let Ok(v) = std::env::var("APP_LB_AUTH_CACHE_SECS")
        && let Ok(n) = v.trim().parse()
    {
        cfg.auth_cache_secs = n;
    }
    if let Ok(v) = std::env::var("APP_LB_AUTH_TIMEOUT_SECS")
        && let Ok(n) = v.trim().parse()
    {
        cfg.auth_timeout_secs = n;
    }
    if let Ok(v) = std::env::var("APP_LB_DASHBOARD_AUTH") {
        cfg.dashboard_auth = matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    if let Ok(v) = std::env::var("APP_LB_PROXY_TLS_ADDR") {
        cfg.tls_addr = v;
        cfg.tls_addr_explicit = true;
    }
    if let Ok(v) = std::env::var("APP_LB_TLS_CERT") {
        cfg.tls_cert_path = Some(v);
    }
    if let Ok(v) = std::env::var("APP_LB_TLS_KEY") {
        cfg.tls_key_path = Some(v);
    }
    if let Ok(v) = std::env::var("APP_LB_ACME_EMAIL") {
        cfg.acme_email = Some(v);
    }
    if let Ok(v) = std::env::var("APP_LB_ACME_DIR") {
        cfg.acme_dir = v;
    }
    if let Ok(v) = std::env::var("APP_LB_ACME_DIRECTORY") {
        cfg.acme_directory = v;
    }
    if let Ok(v) = std::env::var("APP_LB_BUILD_DIR") {
        cfg.build_dir = v;
    }
    if let Ok(v) = std::env::var("APP_LB_SITES_DIR") {
        cfg.sites_dir = v;
    }
    if let Ok(v) = std::env::var("APP_LB_LXC_ENABLED") {
        cfg.lxc.enabled = matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    if let Ok(v) = std::env::var("APP_LB_LXC_SOCKET") {
        cfg.lxc.socket = v.trim().into();
    }
    if let Ok(v) = std::env::var("APP_LB_LXC_PROJECT") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            cfg.lxc.project = v;
        }
    }
    // `name=url,name=url`. Replaces the default rather than adding to it, so a
    // host that names its own registries is not silently still pulling from
    // Docker Hub.
    if let Ok(v) = std::env::var("APP_LB_LXC_REMOTES") {
        let remotes: std::collections::BTreeMap<String, String> = v
            .split(',')
            .filter_map(|entry| entry.trim().split_once('='))
            .map(|(name, url)| (name.trim().to_string(), url.trim().to_string()))
            .filter(|(name, url)| !name.is_empty() && !url.is_empty())
            .collect();
        if !remotes.is_empty() {
            cfg.lxc.remotes = remotes;
        }
    }
    if let Ok(v) = std::env::var("APP_LB_LXC_DEFAULT_REMOTE") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            cfg.lxc.default_remote = v;
        }
    }
    if let Ok(v) = std::env::var("APP_LB_LXC_PROFILES") {
        cfg.lxc.profiles = v
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();
    }
    if let Ok(v) = std::env::var("APP_LB_LXC_NETWORK_NIC") {
        let v = v.trim().to_string();
        cfg.lxc.network_nic = (!v.is_empty()).then_some(v);
    }
    if let Ok(v) = std::env::var("APP_LB_HEYVM_BIN") {
        cfg.heyvm_bin = v;
    }
    if let Ok(v) = std::env::var("APP_LB_ART_BIN") {
        cfg.art_bin = v;
    }
    if let Ok(v) = std::env::var("APP_LB_IMAGES_DIR") {
        cfg.images_dir = Some(v);
    }
    if let Ok(v) = std::env::var("APP_LB_MOUNTS_DIR") {
        cfg.mounts_dir = v;
    }
    if let Ok(v) = std::env::var("APP_LB_MOUNT_TTL_SECS") {
        match v.trim().parse::<u64>() {
            Ok(n) => cfg.mount_ttl_secs = n,
            _ => panic!(
                "APP_LB_MOUNT_TTL_SECS must be a number of seconds (0 to keep every mount \
                 tree), got {v:?}"
            ),
        }
    }
    if let Ok(v) = std::env::var("APP_LB_GIT_BIN") {
        cfg.git_bin = v;
    }
    if let Ok(v) = std::env::var("APP_LB_AWS_BIN") {
        cfg.aws_bin = v;
    }
    if let Ok(v) = std::env::var("APP_LB_ACME_WILDCARD") {
        cfg.acme_wildcards = v
            .split(',')
            .map(|d| d.trim().trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
    }
    if let Ok(v) = std::env::var("APP_LB_PUBLIC_IPS") {
        cfg.public_ips = v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| match s.parse::<std::net::IpAddr>() {
                Ok(ip) => Some(ip),
                Err(e) => {
                    tracing::warn!(value = %s, error = %e, "APP_LB_PUBLIC_IPS entry is not an IP address; ignored");
                    None
                }
            })
            .collect();
    }
    if let Ok(v) = std::env::var("APP_LB_ROUTE53_ZONE_ID") {
        cfg.route53_zone_id = Some(v.trim().to_string()).filter(|z| !z.is_empty());
    }
    if let Ok(v) = std::env::var("APP_LB_DEPLOY_BASE_DOMAIN") {
        cfg.deploy_base_domain = Some(v.trim().to_string()).filter(|d| !d.is_empty());
    }
    if let Ok(v) = std::env::var("APP_LB_STRIP_COOKIES") {
        cfg.strip_cookies = crate::request_control::parse_cookie_names(&v);
    }
    if let Ok(v) = std::env::var("APP_LB_UPDATE_SHELL") {
        cfg.update_shell = v;
    }
    if let Ok(v) = std::env::var("APP_LB_BUILD_TIMEOUT_SECS") {
        match v.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => cfg.build_timeout_secs = secs,
            _ => panic!("APP_LB_BUILD_TIMEOUT_SECS must be a positive number of seconds, got {v:?}"),
        }
    }
    if let Ok(v) = std::env::var("APP_LB_HEYVM_HOME") {
        cfg.heyvm_home = Some(v);
    }
    cfg
}

/// Install the subscriber: stderr always, plus a layer that forwards app-lb's own
/// events to app-obs when one is configured.
///
/// The `EnvFilter` sits in front of both, so `RUST_LOG` still decides what app-lb
/// logs *at all* and shipping only ever sees a subset of that. The layer applies
/// its own INFO floor on top — see `obs::EventLayer`.
/// Where the data-plane session signing key lives (`APP_LB_AUTH_KEY`).
fn auth_key_path() -> std::path::PathBuf {
    std::env::var("APP_LB_AUTH_KEY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| auth::default_key_path())
}

/// `APP_LB_SECRET_KEY`, derived, when set.
fn secret_key_from_env() -> Option<Vec<u8>> {
    std::env::var("APP_LB_SECRET_KEY")
        .ok()
        .filter(|k| !k.trim().is_empty())
        .map(|k| secrets::derive_key(&k))
}

/// With `APP_LB_FLEET_DATABASE_URL` set: open the fleet store, register every
/// store's backend with it, and bring the files in line with it. Exits rather
/// than start a host that would serve state it cannot vouch for.
fn fleet_mode(cfg: &LbConfig) -> Option<fleet_sync::FleetStores> {
    let url = std::env::var(fleet_pg::URL_ENV).ok().filter(|u| !u.trim().is_empty())?;
    let Some(key) = secret_key_from_env() else {
        tracing::error!(
            "{} needs APP_LB_SECRET_KEY: secrets and certificate keys are sealed with it in the \
             fleet store, and every host in the fleet must have the same one",
            fleet_pg::URL_ENV
        );
        std::process::exit(1);
    };
    // Who writes, in `updated_by` and on leases: the host, and this process,
    // so a restarted app-lb is a new holder that cannot renew its
    // predecessor's lease.
    let host = std::env::var("APP_LB_FLEET_HOST")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok().map(|h| h.trim().to_string()))
        .unwrap_or_else(|| "app-lb".into());
    if !config::is_valid_fleet_host(&host) {
        tracing::error!(host = %host, "APP_LB_FLEET_HOST must be letters, digits, `-`, `_` and `.`; refusing to start");
        std::process::exit(1);
    }
    let holder = format!("{host}/{}", std::process::id());
    let pg = match fleet_pg::PgStore::open(&url, &holder, fleet_pg::timeout_from_env()) {
        Ok(pg) => pg,
        Err(e) => {
            tracing::error!(error = %e, "refusing to start");
            std::process::exit(1);
        }
    };
    let fleet = fleet_sync::Fleet::new(pg, fleet_sync::snapshot_meta_path(&cfg.state_path), key);
    let layout = fleet_store::Layout {
        state_path: cfg.state_path.clone().into(),
        secrets_path: cfg.secrets_path.clone().into(),
        tokens_path: cfg.tokens_path.clone().into(),
        guard_path: cfg.guard_path.clone().into(),
        acme_dir: cfg.acme_dir.clone().into(),
    };
    let stores = fleet_sync::FleetStores::register(&fleet, &layout, &host, &auth_key_path());
    match fleet.start() {
        Ok(fleet_sync::Started::Seeded { records }) => {
            tracing::info!(holder = %holder, records, "fleet mode: seeded the fleet store from this host")
        }
        Ok(fleet_sync::Started::Synced { records, cursor }) => {
            tracing::info!(holder = %holder, records, cursor, "fleet mode: local snapshot matches the fleet store")
        }
        Ok(fleet_sync::Started::Offline { synced_at, error }) => tracing::warn!(
            holder = %holder,
            synced_at,
            error = %error,
            "fleet mode: the fleet store is not usable; serving the local snapshot and refusing mutations"
        ),
        Err(e) => {
            tracing::error!(error = %e, "fleet mode: refusing to start");
            std::process::exit(1);
        }
    }
    stores.fleet.set_identity(
        &host,
        std::env::var(fleet_hop::ADDRESS_ENV).ok().filter(|a| !a.trim().is_empty()),
    );
    Some(stores)
}

fn init_tracing(events: Option<obs::LogSink>) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,app_lb=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(events.map(obs::EventLayer::new))
        .init();
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--forwarding-worker") {
        let path = std::env::args_os().nth(2).expect("worker control directory required");
        let takeover = std::env::args().nth(3).as_deref() == Some("--takeover");
        worker::run(path.into(), takeover);
    }
    if let Some(code) = host_update::helper_main() { std::process::exit(code); }
    // After the internal helper entry points above, which take their own
    // arguments. Anything else that is not empty is a refusal: see `cli`.
    let command = cli::parse(std::env::args().skip(1));
    if command != cli::Command::Serve {
        std::process::exit(cli::run(&command));
    }
    // Before the subscriber, because shipping app-lb's own events means adding a
    // layer to it, and a subscriber can only be built once. Reads the environment
    // and allocates a channel — no threads, nothing that a later fork would lose.
    //
    // A misconfigured endpoint disables shipping and is reported once the
    // subscriber exists; it is deliberately not fatal. Panicking here would let a
    // typo in the *observability* configuration take the data plane down, which is
    // the one thing `obs` is built not to do.
    let (obs, obs_error) = match obs::from_env() {
        Ok(obs) => (obs, None),
        Err(e) => (None, Some(e)),
    };
    init_tracing(obs.as_ref().and_then(|o| o.events.clone()));
    if let Some(e) = obs_error {
        tracing::error!(
            error = %e,
            "APP_LB_OBS_URL is unusable, so no logs will be shipped to app-obs; \
             everything else starts normally",
        );
    }

    // rustls needs a process-level `CryptoProvider` chosen explicitly whenever
    // more than one is compiled in, and app-lb's graph has both `ring` (iroh,
    // hickory) and `aws-lc-rs` (instant-acme). Without this the *first* rustls
    // handshake panics rather than erroring — which lands in the ACME background
    // service, the only part of app-lb that speaks TLS as a client.
    //
    // pingora installed this itself under its `rustls` feature; the `openssl`
    // feature app-lb now uses never runs that code, so it belongs here. Must
    // happen before any service starts.
    //
    // `Err` means a provider is already installed, which is the desired end
    // state either way.
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls crypto provider was already installed");
    }

    let mut cfg = config_from_env();
    // Stamped on every container so two app-lb processes on one host do not
    // adopt each other's. Defaults to the LB's own name rather than being a
    // separate setting nobody would remember to set.
    if cfg.lxc.instance.is_empty() {
        cfg.lxc.instance = cfg.name.clone();
    }
    let cfg = cfg;
    let discovery_cfg = discovery::DiscoveryConfig::from_env()
        .unwrap_or_else(|e| panic!("invalid discovery configuration: {e}"));

    // Fail fast on a gate that can't enforce anything: asking to protect the
    // admin API while giving it no credential would silently leave it open.
    if cfg.admin_auth && cfg.dashboard_password.is_none() {
        panic!(
            "APP_LB_ADMIN_AUTH is set but APP_LB_DASHBOARD_PASSWORD is not; the admin \
             gate reuses the dashboard credentials, so set a password or unset APP_LB_ADMIN_AUTH"
        );
    }

    // Federated bearers are only ever examined by the admin gate, so an auth
    // URL with the gate off would be accepted config that checks nothing —
    // every customer route would be open to whoever reaches the listener.
    if cfg.auth_url.is_some() && !cfg.admin_auth {
        panic!(
            "APP_LB_AUTH_URL is set but APP_LB_ADMIN_AUTH is off; federated bearers are only \
             checked by the admin gate, so set APP_LB_ADMIN_AUTH=1 (and a dashboard password) \
             or unset APP_LB_AUTH_URL"
        );
    }

    // A password with both gates off protects nothing — likely someone turned
    // off the dashboard prompt (for an SSO proxy in front) and forgot that the
    // CRUD gate is a separate switch. Loud, not fatal: the state is identical
    // to running with no password at all, which is allowed.
    if cfg.dashboard_password.is_some() && !cfg.dashboard_auth {
        if cfg.admin_auth {
            tracing::info!(
                "APP_LB_DASHBOARD_AUTH=0: the dashboard view tier (/, /dashboard, /metrics, \
                 /security…) is open — keep your own sign-in in front of it — while the \
                 deployment CRUD API still requires the dashboard credentials"
            );
        } else {
            tracing::warn!(
                "APP_LB_DASHBOARD_PASSWORD is set but APP_LB_DASHBOARD_AUTH=0 and \
                 APP_LB_ADMIN_AUTH is off: the password gates nothing — every admin route, \
                 /security included, is open to whoever reaches the admin listener"
            );
        }
    }

    // Pre-flight the listener addresses.
    //
    // Pingora binds inside a service task, and a failure there panics *that task
    // only* — the process survives with a dead proxy, the admin API still
    // answering, and the supervisor reporting a healthy service. Checking here
    // turns that silent half-dead state into a startup failure naming the port
    // and the reason.
    // Unless the last manager's forwarding worker is still serving them: this
    // manager takes those listeners over (see `worker`), so they are meant to
    // be taken.
    let worker_dir = std::env::var_os("APP_LB_WORKER_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| worker::worker_dir(&cfg.state_path));
    let inherited_worker = worker::live_worker(&worker_dir);
    if let Some(pid) = inherited_worker {
        tracing::info!(worker_pid = pid, "the last manager's forwarding worker holds the listeners; taking it over");
    }
    for addr in [Some(&cfg.proxy_addr), cfg.tls_enabled().then_some(&cfg.tls_addr)]
        .into_iter()
        .flatten()
        .filter(|_| inherited_worker.is_none())
    {
        if let Err(e) = std::net::TcpListener::bind(addr) {
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                "; binding a port below 1024 as a non-root user needs \
                 `setcap 'cap_net_bind_service=+ep'` on the binary (re-run it after every \
                 reinstall — capabilities do not survive replacing the file), or \
                 `sysctl net.ipv4.ip_unprivileged_port_start=80`"
            } else {
                ""
            };
            panic!("cannot bind {addr}: {e}{hint}");
        }
    }

    // Setting the HTTPS address is a clear statement of intent, but it only says
    // *where* to bind, not whether to. Without ACME or a static cert there is
    // nothing to serve, and the listener is skipped — previously in silence,
    // which looks identical to a bind that failed.
    if cfg.tls_addr_explicit && !cfg.tls_enabled() {
        tracing::warn!(
            tls = %cfg.tls_addr,
            "APP_LB_PROXY_TLS_ADDR is set but no HTTPS listener will be bound: TLS needs \
             either APP_LB_ACME_EMAIL (automatic certificates) or an APP_LB_TLS_CERT / \
             APP_LB_TLS_KEY pair. Set one of them, or unset APP_LB_PROXY_TLS_ADDR.",
        );
    }

    // HTTP-01 validation is fetched on port 80 and nowhere else, so a proxy
    // bound anywhere else can only be validated if something in front forwards
    // that path. Worth saying loudly at startup rather than leaving it to be
    // diagnosed from a CA error much later.
    if cfg.acme_enabled() && !cfg.proxy_addr.ends_with(":80") {
        tracing::warn!(
            proxy = %cfg.proxy_addr,
            "ACME is enabled but the plaintext proxy is not on port 80; Let's Encrypt \
             validates http-01 on port 80 only, so issuance will fail unless something \
             forwards /.well-known/acme-challenge/ to this listener",
        );
    }

    // A wildcard is only issued over DNS-01, which needs somewhere to write the
    // challenge record. Warned rather than fatal: everything else — including
    // per-host issuance — still works, and taking the LB down over a certificate
    // that is not yet configured would be the wrong trade.
    if !cfg.acme_wildcards.is_empty() {
        if !cfg.acme_enabled() {
            tracing::warn!(
                "APP_LB_ACME_WILDCARD is set but APP_LB_ACME_EMAIL is not, so no \
                 certificates are issued at all; set the contact address to enable ACME",
            );
        } else if cfg.route53_zone_id.is_none() {
            tracing::warn!(
                wildcards = ?cfg.acme_wildcards,
                "APP_LB_ACME_WILDCARD is set without APP_LB_ROUTE53_ZONE_ID; wildcard \
                 certificates are issued over DNS-01 and there is nowhere to publish the \
                 challenge, so these domains will be served the fallback certificate",
            );
        } else {
            tracing::info!(
                wildcards = ?cfg.acme_wildcards,
                aws_bin = %cfg.aws_bin,
                "wildcard certificates enabled; hosts beneath these domains will not be \
                 issued certificates of their own",
            );
        }
    }

    // Before anything can reach the daemon: two app-lbs sharing one heyvm each
    // see the other's sandboxes as orphans. See `instance_lock`.
    let lock_setting = instance_lock::setting(std::env::var("APP_LB_INSTANCE_LOCK").ok().as_deref());
    let holder = format!("pid {} state={}", std::process::id(), cfg.state_path);
    let _instance_lock = match instance_lock::acquire_setting(&lock_setting, &holder) {
        Ok(Some((file, path))) => {
            tracing::info!(path = %path.display(), "holding the host's app-lb instance lock");
            Some(file)
        }
        Ok(None) => {
            tracing::warn!("APP_LB_INSTANCE_LOCK=off: nothing stops a second app-lb on this host from managing the same sandboxes");
            None
        }
        Err(e) => {
            tracing::error!(error = %e, "refusing to start");
            std::process::exit(1);
        }
    };
    // Fleet mode: the stores below keep their files as the local snapshot of a
    // shared PostgreSQL. Every kind is registered and synchronized here, before
    // anything loads. See `fleet_sync`.
    let fleet_stores = fleet_mode(&cfg);
    let registry = Arc::new(match &fleet_stores {
        Some(fs) => Registry::new(&cfg.state_path).with_fleet(fs.deployments.clone(), &fs.host),
        None => Registry::new(&cfg.state_path),
    });
    let _controller_lock = registry.controller_lock().unwrap_or_else(|e| {
        tracing::error!(error=%e,"cannot exclusively own deployment state; refusing controller startup");
        std::process::exit(1);
    });
    match registry.load() {
        Ok(0) => {
            tracing::info!(dir = %registry.state_dir().display(), "no persisted deployments")
        }
        Ok(n) => tracing::info!(count = n, "restored deployments"),
        Err(e) => {
            tracing::error!(error=%e,"failed to load persisted state; refusing controller startup");
            std::process::exit(1);
        }
    }
    if let Err(e)=registry.require_complete_load() {
        tracing::error!(error=%e,"refusing controller startup with incomplete deployment state");
        std::process::exit(1);
    }

    // Beside the deployment state, derived the same way: `app-lb-state.json`
    // gives `app-lb-workflows.d/`. One directory per object kind keeps a
    // listing readable and a delete unambiguous.
    let workflow_dir = crate::workflows::workflow_dir(&cfg.state_path);
    let workflows = Arc::new(match &fleet_stores {
        Some(fs) => crate::workflows::WorkflowStore::with_collection(workflow_dir, fs.workflows.clone()),
        None => crate::workflows::WorkflowStore::new(workflow_dir),
    });
    match workflows.load() {
        (0, 0) => tracing::info!(dir = %workflows.dir().display(), "no CI workflows"),
        (n, 0) => tracing::info!(count = n, "restored CI workflows"),
        (n, skipped) => tracing::warn!(
            count = n,
            skipped,
            dir = %workflows.dir().display(),
            "restored CI workflows; some objects were unreadable and were left on disk"
        ),
    }
    // Beside the others, same derivation: `app-lb-state.json` gives
    // `app-lb-namespaces.d/`.
    let namespace_dir = crate::namespaces::namespace_dir(&cfg.state_path);
    let namespaces = Arc::new(match &fleet_stores {
        Some(fs) => crate::namespaces::NamespaceStore::with_collection(namespace_dir, fs.namespaces.clone()),
        None => crate::namespaces::NamespaceStore::new(namespace_dir),
    });
    match namespaces.load() {
        (0, 0) => tracing::debug!(dir = %namespaces.dir().display(), "no declared namespaces"),
        (n, 0) => tracing::info!(count = n, "restored declared namespaces"),
        (n, skipped) => tracing::warn!(
            count = n,
            skipped,
            dir = %namespaces.dir().display(),
            "restored declared namespaces; some objects were unreadable and were left on disk"
        ),
    }
    // Plugins: which built-in plugins run, and with what configuration, is an
    // object per plugin beside the other stores. The host is built once the
    // secret store exists, which plugins resolve their credentials through.
    let plugin_store = match &fleet_stores {
        Some(fs) => plugins::PluginStore::with_collection(plugins::plugin_dir(&cfg.state_path), fs.plugins.clone()),
        None => plugins::PluginStore::new(plugins::plugin_dir(&cfg.state_path)),
    };
    match plugin_store.load() {
        (0, 0) => tracing::debug!(dir = %plugin_store.dir().display(), "no plugin records"),
        (n, 0) => tracing::info!(count = n, "restored plugin records"),
        (n, skipped) => tracing::warn!(
            count = n,
            skipped,
            dir = %plugin_store.dir().display(),
            "restored plugin records; some were unreadable and were left on disk"
        ),
    }
    let auth_provider_dir = crate::auth_providers::auth_provider_dir(&cfg.state_path);
    let auth_providers = Arc::new(match &fleet_stores {
        Some(fs) => crate::auth_providers::AuthProviderStore::with_collection(auth_provider_dir, fs.auth_providers.clone()),
        None => crate::auth_providers::AuthProviderStore::new(auth_provider_dir),
    });
    match auth_providers.load() {
        (0, 0) => tracing::debug!(dir = %auth_providers.dir().display(), "no declared auth providers"),
        (n, 0) => tracing::info!(count = n, "restored declared auth providers"),
        (n, skipped) => tracing::warn!(
            count = n,
            skipped,
            dir = %auth_providers.dir().display(),
            "restored declared auth providers; some objects were unreadable and were left on disk"
        ),
    }

    // A deregistration whose file removal failed would otherwise resurrect the
    // deployment on this start. Declines to run if the load above skipped
    // anything, so it can never delete a spec it merely failed to understand.
    match registry.sweep_orphan_state() {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "removed orphaned deployment state files"),
        Err(e) => tracing::warn!(error = %e, "failed to sweep orphaned state files"),
    }

    // Secrets are read straight from the environment rather than through
    // `LbConfig`, which derives `Debug` and `Serialize` — key material that is
    // never in the struct can never be printed out of it.
    let secret_key = secret_key_from_env();
    let secrets = Arc::new(match &fleet_stores {
        Some(fs) => SecretStore::with_document(&cfg.secrets_path, fs.secrets.clone(), secret_key),
        None => SecretStore::new(&cfg.secrets_path, secret_key),
    });
    match secrets.load() {
        Ok(0) => tracing::info!(path = %secrets.path().display(), "no stored secrets"),
        Ok(n) => tracing::info!(
            count = n,
            encrypted = secrets.is_encrypted(),
            "loaded secrets"
        ),
        // Fatal, unlike a bad deployment spec: starting with an empty store
        // would let the first write replace secrets that are perfectly good and
        // merely unreadable with the key this process was given.
        Err(e) => panic!(
            "cannot read {}: {e}",
            std::path::Path::new(&cfg.secrets_path).display()
        ),
    }
    // One store every namespace shares, with a key only app-lb holds: the
    // artifacts plugin's once the operator enables it, else this one. A bad
    // URL is logged and the gateway left off rather than taking the LB down:
    // every deployment that names its own store keeps working regardless.
    let env_store = match store_gateway::GlobalStore::from_env() {
        Ok(Some(store)) => {
            tracing::info!(
                store = store.base(),
                key = store.has_key(),
                "global artifact store from the environment: storeless `artifact` blocks pull \
                 from it and /namespaces/:name/artifacts fronts it until the artifacts plugin \
                 names another"
            );
            if !store.has_key() {
                tracing::warn!(
                    "{} is unset: the global store is used anonymously, so only public \
                     repositories pull and the artifacts API cannot write",
                    store_gateway::KEY_ENV
                );
            }
            Some(store)
        }
        Ok(None) => None,
        Err(e) => {
            tracing::error!(error = %e, "ignoring the global artifact store");
            None
        }
    };
    let store_slot = Arc::new(store_gateway::StoreSlot::new(env_store));
    // Filled by the tunnel plugin with the hostnames the cloud edge serves
    // TLS for, so ACME never orders certificates it cannot validate.
    let external_tls = plugins::tunnel::ExternalTlsHosts::default();
    // Handed its proxy and daemon client below, once both exist.
    let tunnel_plugin = plugins::tunnel::TunnelPlugin::new(
        plugins::tunnel::key_path(&cfg.state_path),
        external_tls.clone(),
    );
    let plugin_host = Arc::new(plugins::PluginHost::new(
        vec![
            plugins::pgfc::PgFcPlugin::new(secrets.clone()),
            plugins::vapi::VapiPlugin::new(secrets.clone()),
            plugins::obs::ObsPlugin::new(secrets.clone()),
            plugins::ci::CiPlugin::new(secrets.clone()),
            plugins::remote::RemotePlugin::new(secrets.clone()),
            plugins::secrets::SecretsPlugin::new(secrets.clone()),
            plugins::artifacts::ArtifactsPlugin::new(secrets.clone(), store_slot.clone()),
            tunnel_plugin.clone(),
            plugins::auth::AuthPlugin::new(
                plugins::auth::Kind::Heyo,
                auth_providers.clone(),
                registry.clone(),
                cfg.auth_url.clone(),
            ),
            plugins::auth::AuthPlugin::new(
                plugins::auth::Kind::Google,
                auth_providers.clone(),
                registry.clone(),
                cfg.auth_url.clone(),
            ),
            // Its ownership file sits beside the plugin records, in a
            // directory of its own so the record loader never reads it.
            match &fleet_stores {
                Some(fs) => plugins::postgres::PostgresPlugin::with_ownership_document(
                    secrets.clone(),
                    fs.pg_ownership.clone(),
                ),
                None => plugins::postgres::PostgresPlugin::new(
                    secrets.clone(),
                    plugin_store.dir().join("state"),
                ),
            },
        ],
        plugin_store,
    ).with_host(fleet_stores.as_ref().map(|fs| fs.host.clone())));
    // What a default-enabled plugin installs into on the boot that enables
    // it: declared namespaces and any a deployment names.
    let known_namespaces: plugins::KnownNamespaces = {
        let namespaces = namespaces.clone();
        let registry = registry.clone();
        Arc::new(move || {
            let mut all: std::collections::BTreeSet<String> =
                namespaces.list().iter().map(|n| n.name.clone()).collect();
            all.extend(registry.deployments().values().map(|d| d.spec.namespace.clone()));
            all.into_iter().collect()
        })
    };
    let tokens = Arc::new(match &fleet_stores {
        Some(fs) => tokens::TokenStore::with_document(&cfg.tokens_path, fs.tokens.clone()),
        None => tokens::TokenStore::new(&cfg.tokens_path),
    });
    match tokens.load() {
        Ok(0) => tracing::info!(path = %tokens.path().display(), "no app-tokens"),
        Ok(n) => tracing::info!(count = n, "loaded app-tokens"),
        // Fatal for the same reason the secret store is: starting with an empty
        // token store would revoke every client at once, and would look exactly
        // like a healthy server until their calls started failing.
        Err(e) => panic!(
            "cannot read {}: {e}",
            std::path::Path::new(&cfg.tokens_path).display()
        ),
    }
    // In a fleet, sweeping is the token-sweep lease holder's job, on the feed's
    // schedule: hosts sweeping at their own starts would conflict.
    match &fleet_stores {
        None => {
            if tokens.sweep_expired(deployment::now_secs()) > 0 {
                let _ = tokens.persist();
            }
        }
        Some(fs) => {
            let tokens = tokens.clone();
            fs.fleet.duty(fleet_sync::LEASE_TOKEN_SWEEP, std::time::Duration::from_secs(3600), move || {
                if tokens.sweep_expired(deployment::now_secs()) > 0
                    && let Err(e) = tokens.persist()
                {
                    tracing::warn!(error = %e, "expired tokens swept but not saved to the fleet store");
                }
            });
        }
    }
    // Fleet tokens last pulled from the token authority, so a restart while the
    // control plane is unreachable does not log those clients out here.
    match tokens.load_mirror() {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "loaded mirrored fleet tokens"),
        Err(e) => panic!("cannot read the fleet token mirror beside {}: {e}", cfg.tokens_path),
    }

    // Block rules, restored before the data plane accepts anything. Fatal on a
    // corrupt file, for the same reason the token store is: coming up with an
    // empty rule set would silently readmit whatever an operator blocked during
    // an incident, and would look exactly like a healthy server while doing it.
    let guard = Arc::new(match &fleet_stores {
        Some(fs) => guard::Guard::with_document(
            &cfg.guard_path,
            fs.guard.clone(),
            obs::env_flag("APP_LB_GUARD_ENFORCE", true),
        ),
        None => guard::Guard::from_env(&cfg.guard_path),
    });
    match guard.load(deployment::now_secs()) {
        Ok(0) => tracing::info!(path = %guard.path().display(), "no guard rules"),
        Ok(n) => tracing::info!(count = n, enforcing = guard.enforcing(), "loaded guard rules"),
        Err(e) => panic!("cannot read {}: {e}", guard.path().display()),
    }
    // Another host's change to one of these lands in its files through the
    // feed; this has the store that owns them pick it up.
    if let Some(fs) = &fleet_stores {
        let fleet = &fs.fleet;
        let s = namespaces.clone();
        fleet.on_reload("namespaces", move || {
            s.load();
        });
        let s = workflows.clone();
        fleet.on_reload("workflows", move || {
            s.load();
        });
        let s = auth_providers.clone();
        fleet.on_reload("auth-providers", move || {
            s.load();
        });
        let s = secrets.clone();
        fleet.on_reload("secrets", move || {
            if let Err(e) = s.load() {
                tracing::error!(error = %e, "could not apply the fleet's secrets; keeping the ones in memory");
            }
        });
        let s = tokens.clone();
        fleet.on_reload("tokens", move || {
            if let Err(e) = s.load() {
                tracing::error!(error = %e, "could not apply the fleet's tokens; keeping the ones in memory");
            }
        });
        let s = registry.clone();
        fleet.on_reload("deployments", move || s.apply_fleet_changes());
        let s = guard.clone();
        fleet.on_reload("guard", move || {
            if let Err(e) = s.load(deployment::now_secs()) {
                tracing::error!(error = %e, "could not apply the fleet's guard rules; keeping the ones in memory");
            }
        });
    }

    if !guard.enforcing() {
        tracing::warn!(
            "APP_LB_GUARD_ENFORCE=0: guard rules are matched and counted but nothing is \
             refused — this is a dry run, not protection",
        );
    }

    if !secrets.is_encrypted() {
        tracing::info!(
            path = %secrets.path().display(),
            "secrets are stored in plaintext (mode 0600); set APP_LB_SECRET_KEY to encrypt them",
        );
    }

    // Jobs run `git`, `docker` and — for a static deployment's update — whatever
    // its spec says, on this host. An ungated admin API is a remote code
    // execution surface. It was already a "boot VMs of your choosing" surface,
    // but this is worth saying out loud.
    if !cfg.admin_auth {
        tracing::warn!(
            admin = %cfg.admin_addr,
            "the deployment/secret/job API is not authenticated (set APP_LB_ADMIN_AUTH=1 \
             with APP_LB_DASHBOARD_PASSWORD); POST /deployments/:id/build runs git and \
             docker on this host, and POST /deployments/:id/update runs that deployment's \
             own commands",
        );

        // The blanket warning above assumes the admin listener is only on
        // loopback. This one fires when a registered deployment actually fronts
        // it through a sign-in gate: then the CRUD API is not merely open on
        // 127.0.0.1, it is reachable from wherever that deployment's hostname
        // resolves, with no credential at all. A gate's `public_paths` bypass
        // *sign-in* only — the admin listener's own CRUD gate is what
        // `admin_auth` turns on, and with it off nothing is left in front. And
        // because `is_public` matches by prefix (see `AuthGate::is_public`), a
        // single `/deployments` entry also exposes `POST /deployments/:id/build`
        // and `/update`: unauthenticated remote code execution on this host.
        // Best-effort — the upstream is matched to `admin_addr` as a string, so
        // an alias (`localhost` vs `127.0.0.1`) slips past, and the blanket
        // warning above still covers that. See the README, "Putting the
        // dashboard behind Google".
        for dep in registry.deployments().values() {
            let spec = &dep.spec;
            if !spec.upstreams.iter().any(|u| u == &cfg.admin_addr) {
                continue;
            }
            let Some(gate) = &spec.auth else { continue };
            let health = spec.health.path.as_deref();
            // Only the entries that still admit an unauthenticated request. A
            // scoped entry is no longer a bypass — app-lb checks the scope
            // itself — so listing one here would cry wolf about the very fix.
            let exposed: Vec<&str> = gate
                .public_paths
                .iter()
                .filter(|p| p.scope == crate::config::PathScope::Public)
                .map(|p| p.path.as_str())
                .filter(|p| *p != "/healthz" && Some(*p) != health)
                .collect();
            if !exposed.is_empty() {
                tracing::error!(
                    deployment = %spec.id,
                    admin = %cfg.admin_addr,
                    public_paths = ?exposed,
                    "deployment {:?} fronts the admin listener through a sign-in gate while \
                     APP_LB_ADMIN_AUTH is off: these public_paths bypass sign-in and reach the \
                     unauthenticated CRUD API. Paths match by prefix, so \"/deployments\" also \
                     exposes POST /deployments/:id/build and /update — remote code execution on \
                     this host. Set APP_LB_ADMIN_AUTH=1 (with APP_LB_DASHBOARD_PASSWORD) and \
                     restart.",
                    spec.id,
                );
            }
        }
    }

    // The key that signs sign-in sessions. Generated on first use and kept, so
    // a restart doesn't sign every user of a gated deployment out. Loaded even
    // when no deployment is gated — one file read, and it means enabling a gate
    // later needs no restart.
    let auth_key_path = auth_key_path();
    // Attack detection over the same requests the access log describes. Built
    // here because everything downstream takes a clone of its sink, and — like
    // `obs::from_env` — it allocates a channel and nothing else, so it survives
    // the fork `run_forever` may do to daemonize.
    //
    // Independent of `obs`: it needs no collector to be useful, and is on unless
    // `APP_LB_SIEM=0`. The sink it is handed here is only for *shipping* alerts
    // onward, which is why it is `None`-tolerant.
    let siem = siem::from_env(
        obs.as_ref().and_then(|o| o.events.clone()),
        obs.as_ref()
            .and_then(|o| o.events.as_ref().or(o.access.as_ref()))
            .map(|s| s.deployment())
            .unwrap_or_else(|| Arc::from(obs::LB_DEPLOYMENT)),
    );

    let auth_key = Authenticator::load_key(&auth_key_path)
        .unwrap_or_else(|e| panic!("cannot read or create {}: {e}", auth_key_path.display()));
    // A host that generated its signing key just now (none in its files, none
    // in the fleet) offers it to the fleet. Any other host's key that got
    // there first wins, and arrives here at the next start.
    if let Some(fs) = &fleet_stores
        && matches!(fleet_store::Document::read(&*fs.auth_key), Ok(Some((_, 0))))
    {
        match fleet_store::Document::write(&*fs.auth_key, &auth_key, fleet_store::Expect::Absent) {
            Ok(_) => tracing::info!("offered this host's session signing key to the fleet"),
            Err(e) => tracing::warn!(error = %e, "this host's session signing key is not the fleet's yet"),
        }
    }
    let auth = Arc::new(Authenticator::with_admin_addr(
        auth_key,
        secrets.clone(),
        Some(tokens.clone()),
        siem.as_ref().map(|s| s.sink.clone()),
        Some(cfg.admin_addr.clone()),
    ));

    let daemon_api_key = ["APP_LB_DAEMON_API_KEY", "HEYO_API_KEY"]
        .into_iter()
        .find_map(|name| {
            std::env::var(name)
                .ok()
                .and_then(|value| (!value.trim().is_empty()).then(|| value.trim().to_string()))
        });
    // Where guest mount trees live. Created up front so a path app-lb cannot
    // write to is a startup error rather than a pull that fails minutes later,
    // and so the directory exists with the right permissions before heyvmd is
    // ever pointed at something inside it.
    let mount_store = mounts::MountStore::new(cfg.mounts_dir.clone().into(), cfg.mount_ttl_secs);
    if let Err(e) = mount_store.ensure_root() {
        panic!("{e}. Set APP_LB_MOUNTS_DIR to a directory app-lb can write and heyvmd can read");
    }
    if cfg.mount_ttl_secs == 0 {
        tracing::info!(
            dir = %cfg.mounts_dir,
            "mount tree reclamation is off (APP_LB_MOUNT_TTL_SECS=0); trees no deployment \
             names are kept until they are removed by hand",
        );
    }

    let vms = VmManager::new(cfg.daemon_url.clone(), daemon_api_key, mount_store.clone())
        .unwrap_or_else(|e| panic!("cannot build the heyvm daemon client: {e}"));
    // Which transport won: a unix socket when the daemon published a live one,
    // else loopback TCP. Worth a line because nothing else reveals it — a
    // socket client reports `http://localhost` as its base URL, and the choice
    // is made from the environment rather than from app-lb's own config.
    tracing::info!(transport = %vms.transport(), "heyvm daemon transport");
    // Both runtimes. Building this cannot fail and does no I/O: whether Incus is
    // actually usable is asked once from the autoscaler's background service,
    // where there is a runtime to await on. A host with no Incus is a fact about
    // the host, not a misconfiguration — a fleet of microVMs never notices.
    let runtime = runtime::Runtime::new(vms.clone(), cfg.lxc.clone());
    // Kept for the sweeper, which is built after the last move of `registry`.
    let mount_registry = registry.clone();

    // The static cert pair, if configured. With ACME on it is the *fallback*,
    // served for any SNI without an issued cert of its own; with ACME off it is
    // the only certificate. Half-configured TLS stays a hard error rather than a
    // silent fallback to plaintext, so nobody thinks a listener is encrypted
    // when it isn't.
    let fallback = match (&cfg.tls_cert_path, &cfg.tls_key_path) {
        (Some(cert), Some(key)) => Some(Arc::new(
            CertStore::load_pair(cert, key)
                .unwrap_or_else(|e| panic!("failed to load TLS cert {cert} / key {key}: {e}")),
        )),
        (None, None) => None,
        _ => panic!("TLS is half-configured: set both APP_LB_TLS_CERT and APP_LB_TLS_KEY, or neither"),
    };

    // Before anything reads the cert directory: a change of ACME directory makes
    // every cached certificate and the saved account invalid, and neither
    // announces that itself.
    if cfg.acme_enabled() {
        acme::reset_if_directory_changed(
            std::path::Path::new(&cfg.acme_dir),
            &cfg.acme_directory,
        );
    }

    // Loaded from disk *before* the listener binds: the acceptor holds no
    // certificate of its own, so anything not in the store at bind time gets the
    // fallback (or a failed handshake) until ACME reissues it.
    let certs = Arc::new(match &fleet_stores {
        Some(fs) => CertStore::with_collections(fs.cert_chains.clone(), fs.cert_keys.clone(), fallback),
        None => CertStore::new(std::path::Path::new(&cfg.acme_dir).join("certs"), fallback),
    });
    if cfg.tls_enabled() {
        match certs.load_from_disk() {
            0 => tracing::info!("no cached certificates"),
            n => tracing::info!(count = n, "loaded cached certificates"),
        }
        if let Some(fs) = &fleet_stores {
            for kind in ["cert-chains", "cert-keys"] {
                let certs = certs.clone();
                fs.fleet.on_reload(kind, move || {
                    certs.load_from_disk();
                });
            }
        }
    }

    // Shared between the ACME manager (which publishes challenge responses) and
    // the proxy (which serves them).
    let challenges = Arc::new(ChallengeTable::new());
    // In a fleet the CA may ask any member, so every host answers every
    // host's outstanding challenges.
    let shared_challenges = fleet_stores.as_ref().map(|fs| {
        let shared = Arc::new(acme::SharedChallenges::new(
            fs.acme_challenges.clone(),
            fs.fleet.clone(),
            &fs.host,
        ));
        challenges.set_shared(shared.load());
        let (reloaded, table) = (shared.clone(), challenges.clone());
        fs.fleet.on_reload("acme-challenges", move || table.set_shared(reloaded.load()));
        shared
    });

    // One metrics registry, shared by the proxy (request latency), the
    // autoscaler (cold-start timing, scaling activity), and the admin API
    // (which serves the dashboard from it).
    let metrics = Arc::new(Metrics::new());

    // Note: nothing above may spawn threads or build a runtime — `run_forever`
    // may fork for daemonization and anything created before it would be lost.
    // The one exception is the fleet store's worker thread, started only in
    // fleet mode: app-lb never daemonizes (`Server::new(None)` reads no
    // daemon option), and the stores above need the database before this.
    // The manager holds no listener — the forwarding worker does — so it has
    // nothing to drain: on SIGTERM it exits at once, where pingora's default
    // grace period kept it for five minutes, until a supervisor's stop timeout
    // killed it. Every moment it lingers is a moment requests wait in the
    // worker for the next manager.
    let mut server = {
        let mut conf = pingora_core::server::configuration::ServerConf::new()
            .expect("pingora's default configuration");
        conf.grace_period_seconds = Some(0);
        conf.graceful_shutdown_timeout_seconds = Some(5);
        Server::new_with_opt_and_conf(None, conf)
    };
    server.bootstrap();

    // One event feed, shared by the admin API (lifecycle events), the
    // autoscaler (issues) and the proxy (cold-start timeouts, and serving any
    // feed a deployment exposes). In-memory; a restart starts it empty.
    let event_feed = std::sync::Arc::new(feed::Feed::new());

    // Disk management rides the daemon's own routes (`GET /storage`, purge,
    // archive), so there is no data directory to resolve and nothing here
    // can fail but a malformed number in the environment.
    let disk_cfg = match disks::DiskConfig::from_env(&cfg) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };

    // Deployment-owned workspaces (`vm.workspace`). Captures come from the
    // daemon's mount export, so app-lb needs only its own workspace root.
    let workspaces = Arc::new(workspace::Workspaces::new(
        workspace::WorkspaceConfig::from_env(&cfg),
        vms.clone(),
        registry.clone(),
        secrets.clone(),
    ));
    if let Err(e) = workspaces.ensure_root() {
        panic!("{e}. Set APP_LB_WORKSPACES_DIR to a directory app-lb can write");
    }
    match workspaces.load() {
        0 => {}
        n => tracing::info!(count = n, "loaded workspace records"),
    }

    // `background_service` hands back an Arc to the same task the service runs,
    // which is how the admin API reaches the autoscaler to tear deployments down.
    let autoscaler_svc = background_service(
        "autoscaler",
        Autoscaler::new(
            registry.clone(),
            runtime,
            metrics.clone(),
            event_feed.clone(),
            workspaces.clone(),
            secrets.clone(),
        ),
    );
    let autoscaler = autoscaler_svc.task();
    // The operations watcher starts only once existing VMs are adopted.
    let operations_adopted = autoscaler.adopted();
    let adopted = autoscaler.adopted();
    // A spread deployment another host removed is out of routing once the
    // registry applies the change; its VMs on this host's daemon go here.
    if let Some(fs) = &fleet_stores {
        let (registry, autoscaler) = (registry.clone(), autoscaler.clone());
        fs.fleet.on_reload("deployments", move || {
            for d in registry.take_fleet_removed() {
                let autoscaler = autoscaler.clone();
                tokio::spawn(async move { autoscaler.teardown(&d).await });
            }
        });
    }

    let disks = {
        let store = Arc::new(disks::DiskStore::new(disk_cfg, vms.clone(), registry.clone()).with_workspaces(workspaces.clone()));
        workspaces.attach_disk_store(&store);
        match store.load() {
            Ok(0) => {}
            Ok(n) => tracing::info!(count = n, "loaded disk retention policies"),
            // Not fatal, unlike the secret store: the worst case is that a
            // `retain` flag is missed, and the sweep's other four guards
            // (running, claimed, age, daemon reachable) still hold.
            Err(e) => tracing::error!(
                error = %e,
                "cannot read disk retention policies; every disk will be treated as \
                 unretained until this is fixed",
            ),
        }
        let c = store.config();
        if c.ttl_secs == 0 {
            tracing::info!(
                "disk expiry is off (APP_LB_DISK_TTL_SECS=0); disks are listed and can be \
                 purged by hand, but nothing is reclaimed automatically",
            );
        } else {
            // The count of what is already due is logged by the sweeper on its
            // first tick, once the daemon has been asked.
            tracing::info!(
                ttl_secs = c.ttl_secs,
                sweep_secs = c.sweep_secs,
                archive = c.bucket.is_some(),
                "disk expiry is ON; the first sweep runs in {}s and reclaims every unretained \
                 disk older than the retention window. Open /storage to review them first, or \
                 set APP_LB_DISK_TTL_SECS=0 to turn expiry off",
                c.sweep_secs,
            );
        }
        Some(store)
    };

    // app-lb's own scratch for images on their way to the daemon (pulls land
    // here, builds write here), uploaded into the daemon's catalog and
    // removed. Nothing the daemon reads, so nothing to align with its home.
    let images_dir = std::path::PathBuf::from(
        cfg.images_dir
            .clone()
            .unwrap_or_else(|| "/var/lib/app-lb/images".to_string()),
    );
    let image_scratch = images_dir.clone();

    // The job runner is not a service: it has no loop of its own, it runs a task
    // per job. It needs the autoscaler because finishing an image build means
    // rewriting `vm.image` and tearing the old pool down — the same swap the
    // admin API's update path does.
    let jobs = Arc::new(Jobs::new(
        JobConfig {
            work_dir: cfg.build_dir.clone().into(),
            heyvm_bin: cfg.heyvm_bin.clone(),
            art_bin: cfg.art_bin.clone(),
            images_dir,
            git_bin: cfg.git_bin.clone(),
            mounts: mount_store.clone(),
            shell: cfg.update_shell.clone(),
            timeout: std::time::Duration::from_secs(cfg.build_timeout_secs),
            home: cfg.heyvm_home.clone(),
            sites_dir: Some(cfg.sites_dir.clone().into()),
        },
        registry.clone(),
        autoscaler.clone(),
        secrets.clone(),
        // Job output is app-lb's own output, so it rides the same switch as the
        // event stream (`APP_LB_OBS_EVENTS`) rather than getting a third one.
        obs.as_ref().and_then(|o| o.events.clone()),
    ));

    // The image inventory: what heyvm's catalog holds, what references it,
    // and offload of what nothing has used in a while. Records live beside the
    // other stores, in `app-lb-images.d/`.
    let image_store = images::ImageStore::new(images::image_dir(&cfg.state_path));
    match image_store.load() {
        (0, 0) => tracing::debug!(dir = %image_store.dir().display(), "no image records"),
        (n, 0) => tracing::info!(count = n, "restored image records"),
        (n, skipped) => tracing::warn!(count = n, skipped, "restored image records; some were unreadable and were left on disk"),
    }
    let image_catalog = images::ImageCatalog::new(
        images::ImagesConfig::from_env(),
        image_store,
        autoscaler.vms().clone(),
        registry.clone(),
        secrets.clone(),
        artifact::Puller::new(cfg.art_bin.clone(), image_scratch, cfg.heyvm_home.clone(), autoscaler.vms().clone()),
    );
    image_catalog.set_jobs(&jobs);
    jobs.set_images(image_catalog.clone());
    jobs.set_global_store(store_slot.clone());
    autoscaler.set_images(image_catalog.clone());

    // ACME runs only when a contact address is configured. Its `Notify` goes to
    // the admin API so registering a deployment starts issuance immediately
    // rather than at the next 12-hour sweep.
    let acme_svc = cfg.acme_email.clone().map(|email| {
        background_service(
            "acme",
            {
                let config = AcmeConfig {
                    email,
                    dir: cfg.acme_dir.clone().into(),
                    directory_url: cfg.acme_directory.clone(),
                    proxy_addr: cfg.proxy_addr.clone(),
                    wildcards: cfg.acme_wildcards.clone(),
                    dns: cfg
                        .route53_zone_id
                        .clone()
                        .map(|zone| dns::Route53::new(cfg.aws_bin.clone(), zone)),
                    external_tls: external_tls.clone(),
                };
                match &fleet_stores {
                    Some(fs) => AcmeManager::with_documents(
                        registry.clone(),
                        certs.clone(),
                        challenges.clone(),
                        config,
                        fs.acme_account.clone(),
                        fs.acme_backoff.clone(),
                    )
                    .with_lease(fs.fleet.lease(fleet_sync::acme_lease(&fs.host)))
                    .with_shared_challenges(
                        shared_challenges.clone().expect("a fleet shares its challenges"),
                    ),
                    None => AcmeManager::new(registry.clone(), certs.clone(), challenges.clone(), config),
                }
            },
        )
    });
    let acme_signal = acme_svc.as_ref().map(|svc| svc.task().signal());
    // A deployment registered through another host's admin API reaches this
    // one by the feed, and its certificate is this host's to issue.
    if let (Some(fs), Some(signal)) = (&fleet_stores, &acme_signal) {
        let signal = signal.clone();
        fs.fleet.on_reload("deployments", move || signal.notify_one());
    }

    match cfg.deploy_host_base() {
        Some(base) => tracing::info!(
            base = %base,
            explicit = cfg.deploy_base_domain.is_some(),
            "a deployment that names no host will be routed at <id>.{base}"
        ),
        None => tracing::info!(
            "no deploy base domain (APP_LB_DEPLOY_BASE_DOMAIN or a wildcard); a hostless \
             deployment is handled as before"
        ),
    }

    // Background commands in sandboxes: the records sit beside the state file,
    // and the watcher holds each busy VM and follows its operations.
    // Dials `tunnel` deployments' remote app-lbs, from a key of this host's own.
    let tunnel_dialer = tunnel_dialer::TunnelDialer::open(&tunnel_dialer::key_path(&cfg.state_path), registry.clone())
        .unwrap_or_else(|e| panic!("cannot open the tunnel dialer's key: {e}"));

    let operations = operations::Operations::open(
        std::path::Path::new(&cfg.state_path).with_extension("operations.json"),
        registry.clone(),
        vms.clone(),
    );

    // One-time transfer URLs for large files, when a public base is configured.
    let transfers = transfers::TransferConfig::from_env(
        std::path::Path::new(&cfg.state_path).with_extension("transfers"),
    )
    .and_then(|tcfg| {
        let url = tcfg.public_url.clone();
        match transfers::Transfers::open(tcfg, registry.clone(), vms.clone(), metrics.clone(), event_feed.clone()) {
            Ok(t) => {
                tracing::info!(url = %url, "transfers enabled");
                Some(t)
            }
            Err(e) => {
                tracing::error!(error = %e, "transfers disabled: cannot use their directory");
                None
            }
        }
    });

    let admin_svc = background_service(
        "admin",
        AdminApi::new(
            cfg.admin_addr.clone(),
            registry.clone(),
            autoscaler,
            metrics.clone(),
            cfg.name.clone(),
            cfg.dashboard_user.clone(),
            cfg.dashboard_password.clone(),
            cfg.dashboard_auth,
            cfg.admin_auth,
            cfg.auth_url.as_ref().map(|u| {
                tracing::info!(
                    auth_url = %u,
                    cache_secs = cfg.auth_cache_secs,
                    "federated admin auth enabled: heyo bearers are resolved to namespace grants"
                );
                Arc::new(crate::federated::FederatedAuth::new(
                    u.clone(),
                    cfg.auth_cache_secs,
                    cfg.auth_timeout_secs,
                ))
            }),
            certs.clone(),
            acme_signal,
            secrets.clone(),
            workflows,
            namespaces,
            auth_providers.clone(),
            tokens,
            jobs,
            obs.as_ref().map(|o| o.stats.clone()),
            siem.as_ref(),
            guard.clone(),
            disks.clone(),
            admin::PublicUrl::from_config(cfg.tls_enabled(), &cfg.proxy_addr, &cfg.tls_addr),
            event_feed.clone(),
            &cfg.public_ips,
            cfg.deploy_host_base().map(str::to_string),
            plugin_host.clone(),
        ).with_views(Arc::new(fleet::ViewStore::open(
            std::path::Path::new(&cfg.state_path).with_extension("views.json"), secrets.clone(),
            ["APP_LB_FLEET_FILE", "APP_LB_CONTROL_PLANE_FILE"].map(|key| std::env::var_os(key).map(Into::into)),
        ).unwrap_or_else(|error| panic!("invalid view configuration: {error}"))))
        .with_images(image_catalog.clone())
        .with_artifact_store(store_slot.clone())
        .with_fleet_store(fleet_stores.as_ref().map(|fs| fs.fleet.clone()))
        .with_operations(operations.clone())
        .with_tunnel_dialer(tunnel_dialer.clone())
        .with_transfers(transfers.clone()),
    );

    // Fleet mode: hops between members. The peer token is fleet state; the
    // first host to need one makes it.
    let fleet_hop = fleet_stores.as_ref().map(|fs| {
        let forward = obs::env_flag(fleet_hop::FORWARD_ENV, false);
        let hop = Arc::new(fleet_hop::FleetHop::new(&fs.host, fs.fleet.clone(), forward));
        let read = {
            let doc = fs.peer_token.clone();
            move || {
                fleet_store::Document::read(&*doc)
                    .ok()
                    .flatten()
                    .and_then(|(b, _)| String::from_utf8(b).ok())
                    .filter(|t| t.len() >= 32)
            }
        };
        if read().is_none() {
            match fleet_store::Document::write(&*fs.peer_token, fleet_hop::new_token().as_bytes(), fleet_store::Expect::Absent) {
                Ok(_) => tracing::info!("made the fleet's peer token"),
                Err(e) => tracing::warn!(error = %e, "could not make the fleet's peer token; another host's will arrive"),
            }
        }
        hop.set_token(read());
        let reloaded = hop.clone();
        fs.fleet.on_reload("peer-token", move || reloaded.set_token(read()));
        tracing::info!(forward, "fleet hops: accepted from peers{}", if forward { ", and made to them" } else { "" });
        hop
    });
    // Where `spread` deployments' replicas run, fleet-wide.
    let placer = fleet_stores.as_ref().map(|fs| {
        let placer = Arc::new(fleet_placement::Placer::new(
            &fs.host,
            fs.fleet.clone(),
            registry.clone(),
            fleet_hop.as_ref().is_some_and(|h| h.forwards()),
        )
        // DNS TTL plus health-check detection plus margin.
        .with_drain_quiet(
            std::env::var("APP_LB_FLEET_DRAIN_QUIET_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .map_or(fleet_placement::DEFAULT_DRAIN_QUIET, std::time::Duration::from_secs),
        ));
        fleet_placement::install(placer.clone());
        placer
    });
    // Tunnel streams are served in this process, by the same thin proxy the
    // forwarding worker runs, asking this manager for each decision over the
    // same socket. They arrive over the manager's iroh endpoint, so they do
    // not outlive it the way the worker's listeners do; the edge redials.
    tunnel_plugin.attach(
        Arc::new(pingora_proxy::http_proxy(
            &server.configuration,
            proxy::LbProxy::for_tunnel_ingress(
                worker_rpc::Client::new(worker_dir.join("requests")),
                external_tls.clone(),
            ),
        )),
        vms.client().clone(),
    );
    let proxy_svc = background_service("forwarding-worker", worker::Supervisor {
        control: Arc::new(request_control::RequestControl::new(
            registry.clone(), metrics.clone(), challenges, auth, guard.clone(),
            event_feed, auth_providers.clone(), secrets.clone(),
        ).with_stripped_cookies(cfg.strip_cookies.clone()).with_fleet_hop(fleet_hop)),
        metrics,
        access_log: obs.as_ref().and_then(|o| o.access.clone()),
        security: siem.as_ref().map(|s| s.sink.clone()),
        certs,
        proxy_addr: cfg.proxy_addr.clone(),
        tls_addr: cfg.tls_enabled().then(|| cfg.tls_addr.clone()),
        dir: worker_dir,
        adopted: Some(adopted),
    });

    tracing::info!(proxy = %cfg.proxy_addr, admin = %cfg.admin_addr, "starting app-lb");

    let autoscaler_handle = server.add_service(autoscaler_svc);
    if let Some(placer) = placer {
        server.add_service(background_service("fleet-placement", fleet_placement::Service(placer)));
    }
    server.add_service(background_service("tunnel-dialer", tunnel_dialer::Service(tunnel_dialer)));
    server.add_service(admin_svc);
    server.add_service(background_service(
        "discovery",
        discovery::DiscoveryWatcher::new(discovery_cfg, registry, secrets),
    ));
    // Log shipping, when `APP_LB_OBS_URL` is set. Pointedly *not* a dependency of
    // the proxy handle below: whether this service is running, and whether app-obs
    // answers it, must make no difference to serving traffic.
    if let Some(obs) = obs {
        server.add_service(background_service("obs", obs.shipper));
    }
    // Detection, on the same terms as log shipping: deliberately not a
    // dependency of the proxy handle. A stalled or failed analyzer must degrade
    // to losing findings, never to holding up traffic.
    if let Some(siem) = siem {
        server.add_service(background_service("siem", siem.engine));
    }
    if let Some(acme_svc) = acme_svc {
        server.add_service(acme_svc);
    }
    // Disk reclamation, on the same terms as the two above: never a dependency
    // of the proxy handle. It walks directories and shells out to `aws`, and
    // neither may hold up traffic.
    if let Some(disks) = disks {
        server.add_service(background_service("disks", disks::DiskSweeper::new(disks)));
    }
    // The operations watcher and the transfer sweep. Never spawned from `main`
    // directly: there is no runtime here until the server starts one.
    server.add_service(background_service("operations", operations::Watcher(operations, operations_adopted)));
    if let Some(t) = transfers {
        server.add_service(background_service("transfers", transfers::Sweeper(t)));
    }
    // Mount-tree reclamation, on the same terms. Cheaper than the disk sweep —
    // it reads one directory and compares names against the registry — but it
    // unlinks gigabytes when it does act, which is not work for the proxy's
    // path.
    if cfg.mount_ttl_secs > 0 {
        server.add_service(background_service(
            "mounts",
            mounts::MountSweeper::new(
                mount_store,
                mount_registry,
                mounts::DEFAULT_SWEEP_SECS,
                vms.clone(),
            ),
        ));
    }
    // Workspace captures, pushes and restores: gigabytes of disk and network
    // I/O, run one at a time off the proxy's path.
    server.add_service(background_service(
        "workspaces",
        workspace::WorkspaceWorker::new(workspaces.clone()),
    ));
    if let Some(fs) = &fleet_stores {
        server.add_service(background_service("fleet-feed", fleet_sync::FleetFeed::new(fs.fleet.clone())));
    }
    // Plugins own their tasks; this only starts the enabled ones and stops
    // them on shutdown. Not a dependency of the proxy, like the others.
    server.add_service(background_service("plugins", plugins::PluginService::new(plugin_host, known_namespaces)));
    // Offloads idle images one at a time, standing down while pools boot.
    server.add_service(background_service("images", images::ImagePacer::new(image_catalog.clone())));
    // Pulls and holds APP_LB_IMAGE_WARM, so its first VM is never a cold fetch.
    server.add_service(background_service("image-warmer", images::ImageWarmer::new(image_catalog)));
    let proxy_handle = server.add_service(proxy_svc);
    // Don't accept traffic until the autoscaler has adopted existing VMs and
    // built the warm pool; otherwise the first requests all eat a cold start.
    proxy_handle.add_dependency(&autoscaler_handle);

    server.run_forever();
}
