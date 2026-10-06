//! Deployment specs and LB configuration.

use crate::secrets::SecretRef;
use heyo_sdk::{SandboxDriver, SandboxSize};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

fn default_proxy_addr() -> String {
    "0.0.0.0:6188".into()
}
fn default_admin_addr() -> String {
    "127.0.0.1:9090".into()
}
fn default_state_path() -> String {
    "app-lb-state.json".into()
}
fn default_secrets_path() -> String {
    "app-lb-secrets.json".into()
}
fn default_tokens_path() -> String {
    "app-lb-tokens.json".into()
}
fn default_guard_path() -> String {
    "app-lb-guard.json".into()
}
fn default_name() -> String {
    "app-lb".into()
}

/// Process-level configuration, supplied via CLI/env rather than the admin API.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LbConfig {
    #[serde(default = "default_proxy_addr")]
    pub proxy_addr: String,
    #[serde(default = "default_admin_addr")]
    pub admin_addr: String,
    #[serde(default = "default_state_path")]
    pub state_path: String,
    /// Where stored secrets live. A separate file from `state_path` because it
    /// has different handling: `0600`, and sealed when a key is configured.
    #[serde(default = "default_secrets_path")]
    pub secrets_path: String,
    /// Where minted app-tokens live. Its own file, `0600`, for the same reason
    /// the secret store has one: it holds credentials and wants different
    /// handling from the deployment state. Only each token's hash is written, so
    /// unlike the secret store there is nothing here to encrypt.
    #[serde(default = "default_tokens_path")]
    pub tokens_path: String,
    /// Where the guard's block rules live. Persisted for one reason: a restart
    /// that silently unblocks an address somebody blocked during an incident is
    /// a worse failure than any other this file can have.
    #[serde(default = "default_guard_path")]
    pub guard_path: String,
    /// Display name shown in the dashboard header and page title. Defaults to
    /// `app-lb`.
    #[serde(default = "default_name")]
    pub name: String,
    /// heyvm daemon base URL. Defaults to `HeyoClient::local()`'s target.
    pub daemon_url: Option<String>,
    /// Optional HTTP Basic Auth gate on the dashboard and its `/metrics` data
    /// source. Auth is enabled iff `password` is set; `user` defaults to
    /// `"admin"`. The rest of the admin API (deployment CRUD, healthz) is
    /// unaffected — it stays bound to `admin_addr`, localhost by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashboard_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashboard_password: Option<String>,
    /// Whether a configured password actually gates the dashboard view tier
    /// (`/`, `/dashboard`, `/metrics`, `/security`, …). Defaults to true — a
    /// password alone turns the gate on, as ever. Setting it to false keeps
    /// the password for the CRUD gate (`admin_auth`) and token minting while
    /// leaving the browser-facing pages open, which is the shape a deployment
    /// with its own sign-in (e.g. Google auth) in front of the dashboard
    /// needs: humans authenticate at that layer, machines still meet Basic on
    /// the API. With nothing in front, false exposes the view tier —
    /// `/security` included — to whoever can reach `admin_addr`.
    #[serde(default = "default_true")]
    pub dashboard_auth: bool,
    /// When true, the Basic-auth gate also covers the deployment CRUD API
    /// (register/edit/scale/delete/evict and the spec-revealing reads), not just
    /// the dashboard view. It reuses the dashboard credentials, so this requires
    /// `dashboard_password` to be set. `/healthz` stays open for probes.
    #[serde(default)]
    pub admin_auth: bool,
    /// Base URL of the Heyo auth service. Setting it turns on *federated*
    /// auth on the admin API: a bearer that is not one of app-lb's own tokens
    /// is resolved to a set of namespace grants by `GET /api/auth/scopes`
    /// there. Needs `admin_auth`, since only the gate consults it. See
    /// `federated.rs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    /// How long a resolved grant is trusted before it is re-fetched. Bounded
    /// above by the token's own expiry. Also the ceiling on revocation
    /// latency.
    #[serde(default = "default_auth_cache_secs")]
    pub auth_cache_secs: u64,
    /// Per-request timeout for the scopes lookup. An unreachable auth service
    /// fails closed, so this is also how long a caller waits to learn that.
    #[serde(default = "default_auth_timeout_secs")]
    pub auth_timeout_secs: u64,
    /// HTTPS listener for the proxy data plane, bound *in addition to* the
    /// plaintext `proxy_addr`. Enabled when ACME is on or a static cert pair is
    /// configured. Managed VM upstreams stay plaintext on their host-local tap
    /// network; static upstreams may explicitly use HTTPS.
    #[serde(default = "default_tls_addr")]
    pub tls_addr: String,
    /// Whether `tls_addr` was configured explicitly rather than defaulted.
    /// Setting it while TLS stays disabled is a misconfiguration worth warning
    /// about — the HTTPS listener is silently skipped otherwise. Not part of the
    /// serialized form; it describes how the config was built, not what it says.
    #[serde(skip)]
    pub tls_addr_explicit: bool,
    /// A static certificate pair. Once ACME is enabled this is the *fallback*,
    /// served for any SNI with no issued certificate of its own (a `host_suffix`
    /// deployment, or a host whose issuance hasn't completed). Both or neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_path: Option<String>,
    /// ACME account contact. Setting it is what enables automatic certificates;
    /// leaving it unset keeps app-lb's behaviour entirely static.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_email: Option<String>,
    /// Where the ACME account key and issued certificates are stored. Should be
    /// mode `0700` — it holds private keys.
    #[serde(default = "default_acme_dir")]
    pub acme_dir: String,
    /// ACME directory URL. Defaults to Let's Encrypt production; point it at
    /// staging for any testing, because production rate limits are per-account
    /// per-week and a failed-validation loop will lock issuance out for hours.
    #[serde(default = "default_acme_directory")]
    pub acme_directory: String,
    /// Scratch space for git checkouts driven by `build`. One directory per
    /// deployment, kept between builds so a rebuild is a fetch rather than a
    /// full clone.
    #[serde(default = "default_build_dir")]
    pub build_dir: String,
    /// Where app-lb keeps site roots it manages itself, such as a site built
    /// from a git remote. A site `build` into a root under here gets its
    /// parent directories created.
    #[serde(default = "default_sites_dir")]
    pub sites_dir: String,
    /// The `heyvm` CLI that turns a Dockerfile into a guest rootfs. Image
    /// building has no daemon API — it needs a local `docker`, `mke2fs` and
    /// `fakeroot` — so app-lb shells out to the binary on this host.
    #[serde(default = "default_heyvm_bin")]
    pub heyvm_bin: String,
    /// The `art` CLI that materializes a rootfs out of a *local* artifact store.
    /// Only reached when a deployment's `artifact.store` is a path; a store
    /// reached by URL needs no binary here, because app-lb streams the blob
    /// itself.
    #[serde(default = "default_art_bin")]
    pub art_bin: String,
    /// Where a pulled rootfs is written so heyvmd can boot it. Unset resolves
    /// the same way mvm-ctrl does: `$MVM_DATA_DIR/images/firecracker`, else
    /// `<home>/.heyo/images/firecracker` — where `<home>` is `heyvm_home` when
    /// set, because that is the daemon's home and the daemon only finds images
    /// under its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images_dir: Option<String>,
    /// Where a guest mount's tree is unpacked, content-addressed by the digest of
    /// the bundle it came from. Read by heyvmd when it builds each VM's mount
    /// image, so it must be a path the daemon's user can read.
    ///
    /// Unlike `images_dir` this is app-lb's own directory rather than one the
    /// daemon owns: the daemon is handed the path, and never has to find it.
    #[serde(default = "default_mounts_dir")]
    pub mounts_dir: String,
    /// How long a mount tree that no deployment names survives before the sweep
    /// removes it. `0` turns reclamation off, leaving every tree until somebody
    /// deletes it by hand.
    ///
    /// Shorter than the disk retention window by design — see
    /// [`crate::mounts::DEFAULT_TTL_SECS`].
    #[serde(default = "default_mount_ttl_secs")]
    pub mount_ttl_secs: u64,
    /// How to reach Incus. Only consulted for `driver: lxc` deployments; a
    /// fleet of microVMs never touches it.
    #[serde(default)]
    pub lxc: LxcConfig,
    #[serde(default = "default_git_bin")]
    pub git_bin: String,
    /// The `aws` CLI, used for the DNS-01 challenge. Only reached when
    /// `acme_wildcards` is non-empty.
    #[serde(default = "default_aws_bin")]
    pub aws_bin: String,
    /// Domains to certify with a **wildcard** certificate, e.g.
    /// `sb.example.com` → a cert covering `sb.example.com` and
    /// `*.sb.example.com`.
    ///
    /// This is what makes a fleet of sandboxes possible. Let's Encrypt caps new
    /// certificates at 50 per registered domain per week, so issuing per
    /// hostname stops working on the first afternoon; one wildcard covers every
    /// hostname under it forever. Any exact `host` route covered by one of these
    /// is skipped by the per-host issuer for the same reason.
    ///
    /// Needs `route53_zone_id`: wildcards are only issued over DNS-01.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acme_wildcards: Vec<String>,
    /// The addresses DNS should point a deployment's hostname at — this LB's
    /// public IPs (`APP_LB_PUBLIC_IPS`). Purely informational: served by
    /// `GET /ingress` so a client can show the A/AAAA records to add. app-lb
    /// never writes DNS itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_ips: Vec<std::net::IpAddr>,
    /// The Route 53 hosted zone holding `acme_wildcards`, where the DNS-01
    /// challenge records are written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route53_zone_id: Option<String>,
    /// Base domain under which a deployment that names no host of its own is
    /// given one: `<id>.<base>`. Set with `APP_LB_DEPLOY_BASE_DOMAIN`.
    ///
    /// Left unset it falls back to the first `acme_wildcards` entry (see
    /// [`deploy_host_base`]), which is the domain that already has a wildcard
    /// certificate and DNS pointing at this LB — so a synthesized host gets TLS
    /// and resolves with no further setup. Point it elsewhere only if a
    /// different base should carry the generated names, and then make sure that
    /// domain is covered by a certificate and resolves here, since app-lb writes
    /// neither DNS nor a per-host cert for a name outside its wildcards.
    ///
    /// [`deploy_host_base`]: LbConfig::deploy_host_base
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy_base_domain: Option<String>,
    /// Cookies removed from every request before it is forwarded to a VM or
    /// upstream, whatever the deployment (`APP_LB_STRIP_COOKIES`).
    ///
    /// A sign-in cookie set on a parent domain (`Domain=.example.com`) is sent
    /// by the browser to every host under it, and app-lb otherwise passes the
    /// `Cookie` header through untouched. On a host where tenants share that
    /// domain, one tenant's deployment would receive every other signed-in
    /// user's token. Naming the cookie here keeps it between the browser and
    /// app-lb: gates still read it, since they run before forwarding, and the
    /// deployment's code never sees it. Names match exactly (cookie names are
    /// case-sensitive).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strip_cookies: Vec<String>,
    /// Shell that a static deployment's `update.commands` run through. They are
    /// written as shell lines (`git pull && cargo build --release`), so there is
    /// one; pointing this at `bash` buys bashisms.
    #[serde(default = "default_update_shell")]
    pub update_shell: String,
    /// Ceiling on one build step (checkout, then image build), after which the
    /// child is killed. A stuck `docker build` must not hold a deployment's
    /// build slot forever.
    #[serde(default = "default_build_timeout_secs")]
    pub build_timeout_secs: u64,
    /// `HOME` for the `heyvm` child, when app-lb does not run as the same user
    /// as heyvmd. It decides where the built image lands
    /// (`$HOME/.heyo/images/firecracker/<name>.ext4`) — and the daemon only
    /// finds images under *its own* home, so a mismatch builds successfully and
    /// then boots nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heyvm_home: Option<String>,
}

fn default_tls_addr() -> String {
    "0.0.0.0:6189".into()
}
fn default_build_dir() -> String {
    "/var/lib/app-lb/builds".into()
}
fn default_sites_dir() -> String {
    "/var/lib/app-lb/sites".into()
}
fn default_heyvm_bin() -> String {
    "heyvm".into()
}
fn default_art_bin() -> String {
    "art".into()
}
fn default_git_bin() -> String {
    "git".into()
}
fn default_mounts_dir() -> String {
    "/var/lib/app-lb/mounts".into()
}
fn default_mount_ttl_secs() -> u64 {
    crate::mounts::DEFAULT_TTL_SECS
}
fn default_aws_bin() -> String {
    "aws".into()
}
fn default_update_shell() -> String {
    "/bin/sh".into()
}
fn default_build_timeout_secs() -> u64 {
    1800
}
fn default_acme_dir() -> String {
    "/var/lib/app-lb/acme".into()
}
fn default_acme_directory() -> String {
    crate::acme::AcmeConfig::production_directory()
}

impl Default for LbConfig {
    fn default() -> Self {
        Self {
            proxy_addr: default_proxy_addr(),
            admin_addr: default_admin_addr(),
            state_path: default_state_path(),
            secrets_path: default_secrets_path(),
            tokens_path: default_tokens_path(),
            guard_path: default_guard_path(),
            name: default_name(),
            daemon_url: None,
            dashboard_user: None,
            dashboard_password: None,
            dashboard_auth: true,
            admin_auth: false,
            auth_url: None,
            auth_cache_secs: default_auth_cache_secs(),
            auth_timeout_secs: default_auth_timeout_secs(),
            tls_addr: default_tls_addr(),
            tls_addr_explicit: false,
            tls_cert_path: None,
            tls_key_path: None,
            acme_email: None,
            acme_dir: default_acme_dir(),
            acme_directory: default_acme_directory(),
            build_dir: default_build_dir(),
            sites_dir: default_sites_dir(),
            heyvm_bin: default_heyvm_bin(),
            art_bin: default_art_bin(),
            images_dir: None,
            lxc: LxcConfig::default(),
            git_bin: default_git_bin(),
            mounts_dir: default_mounts_dir(),
            mount_ttl_secs: default_mount_ttl_secs(),
            aws_bin: default_aws_bin(),
            acme_wildcards: Vec::new(),
            public_ips: Vec::new(),
            route53_zone_id: None,
            deploy_base_domain: None,
            strip_cookies: Vec::new(),
            update_shell: default_update_shell(),
            build_timeout_secs: default_build_timeout_secs(),
            heyvm_home: None,
        }
    }
}

impl LbConfig {
    /// The base domain a hostless deployment's name is built under, or `None`
    /// when there is nowhere sensible to put one. An explicit
    /// `deploy_base_domain` wins; otherwise the first wildcard is used, because
    /// a name under it already has a certificate and DNS. With neither, host
    /// synthesis is simply off and a hostless deployment is handled as before.
    pub fn deploy_host_base(&self) -> Option<&str> {
        self.deploy_base_domain
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| self.acme_wildcards.iter().map(|w| w.trim()).find(|w| !w.is_empty()))
    }

    /// ACME is on iff a contact address was configured.
    pub fn acme_enabled(&self) -> bool {
        self.acme_email.is_some()
    }

    /// Whether to bind the HTTPS listener at all. ACME alone is enough: it will
    /// have certificates shortly even if none exist at startup.
    pub fn tls_enabled(&self) -> bool {
        self.acme_enabled() || self.tls_cert_path.is_some()
    }
}

/// How a request is matched to a deployment.
///
/// A rule matches when *every* populated field matches. An empty rule matches
/// nothing (rejected at registration) rather than everything, so a typo can't
/// silently swallow all traffic.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct RouteRule {
    /// Exact hostname match, case-insensitive, port stripped. For HTTP/2 this
    /// is matched against `:authority`, which carries no `Host` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Subdomain (wildcard) host match: a domain whose apex *and* any subdomain
    /// match — `host_suffix: "apps.example.com"` routes `apps.example.com`,
    /// `a.apps.example.com`, and `x.y.apps.example.com`, but not
    /// `notapps.example.com` (the match is anchored at a label boundary). A
    /// leading dot is accepted and ignored, so `.apps.example.com` is equivalent.
    /// An exact `host` always outranks a `host_suffix`, and a longer suffix
    /// outranks a shorter one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_suffix: Option<String>,
    /// Path prefix match, e.g. `/api`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    /// Remove `path_prefix` before forwarding to the upstream. Off by default,
    /// preserving the original pass-through behavior for existing specs.
    #[serde(default, skip_serializing_if = "is_false")]
    pub strip_prefix: bool,
}

impl RouteRule {
    pub fn is_empty(&self) -> bool {
        self.host.is_none() && self.host_suffix.is_none() && self.path_prefix.is_none()
    }

    /// Longer/more-specific rules must win, so rules are ranked before matching.
    /// The tiers don't overlap: an exact host beats *any* subdomain rule, which
    /// beats any path-only rule; within a tier a longer suffix or path wins.
    pub fn specificity(&self) -> usize {
        let mut score = 0usize;
        if self.host.is_some() {
            score += 1_000_000;
        }
        if let Some(s) = &self.host_suffix {
            score += 100_000 + s.trim_start_matches('.').len();
        }
        score + self.path_prefix.as_ref().map_or(0, |p| p.len())
    }

    pub fn matches(&self, host: Option<&str>, path: &str) -> bool {
        if self.is_empty() {
            return false;
        }
        if let Some(want) = &self.host {
            match host {
                Some(got) if got.eq_ignore_ascii_case(want) => {}
                _ => return false,
            }
        }
        if let Some(suffix) = &self.host_suffix {
            match host {
                Some(got) if host_in_domain(got, suffix) => {}
                _ => return false,
            }
        }
        if let Some(prefix) = &self.path_prefix
            && !path.starts_with(prefix.as_str())
        {
            return false;
        }
        true
    }
}

/// Whether `host` is the domain `suffix` itself or a subdomain of it, matched at
/// a label boundary so `apps.example.com` covers `a.apps.example.com` but never
/// `notapps.example.com`. Case-insensitive; a leading dot on `suffix` is ignored.
fn host_in_domain(host: &str, suffix: &str) -> bool {
    let suffix = suffix.trim_start_matches('.');
    if suffix.is_empty() {
        return false;
    }
    if host.eq_ignore_ascii_case(suffix) {
        return true; // apex
    }
    // A proper subdomain: the char just before the suffix must be a dot, so
    // `notapps.example.com` doesn't match suffix `apps.example.com`.
    host.len() > suffix.len()
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn default_target_concurrency() -> u32 {
    10
}

fn is_false(value: &bool) -> bool {
    !*value
}
fn default_max_replicas() -> u32 {
    5
}
fn default_scale_to_zero_after_secs() -> u64 {
    300
}
fn default_cold_start_timeout_secs() -> u64 {
    120
}
fn default_drain_timeout_secs() -> u64 {
    30
}
/// Deliberately several times `default_cold_start_timeout_secs`. The two bound
/// different things: a request gives up long before the VM does, because a boot
/// that overran one caller's patience may still be the boot that serves the next
/// one. Five minutes is past the point where a Firecracker guest that is going to
/// come up has come up, so what is left is a guest whose server never started.
fn default_boot_timeout_secs() -> u64 {
    300
}

/// What becomes of a VM the autoscaler no longer needs.
///
/// The distinction only exists because a *sandbox* is not a replica. Retiring
/// one of four interchangeable web VMs should reclaim everything it held;
/// retiring the single VM that is somebody's working directory should not.
///
/// Note what `Retain` can and cannot keep: a stopped sandbox keeps its record
/// and its **`/workspace` data disk** (`vm.disk_size_gb`), and loses its memory
/// and any writes to the rootfs. For Firecracker the daemon enforces that —
/// the rootfs is recopied from the base image on every cold boot — and for KVM
/// the autoscaler does, by discarding the persisted rootfs copy right after a
/// suspend rather than parking a gigabyte per idle replica. A `Retain`
/// deployment with no data disk therefore saves boot time and nothing else.
/// Persistent state has to live under `/workspace`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum IdleAction {
    /// Kill it: the sandbox, its data disk and its rootfs all go. The default,
    /// and right for a pool of interchangeable replicas.
    #[default]
    Destroy,
    /// Stop it: the sandbox stays, keeping its data disk, and a later request or
    /// `exec` resumes it instead of booting a fresh one.
    Retain,
}

/// Which runtime boots a deployment's replicas.
///
/// app-lb's own enum rather than [`heyo_sdk::SandboxDriver`], because not every
/// driver is a heyvm one: `lxc` is a system container app-lb creates on this
/// host through Incus, and the SDK has no name for it. The spellings are
/// deliberately identical to the SDK's, so a spec written against either
/// deserializes the same and the wire fixtures are unchanged.
///
/// `Libvirt` and `FirecrackerContainerd` exist here only so that a spec naming
/// one still *deserializes* and is then refused by
/// [`DeploymentSpec::validate`] with an explanation. Dropping the variants
/// would turn a good error message into an opaque serde failure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Driver {
    #[default]
    Firecracker,
    Kvm,
    /// A system container under Incus, booted from an OCI image. Not a heyvm
    /// driver: app-lb talks to Incus itself, so [`Driver::heyvm`] is `None`.
    Lxc,
    Libvirt,
    #[serde(rename = "firecracker_containerd")]
    FirecrackerContainerd,
}

impl Driver {
    /// The SDK's name for this driver, or `None` when the daemon has none —
    /// which is what makes "can heyvmd boot this?" a compile-time question at
    /// every call site rather than a string comparison.
    pub fn heyvm(self) -> Option<SandboxDriver> {
        match self {
            Self::Firecracker => Some(SandboxDriver::Firecracker),
            Self::Kvm => Some(SandboxDriver::Kvm),
            Self::Lxc | Self::Libvirt | Self::FirecrackerContainerd => None,
        }
    }

    pub fn is_lxc(self) -> bool {
        matches!(self, Self::Lxc)
    }

    /// The wire spelling, which is also what an error message should print.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::Kvm => "kvm",
            Self::Lxc => "lxc",
            Self::Libvirt => "libvirt",
            Self::FirecrackerContainerd => "firecracker_containerd",
        }
    }
}

impl std::fmt::Display for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How app-lb reaches Incus, for `driver: lxc` deployments.
///
/// Every field has a working default, because the common case is a host where
/// Incus is installed the ordinary way. What has no default is *permission*:
/// see `project`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct LxcConfig {
    /// Whether `driver: lxc` may be used at all. Off explicitly disables it
    /// even on a host that has Incus; on is not a promise that Incus works,
    /// only that app-lb should try.
    pub enabled: bool,
    /// Incus's API socket. Its absence is how app-lb decides this host has no
    /// Incus, so pointing it somewhere wrong disables `lxc` rather than failing
    /// loudly — which is why the startup log names the path it tried.
    pub socket: std::path::PathBuf,
    /// The Incus project every request is scoped to.
    ///
    /// **This is the security boundary, not a tenancy convenience.** app-lb's
    /// user should be in the `incus` group rather than `incus-admin`: the former
    /// is confined to a project and, in Incus's own words, "prevents users from
    /// gaining root access", while the latter can attach arbitrary host paths to
    /// an instance and is root by another name. The project needs
    /// `restricted.devices.disk=allow` plus `restricted.devices.disk.paths`
    /// pinned to `mounts_dir` before guest mounts will work — deliberately, so
    /// app-lb can bind-mount its own trees and nothing else.
    pub project: String,
    /// OCI registries a `vm.image` may name, as `name -> server URL`. An image
    /// with no `remote:` prefix uses `default_remote`.
    ///
    /// Host config rather than a spec field on purpose: which registries this
    /// host will pull from is not a decision a deployment's author should make.
    pub remotes: std::collections::BTreeMap<String, String>,
    pub default_remote: String,
    /// Profiles applied to every container. Empty means Incus's own default.
    pub profiles: Vec<String>,
    /// Which interface to read the container's address from. Unset means the
    /// first non-`lo` interface with a global IPv4 — right on a host with one
    /// bridge, and worth setting on a host with two.
    pub network_nic: Option<String>,
    /// Stamped on every container as `user.app-lb.instance`, so two app-lb
    /// processes on one host do not adopt each other's containers. Defaults to
    /// [`LbConfig::name`].
    pub instance: String,
}

impl Default for LxcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket: std::path::PathBuf::from("/var/lib/incus/unix.socket"),
            project: "default".into(),
            remotes: [("docker".to_string(), "https://docker.io".to_string())]
                .into_iter()
                .collect(),
            default_remote: "docker".into(),
            profiles: Vec::new(),
            network_nic: None,
            instance: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ScalingPolicy {
    /// Replicas kept running even with no traffic. Defaults to 0, which lets
    /// the pool scale to zero and makes the next request pay a cold start.
    #[serde(default)]
    pub min_replicas: u32,
    /// Ceiling on replicas the autoscaler may run. Defaults to 5. Must be at most 1
    /// when [`VmSpec::workspace`] is set — a single-writer workspace cannot
    /// have two replicas capturing divergent copies of it.
    #[serde(default = "default_max_replicas")]
    pub max_replicas: u32,
    /// Idle-but-ready spares kept above what current load requires.
    #[serde(default)]
    pub warm_pool: u32,
    /// In-flight requests per VM the autoscaler aims for.
    #[serde(default = "default_target_concurrency")]
    pub target_concurrency: u32,
    /// Idle seconds before a pool with `min_replicas: 0` and no warm pool is
    /// torn down entirely. Defaults to 300; `0` means the pool tears down on
    /// the first idle tick.
    #[serde(default = "default_scale_to_zero_after_secs")]
    pub scale_to_zero_after_secs: u64,
    /// How long a request will wait for a VM to boot before giving up with 503.
    #[serde(default = "default_cold_start_timeout_secs")]
    pub cold_start_timeout_secs: u64,
    /// How long a draining VM may keep serving in-flight requests before it is
    /// killed anyway.
    #[serde(default = "default_drain_timeout_secs")]
    pub drain_timeout_secs: u64,
    /// How long a booting VM has to pass its health check before the autoscaler
    /// gives up on it, kills it and lets the next tick create a replacement.
    ///
    /// Without a deadline here a VM that boots but never serves — the daemon says
    /// `Running`, the guest's process died or never started — is re-queued every
    /// tick indefinitely, so the deployment sits at zero replicas with no error
    /// anywhere. The pool's own `min_replicas` can never be met and nothing says
    /// why. `0` restores that unbounded wait for a deployment whose boots are
    /// genuinely open-ended.
    ///
    /// Replacements back off. Consecutive failed boots — timeouts and terminal
    /// statuses alike — delay the next create, doubling from thirty seconds to
    /// an hour and resetting on the first healthy boot (see
    /// [`crate::deployment::boot_backoff_secs`]). Without that, a guest that
    /// can never become ready churns a fresh sandbox — and, historically, a
    /// fresh set of leaked disk directories — per cycle, forever.
    #[serde(default = "default_boot_timeout_secs")]
    pub boot_timeout_secs: u64,
    /// Whether a VM the autoscaler retires is destroyed or merely stopped. See
    /// [`IdleAction`]; defaults to `destroy`, which is the historical behaviour.
    #[serde(default)]
    pub idle_action: IdleAction,
}

impl Default for ScalingPolicy {
    fn default() -> Self {
        Self {
            min_replicas: 0,
            max_replicas: default_max_replicas(),
            warm_pool: 0,
            target_concurrency: default_target_concurrency(),
            scale_to_zero_after_secs: default_scale_to_zero_after_secs(),
            cold_start_timeout_secs: default_cold_start_timeout_secs(),
            drain_timeout_secs: default_drain_timeout_secs(),
            boot_timeout_secs: default_boot_timeout_secs(),
            idle_action: IdleAction::default(),
        }
    }
}

fn default_health_path() -> Option<String> {
    Some("/".into())
}
fn default_health_timeout_secs() -> u64 {
    2
}

/// A response identity assertion, in addition to HTTP success.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ExpectedHeader {
    pub name: String,
    pub value: String,
}

/// How a freshly-booted VM is proven ready before it joins the pool.
///
/// This exists because the SDK's readiness signal is not trustworthy on its own
/// (see `vm::wait_until_running`), so we always probe the guest ourselves.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct HealthCheck {
    /// With an identity assertion, require a 2xx response and exactly one
    /// matching header. An old baked-in listener must not verify a new release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_header: Option<ExpectedHeader>,
    /// `None` means a bare TCP connect is enough.
    #[serde(default = "default_health_path")]
    pub path: Option<String>,
    /// Health port, if the guest serves health somewhere other than `port`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// How long a single probe may take before it counts as a failure.
    /// Defaults to 2.
    #[serde(default = "default_health_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            expected_header: None,
            path: default_health_path(),
            port: None,
            timeout_secs: default_health_timeout_secs(),
        }
    }
}

/// See [`VmSpec::rootfs`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RootfsMode {
    /// A private, writable copy of the image per boot.
    #[default]
    Copy,
    /// The image itself, attached read-only; no copy.
    Shared,
}

impl RootfsMode {
    fn is_default(&self) -> bool {
        *self == Self::Copy
    }

    /// The value heyvm's create body takes, `None` for the default so a
    /// body for a copy-mode VM is byte-for-byte what it was.
    pub fn daemon_mode(&self) -> Option<&'static str> {
        match self {
            Self::Copy => None,
            Self::Shared => Some("shared"),
        }
    }
}

/// `heyo_sdk::SandboxSize`, mirrored for schema generation only.
///
/// The real type is in another crate and cannot carry a derive from this one.
/// A mirror is the drift risk this whole generator exists to remove, so it is
/// kept to the one thing that cannot be avoided — six unit variants — and the
/// crate that owns them is named here so a version bump has somewhere to look.
/// Nothing deserializes through it; it exists to be pointed at by `schemars(with)`.
#[derive(schemars::JsonSchema)]
#[schemars(rename = "SandboxSize", rename_all = "lowercase")]
#[allow(dead_code)]
enum SandboxSizeSchema {
    Micro,
    Mini,
    Small,
    Medium,
    Large,
    Xlarge,
}

/// The VM template. Mirrors `SandboxCreateOptions`, minus the fields the LB owns
/// (`name` is generated per-replica; `wait_for_ready` is always zero because the
/// autoscaler polls readiness itself rather than blocking its reconcile loop).
///
/// Note the SDK cannot express vcpu/memory directly — `size_class` is the only
/// resource knob, and the daemon resolves it host-side. It cannot express
/// `mounts` either, which is why [`crate::vm::VmManager::create`] builds the
/// create body itself rather than handing the SDK a `SandboxCreateOptions`.
/// `PartialEq` is load-bearing: an in-place edit keeps the running pool only
/// when the VM *template* is unchanged, so the update path compares old and new
/// `VmSpec`s to decide whether the VMs must be rebuilt.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct VmSpec {
    /// `firecracker` or `kvm` (a heyvm microVM) or `lxc` (an Incus system
    /// container from an OCI image). `libvirt` and `firecracker_containerd`
    /// are rejected at registration.
    pub driver: Driver,
    /// Require durable heyvmd operation receipts for autoscaler allocations.
    /// Requires an internal daemon credential and /sandbox-creations support;
    /// unknown outcomes never fall back to legacy create or name matching.
    #[serde(default, skip_serializing_if = "is_false")]
    pub correlated_creates: bool,
    /// Defaults to `ubuntu:24.04` daemon-side when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// How the VM's root filesystem relates to its image.
    ///
    /// `copy` (the default) boots from a private copy of the image that heyvm
    /// makes on every cold boot — a reflink where the filesystem can, a full
    /// copy where it cannot (ext4). `shared` attaches the image itself
    /// read-only, so no copy is made at all: the image must bring its own
    /// writable layer (the hub's base images mount tmpfs over the paths that
    /// need writing), and anything that must persist lives on the data disk or
    /// the workspace mount. The reuse a `/workspace` VM wants.
    ///
    /// heyvm versions without per-sandbox `rootfs_mode` ignore it and copy.
    #[serde(default, skip_serializing_if = "RootfsMode::is_default")]
    pub rootfs: RootfsMode,
    /// The guest port traffic is proxied to.
    pub port: u16,
    /// Shell command that starts the workload, run once per replica after boot.
    ///
    /// Required to run anything: a VM never runs its image's `CMD` or
    /// `ENTRYPOINT` (the rootfs is a `docker export`, which drops the image
    /// config), so without this the guest boots, nothing listens, and every
    /// replica times out. Put what `CMD` did here, `WORKDIR` and `ENV`
    /// included, e.g. `cd /app && setsid nohup node server.js </dev/null &`.
    ///
    /// It must *return*: the daemon runs it and waits, so a command that blocks
    /// in the foreground is a VM that never finishes booting. Daemonize
    /// explicitly with `setsid nohup <program> </dev/null &`. Its stdout and
    /// stderr go to `/var/log/heyvm-start.log` and `.err.log` inside the guest,
    /// and on to app-obs when the image has `socat`; don't redirect them to a
    /// file of your own, or they never leave the guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_command: Option<String>,
    /// CPU and memory, as one of the daemon's named classes.
    ///
    /// The only resource knob the SDK has — vcpu and memory cannot be set
    /// directly — and the daemon resolves it host-side. Unset takes the
    /// daemon's default. On `lxc` the host mapping runs micro (1 CPU, 512 MiB)
    /// through xlarge (8 CPU, 16 GiB), and unset there means `small`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<SandboxSizeSchema>")]
    pub size_class: Option<SandboxSize>,
    /// Size of the replica's persistent data disk, mounted at `/workspace`.
    ///
    /// Separate from the rootfs, which is fixed when the image is built and
    /// cannot be grown afterwards — so this is not the knob for "the image ran
    /// out of space". The disk belongs to one sandbox: a rollout, a restart or
    /// any `vm` edit boots a replica with a fresh one, and only
    /// [`WorkspaceSpec`] carries contents across.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_size_gb: Option<u32>,
    /// Directory `start_command` runs in. Defaults to the guest's own default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    /// Plain environment variables for every replica.
    ///
    /// Stored in the spec as written, so they are readable from
    /// `GET /deployments` and from the state file on disk. Anything secret
    /// belongs in [`env_from`](Self::env_from), which resolves from the secret
    /// store at create time and keeps the value out of both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_vars: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_hooks: Option<Vec<String>>,
    /// Guest ports to open *in addition to* [`port`](Self::port), which is
    /// added automatically.
    ///
    /// For a service reached on more than the one port the proxy forwards to —
    /// a broker with a client port beside its monitoring port, say.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_ports: Vec<u16>,
    /// Directories handed to every replica, unpacked from tarballs in an
    /// artifact store. See [`MountSpec`].
    ///
    /// Part of the *template* rather than a block of its own, because a mount is
    /// attached at boot and can never be added to a VM that is already running —
    /// so changing this list has to recycle the pool, and being here is what
    /// makes that happen.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountSpec>,
    /// A writable directory that belongs to the *deployment* rather than to any
    /// one VM: captured when a replica retires and seeded into the next one, so
    /// its contents survive restarts, rebuilds and rollouts. See
    /// [`WorkspaceSpec`].
    ///
    /// In the template for the same reason `mounts` is: it is attached at boot,
    /// and a VM booted without it has nowhere to put the state the next VM is
    /// supposed to inherit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<WorkspaceSpec>,
    /// Secret values exported to every replica as environment variables,
    /// resolved when the VM is created. The spec carries the reference and the
    /// store the value, which is what keeps a token out of `GET /deployments`
    /// and out of the state file — the reason `env_vars` is the wrong place
    /// for one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_from: Vec<SecretEnv>,
    /// A tarball to seed `/workspace` from on every replica boot. See
    /// [`WorkspaceArchive`]. Unlike [`workspace`](Self::workspace) nothing is
    /// captured back: each replica starts from the same snapshot, so this
    /// composes with a pool of any size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_archive: Option<WorkspaceArchive>,
    /// Where the daemon may fetch `image` from when it does not already hold
    /// it: a public-image catalog URL, with the size and digest the daemon
    /// verifies the download against. Filled in by cloud's namespace door
    /// from its catalog and passed to the daemon untouched; a spec written by
    /// hand against a local daemon leaves all three unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_download_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_sha256: Option<String>,
    /// Backstop TTL so VMs die on their own if this LB crashes and never reaps
    /// them. Renewed by the autoscaler while it is alive.
    #[serde(default = "default_vm_ttl_secs")]
    pub ttl_seconds: u64,
}

fn default_vm_ttl_secs() -> u64 {
    3600
}

/// A workspace archive — a gzipped tarball in the runtime object store — that
/// every replica's `/workspace` is unpacked from at boot.
///
/// A client names it by `archive_id`, the id cloud handed out when the archive
/// was uploaded or captured. Cloud's namespace door owns those ids: it checks
/// the caller owns the archive and fills in `s3_key`, which is what the daemon
/// actually fetches (`POST /sandbox-deploy` with `s3_archive_key`). app-lb
/// refuses a spec that reaches it with the id alone rather than guessing at
/// a key — a wrong guess would boot a replica with someone else's files.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct WorkspaceArchive {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

impl WorkspaceArchive {
    /// The object key the daemon fetches.
    pub fn key(&self) -> Option<&str> {
        self.s3_key.as_deref().map(str::trim).filter(|k| !k.is_empty())
    }

    fn validate(&self) -> Result<(), SpecError> {
        if self.key().is_none() {
            return Err(SpecError::UnresolvedWorkspaceArchive(
                self.archive_id.clone().unwrap_or_default(),
            ));
        }
        Ok(())
    }
}

/// The most guest mounts one deployment may declare.
///
/// heyvmd hands each mount a virtio-blk device, lettered from `/dev/vdb` after
/// the rootfs and the optional `disk_size_gb` data disk, so the real ceiling is
/// the alphabet. Eight is far below it and far above any spec that is describing
/// data rather than assembling a filesystem a piece at a time — and a cap that
/// is refused at registration beats one discovered as a guest that boots with
/// its last mount silently missing.
pub const MAX_MOUNTS: usize = 8;

/// Longest deployment id a `driver: lxc` deployment may have.
///
/// A replica is named `applb-<id>-<12 hex nonce>` (see `vm::replica_name`), so
/// the id gets whatever is left of Incus's 63-character instance-name limit
/// after the 19 characters of prefix, separator and nonce. Checked at
/// registration rather than at create time: an id that can never name a
/// container should be refused while someone is still looking at the spec, not
/// on the first scale-up.
pub const MAX_LXC_DEPLOYMENT_ID: usize = crate::incus::MAX_NAME_LEN - 19;

/// Guest paths a mount may not take, because something else already owns them.
///
/// The first five are the guest's own: mounting a tree over `/proc` or `/dev`
/// produces a VM that boots into a kernel with no way to see itself, and the
/// failure surfaces as an unreachable replica rather than as anything naming
/// this spec. `/workspace` is heyvm's: a mount there suppresses the
/// `disk_size_gb` data disk and makes the start command run from it, so it means
/// something different from every other path and is not a mount this feature
/// should be quietly issuing.
const RESERVED_MOUNT_PATHS: [&str; 6] = ["/proc", "/sys", "/dev", "/boot", "/run", "/workspace"];

/// A directory every replica boots with, unpacked from a tarball in an artifact
/// store.
///
/// The third thing app-lb pulls out of a store, and the only one that is neither
/// the image nor the site. [`ArtifactSpec`] materializes a *rootfs* the guest
/// boots from; a [`SiteSpec`] pull lands a tree on **this** host and serves it;
/// this lands a tree **inside** the guest, beside a rootfs it did not come from.
///
/// That separation is the whole point. A dataset, a model, a seed corpus or a
/// bundle of assets moves on its own schedule, and shipping it inside the rootfs
/// welds the two together: a new copy of a 4 GB corpus becomes a new image,
/// every host re-pulls the operating system to get it, and a rollback of one is
/// a rollback of both. As a mount it is its own digest, pulled once per host and
/// shared by every replica that names it.
///
/// ## How it reaches the guest
///
/// app-lb resolves the reference, verifies the blob against its digest, and
/// unpacks it into a directory on this host named after that digest. The daemon
/// is given the directory, not the tarball: at boot heyvmd builds an ext4 image
/// from it (`mke2fs -d`) and attaches it as a virtio-blk device that the guest's
/// init mounts at [`path`](Self::path) *before* the start command runs, so a
/// workload can read it on its first line.
///
/// Two consequences the spec does not show:
///
/// * **The disk is per VM.** Every replica gets its own image built from the
///   same tree, so no guest can see another's writes and the tree itself is only
///   ever read.
/// * **A mount is boot-time only.** There is no hot-add, which is why this is
///   part of [`VmSpec`]: editing the list is a template change, and a template
///   change recycles the pool.
///
/// ## Why the tree is not fetched when the VM is created
///
/// The autoscaler creates VMs inside its reconcile tick, and a create that first
/// fetched gigabytes would stall every deployment on the host behind one. So the
/// fetch is a job — `POST /deployments/:id/mounts/pull` — which resolves the
/// reference, unpacks the tree once, writes the resolved [`digest`](Self::digest)
/// back into this block and recycles the pool onto it. Until that has happened
/// there is no tree to mount, and the autoscaler refuses to create replicas
/// rather than booting one that is silently missing its data.
///
/// One is started automatically when a deployment with mounts is registered or
/// edited, so the usual path is: `POST /deployments` → a pull job → a pool.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct MountSpec {
    /// Where the tree appears inside the guest: an absolute path, created if it
    /// does not exist.
    ///
    /// Also the identity of the mount within the deployment — two mounts cannot
    /// name the same path, and one cannot sit inside another, because the guest
    /// mounts them in order and the second would hide the first.
    pub path: String,
    /// The store to pull from: an `http(s)://` `art serve`, or a store root on
    /// this host. Exactly as [`ArtifactSpec::store`], including which of the two
    /// transports each spelling selects.
    pub store: String,
    /// A tag or a 64-hex digest naming a `tar` or `tar.gz` of the directory.
    ///
    /// A tag is resolved every time the pull job runs, so a mount pinned to one
    /// follows it; a digest is immutable and is what a rollback names. This is
    /// the same bundle shape a site pulls — `art put data.tgz --tag corpus-v3`
    /// puts one in.
    #[serde(rename = "ref")]
    pub artifact_ref: String,
    /// API key for a store started with `ART_API_KEY`, as a reference into the
    /// secret store. Only meaningful for the URL form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<SecretRef>,
    /// Leading path components to drop while unpacking, as
    /// `tar --strip-components` does — and needed for the same reason
    /// [`ArtifactSpec::strip_components`] is: `tar czf corpus.tgz corpus` writes
    /// every entry as `corpus/…`, so without a `1` here the guest finds its data
    /// at `<path>/corpus` instead of at `<path>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip_components: Option<usize>,
    /// Whether the guest mounts it read-only. Defaults to **true**: the tree is
    /// data the deployment was given, and a replica that can scribble on its own
    /// copy of it makes "which bytes is this VM serving?" a question with a
    /// per-VM answer.
    ///
    /// Writable is allowed on `firecracker`, where each VM's ext4 image is its
    /// own and nothing propagates back to the host tree. It is **refused on
    /// `kvm`**, whose driver syncs a read-write mount image back into the host
    /// directory when the VM stops — and that directory is the shared,
    /// content-addressed tree every other replica is booting from, so one
    /// replica's writes would rewrite what the digest names.
    #[serde(default = "default_true")]
    pub read_only: bool,
    /// What [`artifact_ref`](Self::artifact_ref) resolved to, written by the pull
    /// job. The answer to "which bytes is this deployment mounting?", and the
    /// name of the tree on disk.
    ///
    /// Absent means nothing has been pulled yet and the pool cannot be created;
    /// see the module note above. Setting it by hand pins the mount to a tree
    /// already on this host, which is what an edit that must not re-fetch looks
    /// like — a spec whose digest names no tree is rejected at registration, not
    /// discovered at boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

impl MountSpec {
    /// How many leading path components the unpack drops. Zero unless the spec
    /// says otherwise, matching a bundle rolled with `tar -C dir .`.
    pub fn strip(&self) -> usize {
        self.strip_components.unwrap_or(0)
    }

    /// Whether `store` names a remote `art serve` rather than a path on this
    /// host — the same distinction, and the same consequences, as
    /// [`ArtifactSpec::is_remote`].
    pub fn is_remote(&self) -> bool {
        is_remote_store(&self.store)
    }

    /// The mount path with no trailing slash, which is how it is compared,
    /// nested-checked and sent to the daemon. `path` is validated into this
    /// shape, so this only ever trims whitespace.
    pub fn guest_path(&self) -> &str {
        self.path.trim().trim_end_matches('/')
    }

    /// Rejects a mount the pull could not satisfy or the guest could not boot
    /// with. `driver` is a parameter because one rule genuinely depends on it:
    /// see [`read_only`](Self::read_only).
    fn validate(&self, driver: Driver) -> Result<(), SpecError> {
        if let Some(why) = mount_path_problem(&self.path) {
            return Err(SpecError::BadMountPath {
                path: self.path.clone(),
                why,
            });
        }
        if !is_supported_store(&self.store) {
            return Err(SpecError::BadMountStore {
                path: self.guest_path().to_string(),
                store: self.store.clone(),
            });
        }
        if !is_valid_artifact_ref(&self.artifact_ref) {
            return Err(SpecError::BadMountRef {
                path: self.guest_path().to_string(),
                reference: self.artifact_ref.clone(),
            });
        }
        if let Some(auth) = &self.auth {
            auth.validate().map_err(|e| SpecError::BadSecretRef {
                field: "vm.mounts[].auth",
                detail: e.to_string(),
            })?;
        }
        if let Some(digest) = &self.digest
            && !is_sha256_hex(digest)
        {
            return Err(SpecError::BadMountDigest {
                path: self.guest_path().to_string(),
                digest: digest.clone(),
            });
        }
        if !self.read_only && driver == Driver::Kvm {
            return Err(SpecError::WritableMountOnKvm(self.guest_path().to_string()));
        }
        Ok(())
    }
}

/// The default guest path of a [`WorkspaceSpec`], and the one heyvm treats
/// specially: a mount there replaces the `disk_size_gb` data disk and is sized
/// from it, so `disk_size_gb` becomes the workspace's capacity.
pub const DEFAULT_WORKSPACE_PATH: &str = "/workspace";

/// A persistent, writable workspace owned by the deployment.
///
/// The fourth thing app-lb moves between a store and a guest, and the only one
/// that moves in **both directions**. A [`MountSpec`] is data the deployment
/// was *given*; a workspace is data the deployment *makes* — the agent's
/// sessions, the repositories it cloned, the files it was asked to keep — and
/// it has to outlive the VM that wrote it. heyvm's own `/workspace` data disk
/// does not: it belongs to one sandbox, so every rollout, every `restart`, and
/// every rebuild that recycles the pool boots a replica with an empty one.
///
/// ## The lifecycle
///
/// * **Seed.** When the autoscaler creates a replica it hands heyvmd the
///   workspace's current tree on this host as a writable mount at
///   [`path`](Self::path). The daemon builds the VM its own ext4 image from
///   that tree (`mke2fs -d`), so the guest writes to a block device and the
///   tree itself is only read. With no tree yet — a fresh host, or a swept
///   one — the latest snapshot is pulled from [`store`](Self::store) first;
///   with no snapshot in the store either, the workspace starts empty.
/// * **Capture.** When a replica retires for any reason — drained by a
///   rollout, evicted, torn down by an edit or a deregistration, suspended by
///   `idle_action: retain` — app-lb syncs the guest, stops the VM, replays the
///   image's journal, extracts it into a new tree, and points the deployment
///   at that tree. The replacement is not created until that has happened,
///   which is the whole guarantee: the next VM boots from the last VM's final
///   state, not from whatever the store held when the host came up.
/// * **Push.** Each capture is bundled (`tar.gz`, named by its sha256) and sent
///   to the store under [`ref`](Self::artifact_ref), so the workspace survives
///   the host too. A push that fails is retried; it never blocks the rollout,
///   because the tree the next VM needs is already here.
///
/// ## What this costs, and what it refuses
///
/// A capture stops the VM, so a rollout of a workspace deployment has a gap:
/// the old replica is drained and stopped, its tree is extracted, and only then
/// does the new one boot. That is inherent to single-writer state and it is why
/// `scaling.max_replicas` **must be at most 1** — two replicas would each capture their
/// own divergent copy and the last one to land would win. `warm_pool` must be
/// `0` for the same reason, and the driver must be `firecracker`: the KVM
/// driver has its own idea of what a writable mount means when the VM stops.
///
/// Ownership is flattened: the tree is extracted and rebuilt by app-lb's own
/// user, so every file comes back owned by that uid inside the guest. A
/// workload that runs as root reads and writes them regardless; one that
/// checks ownership (git's `safe.directory`, Postgres's data-directory check)
/// needs to be told. Modes, symlinks and timestamps survive.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct WorkspaceSpec {
    /// Where the workspace appears inside the guest. Defaults to
    /// [`DEFAULT_WORKSPACE_PATH`], which is also the only path heyvmd sizes from
    /// `disk_size_gb`; anywhere else gets 1.5× its content with a 2 GiB floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Where snapshots go, in one of three forms:
    ///
    /// * `s3://bucket[/prefix]` — an S3 bucket, reached with the `aws` CLI and
    ///   whatever credentials it finds (`APP_LB_DISK_ARCHIVE_ENDPOINT` applies
    ///   for an S3-compatible store). Snapshots land at
    ///   `<prefix>/<deployment>/<digest>.tar.gz` with a `latest` pointer.
    /// * `http(s)://host:port` — a remote `art serve`. Each snapshot is a blob,
    ///   and [`ref`](Self::artifact_ref) is the tag that names the newest.
    /// * an absolute path — a local `ART_ROOT`, reached through the `art` CLI.
    pub store: String,
    /// The tag the newest snapshot is published under (artifact stores only —
    /// S3 uses the deployment id as its key prefix). Defaults to
    /// `workspace-<deployment id>`.
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    /// Credentials for the store, as a secret reference. Artifact stores only;
    /// the `aws` CLI reads its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<SecretRef>,
    /// Take a snapshot at least this often, in seconds, by recycling the
    /// replica: drain, capture, then resume it (`idle_action: retain`) or boot
    /// its replacement from the result. Unset, a snapshot is taken only when
    /// the replica retires for some other reason — a VM that runs for days
    /// holds days of work that exist nowhere else. Each one costs the drain
    /// plus the capture as downtime, so at least
    /// [`MIN_SNAPSHOT_INTERVAL_SECS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_interval_secs: Option<u64>,
}

/// The shortest `vm.workspace.snapshot_interval_secs`: every snapshot is an
/// outage of drain + capture, so a tighter schedule would mostly be downtime.
pub const MIN_SNAPSHOT_INTERVAL_SECS: u64 = 300;

/// Which transport a [`WorkspaceSpec::store`] names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceStore {
    /// `s3://bucket/prefix`, with the prefix never leading- or trailing-slashed
    /// and possibly empty.
    S3 { bucket: String, prefix: String },
    /// A remote `art serve`, base URL with no trailing slash.
    Remote(String),
    /// A local store root.
    Local(String),
}

impl WorkspaceSpec {
    /// The guest path with no trailing slash.
    pub fn guest_path(&self) -> &str {
        self.path
            .as_deref()
            .map(|p| p.trim().trim_end_matches('/'))
            .filter(|p| !p.is_empty())
            .unwrap_or(DEFAULT_WORKSPACE_PATH)
    }

    /// The tag snapshots are published under in an artifact store.
    pub fn tag(&self, deployment_id: &str) -> String {
        match self.artifact_ref.as_deref().map(str::trim) {
            Some(r) if !r.is_empty() => r.to_string(),
            _ => format!("workspace-{deployment_id}"),
        }
    }

    /// Parse `store`. `None` when it is none of the three forms.
    pub fn backend(&self) -> Option<WorkspaceStore> {
        let store = self.store.trim();
        if let Some(rest) = store.strip_prefix("s3://") {
            let (bucket, prefix) = match rest.split_once('/') {
                Some((b, p)) => (b, p.trim_matches('/')),
                None => (rest, ""),
            };
            let bucket_ok = !bucket.is_empty()
                && bucket
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'));
            if !bucket_ok {
                return None;
            }
            return Some(WorkspaceStore::S3 {
                bucket: bucket.to_string(),
                prefix: prefix.to_string(),
            });
        }
        if !is_supported_store(store) {
            return None;
        }
        if is_remote_store(store) {
            Some(WorkspaceStore::Remote(store.trim_end_matches('/').to_string()))
        } else {
            Some(WorkspaceStore::Local(store.to_string()))
        }
    }

    fn validate(
        &self,
        driver: Driver,
        scaling: &ScalingPolicy,
        mounts: &[MountSpec],
    ) -> Result<(), SpecError> {
        if driver != Driver::Firecracker {
            return Err(SpecError::WorkspaceDriver(driver));
        }
        if let Some(path) = &self.path
            && let Some(why) = workspace_path_problem(path)
        {
            return Err(SpecError::BadWorkspacePath {
                path: path.clone(),
                why,
            });
        }
        if self.backend().is_none() {
            return Err(SpecError::BadWorkspaceStore(self.store.clone()));
        }
        if let Some(r) = &self.artifact_ref
            && !is_valid_artifact_ref(r.trim())
        {
            return Err(SpecError::BadWorkspaceRef(r.clone()));
        }
        if let Some(auth) = &self.auth {
            auth.validate().map_err(|e| SpecError::BadSecretRef {
                field: "vm.workspace.auth",
                detail: e.to_string(),
            })?;
        }
        if scaling.max_replicas > 1 {
            return Err(SpecError::WorkspaceReplicas(scaling.max_replicas));
        }
        if scaling.warm_pool != 0 {
            return Err(SpecError::WorkspaceWarmPool(scaling.warm_pool));
        }
        if let Some(n) = self.snapshot_interval_secs
            && n < MIN_SNAPSHOT_INTERVAL_SECS
        {
            return Err(SpecError::WorkspaceSnapshotInterval(n));
        }
        let ws = self.guest_path();
        for m in mounts {
            let p = m.guest_path();
            if p == ws || p.starts_with(&format!("{ws}/")) || ws.starts_with(&format!("{p}/")) {
                return Err(SpecError::WorkspaceCollidesWithMount {
                    workspace: ws.to_string(),
                    mount: p.to_string(),
                });
            }
        }
        Ok(())
    }
}

/// [`mount_path_problem`] with `/workspace` allowed: for a workspace that path
/// is not reserved, it is the point.
fn workspace_path_problem(path: &str) -> Option<&'static str> {
    let trimmed = path.trim().trim_end_matches('/');
    if trimmed == DEFAULT_WORKSPACE_PATH {
        return None;
    }
    mount_path_problem(path)
}

/// Why a guest mount path is unusable, or `None` if it is fine.
///
/// Stricter than "a path": it is compared against other mount paths, joined into
/// a `mount` command by the guest's init, and used as the identity of a mount
/// across an edit. The alphabet is therefore the conservative one — a path that
/// needs a quote or a space is a path that behaves differently in one of those
/// three places than it looks like it should.
fn mount_path_problem(path: &str) -> Option<&'static str> {
    let p = path.trim();
    if p.is_empty() {
        return Some("must not be empty");
    }
    if !p.starts_with('/') {
        return Some("must be an absolute path inside the guest");
    }
    if p.len() > 255 {
        return Some("must be shorter than 256 characters");
    }
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() {
        return Some("cannot be the guest's root directory");
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'))
    {
        return Some(
            "may contain only letters, digits, '/', '-', '_' and '.'; it is interpolated into \
             the guest's mount command",
        );
    }
    if std::path::Path::new(trimmed).components().any(|c| {
        !matches!(
            c,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )
    }) {
        return Some("must not contain '.' or '..' segments");
    }
    if trimmed.contains("//") {
        return Some("must not contain an empty path segment");
    }
    if RESERVED_MOUNT_PATHS
        .iter()
        .any(|r| trimmed == *r || trimmed.starts_with(&format!("{r}/")))
    {
        return Some(
            "is reserved: /proc, /sys, /dev, /boot and /run belong to the guest's own boot, \
             and /workspace is heyvm's data disk",
        );
    }
    None
}

/// Rejects a *set* of mounts: the rules one mount cannot see on its own.
fn validate_mounts(mounts: &[MountSpec], driver: Driver) -> Result<(), SpecError> {
    if mounts.len() > MAX_MOUNTS {
        return Err(SpecError::TooManyMounts {
            count: mounts.len(),
            max: MAX_MOUNTS,
        });
    }
    for mount in mounts {
        mount.validate(driver)?;
    }
    // Quadratic over at most `MAX_MOUNTS` entries, and it has to compare pairs:
    // the guest mounts these in order, so a path inside an earlier one is hidden
    // by it from the moment the second mount lands.
    for (i, a) in mounts.iter().enumerate() {
        for b in &mounts[i + 1..] {
            let (x, y) = (a.guest_path(), b.guest_path());
            if x == y {
                return Err(SpecError::DuplicateMountPath(x.to_string()));
            }
            for (outer, inner) in [(x, y), (y, x)] {
                if inner.starts_with(&format!("{outer}/")) {
                    return Err(SpecError::NestedMountPath {
                        outer: outer.to_string(),
                        inner: inner.to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// A sha256 in the only spelling the artifact store writes: 64 lowercase hex.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}


/// Where a deployment's guest image is *built* from — a Dockerfile, and the
/// files it copies in.
///
/// This is the *source*, not the running image. A build assembles the recipe and
/// its context on this host, hands them to `heyvm mvm build`, and only then
/// writes the resulting image name into [`VmSpec::image`] — so the spec always
/// says which image is actually booting, and this block says where the next one
/// will come from. Editing it never disturbs running VMs; running a build does.
///
/// On a **site** it is the files themselves: `repo` at `ref` is checked out and
/// its `context` directory (default: the whole checkout, minus `.git`) is copied
/// into `site.root` with the same staged swap an artifact pull uses. Nothing is
/// built or run, so `store`, `dockerfile`, `image_name` and `image_size_mb` are
/// refused there. This is how a repo on a Heyo git remote becomes a site.
///
/// Two ways to get the recipe here, and exactly one of them must be set:
///
/// * **`repo`** — a git checkout. app-lb fetches `repo` at `ref` and looks for a
///   Dockerfile inside it. The original form, and the right one when the recipe
///   lives with the code it builds.
/// * **`store`** — a Dockerfile manifest in an artifact store, named by `ref`.
///   app-lb fetches the manifest, writes out its `Dockerfile` and unpacks its
///   `context.tar.gz`. See [`ArtifactSpec`] for the two spellings of `store`, and
///   `art dockerfile put` in the artifacts crate for how one gets there.
///
/// The difference that matters is *what the ref pins*. A git ref pins a commit,
/// and the Dockerfile is whatever that commit happens to hold; a store ref
/// resolves to a manifest digest covering the recipe, the context and the
/// annotations together. So a store build can say "these exact inputs" in a way a
/// branch name cannot, and a rollback is expressible: a tag moves, a digest does
/// not.
///
/// It remains a *build* either way, which is why this is one block and not two.
/// Both run `heyvm mvm build` and produce an image that did not exist before,
/// which is the whole distinction from [`ArtifactSpec`] — there, the digest names
/// bytes that already exist and nothing is produced at all.
///
/// Note what is deliberately absent: build arguments and a registry. The image is
/// an ext4 rootfs on this host, built from a Dockerfile the daemon never sees, and
/// `heyvm mvm build` exposes neither `--build-arg` nor a push target for the
/// local-only path.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BuildSpec {
    /// Git remote: `https://…`, `ssh://…`, `git@host:path`, or a local path.
    /// Mutually exclusive with `store`; exactly one must be set.
    ///
    /// `Option` rather than required because `store` is the alternative, not
    /// because a build can have no source — a spec with neither is refused. Every
    /// spec written before `store` existed has it, so nothing on disk needs
    /// migrating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// An artifact store holding a Dockerfile manifest: an `http(s)://` URL of an
    /// `art serve`, or an absolute store root on this host. Mutually exclusive
    /// with `repo`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    /// Which version of the source to build.
    ///
    /// For a `repo`: a branch, tag or commit. `None` follows the remote's default
    /// branch, which is what makes `POST …/build` mean "ship what is on main".
    ///
    /// For a `store`: the tag or digest of a Dockerfile manifest, and **required**
    /// — a store has no default, and guessing one would be picking somebody's
    /// image out of a shared namespace.
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    /// Dockerfile path *within the checkout*. `None` looks for one: `Dockerfile`
    /// at the context root, else a unique `Dockerfile` within three directories
    /// of it. Ambiguity is an error, never a guess.
    ///
    /// Git source only: a Dockerfile manifest names its own recipe, so a path
    /// here would be pointing into an archive this deployment does not choose the
    /// layout of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
    /// Build context within the checkout. Defaults to the Dockerfile's directory,
    /// matching `heyvm mvm build`'s own default. Git source only, for the same
    /// reason as `dockerfile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Base name for built images; the source version is appended, so one
    /// deployment's builds are `<name>-<short sha>` from git and
    /// `<name>-<short manifest digest>` from a store. Defaults to the deployment
    /// id, and overrides the manifest's own `heyvm.image` annotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_name: Option<String>,
    /// Rootfs size passed to `heyvm mvm build --size-mb`. Unset lets heyvm size
    /// it from the exported tar (×1.2 + 64 MB), which is right until the guest
    /// writes to its own rootfs at runtime. On a store source, unset falls back
    /// to the manifest's `heyvm.size_mb` annotation before heyvm's own default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_size_mb: Option<u64>,
    /// Credential, as a reference into the secret store. What it *is* depends on
    /// the source, which is why it is one field: a git token for a private `repo`,
    /// or the `ART_API_KEY` of a gated `store`.
    ///
    /// Unused by an `ssh://` or `git@` remote, which authenticates with the host's
    /// own key material, and by a local store root, which is protected by file
    /// permissions. Both cases are warned about at build time rather than
    /// rejected here — a spec may legitimately carry one while its `repo` is
    /// being switched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<SecretRef>,
}

/// Which of [`BuildSpec`]'s two sources a build will actually use.
///
/// Returned rather than re-derived at each use, so the "exactly one is set"
/// invariant is checked once — in `validate` — and every consumer afterwards has
/// a value that cannot represent both or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildSource<'a> {
    /// A git checkout. `git_ref` unset follows the remote's default branch.
    Git {
        repo: &'a str,
        git_ref: Option<&'a str>,
    },
    /// A Dockerfile manifest in an artifact store.
    Dockerfile { store: &'a str, reference: &'a str },
}

impl BuildSpec {
    /// The image name for a given source version — a commit for git, a manifest
    /// digest for a store. Lowercased and stripped to what both `docker build -t`
    /// and heyvm's `<name>.ext4` filename accept, because the deployment id it
    /// defaults to is only constrained by the route table.
    pub fn image_for(&self, deployment_id: &str, version: &str) -> String {
        let base = self.image_name.as_deref().unwrap_or(deployment_id);
        let base = sanitize_image_name(base);
        let short: String = version.chars().take(12).collect();
        if short.is_empty() {
            base
        } else {
            format!("{base}-{short}")
        }
    }

    /// Which source this build uses. `None` only for a spec that never passed
    /// [`BuildSpec::validate`], which is why callers may treat it as unreachable
    /// rather than as a case to handle.
    pub fn source(&self) -> Option<BuildSource<'_>> {
        match (self.repo.as_deref(), self.store.as_deref()) {
            (Some(repo), None) => Some(BuildSource::Git {
                repo,
                git_ref: self.source_ref.as_deref(),
            }),
            (None, Some(store)) => Some(BuildSource::Dockerfile {
                store,
                reference: self.source_ref.as_deref()?,
            }),
            _ => None,
        }
    }

    /// Whether `store` names a remote `art serve` rather than a path on this
    /// host. Same rule [`ArtifactSpec::is_remote`] applies, and for the same
    /// reason: the scheme is what decides whether `auth` means anything.
    pub fn store_is_remote(&self) -> bool {
        self.store.as_deref().is_some_and(is_remote_store)
    }

    fn validate(&self) -> Result<(), SpecError> {
        match (&self.repo, &self.store) {
            (Some(_), Some(_)) => return Err(SpecError::BothBuildSources),
            (None, None) => return Err(SpecError::NoBuildSource),
            _ => {}
        }

        if let Some(repo) = &self.repo {
            if repo.trim().is_empty() {
                return Err(SpecError::EmptyRepo);
            }
            if !is_supported_repo_url(repo) {
                return Err(SpecError::UnsupportedRepoUrl(repo.clone()));
            }
            if let Some(r) = &self.source_ref
                && !is_safe_git_ref(r)
            {
                return Err(SpecError::BadBuildRef(r.clone()));
            }
            for path in [&self.dockerfile, &self.context].into_iter().flatten() {
                if !is_safe_relative_path(path) {
                    return Err(SpecError::BadBuildPath(path.clone()));
                }
            }
        }

        if let Some(store) = &self.store {
            if store.trim().is_empty() {
                return Err(SpecError::EmptyBuildStore);
            }
            if !is_supported_store(store) {
                return Err(SpecError::UnsupportedBuildStore(store.clone()));
            }
            // Required, unlike a git ref: a store has no default branch to fall
            // back to, and a build with no reference has nothing to fetch.
            let Some(r) = &self.source_ref else {
                return Err(SpecError::MissingBuildRef);
            };
            if !is_valid_artifact_ref(r) {
                return Err(SpecError::BadBuildArtifactRef(r.clone()));
            }
            // Rejected rather than ignored, because both would be somebody
            // expecting a file to be chosen that the manifest already chose. A
            // Dockerfile manifest names its recipe `Dockerfile` and its context
            // `context.tar.gz`; there is nothing left to point at.
            for (present, what) in [
                (self.dockerfile.is_some(), "build.dockerfile"),
                (self.context.is_some(), "build.context"),
            ] {
                if present {
                    return Err(SpecError::OnlyForGitBuilds(what));
                }
            }
        }

        if let Some(name) = &self.image_name
            && sanitize_image_name(name).is_empty()
        {
            return Err(SpecError::BadImageName(name.clone()));
        }
        if let Some(auth) = &self.auth {
            auth.validate().map_err(|e| SpecError::BadSecretRef {
                field: "build.auth",
                detail: e.to_string(),
            })?;
        }
        Ok(())
    }
}

/// Whether a store reference names a remote `art serve` rather than a path.
pub fn is_remote_store(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("http://") || s.starts_with("https://")
}

/// Whether a string names an artifact store this host could reach: an
/// `http(s)://` URL, or an absolute store root.
///
/// Shared by `artifact.store` and `build.store` so the two cannot drift. Only an
/// *absolute* path is accepted, because app-lb's working directory is not
/// something a spec author can see — a relative path would name a different store
/// depending on how the LB was started.
fn is_supported_store(store: &str) -> bool {
    let store = store.trim();
    if store.is_empty() {
        return false;
    }
    if let Some(rest) = store
        .strip_prefix("http://")
        .or_else(|| store.strip_prefix("https://"))
    {
        return !rest.is_empty() && !rest.contains(char::is_whitespace);
    }
    std::path::Path::new(store).is_absolute() && !store.contains("..") && !store.contains('\0')
}

/// Where a deployment's content comes from: bytes already in an artifact store,
/// addressed by content.
///
/// Two backends read this block, and what the same digest means differs:
///
/// * A **managed (`vm`) deployment** pulls a *guest rootfs*. The blob is
///   materialized as an ext4 file heyvmd can boot and [`VmSpec::image`] is
///   rewritten to it, so the spec still says which image is actually booting and
///   this block says where the next one comes from.
/// * A **site** pulls a *directory tree* — a `tar` or `tar.gz` of built files,
///   unpacked into [`SiteSpec::root`]. This is the counterpart of
///   [`UpdateSpec`] and the reason to prefer it: the host needs no toolchain at
///   all, because the build already happened wherever the bundle was made.
///
/// The counterpart of [`BuildSpec`], and the same shape of thing: the *source*
/// of the next content, not the running one.
///
/// What makes this different from a build is that nothing is *produced*. The
/// digest names bytes that already exist, so the same `artifact` block resolves
/// to the same content on every host that can reach the store, which is the
/// whole reason to prefer it over rebuilding per machine. It is also what makes
/// a rollback expressible: a tag moves, a digest cannot.
///
/// See <https://github.com/sarocu/artifacts> — `art heyvm import` puts heyvm's
/// base images in, `art put dist.tgz --tag <name>` puts a site bundle in,
/// `heyctl artifact push` puts a locally-built rootfs in, and any of them is
/// pullable here.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ArtifactSpec {
    /// The store to pull from, in one of two forms:
    ///
    /// * `http://host:port` — a remote `art serve`. app-lb resolves and streams
    ///   the blob itself, verifying the digest as the bytes land.
    /// * `/abs/path` — a store root (`ART_ROOT`) on this host. app-lb shells out
    ///   to the `art` CLI: `art heyvm materialize` for a rootfs, which skips the
    ///   blob's holes instead of copying its zeros, and `art get` for a site
    ///   bundle, which hardlinks it and copies nothing at all.
    ///
    /// A local store is by far the faster of the two and is what a host running
    /// its own store should use; the URL form is what makes one store serve a
    /// fleet.
    pub store: String,
    /// A tag (`debian-hermes`, `marketing-live`) or a 64-hex digest. A tag is
    /// resolved at pull time, so a deployment pinned to one follows whatever the
    /// tag moves to; a digest is immutable and is what a rollback should name.
    #[serde(rename = "ref")]
    pub artifact_ref: String,
    /// API key for a store started with `ART_API_KEY`, as a reference into the
    /// secret store. Only meaningful for the URL form — a local store is
    /// protected by file permissions, not a header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<SecretRef>,
    /// Extend the materialized rootfs to this many gigabytes. Sparse, so it
    /// costs no disk until the guest writes; heyvm still runs the `resize2fs`
    /// that lets the guest filesystem use the room. Set it when the image was
    /// built small and the workload needs space on `/`.
    ///
    /// Guest images only — a site has no filesystem to grow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grow_gb: Option<u64>,
    /// Base name for the materialized image; the digest is appended, so one
    /// deployment's pulls are `<name>-<short digest>`. Defaults to the
    /// deployment id.
    ///
    /// Guest images only — a site's files land in `site.root` under their own
    /// names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_name: Option<String>,
    /// Leading path components to drop from every entry while unpacking, exactly
    /// as `tar --strip-components` does.
    ///
    /// Sites only, and it exists because of how the bundle was almost certainly
    /// made: `tar czf dist.tgz dist` writes every entry as `dist/…`, so
    /// unpacking it straight into `site.root` puts the index at
    /// `<root>/dist/index.html` and the deployment 404s everything. `1` drops
    /// that wrapper. A bundle rolled with `tar czf dist.tgz -C dist .` needs
    /// nothing here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip_components: Option<usize>,
}

impl ArtifactSpec {
    /// The image name for a given blob digest.
    ///
    /// Content-addressed: `img-<digest[..16]>`, plus `-g<N>` when the image is
    /// grown, because a grown image is a different file. The same bytes always
    /// materialize to the same name whichever deployment asked, so five
    /// deployments of one base image share one catalog entry and one pull, and
    /// a re-pull of bytes already on disk is a no-op the job can detect by
    /// name alone.
    ///
    /// An explicit `image_name` keeps the older `<name>-<digest[..12]>` shape,
    /// and so does a digest too short to address anything: that is the
    /// deployment-scoped name images pulled before this carry, and their
    /// deployments keep booting from them.
    pub fn image_for(&self, deployment_id: &str, digest: &str) -> String {
        if self.image_name.is_none()
            && let Some(name) = content_addressed_image(digest, self.grow_gb)
        {
            return name;
        }
        let base = self.image_name.as_deref().unwrap_or(deployment_id);
        let base = sanitize_image_name(base);
        let short: String = digest.chars().take(12).collect();
        if short.is_empty() {
            base
        } else {
            format!("{base}-{short}")
        }
    }

    /// Whether `store` names a remote `art serve` rather than a path on this
    /// host. The two are told apart by the scheme, which is also what decides
    /// whether `auth` means anything.
    pub fn is_remote(&self) -> bool {
        is_remote_store(&self.store)
    }

    /// How many leading path components a site's unpack drops. Zero unless the
    /// spec says otherwise, which is the right default for a bundle rolled with
    /// `tar -C dist .`.
    pub fn strip(&self) -> usize {
        self.strip_components.unwrap_or(0)
    }

    /// `for_site` decides which half of this block is meaningful. Both halves
    /// are rejected on the backend they do not describe rather than ignored: a
    /// `grow_gb` on a site is somebody expecting room they will not get, and a
    /// `strip_components` on a guest image is somebody expecting an unpack that
    /// never happens.
    fn validate(&self, for_site: bool) -> Result<(), SpecError> {
        if self.store.trim().is_empty() {
            return Err(SpecError::EmptyArtifactStore);
        }
        if !is_supported_store(&self.store) {
            return Err(SpecError::UnsupportedArtifactStore(self.store.clone()));
        }

        if !is_valid_artifact_ref(&self.artifact_ref) {
            return Err(SpecError::BadArtifactRef(self.artifact_ref.clone()));
        }
        if let Some(auth) = &self.auth {
            auth.validate().map_err(|e| SpecError::BadSecretRef {
                field: "artifact.auth",
                detail: e.to_string(),
            })?;
        }

        if for_site {
            // Both describe a guest rootfs: one grows its filesystem, the other
            // names the `.ext4` it is written to. A site produces neither.
            for (present, what) in [
                (self.grow_gb.is_some(), "artifact.grow_gb"),
                (self.image_name.is_some(), "artifact.image_name"),
            ] {
                if present {
                    return Err(SpecError::NotForSites(what));
                }
            }
            return Ok(());
        }

        if self.strip_components.is_some() {
            return Err(SpecError::OnlyForSites("artifact.strip_components"));
        }
        if let Some(name) = &self.image_name
            && sanitize_image_name(name).is_empty()
        {
            return Err(SpecError::BadImageName(name.clone()));
        }
        if self.grow_gb == Some(0) {
            return Err(SpecError::ZeroGrow);
        }
        Ok(())
    }
}

/// A tag or a digest, as the artifact store itself defines them.
///
/// Mirrors `TagName::parse` and `Digest::parse` in the `artifacts` crate rather
/// than deferring to the store, because a reference that store would reject
/// should be a registration error here and not a job that fails minutes later.
///
/// Three spellings:
///
/// * a digest — 64 lowercase hex characters;
/// * a flat tag — `[A-Za-z0-9._-]`, not starting with `-` or `.`;
/// * a namespaced tag — `repo[:tag]`, as the hub publishes them
///   (`heyo/postgres:16`). The repo is 1–4 `/`-separated segments of
///   `[a-z0-9._-]`, each starting with a letter or digit, so no segment can be
///   empty, `.` or `..`; the tag after the colon is a flat tag.
///
/// None of them can travel outside the store when pasted into a URL path: the
/// only separator any of them contains is a `/` between segments that cannot
/// be dot entries, and the store routes `/tags/{*name}` as one parameter.
pub(crate) fn is_valid_artifact_ref(r: &str) -> bool {
    if r.is_empty() || r.len() > 256 {
        return false;
    }
    if !(r.contains('/') || r.contains(':')) {
        return is_flat_tag(r);
    }
    let (repo, tag) = r.split_once(':').unwrap_or((r, "latest"));
    if repo.is_empty() || repo.len() > 180 || !is_flat_tag(tag) {
        return false;
    }
    let segments: Vec<&str> = repo.split('/').collect();
    segments.len() <= 4
        && segments.iter().all(|seg| {
            let b = seg.as_bytes();
            !b.is_empty()
                && b.len() <= 64
                && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
                && b.iter().all(|&c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
                })
        })
}

fn is_flat_tag(r: &str) -> bool {
    if r.is_empty() || r.len() > 64 {
        return false;
    }
    let first = r.as_bytes()[0];
    if first == b'-' || first == b'.' {
        return false;
    }
    r.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

/// The catalog name for a blob, by content: `img-<digest[..16]>`, with
/// `-g<N>` when grown to N GiB. `None` for anything that is not a hex digest
/// of at least 16 characters, which callers fall back from.
pub fn content_addressed_image(digest: &str, grow_gb: Option<u64>) -> Option<String> {
    let short: String = digest.chars().take(16).collect();
    if short.len() < 16 || !short.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let short = short.to_ascii_lowercase();
    Some(match grow_gb {
        Some(g) => format!("img-{short}-g{g}"),
        None => format!("img-{short}"),
    })
}

/// Keep to what a docker tag component and an ext4 filename both allow.
fn sanitize_image_name(name: &str) -> String {
    let lowered: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    // A docker tag must start with an alphanumeric, and a filename starting with
    // a dot would be hidden from `heyvm mvm images`.
    lowered
        .trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
        .trim_end_matches(['-', '.', '_'])
        .chars()
        .take(64)
        .collect()
}

/// Remotes app-lb will hand to `git fetch`.
///
/// The list is short on purpose: `git` treats an argument beginning with `-` as
/// a flag, and `ext::`/`--upload-pack=` style remotes run a command of the
/// remote's choosing on this host. A spec comes in over the admin API, so the
/// URL is input, not configuration.
fn is_supported_repo_url(repo: &str) -> bool {
    let repo = repo.trim();
    if repo.starts_with('-') || repo.contains(char::is_whitespace) {
        return false;
    }
    for scheme in ["https://", "http://", "ssh://", "file://"] {
        if let Some(rest) = repo.strip_prefix(scheme) {
            return !rest.is_empty();
        }
    }
    if repo.starts_with('/') {
        return true; // a path on this host, for testing and vendored sources
    }
    // scp-like: user@host:path, which git accepts and which has no scheme.
    matches!(repo.split_once('@'), Some((user, rest))
        if !user.is_empty() && rest.contains(':') && !rest.starts_with(':'))
}

/// A ref is passed to `git fetch` as an argument and appears in an image name,
/// so it may not look like a flag or carry anything a shell or a path would
/// reinterpret. Git's own rules already forbid most of this in a real ref.
fn is_safe_git_ref(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 255
        && !r.starts_with('-')
        && !r.contains("..")
        && !r.starts_with('/')
        && r.chars().all(|c| {
            !c.is_whitespace()
                && !c.is_control()
                && !matches!(c, '~' | '^' | ':' | '?' | '*' | '[' | '\\' | '\'' | '"')
        })
}

/// A path inside the checkout: relative, and unable to climb out of it.
fn is_safe_relative_path(p: &str) -> bool {
    let p = p.trim();
    !p.is_empty()
        && !p.starts_with('/')
        && !p.starts_with('-')
        && !p.contains('\0')
        && std::path::Path::new(p)
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_) | std::path::Component::CurDir))
}

/// How a *static* (proxy_pass) deployment's backend is updated: a working
/// directory on the app-lb host, and commands to run in it.
///
/// The managed counterpart of this is [`BuildSpec`], and the asymmetry is the
/// point. A managed deployment's backend is a microVM app-lb owns, so updating
/// it means producing a new image. A static deployment's backend is a process
/// somebody else runs — usually on this same host, under supervisord or systemd
/// — so updating it means doing on the host what a person would otherwise ssh in
/// and do: pull, build, restart.
///
/// Nothing in the spec changes when this runs. The upstreams are the same
/// addresses; what moved is the code answering on them. That is why the job
/// re-probes those addresses afterwards: "the commands exited 0" is not the same
/// claim as "the service is serving".
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct UpdateSpec {
    /// Absolute path on the app-lb host. Must exist when the job runs — app-lb
    /// never creates it, because a typo that silently created an empty directory
    /// and ran `git pull` in it would be worse than an error.
    pub working_dir: String,
    /// Commands, run in order, each through `sh -c` in `working_dir`. The first
    /// non-zero exit stops the job.
    pub commands: Vec<String>,
    /// Extra environment for every command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,
    /// Environment pulled from the secret store, so a deploy key or registry
    /// token reaches the commands without being written into this spec.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_from: Vec<SecretEnv>,
    /// Git credential for commands that fetch (`git pull`), supplied through
    /// `GIT_ASKPASS`. Only meaningful for HTTP(S) remotes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<SecretRef>,
    /// Ceiling on a single command. Defaults to `APP_LB_BUILD_TIMEOUT_SECS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// How long to wait, after the commands, for every upstream to answer its
    /// health check. `0` skips verification — appropriate when the commands do
    /// not restart anything, and wrong otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_timeout_secs: Option<u64>,
}

fn default_verify_timeout_secs() -> u64 {
    60
}

impl UpdateSpec {
    pub fn verify_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.verify_timeout_secs
                .unwrap_or_else(default_verify_timeout_secs),
        )
    }

    fn validate(&self) -> Result<(), SpecError> {
        let dir = self.working_dir.trim();
        if dir.is_empty() {
            return Err(SpecError::EmptyWorkingDir);
        }
        // Absolute, because the job's CWD is app-lb's own and a relative path
        // would resolve somewhere nobody intended.
        if !dir.starts_with('/')
            || dir.contains('\0')
            || std::path::Path::new(dir)
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(SpecError::BadWorkingDir(self.working_dir.clone()));
        }
        if self.commands.is_empty() {
            return Err(SpecError::NoCommands);
        }
        for c in &self.commands {
            if c.trim().is_empty() || c.contains('\0') {
                return Err(SpecError::BadCommand(c.clone()));
            }
        }
        for from in &self.env_from {
            from.validate("update.env_from")?;
        }
        if let Some(auth) = &self.auth {
            auth.validate().map_err(|e| SpecError::BadSecretRef {
                field: "update.auth",
                detail: e.to_string(),
            })?;
        }
        if self.timeout_secs == Some(0) {
            return Err(SpecError::ZeroTimeout);
        }
        Ok(())
    }
}

/// One secret value, exported to the update commands as an environment variable.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SecretEnv {
    pub secret: String,
    #[serde(default = "default_env_secret_key")]
    pub key: String,
    /// Variable name. Defaults to the key, upper-cased — `{"secret": "obs",
    /// "key": "ingest_token"}` arrives as `INGEST_TOKEN`.
    #[serde(default, rename = "as", skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// The namespace the secret lives in; stamped from the deployment's, see
    /// [`SecretRef::namespace`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

fn default_env_secret_key() -> String {
    "token".into()
}

impl SecretEnv {
    pub fn secret_ref(&self) -> SecretRef {
        SecretRef {
            secret: self.secret.clone(),
            key: self.key.clone(),
            username: None,
            namespace: self.namespace.clone(),
        }
    }

    pub fn env_name(&self) -> String {
        self.env
            .clone()
            .unwrap_or_else(|| self.key.to_ascii_uppercase())
    }

    fn validate(&self, field: &'static str) -> Result<(), SpecError> {
        self.secret_ref()
            .validate()
            .map_err(|e| SpecError::BadSecretRef {
                field,
                detail: e.to_string(),
            })?;
        let name = self.env_name();
        // Not a hard requirement of execve, but a variable name that needs
        // quoting is one the shell cannot read back — so it would be set and
        // then invisible to the command that wanted it.
        let usable = !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if usable {
            Ok(())
        } else {
            Err(SpecError::BadEnvName(name))
        }
    }
}

/// An optional sign-in gate in front of a deployment.
///
/// Orthogonal to the backend kind on purpose: a managed VM pool and a static
/// `proxy_pass` target are gated identically, because this happens in the proxy
/// before either is reached. The application behind it needs to know nothing
/// about OAuth — it sees only requests that got past the gate, optionally with
/// the caller's identity in headers.
///
/// The client *secret* is a [`SecretRef`], not a value, for the same reason a
/// build's git token is: the admin API echoes specs back and the state file
/// holds them in the clear.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AuthGate {
    /// Which credentials get past the gate. A bare string for one
    /// (`"provider": "google"`) or a list for several
    /// (`"provider": ["google", "app-token"]`) — see [`Providers`].
    ///
    /// More than one is the common shape rather than an exotic one: a sandbox
    /// hosting a UI wants a person to sign in with Google *and* the agent
    /// driving it to present an app-token. Any one of the listed providers
    /// admits a request; they are alternatives, not requirements.
    #[serde(default)]
    pub provider: Providers,
    /// OAuth client id from the provider's console. Required for `google`,
    /// meaningless without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Where the client secret is stored. Required for `google`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<SecretRef>,
    /// Google Workspace domains whose accounts may enter, matched against the
    /// `hd` claim (not the email's suffix — see `AuthGate::allows`). `["*"]`
    /// means *any* Google account, which is a real choice and has to be spelled
    /// out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_domains: Vec<String>,
    /// Individual addresses allowed regardless of domain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_emails: Vec<String>,
    /// Path prefixes the *sign-in* gate does not sit in front of.
    ///
    /// This list was never "paths with no authorization" — it is "paths an API
    /// client reaches without being sent to Google", which is a different
    /// thing and was too easily read as the first. Each entry now carries the
    /// scope app-lb requires in the gate's place, and an entry written as a
    /// bare string means [`PathScope::Admin`]: the fail-closed reading, because
    /// the alternative default is the one that leaked.
    ///
    /// A path whose *upstream* does its own authorization — an artifact store
    /// checking its API key, a secret service checking a bearer — says so with
    /// `{"path": "/blobs/", "scope": "public"}`. That is the only spelling that
    /// means "no credential at all", and it has to be written out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_paths: Vec<PublicPath>,
    /// Mint an app-token when somebody signs in here, and present it upstream
    /// for the life of their session.
    ///
    /// This exists because a sign-in gate and the thing behind it are two
    /// different checks. A browser that has signed in with Google holds a
    /// session cookie, which the *upstream* has no way to verify — so a
    /// deployment fronting an API that authenticates for itself (app-lb's own
    /// admin listener, most of all) had no way to accept a signed-in person
    /// except by turning its own authentication off. That is how a dashboard
    /// ends up served by an unauthenticated CRUD API.
    ///
    /// With this set, the gate mints a real app-token at the callback, scoped
    /// as named here and expiring with the session, and the proxy presents it
    /// as `Authorization: Bearer` on every request that session admits. The
    /// upstream then authenticates the person the same way it authenticates any
    /// other client, and scope-checks them the same way too.
    ///
    /// **Absent means no token is minted**, which is the right default for
    /// every gate in front of an ordinary application: signing in to a web app
    /// should not hand the browser a credential for app-lb's admin API. Set it
    /// only on a deployment whose upstream you mean to authorize this way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_scope: Option<crate::tokens::AdminScope>,
    /// Where app-lb's own endpoints live under this deployment's hostname:
    /// `<base_path>/callback`, `/login` and `/logout`. The callback is the URL
    /// that must be registered with the provider.
    #[serde(default = "default_auth_base_path")]
    pub base_path: String,
    /// How long a session lasts before the user is sent back to the provider.
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,
    /// The session cookie's name. Worth changing only if it collides with one
    /// the application already sets.
    #[serde(default = "default_auth_cookie_name")]
    pub cookie_name: String,
    /// Widen the session cookie to a parent domain, so one sign-in covers every
    /// deployment under it. Unset means host-only: the default, and the safe one.
    ///
    /// This is the answer to "why does opening each service from the directory
    /// send me back to Google?". Cookies are scoped to the host that set them, so
    /// signing in at `docs.example.com` leaves `api.example.com` with nothing to
    /// present. Setting `"cookie_domain": "example.com"` on both gates makes the
    /// session one realm, and the second service admits the browser without a
    /// round trip.
    ///
    /// Two properties make that safe, and both are load-bearing:
    ///
    /// * **The cookie is only wider; the check is not.** A session is still
    ///   refused unless the gate presenting it has a byte-identical
    ///   [`AuthGate::policy_fingerprint`], which covers the provider, client id,
    ///   allowed domains, allowed emails *and* this field. Two gates share a
    ///   session only when either would have admitted the same person anyway.
    /// * **It is opt-in.** A cookie scoped to `example.com` is sent to every
    ///   host under it, including ones app-lb does not serve. If anything else
    ///   on that domain is untrusted — a customer subdomain, a legacy box — this
    ///   hands it your session cookie. `HttpOnly` keeps scripts off it, nothing
    ///   keeps a server on that domain off it.
    ///
    /// Must be the request host or a parent of it, at a label boundary. A value
    /// the browser would reject is refused at registration, because the failure
    /// it produces — the cookie silently dropped, sign-in looping forever — is
    /// almost impossible to diagnose from the outside.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_domain: Option<String>,
    /// Redirect URI to send the provider, when app-lb cannot derive it from the
    /// request — something in front rewriting the host or terminating TLS
    /// elsewhere. Normally unset: `https://<request host><base_path>/callback`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    /// Pass the identity upstream as `x-auth-request-{email,user,name}`
    /// (oauth2-proxy's spelling, so apps that already read those work unchanged).
    /// Those headers are stripped from the incoming request either way, so a
    /// client cannot forge them.
    #[serde(default = "default_true")]
    pub forward_identity: bool,
    /// How to verify a JWT, when `jwt` is among the providers. See [`JwtSpec`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<JwtSpec>,
    /// Inherit the *identity* half of this gate from a named provider declared on
    /// the deployment's namespace. See [`AuthProviderSpec`].
    ///
    /// When set, this gate carries only the route-scoped fields — `public_paths`,
    /// `session_scope`, `base_path`, `cookie_name`, `redirect_url`,
    /// `forward_identity`, `session_ttl_secs` — and the provider supplies who may
    /// enter and how they are verified (`provider`, `client_id`, `client_secret`,
    /// `allowed_domains`, `allowed_emails`, `jwt`, `cookie_domain`). Setting any
    /// of those inline *and* a reference is refused
    /// ([`SpecError::ProviderRefWithInlineIdentity`]) rather than silently
    /// overridden, because whoever wrote them believes they take effect.
    ///
    /// Resolution is live: app-lb looks the provider up on every gated request,
    /// so rotating the client secret or tightening the allow-list on the provider
    /// propagates to every deployment that names it — and, because the resolved
    /// gate's [`policy_fingerprint`](Self::policy_fingerprint) changes with it,
    /// re-signs the sessions issued under the old policy. A reference that names
    /// no provider in the namespace is refused at registration, and if one is
    /// removed out from under a live deployment the gate fails *closed*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_ref: Option<String>,
}

/// The default claim a subject is read from, and the default leeway.
const DEFAULT_SUBJECT_CLAIM: &str = "sub";
const DEFAULT_EMAIL_CLAIM: &str = "email";
const DEFAULT_NAME_CLAIM: &str = "name";

/// Ceiling on `leeway_secs`.
///
/// Five minutes is more clock skew than any two machines that can reach each
/// other should have, and the field's whole job is to paper over skew. A gate
/// that wanted an hour of it would be asking for expired tokens to keep working
/// for an hour, which is not leeway — it is a longer expiry, and belongs to
/// whoever issues the token.
pub const MAX_JWT_LEEWAY_SECS: u64 = 300;

/// How a gate verifies a JWT, and which ones it lets past.
///
/// The block exists because a JWT gate is configuration all the way down. app-lb
/// did not issue the token and cannot ask anyone about it, so every question —
/// which key, which algorithm, which issuer, which claim is the user, which
/// claims must hold — is something the spec has to answer. The upside of that is
/// versatility: the Heyo auth API and an Auth0 tenant differ only in this block.
///
/// A gate for the Heyo auth API is:
///
/// ```jsonc
/// "auth": {
///   "provider": "jwt",
///   "jwt": {
///     "secret":     {"secret": "heyo-auth", "key": "jwt_secret"},
///     "algorithms": ["HS256"],
///     "issuer":     "auth-service",
///     "audience":   "heyo-app",
///     "subject_claim": "userId",
///     "require":    {"role": ["user", "admin"]}
///   }
/// }
/// ```
///
/// and the same gate in front of an OIDC provider is the same block with
/// `jwks_url`, `RS256` and the default `sub`.
///
/// ## The allow-list is `require`, not `allowed_emails`
///
/// [`AuthGate::allowed_domains`] and [`AuthGate::allowed_emails`] describe a
/// *Google* identity: the domain is matched on the `hd` claim precisely because
/// an email suffix proves nothing there. Neither statement transfers to a token
/// from your own issuer, where the claims mean what that issuer says they mean —
/// so a gate that accepts `jwt` without also accepting `google` is refused if it
/// sets them, rather than appearing to restrict something it does not.
///
/// `require` is the equivalent and it is more general: any claim, against a
/// value or a set of them. An empty `require` admits any token the issuer signed
/// for this audience, which — unlike Google's empty allow-list, where the
/// population is everyone with a Google account — is exactly "a signed-in user
/// of this product", and a reasonable thing to want.
///
/// ## What is not here
///
/// There is no claim forwarding. The gate puts `x-auth-request-{email,user,name}`
/// upstream like any other, and beyond that the application can read the token
/// itself: it is still in the `Authorization` header the request arrived with,
/// signed, and the app already trusts the issuer or it would not be behind this
/// gate. Copying claims into headers would only give it a second, weaker copy.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct JwtSpec {
    /// The HMAC shared secret, as a reference into the secret store. For the
    /// `HS*` algorithms, and the shape the Heyo auth API uses (`JWT_SECRET`).
    ///
    /// A reference rather than a literal for the usual reason, and one specific
    /// to this: the same value verifies *and mints* tokens, so a spec carrying it
    /// would hand anyone who can read a deployment the ability to issue
    /// identities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretRef>,
    /// A PEM public key or certificate, inline. For the `RS*`, `PS*` and `ES*`
    /// algorithms when the issuer publishes one key rather than a key set.
    ///
    /// Inline rather than a [`SecretRef`] because it is a *public* key: putting
    /// it in the secret store would imply it needs protecting and make rotating
    /// it a two-step operation for no gain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// The issuer's JWKS endpoint, usually `<issuer>/.well-known/jwks.json`.
    ///
    /// The right choice for any provider that rotates keys: the set is fetched,
    /// cached for ten minutes, and refetched when a token names a `kid` that is
    /// not in it — so a rotation needs nothing done here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    /// The signature algorithms this gate accepts, e.g. `["HS256"]` or
    /// `["RS256", "ES256"]`.
    ///
    /// **Required, with no default.** The algorithm is named in the token's own
    /// header, which is attacker-controlled input, and a verifier that dispatches
    /// on it accepts both an unsigned token (`alg: none`) and one signed with a
    /// public key used as an HMAC secret. See [`crate::jwt`].
    pub algorithms: Vec<String>,
    /// The `iss` a token must carry, exactly.
    ///
    /// Required, because a signature proves only that *a* holder of the key
    /// signed the token — and with a shared secret that is every service the
    /// secret was ever handed to.
    pub issuer: String,
    /// The `aud` a token must carry, if the issuer sets one. Matched against a
    /// string audience or a member of an array one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Claims a token must satisfy, on top of being validly signed.
    ///
    /// A value or a list of them per claim: a list is an OR within that claim,
    /// and the map is an AND across claims. A claim that is *itself* a list —
    /// scopes, roles, groups — is satisfied when it contains one of the wanted
    /// values, which is what makes `{"scopes": "deploy"}` mean what it looks
    /// like.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub require: BTreeMap<String, serde_json::Value>,
    /// Which claim holds the stable user id forwarded as `x-auth-request-user`.
    /// `sub` unless the issuer says otherwise — the Heyo auth API uses `userId`.
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
    /// Which claim holds the address forwarded as `x-auth-request-email`.
    #[serde(default = "default_email_claim")]
    pub email_claim: String,
    /// Which claim holds the display name. Absent from most tokens, and absent
    /// here means the header is simply not sent.
    #[serde(default = "default_name_claim")]
    pub name_claim: String,
    /// Clock skew allowed on `exp` and `nbf`, in seconds. Capped at
    /// [`MAX_JWT_LEEWAY_SECS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leeway_secs: Option<u64>,
    /// A cookie to read the token from when there is no `Authorization` header.
    ///
    /// For a browser application whose sign-in put the JWT in a cookie — common,
    /// and the only way a page navigation can carry a credential at all, since a
    /// browser cannot set a header on one. The `Authorization` header still wins
    /// when both are present: a request that says what it is presenting means it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<String>,
    /// Optional Heyo Auth `/api/auth/login` endpoint for browser email/password
    /// sign-in. The returned access token must pass this JWT policy before a
    /// host-only HttpOnly cookie is set. Requires `cookie`; never stores refresh
    /// tokens or passwords. Existing bearer-only gates remain unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_endpoint: Option<String>,
    /// Where to send a browser that reaches a gated path holding no valid token.
    ///
    /// The `jwt` provider is otherwise stateless: it verifies a token that is
    /// already being carried and, finding none, answers `401`. That is right for
    /// a program, and a dead end for a person — a browser cannot set an
    /// `Authorization` header on a navigation, so it has no way to *acquire* one.
    ///
    /// Set this to the issuer's hosted sign-in page and a token-less **browser**
    /// (a request whose `Accept` includes HTML) is redirected there instead, with
    /// the URL it was trying to reach passed in `login_redirect_param`. The issuer
    /// signs the user in, sets the JWT in the `cookie` named above, and redirects
    /// back; the gate then reads the cookie and admits the request. app-lb mints
    /// no session and keeps no flow state — the cookie the issuer set *is* the
    /// session. A program (no HTML in `Accept`) still gets the `401`, which it can
    /// act on and would only fail to parse as a sign-in page.
    ///
    /// Requires `cookie`: the return trip is a navigation, and a navigation can
    /// carry a credential only in a cookie ([`SpecError::LoginUrlWithoutCookie`]).
    /// Must be `https://` (or a loopback `http://` for an issuer on this host),
    /// for the same reason `jwks_url` must.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_url: Option<String>,
    /// The query parameter the hosted sign-in reads the return URL from. Only
    /// meaningful with `login_url`; unset means `redirect_uri`. Set it to whatever
    /// the issuer expects — `return_to`, `next`, `rd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_redirect_param: Option<String>,
    /// **Scoped sign-in**: the issuer's OAuth 2.0 authorization endpoint, for a
    /// browser that reaches this gate with no session. Set together with
    /// [`token_url`](Self::token_url); the Heyo auth API serves both at
    /// `/oauth/authorize` and `/oauth/token`.
    ///
    /// The difference from [`login_url`](Self::login_url) is where the
    /// credential ends up. With `login_url` the issuer leaves its token in a
    /// cookie on a domain it shares with this host, so every host under that
    /// domain — other tenants' deployments included — receives it. With this,
    /// app-lb asks the issuer for access to *this deployment's namespace*
    /// (`scope=namespace:<ns>`, plus PKCE `S256` and `state`), the issuer
    /// decides whether the person may reach it, and the code it returns is
    /// exchanged server to server for a token naming this one host
    /// (`gateHost`) and namespace. The gate verifies it against this policy,
    /// checks both claims, and keeps its own host-only session; the token never
    /// sits in a browser at all.
    ///
    /// Must be `https://` (or loopback `http://`). Cannot be combined with a
    /// shared session realm (`cookie_domain`): a session issued for one
    /// namespace must not be honoured by a sibling gate in another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize_url: Option<String>,
    /// The issuer's token endpoint, which the gate calls server to server to
    /// redeem the code from [`authorize_url`](Self::authorize_url).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
}

fn default_subject_claim() -> String {
    DEFAULT_SUBJECT_CLAIM.to_string()
}
fn default_email_claim() -> String {
    DEFAULT_EMAIL_CLAIM.to_string()
}
fn default_name_claim() -> String {
    DEFAULT_NAME_CLAIM.to_string()
}

impl JwtSpec {
    /// The JWT policy for the Heyo auth API, given only where its signing secret
    /// lives — the "works out of the box" case behind the `heyo` provider preset.
    ///
    /// Every field but the secret is fixed by that service's tokens, and matches
    /// the worked example in this type's own documentation: `HS256`, issuer
    /// `auth-service`, audience `heyo-app`, the id in `userId`, and `role` in
    /// `{user, admin}`. Anything unusual — a different audience, a narrower
    /// `require` — is set by editing the resulting provider; this only removes
    /// the need to know the rest to get started.
    pub fn heyo(secret: SecretRef) -> Self {
        JwtSpec {
            secret: Some(secret),
            public_key: None,
            jwks_url: None,
            algorithms: vec!["HS256".to_string()],
            issuer: "auth-service".to_string(),
            audience: Some("heyo-app".to_string()),
            require: BTreeMap::from([(
                "role".to_string(),
                serde_json::json!(["user", "admin"]),
            )]),
            subject_claim: "userId".to_string(),
            email_claim: DEFAULT_EMAIL_CLAIM.to_string(),
            name_claim: DEFAULT_NAME_CLAIM.to_string(),
            leeway_secs: None,
            cookie: None,
            login_endpoint: None,
            login_url: None,
            login_redirect_param: None,
            authorize_url: None,
            token_url: None,
        }
    }

    /// The JWT policy for the Heyo auth API's **gate tokens**, given where its
    /// key set is published — the "works out of the box" case behind the
    /// `heyo-jwks` provider preset, and the one to prefer.
    ///
    /// The difference from [`heyo`](Self::heyo) is the whole point of it: that
    /// one verifies an `HS256` token with the auth service's *signing* secret,
    /// so the fleet holding it can also mint any identity that service can
    /// issue. This one verifies an `RS256` signature against a published public
    /// key, so it holds nothing secret at all — which is what makes it safe to
    /// declare in a namespace somebody else administers, or on an app-lb
    /// somebody else runs.
    ///
    /// The audience is `heyo-gate` rather than `heyo-app`: a gate token is
    /// minted for this purpose (by the hosted sign-in page, or
    /// `POST /api/auth/gate-token`), and keeping the populations apart means a
    /// platform token cannot be replayed at a gate and a gate token cannot be
    /// replayed at the API.
    pub fn heyo_jwks(jwks_url: String) -> Self {
        JwtSpec {
            secret: None,
            public_key: None,
            jwks_url: Some(jwks_url),
            algorithms: vec!["RS256".to_string()],
            issuer: "auth-service".to_string(),
            audience: Some("heyo-gate".to_string()),
            require: BTreeMap::from([(
                "role".to_string(),
                serde_json::json!(["user", "admin"]),
            )]),
            subject_claim: "userId".to_string(),
            email_claim: DEFAULT_EMAIL_CLAIM.to_string(),
            name_claim: DEFAULT_NAME_CLAIM.to_string(),
            leeway_secs: None,
            cookie: None,
            // The browser path for a gate token is the issuer's own hosted
            // sign-in (`login_url`), which sets the cookie itself. app-lb
            // posting an email and password to `/api/auth/login` would get an
            // *access* token back — `aud: heyo-app` — which this policy is
            // built to refuse.
            login_endpoint: None,
            login_url: None,
            login_redirect_param: None,
            authorize_url: None,
            token_url: None,
        }
    }

    /// The authorization and token endpoints, when this gate runs the scoped
    /// sign-in flow. See [`authorize_url`](Self::authorize_url).
    pub fn scoped_signin(&self) -> Option<(&str, &str)> {
        match (&self.authorize_url, &self.token_url) {
            (Some(a), Some(t)) => Some((a.as_str(), t.as_str())),
            _ => None,
        }
    }

    /// The query parameter the hosted sign-in reads the return URL from. See
    /// [`login_url`](Self::login_url); `redirect_uri` unless overridden.
    pub fn login_redirect_param(&self) -> &str {
        self.login_redirect_param.as_deref().unwrap_or("redirect_uri")
    }

    /// Whether this gate accepts a token signed with `alg`.
    ///
    /// Compared against the configured names rather than a parsed set, so the
    /// answer is a function of what the spec says and nothing else.
    pub fn accepts(&self, alg: crate::jwt::Algorithm) -> bool {
        self.algorithms.iter().any(|a| a == alg.as_str())
    }

    /// The JWKS endpoint, or the empty string for a gate holding a static key.
    /// Callers reach this only after establishing there is no static key.
    pub fn jwks_url(&self) -> &str {
        self.jwks_url.as_deref().unwrap_or("")
    }

    pub fn leeway_secs(&self) -> u64 {
        self.leeway_secs.unwrap_or(0).min(MAX_JWT_LEEWAY_SECS)
    }

    /// Everything about this block that decides *who* gets in, as one string.
    ///
    /// Feeds [`AuthGate::policy_fingerprint`]. Deliberately covers the key
    /// source as well as the policy: rotating an issuer is as much a change of
    /// who may enter as editing `require` is. The secret's *value* is not here —
    /// only which store entry it names — because this digest is not a secret and
    /// ends up in a cookie.
    fn fingerprint(&self) -> String {
        let key = match (&self.secret, &self.public_key, &self.jwks_url) {
            (Some(r), _, _) => format!("secret:{}/{}", r.secret, r.key),
            (_, Some(pem), _) => format!("pem:{}", pem.trim()),
            (_, _, Some(url)) => format!("jwks:{url}"),
            _ => String::new(),
        };
        let mut algorithms = self.algorithms.clone();
        algorithms.sort();
        // `require` is a BTreeMap, so it renders in a stable order without
        // sorting it here.
        let require: Vec<String> = self
            .require
            .iter()
            .map(|(claim, value)| format!("{claim}={value}"))
            .collect();
        let mut material = format!(
            "{key}|{}|{}|{}|{}|{}",
            algorithms.join(","),
            self.issuer,
            self.audience.as_deref().unwrap_or(""),
            require.join(","),
            self.subject_claim,
        );
        // Appended only when set, so a policy without scoped sign-in hashes what
        // it hashed before the field existed. In the material because the
        // issuer behind it decides who gets a session here.
        if let Some((authorize, token)) = self.scoped_signin() {
            material.push_str(&format!("|signin={authorize}|{token}"));
        }
        material
    }

    /// Whether the key material is a shared secret, which is what decides the
    /// algorithm family this gate may name.
    fn is_symmetric(&self) -> bool {
        self.secret.is_some()
    }

    /// [`validate`](Self::validate), reachable from the verifier's tests so the
    /// two halves of the algorithm-confusion defence can be asserted together:
    /// the spec that describes the attack is refused, *and* a token exercising
    /// it would not verify anyway.
    #[cfg(test)]
    pub fn validate_for_test(&self) -> Result<(), SpecError> {
        self.validate()
    }

    fn validate(&self) -> Result<(), SpecError> {
        // Exactly one source of key material. Two would leave "which key
        // verified this?" answerable only by reading the code.
        let sources = [
            ("jwt.secret", self.secret.is_some()),
            ("jwt.public_key", self.public_key.is_some()),
            ("jwt.jwks_url", self.jwks_url.is_some()),
        ];
        let named: Vec<&str> = sources.iter().filter(|(_, set)| *set).map(|(n, _)| *n).collect();
        match named.as_slice() {
            [] => return Err(SpecError::NoJwtKey),
            [_] => {}
            many => {
                return Err(SpecError::AmbiguousJwtKey(
                    many.iter().map(|n| n.to_string()).collect(),
                ));
            }
        }

        if let Some(secret) = &self.secret {
            secret.validate().map_err(|e| SpecError::BadSecretRef {
                field: "jwt.secret",
                detail: e.to_string(),
            })?;
        }
        if let Some(pem) = &self.public_key {
            crate::jwt::public_key_from_pem(pem).map_err(SpecError::BadJwtPublicKey)?;
        }
        if let Some(url) = &self.jwks_url {
            match jwks_url_problem(url.trim()) {
                None => {}
                Some(JwksUrlProblem::Malformed) => {
                    return Err(SpecError::BadJwksUrl(url.trim().to_string()));
                }
                Some(JwksUrlProblem::Plaintext) => {
                    return Err(SpecError::InsecureJwksUrl(url.trim().to_string()));
                }
            }
        }

        if self.algorithms.is_empty() {
            return Err(SpecError::NoJwtAlgorithms);
        }
        for name in &self.algorithms {
            let alg = crate::jwt::Algorithm::parse(name)
                .ok_or_else(|| SpecError::BadJwtAlgorithm(name.clone()))?;
            // The family has to match the key, or the gate could never verify
            // anything — and, for a public key named alongside `HS256`, would be
            // the algorithm-confusion setup itself written down as configuration.
            if alg.is_symmetric() != self.is_symmetric() {
                return Err(SpecError::JwtAlgorithmKeyMismatch {
                    algorithm: name.clone(),
                    symmetric_key: self.is_symmetric(),
                });
            }
        }

        if self.issuer.trim().is_empty() || self.issuer.trim().len() != self.issuer.len() {
            return Err(SpecError::BadJwtIssuer(self.issuer.clone()));
        }
        if let Some(aud) = &self.audience
            && (aud.trim().is_empty() || aud.trim().len() != aud.len())
        {
            return Err(SpecError::BadJwtAudience(aud.clone()));
        }
        for claim in [&self.subject_claim, &self.email_claim, &self.name_claim] {
            if claim.trim().is_empty() {
                return Err(SpecError::EmptyJwtClaimName);
            }
        }
        for claim in self.require.keys() {
            if claim.trim().is_empty() {
                return Err(SpecError::EmptyJwtClaimName);
            }
        }
        if self.leeway_secs.is_some_and(|n| n > MAX_JWT_LEEWAY_SECS) {
            return Err(SpecError::JwtLeewayTooLarge {
                secs: self.leeway_secs.unwrap_or(0),
                max: MAX_JWT_LEEWAY_SECS,
            });
        }
        if let Some(cookie) = &self.cookie
            && !is_valid_cookie_name(cookie)
        {
            return Err(SpecError::BadCookieName(cookie.clone()));
        }
        if let Some(endpoint) = &self.login_endpoint {
            let valid = reqwest::Url::parse(endpoint).is_ok_and(|url| {
                (url.scheme() == "https"
                    || (url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))))
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            });
            if !valid || self.cookie.is_none() {
                return Err(SpecError::BadJwtLoginEndpoint);
            }
        }
        if let Some(url) = &self.login_url {
            // The same transport rule as jwks_url: a browser redirected to
            // plaintext http on another host is a downgrade an attacker on the
            // path can exploit, and loopback is the only http exception.
            match jwks_url_problem(url.trim()) {
                None => {}
                Some(_) => return Err(SpecError::BadLoginUrl(url.trim().to_string())),
            }
            // Without a cookie the return navigation has nowhere to carry the
            // token, so the browser would be redirected to sign in, come back
            // with no header the gate can read, and be redirected again — a loop
            // that is impossible to diagnose from the outside.
            if self.cookie.is_none() {
                return Err(SpecError::LoginUrlWithoutCookie);
            }
        }
        match (&self.authorize_url, &self.token_url) {
            (None, None) => {}
            (Some(authorize), Some(token)) => {
                for url in [authorize, token] {
                    if jwks_url_problem(url.trim()).is_some() {
                        return Err(SpecError::BadScopedSignin(url.trim().to_string()));
                    }
                }
            }
            _ => return Err(SpecError::ScopedSigninIncomplete),
        }
        Ok(())
    }
}

/// A shared session realm would let a session issued for one namespace's
/// deployment admit a browser at a sibling gate in another, whose identical
/// policy fingerprint is no evidence the issuer would have said yes there.
fn check_signin_realm(jwt: &Option<JwtSpec>, cookie_domain: &Option<String>) -> Result<(), SpecError> {
    if cookie_domain.is_some() && jwt.as_ref().is_some_and(|j| j.scoped_signin().is_some()) {
        return Err(SpecError::ScopedSigninWithRealm);
    }
    Ok(())
}

/// What is wrong with a JWKS URL, or `None`.
enum JwksUrlProblem {
    Malformed,
    /// `http://` to somewhere other than this host.
    Plaintext,
}

/// Whether a JWKS endpoint is one app-lb will fetch verifying keys from.
///
/// The transport rule is the security one, and it is stricter than the artifact
/// store's for a reason the two do not share. A blob from a store is verified
/// against a digest the spec names, so a tampered response is caught; a key set
/// **is** the thing everything else is checked against, so anyone who can rewrite
/// the response can mint tokens this gate will accept. Plaintext HTTP therefore
/// buys a complete authentication bypass for anyone on the path.
///
/// Loopback is the exception, and the same one OAuth carves out for redirect
/// URIs: there is no path to be on. An issuer running beside app-lb on this host
/// is a real deployment shape, and refusing it would push people to terminate
/// TLS just to satisfy a check.
fn jwks_url_problem(url: &str) -> Option<JwksUrlProblem> {
    if url.contains(char::is_whitespace) || url.contains('\0') {
        return Some(JwksUrlProblem::Malformed);
    }
    if let Some(rest) = url.strip_prefix("https://") {
        return rest.is_empty().then_some(JwksUrlProblem::Malformed);
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return Some(JwksUrlProblem::Malformed);
    };
    if rest.is_empty() {
        return Some(JwksUrlProblem::Malformed);
    }
    // The authority, up to the path/query and without any port.
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or_else(|| rest.split(['/', '?', '#']).next().unwrap_or(""));
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
        || host.starts_with("127.");
    (!loopback).then_some(JwksUrlProblem::Plaintext)
}

/// The characters a cookie name may hold (RFC 6265 token). Shared by the session
/// cookie and the JWT gate's, so the two cannot drift.
fn is_valid_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Validate the *identity* half of a gate — who may enter and how they are
/// verified — independent of any route-scoped configuration.
///
/// This is the part an [`AuthGate`] and an [`AuthProviderSpec`] hold in common:
/// a provider is exactly this subset given a name, and a gate that inherits one
/// is validated against the merged result. Factoring it out is what keeps the
/// two from drifting — a rule tightened here tightens for both.
fn validate_identity(
    provider: &Providers,
    client_id: &Option<String>,
    client_secret: &Option<SecretRef>,
    allowed_domains: &[String],
    allowed_emails: &[String],
    jwt: &Option<JwtSpec>,
) -> Result<(), SpecError> {
    if provider.is_empty() {
        return Err(SpecError::NoAuthProvider);
    }
    let accepts_google = provider.contains(AuthProvider::Google);
    let accepts_jwt = provider.contains(AuthProvider::Jwt);

    if accepts_google {
        let Some(client_id) = client_id else {
            return Err(SpecError::EmptyClientId);
        };
        if client_id.trim().is_empty() {
            return Err(SpecError::EmptyClientId);
        }
        let Some(client_secret) = client_secret else {
            return Err(SpecError::EmptyClientId);
        };
        client_secret.validate().map_err(|e| SpecError::BadSecretRef {
            field: "auth.client_secret",
            detail: e.to_string(),
        })?;

        // An empty allow-list would gate the deployment behind "has a Google
        // account", which is nearly everyone. That is a legitimate thing to
        // want, so it can be asked for — but only in writing.
        if allowed_domains.is_empty() && allowed_emails.is_empty() {
            return Err(SpecError::EmptyAllowList);
        }
    } else if client_id.is_some() || client_secret.is_some() {
        // OAuth credentials on a gate that will never run an OAuth flow.
        // Rejected rather than ignored: whoever wrote them believes this
        // deployment is behind Google sign-in, and it is not.
        return Err(SpecError::OauthWithoutGoogle);
    }

    match (accepts_jwt, jwt) {
        (true, Some(jwt)) => {
            jwt.validate()?;
            // These describe a Google identity and are checked against a
            // Google identity; a JWT gate's allow-list is `jwt.require`.
            // Refused rather than ignored, because somebody writing them
            // believes this deployment is restricted and it would not be.
            if !accepts_google && (!allowed_domains.is_empty() || !allowed_emails.is_empty()) {
                return Err(SpecError::AllowListOnJwtGate);
            }
        }
        (true, None) => return Err(SpecError::JwtWithoutPolicy),
        // A `jwt` block on a gate that will never verify one, for the same
        // reason OAuth credentials without `google` are refused.
        (false, Some(_)) => return Err(SpecError::JwtPolicyWithoutProvider),
        (false, None) => {}
    }
    for d in allowed_domains {
        // Surrounding whitespace is rejected rather than trimmed: the match
        // is exact, so a stored " example.com " would let nobody in while
        // looking exactly like a rule that does.
        if d.trim().len() != d.len() || d.is_empty() || (d != "*" && !d.contains('.')) {
            return Err(SpecError::BadAllowedDomain(d.clone()));
        }
    }
    for e in allowed_emails {
        if !e.contains('@') || e.trim().len() != e.len() {
            return Err(SpecError::BadAllowedEmail(e.clone()));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AuthProvider {
    /// Google sign-in: an OAuth redirect, a session cookie, an allow-list of
    /// domains and addresses. For people in browsers.
    #[default]
    Google,
    /// An app-token app-lb minted, presented as `Authorization: Bearer applb_…`
    /// or `?app_token=`. For programs — and for a browser WebSocket, which
    /// cannot set headers at all.
    ///
    /// The allow-list here is the *token's* `deployments` scope, not
    /// `allowed_domains`/`allowed_emails`: those describe humans and mean
    /// nothing for a credential issued to a process.
    AppToken,
    /// A JWT somebody else issued, presented as `Authorization: Bearer <jwt>`
    /// or in a cookie the gate names. For an application whose users already
    /// sign in somewhere else — the Heyo auth API, or any OIDC provider.
    ///
    /// Unlike the other two this gate holds no state at all: there is no session
    /// to issue and no token table to look in, because the credential carries
    /// its own proof. Configured by [`AuthGate::jwt`]; the allow-list is that
    /// block's `require`, for the reason given there.
    Jwt,
}

/// The providers a gate accepts.
///
/// Serialized as a bare string when there is exactly one, so every gate written
/// before app-tokens existed round-trips through this byte-for-byte — a spec
/// nobody has edited must not acquire an array in its state file just because
/// the type behind the field grew.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Providers(Vec<AuthProvider>);

impl Default for Providers {
    fn default() -> Self {
        Self(vec![AuthProvider::Google])
    }
}

impl Providers {
    /// A provider list of exactly one kind — what a preset builds.
    pub fn one(p: AuthProvider) -> Self {
        Self(vec![p])
    }

    pub fn contains(&self, p: AuthProvider) -> bool {
        self.0.contains(&p)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[AuthProvider] {
        &self.0
    }
}

impl Serialize for Providers {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.0.as_slice() {
            [one] => one.serialize(s),
            many => many.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for Providers {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(AuthProvider),
            Many(Vec<AuthProvider>),
        }
        Ok(match OneOrMany::deserialize(d)? {
            OneOrMany::One(p) => Self(vec![p]),
            OneOrMany::Many(v) => Self(v),
        })
    }
}

/// Hand-written for the same reason `Serialize` above is: the wire form is a
/// union this type's fields do not describe. A derive would emit the schema of
/// a one-field tuple struct, which is a shape no spec has ever contained.
impl schemars::JsonSchema for Providers {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Providers".into()
    }

    fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let one = g.subschema_for::<AuthProvider>().to_value();
        schemars::Schema::try_from(serde_json::json!({
            "description": "One provider, or several. A single provider is written as a bare \
                            string so a gate authored before app-tokens existed round-trips \
                            unchanged.",
            "anyOf": [one, { "type": "array", "items": one }],
        }))
        .expect("a hand-written schema is an object")
    }
}

fn default_auth_base_path() -> String {
    "/__applb/auth".into()
}
fn default_session_ttl_secs() -> u64 {
    43_200 // 12h — a working day plus slack, short enough that a revoked
           // account loses access the same day.
}
/// Canonicalize a `cookie_domain`, or reject it.
///
/// Lowercased and stripped of the legacy leading dot (RFC 6265 ignores it, and
/// people write it out of habit). Refused when it is not a domain, or when it
/// has fewer than two labels: `com` would be a cookie offered to every `.com`
/// host, which browsers discard — the user would never sign in and nothing would
/// say why.
///
/// It does **not** check the public suffix list, so `co.uk` passes here. Doing
/// that properly means shipping and updating the PSL; the practical guard is
/// that the realm must also cover the request host, so the worst a bad value
/// does is fail to widen. The README says so where an operator will read it.
fn normalize_cookie_domain(raw: &str) -> Option<String> {
    let d = raw.trim().trim_start_matches('.').trim_end_matches('.');
    if d.is_empty() || d.len() > 253 {
        return None;
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let ok = labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    ok.then(|| d.to_ascii_lowercase())
}

fn default_auth_cookie_name() -> String {
    "applb_session".into()
}
fn default_auth_cache_secs() -> u64 {
    60
}

fn default_auth_timeout_secs() -> u64 {
    5
}

fn default_true() -> bool {
    true
}

impl AuthGate {
    /// `<base_path>/callback` — the URL the provider redirects back to, and the
    /// one that has to be registered with it.
    pub fn callback_path(&self) -> String {
        format!("{}/callback", self.base_path.trim_end_matches('/'))
    }

    pub fn login_path(&self) -> String {
        format!("{}/login", self.base_path.trim_end_matches('/'))
    }

    pub fn logout_path(&self) -> String {
        format!("{}/logout", self.base_path.trim_end_matches('/'))
    }

    /// Whether `path` is served without the gate.
    /// What `path` requires in the gate's place, or `None` when the gate
    /// applies normally.
    ///
    /// Longest prefix wins, so a narrow entry can tighten a broad one:
    /// `/api/` at `view` beside `/api/admin/` at `admin` means what it reads
    /// like. Without that rule the answer would depend on list order, which is
    /// not somewhere a security decision should live.
    pub fn public_scope(&self, path: &str) -> Option<PathScope> {
        self.public_paths
            .iter()
            .filter(|p| path.starts_with(p.path.as_str()))
            .max_by_key(|p| p.path.len())
            .map(|p| p.scope)
    }

    /// Whether the sign-in gate is bypassed on `path`, whatever is required
    /// instead. Kept for the places that only care about the redirect.
    pub fn is_public(&self, path: &str) -> bool {
        self.public_scope(path).is_some()
    }

    /// Whether this identity may enter.
    ///
    /// The domain is matched on the provider's `hd` claim rather than the part
    /// after `@`, because only `hd` says the account is *governed by* that
    /// Workspace domain. A personal Gmail account can carry any email address a
    /// Workspace admin has not claimed, so trusting the suffix would let
    /// `someone@yourcompany.com` in from an account you do not control.
    pub fn allows(&self, email: &str, hosted_domain: Option<&str>) -> bool {
        let email = email.to_ascii_lowercase();
        if self.allowed_emails.iter().any(|e| e.eq_ignore_ascii_case(&email)) {
            return true;
        }
        self.allowed_domains.iter().any(|d| {
            d == "*"
                || hosted_domain.is_some_and(|hd| hd.eq_ignore_ascii_case(d.trim_start_matches('@')))
        })
    }

    /// A fingerprint of everything that decides *who* may enter. It goes into
    /// each session, so tightening the allow-list or rotating the client id
    /// invalidates the sessions issued under the old policy instead of leaving
    /// a removed user signed in until their cookie expires.
    /// The `Domain` attribute to set for a request arriving at `host`, if any.
    ///
    /// `None` — a host-only cookie — both when sharing is off and when the
    /// configured realm does not cover this host. The second case is a
    /// misconfiguration, and falling back to host-only is the recoverable
    /// direction: sign-in still works for this hostname, it just is not shared.
    /// Emitting the `Domain` anyway would have the browser discard the cookie
    /// outright and loop the user through the provider forever.
    pub fn cookie_domain_for(&self, host: &str) -> Option<String> {
        let realm = normalize_cookie_domain(self.cookie_domain.as_deref()?)?;
        // The realm must be the host or a parent of it, cut at a label boundary
        // — `example.com` covers `api.example.com` but not `notexample.com`.
        let host = host
            .trim_end_matches('.')
            .split(':')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let covers = host == realm
            || host
                .strip_suffix(&realm)
                .is_some_and(|head| head.ends_with('.'));
        covers.then_some(realm)
    }

    pub fn policy_fingerprint(&self) -> String {
        let mut domains: Vec<String> = self
            .allowed_domains
            .iter()
            .map(|d| d.to_ascii_lowercase())
            .collect();
        let mut emails: Vec<String> = self
            .allowed_emails
            .iter()
            .map(|e| e.to_ascii_lowercase())
            .collect();
        domains.sort();
        emails.sort();
        // A single provider renders exactly as the bare `AuthProvider` did
        // before this field became a list, and an absent client_id as the empty
        // string. That keeps the material byte-identical for every gate written
        // before app-tokens existed — this digest keys the session signature, so
        // any change here signs out every user of every gated deployment, and an
        // upgrade is not a good reason to do that. A gate that genuinely *adds*
        // a provider does change it, which is the point.
        let providers = match self.provider.as_slice() {
            [one] => format!("{one:?}"),
            many => format!("{many:?}"),
        };
        let mut material = format!(
            "{}|{}|{}|{}",
            providers,
            self.client_id.as_deref().unwrap_or(""),
            domains.join(","),
            emails.join(",")
        );
        // Appended only when set, so a gate that does not share sessions hashes
        // exactly what it hashed before this field existed — see the note above
        // about not signing everyone out on an upgrade.
        //
        // It has to be *in* the material, though, and this is the security
        // property that makes sharing safe: a session issued by a host-only gate
        // must not be accepted by a realm gate with otherwise identical policy,
        // or widening the cookie on one deployment would retroactively widen
        // what every neighbouring gate accepts.
        if let Some(realm) = &self.cookie_domain {
            material.push_str(&format!("|realm={}", realm.to_ascii_lowercase()));
        }
        // Likewise appended only when present, so a gate written before JWTs
        // existed hashes exactly what it did before.
        //
        // It belongs in the material for a narrow but real case: a gate that
        // accepts both `google` and `jwt` issues session cookies, and those
        // sessions must not outlive a tightened `require` or a rotated issuer
        // any more than they outlive a tightened `allowed_emails`. A jwt-only
        // gate issues no session at all, so for it this changes nothing.
        if let Some(jwt) = &self.jwt {
            material.push_str(&format!("|jwt={}", jwt.fingerprint()));
        }
        let digest = openssl::hash::hash(
            openssl::hash::MessageDigest::sha256(),
            material.as_bytes(),
        )
        .expect("sha256 of a byte string cannot fail");
        digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
    }

    /// Whether a person can sign in with Google here.
    pub fn accepts_google(&self) -> bool {
        self.provider.contains(AuthProvider::Google)
    }

    /// Whether an app-token scoped to this deployment gets past the gate.
    pub fn accepts_app_token(&self) -> bool {
        self.provider.contains(AuthProvider::AppToken)
    }

    /// Whether a JWT from the configured issuer gets past the gate.
    pub fn accepts_jwt(&self) -> bool {
        self.provider.contains(AuthProvider::Jwt)
    }

    /// The JWT policy, present whenever `validate()` passed and `jwt` is among
    /// the providers. An `Option` for the same reason `google_credentials` is:
    /// the two are linked only by validation, and a gate reaching the verifier
    /// without one should say so rather than invent a policy.
    pub fn jwt_policy(&self) -> Option<&JwtSpec> {
        self.jwt.as_ref().filter(|_| self.accepts_jwt())
    }

    /// The OAuth client id, present whenever `validate()` passed and Google is
    /// among the providers. Returned as an `Option` rather than unwrapped
    /// because the two are only linked by validation, and a gate reaching the
    /// OAuth path without one should say so rather than send Google an empty
    /// `client_id` and report whatever it says back.
    pub fn google_credentials(&self) -> Option<(&str, &SecretRef)> {
        match (&self.client_id, &self.client_secret) {
            (Some(id), Some(secret)) if self.accepts_google() => Some((id.as_str(), secret)),
            _ => None,
        }
    }

    /// Whether this gate carries any of the identity fields a `provider_ref`
    /// would supply. `provider` is deliberately not among them — it defaults to
    /// `[google]`, so serde cannot distinguish an omitted field from one written
    /// as its default, and the resolved provider replaces it regardless. Every
    /// field checked here has an unambiguous absent state.
    fn has_inline_identity(&self) -> bool {
        self.client_id.is_some()
            || self.client_secret.is_some()
            || !self.allowed_domains.is_empty()
            || !self.allowed_emails.is_empty()
            || self.jwt.is_some()
            || self.cookie_domain.is_some()
    }

    fn validate(&self, routes: &[RouteRule]) -> Result<(), SpecError> {
        // A gate that inherits its identity from a namespace provider carries no
        // identity of its own: the provider owns `provider`, `client_id`,
        // `client_secret`, the allow-lists, `jwt` and `cookie_domain`. Setting
        // any of them here alongside a reference is refused rather than silently
        // overridden. The identity checks then run against the *resolved* gate
        // at registration (see `AuthProviderSpec::resolve`); here only the
        // route-scoped half is this gate's to validate.
        if self.provider_ref.is_some() {
            if self.has_inline_identity() {
                return Err(SpecError::ProviderRefWithInlineIdentity);
            }
        } else {
            validate_identity(
                &self.provider,
                &self.client_id,
                &self.client_secret,
                &self.allowed_domains,
                &self.allowed_emails,
                &self.jwt,
            )?;
        }

        let base = self.base_path.trim_end_matches('/');
        if !base.starts_with('/') || base.len() < 2 || base.contains(char::is_whitespace) {
            return Err(SpecError::BadAuthBasePath(self.base_path.clone()));
        }
        for p in &self.public_paths {
            if !p.path.starts_with('/') {
                return Err(SpecError::BadPublicPath(p.path.clone()));
            }
        }
        if self.session_ttl_secs == 0 {
            return Err(SpecError::ZeroSessionTtl);
        }
        if !is_valid_cookie_name(&self.cookie_name) {
            return Err(SpecError::BadCookieName(self.cookie_name.clone()));
        }
        if let Some(d) = &self.cookie_domain
            && normalize_cookie_domain(d).is_none()
        {
            return Err(SpecError::BadCookieDomain(d.clone()));
        }
        check_signin_realm(&self.jwt, &self.cookie_domain)?;

        // The provider redirects the browser to `<host><callback>`, and that
        // request has to route back to *this* deployment or the login can never
        // complete. A rule with a path prefix only matches paths under it, so a
        // deployment routed at `/app` needs its base_path there too. Caught here
        // rather than as a 404 halfway through someone's first sign-in.
        let callback = self.callback_path();
        let routable = routes
            .iter()
            .any(|r| r.path_prefix.as_ref().is_none_or(|p| callback.starts_with(p.as_str())));
        if !routable {
            return Err(SpecError::AuthCallbackUnroutable(callback));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct DeploymentSpec {
    /// Unique name for this deployment, and its handle in every other call.
    /// Registering an id that already exists REPLACES that deployment.
    pub id: String,
    /// The namespace this deployment belongs to. Namespaces segregate use: a
    /// token minted for a namespace reaches only the deployments in it, and the
    /// event feed is kept per namespace. Absent means `"default"`, so a fleet
    /// that never says the word keeps behaving as one namespace.
    #[serde(default = "default_namespace", skip_serializing_if = "is_default_namespace")]
    pub namespace: String,
    /// The heyo account that pays for this deployment's VMs, and the user who
    /// registered it. Stamped by app-lb from the caller's federated grant (the
    /// namespace's owning account) on every register and update, overriding
    /// whatever the body said; an operator or local-token caller keeps what it
    /// sent, which on a self-hosted app-lb is usually nothing. Passed to the
    /// daemon on every VM create so the sandbox is metered to the right
    /// account — including the replacements the autoscaler boots with no
    /// caller present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Which requests reach this deployment, most specific rule winning.
    ///
    /// May be empty only for a `vm` deployment, which is then reachable by exec
    /// and shell but takes no HTTP traffic. A static deployment and a site are
    /// reachable only through the proxy, so both need at least one.
    pub routes: Vec<RouteRule>,
    /// Temporarily fence this deployment's public data plane. Routed requests
    /// receive HTTP 503 before auth or backend selection, while deployment
    /// management and VM exec remain available on the separate admin listener.
    /// Persisted as part of the deployment spec and safe to toggle with PUT.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub maintenance: bool,
    /// The VM template for a *managed* deployment: app-lb boots and autoscales a
    /// pool of microVMs. Mutually exclusive with `upstreams`; exactly one of the
    /// two must be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm: Option<VmSpec>,
    /// How many replicas run and when. Every field defaults, so the whole block
    /// may be omitted; it applies to a `vm` deployment (a static deployment's
    /// upstreams and a site's files are not app-lb's to scale).
    #[serde(default)]
    pub scaling: ScalingPolicy,
    /// How app-lb decides a replica is ready to take traffic. Defaults to an
    /// HTTP GET of `/` on the deployment's own port.
    #[serde(default)]
    pub health: HealthCheck,
    /// A *static* (proxy_pass) deployment: forward matched requests to a fixed
    /// set of upstream addresses (`host:port` or `ip:port`) with no VM lifecycle
    /// and no autoscaling. Load-balanced least-in-flight with failover, and
    /// health-re-probed by the autoscaler so a recovered upstream rejoins.
    /// Mutually exclusive with `vm`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<String>,
    /// Orchestrator service whose healthy endpoint set supplies this static
    /// deployment's upstream membership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<DiscoverySpec>,
    /// Opt-in one-hop regional gateway transport over explicit static upstreams.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<crate::gateway::GatewaySpec>,
    /// Where `vm.image` is built from: a git repo and a Dockerfile. Optional —
    /// a deployment can go on naming a prebuilt image — and only valid on a
    /// managed deployment, since a static one has no image to build.
    ///
    /// Not part of `VmSpec`, so editing it is not a template change and does not
    /// recycle the pool. The pool moves when a build finishes and rewrites
    /// `vm.image`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildSpec>,
    /// Where `vm.image` is pulled from: a rootfs already in an artifact store.
    /// The alternative to `build` and mutually exclusive with it — both rewrite
    /// `vm.image`, and a deployment with two sources for it would have no
    /// answer to "where did this image come from".
    ///
    /// Like `build`, editing it disturbs nothing; the pool moves when a pull
    /// finishes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactSpec>,
    /// Serve files from a directory on this host, with no backend at all — the
    /// third kind of deployment, alongside a managed VM pool and a `proxy_pass`
    /// upstream list. See [`SiteSpec`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<SiteSpec>,
    /// How a *static* deployment's backend is updated: a working directory on
    /// this host and commands to run in it. The static counterpart of `build`,
    /// and mutually exclusive with it for the same reason the backend kinds are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<UpdateSpec>,
    /// An optional sign-in gate in front of everything this deployment serves.
    /// Applies to either backend kind — it runs in the proxy, before a backend
    /// is chosen — so the application behind it needs to know nothing about it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthGate>,
    /// Opt-in hooks into the namespace's event feed. Absent means this
    /// deployment publishes nothing and exposes nothing — the feed only ever
    /// carries what a spec explicitly asked it to. See [`FeedSpec`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feed: Option<FeedSpec>,
    /// A second way in, beside `routes`: a URL on the Heyo cloud's domain
    /// that reaches the pool through the daemon rather than through this
    /// proxy. See [`IngressSpec`]. Managed deployments only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<IngressSpec>,
}

/// How a managed deployment is reached from the Heyo cloud.
///
/// `routes` are this proxy's business: a hostname the operator points at
/// `APP_LB_PUBLIC_IPS`. A machine with no public address — a laptop, a box
/// behind NAT — has nothing to point a hostname at, and that is what this
/// is for. With `cloud` set, app-lb binds every *ready* replica's `vm.port`
/// on the daemon as a proxy endpoint tagged with this deployment, and
/// unbinds it when the replica drains. The daemon carries those binds to the
/// cloud, and the cloud issues one URL for the deployment that fans out to
/// whichever binds exist at the moment — so the URL survives autoscaling,
/// replacement and a pool roll.
///
/// Traffic on that URL never passes through this proxy: no `routes` match,
/// no `auth` gate, no guard rule and no SIEM record. `public: false` puts
/// the cloud's own account gate in front of it instead.
///
/// Not part of [`VmSpec`], so toggling it edits nothing about the VMs and
/// never recycles the pool.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct IngressSpec {
    /// Ask the Heyo cloud for a URL, and keep the pool bound behind it.
    #[serde(default)]
    pub cloud: bool,
    /// Whether that URL is reachable by anyone (the default) or only by the
    /// owning account, signed in to the cloud.
    #[serde(default = "default_true")]
    pub public: bool,
}

impl IngressSpec {
    /// Whether the pool's replicas should be bound on the daemon right now.
    pub fn wants_cloud(spec: Option<&IngressSpec>) -> bool {
        spec.is_some_and(|i| i.cloud)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct DiscoverySpec {
    pub service_id: String,
    /// Opt into region-scoped membership; the authority must echo this scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regional: Option<crate::regional::RegionalSpec>,
    /// Managed per-deployment authority; absent preserves the host env default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<DiscoverySource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct DiscoverySource {
    pub url: String,
    pub auth: SecretRef,
}

/// The namespace a spec gets when it names none. One word, so an installation
/// that never uses namespaces is a single namespace rather than a special case.
pub const DEFAULT_NAMESPACE: &str = "default";

fn default_namespace() -> String {
    DEFAULT_NAMESPACE.to_string()
}

fn is_default_namespace(ns: &String) -> bool {
    ns == DEFAULT_NAMESPACE
}

/// What app-lb requires on a path the sign-in gate does not cover.
///
/// The three lower tiers mirror [`crate::tokens::AdminScope`] exactly, because
/// they are the same scopes an app-token carries; `Public` is the extra one,
/// and it is the only value that admits a request presenting nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PathScope {
    /// No credential at all. For a path whose upstream authorizes it, or one
    /// that genuinely has nothing to protect — a health endpoint.
    Public,
    /// Any credential the gate would admit, with no admin tier required. What
    /// an app-token minted with `admin: none` carries, which is the shape an
    /// application is handed to get past its own deployment's gate.
    None,
    /// `view`-tier: metrics and the dashboard's data.
    View,
    /// Everything. The default when a scope is not written down, because a
    /// forgotten field must not be the one that opens a route.
    #[default]
    Admin,
}

impl PathScope {
    /// The app-token tier this demands, or `None` when no credential is needed.
    pub fn required(self) -> Option<crate::tokens::AdminScope> {
        match self {
            Self::Public => None,
            Self::None => Some(crate::tokens::AdminScope::None),
            Self::View => Some(crate::tokens::AdminScope::View),
            Self::Admin => Some(crate::tokens::AdminScope::Admin),
        }
    }
}

/// One entry in [`AuthGate::public_paths`]: a path prefix and what it requires.
///
/// Deserializes from either spelling, and a bare string is the reason this type
/// exists rather than a plain tuple:
///
/// ```json
/// "public_paths": [
///   {"path": "/healthz", "scope": "public"},
///   {"path": "/api/", "scope": "view"},
///   "/deployments"
/// ]
/// ```
///
/// That last one requires `admin`. Every spec written before scopes existed is
/// a list of bare strings, so this is a deliberate behaviour change on upgrade:
/// paths that were open become closed, loudly, instead of staying open quietly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicPath {
    pub path: String,
    pub scope: PathScope,
}

impl From<&str> for PublicPath {
    /// The bare-string spelling, with the same default the wire form uses —
    /// so a spec built in code and one parsed from JSON cannot disagree about
    /// what an unqualified path means.
    fn from(path: &str) -> Self {
        Self { path: path.to_string(), scope: PathScope::default() }
    }
}

impl From<String> for PublicPath {
    fn from(path: String) -> Self {
        Self { path, scope: PathScope::default() }
    }
}

impl PublicPath {
    /// A path with nothing in front of it and nothing required.
    pub fn public(path: impl Into<String>) -> Self {
        Self { path: path.into(), scope: PathScope::Public }
    }
}

impl<'de> Deserialize<'de> for PublicPath {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Bare(String),
            Full {
                path: String,
                #[serde(default)]
                scope: PathScope,
            },
        }
        Ok(match Wire::deserialize(d)? {
            // The default lives here as well as in `PathScope`, because an
            // absent field and an absent object must land in the same place.
            Wire::Bare(path) => Self { path, scope: PathScope::default() },
            Wire::Full { path, scope } => Self { path, scope },
        })
    }
}

/// Hand-written: the wire form is `string | {path, scope}`, and the bare
/// spelling is the *closed* one. Worth stating in the schema itself, because a
/// reader who assumes a bare path is public has it exactly backwards.
impl schemars::JsonSchema for PublicPath {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PublicPath".into()
    }

    fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let scope = g.subschema_for::<PathScope>().to_value();
        schemars::Schema::try_from(serde_json::json!({
            "description": "A path exempted from the gate, as either a bare string or an \
                            object. A BARE STRING MEANS scope \"admin\" — the most closed \
                            scope, not the most open one — so an entry written as a plain \
                            path is reachable only by an admin credential.",
            "anyOf": [
                { "type": "string" },
                {
                    "type": "object",
                    "properties": { "path": { "type": "string" }, "scope": scope },
                    "required": ["path"],
                },
            ],
        }))
        .expect("a hand-written schema is an object")
    }
}

/// A namespace name a spec or a token may carry: the same alphabet as a
/// deployment id, so it can appear in a URL path and a filename unescaped.
///
/// `.` and `..` are excluded by name rather than by alphabet. A dot is
/// legitimate inside a namespace (`v1.2`, `team.eu`) and banning it would be
/// worse than the problem, but those two spellings are the only ones that mean
/// something to a filesystem — and "unescaped in a filename" is exactly the
/// promise this function makes. `namespaces.rs` re-encodes on the way to disk
/// regardless, so this is the outer of two doors, not the only one.
pub fn is_valid_namespace(ns: &str) -> bool {
    !ns.is_empty()
        && ns != "."
        && ns != ".."
        && ns
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// A deployment's opt-in hooks into its namespace's event feed.
///
/// Everything here defaults to *off*: the feed is a megaphone, and a
/// deployment should end up on it only because its spec said so, never because
/// a default did. The three switches are independent — a deployment can
/// announce itself without reporting issues, report issues without announcing,
/// or neither and only `expose` the feed for the rest of its namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct FeedSpec {
    /// Publish this deployment's lifecycle — registered, updated, removed — to
    /// the namespace feed.
    #[serde(default)]
    pub announce: bool,
    /// Publish this deployment's operational issues — a VM that never boots, a
    /// failed scale-up, a cold start that timed out, an upstream going
    /// unhealthy — to the namespace feed.
    #[serde(default)]
    pub issues: bool,
    /// Serve the namespace's feed as RSS at this path on this deployment's own
    /// routes. This is the only way a feed becomes reachable from outside the
    /// admin listener: without an `expose` somewhere in the namespace, the feed
    /// stays private. Runs after the deployment's `auth` gate, so a gated
    /// deployment exposes its feed only to whoever the gate admits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose: Option<String>,
}

impl FeedSpec {
    fn validate(&self, routes: &[RouteRule]) -> Result<(), SpecError> {
        let Some(expose) = &self.expose else {
            return Ok(());
        };
        // The same shape a route's `path_prefix` must have: rooted, and unable
        // to climb. The feed is served by matching this against request paths,
        // so a relative or traversing value could never match anything sane.
        if !expose.starts_with('/') || expose.split('/').any(|seg| seg == "..") {
            return Err(SpecError::BadFeedExpose(expose.clone()));
        }
        if routes.is_empty() {
            return Err(SpecError::FeedExposeWithoutRoutes);
        }
        Ok(())
    }
}

/// What answers a request routed to a deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// An autoscaled pool of microVMs.
    Vm,
    /// A fixed list of `proxy_pass` addresses.
    Upstreams,
    /// Files on this host, served by app-lb itself.
    Site,
}

/// A static *site*: a directory on this host, served straight off disk.
///
/// The third backend kind, and the one with no backend — app-lb answers the
/// request itself instead of proxying it. What nginx's `root` or a CloudFront
/// origin bucket does: files, an index, a 404, and cache headers. There is no
/// pool, nothing to scale, and nothing to health check.
///
/// Deliberately not configurable: rewrites, redirects, per-location blocks. A
/// site that needs those wants a real server behind a `proxy_pass` deployment.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SiteSpec {
    /// Absolute path ON THE APP-LB HOST to the directory to serve. Nothing
    /// outside it is ever served, symlinks included — see `site::resolve`.
    ///
    /// Omit it to have app-lb choose `<APP_LB_SITES_DIR>/<namespace>/<id>`,
    /// which is what a site filled by `build` or `artifact` wants: the caller
    /// cannot see this host's filesystem, and a path that exists only on the
    /// caller's machine registers fine and then 404s every request.
    #[serde(default)]
    pub root: String,
    /// Served for a request that names a directory. Set to `""` to answer those
    /// with a 404 instead of looking for an index.
    #[serde(default = "default_site_index")]
    pub index: String,
    /// Body for a 404, relative to `root`. Absent means a plain-text 404.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_found: Option<String>,
    /// Serve `index` (with a 200) for any path that matches no file, so a
    /// client-side router owns the URL space. The single-page-app switch; off
    /// by default because it turns every typo into a 200.
    #[serde(default)]
    pub spa: bool,
    /// `Cache-Control` for served files. The default is deliberately short:
    /// a wrong long max-age is not something you can take back, since the
    /// client will not ask again until it expires.
    #[serde(default = "default_site_cache_control")]
    pub cache_control: String,
}

fn default_site_index() -> String {
    "index.html".into()
}

/// Five minutes, and public. Long enough that a page's assets survive a reload,
/// short enough that a bad deploy is not pinned in caches for a day. Sites that
/// fingerprint their asset filenames should raise it.
fn default_site_cache_control() -> String {
    "public, max-age=300".into()
}

impl SiteSpec {
    fn validate(&self) -> Result<(), SpecError> {
        let root = self.root.trim();
        if root.is_empty() {
            return Err(SpecError::EmptySiteRoot);
        }
        // Absolute, because app-lb's working directory is not something a spec
        // author can see — a relative root would resolve differently depending
        // on how the process was started.
        if !std::path::Path::new(root).is_absolute() {
            return Err(SpecError::RelativeSiteRoot(root.to_string()));
        }
        for (field, value) in [("index", Some(&self.index)), ("not_found", self.not_found.as_ref())]
        {
            let Some(value) = value.map(|v| v.trim()).filter(|v| !v.is_empty()) else {
                continue;
            };
            // These are joined onto the root, so a rooted or climbing path here
            // would read a file the site was never meant to expose.
            if value.starts_with('/') || value.split('/').any(|p| p == "..") {
                return Err(SpecError::BadSitePath {
                    field,
                    value: value.to_string(),
                });
            }
        }
        if self.spa && self.index.trim().is_empty() {
            return Err(SpecError::SpaWithoutIndex);
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SpecError {
    EmptyId,
    /// `default` cannot be declared: it is where everything unnamespaced lives.
    ReservedNamespace,
    /// A namespace description long enough to be a document.
    DescriptionTooLong,
    /// A namespace outside the id alphabet; it appears in URLs and filenames.
    BadNamespace(String),
    /// A `feed.expose` path that is not an absolute, traversal-free path.
    BadFeedExpose(String),
    /// A `feed.expose` on a deployment with no routes to serve it from.
    FeedExposeWithoutRoutes,
    /// `ingress.cloud` on a deployment with no VM pool to bind.
    IngressWithoutVm,
    /// Workflow ids are interpolated into NATS subjects and VM names unescaped.
    BadWorkflowId(String),
    EmptyWorkflowRepo,
    EmptyWorkflowRef,
    EmptyWorkflowNetwork,
    BadWorkflowPath(String),
    /// A *static* deployment declared no routes. Managed deployments may:
    /// see [`DeploymentSpec::validate`].
    NoRoutes,
    EmptyRoute,
    StripPrefixWithoutPath,
    /// A sign-in gate on a deployment with no routes. The gate only ever runs
    /// on a proxied request, and an unrouted deployment receives none.
    AuthWithoutRoutes,
    UnsupportedDriver(Driver),
    /// A `driver: lxc` spec naming a block that only means something on heyvm.
    /// Carries the field, because "this is not supported" without saying which
    /// of eight blocks is the problem is not an error anyone can act on.
    NotForLxc(&'static str),
    /// A block that will work on `lxc` eventually but does not yet. A separate
    /// variant from [`Self::NotForLxc`] so the message can say "not yet" rather
    /// than "never" — the two send an operator to different places.
    LxcNotYet(&'static str),
    /// `driver: lxc` with no image. Unlike heyvm there is no catalog default to
    /// fall back to.
    LxcNeedsImage,
    LxcBadImage(String),
    /// A deployment id that cannot produce a legal Incus instance name.
    BadLxcId { id: String, why: &'static str },
    BadReplicaRange { min: u32, max: u32 },
    ZeroTargetConcurrency,
    ZeroPort,
    /// A `site` with no `root` to serve.
    EmptySiteRoot,
    /// A `site.root` that is not an absolute path.
    RelativeSiteRoot(String),
    /// `index` or `not_found` escapes the site root, or is rooted.
    BadSitePath {
        field: &'static str,
        value: String,
    },
    /// `spa` needs an `index` to fall back *to*.
    SpaWithoutIndex,
    /// A `site` alongside a `vm` or `upstreams`: a deployment serves from one
    /// place, and three ways to answer a request has no defined precedence.
    SiteWithOtherBackend,
    /// A guest-image-only block or field on a site (`build.dockerfile`, …).
    NotForSites(&'static str),
    /// A site-only field set on a deployment that is not a site.
    OnlyForSites(&'static str),
    /// A site set more than one of `update`, `artifact` and `build`; each
    /// claims to produce the files under `site.root`.
    BothSiteSources,
    /// Both a `vm` template and a static `upstreams` list were set.
    BothBackendKinds,
    /// Neither a `vm` template nor a static `upstreams` list was set.
    NoBackendKind,
    EmptyDiscoveryServiceId,
    DiscoveryWithOtherBackend,
    InvalidDiscoverySource(String),
    InvalidGateway(String),
    /// A static upstream address is not a valid plaintext `host:port` or HTTPS URL.
    BadUpstream(String),
    /// A static deployment declared a `build` block; there is no image to build.
    BuildOnStaticDeployment,
    /// A static deployment declared an `artifact` block; there is no image to
    /// pull one into.
    ArtifactOnStaticDeployment,
    /// Both `build` and `artifact` were set; both claim to produce `vm.image`.
    BothImageSources,
    /// A managed deployment declared an `update` block; its backend is a VM, not
    /// a process on this host.
    UpdateOnManagedDeployment,
    /// `vm.workspace_archive` reached app-lb without the object key cloud
    /// resolves from the archive id.
    UnresolvedWorkspaceArchive(String),
    /// Both `vm.workspace_archive` and `vm.workspace` claim `/workspace`.
    ArchiveWithWorkspace,
    EmptyWorkingDir,
    BadWorkingDir(String),
    NoCommands,
    BadCommand(String),
    BadEnvName(String),
    ZeroTimeout,
    EmptyClientId,
    /// `"provider": []` — a gate that admits nobody by any means.
    NoAuthProvider,
    /// OAuth credentials on a gate that never runs an OAuth flow.
    OauthWithoutGoogle,
    /// `jwt` is among the providers but there is no `jwt` block to verify with.
    JwtWithoutPolicy,
    /// A `jwt` block on a gate that will never verify one.
    JwtPolicyWithoutProvider,
    /// `allowed_domains`/`allowed_emails` on a gate with no Google provider.
    /// They describe a Google identity and would restrict nothing here.
    AllowListOnJwtGate,
    /// A `jwt` block naming no key material at all.
    NoJwtKey,
    /// A `jwt` block naming more than one source of key material.
    AmbiguousJwtKey(Vec<String>),
    BadJwtPublicKey(String),
    BadJwksUrl(String),
    /// A JWKS endpoint reached over plaintext HTTP, somewhere other than this
    /// host. Whoever can rewrite that response can mint tokens the gate accepts.
    InsecureJwksUrl(String),
    /// `jwt.algorithms` is empty. There is no default: see [`JwtSpec::algorithms`].
    NoJwtAlgorithms,
    BadJwtAlgorithm(String),
    /// An algorithm whose key family is not the one the block configured — an
    /// HMAC algorithm against a public key, or the reverse.
    JwtAlgorithmKeyMismatch {
        algorithm: String,
        symmetric_key: bool,
    },
    BadJwtIssuer(String),
    BadJwtAudience(String),
    BadJwtLoginEndpoint,
    /// A `jwt.login_url` that is not an `https://` URL (or a loopback `http://`).
    BadLoginUrl(String),
    /// `jwt.login_url` set with no `jwt.cookie` to carry the token back on the
    /// return navigation — the redirect would loop forever.
    LoginUrlWithoutCookie,
    /// `jwt.authorize_url` or `jwt.token_url` that is not `https://` (or a
    /// loopback `http://`).
    BadScopedSignin(String),
    /// One of `jwt.authorize_url` and `jwt.token_url` without the other.
    ScopedSigninIncomplete,
    /// Scoped sign-in on a gate that shares sessions across a `cookie_domain`.
    ScopedSigninWithRealm,
    EmptyJwtClaimName,
    JwtLeewayTooLarge {
        secs: u64,
        max: u64,
    },
    /// Neither an allowed domain nor an allowed address was given.
    EmptyAllowList,
    BadAllowedDomain(String),
    BadAllowedEmail(String),
    BadAuthBasePath(String),
    BadPublicPath(String),
    ZeroSessionTtl,
    BadCookieName(String),
    BadCookieDomain(String),
    /// The provider's redirect would not route back to this deployment.
    AuthCallbackUnroutable(String),
    /// `auth.provider_ref` set alongside an inline identity field, which the
    /// referenced provider would supply. Refused rather than silently overridden.
    ProviderRefWithInlineIdentity,
    /// An auth provider name outside the id alphabet; it appears in a filename
    /// and in the deployments that reference it.
    BadAuthProviderName(String),
    /// `auth.provider_ref` names a provider that is not declared in the
    /// deployment's namespace. Carries both so the message can name what was
    /// looked up and where.
    UnknownAuthProvider {
        namespace: String,
        name: String,
    },
    /// A `POST /auth-providers` body named a `preset` app-lb does not know.
    UnknownAuthPreset(String),
    EmptyRepo,
    UnsupportedRepoUrl(String),
    BadBuildRef(String),
    BadBuildPath(String),
    BadImageName(String),
    /// A `build` block set both `repo` and `store`; both name the recipe.
    BothBuildSources,
    /// A `build` block set neither `repo` nor `store`, so there is nothing to
    /// build from.
    NoBuildSource,
    EmptyBuildStore,
    UnsupportedBuildStore(String),
    /// `build.store` was set without a `build.ref`. A store has no default
    /// branch to fall back to.
    MissingBuildRef,
    /// `build.ref` on a store source is neither a tag nor a digest.
    BadBuildArtifactRef(String),
    /// A field that only means something for a git checkout, set on a build
    /// whose recipe comes from a store.
    OnlyForGitBuilds(&'static str),
    EmptyArtifactStore,
    UnsupportedArtifactStore(String),
    BadArtifactRef(String),
    ZeroGrow,
    /// A `vm.mounts[].path` the guest could not mount, or could not survive
    /// mounting. Carries *why* rather than a bare rejection: the rules are
    /// several and unrelated, and "bad mount path" alone leaves the author
    /// guessing which one they hit.
    BadMountPath {
        path: String,
        why: &'static str,
    },
    /// Two mounts on the same guest path.
    DuplicateMountPath(String),
    /// One mount inside another. Ordered rather than symmetric, because which is
    /// which is the fix.
    NestedMountPath {
        outer: String,
        inner: String,
    },
    /// More mounts than a guest has device letters for. See [`MAX_MOUNTS`].
    TooManyMounts {
        count: usize,
        max: usize,
    },
    /// The store half of a mount is empty or is neither a URL nor an absolute
    /// path. Separate from [`Self::UnsupportedArtifactStore`] only so the
    /// message can name the mount it belongs to — one spec can hold eight.
    BadMountStore {
        path: String,
        store: String,
    },
    BadMountRef {
        path: String,
        reference: String,
    },
    /// A pinned `vm.mounts[].digest` that is not a sha256.
    BadMountDigest {
        path: String,
        digest: String,
    },
    /// A writable mount on the `kvm` driver, which would sync the guest's writes
    /// back into the shared tree. See [`MountSpec::read_only`].
    WritableMountOnKvm(String),
    /// A secret reference somewhere in the spec is malformed. Carries the field
    /// it came from: four blocks can hold one, and "a secret ref is unusable"
    /// with no idea which is not an error message anyone can act on.
    BadSecretRef {
        field: &'static str,
        detail: String,
    },
    /// A workspace on a driver other than `firecracker`. See [`WorkspaceSpec`].
    WorkspaceDriver(Driver),
    BadWorkspacePath {
        path: String,
        why: &'static str,
    },
    /// `vm.workspace.store` is not `s3://…`, a URL, or an absolute path.
    BadWorkspaceStore(String),
    BadWorkspaceRef(String),
    /// A workspace with more than one replica: two writers, one snapshot.
    WorkspaceReplicas(u32),
    WorkspaceWarmPool(u32),
    /// `vm.workspace.snapshot_interval_secs` under the floor.
    WorkspaceSnapshotInterval(u64),
    /// The workspace and a mount would land on the same guest path, or one
    /// inside the other.
    WorkspaceCollidesWithMount {
        workspace: String,
        mount: String,
    },
}

impl std::fmt::Display for SpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyId => write!(f, "deployment id must not be empty"),
            Self::ReservedNamespace => write!(
                f,
                "\"default\" cannot be declared: it is where every deployment that names \
                 no namespace already lives, so it exists whether or not anything says so"
            ),
            Self::DescriptionTooLong => {
                write!(f, "a namespace description must be 400 characters or fewer")
            }
            Self::BadNamespace(ns) => write!(
                f,
                "namespace {ns:?} must contain only letters, digits, '-', '_' and '.' — \
                 it is used in URLs and filenames unescaped"
            ),
            Self::BadFeedExpose(p) => write!(
                f,
                "feed.expose {p:?} must be an absolute path with no '..' segments, \
                 like \"/feed.xml\""
            ),
            Self::FeedExposeWithoutRoutes => write!(
                f,
                "feed.expose serves the feed on this deployment's routes, and this \
                 deployment has none"
            ),
            Self::IngressWithoutVm => write!(
                f,
                "ingress.cloud binds a VM's port on the daemon, and this deployment \
                 has no VM pool — only a managed (`vm`) deployment can have a cloud URL"
            ),
            Self::BadWorkflowId(id) => write!(
                f,
                "workflow id {id:?} must contain only letters, digits, '-' and '_'; \
                 it is interpolated into a NATS subject and a VM name unescaped"
            ),
            Self::EmptyWorkflowRepo => write!(f, "workflow.repo must name a repository"),
            Self::EmptyWorkflowRef => write!(f, "workflow.ref must name a branch or ref"),
            Self::EmptyWorkflowNetwork => write!(
                f,
                "workflow.network must name the heyvm network whose hosts run this \
                 workflow"
            ),
            Self::BadWorkflowPath(p) => write!(
                f,
                "workflow.path {p:?} must be a relative path inside the repository, \
                 with no leading '/' and no '..' segments"
            ),
            Self::EmptySiteRoot => write!(f, "site.root must name a directory to serve"),
            Self::RelativeSiteRoot(p) => write!(
                f,
                "site.root must be an absolute path, got {p:?} — app-lb's working \
                 directory is not something a spec can rely on"
            ),
            Self::BadSitePath { field, value } => write!(
                f,
                "site.{field} must be a path inside the site root, got {value:?}"
            ),
            Self::SpaWithoutIndex => {
                write!(f, "site.spa needs a site.index to fall back to")
            }
            Self::SiteWithOtherBackend => write!(
                f,
                "a deployment serves from exactly one place: `site` cannot be combined \
                 with `vm` or `upstreams`"
            ),
            Self::NotForSites(what) => write!(
                f,
                "`{what}` does not apply to a site — it serves files off disk, with no \
                 image and no pool"
            ),
            Self::OnlyForSites(what) => write!(
                f,
                "`{what}` only applies to a site, which unpacks its artifact into a \
                 directory. A managed (vm) deployment's artifact is a single guest rootfs, \
                 and nothing unpacks it"
            ),
            Self::BothSiteSources => write!(
                f,
                "a site sets more than one of `update`, `artifact` and `build`: pick one — \
                 each writes the files under `site.root`, so with two there is no answer to \
                 where what is being served came from. Run the build on this host \
                 (`update`), unpack a bundle somebody already built (`artifact`), or copy a \
                 git checkout in (`build` with `repo`)"
            ),
            Self::NoRoutes => write!(
                f,
                "this deployment must declare at least one route; only a managed (vm) \
                 deployment may have none, and is then reachable only by exec/shell — \
                 a static deployment and a site are both reachable only through the proxy"
            ),
            Self::AuthWithoutRoutes => write!(
                f,
                "a deployment with no routes takes no HTTP traffic, so there is nothing \
                 for `auth` to gate"
            ),
            Self::EmptyRoute => {
                write!(
                    f,
                    "a route must set at least one of `host`, `host_suffix` or `path_prefix`"
                )
            }
            Self::StripPrefixWithoutPath => write!(
                f,
                "route.strip_prefix requires route.path_prefix"
            ),
            Self::UnsupportedDriver(d) => write!(
                f,
                "driver {d} is not supported: app-lb routes directly to the guest IP, \
                 which the daemon only exposes for tap-networked firecracker/kvm backends"
            ),
            Self::NotForLxc(field) => write!(
                f,
                "{field} is not supported on driver lxc: it describes something only the heyvm \
                 daemon does, and an Incus container has no equivalent"
            ),
            Self::LxcNotYet(field) => write!(
                f,
                "{field} is not supported on driver lxc yet"
            ),
            Self::LxcNeedsImage => write!(
                f,
                "driver lxc needs vm.image: an OCI reference such as `nginx:1.27` or \
                 `ghcr.io/org/app:v1`. There is no default — heyvm's `ubuntu:24.04` is a \
                 catalog name, not a registry reference"
            ),
            Self::LxcBadImage(image) => write!(
                f,
                "vm.image {image:?} is not a usable OCI reference"
            ),
            Self::BadLxcId { id, why } => write!(
                f,
                "deployment id {id:?} cannot name an Incus container: {why}. Container names \
                 become DNS labels, so a `driver: lxc` deployment needs an id of at most \
                 {MAX_LXC_DEPLOYMENT_ID} characters made of lowercase letters, digits and \
                 dashes, starting with a letter or digit and not ending in a dash"
            ),
            Self::BadReplicaRange { min, max } => {
                write!(f, "min_replicas ({min}) exceeds max_replicas ({max})")
            }
            Self::ZeroTargetConcurrency => write!(f, "target_concurrency must be greater than 0"),
            Self::ZeroPort => write!(f, "vm.port must be greater than 0"),
            Self::BothBackendKinds => write!(
                f,
                "a deployment sets both `vm` and `upstreams`: pick one — a managed VM \
                 pool or a static proxy_pass upstream list, not both"
            ),
            Self::NoBackendKind => write!(
                f,
                "a deployment must set exactly one of `vm` (managed VM pool) or \
                 `upstreams` (static proxy_pass)"
            ),
            Self::EmptyDiscoveryServiceId => write!(f, "discovery.service_id must not be empty"),
            Self::InvalidDiscoverySource(error) => write!(f, "invalid discovery source: {error}"),
            Self::InvalidGateway(error) => write!(f, "invalid gateway: {error}"),
            Self::DiscoveryWithOtherBackend => write!(
                f,
                "discovery supplies a static upstream set and cannot be combined with `vm` or `site`"
            ),
            Self::BadUpstream(a) => write!(
                f,
                "static upstream {a:?} is not a valid `host:port` address or HTTPS URL"
            ),
            Self::BuildOnStaticDeployment => write!(
                f,
                "a static (proxy_pass) deployment cannot declare `build`: it has no guest \
                 image, it forwards to upstreams somebody else runs. Use `update` to run \
                 commands on the host instead"
            ),
            Self::ArtifactOnStaticDeployment => write!(
                f,
                "a static (proxy_pass) deployment cannot declare `artifact`: it has no guest \
                 image to pull a rootfs into, it forwards to upstreams somebody else runs"
            ),
            Self::BothImageSources => write!(
                f,
                "a deployment sets both `build` and `artifact`: pick one — both rewrite \
                 `vm.image` when they run, so with both there is no answer to where the \
                 running image came from. Build from git, or pull a rootfs somebody already \
                 built; to do both, build on one host and `heyctl artifact push` the result"
            ),
            Self::UnresolvedWorkspaceArchive(id) => write!(
                f,
                "vm.workspace_archive {id:?} has no storage key: name the archive by `archive_id` \
                 through the Heyo cloud API, which resolves it, rather than posting to app-lb \
                 directly"
            ),
            Self::ArchiveWithWorkspace => write!(
                f,
                "`vm.workspace_archive` and `vm.workspace` both claim the workspace directory; \
                 seed from an archive or keep a persistent workspace, not both"
            ),
            Self::UpdateOnManagedDeployment => write!(
                f,
                "a managed (vm) deployment cannot declare `update`: its backends are microVMs, \
                 not processes on this host, so a working directory here would update nothing. \
                 Use `build` to rebuild its image instead"
            ),
            Self::EmptyWorkingDir => write!(f, "update.working_dir must not be empty"),
            Self::BadWorkingDir(d) => write!(
                f,
                "update.working_dir {d:?} must be an absolute path on the app-lb host, with \
                 no `..` components"
            ),
            Self::NoCommands => write!(
                f,
                "update.commands must list at least one command — a working directory with \
                 nothing to run in it updates nothing"
            ),
            Self::BadCommand(c) => write!(f, "update command {c:?} is empty or unusable"),
            Self::BadEnvName(n) => write!(
                f,
                "{n:?} is not a usable environment variable name: use [A-Za-z_][A-Za-z0-9_]*, \
                 or set `as` on the env_from entry"
            ),
            Self::ZeroTimeout => write!(
                f,
                "update.timeout_secs must be greater than 0; omit it to use the server default"
            ),
            Self::EmptyClientId => write!(
                f,
                "auth.client_id and auth.client_secret are required for the `google` provider"
            ),
            Self::NoAuthProvider => write!(
                f,
                "auth.provider is empty, so nothing could ever get past the gate — \
                 name at least one of \"google\", \"app-token\" or \"jwt\""
            ),
            Self::JwtWithoutPolicy => write!(
                f,
                "auth.provider lists `jwt` but there is no auth.jwt block, so there is no \
                 key to verify a token with. Set auth.jwt.algorithms, auth.jwt.issuer and \
                 one of secret / public_key / jwks_url"
            ),
            Self::JwtPolicyWithoutProvider => write!(
                f,
                "auth sets an auth.jwt block but does not list the `jwt` provider, so no \
                 token will ever be verified — add \"jwt\" to auth.provider, or drop the \
                 block"
            ),
            Self::AllowListOnJwtGate => write!(
                f,
                "auth sets allowed_domains/allowed_emails on a gate with no `google` \
                 provider. Those are matched against a Google identity — the domain against \
                 the `hd` claim — and restrict nothing here, so a gate carrying them would \
                 look guarded and not be. Use auth.jwt.require, which can name any claim"
            ),
            Self::NoJwtKey => write!(
                f,
                "auth.jwt names no key: set `secret` (a secret-store reference, for HS*), \
                 `public_key` (an inline PEM, for RS*/PS*/ES*) or `jwks_url` (the issuer's \
                 key set)"
            ),
            Self::AmbiguousJwtKey(fields) => write!(
                f,
                "auth.jwt names more than one key ({}), so which one verified a token would \
                 depend on the order this happens to check them. Keep exactly one",
                fields.join(" and ")
            ),
            Self::BadJwtPublicKey(e) => write!(f, "auth.jwt.public_key is {e}"),
            Self::InsecureJwksUrl(u) => write!(
                f,
                "auth.jwt.jwks_url {u:?} is plaintext http:// to another host. The key set is \
                 what every token is checked against, so anyone able to rewrite that response \
                 could mint tokens this gate would accept — which is an authentication bypass, \
                 not an eavesdropping risk. Use https://, or a loopback address for an issuer \
                 running on this host"
            ),
            Self::BadJwksUrl(u) => write!(
                f,
                "auth.jwt.jwks_url {u:?} must be an http:// or https:// URL — usually \
                 <issuer>/.well-known/jwks.json"
            ),
            Self::NoJwtAlgorithms => write!(
                f,
                "auth.jwt.algorithms is required and has no default: the algorithm is named \
                 in the token's own header, and a gate that trusted that would accept an \
                 unsigned token. Name the one the issuer signs with, e.g. [\"HS256\"]"
            ),
            Self::BadJwtAlgorithm(a) => write!(
                f,
                "auth.jwt.algorithms names {a:?}, which is not a supported JWS algorithm. \
                 Supported: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384. \
                 `none` is not, and never will be"
            ),
            Self::JwtAlgorithmKeyMismatch {
                algorithm,
                symmetric_key,
            } => match symmetric_key {
                true => write!(
                    f,
                    "auth.jwt.algorithms names {algorithm:?}, which needs a key pair, but the \
                     block configures a shared `secret`. Use jwks_url or public_key, or name \
                     an HS* algorithm"
                ),
                false => write!(
                    f,
                    "auth.jwt.algorithms names {algorithm:?}, which is HMAC, but the block \
                     configures a public key. A public key used as an HMAC secret is the \
                     algorithm-confusion attack, so this is refused: use `secret` for HS*, or \
                     name an RS*/PS*/ES* algorithm"
                ),
            },
            Self::BadJwtIssuer(i) => write!(
                f,
                "auth.jwt.issuer {i:?} must be the exact `iss` the tokens carry, with no \
                 surrounding whitespace"
            ),
            Self::BadJwtAudience(a) => write!(
                f,
                "auth.jwt.audience {a:?} must be the exact `aud` the tokens carry, with no \
                 surrounding whitespace"
            ),
            Self::BadJwtLoginEndpoint => write!(f, "auth.jwt.login_endpoint requires a cookie and an HTTPS URL without credentials, query or fragment (HTTP loopback is allowed)"),
            Self::BadLoginUrl(u) => write!(
                f,
                "auth.jwt.login_url {u:?} must be an https:// URL — the hosted sign-in page a \
                 token-less browser is redirected to. http:// is allowed only to a loopback \
                 address, for an issuer running on this host: a browser redirected to \
                 plaintext elsewhere can have the sign-in intercepted"
            ),
            Self::BadScopedSignin(u) => write!(
                f,
                "auth.jwt.authorize_url and auth.jwt.token_url must be https:// URLs ({u:?} is \
                 not); http:// is allowed only to a loopback address"
            ),
            Self::ScopedSigninIncomplete => write!(
                f,
                "auth.jwt.authorize_url and auth.jwt.token_url go together: the browser is sent \
                 to the first, and the code it brings back is redeemed at the second"
            ),
            Self::ScopedSigninWithRealm => write!(
                f,
                "scoped sign-in (auth.jwt.authorize_url) cannot share sessions across \
                 cookie_domain: each session is issued for one host and one namespace, and a \
                 realm would let a sibling gate in another namespace honour it"
            ),
            Self::LoginUrlWithoutCookie => write!(
                f,
                "auth.jwt.login_url is set but auth.jwt.cookie is not. The browser is redirected \
                 to sign in and comes back on a navigation, which can carry the token only in a \
                 cookie — with none named, the gate cannot read it and redirects again, forever. \
                 Set auth.jwt.cookie to the cookie the issuer writes the token into"
            ),
            Self::EmptyJwtClaimName => write!(
                f,
                "auth.jwt names an empty claim; subject_claim, email_claim, name_claim and \
                 every key of `require` have to name a claim"
            ),
            Self::JwtLeewayTooLarge { secs, max } => write!(
                f,
                "auth.jwt.leeway_secs is {secs}, above the {max}s ceiling. Leeway covers \
                 clock skew between two machines; a longer one is a longer expiry, and that \
                 belongs to whoever issues the token"
            ),
            Self::OauthWithoutGoogle => write!(
                f,
                "auth sets client_id/client_secret but does not list the `google` provider, \
                 so no OAuth flow will ever run — add \"google\" to auth.provider, or drop \
                 the credentials"
            ),
            Self::EmptyAllowList => write!(
                f,
                "auth sets neither `allowed_domains` nor `allowed_emails`, which would let \
                 in anyone with a Google account. Name the Workspace domain(s) or the \
                 address(es) — or set `\"allowed_domains\": [\"*\"]` if any Google account \
                 really is the intent"
            ),
            Self::BadAllowedDomain(d) => write!(
                f,
                "auth.allowed_domains entry {d:?} is not a domain: use a Workspace domain \
                 like \"example.com\", or \"*\" for any Google account"
            ),
            Self::BadAllowedEmail(e) => write!(
                f,
                "auth.allowed_emails entry {e:?} is not an email address"
            ),
            Self::BadAuthBasePath(p) => write!(
                f,
                "auth.base_path {p:?} must be an absolute path with at least one segment, \
                 e.g. \"/__applb/auth\""
            ),
            Self::BadPublicPath(p) => {
                write!(f, "auth.public_paths entry {p:?} must start with `/`")
            }
            Self::ZeroSessionTtl => write!(f, "auth.session_ttl_secs must be greater than 0"),
            Self::BadCookieName(c) => write!(
                f,
                "auth.cookie_name {c:?} is not a usable cookie name"
            ),
            Self::BadCookieDomain(d) => write!(
                f,
                "auth.cookie_domain {d:?} is not a domain a browser would accept: it needs at \
                 least two labels (\"example.com\", not \"com\") and must be a parent of the \
                 hostnames this deployment serves. Leave it unset for a per-host session"
            ),
            Self::AuthCallbackUnroutable(c) => write!(
                f,
                "no route would match the sign-in callback {c:?}, so the provider's redirect \
                 would 404 and the login could never finish. Set `auth.base_path` under a \
                 path prefix this deployment serves"
            ),
            Self::ProviderRefWithInlineIdentity => write!(
                f,
                "auth sets `provider_ref` and also an identity field (client_id, \
                 client_secret, allowed_domains, allowed_emails, jwt or cookie_domain). The \
                 referenced provider supplies all of those, so an inline one would be \
                 overridden — set them on the provider, and keep only the route-scoped \
                 fields (public_paths, session_scope, base_path, cookie_name, redirect_url, \
                 forward_identity, session_ttl_secs) here"
            ),
            Self::BadAuthProviderName(n) => write!(
                f,
                "auth provider name {n:?} is not usable: it appears in a filename and in \
                 every deployment that references it, so it takes the namespace alphabet — \
                 letters, digits, '-', '_' and '.'"
            ),
            Self::UnknownAuthProvider { namespace, name } => write!(
                f,
                "auth.provider_ref names {name:?}, but no such auth provider is declared in \
                 the {namespace:?} namespace. A deployment may inherit only a provider in \
                 its own namespace — declare it with POST /auth-providers first"
            ),
            Self::UnknownAuthPreset(p) => write!(
                f,
                "auth provider preset {p:?} is not one app-lb knows. The presets are \
                 \"heyo-jwks\", which verifies the Heyo auth API's gate tokens against its \
                 published key set and needs no secret, or \"heyo\", which verifies its \
                 HS256 access tokens from a `secret`"
            ),
            Self::EmptyRepo => write!(f, "build.repo must not be empty"),
            Self::UnsupportedRepoUrl(r) => write!(
                f,
                "build.repo {r:?} is not a supported remote: use https://, ssh://, \
                 user@host:path or an absolute path on this host"
            ),
            Self::BadBuildRef(r) => write!(
                f,
                "build.ref {r:?} is not a usable git ref: no whitespace, no leading `-`, \
                 and none of ~^:?*[\\'\""
            ),
            Self::BadBuildPath(p) => write!(
                f,
                "build path {p:?} must be relative to the checkout and must not climb out \
                 of it with `..`"
            ),
            Self::BadImageName(n) => write!(
                f,
                "build.image_name {n:?} has no usable characters: image names are \
                 [a-z0-9._-] and must start with a letter or digit"
            ),
            Self::BothBuildSources => write!(
                f,
                "a build sets both `build.repo` and `build.store`: pick one — both name the \
                 Dockerfile to build, and a build with two recipes has no answer to which one \
                 produced the image. Check the recipe into the repo, or `art dockerfile put` \
                 it into the store"
            ),
            Self::NoBuildSource => write!(
                f,
                "a build sets neither `build.repo` nor `build.store`, so there is no \
                 Dockerfile to build. Set `build.repo` for a git checkout, or `build.store` \
                 and `build.ref` for a Dockerfile manifest in an artifact store"
            ),
            Self::EmptyBuildStore => write!(f, "build.store must not be empty"),
            Self::UnsupportedBuildStore(s) => write!(
                f,
                "build.store {s:?} is not a usable store: give either an `art serve` URL \
                 (http://host:port) or an absolute path to a store root on this host"
            ),
            Self::MissingBuildRef => write!(
                f,
                "build.store is set but build.ref is not: name the Dockerfile manifest to \
                 build, as a tag or a digest. Unlike a git remote, a store has no default \
                 branch to fall back to"
            ),
            Self::BadBuildArtifactRef(r) => write!(
                f,
                "build.ref {r:?} is neither a tag nor a digest: a tag is [A-Za-z0-9._-] and \
                 may not start with `-` or `.`, and a digest is 64 lowercase hex characters. \
                 (A git ref would be valid here only if `build.repo` were set instead of \
                 `build.store`)"
            ),
            Self::OnlyForGitBuilds(what) => write!(
                f,
                "`{what}` only applies to a build from a git checkout, where it selects a \
                 file within the repo. A Dockerfile manifest already names its recipe \
                 (`Dockerfile`) and its context (`context.tar.gz`), so there is nothing left \
                 to point at"
            ),
            Self::EmptyArtifactStore => write!(f, "artifact.store must not be empty"),
            Self::UnsupportedArtifactStore(s) => write!(
                f,
                "artifact.store {s:?} is not a usable store: give either an `art serve` URL \
                 (http://host:port) or an absolute path to a store root on this host"
            ),
            Self::BadArtifactRef(r) => write!(
                f,
                "artifact.ref {r:?} is neither a tag nor a digest: a tag is [A-Za-z0-9._-] \
                 and may not start with `-` or `.`, or a repository and tag like \
                 `heyo/postgres:16` (lowercase segments); a digest is 64 lowercase hex characters"
            ),
            Self::ZeroGrow => write!(
                f,
                "artifact.grow_gb must be greater than 0; omit it to keep the image at its \
                 stored size"
            ),
            Self::BadMountPath { path, why } => write!(
                f,
                "vm.mounts[].path {path:?} {why}"
            ),
            Self::DuplicateMountPath(p) => write!(
                f,
                "two mounts both land on {p:?}; a guest path identifies a mount, so give \
                 them separate paths"
            ),
            Self::NestedMountPath { outer, inner } => write!(
                f,
                "mount {inner:?} is inside mount {outer:?}; the guest mounts them in order, \
                 so the inner one would be hidden by the outer. Move it elsewhere, or ship \
                 both trees in the one tarball"
            ),
            Self::TooManyMounts { count, max } => write!(
                f,
                "{count} mounts is more than the {max} a guest is given device letters for; \
                 combine them into fewer tarballs"
            ),
            Self::BadMountStore { path, store } => write!(
                f,
                "the store for mount {path:?} must be an `art serve` URL (http:// or \
                 https://) or an absolute store root on this host, got {store:?}"
            ),
            Self::BadMountRef { path, reference } => write!(
                f,
                "the ref for mount {path:?} is neither a tag nor a digest: a tag is \
                 [A-Za-z0-9._-] and may not start with `-` or `.`, and a digest is 64 \
                 lowercase hex characters, got {reference:?}"
            ),
            Self::BadMountDigest { path, digest } => write!(
                f,
                "the digest pinned on mount {path:?} must be 64 lowercase hex characters, \
                 got {digest:?}. Omit it to let a pull resolve `ref` and fill it in"
            ),
            Self::WritableMountOnKvm(p) => write!(
                f,
                "mount {p:?} is read_only: false on the kvm driver, which syncs a writable \
                 mount back into the host tree when the VM stops — and that tree is the \
                 content-addressed copy every other replica boots from. Keep the mount \
                 read-only, or use the firecracker driver, where each VM's copy is its own"
            ),
            Self::BadSecretRef { field, detail } => {
                write!(f, "{field} is unusable: {detail}")
            }
            Self::WorkspaceDriver(d) => write!(
                f,
                "vm.workspace needs the firecracker driver, got {d}: the kvm driver syncs a \
                 writable mount back into the host tree itself when the VM stops, which is not \
                 the capture this feature performs"
            ),
            Self::BadWorkspacePath { path, why } => {
                write!(f, "vm.workspace.path {path:?} {why}")
            }
            Self::BadWorkspaceStore(s) => write!(
                f,
                "vm.workspace.store {s:?} is not a snapshot destination: use `s3://bucket/prefix`, \
                 an `http(s)://` artifact store, or the absolute path of a local one"
            ),
            Self::BadWorkspaceRef(r) => write!(
                f,
                "vm.workspace.ref {r:?} is not a tag: [A-Za-z0-9._-], not starting with `-` or `.`"
            ),
            Self::WorkspaceReplicas(n) => write!(
                f,
                "vm.workspace needs scaling.max_replicas <= 1, got {n}: the workspace is one \
                 directory with one writer, captured from the replica that retires and seeded \
                 into the one that replaces it; two replicas would each capture a different copy"
            ),
            Self::WorkspaceWarmPool(n) => write!(
                f,
                "vm.workspace needs scaling.warm_pool = 0, got {n}: a warm replica is booted \
                 ahead of time from a tree the live replica is still changing"
            ),
            Self::WorkspaceSnapshotInterval(n) => write!(
                f,
                "vm.workspace.snapshot_interval_secs must be at least \
                 {MIN_SNAPSHOT_INTERVAL_SECS}, got {n}: each snapshot drains and stops the \
                 replica, so a shorter interval is mostly downtime"
            ),
            Self::WorkspaceCollidesWithMount { workspace, mount } => write!(
                f,
                "vm.workspace.path {workspace:?} and mount {mount:?} overlap; a mount cannot sit \
                 on or inside the workspace, and the workspace cannot sit inside a mount"
            ),
        }
    }
}

impl std::error::Error for SpecError {}

impl DeploymentSpec {
    /// Which of the three backend kinds this deployment is.
    ///
    /// A valid spec sets exactly one of `vm`, `upstreams` and `site` (enforced
    /// by [`validate`](Self::validate)). Prefer matching on this over asking
    /// two questions: the code used to assume "static or managed" throughout,
    /// and a third kind added to that shape is a bug in every place the
    /// question was really "does this have a VM pool?".
    pub fn backend(&self) -> Backend {
        if self.site.is_some() {
            Backend::Site
        } else if !self.upstreams.is_empty() || self.discovery.is_some() {
            Backend::Upstreams
        } else {
            Backend::Vm
        }
    }

    /// A static (proxy_pass) deployment forwards to fixed upstreams instead of a
    /// managed VM pool. **A site is not static in this sense** — it has no
    /// upstreams either — so this is not the predicate for "has no VM pool".
    pub fn is_static(&self) -> bool {
        self.backend() == Backend::Upstreams
    }

    /// Serves files off disk rather than proxying anywhere.
    pub fn is_site(&self) -> bool {
        self.backend() == Backend::Site
    }

    /// Owns an autoscaled VM pool — the only kind the autoscaler, the job
    /// system and the eviction API have anything to do with.
    pub fn is_managed(&self) -> bool {
        self.backend() == Backend::Vm
    }

    /// The VM template of a *managed* deployment. Panics if called on a static
    /// deployment — the VM-lifecycle code (autoscaler) only reaches this after
    /// confirming the deployment is managed, and `validate` guarantees a managed
    /// spec has a `vm`.
    /// Which runtime this deployment's replicas run on, or `None` when it has
    /// no replicas at all (a static or site deployment).
    ///
    /// The non-panicking counterpart to [`Self::vm_spec`], for the paths that
    /// need only the driver and should not have to prove the deployment is
    /// managed first.
    pub fn driver(&self) -> Option<Driver> {
        self.vm.as_ref().map(|vm| vm.driver)
    }

    pub fn vm_spec(&self) -> &VmSpec {
        self.vm
            .as_ref()
            .expect("vm_spec() on a static deployment; guard on is_static() first")
    }

    /// Rejects specs the data plane could not serve.
    ///
    /// A deployment is either *managed* (a `vm` template, autoscaled) or *static*
    /// (a fixed `upstreams` list, proxy_pass); exactly one must be set. For the
    /// managed kind the driver check is load-bearing: `SandboxInfo.guest_ip` is
    /// only populated for tap-networked Firecracker/KVM on a local daemon, so a
    /// Libvirt VM would boot fine and then be unroutable.
    /// Bind every secret reference in the spec to the spec's own namespace.
    ///
    /// Run before [`validate`](Self::validate) on every path a spec enters by
    /// (register, edit, state-file load), so a resolution anywhere downstream —
    /// a build's git token, a gate's client secret, a replica's `env_from` —
    /// can only ever find a secret behind the same wall as the deployment.
    /// Whatever `namespace` the client wrote on a reference is overwritten,
    /// which is the point: naming another namespace's secret is not an error
    /// to report, it is a thing that cannot be expressed.
    pub fn normalize(&mut self) {
        let ns = self.namespace.clone();
        for r in self.secret_refs_mut() {
            r.scope_to(&ns);
        }
        if let Some(vm) = &mut self.vm {
            for e in &mut vm.env_from {
                e.namespace = Some(ns.clone());
            }
        }
        if let Some(update) = &mut self.update {
            for e in &mut update.env_from {
                e.namespace = Some(ns.clone());
            }
        }
    }

    /// Every [`SecretRef`] in the spec, mutably. `env_from` entries are not
    /// refs and are handled beside this in [`normalize`](Self::normalize).
    fn secret_refs_mut(&mut self) -> Vec<&mut SecretRef> {
        let mut out: Vec<&mut SecretRef> = Vec::new();
        if let Some(gateway) = &mut self.gateway {
            out.push(&mut gateway.auth);
        }
        if let Some(discovery) = &mut self.discovery {
            if let Some(source) = &mut discovery.source { out.push(&mut source.auth); }
            if let Some(regional) = &mut discovery.regional { out.push(&mut regional.auth); }
        }
        if let Some(b) = &mut self.build {
            out.extend(b.auth.as_mut());
        }
        if let Some(a) = &mut self.artifact {
            out.extend(a.auth.as_mut());
        }
        if let Some(vm) = &mut self.vm {
            for m in &mut vm.mounts {
                out.extend(m.auth.as_mut());
            }
            if let Some(ws) = &mut vm.workspace {
                out.extend(ws.auth.as_mut());
            }
        }
        if let Some(u) = &mut self.update {
            out.extend(u.auth.as_mut());
        }
        if let Some(gate) = &mut self.auth {
            out.extend(gate.client_secret.as_mut());
            if let Some(jwt) = &mut gate.jwt {
                out.extend(jwt.secret.as_mut());
            }
        }
        out
    }

    /// The ids of every secret the spec refers to, in its own namespace. What
    /// a delete checks before refusing.
    pub fn secret_ids(&self) -> Vec<String> {
        let mut refs: Vec<Option<&SecretRef>> = vec![
            self.gateway.as_ref().map(|g| &g.auth),
            self.discovery.as_ref().and_then(|d| d.source.as_ref()).map(|s| &s.auth),
            self.discovery.as_ref().and_then(|d| d.regional.as_ref()).map(|s| &s.auth),
            self.build.as_ref().and_then(|b| b.auth.as_ref()),
            self.artifact.as_ref().and_then(|a| a.auth.as_ref()),
            self.update.as_ref().and_then(|u| u.auth.as_ref()),
            self.auth.as_ref().and_then(|g| g.client_secret.as_ref()),
            self.auth
                .as_ref()
                .and_then(|g| g.jwt.as_ref())
                .and_then(|j| j.secret.as_ref()),
            self.vm
                .as_ref()
                .and_then(|vm| vm.workspace.as_ref())
                .and_then(|w| w.auth.as_ref()),
        ];
        if let Some(vm) = &self.vm {
            refs.extend(vm.mounts.iter().map(|m| m.auth.as_ref()));
        }
        let mut ids: Vec<String> = refs.into_iter().flatten().map(|r| r.secret.clone()).collect();
        if let Some(vm) = &self.vm {
            ids.extend(vm.env_from.iter().map(|e| e.secret.clone()));
        }
        if let Some(u) = &self.update {
            ids.extend(u.env_from.iter().map(|e| e.secret.clone()));
        }
        ids.sort();
        ids.dedup();
        ids
    }

    /// The rules that only apply to a container.
    ///
    /// Every rejection here is a block that means something specific on heyvmd
    /// and nothing on Incus. Refusing them is deliberate over accepting and
    /// ignoring: a spec that silently does not do what it says is worse than one
    /// that will not register, and `open_ports` in particular is a *security*
    /// field — see its arm below.
    fn validate_lxc(&self, vm: &VmSpec) -> Result<(), SpecError> {
        // An OCI reference, and there is no default to fall back to.
        let image = vm.image.as_deref().map(str::trim).unwrap_or_default();
        if image.is_empty() {
            return Err(SpecError::LxcNeedsImage);
        }
        if image.len() > 255
            || image.bytes().any(|b| b.is_ascii_whitespace())
            || !image
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._/:@-".contains(&b))
        {
            return Err(SpecError::LxcBadImage(image.to_string()));
        }

        // The id has to be able to name a container. `vm::owner_of` parses the
        // deployment back out of the instance name, so this cannot be solved by
        // hashing the id into something legal — an operator running `incus list`
        // has to be able to see what a container belongs to.
        let id = self.id.trim();
        if id.len() > MAX_LXC_DEPLOYMENT_ID {
            return Err(SpecError::BadLxcId {
                id: id.to_string(),
                why: "too long",
            });
        }
        if !id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(SpecError::BadLxcId {
                id: id.to_string(),
                why: "contains something other than a lowercase letter, a digit or a dash",
            });
        }
        if id.ends_with('-') {
            return Err(SpecError::BadLxcId {
                id: id.to_string(),
                why: "ends with a dash",
            });
        }
        // The checks above exist to say *which* rule was broken. This one is the
        // authority: it asks Incus's own predicate about the name app-lb would
        // actually create, so the two can never drift apart. A failure here
        // means a rule above is missing rather than that this id is unusual.
        if !crate::incus::is_legal_name(&crate::vm::replica_name(id, 0)) {
            return Err(SpecError::BadLxcId {
                id: id.to_string(),
                why: "cannot form a legal container name",
            });
        }

        // Blocks that describe heyvmd doing something Incus has no equivalent
        // for. Each is refused by name.
        if vm.correlated_creates {
            return Err(SpecError::NotForLxc("vm.correlated_creates"));
        }
        // A container has no rootfs image to share read-only.
        if vm.rootfs != RootfsMode::Copy {
            return Err(SpecError::NotForLxc("vm.rootfs"));
        }
        if vm.workspace_archive.is_some() {
            return Err(SpecError::NotForLxc("vm.workspace_archive"));
        }
        if vm.image_download_url.is_some()
            || vm.image_size_bytes.is_some()
            || vm.image_sha256.is_some()
        {
            return Err(SpecError::NotForLxc("vm.image_download_url"));
        }
        // heyvmd runs these inside the guest before the start command. A
        // container has no such hook point, and running them after start would
        // race the health probe.
        if vm.setup_hooks.as_ref().is_some_and(|h| !h.is_empty()) {
            return Err(SpecError::NotForLxc("vm.setup_hooks"));
        }
        // A *security* field that would silently do nothing. app-lb routes
        // straight to the container's address on the bridge, so every port is
        // reachable whatever this says — and a spec that believes it has closed
        // a port it has not is worse than one that will not register. Accepting
        // it later stays backward-compatible; removing it later would not.
        if !vm.open_ports.is_empty() {
            return Err(SpecError::NotForLxc("vm.open_ports"));
        }
        // `build` and `artifact` both produce an ext4 rootfs, which is not a
        // thing a container boots.
        if self.build.is_some() {
            return Err(SpecError::NotForLxc("build"));
        }
        if self.artifact.is_some() {
            return Err(SpecError::NotForLxc("artifact"));
        }
        // Cloud URLs are daemon-side proxy binds, which belong to heyvmd.
        if self.ingress.is_some() {
            return Err(SpecError::NotForLxc("ingress"));
        }

        // Staged, not refused forever — the message says so.
        if !vm.mounts.is_empty() {
            return Err(SpecError::LxcNotYet("vm.mounts"));
        }
        Ok(())
    }

    /// Whether any route pins a hostname — an exact `host` or a `host_suffix`.
    /// A deployment with none either is reached without one (a path-only route,
    /// or a headless routeless VM) or is a candidate for a synthesized host.
    pub fn has_host_route(&self) -> bool {
        self.routes
            .iter()
            .any(|r| r.host.is_some() || r.host_suffix.is_some())
    }

    pub fn validate(&self) -> Result<(), SpecError> {
        if self.id.trim().is_empty() {
            return Err(SpecError::EmptyId);
        }
        if let Some(gateway) = &self.gateway {
            if self.vm.is_some() || self.discovery.is_some() || self.site.is_some()
                || self.routes.len() != 1 || self.routes[0].host.is_none()
                || self.routes[0].strip_prefix || self.routes[0].host_suffix.is_some() {
                return Err(SpecError::InvalidGateway("gateway transport requires static upstreams and one exact-host route with preserved path".into()));
            }
            gateway.validate(&self.upstreams).map_err(SpecError::InvalidGateway)?;
        }
        if !is_valid_namespace(&self.namespace) {
            return Err(SpecError::BadNamespace(self.namespace.clone()));
        }
        if let Some(feed) = &self.feed {
            feed.validate(&self.routes)?;
        }
        if self.routes.iter().any(RouteRule::is_empty) {
            return Err(SpecError::EmptyRoute);
        }
        if self
            .routes
            .iter()
            .any(|route| route.strip_prefix && route.path_prefix.is_none())
        {
            return Err(SpecError::StripPrefixWithoutPath);
        }
        // A cloud URL is a bind on a VM's port. A static deployment's
        // upstreams and a site's files are not on any daemon to bind.
        if IngressSpec::wants_cloud(self.ingress.as_ref()) && self.vm.is_none() {
            return Err(SpecError::IngressWithoutVm);
        }
        // No routes means no ingress. For a *managed* deployment that is a
        // legitimate shape — an agent sandbox reached only through `exec` and
        // `shell`, never over HTTP — and it is the common one at fleet scale,
        // where exposure is the exception. Neither other kind has such a door:
        // a static deployment's backend is a fixed upstream list and a site is
        // files on disk, and for both the proxy is the only way in, so an
        // unrouted one is simply dead weight.
        if self.routes.is_empty() {
            if self.vm.is_none() {
                return Err(SpecError::NoRoutes);
            }
            // Nothing arrives over HTTP, so there is no request for a sign-in
            // gate to intercept and no browser to redirect. Rejected here
            // because `AuthGate::validate` would otherwise fail this on
            // callback routability, reporting a path the author never wrote.
            if self.auth.is_some() {
                return Err(SpecError::AuthWithoutRoutes);
            }
        }

        // Checked for either backend kind: the gate runs in the proxy, ahead of
        // whichever backend the deployment has.
        if let Some(auth) = &self.auth {
            auth.validate(&self.routes)?;
        }

        // Exactly one backend kind.
        if let Some(site) = &self.site {
            if self.vm.is_some() || !self.upstreams.is_empty() || self.discovery.is_some() {
                return Err(SpecError::SiteWithOtherBackend);
            }
            site.validate()?;
            // A site's `build` is a git checkout copied into `site.root`: no
            // Dockerfile, no image, nothing run. So only the git half of the
            // block means anything, and the image half is refused rather than
            // silently ignored.
            if let Some(build) = &self.build {
                if build.store.is_some() {
                    return Err(SpecError::NotForSites("build.store"));
                }
                for (field, set) in [
                    ("build.dockerfile", build.dockerfile.is_some()),
                    ("build.image_name", build.image_name.is_some()),
                    ("build.image_size_mb", build.image_size_mb.is_some()),
                ] {
                    if set {
                        return Err(SpecError::NotForSites(field));
                    }
                }
                build.validate()?;
            }
            // The three ways a site's files get replaced: `update` runs
            // `git pull && npm run build` in a directory on this host,
            // `artifact` unpacks a bundle somebody else built, and `build`
            // copies a git checkout in. At most one — see
            // [`SpecError::BothSiteSources`].
            let sources = [self.update.is_some(), self.artifact.is_some(), self.build.is_some()];
            if sources.iter().filter(|s| **s).count() > 1 {
                return Err(SpecError::BothSiteSources);
            }
            if let Some(update) = &self.update {
                update.validate()?;
            }
            if let Some(artifact) = &self.artifact {
                artifact.validate(true)?;
            }
            return Ok(());
        }

        if let Some(discovery) = &self.discovery {
            if discovery.service_id.trim().is_empty() {
                return Err(SpecError::EmptyDiscoveryServiceId);
            }
            if discovery.region.as_ref().is_some_and(|r| r.is_empty() || r.len() > 128
                || !r.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))) {
                return Err(SpecError::InvalidDiscoverySource("region must be a bounded identifier".into()));
            }
            if let Some(source) = &discovery.source {
                crate::discovery::validate_source_url(&source.url).map_err(SpecError::InvalidDiscoverySource)?;
                source.auth.validate().map_err(|e| SpecError::InvalidDiscoverySource(e.to_string()))?;
            }
            if let Some(regional) = &discovery.regional {
                if discovery.region.is_none() || discovery.source.is_none() || self.gateway.is_some()
                    || self.routes.len() != 1 || self.routes[0].host.is_none()
                    || self.routes[0].strip_prefix || self.routes[0].host_suffix.is_some() {
                    return Err(SpecError::InvalidDiscoverySource("regional routing requires region, explicit authority and one exact-host route with preserved path".into()));
                }
                for value in [&regional.gateway_id, &regional.backend_server_id, &regional.environment, &discovery.service_id] {
                    if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
                        return Err(SpecError::InvalidDiscoverySource("regional identity must be a bounded identifier".into()));
                    }
                }
                regional.auth.validate().map_err(|e| SpecError::InvalidDiscoverySource(e.to_string()))?;
            }
            if self.vm.is_some() || self.site.is_some() {
                return Err(SpecError::DiscoveryWithOtherBackend);
            }
        }

        match (&self.vm, self.upstreams.is_empty() && self.discovery.is_none()) {
            (Some(_), false) => return Err(SpecError::BothBackendKinds),
            (None, true) => return Err(SpecError::NoBackendKind),
            _ => {}
        }

        if let Some(vm) = &self.vm {
            // Managed: validate the VM template and scaling policy.
            match vm.driver {
                Driver::Firecracker | Driver::Kvm => {}
                Driver::Lxc => self.validate_lxc(vm)?,
                d @ (Driver::Libvirt | Driver::FirecrackerContainerd) => {
                    return Err(SpecError::UnsupportedDriver(d));
                }
            }
            if vm.port == 0 {
                return Err(SpecError::ZeroPort);
            }
            // After the driver check, because one mount rule depends on which
            // driver this is.
            validate_mounts(&vm.mounts, vm.driver)?;
            // Before the workspace's own checks, so two claims on `/workspace`
            // are reported as that rather than as whichever rule the
            // persistent workspace happens to trip first.
            if let Some(archive) = &vm.workspace_archive {
                if vm.workspace.is_some() {
                    return Err(SpecError::ArchiveWithWorkspace);
                }
                archive.validate()?;
            }
            if let Some(workspace) = &vm.workspace {
                workspace.validate(vm.driver, &self.scaling, &vm.mounts)?;
            }
            for from in &vm.env_from {
                from.validate("vm.env_from")?;
            }
            if self.scaling.min_replicas > self.scaling.max_replicas {
                return Err(SpecError::BadReplicaRange {
                    min: self.scaling.min_replicas,
                    max: self.scaling.max_replicas,
                });
            }
            if self.scaling.target_concurrency == 0 {
                return Err(SpecError::ZeroTargetConcurrency);
            }
            // `build` and `artifact` are the two ways `vm.image` gets rewritten,
            // and each has its own explicit trigger. Two of them on one
            // deployment would make the running image depend on which job ran
            // last, which is not something the spec says anywhere.
            if self.build.is_some() && self.artifact.is_some() {
                return Err(SpecError::BothImageSources);
            }
            if let Some(build) = &self.build {
                build.validate()?;
            }
            if let Some(artifact) = &self.artifact {
                artifact.validate(false)?;
            }
            // An `update` runs commands in a directory on this host; a managed
            // deployment's backend is a microVM, so there is nothing here for
            // those commands to act on.
            if self.update.is_some() {
                return Err(SpecError::UpdateOnManagedDeployment);
            }
        } else {
            // A `build` produces a guest image, and a static deployment has no
            // guest. Rejecting it here beats accepting a spec whose build block
            // could never run.
            if self.build.is_some() {
                return Err(SpecError::BuildOnStaticDeployment);
            }
            // Same reasoning for a pull: there is no `vm.image` to point at the
            // rootfs it would materialize.
            if self.artifact.is_some() {
                return Err(SpecError::ArtifactOnStaticDeployment);
            }
            if let Some(update) = &self.update {
                update.validate()?;
            }
            // Static: every upstream must be a well-formed plaintext `host:port`
            // or HTTPS URL. Actual
            // name resolution happens at request time (pingora) and per tick (the
            // health re-probe), so a temporarily-unresolvable name is not a
            // registration error — only a malformed address is.
            for addr in &self.upstreams {
                if StaticUpstream::parse(addr).is_none() {
                    return Err(SpecError::BadUpstream(addr.clone()));
                }
            }
        }
        Ok(())
    }
}

/// Whether `s` is a syntactically valid `host:port` (or `ip:port`) upstream: a
/// non-empty host and a numeric port in `1..=65535`. Splits on the last colon so
/// IPv6 literals like `[::1]:8080` are handled; the host is not otherwise
/// resolved here.
fn is_valid_host_port(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    // Strip brackets from an IPv6 literal for the emptiness check.
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if host.is_empty() {
        return false;
    }
    matches!(port.parse::<u16>(), Ok(p) if p > 0)
}

/// The connection details encoded by a static upstream string. Bare addresses
/// retain their historical plaintext meaning; an `https://` URL opts into TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaticUpstream {
    pub address: String,
    pub tls: bool,
    pub sni: String,
}

impl StaticUpstream {
    pub fn parse(value: &str) -> Option<Self> {
        if !value.contains("://") {
            return is_valid_host_port(value).then(|| Self {
                address: value.to_string(),
                tls: false,
                sni: String::new(),
            });
        }

        // URL parsing normalizes dot segments and backslashes. Refuse them
        // before parsing rather than silently accepting a non-origin input.
        let (_, authority) = value.split_once("://")?;
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        if authority.contains(['/', '\\', '?', '#', '@'])
            || value.chars().any(char::is_whitespace)
        {
            return None;
        }
        let parsed = url::Url::parse(value).ok()?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return None;
        }
        let port = parsed.port_or_known_default()?;
        if port == 0 { return None; }
        // Pingora verifies DNS names with X509_VERIFY_PARAM_add1_host, not
        // the IP-SAN verifier. Do not promise IP-literal certificate support.
        let url::Host::Domain(host) = parsed.host()? else { return None; };
        Some(Self { address: format!("{host}:{port}"), tls: true, sni: host.to_string() })
    }
}

// ---- namespace objects --------------------------------------------------

/// A declared namespace.
///
/// Namespaces began as a *field*: a deployment named one and that was the whole
/// of their existence, so a namespace appeared when the first deployment in it
/// was registered and vanished with the last. That is still true of any name a
/// deployment mentions — an undeclared namespace is not an error — but it made
/// two ordinary things impossible: creating a room before putting anything in
/// it, and saying what a room is *for*.
///
/// So this object is additive, not a replacement. Declaring `sam` and having a
/// deployment in `sam` are independent facts, and `GET /namespaces` reports the
/// union with `declared` saying which is which. Nothing about deployment
/// validation changed: naming an undeclared namespace still works, because
/// requiring declaration first would break every spec already written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceSpec {
    /// The namespace's name, and its identity: there is nothing else to key on.
    pub name: String,
    /// Free text for whoever finds it later. A namespace with no description is
    /// a room with no label on the door, which is fine until there are twenty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Stamped by app-lb when the object is created, never read from the body —
    /// a client-supplied creation time is a client-supplied lie.
    #[serde(default)]
    pub created_at: u64,
}

impl NamespaceSpec {
    pub fn validate(&self) -> Result<(), SpecError> {
        if !is_valid_namespace(&self.name) {
            return Err(SpecError::BadNamespace(self.name.clone()));
        }
        // `default` is where every deployment that never named a namespace
        // lives. It exists whether or not anything declares it, so declaring it
        // would create an object whose deletion could not mean anything.
        if self.name == DEFAULT_NAMESPACE {
            return Err(SpecError::ReservedNamespace);
        }
        if self.description.as_ref().is_some_and(|d| d.len() > 400) {
            return Err(SpecError::DescriptionTooLong);
        }
        Ok(())
    }
}

// ---- auth provider objects ----------------------------------------------

/// A named, reusable auth *identity* declared on a namespace, inherited by the
/// deployments in it.
///
/// A gate has always been two things wearing one name: the *identity* half — who
/// may enter and how they are verified (`provider`, the OAuth credentials and
/// allow-lists, the `jwt` policy) — and the *route-scoped* half — where the
/// callback lives, which paths skip the gate, what token a session mints. The
/// first is an organisation's fact and rarely differs between two services; the
/// second is each deployment's own. Written inline they were copied together, so
/// rotating a client secret or tightening a domain meant editing every spec, out
/// of step until the last one was done.
///
/// This object is the identity half on its own, given a name and an owning
/// namespace. A deployment inherits it with `auth.provider_ref`, keeping only
/// its route-scoped fields. Resolution is live — app-lb reads the provider on
/// every gated request — so an edit here reaches every deployment that names it
/// at once, and (because it changes the resolved gate's
/// [`policy_fingerprint`](AuthGate::policy_fingerprint)) re-signs the sessions
/// issued under the old policy rather than leaving a removed user signed in.
///
/// The fields are exactly [`AuthGate`]'s identity subset, validated by the same
/// [`validate_identity`] both call.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AuthProviderSpec {
    /// The provider's name, unique within its namespace. Appears in a filename
    /// and in every deployment that references it, so it takes the namespace
    /// alphabet.
    pub name: String,
    /// The namespace that owns it. A deployment may reference only a provider in
    /// its own namespace. Absent means `"default"`.
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Free text for whoever finds it later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Stamped by app-lb when the object is created, never read from the body.
    #[serde(default)]
    pub created_at: u64,
    /// Which credentials get past a gate inheriting this provider. See
    /// [`AuthGate::provider`].
    #[serde(default)]
    pub provider: Providers,
    /// OAuth client id, for the `google` provider. See [`AuthGate::client_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Where the OAuth client secret is stored. See [`AuthGate::client_secret`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<SecretRef>,
    /// Google Workspace domains admitted. See [`AuthGate::allowed_domains`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_domains: Vec<String>,
    /// Individual addresses admitted. See [`AuthGate::allowed_emails`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_emails: Vec<String>,
    /// How to verify a JWT, for the `jwt` provider. See [`JwtSpec`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<JwtSpec>,
    /// The session-cookie realm shared across the deployments that inherit this
    /// provider — the natural place for it, since one provider is one sign-in
    /// realm. See [`AuthGate::cookie_domain`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_domain: Option<String>,
}

impl AuthProviderSpec {
    pub fn validate(&self) -> Result<(), SpecError> {
        if !is_valid_namespace(&self.name) {
            return Err(SpecError::BadAuthProviderName(self.name.clone()));
        }
        if !is_valid_namespace(&self.namespace) {
            return Err(SpecError::BadNamespace(self.namespace.clone()));
        }
        if self.description.as_ref().is_some_and(|d| d.len() > 400) {
            return Err(SpecError::DescriptionTooLong);
        }
        if let Some(d) = &self.cookie_domain
            && normalize_cookie_domain(d).is_none()
        {
            return Err(SpecError::BadCookieDomain(d.clone()));
        }
        check_signin_realm(&self.jwt, &self.cookie_domain)?;
        validate_identity(
            &self.provider,
            &self.client_id,
            &self.client_secret,
            &self.allowed_domains,
            &self.allowed_emails,
            &self.jwt,
        )
    }

    /// Bind every secret reference this provider holds to its own namespace.
    ///
    /// The counterpart of [`DeploymentSpec::normalize`], run on every path an
    /// object enters by (create, and the state directory on load), and for the
    /// same reason: a reference that names no namespace resolves in `default`
    /// ([`crate::secrets::SecretStore::resolve`]), so without this the obvious
    /// body — the secret id and key, nothing else — either failed to find a
    /// secret that plainly exists or, in a fleet that keeps one in `default`
    /// under the same id, verified against another namespace's key. Whatever
    /// the client wrote is overwritten, which is the point: naming another
    /// namespace's secret is not an error to report, it is a thing a provider
    /// cannot express.
    pub fn normalize(&mut self) {
        let ns = self.namespace.clone();
        if let Some(r) = self.client_secret.as_mut() {
            r.scope_to(&ns);
        }
        if let Some(jwt) = self.jwt.as_mut()
            && let Some(r) = jwt.secret.as_mut()
        {
            r.scope_to(&ns);
        }
    }

    /// The effective gate when `gate` inherits this provider: the identity comes
    /// from here, everything route-scoped stays on `gate`, and `provider_ref` is
    /// cleared so the result is a plain, self-contained [`AuthGate`] — the same
    /// shape it would have been written inline, which is what lets the resolved
    /// gate go through the unchanged `Authenticator` and `policy_fingerprint`.
    pub fn resolve(&self, gate: &AuthGate) -> AuthGate {
        AuthGate {
            provider: self.provider.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            allowed_domains: self.allowed_domains.clone(),
            allowed_emails: self.allowed_emails.clone(),
            jwt: self.jwt.clone(),
            cookie_domain: self.cookie_domain.clone(),
            provider_ref: None,
            // Route-scoped, this deployment's own — kept verbatim.
            public_paths: gate.public_paths.clone(),
            session_scope: gate.session_scope,
            base_path: gate.base_path.clone(),
            session_ttl_secs: gate.session_ttl_secs,
            cookie_name: gate.cookie_name.clone(),
            redirect_url: gate.redirect_url.clone(),
            forward_identity: gate.forward_identity,
        }
    }
}

// ---- workflow objects ---------------------------------------------------

/// A CI workflow: which repository to build, and on which heyvm network.
///
/// app-lb stores and serves these; it never runs them. The `ci` orchestrator
/// polls `GET /workflows` and does the work. Keeping the object here rather than
/// in `ci` means one place holds "what this fleet knows about" — the same
/// argument that puts deployments and secrets here.
///
/// The object names a repository and a path *glob*, not a workflow body. A
/// workflow lives in the repository it builds, versioned with the code, so the
/// object is a pointer rather than a copy that can drift.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkflowSpec {
    pub id: String,
    /// Clone URL. Only ever compared and displayed by app-lb; the orchestrator
    /// never clones it either — a submit carries its own source.
    pub repo: String,
    /// Branch or ref this workflow is for. `ref` is a Rust keyword.
    #[serde(rename = "ref", default = "default_workflow_ref")]
    pub git_ref: String,
    /// Where workflow files live inside the repository.
    #[serde(default = "default_workflow_path")]
    pub path: String,
    /// The heyvm network whose hosts may run it.
    pub network: String,
    /// Credential for the repository, if the orchestrator is ever made to fetch
    /// one. A reference, never a value — the admin API echoes specs back and the
    /// state file holds them in the clear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<SecretRef>,
    /// heyosecret prefix override. Defaults to `ci/<id>` in the orchestrator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets_prefix: Option<String>,
    /// Disabled workflows stay listed but are not run, so turning one off does
    /// not lose its configuration.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_workflow_ref() -> String {
    "main".to_string()
}

fn default_workflow_path() -> String {
    ".ci/workflows/*.yml".to_string()
}

impl WorkflowSpec {
    pub fn validate(&self) -> Result<(), SpecError> {
        // The id reaches a NATS subject token, a durable consumer name and a VM
        // name in the orchestrator, all unescaped. Restricting the alphabet is
        // cheaper than escaping it in four places.
        if self.id.is_empty() {
            return Err(SpecError::EmptyId);
        }
        if !self
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(SpecError::BadWorkflowId(self.id.clone()));
        }
        if self.repo.trim().is_empty() {
            return Err(SpecError::EmptyWorkflowRepo);
        }
        if self.git_ref.trim().is_empty() {
            return Err(SpecError::EmptyWorkflowRef);
        }
        if self.network.trim().is_empty() {
            return Err(SpecError::EmptyWorkflowNetwork);
        }
        // The path is joined onto an extracted tree, so it must not escape it.
        let path = self.path.trim();
        if path.is_empty() || path.starts_with('/') || path.split('/').any(|s| s == "..") {
            return Err(SpecError::BadWorkflowPath(self.path.clone()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The base domain a hostless deployment is routed under: an explicit
    /// setting wins, else the first wildcard (which already has a cert and DNS),
    /// else nothing — and blank strings count as nothing on either side.
    #[test]
    fn deploy_host_base_prefers_explicit_then_the_first_wildcard() {
        let mut cfg = LbConfig::default();
        assert_eq!(cfg.deploy_host_base(), None);

        cfg.acme_wildcards = vec!["sb.example.com".into(), "other.example.com".into()];
        assert_eq!(cfg.deploy_host_base(), Some("sb.example.com"));

        cfg.deploy_base_domain = Some("apps.example.com".into());
        assert_eq!(cfg.deploy_host_base(), Some("apps.example.com"));

        // A blank explicit value falls back rather than producing ".<id>".
        cfg.deploy_base_domain = Some("  ".into());
        assert_eq!(cfg.deploy_host_base(), Some("sb.example.com"));
    }

    /// A declared namespace is an object with a name and very little else, so
    /// validation is where all of its rules live.
    mod namespace_objects {
        use super::*;

        fn ns(name: &str) -> NamespaceSpec {
            NamespaceSpec { name: name.into(), description: None, created_at: 0 }
        }

        #[test]
        fn a_name_must_survive_a_url_and_a_filename() {
            // The same alphabet a deployment's `namespace` field takes, because
            // they are the same namespace — one declared, one merely named.
            assert!(ns("sam").validate().is_ok());
            assert!(ns("team-a").validate().is_ok());
            assert!(ns("v1.2_x").validate().is_ok());
            // `.` and `..` are legal under the alphabet and meaningless as
            // directories, which is the one place a namespace lands unescaped.
            // A dot elsewhere is fine — `v1.2` above — so they are excluded by
            // name, not by banning the character.
            for bad in ["", "has spaces", "slash/es", "unicodé", ".", "..", "../etc"] {
                assert!(
                    matches!(ns(bad).validate(), Err(SpecError::BadNamespace(_))),
                    "{bad:?} should be refused",
                );
            }
        }

        #[test]
        fn default_cannot_be_declared() {
            // It is where every deployment that names no namespace already
            // lives, so an object for it could never be deleted meaningfully —
            // the namespace would carry on existing regardless.
            assert!(matches!(
                ns(DEFAULT_NAMESPACE).validate(),
                Err(SpecError::ReservedNamespace)
            ));
            let msg = SpecError::ReservedNamespace.to_string();
            assert!(msg.contains("default"), "{msg}");
        }

        #[test]
        fn a_description_is_a_label_not_a_document() {
            let ok = NamespaceSpec { description: Some("x".repeat(400)), ..ns("sam") };
            assert!(ok.validate().is_ok());
            let too_long = NamespaceSpec { description: Some("x".repeat(401)), ..ns("sam") };
            assert!(matches!(
                too_long.validate(),
                Err(SpecError::DescriptionTooLong)
            ));
        }

        #[test]
        fn declaring_one_changes_nothing_about_naming_one() {
            // The compatibility promise: a deployment may still name a namespace
            // no object exists for. Requiring declaration first would invalidate
            // every spec written before this existed.
            let mut d = static_spec(&["10.0.0.9:8080"]);
            d.namespace = "never-declared".into();
            assert!(d.validate().is_ok());
        }
    }

    /// `ingress.cloud` is a bind on a VM port, so only a managed deployment
    /// may ask for it; it is off the wire unless set, and public by default.
    mod cloud_ingress {
        use super::*;

        #[test]
        fn a_cloud_url_needs_a_vm_pool() {
            let mut s = static_spec(&["10.0.0.9:8080"]);
            s.ingress = Some(IngressSpec { cloud: true, public: true });
            assert!(matches!(s.validate(), Err(SpecError::IngressWithoutVm)));

            let mut s = spec();
            s.ingress = Some(IngressSpec { cloud: true, public: false });
            assert!(s.validate().is_ok());

            // `cloud: false` asks for nothing, so it is harmless anywhere.
            let mut s = static_spec(&["10.0.0.9:8080"]);
            s.ingress = Some(IngressSpec { cloud: false, public: true });
            assert!(s.validate().is_ok());
        }

        #[test]
        fn absent_from_the_wire_unless_set_and_public_by_default() {
            let v = serde_json::to_value(spec()).unwrap();
            assert!(v.get("ingress").is_none());

            let parsed: DeploymentSpec = serde_json::from_value(serde_json::json!({
                "id": "web", "routes": [],
                "vm": {"driver": "firecracker", "port": 8080},
                "ingress": {"cloud": true}
            }))
            .unwrap();
            assert_eq!(parsed.ingress, Some(IngressSpec { cloud: true, public: true }));
            assert!(IngressSpec::wants_cloud(parsed.ingress.as_ref()));
            assert!(!IngressSpec::wants_cloud(None));
            assert!(!IngressSpec::wants_cloud(Some(&IngressSpec { cloud: false, public: true })));

            let back = serde_json::to_value(&parsed).unwrap();
            assert_eq!(back["ingress"], serde_json::json!({"cloud": true, "public": true}));
        }
    }

    #[test]
    fn normalize_binds_every_secret_reference_to_the_spec_namespace() {
        let mut spec: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id": "web",
            "namespace": "team-a",
            "routes": [{"host": "web.example.com"}],
            "vm": {
                "driver": "firecracker", "port": 8080,
                "env_from": [{"secret": "db", "key": "url", "as": "DATABASE_URL", "namespace": "team-b"}],
                "mounts": [{"path": "/data", "store": "/srv/art", "ref": "corpus",
                             "auth": {"secret": "art-key", "namespace": "elsewhere"}}]
            },
            "build": {"repo": "https://github.com/acme/web", "auth": {"secret": "github"}},
            "auth": {"provider": "google", "client_id": "cid", "allowed_emails": ["a@example.com"],
                     "client_secret": {"secret": "google", "key": "client_secret"}}
        }))
        .unwrap();
        spec.normalize();
        let vm = spec.vm.as_ref().unwrap();
        assert_eq!(vm.env_from[0].namespace.as_deref(), Some("team-a"));
        assert_eq!(vm.env_from[0].secret_ref().namespace(), "team-a");
        assert_eq!(vm.mounts[0].auth.as_ref().unwrap().namespace(), "team-a");
        assert_eq!(spec.build.as_ref().unwrap().auth.as_ref().unwrap().namespace(), "team-a");
        assert_eq!(
            spec.auth.as_ref().unwrap().client_secret.as_ref().unwrap().namespace(),
            "team-a"
        );
        let mut ids = spec.secret_ids();
        ids.sort();
        assert_eq!(ids, vec!["art-key", "db", "github", "google"]);
        assert!(spec.validate().is_ok(), "{:?}", spec.validate());
    }

    #[test]
    fn the_hub_example_is_a_valid_ungated_global_store_cache() {
        let mut spec: DeploymentSpec =
            serde_json::from_str(include_str!("../examples/artifacts-hub.json")).unwrap();
        spec.normalize();
        spec.validate().unwrap();
        // art gates itself: anonymous pulls of public repositories are the point,
        // so an app-lb auth gate in front would break the hub.
        assert!(spec.auth.is_none());
        let vm = spec.vm.as_ref().unwrap();
        for env in ["ART_API_KEY", "ART_S3_ACCESS_KEY_ID", "ART_S3_SECRET_ACCESS_KEY"] {
            assert!(vm.env_from.iter().any(|s| s.env.as_deref() == Some(env)), "{env}");
            assert!(!vm.env_vars.as_ref().is_some_and(|v| v.contains_key(env)), "{env} must come from a secret");
        }
    }

    #[test]
    fn the_git_remote_spec_is_a_valid_ungated_vm_with_secret_credentials() {
        let mut spec: DeploymentSpec =
            serde_json::from_str(include_str!("../../remote/deploy/remote.json")).unwrap();
        spec.normalize();
        spec.validate().unwrap();
        // git sends one credential, to the remote itself; a gate in front would
        // demand a second one that git cannot send.
        assert!(spec.auth.is_none());
        let vm = spec.vm.as_ref().unwrap();
        // The cache is disposable (the bucket is the authority), so no workspace
        // capture: a replaced VM re-hydrates from S3.
        assert!(vm.workspace.is_none());
        for env in ["REMOTE_S3_ACCESS_KEY_ID", "REMOTE_S3_SECRET_ACCESS_KEY", "REMOTE_ADMIN_TOKEN"] {
            assert!(vm.env_from.iter().any(|s| s.env.as_deref() == Some(env)), "{env}");
            assert!(!vm.env_vars.as_ref().is_some_and(|v| v.contains_key(env)), "{env} must come from a secret");
        }
        // A VM cannot reach the host's loopback admin listener.
        let applb = &vm.env_vars.as_ref().unwrap()["REMOTE_APPLB_URL"];
        assert!(!applb.contains("127.0.0.1"), "{applb}");
    }

    #[test]
    fn managed_nats_template_preserves_single_writer_storage_and_private_access() {
        let mut spec: DeploymentSpec = serde_json::from_str(include_str!("../examples/nats/managed.json")).unwrap();
        spec.normalize();
        spec.validate().unwrap();
        let vm = spec.vm.as_ref().unwrap();
        assert_eq!(vm.driver, Driver::Firecracker);
        assert_eq!(vm.workspace.as_ref().unwrap().guest_path(), "/workspace");
        assert_eq!(vm.ttl_seconds, 0);
        assert!(vm.env_from.iter().any(|secret| secret.env.as_deref() == Some("NATS_TOKEN")));
        assert!(spec.routes.is_empty());
        assert_eq!(spec.scaling.min_replicas, 0);
        assert_eq!(spec.scaling.max_replicas, 1);
        assert_eq!(spec.scaling.warm_pool, 0);
        assert_eq!(spec.scaling.idle_action, IdleAction::Retain);
        spec.scaling.min_replicas = 1;
        spec.validate().unwrap();
        spec.scaling.max_replicas = 2;
        assert!(spec.validate().is_err());
    }

    #[test]
    fn a_workspace_archive_needs_its_key_and_excludes_a_persistent_workspace() {
        let mut spec: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id": "web", "routes": [],
            "vm": {"driver": "firecracker", "port": 8080,
                   "workspace_archive": {"archive_id": "ar-12345678"}}
        }))
        .unwrap();
        assert!(matches!(
            spec.validate(),
            Err(SpecError::UnresolvedWorkspaceArchive(id)) if id == "ar-12345678"
        ));
        let vm = spec.vm.as_mut().unwrap();
        vm.workspace_archive.as_mut().unwrap().s3_key = Some("users/u1/archives/ar-12345678.tar.gz".into());
        assert!(spec.validate().is_ok());
        let vm = spec.vm.as_mut().unwrap();
        vm.workspace = Some(WorkspaceSpec {
            path: None,
            store: "s3://bucket/prefix".into(),
            artifact_ref: None,
            auth: None,
            snapshot_interval_secs: None,
        });
        assert!(matches!(spec.validate(), Err(SpecError::ArchiveWithWorkspace)), "{:?}", spec.validate());
    }

    #[test]
    fn vm_env_from_is_validated_like_update_env_from() {
        let spec: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id": "web", "routes": [],
            "vm": {"driver": "firecracker", "port": 8080,
                   "env_from": [{"secret": "db", "key": "url", "as": "1BAD"}]}
        }))
        .unwrap();
        assert!(matches!(spec.validate(), Err(SpecError::BadEnvName(n)) if n == "1BAD"));
    }


    /// A deployment with the given mounts, otherwise the minimal valid one.
    fn spec_with_mounts(mounts: Vec<MountSpec>) -> DeploymentSpec {
        let mut s = spec();
        s.vm.as_mut().unwrap().mounts = mounts;
        s
    }

    fn a_mount(path: &str) -> MountSpec {
        MountSpec {
            path: path.into(),
            store: "/srv/artifacts".into(),
            artifact_ref: "corpus".into(),
            auth: None,
            strip_components: None,
            read_only: true,
            digest: None,
        }
    }

    fn spec() -> DeploymentSpec {
        DeploymentSpec {
            ingress: None,
            account_id: None,
            user_id: None,
            namespace: "default".into(),
            feed: None,
            id: "demo".into(),
            routes: vec![RouteRule {
                host: Some("demo.local".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
            }],
            vm: Some(VmSpec {
                correlated_creates: false,
                env_from: vec![],
                workspace_archive: None,
                image_download_url: None,
                image_size_bytes: None,
                image_sha256: None,
                driver: Driver::Firecracker,
                image: None,
                rootfs: Default::default(),
                port: 8080,
                start_command: None,
                size_class: None,
                disk_size_gb: None,
                working_directory: None,
                env_vars: None,
                setup_hooks: None,
                open_ports: vec![],
                mounts: vec![],
                workspace: None,
                ttl_seconds: 3600,
            }),
            scaling: ScalingPolicy::default(),
            maintenance: false,
            health: HealthCheck::default(),
            upstreams: vec![],
            discovery: None,
            gateway: None,
            build: None,
            artifact: None,
            site: None,
            update: None,
            auth: None,
        }
    }

    fn build_spec() -> BuildSpec {
        BuildSpec {
            repo: Some("https://github.com/acme/web.git".into()),
            store: None,
            source_ref: Some("main".into()),
            dockerfile: None,
            context: None,
            image_name: None,
            image_size_mb: None,
            auth: None,
        }
    }

    /// The other source: a Dockerfile manifest in an artifact store.
    fn store_build_spec() -> BuildSpec {
        BuildSpec {
            repo: None,
            store: Some("http://art.internal:8080".into()),
            source_ref: Some("web-rootfs".into()),
            dockerfile: None,
            context: None,
            image_name: None,
            image_size_mb: None,
            auth: None,
        }
    }

    /// A static (proxy_pass) deployment: `upstreams` set, no `vm`.
    fn static_spec(upstreams: &[&str]) -> DeploymentSpec {
        DeploymentSpec {
            ingress: None,
            account_id: None,
            user_id: None,
            namespace: "default".into(),
            feed: None,
            id: "proxy".into(),
            routes: vec![RouteRule {
                host: None,
                host_suffix: None,
                path_prefix: Some("/legacy".into()),
                strip_prefix: false,
            }],
            vm: None,
            scaling: ScalingPolicy::default(),
            maintenance: false,
            health: HealthCheck::default(),
            upstreams: upstreams.iter().map(|s| s.to_string()).collect(),
            discovery: None,
            gateway: None,
            build: None,
            artifact: None,
            site: None,
            update: None,
            auth: None,
        }
    }

    #[test]
    fn accepts_a_git_and_dockerfile_build_source() {
        let mut s = spec();
        s.build = Some(build_spec());
        assert_eq!(s.validate(), Ok(()));

        // scp-like and local remotes are accepted too.
        for repo in [
            "git@github.com:acme/web.git",
            "ssh://git@github.com/acme/web.git",
            "/srv/src/web",
        ] {
            let mut s = spec();
            s.build = Some(BuildSpec {
                repo: Some(repo.into()),
                ..build_spec()
            });
            assert_eq!(s.validate(), Ok(()), "{repo} should be accepted");
        }
    }

    #[test]
    fn rejects_remotes_and_refs_that_git_would_read_as_flags_or_commands() {
        for repo in [
            "--upload-pack=/bin/sh",
            "ext::sh -c whoami",
            "https://",
            "https://host/a b",
            "",
        ] {
            let mut s = spec();
            s.build = Some(BuildSpec {
                repo: Some(repo.into()),
                ..build_spec()
            });
            assert!(s.validate().is_err(), "{repo:?} should be rejected");
        }

        for git_ref in ["--upload-pack=x", "a b", "a..b", "/refs/heads/main", "v1^"] {
            let mut s = spec();
            s.build = Some(BuildSpec {
                source_ref: Some(git_ref.into()),
                ..build_spec()
            });
            assert_eq!(
                s.validate(),
                Err(SpecError::BadBuildRef(git_ref.to_string())),
                "{git_ref:?} should be rejected",
            );
        }
    }

    #[test]
    fn build_paths_cannot_escape_the_checkout() {
        for path in ["../../etc/passwd", "/etc/passwd", "a/../../b", "-f"] {
            let mut s = spec();
            s.build = Some(BuildSpec {
                dockerfile: Some(path.into()),
                ..build_spec()
            });
            assert_eq!(
                s.validate(),
                Err(SpecError::BadBuildPath(path.to_string())),
                "{path:?} should be rejected",
            );
        }
        // Ordinary in-tree paths are fine.
        let mut s = spec();
        s.build = Some(BuildSpec {
            dockerfile: Some("deploy/Dockerfile".into()),
            context: Some("./".into()),
            ..build_spec()
        });
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn accepts_a_dockerfile_manifest_build_source() {
        let mut s = spec();
        s.build = Some(store_build_spec());
        assert_eq!(s.validate(), Ok(()));

        // Both spellings of a store, and a digest as well as a tag.
        for store in ["https://art.example.com", "/srv/artifacts"] {
            let mut s = spec();
            s.build = Some(BuildSpec {
                store: Some(store.into()),
                source_ref: Some("a".repeat(64)),
                ..store_build_spec()
            });
            assert_eq!(s.validate(), Ok(()), "{store} should be accepted");
        }
    }

    #[test]
    fn a_build_needs_exactly_one_source() {
        // Both: two recipes, and no answer to which produced the image.
        let mut s = spec();
        s.build = Some(BuildSpec {
            store: Some("http://art:8080".into()),
            ..build_spec()
        });
        assert_eq!(s.validate(), Err(SpecError::BothBuildSources));

        // Neither: nothing to build.
        let mut s = spec();
        s.build = Some(BuildSpec {
            repo: None,
            ..build_spec()
        });
        assert_eq!(s.validate(), Err(SpecError::NoBuildSource));
    }

    #[test]
    fn a_store_build_requires_a_ref_and_a_reachable_store() {
        // A git remote has a default branch to fall back to. A store does not,
        // and guessing one would pick somebody's image out of a shared namespace.
        let mut s = spec();
        s.build = Some(BuildSpec {
            source_ref: None,
            ..store_build_spec()
        });
        assert_eq!(s.validate(), Err(SpecError::MissingBuildRef));

        // Same store rule as `artifact.store`, because it is the same function:
        // a relative path names a different store depending on how the LB was
        // started.
        for store in ["srv/artifacts", "ftp://art", "/srv/../etc", ""] {
            let mut s = spec();
            s.build = Some(BuildSpec {
                store: Some(store.into()),
                ..store_build_spec()
            });
            assert!(s.validate().is_err(), "{store:?} should be rejected");
        }
    }

    #[test]
    fn a_git_ref_is_not_accepted_on_a_store_build() {
        // The two sources share the `ref` field and read it by different rules.
        // A branch name with a slash is a perfectly good git ref and not a tag,
        // so which rule applies has to follow from which source is set.
        // `Release/2.1` is still no tag: repositories are lowercase. (A
        // lowercase `release/2.1` now reads as the repository
        // `release/2.1:latest`, which the store would resolve.)
        for r in ["Release/2.1", "a b", "-flag"] {
            let mut s = spec();
            s.build = Some(BuildSpec {
                source_ref: Some(r.into()),
                ..store_build_spec()
            });
            assert_eq!(
                s.validate(),
                Err(SpecError::BadBuildArtifactRef(r.to_string())),
                "{r:?} should be rejected on a store source",
            );
        }
    }

    #[test]
    fn checkout_relative_paths_are_refused_on_a_store_build() {
        // A Dockerfile manifest names its own recipe and context. A path here is
        // somebody expecting a file to be chosen that was already chosen.
        for (field, with) in [
            (
                "build.dockerfile",
                BuildSpec {
                    dockerfile: Some("deploy/Dockerfile".into()),
                    ..store_build_spec()
                },
            ),
            (
                "build.context",
                BuildSpec {
                    context: Some(".".into()),
                    ..store_build_spec()
                },
            ),
        ] {
            let mut s = spec();
            s.build = Some(with);
            assert_eq!(s.validate(), Err(SpecError::OnlyForGitBuilds(field)));
        }
    }

    #[test]
    fn a_store_build_still_cannot_coexist_with_an_artifact_block() {
        // Both rewrite `vm.image`. That one of them now also *builds* changes
        // nothing about why a deployment cannot have two.
        let mut s = spec();
        s.build = Some(store_build_spec());
        s.artifact = Some(ArtifactSpec {
            store: "http://art:8080".into(),
            artifact_ref: "web".into(),
            auth: None,
            grow_gb: None,
            image_name: None,
            strip_components: None,
        });
        assert_eq!(s.validate(), Err(SpecError::BothImageSources));
    }

    #[test]
    fn a_build_source_is_a_repo_or_a_store_and_never_both() {
        match store_build_spec().source() {
            Some(BuildSource::Dockerfile { store, reference }) => {
                assert_eq!(store, "http://art.internal:8080");
                assert_eq!(reference, "web-rootfs");
            }
            other => panic!("expected a Dockerfile source, got {other:?}"),
        }
        match build_spec().source() {
            Some(BuildSource::Git { repo, git_ref }) => {
                assert_eq!(repo, "https://github.com/acme/web.git");
                assert_eq!(git_ref, Some("main"));
            }
            other => panic!("expected a Git source, got {other:?}"),
        }
        // A spec that never passed validate() has no source at all, rather than
        // a half-formed one a consumer would have to defend against.
        assert!(
            BuildSpec {
                repo: None,
                ..build_spec()
            }
            .source()
            .is_none()
        );
    }

    #[test]
    fn a_store_built_image_is_named_after_its_manifest() {
        let digest = "c74abee2f1a0".to_string() + &"0".repeat(52);
        assert_eq!(store_build_spec().image_for("web", &digest), "web-c74abee2f1a0");
        // The same shape a commit gets, so one deployment's images sort together
        // whichever source made them.
        assert_eq!(
            build_spec().image_for("web", "abcdef0123456789"),
            "web-abcdef012345"
        );
    }

    #[test]
    fn a_build_spec_round_trips_through_json_under_both_sources() {
        for original in [build_spec(), store_build_spec()] {
            let json = serde_json::to_string(&original).unwrap();
            let back: BuildSpec = serde_json::from_str(&json).unwrap();
            assert_eq!(back, original, "{json}");
            // One wire name for the version, whichever source it selects.
            assert!(json.contains("\"ref\""), "{json}");
            assert!(!json.contains("source_ref"), "{json}");
        }

        // A spec written before `store` existed still loads: `repo` became
        // optional by type but is still required in practice, so nothing on disk
        // needs migrating.
        let old: BuildSpec =
            serde_json::from_str(r#"{"repo":"https://x/y.git","ref":"main"}"#).unwrap();
        assert_eq!(old.repo.as_deref(), Some("https://x/y.git"));
        assert_eq!(old.store, None);
        // And still serializes without mentioning a store it does not have.
        assert!(!serde_json::to_string(&old).unwrap().contains("store"));
    }

    #[test]
    fn a_static_deployment_cannot_declare_a_build() {
        let mut s = static_spec(&["10.0.0.9:8080"]);
        s.build = Some(build_spec());
        assert_eq!(s.validate(), Err(SpecError::BuildOnStaticDeployment));
    }

    fn update_spec() -> UpdateSpec {
        UpdateSpec {
            working_dir: "/srv/app-obs".into(),
            commands: vec![
                "git pull --ff-only".into(),
                "cargo build --release".into(),
                "supervisorctl restart app-obs".into(),
            ],
            env: None,
            env_from: vec![],
            auth: None,
            timeout_secs: None,
            verify_timeout_secs: None,
        }
    }

    #[test]
    fn accepts_a_working_directory_and_commands_on_a_static_deployment() {
        let mut s = static_spec(&["127.0.0.1:9600"]);
        s.update = Some(update_spec());
        assert_eq!(s.validate(), Ok(()));
    }

    /// The two update paths are exclusive, and each error has to point at the
    /// other one — landing on the wrong verb is the obvious mistake to make.
    #[test]
    fn each_kind_of_deployment_gets_exactly_one_update_path() {
        let mut managed = spec();
        managed.update = Some(update_spec());
        assert_eq!(managed.validate(), Err(SpecError::UpdateOnManagedDeployment));
        assert!(
            SpecError::UpdateOnManagedDeployment.to_string().contains("build"),
            "the error should name the path that does apply"
        );

        let mut static_dep = static_spec(&["10.0.0.9:8080"]);
        static_dep.build = Some(build_spec());
        assert!(
            SpecError::BuildOnStaticDeployment.to_string().contains("update"),
            "and likewise in the other direction"
        );
        assert_eq!(static_dep.validate(), Err(SpecError::BuildOnStaticDeployment));
    }

    #[test]
    fn a_working_directory_must_be_absolute_and_cannot_climb() {
        for dir in ["", "   "] {
            let mut s = static_spec(&["10.0.0.9:8080"]);
            s.update = Some(UpdateSpec {
                working_dir: dir.into(),
                ..update_spec()
            });
            assert_eq!(s.validate(), Err(SpecError::EmptyWorkingDir));
        }
        for dir in ["srv/app", "./app", "/srv/../../etc", "~/app"] {
            let mut s = static_spec(&["10.0.0.9:8080"]);
            s.update = Some(UpdateSpec {
                working_dir: dir.into(),
                ..update_spec()
            });
            assert_eq!(
                s.validate(),
                Err(SpecError::BadWorkingDir(dir.to_string())),
                "{dir:?} should be rejected",
            );
        }
    }

    #[test]
    fn an_update_needs_something_to_run() {
        let mut s = static_spec(&["10.0.0.9:8080"]);
        s.update = Some(UpdateSpec {
            commands: vec![],
            ..update_spec()
        });
        assert_eq!(s.validate(), Err(SpecError::NoCommands));

        let mut s = static_spec(&["10.0.0.9:8080"]);
        s.update = Some(UpdateSpec {
            commands: vec!["  ".into()],
            ..update_spec()
        });
        assert_eq!(s.validate(), Err(SpecError::BadCommand("  ".to_string())));
    }

    #[test]
    fn secret_env_defaults_to_the_upper_cased_key_and_must_be_a_usable_name() {
        let from = SecretEnv {
            namespace: None,
            secret: "obs".into(),
            key: "ingest_token".into(),
            env: None,
        };
        assert_eq!(from.env_name(), "INGEST_TOKEN");
        assert_eq!(from.secret_ref().key, "ingest_token");

        let renamed = SecretEnv {
            namespace: None,
            env: Some("APP_OBS_INGEST_TOKEN".into()),
            ..from.clone()
        };
        assert_eq!(renamed.env_name(), "APP_OBS_INGEST_TOKEN");

        // A name the shell cannot read back would be set and then invisible.
        let mut s = static_spec(&["10.0.0.9:8080"]);
        s.update = Some(UpdateSpec {
            env_from: vec![SecretEnv {
                namespace: None,
                env: Some("2FA-TOKEN".into()),
                ..from
            }],
            ..update_spec()
        });
        assert_eq!(
            s.validate(),
            Err(SpecError::BadEnvName("2FA-TOKEN".to_string()))
        );
    }

    #[test]
    fn verification_defaults_to_a_minute_and_can_be_switched_off() {
        assert_eq!(update_spec().verify_timeout().as_secs(), 60);
        let off = UpdateSpec {
            verify_timeout_secs: Some(0),
            ..update_spec()
        };
        assert!(off.verify_timeout().is_zero());

        // A zero *command* timeout is a mistake, not a switch.
        let mut s = static_spec(&["10.0.0.9:8080"]);
        s.update = Some(UpdateSpec {
            timeout_secs: Some(0),
            ..update_spec()
        });
        assert_eq!(s.validate(), Err(SpecError::ZeroTimeout));
    }

    #[test]
    fn an_update_block_round_trips_and_is_absent_when_unset() {
        let mut s = static_spec(&["127.0.0.1:9600"]);
        s.update = Some(UpdateSpec {
            env_from: vec![SecretEnv {
                namespace: None,
                secret: "obs".into(),
                key: "token".into(),
                env: Some("APP_OBS_TOKEN".into()),
            }],
            ..update_spec()
        });
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""working_dir":"/srv/app-obs""#), "{json}");
        assert!(json.contains(r#""as":"APP_OBS_TOKEN""#), "{json}");
        let parsed: DeploymentSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.update, s.update);

        // An older persisted spec has no `update` key at all.
        let plain: DeploymentSpec =
            serde_json::from_str(&serde_json::to_string(&static_spec(&["10.0.0.9:80"])).unwrap())
                .unwrap();
        assert!(plain.update.is_none());
    }

    #[test]
    fn image_names_are_derived_from_the_commit_and_kept_docker_safe() {
        let b = build_spec();
        assert_eq!(
            b.image_for("web", "0123456789abcdef0123"),
            "web-0123456789ab",
            "the short sha is what makes each build a distinct image"
        );
        // The deployment id is only constrained by routing, so it is sanitized.
        assert_eq!(b.image_for("Web.API_v2", "abc"), "web.api_v2-abc");
        assert_eq!(b.image_for("--weird--", "abc"), "weird-abc");

        let named = BuildSpec {
            image_name: Some("Custom Name".into()),
            ..build_spec()
        };
        assert_eq!(named.image_for("web", "deadbeef"), "custom-name-deadbeef");

        let mut s = spec();
        s.build = Some(BuildSpec {
            image_name: Some("///".into()),
            ..build_spec()
        });
        assert_eq!(
            s.validate(),
            Err(SpecError::BadImageName("///".to_string()))
        );
    }

    #[test]
    fn a_build_credential_is_a_reference_not_a_value() {
        let mut s = spec();
        s.build = Some(BuildSpec {
            auth: Some(crate::secrets::SecretRef {
                namespace: None,
                secret: "github".into(),
                key: "token".into(),
                username: None,
            }),
            ..build_spec()
        });
        assert_eq!(s.validate(), Ok(()));
        // Round-tripping a spec must not require the value to exist.
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""auth":{"secret":"github","key":"token"}"#), "{json}");

        s.build = Some(BuildSpec {
            auth: Some(crate::secrets::SecretRef {
                namespace: None,
                secret: "../etc".into(),
                key: "token".into(),
                username: None,
            }),
            ..build_spec()
        });
        assert!(matches!(
            s.validate(),
            Err(SpecError::BadSecretRef { field: "build.auth", .. })
        ));
    }

    #[test]
    fn a_build_block_is_optional_and_absent_from_a_spec_that_has_none() {
        let json = serde_json::to_string(&spec()).unwrap();
        assert!(!json.contains("build"), "{json}");
        // And an old persisted spec (no `build` key) still parses.
        let parsed: DeploymentSpec = serde_json::from_str(&json).unwrap();
        assert!(parsed.build.is_none());
    }

    fn artifact_spec() -> ArtifactSpec {
        ArtifactSpec {
            store: "http://127.0.0.1:8080".into(),
            artifact_ref: "debian-hermes".into(),
            auth: None,
            grow_gb: None,
            image_name: None,
            strip_components: None,
        }
    }

    #[test]
    fn an_artifact_store_is_a_url_or_an_absolute_path_and_nothing_else() {
        let ok = ["http://127.0.0.1:8080", "https://art.example.com", "/srv/artifacts"];
        for store in ok {
            let s = DeploymentSpec {
                ingress: None,
                account_id: None,
                user_id: None,
                artifact: Some(ArtifactSpec { store: store.into(), ..artifact_spec() }),
                ..spec()
            };
            assert!(s.validate().is_ok(), "{store} should be accepted");
        }

        // A relative root would resolve against app-lb's working directory,
        // which nobody writing a spec can see; the rest are not stores at all.
        for store in ["", ".artifacts", "art.example.com", "/srv/../etc", "file:///srv/art"] {
            let s = DeploymentSpec {
                ingress: None,
                account_id: None,
                user_id: None,
                artifact: Some(ArtifactSpec { store: store.into(), ..artifact_spec() }),
                ..spec()
            };
            assert!(s.validate().is_err(), "{store:?} should be refused");
        }
    }

    #[test]
    fn only_the_url_form_is_remote() {
        assert!(artifact_spec().is_remote());
        assert!(
            !ArtifactSpec { store: "/srv/artifacts".into(), ..artifact_spec() }.is_remote(),
            "a store root is materialized locally, not fetched"
        );
    }

    #[test]
    fn an_artifact_ref_is_a_tag_or_a_digest() {
        let digest = "c74abee2ce84".repeat(5) + "abcd";
        assert_eq!(digest.len(), 64);
        for r in [
            "debian-hermes",
            "ubuntu-24.04",
            "web_v2",
            digest.as_str(),
            // Namespaced, as the hub publishes them.
            "heyo/postgres:16",
            "heyo/postgres",
            "postgres:16",
            "acme/team/web:v1.2",
        ] {
            let s = DeploymentSpec {
                ingress: None,
                account_id: None,
                user_id: None,
                artifact: Some(ArtifactSpec { artifact_ref: r.into(), ..artifact_spec() }),
                ..spec()
            };
            assert!(s.validate().is_ok(), "{r} should be accepted");
        }
        // A leading `-` reads as a flag to anything that shells out, and an
        // empty or dot segment would leave the store when pasted into a URL
        // path. Repositories are lowercase, as registries' are.
        for r in [
            "",
            "-flag",
            ".hidden",
            "a//b",
            "../etc/passwd",
            "a/../b",
            "/a",
            "a/",
            "Heyo/pg:16",
            "a/b:c/d",
            "a/b:",
            "a/b/c/d/e",
            "has space",
        ] {
            let s = DeploymentSpec {
                ingress: None,
                account_id: None,
                user_id: None,
                artifact: Some(ArtifactSpec { artifact_ref: r.into(), ..artifact_spec() }),
                ..spec()
            };
            assert!(
                matches!(s.validate(), Err(SpecError::BadArtifactRef(_))),
                "{r:?} should be refused"
            );
        }
    }

    #[test]
    fn a_pulled_image_is_named_after_the_digest_it_came_from() {
        let a = artifact_spec();
        let digest = "c74abee2ce8409f1aa00bb11cc22dd33ee44ff5566778899aabbccddeeff0011";
        assert_eq!(
            a.image_for("web", digest),
            "img-c74abee2ce8409f1",
            "named by content, so a re-pull of the same bytes is detectable by name",
        );
        assert_eq!(
            a.image_for("api", digest),
            a.image_for("web", digest),
            "two deployments of one image share one catalog entry",
        );
        let grown = ArtifactSpec { grow_gb: Some(4), ..artifact_spec() };
        assert_eq!(grown.image_for("web", digest), "img-c74abee2ce8409f1-g4", "a grown image is a different file");
        assert_eq!(
            a.image_for("web", "c74abee2"),
            "web-c74abee2",
            "a digest too short to address anything keeps the deployment-scoped name",
        );
        assert_eq!(content_addressed_image("not-hex-at-all-xx", None), None);
        let named = ArtifactSpec { image_name: Some("Custom Name".into()), ..artifact_spec() };
        assert_eq!(named.image_for("web", "deadbeefcafe0"), "custom-name-deadbeefcafe");
    }

    #[test]
    fn a_deployment_cannot_both_build_and_pull_its_image() {
        let s = DeploymentSpec {
            ingress: None,
            account_id: None,
            user_id: None,
            build: Some(build_spec()),
            artifact: Some(artifact_spec()),
            ..spec()
        };
        assert_eq!(s.validate(), Err(SpecError::BothImageSources));
    }

    #[test]
    fn a_static_deployment_has_no_image_to_pull_into() {
        let s = DeploymentSpec {
            ingress: None,
            account_id: None,
            user_id: None,
            artifact: Some(artifact_spec()),
            ..static_spec(&["127.0.0.1:9000"])
        };
        assert_eq!(s.validate(), Err(SpecError::ArtifactOnStaticDeployment));
    }

    #[test]
    fn growing_to_zero_is_refused_rather_than_silently_shrinking_nothing() {
        let s = DeploymentSpec {
            ingress: None,
            account_id: None,
            user_id: None,
            artifact: Some(ArtifactSpec { grow_gb: Some(0), ..artifact_spec() }),
            ..spec()
        };
        assert_eq!(s.validate(), Err(SpecError::ZeroGrow));
    }

    #[test]
    fn an_artifact_block_is_optional_and_absent_from_a_spec_that_has_none() {
        let json = serde_json::to_string(&spec()).unwrap();
        assert!(!json.contains("artifact"), "{json}");
        let parsed: DeploymentSpec = serde_json::from_str(&json).unwrap();
        assert!(parsed.artifact.is_none());
    }

    #[test]
    fn an_artifact_block_round_trips_with_ref_spelled_the_way_a_spec_spells_it() {
        let s = DeploymentSpec { artifact: Some(artifact_spec()), ..spec() };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""ref":"debian-hermes""#), "{json}");
        let parsed: DeploymentSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.artifact, Some(artifact_spec()));
    }

    fn auth_gate() -> AuthGate {
        AuthGate {
            session_scope: None,
            provider: Default::default(),
            client_id: Some("cid.apps.googleusercontent.com".into()),
            client_secret: Some(crate::secrets::SecretRef {
                namespace: None,
                secret: "google".into(),
                key: "client_secret".into(),
                username: None,
            }),
            allowed_domains: vec!["example.com".into()],
            allowed_emails: vec![],
            public_paths: vec![],
            base_path: default_auth_base_path(),
            session_ttl_secs: default_session_ttl_secs(),
            cookie_name: default_auth_cookie_name(),
            cookie_domain: None,
            redirect_url: None,
            forward_identity: true,
            jwt: None,
            provider_ref: None,
        }
    }

    #[test]
    fn a_gate_applies_to_either_backend_kind() {
        // The gate runs in the proxy, ahead of whichever backend the deployment
        // has, so both shapes accept one.
        let mut managed = spec();
        managed.auth = Some(auth_gate());
        assert_eq!(managed.validate(), Ok(()));

        // `static_spec` routes on a path prefix, so its gate has to put its
        // endpoints under that prefix for the callback to route back — which is
        // the check below, and the reason this is spelled out rather than
        // defaulted.
        let mut static_dep = static_spec(&["127.0.0.1:9600"]);
        static_dep.auth = Some(AuthGate {
            base_path: "/legacy/__auth".into(),
            ..auth_gate()
        });
        assert_eq!(static_dep.validate(), Ok(()));
    }

    /// Gating behind "has a Google account" is a real choice, and a very
    /// different one from what an empty list looks like it means.
    #[test]
    fn an_empty_allow_list_is_refused_and_the_escape_hatch_is_explicit() {
        let mut s = spec();
        s.auth = Some(AuthGate {
            allowed_domains: vec![],
            allowed_emails: vec![],
            ..auth_gate()
        });
        assert_eq!(s.validate(), Err(SpecError::EmptyAllowList));
        assert!(
            SpecError::EmptyAllowList.to_string().contains("\"*\""),
            "the error has to name the way to say what was meant"
        );

        s.auth = Some(AuthGate {
            allowed_domains: vec!["*".into()],
            allowed_emails: vec![],
            ..auth_gate()
        });
        assert_eq!(s.validate(), Ok(()));

        // An address alone is enough.
        s.auth = Some(AuthGate {
            allowed_domains: vec![],
            allowed_emails: vec!["someone@gmail.com".into()],
            ..auth_gate()
        });
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn a_gate_rejects_unusable_allow_list_entries() {
        for domain in ["", "not-a-domain", " example.com "] {
            let mut s = spec();
            s.auth = Some(AuthGate {
                allowed_domains: vec![domain.into()],
                ..auth_gate()
            });
            assert!(
                matches!(s.validate(), Err(SpecError::BadAllowedDomain(_))),
                "{domain:?} should be rejected",
            );
        }
        let mut s = spec();
        s.auth = Some(AuthGate {
            allowed_emails: vec!["not-an-address".into()],
            ..auth_gate()
        });
        assert!(matches!(s.validate(), Err(SpecError::BadAllowedEmail(_))));
    }

    /// Regression: a deployment routed only at `/app` would 404 the provider's
    /// redirect to `/__applb/auth/callback`, and the sign-in could never finish.
    #[test]
    fn the_callback_must_route_back_to_this_deployment() {
        let mut s = spec();
        s.routes = vec![RouteRule {
            host: None,
            host_suffix: None,
            path_prefix: Some("/app".into()),
            strip_prefix: false,
        }];
        s.auth = Some(auth_gate());
        assert_eq!(
            s.validate(),
            Err(SpecError::AuthCallbackUnroutable(
                "/__applb/auth/callback".to_string()
            ))
        );

        // Putting the gate's endpoints inside the prefix fixes it.
        s.auth = Some(AuthGate {
            base_path: "/app/__auth".into(),
            ..auth_gate()
        });
        assert_eq!(s.validate(), Ok(()));

        // A host route matches any path, so the default is fine there.
        let mut hosted = spec();
        hosted.auth = Some(auth_gate());
        assert_eq!(hosted.validate(), Ok(()));
    }

    #[test]
    fn a_gate_rejects_degenerate_settings() {
        let cases: Vec<(AuthGate, SpecError)> = vec![
            (
                AuthGate { client_id: Some("  ".into()), ..auth_gate() },
                SpecError::EmptyClientId,
            ),
            (
                AuthGate { base_path: "relative".into(), ..auth_gate() },
                SpecError::BadAuthBasePath("relative".into()),
            ),
            (
                AuthGate { base_path: "/".into(), ..auth_gate() },
                SpecError::BadAuthBasePath("/".into()),
            ),
            (
                AuthGate { public_paths: vec!["healthz".into()], ..auth_gate() },
                SpecError::BadPublicPath("healthz".into()),
            ),
            (
                AuthGate { session_ttl_secs: 0, ..auth_gate() },
                SpecError::ZeroSessionTtl,
            ),
            (
                AuthGate { cookie_name: "bad name".into(), ..auth_gate() },
                SpecError::BadCookieName("bad name".into()),
            ),
            // A single label is a cookie every browser discards, and the
            // symptom — sign-in looping forever with nothing logged — is close
            // to undiagnosable from outside. Refuse it at registration.
            (
                AuthGate { cookie_domain: Some("com".into()), ..auth_gate() },
                SpecError::BadCookieDomain("com".into()),
            ),
            (
                AuthGate { cookie_domain: Some("not a domain".into()), ..auth_gate() },
                SpecError::BadCookieDomain("not a domain".into()),
            ),
        ];
        for (gate, want) in cases {
            let mut s = spec();
            s.auth = Some(gate);
            assert_eq!(s.validate(), Err(want));
        }
    }

    #[test]
    fn the_gates_endpoints_hang_off_its_base_path() {
        let g = AuthGate {
            base_path: "/app/__auth/".into(),
            ..auth_gate()
        };
        assert_eq!(g.callback_path(), "/app/__auth/callback");
        assert_eq!(g.login_path(), "/app/__auth/login");
        assert_eq!(g.logout_path(), "/app/__auth/logout");
    }

    #[test]
    fn public_paths_are_prefixes() {
        let g = AuthGate {
            public_paths: vec!["/healthz".into(), "/hooks/".into()],
            ..auth_gate()
        };
        assert!(g.is_public("/healthz"));
        assert!(g.is_public("/hooks/github"));
        assert!(!g.is_public("/hooks"), "the trailing slash was deliberate");
        assert!(!g.is_public("/"));
    }

    /// The fingerprint is what makes a session stop working when the policy
    /// changes, so it has to move for every input that decides who gets in —
    /// and stay put for everything else.
    #[test]
    fn the_policy_fingerprint_tracks_who_may_enter() {
        let base = auth_gate();
        let same_order = AuthGate {
            allowed_emails: vec!["b@x.com".into(), "a@x.com".into()],
            ..base.clone()
        };
        let other_order = AuthGate {
            allowed_emails: vec!["a@x.com".into(), "B@x.com".into()],
            ..base.clone()
        };
        assert_eq!(
            same_order.policy_fingerprint(),
            other_order.policy_fingerprint(),
            "order and case are not policy",
        );

        for changed in [
            AuthGate { client_id: Some("other".into()), ..base.clone() },
            AuthGate { allowed_domains: vec!["other.example".into()], ..base.clone() },
            AuthGate { allowed_emails: vec!["extra@x.com".into()], ..base.clone() },
        ] {
            assert_ne!(changed.policy_fingerprint(), base.policy_fingerprint());
        }

        // Cosmetic settings must not sign everybody out.
        let cosmetic = AuthGate {
            session_ttl_secs: 999,
            public_paths: vec!["/healthz".into()],
            forward_identity: false,
            ..base.clone()
        };
        assert_eq!(cosmetic.policy_fingerprint(), base.policy_fingerprint());
    }

    #[test]
    fn a_gate_round_trips_and_keeps_the_secret_a_reference() {
        let mut s = spec();
        s.auth = Some(auth_gate());
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""provider":"google""#), "{json}");
        assert!(
            json.contains(r#""client_secret":{"secret":"google","key":"client_secret"}"#),
            "{json}"
        );
        let parsed: DeploymentSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.auth, s.auth);

        // A spec written before the gate existed still parses.
        let plain: DeploymentSpec =
            serde_json::from_str(&serde_json::to_string(&spec()).unwrap()).unwrap();
        assert!(plain.auth.is_none());
    }

    /// A valid Google provider, mirroring `auth_gate`'s identity half.
    fn google_provider() -> AuthProviderSpec {
        AuthProviderSpec {
            name: "corp".into(),
            namespace: "team-a".into(),
            description: None,
            created_at: 1,
            provider: Providers::default(),
            client_id: Some("cid.apps.googleusercontent.com".into()),
            client_secret: Some(crate::secrets::SecretRef {
                namespace: None,
                secret: "google".into(),
                key: "client_secret".into(),
                username: None,
            }),
            allowed_domains: vec!["example.com".into()],
            allowed_emails: vec![],
            jwt: None,
            cookie_domain: None,
        }
    }

    #[test]
    fn a_provider_validates_by_the_same_rules_as_an_inline_gate() {
        // Good.
        assert_eq!(google_provider().validate(), Ok(()));

        // The same empty-allow-list refusal an inline Google gate gets.
        let no_list = AuthProviderSpec { allowed_domains: vec![], ..google_provider() };
        assert_eq!(no_list.validate(), Err(SpecError::EmptyAllowList));

        // A Google allow-list on a jwt-only provider is refused, exactly as on a
        // gate — the identity checks are the same function.
        let jwt_with_google_list = AuthProviderSpec {
            provider: Providers::one(AuthProvider::Jwt),
            client_id: None,
            client_secret: None,
            allowed_domains: vec!["example.com".into()],
            jwt: Some(JwtSpec::heyo(crate::secrets::SecretRef {
                namespace: None,
                secret: "heyo-auth".into(),
                key: "jwt_secret".into(),
                username: None,
            })),
            ..google_provider()
        };
        assert_eq!(jwt_with_google_list.validate(), Err(SpecError::AllowListOnJwtGate));

        // A name outside the alphabet is refused: it becomes a filename.
        let bad_name = AuthProviderSpec { name: "has space".into(), ..google_provider() };
        assert!(matches!(bad_name.validate(), Err(SpecError::BadAuthProviderName(_))));
    }

    #[test]
    fn the_heyo_preset_is_a_valid_jwt_provider_from_a_secret_alone() {
        let secret = crate::secrets::SecretRef {
            namespace: None,
            secret: "heyo-auth".into(),
            key: "jwt_secret".into(),
            username: None,
        };
        let jwt = JwtSpec::heyo(secret.clone());
        // The documented shape of the Heyo auth API's tokens.
        assert_eq!(jwt.algorithms, vec!["HS256".to_string()]);
        assert_eq!(jwt.issuer, "auth-service");
        assert_eq!(jwt.audience.as_deref(), Some("heyo-app"));
        assert_eq!(jwt.subject_claim, "userId");

        let provider = AuthProviderSpec {
            provider: Providers::one(AuthProvider::Jwt),
            client_id: None,
            client_secret: None,
            allowed_domains: vec![],
            jwt: Some(jwt),
            ..google_provider()
        };
        assert_eq!(provider.validate(), Ok(()), "the preset must validate on its own");
    }

    /// The wall: whatever namespace a body wrote on a provider's secret
    /// references, they resolve behind the provider's own.
    #[test]
    fn normalize_binds_a_providers_secret_refs_to_its_namespace() {
        let elsewhere = |name: &str| crate::secrets::SecretRef {
            namespace: Some("someone-else".into()),
            secret: name.into(),
            key: "k".into(),
            username: None,
        };
        let mut p = AuthProviderSpec {
            namespace: "team-a".into(),
            client_secret: Some(elsewhere("google-oauth")),
            jwt: None,
            ..google_provider()
        };
        p.normalize();
        assert_eq!(p.client_secret.as_ref().unwrap().namespace(), "team-a");

        // And the JWT key, which is the one that verifies identities.
        let mut p = AuthProviderSpec {
            namespace: "team-a".into(),
            provider: Providers::one(AuthProvider::Jwt),
            client_id: None,
            client_secret: None,
            allowed_domains: vec![],
            // The shape the `heyo` preset builds: a reference with no namespace,
            // which before this resolved in `default`.
            jwt: Some(JwtSpec::heyo(crate::secrets::SecretRef {
                namespace: None,
                secret: "heyo-auth".into(),
                key: "jwt_secret".into(),
                username: None,
            })),
            ..google_provider()
        };
        p.normalize();
        assert_eq!(
            p.jwt.as_ref().unwrap().secret.as_ref().unwrap().namespace(),
            "team-a",
            "an unqualified reference must not resolve in `default`",
        );
        assert_eq!(p.validate(), Ok(()));
    }

    /// The preset that needs nothing secret — the one to reach for when the
    /// namespace, or the app-lb, belongs to somebody else.
    #[test]
    fn the_heyo_jwks_preset_verifies_against_a_key_set_and_holds_no_secret() {
        let jwt = JwtSpec::heyo_jwks("https://auth.example.com/.well-known/jwks.json".into());
        assert_eq!(jwt.algorithms, vec!["RS256".to_string()]);
        assert_eq!(jwt.issuer, "auth-service");
        assert_eq!(
            jwt.audience.as_deref(),
            Some("heyo-gate"),
            "a gate token's audience, so a platform token cannot be replayed here",
        );
        assert_eq!(jwt.subject_claim, "userId");
        assert!(jwt.secret.is_none(), "nothing secret may be part of this policy");
        assert!(jwt.public_key.is_none());

        let provider = AuthProviderSpec {
            provider: Providers::one(AuthProvider::Jwt),
            client_id: None,
            client_secret: None,
            allowed_domains: vec![],
            jwt: Some(jwt),
            ..google_provider()
        };
        assert_eq!(provider.validate(), Ok(()));

        // And normalizing it touches nothing, because there is no reference to
        // bind to a namespace — the property that makes it safe behind a wall
        // somebody else administers.
        let mut normalized = provider.clone();
        normalized.normalize();
        assert_eq!(normalized, provider);
    }

    #[test]
    fn a_reference_gate_refuses_inline_identity_but_keeps_route_scoped_fields() {
        // Only route-scoped fields alongside a reference: fine.
        let ok: DeploymentSpec = {
            let mut s = spec();
            s.auth = Some(AuthGate {
                provider_ref: Some("corp".into()),
                client_id: None,
                client_secret: None,
                allowed_domains: vec![],
                allowed_emails: vec![],
                jwt: None,
                cookie_domain: None,
                public_paths: vec![PublicPath::public("/healthz")],
                ..auth_gate()
            });
            s
        };
        assert_eq!(ok.validate(), Ok(()));

        // Any inline identity field alongside the reference is refused.
        for gate in [
            AuthGate { provider_ref: Some("corp".into()), ..auth_gate() }, // carries client_id
            AuthGate {
                provider_ref: Some("corp".into()),
                client_id: None,
                client_secret: None,
                allowed_domains: vec![],
                allowed_emails: vec![],
                jwt: None,
                cookie_domain: Some("example.com".into()),
                ..auth_gate()
            },
        ] {
            let mut s = spec();
            s.auth = Some(gate);
            assert_eq!(s.validate(), Err(SpecError::ProviderRefWithInlineIdentity));
        }
    }

    #[test]
    fn resolving_a_reference_overlays_identity_and_tracks_the_policy() {
        // A bare reference gate — route-scoped fields only.
        let gate = AuthGate {
            provider_ref: Some("corp".into()),
            client_id: None,
            client_secret: None,
            allowed_domains: vec![],
            allowed_emails: vec![],
            jwt: None,
            cookie_domain: None,
            public_paths: vec![PublicPath::public("/healthz")],
            ..auth_gate()
        };
        let provider = google_provider();
        let resolved = provider.resolve(&gate);

        // Identity came from the provider; route-scoped fields stayed on the gate;
        // the reference is cleared so the result is a plain gate.
        assert_eq!(resolved.provider_ref, None);
        assert_eq!(resolved.client_id, provider.client_id);
        assert_eq!(resolved.allowed_domains, provider.allowed_domains);
        assert_eq!(resolved.public_paths, gate.public_paths);
        // A resolved gate validates exactly like an inline one.
        let mut s = spec();
        s.auth = Some(resolved.clone());
        assert_eq!(s.validate(), Ok(()));

        // The live-inheritance invariant: tightening the provider's allow-list
        // moves the resolved gate's fingerprint, so sessions issued under the old
        // policy stop being accepted — without the deployment being touched.
        let tightened = AuthProviderSpec {
            allowed_emails: vec!["only-me@example.com".into()],
            ..provider.clone()
        };
        assert_ne!(
            resolved.policy_fingerprint(),
            tightened.resolve(&gate).policy_fingerprint(),
            "a change to the provider must re-sign inheriting deployments' sessions",
        );
    }

    /// The minimum a spec has to say: everything else defaults.
    /// The reason `Providers` has a hand-written codec instead of being a plain
    /// `Vec`: a gate written before app-tokens existed must round-trip through
    /// the new type unchanged, because every spec in every state file is one.
    #[test]
    fn a_single_provider_round_trips_as_a_bare_string() {
        let one: AuthGate = serde_json::from_str(
            r#"{"provider":"google","client_id":"cid","client_secret":{"secret":"g"},
                "allowed_domains":["example.com"]}"#,
        )
        .unwrap();
        let json = serde_json::to_string(&one).unwrap();
        assert!(
            json.contains(r#""provider":"google""#),
            "a one-provider gate must not acquire an array: {json}"
        );

        // And a gate that omits `provider` entirely still means Google, and
        // still writes it back the same way.
        let implied: AuthGate = serde_json::from_str(
            r#"{"client_id":"cid","client_secret":{"secret":"g"},
                "allowed_domains":["example.com"]}"#,
        )
        .unwrap();
        assert_eq!(implied.provider, one.provider);
    }

    #[test]
    fn several_providers_round_trip_as_a_list() {
        let gate: AuthGate = serde_json::from_str(
            r#"{"provider":["google","app-token"],"client_id":"cid",
                "client_secret":{"secret":"g"},"allowed_domains":["example.com"]}"#,
        )
        .unwrap();
        assert!(gate.accepts_google());
        assert!(gate.accepts_app_token());
        gate.validate(&[RouteRule {
            host: Some("app.example.com".into()),
            host_suffix: None,
            path_prefix: None,
            strip_prefix: false,
        }]).unwrap();

        let json = serde_json::to_string(&gate).unwrap();
        assert!(json.contains(r#""provider":["google","app-token"]"#), "{json}");
        let back: AuthGate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider, gate.provider);
    }

    #[test]
    fn a_token_only_gate_needs_no_oauth_credentials() {
        let gate: AuthGate = serde_json::from_str(r#"{"provider":"app-token"}"#).unwrap();
        assert!(!gate.accepts_google());
        assert!(gate.accepts_app_token());
        assert!(gate.google_credentials().is_none());
        // No client_id, no allow-list, and still valid: neither describes a
        // credential issued to a program.
        gate.validate(&[RouteRule {
            host: Some("app.example.com".into()),
            host_suffix: None,
            path_prefix: None,
            strip_prefix: false,
        }]).unwrap();
    }

    #[test]
    fn oauth_credentials_without_the_google_provider_are_refused() {
        // Not ignored: whoever wrote these believes the deployment is behind
        // Google sign-in, and it is not.
        let gate: AuthGate = serde_json::from_str(
            r#"{"provider":"app-token","client_id":"cid","client_secret":{"secret":"g"}}"#,
        )
        .unwrap();
        assert_eq!(
            gate.validate(&[RouteRule {
                host: Some("app.example.com".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
            }]),
            Err(SpecError::OauthWithoutGoogle)
        );
    }

    #[test]
    fn a_gate_that_admits_nobody_is_refused() {
        let gate: AuthGate = serde_json::from_str(r#"{"provider":[]}"#).unwrap();
        assert_eq!(
            gate.validate(&[RouteRule {
                host: Some("app.example.com".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
            }]),
            Err(SpecError::NoAuthProvider)
        );
    }

    #[test]
    fn a_google_gate_still_demands_its_credentials_and_an_allow_list() {
        let missing: AuthGate = serde_json::from_str(r#"{"provider":"google"}"#).unwrap();
        assert_eq!(
            missing.validate(&[RouteRule {
                host: Some("app.example.com".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
            }]),
            Err(SpecError::EmptyClientId)
        );

        let no_list: AuthGate = serde_json::from_str(
            r#"{"provider":"google","client_id":"cid","client_secret":{"secret":"g"}}"#,
        )
        .unwrap();
        assert_eq!(
            no_list.validate(&[RouteRule {
                host: Some("app.example.com".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
            }]),
            Err(SpecError::EmptyAllowList)
        );
    }

    /// This digest signs sessions, so a change to it signs everyone out. Adding
    /// a provider is a policy change and *should* invalidate; merely upgrading
    /// app-lb is not and must not.
    #[test]
    fn the_session_fingerprint_is_unchanged_for_a_gate_nobody_edited() {
        let before: AuthGate = serde_json::from_str(
            r#"{"provider":"google","client_id":"cid","client_secret":{"secret":"g"},
                "allowed_domains":["example.com"]}"#,
        )
        .unwrap();
        let implied: AuthGate = serde_json::from_str(
            r#"{"client_id":"cid","client_secret":{"secret":"g"},
                "allowed_domains":["example.com"]}"#,
        )
        .unwrap();
        assert_eq!(before.policy_fingerprint(), implied.policy_fingerprint());

        let widened: AuthGate = serde_json::from_str(
            r#"{"provider":["google","app-token"],"client_id":"cid",
                "client_secret":{"secret":"g"},"allowed_domains":["example.com"]}"#,
        )
        .unwrap();
        assert_ne!(
            before.policy_fingerprint(),
            widened.policy_fingerprint(),
            "adding a provider changes the gate's policy and must invalidate sessions"
        );
    }

    #[test]
    fn a_gate_parses_from_just_a_client_id_secret_and_allow_list() {
        let gate: AuthGate = serde_json::from_str(
            r#"{"client_id":"cid","client_secret":{"secret":"google"},
                "allowed_domains":["example.com"]}"#,
        )
        .unwrap();
        assert_eq!(gate.provider.as_slice(), [AuthProvider::Google]);
        assert!(gate.accepts_google());
        assert!(!gate.accepts_app_token());
        assert_eq!(
            gate.client_secret.as_ref().unwrap().key,
            "token",
            "the SecretRef default"
        );
        assert_eq!(gate.base_path, "/__applb/auth");
        assert_eq!(gate.cookie_name, "applb_session");
        assert!(gate.forward_identity);
        assert_eq!(gate.session_ttl_secs, 43_200);
    }

    #[test]
    fn accepts_supported_drivers() {
        let mut s = spec();
        s.vm.as_mut().unwrap().driver = Driver::Firecracker;
        assert!(s.validate().is_ok());
        s.vm.as_mut().unwrap().driver = Driver::Kvm;
        assert!(s.validate().is_ok());
    }

    #[test]
    fn rejects_libvirt_because_it_has_no_guest_ip() {
        let mut s = spec();
        s.vm.as_mut().unwrap().driver = Driver::Libvirt;
        assert_eq!(
            s.validate(),
            Err(SpecError::UnsupportedDriver(Driver::Libvirt))
        );
    }

    /// The whole reason `Driver` is app-lb's own enum and not the SDK's: it has
    /// to spell every driver the same way on the wire, or 30 golden fixtures and
    /// every persisted deployment change meaning under an in-place upgrade.
    #[test]
    fn driver_spellings_are_the_wire_contract() {
        for (json, driver) in [
            ("firecracker", Driver::Firecracker),
            ("kvm", Driver::Kvm),
            ("lxc", Driver::Lxc),
            ("libvirt", Driver::Libvirt),
            ("firecracker_containerd", Driver::FirecrackerContainerd),
        ] {
            let quoted = format!("\"{json}\"");
            assert_eq!(
                serde_json::from_str::<Driver>(&quoted).unwrap(),
                driver,
                "{json} must deserialize",
            );
            assert_eq!(
                serde_json::to_string(&driver).unwrap(),
                quoted,
                "{driver:?} must serialize back to the same string",
            );
            // What an error message prints, and what `heyctl --driver` accepts.
            assert_eq!(driver.to_string(), json);
        }
    }

    /// A driver the daemon cannot boot must still *parse*, so the spec reaches
    /// `validate` and the caller gets an explanation instead of a serde error
    /// pointing at a byte offset.
    #[test]
    fn an_unbootable_driver_is_refused_by_validate_not_by_serde() {
        for (json, expected) in [
            ("libvirt", SpecError::UnsupportedDriver(Driver::Libvirt)),
            (
                "firecracker_containerd",
                SpecError::UnsupportedDriver(Driver::FirecrackerContainerd),
            ),
        ] {
            let mut s = spec();
            s.vm.as_mut().unwrap().driver = serde_json::from_str(&format!("\"{json}\"")).unwrap();
            assert_eq!(s.validate(), Err(expected), "driver {json}");
        }
    }

    /// ...but a driver that is not a driver at all is still a parse failure.
    /// `Driver` has no `#[serde(other)]`, deliberately: a typo should not
    /// silently become a deployment that boots the default runtime.
    #[test]
    fn an_unknown_driver_is_still_a_serde_error() {
        assert!(serde_json::from_str::<Driver>("\"firecraker\"").is_err());
        assert!(serde_json::from_str::<Driver>("\"docker\"").is_err());
        assert!(serde_json::from_str::<Driver>("\"\"").is_err());
    }

    /// A container spec needs an image, and the message has to say so without
    /// sending the reader to heyvm's catalog default — which is a catalog
    /// *name*, not a registry reference, and would not work here.
    #[test]
    fn lxc_needs_an_image_and_says_what_kind() {
        let mut s = spec();
        let vm = s.vm.as_mut().unwrap();
        vm.driver = Driver::Lxc;
        vm.image = None;
        assert_eq!(s.validate(), Err(SpecError::LxcNeedsImage));

        let refusal = SpecError::LxcNeedsImage.to_string();
        assert!(refusal.contains("vm.image"), "{refusal}");
        assert!(refusal.contains("nginx:1.27"), "names a usable example: {refusal}");
    }

    /// The blocks that mean something on heyvmd and nothing on Incus are each
    /// refused *by name*. "Not supported" without saying which of eight blocks
    /// is the problem is not an error anyone can act on.
    #[test]
    fn lxc_refuses_heyvm_only_blocks_by_name() {
        let base = || {
            let mut s = spec();
            let vm = s.vm.as_mut().unwrap();
            vm.driver = Driver::Lxc;
            vm.image = Some("nginx:1.27".into());
            vm.open_ports = vec![];
            s
        };
        // The clean spec registers, so every failure below is the field under
        // test rather than something the fixture already tripped.
        assert!(base().validate().is_ok(), "{:?}", base().validate());

        let mut s = base();
        s.vm.as_mut().unwrap().setup_hooks = Some(vec!["apt-get update".into()]);
        assert_eq!(s.validate(), Err(SpecError::NotForLxc("vm.setup_hooks")));

        let mut s = base();
        s.vm.as_mut().unwrap().image_download_url = Some("https://example/img".into());
        assert_eq!(s.validate(), Err(SpecError::NotForLxc("vm.image_download_url")));

        let mut s = base();
        s.vm.as_mut().unwrap().workspace_archive = Some(WorkspaceArchive {
            archive_id: Some("ar-1".into()),
            s3_key: Some("k".into()),
            size_bytes: None,
        });
        assert_eq!(s.validate(), Err(SpecError::NotForLxc("vm.workspace_archive")));
    }

    /// `open_ports` is a *security* field. On a bridged container every port is
    /// reachable whatever it says, so accepting and ignoring it would leave a
    /// spec believing it had closed a port it had not.
    #[test]
    fn lxc_refuses_open_ports_rather_than_ignoring_them() {
        let mut s = spec();
        let vm = s.vm.as_mut().unwrap();
        vm.driver = Driver::Lxc;
        vm.image = Some("nginx:1.27".into());
        vm.open_ports = vec![9000];
        assert_eq!(s.validate(), Err(SpecError::NotForLxc("vm.open_ports")));
    }

    /// A deployment id has to be able to name a container. Incus names are DNS
    /// labels, and app-lb ids are only checked for non-empty — so this is the
    /// one rule `driver: lxc` adds that no other deployment kind has.
    #[test]
    fn lxc_refuses_an_id_that_cannot_name_a_container() {
        let with_id = |id: &str| {
            let mut s = spec();
            s.id = id.to_string();
            let vm = s.vm.as_mut().unwrap();
            vm.driver = Driver::Lxc;
            vm.image = Some("nginx:1.27".into());
            vm.open_ports = vec![];
            s
        };
        assert!(with_id("web").validate().is_ok());
        assert!(with_id("web-v2").validate().is_ok());

        // Legal as an app-lb id, illegal as a DNS label.
        for bad in ["my_app", "web.v2", "Web", "web-"] {
            assert!(
                matches!(with_id(bad).validate(), Err(SpecError::BadLxcId { .. })),
                "{bad} should be refused",
            );
        }

        // The budget is Incus's 63 minus the 19 characters of
        // `applb-` + `-` + a 12-hex nonce that `vm::replica_name` adds.
        let longest = "a".repeat(MAX_LXC_DEPLOYMENT_ID);
        assert!(with_id(&longest).validate().is_ok(), "{MAX_LXC_DEPLOYMENT_ID} must fit");
        assert!(crate::incus::is_legal_name(&crate::vm::replica_name(&longest, 0)));

        let too_long = "a".repeat(MAX_LXC_DEPLOYMENT_ID + 1);
        assert!(matches!(
            with_id(&too_long).validate(),
            Err(SpecError::BadLxcId { .. })
        ));
        // ...and the rule is not arbitrary: one more character genuinely
        // overflows the name Incus would have to accept.
        assert!(!crate::incus::is_legal_name(&crate::vm::replica_name(&too_long, 0)));
    }

    #[test]
    fn accepts_a_static_upstream_spec() {
        assert!(!spec().is_static());
        let s = static_spec(&["10.0.0.9:8080", "backend.internal:8080", "[::1]:9000"]);
        assert!(s.is_static());
        assert_eq!(s.validate(), Ok(()));

        let https = static_spec(&["https://ci.eu1.heyo.work:443"]);
        assert_eq!(https.validate(), Ok(()));
    }

    #[test]
    fn rejects_both_or_neither_backend_kind() {
        // Both `vm` and `upstreams`.
        let mut both = spec();
        both.upstreams = vec!["10.0.0.9:8080".into()];
        assert_eq!(both.validate(), Err(SpecError::BothBackendKinds));

        // Neither.
        let mut neither = spec();
        neither.vm = None;
        assert_eq!(neither.validate(), Err(SpecError::NoBackendKind));
    }

    #[test]
    fn rejects_malformed_upstreams() {
        for bad in [
            "no-port", "host:", ":8080", "host:0", "host:notaport",
            "http://ci.example:80", "ftp://ci.example:21", "https://user@ci.example:443",
            "https://ci.example:443/api", "https://ci.example:443/?q=1",
            "https://ci.example:443/#fragment", "https://:443",
            "https://ci.example:0", "https://ci.example/a/..",
            "https://ci.example/%2e/", "https://ci.example\\",
            " https://ci.example", "https://ci.example\n",
            "https://127.0.0.1:443", "https://[::1]:443",
        ] {
            let s = static_spec(&[bad]);
            assert_eq!(
                s.validate(),
                Err(SpecError::BadUpstream(bad.to_string())),
                "{bad:?} should be rejected",
            );
        }
    }

    #[test]
    fn rejects_degenerate_specs() {
        let mut s = static_spec(&["127.0.0.1:9000"]);
        s.routes.clear();
        assert_eq!(s.validate(), Err(SpecError::NoRoutes));

        let mut s = spec();
        s.routes = vec![RouteRule::default()];
        assert_eq!(s.validate(), Err(SpecError::EmptyRoute));

        let mut s = spec();
        s.scaling.min_replicas = 3;
        s.scaling.max_replicas = 2;
        assert_eq!(
            s.validate(),
            Err(SpecError::BadReplicaRange { min: 3, max: 2 })
        );

        let mut s = spec();
        s.scaling.target_concurrency = 0;
        assert_eq!(s.validate(), Err(SpecError::ZeroTargetConcurrency));

        let mut s = spec();
        s.vm.as_mut().unwrap().port = 0;
        assert_eq!(s.validate(), Err(SpecError::ZeroPort));
    }

    #[test]
    fn strip_prefix_requires_and_serializes_its_route_prefix() {
        let mut s = static_spec(&["127.0.0.1:9000"]);
        s.routes[0].strip_prefix = true;
        assert_eq!(s.validate(), Ok(()));
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""strip_prefix":true"#), "{json}");

        s.routes[0].path_prefix = None;
        s.routes[0].host = Some("example.com".to_string());
        assert_eq!(s.validate(), Err(SpecError::StripPrefixWithoutPath));
    }

    /// `destroy` is the historical behaviour, so a spec written before
    /// `idle_action` existed must keep meaning what it meant.
    #[test]
    fn idle_action_defaults_to_destroy_and_round_trips() {
        let s: ScalingPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(s.idle_action, IdleAction::Destroy);

        let s: ScalingPolicy = serde_json::from_str(r#"{"idle_action":"retain"}"#).unwrap();
        assert_eq!(s.idle_action, IdleAction::Retain);

        let round = serde_json::to_string(&s).unwrap();
        assert!(round.contains(r#""idle_action":"retain""#), "got {round}");
    }

    mod sites {
        use super::*;

        fn site_spec() -> DeploymentSpec {
            let mut s = static_spec(&["127.0.0.1:9000"]);
            s.upstreams.clear();
            s.site = Some(SiteSpec {
                root: "/var/www/docs".into(),
                index: "index.html".into(),
                not_found: None,
                spa: false,
                cache_control: "public, max-age=300".into(),
            });
            s
        }

        #[test]
        fn a_site_is_its_own_backend_kind() {
            let s = site_spec();
            assert_eq!(s.validate(), Ok(()));
            assert_eq!(s.backend(), Backend::Site);
            assert!(s.is_site());
            // The distinction that matters everywhere else: a site is *not*
            // static, and code asking "does this have a VM pool?" must not get
            // its answer from `is_static`.
            assert!(!s.is_static());
            assert!(!s.is_managed());
        }

        #[test]
        fn a_site_cannot_also_be_something_else() {
            let mut s = site_spec();
            s.upstreams = vec!["127.0.0.1:9000".into()];
            assert_eq!(s.validate(), Err(SpecError::SiteWithOtherBackend));

            let mut s = site_spec();
            s.vm = spec().vm;
            assert_eq!(s.validate(), Err(SpecError::SiteWithOtherBackend));
        }

        /// A site's `build` is a git checkout copied into the root. The image
        /// half of the block (a store recipe, a Dockerfile, an image name or
        /// size) means nothing without an image, so it is refused rather than
        /// ignored.
        #[test]
        fn a_site_build_is_a_git_checkout_and_nothing_else() {
            let mut s = site_spec();
            s.build = Some(
                serde_json::from_str(r#"{"repo":"https://github.com/acme/site.git","ref":"main","context":"dist"}"#)
                    .unwrap(),
            );
            assert_eq!(s.validate(), Ok(()));

            for (json, field) in [
                (r#"{"store":"http://127.0.0.1:8080","ref":"x"}"#, "build.store"),
                (r#"{"repo":"https://h/r.git","dockerfile":"Dockerfile"}"#, "build.dockerfile"),
                (r#"{"repo":"https://h/r.git","image_name":"x"}"#, "build.image_name"),
                (r#"{"repo":"https://h/r.git","image_size_mb":512}"#, "build.image_size_mb"),
            ] {
                let mut s = site_spec();
                s.build = Some(serde_json::from_str(json).unwrap());
                assert_eq!(s.validate(), Err(SpecError::NotForSites(field)), "{json}");
            }

            let mut s = site_spec();
            s.build = Some(serde_json::from_str(r#"{"repo":"https://h/r.git","context":"../x"}"#).unwrap());
            assert!(s.validate().is_err(), "the context stays inside the checkout");

            let mut s = site_spec();
            s.build = Some(serde_json::from_str(r#"{"repo":"https://h/r.git"}"#).unwrap());
            s.artifact = Some(
                serde_json::from_str(r#"{"store":"http://127.0.0.1:8080","ref":"x"}"#).unwrap(),
            );
            assert_eq!(s.validate(), Err(SpecError::BothSiteSources));
        }

        /// `update` *is* allowed: `git pull && npm run build` in a directory on
        /// this host is exactly how a site is redeployed.
        #[test]
        fn an_update_block_is_how_a_site_is_deployed() {
            let mut s = site_spec();
            s.update = Some(
                serde_json::from_str(
                    r#"{"working_dir":"/srv/docs","commands":["git pull","npm run build"]}"#,
                )
                .unwrap(),
            );
            assert_eq!(s.validate(), Ok(()));
        }

        /// And so is `artifact`: unpacking a bundle somebody else built is the
        /// other way a site is redeployed, and the one that needs no toolchain on
        /// this host at all.
        #[test]
        fn an_artifact_block_is_the_other_way_a_site_is_deployed() {
            let mut s = site_spec();
            s.artifact = Some(
                serde_json::from_str(
                    r#"{"store":"http://127.0.0.1:8080","ref":"marketing-live"}"#,
                )
                .unwrap(),
            );
            assert_eq!(s.validate(), Ok(()));

            // The one field that only means something here.
            s.artifact.as_mut().unwrap().strip_components = Some(1);
            assert_eq!(s.validate(), Ok(()));
            assert_eq!(s.artifact.as_ref().unwrap().strip(), 1);
        }

        /// The half of `artifact` that describes a guest rootfs. Refused rather
        /// than ignored: somebody setting `grow_gb` on a site expects room they
        /// are never going to get.
        #[test]
        fn the_guest_image_half_of_an_artifact_block_is_refused_on_a_site() {
            let base: ArtifactSpec =
                serde_json::from_str(r#"{"store":"/srv/artifacts","ref":"marketing-live"}"#)
                    .unwrap();

            let mut s = site_spec();
            s.artifact = Some(ArtifactSpec { grow_gb: Some(8), ..base.clone() });
            assert_eq!(s.validate(), Err(SpecError::NotForSites("artifact.grow_gb")));

            let mut s = site_spec();
            s.artifact = Some(ArtifactSpec { image_name: Some("web".into()), ..base });
            assert_eq!(s.validate(), Err(SpecError::NotForSites("artifact.image_name")));
        }

        /// And the reverse: a guest rootfs is one file, so there is nothing for
        /// `strip_components` to strip.
        #[test]
        fn strip_components_is_refused_off_a_site() {
            let mut s = spec();
            s.artifact = Some(ArtifactSpec {
                strip_components: Some(1),
                ..artifact_spec()
            });
            assert_eq!(
                s.validate(),
                Err(SpecError::OnlyForSites("artifact.strip_components"))
            );
        }

        /// Both blocks write the files under `site.root`, so a site holding both
        /// has no answer to where what it is serving came from — the same
        /// reasoning that refuses `build` next to `artifact` on a VM.
        #[test]
        fn a_site_deploys_one_way_or_the_other_not_both() {
            let mut s = site_spec();
            s.update = Some(
                serde_json::from_str(r#"{"working_dir":"/srv/docs","commands":["make"]}"#)
                    .unwrap(),
            );
            s.artifact = Some(
                serde_json::from_str(r#"{"store":"/srv/artifacts","ref":"docs-live"}"#).unwrap(),
            );
            assert_eq!(s.validate(), Err(SpecError::BothSiteSources));
        }

        #[test]
        fn the_root_must_be_absolute_and_present() {
            let mut s = site_spec();
            s.site.as_mut().unwrap().root = "  ".into();
            assert_eq!(s.validate(), Err(SpecError::EmptySiteRoot));

            let mut s = site_spec();
            s.site.as_mut().unwrap().root = "www".into();
            assert_eq!(
                s.validate(),
                Err(SpecError::RelativeSiteRoot("www".into())),
                "a relative root would resolve against app-lb's working directory",
            );
        }

        /// `index` and `not_found` are joined onto the root, so a climbing or
        /// rooted value would read a file the site never meant to expose.
        #[test]
        fn the_index_and_404_page_cannot_escape_the_root() {
            for (field, value) in [("index", "../../etc/passwd"), ("not_found", "/etc/passwd")] {
                let mut s = site_spec();
                match field {
                    "index" => s.site.as_mut().unwrap().index = value.into(),
                    _ => s.site.as_mut().unwrap().not_found = Some(value.into()),
                }
                assert_eq!(
                    s.validate(),
                    Err(SpecError::BadSitePath {
                        field,
                        value: value.into()
                    }),
                );
            }
        }

        #[test]
        fn spa_mode_needs_an_index_to_fall_back_to() {
            let mut s = site_spec();
            s.site.as_mut().unwrap().spa = true;
            s.site.as_mut().unwrap().index = "".into();
            assert_eq!(s.validate(), Err(SpecError::SpaWithoutIndex));
        }

        /// A site is only reachable through the proxy, so an unrouted one is
        /// dead weight — the same reasoning as a static deployment.
        #[test]
        fn a_site_needs_a_route() {
            let mut s = site_spec();
            s.routes.clear();
            assert_eq!(s.validate(), Err(SpecError::NoRoutes));
        }

        #[test]
        fn the_defaults_are_what_a_build_output_wants() {
            let s: SiteSpec = serde_json::from_str(r#"{"root":"/var/www"}"#).unwrap();
            assert_eq!(s.index, "index.html");
            assert_eq!(s.cache_control, "public, max-age=300");
            assert!(!s.spa, "SPA mode turns every typo into a 200; opt in");
            assert_eq!(s.not_found, None);
        }
    }

    /// The agent-sandbox shape: a managed VM with no ingress at all, reached
    /// only through exec/shell. It is the *common* case at fleet scale, so it
    /// has to validate rather than being a special case someone works around.
    #[test]
    fn a_managed_deployment_may_have_no_routes() {
        let mut s = spec();
        s.routes.clear();
        assert_eq!(s.validate(), Ok(()));
    }

    /// The same shape is meaningless for a static deployment: the proxy is the
    /// only way in, so no route means nothing can ever reach it.
    #[test]
    fn a_static_deployment_may_not() {
        let mut s = static_spec(&["127.0.0.1:9000"]);
        s.routes.clear();
        assert_eq!(s.validate(), Err(SpecError::NoRoutes));
    }

    /// A gate runs on a proxied request. With no routes there are none, and the
    /// callback-routability check would otherwise reject this while talking
    /// about a path the author never wrote.
    #[test]
    fn a_gate_needs_something_to_gate() {
        let mut s = spec();
        s.routes.clear();
        s.auth = Some(auth_gate());
        assert_eq!(s.validate(), Err(SpecError::AuthWithoutRoutes));
    }

    #[test]
    fn empty_rule_matches_nothing() {
        assert!(!RouteRule::default().matches(Some("a.local"), "/"));
    }

    #[test]
    fn host_match_is_case_insensitive() {
        let r = RouteRule {
            host: Some("Demo.Local".into()),
            host_suffix: None,
            path_prefix: None,
            strip_prefix: false,
        };
        assert!(r.matches(Some("demo.local"), "/"));
        assert!(r.matches(Some("DEMO.LOCAL"), "/"));
        assert!(!r.matches(Some("other.local"), "/"));
        assert!(!r.matches(None, "/"));
    }

    #[test]
    fn host_and_path_must_both_match() {
        let r = RouteRule {
            host: Some("demo.local".into()),
            host_suffix: None,
            path_prefix: Some("/api".into()),
            strip_prefix: false,
        };
        assert!(r.matches(Some("demo.local"), "/api/v1"));
        assert!(!r.matches(Some("demo.local"), "/web"));
        assert!(!r.matches(Some("other.local"), "/api/v1"));
    }

    #[test]
    fn host_suffix_matches_apex_and_subdomains_at_a_label_boundary() {
        let r = RouteRule {
            host: None,
            host_suffix: Some("apps.example.com".into()),
            path_prefix: None,
            strip_prefix: false,
        };
        // Apex and any depth of subdomain.
        assert!(r.matches(Some("apps.example.com"), "/"));
        assert!(r.matches(Some("a.apps.example.com"), "/"));
        assert!(r.matches(Some("x.y.apps.example.com"), "/"));
        // Case-insensitive.
        assert!(r.matches(Some("A.Apps.Example.Com"), "/"));
        // Boundary is anchored: a label that merely ends with the string is not
        // a subdomain of it.
        assert!(!r.matches(Some("notapps.example.com"), "/"));
        assert!(!r.matches(Some("example.com"), "/"));
        assert!(!r.matches(None, "/"));
    }

    #[test]
    fn host_suffix_accepts_a_leading_dot() {
        let r = RouteRule {
            host: None,
            host_suffix: Some(".example.com".into()),
            path_prefix: None,
            strip_prefix: false,
        };
        assert!(r.matches(Some("a.example.com"), "/"));
        assert!(r.matches(Some("example.com"), "/"));
    }

    #[test]
    fn host_suffix_and_path_must_both_match() {
        let r = RouteRule {
            host: None,
            host_suffix: Some("example.com".into()),
            path_prefix: Some("/api".into()),
            strip_prefix: false,
        };
        assert!(r.matches(Some("a.example.com"), "/api/v1"));
        assert!(!r.matches(Some("a.example.com"), "/web"));
        assert!(!r.matches(Some("a.other.com"), "/api/v1"));
    }

    #[test]
    fn exact_host_outranks_subdomain_outranks_path() {
        let exact = RouteRule {
            host: Some("a.example.com".into()),
            host_suffix: None,
            path_prefix: None,
            strip_prefix: false,
        };
        let wild = RouteRule {
            host: None,
            host_suffix: Some("example.com".into()),
            path_prefix: None,
            strip_prefix: false,
        };
        let long_wild = RouteRule {
            host: None,
            host_suffix: Some("apps.example.com".into()),
            path_prefix: None,
            strip_prefix: false,
        };
        let path_only = RouteRule {
            host: None,
            host_suffix: None,
            path_prefix: Some("/some/long/path".into()),
            strip_prefix: false,
        };
        assert!(exact.specificity() > long_wild.specificity());
        assert!(long_wild.specificity() > wild.specificity(), "longer suffix wins");
        assert!(wild.specificity() > path_only.specificity(), "subdomain beats path");
    }

    #[test]
    fn empty_and_dot_only_suffix_match_nothing() {
        assert!(RouteRule::default().is_empty());
        let dot = RouteRule {
            host: None,
            host_suffix: Some(".".into()),
            path_prefix: None,
            strip_prefix: false,
        };
        assert!(!dot.is_empty(), "a suffix field is set");
        assert!(!dot.matches(Some("example.com"), "/"), "but it matches nothing");
    }

    #[test]
    fn host_outranks_path_and_longer_prefix_wins() {
        let host_only = RouteRule {
            host: Some("a".into()),
            host_suffix: None,
            path_prefix: None,
            strip_prefix: false,
        };
        let long_path = RouteRule {
            host: None,
            host_suffix: None,
            path_prefix: Some("/a/very/long/prefix".into()),
            strip_prefix: false,
        };
        let short_path = RouteRule {
            host: None,
            host_suffix: None,
            path_prefix: Some("/a".into()),
            strip_prefix: false,
        };
        assert!(host_only.specificity() > long_path.specificity());
        assert!(long_path.specificity() > short_path.specificity());
    }

    // -- guest mounts ------------------------------------------------------

    #[test]
    fn a_mount_needs_an_absolute_traversal_free_path() {
        for (path, fragment) in [
            ("", "must not be empty"),
            ("data", "absolute"),
            ("/", "root directory"),
            ("/data/../etc", "'..'"),
            ("/data//corpus", "empty path segment"),
            ("/data/my corpus", "may contain only"),
        ] {
            let err = spec_with_mounts(vec![a_mount(path)]).validate().unwrap_err();
            let SpecError::BadMountPath { why, .. } = &err else {
                panic!("{path:?} was accepted or misclassified: {err}");
            };
            assert!(why.contains(fragment), "{path:?}: {why}");
        }
    }

    /// The guest's own directories, and heyvm's. Mounting over any of them
    /// produces a VM that fails in a way whose message names none of this.
    #[test]
    fn the_guests_own_directories_are_refused() {
        for path in ["/proc", "/sys/fs", "/dev", "/boot", "/run", "/workspace"] {
            let err = spec_with_mounts(vec![a_mount(path)]).validate().unwrap_err();
            assert!(
                matches!(&err, SpecError::BadMountPath { why, .. } if why.contains("reserved")),
                "{path} was accepted: {err}",
            );
        }
        // A path that merely *starts with* a reserved name is not one of them.
        spec_with_mounts(vec![a_mount("/development")]).validate().unwrap();
        spec_with_mounts(vec![a_mount("/workspaces/data")]).validate().unwrap();
    }

    #[test]
    fn two_mounts_cannot_share_or_nest_a_path() {
        let err = spec_with_mounts(vec![a_mount("/data"), a_mount("/data")])
            .validate()
            .unwrap_err();
        assert_eq!(err, SpecError::DuplicateMountPath("/data".into()));

        // A trailing slash is the same path, not a different one.
        let err = spec_with_mounts(vec![a_mount("/data"), a_mount("/data/")])
            .validate()
            .unwrap_err();
        assert_eq!(err, SpecError::DuplicateMountPath("/data".into()));

        // Nesting, in both orders: the guest mounts them in array order, so the
        // inner one is hidden whichever way round they are declared.
        for pair in [["/data", "/data/corpus"], ["/data/corpus", "/data"]] {
            let err = spec_with_mounts(vec![a_mount(pair[0]), a_mount(pair[1])])
                .validate()
                .unwrap_err();
            assert_eq!(
                err,
                SpecError::NestedMountPath {
                    outer: "/data".into(),
                    inner: "/data/corpus".into(),
                },
                "{pair:?}",
            );
        }

        // Sharing a prefix without nesting is fine.
        spec_with_mounts(vec![a_mount("/data"), a_mount("/database")])
            .validate()
            .unwrap();
    }

    #[test]
    fn there_is_a_ceiling_on_how_many_mounts_a_guest_gets() {
        let many: Vec<MountSpec> = (0..=MAX_MOUNTS)
            .map(|i| a_mount(&format!("/data{i}")))
            .collect();
        assert_eq!(
            spec_with_mounts(many).validate().unwrap_err(),
            SpecError::TooManyMounts {
                count: MAX_MOUNTS + 1,
                max: MAX_MOUNTS,
            },
        );

        let exactly: Vec<MountSpec> = (0..MAX_MOUNTS)
            .map(|i| a_mount(&format!("/data{i}")))
            .collect();
        spec_with_mounts(exactly).validate().unwrap();
    }

    #[test]
    fn a_mounts_store_and_ref_are_held_to_the_artifact_rules() {
        for store in ["", "   ", "relative/store", "ftp://example.com", "/srv/../etc"] {
            let mut m = a_mount("/data");
            m.store = store.into();
            let err = spec_with_mounts(vec![m]).validate().unwrap_err();
            assert!(
                matches!(&err, SpecError::BadMountStore { path, .. } if path == "/data"),
                "{store:?} was accepted: {err}",
            );
        }

        for reference in ["", "-leading-dash", ".leading-dot", "Has/Upper", "a//b", "has space"] {
            let mut m = a_mount("/data");
            m.artifact_ref = reference.into();
            let err = spec_with_mounts(vec![m]).validate().unwrap_err();
            assert!(
                matches!(&err, SpecError::BadMountRef { path, .. } if path == "/data"),
                "{reference:?} was accepted: {err}",
            );
        }

        // Both spellings a store accepts.
        for reference in ["corpus-2026.08_v3", &"a1b2c3d4".repeat(8)] {
            let mut m = a_mount("/data");
            m.artifact_ref = reference.into();
            spec_with_mounts(vec![m]).validate().unwrap();
        }
    }

    /// A pinned digest names a tree by its filename, so a value that is not a
    /// sha256 could never name one.
    #[test]
    fn a_pinned_digest_must_be_a_sha256() {
        for digest in ["deadbeef", &"A1B2C3D4".repeat(8), &"g".repeat(64), &"ab".repeat(33)] {
            let mut m = a_mount("/data");
            m.digest = Some(digest.into());
            let err = spec_with_mounts(vec![m]).validate().unwrap_err();
            assert!(
                matches!(&err, SpecError::BadMountDigest { path, .. } if path == "/data"),
                "{digest:?} was accepted: {err}",
            );
        }

        let mut m = a_mount("/data");
        m.digest = Some("0f1e2d3c4b5a".repeat(5) + "abcd");
        assert_eq!(m.digest.as_ref().unwrap().len(), 64);
        spec_with_mounts(vec![m]).validate().unwrap();
    }

    /// The one rule that depends on the driver: the KVM backend syncs a
    /// read-write mount image back into the host directory when the VM stops,
    /// and that directory is shared by every replica.
    #[test]
    fn a_writable_mount_is_refused_on_kvm_and_allowed_on_firecracker() {
        let writable = MountSpec {
            read_only: false,
            ..a_mount("/scratch")
        };

        let mut on_kvm = spec_with_mounts(vec![writable.clone()]);
        on_kvm.vm.as_mut().unwrap().driver = Driver::Kvm;
        let err = on_kvm.validate().unwrap_err();
        assert_eq!(err, SpecError::WritableMountOnKvm("/scratch".into()));
        let message = err.to_string();
        assert!(message.contains("firecracker"), "{message}");

        spec_with_mounts(vec![writable]).validate().unwrap();

        // Read-only is fine on both.
        let mut ro_on_kvm = spec_with_mounts(vec![a_mount("/data")]);
        ro_on_kvm.vm.as_mut().unwrap().driver = Driver::Kvm;
        ro_on_kvm.validate().unwrap();
    }

    /// A mount is read-only unless the spec says otherwise, and that has to hold
    /// for the spelling an operator actually writes — a YAML block with no
    /// `read_only` key at all.
    #[test]
    fn a_mount_deserializes_read_only_by_default() {
        let m: MountSpec = serde_json::from_value(serde_json::json!({
            "path": "/data",
            "store": "/srv/artifacts",
            "ref": "corpus",
        }))
        .unwrap();
        assert!(m.read_only);
        assert_eq!(m.strip(), 0);
        assert!(!m.is_remote());
        assert_eq!(m.digest, None);

        let remote: MountSpec = serde_json::from_value(serde_json::json!({
            "path": "/data/",
            "store": "https://art.example.com/",
            "ref": "corpus",
            "read_only": false,
            "strip_components": 2,
        }))
        .unwrap();
        assert!(!remote.read_only);
        assert_eq!(remote.strip(), 2);
        assert!(remote.is_remote());
        assert_eq!(remote.guest_path(), "/data", "the trailing slash is not part of it");
    }

    /// Mounts are part of the VM *template*, which is what makes an edit to them
    /// recycle the pool: the update path compares `old.spec.vm != new.spec.vm`.
    #[test]
    fn changing_a_mount_changes_the_template() {
        let before = spec_with_mounts(vec![a_mount("/data")]);
        let mut after = before.clone();
        after.vm.as_mut().unwrap().mounts[0].digest = Some("ab".repeat(32));
        assert_ne!(before.vm, after.vm, "a resolved digest must move the pool");

        let mut moved = before.clone();
        moved.vm.as_mut().unwrap().mounts[0].path = "/data2".into();
        assert_ne!(before.vm, moved.vm);

        assert_eq!(before.vm, spec_with_mounts(vec![a_mount("/data")]).vm);
    }

    /// An empty list is absent on the wire, so a deployment that never heard of
    /// mounts serializes exactly as it did before they existed.
    #[test]
    fn mounts_are_absent_from_the_wire_when_there_are_none() {
        let json = serde_json::to_value(spec()).unwrap();
        assert!(json["vm"].get("mounts").is_none(), "{json}");

        let with = serde_json::to_value(spec_with_mounts(vec![a_mount("/data")])).unwrap();
        assert_eq!(with["vm"]["mounts"][0]["path"], "/data");
        assert_eq!(with["vm"]["mounts"][0]["ref"], "corpus");
        assert_eq!(with["vm"]["mounts"][0]["read_only"], true);
        assert!(
            with["vm"]["mounts"][0].get("digest").is_none(),
            "an unpulled mount carries no digest",
        );
    }

    // -- workspaces --------------------------------------------------------

    mod workspaces {
        use super::*;

        fn with_workspace(ws: serde_json::Value) -> DeploymentSpec {
            let mut s = spec();
            s.vm.as_mut().unwrap().workspace = Some(serde_json::from_value(ws).unwrap());
            s.scaling.max_replicas = 1;
            s.scaling.warm_pool = 0;
            s
        }

        #[test]
        fn the_three_store_forms_parse_and_nothing_else_does() {
            let ws = |store: &str| WorkspaceSpec {
                path: None,
                store: store.into(),
                artifact_ref: None,
                auth: None,
                snapshot_interval_secs: None,
            };
            assert_eq!(
                ws("s3://my-bucket/ws/").backend(),
                Some(WorkspaceStore::S3 {
                    bucket: "my-bucket".into(),
                    prefix: "ws".into()
                })
            );
            assert_eq!(
                ws("s3://my-bucket").backend(),
                Some(WorkspaceStore::S3 {
                    bucket: "my-bucket".into(),
                    prefix: String::new()
                })
            );
            assert_eq!(
                ws("https://art.example.com/").backend(),
                Some(WorkspaceStore::Remote("https://art.example.com".into()))
            );
            assert_eq!(
                ws("/srv/artifacts").backend(),
                Some(WorkspaceStore::Local("/srv/artifacts".into()))
            );
            assert_eq!(ws("s3://").backend(), None);
            assert_eq!(ws("s3://Bad_Bucket").backend(), None);
            assert_eq!(ws("ftp://x").backend(), None);
            assert_eq!(ws("relative/path").backend(), None);
        }

        #[test]
        fn defaults_are_workspace_and_a_tag_named_after_the_deployment() {
            let s = with_workspace(serde_json::json!({"store": "s3://b"}));
            let ws = s.vm.as_ref().unwrap().workspace.as_ref().unwrap();
            assert_eq!(ws.guest_path(), "/workspace");
            assert_eq!(ws.tag("fastcar"), "workspace-fastcar");
            s.validate().expect("the minimal workspace is valid");

            let s = with_workspace(
                serde_json::json!({"store": "https://art", "ref": "fc-ws", "path": "/data/"}),
            );
            let ws = s.vm.as_ref().unwrap().workspace.as_ref().unwrap();
            assert_eq!(ws.guest_path(), "/data");
            assert_eq!(ws.tag("fastcar"), "fc-ws");
            s.validate().unwrap();
        }

        #[test]
        fn a_snapshot_interval_has_a_floor() {
            let s = with_workspace(serde_json::json!({"store": "s3://b", "snapshot_interval_secs": 21600}));
            s.validate().expect("six hours is fine");
            let ws = s.vm.as_ref().unwrap().workspace.as_ref().unwrap();
            assert_eq!(ws.snapshot_interval_secs, Some(21600));

            let s = with_workspace(serde_json::json!({"store": "s3://b", "snapshot_interval_secs": 60}));
            assert!(matches!(s.validate(), Err(SpecError::WorkspaceSnapshotInterval(60))));

            let s = with_workspace(serde_json::json!({"store": "s3://b"}));
            let ws = s.vm.as_ref().unwrap().workspace.as_ref().unwrap();
            assert_eq!(ws.snapshot_interval_secs, None, "unset stays unset");
            assert!(!serde_json::to_string(ws).unwrap().contains("snapshot_interval_secs"));
        }

        #[test]
        fn one_writer_only() {
            let mut s = with_workspace(serde_json::json!({"store": "s3://b"}));
            s.scaling.min_replicas = 0;
            s.scaling.max_replicas = 0;
            s.scaling.idle_action = IdleAction::Retain;
            s.validate().expect("a retained workspace can pause without another writer");
            s.scaling.min_replicas = 1;
            assert!(s.validate().is_err(), "a paused ceiling cannot retain a running minimum");

            let mut s = with_workspace(serde_json::json!({"store": "s3://b"}));
            s.scaling.max_replicas = 2;
            assert!(matches!(s.validate(), Err(SpecError::WorkspaceReplicas(2))));

            let mut s = with_workspace(serde_json::json!({"store": "s3://b"}));
            s.scaling.warm_pool = 1;
            assert!(matches!(s.validate(), Err(SpecError::WorkspaceWarmPool(1))));

            let mut s = with_workspace(serde_json::json!({"store": "s3://b"}));
            s.vm.as_mut().unwrap().driver = Driver::Kvm;
            assert!(matches!(s.validate(), Err(SpecError::WorkspaceDriver(_))));
        }

        #[test]
        fn workspace_is_allowed_for_the_workspace_but_still_not_for_a_mount() {
            let s = with_workspace(serde_json::json!({"store": "s3://b", "path": "/workspace"}));
            s.validate().unwrap();
            let s = with_workspace(serde_json::json!({"store": "s3://b", "path": "/proc/x"}));
            assert!(matches!(s.validate(), Err(SpecError::BadWorkspacePath { .. })));
            let s = with_workspace(serde_json::json!({"store": "s3://b", "path": "relative"}));
            assert!(matches!(s.validate(), Err(SpecError::BadWorkspacePath { .. })));
        }

        #[test]
        fn a_mount_may_not_overlap_the_workspace() {
            let mut s = with_workspace(serde_json::json!({"store": "s3://b", "path": "/data"}));
            s.vm.as_mut().unwrap().mounts = vec![a_mount("/data/corpus")];
            assert!(matches!(s.validate(), Err(SpecError::WorkspaceCollidesWithMount { .. })));
            let mut s = with_workspace(serde_json::json!({"store": "s3://b", "path": "/data/ws"}));
            s.vm.as_mut().unwrap().mounts = vec![a_mount("/data")];
            assert!(matches!(s.validate(), Err(SpecError::WorkspaceCollidesWithMount { .. })));
            let mut s = with_workspace(serde_json::json!({"store": "s3://b"}));
            s.vm.as_mut().unwrap().mounts = vec![a_mount("/data")];
            s.validate().unwrap();
        }

        #[test]
        fn bad_store_and_ref_are_named() {
            let s = with_workspace(serde_json::json!({"store": "nope"}));
            assert!(matches!(s.validate(), Err(SpecError::BadWorkspaceStore(_))));
            let s = with_workspace(serde_json::json!({"store": "s3://b", "ref": "-x"}));
            assert!(matches!(s.validate(), Err(SpecError::BadWorkspaceRef(_))));
        }

        /// Absent from the wire when unset, so existing specs round-trip
        /// byte-for-byte.
        #[test]
        fn absent_when_unset_and_a_template_change_when_set() {
            let json = serde_json::to_value(spec()).unwrap();
            assert!(json["vm"].get("workspace").is_none(), "{json}");
            let with = with_workspace(serde_json::json!({"store": "s3://b"}));
            assert_ne!(spec().vm, with.vm, "adding a workspace must recycle the pool");
            let json = serde_json::to_value(&with).unwrap();
            assert_eq!(json["vm"]["workspace"]["store"], "s3://b");
            assert!(json["vm"]["workspace"].get("path").is_none());
        }
    }

    // -- JWT gates ---------------------------------------------------------

    mod jwt_gates {
        use super::*;

        /// A spec whose `auth.jwt` block is the given JSON, otherwise valid.
        fn with_jwt(provider: &str, jwt: serde_json::Value) -> DeploymentSpec {
            let mut s = spec();
            let mut gate = serde_json::json!({
                "provider": serde_json::from_str::<serde_json::Value>(provider).unwrap(),
                "base_path": "/__applb/auth",
            });
            if provider.contains("google") {
                gate["client_id"] = serde_json::json!("cid.apps.googleusercontent.com");
                gate["client_secret"] = serde_json::json!({"secret": "google"});
                gate["allowed_domains"] = serde_json::json!(["example.com"]);
            }
            if !jwt.is_null() {
                gate["jwt"] = jwt;
            }
            s.auth = Some(serde_json::from_value(gate).expect("the gate parses"));
            s
        }

        fn heyo_block() -> serde_json::Value {
            serde_json::json!({
                "secret": {"secret": "heyo-auth", "key": "jwt_secret"},
                "algorithms": ["HS256"],
                "issuer": "auth-service",
                "audience": "heyo-app",
                "subject_claim": "userId",
            })
        }

        #[test]
        fn browser_login_requires_cookie_and_safe_issuer_transport() {
            for endpoint in ["http://issuer.example/login", "https://user:pass@issuer.example/login", "https://issuer.example/login#fragment", "https://issuer.example/login?token=x", "file:///login"] {
                let mut block = heyo_block();
                block["cookie"] = serde_json::json!("heyo_login");
                block["login_endpoint"] = serde_json::json!(endpoint);
                assert!(matches!(with_jwt(r#""jwt""#, block).validate(), Err(SpecError::BadJwtLoginEndpoint)), "{endpoint}");
            }
            let mut block = heyo_block();
            block["login_endpoint"] = serde_json::json!("https://stage.heyo.computer/api/auth/login");
            assert!(matches!(with_jwt(r#""jwt""#, block.clone()).validate(), Err(SpecError::BadJwtLoginEndpoint)));
            block["cookie"] = serde_json::json!("heyo_login");
            with_jwt(r#""jwt""#, block).validate().unwrap();
        }

        /// The shape a Heyo auth API gate is actually written in.
        #[test]
        fn the_heyo_auth_api_gate_is_a_valid_spec() {
            with_jwt(r#""jwt""#, heyo_block()).validate().unwrap();

            let gate = with_jwt(r#""jwt""#, heyo_block()).auth.unwrap();
            let jwt = gate.jwt_policy().expect("the policy is reachable");
            assert!(jwt.accepts(crate::jwt::Algorithm::Hs256));
            assert!(!jwt.accepts(crate::jwt::Algorithm::Hs512));
            assert_eq!(jwt.subject_claim, "userId");
            // The defaults nobody wrote down.
            assert_eq!(jwt.email_claim, "email");
            assert_eq!(jwt.name_claim, "name");
            assert_eq!(jwt.leeway_secs(), 0);
        }

        #[test]
        fn a_gate_needs_exactly_one_source_of_key_material() {
            let mut none = heyo_block();
            none.as_object_mut().unwrap().remove("secret");
            assert_eq!(
                with_jwt(r#""jwt""#, none).validate().unwrap_err(),
                SpecError::NoJwtKey,
            );

            let mut two = heyo_block();
            two["jwks_url"] = serde_json::json!("https://idp.example.com/.well-known/jwks.json");
            let err = with_jwt(r#""jwt""#, two).validate().unwrap_err();
            assert!(
                matches!(&err, SpecError::AmbiguousJwtKey(fields) if fields.len() == 2),
                "{err}",
            );
        }

        /// The provider and the block have to agree, in both directions —
        /// neither a policy nothing consults nor a provider with no policy.
        #[test]
        fn the_provider_and_the_block_must_agree() {
            assert_eq!(
                with_jwt(r#""jwt""#, serde_json::Value::Null).validate().unwrap_err(),
                SpecError::JwtWithoutPolicy,
            );
            assert_eq!(
                with_jwt(r#""google""#, heyo_block()).validate().unwrap_err(),
                SpecError::JwtPolicyWithoutProvider,
            );
        }

        /// Hosted sign-in: a `login_url` needs a cookie to carry the token back,
        /// must be https (loopback http aside), and is otherwise accepted.
        #[test]
        fn a_hosted_login_url_needs_a_cookie_and_https() {
            // login_url without a cookie loops forever, so it is refused.
            let mut no_cookie = heyo_block();
            no_cookie["login_url"] = serde_json::json!("https://auth.example.com/login");
            assert_eq!(
                with_jwt(r#""jwt""#, no_cookie).validate().unwrap_err(),
                SpecError::LoginUrlWithoutCookie,
            );

            // Plaintext to another host is a redirect an attacker can intercept.
            let mut plaintext = heyo_block();
            plaintext["cookie"] = serde_json::json!("heyo_access_token");
            plaintext["login_url"] = serde_json::json!("http://auth.example.com/login");
            assert!(matches!(
                with_jwt(r#""jwt""#, plaintext).validate().unwrap_err(),
                SpecError::BadLoginUrl(_),
            ));

            // https with a cookie is the shape that works.
            let mut ok = heyo_block();
            ok["cookie"] = serde_json::json!("heyo_access_token");
            ok["login_url"] = serde_json::json!("https://auth.example.com/login");
            assert_eq!(with_jwt(r#""jwt""#, ok).validate(), Ok(()));
        }

        /// Scoped sign-in: both endpoints or neither, https (loopback http
        /// aside), and never alongside a shared session realm.
        #[test]
        fn scoped_signin_needs_both_https_endpoints_and_no_realm() {
            let mut half = heyo_block();
            half["authorize_url"] = serde_json::json!("https://auth.example.com/oauth/authorize");
            assert_eq!(
                with_jwt(r#""jwt""#, half).validate().unwrap_err(),
                SpecError::ScopedSigninIncomplete,
            );

            let mut plaintext = heyo_block();
            plaintext["authorize_url"] = serde_json::json!("https://auth.example.com/oauth/authorize");
            plaintext["token_url"] = serde_json::json!("http://auth.example.com/oauth/token");
            assert!(matches!(
                with_jwt(r#""jwt""#, plaintext).validate().unwrap_err(),
                SpecError::BadScopedSignin(_),
            ));

            let mut ok = heyo_block();
            ok["authorize_url"] = serde_json::json!("https://auth.example.com/oauth/authorize");
            ok["token_url"] = serde_json::json!("http://127.0.0.1:3001/oauth/token");
            assert_eq!(with_jwt(r#""jwt""#, ok.clone()).validate(), Ok(()));

            let mut realm = with_jwt(r#""jwt""#, ok);
            realm.auth.as_mut().unwrap().cookie_domain = Some("example.com".into());
            assert_eq!(realm.validate().unwrap_err(), SpecError::ScopedSigninWithRealm);
        }

        /// `algorithms` has no default, because the only available default would
        /// be "whatever the token says".
        #[test]
        fn algorithms_are_required_and_checked() {
            let mut empty = heyo_block();
            empty["algorithms"] = serde_json::json!([]);
            assert_eq!(
                with_jwt(r#""jwt""#, empty).validate().unwrap_err(),
                SpecError::NoJwtAlgorithms,
            );

            for bad in ["none", "NONE", "HS128", "RSA256", ""] {
                let mut block = heyo_block();
                block["algorithms"] = serde_json::json!([bad]);
                assert_eq!(
                    with_jwt(r#""jwt""#, block).validate().unwrap_err(),
                    SpecError::BadJwtAlgorithm(bad.to_string()),
                    "{bad:?} was accepted as an algorithm",
                );
            }
        }

        /// The written-down form of the algorithm-confusion attack: a public key
        /// alongside an HMAC algorithm. Refused at registration, so it cannot
        /// reach the verifier at all.
        #[test]
        fn an_algorithm_must_match_the_kind_of_key_configured() {
            let mut block = heyo_block();
            block["algorithms"] = serde_json::json!(["RS256"]);
            let err = with_jwt(r#""jwt""#, block).validate().unwrap_err();
            assert!(
                matches!(&err, SpecError::JwtAlgorithmKeyMismatch { symmetric_key: true, .. }),
                "{err}",
            );
            assert!(err.to_string().contains("jwks_url"), "{err}");

            let mut block = heyo_block();
            block.as_object_mut().unwrap().remove("secret");
            block["jwks_url"] = serde_json::json!("https://idp.example.com/.well-known/jwks.json");
            block["algorithms"] = serde_json::json!(["HS256"]);
            let err = with_jwt(r#""jwt""#, block).validate().unwrap_err();
            assert!(
                matches!(&err, SpecError::JwtAlgorithmKeyMismatch { symmetric_key: false, .. }),
                "{err}",
            );
            assert!(
                err.to_string().contains("algorithm-confusion"),
                "the message has to say why, not just no: {err}",
            );
        }

        #[test]
        fn an_issuer_is_required_and_exact() {
            let mut block = heyo_block();
            block.as_object_mut().unwrap().remove("issuer");
            // A block with no issuer at all does not even deserialize, which is
            // the strongest form of "required" available.
            let gate = serde_json::json!({"provider": "jwt", "jwt": block});
            assert!(serde_json::from_value::<AuthGate>(gate).is_err());

            for bad in ["", "  ", " auth-service", "auth-service "] {
                let mut block = heyo_block();
                block["issuer"] = serde_json::json!(bad);
                assert_eq!(
                    with_jwt(r#""jwt""#, block).validate().unwrap_err(),
                    SpecError::BadJwtIssuer(bad.to_string()),
                );
            }
        }

        #[test]
        fn a_jwks_url_must_be_one() {
            for bad in ["", "idp.example.com/jwks", "ftp://idp/jwks", "https://a b/jwks"] {
                let mut block = heyo_block();
                block.as_object_mut().unwrap().remove("secret");
                block["jwks_url"] = serde_json::json!(bad);
                block["algorithms"] = serde_json::json!(["RS256"]);
                assert!(
                    matches!(
                        with_jwt(r#""jwt""#, block).validate().unwrap_err(),
                        SpecError::BadJwksUrl(_)
                    ),
                    "{bad:?} was accepted as a JWKS URL",
                );
            }

            let mut block = heyo_block();
            block.as_object_mut().unwrap().remove("secret");
            block["jwks_url"] = serde_json::json!("https://idp.example.com/.well-known/jwks.json");
            block["algorithms"] = serde_json::json!(["RS256", "ES256"]);
            with_jwt(r#""jwt""#, block).validate().unwrap();
        }

        /// The key set is what every token is checked against, so rewriting it
        /// mints identities. Plaintext to another host is refused; loopback is
        /// the OAuth carve-out — there is no path to be on.
        #[test]
        fn a_jwks_url_must_be_https_unless_it_is_loopback() {
            let jwks = |url: &str| {
                let mut block = heyo_block();
                block.as_object_mut().unwrap().remove("secret");
                block["jwks_url"] = serde_json::json!(url);
                block["algorithms"] = serde_json::json!(["RS256"]);
                with_jwt(r#""jwt""#, block).validate()
            };

            for url in [
                "http://idp.example.com/.well-known/jwks.json",
                "http://10.0.0.4:8080/jwks",
                "http://localhost.evil.example/jwks",
            ] {
                assert!(
                    matches!(jwks(url), Err(SpecError::InsecureJwksUrl(_))),
                    "{url} was accepted over plaintext",
                );
            }
            assert!(
                jwks("http://idp.example.com/jwks")
                    .unwrap_err()
                    .to_string()
                    .contains("authentication bypass"),
                "the message has to say why plaintext is refused here and not elsewhere",
            );

            for url in [
                "http://127.0.0.1:8080/jwks",
                "http://127.0.0.53/jwks",
                "http://localhost:3000/.well-known/jwks.json",
                "http://[::1]:8080/jwks",
                "https://idp.example.com/jwks",
            ] {
                jwks(url).unwrap_or_else(|e| panic!("{url} was refused: {e}"));
            }
        }

        #[test]
        fn a_public_key_that_will_never_parse_is_caught_at_registration() {
            let mut block = heyo_block();
            block.as_object_mut().unwrap().remove("secret");
            block["public_key"] = serde_json::json!("-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----");
            block["algorithms"] = serde_json::json!(["RS256"]);
            assert!(matches!(
                with_jwt(r#""jwt""#, block).validate().unwrap_err(),
                SpecError::BadJwtPublicKey(_),
            ));
        }

        /// The allow-lists describe a Google identity. On a gate with no Google
        /// provider they would restrict nothing, so a spec carrying them is
        /// refused rather than left looking guarded.
        #[test]
        fn a_google_allow_list_is_refused_on_a_jwt_only_gate() {
            let mut s = with_jwt(r#""jwt""#, heyo_block());
            s.auth.as_mut().unwrap().allowed_emails = vec!["someone@example.com".into()];
            assert_eq!(s.validate().unwrap_err(), SpecError::AllowListOnJwtGate);

            let mut s = with_jwt(r#""jwt""#, heyo_block());
            s.auth.as_mut().unwrap().allowed_domains = vec!["example.com".into()];
            assert_eq!(s.validate().unwrap_err(), SpecError::AllowListOnJwtGate);

            // On a gate that *does* accept Google they are exactly as meaningful
            // as they always were.
            with_jwt(r#"["google","jwt"]"#, heyo_block()).validate().unwrap();
        }

        #[test]
        fn leeway_is_capped_and_claim_names_are_not_empty() {
            let mut block = heyo_block();
            block["leeway_secs"] = serde_json::json!(MAX_JWT_LEEWAY_SECS + 1);
            assert!(matches!(
                with_jwt(r#""jwt""#, block).validate().unwrap_err(),
                SpecError::JwtLeewayTooLarge { .. },
            ));

            for field in ["subject_claim", "email_claim", "name_claim"] {
                let mut block = heyo_block();
                block[field] = serde_json::json!("  ");
                assert_eq!(
                    with_jwt(r#""jwt""#, block).validate().unwrap_err(),
                    SpecError::EmptyJwtClaimName,
                );
            }

            let mut block = heyo_block();
            block["require"] = serde_json::json!({"": "admin"});
            assert_eq!(
                with_jwt(r#""jwt""#, block).validate().unwrap_err(),
                SpecError::EmptyJwtClaimName,
            );
        }

        /// The gate's session signature is keyed on its policy, and a JWT policy
        /// is part of who may enter — so tightening one signs out the sessions
        /// issued under the old one, exactly as tightening an allow-list does.
        #[test]
        fn the_jwt_policy_is_part_of_the_gates_fingerprint() {
            let mixed = |block: serde_json::Value| {
                with_jwt(r#"["google","jwt"]"#, block).auth.unwrap().policy_fingerprint()
            };
            let base = mixed(heyo_block());

            for change in [
                serde_json::json!({"require": {"role": "admin"}}),
                serde_json::json!({"issuer": "someone-else"}),
                serde_json::json!({"audience": "heyo-server"}),
                serde_json::json!({"algorithms": ["HS512"]}),
                serde_json::json!({"secret": {"secret": "other", "key": "jwt_secret"}}),
                serde_json::json!({"subject_claim": "sub"}),
            ] {
                let mut block = heyo_block();
                for (k, v) in change.as_object().unwrap() {
                    block[k] = v.clone();
                }
                assert_ne!(base, mixed(block), "{change} did not move the fingerprint");
            }

            // ...and a gate with no JWT block hashes exactly what it did before
            // the field existed, so an upgrade does not sign anyone out.
            let before = auth_gate().policy_fingerprint();
            assert_ne!(before, base);
        }

        /// A block written with only what is required, to pin the defaults that
        /// fill in the rest.
        #[test]
        fn a_minimal_block_gets_the_documented_defaults() {
            let block = serde_json::json!({
                "jwks_url": "https://idp.example.com/.well-known/jwks.json",
                "algorithms": ["RS256"],
                "issuer": "https://idp.example.com/",
            });
            let s = with_jwt(r#""jwt""#, block);
            s.validate().unwrap();
            let jwt = s.auth.unwrap().jwt.unwrap();
            assert_eq!(jwt.subject_claim, "sub");
            assert_eq!(jwt.email_claim, "email");
            assert_eq!(jwt.audience, None);
            assert!(jwt.require.is_empty(), "an empty require admits any token the issuer signed");
            assert_eq!(jwt.cookie, None);
            assert_eq!(jwt.leeway_secs(), 0);
        }

        /// A gate that never mentions JWTs serializes exactly as it did before
        /// the block existed.
        #[test]
        fn the_block_is_absent_from_the_wire_when_unused() {
            let json = serde_json::to_value(auth_gate()).unwrap();
            assert!(json.get("jwt").is_none(), "{json}");

            let with = serde_json::to_value(with_jwt(r#""jwt""#, heyo_block()).auth.unwrap()).unwrap();
            assert_eq!(with["jwt"]["issuer"], "auth-service");
            assert_eq!(with["jwt"]["subject_claim"], "userId");
            // Defaults are written out, so reading a spec back shows what is in
            // force rather than what somebody happened to type.
            assert_eq!(with["jwt"]["email_claim"], "email");
            assert!(with["jwt"].get("require").is_none(), "an empty require is not written");
        }
    }

    /// The generated JSON Schema for `DeploymentSpec`, as a checked-in file.
    ///
    /// Written from the types themselves rather than transcribed, because
    /// transcription is what went wrong every previous time: the TypeScript SDK
    /// omits `ingress` and still lists `libvirt` as a driver, and `heyctl`'s
    /// mirror lost five fields without a test failing. A generated artifact
    /// cannot drift from its source — it can only be *stale*, which is a diff,
    /// which is a failing test.
    ///
    /// Regenerate with `UPDATE_GOLDEN=1 cargo test --bins schema_golden`, and
    /// read the diff: a changed schema is a changed API, and something
    /// downstream is now describing a shape that no longer exists.
    mod schema_golden {
        use super::*;
        use std::path::PathBuf;

        fn schema_path() -> PathBuf {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schema").join("deployment-spec.json")
        }

        #[test]
        fn the_checked_in_schema_matches_the_types() {
            let schema = schemars::schema_for!(DeploymentSpec);
            let rendered = format!(
                "{}\n",
                serde_json::to_string_pretty(&schema).expect("a schema serializes")
            );
            let path = schema_path();

            if std::env::var("UPDATE_GOLDEN").is_ok() {
                std::fs::create_dir_all(path.parent().expect("schema/ has a parent"))
                    .expect("create schema dir");
                std::fs::write(&path, &rendered).expect("write schema");
                return;
            }

            let current = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!(
                    "{}: {e}\nrun `UPDATE_GOLDEN=1 cargo test --bins schema_golden`",
                    path.display()
                )
            });
            // Deliberately not `assert_eq!`: these are 70 KB documents, and
            // printing both of them buries the one line that matters under a
            // screenful nobody reads. Name what moved instead, and leave the
            // diff to git — which is where the reviewer is going to read it.
            if serde_json::from_str::<serde_json::Value>(&current).expect("recorded schema is JSON")
                != serde_json::from_str::<serde_json::Value>(&rendered).expect("generated schema is JSON")
            {
                let (old, new) = (parse_defs(&current), parse_defs(&rendered));
                let added: Vec<_> = new.iter().filter(|k| !old.contains(*k)).collect();
                let removed: Vec<_> = old.iter().filter(|k| !new.contains(*k)).collect();
                panic!(
                    "the checked-in schema is stale — every client that reads it is now \
                     describing the wrong shape.\n\
                     types added: {added:?}\n\
                     types removed: {removed:?}\n\
                     (an empty pair here means a field or a doc comment moved, not a type)\n\
                     Regenerate with `UPDATE_GOLDEN=1 cargo test --bins schema_golden` \
                     and read the diff.",
                );
            }
        }

        #[test]
        fn the_schema_is_no_stricter_than_the_server() {
            // `DeploymentSpec` carries no `deny_unknown_fields`, and heyctl
            // deliberately edits specs as untyped JSON so a field it has never
            // heard of survives the trip. A schema that forbade unknown keys
            // would make every future field an error in clients that are
            // merely out of date — turning drift from "under-documented" into
            // "valid spec rejected", which is the worse failure by far.
            let schema = serde_json::to_value(schemars::schema_for!(DeploymentSpec))
                .expect("a schema serializes");
            let mut closed = Vec::new();
            find_closed(&schema, String::from("#"), &mut closed);
            assert!(closed.is_empty(), "these object schemas forbid unknown keys: {closed:?}");
        }

        /// The names of the types a rendered schema defines, for a failure
        /// message that says what changed rather than printing both documents.
        fn parse_defs(text: &str) -> Vec<String> {
            serde_json::from_str::<serde_json::Value>(text)
                .ok()
                .and_then(|v| v.get("$defs").and_then(|d| d.as_object()).cloned())
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default()
        }

        /// Every string a unit enum accepts, however schemars chose to render it.
        ///
        /// A variant carrying a doc comment becomes its own `oneOf` branch with
        /// a `const`; variants without one are grouped into a single `enum`
        /// array. A type with some of each — `Driver` — contains both spellings
        /// at once, so a test that assumes either alone is wrong half the time.
        fn enum_values(v: &serde_json::Value) -> Vec<String> {
            let mut out = Vec::new();
            if let Some(one_of) = v.get("oneOf").and_then(|o| o.as_array()) {
                for branch in one_of {
                    out.extend(enum_values(branch));
                }
            }
            if let Some(c) = v.get("const").and_then(|c| c.as_str()) {
                out.push(c.to_string());
            }
            if let Some(values) = v.get("enum").and_then(|e| e.as_array()) {
                out.extend(values.iter().filter_map(|x| x.as_str().map(String::from)));
            }
            out
        }

        fn find_closed(v: &serde_json::Value, at: String, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Object(map) => {
                    if map.get("additionalProperties") == Some(&serde_json::Value::Bool(false)) {
                        out.push(at.clone());
                    }
                    for (k, child) in map {
                        find_closed(child, format!("{at}/{k}"), out);
                    }
                }
                serde_json::Value::Array(items) => {
                    for (i, child) in items.iter().enumerate() {
                        find_closed(child, format!("{at}/{i}"), out);
                    }
                }
                _ => {}
            }
        }

        #[test]
        fn the_awkward_shapes_survived_generation() {
            // The three the derive could not have got right on its own, and the
            // ones a hand-written mirror has always got wrong. If any of these
            // stops holding, the manual impls above have gone stale.
            let schema = serde_json::to_value(schemars::schema_for!(DeploymentSpec))
                .expect("a schema serializes");
            let defs = schema.get("$defs").expect("nested types are defined");

            // A union, not a struct with one field.
            assert!(
                defs["Providers"].get("anyOf").is_some(),
                "auth.provider lost its one-or-many form",
            );
            // A union whose bare form is the *closed* one.
            assert!(defs["PublicPath"].get("anyOf").is_some(), "public_paths lost its bare form");
            assert!(
                defs["PublicPath"]["description"].as_str().is_some_and(|d| d.contains("admin")),
                "public_paths no longer warns that a bare string means admin",
            );
            // Mirrored from another crate, so worth asserting it is still there
            // and still six.
            let sizes = enum_values(&defs["SandboxSize"]);
            assert_eq!(sizes.len(), 6, "the size classes moved: {sizes:?}");
            // `libvirt` and `firecracker_containerd` deserialize and are then
            // refused, so the schema lists them — it describes what parses. The
            // caveat has to travel with them, and it does, because the doc
            // comments say so and doc comments are what a generated schema is
            // made of. That is the whole argument for generating this file.
            let drivers = enum_values(&defs["Driver"]);
            for expected in ["firecracker", "kvm", "lxc", "libvirt"] {
                assert!(drivers.contains(&expected.to_string()), "driver lost {expected}: {drivers:?}");
            }
            let caveat = defs["VmSpec"]["properties"]["driver"]["description"]
                .as_str()
                .expect("the driver field is documented");
            assert!(
                caveat.contains("libvirt") && caveat.contains("rejected"),
                "the driver field no longer warns that two of its values are refused: {caveat}",
            );
        }
    }

    /// The specs in `examples/`, held to the same standard as a real request.
    ///
    /// They ship as ready-to-POST documents and were parsed by nothing: not one
    /// line in this crate ever read them, so an example could name a field that
    /// no longer exists, or describe a deployment the server would refuse, and
    /// stay that way indefinitely. They are also the closest thing this
    /// repository has to a specification by demonstration — the clients that
    /// mirror `DeploymentSpec` read them, and so does anyone learning the shape
    /// — which makes "does it still parse" a contract rather than housekeeping.
    mod examples {
        use super::*;
        use std::path::{Path, PathBuf};

        /// Every `*.json` under `examples/`, including the one in a subdirectory.
        fn example_files() -> Vec<PathBuf> {
            fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
                let entries = std::fs::read_dir(dir)
                    .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        walk(&path, out);
                    } else if path.extension().is_some_and(|e| e == "json") {
                        out.push(path);
                    }
                }
            }
            let mut out = Vec::new();
            walk(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples"), &mut out);
            out.sort();
            out
        }

        #[test]
        fn every_example_parses_and_validates() {
            let files = example_files();
            assert!(!files.is_empty(), "no examples found — did the directory move?");

            for path in files {
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                let mut spec: DeploymentSpec = serde_json::from_str(&text).unwrap_or_else(|e| {
                    panic!("{} is not a DeploymentSpec: {e}", path.display())
                });
                // Through the same front door a POST takes: `normalize` runs
                // first on every entry path, so validating without it would
                // hold the examples to a stricter standard than real requests.
                spec.normalize();
                if let Err(e) = spec.validate() {
                    panic!("{} would be refused by the server: {e}", path.display());
                }
            }
        }

        #[test]
        fn an_example_does_not_quietly_lose_fields() {
            // Round-tripping catches the other half: a key the server no longer
            // deserializes parses fine and vanishes. `skip_serializing_if` is on
            // nearly every field, so this compares only what was actually
            // written — an example that omits a field stays legal, one that
            // names a field into the void does not.
            for path in example_files() {
                let text = std::fs::read_to_string(&path).expect("read example");
                let raw: serde_json::Value = serde_json::from_str(&text).expect("example is JSON");
                let spec: DeploymentSpec = serde_json::from_str(&text).expect("example is a spec");
                let round: serde_json::Value =
                    serde_json::to_value(&spec).expect("a spec serializes");

                let (raw_obj, round_obj) = (
                    raw.as_object().expect("an example is an object"),
                    round.as_object().expect("a spec serializes to an object"),
                );
                for key in raw_obj.keys() {
                    assert!(
                        round_obj.contains_key(key),
                        "{}: `{key}` was accepted and then dropped — the field is gone from \
                         DeploymentSpec and this example is describing something that no \
                         longer exists",
                        path.display(),
                    );
                }
            }
        }
    }
}
