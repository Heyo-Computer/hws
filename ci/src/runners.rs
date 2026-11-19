//! The runner pool: heyvm network members that jobs can run on.
//!
//! **A runner is a `heyvmd` host that joined the configured network.** There is
//! no agent to install and nothing to register with this app. Two control-plane
//! reads compose into the pool:
//!
//! - `GET /networks/{id}/members` — members whose `sandbox_kind` is `host`: a
//!   daemon host machine, with `sandbox_ref` its `hd-*` id. Assigning a host to
//!   a network is what unlocks host-shell access to it, so membership is the
//!   authorization.
//!
//!   The string is compared rather than an SDK enum because **the SDK has no
//!   `host` variant**: `NetworkMemberKind` is `Local | Deployed` only, which is
//!   also why [`Runners::join_network`] posts the member by hand. `heyvm network
//!   add-host` does the same.
//! - `GET /me/daemons` — liveness and the human-readable name. `Online` means a
//!   heartbeat within ~3 minutes.
//!
//! Neither alone is enough. Membership without a daemon row is a host that was
//! unregistered but never removed from the network; a daemon without membership
//! is a machine the operator has not opted into CI. Both are reported rather
//! than silently dropped, because "my runner isn't picking up jobs" is otherwise
//! unanswerable from the dashboard.
//!
//! ## Reaching one
//!
//! The cloud proxies shell and status routes to a daemon but **not sandbox
//! creation**, so driving a runner means dialing it directly:
//! `GET /me/daemons/{id}/connection-ticket` yields an iroh ticket,
//! [`HeyoClient::connect_p2p`] turns it into a client whose `base_url` is a local
//! forwarded port, and every subsequent SDK call rides that link.
//!
//! The tunnel lives in a background task that [`Drop`] aborts, so the cache here
//! is what keeps a runner reachable — dropping the last clone of a client closes
//! its tunnel.
//!
//! ## An iroh ticket is bearer-equivalent
//!
//! `mvm-ctrl/docs/cross-machine-hardening.md` is explicit: the `hey-proxy/tcp/0`
//! ALPN accepts any peer that knows the ticket, and the daemon has no way to
//! verify the peer. If a runner daemon runs without `JWT_SECRET`, its entire
//! HTTP API — including host shell — is open to anyone holding a ticket that may
//! have transited a log. So every tunnel is probed once, unauthenticated, and a
//! daemon that answers is refused by default.

use crate::config::Config;
use arc_swap::ArcSwap;
use heyo_sdk::{
    DaemonInfo, DaemonStatus, Daemons, HeyoClient, HeyoClientOptions, Network, NetworkInfo,
    RequestOptions,
};
use reqwest::Method;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// SDK options plus ownership of the forwarding listener they refer to.
/// Evicting a cached tunnel must not close it underneath in-flight work.
#[derive(Clone)]
pub struct Connection {
    pub options: HeyoClientOptions,
    pub(crate) _tunnel: Option<Arc<HeyoClient>>,
    /// How a VM handle opened on this connection gets a new one when the
    /// tunnel underneath dies mid-operation. `None` for a direct URL (a local
    /// runner, a test), where there is no tunnel to replace.
    pub(crate) redial: Option<Redial>,
}

impl From<HeyoClientOptions> for Connection {
    fn from(options: HeyoClientOptions) -> Self {
        Self { options, _tunnel: None, redial: None }
    }
}

/// Replace a dead tunnel to one runner: given the base URL that stopped
/// answering, return a connection over a freshly dialed tunnel.
///
/// A closure rather than a `Runners` handle so the VM layer stays ignorant of
/// tunnels and credentials — the seam [`Runners::options_for`] documents — and
/// so a test can hand a `Vm` a route to a second fake daemon.
///
/// **Why a VM needs this at all.** A step's exec operation runs on the daemon
/// whether or not anybody is polling it. A tunnel that dropped while a build
/// was in its seventh minute used to fail the job after two quick retries on
/// the same dead local port, although the build went on to finish with exit
/// 0; the eviction in `run_job` only spared the *next* job. With a redial the
/// poll resumes against the same operation id on the new tunnel and reads the
/// result the daemon kept.
pub(crate) type Redial = Arc<
    dyn Fn(String) -> futures::future::BoxFuture<'static, Result<Connection, String>>
        + Send
        + Sync,
>;

/// Pick the daemon a name or id refers to.
///
/// An exact id is unambiguous and wins outright. A **name is not**: `name`
/// defaults to the hostname, so a machine that re-registered — a reinstall, a
/// rebuilt container, a changed `BACKEND_SERVER_ID` — leaves two rows with the
/// same name, one dead and one live.
///
/// Matching those with `.find()` takes whichever the cloud happened to list
/// first, which can be the dead one: `ci` then pins jobs to a daemon that is not
/// heartbeating while the real one sits idle, and the only symptom is a queue
/// nothing consumes. So a live daemon is preferred, and a tie between live ones
/// is refused rather than guessed — the same stance `CI_NETWORK` takes on an
/// ambiguous network name, and for the same reason.
fn pick_daemon<'a>(daemons: &'a [DaemonInfo], wanted: &str) -> Result<&'a DaemonInfo, PickError> {
    if let Some(exact) = daemons.iter().find(|d| d.id == wanted) {
        return Ok(exact);
    }
    let by_name: Vec<&DaemonInfo> = daemons
        .iter()
        .filter(|d| d.name.as_deref() == Some(wanted))
        .collect();
    match by_name.len() {
        0 => Err(PickError::NoMatch),
        1 => Ok(by_name[0]),
        _ => {
            let live: Vec<&DaemonInfo> = by_name
                .iter()
                .copied()
                .filter(|d| d.status == DaemonStatus::Online)
                .collect();
            match live.len() {
                1 => Ok(live[0]),
                // Nothing live, or several: either way there is no answer that
                // is not a guess, and guessing is what produced a silent stall.
                _ => Err(PickError::Ambiguous(
                    by_name
                        .iter()
                        .map(|d| format!("{} ({:?})", d.id, d.status))
                        .collect(),
                )),
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PickError {
    NoMatch,
    Ambiguous(Vec<String>),
}

/// How long to wait for an iroh tunnel to a runner before giving up.
///
/// Generous — NAT traversal through a relay is not instant — but finite, which
/// is the point: this happens before a VM exists, so an unbounded dial shows up
/// as a job that never starts a step and never errors.
const DIAL_TIMEOUT: Duration = Duration::from_secs(90);

/// Membership kind for a daemon host, as the control plane spells it.
const MEMBER_KIND_HOST: &str = "host";

/// `GET /daemon/name` on a heyvmd, which is the only route that says who a
/// daemon is. Not in the SDK, so the shape is re-declared here; both fields are
/// optional because a `heyvm --api` that is not heyvmd answers with an error and
/// a heyvmd with no `BACKEND_SERVER_ID` answers with a null id.
#[derive(Debug, Clone, serde::Deserialize)]
struct DaemonNameResponse {
    #[serde(default)]
    backend_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerStatus {
    /// Heartbeat within the cloud's ~3 minute window.
    Online,
    /// Registered and a member, but missing heartbeats.
    Stale,
    /// The cloud has flipped the row away from available.
    Offline,
    /// A network member of kind `host` with no matching daemon row — the host
    /// was unregistered but left in the network.
    Orphaned,
}

impl RunnerStatus {
    /// Whether a job may be dispatched here now.
    pub fn is_dispatchable(&self) -> bool {
        matches!(self, Self::Online)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Stale => "stale",
            Self::Offline => "offline",
            Self::Orphaned => "orphaned",
        }
    }
}

impl From<DaemonStatus> for RunnerStatus {
    fn from(s: DaemonStatus) -> Self {
        match s {
            DaemonStatus::Online => Self::Online,
            DaemonStatus::Stale => Self::Stale,
            DaemonStatus::Offline => Self::Offline,
        }
    }
}

/// One host in the pool.
#[derive(Debug, Clone)]
pub struct Runner {
    /// The daemon id (`hd-…`). Stable, and what a job's subject is keyed on.
    pub id: String,
    /// Display name: the daemon's own label, else the network member's device
    /// name, else the id. A workflow's `uses:` may name any of the three.
    pub name: String,
    pub status: RunnerStatus,
    pub last_seen_at: Option<String>,
}

impl Runner {
    /// Whether `needle` addresses this runner — by id or by name,
    /// case-insensitively on the name.
    ///
    /// Ids are matched exactly: an `hd-…` is machine-generated and a
    /// case-folded match on one would only ever hide a typo.
    pub fn matches(&self, needle: &str) -> bool {
        self.id == needle || self.name.eq_ignore_ascii_case(needle)
    }
}

/// One network and the hosts in it.
#[derive(Debug, Default, Clone)]
pub struct RunnerSet {
    pub network_id: String,
    pub network_name: String,
    /// heyvm's own "default network" flag. Used to pick a default when
    /// `CI_NETWORK=*` names none.
    pub is_default: bool,
    /// Whether this instance takes work for it. An unserved network is still
    /// listed — "the network exists but nothing here builds for it" is an
    /// answer, and an empty page is not.
    pub served: bool,
    pub runners: Vec<Runner>,
}

impl RunnerSet {
    pub fn find(&self, needle: &str) -> Option<&Runner> {
        self.runners.iter().find(|r| r.matches(needle))
    }

    /// Every runner a job may be dispatched to right now.
    pub fn dispatchable(&self) -> impl Iterator<Item = &Runner> {
        self.runners.iter().filter(|r| r.status.is_dispatchable())
    }

    /// Whether `needle` names this network, by id or name.
    pub fn matches(&self, needle: &str) -> bool {
        self.network_id == needle || self.network_name.eq_ignore_ascii_case(needle)
    }
}

/// An immutable snapshot of every network on the account, swapped in whole by
/// the refresh loop so readers never take a lock. The same copy-on-write shape
/// as app-lb's registry.
#[derive(Debug, Default)]
pub struct Pool {
    /// Every network the account has, served or not, sorted by name.
    pub networks: Vec<RunnerSet>,
    /// Daemons the caller owns that are members of no network at all. Not
    /// usable, but shown on the dashboard so "why isn't my machine listed" has
    /// an answer that names the fix.
    pub unjoined: Vec<Runner>,
    /// `None` when the last refresh succeeded; otherwise why it did not, so a
    /// stale snapshot is visibly stale rather than quietly wrong.
    pub last_error: Option<String>,
    /// Where a run goes when nothing names a network: the first entry of
    /// `CI_NETWORK`, or the account's own default when that is `*`.
    pub default_network_id: String,
    /// The daemon `uses: default` means — this orchestrator's own host. Empty
    /// when it could not be worked out, which makes `uses: default` a refused
    /// job naming `CI_DEFAULT_NODE` rather than one that lands somewhere
    /// arbitrary.
    pub default_node_id: String,
}

impl Pool {
    /// The networks this instance takes work for.
    pub fn served(&self) -> impl Iterator<Item = &RunnerSet> {
        self.networks.iter().filter(|n| n.served)
    }

    /// A network by id or name, whether or not it is served.
    pub fn find(&self, needle: &str) -> Option<&RunnerSet> {
        let needle = needle.trim();
        self.networks.iter().find(|n| n.matches(needle))
    }

    /// The network a job with no `uses:` and no repository assignment runs in.
    pub fn default_set(&self) -> Option<&RunnerSet> {
        self.networks
            .iter()
            .find(|n| n.served && n.network_id == self.default_network_id)
            .or_else(|| self.served().next())
    }

    /// Every runner in every served network, for reclaiming pooled VMs.
    pub fn all_runners(&self) -> impl Iterator<Item = &Runner> {
        self.served().flat_map(|n| n.runners.iter())
    }

    /// The served network holding a given host, and the host itself.
    ///
    /// A machine may be a member of several networks, which is legitimate; the
    /// default network wins so that `uses: default` and an unpinned job land in
    /// the same place rather than two.
    pub fn locate(&self, node_id: &str) -> Option<(&RunnerSet, &Runner)> {
        let mut found: Option<(&RunnerSet, &Runner)> = None;
        for set in self.served() {
            if let Some(runner) = set.runners.iter().find(|r| r.id == node_id) {
                let preferred = set.network_id == self.default_network_id;
                if preferred {
                    return Some((set, runner));
                }
                found.get_or_insert((set, runner));
            }
        }
        found
    }

    /// The names of served networks, for an error that has to say what *is*
    /// available.
    pub fn served_names(&self) -> Vec<String> {
        self.served().map(|n| n.network_name.clone()).collect()
    }
}

/// Pool discovery plus the per-runner tunnel cache.
/// The last time a runner's tunnel failed, and how.
///
/// Kept so the networks page can say "Online, but unreachable over iroh" —
/// the cloud's `Online` comes from the daemon's heartbeat, a different path
/// entirely, so the two disagreeing is exactly the state an operator needs to
/// see and previously could not: the tab showed a healthy idle runner while
/// every job against it burned its retry ladder.
#[derive(Debug, Clone)]
pub struct TunnelFailure {
    pub reason: String,
    pub at: std::time::Instant,
}

impl TunnelFailure {
    /// `"3m ago"`, for a table cell.
    pub fn ago(&self) -> String {
        let secs = self.at.elapsed().as_secs();
        match secs {
            0..=89 => format!("{secs}s ago"),
            90..=5399 => format!("{}m ago", secs / 60),
            _ => format!("{}h ago", secs / 3600),
        }
    }
}

pub struct Runners {
    config: Arc<Config>,
    snapshot: ArcSwap<Pool>,
    /// One client per runner, each owning its iroh tunnel. Keyed on daemon id.
    ///
    /// The lock is held only to look up and to insert — never across the dial
    /// and its probes. It used to be, and the cost was head-of-line blocking
    /// for the whole fleet: one runner whose tunnel dials but carries no data
    /// held the lock for the dial timeout plus the probe, and every job on
    /// every *other* runner queued behind it. Two concurrent misses for the
    /// same runner may now both dial; the first to insert wins and the loser's
    /// client is dropped, which closes its tunnel — a leaked dial for a moment,
    /// never a leaked tunnel.
    tunnels: Mutex<HashMap<String, HeyoClient>>,
    /// Last tunnel failure per runner, for the networks page. Std mutex: the
    /// critical sections are map operations.
    failures: std::sync::Mutex<HashMap<String, TunnelFailure>>,
    /// Which sandbox drivers each daemon supports (`GET /capabilities`),
    /// learned on first need and kept for the life of the process — a host
    /// does not change operating systems between jobs. `None` is a daemon that
    /// answered without the field: an older build, treated as "cannot tell".
    capabilities: std::sync::Mutex<HashMap<String, Option<Arc<Vec<String>>>>>,
    /// This value's own `Arc`, so a [`Connection`] can carry a [`Redial`] back
    /// to it. Weak: a connection held past shutdown must not keep the runner
    /// set alive, and its redial then fails instead of dialing.
    me: std::sync::Weak<Runners>,
}

impl Runners {
    pub fn new(config: Arc<Config>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            config,
            snapshot: ArcSwap::from_pointee(Pool::default()),
            tunnels: Mutex::new(HashMap::new()),
            failures: std::sync::Mutex::new(HashMap::new()),
            capabilities: std::sync::Mutex::new(HashMap::new()),
            me: me.clone(),
        })
    }

    /// Each runner's most recent tunnel failure, if it has not carried traffic
    /// since.
    pub fn tunnel_failures(&self) -> HashMap<String, TunnelFailure> {
        self.failures.lock().unwrap().clone()
    }

    fn note_tunnel_failure(&self, runner_id: &str, reason: &str) {
        self.failures.lock().unwrap().insert(
            runner_id.to_string(),
            TunnelFailure {
                reason: reason.to_string(),
                at: std::time::Instant::now(),
            },
        );
    }

    fn clear_tunnel_failure(&self, runner_id: &str) {
        self.failures.lock().unwrap().remove(runner_id);
    }

    pub fn snapshot(&self) -> Arc<Pool> {
        self.snapshot.load_full()
    }

    #[cfg(test)]
    pub(crate) fn set_test_pool(&self, pool: Pool) {
        self.snapshot.store(Arc::new(pool));
    }

    fn client_options(&self) -> HeyoClientOptions {
        HeyoClientOptions {
            api_key: Some(self.config.heyvm.api_key.clone()),
            base_url: self.config.heyvm.base_url.clone(),
            timeout: None,
        }
    }

    /// Re-read the pool from the control plane and swap in a new snapshot.
    ///
    /// A failure keeps the previous snapshot and records the reason on it. The
    /// alternative — emptying the pool on a transient cloud error — would fail
    /// every queued job for the duration of a blip.
    pub async fn refresh(&self) -> Result<(), RunnerError> {
        match self.load().await {
            Ok(pool) => {
                self.snapshot.store(Arc::new(pool));
                Ok(())
            }
            Err(e) => {
                let prev = self.snapshot.load();
                self.snapshot.store(Arc::new(Pool {
                    networks: prev.networks.clone(),
                    unjoined: prev.unjoined.clone(),
                    last_error: Some(e.to_string()),
                    default_network_id: prev.default_network_id.clone(),
                    // Carried over with everything else: a cloud blip must not
                    // turn `uses: default` into a refused job.
                    default_node_id: prev.default_node_id.clone(),
                }));
                Err(e)
            }
        }
    }

    /// The single synthetic runner backing `CI_LOCAL_RUNNER`.
    ///
    /// Named `local` and given the id `hd-local`, which is a valid subject token
    /// and so routes like any other host.
    ///
    /// The network is named plainly `local`, **not** `local (<url>)`. A network
    /// name has to be spellable in `uses: <network>/<runner>`, which splits on
    /// the first `/` — so a name carrying a URL cannot be addressed by the one
    /// syntax that addresses networks. The daemon's URL is in the startup
    /// summary instead, where it is a configuration detail rather than an
    /// identifier.
    fn local_pool() -> Pool {
        Pool {
            networks: vec![RunnerSet {
                network_id: "local".to_string(),
                network_name: "local".to_string(),
                is_default: true,
                served: true,
                runners: vec![Runner {
                    id: "hd-local".to_string(),
                    name: "local".to_string(),
                    status: RunnerStatus::Online,
                    last_seen_at: None,
                }],
            }],
            unjoined: Vec::new(),
            last_error: None,
            default_network_id: "local".to_string(),
            // The one case where a synthetic id is safe: local mode drives one
            // daemon on this machine and talks to no cloud, so nothing else can
            // be binding the same subject.
            default_node_id: "hd-local".to_string(),
        }
    }

    /// Read every network on the account, and the hosts in each.
    ///
    /// **Members are read per network, concurrently.** The control plane has no
    /// "all members everywhere" route and `NetworkInfo` carries no member count,
    /// so N+1 reads is the only shape available. Running them together makes the
    /// refresh one round trip's worth of latency rather than N, which is what
    /// matters on a `CI_RUNNER_REFRESH_SECS` ticker.
    ///
    /// Unserved networks are read too, because the dashboard's whole job here is
    /// to answer "which network should this repository build in" — and a list of
    /// names with no hosts under them does not answer it.
    async fn load(&self) -> Result<Pool, RunnerError> {
        // Local mode short-circuits every cloud call: no account, no network,
        // no tunnel.
        if self.config.heyvm.local_runner.is_some() {
            return Ok(Self::local_pool());
        }

        let infos = self.list_networks().await?;
        let daemons = Daemons::list(self.client_options())
            .await
            .map_err(|e| RunnerError::ControlPlane(format!("GET /me/daemons: {e}")))?;

        let reads = infos.iter().map(|info| {
            let opts = self.client_options();
            async move {
                let network = Network::get(&info.id, opts).await.map_err(|e| {
                    RunnerError::ControlPlane(format!("GET /networks/{}: {e}", info.id))
                })?;
                let members = network.list_members().await.map_err(|e| {
                    RunnerError::ControlPlane(format!("members of {}: {e}", info.name))
                })?;
                Ok::<_, RunnerError>(members)
            }
        });
        let member_lists = futures::future::join_all(reads).await;

        let mut networks = Vec::with_capacity(infos.len());
        let mut joined: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (info, members) in infos.iter().zip(member_lists) {
            // One unreadable network must not empty the others — the pool is
            // per-network, so the honest result is that network with no hosts
            // and a logged reason.
            let members = match members {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("could not read members of {}: {e}", info.name);
                    Vec::new()
                }
            };
            let (runners, in_network) = Self::project(&members, &daemons);
            joined.extend(in_network);
            networks.push(RunnerSet {
                network_id: info.id.clone(),
                network_name: info.name.clone(),
                is_default: info.is_default,
                served: self.config.heyvm.networks.includes(&info.id, &info.name),
                runners,
            });
        }
        networks.sort_by(|a, b| a.network_name.cmp(&b.network_name));

        // A daemon in *no* network at all, which is the commonest "why is
        // nothing running" cause. Computed across every network rather than one,
        // so a host that joined a network this instance does not serve is not
        // reported as homeless.
        let mut unjoined: Vec<Runner> = daemons
            .iter()
            .filter(|d| !joined.contains(&d.id))
            .map(|d| Runner {
                id: d.id.clone(),
                name: d.name.clone().unwrap_or_else(|| d.id.clone()),
                status: RunnerStatus::from(d.status),
                last_seen_at: Some(d.last_seen_at.clone()),
            })
            .collect();
        unjoined.sort_by(|a, b| a.name.cmp(&b.name));

        let default_network_id = Self::pick_default(&networks, &self.config);
        let default_node_id = self.resolve_default_node(&daemons).await;
        Ok(Pool {
            networks,
            unjoined,
            last_error: None,
            default_network_id,
            default_node_id,
        })
    }

    /// Which daemon `uses: default` means.
    ///
    /// The answer has to be a *real* daemon id, because it becomes a NATS
    /// subject: two orchestrators that both invented `hd-local` would bind
    /// consumers to the same subject and eat each other's jobs. So a synthetic
    /// id is never returned outside local-runner mode — an unresolvable default
    /// is empty, and `uses: default` is then refused by name.
    ///
    /// Best-effort and never fatal: the probe is one short request to a daemon
    /// that may not be there at all, and an installation that never writes
    /// `uses: default` should not have its pool refresh fail over it.
    async fn resolve_default_node(&self, daemons: &[DaemonInfo]) -> String {
        // Configuration wins: it is the only source an operator controls
        // directly, and the only one that works when the orchestrator is not
        // co-located with a daemon at all.
        if let Some(wanted) = self.config.heyvm.default_node.as_deref() {
            let wanted = wanted.trim();
            match pick_daemon(daemons, wanted) {
                Ok(d) => return d.id.clone(),
                Err(PickError::Ambiguous(candidates)) => {
                    tracing::warn!(
                        "CI_DEFAULT_NODE={wanted:?} matches {} daemons ({}), and none is \
                         the obvious live one. Set it to a daemon id — a name defaults \
                         to the hostname, so a machine that re-registered has two.",
                        candidates.len(),
                        candidates.join(", ")
                    );
                    return String::new();
                }
                Err(PickError::NoMatch) => {}
            }
            tracing::warn!(
                "CI_DEFAULT_NODE={wanted:?} matches no daemon on this account, so \
                 `uses: default` will be refused. Registered: {}",
                daemons
                    .iter()
                    .map(|d| d.name.clone().unwrap_or_else(|| d.id.clone()))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return String::new();
        }

        // `~/.heyo/daemon.json` is the authority, and it is the same file
        // `heyvm network add-host` consults (`resolve_local_daemon_id`). heyvmd
        // mints `backend_id` there on first start and *registers and heartbeats
        // under it* — so it is the identity the cloud knows this machine by.
        //
        // The daemon's HTTP API is deliberately not asked first: `/daemon/name`
        // returns `backend_server_id`, which comes from the `BACKEND_SERVER_ID`
        // environment and is a different field entirely. Trusting it pins jobs
        // to an id the cloud may have no live registration for — a queue with
        // no consumer beside a daemon that is perfectly healthy.
        if let Some(id) = self.local_daemon_id_from_disk()
            && daemons.iter().any(|d| d.id == id)
        {
            return id;
        }

        let Some(probe) = self.probe_local_daemon().await else {
            return String::new();
        };

        // `backend_id` is the daemon's own id, but it comes from its
        // environment (`BACKEND_SERVER_ID`/`HEYVM_BACKEND_ID`) and may be
        // absent or stale — so it is only believed when the account agrees it
        // exists. The name is the fallback because a daemon owns its name and
        // republishes it on every heartbeat.
        if let Some(id) = probe.backend_id.as_deref().filter(|s| !s.trim().is_empty())
            && daemons.iter().any(|d| d.id == id)
        {
            return id.to_string();
        }
        if let Some(name) = probe.name.as_deref().filter(|s| !s.trim().is_empty()) {
            match pick_daemon(daemons, name) {
                Ok(d) => return d.id.clone(),
                Err(PickError::Ambiguous(candidates)) => {
                    tracing::warn!(
                        "the local daemon calls itself {name:?}, which matches {} daemons \
                         ({}) — a machine that re-registered keeps both rows. Set \
                         CI_DEFAULT_NODE to the live daemon id.",
                        candidates.len(),
                        candidates.join(", ")
                    );
                    return String::new();
                }
                Err(PickError::NoMatch) => {}
            }
        }

        tracing::warn!(
            "a daemon answered at {} but neither its backend id nor its name {:?} \
             matches a daemon on this account, so `uses: default` will be refused. \
             Set CI_DEFAULT_NODE.",
            self.config.heyvm.local_daemon_url,
            probe.name.as_deref().unwrap_or("(unset)")
        );
        String::new()
    }

    /// The daemon id this machine registered with, read from `~/.heyo/daemon.json`.
    ///
    /// Only meaningful for `uses: default`, which is by definition the local
    /// host — there is no equivalent for a remote one, which is why the network
    /// member list is the source everywhere else.
    fn local_daemon_id_from_disk(&self) -> Option<String> {
        let path = self.config.heyvm.daemon_state_path.clone()?;
        let text = std::fs::read_to_string(&path).ok()?;
        let state: serde_json::Value = serde_json::from_str(&text).ok()?;
        state
            .get("backend_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    /// `GET /daemon/name` on the co-located daemon.
    async fn probe_local_daemon(&self) -> Option<DaemonNameResponse> {
        let url = format!("{}/daemon/name", self.config.heyvm.local_daemon_url);
        let response = reqwest::Client::builder()
            // Short: nothing here is worth delaying a pool refresh for, and the
            // common case is that no daemon is listening at all.
            .timeout(Duration::from_secs(3))
            .build()
            .ok()?
            .get(&url)
            .bearer_auth(&self.config.heyvm.api_key)
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            tracing::debug!("no local daemon identity from {url}: {}", response.status());
            return None;
        }
        response.json::<DaemonNameResponse>().await.ok()
    }

    /// Which served network a run lands in when nothing names one.
    ///
    /// The first entry of `CI_NETWORK`, because that is the one a person wrote
    /// first. Under `CI_NETWORK=*` there is no such entry, so the account's own
    /// default network is used — and failing that, the first served network by
    /// name, which at least does not change from one refresh to the next.
    fn pick_default(networks: &[RunnerSet], config: &Config) -> String {
        if let Some(wanted) = config.heyvm.networks.preferred()
            && let Some(set) = networks.iter().find(|n| n.served && n.matches(wanted))
        {
            return set.network_id.clone();
        }
        networks
            .iter()
            .find(|n| n.served && n.is_default)
            .or_else(|| networks.iter().find(|n| n.served))
            .map(|n| n.network_id.clone())
            .unwrap_or_default()
    }

    /// Join the two control-plane reads into one network's hosts.
    ///
    /// Returns the runners and the set of daemon ids that are members, so the
    /// caller can work out which daemons belong to no network at all.
    ///
    /// Pure, so the filtering that decides what counts as a runner is testable
    /// without a control plane. That filtering is the part most likely to be
    /// wrong in a way nobody notices: a real network is mostly `deployed`
    /// members (every sandbox joins one), and treating those as hosts would
    /// route jobs at VMs.
    fn project(
        members: &[heyo_sdk::NetworkMember],
        daemons: &[DaemonInfo],
    ) -> (Vec<Runner>, Vec<String>) {
        let by_id: HashMap<&str, &DaemonInfo> =
            daemons.iter().map(|d| (d.id.as_str(), d)).collect();

        let mut runners = Vec::new();
        let mut joined = Vec::new();
        for m in members
            .iter()
            .filter(|m| m.sandbox_kind == MEMBER_KIND_HOST)
        {
            joined.push(m.sandbox_ref.clone());
            let daemon = by_id.get(m.sandbox_ref.as_str());
            runners.push(Runner {
                id: m.sandbox_ref.clone(),
                name: daemon
                    .and_then(|d| d.name.clone())
                    .or_else(|| m.device_name.clone())
                    .unwrap_or_else(|| m.sandbox_ref.clone()),
                // No daemon row for a host member means the daemon was
                // unregistered but left in the network. Reporting it as
                // `Orphaned` rather than dropping it is what makes "my runner
                // vanished" answerable.
                status: daemon
                    .map(|d| RunnerStatus::from(d.status))
                    .unwrap_or(RunnerStatus::Orphaned),
                last_seen_at: daemon
                    .map(|d| d.last_seen_at.clone())
                    .or_else(|| m.last_seen_at.clone()),
            });
        }
        runners.sort_by(|a, b| a.name.cmp(&b.name));
        (runners, joined)
    }

    /// Every network on the account, with `CI_NETWORK`'s entries validated.
    ///
    /// A name in `CI_NETWORK` that matches nothing, or matches two networks, is
    /// an error rather than a silent omission: the two candidates have different
    /// runner pools, and picking one — or quietly serving neither — is how a job
    /// lands on a machine nobody expected, or on none at all.
    async fn list_networks(&self) -> Result<Vec<NetworkInfo>, RunnerError> {
        let networks = Network::list(self.client_options())
            .await
            .map_err(|e| RunnerError::ControlPlane(format!("GET /networks: {e}")))?;

        if let crate::config::ServedNetworks::Named(wanted) = &self.config.heyvm.networks {
            for name in wanted {
                let name = name.trim();
                if networks.iter().any(|n| n.id == name) {
                    continue;
                }
                let by_name = networks
                    .iter()
                    .filter(|n| n.name.eq_ignore_ascii_case(name))
                    .count();
                match by_name {
                    1 => {}
                    0 => {
                        return Err(RunnerError::UnknownNetwork {
                            wanted: name.to_string(),
                            available: networks.iter().map(|n| n.name.clone()).collect(),
                        });
                    }
                    _ => {
                        return Err(RunnerError::AmbiguousNetwork {
                            wanted: name.to_string(),
                            ids: networks
                                .iter()
                                .filter(|n| n.name.eq_ignore_ascii_case(name))
                                .map(|n| n.id.clone())
                                .collect(),
                        });
                    }
                }
            }
        }
        Ok(networks)
    }

    /// A client whose `base_url` is a live tunnel into `runner_id`'s daemon.
    ///
    /// Cheap on a hit. On a miss it fetches a ticket, dials over iroh, and — the
    /// first time — proves the daemon actually enforces authentication.
    pub async fn client_for(&self, runner_id: &str) -> Result<HeyoClient, RunnerError> {
        if let Some(c) = self.tunnels.lock().await.get(runner_id) {
            return Ok(c.clone());
        }

        let dialed = self.dial(runner_id).await;
        match &dialed {
            Ok(_) => self.clear_tunnel_failure(runner_id),
            Err(RunnerError::Unreachable { reason, .. }) => {
                self.note_tunnel_failure(runner_id, reason);
            }
            Err(RunnerError::DaemonUnauthenticated(_)) => {
                self.note_tunnel_failure(
                    runner_id,
                    "daemon refused: it serves its API without authentication",
                );
            }
            Err(_) => {}
        }
        let client = dialed?;

        let mut cache = self.tunnels.lock().await;
        if let Some(existing) = cache.get(runner_id) {
            // A concurrent miss dialed too and beat us here. Theirs is the one
            // everybody else already holds; ours is dropped, which closes it.
            return Ok(existing.clone());
        }
        cache.insert(runner_id.to_string(), client.clone());
        tracing::info!(runner = runner_id, "opened an iroh tunnel to the daemon");
        Ok(client)
    }

    /// Ticket, dial, probe — everything that must not run under the cache lock.
    async fn dial(&self, runner_id: &str) -> Result<HeyoClient, RunnerError> {
        let ticket = self.connection_ticket(runner_id).await?;
        // Bounded. This runs *before* the VM boot timeout applies, so an iroh
        // dial that never completes is a job with no steps and no error — the
        // hang looks identical to a runner that is merely slow.
        let client = tokio::time::timeout(
            DIAL_TIMEOUT,
            HeyoClient::connect_p2p(
                &ticket,
                self.config.heyvm.relay.as_deref(),
                Some(self.config.heyvm.api_key.clone()),
            ),
        )
        .await
        .map_err(|_| RunnerError::Unreachable {
            runner: runner_id.to_string(),
            reason: format!("the iroh dial did not complete within {DIAL_TIMEOUT:?}"),
        })?
        .map_err(|e| RunnerError::Unreachable {
            runner: runner_id.to_string(),
            reason: format!("iroh connect failed: {e}"),
        })?;

        self.assert_daemon_requires_auth(runner_id, &client).await?;
        Ok(client)
    }

    /// SDK client options pointed at a live tunnel to `runner_id`.
    ///
    /// This is the seam between this module and [`crate::vm`]: tunnels and
    /// credentials live here, and the VM layer only ever sees options. The
    /// returned connection keeps its local forwarded port alive independently
    /// of the cache. Keep it for the entire operation, including VM teardown.
    pub async fn options_for(&self, runner_id: &str) -> Result<Connection, RunnerError> {
        if let Some(url) = &self.config.heyvm.local_runner {
            // Development daemons may need no bearer; regional hosts can
            // require their own internal key rather than the Cloud token.
            return Ok(HeyoClientOptions {
                api_key: self.config.heyvm.local_runner_token.clone(),
                base_url: Some(url.clone()),
                timeout: None,
            }.into());
        }
        let client = self.client_for(runner_id).await?;
        Ok(self.tunnel_connection(runner_id, client))
    }

    /// A [`Connection`] over `client`'s tunnel, with a redial back here.
    ///
    /// Synchronous on purpose: the redial's future awaits
    /// [`Self::replace_tunnel`], and if building the closure happened inside an
    /// `async fn` that future awaits, proving it `Send` would be circular.
    fn tunnel_connection(&self, runner_id: &str, client: HeyoClient) -> Connection {
        let me = self.me.clone();
        let runner = runner_id.to_string();
        let redial: Redial = Arc::new(move |dead: String| {
            let me = me.clone();
            let runner = runner.clone();
            Box::pin(async move {
                let runners = me
                    .upgrade()
                    .ok_or_else(|| "the CI service is shutting down".to_string())?;
                runners.replace_tunnel(&runner, &dead).await.map_err(|e| e.to_string())
            })
        });
        Connection {
            options: HeyoClientOptions {
                api_key: Some(self.config.heyvm.api_key.clone()),
                base_url: Some(client.base_url().to_string()),
                timeout: None,
            },
            _tunnel: Some(Arc::new(client)),
            redial: Some(redial),
        }
    }

    /// A connection over a tunnel other than the one at `dead`, dialing one if
    /// the cache still holds `dead`.
    ///
    /// Evicts only when the cached tunnel *is* the dead one. Every job on a
    /// runner shares its tunnel, so when it drops they all notice at once; the
    /// first to get here redials, and the rest must pick up its fresh tunnel
    /// rather than evict it and dial again — five builds on one runner would
    /// otherwise churn through five tunnels, each killing the last.
    pub(crate) async fn replace_tunnel(
        &self,
        runner_id: &str,
        dead: &str,
    ) -> Result<Connection, RunnerError> {
        {
            let mut tunnels = self.tunnels.lock().await;
            if tunnels.get(runner_id).is_some_and(|c| c.base_url() == dead) {
                tunnels.remove(runner_id);
                tracing::info!(runner = runner_id, "evicted a dead daemon tunnel to redial");
            }
        }
        // Not `options_for`: see `tunnel_connection`. A redial only exists for
        // tunnel connections, so the local-runner branch cannot apply here.
        let client = self.client_for(runner_id).await?;
        Ok(self.tunnel_connection(runner_id, client))
    }

    /// Join a daemon host to a network — what `heyvm network add-host` does.
    ///
    /// Through the raw client rather than the SDK's `Network::add_member`, and
    /// not by preference: `NetworkMemberKind` has only `Local` and `Deployed`,
    /// so the typed API **cannot say `host`** at all. `heyvm network add-host`
    /// has the same problem and solves it the same way, posting the string
    /// (`network_client::register_member(..., "host", ...)`).
    ///
    /// `POST /networks/{id}/members` rather than the CLI's `/networks/me/members`,
    /// because `me` is whichever network the account calls default and this is a
    /// page where somebody picks one. The route is documented idempotent on
    /// `(network_id, sandbox_kind, sandbox_ref)`, so a second click is a no-op
    /// rather than a duplicate member.
    pub async fn join_network(&self, network_id: &str, node_id: &str) -> Result<(), RunnerError> {
        let client = HeyoClient::new(self.client_options()).map_err(|e| {
            RunnerError::ControlPlane(format!("could not build a cloud client: {e}"))
        })?;
        let path = format!("/networks/{network_id}/members");
        let body = serde_json::json!({
            "sandbox_kind": MEMBER_KIND_HOST,
            "sandbox_ref": node_id,
        });

        let response = client
            .raw_request(Method::POST, &path, Some(&body), RequestOptions::default())
            .await
            .map_err(|e| RunnerError::ControlPlane(format!("POST {path}: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            return Err(RunnerError::ControlPlane(format!(
                "POST {path} returned {status}: {}",
                detail.chars().take(200).collect::<String>()
            )));
        }
        Ok(())
    }

    /// The sandbox drivers a runner's daemon says it supports.
    ///
    /// `Ok(None)` is an honest "cannot tell" — a daemon predating
    /// `/capabilities`, or one that answered without the field — and the
    /// caller should give it the benefit of the doubt rather than refuse a
    /// fleet that merely has not upgraded. `Err` is a runner that could not be
    /// asked at all.
    pub async fn supported_drivers(
        &self,
        runner_id: &str,
    ) -> Result<Option<Arc<Vec<String>>>, RunnerError> {
        if let Some(known) = self.capabilities.lock().unwrap().get(runner_id) {
            return Ok(known.clone());
        }
        let connection = self.options_for(runner_id).await?;
        let client = HeyoClient::new(connection.options.clone()).map_err(|e| {
            RunnerError::Unreachable {
                runner: runner_id.to_string(),
                reason: format!("could not build a daemon client: {e}"),
            }
        })?;
        let response = client
            .raw_request(
                Method::GET,
                "/capabilities",
                None::<&()>,
                RequestOptions {
                    timeout: Some(Duration::from_secs(30)),
                    query: Vec::new(),
                },
            )
            .await
            .map_err(|e| RunnerError::Unreachable {
                runner: runner_id.to_string(),
                reason: format!("GET /capabilities failed: {e}"),
            })?;
        let drivers: Option<Arc<Vec<String>>> = if response.status().is_success() {
            response
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| {
                    v.get("supportedDrivers")
                        .and_then(|d| d.as_array())
                        .map(|list| {
                            Arc::new(
                                list.iter()
                                    .filter_map(|s| s.as_str().map(str::to_string))
                                    .collect::<Vec<_>>(),
                            )
                        })
                })
        } else {
            // A 404 is an older daemon; anything else is still not evidence
            // about what it can run.
            None
        };
        self.capabilities
            .lock()
            .unwrap()
            .insert(runner_id.to_string(), drivers.clone());
        Ok(drivers)
    }

    /// Fresh free-space measurement from the same daemon inventory app-lb uses.
    /// Unlike driver capabilities this must not be cached across allocations.
    pub async fn free_disk_bytes(&self, runner_id: &str) -> Result<u64, RunnerError> {
        let mut first_error = None;
        for attempt in 0..2 {
            let result = async {
                let options = self.options_for(runner_id).await?;
                let client = HeyoClient::new(options.options.clone())?;
                let response = client.raw_request(
                    Method::GET, "/storage", None::<&()>,
                    RequestOptions { timeout: Some(Duration::from_secs(15)), query: Vec::new() },
                ).await?;
                let response = response.error_for_status()?;
                #[derive(serde::Deserialize)]
                struct Storage { free_bytes: u64 }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(response.json::<Storage>().await?.free_bytes)
            }.await;
            match result {
                Ok(free) => return Ok(free),
                Err(error) => {
                    if attempt == 0 { first_error = Some(error.to_string()); }
                    // Placement failures happen before run_claimed, so its
                    // transport recovery never sees them. Evict now and retry
                    // this idempotent read once through a freshly dialed tunnel
                    // instead of consuming a whole job attempt and 60s backoff.
                    self.evict(runner_id).await;
                    if attempt == 1 {
                        let detail = match first_error {
                            Some(first) if first != error.to_string() => format!("{first}; fresh-tunnel retry failed: {error}"),
                            _ => error.to_string(),
                        };
                        return Err(RunnerError::Unreachable {
                            runner: runner_id.to_string(),
                            reason: format!("GET /storage free-space measurement failed: {detail}"),
                        });
                    }
                }
            }
        }
        unreachable!("capacity read performs exactly two attempts")
    }

    /// Drop a runner's tunnel so the next `client_for` redials.
    ///
    /// Called when a request over the tunnel fails in a way that suggests the
    /// link rather than the request — the daemon restarted, the relay dropped
    /// it, the host rebooted.
    pub async fn evict(&self, runner_id: &str) {
        if self.tunnels.lock().await.remove(runner_id).is_some() {
            tracing::info!(runner = runner_id, "evicted the daemon tunnel");
        }
    }

    /// Seed the cache with `client` as `runner_id`'s tunnel and return a
    /// connection over it, as `options_for` would after a real dial.
    #[cfg(test)]
    pub(crate) async fn options_for_tunnel_test(&self, runner_id: &str, client: HeyoClient) -> Connection {
        self.tunnels.lock().await.insert(runner_id.to_string(), client);
        self.options_for(runner_id).await.expect("a cached tunnel needs no dial")
    }

    #[cfg(test)]
    pub(crate) async fn tunnel_cache_for_test(&self) -> tokio::sync::MutexGuard<'_, HashMap<String, HeyoClient>> {
        self.tunnels.lock().await
    }

    /// `GET /me/daemons/{id}/connection-ticket`.
    ///
    /// Not on `Daemons` in the SDK, so it goes through the raw client. Uses
    /// `raw_request` rather than `request` to keep the status code: the SDK
    /// folds every 4xx that is not 401/403/404 into one variant, and the
    /// difference between "this daemon has no tunnel yet" (409, normal while a
    /// host is booting) and "no such daemon" (404, a configuration error) is
    /// exactly what an operator needs to see.
    async fn connection_ticket(&self, runner_id: &str) -> Result<String, RunnerError> {
        let client = HeyoClient::new(self.client_options()).map_err(|e| {
            RunnerError::ControlPlane(format!("could not build a cloud client: {e}"))
        })?;
        let path = format!("/me/daemons/{runner_id}/connection-ticket");
        let response = client
            .raw_request(Method::GET, &path, None::<&()>, RequestOptions::default())
            .await
            .map_err(|e| RunnerError::Unreachable {
                runner: runner_id.to_string(),
                reason: format!("fetching a connection ticket: {e}"),
            })?;

        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);

        if !status.is_success() {
            let detail = body
                .get("message")
                .or_else(|| body.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("no detail")
                .to_string();
            return Err(match status.as_u16() {
                409 => RunnerError::NoTicket {
                    runner: runner_id.to_string(),
                    detail,
                },
                404 => RunnerError::UnknownRunner(runner_id.to_string()),
                other => RunnerError::Unreachable {
                    runner: runner_id.to_string(),
                    reason: format!("connection-ticket returned {other}: {detail}"),
                },
            });
        }

        body.get("connectionUrl")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| RunnerError::NoTicket {
                runner: runner_id.to_string(),
                detail: "the cloud returned an empty connectionUrl".to_string(),
            })
    }

    /// Prove the daemon rejects an unauthenticated request before trusting the
    /// tunnel with anything.
    ///
    /// A daemon started without `JWT_SECRET` (and without an internal API key)
    /// disables its auth middleware entirely — `mvm-ctrl/src/api.rs:885` passes
    /// every request through. Combined with a bearer-equivalent ticket, that
    /// means anyone who ever saw the ticket has the host. Probing costs one
    /// round trip per tunnel and turns a silent exposure into a startup error.
    ///
    /// That round trip does double duty: it is also the only proof that the
    /// tunnel carries data before it is cached. Both obligations are discharged
    /// by the same request, and neither is optional — see the `Err` arm below.
    ///
    /// `CI_ALLOW_UNAUTHENTICATED_RUNNERS=true` downgrades it to a warning, for a
    /// single-machine development loop where the tunnel never leaves localhost.
    async fn assert_daemon_requires_auth(
        &self,
        runner_id: &str,
        tunneled: &HeyoClient,
    ) -> Result<(), RunnerError> {
        // Same local port, no bearer. `local_at` exists for exactly this: a
        // client pointed at a port somebody else bound.
        let anon = match HeyoClient::local_at(tunneled.base_url()) {
            Ok(c) => c,
            Err(e) => {
                // Not being able to build the probe is not evidence either way,
                // so it must not read as a pass.
                return Err(RunnerError::Unreachable {
                    runner: runner_id.to_string(),
                    reason: format!("could not build an auth probe: {e}"),
                });
            }
        };

        // Two probes with two different questions, because conflating them
        // turned load into an outage: the old single probe hit `/sandboxes`
        // with 10 seconds, and a daemon that was merely busy — a host mid way
        // through preallocating a 40 GB data disk answers slowly — read as "the
        // tunnel carried no data". Every job then burned its whole retry
        // ladder against a runner that was fine, while the networks tab showed
        // it Online, because the heartbeat rides a different path entirely.
        //
        // **Transport** is asked of `/health`: public on the daemon, no auth,
        // no work — it reads a struct. If that carries no reply in 30 seconds
        // the tunnel really is dead, and failing here names the runner and the
        // tunnel instead of whatever request would have hit it first.
        let transport = anon
            .raw_request(
                Method::GET,
                "/health",
                None::<&()>,
                RequestOptions {
                    timeout: Some(Duration::from_secs(30)),
                    query: Vec::new(),
                },
            )
            .await;
        if let Err(e) = transport {
            return Err(RunnerError::Unreachable {
                runner: runner_id.to_string(),
                reason: format!("the tunnel carried no reply to a probe request: {e}"),
            });
        }

        // **Auth** is asked of `/sandboxes`, which must refuse an anonymous
        // caller. The tunnel is already proven, so a transport error here is a
        // daemon too loaded to answer a real route in time — retried once with
        // a longer budget, and past that the question is left *open* with a
        // warning rather than the runner declared unreachable: the lint runs
        // again on every fresh tunnel, and an actually-open daemon answers
        // quickly precisely because it is doing no auth work.
        let mut probe = anon
            .raw_request(
                Method::GET,
                "/sandboxes",
                None::<&()>,
                RequestOptions {
                    timeout: Some(Duration::from_secs(10)),
                    query: Vec::new(),
                },
            )
            .await;
        if probe.is_err() {
            probe = anon
                .raw_request(
                    Method::GET,
                    "/sandboxes",
                    None::<&()>,
                    RequestOptions {
                        timeout: Some(Duration::from_secs(30)),
                        query: Vec::new(),
                    },
                )
                .await;
        }

        let open = match probe {
            // A protected route answering without a bearer is the failure.
            Ok(r) => r.status().is_success(),
            Err(e) => {
                tracing::warn!(
                    runner = runner_id,
                    "the tunnel is up (/health answers) but /sandboxes did not reply to the \
                     auth probe ({e}); proceeding without the auth verdict — the daemon is \
                     likely under load. The check runs again on the next tunnel."
                );
                return Ok(());
            }
        };

        if !open {
            return Ok(());
        }
        if self.config.allow_unauthenticated_runners {
            tracing::warn!(
                runner = runner_id,
                "this daemon serves its API without authentication; its iroh ticket \
                 is equivalent to a host shell. Set JWT_SECRET on the runner."
            );
            return Ok(());
        }
        Err(RunnerError::DaemonUnauthenticated(runner_id.to_string()))
    }

    /// Refresh now, then on `CI_RUNNER_REFRESH_SECS`, until the process ends.
    ///
    /// The first refresh is awaited by the caller so startup can report a
    /// broken network immediately; failures after that are logged and retried
    /// rather than fatal, because a cloud blip is not a reason to stop serving
    /// a dashboard.
    pub fn spawn_refresh_loop(self: Arc<Self>) {
        let interval = self.config.heyvm.refresh_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(e) = self.refresh().await {
                    tracing::warn!("runner refresh failed, keeping the last snapshot: {e}");
                }
            }
        });
    }
}

#[derive(Debug)]
pub enum RunnerError {
    ControlPlane(String),
    UnknownNetwork {
        wanted: String,
        available: Vec<String>,
    },
    AmbiguousNetwork {
        wanted: String,
        ids: Vec<String>,
    },
    UnknownRunner(String),
    NoTicket {
        runner: String,
        detail: String,
    },
    Unreachable {
        runner: String,
        reason: String,
    },
    DaemonUnauthenticated(String),
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ControlPlane(msg) => write!(f, "heyvm control plane: {msg}"),
            Self::UnknownNetwork { wanted, available } => {
                if available.is_empty() {
                    write!(
                        f,
                        "CI_NETWORK={wanted:?} matches no network, and this account has none. \
                         Create one with `heyvm network create`."
                    )
                } else {
                    write!(
                        f,
                        "CI_NETWORK={wanted:?} matches no network. Available: {}",
                        available.join(", ")
                    )
                }
            }
            Self::AmbiguousNetwork { wanted, ids } => write!(
                f,
                "CI_NETWORK={wanted:?} matches {} networks ({}); set it to an id instead, \
                 because the two have different runner pools",
                ids.len(),
                ids.join(", ")
            ),
            Self::UnknownRunner(id) => write!(
                f,
                "no daemon {id:?} is registered to this account; it may have been \
                 unregistered while still a member of the network"
            ),
            Self::NoTicket { runner, detail } => write!(
                f,
                "runner {runner:?} has no P2P connection ticket ({detail}). It is \
                 registered but its heyvmd tunnel is not up — check that heyvmd is \
                 running on that host."
            ),
            Self::Unreachable { runner, reason } => {
                write!(f, "could not reach runner {runner:?}: {reason}")
            }
            Self::DaemonUnauthenticated(id) => write!(
                f,
                "runner {id:?} serves its heyvm API without authentication, so its \
                 iroh ticket grants a host shell to anyone who has seen it. Start \
                 heyvmd with JWT_SECRET set, or set \
                 CI_ALLOW_UNAUTHENTICATED_RUNNERS=true if this host is local-only."
            ),
        }
    }
}

impl std::error::Error for RunnerError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn runner(id: &str, name: &str, status: RunnerStatus) -> Runner {
        Runner {
            id: id.into(),
            name: name.into(),
            status,
            last_seen_at: None,
        }
    }

    #[test]
    fn a_runner_is_addressable_by_id_or_by_name() {
        let r = runner("hd-abc123", "bigbox", RunnerStatus::Online);
        assert!(r.matches("hd-abc123"));
        assert!(r.matches("bigbox"));
        assert!(r.matches("BigBox"), "names are case-insensitive");
        assert!(!r.matches("hd-ABC123"), "ids are matched exactly");
        assert!(!r.matches("smallbox"));
    }

    /// Only `Online` may take work. A stale daemon still has a row and a
    /// tunnel ticket, so dispatching to it would hang until the job timed out
    /// rather than failing fast.
    #[test]
    fn only_online_runners_are_dispatchable() {
        assert!(RunnerStatus::Online.is_dispatchable());
        for s in [
            RunnerStatus::Stale,
            RunnerStatus::Offline,
            RunnerStatus::Orphaned,
        ] {
            assert!(!s.is_dispatchable(), "{} must not take work", s.as_str());
        }
    }

    fn set(id: &str, name: &str, served: bool, runners: Vec<Runner>) -> RunnerSet {
        RunnerSet {
            network_id: id.into(),
            network_name: name.into(),
            is_default: false,
            served,
            runners,
        }
    }

    #[test]
    fn a_set_finds_by_either_spelling_and_filters_to_dispatchable() {
        let set = set(
            "net-1",
            "prod-runners",
            true,
            vec![
                runner("hd-1", "bigbox", RunnerStatus::Online),
                runner("hd-2", "oldbox", RunnerStatus::Stale),
                runner("hd-3", "ghost", RunnerStatus::Orphaned),
            ],
        );
        assert_eq!(set.find("bigbox").unwrap().id, "hd-1");
        assert_eq!(set.find("hd-2").unwrap().name, "oldbox");
        assert!(set.find("nope").is_none());

        let live: Vec<&str> = set.dispatchable().map(|r| r.id.as_str()).collect();
        assert_eq!(live, ["hd-1"]);
    }

    /// A network is addressed by name or id, the same two spellings `uses:` and
    /// a repository assignment may use.
    #[test]
    fn a_network_is_addressable_by_id_or_by_name() {
        let s = set("net-1", "prod-runners", true, vec![]);
        assert!(s.matches("net-1"));
        assert!(s.matches("prod-runners"));
        assert!(s.matches("PROD-Runners"), "names are case-insensitive");
        assert!(!s.matches("net-2"));
    }

    /// The pool's job: hand back only what this instance may dispatch to, while
    /// still knowing about the rest so the dashboard can explain the difference.
    #[test]
    fn a_pool_separates_served_networks_from_the_ones_it_only_knows_about() {
        let pool = Pool {
            networks: vec![
                set(
                    "net-1",
                    "prod",
                    true,
                    vec![runner("hd-1", "big", RunnerStatus::Online)],
                ),
                set(
                    "net-2",
                    "lab",
                    false,
                    vec![runner("hd-2", "bench", RunnerStatus::Online)],
                ),
            ],
            unjoined: vec![],
            last_error: None,
            default_network_id: "net-1".into(),
            default_node_id: String::new(),
        };

        assert_eq!(pool.served().count(), 1);
        assert_eq!(pool.served_names(), ["prod"]);
        assert_eq!(pool.default_set().unwrap().network_id, "net-1");
        // `find` sees every network — the caller decides what an unserved one
        // means, because "exists but not served" is a different message from
        // "no such network".
        assert!(pool.find("lab").is_some());
        assert!(!pool.find("lab").unwrap().served);
        assert!(pool.find("nope").is_none());
        // Only served runners are reclaimable: a VM on a host this instance does
        // not dispatch to belongs to whichever instance does.
        let ours: Vec<&str> = pool.all_runners().map(|r| r.id.as_str()).collect();
        assert_eq!(ours, ["hd-1"]);
    }

    /// With no network served there is nothing to default to, and saying so is
    /// what turns "my build is stuck" into "CI_NETWORK matches nothing".
    #[test]
    fn a_pool_with_nothing_served_has_no_default() {
        let pool = Pool {
            networks: vec![set("net-2", "lab", false, vec![])],
            unjoined: vec![],
            last_error: None,
            default_network_id: String::new(),
            default_node_id: String::new(),
        };
        assert!(pool.default_set().is_none());
        assert!(pool.served_names().is_empty());
    }

    /// The default falls back rather than vanishing: `CI_NETWORK=*` names no
    /// first entry, so the account's own default network is used.
    #[test]
    fn the_default_network_falls_back_to_the_accounts_own() {
        let mut lab = set("net-2", "lab", true, vec![]);
        lab.is_default = true;
        let networks = vec![set("net-1", "prod", true, vec![]), lab];

        unsafe { std::env::set_var("CI_NETWORK", "*") };
        let config = test_config();
        assert_eq!(Runners::pick_default(&networks, &config), "net-2");

        // A named first entry wins over the account default.
        unsafe { std::env::set_var("CI_NETWORK", "prod") };
        let config = test_config();
        assert_eq!(Runners::pick_default(&networks, &config), "net-1");
        unsafe { std::env::set_var("CI_NETWORK", "test-net") };
    }

    /// A member of kind `host` with no daemon row is the "unregistered but
    /// still in the network" case, and must be visible rather than dropped.
    #[test]
    fn daemon_status_maps_onto_runner_status() {
        assert_eq!(
            RunnerStatus::from(DaemonStatus::Online),
            RunnerStatus::Online
        );
        assert_eq!(RunnerStatus::from(DaemonStatus::Stale), RunnerStatus::Stale);
        assert_eq!(
            RunnerStatus::from(DaemonStatus::Offline),
            RunnerStatus::Offline
        );
    }

    /// Every error has to name what to do about it — these are read by whoever
    /// is staring at a job that will not start.
    #[test]
    fn errors_name_the_fix() {
        let e = RunnerError::UnknownNetwork {
            wanted: "prod".into(),
            available: vec!["default".into(), "lab".into()],
        };
        let s = e.to_string();
        assert!(s.contains("prod"), "{s}");
        assert!(s.contains("default, lab"), "{s}");

        let e = RunnerError::NoTicket {
            runner: "hd-1".into(),
            detail: "not yet fully online".into(),
        };
        assert!(e.to_string().contains("heyvmd is running"), "{e}");

        let e = RunnerError::DaemonUnauthenticated("hd-1".into());
        assert!(e.to_string().contains("JWT_SECRET"), "{e}");
    }

    /// Member and daemon payloads exactly as the stage control plane returned
    /// them on 2026-08-03, so the projection is pinned to the real wire shape
    /// rather than to my reading of the SDK's structs.
    fn members(json: &str) -> Vec<heyo_sdk::NetworkMember> {
        serde_json::from_str(json).expect("members parse")
    }
    fn daemons(json: &str) -> Vec<DaemonInfo> {
        serde_json::from_str(json).expect("daemons parse")
    }

    /// The failure this guards against is the expensive one: a real network is
    /// mostly `deployed` members, because every sandbox joins one. Treating
    /// those as runners would aim jobs at VMs instead of hosts.
    #[test]
    fn only_host_members_become_runners() {
        let m = members(
            r#"[
              {"device_name":null,"last_seen_at":null,"network_id":"net-1",
               "registered_at":"2026-08-03T20:06:39.420241Z",
               "sandbox_kind":"deployed","sandbox_ref":"dep-d9426372"},
              {"device_name":null,"last_seen_at":null,"network_id":"net-1",
               "registered_at":"2026-08-03T19:50:36.461185Z",
               "sandbox_kind":"deployed","sandbox_ref":"dep-7fa5890b"},
              {"device_name":"pop-os","last_seen_at":null,"network_id":"net-1",
               "registered_at":"2026-08-03T19:12:00.840094Z",
               "sandbox_kind":"host","sandbox_ref":"hd-e_QxrdQOWUsfINWO"},
              {"device_name":null,"last_seen_at":null,"network_id":"net-1",
               "registered_at":"2026-08-03T19:00:00.000000Z",
               "sandbox_kind":"local","sandbox_ref":"sb-123"}
            ]"#,
        );
        let d = daemons(
            r#"[{"id":"hd-e_QxrdQOWUsfINWO","name":"pop-os","status":"online",
                 "lastSeenAt":"2026-08-03T23:39:00Z","createdAt":"2026-07-16T14:04:00Z"}]"#,
        );

        let (runners, joined) = Runners::project(&m, &d);
        assert_eq!(runners.len(), 1, "only the host member is a runner");
        assert_eq!(runners[0].id, "hd-e_QxrdQOWUsfINWO");
        assert_eq!(runners[0].name, "pop-os");
        assert_eq!(runners[0].status, RunnerStatus::Online);
        assert_eq!(joined, ["hd-e_QxrdQOWUsfINWO"]);
    }

    /// The live account on 2026-08-03: members present, but every one of them
    /// `deployed`. Zero runners is the truthful answer, not a bug.
    #[test]
    fn a_network_of_only_deployed_members_yields_no_runners() {
        let m = members(
            r#"[{"device_name":null,"last_seen_at":null,"network_id":"net-1",
                 "registered_at":"2026-08-03T20:06:39.420241Z",
                 "sandbox_kind":"deployed","sandbox_ref":"dep-d9426372"}]"#,
        );
        let (runners, joined) = Runners::project(&m, &[]);
        assert!(runners.is_empty());
        assert!(joined.is_empty());
    }

    fn daemon(id: &str, name: &str, status: DaemonStatus) -> DaemonInfo {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": name,
            "status": match status {
                DaemonStatus::Online => "online",
                DaemonStatus::Stale => "stale",
                DaemonStatus::Offline => "offline",
            },
            "lastSeenAt": "2026-08-08T00:00:00Z",
            "createdAt": "2026-07-01T00:00:00Z",
        }))
        .expect("daemon parses")
    }

    /// The failure this exists to stop: a machine that re-registered keeps two
    /// daemon rows with the same hostname-derived name, and taking whichever
    /// the cloud listed first can pin every job to the dead one — a queue
    /// nothing consumes, with a locally healthy daemon sitting beside it.
    #[test]
    fn a_name_shared_by_a_dead_and_a_live_daemon_resolves_to_the_live_one() {
        let daemons = [
            daemon("hd-old", "us2.heyo.computer", DaemonStatus::Stale),
            daemon(
                "hd-YdBcLuMVw4mA-zv9",
                "us2.heyo.computer",
                DaemonStatus::Online,
            ),
        ];
        assert_eq!(
            pick_daemon(&daemons, "us2.heyo.computer").unwrap().id,
            "hd-YdBcLuMVw4mA-zv9",
            "the live daemon wins, whatever the order"
        );

        // And regardless of which the cloud lists first.
        let reversed = [daemons[1].clone(), daemons[0].clone()];
        assert_eq!(
            pick_daemon(&reversed, "us2.heyo.computer").unwrap().id,
            "hd-YdBcLuMVw4mA-zv9"
        );
    }

    /// An exact id is unambiguous even when a name collides with it.
    #[test]
    fn an_exact_daemon_id_wins_outright() {
        let daemons = [
            daemon("hd-old", "us2.heyo.computer", DaemonStatus::Online),
            daemon("hd-new", "us2.heyo.computer", DaemonStatus::Stale),
        ];
        assert_eq!(pick_daemon(&daemons, "hd-new").unwrap().id, "hd-new");
    }

    /// With no live candidate — or several — there is no answer that is not a
    /// guess, and guessing is what produced the silent stall.
    #[test]
    fn an_unresolvable_name_is_refused_rather_than_guessed() {
        let both_dead = [
            daemon("hd-a", "box", DaemonStatus::Stale),
            daemon("hd-b", "box", DaemonStatus::Offline),
        ];
        match pick_daemon(&both_dead, "box") {
            Err(PickError::Ambiguous(c)) => {
                assert_eq!(c.len(), 2);
                assert!(c.iter().any(|s| s.contains("hd-a")), "{c:?}");
            }
            Ok(d) => panic!("guessed {}", d.id),
            Err(e) => panic!("{e:?}"),
        }

        let both_live = [
            daemon("hd-a", "box", DaemonStatus::Online),
            daemon("hd-b", "box", DaemonStatus::Online),
        ];
        assert!(matches!(
            pick_daemon(&both_live, "box"),
            Err(PickError::Ambiguous(_))
        ));

        assert!(matches!(
            pick_daemon(&both_live, "nope"),
            Err(PickError::NoMatch)
        ));
    }

    /// A network name has to be spellable in `uses: <network>/<runner>`, which
    /// splits on the first `/`. The local-mode network once carried its daemon
    /// URL in its name, which made it the one network no workflow could name.
    #[test]
    fn the_local_networks_name_is_addressable_by_uses() {
        let pool = Runners::local_pool();
        let name = &pool.networks[0].network_name;
        assert!(!name.contains('/'), "{name:?} cannot be spelled in `uses:`");

        let target = crate::workflow::Target::parse(name).expect("uses: accepts it");
        assert_eq!(target.network.as_deref(), Some(name.as_str()));
        assert!(pool.find(name).is_some(), "and it resolves back");
    }

    /// A daemon in no network is the commonest "why is nothing running" cause.
    /// `project` reports membership per network; whether a daemon belongs to
    /// *none* is the caller's join across all of them, and this pins the half
    /// that makes that possible.
    #[test]
    fn a_daemon_in_no_network_is_absent_from_every_membership_list() {
        let d = daemons(
            r#"[{"id":"hd-laptop","name":"laptop","status":"online",
                 "lastSeenAt":"2026-08-03T23:39:00Z","createdAt":"2026-07-16T14:04:00Z"}]"#,
        );
        let (runners, joined) = Runners::project(&[], &d);
        assert!(runners.is_empty());
        assert!(
            joined.is_empty(),
            "it joined nothing, so it is nobody's member"
        );
    }

    /// A host member with no daemon row was unregistered but left behind. It
    /// must stay visible — and must not be dispatchable.
    #[test]
    fn a_host_member_with_no_daemon_row_is_orphaned() {
        let m = members(
            r#"[{"device_name":"ghost","last_seen_at":"2026-08-01T00:00:00Z",
                 "network_id":"net-1","registered_at":"2026-08-01T00:00:00Z",
                 "sandbox_kind":"host","sandbox_ref":"hd-gone"}]"#,
        );
        let (runners, _) = Runners::project(&m, &[]);
        assert_eq!(runners.len(), 1);
        assert_eq!(runners[0].status, RunnerStatus::Orphaned);
        assert!(!runners[0].status.is_dispatchable());
        // Falls back to the member's device name when there is no daemon label.
        assert_eq!(runners[0].name, "ghost");
        assert_eq!(
            runners[0].last_seen_at.as_deref(),
            Some("2026-08-01T00:00:00Z")
        );
    }

    /// With neither a daemon label nor a device name there is still something
    /// to address the runner by, and `uses:` has to be able to name it.
    #[test]
    fn a_nameless_host_falls_back_to_its_daemon_id() {
        let m = members(
            r#"[{"device_name":null,"last_seen_at":null,"network_id":"net-1",
                 "registered_at":"2026-08-01T00:00:00Z",
                 "sandbox_kind":"host","sandbox_ref":"hd-anon"}]"#,
        );
        let (runners, _) = Runners::project(&m, &[]);
        assert_eq!(runners[0].name, "hd-anon");
        assert!(runners[0].matches("hd-anon"));
    }

    /// Daemon ids carry `_` (the live one is `hd-e_QxrdQOWUsfINWO`), and they
    /// are interpolated into NATS subjects and durable consumer names verbatim.
    #[test]
    fn a_real_daemon_id_is_a_valid_subject_token() {
        assert!(crate::config::is_subject_token("hd-e_QxrdQOWUsfINWO"));
    }

    #[test]
    fn an_empty_account_says_so_rather_than_listing_nothing() {
        let e = RunnerError::UnknownNetwork {
            wanted: "prod".into(),
            available: vec![],
        };
        assert!(e.to_string().contains("this account has none"), "{e}");
    }

    fn test_config() -> Config {
        unsafe {
            std::env::set_var("CI_HEYO_API_KEY", "test-key");
            // Required by `Config::from_env`; without it these tests passed
            // only when another test had happened to set it first. Only a
            // default: some tests set their own before calling this.
            if std::env::var_os("CI_NETWORK").is_none() {
                std::env::set_var("CI_NETWORK", "test-net");
            }
            std::env::set_var("CI_DATABASE_URL", "postgres://localhost/ci_test");
            std::env::set_var("CI_WEBHOOK_SECRET", "0123456789abcdef");
        }
        Config::from_env().expect("test config resolves")
    }

    #[tokio::test]
    async fn active_vms_keep_evicted_tunnel_ownership_until_last_handle_drops() {
        let mut config = test_config();
        config.heyvm.local_runner = None;
        let runners = Runners::new(Arc::new(config));
        let client = |port| HeyoClient::new(HeyoClientOptions {
            api_key: Some("test-key".into()),
            base_url: Some(format!("http://127.0.0.1:{port}")),
            timeout: None,
        }).unwrap();
        runners.tunnels.lock().await.insert("hd-test".into(), client(31001));
        let connection = runners.options_for("hd-test").await.unwrap();
        let owner = Arc::downgrade(connection._tunnel.as_ref().unwrap());
        let vms = crate::vm::Vms::new();
        let first = vms.open(connection.clone(), "sb-first".into()).await.unwrap();
        let second = vms.open(connection, "sb-second".into()).await.unwrap();

        runners.evict("hd-test").await;
        assert!(runners.tunnels.lock().await.is_empty());
        assert!(owner.upgrade().is_some(), "cache eviction dropped active VM connection ownership");
        // A replacement connection must not redirect existing operations.
        runners.tunnels.lock().await.insert("hd-test".into(), client(31002));
        let replacement = runners.options_for("hd-test").await.unwrap();
        assert_eq!(replacement.options.base_url.as_deref(), Some("http://127.0.0.1:31002"));
        assert_eq!(owner.upgrade().unwrap().base_url(), "http://127.0.0.1:31001");
        drop(first);
        assert!(owner.upgrade().is_some(), "another VM still owns the old connection");
        drop(second);
        assert!(owner.upgrade().is_none(), "unused connection must not leak");
    }

    #[tokio::test]
    async fn direct_runner_capabilities_use_daemon_credentials_without_cloud_registration() {
        use axum::{Json, Router, http::HeaderMap, routing::get};
        let app = Router::new().route("/capabilities", get(|headers: HeaderMap| async move {
            assert_eq!(headers["authorization"], "Bearer daemon-only-key");
            Json(serde_json::json!({"supportedDrivers":["firecracker","libvirt"]}))
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        unsafe { std::env::set_var("CI_NETWORK", "test-net") };
        let mut config = test_config();
        config.heyvm.base_url = Some("http://127.0.0.1:1".into());
        config.heyvm.local_runner = Some(url);
        config.heyvm.local_runner_token = Some("daemon-only-key".into());
        let runners = Runners::new(Arc::new(config));
        let result = runners.supported_drivers("hd-local").await;
        server.abort();
        assert_eq!(result.unwrap().unwrap().as_ref(), &["firecracker", "libvirt"]);
    }

    #[tokio::test]
    async fn disk_placement_reads_fresh_authenticated_capacity_and_rejects_unknown() {
        use axum::{Json, Router, http::{HeaderMap, StatusCode}, routing::get};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let reads = Arc::new(AtomicUsize::new(0));
        let calls = reads.clone();
        let app = Router::new().route("/storage", get(move |headers: HeaderMap| {
            let calls = calls.clone();
            async move {
                assert_eq!(headers["authorization"], "Bearer daemon-only-key");
                match calls.fetch_add(1, Ordering::SeqCst) {
                    0 => (StatusCode::OK, Json(serde_json::json!({"free_bytes": 100}))),
                    1 => (StatusCode::OK, Json(serde_json::json!({"free_bytes": 0}))),
                    2 => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"free_bytes": 999}))),
                    3 => (StatusCode::OK, Json(serde_json::json!({"free_bytes": 75}))),
                    4 | 5 => (StatusCode::OK, Json(serde_json::json!({}))),
                    _ => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"free_bytes": 999}))),
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        unsafe { std::env::set_var("CI_NETWORK", "test-net") };
        let mut config = test_config();
        config.heyvm.local_runner = Some(url);
        config.heyvm.local_runner_token = Some("daemon-only-key".into());
        let runners = Runners::new(Arc::new(config));
        let cached = HeyoClient::new(runners.client_options()).unwrap();
        runners.tunnels.lock().await.insert("hd-local".into(), cached.clone());
        assert_eq!(runners.free_disk_bytes("hd-local").await.unwrap(), 100);
        assert_eq!(runners.free_disk_bytes("hd-local").await.unwrap(), 0);
        assert!(runners.tunnels.lock().await.contains_key("hd-local"), "low capacity is not a broken connection");
        assert_eq!(runners.free_disk_bytes("hd-local").await.unwrap(), 75,
            "an idempotent capacity read retries immediately after a fresh connection");
        assert!(runners.free_disk_bytes("hd-local").await.is_err());
        assert!(!runners.tunnels.lock().await.contains_key("hd-local"), "unknown capacity must not poison every retry");
        runners.tunnels.lock().await.insert("hd-local".into(), cached);
        assert!(runners.free_disk_bytes("hd-local").await.is_err());
        assert!(!runners.tunnels.lock().await.contains_key("hd-local"), "HTTP failure must force a fresh connection");
        assert_eq!(reads.load(Ordering::SeqCst), 8);
        server.abort();
        let _ = server.await;
        runners.tunnels.lock().await.insert("hd-local".into(), HeyoClient::new(runners.client_options()).unwrap());
        assert!(runners.free_disk_bytes("hd-local").await.is_err());
        assert!(!runners.tunnels.lock().await.contains_key("hd-local"), "transport failure must force a fresh connection");
    }

    /// Every job on a runner shares its tunnel, so a drop is noticed by all of
    /// them at once. Only the tunnel that actually died may be evicted: a job
    /// arriving after another already redialed must pick up the fresh tunnel,
    /// not throw it away and dial again.
    #[tokio::test]
    async fn a_redial_evicts_only_the_tunnel_that_died() {
        let mut config = test_config();
        config.heyvm.local_runner = None;
        // A ticket fetch that fails at once, so a real dial ends quickly.
        config.heyvm.base_url = Some("http://127.0.0.1:1".into());
        let runners = Runners::new(Arc::new(config));
        let client = |port| HeyoClient::new(HeyoClientOptions {
            api_key: Some("test-key".into()),
            base_url: Some(format!("http://127.0.0.1:{port}")),
            timeout: None,
        }).unwrap();

        let connection = runners.options_for_tunnel_test("hd-test", client(31001)).await;
        assert!(connection.redial.is_some(), "a tunnel connection must be able to redial");

        // Somebody else already replaced 31000 with 31001: reuse it.
        let reused = runners.replace_tunnel("hd-test", "http://127.0.0.1:31000").await.unwrap();
        assert_eq!(reused.options.base_url.as_deref(), Some("http://127.0.0.1:31001"));
        assert!(runners.tunnels.lock().await.contains_key("hd-test"));

        // 31001 itself died: evicted, and the redial goes to the control plane.
        assert!(runners.replace_tunnel("hd-test", "http://127.0.0.1:31001").await.is_err());
        assert!(!runners.tunnels.lock().await.contains_key("hd-test"), "the dead tunnel stayed cached");

        // A redial outliving the runner set fails instead of dialing.
        let redial = connection.redial.clone().unwrap();
        drop(runners);
        let err = redial("http://127.0.0.1:31001".into()).await.err().unwrap();
        assert!(err.contains("shutting down"), "{err}");
    }

    fn test_runners(allow_unauthenticated: bool) -> Arc<Runners> {
        unsafe {
            std::env::set_var("CI_HEYO_API_KEY", "test-key");
            std::env::set_var("CI_NETWORK", "test-net");
            std::env::set_var("CI_DATABASE_URL", "postgres://localhost/ci_test");
            std::env::set_var("CI_WEBHOOK_SECRET", "0123456789abcdef");
            std::env::set_var(
                "CI_ALLOW_UNAUTHENTICATED_RUNNERS",
                if allow_unauthenticated {
                    "true"
                } else {
                    "false"
                },
            );
        }
        let c = Config::from_env().expect("test config resolves");
        Runners::new(Arc::new(c))
    }

    /// Requires a local `heyvmd` on 34099. Run with:
    /// `cargo test -- --ignored auth_probe`
    ///
    /// This is the check that matters most and the one unit tests cannot reach:
    /// a daemon started without `JWT_SECRET` serves its whole API — host shell
    /// included — to anyone holding its iroh ticket, and a ticket is
    /// bearer-equivalent. Verified against the daemon on this machine, which
    /// answers `GET /sandboxes` with 200 and no credential.
    #[tokio::test]
    #[ignore = "needs a local heyvmd on 127.0.0.1:34099"]
    async fn auth_probe_catches_a_daemon_that_serves_without_a_credential() {
        let local = HeyoClient::local().expect("local client");

        let strict = test_runners(false);
        let err = strict
            .assert_daemon_requires_auth("hd-local", &local)
            .await
            .expect_err("an unauthenticated daemon must be refused");
        assert!(
            matches!(err, RunnerError::DaemonUnauthenticated(_)),
            "got {err:?}"
        );
        assert!(err.to_string().contains("JWT_SECRET"), "{err}");

        // The escape hatch exists for a local-only loop, and must downgrade the
        // refusal to a warning rather than change what was detected.
        let lax = test_runners(true);
        lax.assert_daemon_requires_auth("hd-local", &local)
            .await
            .expect("the opt-out permits it");
    }

    /// A daemon that cannot be reached proves nothing about its auth, so the
    /// probe must not report it as open — but it must still fail, and it must
    /// fail as `Unreachable` rather than as an auth verdict.
    ///
    /// The probe used to return `Ok(())` here and defer to the real request.
    /// That real request is the first tunnel traffic a job sends, so deferring
    /// meant caching a tunnel that carries nothing and rediscovering it one
    /// request timeout later, blamed on whichever route happened to be first.
    #[tokio::test]
    async fn an_unreachable_daemon_fails_as_unreachable_not_as_an_auth_verdict() {
        // Port 1 on loopback: nothing listens, and connecting fails fast.
        let dead = HeyoClient::local_at("http://127.0.0.1:1").expect("client");
        let err = test_runners(false)
            .assert_daemon_requires_auth("hd-dead", &dead)
            .await
            .expect_err("a tunnel that carries nothing must not be cached");
        assert!(
            matches!(&err, RunnerError::Unreachable { runner, .. } if runner == "hd-dead"),
            "a transport failure must not be reported as an auth verdict: {err:?}"
        );
    }

    /// The opt-out covers *auth*, not reachability. A dead tunnel is still dead
    /// however permissive the config is, and must not be cached either way.
    #[tokio::test]
    async fn allowing_unauthenticated_runners_does_not_excuse_a_dead_tunnel() {
        let dead = HeyoClient::local_at("http://127.0.0.1:1").expect("client");
        let err = test_runners(true)
            .assert_daemon_requires_auth("hd-dead", &dead)
            .await
            .expect_err("the opt-out is about bearers, not about transport");
        assert!(matches!(err, RunnerError::Unreachable { .. }), "{err:?}");
    }
}
