//! Where a `spread` deployment's replicas run (`docs/design/fleet-shared-state.md`
//! § 4): the placement controller, and each host's view of its decisions.
//!
//! **Every host**, once a second:
//! - reports `(in_flight, waiters, ready, booting, idle)` for each `spread`
//!   deployment it runs into `host_demand`, only when the numbers change;
//! - reads every host's reports and every placement target into a [`View`].
//!   The data plane reads the view, never the database.
//!
//! **The controller**, whichever host holds the `placement` lease, every 2 s:
//! - computes each `spread` deployment's fleet-wide replica count with the
//!   same formula a single host uses ([`crate::deployment::desired_for`]),
//!   from the fleet's summed demand, so `min_replicas` and `warm_pool` count
//!   once for the fleet;
//! - splits it over the live, active hosts the deployment may run on,
//!   preferring hosts with demand, then hosts already running replicas;
//! - writes `placement_targets`, fenced by the lease's epoch.
//!
//! It never creates a VM. Each host's autoscaler reconciles its own daemon to
//! its own target ([`target`]). Without a controller, a host keeps its last
//! target. One exception covers scale-from-zero: a request waits on a host
//! only when no peer has replicas ready or is asked to run any (or it arrived
//! by hop), so a host holding a waiter with a target of zero boots one
//! replica on its own authority. The controller absorbs it on its next tick,
//! since that host now reports the demand.

use crate::config::{DeploymentSpec, PlacementMode, ScalingPolicy};
use crate::fleet_pg::{DemandReport, HostRow};
use crate::fleet_sync::{Fleet, Lease};
use crate::registry::Registry;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const LEASE_PLACEMENT: &str = "placement";
const SYNC_EVERY: Duration = Duration::from_secs(1);
const PLAN_EVERY: Duration = Duration::from_secs(2);
/// The controller rewrites an unchanged plan this often, so a target lost
/// to a failed write never stays lost.
const REWRITE_EVERY: Duration = Duration::from_secs(30);

/// This process's placer, in fleet mode. Global because every `Deployment`
/// asks it for its target and deployments are rebuilt on every spec write.
static PLACER: OnceLock<Arc<Placer>> = OnceLock::new();

pub fn install(placer: Arc<Placer>) {
    let _ = PLACER.set(placer);
}

pub fn placer() -> Option<&'static Arc<Placer>> {
    PLACER.get()
}

pub(crate) fn spreads(spec: &DeploymentSpec) -> bool {
    spec.placement
        .as_ref()
        .is_some_and(|p| p.mode == PlacementMode::Spread)
}

/// How many replicas this host should run for `spec`, when the fleet decides
/// that rather than this host: `None` for anything but a `spread` deployment
/// in fleet mode.
pub fn target(spec: &DeploymentSpec, waiters: usize) -> Option<u32> {
    if !spreads(spec) {
        return None;
    }
    let placer = placer()?;
    let view = placer.view.load();
    // Before the first read, the host sizes itself: a restart must keep the
    // replicas it adopts, not drain them for an empty view.
    if !view.loaded {
        return None;
    }
    let mine = view
        .targets
        .get(&spec.id)
        .and_then(|(_, hosts)| hosts.get(&placer.host).copied())
        .unwrap_or(0);
    // A request waits here only when no peer could take it (or it arrived
    // by hop), so a waiter with no target here boots one replica here.
    let stranded = waiters > 0 && mine == 0;
    Some(if stranded { 1 } else { mine }.min(spec.scaling.max_replicas))
}

/// The cached state of the fleet's placement, as of the last sync.
#[derive(Debug, Default)]
pub struct View {
    /// Whether this was read from the fleet, not the empty start.
    loaded: bool,
    /// deployment → (generation, host → desired).
    targets: HashMap<String, (u64, HashMap<String, u32>)>,
    /// deployment → host → report.
    demand: HashMap<String, HashMap<String, DemandReport>>,
}

pub struct Placer {
    host: String,
    fleet: Arc<Fleet>,
    registry: Arc<Registry>,
    forwards: bool,
    lease: Arc<Lease>,
    view: ArcSwap<View>,
    /// What this host last reported, so unchanged numbers are not rewritten.
    reported: Mutex<Option<HashMap<String, DemandReport>>>,
    planned: Mutex<Option<Instant>>,
    last_write: Mutex<Option<Instant>>,
}

impl Placer {
    pub fn new(host: &str, fleet: Arc<Fleet>, registry: Arc<Registry>, forwards: bool) -> Self {
        let lease = fleet.lease(LEASE_PLACEMENT);
        Self {
            host: host.to_string(),
            fleet,
            registry,
            forwards,
            lease,
            view: ArcSwap::from_pointee(View::default()),
            reported: Mutex::new(None),
            planned: Mutex::new(None),
            last_write: Mutex::new(None),
        }
    }

    /// A live peer with ready replicas of `id`, least utilised first: where a
    /// request goes when this host has none ready.
    pub fn peer_ready(&self, id: &str) -> Option<String> {
        let view = self.view.load();
        // A peer the controller no longer asks to run any is about to drain
        // the ones it has, so it is passed over.
        let targets = view.targets.get(id).map(|(_, t)| t);
        view.demand
            .get(id)?
            .iter()
            .filter(|(h, r)| {
                r.ready > 0
                    && targets.is_none_or(|t| t.get(*h).is_some_and(|n| *n > 0))
                    && self.reachable(h)
            })
            // in_flight / ready, compared without division.
            .min_by(|(ha, a), (hb, b)| {
                (a.in_flight * b.ready)
                    .cmp(&(b.in_flight * a.ready))
                    .then_with(|| ha.cmp(hb))
            })
            .map(|(h, _)| h.clone())
    }

    /// A live peer the controller has asked to run `id`, the one asked for
    /// most first: where a request goes to wait for a cold start this host
    /// is not asked to make.
    pub fn peer_targeted(&self, id: &str) -> Option<String> {
        let view = self.view.load();
        let (_, hosts) = view.targets.get(id)?;
        hosts
            .iter()
            .filter(|(h, n)| **n > 0 && self.reachable(h))
            .max_by(|(ha, a), (hb, b)| a.cmp(b).then_with(|| hb.cmp(ha)))
            .map(|(h, _)| h.clone())
    }

    /// This host's target for `id`.
    pub fn mine(&self, id: &str) -> u32 {
        let view = self.view.load();
        view.targets
            .get(id)
            .and_then(|(_, hosts)| hosts.get(&self.host).copied())
            .unwrap_or(0)
    }

    fn reachable(&self, host: &str) -> bool {
        host != self.host
            && self
                .fleet
                .live_member(host)
                .is_some_and(|m| m.address.is_some())
    }

    /// Whether this host issues `spec`'s certificate. A `spread` deployment
    /// runs on several hosts and so is certified by one of them: the first by
    /// name among the live hosts that run it, or this host when it knows of
    /// no other.
    pub fn issues_certificate(&self, spec: &DeploymentSpec) -> bool {
        let Some(placement) = spec.placement.as_ref().filter(|_| spreads(spec)) else {
            return true;
        };
        let mut hosts: Vec<String> = self
            .fleet
            .live_members()
            .into_iter()
            .filter(|m| m.state == "active" && placement.includes(&m.host))
            .map(|m| m.host)
            .collect();
        if placement.includes(&self.host) {
            hosts.push(self.host.clone());
        }
        hosts
            .into_iter()
            .min()
            .is_none_or(|first| first == self.host)
    }

    /// Report, read, and — holding the lease — plan.
    async fn sync(&self) {
        self.report().await;
        let pg = self.fleet.pg();
        match (pg.demand().await, pg.targets().await) {
            (Ok(demand), Ok(targets)) => {
                let mut view = View {
                    loaded: true,
                    ..View::default()
                };
                for (host, id, report) in demand {
                    view.demand.entry(id).or_default().insert(host, report);
                }
                for (id, host, desired, generation) in targets {
                    let entry = view.targets.entry(id).or_default();
                    entry.0 = entry.0.max(generation);
                    entry.1.insert(host, desired);
                }
                self.view.store(Arc::new(view));
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::debug!(error = %e, "could not read the fleet's placement; keeping the last view")
            }
        }
        let due = self
            .planned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none_or(|t| t.elapsed() >= PLAN_EVERY);
        if due && let Some(epoch) = self.lease.held() {
            *self.planned.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
            self.plan(epoch).await;
        }
    }

    /// Publish this host's numbers for the `spread` deployments it runs.
    async fn report(&self) {
        let now: HashMap<String, DemandReport> = self
            .registry
            .deployments()
            .values()
            .filter(|d| spreads(&d.spec))
            .map(|d| {
                (
                    d.spec.id.clone(),
                    DemandReport {
                        in_flight: d.total_in_flight() as u64,
                        waiters: d.waiters() as u64,
                        ready: d.backends().iter().filter(|b| !b.is_draining()).count() as u64,
                        booting: d.pending().len() as u64,
                        idle_secs: d.idle_for().min(u32::MAX as u64),
                    },
                )
            })
            .collect();
        let last = self
            .reported
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let clear = last.is_none();
        let last = last.unwrap_or_default();
        let rows: Vec<_> = now
            .iter()
            .filter(|(id, r)| last.get(*id) != Some(r))
            .map(|(id, r)| (id.clone(), *r))
            .collect();
        let gone: Vec<_> = last
            .keys()
            .filter(|id| !now.contains_key(*id))
            .cloned()
            .collect();
        if !clear && rows.is_empty() && gone.is_empty() {
            return;
        }
        match self
            .fleet
            .pg()
            .report_demand(&self.host, rows, gone, clear)
            .await
        {
            Ok(()) => *self.reported.lock().unwrap_or_else(|e| e.into_inner()) = Some(now),
            Err(e) => tracing::debug!(error = %e, "could not report this host's demand"),
        }
    }

    /// The controller's tick.
    async fn plan(&self, epoch: u64) {
        let members: Vec<HostRow> = self
            .fleet
            .live_members()
            .into_iter()
            .filter(|m| m.state == "active")
            .collect();
        if members.is_empty() {
            // Not even this host: the member list is not readable yet.
            return;
        }
        let local = self.registry.deployments();
        let foreign = self.registry.foreign();
        let specs = local
            .values()
            .map(|d| &d.spec)
            .chain(foreign.values().map(|s| s.as_ref()))
            .filter(|s| spreads(s));
        let view = self.view.load();
        let mut plan = Vec::new();
        let mut changed = false;
        for spec in specs {
            let placement = spec.placement.as_ref().expect("spread has a placement");
            let eligible: Vec<&str> = members
                .iter()
                .map(|m| m.host.as_str())
                .filter(|h| placement.includes(h))
                .collect();
            let reports = view.demand.get(&spec.id);
            let assigned = assign(&spec.scaling, &eligible, reports);
            let (generation, current) = view.targets.get(&spec.id).cloned().unwrap_or_default();
            let same = assigned.len() == current.len()
                && assigned.iter().all(|(h, n)| current.get(h) == Some(n));
            if !same {
                changed = true;
                tracing::info!(
                    deployment = %spec.id,
                    targets = ?assigned,
                    generation = generation + 1,
                    "placement changed"
                );
            }
            plan.push((
                spec.id.clone(),
                if same { generation } else { generation + 1 },
                assigned,
            ));
        }
        changed |= view
            .targets
            .keys()
            .any(|id| !plan.iter().any(|(p, _, _)| p == id));
        let rewrite = {
            let mut last = self.last_write.lock().unwrap_or_else(|e| e.into_inner());
            let due = changed || last.is_none_or(|t| t.elapsed() >= REWRITE_EVERY);
            if due {
                *last = Some(Instant::now());
            }
            due
        };
        if !rewrite {
            return;
        }
        match self
            .fleet
            .pg()
            .write_targets(LEASE_PLACEMENT, epoch, plan)
            .await
        {
            Ok(true) => {}
            Ok(false) => tracing::warn!(epoch, "placement lease lost; the plan was not written"),
            Err(e) => tracing::warn!(error = %e, "could not write the placement plan"),
        }
    }
}

/// Split `spec`'s fleet-wide replica count over `eligible` hosts. Every
/// eligible host gets a row, zero included, so a host that should run nothing
/// is told so.
pub fn assign(
    policy: &ScalingPolicy,
    eligible: &[&str],
    reports: Option<&HashMap<String, DemandReport>>,
) -> Vec<(String, u32)> {
    let report = |h: &str| reports.and_then(|r| r.get(h)).copied().unwrap_or_default();
    let counted: Vec<DemandReport> = eligible.iter().map(|h| report(h)).collect();
    let demand: u64 = counted.iter().map(|r| r.in_flight + r.waiters).sum();
    let idle = counted
        .iter()
        .filter(|r| r.ready + r.booting > 0)
        .map(|r| r.idle_secs)
        .min()
        .unwrap_or(u64::MAX);
    let desired = crate::deployment::desired_for(policy, demand as usize, idle);

    // Demand first (a replica where the requests are), then replicas already
    // running (no churn), then name (stable).
    let mut order: Vec<&str> = eligible.to_vec();
    order.sort_by(|a, b| {
        let (ra, rb) = (report(a), report(b));
        (rb.in_flight + rb.waiters)
            .cmp(&(ra.in_flight + ra.waiters))
            .then((rb.ready + rb.booting).cmp(&(ra.ready + ra.booting)))
            .then(a.cmp(b))
    });
    let n = order.len().max(1) as u32;
    let shares: Vec<(&str, u32)> = order
        .iter()
        .enumerate()
        .map(|(i, h)| (*h, desired / n + u32::from((i as u32) < desired % n)))
        .collect();
    // Make before break: while any host is short of its share, no host is
    // asked to give up a replica it has ready, so moving one never dips
    // serving capacity. Once the new ones are ready the shares apply, and
    // the old host drains its extra.
    let hold = shares
        .iter()
        .any(|(h, share)| u64::from(*share) > report(h).ready);
    shares
        .into_iter()
        .map(|(h, share)| {
            let ready = report(h).ready.min(u64::from(u32::MAX)) as u32;
            (h.to_string(), if hold { share.max(ready) } else { share })
        })
        .collect()
}

/// The placer as a pingora service.
pub struct Service(pub Arc<Placer>);

#[async_trait]
impl BackgroundService for Service {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let placer = &self.0;
        tracing::info!(host = %placer.host, forwards = placer.forwards, "fleet placement running");
        let mut ticker = tokio::time::interval(SYNC_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => placer.sync().await,
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(min: u32, max: u32, warm: u32, tc: u32) -> ScalingPolicy {
        ScalingPolicy {
            min_replicas: min,
            max_replicas: max,
            warm_pool: warm,
            target_concurrency: tc,
            scale_to_zero_after_secs: 300,
            ..Default::default()
        }
    }

    fn reports(rows: &[(&str, u64, u64, u64)]) -> HashMap<String, DemandReport> {
        rows.iter()
            .map(|(h, in_flight, waiters, ready)| {
                (
                    h.to_string(),
                    DemandReport {
                        in_flight: *in_flight,
                        waiters: *waiters,
                        ready: *ready,
                        booting: 0,
                        idle_secs: 0,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn min_replicas_count_once_for_the_fleet() {
        let a = assign(&policy(2, 5, 0, 10), &["us4", "us5"], None);
        assert_eq!(a, vec![("us4".into(), 1), ("us5".into(), 1)]);
        let a = assign(&policy(3, 5, 0, 10), &["us4", "us5"], None);
        assert_eq!(a.iter().map(|(_, n)| n).sum::<u32>(), 3);
    }

    #[test]
    fn a_lone_replica_goes_where_the_demand_is() {
        let r = reports(&[("us5", 0, 1, 0)]);
        let a = assign(&policy(0, 5, 0, 10), &["us4", "us5"], Some(&r));
        assert_eq!(a, vec![("us5".into(), 1), ("us4".into(), 0)]);
    }

    #[test]
    fn demand_is_summed_across_hosts() {
        // 12 + 9 in flight at 10 per replica: 3 replicas for the fleet,
        // where one host alone would have asked for 2 and the other for 1.
        let r = reports(&[("us4", 12, 0, 2), ("us5", 9, 0, 1)]);
        let a = assign(&policy(0, 10, 0, 10), &["us4", "us5"], Some(&r));
        assert_eq!(a, vec![("us4".into(), 2), ("us5".into(), 1)]);
    }

    #[test]
    fn with_no_demand_running_replicas_stay_put() {
        let r = reports(&[("us5", 0, 0, 1)]);
        let a = assign(&policy(1, 5, 0, 10), &["us4", "us5"], Some(&r));
        assert_eq!(a, vec![("us5".into(), 1), ("us4".into(), 0)]);
    }

    #[test]
    fn a_moved_replica_is_made_before_the_old_one_is_broken() {
        // Both of min 2 on us4; us5 joins. us5 is asked for one while us4
        // keeps both until us5's is ready, then gives one up.
        let joining = reports(&[("us4", 0, 0, 2)]);
        let a = assign(&policy(2, 5, 0, 10), &["us4", "us5"], Some(&joining));
        assert_eq!(a, vec![("us4".into(), 2), ("us5".into(), 1)]);
        let a = assign(
            &policy(2, 5, 0, 10),
            &["us4", "us5"],
            Some(&reports(&[("us4", 0, 0, 2), ("us5", 0, 0, 0)])),
        );
        assert_eq!(
            a,
            vec![("us4".into(), 2), ("us5".into(), 1)],
            "still booting"
        );
        let ready = reports(&[("us4", 0, 0, 2), ("us5", 0, 0, 1)]);
        let a = assign(&policy(2, 5, 0, 10), &["us4", "us5"], Some(&ready));
        assert_eq!(a, vec![("us4".into(), 1), ("us5".into(), 1)]);
    }

    #[test]
    fn max_replicas_caps_the_fleet() {
        let r = reports(&[("us4", 100, 0, 1), ("us5", 100, 0, 1)]);
        let a = assign(&policy(0, 3, 0, 10), &["us4", "us5"], Some(&r));
        assert_eq!(a.iter().map(|(_, n)| n).sum::<u32>(), 3);
    }

    fn member(host: &str) -> HostRow {
        HostRow {
            host: host.into(),
            address: Some(format!("{host}.example")),
            state: "active".into(),
            boot_id: "b".into(),
            age_secs: 0.0,
        }
    }

    /// The installed placer, as `Deployment`, the request path and ACME see
    /// it. One test, since there is one per process.
    #[test]
    fn the_installed_placer_steers_targets_peers_and_certificates() {
        let pg = crate::fleet_pg::PgStore::open_in(
            "postgres://u@127.0.0.1:9/x",
            "us4",
            Duration::from_secs(1),
            "fleet",
        )
        .unwrap();
        let fleet = Fleet::new(pg, "/nonexistent/m.json", vec![0; 32]);
        let placer = Arc::new(Placer::new(
            "us4",
            fleet.clone(),
            Arc::new(Registry::new("/dev/null")),
            true,
        ));
        install(placer.clone());

        let mut spec: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id": "web", "routes": [{"host": "web.example"}],
            "vm": {"image": "i", "port": 8080, "driver": "firecracker"},
            "scaling": {"max_replicas": 4},
            "placement": {"mode": "spread"}
        }))
        .unwrap();
        // Before the first read the host sizes itself.
        assert_eq!(target(&spec, 1), None);
        placer.view.store(Arc::new(View {
            loaded: true,
            ..View::default()
        }));
        // Read, with no targets yet: nothing, unless a request is waiting here.
        assert_eq!(target(&spec, 0), Some(0));
        assert_eq!(
            target(&spec, 1),
            Some(1),
            "a stranded waiter boots one here"
        );

        let mut view = View {
            loaded: true,
            ..View::default()
        };
        view.targets.insert(
            "web".into(),
            (
                3,
                HashMap::from([("us4".into(), 0), ("us5".into(), 2), ("us6".into(), 1)]),
            ),
        );
        view.demand.insert(
            "web".into(),
            HashMap::from([
                (
                    "us5".to_string(),
                    DemandReport {
                        in_flight: 9,
                        ready: 2,
                        ..Default::default()
                    },
                ),
                (
                    "us6".to_string(),
                    DemandReport {
                        in_flight: 2,
                        ready: 1,
                        ..Default::default()
                    },
                ),
            ]),
        );
        placer.view.store(Arc::new(view));
        assert_eq!(target(&spec, 0), Some(0));

        // Peers count only while they are live members with an address.
        assert_eq!(placer.peer_ready("web"), None);
        fleet.set_members(vec![member("us4"), member("us5"), member("us6")]);
        assert_eq!(
            placer.peer_ready("web").as_deref(),
            Some("us6"),
            "2/1 beats 9/2"
        );
        assert_eq!(placer.peer_targeted("web").as_deref(), Some("us5"));
        fleet.set_members(vec![member("us4"), member("us5")]);
        assert_eq!(placer.peer_ready("web").as_deref(), Some("us5"));
        // A ready peer whose target went to zero is about to drain.
        let mut view = View {
            loaded: true,
            ..View::default()
        };
        view.targets.insert(
            "web".into(),
            (4, HashMap::from([("us4".into(), 1), ("us5".into(), 0)])),
        );
        view.demand.insert(
            "web".into(),
            HashMap::from([(
                "us5".to_string(),
                DemandReport {
                    ready: 1,
                    ..Default::default()
                },
            )]),
        );
        placer.view.store(Arc::new(view));
        assert_eq!(placer.peer_ready("web"), None);
        assert_eq!(
            placer.peer_targeted("web"),
            None,
            "and nobody else is asked"
        );

        // The first live host by name certifies a spread deployment.
        assert!(placer.issues_certificate(&spec), "us4 < us5");
        spec.placement.as_mut().unwrap().hosts = vec!["us5".into(), "us6".into()];
        assert!(!placer.issues_certificate(&spec), "us4 does not run it");
        fleet.set_members(vec![member("us3"), member("us4")]);
        spec.placement.as_mut().unwrap().hosts = vec![];
        assert!(!placer.issues_certificate(&spec), "us3 < us4");

        // Anything not spread is not the placer's.
        spec.placement = None;
        assert_eq!(target(&spec, 5), None);
        assert!(placer.issues_certificate(&spec));
    }

    #[test]
    fn no_eligible_host_gets_nothing() {
        assert!(assign(&policy(2, 5, 0, 10), &[], None).is_empty());
    }
}
