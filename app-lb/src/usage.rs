//! Billable traffic, counted for whoever bills it.
//!
//! app-lb meters; it never prices. Every proxied request is counted against
//! the deployment that answered it — one request, and the response body bytes
//! sent back to the client — under the account the deployment is metered to
//! (`DeploymentSpec::account_id`). `GET /usage` serves the running totals to a
//! fleet-wide caller (the managed platform's billing collector), which turns
//! them into charges. What a request or a byte costs is not this crate's
//! business and nothing here knows it.
//!
//! ## Counted once
//!
//! A request is counted by the host the client connected to. A fleet hop is
//! counted by the ingress host that forwarded it, never again by the home
//! host that served it (`RequestState::arrived_as_hop`), so a request that
//! crosses two hosts is not counted twice.
//!
//! ## Series, not resets
//!
//! Totals are cumulative and only ever grow. Each (deployment, namespace,
//! account) gets a **series** with an id unique across restarts. A restart, or
//! a series pruned for idleness and then revived, starts a *new* series at
//! zero rather than resetting an old one. A collector therefore keys its
//! watermark by series id and bills `total − watermark`: a series it has
//! never seen is billed from zero, and a counter can never appear to go
//! backwards.
//!
//! ## Bounded memory
//!
//! Deployment ids churn in a sandbox fleet. A series nobody has recorded to
//! for `APP_LB_USAGE_RETENTION_SECS` (default one day) is dropped, so the map
//! is bounded by recent traffic, not by every id ever seen. Traffic recorded
//! before a series is pruned is lost to a collector that did not read it
//! within the retention window. Lost usage is under-billed, never over-billed.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const RETENTION_ENV: &str = "APP_LB_USAGE_RETENTION_SECS";
const DEFAULT_RETENTION_SECS: u64 = 24 * 60 * 60;
/// Prune at most this often when new series are created, so a burst of new
/// deployments does not rescan the map once per series.
const PRUNE_EVERY_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SeriesKey {
    deployment_id: String,
    namespace: String,
    account_id: Option<String>,
}

#[derive(Debug)]
struct Series {
    id: String,
    requests: AtomicU64,
    egress_bytes: AtomicU64,
    first_recorded_at: u64,
    last_recorded_at: AtomicU64,
}

/// Cumulative per-deployment billable traffic. Shared through [`crate::metrics::Metrics`].
#[derive(Debug)]
pub struct UsageMeter {
    boot_id: String,
    next_series: AtomicU64,
    retention_secs: u64,
    last_prune: AtomicU64,
    series: RwLock<HashMap<SeriesKey, Arc<Series>>>,
}

/// One series as `GET /usage` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsageSeries {
    /// Unique across restarts; the collector's watermark key.
    pub series_id: String,
    pub deployment_id: String,
    pub namespace: String,
    /// Who the traffic is metered to. `None` on a self-hosted app-lb, or for a
    /// deployment registered without an owner: counted, but billable to nobody.
    pub account_id: Option<String>,
    /// Requests answered, cumulative for this series.
    pub requests: u64,
    /// Response body bytes sent to clients, cumulative for this series.
    pub egress_bytes: u64,
    /// Unix seconds.
    pub first_recorded_at: u64,
    /// Unix seconds.
    pub last_recorded_at: u64,
}

/// The body of `GET /usage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsageReport {
    /// This process's run. Every series id begins with it.
    pub boot_id: String,
    /// Unix seconds.
    pub generated_at: u64,
    /// How long an idle series is kept before it is dropped. A collector must
    /// read more often than this or lose the tail of idle series.
    pub retention_secs: u64,
    pub series: Vec<UsageSeries>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn retention_from_env() -> u64 {
    std::env::var(RETENTION_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_RETENTION_SECS)
}

/// A run id: the start time in nanoseconds and the pid, which no two runs of
/// one host share.
fn new_boot_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}-{:x}", std::process::id())
}

impl Default for UsageMeter {
    fn default() -> Self {
        Self::with_retention(retention_from_env())
    }
}

impl UsageMeter {
    pub fn with_retention(retention_secs: u64) -> Self {
        Self {
            boot_id: new_boot_id(),
            next_series: AtomicU64::new(1),
            retention_secs: retention_secs.max(1),
            last_prune: AtomicU64::new(0),
            series: RwLock::new(HashMap::new()),
        }
    }

    /// Count one answered request for a deployment and the body bytes it sent.
    pub fn record(&self, deployment_id: &str, namespace: &str, account_id: Option<&str>, egress_bytes: u64) {
        self.record_at(deployment_id, namespace, account_id, egress_bytes, now_secs());
    }

    fn record_at(&self, deployment_id: &str, namespace: &str, account_id: Option<&str>, egress_bytes: u64, now: u64) {
        let series = self.series_for(deployment_id, namespace, account_id, now);
        series.requests.fetch_add(1, Ordering::Relaxed);
        series.egress_bytes.fetch_add(egress_bytes, Ordering::Relaxed);
        series.last_recorded_at.fetch_max(now, Ordering::Relaxed);
    }

    fn series_for(&self, deployment_id: &str, namespace: &str, account_id: Option<&str>, now: u64) -> Arc<Series> {
        let key = SeriesKey {
            deployment_id: deployment_id.to_owned(),
            namespace: namespace.to_owned(),
            account_id: account_id.map(str::to_owned),
        };
        if let Ok(map) = self.series.read()
            && let Some(series) = map.get(&key)
        {
            return series.clone();
        }
        let mut map = self.series.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.last_prune.load(Ordering::Relaxed) + PRUNE_EVERY_SECS <= now {
            self.last_prune.store(now, Ordering::Relaxed);
            self.prune_locked(&mut map, now);
        }
        map.entry(key)
            .or_insert_with(|| {
                let seq = self.next_series.fetch_add(1, Ordering::Relaxed);
                Arc::new(Series {
                    id: format!("{}-{seq}", self.boot_id),
                    requests: AtomicU64::new(0),
                    egress_bytes: AtomicU64::new(0),
                    first_recorded_at: now,
                    last_recorded_at: AtomicU64::new(now),
                })
            })
            .clone()
    }

    fn prune_locked(&self, map: &mut HashMap<SeriesKey, Arc<Series>>, now: u64) {
        map.retain(|_, s| s.last_recorded_at.load(Ordering::Relaxed) + self.retention_secs > now);
    }

    /// Every live series' running totals. Idle series past retention are
    /// dropped first.
    pub fn report(&self) -> UsageReport {
        self.report_at(now_secs())
    }

    fn report_at(&self, now: u64) -> UsageReport {
        let mut map = self.series.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.prune_locked(&mut map, now);
        let mut series: Vec<UsageSeries> = map
            .iter()
            .map(|(key, s)| UsageSeries {
                series_id: s.id.clone(),
                deployment_id: key.deployment_id.clone(),
                namespace: key.namespace.clone(),
                account_id: key.account_id.clone(),
                requests: s.requests.load(Ordering::Relaxed),
                egress_bytes: s.egress_bytes.load(Ordering::Relaxed),
                first_recorded_at: s.first_recorded_at,
                last_recorded_at: s.last_recorded_at.load(Ordering::Relaxed),
            })
            .collect();
        drop(map);
        series.sort_by(|a, b| a.series_id.cmp(&b.series_id));
        UsageReport {
            boot_id: self.boot_id.clone(),
            generated_at: now,
            retention_secs: self.retention_secs,
            series,
        }
    }
}

#[cfg(test)]
pub(crate) fn sample_report() -> UsageReport {
    UsageReport {
        boot_id: "18a2f0c4d5e6f700-1f40".into(),
        generated_at: 1_790_000_300,
        retention_secs: DEFAULT_RETENTION_SECS,
        series: vec![
            UsageSeries {
                series_id: "18a2f0c4d5e6f700-1f40-1".into(),
                deployment_id: "shop".into(),
                namespace: "acme".into(),
                account_id: Some("4b7c0e9e-2f0a-4d1c-9a53-0d6b2f1e8c11".into()),
                requests: 1_204,
                egress_bytes: 48_211_903,
                first_recorded_at: 1_790_000_000,
                last_recorded_at: 1_790_000_290,
            },
            UsageSeries {
                series_id: "18a2f0c4d5e6f700-1f40-2".into(),
                deployment_id: "internal-tools".into(),
                namespace: "default".into(),
                account_id: None,
                requests: 17,
                egress_bytes: 9_330,
                first_recorded_at: 1_790_000_100,
                last_recorded_at: 1_790_000_200,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn by_deployment<'a>(report: &'a UsageReport, id: &str) -> Vec<&'a UsageSeries> {
        report.series.iter().filter(|s| s.deployment_id == id).collect()
    }

    #[test]
    fn requests_and_bytes_accumulate_per_deployment_and_owner() {
        let meter = UsageMeter::with_retention(3600);
        meter.record_at("shop", "acme", Some("acct-1"), 100, 1_000);
        meter.record_at("shop", "acme", Some("acct-1"), 250, 1_010);
        meter.record_at("blog", "acme", Some("acct-1"), 7, 1_020);
        let report = meter.report_at(1_030);
        let shop = by_deployment(&report, "shop");
        assert_eq!(shop.len(), 1);
        assert_eq!((shop[0].requests, shop[0].egress_bytes), (2, 350));
        assert_eq!((shop[0].first_recorded_at, shop[0].last_recorded_at), (1_000, 1_010));
        assert_eq!(shop[0].account_id.as_deref(), Some("acct-1"));
        assert_eq!(by_deployment(&report, "blog")[0].requests, 1);
    }

    #[test]
    fn a_new_owner_is_a_new_series() {
        let meter = UsageMeter::with_retention(3600);
        meter.record_at("shop", "acme", Some("acct-1"), 10, 1_000);
        meter.record_at("shop", "acme", Some("acct-2"), 20, 1_001);
        meter.record_at("shop", "acme", None, 30, 1_002);
        let report = meter.report_at(1_003);
        let shop = by_deployment(&report, "shop");
        assert_eq!(shop.len(), 3);
        let ids: std::collections::HashSet<_> = shop.iter().map(|s| &s.series_id).collect();
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn series_ids_are_unique_across_runs() {
        let a = UsageMeter::with_retention(3600);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = UsageMeter::with_retention(3600);
        a.record_at("shop", "acme", Some("acct-1"), 1, 1_000);
        b.record_at("shop", "acme", Some("acct-1"), 1, 1_000);
        let (ra, rb) = (a.report_at(1_001), b.report_at(1_001));
        assert_ne!(ra.boot_id, rb.boot_id);
        assert_ne!(ra.series[0].series_id, rb.series[0].series_id);
        assert!(ra.series[0].series_id.starts_with(&ra.boot_id));
    }

    #[test]
    fn idle_series_are_pruned_and_revive_as_new_series() {
        let meter = UsageMeter::with_retention(100);
        meter.record_at("shop", "acme", Some("acct-1"), 5, 1_000);
        let first = meter.report_at(1_050).series[0].series_id.clone();
        // Past retention with no traffic: gone.
        assert!(meter.report_at(1_100).series.is_empty());
        // Traffic again: a fresh series from zero, never the old id.
        meter.record_at("shop", "acme", Some("acct-1"), 9, 1_200);
        let revived = meter.report_at(1_201);
        assert_eq!(revived.series.len(), 1);
        assert_ne!(revived.series[0].series_id, first);
        assert_eq!((revived.series[0].requests, revived.series[0].egress_bytes), (1, 9));
    }

    #[test]
    fn creating_series_prunes_idle_ones_without_a_report() {
        let meter = UsageMeter::with_retention(100);
        meter.record_at("old", "acme", Some("acct-1"), 1, 1_000);
        // Only a later *new* series triggers the opportunistic prune.
        meter.record_at("new", "acme", Some("acct-1"), 1, 1_000 + 100 + PRUNE_EVERY_SECS);
        let map = meter.series.read().unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.keys().all(|k| k.deployment_id == "new"));
    }
}
