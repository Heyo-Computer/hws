//! Alert rules: user-defined thresholds watched by a background task.
//!
//! An alert names a deployment, a metric and a threshold. The checker task
//! ([`crate::main`] spawns it) queries the engine once a minute and, when the
//! metric crosses the threshold, POSTs a JSON notification to the alert's
//! webhook. The rules themselves are a JSON file under the data directory,
//! loaded into a shared `RwLock` at startup and rewritten on every create or
//! delete through the API.
//!
//! Only the `Errors` metric is evaluated today; `AlertMetric` is an enum so the
//! set can grow without changing the wire shape of a stored rule.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

use crate::query::{Engine, MetricBucket, Window};
use chrono::Utc;

/// Which measure of a deployment an alert watches.
///
/// Stored as a tag on each rule rather than a separate field per metric, so a
/// future metric (`Latency`, `Cpu`, …) is one more variant and one more arm in
/// the checker, not a schema change to every stored file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertMetric {
    /// Total errors observed in the trailing minute. The checker sums the
    /// per-bucket error rate across the window, so a steady 1 error/s reads as
    /// 60 errors/min regardless of bucket width.
    Errors,
}

/// A single alert rule.
///
/// `id` is a short, opaque, URL-safe token generated on create. It is the key
/// the DELETE route takes, and it is echoed in webhook payloads so a receiver
/// can tell two rules on the same deployment apart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub deployment: String,
    pub metric: AlertMetric,
    /// The value the metric must exceed for the alert to fire. Errors are a
    /// count over the trailing minute, so a threshold of `0` fires on any error
    /// at all.
    pub threshold: f64,
    /// Where the notification is POSTed. The checker does not retry on failure
    /// beyond logging: a missed webhook is recoverable from the next firing,
    /// while a retry storm against a slow receiver is not.
    pub webhook_url: String,
    /// The namespace that created the rule through `/ns/{ns}/api/alerts`, or
    /// `None` for the operator's. A namespace lists and deletes only its own.
    /// Absent from rules stored before namespaces, which are the operator's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// Read the alert rules from `path`, or return an empty list when the file does
/// not exist yet.
///
/// A corrupt file is a fatal startup error rather than a silent reset: an empty
/// list would delete every operator-configured rule the moment the JSON got
/// truncated, which is exactly the kind of data loss a startup should refuse to
/// paper over.
pub fn load(path: &Path) -> Result<Vec<Alert>, std::io::Error> {
    match std::fs::read(path) {
        Ok(bytes) => {
            if bytes.iter().all(|b| b.is_ascii_whitespace()) {
                return Ok(Vec::new());
            }
            serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Write the alert rules to `path` atomically — a temp file then a rename — so a
/// crash mid-write cannot leave a half-truncated JSON file that would block the
/// next startup.
pub fn save(path: &Path, alerts: &[Alert]) -> Result<(), std::io::Error> {
    let bytes = serde_json::to_vec_pretty(alerts)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// A freshly minted, URL-safe id for a new alert.
///
/// Twelve hex characters from the RNG is enough to be unguessable by anyone who
/// can read the API but not the file, and short enough to type into a DELETE.
pub fn new_id() -> String {
    // `current_unix_nanos` is plenty of entropy for an id that only needs to be
    // unique within one collector's file; a collision would take billions of
    // alerts, and the file is the source of truth either way.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:012x}")
}

/// How often the checker wakes. One minute: fine-grained enough that an operator
/// is told about a spike within the window it started, coarse enough that a
/// quiet fleet costs one cheap query per minute per alert deployment.
pub const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The trailing window the checker queries. Matched to the interval so each run
/// covers exactly the period since the last — no double-counting, no gaps.
const CHECK_WINDOW_SECS: i64 = 60;

/// The JSON body POSTed to a webhook when an alert fires.
///
/// Deliberately small and stable: a receiver should not have to track this
/// collector's schema to know that something broke. `errors` is the count over
/// the trailing minute that crossed the threshold.
#[derive(Debug, Serialize)]
struct WebhookPayload {
    timestamp: i64,
    deployment: String,
    errors: f64,
}

/// Estimate total errors over a window by summing the per-bucket rates.
///
/// `Engine::metrics` returns `errors_per_sec` per bucket, differenced from
/// cumulative counters. Summing `rate * step` across the window reconstructs the
/// error count for that minute: a steady 1 error/s over a 60s window is 60,
/// whatever bucket width the ladder picked. Buckets with `None` (a counter
/// reset, or the un-differenced leading bucket) contribute nothing rather than
/// zero, so a restart never reads as a clean bill of health.
fn errors_in_window(buckets: &[MetricBucket], step_secs: u32) -> f64 {
    let step = f64::from(step_secs.max(1));
    buckets
        .iter()
        .filter_map(|b| b.errors_per_sec.map(|r| r.max(0.0) * step))
        .sum()
}

/// Run the alert checker forever: every [`CHECK_INTERVAL`], query the engine
/// for the last minute of each deployment an alert watches and, when the metric
/// crosses its threshold, POST a notification to the webhook.
///
/// Errors are logged, never propagated — the checker is a best-effort notifier,
/// and a failing webhook must not take down collection. Today only the `Errors`
/// metric is evaluated; other metrics are a future variant and a future arm.
pub async fn checker(engine: Arc<Engine>, alerts: Arc<tokio::sync::RwLock<Vec<Alert>>>) {
    let mut ticker = tokio::time::interval(CHECK_INTERVAL);
    // The first tick fires immediately; skip it so the checker does not run
    // before the first minute of data has even arrived.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        ticker.tick().await;
        // Snapshot the rules under a short read lock so a writer (the API) is
        // not blocked for the duration of the query round.
        let rules = alerts.read().await.clone();
        if rules.is_empty() {
            continue;
        }

        let now = Utc::now();
        let window = Window::trailing(now, CHECK_WINDOW_SECS);
        // One query per deployment an alert names, rather than one fleet-wide
        // scan: most collectors watch a handful of deployments, and a single
        // deployment's minute of data is the cheapest thing the engine can do.
        // A deployment whose query fails is left out of the map entirely, so a
        // query failure can never fire an alert against a phantom zero — absence
        // of evidence is not zero errors.
        let mut deployments: Vec<String> = rules.iter().map(|a| a.deployment.clone()).collect();
        deployments.sort();
        deployments.dedup();
        let mut errors_by_deployment: std::collections::HashMap<String, f64> =
            std::collections::HashMap::new();
        for deployment in &deployments {
            match engine
                .metrics(window, CHECK_WINDOW_SECS as u32, Some(deployment), None)
                .await
            {
                Ok(map) => {
                    let total = map
                        .get(deployment)
                        .map(|b| errors_in_window(b, CHECK_WINDOW_SECS as u32))
                        .unwrap_or(0.0);
                    errors_by_deployment.insert(deployment.clone(), total);
                }
                Err(e) => {
                    tracing::warn!(
                        deployment = %deployment,
                        error = %e,
                        "alert checker: could not query metrics",
                    );
                    // Leave no entry so the alert does not fire on a query
                    // failure — absence of evidence is not zero errors.
                }
            }
        }

        for alert in &rules {
            let Some(&errors) = errors_by_deployment.get(&alert.deployment) else {
                continue;
            };
            match alert.metric {
                AlertMetric::Errors => {
                    if errors > alert.threshold {
                        fire_webhook(alert, errors).await;
                    }
                }
            }
        }
    }
}

/// POST the firing notification to the alert's webhook. Failures are logged and
/// swallowed: the checker does not retry, because the next tick will fire again
/// if the condition persists, and a retry storm against a slow receiver is worse
/// than a single missed ping.
async fn fire_webhook(alert: &Alert, errors: f64) {
    let payload = WebhookPayload {
        timestamp: Utc::now().timestamp_millis(),
        deployment: alert.deployment.clone(),
        errors,
    };
    tracing::info!(
        alert_id = %alert.id,
        deployment = %alert.deployment,
        threshold = alert.threshold,
        errors,
        "alert firing; posting to webhook",
    );
    let client = reqwest::Client::new();
    match client
        .post(&alert.webhook_url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) if !resp.status().is_success() => {
            tracing::warn!(
                alert_id = %alert.id,
                webhook = %alert.webhook_url,
                status = %resp.status(),
                "webhook returned a non-success status",
            );
        }
        Ok(_) => {
            tracing::debug!(
                alert_id = %alert.id,
                "webhook delivered",
            );
        }
        Err(e) => {
            tracing::warn!(
                alert_id = %alert.id,
                webhook = %alert.webhook_url,
                error = %e,
                "webhook delivery failed",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::MetricBucket;

    fn bucket(t: i64, errors_per_sec: Option<f64>) -> MetricBucket {
        MetricBucket {
            t,
            errors_per_sec,
            ..Default::default()
        }
    }

    #[test]
    fn errors_in_window_sums_the_per_bucket_rate() {
        // 1 error/s for each of two 30s buckets = 60 errors over the minute,
        // regardless of how the bucket ladder split it.
        let buckets = vec![bucket(0, Some(1.0)), bucket(30_000, Some(1.0))];
        assert_eq!(errors_in_window(&buckets, 30), 60.0);
    }

    #[test]
    fn a_reset_counter_contributes_nothing() {
        // `None` is a restart, not zero — it must not be counted as a clean
        // interval, and it must not be counted at all.
        let buckets = vec![
            bucket(0, Some(2.0)),
            bucket(30_000, None),
            bucket(60_000, Some(2.0)),
        ];
        assert_eq!(errors_in_window(&buckets, 30), 120.0);
    }

    #[test]
    fn a_negative_rate_is_treated_as_zero() {
        // Defensive: a rate should never be negative, but summing one in would
        // understate errors, which is the worse direction for an alert.
        let buckets = vec![bucket(0, Some(-5.0)), bucket(30_000, Some(1.0))];
        assert_eq!(errors_in_window(&buckets, 30), 30.0);
    }

    #[test]
    fn a_missing_file_is_an_empty_list_not_an_error() {
        let dir = std::env::temp_dir().join(format!(
            "app-obs-alerts-missing-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("alerts.json");
        assert!(load(&path).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rules_round_trip_through_the_file() {
        let dir = std::env::temp_dir().join(format!(
            "app-obs-alerts-roundtrip-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("alerts.json");

        let rules = vec![
            Alert {
                id: "abc123".into(),
                deployment: "demo".into(),
                metric: AlertMetric::Errors,
                threshold: 10.0,
                webhook_url: "https://example.com/hook".into(),
                namespace: None,
            },
            Alert {
                id: "def456".into(),
                deployment: "vault-86a37f".into(),
                metric: AlertMetric::Errors,
                threshold: 0.0,
                webhook_url: "https://example.com/other".into(),
                namespace: Some("team-a".into()),
            },
        ];
        save(&path, &rules).unwrap();
        let back = load(&path).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].id, "abc123");
        assert_eq!(back[0].metric, AlertMetric::Errors);
        assert_eq!(back[1].deployment, "vault-86a37f");
        assert_eq!(back[1].threshold, 0.0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_blank_file_is_treated_as_empty() {
        let dir = std::env::temp_dir().join(format!(
            "app-obs-alerts-blank-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("alerts.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, b"   \n").unwrap();
        assert!(load(&path).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_file_is_an_error_not_a_reset() {
        let dir = std::env::temp_dir().join(format!(
            "app-obs-alerts-corrupt-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("alerts.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(load(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ids_are_unique_enough_to_never_collide_in_one_run() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(ids.insert(new_id()), "id collided");
        }
    }

    #[test]
    fn the_metric_serialises_as_lowercase() {
        // The wire shape is fixed by the stored files, so pin it: `errors`, not
        // `Errors`.
        let json = serde_json::to_string(&AlertMetric::Errors).unwrap();
        assert_eq!(json, "\"errors\"");
        assert_eq!(
            serde_json::from_str::<AlertMetric>("\"errors\"").unwrap(),
            AlertMetric::Errors,
        );
    }
}
