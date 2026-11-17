//! Webhook delivery: payloads, signatures, a bounded queue, retries, and the
//! per-namespace delivery log.
//!
//! Every send re-vets the receiver's URL through [`crate::net_guard`] — the
//! name is resolved, every address checked, and the connection pinned to
//! what was checked — so a receiver that passed validation last week and
//! resolves to the metadata service today is refused today.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::config::{Format, Receiver};
use super::engine::{Alert, hex};
use crate::net_guard;
use crate::secrets::SecretStore;

pub const MAX_QUEUE: usize = 1000;
pub const MAX_LOG: usize = 200;
pub const ATTEMPTS: u32 = 5;
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
const CONCURRENCY: usize = 8;

/// Exponential backoff between attempts: `base`, `2·base`, … up to `cap`.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    pub base: Duration,
    pub cap: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(60),
        }
    }
}

impl Backoff {
    /// The wait after failed attempt `n` (1-based).
    pub fn after(&self, n: u32) -> Duration {
        let factor = 1u32.checked_shl(n.saturating_sub(1)).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.cap)
    }
}

/// The alert as a webhook carries it.
#[derive(Debug, Clone, Serialize)]
pub struct AlertPayload {
    pub fingerprint: String,
    pub rule: String,
    pub deployment: String,
    pub severity: String,
    pub summary: String,
    pub started_at: Option<u64>,
    pub resolved_at: Option<u64>,
    pub labels: std::collections::BTreeMap<String, String>,
}

impl From<&Alert> for AlertPayload {
    fn from(a: &Alert) -> Self {
        Self {
            fingerprint: a.fingerprint.clone(),
            rule: a.rule.clone(),
            deployment: a.deployment.clone(),
            severity: a.severity.as_str().to_string(),
            summary: a.summary.clone(),
            started_at: a.started_at,
            resolved_at: a.resolved_at,
            labels: a.labels.clone(),
        }
    }
}

/// `firing`, `resolved` or `test`.
pub fn event_header(status: &str) -> &'static str {
    match status {
        "firing" => "alert.firing",
        "resolved" => "alert.resolved",
        _ => "alert.test",
    }
}

/// The request body for `format`.
pub fn body(format: Format, ns: &str, status: &str, alert: &AlertPayload, delivery_id: &str) -> Vec<u8> {
    let v = match format {
        Format::Generic => json!({
            "version": 1,
            "namespace": ns,
            "status": status,
            "alert": alert,
            "delivery_id": delivery_id,
        }),
        Format::Slack => {
            let icon = match status {
                "firing" => ":rotating_light:",
                "resolved" => ":white_check_mark:",
                _ => ":wave:",
            };
            json!({
                "text": format!(
                    "{icon} [{}] {} {} in {ns}: {}",
                    status.to_uppercase(),
                    alert.severity,
                    alert.rule,
                    alert.summary
                ),
            })
        }
    };
    serde_json::to_vec(&v).expect("a JSON value serializes")
}

/// `t=<unix>,v1=<hex hmac-sha256(secret, "<t>.<body>")>`.
pub fn signature(secret: &[u8], t: u64, body: &[u8]) -> Result<String, String> {
    let key = openssl::pkey::PKey::hmac(secret).map_err(|e| e.to_string())?;
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key)
        .map_err(|e| e.to_string())?;
    signer.update(t.to_string().as_bytes()).map_err(|e| e.to_string())?;
    signer.update(b".").map_err(|e| e.to_string())?;
    signer.update(body).map_err(|e| e.to_string())?;
    let mac = signer.sign_to_vec().map_err(|e| e.to_string())?;
    Ok(format!("t={t},v1={}", hex(&mac)))
}

pub fn new_delivery_id() -> String {
    let mut b = [0u8; 12];
    openssl::rand::rand_bytes(&mut b).expect("entropy for a delivery id");
    format!("dlv_{}", hex(&b))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    Queued,
    Retrying,
    Delivered,
    Failed,
    /// Pushed out of a full queue before it was tried.
    Dropped,
}

/// One webhook, as the delivery log shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryRecord {
    pub delivery_id: String,
    pub receiver: String,
    /// `alert.firing`, `alert.resolved` or `alert.test`.
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub status: DeliveryStatus,
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// One webhook to send.
#[derive(Debug, Clone)]
pub struct Job {
    pub namespace: String,
    pub receiver: Receiver,
    pub event: &'static str,
    pub fingerprint: Option<String>,
    pub delivery_id: String,
    pub body: Vec<u8>,
}

/// The queue, its worker, and the log.
pub struct Deliverer {
    secrets: Arc<SecretStore>,
    policy: RwLock<net_guard::Policy>,
    backoff: RwLock<Backoff>,
    queue: Mutex<VecDeque<Job>>,
    wake: tokio::sync::Notify,
    permits: Arc<tokio::sync::Semaphore>,
    dropped: AtomicU64,
    delivered: AtomicU64,
    failed: AtomicU64,
    log: Mutex<HashMap<String, VecDeque<DeliveryRecord>>>,
}

impl Deliverer {
    pub fn new(secrets: Arc<SecretStore>) -> Arc<Self> {
        Arc::new(Self {
            secrets,
            policy: RwLock::new(net_guard::Policy::default()),
            backoff: RwLock::new(Backoff::default()),
            queue: Mutex::new(VecDeque::new()),
            wake: tokio::sync::Notify::new(),
            permits: Arc::new(tokio::sync::Semaphore::new(CONCURRENCY)),
            dropped: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            log: Mutex::new(HashMap::new()),
        })
    }

    pub fn set_policy(&self, p: net_guard::Policy) {
        *self.policy.write().unwrap() = p;
    }

    pub fn policy(&self) -> net_guard::Policy {
        *self.policy.read().unwrap()
    }

    #[cfg(test)]
    pub fn set_backoff(&self, b: Backoff) {
        *self.backoff.write().unwrap() = b;
    }

    pub fn stats(&self) -> Value {
        json!({
            "queued": self.queue.lock().unwrap().len(),
            "delivered": self.delivered.load(Ordering::Relaxed),
            "failed": self.failed.load(Ordering::Relaxed),
            "dropped": self.dropped.load(Ordering::Relaxed),
        })
    }

    /// Add a job, pushing the oldest out if the queue is full.
    pub fn enqueue(&self, job: Job) {
        let now = crate::deployment::now_secs();
        self.record(
            &job.namespace,
            DeliveryRecord {
                delivery_id: job.delivery_id.clone(),
                receiver: job.receiver.id.clone(),
                event: job.event.to_string(),
                fingerprint: job.fingerprint.clone(),
                status: DeliveryStatus::Queued,
                attempts: 0,
                response_status: None,
                last_error: None,
                created_at: now,
                updated_at: now,
            },
        );
        let evicted = {
            let mut q = self.queue.lock().unwrap();
            q.push_back(job);
            if q.len() > MAX_QUEUE { q.pop_front() } else { None }
        };
        if let Some(old) = evicted {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(namespace = %old.namespace, receiver = %old.receiver.id, "alerting delivery queue is full; dropped the oldest webhook");
            self.update(&old.namespace, &old.delivery_id, |r| {
                r.status = DeliveryStatus::Dropped;
                r.last_error = Some("the delivery queue was full".into());
            });
        }
        self.wake.notify_one();
    }

    /// The namespace's delivery log, newest first.
    pub fn log(&self, ns: &str) -> Vec<DeliveryRecord> {
        self.log
            .lock()
            .unwrap()
            .get(ns)
            .map(|l| l.iter().rev().cloned().collect())
            .unwrap_or_default()
    }

    pub fn forget(&self, ns: &str) {
        self.log.lock().unwrap().remove(ns);
        self.queue.lock().unwrap().retain(|j| j.namespace != ns);
    }

    fn record(&self, ns: &str, r: DeliveryRecord) {
        let mut log = self.log.lock().unwrap();
        let ring = log.entry(ns.to_string()).or_default();
        ring.push_back(r);
        while ring.len() > MAX_LOG {
            ring.pop_front();
        }
    }

    fn update(&self, ns: &str, id: &str, f: impl FnOnce(&mut DeliveryRecord)) {
        let mut log = self.log.lock().unwrap();
        if let Some(r) = log
            .get_mut(ns)
            .and_then(|l| l.iter_mut().rev().find(|r| r.delivery_id == id))
        {
            f(r);
            r.updated_at = crate::deployment::now_secs();
        }
    }

    /// Drain the queue for as long as the task lives, a few sends at a time.
    pub async fn run(self: Arc<Self>) {
        loop {
            let job = self.queue.lock().unwrap().pop_front();
            let Some(job) = job else {
                self.wake.notified().await;
                continue;
            };
            let permit = match self.permits.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let me = self.clone();
            tokio::spawn(async move {
                me.deliver(job).await;
                drop(permit);
            });
        }
    }

    /// Send one job, retrying with backoff.
    pub async fn deliver(&self, job: Job) {
        let backoff = *self.backoff.read().unwrap();
        for attempt in 1..=ATTEMPTS {
            let result = self.attempt(&job).await;
            let (ok, status, error) = match &result {
                Ok(s) if (200..300).contains(s) => (true, Some(*s), None),
                Ok(s) => (false, Some(*s), Some(format!("the receiver answered HTTP {s}"))),
                Err(e) => (false, None, Some(e.clone())),
            };
            let last = attempt == ATTEMPTS;
            self.update(&job.namespace, &job.delivery_id, |r| {
                r.attempts = attempt;
                r.response_status = status;
                r.last_error = error.clone();
                r.status = if ok {
                    DeliveryStatus::Delivered
                } else if last {
                    DeliveryStatus::Failed
                } else {
                    DeliveryStatus::Retrying
                };
            });
            if ok {
                self.delivered.fetch_add(1, Ordering::Relaxed);
                return;
            }
            if last {
                self.failed.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(namespace = %job.namespace, receiver = %job.receiver.id,
                    delivery = %job.delivery_id, error = ?error, "alert webhook failed after every attempt");
                return;
            }
            tokio::time::sleep(backoff.after(attempt)).await;
        }
    }

    /// One try: vet, sign, send. `Ok` carries whatever status came back.
    async fn attempt(&self, job: &Job) -> Result<u16, String> {
        let vetted = net_guard::vet(&job.receiver.url, self.policy()).await?;
        let client = net_guard::client_for(&vetted, SEND_TIMEOUT)?;
        let mut req = client
            .post(vetted.url.clone())
            .header("content-type", "application/json")
            .header("x-heyo-event", job.event)
            .header("x-heyo-delivery", &job.delivery_id);
        for (k, v) in &job.receiver.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(secret) = &job.receiver.secret {
            // Always the installing namespace's secret, whatever the
            // reference was written with.
            let mut r = secret.clone();
            r.scope_to(&job.namespace);
            let key = self
                .secrets
                .resolve(&r)
                .map_err(|e| format!("cannot resolve the receiver's signing secret: {e}"))?;
            let sig = signature(key.as_bytes(), crate::deployment::now_secs(), &job.body)?;
            req = req.header("x-heyo-signature", sig);
        }
        let resp = req
            .body(job.body.clone())
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        Ok(resp.status().as_u16())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_its_cap() {
        let b = Backoff::default();
        let secs: Vec<u64> = (1..=8).map(|n| b.after(n).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 32, 60, 60]);
        assert_eq!(b.after(64).as_secs(), 60);
    }

    #[test]
    fn signatures_are_hmac_sha256_over_timestamp_dot_body() {
        // RFC 4231 test case 2 shape, with the message built as "<t>.<body>".
        let sig = signature(b"Jefe", 1_700_000_000, b"{}").unwrap();
        let (t, v1) = sig.split_once(',').unwrap();
        assert_eq!(t, "t=1700000000");
        let v1 = v1.strip_prefix("v1=").unwrap();
        assert_eq!(v1.len(), 64);
        assert!(v1.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        // Independent HMAC of the same message.
        let key = openssl::pkey::PKey::hmac(b"Jefe").unwrap();
        let mut s = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
        s.update(b"1700000000.{}").unwrap();
        assert_eq!(v1, hex(&s.sign_to_vec().unwrap()));
        // Known answer: RFC 4231 test case 2.
        let key = openssl::pkey::PKey::hmac(b"Jefe").unwrap();
        let mut s = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
        s.update(b"what do ya want for nothing?").unwrap();
        assert_eq!(
            hex(&s.sign_to_vec().unwrap()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_ne!(sig, signature(b"other", 1_700_000_000, b"{}").unwrap());
    }

    #[test]
    fn bodies_follow_the_documented_shape() {
        let alert = AlertPayload {
            fingerprint: "fp".into(),
            rule: "down".into(),
            deployment: "web".into(),
            severity: "critical".into(),
            summary: "web: no healthy replicas".into(),
            started_at: Some(10),
            resolved_at: None,
            labels: Default::default(),
        };
        let v: Value = serde_json::from_slice(&body(Format::Generic, "team-a", "firing", &alert, "dlv_1")).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["namespace"], "team-a");
        assert_eq!(v["status"], "firing");
        assert_eq!(v["delivery_id"], "dlv_1");
        assert_eq!(v["alert"]["fingerprint"], "fp");
        assert_eq!(v["alert"]["resolved_at"], Value::Null);
        let s: Value = serde_json::from_slice(&body(Format::Slack, "team-a", "resolved", &alert, "dlv_1")).unwrap();
        let text = s["text"].as_str().unwrap();
        assert!(text.contains("RESOLVED") && text.contains("down") && text.contains("team-a"), "{text}");
        assert_eq!(s.as_object().unwrap().len(), 1);
        assert_eq!(event_header("firing"), "alert.firing");
        assert_eq!(event_header("resolved"), "alert.resolved");
        assert_eq!(event_header("test"), "alert.test");
    }
}
