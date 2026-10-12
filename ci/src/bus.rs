//! The JetStream job queue.
//!
//! ## Subjects are sharded per runner, and that is the whole design
//!
//! `WorkQueue` retention deletes a message on ack, so the stream's depth *is*
//! the backlog — self-clearing, and exactly what a dashboard wants to show. The
//! cost is that JetStream permits **only one consumer per subject** under that
//! policy, which is why queue-fn documents itself as single-instance.
//!
//! Sharding the subject by runner sidesteps it entirely. One durable pull
//! consumer per runner, each filtering a subject nothing else filters, means
//! several orchestrators can run at once as long as they own disjoint runner
//! sets. The constraint stops being a limit and starts being the partitioning
//! scheme.
//!
//! Two disjoint subject spaces:
//!
//! ```text
//! <prefix>.job.r.<runner_id>     pinned to one host
//! <prefix>.job.n.<network_id>    any online host in that network
//! ```
//!
//! The `r`/`n` segment is load-bearing. Without it a network happening to be
//! named `hd-something` — or a runner named after a network — would produce
//! overlapping filters, and under `WorkQueue` two consumers would silently
//! consume each other's work. Both tokens are machine-generated ids
//! (`hd-…`, `net-…`), so neither needs escaping; both are checked anyway.
//!
//! ## What is *not* on the bus
//!
//! **Step logs.** They are megabytes per job and JetStream is the wrong medium;
//! they go to disk with offsets in Postgres.
//!
//! **The job's plan.** A message carries ids only. The database is the source of
//! truth, so a redelivery runs what the original delivery would have, even if
//! the branch moved underneath it.
//!
//! **heyvm's own stream.** `HEYO_MVM_CMD` / `mvm.cmd.<backend>.{create,delete}`
//! carries VM lifecycle with its own retention and dispatcher. Sharing it would
//! mean a purge here destroying pending VM creates there.

use crate::config::is_subject_token;
use crate::nats_auth::NatsEndpoint;
use async_nats::jetstream::consumer::PullConsumer;
use async_nats::jetstream::consumer::pull::Config as PullConfig;
use async_nats::jetstream::stream::{DiscardPolicy, RetentionPolicy, StorageType};
use async_nats::jetstream::{self, Context as Jetstream};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// Slack above a job's own timeout before JetStream assumes the dispatcher died
/// and redelivers. Must exceed the job timeout plus the poll interval, or a
/// perfectly healthy job is redelivered while it is still running — and then two
/// dispatchers are driving one VM.
/// How long JetStream waits for an ack before redelivering.
///
/// Short on purpose. The executor extends it with `AckKind::Progress` every
/// [`ACK_PROGRESS_EVERY`] for as long as a job is running, so this is not a
/// ceiling on job length — it is how quickly a job is released when the process
/// running it *stops* saying anything, which is the case that matters after a
/// crash or a restart.
pub const ACK_WAIT: Duration = Duration::from_secs(60);

/// How often a running job says it is still running.
///
/// Comfortably inside [`ACK_WAIT`], so a slow round trip or a busy runtime does
/// not cost a redelivery — that would put two dispatchers on one VM, which is
/// far worse than releasing a dead job a minute late.
pub const ACK_PROGRESS_EVERY: Duration = Duration::from_secs(20);

/// Application failure retry delays, sent as explicit delayed NAKs. Do not
/// install this as broker BackOff: it overrides AckWait and older servers
/// reject it with unlimited delivery. Drain handoffs use a separate short delay.
const BACKOFF: [Duration; 3] = [
    ACK_WAIT,
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
];

pub fn backoff_for(attempt: u32) -> Duration {
    let idx = (attempt as usize).saturating_sub(1).min(BACKOFF.len() - 1);
    BACKOFF[idx]
}

/// How long the failure retry ladder takes, excluding drain handoffs.
///
/// The waits *between* [`MAX_PRECLAIM_FAILURES`] failures — one fewer rungs,
/// saturating at the last entry. With the ladder above and four deliveries that
/// is 60s + 5m + 15m = 21 minutes.
///
/// This exists because something else has to be longer than it.
/// `CI_RUNNER_WAIT_SECS` reaps a job that is still `queued`, and a job being
/// retried by this ladder is `queued` for the whole of it — `run_job` picks a
/// runner *before* `claim_job`, so a failure there never moves the row off
/// `queued`. A reaper set shorter than this kills a job the queue was still
/// legitimately retrying, and overwrites the real error with "no runner took
/// this job", which is both wrong and the opposite of a lead.
pub fn ladder_total() -> Duration {
    (1..MAX_PRECLAIM_FAILURES as u32).map(backoff_for).sum()
}

/// Bound actual pre-claim failures in Postgres, not queue deliveries. Draining
/// an instance and returning its outstanding pull must not spend this budget.
pub const MAX_PRECLAIM_FAILURES: i32 = 4;

/// Unlimited transport redelivery. Claimed jobs cannot execute again, and
/// pre-claim failures have their own durable limit above.
pub const MAX_DELIVER: i64 = -1;

/// What a queue message carries: enough to find the work, nothing more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobMessage {
    pub run_id: String,
    pub job_id: String,
    pub job_key: String,
}

/// Where a job should run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// A specific host.
    Runner(String),
    /// Any online host in a network.
    Network(String),
}

/// A route's backlog, as JetStream sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueDepth {
    /// Delivered to nobody yet.
    pub waiting: u64,
    /// Delivered and not yet acked — jobs being worked on right now. With the
    /// progress heartbeat extending each ack, this is a live count rather than a
    /// count of things that might have been abandoned.
    pub in_flight: u64,
}

impl QueueDepth {
    pub fn is_empty(&self) -> bool {
        self.waiting == 0 && self.in_flight == 0
    }
}

pub struct Bus {
    js: Jetstream,
    prefix: String,
    jobs_stream: String,
    events_stream: String,
}

impl Bus {
    /// Connect and ensure both streams exist.
    ///
    /// Takes a resolved [`NatsEndpoint`] rather than a URL so credentials cannot
    /// arrive here still embedded in a string — `async_nats` would parse them,
    /// drop them, and fail with an authorization error naming nothing.
    pub async fn connect(endpoint: &NatsEndpoint, prefix: &str) -> Result<Self, BusError> {
        if !is_subject_token(prefix) {
            return Err(BusError::BadToken(prefix.to_string()));
        }
        let (opts, servers) = endpoint
            .connect_options("ci")
            .map_err(|e| BusError::Connect(e.to_string()))?;
        let client = opts
            .connect(servers)
            .await
            .map_err(|e| BusError::Connect(format!("{e} (servers: {})", endpoint.redacted())))?;
        let js = jetstream::new(client);

        let jobs_stream = format!("{}_JOBS", prefix.to_uppercase());
        let events_stream = format!("{}_EVENTS", prefix.to_uppercase());

        js.get_or_create_stream(jetstream::stream::Config {
            name: jobs_stream.clone(),
            subjects: vec![format!("{prefix}.job.>")],
            // Deletes on ack, so the message count is the backlog.
            retention: RetentionPolicy::WorkQueue,
            storage: StorageType::File,
            // Refuse new work rather than silently dropping the oldest queued
            // job when the stream is full. A job that vanishes from the queue
            // looks to a user exactly like one that was never submitted.
            discard: DiscardPolicy::New,
            ..Default::default()
        })
        .await
        .map_err(|e| BusError::Stream {
            stream: jobs_stream.clone(),
            reason: e.to_string(),
        })?;

        js.get_or_create_stream(jetstream::stream::Config {
            name: events_stream.clone(),
            subjects: vec![format!("{prefix}.evt.>")],
            // Limits, not WorkQueue: events are fan-out. Several dashboards may
            // tail them and none of them consume.
            retention: RetentionPolicy::Limits,
            storage: StorageType::File,
            max_age: Duration::from_secs(24 * 60 * 60),
            ..Default::default()
        })
        .await
        .map_err(|e| BusError::Stream {
            stream: events_stream.clone(),
            reason: e.to_string(),
        })?;

        Ok(Self {
            js,
            prefix: prefix.to_string(),
            jobs_stream,
            events_stream,
        })
    }

    pub fn jobs_stream(&self) -> &str {
        &self.jobs_stream
    }

    pub fn events_stream(&self) -> &str {
        &self.events_stream
    }

    /// The subject a route publishes to.
    pub fn subject_for(&self, route: &Route) -> Result<String, BusError> {
        match route {
            Route::Runner(id) => {
                check_token(id)?;
                Ok(format!("{}.job.r.{id}", self.prefix))
            }
            Route::Network(id) => {
                check_token(id)?;
                Ok(format!("{}.job.n.{id}", self.prefix))
            }
        }
    }

    /// The durable consumer name for a route. NATS forbids `.`, `*`, `>` and
    /// whitespace in a durable name; the ids are already restricted to
    /// `[A-Za-z0-9_-]`, which is a subset.
    pub fn durable_for(&self, route: &Route) -> Result<String, BusError> {
        match route {
            Route::Runner(id) => {
                check_token(id)?;
                Ok(format!("{}-r-{id}", self.prefix))
            }
            Route::Network(id) => {
                check_token(id)?;
                Ok(format!("{}-n-{id}", self.prefix))
            }
        }
    }

    /// Enqueue a job.
    ///
    /// `Nats-Msg-Id` is the job's own id, so JetStream deduplicates a double
    /// publish — which happens whenever a submit is retried by a client that did
    /// not see the response.
    pub async fn publish_job(&self, route: &Route, msg: &JobMessage) -> Result<(), BusError> {
        let subject = self.subject_for(route)?;
        let payload = serde_json::to_vec(msg).map_err(|e| BusError::Encode(e.to_string()))?;
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("Nats-Msg-Id", msg.job_id.as_str());

        self.js
            .publish_with_headers(subject.clone(), headers, payload.into())
            .await
            .map_err(|e| BusError::Publish {
                subject: subject.clone(),
                reason: e.to_string(),
            })?
            .await
            .map_err(|e| BusError::Publish {
                subject,
                reason: e.to_string(),
            })?;
        Ok(())
    }

    /// Bind (creating if needed) the durable consumer for a route.
    ///
    /// `ack_wait` is [`ACK_WAIT`] — short, and deliberately **not** derived from
    /// the longest job. The executor sends `AckKind::Progress` while a job runs,
    /// which extends the window by another `ack_wait` each time, so a healthy
    /// build of any length is never redelivered while its dispatcher is alive.
    ///
    /// Sizing it to `CI_MAX_JOB_SECONDS` instead — the obvious reading of "never
    /// redeliver a running job" — meant a dispatcher that *died* held its job for
    /// the entire job budget, four hours by default, with the run showing
    /// `running` the whole time. The heartbeat says "still working" rather than
    /// the configuration promising it in advance.
    ///
    /// **An existing consumer is reconciled, not reused blindly.** JetStream
    /// returns the consumer that is already there and ignores the config passed
    /// with it, so an installation upgrading into this would silently keep its
    /// old four-hour window and none of this would take effect. A mismatch is
    /// therefore repaired in place, preserving in-flight delivery state.
    pub async fn consumer_for(&self, route: &Route) -> Result<PullConsumer, BusError> {
        let durable = self.durable_for(route)?;
        let filter = self.subject_for(route)?;
        let stream = self
            .js
            .get_stream(&self.jobs_stream)
            .await
            .map_err(|e| BusError::Stream {
                stream: self.jobs_stream.clone(),
                reason: e.to_string(),
            })?;

        let config = PullConfig {
            durable_name: Some(durable.clone()),
            filter_subject: filter,
            ack_wait: ACK_WAIT,
            max_deliver: MAX_DELIVER,
            // Explicit delayed NAKs carry application failure backoff. Older
            // servers reject a broker BackOff list with unlimited delivery.
            ..Default::default()
        };

        let consumer = stream
            .get_or_create_consumer(&durable, config.clone())
            .await
            .map_err(|e| BusError::Consumer {
                durable: durable.clone(),
                reason: e.to_string(),
            })?;

        let mut consumer = consumer;
        let mut current = consumer.info().await.map_err(|e| BusError::Consumer {
            durable: durable.clone(),
            reason: e.to_string(),
        })?.config.clone();
        if current.ack_wait == ACK_WAIT && current.max_deliver == MAX_DELIVER && current.backoff.is_empty() {
            return Ok(consumer);
        }
        tracing::info!("{durable}: updating acknowledgement timing and transport delivery limit in place");
        current.ack_wait = ACK_WAIT;
        current.max_deliver = MAX_DELIVER;
        current.backoff.clear();
        // Keep immutable consumer settings. Updating avoids resetting pending
        // acknowledgements or delivery counts while another region is working.
        stream
            .create_consumer(current)
            .await
            .map_err(|e| BusError::Consumer {
                durable: durable.clone(),
                reason: e.to_string(),
            })?;
        stream.get_consumer(&durable).await.map_err(|e| BusError::Consumer {
            durable,
            reason: e.to_string(),
        })
    }

    /// What is on a route's queue, and whether anything is reading it.
    ///
    /// `Ok(None)` means **no durable consumer exists** — the state that matters
    /// most and the one the old `pending()` reported as an error, indistinguishable
    /// from NATS being down. A job routed to a subject nothing consumes waits for
    /// ever, so "nobody is listening" has to be a value the dashboard can render
    /// rather than a failure it swallows.
    ///
    /// Exact rather than approximate: `WorkQueue` retention deletes on ack, so
    /// the counts are the backlog rather than a high-water mark.
    pub async fn depth(&self, route: &Route) -> Result<Option<QueueDepth>, BusError> {
        let durable = self.durable_for(route)?;
        // A stream failure is a real error — NATS is unreachable or the stream
        // is gone — and must not be reported as "nothing is consuming".
        let stream = self
            .js
            .get_stream(&self.jobs_stream)
            .await
            .map_err(|e| BusError::Stream {
                stream: self.jobs_stream.clone(),
                reason: e.to_string(),
            })?;

        let Ok(mut consumer) = stream.get_consumer::<PullConfig>(&durable).await else {
            return Ok(None);
        };
        let Ok(info) = consumer.info().await else {
            return Ok(None);
        };
        Ok(Some(QueueDepth {
            waiting: info.num_pending,
            in_flight: info.num_ack_pending as u64,
        }))
    }

    /// Each CI instance gets availability notifications. These are wakeups,
    /// not deployment commands; missed events are recovered from the catalog.
    pub async fn candidate_events(&self) -> Result<PullConsumer, BusError> {
        let stream = self.js.get_stream(&self.events_stream).await
            .map_err(|e| BusError::Stream { stream: self.events_stream.clone(), reason: e.to_string() })?;
        stream.create_consumer(PullConfig {
            filter_subject: format!("{}.evt.release.candidate.ready", self.prefix),
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::New,
            inactive_threshold: Duration::from_secs(120),
            ..Default::default()
        }).await.map_err(|e| BusError::Consumer { durable: "candidate-events".into(), reason: e.to_string() })
    }

    /// Publish one durable outbox row and wait for the JetStream PubAck.
    async fn publish_outbox(&self, event: &crate::store::OutboxEvent) -> Result<(), BusError> {
        let subject = format!("{}.evt.{}", self.prefix, event.subject);
        let payload = serde_json::to_vec(&event.payload).map_err(|e| BusError::Encode(e.to_string()))?;
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("Nats-Msg-Id", event.id.to_string());
        self.js.publish_with_headers(subject.clone(), headers, payload.into()).await
            .map_err(|e| BusError::Publish { subject: subject.clone(), reason: e.to_string() })?
            .await.map_err(|e| BusError::Publish { subject, reason: e.to_string() })?;
        Ok(())
    }

    /// Start the only event publisher. Rows survive process and NATS restarts;
    /// a crash after PubAck but before the DB update republishes the same stable
    /// message id, so JetStream deduplication makes delivery effectively once
    /// within its duplicate window. Consumers must still be idempotent.
    pub fn spawn_outbox_publisher(self: std::sync::Arc<Self>, store: crate::store::Store) {
        tokio::spawn(async move {
            loop {
                match store.next_outbox_event().await {
                    Ok(Some(event)) => match self.publish_outbox(&event).await {
                        Ok(()) => {
                            if let Err(e) = store.mark_outbox_published(event.id).await {
                                tracing::warn!(event_id=%event.id, "PubAck received but outbox update failed: {e}");
                                // Avoid a tight duplicate-publish loop while Postgres is
                                // recovering. Nats-Msg-Id still deduplicates the retry.
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(event_id=%event.id, "event publish failed; will retry: {e}");
                            if let Err(mark_error) = store.mark_outbox_failed(event.id, &e.to_string()).await {
                                tracing::warn!(event_id=%event.id, "could not record outbox publish failure: {mark_error}");
                            }
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    },
                    Ok(None) => tokio::time::sleep(Duration::from_millis(250)).await,
                    Err(e) => {
                        tracing::warn!("reading event outbox failed; will retry: {e}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
    }
}

impl Bus {
    /// Delete both streams. Test-only: production never wants this, and a
    /// `WorkQueue` purge would destroy queued jobs.
    #[cfg(test)]
    pub async fn js_delete_streams(&self) -> Result<(), BusError> {
        let _ = self.js.delete_stream(&self.jobs_stream).await;
        let _ = self.js.delete_stream(&self.events_stream).await;
        Ok(())
    }
}

fn check_token(s: &str) -> Result<(), BusError> {
    if is_subject_token(s) {
        Ok(())
    } else {
        Err(BusError::BadToken(s.to_string()))
    }
}

#[derive(Debug)]
pub enum BusError {
    Connect(String),
    Stream { stream: String, reason: String },
    Consumer { durable: String, reason: String },
    Publish { subject: String, reason: String },
    Encode(String),
    BadToken(String),
}

impl fmt::Display for BusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "could not connect to NATS: {e}"),
            Self::Stream { stream, reason } => {
                write!(f, "JetStream stream {stream}: {reason}")
            }
            Self::Consumer { durable, reason } => {
                write!(f, "JetStream consumer {durable}: {reason}")
            }
            Self::Publish { subject, reason } => {
                write!(f, "publishing to {subject}: {reason}")
            }
            Self::Encode(e) => write!(f, "encoding a job message: {e}"),
            Self::BadToken(t) => write!(
                f,
                "{t:?} cannot be part of a NATS subject; ids must be \
                 [A-Za-z0-9_-]. This is checked here because a subject is \
                 interpolated, not escaped."
            ),
        }
    }
}

impl std::error::Error for BusError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> NatsEndpoint {
        let url = std::env::var("CI_TEST_NATS_URL")
            .unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
        NatsEndpoint::resolve(&url, &crate::nats_auth::EnvCredentials::default()).unwrap()
    }

    /// A distinct prefix per test run, so tests never share a stream and can be
    /// run against a NATS that other things already use.
    fn test_prefix() -> String {
        format!("citest{}", crate::vm::new_id().replace('-', ""))
    }

    /// Keep the first application retry delay at the normal ACK timeout.
    #[test]
    fn the_first_backoff_step_is_the_ack_wait() {
        assert_eq!(
            BACKOFF[0], ACK_WAIT,
            "nats-server takes ack_wait from backoff[0]; they cannot disagree"
        );
    }

    #[test]
    fn the_backoff_ladder_saturates() {
        assert_eq!(backoff_for(1), ACK_WAIT);
        assert_eq!(backoff_for(2), Duration::from_secs(5 * 60));
        assert_eq!(backoff_for(3), Duration::from_secs(15 * 60));
        assert_eq!(backoff_for(99), Duration::from_secs(15 * 60));
        // Attempt 0 should not underflow into a panic.
        assert_eq!(backoff_for(0), ACK_WAIT);
    }

    #[test]
    fn a_job_message_round_trips() {
        let m = JobMessage {
            run_id: "019f-0001".into(),
            job_id: "019f-0001.build-x86_64".into(),
            job_key: "build-x86_64".into(),
        };
        let json = serde_json::to_vec(&m).unwrap();
        assert_eq!(serde_json::from_slice::<JobMessage>(&json).unwrap(), m);
    }

    // ---- integration ----------------------------------------------------
    //
    //   CI_TEST_NATS_URL=nats://127.0.0.1:4222 cargo test -- --ignored bus::

    async fn test_bus(prefix: &str) -> Bus {
        Bus::connect(&endpoint(), prefix).await.expect("connects")
    }

    /// Deletes the streams a test made, so a NATS server does not accumulate
    /// one pair per test run forever.
    async fn cleanup(bus: &Bus) {
        let _ = bus.js.delete_stream(bus.jobs_stream()).await;
        let _ = bus.js.delete_stream(bus.events_stream()).await;
    }

    /// Four actual failures have three retry waits between them.
    #[test]
    fn the_ladder_totals_the_waits_between_deliveries() {
        assert_eq!(ladder_total(), Duration::from_secs(60 + 5 * 60 + 15 * 60));
        assert_eq!(ladder_total().as_secs(), 1260);
    }

    /// The guard that keeps the reaper behind the ladder. If `MAX_PRECLAIM_FAILURES` or
    /// `BACKOFF` grows this fails, and `CI_RUNNER_WAIT_SECS`'s default has to
    /// move with it — which is the point, because the failure it prevents is
    /// silent and shows up only for jobs whose first delivery happens to fail.
    #[test]
    fn the_default_runner_wait_outlasts_the_ladder() {
        assert!(
            Duration::from_secs(1800) > ladder_total(),
            "CI_RUNNER_WAIT_SECS default must exceed {:?}",
            ladder_total()
        );
    }

    #[tokio::test]
    #[ignore = "needs a NATS with JetStream"]
    async fn subjects_and_durables_are_disjoint_between_routes() {
        let prefix = test_prefix();
        let bus = test_bus(&prefix).await;

        let r = bus.subject_for(&Route::Runner("hd-abc".into())).unwrap();
        let n = bus.subject_for(&Route::Network("hd-abc".into())).unwrap();
        assert_eq!(r, format!("{prefix}.job.r.hd-abc"));
        assert_eq!(n, format!("{prefix}.job.n.hd-abc"));
        assert_ne!(
            r, n,
            "a network named like a runner must not share its subject"
        );

        assert_ne!(
            bus.durable_for(&Route::Runner("x".into())).unwrap(),
            bus.durable_for(&Route::Network("x".into())).unwrap()
        );

        // A token that would reshape the subject is refused rather than escaped.
        for bad in ["has.dot", "has>wild", "has space", ""] {
            assert!(
                bus.subject_for(&Route::Runner(bad.into())).is_err(),
                "{bad:?} must be refused"
            );
        }
        cleanup(&bus).await;
    }

    #[tokio::test]
    #[ignore = "needs a NATS with JetStream"]
    async fn a_published_job_is_pulled_by_its_runners_consumer() {
        use futures::StreamExt;
        let prefix = test_prefix();
        let bus = test_bus(&prefix).await;
        let route = Route::Runner("hd-one".into());

        let msg = JobMessage {
            run_id: "run1".into(),
            job_id: "run1.build".into(),
            job_key: "build".into(),
        };
        // Consumer first: creating it after publishing still works for a
        // durable, but binding first is what a dispatcher actually does.
        let consumer = bus.consumer_for(&route).await.expect("consumer");
        bus.publish_job(&route, &msg).await.expect("published");

        let mut batch = consumer.fetch().max_messages(1).messages().await.unwrap();
        let got = batch.next().await.expect("a message").expect("ok");
        let decoded: JobMessage = serde_json::from_slice(&got.payload).unwrap();
        assert_eq!(decoded, msg);
        got.ack().await.expect("acked");

        // WorkQueue deletes on ack, so the backlog is now genuinely zero.
        assert_eq!(bus.depth(&route).await.unwrap().unwrap().waiting, 0);
        cleanup(&bus).await;
    }

    /// The partitioning claim: two runners' consumers coexist under WorkQueue
    /// because their filters do not overlap, and neither sees the other's work.
    #[tokio::test]
    #[ignore = "needs a NATS with JetStream"]
    async fn two_runners_have_independent_queues() {
        use futures::StreamExt;
        let prefix = test_prefix();
        let bus = test_bus(&prefix).await;
        let a = Route::Runner("hd-a".into());
        let b = Route::Runner("hd-b".into());

        let ca = bus.consumer_for(&a).await.unwrap();
        let cb = bus.consumer_for(&b).await.unwrap();

        for (route, key) in [(&a, "for-a"), (&b, "for-b")] {
            bus.publish_job(
                route,
                &JobMessage {
                    run_id: "run1".into(),
                    job_id: format!("run1.{key}"),
                    job_key: key.into(),
                },
            )
            .await
            .unwrap();
        }

        assert_eq!(bus.depth(&a).await.unwrap().unwrap().waiting, 1);
        assert_eq!(bus.depth(&b).await.unwrap().unwrap().waiting, 1);

        let mut batch = ca.fetch().max_messages(5).messages().await.unwrap();
        let m = batch.next().await.unwrap().unwrap();
        let decoded: JobMessage = serde_json::from_slice(&m.payload).unwrap();
        assert_eq!(
            decoded.job_key, "for-a",
            "a runner must only see its own work"
        );
        m.ack().await.unwrap();
        assert!(batch.next().await.is_none(), "and nothing else");

        // b's message is untouched by a's consumer.
        assert_eq!(bus.depth(&b).await.unwrap().unwrap().waiting, 1);
        let mut batch = cb.fetch().max_messages(5).messages().await.unwrap();
        let m = batch.next().await.unwrap().unwrap();
        let decoded: JobMessage = serde_json::from_slice(&m.payload).unwrap();
        assert_eq!(decoded.job_key, "for-b");
        m.ack().await.unwrap();

        cleanup(&bus).await;
    }

    /// The recovery property: a runner that was offline when work was queued
    /// must drain that work when it comes back. Messages outlive the absence of
    /// a consumer — the durable is created with the default `DeliverAll`, so it
    /// receives everything already on its filter subject rather than only what
    /// arrives after it binds.
    #[tokio::test]
    #[ignore = "needs CI_TEST_NATS_URL"]
    async fn work_queued_before_a_consumer_existed_is_delivered_when_it_binds() {
        let prefix = test_prefix();
        let bus = test_bus(&prefix).await;
        let route = Route::Runner("hd-comesback".into());

        // Published while the host is offline: nothing is bound to this subject.
        bus.publish_job(
            &route,
            &JobMessage {
                run_id: "run1".into(),
                job_id: "run1.build".into(),
                job_key: "build".into(),
            },
        )
        .await
        .expect("published");
        assert_eq!(
            bus.depth(&route).await.unwrap(),
            None,
            "no consumer yet, which is what the dashboard flags"
        );

        // The host comes back and `spawn_consumers` binds on the next tick.
        let consumer = bus.consumer_for(&route).await.expect("consumer");
        let depth = bus.depth(&route).await.unwrap().expect("now bound");
        assert_eq!(depth.waiting, 1, "the queued job survived the outage");

        use futures::StreamExt;
        let mut batch = consumer.fetch().max_messages(1).messages().await.unwrap();
        let msg = batch.next().await.expect("delivered").unwrap();
        let job: JobMessage = serde_json::from_slice(&msg.payload).unwrap();
        assert_eq!(job.job_id, "run1.build");
        msg.ack().await.unwrap();

        cleanup(&bus).await;
    }

    /// The half of this that is easy to ship broken.
    ///
    /// JetStream returns an existing durable and ignores the config passed with
    /// it, so an installation upgrading into a shorter `ack_wait` would keep its
    /// old one and none of the fix would take effect — the code would look
    /// right and the four-hour window would still be there.
    #[tokio::test]
    #[ignore = "needs CI_TEST_NATS_URL"]
    async fn an_existing_consumer_is_updated_without_losing_pending_delivery() {
        use futures::StreamExt;
        let prefix = test_prefix();
        let bus = test_bus(&prefix).await;
        let route = Route::Runner("hd-ackwait".into());
        let durable = bus.durable_for(&route).unwrap();

        // Stand in for a consumer created by a previous build.
        let stream = bus.js.get_stream(&bus.jobs_stream).await.unwrap();
        let mut old = stream
            .get_or_create_consumer(
                &durable,
                PullConfig {
                    durable_name: Some(durable.clone()),
                    filter_subject: bus.subject_for(&route).unwrap(),
                    ack_wait: Duration::from_secs(4 * 60 * 60),
                    max_deliver: 4,
                    backoff: Vec::new(),
                    ..Default::default()
                },
            )
            .await
            .expect("the old consumer");

        bus.publish_job(&route, &JobMessage {
            run_id: "run".into(), job_id: "job".into(), job_key: "build".into(),
        }).await.unwrap();
        let mut batch = old.fetch().max_messages(1).messages().await.unwrap();
        let pending = batch.next().await.unwrap().unwrap();
        let created = old.info().await.unwrap().created;
        let mut reconciled = bus.consumer_for(&route).await.expect("consumer");
        let info = reconciled.info().await.unwrap();
        assert_eq!(info.config.ack_wait, ACK_WAIT);
        assert_eq!(info.config.max_deliver, -1);
        assert!(info.config.backoff.is_empty());
        assert_eq!(info.created, created, "must update rather than recreate");
        assert_eq!(info.num_ack_pending, 1);
        pending.double_ack().await.unwrap();

        // A correct AckWait alone must not hide an old finite delivery limit.
        let mut limited = reconciled.info().await.unwrap().config.clone();
        limited.max_deliver = 4;
        limited.backoff = BACKOFF.to_vec();
        stream.create_consumer(limited).await.unwrap();
        let mut updated = bus.consumer_for(&route).await.unwrap();
        assert_eq!(updated.info().await.unwrap().config.max_deliver, -1);
        assert!(updated.info().await.unwrap().config.backoff.is_empty());

        // And binding again is a no-op rather than a delete/recreate cycle,
        // which would redeliver in-flight work on every reconnect.
        let mut again = bus.consumer_for(&route).await.expect("consumer");
        assert_eq!(again.info().await.unwrap().config.ack_wait, ACK_WAIT);
        assert_eq!(again.info().await.unwrap().created, created);
        assert_eq!(again.info().await.unwrap().num_ack_pending, 0);
        cleanup(&bus).await;
    }

    /// A client that retries a submit it never saw the response to must not
    /// enqueue the job twice.
    #[tokio::test]
    #[ignore = "needs a NATS with JetStream"]
    async fn publishing_the_same_job_id_twice_is_deduplicated() {
        let prefix = test_prefix();
        let bus = test_bus(&prefix).await;
        let route = Route::Runner("hd-dedupe".into());
        let _ = bus.consumer_for(&route).await.unwrap();

        let msg = JobMessage {
            run_id: "run1".into(),
            job_id: "run1.build".into(),
            job_key: "build".into(),
        };
        bus.publish_job(&route, &msg).await.unwrap();
        bus.publish_job(&route, &msg).await.unwrap();

        assert_eq!(
            bus.depth(&route).await.unwrap().unwrap().waiting,
            1,
            "Nats-Msg-Id must collapse the duplicate"
        );
        cleanup(&bus).await;
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_NATS_URL"]
    async fn an_outbox_retry_after_puback_is_deduplicated() {
        let prefix = test_prefix();
        let bus = test_bus(&prefix).await;
        let event = crate::store::OutboxEvent {
            id: uuid::Uuid::new_v4(),
            subject: "run1.build".into(),
            payload: serde_json::json!({"version": 1, "status": "running"}),
        };

        bus.publish_outbox(&event).await.unwrap();
        // Models PubAck succeeding and the following Postgres mark failing.
        bus.publish_outbox(&event).await.unwrap();

        let mut stream = bus.js.get_stream(bus.events_stream()).await.unwrap();
        assert_eq!(stream.info().await.unwrap().state.messages, 1,
            "the stable Nats-Msg-Id must collapse a post-PubAck retry");
        cleanup(&bus).await;
    }

    /// A message that is never acked comes back, which is what makes a
    /// dispatcher crash recoverable — and the reason `ack_wait` must exceed the
    /// job timeout.
    #[tokio::test]
    #[ignore = "needs a NATS with JetStream"]
    async fn an_unacked_message_is_redelivered() {
        use futures::StreamExt;
        let prefix = test_prefix();
        let bus = test_bus(&prefix).await;
        let route = Route::Runner("hd-redeliver".into());

        // A deliberately tiny ack_wait; a real consumer derives it from the job
        // timeout, which is the point being tested.
        let durable = bus.durable_for(&route).unwrap();
        let stream = bus.js.get_stream(bus.jobs_stream()).await.unwrap();
        let consumer: PullConsumer = stream
            .get_or_create_consumer(
                &durable,
                PullConfig {
                    durable_name: Some(durable.clone()),
                    filter_subject: bus.subject_for(&route).unwrap(),
                    ack_wait: Duration::from_secs(1),
                    max_deliver: MAX_DELIVER,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        bus.publish_job(
            &route,
            &JobMessage {
                run_id: "run1".into(),
                job_id: "run1.build".into(),
                job_key: "build".into(),
            },
        )
        .await
        .unwrap();

        let mut batch = consumer.fetch().max_messages(1).messages().await.unwrap();
        let first = batch.next().await.unwrap().unwrap();
        assert_eq!(first.info().unwrap().delivered, 1);
        drop(first); // never acked — the dispatcher "crashed"

        tokio::time::sleep(Duration::from_millis(1500)).await;

        let mut batch = consumer.fetch().max_messages(1).messages().await.unwrap();
        let again = batch.next().await.expect("redelivered").unwrap();
        assert_eq!(
            again.info().unwrap().delivered,
            2,
            "the second delivery must be marked as a retry"
        );
        again.ack().await.unwrap();
        cleanup(&bus).await;
    }

}

#[cfg(test)]
mod maintenance {
    use super::*;

    /// Delete streams left behind by a test run that panicked before its own
    /// cleanup. Run with:
    /// `CI_TEST_NATS_URL=… cargo test --bin ci -- --ignored delete_leftover`
    ///
    /// Matches only prefixes this repository's tests and local runs mint, so it
    /// cannot touch `HEYO_SANDBOX` or anything else sharing the server. Set
    /// `CI_TEST_STREAM_PREFIXES` (comma-separated) to add more — a manual run
    /// with `CI_NATS_SUBJECT_PREFIX=myrun` leaves `MYRUN_JOBS` behind.
    #[tokio::test]
    #[ignore = "maintenance: needs a NATS with JetStream"]
    async fn delete_leftover_test_streams() {
        use futures::StreamExt;
        let url = std::env::var("CI_TEST_NATS_URL")
            .unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
        let endpoint =
            NatsEndpoint::resolve(&url, &crate::nats_auth::EnvCredentials::default()).unwrap();
        let (opts, servers) = endpoint.connect_options("ci-maintenance").unwrap();
        let client = opts.connect(servers).await.expect("nats");
        let js = jetstream::new(client);

        let mut names = js.stream_names();
        let mut doomed = Vec::new();
        while let Some(Ok(name)) = names.next().await {
            let upper = name.to_uppercase();
            let mut prefixes: Vec<String> = vec!["E2E".into(), "CITEST".into()];
            if let Ok(extra) = std::env::var("CI_TEST_STREAM_PREFIXES") {
                prefixes.extend(
                    extra
                        .split(',')
                        .map(|p| p.trim().to_uppercase())
                        .filter(|p| !p.is_empty()),
                );
            }
            if prefixes.iter().any(|p| upper.starts_with(p.as_str())) {
                doomed.push(name);
            }
        }
        for name in doomed {
            println!("deleting leftover stream {name}");
            js.delete_stream(&name).await.expect("deleted");
        }
    }
}
