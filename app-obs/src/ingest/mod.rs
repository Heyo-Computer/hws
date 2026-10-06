//! Getting records in.
//!
//! # Why push exists, and why it binds every interface
//!
//! Push was originally the only way to get application logs at all — the
//! daemon's log store used to hold nothing but `execute_command` output. The
//! daemon now streams a sandbox's console and start-command output natively
//! (see `sources::heyvm`), so push remains for what the console never sees:
//! records with application-authored levels and structured fields.
//!
//! Each microVM sits on its own /30 — the host is at `guest_ip - 1` — so there
//! is no single address every guest could be pointed at. Guests instead send to
//! their **default gateway**, which is always this host on their subnet, and we
//! bind `0.0.0.0` so we are reachable on all of them.
//!
//! # Dropping is a feature
//!
//! Everything funnels through one bounded queue. When it is full, records are
//! dropped and counted; they are never allowed to block the sender. A customer's
//! application must not stall because the collector fell behind, so losing
//! telemetry is always the correct trade against applying backpressure.
//!
//! # Attribution and the install gate
//!
//! The sink is also the one place every record passes, whatever its source, so
//! it is where the namespace is stamped and where a namespace that has not
//! installed the obs plugin is turned away. See [`crate::namespaces`].

pub mod http;
pub mod syslog;

use crate::namespaces::Directory;
use crate::store::schema::Record;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

/// The write end of the ingest queue, shared by every source.
#[derive(Clone)]
pub struct Sink {
    tx: mpsc::Sender<Record>,
    stats: Arc<Stats>,
    /// Stamps the namespace and applies the install gate. `None` writes every
    /// record unattributed, which only tests want.
    directory: Option<Arc<Directory>>,
}

#[derive(Default)]
pub struct Stats {
    pub accepted: AtomicU64,
    pub dropped: AtomicU64,
    /// Records for a namespace that has not installed the obs plugin. Not a
    /// failure — the sender did nothing wrong and must not retry — so counted
    /// apart from `dropped`.
    pub gated: AtomicU64,
}

impl Sink {
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<Record>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self {
                tx,
                stats: Arc::new(Stats::default()),
                directory: None,
            },
            rx,
        )
    }

    /// Attribute every record through `directory` and apply its install gate.
    pub fn with_directory(mut self, directory: Arc<Directory>) -> Self {
        self.directory = Some(directory);
        self
    }

    /// Queue a record. Returns `false` if it was dropped for lack of room.
    ///
    /// `try_send` rather than `send` is the whole point: `send` would await a
    /// free slot and turn a backed-up collector into latency in whatever is
    /// shipping to us.
    ///
    /// A record the install gate refuses returns `true`: it was handled as
    /// intended, and a sender told otherwise would retry it forever.
    pub fn send(&self, mut record: Record) -> bool {
        if let Some(directory) = &self.directory {
            match directory.admit(record.deployment()) {
                Some(namespace) => record.set_namespace(namespace),
                None => {
                    self.stats.gated.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
        }
        match self.tx.try_send(record) {
            Ok(()) => {
                self.stats.accepted.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn accepted(&self) -> u64 {
        self.stats.accepted.load(Ordering::Relaxed)
    }

    pub fn dropped(&self) -> u64 {
        self.stats.dropped.load(Ordering::Relaxed)
    }

    pub fn gated(&self) -> u64 {
        self.stats.gated.load(Ordering::Relaxed)
    }
}

/// Constant-time comparison for the ingest token, so a matching prefix can't be
/// timed out of it. Same approach as app-lb's dashboard auth.
pub fn token_matches(expected: &str, presented: Option<&str>) -> bool {
    let Some(presented) = presented.and_then(|v| v.strip_prefix("Bearer ")) else {
        return false;
    };
    let (a, b) = (expected.as_bytes(), presented.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::schema::LogRecord;

    fn log() -> Record {
        Record::Log(LogRecord {
            ts_millis: 1_785_260_096_000,
            deployment: "demo".into(),
            backend: None,
            source: "stdout".into(),
            level: None,
            message: "x".into(),
            fields: None,
            host: None,
            namespace: None,
        })
    }

    #[tokio::test]
    async fn a_full_queue_drops_instead_of_blocking() {
        // The defining property of this layer. If this ever blocks, a slow
        // collector becomes latency in somebody's application.
        let (sink, _rx) = Sink::new(2);
        assert!(sink.send(log()));
        assert!(sink.send(log()));

        // Third send has nowhere to go. It must return immediately, not await.
        let overflow = tokio::time::timeout(std::time::Duration::from_millis(100), async {
            sink.send(log())
        })
        .await
        .expect("send must never block");

        assert!(!overflow, "the record was dropped");
        assert_eq!(sink.accepted(), 2);
        assert_eq!(sink.dropped(), 1);
    }

    #[tokio::test]
    async fn records_are_stamped_with_their_namespace_or_gated_out() {
        use crate::namespaces::Gate;
        use std::collections::{HashMap, HashSet};

        let directory = Arc::new(Directory::new(true));
        directory.set_namespaces(HashMap::from([
            ("demo".to_string(), "team-a".to_string()),
            ("other".to_string(), "team-b".to_string()),
        ]));
        directory.set_gate(Gate::Installed(HashSet::from(["team-a".to_string()])));
        let (sink, mut rx) = Sink::new(8);
        let sink = sink.with_directory(directory);

        assert!(sink.send(log()));
        let Record::Log(written) = rx.recv().await.unwrap() else {
            unreachable!()
        };
        assert_eq!(written.namespace.as_deref(), Some("team-a"));

        let Record::Log(mut other) = log() else {
            unreachable!()
        };
        other.deployment = "other".into();
        assert!(
            sink.send(Record::Log(other)),
            "a gated record is not the sender's failure"
        );
        assert!(rx.try_recv().is_err(), "team-b never installed obs");
        assert_eq!((sink.accepted(), sink.dropped(), sink.gated()), (1, 0, 1));
    }

    #[tokio::test]
    async fn draining_the_queue_makes_room_again() {
        let (sink, mut rx) = Sink::new(1);
        assert!(sink.send(log()));
        assert!(!sink.send(log()));
        rx.recv().await.unwrap();
        assert!(sink.send(log()), "a drained slot is reusable");
    }

    #[test]
    fn token_comparison_requires_the_bearer_scheme_and_exact_value() {
        assert!(token_matches("s3cret", Some("Bearer s3cret")));
        assert!(!token_matches("s3cret", Some("Bearer wrong")));
        assert!(!token_matches("s3cret", Some("Bearer s3cre")), "prefix");
        assert!(!token_matches("s3cret", Some("s3cret")), "no scheme");
        assert!(
            !token_matches("s3cret", Some("Basic s3cret")),
            "wrong scheme"
        );
        assert!(!token_matches("s3cret", None));
    }
}
