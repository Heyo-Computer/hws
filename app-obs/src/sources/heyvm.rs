//! Tails the daemon's native per-sandbox log streams.
//!
//! Historically this collector could only receive what an application pushed
//! itself: the daemon's log store held nothing but `execute_command` output, so
//! a `start_command`'s stdout went to a file inside the guest and died there.
//! The daemon now captures each sandbox's serial console and its start
//! command's stdout/stderr natively and serves them — 1000-entry backlog plus
//! live follow — over a WebSocket at `GET /sandboxes/:id/logs/stream`. This
//! module drinks from that: every line a managed VM prints lands here with
//! zero guest cooperation, no shipper, no ingest token inside the guest.
//!
//! Which sandboxes to tail comes from the app-lb poll, because app-lb is the
//! authority on which VM serves which deployment — the daemon knows sandboxes,
//! not deployments. A backend the poller stops reporting gets its tailer
//! stopped; one it starts reporting gets one spawned. The push paths in
//! `ingest` remain for applications that emit structured records; an app that
//! both prints to stdout *and* pushes the same lines will store them twice,
//! under different `source` values.
//!
//! # Reconnects and duplicates
//!
//! The stream carries no cursor, only a count-based backlog, and timestamps
//! have one-second precision. On the first attach we ask for the daemon's full
//! backlog (it caps at 1000) so boot lines predating this process are kept; on
//! reconnect we ask for a small backlog to cover the gap and drop replayed
//! frames we have already stored, recognised by (timestamp, source, message)
//! against a ring of recent lines. Only the replayed prefix is deduplicated —
//! a live application legitimately printing the same line twice in one second
//! must not lose the second copy. Across an app-obs restart the ring is empty,
//! so up to one backlog of duplicates can be stored; that trade goes the same
//! way every trade here goes: prefer a duplicate line to a lost one.

use crate::ingest::Sink;
use crate::sources::VmTarget;
use crate::store::schema::{LogRecord, Record};
use futures_util::StreamExt;
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::Message;

/// First attach replays everything the daemon holds; its store caps at 1000
/// per sandbox, so this asks for all of it.
const FIRST_BACKLOG: usize = 1000;

/// Reconnect replay depth. Covers the lines printed during a short disconnect;
/// anything the sandbox printed beyond this during an outage is lost, which is
/// this codebase's standing trade against complexity.
const RECONNECT_BACKLOG: usize = 200;

/// How many recently-stored lines the dedup ring remembers. Must comfortably
/// exceed [`RECONNECT_BACKLOG`], or a replayed frame could outlive the memory
/// of its first delivery.
const SEEN_CAP: usize = 1024;

/// Reconnect backoff bounds. The floor keeps a crash-looping sandbox from
/// being hammered; the ceiling keeps a recovered daemon from being ignored.
const BACKOFF_FLOOR: Duration = Duration::from_secs(2);
const BACKOFF_CEIL: Duration = Duration::from_secs(30);

/// How often the manager wakes without a snapshot change, to respawn a tailer
/// task that died (a panic — disconnects are handled inside the task).
const REAP_INTERVAL: Duration = Duration::from_secs(30);

/// One frame off the daemon's stream. Mirrors the daemon's `LogEntry`
/// serialisation: epoch seconds, lowercase source and level. Only the fields
/// consumed here are declared, so the daemon can add to its frames without
/// breaking this.
#[derive(Debug, Deserialize)]
struct WireEntry {
    /// Epoch **seconds** — the daemon's wire precision for log timestamps.
    timestamp: u64,
    /// `stdout`, `stderr`, or `console`.
    source: String,
    #[serde(default)]
    level: Option<String>,
    message: String,
}

impl WireEntry {
    fn into_record(self, deployment: &str, backend: &str) -> Record {
        Record::Log(LogRecord {
            ts_millis: (self.timestamp as i64).saturating_mul(1000),
            deployment: deployment.to_string(),
            backend: Some(backend.to_string()),
            source: self.source,
            level: self.level,
            message: self.message,
            fields: None,
            host: None,
            namespace: None,
        })
    }

    /// Identity for reconnect dedup. A hash rather than the strings themselves
    /// so the ring costs 8 bytes a line; a collision drops an innocent line at
    /// hash-collision odds, which loses to actual disk errors.
    fn dedup_key(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.timestamp.hash(&mut hasher);
        self.source.hash(&mut hasher);
        self.message.hash(&mut hasher);
        hasher.finish()
    }
}

/// FIFO set of recently-stored line identities.
struct SeenRing {
    order: VecDeque<u64>,
    set: HashSet<u64>,
    cap: usize,
}

impl SeenRing {
    fn new(cap: usize) -> Self {
        Self {
            order: VecDeque::with_capacity(cap),
            set: HashSet::with_capacity(cap),
            cap,
        }
    }

    fn contains(&self, key: u64) -> bool {
        self.set.contains(&key)
    }

    fn insert(&mut self, key: u64) {
        if !self.set.insert(key) {
            return; // already present; keep its original eviction position
        }
        self.order.push_back(key);
        if self.order.len() > self.cap {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            }
        }
    }
}

/// Owns one tailer task per live VM backend and reconciles them against the
/// target set the app-lb poller publishes.
pub struct Tailers {
    base_url: String,
    /// Bearer token for the daemon, needed when it runs with `JWT_SECRET` set.
    token: Option<Arc<String>>,
    targets: tokio::sync::watch::Receiver<Vec<VmTarget>>,
    sink: Sink,
}

struct RunningTailer {
    deployment: String,
    task: tokio::task::JoinHandle<()>,
}

impl Tailers {
    pub fn new(
        base_url: String,
        token: Option<String>,
        targets: tokio::sync::watch::Receiver<Vec<VmTarget>>,
        sink: Sink,
    ) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.map(Arc::new),
            targets,
            sink,
        }
    }

    /// Reconcile until the target publisher goes away (process shutdown).
    pub async fn run(mut self) {
        let mut running: HashMap<String, RunningTailer> = HashMap::new();

        loop {
            let wanted: HashMap<String, String> = self
                .targets
                .borrow_and_update()
                .iter()
                .map(|t| (t.backend.clone(), t.deployment.clone()))
                .collect();

            // Stop what is no longer wanted (or moved deployments, which makes
            // its stored attribution wrong), and forget tasks that died so the
            // spawn pass below restarts them.
            running.retain(|backend, tailer| {
                let keep = wanted.get(backend) == Some(&tailer.deployment)
                    && !tailer.task.is_finished();
                if !keep {
                    tailer.task.abort();
                }
                keep
            });

            for (backend, deployment) in wanted {
                if running.contains_key(&backend) {
                    continue;
                }
                tracing::info!(sandbox = %backend, deployment = %deployment, "tailing daemon logs");
                let task = tokio::spawn(tail(
                    self.base_url.clone(),
                    self.token.clone(),
                    deployment.clone(),
                    backend.clone(),
                    self.sink.clone(),
                ));
                running.insert(backend, RunningTailer { deployment, task });
            }

            // Sleep until the snapshot changes, waking periodically to respawn
            // panicked tasks. A closed channel means the poller — and with it
            // the process — is going down.
            match tokio::time::timeout(REAP_INTERVAL, self.targets.changed()).await {
                Ok(Err(_)) => break,
                Ok(Ok(())) | Err(_) => {}
            }
        }

        for (_, tailer) in running {
            tailer.task.abort();
        }
    }
}

/// Stream one sandbox's logs forever, reconnecting with backoff. Ends only by
/// abort from the manager.
async fn tail(
    base_url: String,
    token: Option<Arc<String>>,
    deployment: String,
    backend: String,
    sink: Sink,
) {
    let mut backlog = FIRST_BACKLOG;
    let mut seen = SeenRing::new(SEEN_CAP);
    let mut delay = BACKOFF_FLOOR;

    loop {
        match stream_once(&base_url, token.as_deref(), &deployment, &backend, backlog, &mut seen, &sink).await {
            // A connection that carried frames was healthy; start the next
            // attempt from the floor rather than compounding old failures.
            Ok(frames) if frames > 0 => delay = BACKOFF_FLOOR,
            Ok(_) => {}
            Err(e) => {
                // Debug, not warn: a sandbox that is booting, stopping, or on
                // a pre-stream daemon fails here on every attempt, and the
                // condition is visible in the dashboard as absent logs.
                tracing::debug!(sandbox = %backend, error = %e, "daemon log stream disconnected");
            }
        }
        // Whatever the daemon replays next time overlaps what we stored; the
        // seen-ring drops the overlap.
        backlog = RECONNECT_BACKLOG;
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(BACKOFF_CEIL);
    }
}

type StreamError = Box<dyn std::error::Error + Send + Sync>;

/// One connection: attach, drain frames into the sink until the peer closes.
/// Returns how many text frames arrived, so the caller can tell a healthy
/// stream that ended from a connect that never got anywhere.
async fn stream_once(
    base_url: &str,
    token: Option<&String>,
    deployment: &str,
    backend: &str,
    backlog: usize,
    seen: &mut SeenRing,
    sink: &Sink,
) -> Result<u64, StreamError> {
    let url = format!(
        "{}/sandboxes/{}/logs/stream?backlog={}",
        http_to_ws(base_url),
        backend,
        backlog,
    );
    let mut request = url.into_client_request()?;
    if let Some(token) = token {
        request.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse()?,
        );
    }

    let (mut socket, _) = connect_async(request).await?;

    let mut frames = 0u64;
    // The server sends the backlog replay first, then live frames, with no
    // marker between them. Dedup-check exactly the first `backlog` frames:
    // every replayed frame is inside that prefix, and the few live frames that
    // may also fall in it are only dropped if they collide with a stored
    // (second, source, message) — the documented trade.
    let mut replay_left = backlog;

    while let Some(message) = socket.next().await {
        match message? {
            Message::Text(text) => {
                frames += 1;
                // A frame this process can't parse is a daemon newer than it;
                // skip the frame rather than the stream.
                let Ok(entry) = serde_json::from_str::<WireEntry>(text.as_ref()) else {
                    continue;
                };
                let key = entry.dedup_key();
                if replay_left > 0 {
                    replay_left -= 1;
                    if seen.contains(key) {
                        continue;
                    }
                }
                seen.insert(key);
                sink.send(entry.into_record(deployment, backend));
            }
            Message::Close(_) => break,
            // Pings are answered by tungstenite itself; binary frames are not
            // part of this protocol.
            _ => {}
        }
    }

    Ok(frames)
}

/// The daemon URL is configured as `http(s)://`, the same string every other
/// client uses; the stream endpoint needs the WebSocket scheme.
fn http_to_ws(base_url: &str) -> String {
    if let Some(rest) = base_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base_url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::SinkExt;

    #[test]
    fn wire_entries_parse_the_daemon_frame_shape() {
        // What the daemon actually sends: epoch seconds, lowercase enums,
        // level omitted when unknown.
        let entry: WireEntry = serde_json::from_str(
            r#"{"timestamp":1785260096,"source":"stderr","level":"error","message":"boom"}"#,
        )
        .unwrap();
        assert_eq!(entry.timestamp, 1_785_260_096);
        assert_eq!(entry.source, "stderr");
        assert_eq!(entry.level.as_deref(), Some("error"));

        let bare: WireEntry =
            serde_json::from_str(r#"{"timestamp":1,"source":"console","message":"[    0.0] Linux"}"#)
                .unwrap();
        assert_eq!(bare.level, None);
    }

    #[test]
    fn records_carry_the_deployment_and_backend_the_poller_knew() {
        // The guest never states these; attribution is entirely the mapping
        // app-lb reported.
        let entry: WireEntry = serde_json::from_str(
            r#"{"timestamp":1785260096,"source":"stdout","message":"started"}"#,
        )
        .unwrap();
        let Record::Log(record) = entry.into_record("demo", "sb-abc") else {
            panic!("expected a log record");
        };
        assert_eq!(record.deployment, "demo");
        assert_eq!(record.backend.as_deref(), Some("sb-abc"));
        assert_eq!(record.ts_millis, 1_785_260_096_000, "seconds became millis");
        assert_eq!(record.source, "stdout");
    }

    #[test]
    fn the_seen_ring_evicts_oldest_first_and_tolerates_reinsertion() {
        let mut ring = SeenRing::new(2);
        ring.insert(1);
        ring.insert(1); // must not occupy a second slot
        ring.insert(2);
        assert!(ring.contains(1) && ring.contains(2));
        ring.insert(3);
        assert!(!ring.contains(1), "oldest evicted");
        assert!(ring.contains(2) && ring.contains(3));
    }

    #[test]
    fn unparseable_base_urls_pass_through_and_fail_at_connect() {
        assert_eq!(http_to_ws("http://127.0.0.1:34099"), "ws://127.0.0.1:34099");
        assert_eq!(http_to_ws("https://host"), "wss://host");
        // Not this function's job to validate; the connect error names the
        // string the operator actually configured.
        assert_eq!(http_to_ws("garbage"), "garbage");
    }

    /// A stand-in daemon: accepts one WebSocket, sends the given frames, then
    /// closes.
    async fn serve_frames(frames: Vec<String>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            for frame in frames {
                socket.send(Message::Text(frame.into())).await.unwrap();
            }
            socket.close(None).await.ok();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn a_stream_lands_in_the_sink_with_replay_dedup() {
        let line = |n: u64| {
            format!(r#"{{"timestamp":{n},"source":"stdout","message":"line {n}"}}"#)
        };

        // First connection: two lines, both new.
        let (sink, mut rx) = Sink::new(64);
        let mut seen = SeenRing::new(SEEN_CAP);
        let url = serve_frames(vec![line(1), line(2)]).await;
        let frames = stream_once(&url, None, "demo", "sb-abc", 100, &mut seen, &sink)
            .await
            .unwrap();
        assert_eq!(frames, 2);

        // Reconnect: the daemon replays line 2, then delivers a new line 3.
        let url = serve_frames(vec![line(2), line(3)]).await;
        let frames = stream_once(&url, None, "demo", "sb-abc", 100, &mut seen, &sink)
            .await
            .unwrap();
        assert_eq!(frames, 2, "the duplicate frame still arrived on the wire");

        // ...but only three records were stored.
        let mut messages = Vec::new();
        while let Ok(record) = rx.try_recv() {
            let Record::Log(log) = record else { panic!() };
            messages.push(log.message);
        }
        assert_eq!(messages, vec!["line 1", "line 2", "line 3"]);
    }

    #[tokio::test]
    async fn live_frames_beyond_the_replay_window_are_never_deduplicated() {
        // backlog=1 marks only the first frame as replay. The two identical
        // frames after it are live — an app printing the same line twice —
        // and both must be kept.
        let repeated = r#"{"timestamp":9,"source":"stdout","message":"tick"}"#.to_string();
        let (sink, mut rx) = Sink::new(64);
        let mut seen = SeenRing::new(SEEN_CAP);
        seen.insert(
            serde_json::from_str::<WireEntry>(&repeated)
                .unwrap()
                .dedup_key(),
        );

        let url = serve_frames(vec![repeated.clone(), repeated.clone(), repeated]).await;
        stream_once(&url, None, "demo", "sb-abc", 1, &mut seen, &sink)
            .await
            .unwrap();

        let mut stored = 0;
        while rx.try_recv().is_ok() {
            stored += 1;
        }
        assert_eq!(stored, 2, "replayed copy dropped, live copies kept");
    }
}
