//! `POST /ingest` — batched log records over HTTP.
//!
//! The wire format is deliberately forgiving about timestamps and about where
//! `deployment` is stated, because the senders are heterogeneous: a Rust
//! shipper, a shell one-liner piping through `curl`, and application code that
//! just wants to emit a line. Being strict here would mostly produce silently
//! unshipped logs.

use super::{Sink, token_matches};
use crate::store::schema::{LogRecord, Record};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct IngestState {
    pub sink: Sink,
    /// `None` leaves ingest unauthenticated, which is only defensible when the
    /// listener is unreachable from outside the tap networks.
    pub token: Option<Arc<String>>,
}

/// One batch. `deployment`, `backend`, and `host` at the top level apply to
/// every record that doesn't state its own, so the common case — one VM
/// shipping its own lines — doesn't repeat them per record.
#[derive(Debug, Deserialize)]
pub struct Batch {
    #[serde(default)]
    pub deployment: Option<String>,
    /// Which instance produced this — a sandbox id for a VM deployment, a
    /// `host:port` for a static upstream. `sandbox_id` is accepted as an alias,
    /// because a guest naturally knows itself by that name.
    #[serde(default, alias = "sandbox_id")]
    pub backend: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    pub records: Vec<IncomingRecord>,
}

#[derive(Debug, Deserialize)]
pub struct IncomingRecord {
    /// Epoch milliseconds, or RFC 3339. Absent means "now" — a shipper that
    /// doesn't know the time is better than a dropped line.
    #[serde(default)]
    pub ts: Option<serde_json::Value>,
    #[serde(default)]
    pub deployment: Option<String>,
    /// Which instance produced this — a sandbox id for a VM deployment, a
    /// `host:port` for a static upstream. `sandbox_id` is accepted as an alias,
    /// because a guest naturally knows itself by that name.
    #[serde(default, alias = "sandbox_id")]
    pub backend: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    pub message: String,
    /// Arbitrary structured payload, stored as a JSON string.
    #[serde(default)]
    pub fields: Option<serde_json::Value>,
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub accepted: usize,
    /// Queue was full. The sender may retry, but should not assume it will help.
    pub dropped: usize,
    /// Rejected outright — no usable `deployment`. Retrying will not help.
    pub rejected: usize,
}

pub fn router(state: IngestState) -> Router {
    Router::new()
        .route("/ingest", post(ingest))
        // Unauthenticated so a shipper can check reachability before it holds
        // any credentials, and so a health probe needs no secret.
        .route("/healthz", get(health))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    if let Some(value) = std::env::var("APP_OBS_REVISION")
        .ok()
        .and_then(|value| HeaderValue::from_str(&value).ok())
    {
        headers.insert("x-heyo-revision", value);
    }
    (headers, "ok\n")
}

async fn ingest(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Json(batch): Json<Batch>,
) -> impl IntoResponse {
    if let Some(expected) = &state.token {
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        if !token_matches(expected, presented) {
            return (StatusCode::UNAUTHORIZED, "invalid ingest token\n").into_response();
        }
    }

    let now = Utc::now().timestamp_millis();
    let mut response = IngestResponse {
        accepted: 0,
        dropped: 0,
        rejected: 0,
    };

    for incoming in batch.records {
        let Some(deployment) = incoming
            .deployment
            .clone()
            .or_else(|| batch.deployment.clone())
        else {
            response.rejected += 1;
            continue;
        };

        let record = Record::Log(LogRecord {
            ts_millis: parse_ts(incoming.ts.as_ref()).unwrap_or(now),
            deployment,
            backend: incoming.backend.or_else(|| batch.backend.clone()),
            source: incoming.source.unwrap_or_else(|| "stdout".into()),
            level: incoming.level,
            message: incoming.message,
            // Serialised here rather than stored as a nested Arrow type: one
            // application emitting unusual keys must not widen the schema for
            // every other deployment sharing the table.
            fields: incoming.fields.as_ref().map(|f| f.to_string()),
            host: incoming.host.or_else(|| batch.host.clone()),
            namespace: None,
        });

        if state.sink.send(record) {
            response.accepted += 1;
        } else {
            response.dropped += 1;
        }
    }

    if response.dropped > 0 {
        tracing::warn!(
            dropped = response.dropped,
            "ingest queue full; records dropped rather than blocking the sender",
        );
    }

    // 202, not 200: the records are queued, not yet durable. A sender that
    // needs delivery confirmation would have to poll, and none do.
    (StatusCode::ACCEPTED, Json(response)).into_response()
}

/// Accept epoch millis (number or numeric string) or RFC 3339.
///
/// Seconds-vs-milliseconds is guessed by magnitude: anything below ~2001 in
/// milliseconds is far likelier to be a seconds value from a shell script than
/// a genuine 1970s timestamp.
fn parse_ts(value: Option<&serde_json::Value>) -> Option<i64> {
    const SECONDS_CUTOFF: i64 = 100_000_000_000;

    match value? {
        serde_json::Value::Number(n) => {
            let raw = n.as_i64()?;
            // `unsigned_abs`, not `abs`: negating `i64::MIN` overflows, and
            // this value comes straight off the wire.
            Some(if raw.unsigned_abs() < SECONDS_CUTOFF as u64 {
                raw.checked_mul(1000)?
            } else {
                raw
            })
        }
        serde_json::Value::String(s) => {
            if let Ok(raw) = s.parse::<i64>() {
                return Some(if raw.abs() < SECONDS_CUTOFF {
                    raw.checked_mul(1000)?
                } else {
                    raw
                });
            }
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.timestamp_millis())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn timestamps_are_accepted_in_the_shapes_senders_actually_emit() {
        // Epoch millis, the canonical form.
        assert_eq!(parse_ts(Some(&json!(1_785_260_096_000i64))), Some(1_785_260_096_000));
        // Epoch seconds, what `date +%s` gives a shell shipper.
        assert_eq!(parse_ts(Some(&json!(1_785_260_096i64))), Some(1_785_260_096_000));
        // Numeric string, what a JSON encoder without 64-bit ints produces.
        assert_eq!(parse_ts(Some(&json!("1785260096000"))), Some(1_785_260_096_000));
        // RFC 3339, what structured loggers emit.
        assert_eq!(
            parse_ts(Some(&json!("2026-07-28T17:34:56Z"))),
            Some(1_785_260_096_000),
        );
    }

    #[test]
    fn an_unusable_timestamp_falls_back_rather_than_failing() {
        // The caller substitutes "now"; losing precise ordering beats losing
        // the line.
        assert_eq!(parse_ts(None), None);
        assert_eq!(parse_ts(Some(&json!("not a time"))), None);
        assert_eq!(parse_ts(Some(&json!({}))), None);
        assert_eq!(parse_ts(Some(&json!(null))), None);
    }

    #[test]
    fn extreme_values_do_not_panic() {
        // `i64::MIN` is the interesting one: `abs()` on it overflows, and this
        // value arrives straight off the wire from an untrusted sender. It is
        // past the seconds cutoff, so it passes through unscaled and gets
        // rejected later by `PartitionKey`, which is where that judgement
        // belongs.
        assert_eq!(parse_ts(Some(&json!(i64::MIN))), Some(i64::MIN));
        assert_eq!(parse_ts(Some(&json!(i64::MAX))), Some(i64::MAX));

        // Large negative seconds still scale correctly rather than wrapping.
        assert_eq!(
            parse_ts(Some(&json!(-99_999_999_999i64))),
            Some(-99_999_999_999_000),
        );
    }

    #[tokio::test]
    async fn records_without_a_deployment_are_rejected_not_queued() {
        let (sink, _rx) = Sink::new(10);
        let state = IngestState {
            sink: sink.clone(),
            token: None,
        };

        let batch = Batch {
            deployment: None,
            backend: None,
            host: None,
            records: vec![IncomingRecord {
                ts: None,
                deployment: None,
                backend: None,
                source: None,
                level: None,
                message: "orphan".into(),
                fields: None,
                host: None,
            }],
        };

        let response = ingest(State(state), HeaderMap::new(), Json(batch))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(sink.accepted(), 0, "nothing unattributable reaches the queue");
    }

    #[tokio::test]
    async fn the_batch_supplies_defaults_for_its_records() {
        let (sink, mut rx) = Sink::new(10);
        let state = IngestState {
            sink: sink.clone(),
            token: None,
        };

        let batch = Batch {
            deployment: Some("demo".into()),
            backend: Some("sb-abc".into()),
            host: Some("us2".into()),
            records: vec![
                IncomingRecord {
                    ts: Some(json!(1_785_260_096_000i64)),
                    deployment: None,
                    backend: None,
                    source: None,
                    level: Some("info".into()),
                    message: "inherits".into(),
                    fields: None,
                    host: None,
                },
                IncomingRecord {
                    ts: None,
                    // A record may override the batch — one shipper can carry
                    // lines for several deployments.
                    deployment: Some("other".into()),
                    backend: None,
                    source: Some("stderr".into()),
                    level: None,
                    message: "overrides".into(),
                    fields: None,
                    host: None,
                },
            ],
        };

        ingest(State(state), HeaderMap::new(), Json(batch)).await;
        assert_eq!(sink.accepted(), 2);

        let Record::Log(first) = rx.recv().await.unwrap() else {
            panic!("expected a log record");
        };
        assert_eq!(first.deployment, "demo");
        assert_eq!(first.backend.as_deref(), Some("sb-abc"));
        assert_eq!(first.host.as_deref(), Some("us2"));
        assert_eq!(first.source, "stdout", "defaulted");

        let Record::Log(second) = rx.recv().await.unwrap() else {
            panic!("expected a log record");
        };
        assert_eq!(second.deployment, "other");
        assert_eq!(second.source, "stderr");
        assert_eq!(second.backend.as_deref(), Some("sb-abc"), "still inherits");
    }

    #[tokio::test]
    async fn a_bad_token_is_rejected_before_anything_is_queued() {
        let (sink, _rx) = Sink::new(10);
        let state = IngestState {
            sink: sink.clone(),
            token: Some(Arc::new("s3cret".into())),
        };

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer wrong".parse().unwrap());

        let batch = Batch {
            deployment: Some("demo".into()),
            backend: None,
            host: None,
            records: vec![IncomingRecord {
                ts: None,
                deployment: None,
                backend: None,
                source: None,
                level: None,
                message: "should not land".into(),
                fields: None,
                host: None,
            }],
        };

        let response = ingest(State(state), headers, Json(batch))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(sink.accepted(), 0);
    }

    #[test]
    fn sandbox_id_is_accepted_as_an_alias_for_backend() {
        // Stored as `backend` because a static deployment's is a `host:port`,
        // but a guest knows itself as a sandbox and should be able to say so.
        let batch: Batch = serde_json::from_value(json!({
            "deployment": "demo",
            "sandbox_id": "sb-abc",
            "records": [{"message": "hi", "sandbox_id": "sb-xyz"}]
        }))
        .unwrap();
        assert_eq!(batch.backend.as_deref(), Some("sb-abc"));
        assert_eq!(batch.records[0].backend.as_deref(), Some("sb-xyz"));

        // And the canonical name works too.
        let canonical: Batch = serde_json::from_value(json!({
            "deployment": "demo",
            "backend": "127.0.0.1:8080",
            "records": [{"message": "hi"}]
        }))
        .unwrap();
        assert_eq!(canonical.backend.as_deref(), Some("127.0.0.1:8080"));
    }

    #[tokio::test]
    async fn structured_fields_are_stored_as_json() {
        let (sink, mut rx) = Sink::new(10);
        let state = IngestState {
            sink: sink.clone(),
            token: None,
        };

        let batch = Batch {
            deployment: Some("demo".into()),
            backend: None,
            host: None,
            records: vec![IncomingRecord {
                ts: None,
                deployment: None,
                backend: None,
                source: None,
                level: None,
                message: "structured".into(),
                fields: Some(json!({"request_id": "abc", "ms": 12})),
                host: None,
            }],
        };

        ingest(State(state), HeaderMap::new(), Json(batch)).await;
        let Record::Log(record) = rx.recv().await.unwrap() else {
            panic!("expected a log record");
        };
        let fields = record.fields.expect("fields preserved");
        let parsed: serde_json::Value = serde_json::from_str(&fields).unwrap();
        assert_eq!(parsed["request_id"], "abc");
        assert_eq!(parsed["ms"], 12);
    }
}
