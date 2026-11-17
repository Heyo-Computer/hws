//! The namespace surface: `/namespaces/<ns>/plugins/alerting/…`.
//!
//! Every handler reads its namespace from the [`NamespaceScope`] the host put
//! on the request and touches only that namespace's alerts, silences, checks
//! and deliveries — a fingerprint or silence id from another namespace is a
//! 404 here, not a 403, because to this namespace it does not exist.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::AlertingPlugin;
use super::config::Format;
use super::delivery::{self, AlertPayload, DeliveryRecord, Job};
use super::engine::{Alert, CheckResult, Matchers, Silence, MAX_SILENCES};
use crate::deployment::now_secs;
use crate::plugins::NamespaceScope;
use crate::plugins::ns_proxy::{NamespaceActor, fail};

const MAX_BODY: usize = 8 * 1024;
const MAX_COMMENT: usize = 1024;
const MAX_SILENCE_SECS: u64 = 90 * 86_400;

pub(super) fn router(p: Arc<AlertingPlugin>) -> Router {
    Router::new()
        .route("/ui", get(ui))
        .route("/api/status", get(status))
        .route("/api/alerts", get(alerts))
        .route("/api/alerts/:fingerprint/ack", post(ack))
        .route("/api/silences", get(silences).post(create_silence))
        .route("/api/silences/:silence", delete(delete_silence))
        .route("/api/checks", get(checks))
        .route("/api/deliveries", get(deliveries))
        .route("/api/receivers/:receiver/test", post(test_receiver))
        .fallback(|| async { fail(StatusCode::NOT_FOUND, "no alerting plugin route here") })
        .with_state(p)
}

#[allow(clippy::result_large_err)]
fn scope(req: &Request) -> Result<String, Response> {
    req.extensions()
        .get::<NamespaceScope>()
        .map(|s| s.0.clone())
        .ok_or_else(|| fail(StatusCode::INTERNAL_SERVER_ERROR, "no namespace scope on the request"))
}

/// A path parameter by name. Nested under `/namespaces/:name/plugins/:id`,
/// the request carries the outer parameters too, so a positional `Path<String>`
/// would fail to extract (a 500) on every real request — and these names must
/// not be `name` or `id`, which the outer route already uses.
#[allow(clippy::result_large_err)]
fn param(params: &HashMap<String, String>, key: &str) -> Result<String, Response> {
    params
        .get(key)
        .cloned()
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, format!("no {key} in the path")))
}

fn actor(req: &Request) -> Option<String> {
    req.extensions()
        .get::<NamespaceActor>()
        .and_then(|a| a.principal.clone().or_else(|| a.email.clone()))
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn json_ok<T: Serialize>(v: T) -> Response {
    no_store(axum::Json(v).into_response())
}

#[allow(clippy::result_large_err)]
async fn read_body<T: for<'de> Deserialize<'de>>(req: Request, empty_ok: bool) -> Result<T, Response> {
    let bytes = axum::body::to_bytes(req.into_body(), MAX_BODY)
        .await
        .map_err(|_| fail(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"))?;
    let bytes: &[u8] = if empty_ok && bytes.iter().all(u8::is_ascii_whitespace) { b"{}" } else { &bytes };
    serde_json::from_slice(bytes).map_err(|e| fail(StatusCode::BAD_REQUEST, format!("invalid body: {e}")))
}

#[allow(clippy::result_large_err)]
fn writable(p: &AlertingPlugin) -> Result<(), Response> {
    match &p.store.broken {
        Some(e) => Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("the alerting plugin's state cannot be read ({e}); an operator must fix it"),
        )),
        None => Ok(()),
    }
}

/// `GET …/ui`
async fn ui(req: Request) -> Response {
    match scope(&req) {
        Ok(ns) => crate::plugins::page(super::PAGE_HTML, &ns, &req),
        Err(r) => r,
    }
}

#[derive(Debug, Serialize)]
struct ReceiverView {
    id: String,
    format: Format,
    /// Scheme, host and port only: a webhook path is often itself a secret.
    endpoint: String,
    signed: bool,
}

/// `GET …/api/status`
async fn status(State(p): State<Arc<AlertingPlugin>>, req: Request) -> Response {
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let cfg = p.install(&ns).unwrap_or_default();
    let receivers: Vec<ReceiverView> = cfg
        .receivers
        .iter()
        .map(|r| ReceiverView {
            id: r.id.clone(),
            format: r.format,
            endpoint: url::Url::parse(&r.url)
                .map(|u| u.origin().ascii_serialization())
                .unwrap_or_default(),
            signed: r.secret.is_some(),
        })
        .collect();
    let (firing, pending, silences) = {
        let all = p.store.namespaces.lock().unwrap();
        all.get(&ns).map_or((0, 0, 0), |s| {
            let firing = s.alerts.values().filter(|a| a.status == super::engine::AlertStatus::Firing).count();
            (firing, s.alerts.len() - firing, s.silences.len())
        })
    };
    let rules: Vec<_> = cfg
        .rules
        .iter()
        .map(|r| json!({"id": r.id, "deployment": r.deployment, "condition": r.condition.kind(),
            "severity": r.severity, "receivers": r.receivers}))
        .collect();
    json_ok(json!({
        "namespace": ns,
        "receivers": receivers,
        "rules": rules,
        "checks": cfg.checks.len(),
        "firing": firing,
        "pending": pending,
        "silences": silences,
        "last_tick": p.runtime.lock().unwrap().last_tick,
        "state_error": p.store.broken,
    }))
}

#[derive(Debug, Serialize)]
struct AlertView {
    #[serde(flatten)]
    alert: Alert,
    silenced: bool,
}

/// `GET …/api/alerts` — pending and firing, then the recently resolved
/// (newest first).
async fn alerts(State(p): State<Arc<AlertingPlugin>>, req: Request) -> Response {
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let now = now_secs();
    let all = p.store.namespaces.lock().unwrap();
    let (active, resolved): (Vec<AlertView>, Vec<AlertView>) = match all.get(&ns) {
        None => (vec![], vec![]),
        Some(s) => (
            s.alerts
                .values()
                .map(|a| AlertView { silenced: s.silenced(a, now), alert: a.clone() })
                .collect(),
            s.resolved
                .iter()
                .rev()
                .map(|a| AlertView { silenced: false, alert: a.clone() })
                .collect(),
        ),
    };
    drop(all);
    json_ok(json!({"namespace": ns, "active": active, "resolved": resolved}))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AckBody {
    #[serde(default)]
    comment: Option<String>,
}

/// `POST …/api/alerts/:fingerprint/ack` — `{comment?}`. Stops the repeats
/// until the alert resolves.
async fn ack(
    State(p): State<Arc<AlertingPlugin>>,
    Path(params): Path<HashMap<String, String>>,
    req: Request,
) -> Response {
    let fp = match param(&params, "fingerprint") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let by = actor(&req).unwrap_or_else(|| "operator".into());
    if let Err(r) = writable(&p) {
        return r;
    }
    let body: AckBody = match read_body(req, true).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    if body.comment.as_ref().is_some_and(|c| c.len() > MAX_COMMENT) {
        return fail(StatusCode::BAD_REQUEST, format!("comment is longer than {MAX_COMMENT} bytes"));
    }
    let _held = p.writes.lock().await;
    let mut all = p.store.namespaces.lock().unwrap();
    let Some(alert) = all.get_mut(&ns).and_then(|s| s.alerts.get_mut(&fp)) else {
        return fail(StatusCode::NOT_FOUND, format!("no active alert {fp:?} in namespace \"{ns}\""));
    };
    alert.acked_by = Some(by);
    alert.acked_at = Some(now_secs());
    alert.ack_comment = body.comment;
    let view = alert.clone();
    if let Err(e) = p.store.persist(&all) {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, format!("could not save the acknowledgement: {e}"));
    }
    drop(all);
    json_ok(view)
}

/// `GET …/api/silences`
async fn silences(State(p): State<Arc<AlertingPlugin>>, req: Request) -> Response {
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let now = now_secs();
    let list: Vec<Silence> = p
        .store
        .namespaces
        .lock()
        .unwrap()
        .get(&ns)
        .map(|s| s.silences.iter().filter(|s| s.until > now).cloned().collect())
        .unwrap_or_default();
    json_ok(json!({"namespace": ns, "silences": list}))
}

/// `until` as unix seconds or RFC 3339.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Until {
    Unix(u64),
    Text(String),
}

impl Until {
    fn secs(&self) -> Result<u64, String> {
        match self {
            Until::Unix(n) => Ok(*n),
            Until::Text(s) => chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("until {s:?} is not RFC 3339: {e}"))
                .and_then(|t| u64::try_from(t.timestamp()).map_err(|_| "until is before 1970".into())),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewSilence {
    #[serde(default)]
    matchers: Matchers,
    until: Until,
    #[serde(default)]
    comment: String,
}

/// `POST …/api/silences` — `{matchers: {rule?, deployment?, severity?},
/// until, comment?}`. An empty matcher set silences the whole namespace.
async fn create_silence(State(p): State<Arc<AlertingPlugin>>, req: Request) -> Response {
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let by = actor(&req);
    if let Err(r) = writable(&p) {
        return r;
    }
    let body: NewSilence = match read_body(req, false).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let now = now_secs();
    let until = match body.until.secs() {
        Ok(t) => t,
        Err(e) => return fail(StatusCode::BAD_REQUEST, e),
    };
    if until <= now {
        return fail(StatusCode::BAD_REQUEST, "until must be in the future");
    }
    if until > now + MAX_SILENCE_SECS {
        return fail(StatusCode::BAD_REQUEST, "a silence may last at most 90 days");
    }
    if body.comment.len() > MAX_COMMENT {
        return fail(StatusCode::BAD_REQUEST, format!("comment is longer than {MAX_COMMENT} bytes"));
    }
    for v in [&body.matchers.rule, &body.matchers.deployment].into_iter().flatten() {
        if v.is_empty() || v.len() > 128 {
            return fail(StatusCode::BAD_REQUEST, "a matcher must be 1–128 bytes");
        }
    }
    let mut id = [0u8; 8];
    if openssl::rand::rand_bytes(&mut id).is_err() {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "no entropy for a silence id");
    }
    let silence = Silence {
        id: format!("sil_{}", super::engine::hex(&id)),
        matchers: body.matchers,
        until,
        comment: body.comment,
        created_by: by,
        created_at: now,
    };
    let _held = p.writes.lock().await;
    let mut all = p.store.namespaces.lock().unwrap();
    let state = all.entry(ns.clone()).or_default();
    state.silences.retain(|s| s.until > now);
    if state.silences.len() >= MAX_SILENCES {
        return fail(StatusCode::CONFLICT, format!("namespace \"{ns}\" already has {MAX_SILENCES} silences"));
    }
    state.silences.push(silence.clone());
    if let Err(e) = p.store.persist(&all) {
        if let Some(s) = all.get_mut(&ns) {
            s.silences.retain(|s| s.id != silence.id);
        }
        return fail(StatusCode::INTERNAL_SERVER_ERROR, format!("could not save the silence: {e}"));
    }
    drop(all);
    (StatusCode::CREATED, json_ok(silence)).into_response()
}

/// `DELETE …/api/silences/:id`
async fn delete_silence(
    State(p): State<Arc<AlertingPlugin>>,
    Path(params): Path<HashMap<String, String>>,
    req: Request,
) -> Response {
    let id = match param(&params, "silence") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    if let Err(r) = writable(&p) {
        return r;
    }
    let _held = p.writes.lock().await;
    let mut all = p.store.namespaces.lock().unwrap();
    let Some(state) = all.get_mut(&ns) else {
        return fail(StatusCode::NOT_FOUND, format!("no silence {id:?} in namespace \"{ns}\""));
    };
    let Some(pos) = state.silences.iter().position(|s| s.id == id) else {
        return fail(StatusCode::NOT_FOUND, format!("no silence {id:?} in namespace \"{ns}\""));
    };
    let removed = state.silences.remove(pos);
    if let Err(e) = p.store.persist(&all) {
        if let Some(s) = all.get_mut(&ns) {
            s.silences.insert(pos, removed);
        }
        return fail(StatusCode::INTERNAL_SERVER_ERROR, format!("could not save: {e}"));
    }
    drop(all);
    json_ok(json!({"deleted": id}))
}

#[derive(Debug, Serialize)]
struct CheckView {
    id: String,
    deployment: String,
    path: String,
    interval_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    expect_status: Option<u16>,
    min_passing: u32,
    /// `None` until the check first runs.
    result: Option<CheckResult>,
}

/// `GET …/api/checks`
async fn checks(State(p): State<Arc<AlertingPlugin>>, req: Request) -> Response {
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let cfg = p.install(&ns).unwrap_or_default();
    let rt = p.runtime.lock().unwrap();
    let results = rt.checks.get(&ns);
    let list: Vec<CheckView> = cfg
        .checks
        .iter()
        .map(|c| CheckView {
            id: c.id.clone(),
            deployment: c.deployment.clone(),
            path: c.path.clone(),
            interval_secs: c.interval_secs,
            expect_status: c.expect_status,
            min_passing: c.min_passing,
            result: results.and_then(|r| r.get(&c.id)).cloned(),
        })
        .collect();
    drop(rt);
    json_ok(json!({"namespace": ns, "checks": list}))
}

/// `GET …/api/deliveries` — the last webhooks, newest first.
async fn deliveries(State(p): State<Arc<AlertingPlugin>>, req: Request) -> Response {
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let list: Vec<DeliveryRecord> = p.deliverer.log(&ns);
    json_ok(json!({"namespace": ns, "deliveries": list}))
}

/// `POST …/api/receivers/:id/test` — queue an `alert.test` webhook.
async fn test_receiver(
    State(p): State<Arc<AlertingPlugin>>,
    Path(params): Path<HashMap<String, String>>,
    req: Request,
) -> Response {
    let id = match param(&params, "receiver") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let ns = match scope(&req) {
        Ok(ns) => ns,
        Err(r) => return r,
    };
    let by = actor(&req).unwrap_or_else(|| "operator".into());
    let Some(cfg) = p.install(&ns) else {
        return fail(StatusCode::NOT_FOUND, format!("no receiver {id:?} in namespace \"{ns}\""));
    };
    let Some(receiver) = cfg.receivers.iter().find(|r| r.id == id) else {
        return fail(StatusCode::NOT_FOUND, format!("no receiver {id:?} in namespace \"{ns}\""));
    };
    let now = now_secs();
    let payload = AlertPayload {
        fingerprint: "test".into(),
        rule: "test".into(),
        deployment: String::new(),
        severity: "info".into(),
        summary: format!("test notification for receiver {id}, sent by {by}"),
        started_at: Some(now),
        resolved_at: None,
        labels: [("namespace".to_string(), ns.clone())].into(),
    };
    let delivery_id = delivery::new_delivery_id();
    p.deliverer.enqueue(Job {
        namespace: ns.clone(),
        receiver: receiver.clone(),
        event: delivery::event_header("test"),
        fingerprint: None,
        body: delivery::body(receiver.format, &ns, "test", &payload, &delivery_id),
        delivery_id: delivery_id.clone(),
    });
    (
        StatusCode::ACCEPTED,
        json_ok(json!({"delivery_id": delivery_id, "receiver": id, "status": "queued"})),
    )
        .into_response()
}
