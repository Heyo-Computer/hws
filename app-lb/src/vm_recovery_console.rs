//! Operator UI transport. Cloud owns recovery admission, fencing records and progress.
use super::*;
use serde_json::{Value, json};

pub(super) async fn page(
    State(state): State<AdminState>,
    axum::Extension(caller): axum::Extension<Caller>,
    headers: HeaderMap,
) -> Response {
    if !fleet_handoff_authorized(&caller) {
        return forbidden("authenticated fleet admin required");
    }
    (
        [(header::CACHE_CONTROL, "no-store")],
        Html(render_page(
            &state,
            include_str!("vm_recovery.html"),
            &headers,
        )),
    )
        .into_response()
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn endpoint(
    base: &str,
    vm: &str,
    resource: &str,
    operation: Option<&str>,
    method: &axum::http::Method,
) -> Result<reqwest::Url, &'static str> {
    if !identifier(vm) || operation.is_some_and(|v| !uuid(v)) {
        return Err("invalid Cloud VM or operation ID");
    }
    if !matches!(
        (method.as_str(), resource),
        ("GET", "checkpoints" | "destinations" | "recoveries" | "checkpoint-policy")
            | ("PUT", "checkpoint-policy") | ("POST", "recoveries")
    ) || operation.is_some() && (resource != "recoveries" || method != axum::http::Method::GET)
    {
        return Err("unsupported recovery operation");
    }
    let mut url = reqwest::Url::parse(base).map_err(|_| "invalid Cloud URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Cloud URL must use HTTPS without credentials, query or fragment");
    }
    let resource = if resource == "destinations" {
        "recovery-destinations"
    } else {
        resource
    };
    let mut path = url.path_segments_mut().map_err(|_| "invalid Cloud URL")?;
    path.pop_if_empty()
        .extend(["deployed-sandboxes", vm, resource]);
    if let Some(op) = operation {
        path.push(op);
    }
    drop(path);
    Ok(url)
}
fn validate_start(value: &Value) -> Result<(), &'static str> {
    let Some(object) = value.as_object() else {
        return Err("recovery request must be an object");
    };
    let fields = [
        "operation_id",
        "checkpoint_id",
        "destination_backend_id",
        "source_fenced",
        "fencing_evidence",
    ];
    if object.len() != fields.len() || object.keys().any(|k| !fields.contains(&k.as_str())) {
        return Err("unexpected or missing recovery request fields");
    }
    if !["operation_id", "checkpoint_id"]
        .iter()
        .all(|k| value[k].as_str().is_some_and(uuid))
    {
        return Err("operation_id and checkpoint_id must be UUIDs");
    }
    if !value["destination_backend_id"]
        .as_str()
        .is_some_and(identifier)
    {
        return Err("destination backend ID required");
    }
    if value["source_fenced"] != true
        || !value["fencing_evidence"]
            .as_str()
            .is_some_and(|v| !v.trim().is_empty())
    {
        return Err("confirm external source fencing and supply evidence; timeout is not proof");
    }
    Ok(())
}
fn operation_metadata(value: &Value) -> Value {
    let mut result = serde_json::Map::new();
    for key in [
        "operation_id",
        "sandbox_id",
        "source_backend_id",
        "runtime_id",
        "destination_backend_id",
        "phase",
        "error",
        "recovery_checkpoint_id",
        "source_fenced",
        "fencing_evidence",
        "created_at",
        "updated_at",
    ] {
        if let Some(v) = value.get(key) {
            result.insert(key.into(), v.clone());
        }
    }
    Value::Object(result)
}

pub(super) async fn api(
    axum::Extension(caller): axum::Extension<Caller>,
    Path((vm, resource)): Path<(String, String)>,
    method: axum::http::Method,
    body: axum::body::Bytes,
) -> Response {
    proxy(caller, vm, resource, None, method, body).await
}
pub(super) async fn status(
    axum::Extension(caller): axum::Extension<Caller>,
    Path((vm, operation)): Path<(String, String)>,
) -> Response {
    proxy(
        caller,
        vm,
        "recoveries".into(),
        Some(operation),
        axum::http::Method::GET,
        axum::body::Bytes::new(),
    )
    .await
}
async fn proxy(
    caller: Caller,
    vm: String,
    resource: String,
    operation: Option<String>,
    method: axum::http::Method,
    body: axum::body::Bytes,
) -> Response {
    if !fleet_handoff_authorized(&caller) {
        return forbidden("authenticated fleet admin required");
    }
    if method == axum::http::Method::PUT {
        let value = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
        if resource != "checkpoint-policy"
            || value.as_object().map(|v| v.len()) != Some(3)
            || !value["enabled"].is_boolean()
            || !value["interval_seconds"].as_u64().is_some_and(|v| (60..=86400).contains(&v))
            || !value["retain_count"].as_u64().is_some_and(|v| (1..=100).contains(&v))
        {
            return err(StatusCode::BAD_REQUEST, "Use enabled, interval_seconds (60–86400), and retain_count (1–100)").into_response();
        }
    }
    if method == axum::http::Method::POST {
        let value = match serde_json::from_slice::<Value>(&body) {
            Ok(v) => v,
            Err(_) => return err(StatusCode::BAD_REQUEST, "invalid recovery JSON").into_response(),
        };
        if let Err(message) = validate_start(&value) {
            return err(StatusCode::BAD_REQUEST, message).into_response();
        }
    }
    let (base, key) = match (std::env::var("APP_LB_RECOVERY_CLOUD_URL"), std::env::var("APP_LB_RECOVERY_CLOUD_API_KEY")) {
        (Ok(base), Ok(key)) if !key.trim().is_empty() => (base, key),
        _ => return err(StatusCode::SERVICE_UNAVAILABLE, "VM recovery is not configured: set APP_LB_RECOVERY_CLOUD_URL and server-side APP_LB_RECOVERY_CLOUD_API_KEY").into_response(),
    };
    let url = match endpoint(&base, &vm, &resource, operation.as_deref(), &method) {
        Ok(url) => url,
        Err(message) => return err(StatusCode::BAD_REQUEST, message).into_response(),
    };
    forward(url, &key, method, body, &resource).await
}

async fn forward(
    url: reqwest::Url,
    key: &str,
    method: axum::http::Method,
    body: axum::body::Bytes,
    resource: &str,
) -> Response {
    let result = async {
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(30)).build().map_err(|_| "Cloud client unavailable")?;
        let mut response = client.request(method, url).bearer_auth(key).header(header::CONTENT_TYPE,"application/json").body(body).send().await.map_err(|_| "Cloud request interrupted; check the operation ID before retrying the identical request")?;
        let status = response.status();
        if status.is_redirection() { return Err("Cloud redirected the request; check the configured URL"); }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "Cloud response interrupted; check the operation ID")? {
            if bytes.len() + chunk.len() > 2 * 1024 * 1024 { return Err("Cloud response too large"); }
            bytes.extend_from_slice(&chunk);
        }
        let mut value: Value = serde_json::from_slice(&bytes).map_err(|_| "Cloud did not return JSON; check the configured ingress and credentials")?;
        if !status.is_success() {
            // Do not forward arbitrary runtime payloads or configuration on errors.
            value = json!({"error":value.get("error").and_then(Value::as_str).unwrap_or("Cloud recovery request failed")});
        } else if resource == "recoveries" {
            value = match value.as_array() { Some(items) => Value::Array(items.iter().map(operation_metadata).collect()), None => operation_metadata(&value) };
        }
        Ok((status, value))
    }.await;
    match result {
        Ok((status, value)) => {
            (status, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
        }
        Err(message) => err(StatusCode::BAD_GATEWAY, message).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn policy_write_requires_admin_and_valid_bounds() {
        let body = json!({"enabled":true,"interval_seconds":120,"retain_count":2});
        let response = proxy(Caller::Ungated, "dep-test".into(), "checkpoint-policy".into(), None,
            axum::http::Method::PUT, serde_json::to_vec(&body).unwrap().into()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        for (field, invalid) in [("interval_seconds", json!(59)), ("interval_seconds", json!(86401)),
            ("retain_count", json!(0)), ("retain_count", json!(101)), ("enabled", json!("true")), ("extra", json!(1))] {
            let mut invalid_body = body.clone();
            invalid_body[field] = invalid;
            let response = proxy(Caller::Operator, "dep-test".into(), "checkpoint-policy".into(), None,
                axum::http::Method::PUT, serde_json::to_vec(&invalid_body).unwrap().into()).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
        }
        assert!(endpoint("https://example/cloud", "dep-test", "checkpoint-policy", None, &axum::http::Method::PUT).is_ok());
        assert!(endpoint("https://example/cloud", "dep-test", "recoveries", None, &axum::http::Method::PUT).is_err());
    }
    #[tokio::test]
    async fn recovery_requires_authenticated_fleet_admin_and_explicit_fencing() {
        let response = proxy(
            Caller::Ungated,
            "dep-test".into(),
            "recoveries".into(),
            None,
            axum::http::Method::POST,
            axum::body::Bytes::from_static(b"{}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let mut intent = json!({"operation_id":"12345678-0000-4000-8000-000000000000","checkpoint_id":"12345678-0000-4000-8000-000000000001","destination_backend_id":"host-2","source_fenced":false,"fencing_evidence":"power off receipt"});
        assert!(validate_start(&intent).is_err());
        intent["source_fenced"] = json!(true);
        assert!(validate_start(&intent).is_ok());
        intent["fencing_evidence"] = json!("  ");
        assert!(validate_start(&intent).is_err());
    }
    #[test]
    fn paths_are_fixed_and_cloud_prefix_is_preserved() {
        let get = axum::http::Method::GET;
        assert_eq!(
            endpoint(
                "https://stage.example/cloud/",
                "dep-a",
                "destinations",
                None,
                &get
            )
            .unwrap()
            .as_str(),
            "https://stage.example/cloud/deployed-sandboxes/dep-a/recovery-destinations"
        );
        for id in ["..", "a/b", "a?x", "%2e%2e"] {
            assert!(endpoint("https://example/cloud", id, "checkpoints", None, &get).is_err());
        }
        assert!(endpoint("https://example", "dep-a", "secrets", None, &get).is_err());
        assert!(endpoint("http://example", "dep-a", "checkpoints", None, &get).is_err());
    }
    #[tokio::test]
    async fn transport_uses_server_key_and_never_returns_restored_secrets() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router=Router::new().route("/recovery",get(|headers: HeaderMap| async move {
            assert_eq!(headers[header::AUTHORIZATION],"Bearer operator-test-key");
            Json(json!({"operation_id":"op-1","phase":"completed","restored":{"env_vars":{"PASSWORD":"do-not-return"}},"request":{"secret":"do-not-return"}}))
        }));
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let response = forward(
            format!("http://{addr}/recovery").parse().unwrap(),
            "operator-test-key",
            axum::http::Method::GET,
            axum::body::Bytes::new(),
            "recoveries",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"operation_id":"op-1","phase":"completed"})
        );
        server.abort();
    }
}
