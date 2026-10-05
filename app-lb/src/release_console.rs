//! Control-panel transport only. CI owns policy, catalog and deployment state.
use super::*;

pub(super) async fn page(
    State(state): State<AdminState>,
    headers: axum::http::HeaderMap,
) -> Response {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Html(render_page(&state, include_str!("releases.html"), &headers)),
    )
        .into_response()
}

fn endpoint(
    base: &str,
    resource: &str,
    method: &axum::http::Method,
) -> Result<reqwest::Url, &'static str> {
    let allowed = match method.as_str() {
        "GET" => matches!(
            resource,
            "releases" | "release-builds" | "release-environments"
        ),
        "POST" => matches!(
            resource,
            "release-builds" | "release-promotions" | "release-automation"
        ),
        _ => false,
    };
    if !allowed {
        return Err("unsupported release operation");
    }
    let mut url = reqwest::Url::parse(base).map_err(|_| "invalid CI ingress URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("CI ingress must be an HTTPS origin without credentials, path or query");
    }
    url.set_path(resource);
    Ok(url)
}

pub(super) async fn api(
    axum::Extension(caller): axum::Extension<Caller>,
    Path(resource): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
    method: axum::http::Method,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !caller.covers_fleet() {
        return forbidden("fleet admin required");
    }
    let Some(credential) = fleet_credential(&caller, &headers) else {
        return forbidden(
            "Heyo sign-in required; local gateway credentials are not forwarded to CI",
        );
    };
    let base = match std::env::var("APP_LB_RELEASE_CI_URL") {
        Ok(value) => value,
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "release console is not configured: set APP_LB_RELEASE_CI_URL to the authenticated CI ingress").into_response(),
    };
    let mut url = match endpoint(&base, &resource, &method) {
        Ok(url) => url,
        Err(error) => return err(StatusCode::BAD_REQUEST, error).into_response(),
    };
    if resource == "releases" {
        if let Some(before) = query.get("before") {
            url.query_pairs_mut().append_pair("before", before);
        }
    }
    // No redirects or retry: never leak credentials or repeat a deployment.
    let result = async {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|_| "CI client unavailable")?;
        let mut response = client
            .request(method, url)
            .bearer_auth(credential)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| "CI request interrupted; refresh history before retrying")?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "CI response interrupted; refresh history before retrying")?
        {
            if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err("CI response exceeds console limit");
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| "CI ingress did not return JSON; check sign-in and CI admin access")?;
        Ok((status, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response())
    }
    .await;
    result.unwrap_or_else(|error| err(StatusCode::BAD_GATEWAY, error).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transport_is_origin_bound_and_operation_limited() {
        let get = axum::http::Method::GET;
        assert_eq!(
            endpoint("https://ci.example", "releases", &get)
                .unwrap()
                .as_str(),
            "https://ci.example/releases"
        );
        for base in [
            "http://ci.example",
            "https://user:pass@ci.example",
            "https://ci.example/api",
            "https://ci.example?x=1",
        ] {
            assert!(endpoint(base, "releases", &get).is_err());
        }
        assert!(endpoint("https://ci.example", "../secrets", &get).is_err());
        assert!(endpoint("https://ci.example", "release-promotions", &get).is_err());
        assert!(endpoint("https://ci.example", "releases", &axum::http::Method::POST).is_err());
    }

    #[tokio::test]
    async fn local_credentials_never_reach_release_transport() {
        for caller in [Caller::Ungated, Caller::Operator] {
            let response = api(
                axum::Extension(caller),
                Path("release-promotions".into()),
                Query(BTreeMap::new()),
                axum::http::Method::POST,
                axum::http::HeaderMap::new(),
                axum::body::Bytes::from_static(b"{}"),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }
}
