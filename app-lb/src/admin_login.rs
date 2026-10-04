//! Browser sessions use the same Heyo scopes authority as API bearers.
use super::*;
use axum::http::{HeaderMap, Method};

const COOKIE: &str = "__Host-heyo-admin";

pub(super) fn same_origin(headers: &HeaderMap) -> bool {
    let expected = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|host| reqwest::Url::parse(&format!("https://{host}")).ok());
    let actual = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .and_then(|origin| reqwest::Url::parse(origin).ok());
    matches!((expected, actual), (Some(e), Some(a)) if a.scheme() == "https" && a.origin() == e.origin())
}

pub(super) fn session(headers: &HeaderMap, method: &Method) -> Result<Option<String>, ()> {
    // Explicit API credentials always take precedence over ambient cookies.
    if headers.contains_key(header::AUTHORIZATION) {
        return Ok(None);
    }
    let mut values = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|h| h.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .filter_map(|(name, value)| (name == COOKIE).then_some(value));
    let Some(token) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some()
        || token.is_empty()
        || token.len() > 3800
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(());
    }
    // SameSite is additional protection, not a substitute for a CSRF check.
    // WebSocket handshakes are GETs but can execute commands after upgrading.
    if (!matches!(*method, Method::GET | Method::HEAD) || headers.contains_key(header::UPGRADE))
        && !same_origin(headers)
    {
        return Err(());
    }
    Ok(Some(format!("Bearer {token}")))
}

pub(super) async fn page(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if !state.gate_admin || state.auth.is_none() || state.federated.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Html(render_page(
            &state,
            include_str!("admin_login.html"),
            &headers,
        )),
    )
        .into_response()
}

#[derive(Deserialize)]
pub(super) struct Credentials {
    email: String,
    password: String,
}

pub(super) async fn login(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(input): Json<Credentials>,
) -> Response {
    if !state.gate_admin || state.auth.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(auth) = &state.federated else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !same_origin(&headers) {
        return forbidden("sign-in requires this HTTPS origin");
    }
    if input.email.trim().is_empty()
        || input.email.len() > 320
        || input.password.is_empty()
        || input.password.len() > 4096
    {
        return err(StatusCode::BAD_REQUEST, "email and password are required").into_response();
    }
    let Some((token, lifetime)) = auth.login(input.email.trim(), &input.password).await else {
        return err(StatusCode::UNAUTHORIZED, "Sign-in refused or unavailable. Your Heyo account must reach the fleet or at least one namespace.").into_response();
    };
    ([(header::CACHE_CONTROL, "no-store".to_owned()),
        (header::SET_COOKIE, format!("{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={lifetime}"))],
        Json(serde_json::json!({"ok":true}))).into_response()
}

/// The form a Heyo front end posts, in a new tab, to open the dashboard for
/// one namespace: a bearer the auth service minted for it (a namespace-token,
/// confined to that namespace at the caller's own tier) and the namespace.
#[derive(Deserialize)]
pub(super) struct Handoff {
    token: String,
    namespace: String,
}

/// Whether a token is shaped like one the session cookie can carry — the same
/// alphabet and bound [`session`] enforces on the way back in.
fn cookie_safe(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 3800
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Whether `grant` may open the dashboard for `ns`: it reaches that namespace,
/// or it is not behind any wall.
fn grant_opens(grant: &crate::federated::Grant, ns: &str) -> bool {
    grant.fleet || grant.namespaces.contains_key(ns)
}

/// Seconds until the JWT's `exp`, read without verifying it — only to size the
/// cookie. The token is still resolved against the auth service on every
/// request, so a lie here buys nothing but a cookie that outlives its token.
fn remaining_lifetime(token: &str, now: u64) -> u64 {
    use base64::Engine as _;
    let exp = token
        .split('.')
        .nth(1)
        .and_then(|p| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(p)
                .ok()
        })
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("exp").and_then(|e| e.as_u64()));
    exp.map(|exp| exp.saturating_sub(now))
        .unwrap_or(3600)
        .clamp(60, 86400)
}

fn handoff_page(
    status: StatusCode,
    title: &str,
    body: &str,
    refresh: Option<&str>,
    home: Option<&str>,
) -> Response {
    let body = match home {
        Some(home) if refresh.is_none() => {
            format!(r#"{body} <a href="{}">Back to Heyo</a>"#, html_escape(home))
        }
        _ => body.to_string(),
    };
    let meta = refresh
        .map(|to| format!(r#"<meta http-equiv="refresh" content="0;url={to}">"#))
        .unwrap_or_default();
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">{meta}\
         <title>{title}</title><link rel=\"stylesheet\" href=\"/__ui/heyo.css\"></head>\
         <body><main><h1>{title}</h1><p>{body}</p></main></body></html>"
    );
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Html(html),
    )
        .into_response()
}

/// `POST /login/handoff` — the way a namespace user reaches this dashboard.
///
/// A Heyo front end (retail) cannot set this origin's cookie, and `/login`'s
/// password form signs a caller in to whatever their grant reaches — a fleet
/// admin to the fleet console, a namespace owner to the rollup of theirs —
/// but it cannot *aim* a session at one namespace. So the front end asks the
/// auth service for a token confined to that namespace, and posts it here
/// from a form in a new tab. The token is resolved like any bearer; if it
/// reaches the namespace it becomes the session cookie, and the answer is a
/// page that navigates to the dashboard *from this origin* — a redirect
/// straight off a cross-site POST would not carry a `SameSite=Strict` cookie.
///
/// This is the one cookie write that is cross-site on purpose, so it skips the
/// origin check. What a forged post can do is sign a victim into the forger's
/// own namespace view — the token names the namespace, and the page says which
/// one is open.
pub(super) async fn handoff(
    State(state): State<AdminState>,
    axum::Form(input): axum::Form<Handoff>,
) -> Response {
    if !state.gate_admin || state.auth.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(auth) = &state.federated else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let home = state.home_url.as_deref();
    let ns = input.namespace.trim();
    if !crate::config::is_valid_namespace(ns) || !cookie_safe(&input.token) {
        return handoff_page(
            StatusCode::BAD_REQUEST,
            "Cannot open dashboard",
            "The request was malformed. Open the dashboard again from Heyo.",
            None,
            home,
        );
    }
    let Some(grant) = auth.resolve(&input.token).await else {
        return handoff_page(
            StatusCode::UNAUTHORIZED,
            "Session expired",
            "Your Heyo session could not be verified. Open the dashboard again from Heyo.",
            None,
            home,
        );
    };
    if !grant_opens(&grant, ns) {
        return handoff_page(
            StatusCode::FORBIDDEN,
            "No access",
            "Your Heyo account cannot reach this namespace.",
            None,
            home,
        );
    }
    let lifetime = remaining_lifetime(&input.token, now_secs());
    // `is_valid_namespace` keeps the alphabet URL- and HTML-safe.
    let target = format!("/dashboard?namespace={ns}");
    let mut response = handoff_page(
        StatusCode::OK,
        "Opening dashboard",
        &format!(r#"Signed in to namespace <b>{ns}</b>. <a href="{target}">Continue</a>."#),
        Some(&target),
        None,
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "{COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={lifetime}",
            input.token
        )
        .parse()
        .expect("cookie-safe token is a valid header value"),
    );
    response
}

pub(super) async fn logout(headers: HeaderMap) -> Response {
    if !same_origin(&headers) {
        return forbidden("sign-out requires this HTTPS origin");
    }
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, "/login".to_owned()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
            (
                header::SET_COOKIE,
                format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"),
            ),
        ],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(origin: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "admin.eu1.example".parse().unwrap());
        h.insert(
            header::COOKIE,
            "__Host-heyo-admin=valid.jwt.signature".parse().unwrap(),
        );
        if let Some(origin) = origin {
            h.insert(header::ORIGIN, origin.parse().unwrap());
        }
        h
    }

    #[test]
    fn cookie_writes_and_websockets_require_exact_https_origin() {
        for origin in [
            None,
            Some("null"),
            Some("https://admin.us3.example"),
            Some("http://admin.eu1.example"),
            Some("https://admin.eu1.example:444"),
        ] {
            let mut h = headers(origin);
            assert!(session(&h, &Method::GET).unwrap().is_some());
            assert!(session(&h, &Method::POST).is_err());
            h.insert(header::UPGRADE, "websocket".parse().unwrap());
            assert!(session(&h, &Method::GET).is_err());
        }
        let h = headers(Some("https://admin.eu1.example"));
        assert_eq!(
            session(&h, &Method::PUT).unwrap().as_deref(),
            Some("Bearer valid.jwt.signature")
        );
    }

    fn grant(namespaces: &[&str], fleet: bool) -> crate::federated::Grant {
        crate::federated::Grant {
            subject: serde_json::from_value(serde_json::json!({"userId": "u1"})).unwrap(),
            namespaces: namespaces
                .iter()
                .map(|n| (n.to_string(), crate::tokens::AdminScope::View))
                .collect(),
            accounts: Default::default(),
            fleet,
        }
    }

    #[test]
    fn handoff_opens_only_the_namespaces_a_grant_reaches() {
        assert!(grant_opens(&grant(&["acme"], false), "acme"));
        assert!(!grant_opens(&grant(&["acme"], false), "other"));
        assert!(grant_opens(&grant(&[], true), "other"));
    }

    #[test]
    fn handoff_cookie_follows_the_token_expiry_within_bounds() {
        use base64::Engine as _;
        let jwt = |exp: u64| {
            format!(
                "h.{}.s",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(serde_json::json!({"exp": exp}).to_string())
            )
        };
        assert_eq!(remaining_lifetime(&jwt(1_000 + 1_800), 1_000), 1_800);
        assert_eq!(remaining_lifetime(&jwt(1_000 + 999_999), 1_000), 86_400);
        assert_eq!(remaining_lifetime(&jwt(10), 1_000), 60);
        assert_eq!(remaining_lifetime("not-a-jwt", 1_000), 3_600);
        assert!(cookie_safe("a.b-c_d"));
        assert!(!cookie_safe("a b") && !cookie_safe("") && !cookie_safe("a;b"));
    }

    #[test]
    fn api_credentials_win_and_ambiguous_cookies_fail_closed() {
        let mut h = headers(None);
        h.append(
            header::COOKIE,
            "__Host-heyo-admin=other.jwt.signature".parse().unwrap(),
        );
        assert!(session(&h, &Method::GET).is_err());
        h.insert(header::AUTHORIZATION, "Bearer explicit".parse().unwrap());
        assert!(session(&h, &Method::POST).unwrap().is_none());
    }
}
