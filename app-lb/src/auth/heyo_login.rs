//! Optional browser sign-in against the existing Heyo Auth login API.
//! Passwords only cross the configured HTTPS connection. Identity and access
//! still come from the normal JWT verifier and deployment policy.
use super::*;

fn escape(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
        .replace('"', "&quot;").replace('\'', "&#39;")
}

impl Authenticator {
    pub(super) fn heyo_login_page(
        &self, gate: &AuthGate, deployment: &str, req: &RequestInfo<'_>, return_to: &str,
    ) -> Response {
        if !req.secure {
            return Response::text(403, "Browser sign-in requires HTTPS.\n");
        }
        // Keep the browser's CSRF nonce stable across tabs and reloads. A new
        // nonce on every page invalidates any form that is already open.
        let nonce = cookie_values(&req.cookies, FLOW_COOKIE).iter()
            .filter_map(|v| self.verify(v)).filter_map(|b| Flow::decode(&b))
            .find(|f| f.exp > now_secs() && f.deployment == deployment && f.verifier.is_empty())
            .map(|f| f.nonce).unwrap_or_else(random_token);
        let flow = Flow {
            nonce, verifier: String::new(),
            deployment: deployment.into(), return_to: safe_return_path(return_to),
            exp: now_secs() + FLOW_TTL.as_secs(),
        };
        let endpoint = gate.jwt_policy().and_then(|p| p.login_endpoint.as_deref()).unwrap_or("");
        let issuer = reqwest::Url::parse(endpoint).ok()
            .and_then(|u| u.host_str().map(str::to_owned)).unwrap_or_default();
        Response {
            status: 200, content_type: "text/html; charset=utf-8", location: None,
            cookies: vec![set_cookie(FLOW_COOKIE, &self.sign(&flow.encode()), true, Some(FLOW_TTL.as_secs()), None)],
            body: format!(r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in · Heyo</title>
<style>{css}
body {{ display:grid; min-height:100vh; place-items:center; margin:0; }}
main {{ width:min(26rem, calc(100% - 3rem)); }}
form {{ display:grid; gap:1rem; }} label {{ display:grid; gap:.4rem; }}
input,button {{ font:inherit; padding:.75rem; }} p {{ color:var(--text-muted); }}
</style></head><body><main><h1>Sign in to Heyo</h1>
<p>Use your existing account at {issuer}.</p>
<form method="post" action="{action}">
<input type="hidden" name="state" value="{nonce}">
<input type="hidden" name="return_to" value="{return_to}">
<label>Email<input name="email" type="email" autocomplete="username" required maxlength="320"></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required maxlength="4096"></label>
<button type="submit">Sign in</button></form>
<p>Your password is verified by Heyo Auth, not stored by this control panel.</p>
</main></body></html>"#,
                css = include_str!("../../../ui/heyo.css"), issuer = escape(&issuer),
                action = escape(&gate.login_path()), nonce = escape(&flow.nonce),
                return_to = escape(&flow.return_to)),
        }
    }

    pub(crate) async fn heyo_login_submit(
        &self, gate: &AuthGate, deployment: &str, req: &RequestInfo<'_>,
        request_origin: Option<&str>, body: &[u8],
    ) -> Response {
        let same_origin = request_origin.and_then(|value| reqwest::Url::parse(value).ok())
            .zip(reqwest::Url::parse(&origin(req)).ok())
            .is_some_and(|(actual, expected)| actual.origin() == expected.origin());
        if !req.secure || !same_origin {
            return Response::text(403, "Sign-in must originate on this HTTPS site.\n");
        }
        if body.len() > 8192 {
            return Response::text(413, "Sign-in request is too large.\n");
        }
        let Some(policy) = gate.jwt_policy() else { return Response::text(404, "Not found\n"); };
        let (Some(endpoint), Some(cookie)) = (&policy.login_endpoint, &policy.cookie) else {
            return Response::text(404, "Browser sign-in is not configured.\n");
        };
        let fields: Vec<_> = form_urlencoded::parse(body).collect();
        let field = |name: &str| fields.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_ref());
        let Some(state) = field("state") else { return Response::text(400, "Missing sign-in state.\n"); };
        let flow = cookie_values(&req.cookies, FLOW_COOKIE).iter()
            .filter_map(|v| self.verify(v)).filter_map(|b| Flow::decode(&b))
            .find(|f| f.exp > now_secs() && f.deployment == deployment && ct_eq(state.as_bytes(), f.nonce.as_bytes()));
        let Some(flow) = flow else { return Response::text(403, "Sign-in expired or state did not match. Reload and try again.\n"); };
        let (Some(email), Some(password)) = (field("email"), field("password")) else {
            return Response::text(400, "Email and password are required.\n");
        };
        if email.trim().is_empty() || email.len() > 320 || password.is_empty() || password.len() > 4096 {
            return Response::text(400, "Email or password is invalid.\n");
        }
        // Never follow a redirect with credentials, including a 307/308.
        let http = match reqwest::Client::builder().timeout(TOKEN_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none()).build() {
            Ok(http) => http,
            Err(_) => return Response::text(502, "Sign-in service unavailable.\n"),
        };
        let response = http.post(endpoint).json(&serde_json::json!({"email": email.trim(), "password": password})).send().await;
        let mut response = match response {
            Ok(response) if response.status().is_success() => response,
            Ok(response) if response.status().is_client_error() => return Response::text(401, "Sign-in was refused. Check your credentials or sign-in requirements and try again.\n"),
            _ => return Response::text(502, "Sign-in service unavailable.\n"),
        };
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if bytes.len() + chunk.len() <= 65536 => bytes.extend_from_slice(&chunk),
                Ok(None) => break,
                _ => return Response::text(502, "Invalid sign-in service response.\n"),
            }
        }
        let value: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => return Response::text(502, "Invalid sign-in service response.\n"),
        };
        let token = value.pointer("/data/tokens/accessToken").and_then(|v| v.as_str());
        let Some(token) = token.filter(|_| value.get("success").and_then(|v| v.as_bool()) == Some(true)) else {
            return Response::text(401, "Sign-in was refused.\n");
        };
        if token.len() > 3800 || self.verify_jwt(policy, token, req.host, None).await.is_err() {
            self.observe_auth(deployment, req, crate::siem::AuthAction::GateJwt, None);
            return Response::text(403, "This account is not permitted to access this application.\n");
        }
        let lifetime = value.pointer("/data/tokens/expiresIn").and_then(|v| v.as_u64()).unwrap_or(3600).min(86400);
        // The destination belongs to the submitted tab, not the last tab to
        // refresh the shared cookie. Restrict it to a local path as usual.
        Response::redirect(safe_return_path(field("return_to").unwrap_or(&flow.return_to)), vec![
            set_cookie(cookie, token, true, Some(lifetime), None),
            clear_cookie(FLOW_COOKIE, true, None),
        ])
    }
}
