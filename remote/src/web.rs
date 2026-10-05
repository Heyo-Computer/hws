//! The web UI: server-rendered pages for browsing and managing repos, in the
//! shape GitHub taught everybody — a dashboard of your repos, a namespace
//! page, and per repo a code tab, history, commits with diffs, branches,
//! tags and settings.
//!
//! ## Who sees what
//!
//! There is no second permission model here. A browser session is a bearer
//! in a cookie, and every page resolves it through the same
//! [`Authenticator`](crate::auth::Authenticator) the API and git use:
//!
//! - a Heyo sign-in (email and password, posted to the auth service exactly as
//!   app-lb's dashboard does) or a handoff from the Heyo front end yields a
//!   Heyo token, whose namespaces come from `/api/auth/scopes` — the grants
//!   app-lb itself enforces;
//! - a pasted `applb_` token is resolved by app-lb's own `GET /whoami`;
//! - a pasted `hrm_` token reaches its one namespace and its repos.
//!
//! So a person sees the namespaces app-lb would let them administer or view,
//! and nothing else. A repo they cannot read is a 404, never a 403: a page
//! does not confirm that a repo exists to someone who may not see it.
//!
//! app-lb's deployment gate is not used for this, on purpose. The gate
//! forwards a name and an email but no namespaces, and git clients reach the
//! same host and cannot pass a sign-in page.
//!
//! ## Cookies and forgery
//!
//! The session cookie is `HttpOnly`, `SameSite=Lax`, and `__Host-` prefixed
//! and `Secure` when `REMOTE_PUBLIC_URL` is https. Every state-changing form
//! post must come from this origin (`Origin`, else `Sec-Fetch-Site`), as
//! app-lb requires of its cookie-authenticated writes. The one exception is
//! [`handoff`], which is cross-site by design and can only sign a browser in.

// A handler's early exit is a whole rendered page; boxing it buys nothing.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use axum::Router;
use axum::extract::{Form, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use futures_util::StreamExt;
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::Deserialize;

use crate::api::{self, AppState, CreateRepo};
use crate::auth::{self, MintError, Principal, Tier};
use crate::browse::{self, CommitSummary, EntryKind, LineKind, RefKind, Resolved};
use crate::git::{ReadView, RepoRef};
use crate::heyo_ui;
use crate::registry::{self, RepoMeta, RepoState};
use crate::sigv4::now_unix;

/// How long a pasted token's session lasts, when the token does not say.
const SESSION_SECS: u64 = 12 * 3600;
const PAGE_SIZE: usize = 30;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(home))
        .route("/__ui/{*path}", get(ui_asset))
        .route("/-/login", get(login_page).post(login))
        .route("/-/handoff", post(handoff))
        .route("/-/logout", get(logout_page).post(logout))
        .route("/{ns}", get(namespace_page))
        .route("/{ns}/-/new", get(new_repo_page).post(new_repo))
        .route("/{ns}/-/tokens", get(tokens_page).post(mint_token))
        .route("/{ns}/-/tokens/{id}/revoke", post(revoke_token))
        .route("/{ns}/{repo}", get(repo_home))
        .route("/{ns}/{repo}/tree/{*rest}", get(tree_page))
        .route("/{ns}/{repo}/blob/{*rest}", get(blob_page))
        .route("/{ns}/{repo}/raw/{*rest}", get(raw))
        .route("/{ns}/{repo}/commits", get(commits_default))
        .route("/{ns}/{repo}/commits/{*rest}", get(commits_page))
        .route("/{ns}/{repo}/commit/{id}", get(commit_page))
        .route("/{ns}/{repo}/branches", get(branches_page))
        .route("/{ns}/{repo}/tags", get(tags_page))
        .route("/{ns}/{repo}/settings", get(settings_page))
        .route("/{ns}/{repo}/settings/delete", post(delete_repo))
        .layer(middleware::from_fn(page_headers))
}

/// Pages are per-person: never cached by anything in between, never framed.
async fn page_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("private, no-store"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    resp
}

async fn ui_asset(Path(path): Path<String>) -> Response {
    match heyo_ui::asset(&path) {
        Some(a) => (
            [
                (header::CONTENT_TYPE, a.content_type),
                (header::CACHE_CONTROL, heyo_ui::cache_control(&a)),
            ],
            a.bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

pub fn secure(s: &AppState) -> bool {
    s.cfg.public_url.starts_with("https://")
}

/// `__Host-` needs `Secure`, which a plain-http development instance cannot
/// set, so the name follows the scheme.
pub fn cookie_name(s: &AppState) -> &'static str {
    if secure(s) {
        "__Host-heyo-git"
    } else {
        "heyo_git"
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|h| h.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
        .filter(|v| auth::cookie_safe(v))
}

fn set_cookie(s: &AppState, token: &str, max_age: u64) -> String {
    format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        cookie_name(s),
        if secure(s) { "; Secure" } else { "" }
    )
}

fn clear_cookie(s: &AppState) -> String {
    set_cookie(s, "", 0).replacen("=;", "=deleted;", 1)
}

/// The caller: an explicit `Authorization` header first (so a script can read
/// a page with a token), else the session cookie.
async fn viewer(s: &AppState, headers: &HeaderMap) -> Option<Arc<Principal>> {
    let bearer = auth::bearer(headers).or_else(|| cookie_value(headers, cookie_name(s)))?;
    s.auth.authenticate(&bearer).await
}

/// Whether a form post came from this origin. A post carrying its own
/// `Authorization` header is not a browser's ambient credential, so it passes.
fn same_origin(s: &AppState, headers: &HeaderMap) -> bool {
    if headers.contains_key(header::AUTHORIZATION) {
        return true;
    }
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .and_then(|o| reqwest::Url::parse(o).ok());
    let Some(origin) = origin else {
        return headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("same-origin");
    };
    let public = reqwest::Url::parse(&s.cfg.public_url).ok();
    let scheme = public.as_ref().map_or("https", |u| u.scheme()).to_string();
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| reqwest::Url::parse(&format!("{scheme}://{h}")).ok());
    [public, host]
        .into_iter()
        .flatten()
        .any(|u| u.origin() == origin.origin())
}

/// What every page needs from the request: the theme and who is signed in.
struct Ctx {
    p: Option<Arc<Principal>>,
    attrs: String,
}

impl Ctx {
    async fn new(s: &AppState, headers: &HeaderMap) -> Self {
        let cookies = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
        Ctx {
            p: viewer(s, headers).await,
            attrs: s.ui.attrs(cookies),
        }
    }

    /// The signed-in principal, or a redirect to sign in that comes back here.
    fn signed_in(&self, here: &str) -> Result<Arc<Principal>, Response> {
        self.p.clone().ok_or_else(|| {
            Redirect::to(&format!("/-/login?next={}", enc_query(here))).into_response()
        })
    }
}

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

/// Only what this app adds to `ui/heyo.css`: GitHub's vocabulary. No palette:
/// every colour is a shared token, so both themes work.
const STYLE: &str = include_str!("web.css");

const ICON_REPO: &str = r#"<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M2 2.5A2.5 2.5 0 0 1 4.5 0h8.75a.75.75 0 0 1 .75.75v12.5a.75.75 0 0 1-.75.75h-2.5a.75.75 0 0 1 0-1.5h1.75v-2h-8a1 1 0 0 0-.71 1.71.75.75 0 0 1-1.07 1.05A2.5 2.5 0 0 1 2 11.5Zm10.5-1h-8a1 1 0 0 0-1 1v6.71A2.5 2.5 0 0 1 4.5 9h8ZM5 12.25a.25.25 0 0 1 .25-.25h3.5a.25.25 0 0 1 .25.25v3.25a.25.25 0 0 1-.4.2l-1.45-1.09a.25.25 0 0 0-.3 0L5.4 15.7a.25.25 0 0 1-.4-.2Z"/></svg>"#;
const ICON_DIR: &str = r#"<svg class="ico ico-dir" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M1.75 1A1.75 1.75 0 0 0 0 2.75v10.5C0 14.22.78 15 1.75 15h12.5A1.75 1.75 0 0 0 16 13.25v-8.5A1.75 1.75 0 0 0 14.25 3H7.5a.25.25 0 0 1-.2-.1l-.9-1.2C6.07 1.26 5.55 1 5 1H1.75Z"/></svg>"#;
const ICON_FILE: &str = r#"<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M2 1.75C2 .78 2.78 0 3.75 0h6.59c.46 0 .9.18 1.23.51l2.92 2.92c.33.33.51.77.51 1.23v9.59A1.75 1.75 0 0 1 13.25 16h-9.5A1.75 1.75 0 0 1 2 14.25Zm1.75-.25a.25.25 0 0 0-.25.25v12.5c0 .14.11.25.25.25h9.5a.25.25 0 0 0 .25-.25V6h-2.75A1.75 1.75 0 0 1 9 4.25V1.5Zm6.75.06V4.25c0 .14.11.25.25.25h2.69Z"/></svg>"#;
const ICON_BRANCH: &str = r#"<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M9.5 3.25a2.25 2.25 0 1 1 3 2.12V6A2.5 2.5 0 0 1 10 8.5H6a1 1 0 0 0-1 1v1.13a2.25 2.25 0 1 1-1.5 0V5.37a2.25 2.25 0 1 1 1.5 0v1.84A2.5 2.5 0 0 1 6 7h4a1 1 0 0 0 1-1v-.63a2.25 2.25 0 0 1-1.5-2.12ZM4.25 12a.75.75 0 1 0 0 1.5.75.75 0 0 0 0-1.5ZM3.5 3.25a.75.75 0 1 0 1.5 0 .75.75 0 0 0-1.5 0Zm8.25-.75a.75.75 0 1 0 0 1.5.75.75 0 0 0 0-1.5Z"/></svg>"#;
const ICON_COMMIT: &str = r#"<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M11.93 8.5a4 4 0 0 1-7.86 0H.75a.75.75 0 0 1 0-1.5h3.32a4 4 0 0 1 7.86 0h3.32a.75.75 0 0 1 0 1.5Zm-1.43-.75a2.5 2.5 0 1 0-5 0 2.5 2.5 0 0 0 5 0Z"/></svg>"#;
const ICON_TAG: &str = r#"<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M1 7.78V2.75C1 1.78 1.78 1 2.75 1h5.03c.46 0 .9.18 1.23.51l5.5 5.5a1.75 1.75 0 0 1 0 2.48l-5.03 5.03a1.75 1.75 0 0 1-2.48 0l-5.5-5.5A1.75 1.75 0 0 1 1 7.78Zm1.5-5.03v5.03c0 .07.03.13.07.18l5.5 5.5c.1.1.26.1.36 0l5.03-5.03a.25.25 0 0 0 0-.36l-5.5-5.5a.25.25 0 0 0-.18-.07H2.75a.25.25 0 0 0-.25.25ZM6 5a1 1 0 1 1-2 0 1 1 0 0 1 2 0Z"/></svg>"#;

fn shell(ctx: &Ctx, title: &str, current: &str, body: Markup) -> Markup {
    let nav: Vec<(&str, &str, bool)> = if ctx.p.is_some() {
        vec![
            ("Repositories", "/", current == "home"),
            ("Sign out", "/-/logout", false),
        ]
    } else {
        vec![("Sign in", "/-/login", current == "login")]
    };
    let who = ctx.p.as_ref().map(|p| p.display().to_string());
    html! {
        (DOCTYPE)
        // Injected whole: the theme attributes are a pre-rendered run of
        // attributes, not one value maud could quote.
        (PreEscaped(format!("<html lang=\"en\" {}>", ctx.attrs)))
        head {
            meta charset="utf-8";
            meta name="viewport" content="width=device-width, initial-scale=1";
            title { (title) " · heyo git" }
            (PreEscaped(heyo_ui::head_tags()))
            style { (PreEscaped(STYLE)) }
        }
        body {
            (PreEscaped(heyo_ui::topbar_html("git", &nav, who.as_deref())))
            main.wrap { (body) }
            script { (PreEscaped(COPY_JS)) }
        }
        (PreEscaped("</html>"))
    }
}

/// Copy buttons: `data-copy` names the text to copy. Progressive: without
/// script the URL is still a selectable input.
const COPY_JS: &str = r#"document.addEventListener('click',function(e){var b=e.target.closest('[data-copy]');if(!b)return;navigator.clipboard&&navigator.clipboard.writeText(b.getAttribute('data-copy')).then(function(){var t=b.textContent;b.textContent='copied';setTimeout(function(){b.textContent=t},1200)})});"#;

fn render(status: StatusCode, page: Markup) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        page.into_string(),
    )
        .into_response()
}

fn ok(page: Markup) -> Response {
    render(StatusCode::OK, page)
}

fn not_found(ctx: &Ctx) -> Response {
    render(
        StatusCode::NOT_FOUND,
        shell(
            ctx,
            "Not found",
            "",
            html! {
                div.empty {
                    h1 { "404" }
                    p { "There is nothing here, or this sign-in cannot see it." }
                    p { a href="/" { "Back to your repositories" } }
                }
            },
        ),
    )
}

fn failure(ctx: &Ctx, status: StatusCode, msg: &str) -> Response {
    render(
        status,
        shell(
            ctx,
            "Error",
            "",
            html! { div.banner.banner-error { (msg) } },
        ),
    )
}

fn forbidden_origin(ctx: &Ctx) -> Response {
    failure(
        ctx,
        StatusCode::FORBIDDEN,
        "This form must be submitted from this site. Reload the page and try again.",
    )
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Percent-encode a path, keeping `/`, for a ref or a file in a URL.
fn enc_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn enc_query(s: &str) -> String {
    enc_path(s).replace('/', "%2F")
}

fn ago(t: i64) -> String {
    let d = now_unix() as i64 - t;
    let (n, unit) = match d {
        i64::MIN..=44 => return "just now".into(),
        45..=5399 => ((d + 30) / 60, "minute"),
        5400..=129_599 => ((d + 1800) / 3600, "hour"),
        129_600..=2_591_999 => ((d + 43_200) / 86_400, "day"),
        2_592_000..=31_535_999 => ((d + 1_296_000) / 2_592_000, "month"),
        _ => (d / 31_536_000, "year"),
    };
    let n = n.max(1);
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

/// (year, month, day) of a unix time, UTC. Howard Hinnant's civil_from_days.
fn ymd(t: i64) -> (i64, u32, u32) {
    let z = t.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn date(t: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (y, m, d) = ymd(t);
    format!("{} {d}, {y}", MONTHS[(m - 1) as usize])
}

fn bytes(n: u64) -> String {
    match n {
        0..1024 => format!("{n} B"),
        1024..1_048_576 => format!("{:.1} KB", n as f64 / 1024.0),
        _ => format!("{:.1} MB", n as f64 / 1_048_576.0),
    }
}

fn plural(n: usize, what: &str) -> String {
    format!("{n} {what}{}", if n == 1 { "" } else { "s" })
}

fn initials(name: &str) -> String {
    name.split(|c: char| c.is_whitespace() || c == '.' || c == '-' || c == '@')
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase()
}

fn avatar(name: &str) -> Markup {
    html! { span.avatar title=(name) { (initials(name)) } }
}

/// Markdown to HTML, with raw HTML shown as text (a README is pushed by
/// anyone with write access, and this page carries a session), only
/// http(s)/mailto/relative links, and relative links resolved into the repo
/// as GitHub does.
fn markdown(src: &str, base: &LinkBase) -> String {
    use pulldown_cmark::{Event, Options, Parser, Tag};
    let opts = Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_FOOTNOTES;
    let events = Parser::new_ext(src, opts).map(|ev| match ev {
        Event::Html(h) | Event::InlineHtml(h) => Event::Text(h),
        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Link {
            link_type,
            dest_url: base.resolve(&dest_url, false).into(),
            title,
            id,
        }),
        Event::Start(Tag::Image {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Image {
            link_type,
            dest_url: base.resolve(&dest_url, true).into(),
            title,
            id,
        }),
        e => e,
    });
    let mut out = String::new();
    pulldown_cmark::html::push_html(&mut out, events);
    out
}

/// Where a README's relative links point: the directory it is in, at the ref
/// it was read from.
struct LinkBase {
    repo: String,
    rev: String,
    dir: String,
}

impl LinkBase {
    fn resolve(&self, url: &str, image: bool) -> String {
        let lower = url.to_ascii_lowercase();
        if lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("mailto:")
            || url.starts_with('#')
        {
            return url.to_string();
        }
        // Any other scheme (javascript:, data:, …) goes nowhere.
        let first = url.split(['/', '?', '#']).next().unwrap_or("");
        if first.contains(':') || url.starts_with("//") {
            return "#".into();
        }
        let (path, frag) = match url.find(['#', '?']) {
            Some(i) => (&url[..i], &url[i..]),
            None => (url, ""),
        };
        let mut parts: Vec<&str> = if path.starts_with('/') {
            vec![]
        } else {
            self.dir.split('/').filter(|s| !s.is_empty()).collect()
        };
        for seg in path.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                s => parts.push(s),
            }
        }
        format!(
            "{}/{}/{}/{}{frag}",
            self.repo,
            if image { "raw" } else { "blob" },
            enc_path(&self.rev),
            parts.join("/")
        )
    }
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct NextQuery {
    #[serde(default)]
    next: Option<String>,
}

/// A local path to return to, never another site.
fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.contains('\\') => n.into(),
        _ => "/".into(),
    }
}

fn login_form(s: &AppState, ctx: &Ctx, next: &str, error: Option<&str>) -> Markup {
    shell(
        ctx,
        "Sign in",
        "login",
        html! {
            div.narrow {
                h1 { "Sign in to heyo git" }
                p.meta {
                    "You see the namespaces your Heyo account or token can reach on app-lb, "
                    "and nothing else."
                }
                @if let Some(e) = error { div.banner.banner-error { (e) } }
                @if s.auth.can_login() {
                    form.card method="post" action="/-/login" {
                        input type="hidden" name="next" value=(next);
                        div.field { label for="email" { "Email" } input id="email" type="email" name="email" autocomplete="username" required; }
                        div.field { label for="password" { "Password" } input id="password" type="password" name="password" autocomplete="current-password" required; }
                        button.btn.btn-primary type="submit" { "Sign in" }
                    }
                    p.or { "or" }
                }
                form.card method="post" action="/-/login" {
                    input type="hidden" name="next" value=(next);
                    div.field {
                        label for="token" { "Token" }
                        input id="token" type="password" name="token" placeholder="applb_…, hrm_… or a Heyo API key" autocomplete="off" required;
                    }
                    button.btn type="submit" { "Sign in with a token" }
                }
            }
        },
    )
}

async fn login_page(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<NextQuery>,
) -> Response {
    let ctx = Ctx::new(&s, &headers).await;
    let next = safe_next(q.next.as_deref());
    if ctx.p.is_some() {
        return Redirect::to(&next).into_response();
    }
    ok(login_form(&s, &ctx, &next, None))
}

#[derive(Deserialize)]
struct LoginForm {
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    next: Option<String>,
}

async fn login(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<LoginForm>,
) -> Response {
    let ctx = Ctx {
        p: None,
        attrs: s
            .ui
            .attrs(headers.get(header::COOKIE).and_then(|v| v.to_str().ok())),
    };
    let next = safe_next(f.next.as_deref());
    // Login forgery would sign a victim into someone else's namespaces.
    if !same_origin(&s, &headers) {
        return forbidden_origin(&ctx);
    }
    let refuse = |msg: &str| {
        render(
            StatusCode::UNAUTHORIZED,
            login_form(&s, &ctx, &next, Some(msg)),
        )
    };
    let (token, lifetime) = if !f.token.trim().is_empty() {
        let t = f.token.trim().to_string();
        if !auth::cookie_safe(&t) {
            return refuse("That is not a token.");
        }
        let life =
            auth::jwt_remaining(&t, now_unix()).map_or(SESSION_SECS, |r| r.min(SESSION_SECS));
        (t, life)
    } else {
        if f.email.trim().is_empty()
            || f.email.len() > 320
            || f.password.is_empty()
            || f.password.len() > 4096
        {
            return refuse("Email and password are required.");
        }
        match s.auth.login(f.email.trim(), &f.password).await {
            Some(x) => x,
            None => return refuse("Sign-in refused, or the Heyo auth service is unreachable."),
        }
    };
    if s.auth.authenticate(&token).await.is_none() {
        return refuse("That credential was refused: unknown, expired or revoked.");
    }
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, set_cookie(&s, &token, lifetime)),
            (header::LOCATION, next),
        ],
    )
        .into_response()
}

#[derive(Deserialize)]
struct HandoffForm {
    token: String,
    #[serde(default)]
    namespace: Option<String>,
}

/// The form a Heyo front end posts to open one namespace here, as app-lb's
/// `/login/handoff`. Cross-site on purpose, so it skips the origin check: the
/// worst a forged post can do is sign a browser into the forger's own
/// namespace, which the page then names.
async fn handoff(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<HandoffForm>,
) -> Response {
    let ctx = Ctx::new(&s, &headers).await;
    let token = f.token.trim();
    let ns = f
        .namespace
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty());
    if !auth::cookie_safe(token) || ns.is_some_and(|n| !registry::valid_namespace(n)) {
        return failure(
            &ctx,
            StatusCode::BAD_REQUEST,
            "Malformed request. Open this page again from Heyo.",
        );
    }
    let Some(p) = s.auth.authenticate(token).await else {
        return failure(
            &ctx,
            StatusCode::UNAUTHORIZED,
            "Your Heyo session could not be verified. Open this page again from Heyo.",
        );
    };
    if let Some(ns) = ns
        && p.tier_in(ns).is_none()
    {
        return failure(
            &ctx,
            StatusCode::FORBIDDEN,
            "Your Heyo account cannot reach this namespace.",
        );
    }
    let lifetime =
        auth::jwt_remaining(token, now_unix()).map_or(SESSION_SECS, |r| r.min(SESSION_SECS));
    let target = ns.map_or("/".to_string(), |n| format!("/{n}"));
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, set_cookie(&s, token, lifetime)),
            (header::LOCATION, target),
        ],
    )
        .into_response()
}

async fn logout_page(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let ctx = Ctx::new(&s, &headers).await;
    ok(shell(
        &ctx,
        "Sign out",
        "",
        html! {
            div.narrow {
                h1 { "Sign out" }
                form.card method="post" action="/-/logout" {
                    p { "Sign out of heyo git on this browser?" }
                    button.btn.btn-primary type="submit" { "Sign out" }
                }
            }
        },
    ))
}

async fn logout(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if !same_origin(&s, &headers) {
        let ctx = Ctx::new(&s, &headers).await;
        return forbidden_origin(&ctx);
    }
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, clear_cookie(&s)),
            (header::LOCATION, "/-/login".to_string()),
        ],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Dashboard and namespaces
// ---------------------------------------------------------------------------

/// Every namespace this caller reaches: its grants, plus every bound
/// namespace for a fleet-wide caller.
async fn visible_namespaces(s: &AppState, p: &Principal) -> Vec<String> {
    let mut set: BTreeSet<String> = p.namespaces.keys().cloned().collect();
    if p.fleet.is_some()
        && let Ok(all) = s.registry.namespaces().await
    {
        set.extend(all);
    }
    set.into_iter().collect()
}

struct Listed {
    meta: RepoMeta,
    state: Option<RepoState>,
}

/// The repos in `ns` this caller may read, with their state, newest first.
async fn readable_repos(s: &AppState, p: &Principal, ns: &str) -> Vec<Listed> {
    let Ok(Some(b)) = s.registry.binding(ns).await else {
        return vec![];
    };
    let metas = s.registry.list_repos(&b, ns).await.unwrap_or_default();
    let bucket = b.bucket.clone();
    let mut out: Vec<Listed> = futures_util::stream::iter(
        metas
            .into_iter()
            .filter(|m| p.allows(ns, Some(&m.name), Tier::Read)),
    )
    .map(|meta| {
        let bucket = bucket.clone();
        async move {
            let state = s
                .registry
                .state(&bucket, ns, &meta.name)
                .await
                .ok()
                .map(|(st, _)| st);
            Listed { meta, state }
        }
    })
    .buffer_unordered(16)
    .collect()
    .await;
    out.sort_by_key(|l| {
        std::cmp::Reverse(
            l.state
                .as_ref()
                .map_or(l.meta.created_at, |st| st.updated_at.max(l.meta.created_at)),
        )
    });
    out
}

fn repo_list(items: &[Listed], show_ns: bool) -> Markup {
    html! {
        ul.repo-list {
            @for l in items {
                @let m = &l.meta;
                li {
                    div.row.spread {
                        div.grow {
                            (PreEscaped(ICON_REPO)) " "
                            a.repo-name href=(format!("/{}/{}", m.namespace, m.name)) {
                                @if show_ns { span.meta { (m.namespace) " / " } }
                                strong { (m.name) }
                            }
                            @if l.state.as_ref().is_some_and(|st| st.refs.is_empty()) {
                                " " span.pill.pill-muted { "empty" }
                            }
                        }
                    }
                    @if let Some(d) = &m.description { p.desc { (d) } }
                    div.meta {
                        (PreEscaped(ICON_BRANCH)) " " (m.default_branch)
                        @if let Some(st) = &l.state && st.updated_at > 0 {
                            " · Updated " (ago(st.updated_at as i64))
                        } @else {
                            " · Created " (ago(m.created_at as i64))
                        }
                    }
                }
            }
        }
    }
}

async fn home(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let ctx = Ctx::new(&s, &headers).await;
    let p = match ctx.signed_in("/") {
        Ok(p) => p,
        Err(r) => return r,
    };
    let namespaces = visible_namespaces(&s, &p).await;
    let mut all: Vec<Listed> = Vec::new();
    for ns in &namespaces {
        all.extend(readable_repos(&s, &p, ns).await);
    }
    all.sort_by_key(|l| {
        std::cmp::Reverse(
            l.state
                .as_ref()
                .map_or(l.meta.created_at, |st| st.updated_at.max(l.meta.created_at)),
        )
    });
    ok(shell(
        &ctx,
        "Repositories",
        "home",
        html! {
            div.layout {
                aside.sidebar {
                    div.who { (avatar(p.display())) div { strong { (p.display()) } div.meta { (kind_label(&p)) } } }
                    h3 { "Namespaces" }
                    @if namespaces.is_empty() {
                        p.meta { "This sign-in reaches no namespace." }
                    }
                    ul.side-list {
                        @for ns in &namespaces {
                            li.row.spread {
                                a href=(format!("/{ns}")) { (ns) }
                                span.pill.pill-muted { (p.tier_in(ns).map_or("—", Tier::as_str)) }
                            }
                        }
                    }
                }
                section.grow {
                    div.row.spread.section-head {
                        h2 { "Repositories" }
                        @if let Some(ns) = namespaces.iter().find(|ns| p.allows(ns, None, Tier::Admin)) {
                            a.btn.btn-primary href=(format!("/{ns}/-/new")) { "New" }
                        }
                    }
                    @if all.is_empty() {
                        div.empty {
                            p { "No repositories yet." }
                            p { "Create one here, or with the MCP server's " code { "repo_create" } "." }
                        }
                    } @else {
                        (repo_list(&all, true))
                    }
                }
            }
        },
    ))
}

fn kind_label(p: &Principal) -> &'static str {
    match p.kind {
        auth::Kind::Operator => "operator",
        auth::Kind::Federated => "Heyo account",
        auth::Kind::AppToken => "app-lb token",
        auth::Kind::RepoToken => "repo token",
    }
}

/// Tabs on a namespace page.
fn ns_header(ns: &str, p: &Principal, tab: &str) -> Markup {
    let admin = p.allows(ns, None, Tier::Admin);
    html! {
        div.repo-head {
            h1.repo-title { a href=(format!("/{ns}")) { (ns) } }
            nav.tabs {
                a href=(format!("/{ns}")) aria-current=[(tab == "repos").then_some("page")] { (PreEscaped(ICON_REPO)) " Repositories" }
                @if admin {
                    a href=(format!("/{ns}/-/tokens")) aria-current=[(tab == "tokens").then_some("page")] { "Tokens" }
                }
            }
        }
    }
}

async fn namespace_page(
    State(s): State<AppState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
) -> Response {
    let ctx = Ctx::new(&s, &headers).await;
    let p = match ctx.signed_in(&format!("/{ns}")) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if !registry::valid_namespace(&ns) || p.tier_in(&ns).is_none() {
        return not_found(&ctx);
    }
    let repos = readable_repos(&s, &p, &ns).await;
    let admin = p.allows(&ns, None, Tier::Admin);
    ok(shell(
        &ctx,
        &ns,
        "",
        html! {
            (ns_header(&ns, &p, "repos"))
            div.row.spread.section-head {
                span.meta { (repos.len()) " repositories · you have " (p.tier_in(&ns).map_or("no", Tier::as_str)) " access" }
                @if admin { a.btn.btn-primary href=(format!("/{ns}/-/new")) { "New repository" } }
            }
            @if repos.is_empty() {
                div.empty { p { "No repositories in " (ns) " yet." } }
            } @else {
                (repo_list(&repos, false))
            }
        },
    ))
}

fn new_repo_form(
    ctx: &Ctx,
    p: &Principal,
    ns: &str,
    f: &NewRepoForm,
    error: Option<&str>,
) -> Markup {
    shell(
        ctx,
        "New repository",
        "",
        html! {
            (ns_header(ns, p, ""))
            div.narrow {
                h2 { "Create a new repository" }
                @if let Some(e) = error { div.banner.banner-error { (e) } }
                form.card method="post" action=(format!("/{ns}/-/new")) {
                    div.field {
                        label for="name" { "Repository name" }
                        div.row.row-tight { span.meta { (ns) " /" } input id="name".grow type="text" name="name" value=(f.name) required pattern="[A-Za-z0-9_][A-Za-z0-9._\\-]{0,99}" autofocus; }
                    }
                    div.field { label for="description" { "Description (optional)" } input id="description" type="text" name="description" value=(f.description); }
                    div.field { label for="default_branch" { "Default branch" } input id="default_branch" type="text" name="default_branch" value=(if f.default_branch.is_empty() { registry::DEFAULT_BRANCH } else { &f.default_branch }); }
                    button.btn.btn-primary type="submit" { "Create repository" }
                }
            }
        },
    )
}

#[derive(Deserialize, Default)]
struct NewRepoForm {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    default_branch: String,
}

async fn new_repo_page(
    State(s): State<AppState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
) -> Response {
    let ctx = Ctx::new(&s, &headers).await;
    let p = match ctx.signed_in(&format!("/{ns}/-/new")) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if !registry::valid_namespace(&ns) || !p.allows(&ns, None, Tier::Admin) {
        return not_found(&ctx);
    }
    ok(new_repo_form(&ctx, &p, &ns, &NewRepoForm::default(), None))
}

async fn new_repo(
    State(s): State<AppState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
    Form(f): Form<NewRepoForm>,
) -> Response {
    let ctx = Ctx::new(&s, &headers).await;
    let p = match ctx.signed_in(&format!("/{ns}/-/new")) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if !same_origin(&s, &headers) {
        return forbidden_origin(&ctx);
    }
    if !registry::valid_namespace(&ns) || !p.allows(&ns, None, Tier::Admin) {
        return not_found(&ctx);
    }
    let body = CreateRepo {
        name: f.name.trim().to_string(),
        description: Some(f.description.trim().to_string()),
        default_branch: Some(f.default_branch.trim().to_string()),
    };
    match api::new_repo(&s, &p, &ns, body).await {
        Ok(m) => Redirect::to(&format!("/{ns}/{}", m.name)).into_response(),
        Err(e) => render(
            e.status(),
            new_repo_form(&ctx, &p, &ns, &f, Some(&e.message())),
        ),
    }
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct MintForm {
    #[serde(default)]
    name: String,
    #[serde(default)]
    access: String,
    #[serde(default)]
    repos: String,
    #[serde(default)]
    ttl_days: String,
}

async fn tokens_view(
    s: &AppState,
    ctx: &Ctx,
    p: &Principal,
    ns: &str,
    minted: Option<(&str, &str)>,
    error: Option<&str>,
) -> Markup {
    let tokens = s.auth.tokens(ns).await.unwrap_or_default();
    let max_days = s.cfg.max_token_ttl_secs / 86_400;
    shell(
        ctx,
        &format!("{ns} tokens"),
        "",
        html! {
            (ns_header(ns, p, "tokens"))
            @if let Some((name, tok)) = minted {
                div.banner.banner-ok {
                    p { "Token " strong { (name) } " minted. Copy it now: it is not shown again." }
                    div.clone-box { input.grow type="text" readonly value=(tok); button.btn.btn-sm type="button" data-copy=(tok) { "copy" } }
                    p.meta { "git sends it as the password of Basic auth, with any username. For an app-lb build: " code { "build.auth" } " with username " code { "x-access-token" } "." }
                }
            }
            @if let Some(e) = error { div.banner.banner-error { (e) } }
            div.card {
                div.card-head { h3 { "Repo tokens" } span.meta { "read or write, for git and app-lb builds" } }
                @if tokens.is_empty() {
                    p.meta { "No tokens in " (ns) "." }
                } @else {
                    div.scroll { table {
                        thead { tr { th { "Name" } th { "Access" } th { "Repos" } th { "Created" } th { "Expires" } th {} } }
                        tbody {
                            @for t in &tokens {
                                tr {
                                    td { strong { (t.name) } div.meta { (t.created_by.as_deref().unwrap_or("")) } }
                                    td { span.pill.pill-accent[t.access == Tier::Write] { (t.access.as_str()) } }
                                    td { @if t.repos.is_empty() { span.meta { "all" } } @else { (t.repos.join(", ")) } }
                                    td.meta { (ago(t.created_at as i64)) }
                                    td.meta {
                                        @match t.expires_at {
                                            None => "never",
                                            Some(e) if e <= now_unix() => span.pill.pill-fail { "expired" },
                                            Some(e) => (date(e as i64)),
                                        }
                                    }
                                    td.num {
                                        form method="post" action=(format!("/{ns}/-/tokens/{}/revoke", t.id)) {
                                            button.btn.btn-sm.btn-danger type="submit" { "Revoke" }
                                        }
                                    }
                                }
                            }
                        }
                    } }
                }
            }
            form.card method="post" action=(format!("/{ns}/-/tokens")) {
                div.card-head { h3 { "Mint a token" } }
                div.grid {
                    div.field { label for="tname" { "Name" } input id="tname" type="text" name="name" placeholder="ci-build"; }
                    div.field { label for="access" { "Access" } select id="access" name="access" { option value="read" { "read" } option value="write" { "write" } } }
                    div.field { label for="repos" { "Repos (comma-separated, empty = all)" } input id="repos" type="text" name="repos"; }
                    div.field { label for="ttl" { "Expires in days (0 = never, max " (max_days) ")" } input id="ttl" type="number" name="ttl_days" min="0" max=(max_days) value=(max_days.min(30)); }
                }
                button.btn.btn-primary type="submit" { "Mint token" }
            }
        },
    )
}

async fn tokens_page(
    State(s): State<AppState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
) -> Response {
    let ctx = Ctx::new(&s, &headers).await;
    let p = match ctx.signed_in(&format!("/{ns}/-/tokens")) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if !registry::valid_namespace(&ns) || !p.allows(&ns, None, Tier::Admin) {
        return not_found(&ctx);
    }
    ok(tokens_view(&s, &ctx, &p, &ns, None, None).await)
}

async fn mint_token(
    State(s): State<AppState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
    Form(f): Form<MintForm>,
) -> Response {
    let ctx = Ctx::new(&s, &headers).await;
    let p = match ctx.signed_in(&format!("/{ns}/-/tokens")) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if !same_origin(&s, &headers) {
        return forbidden_origin(&ctx);
    }
    if !registry::valid_namespace(&ns) || !p.allows(&ns, None, Tier::Admin) {
        return not_found(&ctx);
    }
    let access = if f.access == "write" {
        Tier::Write
    } else {
        Tier::Read
    };
    let repos: Vec<String> = f
        .repos
        .split(',')
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(String::from)
        .collect();
    if let Some(bad) = repos.iter().find(|r| !registry::valid_repo_name(r)) {
        let msg = format!("invalid repo name {bad:?}");
        return render(
            StatusCode::BAD_REQUEST,
            tokens_view(&s, &ctx, &p, &ns, None, Some(&msg)).await,
        );
    }
    let ttl = f
        .ttl_days
        .trim()
        .parse::<u64>()
        .ok()
        .map(|d| d.saturating_mul(86_400));
    match s
        .auth
        .mint(
            &p,
            &ns,
            f.name.trim(),
            repos,
            access,
            ttl,
            s.cfg.max_token_ttl_secs,
        )
        .await
    {
        Ok((token, rec)) => {
            ok(tokens_view(&s, &ctx, &p, &ns, Some((&rec.name, &token)), None).await)
        }
        Err(e) => {
            let (status, msg) = match e {
                MintError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
                MintError::Invalid(m) => (StatusCode::BAD_REQUEST, m),
                MintError::Store(e) => (StatusCode::BAD_GATEWAY, e.to_string()),
            };
            render(
                status,
                tokens_view(&s, &ctx, &p, &ns, None, Some(&msg)).await,
            )
        }
    }
}

async fn revoke_token(
    State(s): State<AppState>,
    Path((ns, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let ctx = Ctx::new(&s, &headers).await;
    let p = match ctx.signed_in(&format!("/{ns}/-/tokens")) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if !same_origin(&s, &headers) {
        return forbidden_origin(&ctx);
    }
    // The token's own namespace decides, not the URL's.
    match s.auth.token(&id).await {
        Ok(Some(rec)) if rec.namespace == ns && p.allows(&ns, None, Tier::Admin) => {
            if let Err(e) = s.auth.revoke(&id).await {
                return failure(&ctx, StatusCode::BAD_GATEWAY, &e.to_string());
            }
            Redirect::to(&format!("/{ns}/-/tokens")).into_response()
        }
        _ => not_found(&ctx),
    }
}

// ---------------------------------------------------------------------------
// Repos
// ---------------------------------------------------------------------------

/// A repo the caller may read, located and hydrated.
struct RepoCtx {
    ctx: Ctx,
    p: Arc<Principal>,
    meta: RepoMeta,
    r: RepoRef,
    view: ReadView,
    clone_url: String,
}

impl RepoCtx {
    fn base(&self) -> String {
        format!("/{}/{}", self.r.ns, self.r.name)
    }

    fn admin(&self) -> bool {
        self.p.allows(&self.r.ns, None, Tier::Admin)
    }
}

/// Everything a repo page starts with. A repo the caller cannot read is a 404,
/// whether or not it exists.
async fn open_repo(
    s: &AppState,
    headers: &HeaderMap,
    ns: &str,
    repo: &str,
    here: &str,
) -> Result<RepoCtx, Response> {
    let ctx = Ctx::new(s, headers).await;
    let p = ctx.signed_in(here)?;
    if api::check_names(ns, Some(repo)).is_err() || !p.allows(ns, Some(repo), Tier::Read) {
        return Err(not_found(&ctx));
    }
    let (b, meta) = match api::existing(s, ns, repo).await {
        Ok(x) => x,
        Err(e) if e.status() == StatusCode::NOT_FOUND => return Err(not_found(&ctx)),
        Err(e) => return Err(failure(&ctx, e.status(), &e.message())),
    };
    let r = RepoRef {
        bucket: b.bucket,
        ns: ns.to_string(),
        name: repo.to_string(),
    };
    let view = match s.git.read(&r).await {
        Ok(v) => v,
        Err(e) => return Err(failure(&ctx, e.status, &e.message)),
    };
    Ok(RepoCtx {
        clone_url: api::clone_url(s, ns, repo),
        ctx,
        p,
        meta,
        r,
        view,
    })
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Code,
    Commits,
    Branches,
    Tags,
    Settings,
}

fn repo_header(rc: &RepoCtx, tab: Tab) -> Markup {
    let base = rc.base();
    let cur = |t: Tab| (t == tab).then_some("page");
    let nbranches = browse::branches(&rc.view).len();
    let ntags = browse::tags(&rc.view).len();
    html! {
        div.repo-head {
            h1.repo-title {
                (PreEscaped(ICON_REPO)) " "
                a href=(format!("/{}", rc.r.ns)) { (rc.r.ns) }
                span.sep { " / " }
                a href=(base) { strong { (rc.r.name) } }
                " " span.pill.pill-muted { (rc.p.tier_in(&rc.r.ns).map_or("read", Tier::as_str)) }
            }
            @if let Some(d) = &rc.meta.description { p.desc { (d) } }
            nav.tabs {
                a href=(base) aria-current=[cur(Tab::Code)] { (PreEscaped(ICON_FILE)) " Code" }
                a href=(format!("{base}/commits")) aria-current=[cur(Tab::Commits)] { (PreEscaped(ICON_COMMIT)) " Commits" }
                a href=(format!("{base}/branches")) aria-current=[cur(Tab::Branches)] { (PreEscaped(ICON_BRANCH)) " Branches " span.count { (nbranches) } }
                a href=(format!("{base}/tags")) aria-current=[cur(Tab::Tags)] { (PreEscaped(ICON_TAG)) " Tags " span.count { (ntags) } }
                @if rc.admin() {
                    a href=(format!("{base}/settings")) aria-current=[cur(Tab::Settings)] { "Settings" }
                }
            }
        }
    }
}

fn clone_box(url: &str) -> Markup {
    html! {
        details.dropdown.clone-dd {
            summary.btn.btn-primary { "Code ▾" }
            div.dropdown-menu {
                label { "Clone over HTTPS" }
                div.clone-box { input.grow type="text" readonly value=(url); button.btn.btn-sm type="button" data-copy=(url) { "copy" } }
                p.meta { "Username: anything. Password: a repo token, app-lb token or Heyo API key." }
            }
        }
    }
}

/// The branch/tag picker. `kind` and `path` say where each choice leads.
fn ref_picker(rc: &RepoCtx, current: &str, kind: &str, path: &str) -> Markup {
    let base = rc.base();
    let target = |name: &str| {
        let mut u = format!("{base}/{kind}/{}", enc_path(name));
        if !path.is_empty() {
            u.push('/');
            u.push_str(&enc_path(path));
        }
        u
    };
    let branches = browse::branches(&rc.view);
    let tags = browse::tags(&rc.view);
    html! {
        details.dropdown {
            summary.btn { (PreEscaped(ICON_BRANCH)) " " (short_ref(current)) " ▾" }
            div.dropdown-menu {
                label { "Branches" }
                @for b in &branches {
                    a.dd-item href=(target(b)) aria-current=[(b == current).then_some("true")] {
                        (b) @if b == &rc.meta.default_branch { " " span.pill.pill-muted { "default" } }
                    }
                }
                @if !tags.is_empty() {
                    label { "Tags" }
                    @for t in &tags { a.dd-item href=(target(t)) aria-current=[(t == current).then_some("true")] { (t) } }
                }
            }
        }
    }
}

fn short_ref(name: &str) -> &str {
    if name.len() == 40 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
        &name[..7]
    } else {
        name
    }
}

/// `repo / dir / file` with every segment a link to its tree.
fn breadcrumb(rc: &RepoCtx, rev: &str, path: &str) -> Markup {
    let base = rc.base();
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    html! {
        nav.crumbs {
            a href=(format!("{base}/tree/{}", enc_path(rev))) { strong { (rc.r.name) } }
            @for (i, seg) in segs.iter().enumerate() {
                span.sep { " / " }
                @if i + 1 == segs.len() {
                    strong { (seg) }
                } @else {
                    a href=(format!("{base}/tree/{}/{}", enc_path(rev), enc_path(&segs[..=i].join("/")))) { (seg) }
                }
            }
        }
    }
}

fn commit_bar(rc: &RepoCtx, c: &CommitSummary, count: Option<u64>, history: &str) -> Markup {
    let base = rc.base();
    html! {
        div.commit-bar {
            (avatar(&c.author))
            strong { (c.author) }
            a.subject href=(format!("{base}/commit/{}", c.id)) { (c.subject) }
            span.grow {}
            a.mono.meta href=(format!("{base}/commit/{}", c.id)) { (c.short()) }
            span.meta { " · " (ago(c.time)) }
            @if let Some(n) = count {
                a.history href=(history) { (PreEscaped(ICON_COMMIT)) " " strong { (n) } " commits" }
            }
        }
    }
}

fn empty_repo(rc: &RepoCtx) -> Markup {
    let url = &rc.clone_url;
    let branch = &rc.meta.default_branch;
    let api = format!(
        "curl -X POST {}/api/repos/{}/{}/commits \\\n  -H 'Authorization: Bearer <write token>' \\\n  -H 'Content-Type: application/json' \\\n  -d '{{\"message\": \"First commit\", \"files\": [{{\"path\": \"README.md\", \"content\": \"# {}\\n\"}}]}}'",
        url.trim_end_matches(&format!("/{}/{}.git", rc.r.ns, rc.r.name)),
        rc.r.ns,
        rc.r.name,
        rc.r.name
    );
    html! {
        div.card.quick {
            div.card-head { h3 { "Quick setup" } }
            div.clone-box { input.grow type="text" readonly value=(url); button.btn.btn-sm type="button" data-copy=(url) { "copy" } }
            h4 { "Push an existing repository from the command line" }
            pre { "git remote add heyo " (url) "\ngit push heyo HEAD:" (branch) }
            p.meta { "git asks for a password: give it a write token (mint one under the namespace's Tokens tab), an app-lb token or a Heyo API key. Any username." }
            h4 { "…or commit without git" }
            pre { (api) }
            p.meta { "Agents can do the same with the MCP server's " code { "repo_write_files" } "." }
        }
    }
}

async fn repo_home(
    State(s): State<AppState>,
    Path((ns, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Some(bare) = repo.strip_suffix(".git") {
        return Redirect::permanent(&format!("/{ns}/{bare}")).into_response();
    }
    let rc = match open_repo(&s, &headers, &ns, &repo, &format!("/{ns}/{repo}")).await {
        Ok(rc) => rc,
        Err(r) => return r,
    };
    let Some(branch) =
        browse::head_branch(&rc.view).or_else(|| browse::branches(&rc.view).into_iter().next())
    else {
        return ok(shell(
            &rc.ctx,
            &format!("{ns}/{repo}"),
            "",
            html! { (repo_header(&rc, Tab::Code)) (empty_repo(&rc)) },
        ));
    };
    let Some(res) = browse::resolve(&s.git, &rc.view, &branch).await else {
        return not_found(&rc.ctx);
    };
    tree_view(&s, rc, res).await
}

async fn tree_page(
    State(s): State<AppState>,
    Path((ns, repo, rest)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let here = format!("/{ns}/{repo}/tree/{}", enc_path(&rest));
    let rc = match open_repo(&s, &headers, &ns, &repo, &here).await {
        Ok(rc) => rc,
        Err(r) => return r,
    };
    let Some(res) = browse::resolve(&s.git, &rc.view, &rest).await else {
        return not_found(&rc.ctx);
    };
    match browse::kind_at(&s.git, &rc.view, &res.commit, &res.path).await {
        Some(EntryKind::Tree) => tree_view(&s, rc, res).await,
        Some(_) => Redirect::to(&format!("/{ns}/{repo}/blob/{}", enc_path(&rest))).into_response(),
        None => not_found(&rc.ctx),
    }
}

async fn tree_view(s: &AppState, rc: RepoCtx, res: Resolved) -> Response {
    let base = rc.base();
    let entries = match browse::tree(&s.git, &rc.view, &res.commit, &res.path).await {
        Ok(e) => e,
        Err(_) => return not_found(&rc.ctx),
    };
    let latest = browse::log(&s.git, &rc.view, &res.commit, Some(&res.path), 0, 1)
        .await
        .ok()
        .and_then(|l| l.into_iter().next());
    let count = if res.path.is_empty() {
        browse::count(&s.git, &rc.view, &res.commit).await
    } else {
        None
    };
    let last = browse::last_commits(&s.git, &rc.view, &res.commit, &res.path, &entries).await;
    let readme_html = match browse::readme(&entries) {
        Some(e) => {
            let path = join(&res.path, &e.name);
            match browse::blob(&s.git, &rc.view, &res.commit, &path, browse::MAX_INLINE).await {
                Ok(b) => b.bytes.map(|bytes| {
                    let text = String::from_utf8_lossy(&bytes);
                    let body = if browse::is_markdown(&e.name) {
                        PreEscaped(markdown(
                            &text,
                            &LinkBase {
                                repo: base.clone(),
                                rev: res.name.clone(),
                                dir: res.path.clone(),
                            },
                        ))
                    } else {
                        PreEscaped(html! { pre.plain { (text) } }.into_string())
                    };
                    (e.name.clone(), path, body)
                }),
                Err(_) => None,
            }
        }
        None => None,
    };
    let rev = enc_path(&res.name);
    let link = |e: &browse::Entry| -> String {
        let kind = if e.kind == EntryKind::Tree {
            "tree"
        } else {
            "blob"
        };
        format!(
            "{base}/{kind}/{rev}/{}",
            enc_path(&join(&res.path, &e.name))
        )
    };
    let history = format!("{base}/commits/{rev}");
    let title = if res.path.is_empty() {
        format!("{}/{}", rc.r.ns, rc.r.name)
    } else {
        format!("{} at {} · {}/{}", res.path, res.name, rc.r.ns, rc.r.name)
    };
    let page = html! {
        (repo_header(&rc, Tab::Code))
        div.row.spread.toolbar {
            div.row.row-tight {
                (ref_picker(&rc, &res.name, "tree", &res.path))
                @if res.path.is_empty() {
                    span.meta { (PreEscaped(ICON_BRANCH)) " " (browse::branches(&rc.view).len()) " branches · " (PreEscaped(ICON_TAG)) " " (browse::tags(&rc.view).len()) " tags" }
                } @else {
                    (breadcrumb(&rc, &res.name, &res.path))
                }
            }
            (clone_box(&rc.clone_url))
        }
        div.files {
            @if let Some(c) = &latest { (commit_bar(&rc, c, count, &history)) }
            table.file-table {
                tbody {
                    @if !res.path.is_empty() {
                        @let parent = res.path.rsplit_once('/').map_or("", |(p, _)| p);
                        tr { td colspan="3" { a href=(if parent.is_empty() { format!("{base}/tree/{rev}") } else { format!("{base}/tree/{rev}/{}", enc_path(parent)) }) { ".." } } }
                    }
                    @for e in &entries {
                        tr {
                            td.name {
                                @match e.kind {
                                    EntryKind::Tree => { (PreEscaped(ICON_DIR)) " " a href=(link(e)) { (e.name) } }
                                    EntryKind::Blob => { (PreEscaped(ICON_FILE)) " " a href=(link(e)) { (e.name) } }
                                    EntryKind::Commit => { (PreEscaped(ICON_COMMIT)) " " span { (e.name) } " " span.pill.pill-muted { "submodule" } }
                                }
                            }
                            td.msg {
                                @if let Some(c) = last.get(&e.name) {
                                    a.meta href=(format!("{base}/commit/{}", c.id)) { (c.subject) }
                                }
                            }
                            td.num.meta { @if let Some(c) = last.get(&e.name) { (ago(c.time)) } }
                        }
                    }
                }
            }
        }
        @if let Some((name, path, body)) = readme_html {
            div.card.readme {
                div.card-head { h3 { (PreEscaped(ICON_FILE)) " " (name) } a.meta href=(format!("{base}/blob/{rev}/{}", enc_path(&path))) { "view" } }
                div.markdown { (body) }
            }
        }
    };
    ok(shell(&rc.ctx, &title, "", page))
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

#[derive(Deserialize, Default)]
struct BlobQuery {
    #[serde(default)]
    plain: Option<String>,
}

async fn blob_page(
    State(s): State<AppState>,
    Path((ns, repo, rest)): Path<(String, String, String)>,
    Query(q): Query<BlobQuery>,
    headers: HeaderMap,
) -> Response {
    let here = format!("/{ns}/{repo}/blob/{}", enc_path(&rest));
    let rc = match open_repo(&s, &headers, &ns, &repo, &here).await {
        Ok(rc) => rc,
        Err(r) => return r,
    };
    let Some(res) = browse::resolve(&s.git, &rc.view, &rest).await else {
        return not_found(&rc.ctx);
    };
    match browse::kind_at(&s.git, &rc.view, &res.commit, &res.path).await {
        Some(EntryKind::Blob) => {}
        Some(EntryKind::Tree) => {
            return Redirect::to(&format!("/{ns}/{repo}/tree/{}", enc_path(&rest))).into_response();
        }
        _ => return not_found(&rc.ctx),
    }
    let blob =
        match browse::blob(&s.git, &rc.view, &res.commit, &res.path, browse::MAX_INLINE).await {
            Ok(b) => b,
            Err(e) => return failure(&rc.ctx, e.status, &e.message),
        };
    let base = rc.base();
    let rev = enc_path(&res.name);
    let raw_url = format!("{base}/raw/{rev}/{}", enc_path(&res.path));
    let history = format!("{base}/commits/{rev}/{}", enc_path(&res.path));
    let latest = browse::log(&s.git, &rc.view, &res.commit, Some(&res.path), 0, 1)
        .await
        .ok()
        .and_then(|l| l.into_iter().next());
    let is_md = browse::is_markdown(&res.path);
    let rendered = is_md && q.plain.as_deref() != Some("1");
    let name = res.path.rsplit('/').next().unwrap_or(&res.path).to_string();
    let dir = res.path.rsplit_once('/').map_or("", |(d, _)| d).to_string();

    let content = match &blob.bytes {
        None => {
            html! { div.empty { p { "This file is " (bytes(blob.size)) ", too big to show." } a.btn href=(raw_url) { "View raw" } } }
        }
        Some(_) if browse::image_type(&res.path).is_some() => {
            html! { div.image-view { img src=(raw_url) alt=(name); } }
        }
        Some(b) if browse::is_binary(b) => {
            html! { div.empty { p { "Binary file not shown." } a.btn href=(raw_url) { "Download" } } }
        }
        Some(b) => {
            let text = String::from_utf8_lossy(b);
            if rendered {
                html! { div.markdown.blob-md { (PreEscaped(markdown(&text, &LinkBase { repo: base.clone(), rev: res.name.clone(), dir: dir.clone() }))) } }
            } else {
                html! {
                    div.scroll { table.code {
                        tbody {
                            @for (i, line) in text.lines().enumerate() {
                                tr id=(format!("L{}", i + 1)) {
                                    td.ln { a href=(format!("#L{}", i + 1)) { (i + 1) } }
                                    td.lc { (line) }
                                }
                            }
                        }
                    } }
                }
            }
        }
    };
    let nlines = blob
        .bytes
        .as_ref()
        .filter(|b| !browse::is_binary(b))
        .map(|b| String::from_utf8_lossy(b).lines().count());
    let page = html! {
        (repo_header(&rc, Tab::Code))
        div.row.row-tight.toolbar {
            (ref_picker(&rc, &res.name, "blob", &res.path))
            (breadcrumb(&rc, &res.name, &res.path))
        }
        div.files {
            @if let Some(c) = &latest { (commit_bar(&rc, c, None, &history)) }
            div.file-head.row.spread {
                span.meta {
                    @if let Some(n) = nlines { (n) " lines · " }
                    (bytes(blob.size))
                }
                div.row.row-tight {
                    @if is_md {
                        a.btn.btn-sm aria-current=[rendered.then_some("true")] href=(format!("{base}/blob/{rev}/{}", enc_path(&res.path))) { "Preview" }
                        a.btn.btn-sm aria-current=[(!rendered).then_some("true")] href=(format!("{base}/blob/{rev}/{}?plain=1", enc_path(&res.path))) { "Code" }
                    }
                    a.btn.btn-sm href=(raw_url) { "Raw" }
                    a.btn.btn-sm href=(history) { "History" }
                }
            }
            (content)
        }
    };
    ok(shell(
        &rc.ctx,
        &format!("{} at {} · {}/{}", res.path, res.name, ns, repo),
        "",
        page,
    ))
}

async fn raw(
    State(s): State<AppState>,
    Path((ns, repo, rest)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let here = format!("/{ns}/{repo}/raw/{}", enc_path(&rest));
    let rc = match open_repo(&s, &headers, &ns, &repo, &here).await {
        Ok(rc) => rc,
        Err(r) => return r,
    };
    let Some(res) = browse::resolve(&s.git, &rc.view, &rest).await else {
        return not_found(&rc.ctx);
    };
    if browse::kind_at(&s.git, &rc.view, &res.commit, &res.path).await != Some(EntryKind::Blob) {
        return not_found(&rc.ctx);
    }
    let blob = match browse::blob(&s.git, &rc.view, &res.commit, &res.path, browse::MAX_RAW).await {
        Ok(b) => b,
        Err(e) => return failure(&rc.ctx, e.status, &e.message),
    };
    let Some(bytes) = blob.bytes else {
        return failure(
            &rc.ctx,
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!(
                "This file is {}; clone the repo to get it.",
                bytes(blob.size)
            ),
        );
    };
    // Raster images as themselves; everything else as inert text, in a
    // sandbox, so a pushed HTML or SVG file cannot run as this origin.
    let ctype = browse::image_type(&res.path).unwrap_or("text/plain; charset=utf-8");
    (
        [
            (header::CONTENT_TYPE, ctype),
            (
                header::CONTENT_SECURITY_POLICY,
                "sandbox; default-src 'none'; img-src 'self'",
            ),
        ],
        bytes,
    )
        .into_response()
}

#[derive(Deserialize, Default)]
struct PageQuery {
    #[serde(default)]
    page: Option<usize>,
}

async fn commits_default(
    State(s): State<AppState>,
    Path((ns, repo)): Path<(String, String)>,
    Query(q): Query<PageQuery>,
    headers: HeaderMap,
) -> Response {
    let rc = match open_repo(&s, &headers, &ns, &repo, &format!("/{ns}/{repo}/commits")).await {
        Ok(rc) => rc,
        Err(r) => return r,
    };
    let Some(branch) =
        browse::head_branch(&rc.view).or_else(|| browse::branches(&rc.view).into_iter().next())
    else {
        return ok(shell(
            &rc.ctx,
            &format!("Commits · {ns}/{repo}"),
            "",
            html! { (repo_header(&rc, Tab::Commits)) div.empty { p { "No commits yet." } } },
        ));
    };
    let Some(res) = browse::resolve(&s.git, &rc.view, &branch).await else {
        return not_found(&rc.ctx);
    };
    commits_view(&s, rc, res, q.page.unwrap_or(1)).await
}

async fn commits_page(
    State(s): State<AppState>,
    Path((ns, repo, rest)): Path<(String, String, String)>,
    Query(q): Query<PageQuery>,
    headers: HeaderMap,
) -> Response {
    let here = format!("/{ns}/{repo}/commits/{}", enc_path(&rest));
    let rc = match open_repo(&s, &headers, &ns, &repo, &here).await {
        Ok(rc) => rc,
        Err(r) => return r,
    };
    let Some(res) = browse::resolve(&s.git, &rc.view, &rest).await else {
        return not_found(&rc.ctx);
    };
    commits_view(&s, rc, res, q.page.unwrap_or(1)).await
}

async fn commits_view(s: &AppState, rc: RepoCtx, res: Resolved, page: usize) -> Response {
    let page = page.max(1);
    let path = (!res.path.is_empty()).then_some(res.path.as_str());
    // One extra to learn whether there is an older page.
    let mut list = match browse::log(
        &s.git,
        &rc.view,
        &res.commit,
        path,
        (page - 1) * PAGE_SIZE,
        PAGE_SIZE + 1,
    )
    .await
    {
        Ok(l) => l,
        Err(e) => return failure(&rc.ctx, e.status, &e.message),
    };
    let more = list.len() > PAGE_SIZE;
    list.truncate(PAGE_SIZE);
    let base = rc.base();
    let here = {
        let mut u = format!("{base}/commits/{}", enc_path(&res.name));
        if let Some(p) = path {
            u.push('/');
            u.push_str(&enc_path(p));
        }
        u
    };
    let mut groups: Vec<(String, Vec<&CommitSummary>)> = Vec::new();
    for c in &list {
        let d = date(c.time);
        match groups.last_mut() {
            Some((g, v)) if *g == d => v.push(c),
            _ => groups.push((d, vec![c])),
        }
    }
    let html = html! {
        (repo_header(&rc, Tab::Commits))
        div.row.row-tight.toolbar {
            (ref_picker(&rc, &res.name, "commits", &res.path))
            @if let Some(p) = path { span.meta { "History for " } (breadcrumb(&rc, &res.name, p)) }
        }
        @if list.is_empty() { div.empty { p { "No commits." } } }
        @for (day, commits) in &groups {
            div.timeline {
                h4.day { (PreEscaped(ICON_COMMIT)) " Commits on " (day) }
                ul.commit-list {
                    @for c in commits {
                        li.row.spread {
                            div.grow {
                                a.subject href=(format!("{base}/commit/{}", c.id)) { strong { (c.subject) } }
                                div.meta { (avatar(&c.author)) " " (c.author) " committed " (ago(c.time)) }
                            }
                            div.row.row-tight {
                                a.btn.btn-sm.mono href=(format!("{base}/commit/{}", c.id)) { (c.short()) }
                                button.btn.btn-sm type="button" data-copy=(c.id) title="Copy the full SHA" { "copy" }
                                a.btn.btn-sm href=(format!("{base}/tree/{}", c.id)) title="Browse the repository at this point" { "<>" }
                            }
                        }
                    }
                }
            }
        }
        div.row.pager {
            @if page > 1 { a.btn href=(format!("{here}?page={}", page - 1)) { "Newer" } } @else { span.btn.disabled { "Newer" } }
            @if more { a.btn href=(format!("{here}?page={}", page + 1)) { "Older" } } @else { span.btn.disabled { "Older" } }
        }
    };
    ok(shell(
        &rc.ctx,
        &format!("Commits · {}/{}", rc.r.ns, rc.r.name),
        "",
        html,
    ))
}

async fn commit_page(
    State(s): State<AppState>,
    Path((ns, repo, id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let here = format!("/{ns}/{repo}/commit/{id}");
    let rc = match open_repo(&s, &headers, &ns, &repo, &here).await {
        Ok(rc) => rc,
        Err(r) => return r,
    };
    let Some(c) = browse::commit(&s.git, &rc.view, &id).await else {
        return not_found(&rc.ctx);
    };
    let diff = match browse::diff(&s.git, &rc.view, &c.summary.id).await {
        Ok(d) => d,
        Err(e) => return failure(&rc.ctx, e.status, &e.message),
    };
    let base = rc.base();
    let (adds, dels) = diff
        .files
        .iter()
        .fold((0, 0), |(a, d), f| (a + f.additions, d + f.deletions));
    let page = html! {
        (repo_header(&rc, Tab::Commits))
        div.card.commit-head {
            div.row.spread {
                h2.commit-subject { (c.summary.subject) }
                a.btn.btn-sm href=(format!("{base}/tree/{}", c.summary.id)) { "Browse files" }
            }
            @if !c.body.is_empty() { pre.commit-body { (c.body) } }
            div.row.meta {
                (avatar(&c.summary.author))
                strong { (c.summary.author) }
                span { "committed " (ago(c.summary.time)) " · " (date(c.summary.time)) }
                @if c.committer != c.summary.author { span { "· committed by " (c.committer) } }
                span.grow {}
                @if !c.parents.is_empty() {
                    span { (if c.parents.len() == 1 { "parent " } else { "parents " })
                        @for (i, p) in c.parents.iter().enumerate() {
                            @if i > 0 { " + " }
                            a.mono href=(format!("{base}/commit/{p}")) { (&p[..7.min(p.len())]) }
                        }
                    }
                }
                span { "commit " code { (c.summary.id) } }
            }
        }
        p.meta {
            "Showing " strong { (plural(diff.files.len(), "changed file")) } " with "
            span.add { (plural(adds, "addition")) } " and " span.del { (plural(dels, "deletion")) } "."
            @if diff.truncated { " " span.pill.pill-warn { "diff truncated" } }
        }
        @for f in &diff.files {
            div.diff-file {
                div.diff-head.row {
                    span.pill.(format!("st-{}", f.status())) { (f.status()) }
                    @if f.status() == "renamed" {
                        span.mono { (f.old_path.as_deref().unwrap_or("")) " → " (f.path()) }
                    } @else {
                        span.mono { (f.path()) }
                    }
                    span.grow {}
                    span.add { "+" (f.additions) } span.del { "−" (f.deletions) }
                    @if f.new_path.is_some() {
                        a.btn.btn-sm href=(format!("{base}/blob/{}/{}", c.summary.id, enc_path(f.path()))) { "View file" }
                    }
                }
                @if f.binary {
                    p.meta.diff-note { "Binary file not shown." }
                } @else if f.lines.is_empty() {
                    p.meta.diff-note { "No content changes." }
                } @else {
                    div.scroll { table.code.diff { tbody {
                        @for (k, l) in &f.lines {
                            @match k {
                                LineKind::Hunk => tr.hunk { td.lc colspan="2" { (l) } },
                                LineKind::Add => tr.ins { td.sign { "+" } td.lc { (l) } },
                                LineKind::Del => tr.rem { td.sign { "−" } td.lc { (l) } },
                                LineKind::Context => tr { td.sign { " " } td.lc { (l) } },
                            }
                        }
                    } } }
                }
            }
        }
    };
    ok(shell(
        &rc.ctx,
        &format!("{} · {}/{}", c.summary.subject, ns, repo),
        "",
        page,
    ))
}

/// The tip commit of each ref, for the branches and tags pages.
async fn tips(s: &AppState, rc: &RepoCtx, names: &[String]) -> HashMap<String, CommitSummary> {
    futures_util::stream::iter(names.iter().take(200).cloned())
        .map(|n| async move {
            let res = browse::resolve(&s.git, &rc.view, &n).await?;
            let c = browse::log(&s.git, &rc.view, &res.commit, None, 0, 1)
                .await
                .ok()?
                .into_iter()
                .next()?;
            Some((n, c))
        })
        .buffer_unordered(8)
        .filter_map(|x| async move { x })
        .collect()
        .await
}

fn refs_table(
    rc: &RepoCtx,
    names: &[String],
    tips: &HashMap<String, CommitSummary>,
    kind: RefKind,
) -> Markup {
    let base = rc.base();
    let mut sorted: Vec<&String> = names.iter().collect();
    sorted.sort_by_key(|n| std::cmp::Reverse(tips.get(*n).map_or(0, |c| c.time)));
    html! {
        div.card.flush {
            @if sorted.is_empty() { div.empty { p { @if kind == RefKind::Tag { "No tags yet. " code { "git tag v1.0 && git push heyo v1.0" } } @else { "No branches yet." } } } }
            ul.ref-list {
                @for n in sorted {
                    li.row.spread {
                        div.grow {
                            a href=(format!("{base}/tree/{}", enc_path(n))) { strong.mono { (n) } }
                            @if kind == RefKind::Branch && *n == rc.meta.default_branch { " " span.pill.pill-accent { "default" } }
                            @if let Some(c) = tips.get(n) {
                                div.meta { "Updated " (ago(c.time)) " by " (c.author) " · " a href=(format!("{base}/commit/{}", c.id)) { (c.subject) } }
                            }
                        }
                        a.btn.btn-sm href=(format!("{base}/commits/{}", enc_path(n))) { "History" }
                    }
                }
            }
        }
    }
}

async fn branches_page(
    State(s): State<AppState>,
    Path((ns, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let rc = match open_repo(&s, &headers, &ns, &repo, &format!("/{ns}/{repo}/branches")).await {
        Ok(rc) => rc,
        Err(r) => return r,
    };
    let names = browse::branches(&rc.view);
    let tips = tips(&s, &rc, &names).await;
    let page = html! { (repo_header(&rc, Tab::Branches)) (refs_table(&rc, &names, &tips, RefKind::Branch)) };
    ok(shell(&rc.ctx, &format!("Branches · {ns}/{repo}"), "", page))
}

async fn tags_page(
    State(s): State<AppState>,
    Path((ns, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let rc = match open_repo(&s, &headers, &ns, &repo, &format!("/{ns}/{repo}/tags")).await {
        Ok(rc) => rc,
        Err(r) => return r,
    };
    let names = browse::tags(&rc.view);
    let tips = tips(&s, &rc, &names).await;
    let page =
        html! { (repo_header(&rc, Tab::Tags)) (refs_table(&rc, &names, &tips, RefKind::Tag)) };
    ok(shell(&rc.ctx, &format!("Tags · {ns}/{repo}"), "", page))
}

fn settings_view(rc: &RepoCtx, error: Option<&str>) -> Markup {
    let base = rc.base();
    let full = format!("{}/{}", rc.r.ns, rc.r.name);
    html! {
        (repo_header(rc, Tab::Settings))
        div.narrow.wide {
            div.card {
                div.card-head { h3 { "General" } }
                table { tbody {
                    tr { td { "Name" } td.mono { (full) } }
                    tr { td { "Default branch" } td.mono { (rc.meta.default_branch) } }
                    tr { td { "Clone URL" } td.mono { (rc.clone_url) } }
                    tr { td { "Created" } td { (date(rc.meta.created_at as i64)) @if let Some(by) = &rc.meta.created_by { " by " (by) } } }
                    tr { td { "State version" } td.mono { (rc.view.state.version) " · " (rc.view.state.packs.len()) " packs" } }
                } }
            }
            div.card.danger-zone {
                div.card-head { h3 { "Danger zone" } }
                @if let Some(e) = error { div.banner.banner-error { (e) } }
                p { "Deleting a repository removes its history from every region. There is no undo." }
                form method="post" action=(format!("{base}/settings/delete")) {
                    div.field {
                        label for="confirm" { "Type " (full) " to confirm" }
                        input id="confirm" type="text" name="confirm" autocomplete="off" required;
                    }
                    button.btn.btn-danger type="submit" { "Delete this repository" }
                }
            }
        }
    }
}

async fn settings_page(
    State(s): State<AppState>,
    Path((ns, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let rc = match open_repo(&s, &headers, &ns, &repo, &format!("/{ns}/{repo}/settings")).await {
        Ok(rc) => rc,
        Err(r) => return r,
    };
    if !rc.admin() {
        return not_found(&rc.ctx);
    }
    ok(shell(
        &rc.ctx,
        &format!("Settings · {ns}/{repo}"),
        "",
        settings_view(&rc, None),
    ))
}

#[derive(Deserialize)]
struct DeleteForm {
    #[serde(default)]
    confirm: String,
}

async fn delete_repo(
    State(s): State<AppState>,
    Path((ns, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Form(f): Form<DeleteForm>,
) -> Response {
    let ctx = Ctx::new(&s, &headers).await;
    let p = match ctx.signed_in(&format!("/{ns}/{repo}/settings")) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if !same_origin(&s, &headers) {
        return forbidden_origin(&ctx);
    }
    if !p.allows(&ns, None, Tier::Admin) {
        return not_found(&ctx);
    }
    if f.confirm.trim() != format!("{ns}/{repo}") {
        let rc = match open_repo(&s, &headers, &ns, &repo, "/").await {
            Ok(rc) => rc,
            Err(r) => return r,
        };
        return render(
            StatusCode::BAD_REQUEST,
            shell(
                &rc.ctx,
                "Settings",
                "",
                settings_view(&rc, Some("The name did not match; nothing was deleted.")),
            ),
        );
    }
    match api::remove_repo(&s, &p, &ns, &repo).await {
        Ok(_) => Redirect::to(&format!("/{ns}")).into_response(),
        Err(e) => failure(&ctx, e.status(), &e.message()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_durations() {
        assert_eq!(ymd(0), (1970, 1, 1));
        assert_eq!(ymd(1_791_158_400), (2026, 10, 5));
        assert_eq!(date(951_782_400), "Feb 29, 2000");
        assert_eq!(bytes(2048), "2.0 KB");
        assert_eq!(initials("Ada Lovelace"), "AL");
    }

    #[test]
    fn next_never_leaves_the_site() {
        assert_eq!(safe_next(Some("/team/site")), "/team/site");
        for bad in ["//evil.com", "https://evil.com", "/\\evil.com", ""] {
            assert_eq!(safe_next(Some(bad)), "/", "{bad}");
        }
    }

    #[test]
    fn readme_links_stay_in_the_repo_and_scripts_go_nowhere() {
        let base = LinkBase {
            repo: "/team/site".into(),
            rev: "main".into(),
            dir: "docs".into(),
        };
        assert_eq!(
            base.resolve("guide.md", false),
            "/team/site/blob/main/docs/guide.md"
        );
        assert_eq!(
            base.resolve("../logo.png", true),
            "/team/site/raw/main/logo.png"
        );
        assert_eq!(
            base.resolve("/src#L3", false),
            "/team/site/blob/main/src#L3"
        );
        assert_eq!(
            base.resolve("https://heyo.computer", false),
            "https://heyo.computer"
        );
        assert_eq!(base.resolve("javascript:alert(1)", false), "#");
        assert_eq!(base.resolve("//evil.com/x", false), "#");
        let html = markdown(
            "<script>alert(1)</script>\n\n[x](javascript:alert(1)) ![i](a.png)",
            &base,
        );
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
        assert!(!html.contains("javascript:"), "{html}");
        assert!(
            html.contains(r#"src="/team/site/raw/main/docs/a.png""#),
            "{html}"
        );
    }

    #[test]
    fn the_local_stylesheet_declares_no_palette_of_its_own() {
        assert!(!STYLE.contains(":root"), "tokens belong in ui/heyo.css");
        assert!(!STYLE.contains("prefers-color-scheme"));
        for line in STYLE.lines() {
            let code = line.split("/*").next().unwrap_or("");
            assert!(
                !code.contains('#'),
                "hard-coded colour in the local sheet: {line}"
            );
        }
    }
}
