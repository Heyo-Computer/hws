//! The public hub: a catalog of the public repositories, readable by anyone.
//!
//! Mounted outside every gate. It shows nothing the anonymous API would not
//! already hand out — a repository is listed only when it is public, and a
//! public repository's tags, manifests and blobs are anonymously pullable by
//! definition (see `anon_allowed` in [`crate::http`]). A private repository is
//! a 404 here, not a 403, so the hub does not confirm that a name exists.
//!
//! Server-rendered with the dashboard's stylesheet and no JavaScript, for the
//! same reason the dashboard is: it must render from inside a VM with no route
//! to a CDN.
//!
//! Routes:
//!
//! - `/hub` — every public repository, grouped by namespace.
//! - `/hub/r/{repo}` — one repository's tags and how to pull them.
//! - `/hub/r/{repo}/-/{tag}` — one tag's manifest. `-` cannot begin a
//!   repository segment, so the separator is unambiguous.

use crate::digest::Digest;
use crate::registry::Registry;
use crate::store::Repository;
use crate::tags::{RepoName, TagName};
use crate::web::{STYLE, human, short};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use maud::{DOCTYPE, Markup, PreEscaped, html};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct HubState {
    pub registry: Registry,
    /// The hub's own host. A request for `/` on it lands on the catalog.
    pub host: Option<String>,
    pub ui: Arc<crate::heyo_ui::CookieConfig>,
}

pub fn router(hub: Option<HubState>) -> Router {
    let Some(state) = hub else {
        return Router::new();
    };
    let mut r = Router::new()
        .route("/hub", get(catalog))
        .route("/hub/r/{*path}", get(repo_or_tag));
    if state.host.is_some() {
        r = r.route("/", get(index));
    }
    r.layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

async fn index(State(st): State<HubState>, headers: header::HeaderMap) -> Response {
    let host = request_host(&headers);
    if st
        .host
        .as_deref()
        .is_some_and(|h| Some(h) == host.as_deref())
    {
        return Redirect::to("/hub").into_response();
    }
    // Any other host: the dashboard's `/`, which is just this redirect too.
    Redirect::to("/dashboard").into_response()
}

fn request_host(headers: &header::HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(',').next().unwrap_or(h).trim().to_string())
}

/// `https://host` as the visitor reached it, for copyable pull commands.
fn base_url(st: &HubState, headers: &header::HeaderMap) -> String {
    let host = request_host(headers)
        .or_else(|| st.host.clone())
        .unwrap_or_else(|| "localhost:8080".into());
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(
            if host.starts_with("localhost") || host.starts_with("127.") {
                "http"
            } else {
                "https"
            },
        );
    format!("{proto}://{host}")
}

async fn public_repos(st: &HubState) -> crate::Result<Vec<Repository>> {
    let idx = st.registry.public_index();
    Ok(st
        .registry
        .store()
        .repositories()
        .await?
        .into_iter()
        .filter(|r| idx.repo_is_public(&r.name))
        .collect())
}

async fn catalog(
    State(st): State<HubState>,
    headers: header::HeaderMap,
) -> Result<Markup, HubError> {
    let repos = public_repos(&st).await?;
    let mut by_ns: BTreeMap<String, Vec<&Repository>> = BTreeMap::new();
    for r in &repos {
        by_ns
            .entry(r.name.namespace().to_string())
            .or_default()
            .push(r);
    }
    Ok(page(
        &st,
        &headers,
        "hub",
        html! {
            section.hero {
                div.hero-value { (repos.len()) }
                div.hero-label {
                    "public " (if repos.len() == 1 { "repository" } else { "repositories" })
                    " — pull any of them without an account"
                }
            }
            @if repos.is_empty() {
                p.empty { "Nothing has been published yet." }
            }
            @for (ns, rs) in &by_ns {
                section {
                    div.sec-head { h2 { (ns) } span.count { (rs.len()) } }
                    table {
                        thead { tr { th { "Repository" } th { "Tags" } th { "About" } th { "Updated" } } }
                        tbody {
                            @for r in rs {
                                tr {
                                    td.name { a href=(format!("/hub/r/{}", r.name)) { (r.name.as_str()) } }
                                    td {
                                        @for (t, _) in r.tags.iter().take(6) {
                                            span.chip { (t.short()) } " "
                                        }
                                        @if r.tags.len() > 6 { span.muted { "+" (r.tags.len() - 6) } }
                                        @if r.tags.is_empty() { span.muted { "—" } }
                                    }
                                    td {
                                        @match first_line(r.meta.description.as_deref()) {
                                            Some(d) => (d),
                                            None => span.muted { "—" },
                                        }
                                    }
                                    td.muted { (when(r.meta.updated)) }
                                }
                            }
                        }
                    }
                }
            }
        },
    ))
}

async fn repo_or_tag(
    State(st): State<HubState>,
    Path(path): Path<String>,
    headers: header::HeaderMap,
) -> Result<Markup, HubError> {
    match path.split_once("/-/") {
        Some((repo, tag)) => tag_page(&st, &headers, repo, tag).await,
        None => repo_page(&st, &headers, &path).await,
    }
}

async fn find_public(st: &HubState, repo: &str) -> Result<Repository, HubError> {
    let name = RepoName::parse(repo).map_err(|_| HubError::NotFound)?;
    public_repos(st)
        .await?
        .into_iter()
        .find(|r| r.name == name)
        .ok_or(HubError::NotFound)
}

async fn repo_page(
    st: &HubState,
    headers: &header::HeaderMap,
    repo: &str,
) -> Result<Markup, HubError> {
    let r = find_public(st, repo).await?;
    let base = base_url(st, headers);
    let host = base.split("://").nth(1).unwrap_or(&base).to_string();
    let mut rows = Vec::new();
    for (t, d) in &r.tags {
        let m = st.registry.manifest(d).await.ok();
        rows.push((t, d, m));
    }
    let example = r
        .tags
        .iter()
        .find(|(t, _)| t.short() == crate::tags::DEFAULT_TAG)
        .or(r.tags.first())
        .map(|(t, _)| t.as_str().to_string())
        .unwrap_or_else(|| format!("{}:{}", r.name, crate::tags::DEFAULT_TAG));

    Ok(page(
        st,
        headers,
        r.name.as_str(),
        html! {
            p.crumbs { a href="/hub" { "hub" } " / " (r.name.as_str()) }
            h1 { (r.name.as_str()) }
            @if let Some(d) = &r.meta.description { p.about { (d) } }

            section {
                div.sec-head { h2 { "Pull" } }
                p.muted { "No account or key needed." }
                h3 { "heyctl" }
                pre { code { "heyctl artifact pull " (host) "/" (example) " --dest ./" (r.name.as_str().rsplit('/').next().unwrap_or("out")) } }
                h3 { "app-lb deployment" }
                pre { code { (format!("\"artifact\": {{ \"store\": \"{base}\", \"ref\": \"{example}\" }}")) } }
                h3 { "HTTP" }
                pre { code {
                    "curl -fsSL " (base) "/manifests/" (example) "\n"
                    "curl -fsSL -o blob " (base) "/blobs/<digest from an entry>"
                } }
            }

            section {
                div.sec-head { h2 { "Tags" } span.count { (rows.len()) } }
                @if rows.is_empty() {
                    p.empty { "No tags yet." }
                } @else {
                    table {
                        thead { tr { th { "Tag" } th { "Kind" } th { "Size" } th { "Digest" } } }
                        tbody {
                            @for (t, d, m) in &rows {
                                tr {
                                    td.name { a href=(tag_href(t)) { (t.short()) } }
                                    td { @match m { Some(m) => (m.kind.as_str()), None => span.muted { "blob" } } }
                                    td { @match m { Some(m) => (human(m.total_size())), None => span.muted { "—" } } }
                                    td.mono { (short(d)) }
                                }
                            }
                        }
                    }
                }
            }
        },
    ))
}

fn tag_href(t: &TagName) -> String {
    match t.repo() {
        Some(r) => format!("/hub/r/{}/-/{}", r, t.short()),
        None => "/hub".into(),
    }
}

async fn tag_page(
    st: &HubState,
    headers: &header::HeaderMap,
    repo: &str,
    tag: &str,
) -> Result<Markup, HubError> {
    let r = find_public(st, repo).await?;
    let (t, d) = r
        .tags
        .iter()
        .find(|(t, _)| t.short() == tag)
        .cloned()
        .ok_or(HubError::NotFound)?;
    let m = st.registry.manifest(&d).await.ok();
    let base = base_url(st, headers);
    Ok(page(
        st,
        headers,
        t.as_str(),
        html! {
            p.crumbs {
                a href="/hub" { "hub" } " / "
                a href=(format!("/hub/r/{}", r.name)) { (r.name.as_str()) } " / "
                (t.short())
            }
            h1 { (t.as_str()) }
            p.mono.muted { (d.as_str()) }
            @match &m {
                Some(m) => {
                    section {
                        div.sec-head { h2 { "Entries" } span.count { (m.entries.len()) } }
                        table {
                            thead { tr { th { "Name" } th { "Size" } th { "Digest" } } }
                            tbody {
                                @for e in &m.entries {
                                    tr {
                                        td.name { (e.name.as_str()) }
                                        td { (human(e.size)) }
                                        td.mono { a href=(blob_href(&base, &e.digest)) { (short(&e.digest)) } }
                                    }
                                }
                            }
                        }
                    }
                    @if !m.annotations.is_empty() {
                        section {
                            div.sec-head { h2 { "Annotations" } }
                            table { tbody {
                                @for (k, v) in &m.annotations { tr { td.name { (k) } td { (v) } } }
                            } }
                        }
                    }
                }
                None => {
                    section {
                        p { "A single blob. " a href=(blob_href(&base, &d)) { "Download" } }
                    }
                }
            }
        },
    ))
}

fn blob_href(base: &str, d: &Digest) -> String {
    format!("{base}/blobs/{d}")
}

fn first_line(s: Option<&str>) -> Option<&str> {
    s.and_then(|d| d.lines().next())
        .map(str::trim)
        .filter(|l| !l.is_empty())
}

fn when(unix: u64) -> String {
    if unix == 0 {
        return "—".into();
    }
    let now = crate::repos::now_unix();
    let ago = now.saturating_sub(unix);
    match ago {
        0..=119 => "just now".into(),
        120..=7199 => format!("{} min ago", ago / 60),
        7200..=172_799 => format!("{} h ago", ago / 3600),
        _ => format!("{} days ago", ago / 86_400),
    }
}

const HUB_STYLE: &str = r#"
.crumbs { color: var(--text-muted); font-size: 12px; margin-bottom: var(--gap-2); }
.about { color: var(--text-muted); max-width: 70ch; }
pre { background: var(--bg-panel); border: 1px solid var(--border-color); padding: var(--gap-3); overflow-x: auto; }
h3 { font-size: 12px; margin: var(--gap-3) 0 var(--gap-1); }
.chip { display: inline-block; padding: 0 6px; border: 1px solid var(--border-color); font-size: 11px; }
.muted { color: var(--text-muted); }
"#;

fn page(st: &HubState, headers: &header::HeaderMap, title: &str, body: Markup) -> Markup {
    let cookies = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
    let attrs = st.ui.attrs(cookies);
    let nav: Vec<(&str, &str, bool)> = vec![("Repositories", "/hub", true)];
    html! {
        (DOCTYPE)
        (PreEscaped(format!("<html lang=\"en\" {attrs}>").replace(" >", ">")))
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "heyo hub · " (title) }
                (PreEscaped(crate::heyo_ui::head_tags()))
                style { (PreEscaped(STYLE)) (PreEscaped(HUB_STYLE)) }
            }
            body {
                (PreEscaped(crate::heyo_ui::topbar_html("hub", &nav, None)))
                main { (body) }
            }
        (PreEscaped("</html>"))
    }
}

pub enum HubError {
    NotFound,
    Internal(crate::Error),
}

impl From<crate::Error> for HubError {
    fn from(e: crate::Error) -> Self {
        HubError::Internal(e)
    }
}

impl IntoResponse for HubError {
    fn into_response(self) -> Response {
        match self {
            HubError::NotFound => (StatusCode::NOT_FOUND, "not found\n").into_response(),
            HubError::Internal(e) => {
                tracing::error!(error = %e, "hub page failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "something went wrong\n").into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::manifest::Manifest;
    use crate::repos::RepoMeta;
    use crate::store::Store;
    use axum::body::{Body, to_bytes};
    use std::time::Duration;
    use tower::ServiceExt;

    async fn hub() -> (tempfile::TempDir, Registry, Router) {
        let d = tempfile::tempdir().unwrap();
        let store = Store::open(&Config {
            root: d.path().join("store"),
            min_free_bytes: 0,
            gc_min_age: Duration::ZERO,
            heyvm_images_dir: d.path().join("images"),
        })
        .unwrap();
        let reg = Registry::local(store);
        let state = HubState {
            registry: reg.clone(),
            host: Some("hub.example".into()),
            ui: Arc::new(crate::heyo_ui::CookieConfig::from_env("ART_TEST_HUB")),
        };
        (d, reg, router(Some(state)))
    }

    async fn get(app: &Router, path: &str) -> (StatusCode, String) {
        let r = app
            .clone()
            .oneshot(
                axum::http::Request::get(path)
                    .header("host", "hub.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let s = r.status();
        let b = to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (s, String::from_utf8_lossy(&b).into_owned())
    }

    #[tokio::test]
    async fn lists_public_repositories_and_hides_private_ones() {
        let (_d, reg, app) = hub().await;
        let store = reg.store();
        let blob = store.insert_bytes(b"rootfs".to_vec()).await.unwrap();
        let m = Manifest::new(crate::KIND_ROOTFS).with_entry("rootfs.ext4", blob.digest.clone(), 6);
        let md = store.put_manifest(&m).await.unwrap();
        for t in ["heyo/postgres:16", "acme/secret:1"] {
            reg.set_tag(&TagName::parse(t).unwrap(), &md, None)
                .await
                .unwrap();
        }
        reg.set_repo(
            &RepoName::parse("heyo/postgres").unwrap(),
            &RepoMeta {
                public: true,
                description: Some("PostgreSQL 16 rootfs".into()),
                updated: 1,
            },
        )
        .await
        .unwrap();

        let (s, body) = get(&app, "/hub").await;
        assert_eq!(s, StatusCode::OK);
        assert!(body.contains("heyo/postgres"), "{body}");
        assert!(body.contains("PostgreSQL 16 rootfs"));
        assert!(!body.contains("acme/secret"), "private repo leaked: {body}");

        let (s, body) = get(&app, "/hub/r/heyo/postgres").await;
        assert_eq!(s, StatusCode::OK);
        assert!(
            body.contains("heyctl artifact pull hub.example/heyo/postgres:16"),
            "{body}"
        );
        let (s, body) = get(&app, "/hub/r/heyo/postgres/-/16").await;
        assert_eq!(s, StatusCode::OK);
        assert!(body.contains("rootfs.ext4"));

        // Private and absent are indistinguishable.
        assert_eq!(
            get(&app, "/hub/r/acme/secret").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(get(&app, "/hub/r/acme/nope").await.0, StatusCode::NOT_FOUND);
        assert_eq!(
            get(&app, "/hub/r/acme/secret/-/1").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(get(&app, "/hub/r/../etc").await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_hub_host_lands_on_the_catalog() {
        let (_d, _reg, app) = hub().await;
        let r = app
            .clone()
            .oneshot(
                axum::http::Request::get("/")
                    .header("host", "hub.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.headers().get("location").unwrap(), "/hub");
    }
}
