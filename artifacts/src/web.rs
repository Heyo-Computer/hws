//! Server-rendered dashboard, gated on admin credentials unless the operator
//! has declared the listener private (`ART_DASHBOARD_OPEN`), in which case
//! [`WebState::auth`] is `None` and every request authorizes.
//!
//! Zero JavaScript and zero external assets. Not minimalism for its own sake:
//! this runs inside a Firecracker microVM with no route to a CDN, so a remote
//! font or script would simply fail to load, and a dashboard that needs the
//! network to render is useless exactly when you most want to look at it.
//!
//! Everything here is read-only. Deleting a blob, moving a tag, and running a
//! sweep all stay in the CLI — a dashboard is for answering "what is in there
//! and what is it costing me", and a misplaced click should not be able to
//! collect a blob a VM is booting from. Garbage collection is doubly excluded:
//! even a dry run takes the store lock exclusively, so a page load would stall
//! every writer on the host.
//!
//! ## Visual encoding
//!
//! The numbers that matter here are single values, so the forms are a hero
//! figure and stat tiles rather than charts. Two exceptions carry a bar:
//!
//! - **The capacity meter** is a status encoding (good / warning / critical).
//!   Status colour never carries meaning alone, so it always ships beside a
//!   glyph and a written percentage — which is also the required relief for the
//!   warning step sitting below 3:1 on the light surface.
//! - **Sparsity bars** are one sequential hue, light→dark, on a lighter step of
//!   the same ramp for the track. A single series needs no legend; the column
//!   header names it.

use crate::admin::{AdminAuth, SESSION_COOKIE};
use crate::digest::Digest;
use crate::labels::Label;
use crate::manifest::Manifest;
use crate::store::{BlobInfo, Store, Usage};
use crate::tags::TagName;
use axum::extract::{Form, Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

/// Rows before the overview stops listing and points at the full page.
const OVERVIEW_ROWS: usize = 12;

#[derive(Clone)]
pub struct WebState {
    pub store: Store,
    /// `None` is a dashboard with no local login — either the open one
    /// (`ART_DASHBOARD_OPEN`) or the gated one (`ART_DASHBOARD_GATE`), told
    /// apart by `gate` below. Never from an unset variable — see
    /// [`crate::config::DashboardAccess`].
    pub auth: Option<Arc<AdminAuth>>,
    /// Authentication happens upstream, in app-lb, and this app trusts the
    /// `x-auth-request-*` headers it forwards.
    ///
    /// Separate from `auth: None` because the two look identical from inside a
    /// handler and mean opposite things: open serves anybody, gated serves only
    /// a request that arrived with an identity attached.
    pub gate: bool,
    /// Where the theme cookie is written, and under what name.
    pub ui: Arc<crate::heyo_ui::CookieConfig>,
}

/// Everything the page shell needs about *this* request.
pub struct Shell {
    /// `data-theme="…" data-cookie-domain="…"`, resolved from the cookie before
    /// a byte is sent, so no page flashes the wrong palette.
    pub attrs: String,
    /// Who the gate says is here. `None` on an open or password dashboard,
    /// which have no identity to show — a password is not a person.
    pub who: Option<String>,
    /// Whether to offer a local sign-out. False under a gate: the session is
    /// app-lb's, and a button here could not end it.
    pub signout: bool,
}

impl Default for Shell {
    /// For a response rendered from an error value, which has no request in
    /// hand and so cannot know the theme.
    ///
    /// The attributes are **empty rather than `data-theme="dark"`**: with no
    /// attribute the toggle script reads the cookie and applies it on load, so
    /// a light-mode reader gets one frame of dark and then their own palette.
    /// Pinning dark here would have given them a dark error page and no
    /// explanation. Every page rendered from a real request stamps the theme
    /// server-side and does not flash at all.
    fn default() -> Self {
        Shell {
            attrs: String::new(),
            who: None,
            signout: false,
        }
    }
}

pub fn shell(st: &WebState, headers: &header::HeaderMap) -> Shell {
    let cookies = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
    Shell {
        attrs: st.ui.attrs(cookies),
        who: if st.gate {
            forwarded_identity(headers).map(|i| i.display().to_string())
        } else {
            None
        },
        signout: st.auth.is_some(),
    }
}

/// The identity app-lb forwarded, if any.
fn forwarded_identity(headers: &header::HeaderMap) -> Option<crate::heyo_ui::Identity> {
    crate::heyo_ui::identity_from(|name| headers.get(name).and_then(|v| v.to_str().ok()))
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginForm {
    user: String,
    password: String,
}

pub async fn login_page(
    State(st): State<WebState>,
    headers: header::HeaderMap,
    jar: CookieJar,
) -> Response {
    // No local login to present — either there is no gate at all, or there is
    // one and it is upstream. Rendering a form that accepts nothing would be a
    // worse lie than the redirect.
    let Some(auth) = st.auth.as_deref() else {
        return Redirect::to("/dashboard").into_response();
    };
    if session_ok(auth, &jar) {
        return Redirect::to("/dashboard").into_response();
    }
    page_bare(&shell(&st, &headers), "sign in", login_body(false)).into_response()
}

pub async fn login_submit(
    State(st): State<WebState>,
    headers: header::HeaderMap,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(auth) = st.auth.as_deref() else {
        return Redirect::to("/dashboard").into_response();
    };
    if !auth.verify_login(&form.user, &form.password) {
        tracing::warn!(user = %form.user, "dashboard login failed");
        // Same page, same status shape, no hint about which field was wrong.
        return (
            StatusCode::UNAUTHORIZED,
            page_bare(&shell(&st, &headers), "sign in", login_body(true)),
        )
            .into_response();
    }
    let cookie = Cookie::build((SESSION_COOKIE, auth.session_token().to_string()))
        // HttpOnly: script must never be able to read it. SameSite=Strict: the
        // dashboard has no cross-site flows, so nothing legitimate is lost and
        // CSRF against the login POST is closed off.
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .build();
    (jar.add(cookie), Redirect::to("/dashboard")).into_response()
}

pub async fn logout(jar: CookieJar) -> Response {
    let mut removal = Cookie::from(SESSION_COOKIE);
    removal.set_path("/");
    (jar.remove(removal), Redirect::to("/login")).into_response()
}

fn session_ok(auth: &AdminAuth, jar: &CookieJar) -> bool {
    jar.get(SESSION_COOKIE)
        .map(|c| auth.verify_session(c.value()))
        .unwrap_or(false)
}

/// Authorize a dashboard request: session cookie, or Basic auth for `curl -u`.
///
/// An unconfigured gate authorizes everything. That is the whole of the open
/// mode — one `None` here, rather than a bypass flag threaded through the
/// checks, so there is no branch that can be reached with a gate configured.
pub fn dashboard_authorized(st: &WebState, headers: &header::HeaderMap, jar: &CookieJar) -> bool {
    // Under a gate, an identity *is* the authorization: app-lb only forwards
    // one for a request it authenticated, and it strips the headers before
    // setting them so a client cannot supply its own. A request with none is an
    // app-token caller or a direct hit on the listener, and neither is a person
    // this dashboard should answer.
    if st.gate {
        return forwarded_identity(headers).is_some();
    }
    let Some(auth) = st.auth.as_deref() else {
        return true;
    };
    if session_ok(auth, jar) {
        return true;
    }
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|h| auth.verify_basic(h))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

pub async fn index() -> Redirect {
    Redirect::to("/dashboard")
}

pub async fn overview(
    State(st): State<WebState>,
    headers: header::HeaderMap,
) -> Result<Markup, WebError> {
    let usage = st.store.usage().await?;
    let tags = st.store.list_tags().await?;
    let blobs = st.store.list_blobs().await?;
    let names = Names::load(&st.store).await?;

    let pinned = blobs.iter().filter(|b| b.nlink > 1).count();
    let shown: Vec<_> = blobs.iter().take(OVERVIEW_ROWS).collect();

    Ok(page(
        &shell(&st, &headers),
        "overview",
        "/dashboard",
        html! {
            // Hero: the one number this store exists to improve. Exactly one
            // per view, proportional figures (tabular-nums is for columns).
            section.hero {
                div.hero-value { (format!("{:.1}×", dedup_ratio(&usage))) }
                div.hero-label {
                    "effective capacity — "
                    (human(usage.logical)) " of content stored in " (human(usage.allocated))
                }
            }

            section.tiles {
                (tile("Blobs", &usage.blobs.to_string(), None))
                (tile("Logical", &human(usage.logical), None))
                (tile("On disk", &human(usage.allocated), None))
                (tile("Manifests", &usage.manifests.to_string(), None))
                (tile("Tags", &usage.tags.to_string(), None))
                (tile("Pinned", &pinned.to_string(), Some("materialized elsewhere")))
            }

            (capacity_meter(&usage))

            section {
                (section_head("Tags", tags.len(), None))
                @if tags.is_empty() {
                    p.empty { "No tags. " code { "art tag <name> <ref>" } }
                } @else {
                    table {
                        thead { tr { th { "Tag" } th { "Target" } th { "What it is" } } }
                        tbody {
                            @for (t, d) in &tags {
                                tr {
                                    td.name { (t.as_str()) }
                                    td { a.mono href=(format!("/dashboard/blob/{d}")) { (short(d)) } }
                                    // The tag says what to type; this says
                                    // whether it is the one you want.
                                    td {
                                        @match names.label(d).and_then(Label::display_name) {
                                            Some(name) => span.labelname { (name) },
                                            None => span.muted { "—" },
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            section {
                (section_head("Largest blobs", blobs.len(), Some("/dashboard/blobs")))
                (blob_table(&shown, &names))
            }
        },
    ))
}

pub async fn blobs_page(
    State(st): State<WebState>,
    headers: header::HeaderMap,
) -> Result<Markup, WebError> {
    let blobs = st.store.list_blobs().await?;
    let names = Names::load(&st.store).await?;
    let refs: Vec<&BlobInfo> = blobs.iter().collect();
    Ok(page(
        &shell(&st, &headers),
        "blobs",
        "/dashboard/blobs",
        html! {
            section {
                (section_head("All blobs", blobs.len(), None))
                (blob_table(&refs, &names))
            }
        },
    ))
}

pub async fn blob_page(
    State(st): State<WebState>,
    headers: header::HeaderMap,
    Path(digest): Path<String>,
) -> Result<Markup, WebError> {
    let d = Digest::parse(&digest).map_err(crate::Error::from)?;
    let info = st.store.stat(&d).await?;
    let label = st.store.get_label(&d).await?;
    let public = st.store.is_public(&d).await?;

    // Which tags and manifests point here. Both lists are small enough to scan
    // directly; an index would be a second source of truth for something the
    // filesystem already answers.
    let tags: Vec<TagName> = st
        .store
        .list_tags()
        .await?
        .into_iter()
        .filter(|(_, td)| *td == d)
        .map(|(t, _)| t)
        .collect();

    let mut manifests = Vec::new();
    for md in st.store.list_manifests().await? {
        if let Ok(m) = st.store.get_manifest(&md).await
            && m.entries.iter().any(|e| e.digest == d)
        {
            manifests.push((md, m));
        }
    }

    let saved = info.size.saturating_sub(info.allocated);
    Ok(page(
        &shell(&st, &headers),
        "blob",
        "/dashboard/blobs",
        html! {
            section {
                (heading("Blob", label.as_ref()))
                p.digest.mono { (info.digest.as_str()) }
                (description(label.as_ref()))
                section.tiles {
                    (tile("Logical", &human(info.size), None))
                    (tile("On disk", &human(info.allocated), None))
                    (tile("Reclaimed", &human(saved), Some("zero runs punched out")))
                    (tile("Links", &info.nlink.to_string(),
                          Some(if info.nlink > 1 { "pinned by a materialization" }
                               else { "store entry only" })))
                    (tile("Access", if public { "public" } else { "key required" },
                          Some(if public { "anyone may GET this blob" }
                               else { "downloads need the API key" })))
                }
                (sparsity_bar(&info, true))
            }

            section {
                (section_head("Referenced by", tags.len() + manifests.len(), None))
                @if tags.is_empty() && manifests.is_empty() {
                    p.empty {
                        "Nothing references this blob. "
                        @if info.nlink > 1 {
                            "It survives collection only because something outside the store holds a hardlink."
                        } @else {
                            "It is eligible for collection once it is older than the grace window."
                        }
                    }
                }
                @if !tags.is_empty() {
                    table {
                        thead { tr { th { "Tag" } } }
                        tbody { @for t in &tags { tr { td.name { (t.as_str()) } } } }
                    }
                }
                @if !manifests.is_empty() {
                    table {
                        thead { tr { th { "Manifest" } th { "Kind" } th { "Entry" } } }
                        tbody {
                            @for (md, m) in &manifests {
                                tr {
                                    td { a.mono href=(format!("/dashboard/manifest/{md}")) { (short(md)) } }
                                    td { (m.kind) }
                                    td.name {
                                        (m.entries.iter().find(|e| e.digest == d)
                                          .map(|e| e.name.as_str()).unwrap_or("—"))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    ))
}

pub async fn manifests_page(
    State(st): State<WebState>,
    headers: header::HeaderMap,
) -> Result<Markup, WebError> {
    let names = Names::load(&st.store).await?;
    let mut rows = Vec::new();
    for d in st.store.list_manifests().await? {
        let m = st.store.get_manifest(&d).await.ok();
        rows.push((d, m));
    }
    Ok(page(
        &shell(&st, &headers),
        "manifests",
        "/dashboard/manifests",
        html! {
            section {
                (section_head("Manifests", rows.len(), None))
                @if rows.is_empty() {
                    p.empty { "No manifests." }
                } @else {
                    table {
                        thead { tr { th { "What" } th { "Digest" } th { "Kind" } th.r { "Entries" } th.r { "Total" } } }
                        tbody {
                            @for (d, m) in &rows {
                                tr {
                                    td { (names.cell(d)) }
                                    td { a.mono href=(format!("/dashboard/manifest/{d}")) { (short(d)) } }
                                    td { (m.as_ref().map(|m| m.kind.as_str()).unwrap_or("unreadable")) }
                                    td.r { (m.as_ref().map(|m| m.entries.len()).unwrap_or(0)) }
                                    td.r { (m.as_ref().map(|m| human(m.total_size())).unwrap_or_else(|| "—".into())) }
                                }
                            }
                        }
                    }
                }
            }
        },
    ))
}

pub async fn manifest_page(
    State(st): State<WebState>,
    headers: header::HeaderMap,
    Path(digest): Path<String>,
) -> Result<Markup, WebError> {
    let d = Digest::parse(&digest).map_err(crate::Error::from)?;
    let m: Manifest = st.store.get_manifest(&d).await?;
    let label = st.store.get_label(&d).await?;
    let tags: Vec<TagName> = st
        .store
        .list_tags()
        .await?
        .into_iter()
        .filter(|(_, td)| *td == d)
        .map(|(t, _)| t)
        .collect();
    Ok(page(
        &shell(&st, &headers),
        "manifest",
        "/dashboard/manifests",
        html! {
            section {
                (heading("Manifest", label.as_ref()))
                p.digest.mono { (d.as_str()) }
                @if !tags.is_empty() {
                    p { @for t in &tags { span.tagchip { (t.as_str()) } } }
                }
                (description(label.as_ref()))
                section.tiles {
                    (tile("Kind", &m.kind, None))
                    (tile("Schema", &m.schema.to_string(), None))
                    (tile("Entries", &m.entries.len().to_string(), None))
                    (tile("Total", &human(m.total_size()), None))
                }
            }
            section {
                (section_head("Entries", m.entries.len(), None))
                table {
                    thead { tr { th { "Name" } th { "Digest" } th.r { "Size" } } }
                    tbody {
                        @for e in &m.entries {
                            tr {
                                td.name { (e.name) }
                                td { a.mono href=(format!("/dashboard/blob/{}", e.digest)) { (short(&e.digest)) } }
                                td.r { (human(e.size)) }
                            }
                        }
                    }
                }
            }
            @if !m.annotations.is_empty() {
                section {
                    (section_head("Annotations", m.annotations.len(), None))
                    table {
                        tbody {
                            @for (k, v) in &m.annotations {
                                tr { td.name { (k) } td.mono { (v) } }
                            }
                        }
                    }
                }
            }
        },
    ))
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

/// A detail page's heading: what the thing is called, falling back to what kind
/// of thing it is.
///
/// The name replaces the generic word rather than sitting beside it. A page
/// headed "Blob" over a digest told the reader only what they already knew from
/// the URL; one headed "Debian rootfs, hermes agents" is the answer they came
/// for, and the word "blob" is still in the breadcrumb above it.
fn heading(kind: &str, label: Option<&Label>) -> Markup {
    match label.and_then(Label::display_name) {
        Some(name) => html! { h2 { (name) } p.muted { (kind) } },
        None => html! { h2 { (kind) } },
    }
}

/// A label's description, when it has one beyond its name.
///
/// Suppressed when the description *is* the display name — a label with only a
/// one-line description already had it promoted into the heading, and printing
/// it twice reads as a rendering fault rather than as emphasis.
fn description(label: Option<&Label>) -> Markup {
    let Some(label) = label else {
        return html! {};
    };
    let Some(text) = &label.description else {
        return html! {};
    };
    if label.name.is_none() && text.lines().count() <= 1 {
        return html! {};
    }
    html! { p.description { (text) } }
}

fn section_head(title: &str, count: usize, more: Option<&str>) -> Markup {
    html! {
        div.sec-head {
            h2 { (title) " " span.count { (count) } }
            @if let Some(href) = more {
                a.more href=(href) { "view all →" }
            }
        }
    }
}

/// Stat tile: label in sentence case with no trailing colon, value semibold.
fn tile(label: &str, value: &str, note: Option<&str>) -> Markup {
    html! {
        div.tile {
            div.tile-label { (label) }
            div.tile-value { (value) }
            @if let Some(n) = note { div.tile-note { (n) } }
        }
    }
}

/// Filesystem capacity, as a status meter.
///
/// The fill carries severity and the track is a lighter step of the same ramp,
/// so state reads across the whole bar. Status colour never stands alone: the
/// glyph and the written percentage carry the same information, which is what
/// makes this legible to a colourblind reader, in forced-colors mode, and on
/// the light surface where the warning step falls below 3:1.
fn capacity_meter(u: &Usage) -> Markup {
    let used = u.fs_total.saturating_sub(u.fs_available);
    let pct = if u.fs_total > 0 {
        (used as f64 / u.fs_total as f64 * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    };
    let (level, glyph, word) = match pct {
        p if p >= 95.0 => ("critical", "!!", "critical"),
        p if p >= 85.0 => ("warning", "! ", "low"),
        _ => ("good", "OK", "healthy"),
    };
    html! {
        section.meter-wrap {
            div.meter-head {
                span.meter-title { "Filesystem" }
                span.(format!("badge badge-{level}")) {
                    span.badge-glyph aria-hidden="true" { (glyph) }
                    " " (word)
                }
            }
            div.meter role="img"
                aria-label=(format!("{:.0}% of the filesystem used, {} free of {}", pct, human(u.fs_available), human(u.fs_total))) {
                div.(format!("meter-fill meter-{level}")) style=(format!("width:{pct:.1}%")) {}
            }
            div.meter-foot {
                span { (format!("{pct:.0}% used")) }
                span { (human(u.fs_available)) " free of " (human(u.fs_total)) }
            }
        }
    }
}

/// One sequential hue, light→dark, on a lighter step of the same ramp.
///
/// A single series, so no legend — the column header names it.
fn sparsity_bar(b: &BlobInfo, wide: bool) -> Markup {
    let pct = if b.size > 0 {
        (b.allocated as f64 / b.size as f64 * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    };
    let label = format!(
        "{} stored of {} logical ({:.0}%)",
        human(b.allocated),
        human(b.size),
        pct
    );
    html! {
        div.(if wide { "spark spark-wide" } else { "spark" })
            role="img" aria-label=(label) title=(label) {
            div.spark-fill style=(format!("width:{:.1}%", pct.max(1.0))) {}
        }
    }
}

/// The rows of a blob listing, with whatever is known about what each one *is*.
///
/// The identity column comes first, before the digest, and that ordering is the
/// whole fix: a table that opened with twelve hex characters made the reader
/// scan every row to find the one they wanted, because the leading column
/// carried no information a person holds in their head.
fn blob_table(blobs: &[&BlobInfo], names: &Names) -> Markup {
    html! {
        @if blobs.is_empty() {
            p.empty { "No blobs yet. " code { "art put <file>" } }
        } @else {
            div.scroll {
                table {
                    thead {
                        tr {
                            th { "What" }
                            th { "Digest" }
                            th.r { "Logical" }
                            th.r { "On disk" }
                            th { "Stored / logical" }
                            th.r { "Links" }
                        }
                    }
                    tbody {
                        @for b in blobs {
                            tr {
                                td { (names.cell(&b.digest)) }
                                td { a.mono href=(format!("/dashboard/blob/{}", b.digest)) { (short(&b.digest)) } }
                                td.r.num { (human(b.size)) }
                                td.r.num { (human(b.allocated)) }
                                td.barcell { (sparsity_bar(b, false)) }
                                td.r.num {
                                    (b.nlink)
                                    @if b.nlink > 1 { span.pin title="pinned by a materialization" { " ●" } }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The labels and tags for a page's worth of rows, fetched once.
///
/// Both are whole-store reads — a `readdir` of the label shards and one of the
/// tag directory — so they are done per *page*, not per row. Asking per row
/// would turn a listing of a thousand blobs into two thousand directory walks.
pub struct Names {
    labels: HashMap<Digest, Label>,
    tags: HashMap<Digest, Vec<TagName>>,
}

impl Names {
    async fn load(store: &Store) -> Result<Names, crate::Error> {
        Ok(Names {
            labels: store.label_map().await?,
            tags: store.tags_by_digest().await?,
        })
    }

    fn label(&self, d: &Digest) -> Option<&Label> {
        self.labels.get(d)
    }

    fn tags(&self, d: &Digest) -> &[TagName] {
        self.tags.get(d).map(Vec::as_slice).unwrap_or(&[])
    }

    /// One table cell: the tags that name a digest, and what somebody called
    /// it.
    ///
    /// A tag is rendered as a chip and the label as text, because they are
    /// different kinds of thing — a tag is an address you can type into the next
    /// command, a label is prose about what you would get. An unlabelled,
    /// untagged blob gets a dash rather than an empty cell, so "nothing is known
    /// about this" is visibly a state rather than a rendering bug.
    fn cell(&self, d: &Digest) -> Markup {
        let tags = self.tags(d);
        let name = self.label(d).and_then(Label::display_name);
        html! {
            @if tags.is_empty() && name.is_none() {
                span.muted { "—" }
            } @else {
                @for t in tags {
                    span.tagchip { (t.as_str()) }
                }
                @if let Some(name) = name {
                    span.labelname { (name) }
                }
            }
        }
    }
}

fn dedup_ratio(u: &Usage) -> f64 {
    if u.allocated > 0 {
        u.logical as f64 / u.allocated as f64
    } else {
        1.0
    }
}

pub(crate) fn short(d: &Digest) -> String {
    format!("{}…", &d.as_str()[..12])
}

pub(crate) fn human(n: u64) -> String {
    crate::cli::human(n)
}

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

/// `signout` is false on the open dashboard: there is no session to end, and a
/// button that logs nobody out is a claim the page cannot keep.
fn page(shell: &Shell, title: &str, active: &str, body: Markup) -> Markup {
    let nav: Vec<(&str, &str, bool)> = vec![
        ("Overview", "/dashboard", active == "/dashboard"),
        ("Blobs", "/dashboard/blobs", active == "/dashboard/blobs"),
        (
            "Manifests",
            "/dashboard/manifests",
            active == "/dashboard/manifests",
        ),
    ];
    html! {
        (DOCTYPE)
        // Injected whole rather than as maud attributes: this is a run of
        // several, built by the shared module from typed values.
        (PreEscaped(format!("<html lang=\"en\" {}>", shell.attrs).replace(" >", ">")))
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "artifacts · " (title) }
                (PreEscaped(crate::heyo_ui::head_tags()))
                style { (PreEscaped(STYLE)) }
            }
            body {
                (PreEscaped(crate::heyo_ui::topbar_html("artifacts", &nav, shell.who.as_deref())))
                @if shell.signout {
                    // Only the password dashboard has a session of its own to
                    // end. Under app-lb the session is the gate's, and a button
                    // here would clear nothing.
                    form.signout-form method="post" action="/logout" {
                        button.btn.btn-sm type="submit" { "sign out" }
                    }
                }
                main { (body) }
            }
        (PreEscaped("</html>"))
    }
}

/// The login page: no nav, no identity, no sign-out.
fn page_bare(shell: &Shell, title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        (PreEscaped(format!("<html lang=\"en\" {}>", shell.attrs).replace(" >", ">")))
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "artifacts · " (title) }
                (PreEscaped(crate::heyo_ui::head_tags()))
                style { (PreEscaped(STYLE)) }
            }
            body.centered { main { (body) } }
        (PreEscaped("</html>"))
    }
}

fn login_body(failed: bool) -> Markup {
    html! {
        div.login {
            h1 { "artifacts" }
            p.sub { "sign in to the dashboard" }
            @if failed {
                // One message for both fields: which one was wrong is not the
                // visitor's business to learn by probing.
                p.err role="alert" { "Incorrect username or password." }
            }
            form method="post" action="/login" {
                label for="user" { "Username" }
                input #user name="user" type="text" autocomplete="username" required autofocus;
                label for="password" { "Password" }
                input #password name="password" type="password" autocomplete="current-password" required;
                button type="submit" { "sign in" }
            }
        }
    }
}

/// What is specific to the artifacts dashboard, layered on `ui/heyo.css`.
///
/// Tokens, type, tables, buttons, pills and forms come from the shared sheet.
/// What is left here is this store's own vocabulary: the dedup hero, the stat
/// tiles, the capacity meter and the sparkline bars.
///
/// The meter and the badges keep a **sequential** relationship to their value —
/// good, warning, critical — rather than being tinted with the one accent,
/// because the whole point of the capacity meter is that 94% looks different
/// from 40% before anybody reads the number.
pub(crate) const STYLE: &str = r#"
main { max-width: 1200px; margin: 0 auto; padding: var(--gap-5) var(--gap-5) var(--gap-6); }
section { margin-bottom: var(--gap-5); }
body.centered { display: grid; place-items: center; min-height: 100vh; }
body.centered main { width: min(360px, 92vw); }

/* The sign-out button sits under the top bar rather than in it: it exists only
   on the password dashboard, and a control that is present in one deployment
   mode and absent in another does not belong in shared chrome. */
.signout-form { max-width: 1200px; margin: var(--gap-3) auto calc(-1 * var(--gap-2)); padding: 0 var(--gap-5); text-align: right; }

/* The hero: one number per view, the one this store exists to improve. */
.hero { border: 1px solid var(--border-color); background: var(--bg-panel); padding: var(--gap-5) var(--gap-4); text-align: center; }
.hero-value { font-size: 40px; line-height: 1; font-weight: 600; color: var(--accent); }
.hero-label { margin-top: var(--gap-2); color: var(--text-muted); font-size: 12px; }

/* Stat tiles. `.tile` is `.stat` from the shared sheet with a grid around it;
   kept under its own name because the markup is generated in six places. */
.tiles { display: grid; gap: var(--gap-3); grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
.tile { background: var(--bg-panel); border: 1px solid var(--border-color); padding: var(--gap-3) var(--gap-4); }
.tile-value { font-size: 20px; font-weight: 600; font-variant-numeric: tabular-nums; }
.tile-label { margin-top: 2px; font-family: var(--font-display); font-size: 9px; letter-spacing: 0.8px; text-transform: uppercase; color: var(--text-muted); }
.tile-note { margin-top: 2px; font-size: 11px; color: var(--text-muted); }

/* Capacity meter. Three states, and the colour is the message. */
.meter-wrap { border: 1px solid var(--border-color); background: var(--bg-panel); padding: var(--gap-3) var(--gap-4); }
.meter-head { display: flex; justify-content: space-between; align-items: baseline; gap: var(--gap-3); }
.meter-title { font-family: var(--font-display); font-size: 9px; letter-spacing: 0.8px; text-transform: uppercase; color: var(--text-muted); }
.meter { position: relative; height: 8px; margin: var(--gap-2) 0; background: var(--bg-dark); border: 1px solid var(--border-color); }
.meter-fill { position: absolute; inset: 0 auto 0 0; background: var(--success); }
.meter-good .meter-fill { background: var(--success); }
.meter-warning .meter-fill { background: var(--warning); }
.meter-critical .meter-fill { background: var(--critical); }
.meter-foot { color: var(--text-muted); font-size: 11px; }

.badge { display: inline-flex; align-items: center; gap: 5px; font-size: 11px; }
.badge-good { color: var(--success); }
.badge-warning { color: var(--warning); }
.badge-critical { color: var(--critical); }
/* A glyph beside the colour, so the three states are distinguishable without
   relying on hue — the same reason the chart series are not tints of one hue. */
.badge-glyph { font-size: 10px; }

/* Blob size bars, drawn in the table itself. */
.barcell { min-width: 90px; }
.spark { position: relative; height: 6px; background: var(--bg-dark); border: 1px solid var(--border-color); }
.spark-wide { height: 8px; }
.spark-fill { position: absolute; inset: 0 auto 0 0; background: var(--series-1); }

.sec-head { display: flex; align-items: baseline; gap: var(--gap-2); margin-bottom: var(--gap-2); }
.sec-head .count { color: var(--text-muted); font-size: 12px; }
.sec-head .more { margin-left: auto; font-size: 12px; }

.digest, .mono { font-family: var(--font-body); }
td.name { color: var(--text-primary); }

/* Identity: what a digest is called, and what resolves to it.

   A tag is a chip and a label is plain text, because they are different kinds
   of claim. A chip reads as a token you can copy into a command — which is
   exactly what a tag is — while a description is prose and should not be
   dressed up as something clickable. The muted dash is the third state, and it
   has to be visible: an empty cell reads as a broken renderer rather than as
   "nothing is known about this". */
.tagchip { display: inline-block; margin-right: 6px; padding: 1px 6px; border: 1px solid var(--border-color); background: var(--bg-dark); font-size: 11px; color: var(--text-primary); }
.labelname { color: var(--text-primary); }
.muted { color: var(--text-muted); }
/* `pre-wrap`, because a description is the one field in this store that carries
   line breaks somebody typed on purpose. */
.description { white-space: pre-wrap; color: var(--text-secondary); max-width: 70ch; margin-bottom: var(--gap-3); }
td.num, .num, .r { text-align: right; font-variant-numeric: tabular-nums; }
.pin { color: var(--accent); }
.sub { color: var(--text-muted); font-size: 12px; margin: 0 0 var(--gap-4); }
.empty { color: var(--text-muted); padding: var(--gap-4) 0; border: 0; text-align: left; }
.empty code { color: var(--accent); }

/* The login card, the one page with no top bar. */
.login { border: 1px solid var(--border-color); background: var(--bg-panel); padding: var(--gap-5); }
.login h1 { margin-bottom: var(--gap-1); }
.login .err { color: var(--danger); margin-bottom: var(--gap-3); }
.login button { width: 100%; margin-top: var(--gap-3); background: var(--accent); border: 1px solid var(--accent); color: var(--bg-dark); font-weight: 600; padding: 7px 12px; cursor: pointer; }
.login button:hover { background: var(--accent-dim); border-color: var(--accent-dim); }
"#;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Dashboard errors render as HTML, never JSON — the format follows the
/// handler's return type, so a mismatch is impossible.
#[derive(Debug)]
pub struct WebError(crate::Error);

impl From<crate::Error> for WebError {
    fn from(e: crate::Error) -> Self {
        WebError(e)
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            crate::Error::NotFound(_) | crate::Error::TagNotFound(_) => StatusCode::NOT_FOUND,
            crate::Error::Digest(_) | crate::Error::TagName(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status.is_server_error() {
            tracing::error!(error = %self.0, "dashboard request failed");
        }
        let body = page_bare(
            &Shell::default(),
            "error",
            html! {
                div.login {
                    h1 { (status.as_u16()) }
                    p.sub { (self.0.to_string()) }
                    p { a.more href="/dashboard" { "← back to the dashboard" } }
                }
            },
        );
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::AdminAuth;

    /// A fresh store per test. The `TempDir` is returned, not dropped: tests run
    /// in parallel threads of one process, so anything keyed on the process id
    /// would have them deleting each other's store out from under themselves.
    fn state() -> (WebState, tempfile::TempDir) {
        let dir = match std::env::var_os("ART_TEST_DIR").map(std::path::PathBuf::from) {
            Some(b) => tempfile::tempdir_in(b).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let store = Store::open(&crate::Config {
            root: dir.path().join("store"),
            min_free_bytes: 0,
            gc_min_age: std::time::Duration::ZERO,
            heyvm_images_dir: std::path::PathBuf::from("/nonexistent"),
        })
        .unwrap();
        (
            WebState {
                store,
                auth: Some(Arc::new(AdminAuth::new("admin".into(), "pw".into()))),
                gate: false,
                ui: Default::default(),
            },
            dir,
        )
    }

    /// The shell these tests render against: default theme, nobody signed in
    /// by a gate, sign-out offered (the password dashboard's shape).
    fn test_shell() -> Shell {
        Shell {
            attrs: r#"data-theme="dark""#.into(),
            who: None,
            signout: true,
        }
    }

    fn usage(logical: u64, allocated: u64, avail: u64, total: u64) -> Usage {
        Usage {
            blobs: 1,
            logical,
            allocated,
            manifests: 0,
            tags: 0,
            fs_available: avail,
            fs_total: total,
        }
    }

    #[test]
    fn dedup_ratio_handles_an_empty_store() {
        // No division by zero on a store that has never been written to.
        assert_eq!(dedup_ratio(&usage(0, 0, 1, 2)), 1.0);
        assert!((dedup_ratio(&usage(1000, 100, 1, 2)) - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn capacity_meter_escalates_and_always_carries_text() {
        for (avail, total, level, word) in [
            (50u64, 100u64, "good", "healthy"),
            (10, 100, "warning", "low"),
            (2, 100, "critical", "critical"),
        ] {
            let html = capacity_meter(&usage(0, 0, avail, total)).into_string();
            assert!(html.contains(level), "expected {level} in {html}");
            // Status colour never stands alone: the word and the percentage are
            // what a colourblind or forced-colors reader relies on.
            assert!(html.contains(word), "missing status word {word}");
            assert!(html.contains("% used"), "missing written percentage");
            assert!(
                html.contains("aria-label"),
                "meter needs an accessible name"
            );
        }
    }

    #[test]
    fn capacity_meter_survives_a_zero_sized_filesystem() {
        let html = capacity_meter(&usage(0, 0, 0, 0)).into_string();
        assert!(html.contains("0% used"));
    }

    #[test]
    fn sparsity_bar_is_labelled_and_clamped() {
        let b = BlobInfo {
            digest: Digest::parse(&hex::encode([1u8; 32])).unwrap(),
            size: 1000,
            allocated: 100,
            nlink: 1,
            created: std::time::SystemTime::UNIX_EPOCH,
            deduped: false,
        };
        let html = sparsity_bar(&b, false).into_string();
        assert!(html.contains("aria-label"));
        assert!(html.contains("10%"));

        // A zero-length blob must not divide by zero or overflow the track.
        let empty = BlobInfo {
            size: 0,
            allocated: 0,
            ..b.clone()
        };
        let html = sparsity_bar(&empty, false).into_string();
        assert!(html.contains("width:1.0%"), "{html}");

        // Allocation above logical size (a dense small file with metadata
        // overhead) must clamp rather than run past 100%.
        let over = BlobInfo {
            size: 100,
            allocated: 4096,
            ..b.clone()
        };
        assert!(
            sparsity_bar(&over, false)
                .into_string()
                .contains("width:100.0%")
        );
    }

    #[test]
    fn login_page_has_no_external_assets() {
        let html = page_bare(&test_shell(), "sign in", login_body(false)).into_string();
        // The VM has no route to a CDN, so anything remote would not load. The
        // stylesheet and the theme script are this binary's own, at /__ui/ —
        // same origin, and the only script on the page.
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        assert!(!html.contains("src=\"//"));
        assert!(html.contains(r#"href="/__ui/heyo.css""#));
        assert!(html.contains(r#"src="/__ui/theme.js""#));
        assert!(html.contains("type=\"password\""));
        assert!(html.contains("autocomplete=\"current-password\""));
    }

    #[test]
    fn a_failed_login_does_not_say_which_field_was_wrong() {
        let html = page_bare(&test_shell(), "sign in", login_body(true)).into_string();
        assert!(html.contains("Incorrect username or password"));
        assert!(!html.to_lowercase().contains("no such user"));
        assert!(!html.to_lowercase().contains("wrong password"));
    }

    #[test]
    fn page_shell_marks_the_active_nav_item() {
        let html = page(&test_shell(), "overview", "/dashboard", html! {}).into_string();
        // The shared top bar marks the current page with `aria-current`, which
        // is also what the stylesheet selects on — one signal, read by both a
        // screen reader and the border under the tab.
        assert!(
            html.contains(r#"<a href="/dashboard" aria-current="page">Overview</a>"#),
            "{html}"
        );
        assert!(html.contains("/dashboard/blobs"));
        assert!(html.contains(r#"data-theme="dark""#));
    }

    /// Under an upstream gate the page shows who app-lb says is here and offers
    /// no sign-out — the session belongs to the gate, and a button here could
    /// not end it.
    #[test]
    fn a_gated_page_shows_the_forwarded_identity_and_no_signout() {
        let shell = Shell {
            attrs: r#"data-theme="dark""#.into(),
            who: Some("ops@example.com".into()),
            signout: false,
        };
        let html = page(&shell, "overview", "/dashboard", html! {}).into_string();
        assert!(html.contains("ops@example.com"));
        assert!(!html.contains("/logout"), "{html}");
    }

    /// Themes moved to the shared sheet, and this page must not re-declare
    /// them: a second palette here would win by specificity in one app and
    /// leave the other four looking different.
    #[test]
    fn the_local_stylesheet_declares_no_palette_of_its_own() {
        assert!(!STYLE.contains(":root"), "tokens belong in ui/heyo.css");
        assert!(!STYLE.contains("prefers-color-scheme"));
        // It reads the shared tokens rather than hard-coding hexes. A stray
        // `#rrggbb` here is a colour that will not follow the theme.
        for line in STYLE.lines() {
            let code = line.split("/*").next().unwrap_or("");
            assert!(
                !code.contains('#'),
                "hard-coded colour in the local sheet: {line}"
            );
        }
    }

    #[tokio::test]
    async fn overview_renders_on_an_empty_store() {
        let (st, _dir) = state();
        let html = overview(State(st), Default::default())
            .await
            .unwrap()
            .into_string();
        assert!(html.contains("No blobs yet"));
        assert!(html.contains("effective capacity"));
    }

    #[tokio::test]
    async fn blob_page_reports_what_references_a_blob() {
        let (st, _dir) = state();
        let blob = st.store.insert_bytes(b"referenced".to_vec()).await.unwrap();
        let m = Manifest::new(crate::manifest::KIND_GENERIC).with_entry(
            "rootfs.ext4",
            blob.digest.clone(),
            blob.size,
        );
        let md = st.store.put_manifest(&m).await.unwrap();
        st.store
            .set_tag(&TagName::parse("live").unwrap(), &md)
            .await
            .unwrap();

        let html = blob_page(State(st), Default::default(), Path(blob.digest.to_string()))
            .await
            .unwrap()
            .into_string();
        assert!(html.contains("rootfs.ext4"));
        assert!(html.contains(&short(&md)));
    }

    #[tokio::test]
    async fn an_unreferenced_blob_says_so() {
        let (st, _dir) = state();
        let blob = st.store.insert_bytes(b"orphan".to_vec()).await.unwrap();
        let html = blob_page(State(st), Default::default(), Path(blob.digest.to_string()))
            .await
            .unwrap()
            .into_string();
        assert!(html.contains("Nothing references this blob"));
        assert!(html.contains("eligible for collection"));
    }

    #[tokio::test]
    async fn a_bad_digest_renders_an_html_error_not_json() {
        let (st, _dir) = state();
        let resp = blob_page(State(st), Default::default(), Path("not-a-digest".into()))
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -- identity in the listings ------------------------------------------

    /// The complaint this feature answers: every listing was a column of hex.
    /// A row now leads with what the thing is, and the digest follows it.
    #[tokio::test]
    async fn a_listing_leads_with_what_the_thing_is() {
        let (st, _dir) = state();
        let blob = st.store.insert_bytes(b"rootfs".to_vec()).await.unwrap();
        st.store
            .set_tag(&TagName::parse("web-v2").unwrap(), &blob.digest)
            .await
            .unwrap();
        st.store
            .set_label(
                &blob.digest,
                &Label::new(Some("the web rootfs".into()), None).unwrap(),
            )
            .await
            .unwrap();

        let html = blobs_page(State(st), Default::default())
            .await
            .unwrap()
            .into_string();
        assert!(html.contains("the web rootfs"), "the label is missing");
        assert!(html.contains("web-v2"), "the tag is missing");
        // The identity column comes before the digest, which is the ordering
        // that makes the table scannable.
        let what = html.find("<th>What</th>").expect("a What column");
        let digest = html.find("<th>Digest</th>").expect("a Digest column");
        assert!(what < digest, "identity has to lead the row");
    }

    /// Nothing known about a blob is a *state*, and it has to look like one. An
    /// empty cell reads as a broken renderer.
    #[tokio::test]
    async fn an_unlabelled_blob_says_so_rather_than_showing_a_blank() {
        let (st, _dir) = state();
        st.store.insert_bytes(b"anonymous".to_vec()).await.unwrap();
        let html = blobs_page(State(st), Default::default())
            .await
            .unwrap()
            .into_string();
        assert!(html.contains(r#"<span class="muted">—</span>"#), "{html}");
    }

    /// A detail page is headed by what the thing is called, with the generic
    /// word demoted — the heading used to say "Blob" over a digest, which the
    /// reader already knew from the URL.
    #[tokio::test]
    async fn a_labelled_blob_page_is_headed_by_its_name() {
        let (st, _dir) = state();
        let blob = st.store.insert_bytes(b"rootfs".to_vec()).await.unwrap();
        st.store
            .set_label(
                &blob.digest,
                &Label::new(
                    Some("the web rootfs".into()),
                    Some("debian, plus the hermes agents".into()),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let html = blob_page(
            State(st.clone()),
            Default::default(),
            axum::extract::Path(blob.digest.to_string()),
        )
        .await
        .unwrap()
        .into_string();
        assert!(html.contains("<h2>the web rootfs</h2>"), "{html}");
        assert!(html.contains("debian, plus the hermes agents"));

        // An unlabelled one keeps the generic heading.
        let bare = st.store.insert_bytes(b"bare".to_vec()).await.unwrap();
        let html = blob_page(
            State(st),
            Default::default(),
            axum::extract::Path(bare.digest.to_string()),
        )
        .await
        .unwrap()
        .into_string();
        assert!(html.contains("<h2>Blob</h2>"), "{html}");
    }

    /// A one-line, name-less label is promoted into the heading; printing it
    /// again underneath reads as a rendering fault.
    #[tokio::test]
    async fn a_description_only_label_is_not_shown_twice() {
        let (st, _dir) = state();
        let blob = st.store.insert_bytes(b"x".to_vec()).await.unwrap();
        st.store
            .set_label(
                &blob.digest,
                &Label::new(None, Some("just the one line".into())).unwrap(),
            )
            .await
            .unwrap();

        let html = blob_page(
            State(st),
            Default::default(),
            axum::extract::Path(blob.digest.to_string()),
        )
        .await
        .unwrap()
        .into_string();
        assert_eq!(
            html.matches("just the one line").count(),
            1,
            "the description was promoted to the heading and printed again",
        );
    }

    /// Manifests get the same treatment, and a manifest's tags are shown on its
    /// own page — previously only a blob's were.
    #[tokio::test]
    async fn a_manifest_page_shows_its_tags_and_its_label() {
        let (st, _dir) = state();
        let blob = st.store.insert_bytes(b"entry".to_vec()).await.unwrap();
        let m = Manifest::new(crate::KIND_GENERIC).with_entry("f", blob.digest.clone(), blob.size);
        let md = st.store.put_manifest(&m).await.unwrap();
        st.store
            .set_tag(&TagName::parse("bundle-v1").unwrap(), &md)
            .await
            .unwrap();
        st.store
            .set_label(
                &md,
                &Label::new(Some("the nightly bundle".into()), None).unwrap(),
            )
            .await
            .unwrap();

        let html = manifest_page(
            State(st.clone()),
            Default::default(),
            axum::extract::Path(md.to_string()),
        )
        .await
        .unwrap()
        .into_string();
        assert!(html.contains("<h2>the nightly bundle</h2>"), "{html}");
        assert!(
            html.contains("bundle-v1"),
            "a manifest's tags belong on its page"
        );

        // And it appears in the listing with both.
        let html = manifests_page(State(st), Default::default())
            .await
            .unwrap()
            .into_string();
        assert!(html.contains("the nightly bundle"));
        assert!(html.contains("bundle-v1"));
    }

    /// The overview's tag table answers "what is this tag" as well as "what
    /// does it point at".
    #[tokio::test]
    async fn the_overview_tag_table_says_what_each_tag_is() {
        let (st, _dir) = state();
        let blob = st.store.insert_bytes(b"rootfs".to_vec()).await.unwrap();
        st.store
            .set_tag(&TagName::parse("web-v2").unwrap(), &blob.digest)
            .await
            .unwrap();
        st.store
            .set_label(
                &blob.digest,
                &Label::new(Some("the web rootfs".into()), None).unwrap(),
            )
            .await
            .unwrap();

        let html = overview(State(st), Default::default())
            .await
            .unwrap()
            .into_string();
        assert!(html.contains("What it is"));
        assert!(html.contains("the web rootfs"));
    }

    /// A label is attacker-supplied text rendered into HTML. maud escapes by
    /// construction; this is the regression test that says so out loud.
    #[tokio::test]
    async fn a_label_cannot_inject_markup() {
        let (st, _dir) = state();
        let blob = st.store.insert_bytes(b"x".to_vec()).await.unwrap();
        st.store
            .set_label(
                &blob.digest,
                &Label::new(
                    Some("<script>alert(1)</script>".into()),
                    Some("<img src=x onerror=alert(2)>".into()),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        for html in [
            blobs_page(State(st.clone()), Default::default())
                .await
                .unwrap()
                .into_string(),
            blob_page(
                State(st.clone()),
                Default::default(),
                axum::extract::Path(blob.digest.to_string()),
            )
            .await
            .unwrap()
            .into_string(),
        ] {
            assert!(!html.contains("<script>alert(1)</script>"), "{html}");
            assert!(!html.contains("<img src=x"), "{html}");
            assert!(
                html.contains("&lt;script&gt;"),
                "escaped rather than dropped"
            );
        }
    }
}
