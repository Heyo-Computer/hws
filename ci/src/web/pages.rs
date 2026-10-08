//! Server-rendered pages.
//!
//! maud rather than a runtime template engine, matching vault and artifacts. The
//! reason is not taste: a placeholder that never gets filled is a compile error
//! here, where app-lb's `include_str!` + `str::replace` approach needs a test
//! asserting no `{{` survives rendering.
//!
//! The look is the platform's, from `ui/heyo.css` — the same tokens the
//! marketing and retail sites use — served by *this binary* at `/__ui/`, not by
//! a CDN. That distinction is the one that matters: everything in this
//! ecosystem gets read over an SSH tunnel sooner or later, and a dashboard that
//! needs a third party is a dashboard that is blank exactly when someone is
//! debugging. What is left in `STYLE` below is only what is peculiar to this
//! app; anything a second app would want belongs in the shared file.

use crate::release::ReleaseRow;
use crate::runners::{Pool, Runner, RunnerSet, RunnerStatus, TunnelFailure};
use crate::store::{ArtifactRow, JobRow, Repo, RepoToken, Run, RunEvent, ServiceDeploymentRow, StepRow};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use std::collections::HashMap;
use std::time::Duration;

/// What is specific to `ci`, layered on `ui/heyo.css`.
///
/// Everything general — tokens, type, tables, buttons, forms, pills, banners —
/// comes from the shared sheet. This is the residue: the step accordion, the
/// job DAG, the repository cards, and the mapping from this app's status
/// vocabulary onto the shared pill colours.
const STYLE: &str = r#"
/* Page furniture. `main` is the shared `.wrap` by another name; ci's pages
   predate it and there are 26 of them, so the element is styled instead of
   every page being edited to add a class. */
main { max-width: 1200px; margin: 0 auto; padding: var(--gap-5) var(--gap-5) var(--gap-6); }
section { margin-bottom: var(--gap-6); }
h1.page { font-size: 15px; margin: 0 0 var(--gap-1); }
.sub { color: var(--text-muted); font-size: 12px; margin: calc(-1 * var(--gap-2)) 0 var(--gap-4); }

/* This app's status vocabulary, mapped onto the shared status colours. The
   names come from the database (`ci_job.status`, `ci_vm_pool.status`) and from
   heyvm's runner states, so they are mapped here rather than renamed at 40 call
   sites — and a status this list forgets still renders as a neutral pill rather
   than as nothing. */
.pill.online, .pill.success, .pill.ready, .pill.passed { border-color: var(--success); color: var(--success); }
.pill.stale, .pill.warn, .pill.submission_unknown { border-color: var(--warning); color: var(--warning); }
.pill.failure, .pill.orphaned, .pill.error, .pill.failed { border-color: var(--danger); color: var(--danger); }
.pill.running, .pill.building, .pill.submitting { border-color: var(--accent); color: var(--accent); }
.pill.offline, .pill.queued, .pill.pending, .pill.skipped, .pill.cancelled, .pill.draining {
  border-color: var(--border-color); color: var(--text-muted);
}

/* The step accordion on a job page. `details`/`summary` rather than a
   scripted toggle: it works with JavaScript off, it is keyboard-navigable for
   free, and `open` survives a page that re-renders under a live log stream. */
.step { border: 1px solid var(--border-color); margin-bottom: var(--gap-2); background: var(--bg-panel); }
.step > summary {
  display: flex; align-items: center; gap: var(--gap-2);
  padding: var(--gap-2) var(--gap-3); cursor: pointer; list-style: none; font-size: 12px;
}
.step > summary::-webkit-details-marker { display: none; }
.step > summary::before { content: "\25b8"; color: var(--text-muted); font-size: 10px; }
.step[open] > summary::before { content: "\25be"; }
.step .grow { flex: 1; }

/* Step output. The shared `.log` rules cover the body; these two are about
   living inside a `<details>` — flush to the summary above it, and saying so
   when a step produced nothing rather than collapsing to a 2px sliver. */
pre.log { margin: 0; border-top: 1px solid var(--border-color); border-left: 0; border-right: 0; border-bottom: 0; max-height: 32rem; }
pre.log:empty::after { content: "(no output)"; color: var(--text-muted); }

/* The job graph on a run page: one row per wave, jobs left to right. */
.dag { display: flex; flex-direction: column; gap: var(--gap-1); }
.dag .wave { display: flex; gap: var(--gap-2); flex-wrap: wrap; align-items: center; }
.dag .needs { color: var(--text-muted); font-size: 11px; }

/* A registered repository on /repos. */
.repo { border: 1px solid var(--border-color); background: var(--bg-panel); padding: var(--gap-3) var(--gap-4); margin-bottom: var(--gap-3); }
.repo h3 { margin: 0 0 2px; }
.repo .head { display: flex; align-items: baseline; gap: var(--gap-2); }
.repo .head form { margin-left: auto; }
/* Side-by-side buttons under a run's heading: cancel, run again, re-run failed. */
.actions { display: flex; gap: var(--gap-2); flex-wrap: wrap; align-items: center; }

/* A freshly minted token, shown exactly once. Dashed and in the warning colour
   because that is the point: this is the only time anyone will see it, and the
   border is the difference between a value you copy now and one you assume you
   can come back for. `user-select: all` makes it one click to take. */
.secret {
  margin: var(--gap-2) 0 0; padding: var(--gap-2) var(--gap-3);
  background: var(--bg-dark); border: 1px dashed var(--warning);
  font-size: 12px; white-space: pre-wrap; word-break: break-all; user-select: all;
}

/* A destructive control that should not look like a call to action — revoke,
   delete, disable. Invisible until hovered, then unmistakably red. */
button.quiet { background: none; border-color: transparent; color: var(--text-muted); }
button.quiet:hover { color: var(--danger); border-color: var(--border-color); background: none; }

/* `.notice` predates the shared `.banner` and means "this worked". Kept as an
   alias rather than renamed at its call sites. */
.notice { padding: var(--gap-3) var(--gap-4); margin-bottom: var(--gap-4);
  background: var(--bg-panel); border: 1px solid var(--border-accent);
  border-left: 3px solid var(--success); font-size: 12px; }
.banner { border-left-color: var(--danger); }

/* Forms on /repos are inline: label above field, wrapped in a row. */
form.row { display: flex; gap: var(--gap-2); flex-wrap: wrap; align-items: flex-end; }
form.row label { display: flex; flex-direction: column; gap: 2px; }
form.row input[type=text], form.row select { min-width: 16rem; }

.deployment-table { table-layout: fixed; width: 100%; }
.deployment-table td { overflow-wrap: anywhere; }
.deployment-table code { white-space: normal; }
.release-table { table-layout: fixed; width: 100%; }
.release-table th { width: 110px; }
.release-table td, .release-table code { overflow-wrap: anywhere; white-space: normal; }
@media (max-width: 900px) {
  .deployment-table, .deployment-table tbody { display: block; }
  .deployment-table thead { display: none; }
  .deployment-table tr { display: block; margin-bottom: var(--gap-3); border: 1px solid var(--border-color); }
  .deployment-table td { display: grid; grid-template-columns: 90px minmax(0, 1fr); gap: var(--gap-2); }
  .deployment-table td::before { content: attr(data-label); color: var(--text-muted); font-size: 11px; }
  .deployment-table td > div { min-width: 0; }
}
"#;

/// Everything the shell needs that is not the page itself.
///
/// One struct rather than three parameters threaded through seven page
/// functions, and it exists because the *theme* has to reach the `<html>` tag.
/// The alternative — reading the cookie in JavaScript on load — is a page that
/// flashes the wrong ground on every navigation, which is the one thing people
/// notice about a dashboard's theming.
pub struct Chrome<'a> {
    pub app_name: &'a str,
    /// The app-lb identity, when there is one. An app-token caller and an
    /// ungated deployment both render without it rather than inventing a user.
    pub who: Option<&'a str>,
    /// `data-theme="…" data-cookie-domain="…"`, already rendered by
    /// `heyo_ui::html_attrs` from the request's cookie and this instance's
    /// configuration. Owned, so a handler can build one and hand it to a page,
    /// an error renderer and a redirect target without threading a second
    /// lifetime through all three.
    pub html_attrs: String,
    /// Whose pages these are, and the URLs they link with. Every link and form
    /// on the pages a namespace can see is built through this, never written
    /// as a literal path.
    pub scope: Scope,
}

/// Which installation a page belongs to, and how its URLs are spelled.
///
/// The fleet's pages are served at this binary's root and link with plain
/// absolute paths, exactly as they always have. A namespace's pages are
/// served at `/ns/{ns}/` and reached two ways:
///
/// - **Through app-lb's plugin proxy**, which forwards `x-heyo-base:
///   /namespaces/{ns}/plugins/ci` and maps `{base}/ui/<tail>` to
///   `/ns/{ns}/<tail>` and `{base}/api/<x>` to `/ns/{ns}/api/<x>`. The browser
///   only ever sees app-lb's URLs, so that is what every link must be.
/// - **Directly**, with no base, where the native paths are the URLs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Scope {
    #[default]
    Fleet,
    Namespace {
        namespace: String,
        /// app-lb's base for this namespace's plugin, when the request came
        /// through it. Validated by the caller; see `ns::scope_for`.
        base: Option<String>,
    },
}

impl Scope {
    pub fn namespace(namespace: &str, base: Option<&str>) -> Self {
        Self::Namespace {
            namespace: namespace.to_string(),
            base: base.map(str::to_string),
        }
    }

    pub fn is_namespace(&self) -> bool {
        matches!(self, Self::Namespace { .. })
    }

    /// A page's URL, from its path within the dashboard (`"/"`, `"/repos"`,
    /// `"/runs/<id>"`).
    pub fn ui(&self, path: &str) -> String {
        match self {
            Self::Fleet => path.to_string(),
            Self::Namespace { base: Some(base), .. } => match path {
                "" | "/" => format!("{base}/ui"),
                p => format!("{base}/ui{p}"),
            },
            Self::Namespace { namespace, base: None } => match path {
                "" | "/" => format!("/ns/{namespace}/"),
                p => format!("/ns/{namespace}{p}"),
            },
        }
    }

    /// A machine route's URL — JSON or the log stream — from its path under
    /// `/api`.
    pub fn api(&self, path: &str) -> String {
        match self {
            Self::Fleet => format!("/api{path}"),
            Self::Namespace { base: Some(base), .. } => format!("{base}/api{path}"),
            Self::Namespace { namespace, base: None } => format!("/ns/{namespace}/api{path}"),
        }
    }

    /// Where the shared stylesheet, script and fonts are fetched from. A
    /// namespace serves its own copy under its prefix, so a proxied page never
    /// asks app-lb's root for anything.
    fn assets(&self) -> String {
        match self {
            Self::Fleet => crate::heyo_ui::ASSET_PREFIX.to_string(),
            scope => scope.ui(crate::heyo_ui::ASSET_PREFIX),
        }
    }
}

/// Chrome shared by every page.
///
/// `who` is the app-lb identity when there is one. An app-token caller and an
/// ungated deployment both render without it rather than inventing a user.
pub fn layout(chrome: &Chrome, current: &str, body: Markup) -> Markup {
    if chrome.scope.is_namespace() {
        return namespace_layout(chrome, current, body);
    }
    let nav: Vec<(&str, &str, bool)> = vec![
        ("Runs", "/", current == "runs"),
        ("Networks", "/networks", current == "networks"),
        ("Workflows", "/workflows", current == "workflows"),
        ("VMs", "/vms", current == "vms"),
        ("Repositories", "/repos", current == "repos"),
    ];
    html! {
        (DOCTYPE)
        // The attributes are rendered upstream and injected whole: maud escapes
        // an attribute *value*, and this is a run of several attributes.
        // `html_attrs` is built by the shared module from typed values, never
        // from anything a request supplied.
        (PreEscaped(format!("<html lang=\"en\" {}>", chrome.html_attrs)))
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (chrome.app_name) }
                (PreEscaped(crate::heyo_ui::head_tags()))
                style { (PreEscaped(STYLE)) }
            }
            body {
                (PreEscaped(crate::heyo_ui::topbar_html(chrome.app_name, &nav, chrome.who)))
                main { (body) }
            }
        (PreEscaped("</html>"))
    }
}

/// The shell for a namespace's pages.
///
/// Three tabs — Runs, Repositories, Workflows — because those are the only
/// pages a namespace has: networks, VMs, releases and maintenance are the
/// fleet's. The top bar is built here rather than by `heyo_ui::topbar_html`,
/// whose brand link is this binary's `/`; under the proxy that is app-lb's
/// root, not this namespace's runs.
///
/// Embedded in app-lb's plugin console, the page sits under app-lb's own
/// chrome, so a one-line script marks `<html>` with `embedded` before first
/// paint and the stylesheet hides this bar. Opened on its own, the bar stays.
fn namespace_layout(chrome: &Chrome, current: &str, body: Markup) -> Markup {
    let scope = &chrome.scope;
    let nav = [
        ("Runs", scope.ui("/"), current == "runs"),
        ("Repositories", scope.ui("/repos"), current == "repos"),
        ("Workflows", scope.ui("/workflows"), current == "workflows"),
    ];
    let assets = scope.assets();
    html! {
        (DOCTYPE)
        (PreEscaped(format!("<html lang=\"en\" {}>", chrome.html_attrs)))
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (chrome.app_name) }
                script { (PreEscaped(EMBEDDED_SCRIPT)) }
                link rel="stylesheet" href={ (assets) "heyo.css" };
                script defer src={ (assets) "theme.js" } {}
                style { (PreEscaped(STYLE)) (PreEscaped(".embedded .topbar { display: none; }")) }
            }
            body {
                header .topbar {
                    a .topbar-brand href=(scope.ui("/")) {
                        span { "heyo" }
                        span .topbar-app { (chrome.app_name) }
                    }
                    nav .topbar-nav {
                        @for (label, href, here) in &nav {
                            a href=(href) aria-current=[here.then_some("page")] { (label) }
                        }
                    }
                    div .topbar-right {
                        @if let Some(who) = chrome.who {
                            span .topbar-user title=(who) { (who) }
                        }
                        (PreEscaped(crate::heyo_ui::theme_toggle_html()))
                    }
                }
                main { (body) }
            }
        (PreEscaped("</html>"))
    }
}

/// Runs before the stylesheet applies, so an embedded page never flashes its
/// own top bar under app-lb's.
const EMBEDDED_SCRIPT: &str =
    "if (window.self !== window.top) document.documentElement.classList.add('embedded');";

fn status_pill(status: RunnerStatus) -> Markup {
    html! { span class={ "pill " (status.as_str()) } { (status.as_str()) } }
}

fn runner_rows(runners: &[Runner]) -> Markup {
    runner_rows_marking(runners, "", &QueueDepths::default(), &HashMap::new())
}

fn runner_rows_marking(
    runners: &[Runner],
    this_host: &str,
    depths: &QueueDepths,
    tunnel_failures: &HashMap<String, TunnelFailure>,
) -> Markup {
    html! {
        @for r in runners {
            tr {
                td {
                    (r.name)
                    // Which row is this machine, so "add this host" and the list
                    // are obviously about the same thing.
                    @if !this_host.is_empty() && r.id == this_host {
                        " " span .pill.queued { "this host" }
                    }
                }
                td .mono { (r.id) }
                td {
                    (status_pill(r.status))
                    // `Online` is the cloud's word, carried by the daemon's
                    // heartbeat; the tunnel is how jobs actually reach it, and
                    // the two can disagree. A row that says both is the only
                    // honest answer to "the tab says idle but every job fails".
                    @if let Some(failure) = tunnel_failures.get(&r.id) {
                        " " span .pill.failure title=(failure.reason) { "tunnel down" }
                        div .meta { (failure.ago()) ": " (failure.reason) }
                    }
                }
                td { (queue_cell(depths, &r.id, r.status.is_dispatchable())) }
                td .mono { (r.last_seen_at.as_deref().unwrap_or("—")) }
            }
        }
    }
}

fn runner_table(runners: &[Runner]) -> Markup {
    html! {
        div .scroll {
            table {
                thead { tr { th { "Name" } th { "Daemon" } th { "Status" } th { "Last seen" } } }
                tbody { (runner_rows(runners)) }
            }
        }
    }
}

/// One network and the hosts in it.
fn network_section(
    set: &RunnerSet,
    default_id: &str,
    this_host: &str,
    depths: &QueueDepths,
    tunnel_failures: &HashMap<String, TunnelFailure>,
) -> Markup {
    let joined = !this_host.is_empty() && set.runners.iter().any(|r| r.id == this_host);
    html! {
        div .repo {
            div .head {
                h3 { (set.network_name) }
                @if set.served {
                    span .pill.success { "serving" }
                } @else {
                    span .pill.cancelled { "not served" }
                }
                @if set.network_id == default_id {
                    span .pill.queued { "default" }
                }
                @if set.is_default {
                    span .meta { "heyvm default" }
                }
                // Joining is what makes a network usable from here at all: an
                // unserved network with no hosts is not something a job can be
                // pointed at, and `uses: default` needs this machine to be a
                // member of one.
                @if !this_host.is_empty() && !joined {
                    form method="post" action={ "/networks/" (set.network_id) "/join" } {
                        button type="submit" { "Add this host" }
                    }
                }
            }
            p .meta {
                code .mono { (set.network_id) }
                " · " (set.dispatchable().count()) " of " (set.runners.len())
                " host(s) can take work"
                @if set.served {
                    " · unpinned queue: "
                    (queue_cell(depths, &set.network_id, set.dispatchable().count() > 0))
                }
            }
            @if set.runners.is_empty() {
                p .empty {
                    "No host has joined this network. Add this machine with the button \
                     above, or on another machine run "
                    code .mono { "heyvmd" } " and then " code .mono { "heyvm network add-host" } "."
                }
            } @else {
                div .scroll {
                    table {
                        thead { tr {
                            th { "Name" } th { "Daemon" } th { "Status" }
                            th { "Queue" } th { "Last seen" }
                        } }
                        tbody { (runner_rows_marking(&set.runners, this_host, depths, tunnel_failures)) }
                    }
                }
            }
            @if !set.served {
                p .meta {
                    "This orchestrator does not take work for this network, so a repository \
                     assigned to it would have its submits refused. Add it to "
                    code .mono { "CI_NETWORK" } ", or set " code .mono { "CI_NETWORK=*" } "."
                }
            }
        }
    }
}

/// The outcome of an action, rendered on the response to the POST that did it.
#[derive(Default)]
pub struct Notice {
    pub ok: Option<String>,
    pub error: Option<String>,
}

impl Notice {
    pub fn done(message: impl Into<String>) -> Self {
        Self {
            ok: Some(message.into()),
            error: None,
        }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            ok: None,
            error: Some(message.into()),
        }
    }
}

/// A job id is `<run>.<job key>`; the run is already its own column here, so
/// only the key is worth the width.
fn short_job(job_id: &str) -> &str {
    job_id
        .rsplit_once('.')
        .map(|(_, key)| key)
        .unwrap_or(job_id)
}

/// `GET /vms` — the warm pool, and what is left over in it.
///
/// Two questions this has to answer, and the layout follows them. **Is reuse
/// The daemon's size classes, in order, as `heyvm resize --size-class` spells
/// them. Mirrors `SizeClass::ALL` in mvm-ctrl; the SDK enum has the same set
/// and the form value round-trips through it, so a name that is not here is
/// refused rather than guessed.
const SIZE_CLASSES: [&str; 6] = ["micro", "mini", "small", "medium", "large", "xlarge"];

/// What the Size cell says under the class the job asked for.
enum SizeVerdict {
    /// The daemon named the class asked for.
    AsDeclared(String),
    /// Less than asked for — the finding the cell exists for. The dispatcher
    /// refuses to start a build on such a VM (after one resize attempt), so
    /// this row is where somebody fixes it.
    TooSmall(String),
    /// More than asked for: a resize up from this page. Builds run on it.
    Larger(String),
    /// The daemon gave numbers but no class name (an explicitly sized VM, or
    /// a daemon that reports cpus and memory only).
    Unclassified(String),
    /// The daemon reported nothing about size: too old to be checked.
    Unreported,
    /// This app has not read the size yet (a row from before it did).
    Unread,
}

fn size_verdict(v: &crate::pool::PooledVmView) -> SizeVerdict {
    if v.observed_at.is_none() {
        return SizeVerdict::Unread;
    }
    if !v.observed.is_reported() {
        return SizeVerdict::Unreported;
    }
    let got = v.observed.label();
    let wanted = v
        .size_class
        .as_deref()
        .and_then(crate::vm::parse_size_class);
    match wanted {
        // Nothing declared, or a class this does not know: the reading is
        // shown, and there is nothing to hold it against.
        None => match v.observed.size_class {
            Some(_) => SizeVerdict::AsDeclared(got),
            None => SizeVerdict::Unclassified(got),
        },
        Some(wanted) => match v.observed.check(wanted) {
            crate::vm::SizeCheck::TooSmall => SizeVerdict::TooSmall(got),
            crate::vm::SizeCheck::Larger => SizeVerdict::Larger(got),
            crate::vm::SizeCheck::AsDeclared => SizeVerdict::AsDeclared(got),
            crate::vm::SizeCheck::Unreported => SizeVerdict::Unreported,
        },
    }
}

/// working**: rows are grouped by runner and fingerprint, because a pool that is
/// working shows one row per fingerprint per host and a pool that is not shows
/// several. **What is left over**: each row carries the outcome of the run that
/// last used it, so a machine a failed build left behind is visible rather than
/// inferred.
pub fn vms_page(
    chrome: &Chrome,
    vms: &[crate::pool::PooledVmView],
    images: &[crate::image::CatalogEntry],
    notice: &Notice,
) -> Markup {
    // A fingerprint appearing twice on one host means two VMs that could have
    // been one — the pool missing, not doing its job.
    //
    // One being *built* does not count towards that. A job builds precisely
    // because no idle VM matched, and the row disappears the moment the daemon
    // answers; flagging it would put a red "not reused" against every cold
    // start, which is the pool working rather than failing.
    let mut seen: std::collections::BTreeMap<(&str, &str), usize> =
        std::collections::BTreeMap::new();
    for v in vms.iter().filter(|v| v.status != "building") {
        *seen
            .entry((v.runner_hd_id.as_str(), v.fingerprint.as_str()))
            .or_default() += 1;
    }
    let idle_failed = vms
        .iter()
        .filter(|v| {
            v.status == "idle"
                && matches!(
                    v.last_run_status.as_deref(),
                    Some("failure") | Some("cancelled")
                )
        })
        .count();

    let body = html! {
        @if let Some(err) = &notice.error { div .banner { (err) } }
        @if let Some(ok) = &notice.ok { div .notice { (ok) } }

        section {
            h2 { "Warm VMs" }
            p .sub {
                "Every VM this orchestrator has pooled, on the hosts it serves. A job \
                 reuses one when its fingerprint matches — so two rows with the same \
                 fingerprint on the same host means reuse did not happen."
            }

            @if idle_failed > 0 {
                form method="post" action="/vms/cleanup-failed" {
                    button type="submit" {
                        "Destroy " (idle_failed) " idle VM(s) left by failed runs"
                    }
                }
            }

            @if vms.is_empty() {
                p .empty {
                    "Nothing is pooled. A VM appears here as soon as a job starts building \
                     one — if a run is going and this is empty, no job has reached a runner \
                     yet, and the run's own page says why."
                }
            } @else {
                div .scroll {
                    table {
                        thead { tr {
                            th { "VM" } th { "Host" } th { "Fingerprint" } th { "Size" } th { "Status" }
                            th { "Last run" } th { "Age" } th { "Last used" } th { }
                        } }
                        tbody {
                            @for v in vms {
                                tr {
                                    td .mono {
                                        // A VM being created has no id yet — the
                                        // daemon assigns one — so its row is
                                        // keyed on a placeholder that would be
                                        // meaningless here. Say what it is
                                        // instead.
                                        @if v.status == "building" {
                                            span .meta { "creating…" }
                                        } @else {
                                            (v.sandbox_id)
                                        }
                                        // What the VM was built for. Part of its
                                        // identity, and the first thing to look
                                        // at when a fingerprint is unfamiliar.
                                        @if !v.workflow_id.trim().is_empty() {
                                            span .meta { " " (v.workflow_id) }
                                        }
                                    }
                                    td .mono { (v.runner_hd_id) }
                                    td .mono {
                                        (short(&v.fingerprint, 12))
                                        @if seen.get(&(v.runner_hd_id.as_str(), v.fingerprint.as_str()))
                                            .copied().unwrap_or(0) > 1 {
                                            " " span .pill.failure { "not reused" }
                                        }
                                    }
                                    // Asked versus got. The first is the job's
                                    // `vm.size_class`; the second is what the
                                    // runner's daemon reported the last time
                                    // this app touched the VM — its own class
                                    // name and the cpus and memory behind it.
                                    // "Is this VM the size I declared" was
                                    // unanswerable from here before, and a
                                    // `xlarge` build on a `small` VM looks
                                    // exactly like a slow build.
                                    td .mono {
                                        @if let Some(size) = v.size_class.as_deref() {
                                            (size)
                                        } @else {
                                            span .meta { "—" }
                                        }
                                        @if v.status != "building" {
                                            br;
                                            @match size_verdict(v) {
                                                SizeVerdict::AsDeclared(got) => span .meta { "got " (got) },
                                                SizeVerdict::TooSmall(got) => span .pill.failure { "got " (got) " — too small" },
                                                SizeVerdict::Larger(got) => span .meta { "got " (got) " — larger" },
                                                SizeVerdict::Unclassified(got) => span .meta { "got " (got) },
                                                SizeVerdict::Unreported => span .meta { "size unreported" },
                                                SizeVerdict::Unread => span .meta { "size not read yet" },
                                            }
                                        }
                                    }
                                    td {
                                        (pill(&v.status))
                                        @if v.status == "claimed" && v.leased_by.is_some() {
                                            span .meta { " held" }
                                        }
                                    }
                                    td {
                                        @match (&v.last_run_id, &v.last_run_status) {
                                            (Some(id), Some(st)) => a href={ "/runs/" (id) } { (pill(st)) },
                                            _ => span .meta { "—" },
                                        }
                                        // Which job, so a VM can be traced to the
                                        // work that left it in this state.
                                        @if let Some(job) = v.claimed_by_job.as_ref().or(v.last_job.as_ref()) {
                                            span .meta { " " (short_job(job)) }
                                        }
                                    }
                                    td .mono {
                                        ((chrono::Utc::now() - v.created_at)
                                            .to_std()
                                            .map(human_duration)
                                            .unwrap_or_else(|_| "—".into()))
                                    }
                                    td .mono { (v.last_used_at.format("%Y-%m-%d %H:%M").to_string()) }
                                    td {
                                        // A claimed VM has a job on it; destroying
                                        // it would fail that build from underneath.
                                        // A building one has no sandbox to destroy
                                        // yet — the id in its row is a placeholder,
                                        // and the server refuses it for that reason.
                                        @if !matches!(v.status.as_str(), "claimed" | "building") {
                                            form method="post"
                                                 action={ "/vms/" (v.sandbox_id) "/destroy" } {
                                                button .quiet type="submit" { "Destroy" }
                                            }
                                        }
                                        // In place, cache kept: the only way to
                                        // change a pooled VM's size without a
                                        // cold build, since editing the class in
                                        // the workflow retires the VM. Idle only;
                                        // the daemon restarts the VM to apply it.
                                        @if v.status == "idle" {
                                            form method="post"
                                                 action={ "/vms/" (v.sandbox_id) "/resize" } {
                                                select name="size_class" {
                                                    @for class in SIZE_CLASSES {
                                                        option value=(class)
                                                            selected[v.observed.size_class.as_deref()
                                                                .or(v.size_class.as_deref()) == Some(class)] {
                                                            (class)
                                                        }
                                                    }
                                                }
                                                " "
                                                button .quiet type="submit" { "Resize" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        section {
            h2 { "Images" }
            p .sub {
                "Rootfs images built from a workflow's "
                code { "vm.build" }
                " Dockerfile, one row per host that has one. The name is the hash of the \
                 Dockerfile and its build context, so an unchanged one is reused and any \
                 change builds a new image. Unlike a warm VM these survive a reboot, and \
                 nothing sweeps them — remove one on the host to force a rebuild."
            }
            @if images.is_empty() {
                p .empty {
                    "No image has been built. A workflow with a "
                    code { "vm.build" }
                    " block builds one the first time it runs on a host."
                }
            } @else {
                div .scroll {
                    table {
                        thead { tr {
                            th { "Image" } th { "Host" } th { "Status" } th { "Workflow" }
                            th { "Size" } th { "Built" }
                        } }
                        tbody {
                            @for i in images {
                                tr {
                                    td .mono { (i.name) }
                                    td .mono { (i.runner_hd_id) }
                                    td {
                                        (pill(&i.status))
                                        // The reason belongs next to the status:
                                        // a failed build is the one row on this
                                        // page somebody has to act on.
                                        @if let Some(err) = &i.error {
                                            div .meta { (err) }
                                        }
                                    }
                                    td .mono { (i.workflow_id) }
                                    td .mono {
                                        @if i.size_bytes > 0 {
                                            (human_bytes(i.size_bytes))
                                        } @else {
                                            span .meta { "—" }
                                        }
                                    }
                                    td .mono {
                                        @match &i.ready_at {
                                            Some(t) => (t.format("%Y-%m-%d %H:%M").to_string()),
                                            None => (format!(
                                                "building for {}",
                                                (chrono::Utc::now() - i.created_at)
                                                    .to_std()
                                                    .map(human_duration)
                                                    .unwrap_or_else(|_| "—".into())
                                            )),
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    layout(chrome, "vms", body)
}

/// Queue depth per route, keyed by network id or runner id.
///
/// A missing key is "not read"; a present `None` is **no consumer bound**, which
/// is a different and much more interesting thing.
#[derive(Default)]
pub struct QueueDepths {
    pub by_route: std::collections::HashMap<String, Option<crate::bus::QueueDepth>>,
    pub error: Option<String>,
}

/// The gauge, and the warning that replaces it when nothing is listening.
fn queue_cell(depths: &QueueDepths, key: &str, dispatchable: bool) -> Markup {
    html! {
        @match depths.by_route.get(key) {
            // The state a stuck run looks like: work routed here and nothing
            // bound to read it. Consumers are only created for online hosts, so
            // this is expected on an offline one and alarming on a live one.
            Some(None) => {
                @if dispatchable {
                    span .pill.failure { "no consumer" }
                } @else {
                    span .meta { "no consumer" }
                }
            }
            Some(Some(d)) if d.is_empty() => span .meta { "idle" },
            Some(Some(d)) => {
                span .mono {
                    (d.waiting) " queued"
                    @if d.in_flight > 0 { ", " (d.in_flight) " running" }
                }
            }
            None => span .meta { "—" },
        }
    }
}

/// `GET /networks` — every network on the account, the hosts in each, and which
/// of them this orchestrator builds for.
pub fn networks_page(
    chrome: &Chrome,
    pool: &Pool,
    depths: &QueueDepths,
    tunnel_failures: &HashMap<String, TunnelFailure>,
    notice: &Notice,
) -> Markup {
    let served = pool.served().count();
    let body = html! {
        @if let Some(err) = &notice.error {
            div .banner { (err) }
        }
        @if let Some(ok) = &notice.ok {
            div .notice { (ok) }
        }
        @if let Some(err) = &pool.last_error {
            div .banner {
                strong { "The runner pool is stale. " }
                (err)
            }
        }
        @if let Some(err) = &depths.error {
            div .banner {
                strong { "Queue depths are unavailable. " }
                (err)
            }
        }

        // `uses: default` is the one form that needs this host to be somewhere,
        // so when it is not identifiable at all that is worth saying before the
        // list rather than leaving every join button mysteriously absent.
        @if pool.default_node_id.is_empty() {
            div .banner {
                strong { "This machine's daemon could not be identified. " }
                "So " code .mono { "uses: default" } " is refused, and there is no host \
                 to add to a network from here. Set " code .mono { "CI_DEFAULT_NODE" }
                " to its daemon id or name — heyvmd reports its own id only when \
                 BACKEND_SERVER_ID is set in its environment."
            }
        }

        section {
            h2 { "Networks" }
            p .sub {
                "Every heyvm network on this account. " (served) " of " (pool.networks.len())
                " are served by this orchestrator — a job may only run in one that is, and a \
                 repository is assigned one on "
                a href="/repos" { "Repositories" } "."
            }
            @if pool.networks.is_empty() {
                p .empty {
                    "This account has no network. Create one with "
                    code .mono { "heyvm network create" } ", then join a host to it with "
                    code .mono { "heyvm network add-host" } "."
                }
            }
            @for set in &pool.networks {
                (network_section(set, &pool.default_network_id, &pool.default_node_id, depths, tunnel_failures))
            }
        }

        // Shown because "my machine isn't in the list" is otherwise a dead end:
        // a registered daemon that never joined a network looks identical to one
        // that was never registered at all.
        @if !pool.unjoined.is_empty() {
            section {
                h2 { "Registered but in no network" }
                p .sub {
                    "These daemons belong to this account but have joined no network at all, \
                     so nothing can dispatch to them. Add one with "
                    code .mono { "heyvm network add-host" } "."
                }
                (runner_table(&pool.unjoined))
            }
        }
    };
    layout(chrome, "networks", body)
}

#[cfg(test)]
mod tests {
    /// The shell every page test renders against: this app, nobody signed in,
    /// the default theme and a host-only cookie. Tests that care about the
    /// signed-in name use [`chrome_as`].
    fn chrome() -> Chrome<'static> {
        Chrome {
            app_name: "ci",
            who: None,
            html_attrs: r#"data-theme="dark""#.into(),
            scope: Scope::Fleet,
        }
    }

    fn chrome_as(who: &str) -> Chrome<'_> {
        Chrome {
            app_name: "ci",
            who: Some(who),
            html_attrs: r#"data-theme="dark""#.into(),
            scope: Scope::Fleet,
        }
    }

    use super::*;

    pub(super) fn runner(id: &str, name: &str, status: RunnerStatus) -> Runner {
        Runner {
            id: id.into(),
            name: name.into(),
            status,
            last_seen_at: Some("2026-08-03T22:00:00Z".into()),
        }
    }

    pub(super) fn populated() -> Pool {
        Pool {
            networks: vec![
                RunnerSet {
                    network_id: "net-1".into(),
                    network_name: "prod-runners".into(),
                    is_default: true,
                    served: true,
                    runners: vec![
                        runner("hd-1", "bigbox", RunnerStatus::Online),
                        runner("hd-2", "oldbox", RunnerStatus::Stale),
                    ],
                },
                RunnerSet {
                    network_id: "net-2".into(),
                    network_name: "lab".into(),
                    is_default: false,
                    served: false,
                    runners: vec![runner("hd-3", "benchbox", RunnerStatus::Online)],
                },
            ],
            unjoined: vec![runner("hd-9", "laptop", RunnerStatus::Online)],
            last_error: None,
            default_network_id: "net-1".into(),
            default_node_id: String::new(),
        }
    }

    #[test]
    fn the_page_lists_every_network_and_its_runners() {
        let html = networks_page(
            &chrome_as("Sam Currie"),
            &populated(),
            &QueueDepths::default(),
            &HashMap::new(),
            &Notice::default(),
        )
        .into_string();
        assert!(html.contains("prod-runners"));
        assert!(html.contains("lab"), "an unserved network is still listed");
        assert!(html.contains("bigbox"));
        assert!(html.contains("benchbox"));
        assert!(html.contains("hd-1"));
        assert!(html.contains(r#"class="pill online""#));
        assert!(html.contains(r#"class="pill stale""#));
        assert!(html.contains("1 of 2 host(s) can take work"));
        assert!(html.contains("Sam Currie"));
    }

    /// A runner the cloud calls Online but whose tunnel carries nothing shows
    /// both facts on one row — the exact disagreement that used to be
    /// invisible while jobs burned their retries.
    #[test]
    fn a_dead_tunnel_is_shown_next_to_an_online_status() {
        let mut failures = HashMap::new();
        failures.insert(
            "hd-1".to_string(),
            crate::runners::TunnelFailure {
                reason: "the tunnel carried no reply to a probe request: timeout".into(),
                at: std::time::Instant::now(),
            },
        );
        let html = networks_page(
            &chrome(),
            &populated(),
            &QueueDepths::default(),
            &failures,
            &Notice::default(),
        )
        .into_string();
        assert!(html.contains("tunnel down"), "{html}");
        assert!(html.contains("carried no reply"));
    }

    /// The distinction the whole page turns on: a network this instance builds
    /// for, versus one that merely exists.
    #[test]
    fn served_and_unserved_networks_are_told_apart_with_the_fix_named() {
        let html = networks_page(
            &chrome(),
            &populated(),
            &QueueDepths::default(),
            &HashMap::new(),
            &Notice::default(),
        )
        .into_string();
        assert!(html.contains("serving"));
        assert!(html.contains("not served"));
        assert!(html.contains("CI_NETWORK"), "and what to do about it");
    }

    /// An unjoined daemon is the single most common "why is nothing running"
    /// cause, so the page must name it and the command that fixes it.
    #[test]
    fn unjoined_daemons_get_their_own_section_naming_the_fix() {
        let html = networks_page(
            &chrome(),
            &populated(),
            &QueueDepths::default(),
            &HashMap::new(),
            &Notice::default(),
        )
        .into_string();
        assert!(html.contains("Registered but in no network"));
        assert!(html.contains("laptop"));
        assert!(html.contains("heyvm network add-host"));
    }

    #[test]
    fn an_empty_account_explains_how_to_add_a_network() {
        let html = networks_page(
            &chrome(),
            &Pool::default(),
            &QueueDepths::default(),
            &HashMap::new(),
            &Notice::default(),
        )
        .into_string();
        assert!(html.contains("heyvm network create"));
        assert!(!html.contains("Registered but in no network"));
    }

    /// A refresh failure must not render as an empty-but-healthy pool.
    #[test]
    fn a_stale_snapshot_says_so() {
        let mut pool = populated();
        pool.last_error = Some("heyvm control plane: GET /networks: timeout".into());
        let html = networks_page(
            &chrome(),
            &pool,
            &QueueDepths::default(),
            &HashMap::new(),
            &Notice::default(),
        )
        .into_string();
        assert!(html.contains("The runner pool is stale"));
        assert!(html.contains("GET /networks: timeout"));
    }

    /// An anonymous request (app-token, or no gate) must not render a user chip
    /// — "a token is not a person".
    #[test]
    fn an_anonymous_request_renders_no_identity() {
        let html = networks_page(
            &chrome(),
            &populated(),
            &QueueDepths::default(),
            &HashMap::new(),
            &Notice::default(),
        )
        .into_string();
        assert!(!html.contains(r#"class="who""#));
    }

    fn pooled(
        sandbox: &str,
        runner: &str,
        fingerprint: &str,
        status: &str,
        run_status: Option<&str>,
    ) -> crate::pool::PooledVmView {
        crate::pool::PooledVmView {
            sandbox_id: sandbox.into(),
            runner_hd_id: runner.into(),
            fingerprint: fingerprint.into(),
            workflow_id: "build".into(),
            size_class: Some("large".into()),
            observed: crate::vm::VmSize {
                size_class: Some("large".into()),
                cpus: Some(4),
                memory: Some(8 * 1024 * 1024 * 1024),
            },
            observed_at: Some(chrono::Utc::now()),
            status: status.into(),
            claimed_by_job: None,
            last_job: Some("run.build".into()),
            last_run_id: run_status.map(|_| "019fca648a6e-00000000".to_string()),
            last_run_status: run_status.map(str::to_string),
            leased_by: None,
            created_at: chrono::Utc::now(),
            last_used_at: chrono::Utc::now(),
        }
    }

    /// The size cell says what the daemon gave, and flags it when that is not
    /// what the job asked for — the finding the cell exists to surface.
    #[test]
    fn a_vm_that_is_not_the_size_it_asked_for_is_flagged() {
        let mut small = pooled("sb-small", "hd-1", "fp-a", "idle", Some("success"));
        small.size_class = Some("xlarge".into());
        small.observed = crate::vm::VmSize {
            size_class: Some("small".into()),
            cpus: Some(1),
            memory: Some(2 * 1024 * 1024 * 1024),
        };
        let mut unread = pooled("sb-old", "hd-1", "fp-b", "idle", Some("success"));
        unread.observed_at = None;
        let mut mute = pooled("sb-mute", "hd-1", "fp-c", "idle", Some("success"));
        mute.observed = crate::vm::VmSize::default();

        let html =
            vms_page(&chrome(), &[small, unread, mute], &[], &Notice::default()).into_string();
        assert!(html.contains("got small (1 CPU, 2 GB)"), "{html}");
        assert!(html.contains("size not read yet"), "{html}");
        assert!(html.contains("size unreported"), "{html}");
        // The as-declared fixture from `pooled` is never flagged.
        let fine = pooled("sb-fine", "hd-1", "fp-d", "idle", Some("success"));
        let html = vms_page(&chrome(), &[fine], &[], &Notice::default()).into_string();
        assert!(html.contains("got large (4 CPU, 8 GB)"), "{html}");
        assert!(!html.contains("pill failure\">got"), "{html}");
        // Idle rows offer a resize; the form speaks the daemon's class names.
        assert!(html.contains("/vms/sb-fine/resize"), "{html}");
        assert!(html.contains(r#"option value="xlarge""#), "{html}");
    }

    /// The two questions the page exists to answer.
    #[test]
    fn the_vms_page_shows_reuse_and_what_failed_runs_left_behind() {
        let vms = [
            pooled("sb-1", "hd-1", "fp-aaaa", "idle", Some("success")),
            // Same host, same fingerprint: two VMs where one would have done.
            pooled("sb-2", "hd-1", "fp-aaaa", "idle", Some("failure")),
            pooled("sb-3", "hd-1", "fp-bbbb", "claimed", Some("running")),
        ];
        let html = vms_page(&chrome(), &vms, &[], &Notice::default()).into_string();

        assert!(
            html.contains("not reused"),
            "a repeated fingerprint is flagged"
        );
        assert!(html.contains("Destroy 1 idle VM(s) left by failed runs"));
        // A claimed VM must not be offered for destruction — that would fail a
        // live build from underneath.
        assert!(html.contains(r#"action="/vms/sb-1/destroy""#));
        assert!(!html.contains(r#"action="/vms/sb-3/destroy""#), "{html}");
    }

    /// The gap this page had: a job spends minutes dialling a runner and booting
    /// a VM before there is anything to pool, and for the whole of it the page
    /// said "Nothing is pooled" — which reads as nothing happening, and is
    /// exactly what a *failing* VM creation looks like too.
    #[test]
    fn a_vm_that_is_being_created_is_shown_while_it_is_being_created() {
        let building = pooled(
            &crate::pool::Pool::building_id("019fca648a6e-00000001.build"),
            "hd-1",
            "fp-cccc",
            "building",
            None,
        );
        let html = vms_page(&chrome(), &[building], &[], &Notice::default()).into_string();

        assert!(!html.contains("Nothing is pooled"), "{html}");
        assert!(html.contains("creating…"), "{html}");
        assert!(html.contains(r#"class="pill building""#), "{html}");
        // The placeholder key is not a sandbox id and must never be shown as
        // one, nor offered for destruction — there is nothing there to destroy.
        assert!(!html.contains("building-019fca648a6e"), "{html}");
        assert!(!html.contains("/destroy"), "{html}");
    }

    /// A cold start is the pool working, not failing: there was no idle VM to
    /// match, which is why one is being built. Flagging it would put a red mark
    /// on every first run of a workflow.
    #[test]
    fn building_alongside_a_warm_vm_is_not_a_failure_to_reuse() {
        let vms = [
            pooled("sb-1", "hd-1", "fp-aaaa", "claimed", Some("running")),
            pooled(
                &crate::pool::Pool::building_id("job-2"),
                "hd-1",
                "fp-aaaa",
                "building",
                None,
            ),
        ];
        let html = vms_page(&chrome(), &vms, &[], &Notice::default()).into_string();
        assert!(!html.contains("not reused"), "{html}");
    }

    fn image(name: &str, status: &str, error: Option<&str>) -> crate::image::CatalogEntry {
        crate::image::CatalogEntry {
            name: name.into(),
            runner_hd_id: "hd-1".into(),
            status: status.into(),
            workflow_id: "build".into(),
            built_by_job: None,
            size_bytes: if status == "ready" { 6_442_450_944 } else { 0 },
            error: error.map(str::to_string),
            created_at: chrono::Utc::now(),
            ready_at: (status == "ready").then(chrono::Utc::now),
        }
    }

    /// The image catalog is the answer to "why did this job not start" when the
    /// Dockerfile is what is broken, so a failed build has to carry its reason.
    #[test]
    fn the_image_catalog_shows_what_is_built_building_and_broken() {
        let images = [
            image("ci-img-aaaaaaaaaaaa", "ready", None),
            image("ci-img-bbbbbbbbbbbb", "building", None),
            image("ci-img-cccccccccccc", "failed", Some("apt-get exited 100")),
        ];
        let html = vms_page(&chrome(), &[], &images, &Notice::default()).into_string();

        assert!(!html.contains("No image has been built"), "{html}");
        assert!(html.contains("ci-img-aaaaaaaaaaaa"));
        assert!(
            html.contains("6.0 GiB"),
            "a ready image reports its size: {html}"
        );
        assert!(html.contains("building for"), "{html}");
        assert!(
            html.contains("apt-get exited 100"),
            "a failed build must say why: {html}"
        );

        // And with nothing built, the page says how one comes to exist rather
        // than showing an empty table.
        let html = vms_page(&chrome(), &[], &[], &Notice::default()).into_string();
        assert!(html.contains("No image has been built"), "{html}");
        assert!(html.contains("vm.build"), "{html}");
    }

    /// With nothing left over there is nothing to sweep, so the bulk action is
    /// absent rather than a button that reports doing nothing.
    #[test]
    fn a_healthy_pool_offers_no_cleanup() {
        let vms = [pooled("sb-1", "hd-1", "fp-aaaa", "idle", Some("success"))];
        let html = vms_page(&chrome(), &vms, &[], &Notice::default()).into_string();
        assert!(!html.contains("cleanup-failed"), "{html}");
        assert!(!html.contains("not reused"));

        let html = vms_page(&chrome(), &[], &[], &Notice::default()).into_string();
        assert!(html.contains("Nothing is pooled"));
    }

    /// The gauge exists for one diagnostic above all: work routed to a subject
    /// nothing reads. That is what a stuck run looks like, and it must be
    /// legible at a glance rather than inferred from a queue that never drains.
    #[test]
    fn a_route_with_no_consumer_is_called_out_on_a_live_host() {
        use crate::bus::QueueDepth;
        let mut depths = QueueDepths::default();
        // hd-1 is online in the fixture, so nothing consuming its queue is wrong.
        depths.by_route.insert("hd-1".into(), None);
        depths.by_route.insert(
            "net-1".into(),
            Some(QueueDepth {
                waiting: 3,
                in_flight: 1,
            }),
        );

        let html = networks_page(
            &chrome(),
            &populated(),
            &depths,
            &HashMap::new(),
            &Notice::default(),
        )
        .into_string();
        assert!(html.contains("no consumer"), "{html}");
        assert!(
            html.contains(r#"class="pill failure""#),
            "flagged, not muted"
        );
        assert!(html.contains("3 queued"));
        assert!(html.contains("1 running"));
    }

    /// An offline host with no consumer is expected — consumers are only bound
    /// for online hosts — so it is stated, not alarmed about.
    #[test]
    fn an_offline_host_without_a_consumer_is_not_alarming() {
        use crate::bus::QueueDepth;
        let mut depths = QueueDepths::default();
        // hd-2 is Stale in the fixture.
        depths.by_route.insert("hd-2".into(), None);
        depths.by_route.insert(
            "hd-1".into(),
            Some(QueueDepth {
                waiting: 0,
                in_flight: 0,
            }),
        );

        let html = networks_page(
            &chrome(),
            &populated(),
            &depths,
            &HashMap::new(),
            &Notice::default(),
        )
        .into_string();
        assert!(html.contains("no consumer"));
        assert!(html.contains("idle"), "an empty live queue reads as idle");
    }

    /// NATS being unreachable is not an idle queue, and must not render as one.
    #[test]
    fn an_unreadable_queue_says_so_rather_than_showing_zeroes() {
        let depths = QueueDepths {
            error: Some("could not reach NATS".into()),
            ..QueueDepths::default()
        };
        let html = networks_page(
            &chrome(),
            &populated(),
            &depths,
            &HashMap::new(),
            &Notice::default(),
        )
        .into_string();
        assert!(html.contains("Queue depths are unavailable"), "{html}");
        assert!(html.contains("could not reach NATS"));
    }

    /// The join button is offered only where it would do something: a network
    /// this host is not already in.
    #[test]
    fn joining_is_offered_for_networks_this_host_is_not_in() {
        let mut pool = populated();
        pool.default_node_id = "hd-1".into(); // already a member of net-1
        let html = networks_page(
            &chrome(),
            &pool,
            &QueueDepths::default(),
            &HashMap::new(),
            &Notice::default(),
        )
        .into_string();

        assert!(
            !html.contains(r#"action="/networks/net-1/join""#),
            "already a member; the button would be a no-op: {html}"
        );
        assert!(
            html.contains(r#"action="/networks/net-2/join""#),
            "not a member of lab, so it should be offered: {html}"
        );
        assert!(html.contains("this host"), "the row is marked");
    }

    /// With no identifiable daemon there is no host to add, so the page says
    /// which variable fixes it instead of rendering buttons that cannot work.
    #[test]
    fn an_unidentifiable_host_explains_itself_and_offers_no_join() {
        let mut pool = populated();
        pool.default_node_id = String::new();
        let html = networks_page(
            &chrome(),
            &pool,
            &QueueDepths::default(),
            &HashMap::new(),
            &Notice::default(),
        )
        .into_string();

        assert!(html.contains("CI_DEFAULT_NODE"), "{html}");
        assert!(!html.contains("/join"), "no button without a host: {html}");
    }

    #[test]
    fn a_notice_renders_above_the_networks() {
        let html = networks_page(
            &chrome(),
            &populated(),
            &QueueDepths::default(),
            &HashMap::new(),
            &Notice::done("This host is now a member of lab."),
        )
        .into_string();
        assert!(html.contains("This host is now a member of lab."));

        let html = networks_page(
            &chrome(),
            &populated(),
            &QueueDepths::default(),
            &HashMap::new(),
            &Notice::failed("nope"),
        )
        .into_string();
        assert!(html.contains("nope"));
    }

    /// maud escapes by construction; this pins it, because runner names come
    /// from a daemon's self-reported hostname.
    #[test]
    fn a_hostile_runner_name_is_escaped() {
        let mut pool = populated();
        pool.networks[0].runners[0].name = "<script>alert(1)</script>".into();
        let html = networks_page(
            &chrome(),
            &pool,
            &QueueDepths::default(),
            &HashMap::new(),
            &Notice::default(),
        )
        .into_string();
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}

// ---- shared bits --------------------------------------------------------

/// A status pill for a run, job or step. All three vocabularies overlap and the
/// stylesheet colours them the same way, so one helper is honest here.
fn pill(status: &str) -> Markup {
    html! { span class={ "pill " (status) } { (status) } }
}

/// `1m 04s`, or `4.2s`. Deliberately coarse: nobody reads a build duration to
/// the millisecond, and a stable width keeps a table from jittering as it
/// refreshes.
pub fn human_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else if secs > 0 {
        format!("{}.{}s", secs, d.subsec_millis() / 100)
    } else {
        format!("{}ms", d.as_millis())
    }
}

fn short(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// `refs/heads/main` reads as `main`; anything else is left alone so a tag or a
/// raw sha is still recognisable.
fn short_ref(git_ref: &str) -> &str {
    git_ref.strip_prefix("refs/heads/").unwrap_or(git_ref)
}

// ---- runs list ----------------------------------------------------------

/// `GET /` — recent runs.
pub fn runs_page(
    chrome: &Chrome,
    runs: &[Run],
    repos: &[Repo],
    repo_filter: Option<&str>,
) -> Markup {
    runs_page_with_namespaces(chrome, runs, repos, repo_filter, &[], None)
}

/// [`runs_page`], with the fleet's view of tenant namespaces.
///
/// `namespaces` is every namespace that has a run. While it is empty the page
/// is exactly what it was before namespaces existed; once one has run, the
/// table grows a Namespace column and the filter a namespace picker, where
/// `-` means the fleet's own runs.
pub fn runs_page_with_namespaces(
    chrome: &Chrome,
    runs: &[Run],
    repos: &[Repo],
    repo_filter: Option<&str>,
    namespaces: &[String],
    namespace_filter: Option<&str>,
) -> Markup {
    let tenants = !namespaces.is_empty();
    // The filter's label, resolved from the registrations rather than the runs:
    // a filter that matches no runs still has a name to show.
    let filter_name = repo_filter
        .and_then(|id| repos.iter().find(|rp| rp.id == id))
        .map(|rp| rp.name.as_str());
    let body = html! {
        section {
            h2 { "Runs" }
            // Present only once something is registered — on a fresh install
            // the empty-state text below already points at /repos, and a
            // dropdown with no options is furniture.
            @if !repos.is_empty() || tenants {
                form .row method="get" action=(chrome.scope.ui("/")) {
                    @if !repos.is_empty() {
                        select name="repo" {
                            option value="" selected[repo_filter.is_none()] { "All repositories" }
                            @for rp in repos {
                                option value=(rp.id) selected[repo_filter == Some(rp.id.as_str())] {
                                    (rp.name)
                                }
                            }
                        }
                    }
                    @if tenants {
                        select name="namespace" {
                            option value="" selected[namespace_filter.is_none()] { "All namespaces" }
                            option value="-" selected[namespace_filter == Some("")] { "Fleet only" }
                            @for ns in namespaces {
                                option value=(ns) selected[namespace_filter == Some(ns.as_str())] { (ns) }
                            }
                        }
                    }
                    button type="submit" { "Filter" }
                }
            }
            @if runs.is_empty() {
                @if repo_filter.is_some() {
                    p .empty {
                        "No runs for "
                        @if let Some(name) = filter_name { strong { (name) } }
                        @else { "that repository" }
                        " yet. "
                        a href=(chrome.scope.ui("/")) { "Show all runs" } "."
                    }
                } @else {
                    p .empty {
                        "Nothing has been submitted yet. Register a repository on "
                        a href=(chrome.scope.ui("/repos")) { "Repositories" }
                        " for a token, then from a clone with "
                        code .mono { ".ci/workflows/*.yml" } " run " code .mono { "git submit" } "."
                    }
                }
            } @else {
                div .scroll {
                    table {
                        thead { tr {
                            th { "Workflow" } th { "Repository" }
                            @if tenants { th { "Namespace" } }
                            th { "Ref" } th { "Commit" }
                            th { "Status" } th { "Duration" } th { "Started" } th { "By" }
                        } }
                        tbody {
                            @for r in runs {
                                tr .link {
                                    td { a .row href=(chrome.scope.ui(&format!("/runs/{}", r.id))) {
                                        (r.workflow_name
                                            .as_deref()
                                            .filter(|n| !n.trim().is_empty())
                                            .unwrap_or_else(|| workflow_label(&r.workflow_id)))
                                    } }
                                    // A link that applies the filter, so the
                                    // column is also the affordance — no one
                                    // has to find the dropdown to use it. A
                                    // run without a registration (a shared-
                                    // secret submit) has nothing to filter by.
                                    td { @match (&r.repo_id, &r.repo_name) {
                                        (Some(id), Some(name)) => {
                                            a href={ (chrome.scope.ui("/")) "?repo=" (id) } { (name) }
                                        }
                                        _ => { "—" }
                                    } }
                                    @if tenants {
                                        td { @if r.namespace.is_empty() { span .meta { "fleet" } } @else {
                                            a href={ (chrome.scope.ui("/")) "?namespace=" (r.namespace) } { (r.namespace) }
                                        } }
                                    }
                                    td { (short_ref(&r.git_ref)) }
                                    td .mono { (short(&r.sha, 12)) }
                                    td { (pill(&r.status)) }
                                    td { (r.duration().map(human_duration).unwrap_or_else(|| "—".into())) }
                                    td .mono { (r.created_at.format("%Y-%m-%d %H:%M").to_string()) }
                                    td { (r.actor_email.as_deref().unwrap_or("—")) }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    layout(chrome, "runs", body)
}

// ---- run detail ---------------------------------------------------------

/// `GET /runs/{id}` — one run's jobs, in dependency order, plus its artifacts.
#[cfg(test)]
pub fn run_page(
    chrome: &Chrome,
    run: &Run,
    reruns: &[Run],
    jobs: &[JobRow],
    artifacts: &[ArtifactRow],
    vm_logs: &[(String, Option<String>)],
    retention_days: Option<u64>,
) -> Markup {
    run_page_with_deployments(
        chrome,
        run,
        reruns,
        jobs,
        artifacts,
        vm_logs,
        None,
        &[],
        &[],
        None,
        false,
        retention_days,
    )
}

pub fn run_page_with_deployments(
    chrome: &Chrome,
    run: &Run,
    reruns: &[Run],
    jobs: &[JobRow],
    artifacts: &[ArtifactRow],
    vm_logs: &[(String, Option<String>)],
    release: Option<&ReleaseRow>,
    deployments: &[ServiceDeploymentRow],
    events: &[RunEvent],
    event_before: Option<i64>,
    events_have_more: bool,
    retention_days: Option<u64>,
) -> Markup {
    let body = html! {
        section {
            h1 .page {
                (run.workflow_name
                    .as_deref()
                    .filter(|n| !n.trim().is_empty())
                    .unwrap_or_else(|| workflow_label(&run.workflow_id)))
                " " (pill(&run.status))
            }
            p .meta {
                code .mono { (short(&run.sha, 12)) } " on " code .mono { (short_ref(&run.git_ref)) }
                @if let Some(by) = &run.actor_email { " · " (by) }
                @if let Some(d) = run.duration() { " · " (human_duration(d)) }
                " · " code .mono { (run.workflow_path) }
            }
            // Lineage, both ways: what this run re-plays, and what re-played it.
            @if let Some(of) = &run.rerun_of {
                p .meta {
                    "Re-run of " a href=(chrome.scope.ui(&format!("/runs/{}", of))) { code .mono { (of) } }
                    @if jobs.iter().any(|j| j.carried_from.is_some()) {
                        " — failed jobs only; the rest were carried over"
                    }
                }
            }
            @if !reruns.is_empty() {
                p .meta {
                    "Re-run as "
                    @for (i, r) in reruns.iter().enumerate() {
                        @if i > 0 { ", " }
                        a href=(chrome.scope.ui(&format!("/runs/{}", r.id))) { code .mono { (r.id) } } " " (pill(&r.status))
                    }
                }
            }
            @if let Some(err) = &run.error {
                div .banner { (err) }
            }
            // Offered only while there is something to stop. A finished run
            // would get a button that reports having done nothing.
            @if !matches!(run.status.as_str(), "success" | "failure" | "cancelled") {
                form method="post" action=(chrome.scope.ui(&format!("/runs/{}/cancel", run.id))) {
                    button type="submit" { "Cancel this run" }
                }
                p .meta {
                    "Queued jobs are dropped and running ones stop after their current \
                     step — a step already executing cannot be aborted."
                }
            } @else {
                // A finished run can be run again from the source its submit
                // sent. "Re-run failed jobs" is the one people reach for, so
                // it is not offered on a run with nothing failed to re-run.
                div .actions {
                    form method="post" action=(chrome.scope.ui(&format!("/runs/{}/rerun", run.id))) {
                        button type="submit" { "Run again" }
                    }
                    @if run.status != "success" {
                        form method="post" action=(chrome.scope.ui(&format!("/runs/{}/rerun-failed", run.id))) {
                            button type="submit" { "Re-run failed jobs" }
                        }
                    }
                }
                p .meta {
                    "A re-run is a new run of this commit from the source this submit sent; \
                     trigger filters do not apply, as with `git submit --only`. Re-running \
                     failed jobs carries every job that succeeded over as finished, with its \
                     outputs, and schedules the rest afresh — on the warm VM, where a build \
                     that timed out picks up its cache."
                }
            }
        }

        section {
            h2 { "Jobs" }
            @if jobs.is_empty() {
                p .empty { "This run planned no jobs." }
            } @else {
                div .scroll {
                    table {
                        thead { tr {
                            th { "Job" } th { "Status" } th { "Runner" }
                            th { "VM" } th { "Needs" } th { "Queued" } th { "Duration" }
                        } }
                        tbody {
                            @for j in jobs {
                                tr .link {
                                    td { a .row href=(chrome.scope.ui(&format!("/runs/{}/jobs/{}", run.id, j.job_key))) {
                                        (j.display)
                                    } }
                                    td {
                                        (pill(&j.status))
                                        @if j.carried_from.is_some() {
                                            " " span .meta { "carried over" }
                                        }
                                    }
                                    td { (j.runner_hd_id.as_deref().unwrap_or("—")) }
                                    td .mono { (j.sandbox_id.as_deref().unwrap_or("—")) }
                                    td .mono { (job_needs(j)) }
                                    td { (job_queue_wait(j)) }
                                    td { (job_duration(j)) }
                                }
                            }
                        }
                    }
                }
                @for j in jobs {
                    @if let Some(err) = &j.error {
                        div .banner { strong { (j.display) ": " } (err) }
                    }
                }
            }
        }

        @if let Some(release) = release {
            section {
                h2 { "Release" }
                p {
                    (pill(&release.status))
                    @if release.status == "unknown" {
                        " Publication outcome is unknown; this does not mean the release was published."
                    }
                }
                div .scroll {
                    table .release-table {
                        tbody {
                            tr { th { "Source SHA" } td { code .mono { (release.prepared.source_sha) } } }
                            tr { th { "Release SHA" } td { code .mono { (release.prepared.release_sha) } } }
                            tr { th { "Branch" } td { code .mono { (release.prepared.git_ref) } } }
                            tr { th { "Versions" } td {
                                @if let Some(versions) = release.prepared.versions.as_object() {
                                    @for (name, version) in versions {
                                        div { code .mono { (name) } ": " code .mono {
                                            (version.as_str().map(str::to_owned).unwrap_or_else(|| version.to_string()))
                                        } }
                                    }
                                }
                            } }
                        }
                    }
                }
                @if let Some(error) = &release.error {
                    div .banner { (error) }
                }
            }
        }

        // A namespace run cannot deploy, so the section would only ever say
        // so; the fleet's pages keep it.
        @if !chrome.scope.is_namespace() {
        section id="deployments" {
            h2 { "Deployments" }
            p .sub { "Service deployments requested by this CI run. Unknown submissions are not automatically resubmitted." }
            @if deployments.is_empty() {
                p .empty { "This run requested no service deployments." }
            } @else {
                div .scroll {
                    table .deployment-table {
                        thead { tr {
                            th { "Service" } th { "Operation ID" } th { "Revision" }
                            th { "Status" } th { "Phase" } th { "Message / error" }
                            th { "Updated" }
                        } }
                        tbody {
                            @for deployment in deployments {
                                tr {
                                    td data-label="Service" { div { (deployment.service_id) } }
                                    td .mono data-label="Operation ID" { div { (deployment.id) } }
                                    td data-label="Revision" { div {
                                        code .mono { (deployment.sha) }
                                        br;
                                        code .mono { (deployment.git_ref) }
                                    } }
                                    td data-label="Status" { div { (pill(&deployment.status)) } }
                                    td data-label="Phase" { div { (deployment.phase.as_deref().unwrap_or("—")) } }
                                    td data-label="Message / error" { div {
                                        @if let Some(message) = &deployment.message {
                                            div { (message) }
                                        }
                                        @if let Some(error) = &deployment.error {
                                            div .error { (error) }
                                        }
                                        @if deployment.message.is_none() && deployment.error.is_none() {
                                            "—"
                                        }
                                    } }
                                    td .mono data-label="Updated" { div { (deployment.updated_at.format("%Y-%m-%d %H:%M:%S UTC")) } }
                                }
                            }
                        }
                    }
                }
            }
        }
        }

        section id="events" {
            h2 { "Event timeline" }
            p .sub { "Durable run transitions and their publication state. This history is informational and separate from release and deployment actions." }
            @if events.is_empty() {
                p .empty { "No events on this page." }
            } @else {
                div .scroll {
                    table {
                        thead { tr {
                            th { "Revision / time" } th { "Event" } th { "Target" }
                            th { "Status" } th { "Transition error" } th { "Publication" }
                        } }
                        tbody {
                            @for event in events {
                                tr {
                                    td { code .mono { "#" (event.revision) } br; (event.transitioned_at.format("%Y-%m-%d %H:%M:%S UTC")) }
                                    td {
                                        code .mono { (event.event_type) }
                                        details { summary { "Payload" } pre { (serde_json::to_string_pretty(&event.payload).unwrap_or_else(|_| event.payload.to_string())) } }
                                    }
                                    td {
                                        @if let Some(job) = &event.job_key { div { "Job: " code .mono { (job) } } }
                                        @if let Some(step) = &event.step_id { div { "Step: " code .mono { (step) } } }
                                        @if event.job_key.is_none() && event.step_id.is_none() { "Run" }
                                    }
                                    td { (pill(&event.status)) }
                                    td { (event.error.as_deref().unwrap_or("—")) }
                                    td {
                                        @if let Some(published_at) = event.published_at {
                                            span .pill.success { "published" }
                                            div .meta { (published_at.format("%Y-%m-%d %H:%M:%S UTC")) }
                                        } @else if event.last_error.is_some() {
                                            span .pill.failure { "publication failed" }
                                        } @else {
                                            span .pill.pending { "unpublished" }
                                        }
                                        div .meta { (event.attempts) " attempt" @if event.attempts != 1 { "s" } }
                                        @if let Some(error) = &event.last_error { div .error { (error) } }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div .actions {
                @if event_before.is_some() {
                    a href={ (chrome.scope.ui(&format!("/runs/{}", run.id))) "#events" } { "Newest events" }
                }
                @if events_have_more {
                    @if let Some(last) = events.last() {
                        a href={ (chrome.scope.ui(&format!("/runs/{}", run.id))) "?events_before=" (last.revision) "#events" } { "Older events" }
                    }
                }
            }
        }

        // The VM's own console, captured when each job released its machine.
        // On the run page rather than only the job page because "the VM never
        // came up" is a property of the run somebody is looking at, and it is
        // the one failure with no step log to read.
        @if !vm_logs.is_empty() {
            section {
                h2 { "VM logs" }
                p .sub {
                    "Each job's machine, as its daemon saw it — boot and console output, \
                     captured before the VM was released."
                    @if let Some(days) = retention_days {
                        " Discarded after " (days) " day" (if days == 1 { "" } else { "s" }) "."
                    }
                }
                @for (job_key, log) in vm_logs {
                    details .step {
                        summary {
                            span .grow { (job_key) }
                            @if log.is_none() {
                                span .meta { "no longer retained" }
                            }
                        }
                        @match log {
                            Some(text) => pre .log { (text) },
                            // A job whose log has aged out is different from one
                            // that never had a VM, and the row says which.
                            None => p .empty {
                                "This log has been discarded. Step results are kept; \
                                 only the bytes age out."
                            },
                        }
                    }
                }
            }
        }

        @if !artifacts.is_empty() {
            section {
                h2 { "Artifacts" }
                div .scroll {
                    table {
                        thead { tr { th { "Name" } th { "Sink" } th { "Size" } th { "Location" } th { "Public link" } } }
                        tbody {
                            @for a in artifacts {
                                tr {
                                    td { (a.name) }
                                    td { (a.sink) }
                                    td { (human_bytes(a.size_bytes)) }
                                    td .mono { (a.uri) }
                                    // The one thing a person comes to this
                                    // table for when the upload was public:
                                    // the URL, as a link, ready to copy.
                                    td .mono {
                                        @match &a.public_url {
                                            Some(url) => a href=(url) { (url) },
                                            None => "—",
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    layout(chrome, "runs", body)
}

/// `needs:` comes out of the stored plan rather than a column, because it is a
/// property of the plan and duplicating it into the row would let the two drift.
fn job_needs(j: &JobRow) -> String {
    let needs = j
        .plan
        .get("needs")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    if needs.is_empty() {
        "—".to_string()
    } else {
        needs
    }
}

/// How long the job waited on the queue before being claimed — or has waited
/// so far. Shown beside the duration because the two clocks are separate: a job
/// behind a busy runner accrues queue time, not run time, and its timeouts
/// have not started.
fn job_queue_wait(j: &JobRow) -> String {
    j.queue_wait()
        .map(human_duration)
        .unwrap_or_else(|| "—".into())
}

fn job_duration(j: &JobRow) -> String {
    let Some(start) = j.started_at else {
        return "—".to_string();
    };
    let end = j.finished_at.unwrap_or_else(chrono::Utc::now);
    (end - start)
        .to_std()
        .ok()
        .map(human_duration)
        .unwrap_or_else(|| "—".into())
}

fn human_bytes(n: i64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

// ---- job detail ---------------------------------------------------------

/// `GET /runs/{id}/jobs/{key}` — one job's steps, with logs.
///
/// `stream_token` is `Some` while the job could still produce output. The page
/// mints it server-side and hands it to a fifteen-line `EventSource` handler;
/// see [`crate::web::stream`] for why the stream needs its own credential.
pub fn job_page(
    chrome: &Chrome,
    run: &Run,
    job: &JobRow,
    steps: &[(StepRow, String)],
    stream_token: Option<&str>,
) -> Markup {
    let body = html! {
        section {
            h1 .page { (job.display) " " (pill(&job.status)) }
            p .meta {
                a href=(chrome.scope.ui(&format!("/runs/{}", run.id))) { (run.workflow_name.as_deref().unwrap_or(&run.workflow_id)) }
                " · " code .mono { (short(&run.sha, 12)) }
                @if let Some(r) = &job.runner_hd_id { " · runner " code .mono { (r) } }
                @if let Some(s) = &job.sandbox_id { " · vm " code .mono { (s) } }
                @if let Some(f) = &job.fingerprint { " · fingerprint " code .mono { (f) } }
                @if job.attempt > 1 { " · attempt " (job.attempt) }
            }
            @if let Some(err) = &job.error {
                div .banner { (err) }
            }
            // A carried-over job has no steps of its own, and a success with
            // an empty step list would read as a job that did nothing.
            @if let Some(from) = &job.carried_from {
                div .notice {
                    "This job did not run here. Its result and outputs were carried over from "
                    a href=(chrome.scope.ui(&format!("/runs/{}/jobs/{}", from, job.job_key))) {
                        "the same job in run " code .mono { (from) }
                    }
                    " when that run's failed jobs were re-run; the steps are there."
                }
            }
        }

        section id="steps" {
            @if steps.is_empty() {
                p .empty { "This job has not started any steps yet." }
            }
            @for (step, log) in steps {
                // Open by default when the step failed, because that is the one
                // the reader came for.
                details .step open[step.status == "failure"] {
                    summary {
                        span .grow { (step.name) }
                        @if let Some(code) = step.exit_code {
                            @if code != 0 { span .meta { "exit " (code) } }
                        }
                        span .meta { (step_duration(step)) }
                        (pill(&step.status))
                    }
                    pre .log id={ "log-" (step.idx) } { (log) }
                }
            }
        }

        @if let Some(token) = stream_token {
            (live_log_script(&chrome.scope.api(&format!(
                "/stream/{}/{}?token={}",
                urlencode(&run.id),
                urlencode(&job.job_key),
                urlencode(token)
            ))))
        }
    };
    layout(chrome, "runs", body)
}

fn step_duration(s: &StepRow) -> String {
    let Some(start) = s.started_at else {
        return String::new();
    };
    let end = s.finished_at.unwrap_or_else(chrono::Utc::now);
    (end - start)
        .to_std()
        .ok()
        .map(human_duration)
        .unwrap_or_default()
}

/// The only script on any page.
///
/// Deliberately not htmx or any other library: every page here has to work over
/// an SSH tunnel with no CDN, so an external asset would make the dashboard
/// blank exactly when someone is debugging. The server sends rendered HTML
/// fragments; this appends them and reloads once the job is done, so the final
/// state is the server's rendering rather than one assembled in the browser.
///
/// `url` is the stream's address as the browser must ask for it, built by the
/// caller from its [`Scope`] — behind app-lb's namespace proxy that is not the
/// path this binary routes it on.
fn live_log_script(url: &str) -> Markup {
    let js = format!(
        r#"
(function () {{
  var es = new EventSource({url});
  es.addEventListener("log", function (e) {{
    var d = JSON.parse(e.data);
    var pre = document.getElementById("log-" + d.idx);
    if (!pre) {{ location.reload(); return; }}
    var atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 32;
    pre.appendChild(document.createTextNode(d.text));
    if (atBottom) pre.scrollTop = pre.scrollHeight;
  }});
  es.addEventListener("done", function () {{ es.close(); location.reload(); }});
  es.onerror = function () {{ es.close(); }};
}})();
"#,
        url = serde_json::to_string(&url).unwrap_or_else(|_| "\"\"".into())
    );
    html! { script { (PreEscaped(js)) } }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---- workflows ----------------------------------------------------------

/// A workflow's display name.
///
/// `workflow_id` comes from the submit payload and can legitimately be empty —
/// a caller that sends neither `workflowId` nor a repository name. Rendering an
/// empty cell makes that look like a broken row rather than a missing field.
fn workflow_label(id: &str) -> &str {
    if id.trim().is_empty() {
        "(unnamed)"
    } else {
        id
    }
}

/// `GET /workflows` — what this installation knows how to build.
pub fn workflows_page(
    chrome: &Chrome,
    workflows: &[(String, Option<Run>)],
    pattern: &str,
) -> Markup {
    let body = html! {
        section {
            h2 { "Workflows" }
            p .sub {
                "Discovered from submitted trees matching " code .mono { (pattern) } "."
            }
            @if workflows.is_empty() {
                p .empty {
                    "Nothing has been submitted yet, so no workflow is known. Run "
                    code .mono { "git submit" } " from a repository that has one."
                }
            } @else {
                div .scroll {
                    table {
                        thead { tr { th { "Workflow" } th { "Last run" } th { "When" } } }
                        tbody {
                            @for (id, last) in workflows {
                                tr {
                                    td { (workflow_label(id)) }
                                    td {
                                        @match last {
                                            Some(r) => a href=(chrome.scope.ui(&format!("/runs/{}", r.id))) { (pill(&r.status)) },
                                            None => span .meta { "never" },
                                        }
                                    }
                                    td .mono {
                                        @match last {
                                            Some(r) => (r.created_at.format("%Y-%m-%d %H:%M").to_string()),
                                            None => ("—".to_string()),
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    layout(chrome, "workflows", body)
}

// ---- registered repositories --------------------------------------------

/// One repository as the page needs it: the registration, its tokens, and how
/// its last build went.
pub struct RepoView {
    pub repo: Repo,
    pub tokens: Vec<RepoToken>,
    pub last_run: Option<Run>,
}

/// What just happened, rendered on the response to the POST that did it.
#[derive(Default)]
pub struct RepoFlash {
    pub ok: Option<String>,
    pub error: Option<String>,
    /// `(repository name, the token)`. Shown exactly once — nothing stores the
    /// plaintext, so there is no route that could show it again.
    pub token: Option<(String, String)>,
}

impl RepoFlash {
    pub fn done(message: impl Into<String>) -> Self {
        Self {
            ok: Some(message.into()),
            ..Self::default()
        }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            error: Some(message.into()),
            ..Self::default()
        }
    }

    pub fn minted(repo_name: String, token: String) -> Self {
        Self {
            token: Some((repo_name, token)),
            ..Self::default()
        }
    }
}

/// The two lines that point a clone at this installation.
fn setup_lines(endpoint: &str, token: &str) -> String {
    format!("git config ci.endpoint {endpoint}\ngit config ci.token {token}")
}

/// A network picker listing only what this orchestrator can dispatch to.
///
/// Unserved networks are deliberately absent rather than shown-and-disabled: a
/// choice that cannot be made is not a choice, and `/networks` is where the
/// question "why is that one missing" is answered properly.
fn network_options(pool: &Pool, selected: Option<&str>) -> Markup {
    let default_name = pool
        .default_set()
        .map(|s| s.network_name.as_str())
        .unwrap_or("none resolved");
    html! {
        option value="" selected[selected.is_none()] {
            "Default (" (default_name) ")"
        }
        @for set in pool.served() {
            option value=(set.network_name)
                   selected[selected.is_some_and(|s| set.matches(s))] {
                (set.network_name)
                @if set.dispatchable().count() == 0 { " — no host online" }
            }
        }
    }
}

fn token_rows(scope: &Scope, tokens: &[RepoToken]) -> Markup {
    token_rows_managed(scope, tokens, true)
}

/// [`token_rows`], with the revoke button only for a viewer who may use it.
fn token_rows_managed(scope: &Scope, tokens: &[RepoToken], can_manage: bool) -> Markup {
    html! {
        @for t in tokens {
            tr {
                // The key id, not the token: it is the half that is not secret,
                // and it is what a submit's log line names.
                td .mono { (t.id) }
                td {
                    (if t.name.is_empty() { "—" } else { t.name.as_str() })
                    @if let Some(by) = &t.created_email {
                        span .meta { " · minted by " (by) }
                    }
                }
                td .mono { (t.created_at.format("%Y-%m-%d").to_string()) }
                td .mono {
                    @match t.last_used_at {
                        Some(at) => (at.format("%Y-%m-%d %H:%M").to_string()),
                        None => ("never".to_string()),
                    }
                }
                td {
                    @if t.is_active() {
                        span .pill.success { "active" }
                    } @else {
                        span .pill.cancelled { "revoked" }
                    }
                }
                td {
                    @if can_manage && t.is_active() {
                        form method="post"
                             action=(scope.ui(&format!("/repos/{}/tokens/{}/revoke", t.repo_id, t.id))) {
                            button .quiet type="submit" { "Revoke" }
                        }
                    }
                }
            }
        }
    }
}

/// `GET /repos` — what may submit, and with what.
pub fn repos_page(
    chrome: &Chrome,
    repos: &[RepoView],
    endpoint: &str,
    require_token: bool,
    pool: &Pool,
    flash: &RepoFlash,
) -> Markup {
    let body = html! {
        @if let Some(err) = &flash.error {
            div .banner { (err) }
        }
        @if let Some(ok) = &flash.ok {
            div .notice { (ok) }
        }
        @if let Some((repo_name, token)) = &flash.token {
            div .notice {
                strong { "A new submit token for " (repo_name) "." }
                " This is the only time it is shown — nothing here stores it, only its \
                 digest. Run these two lines in a clone of that repository:"
                pre .secret { (setup_lines(endpoint, token)) }
                "Then " code .mono { "git submit" } " builds it."
            }
        }

        section {
            h2 { "Repositories" }
            p .sub {
                "A registered repository submits with its own tokens, each revocable on \
                 its own. The token says which repository a submit is for, so one \
                 repository's credential cannot start a build of another's workflow."
                @if require_token {
                    " " strong { "CI_REQUIRE_REPO_TOKEN is set" }
                    ", so a token is the only way to submit."
                } @else {
                    " The shared " code .mono { "CI_WEBHOOK_SECRET" } " still submits too, \
                      until CI_REQUIRE_REPO_TOKEN is set."
                }
            }

            form .row method="post" action=(chrome.scope.ui("/repos")) {
                label {
                    "Clone URL"
                    input type="text" name="url" required
                          placeholder="git@github.com:me/app.git";
                }
                label {
                    "Name (optional)"
                    input type="text" name="name" placeholder="me/app";
                }
                label {
                    "Workflow path (optional)"
                    input type="text" name="workflow_path" placeholder=".ci/workflows/*.yml";
                }
                label {
                    "Network"
                    select name="network" { (network_options(pool, None)) }
                }
                button type="submit" { "Register" }
            }
        }

        section {
            @if repos.is_empty() {
                p .empty {
                    "No repository is registered. Until one is, " code .mono { "git submit" }
                    " signs with the installation-wide " code .mono { "CI_WEBHOOK_SECRET" }
                    " — a credential that cannot be revoked for one repository and cannot \
                      say which repository is submitting."
                }
            }
            @for view in repos {
                div .repo {
                    div .head {
                        h3 { (view.repo.name) }
                        @if !view.repo.enabled {
                            span .pill.cancelled { "paused" }
                        }
                        @if let Some(run) = &view.last_run {
                            a href=(chrome.scope.ui(&format!("/runs/{}", run.id))) { (pill(&run.status)) }
                        }
                        form method="post" action=(chrome.scope.ui(&format!("/repos/{}/enabled", view.repo.id))) {
                            input type="hidden" name="enabled"
                                  value=(if view.repo.enabled { "false" } else { "true" });
                            button .quiet type="submit" {
                                (if view.repo.enabled { "Pause" } else { "Resume" })
                            }
                        }
                        form method="post" action=(chrome.scope.ui(&format!("/repos/{}/delete", view.repo.id))) {
                            button .quiet type="submit" { "Remove" }
                        }
                    }
                    p .meta {
                        code .mono { (view.repo.url) }
                        @if let Some(path) = &view.repo.workflow_path {
                            " · " code .mono { (path) }
                        }
                        @if let Some(by) = &view.repo.created_email {
                            " · registered by " (by)
                        }
                        " · " (view.repo.created_at.format("%Y-%m-%d").to_string())
                    }

                    form .row method="post" action=(chrome.scope.ui(&format!("/repos/{}/network", view.repo.id))) {
                        label {
                            "Builds run in"
                            select name="network" {
                                (network_options(pool, view.repo.network.as_deref()))
                            }
                        }
                        button type="submit" { "Assign" }
                    }
                    // A network that was assigned and has since been renamed,
                    // deleted or dropped from CI_NETWORK. Left visible rather
                    // than silently reset, because the fix is a decision.
                    @if let Some(assigned) = &view.repo.network
                        && !pool.served().any(|s| s.matches(assigned))
                    {
                        p .meta {
                            "⚠ Assigned to " code .mono { (assigned) }
                            ", which this orchestrator does not serve — submits for this \
                             repository are refused until it is reassigned or added to "
                            code .mono { "CI_NETWORK" } "."
                        }
                    }

                    @if view.tokens.is_empty() {
                        p .empty { "No token yet, so nothing can submit as this repository." }
                    } @else {
                        div .scroll {
                            table {
                                thead { tr {
                                    th { "Key" } th { "For" } th { "Created" }
                                    th { "Last used" } th { "Status" } th { }
                                } }
                                tbody { (token_rows(&chrome.scope, &view.tokens)) }
                            }
                        }
                    }

                    form .row method="post" action=(chrome.scope.ui(&format!("/repos/{}/tokens", view.repo.id))) {
                        label {
                            "New token for"
                            input type="text" name="name" placeholder="sam's laptop";
                        }
                        button type="submit" { "Mint" }
                    }
                }
            }
        }
    };
    layout(chrome, "repos", body)
}

/// `GET /ns/{ns}/repos` — a namespace's registrations.
///
/// The fleet page's shape without its operator controls: there is no network
/// picker, because a namespace's builds run where app-lb's plugin config says
/// (`network`, shown read-only), and no mention of the shared webhook secret,
/// which can never submit into a namespace. `can_manage` is the forwarded
/// `x-heyo-actor-admin`; without it the forms are not offered, and the routes
/// refuse them anyway.
pub fn namespace_repos_page(
    chrome: &Chrome,
    repos: &[RepoView],
    endpoint: &str,
    network: Option<&str>,
    can_manage: bool,
    flash: &RepoFlash,
) -> Markup {
    let scope = &chrome.scope;
    let body = html! {
        @if let Some(err) = &flash.error {
            div .banner { (err) }
        }
        @if let Some(ok) = &flash.ok {
            div .notice { (ok) }
        }
        @if let Some((repo_name, token)) = &flash.token {
            div .notice {
                strong { "A new submit token for " (repo_name) "." }
                " This is the only time it is shown — nothing here stores it, only its \
                 digest. Run these two lines in a clone of that repository:"
                pre .secret { (setup_lines(endpoint, token)) }
                "Then " code .mono { "git submit" } " builds it."
            }
        }

        section {
            h2 { "Repositories" }
            p .sub {
                "A registered repository submits with its own tokens, each revocable on \
                 its own. Builds run in "
                @match network {
                    Some(n) => code .mono { (n) },
                    None => "no network yet — an operator has to configure one",
                }
                ", in a fresh VM per job; they may upload and download artifacts, and \
                 cannot deploy. Secrets are read from "
                code .mono { "ci/ns/<namespace>/<repository>/<environment>" } "."
            }
            @if can_manage {
                form .row method="post" action=(scope.ui("/repos")) {
                    label {
                        "Clone URL"
                        input type="text" name="url" required
                              placeholder="git@github.com:me/app.git";
                    }
                    label {
                        "Name (optional)"
                        input type="text" name="name" placeholder="me/app";
                    }
                    label {
                        "Workflow path (optional)"
                        input type="text" name="workflow_path" placeholder=".ci/workflows/*.yml";
                    }
                    button type="submit" { "Register" }
                }
            }
        }

        section {
            @if repos.is_empty() {
                p .empty {
                    "No repository is registered yet."
                    @if !can_manage { " A namespace admin registers one and mints its token." }
                }
            }
            @for view in repos {
                div .repo {
                    div .head {
                        h3 { (view.repo.name) }
                        @if !view.repo.enabled {
                            span .pill.cancelled { "paused" }
                        }
                        @if let Some(run) = &view.last_run {
                            a href=(scope.ui(&format!("/runs/{}", run.id))) { (pill(&run.status)) }
                        }
                        @if can_manage {
                            form method="post" action=(scope.ui(&format!("/repos/{}/enabled", view.repo.id))) {
                                input type="hidden" name="enabled"
                                      value=(if view.repo.enabled { "false" } else { "true" });
                                button .quiet type="submit" {
                                    (if view.repo.enabled { "Pause" } else { "Resume" })
                                }
                            }
                            form method="post" action=(scope.ui(&format!("/repos/{}/delete", view.repo.id))) {
                                button .quiet type="submit" { "Remove" }
                            }
                        }
                    }
                    p .meta {
                        code .mono { (view.repo.url) }
                        @if let Some(path) = &view.repo.workflow_path {
                            " · " code .mono { (path) }
                        }
                        @if let Some(by) = &view.repo.created_email {
                            " · registered by " (by)
                        }
                        " · " (view.repo.created_at.format("%Y-%m-%d").to_string())
                    }
                    @if view.tokens.is_empty() {
                        p .empty { "No token yet, so nothing can submit as this repository." }
                    } @else {
                        div .scroll {
                            table {
                                thead { tr {
                                    th { "Key" } th { "For" } th { "Created" }
                                    th { "Last used" } th { "Status" } th { }
                                } }
                                tbody { (token_rows_managed(scope, &view.tokens, can_manage)) }
                            }
                        }
                    }
                    @if can_manage {
                        form .row method="post" action=(scope.ui(&format!("/repos/{}/tokens", view.repo.id))) {
                            label {
                                "New token for"
                                input type="text" name="name" placeholder="sam's laptop";
                            }
                            button type="submit" { "Mint" }
                        }
                    }
                }
            }
        }
    };
    layout(chrome, "repos", body)
}

#[cfg(test)]
mod page_tests {
    /// The shell these tests render against — this app, nobody signed in, the
    /// default theme. Mirrors the one in `tests` above; two test modules, one
    /// shell each, rather than a `pub(crate)` helper reaching across them.
    fn chrome() -> Chrome<'static> {
        Chrome {
            app_name: "ci",
            who: None,
            html_attrs: r#"data-theme="dark""#.into(),
            scope: Scope::Fleet,
        }
    }

    fn chrome_as(who: &str) -> Chrome<'_> {
        Chrome {
            app_name: "ci",
            who: Some(who),
            html_attrs: r#"data-theme="dark""#.into(),
            scope: Scope::Fleet,
        }
    }

    use super::*;
    // The networks fixture, reused so the repositories page is exercised
    // against the same pool the networks page renders.
    use super::tests::populated;
    use chrono::Utc;

    fn run(status: &str) -> Run {
        Run {
            id: "019fca648a6e-00000000".into(),
            workflow_id: "myapp".into(),
            workflow_path: ".ci/workflows/build.yml".into(),
            workflow_name: Some("build".into()),
            repo_url: "git@example.com:me/app.git".into(),
            repo_id: Some("019fca648a6e-00000001".into()),
            repo_name: Some("app".into()),
            git_ref: "refs/heads/main".into(),
            sha: "9183de223817abcdef".into(),
            before_sha: "0000de223817abcdef".into(),
            default_branch: Some("main".into()),
            release_base_sha: None,
            changes: crate::paths::Changes::known(vec!["src/main.rs".into()]),
            actor_email: Some("sam@sarocu.com".into()),
            status: status.into(),
            error: None,
            rerun_of: None,
            namespace: String::new(),
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            finished_at: Some(Utc::now()),
        }
    }

    fn job(key: &str, status: &str) -> JobRow {
        JobRow {
            id: format!("run.{key}"),
            run_id: "019fca648a6e-00000000".into(),
            job_key: key.into(),
            base_id: key.into(),
            display: key.into(),
            network: None,
            runner_hd_id: Some("hd-local".into()),
            fingerprint: Some("2a99fd001e0b".into()),
            sandbox_id: Some("sb-1a341ac0".into()),
            status: status.into(),
            attempt: 1,
            executor_boot: None,
            matrix: serde_json::json!({}),
            outputs: serde_json::json!({}),
            plan: serde_json::json!({ "needs": ["build"] }),
            error: None,
            carried_from: None,
            queued_at: Some(Utc::now()),
            started_at: Some(Utc::now()),
            finished_at: Some(Utc::now()),
        }
    }

    fn step(idx: i32, name: &str, status: &str) -> StepRow {
        StepRow {
            id: format!("run.job.{idx}"),
            job_id: "run.job".into(),
            idx,
            name: name.into(),
            uses: None,
            status: status.into(),
            exit_code: Some(if status == "failure" { 1 } else { 0 }),
            operation_id: None,
            log_path: None,
            log_bytes: 0,
            error: None,
            started_at: Some(Utc::now()),
            finished_at: Some(Utc::now()),
        }
    }

    fn registered_repo() -> Repo {
        Repo {
            id: "019fca648a6e-00000001".into(),
            url: "git@example.com:me/app.git".into(),
            normalized: "example.com/me/app".into(),
            name: "app".into(),
            workflow_path: None,
            network: None,
            enabled: true,
            namespace: String::new(),
            created_email: Some("sam@sarocu.com".into()),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn the_runs_page_lists_runs_and_links_to_them() {
        let html = runs_page(
            &chrome_as("Sam"),
            &[run("success"), run("failure")],
            &[registered_repo()],
            None,
        )
        .into_string();
        assert!(html.contains("/runs/019fca648a6e-00000000"));
        assert!(html.contains(r#"class="pill success""#));
        assert!(html.contains(r#"class="pill failure""#));
        assert!(html.contains("9183de223817"), "the sha is abbreviated");
        assert!(!html.contains("9183de223817abcdef"), "not the whole sha");
        assert!(html.contains("main"), "refs/heads/ is stripped");
        assert!(
            html.contains("/?repo=019fca648a6e-00000001"),
            "the repository cell links to the filtered page"
        );
    }

    #[test]
    fn an_empty_dashboard_says_how_to_start() {
        let html = runs_page(&chrome(), &[], &[], None).into_string();
        assert!(html.contains("git submit"));
        assert!(
            html.contains("/repos"),
            "and where the credential comes from"
        );
        assert!(
            !html.contains("All repositories"),
            "no filter dropdown before anything is registered"
        );
    }

    #[test]
    fn a_filtered_page_with_no_runs_names_the_repo_and_offers_the_way_back() {
        let html = runs_page(
            &chrome(),
            &[],
            &[registered_repo()],
            Some("019fca648a6e-00000001"),
        )
        .into_string();
        assert!(html.contains("No runs for"), "{html}");
        assert!(html.contains("app"), "the filter is named");
        assert!(html.contains(r#"href="/""#), "and can be cleared");
        assert!(
            !html.contains("git submit"),
            "a filtered miss is not a fresh install"
        );
    }

    #[test]
    fn a_run_without_a_registration_shows_no_repo_link() {
        let mut r = run("success");
        r.repo_id = None;
        r.repo_name = None;
        let html = runs_page(&chrome(), &[r], &[registered_repo()], None).into_string();
        assert!(!html.contains("/?repo="), "nothing to filter by");
    }

    fn deployments_fixture(status: &str, service: &str) -> ServiceDeploymentRow {
        ServiceDeploymentRow {
            id: format!("operation-{status}"),
            step_id: "run.deploy.0".into(),
            run_id: "019fca648a6e-00000000".into(),
            job_id: "019fca648a6e-00000000.deploy".into(),
            service_id: service.into(),
            status: status.into(),
            phase: Some(format!("phase-{status}")),
            message: Some(format!("message-{status}")),
            error: (status == "failed").then(|| "bad <script>alert('x')</script>".into()),
            sha: "0123456789abcdef0123456789abcdef01234567".into(),
            git_ref: "refs/heads/release/exact".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn event_fixture(revision: i64) -> RunEvent {
        RunEvent {
            id: uuid::Uuid::new_v4(),
            revision,
            event_type: "ci.job.status.<event>.v1".into(),
            payload: serde_json::json!({"detail": "payload <unsafe> & exact"}),
            job_id: Some("run.job".into()),
            job_key: Some("build <web>".into()),
            step_id: Some("run.job.step".into()),
            status: "failure".into(),
            error: Some("transition <failed> & stopped".into()),
            transitioned_at: Utc::now(),
            published_at: None,
            attempts: 0,
            last_error: None,
        }
    }

    #[test]
    fn event_timeline_escapes_records_and_reports_publication_failures() {
        let mut failed = event_fixture(42);
        failed.attempts = 3;
        failed.last_error = Some("NATS <offline> & unavailable".into());
        let pending = event_fixture(41);
        let html = run_page_with_deployments(
            &chrome(), &run("failure"), &[], &[], &[], &[], None, &[],
            &[failed, pending], None, false, Some(2),
        ).into_string();

        assert!(html.contains("Event timeline"));
        assert!(html.contains("publication failed") && html.contains("unpublished"));
        assert!(html.contains("3 attempts"));
        for escaped in [
            "ci.job.status.&lt;event&gt;.v1",
            "build &lt;web&gt;",
            "transition &lt;failed&gt; &amp; stopped",
            "NATS &lt;offline&gt; &amp; unavailable",
            "payload &lt;unsafe&gt; &amp; exact",
        ] {
            assert!(html.contains(escaped), "missing escaped value {escaped}: {html}");
        }
        assert!(!html.contains("<unsafe>") && !html.contains("NATS <offline>"));
        assert!(html.find("Deployments").unwrap() < html.find("Event timeline").unwrap());
        assert!(!html.contains("Retry event") && !html.contains("Cancel event"));
        if let Ok(path) = std::env::var("CI_EVENTS_HTML") {
            std::fs::write(path, html).unwrap();
        }
    }

    #[test]
    fn event_timeline_pagination_uses_exclusive_oldest_revision_boundaries() {
        let events = [event_fixture(100), event_fixture(99)];
        let first = run_page_with_deployments(
            &chrome(), &run("success"), &[], &[], &[], &[], None, &[],
            &events, None, true, None,
        ).into_string();
        assert!(first.contains("?events_before=99#events"), "{first}");
        assert!(!first.contains("Newest events"));

        let last = run_page_with_deployments(
            &chrome(), &run("success"), &[], &[], &[], &[], None, &[],
            &[event_fixture(98)], Some(99), false, None,
        ).into_string();
        assert!(last.contains("Newest events"));
        assert!(!last.contains("Older events"));
    }

    #[test]
    fn deployments_are_escaped_and_report_unknown_pending_and_success_truthfully() {
        let deployments = [
            deployments_fixture("submission_unknown", "unknown <service>"),
            deployments_fixture("submitting", "submitting-service"),
            deployments_fixture("running", "running-service"),
            deployments_fixture("passed", "passed-service"),
            deployments_fixture("failed", "failed-service"),
        ];
        let html = run_page_with_deployments(
            &chrome(),
            &run("failure"),
            &[],
            &[job("deploy", "failure")],
            &[],
            &[],
            None,
            &deployments,
            &[],
            None,
            false,
            Some(2),
        )
        .into_string();
        for status in [
            "submission_unknown",
            "submitting",
            "running",
            "passed",
            "failed",
        ] {
            assert!(
                html.contains(&format!("pill {status}")),
                "missing truthful state {status}"
            );
        }
        assert!(html.contains("Unknown submissions are not automatically resubmitted"));
        assert!(html.contains("unknown &lt;service&gt;") && !html.contains("unknown <service>"));
        assert!(html.contains("bad &lt;script&gt;") && !html.contains("<script>alert"));
        assert!(
            html.contains("0123456789abcdef0123456789abcdef01234567"),
            "revision is not shortened"
        );
        assert!(html.contains("refs/heads/release/exact"), "ref is exact");
        assert!(html.contains("Event timeline"));
        assert!(!html.contains("Retry deployment") && !html.contains("Cancel deployment"));
        if let Ok(path) = std::env::var("CI_DEPLOYMENTS_HTML") {
            std::fs::write(path, &html).unwrap();
        }
    }

    #[test]
    fn release_and_deployments_render_truthful_escaped_exportable_html() {
        let release = ReleaseRow {
            prepared: crate::release_git::PreparedRelease {
                source_sha: "1111111111111111111111111111111111111111".into(),
                release_sha: "2222222222222222222222222222222222222222".into(),
                git_ref: "refs/heads/release/public".into(),
                versions: serde_json::json!({"ci": "1.2.3", "web": "4.5.6"}),
                tags: vec![],
            },
            status: "unknown".into(),
            error: Some("push outcome <unknown> & must be checked".into()),
        };
        let html = run_page_with_deployments(
            &chrome(),
            &run("failure"),
            &[],
            &[job("release", "failure"), job("deploy", "skipped")],
            &[],
            &[],
            Some(&release),
            &[],
            &[],
            None,
            false,
            Some(2),
        )
        .into_string();

        assert!(html.contains("1111111111111111111111111111111111111111"));
        assert!(html.contains("2222222222222222222222222222222222222222"));
        assert!(html.contains("ci</code>: <code class=\"mono\">1.2.3"));
        assert!(html.contains("outcome &lt;unknown&gt; &amp; must be checked"));
        assert!(!html.contains("outcome <unknown>"));
        assert!(html.contains("does not mean the release was published"));
        assert!(html.find("Release").unwrap() < html.find("Deployments").unwrap());
        if let Ok(path) = std::env::var("CI_RELEASE_HTML") {
            std::fs::write(format!("{path}.unknown.html"), &html).unwrap();
            let mut published = release.clone();
            published.status = "published".into();
            published.error = None;
            let mut deployment = deployments_fixture("passed", "public-ci");
            deployment.sha = published.prepared.release_sha.clone();
            deployment.git_ref = published.prepared.git_ref.clone();
            let published_html = run_page_with_deployments(&chrome(), &run("success"), &[],
                &[job("validate", "success"), job("release", "success"), job("build", "success"), job("deploy", "success")],
                &[], &[], Some(&published), &[deployment], &[], None, false, Some(2)).into_string();
            std::fs::write(path, published_html).unwrap();
        }
    }

    #[test]
    fn the_run_page_shows_jobs_their_needs_and_artifacts() {
        let artifacts = [ArtifactRow {
            name: "dist".into(),
            sink: "disk".into(),
            digest: None,
            size_bytes: 4096,
            uri: "/var/lib/ci/dist".into(),
            public_url: None,
        }];
        let html = run_page(
            &chrome(),
            &run("success"),
            &[],
            &[job("build", "success"), job("deploy", "skipped")],
            &artifacts,
            &[],
            Some(2),
        )
        .into_string();
        assert!(html.contains("build"));
        assert!(html.contains(r#"class="pill skipped""#));
        assert!(html.contains("hd-local"));
        assert!(html.contains("4.0 KiB"));
        assert!(html.contains("/runs/019fca648a6e-00000000/jobs/build"));
    }

    /// A failing job's error has to be on the run page; otherwise the only way
    /// to find out why a run went red is to open each job in turn.
    #[test]
    fn a_job_error_is_surfaced_on_the_run_page() {
        let mut j = job("build", "failure");
        j.error = Some("step \"Build\" exited 101".into());
        let html = run_page(&chrome(), &run("failure"), &[], &[j], &[], &[], Some(2)).into_string();
        assert!(html.contains("exited 101"), "{html}");
    }

    /// The step the reader came for is the one that failed, so it opens without
    /// a click.
    #[test]
    fn a_failed_step_is_expanded_and_a_passing_one_is_not() {
        let steps = vec![
            (step(0, "Compile", "success"), "compiling\n".to_string()),
            (step(1, "Test", "failure"), "assertion failed\n".to_string()),
        ];
        let html = job_page(
            &chrome(),
            &run("failure"),
            &job("build", "failure"),
            &steps,
            None,
        )
        .into_string();
        // Exactly one expanded `<details>`, and it is the failing step's.
        let opened: Vec<&str> = html.matches(r#"class="step" open"#).collect();
        assert_eq!(opened.len(), 1, "expected one expanded step in:\n{html}");
        let open_at = html.find(r#"class="step" open"#).unwrap();
        let compile_at = html.find("Compile").unwrap();
        let test_at = html.find(">Test<").unwrap();
        assert!(
            open_at > compile_at && open_at < test_at,
            "the expanded step must be Test, not Compile"
        );
        assert!(html.contains("assertion failed"));
    }

    /// A finished job gets no token, because nothing needs one.
    #[test]
    fn a_finished_job_page_carries_no_stream_token_or_script() {
        let html = job_page(
            &chrome(),
            &run("success"),
            &job("build", "success"),
            &[(step(0, "Compile", "success"), "done\n".into())],
            None,
        )
        .into_string();
        assert!(
            !html.contains("EventSource"),
            "no live stream when it is over"
        );
        assert!(!html.contains("/api/stream/"));
    }

    #[test]
    fn a_running_job_page_wires_up_the_stream() {
        let html = job_page(
            &chrome(),
            &run("running"),
            &job("build", "running"),
            &[(step(0, "Compile", "running"), "compiling\n".into())],
            Some("1234.abcd"),
        )
        .into_string();
        assert!(html.contains("EventSource"));
        assert!(html.contains("/api/stream/019fca648a6e-00000000/build?token=1234.abcd"));
        // No *external* asset: the whole page must work over an SSH tunnel and
        // from a network with no route off it. Same-origin `/__ui/` is served
        // by this binary and is fine; an absolute URL to anywhere is not.
        // Checked as "no scheme-bearing src or href" rather than by naming
        // known CDNs, because the failure this guards against is somebody
        // adding a script tag for a host nobody thought to list.
        for attr in ["src=\"http", "href=\"http", "src=\"//", "href=\"//"] {
            assert!(!html.contains(attr), "external asset ({attr}) in {html}");
        }
        assert!(html.contains(r#"href="/__ui/heyo.css""#), "{html}");
    }

    /// Log text is guest output — arbitrary bytes chosen by whatever ran.
    #[test]
    fn log_output_is_escaped() {
        let steps = vec![(
            step(0, "Compile", "success"),
            "<script>alert(1)</script>\n".to_string(),
        )];
        let html = job_page(
            &chrome(),
            &run("success"),
            &job("build", "success"),
            &steps,
            None,
        )
        .into_string();
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    /// A job's display name comes from the workflow file.
    #[test]
    fn a_hostile_job_name_is_escaped() {
        let mut j = job("build", "success");
        j.display = "<img src=x onerror=alert(1)>".into();
        let html = run_page(&chrome(), &run("success"), &[], &[j], &[], &[], Some(2)).into_string();
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("&lt;img"));
    }

    /// Cancel is offered while there is something to stop, and not otherwise.
    #[test]
    fn a_running_run_can_be_cancelled_and_a_finished_one_cannot() {
        let mut r = run("success");
        r.status = "running".into();
        let html = run_page(&chrome(), &r, &[], &[], &[], &[], Some(2)).into_string();
        assert!(
            html.contains(r#"action="/runs/019fca648a6e-00000000/cancel""#),
            "{html}"
        );
        assert!(html.contains("cannot be aborted"), "the limit is stated");

        for finished in ["success", "failure", "cancelled"] {
            let mut r = run(finished);
            r.status = finished.into();
            let html = run_page(&chrome(), &r, &[], &[], &[], &[], Some(2)).into_string();
            assert!(!html.contains("/cancel"), "{finished}: {html}");
        }
    }

    /// The two re-run buttons are the mirror image of cancel: offered once the
    /// run is finished, and "failed jobs" only when something failed.
    #[test]
    fn a_finished_run_can_be_run_again_and_a_failed_one_failed_jobs_only() {
        let mut r = run("success");
        r.status = "running".into();
        let html = run_page(&chrome(), &r, &[], &[], &[], &[], Some(2)).into_string();
        assert!(
            !html.contains("/rerun"),
            "a running run offers no re-run: {html}"
        );

        let html = run_page(&chrome(), &run("success"), &[], &[], &[], &[], Some(2)).into_string();
        assert!(
            html.contains(r#"action="/runs/019fca648a6e-00000000/rerun""#),
            "{html}"
        );
        assert!(
            !html.contains("/rerun-failed"),
            "nothing failed to re-run: {html}"
        );

        for failed in ["failure", "cancelled"] {
            let html = run_page(&chrome(), &run(failed), &[], &[], &[], &[], Some(2)).into_string();
            assert!(
                html.contains(r#"action="/runs/019fca648a6e-00000000/rerun-failed""#),
                "{failed}: {html}"
            );
            assert!(html.contains("Re-run failed jobs"), "{failed}: {html}");
        }
    }

    /// Lineage is shown in both directions, and a carried-over job says so on
    /// the run page and on its own.
    #[test]
    fn a_rerun_links_its_original_and_marks_carried_over_jobs() {
        let mut later = run("running");
        later.id = "019fca648a6e-00000009".into();
        later.rerun_of = Some("019fca648a6e-00000000".into());
        let mut build = job("build", "success");
        build.carried_from = Some("019fca648a6e-00000000".into());
        let deploy = job("deploy", "running");

        let html = run_page(
            &chrome(),
            &later,
            &[],
            &[build.clone(), deploy],
            &[],
            &[],
            Some(2),
        )
        .into_string();
        assert!(
            html.contains(r#"href="/runs/019fca648a6e-00000000""#),
            "{html}"
        );
        assert!(html.contains("failed jobs only"), "{html}");
        assert!(html.contains("carried over"), "{html}");

        // The original points forward at the re-run.
        let html = run_page(
            &chrome(),
            &run("failure"),
            &[later.clone()],
            &[],
            &[],
            &[],
            Some(2),
        )
        .into_string();
        assert!(html.contains("Re-run as"), "{html}");
        assert!(
            html.contains(r#"href="/runs/019fca648a6e-00000009""#),
            "{html}"
        );

        let html = job_page(&chrome(), &later, &build, &[], None).into_string();
        assert!(html.contains("did not run here"), "{html}");
        assert!(
            html.contains(r#"href="/runs/019fca648a6e-00000000/jobs/build""#),
            "{html}"
        );
    }

    /// The VM log is the one failure with no step log to read — a machine that
    /// never came up produces no step output at all — so the run page has to
    /// carry it.
    #[test]
    fn the_run_page_shows_each_jobs_vm_log_and_the_retention() {
        let logs = [
            (
                "build".to_string(),
                Some("[    0.00] Linux version".to_string()),
            ),
            ("deploy".to_string(), None),
        ];
        let html = run_page(
            &chrome(),
            &run("failure"),
            &[],
            &[job("build", "failure")],
            &[],
            &logs,
            Some(2),
        )
        .into_string();

        assert!(html.contains("VM logs"));
        assert!(html.contains("Linux version"));
        assert!(html.contains("Discarded after 2 days"));
        // A swept log is a different state from a job that never had a VM, and
        // the page has to say which rather than rendering an empty box.
        assert!(html.contains("no longer retained"), "{html}");
        assert!(html.contains("Step results are kept"));
    }

    /// With retention off there is nothing to promise, so the page must not
    /// claim a period it will not honour.
    #[test]
    fn retention_is_only_mentioned_when_it_applies() {
        let logs = [("build".to_string(), Some("boot".to_string()))];
        let html = run_page(&chrome(), &run("success"), &[], &[], &[], &logs, None).into_string();
        assert!(html.contains("VM logs"));
        assert!(!html.contains("Discarded after"), "{html}");

        // And the section is absent entirely when no job captured one.
        let html = run_page(&chrome(), &run("success"), &[], &[], &[], &[], Some(2)).into_string();
        assert!(!html.contains("VM logs"), "{html}");
    }

    #[test]
    fn durations_read_at_a_glance() {
        assert_eq!(human_duration(Duration::from_millis(420)), "420ms");
        assert_eq!(human_duration(Duration::from_millis(4200)), "4.2s");
        assert_eq!(human_duration(Duration::from_secs(64)), "1m 04s");
        assert_eq!(human_duration(Duration::from_secs(3725)), "1h 02m");
    }

    #[test]
    fn byte_sizes_read_at_a_glance() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(4096), "4.0 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    /// A run submitted with neither a workflow id nor a repository name must
    /// not render as an empty cell that reads as a broken row.
    #[test]
    fn an_unnamed_workflow_gets_a_placeholder() {
        let html = workflows_page(&chrome(), &[(String::new(), None)], "*.yml").into_string();
        assert!(html.contains("(unnamed)"), "{html}");

        let mut r = run("success");
        r.workflow_id = String::new();
        r.workflow_name = None;
        let html = runs_page(&chrome(), &[r], &[], None).into_string();
        assert!(html.contains("(unnamed)"), "{html}");
    }

    #[test]
    fn the_workflows_page_lists_each_workflow_once_with_its_latest_run() {
        let html = workflows_page(
            &chrome(),
            &[
                ("myapp".into(), Some(run("success"))),
                ("other".into(), None),
            ],
            ".ci/workflows/*.yml",
        )
        .into_string();
        assert!(html.contains("myapp"));
        assert!(html.contains("other"));
        assert!(html.contains("never"));
        assert!(html.contains(".ci/workflows/*.yml"));
    }

    // ---- repositories ---------------------------------------------------

    fn repo_view(enabled: bool, revoked: bool) -> RepoView {
        RepoView {
            repo: Repo {
                id: "019fca648a6e-00000001".into(),
                url: "git@github.com:me/app.git".into(),
                normalized: "github.com/me/app".into(),
                name: "me/app".into(),
                workflow_path: None,
                network: Some("prod-runners".into()),
                enabled,
                namespace: String::new(),
                created_email: Some("sam@sarocu.com".into()),
                created_at: Utc::now(),
            },
            tokens: vec![RepoToken {
                id: "019fca648a6e-00000002".into(),
                repo_id: "019fca648a6e-00000001".into(),
                name: "laptop".into(),
                created_email: Some("sam@sarocu.com".into()),
                created_at: Utc::now(),
                last_used_at: None,
                revoked_at: revoked.then(Utc::now),
            }],
            last_run: Some(run("success")),
        }
    }

    #[test]
    fn the_repos_page_lists_a_registration_and_its_tokens() {
        let html = repos_page(
            &chrome_as("Sam"),
            &[repo_view(true, false)],
            "https://ci.example.com",
            false,
            &populated(),
            &RepoFlash::default(),
        )
        .into_string();
        assert!(html.contains("me/app"));
        assert!(
            html.contains("019fca648a6e-00000002"),
            "the key id is shown"
        );
        assert!(html.contains("/repos/019fca648a6e-00000001/tokens"));
        assert!(html.contains("active"));
        assert!(html.contains("Pause"));
    }

    /// A revoked token stays visible — it is still the answer to "what used to
    /// have access" — but must not offer to be revoked again.
    #[test]
    fn a_revoked_token_renders_as_revoked_without_a_second_revoke_button() {
        let html = repos_page(
            &chrome(),
            &[repo_view(true, true)],
            "https://ci.example.com",
            false,
            &populated(),
            &RepoFlash::default(),
        )
        .into_string();
        assert!(html.contains("revoked"));
        assert!(!html.contains("/revoke"), "{html}");
    }

    /// The one-time display, and the only place a token's plaintext is ever
    /// rendered.
    #[test]
    fn a_minted_token_is_shown_once_with_the_two_lines_that_use_it() {
        let html = repos_page(
            &chrome_as("Sam"),
            &[repo_view(true, false)],
            "https://ci.example.com",
            true,
            &populated(),
            &RepoFlash::minted("me/app".into(), "cis_k1.secret-value".into()),
        )
        .into_string();
        assert!(html.contains("git config ci.endpoint https://ci.example.com"));
        assert!(html.contains("git config ci.token cis_k1.secret-value"));
        assert!(
            html.contains("CI_REQUIRE_REPO_TOKEN is set"),
            "the page says the shared secret is off"
        );

        // And nowhere else: a page rendered without the flash must not carry it.
        let plain = repos_page(
            &chrome_as("Sam"),
            &[repo_view(true, false)],
            "https://ci.example.com",
            false,
            &populated(),
            &RepoFlash::default(),
        )
        .into_string();
        assert!(!plain.contains("cis_"), "{plain}");
    }

    #[test]
    fn an_empty_repos_page_says_what_submitting_without_one_means() {
        let html = repos_page(
            &chrome(),
            &[],
            "https://ci.example.com",
            false,
            &populated(),
            &RepoFlash::failed("A clone URL is required."),
        )
        .into_string();
        assert!(html.contains("CI_WEBHOOK_SECRET"));
        assert!(html.contains("A clone URL is required."));
    }

    // ---- namespace scope ----------------------------------------------------

    const BASE: &str = "/namespaces/team-a/plugins/ci";

    fn ns_chrome(base: Option<&str>) -> Chrome<'static> {
        Chrome {
            app_name: "ci",
            who: Some("a@example.com"),
            html_attrs: r#"data-theme="dark""#.into(),
            scope: Scope::namespace("team-a", base),
        }
    }

    /// Every URL the page tells a browser to fetch or follow.
    fn urls(html: &str) -> Vec<String> {
        let mut out = Vec::new();
        for attr in ["href=\"", "action=\"", "src=\""] {
            for piece in html.split(attr).skip(1) {
                out.push(piece.split('"').next().unwrap_or_default().to_string());
            }
        }
        out
    }

    /// Every namespace page, as a namespace sees it.
    fn ns_pages(chrome: &Chrome, admin: bool) -> Vec<(&'static str, String)> {
        let mut r = run("failure");
        r.namespace = "team-a".into();
        r.rerun_of = Some("019fca648a6e-00000009".into());
        let mut carried = job("deploy", "success");
        carried.carried_from = Some("019fca648a6e-00000009".into());
        vec![
            ("runs", runs_page(chrome, &[r.clone()], &[registered_repo()], None).into_string()),
            ("runs filtered", runs_page(chrome, &[], &[registered_repo()], Some("x")).into_string()),
            ("runs empty", runs_page(chrome, &[], &[], None).into_string()),
            (
                "run",
                run_page(chrome, &r, &[run("success")], &[job("build", "failure"), carried.clone()], &[], &[], None)
                    .into_string(),
            ),
            (
                "running run",
                run_page(chrome, &run("running"), &[], &[job("build", "running")], &[], &[], None).into_string(),
            ),
            (
                "job",
                job_page(
                    chrome,
                    &r,
                    &job("build", "running"),
                    &[(step(0, "Compile", "running"), "compiling\n".into())],
                    Some("1234.abcd"),
                )
                .into_string(),
            ),
            ("carried job", job_page(chrome, &r, &carried, &[], None).into_string()),
            (
                "workflows",
                workflows_page(chrome, &[("app".into(), Some(r.clone()))], ".ci/workflows/*.yml").into_string(),
            ),
            (
                "repos",
                namespace_repos_page(
                    chrome,
                    &[repo_view(true, false), repo_view(false, true)],
                    "https://ci.example.com",
                    Some("tenants"),
                    admin,
                    &RepoFlash::minted("app".into(), "cis_secret".into()),
                )
                .into_string(),
            ),
        ]
    }

    #[test]
    fn every_namespace_link_and_form_is_under_the_proxy_base() {
        for admin in [true, false] {
            for (name, html) in ns_pages(&ns_chrome(Some(BASE)), admin) {
                let found = urls(&html);
                assert!(!found.is_empty(), "{name}");
                for url in found {
                    assert!(url.starts_with(&format!("{BASE}/")) || url == format!("{BASE}/ui") || url.starts_with(&format!("{BASE}/ui?")), "{name}: {url} in {html}");
                }
                for fleet in ["\"/vms", "\"/networks", "\"/releases", "\"/maintenance", "\"/runners", "\"/__ui/", "\"/repos", "\"/runs/", "\"/\""] {
                    assert!(!html.contains(fleet), "{name} links the fleet's {fleet}");
                }
            }
        }
    }

    #[test]
    fn a_direct_namespace_page_links_its_native_paths() {
        for (name, html) in ns_pages(&ns_chrome(None), true) {
            for url in urls(&html) {
                assert!(url.starts_with("/ns/team-a/"), "{name}: {url}");
            }
        }
    }

    #[test]
    fn a_namespace_page_has_three_tabs_an_embedded_hook_and_its_own_assets() {
        let html = runs_page(&ns_chrome(Some(BASE)), &[], &[], None).into_string();
        for tab in ["Runs", "Repositories", "Workflows"] {
            assert!(html.contains(&format!(">{tab}</a>")), "{tab}");
        }
        for fleet in ["Networks", "VMs"] {
            assert!(!html.contains(&format!(">{fleet}</a>")), "{fleet}");
        }
        assert!(html.contains("window.self !== window.top"), "{html}");
        assert!(html.contains(".embedded .topbar { display: none; }"));
        assert!(html.contains(&format!(r#"href="{BASE}/ui/__ui/heyo.css""#)), "{html}");
        assert!(html.contains(&format!(r#"src="{BASE}/ui/__ui/theme.js""#)), "{html}");
    }

    #[test]
    fn a_namespace_job_page_streams_through_the_proxy() {
        let html = job_page(
            &ns_chrome(Some(BASE)),
            &run("running"),
            &job("build", "running"),
            &[],
            Some("1234.abcd"),
        )
        .into_string();
        assert!(
            html.contains(&format!("{BASE}/api/stream/019fca648a6e-00000000/build?token=1234.abcd")),
            "{html}"
        );
    }

    #[test]
    fn a_namespace_run_page_has_no_deployments_section() {
        let html = run_page(&ns_chrome(Some(BASE)), &run("success"), &[], &[], &[], &[], None).into_string();
        assert!(!html.contains("id=\"deployments\""));
        let fleet = run_page(&chrome(), &run("success"), &[], &[], &[], &[], None).into_string();
        assert!(fleet.contains("id=\"deployments\""));
    }

    #[test]
    fn the_namespace_repos_page_offers_no_network_and_forms_only_to_admins() {
        let page = |admin| {
            namespace_repos_page(
                &ns_chrome(Some(BASE)),
                &[repo_view(true, false)],
                "https://ci.example.com",
                Some("tenants"),
                admin,
                &RepoFlash::default(),
            )
            .into_string()
        };
        let admin = page(true);
        assert!(!admin.contains("name=\"network\""), "{admin}");
        assert!(!admin.contains("CI_WEBHOOK_SECRET"));
        assert!(admin.contains("tenants"));
        assert!(admin.contains("ci/ns/&lt;namespace&gt;"), "{admin}");
        assert!(admin.contains("<form"));
        assert!(admin.contains("/revoke"));
        let viewer = page(false);
        assert!(!viewer.contains("<form"), "{viewer}");
    }

    /// The fleet page with no namespace in sight is the page it always was.
    #[test]
    fn the_fleet_runs_page_is_unchanged_until_a_namespace_has_run() {
        let runs = [run("success")];
        let repos = [registered_repo()];
        assert_eq!(
            runs_page(&chrome(), &runs, &repos, None).into_string(),
            runs_page_with_namespaces(&chrome(), &runs, &repos, None, &[], None).into_string(),
        );
        assert!(!runs_page(&chrome(), &runs, &repos, None).into_string().contains("Namespace"));

        let mut tenant = run("success");
        tenant.namespace = "team-a".into();
        let html = runs_page_with_namespaces(
            &chrome(),
            &[run("success"), tenant],
            &repos,
            None,
            &["team-a".into()],
            Some("team-a"),
        )
        .into_string();
        assert!(html.contains("<th>Namespace</th>"), "{html}");
        assert!(html.contains(r#"href="/?namespace=team-a""#), "{html}");
        assert!(html.contains(r#"<option value="team-a" selected>"#), "{html}");
        assert!(html.contains(r#"<option value="-">Fleet only</option>"#), "{html}");
    }
}
