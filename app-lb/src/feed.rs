//! The per-namespace event feed — RSS for "what happened to my deployments".
//!
//! A namespace's deployments share an audience: whoever runs them wants to hear
//! that one was deployed, updated, removed, or is in trouble, without watching
//! a dashboard. RSS is the lowest-commitment way to offer that — every chat
//! tool, reader and automation stack already speaks it, and a feed URL is a
//! thing you can hand to someone without handing them a credential.
//!
//! # Nothing is published by default
//!
//! Every event enters through a spec's [`FeedSpec`](crate::config::FeedSpec)
//! switches: `announce` for lifecycle, `issues` for operational trouble. A
//! deployment whose spec says nothing contributes nothing — the feed is a
//! megaphone, and reaching it must be a decision the spec's author made. The
//! check lives *here*, in [`Feed::announce`] and [`Feed::issue`], so a call
//! site cannot forget it.
//!
//! # Reachability
//!
//! The feed is served in two places:
//!
//! - `GET /feeds/:namespace` on the admin listener, behind the view tier and
//!   the token namespace wall (see `decide_access`).
//! - A deployment may carry `feed.expose = "/some/path"`, which serves its
//!   namespace's feed on its own routes, through the data plane — after its
//!   `auth` gate, if it has one. This is the only way a feed becomes public,
//!   and it is public exactly as far as that deployment's gate allows.
//!
//! # What this is not
//!
//! Not persistence: the ring is in memory and a restart empties it. Feed
//! readers tolerate that shape well — an empty feed reads as "nothing new" —
//! and the events are advisories, not records; the record is app-obs and the
//! job history. Not a queue either: repeats of the same issue fold into one
//! entry rather than flooding subscribers, the same trick the SIEM's alert
//! ring uses.

use serde::Serialize;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::DeploymentSpec;

/// Events kept per namespace. Enough for a reader that polls daily against a
/// noisy fleet; old entries fall off the back.
const RING_CAP: usize = 200;

/// Repeats of the same issue inside this window fold into the open entry
/// instead of appending. Lifecycle events never fold — deploying twice is two
/// events.
const SUPPRESS_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedEventKind {
    /// A deployment was registered.
    Deployed,
    /// A deployment's spec was replaced or edited.
    Updated,
    /// A deployment was deregistered.
    Removed,
    /// Something operational went wrong — or recovered.
    Issue,
}

impl FeedEventKind {
    fn label(self) -> &'static str {
        match self {
            Self::Deployed => "deployed",
            Self::Updated => "updated",
            Self::Removed => "removed",
            Self::Issue => "issue",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FeedEvent {
    /// Monotonic across the process, so it can be an RSS `<guid>`.
    pub id: u64,
    /// When the event first happened.
    pub ts: u64,
    /// When it last happened — differs from `ts` only for folded repeats.
    pub last_ts: u64,
    /// How many times it happened inside the suppression window.
    pub count: u64,
    pub namespace: String,
    pub deployment: String,
    pub kind: FeedEventKind,
    pub title: String,
    pub detail: String,
}

/// One ring of events per namespace, behind one lock.
///
/// A `Mutex` rather than the registry's copy-on-write swap: writes are rare
/// (deploys and failures), reads are a feed poller a few times an hour, and
/// nothing here sits on the per-request path — the data plane only touches
/// this when a request actually hits an exposed feed path.
pub struct Feed {
    rings: Mutex<HashMap<String, VecDeque<FeedEvent>>>,
    next_id: AtomicU64,
}

impl std::fmt::Debug for Feed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rings = self.rings.lock().expect("feed lock");
        f.debug_struct("Feed").field("namespaces", &rings.len()).finish()
    }
}

impl Default for Feed {
    fn default() -> Self {
        Self::new()
    }
}

impl Feed {
    pub fn new() -> Self {
        Self {
            rings: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Publish a lifecycle event — if, and only if, the spec opted in with
    /// `feed.announce`.
    pub fn announce(&self, spec: &DeploymentSpec, kind: FeedEventKind, detail: String, now: u64) {
        if !spec.feed.as_ref().is_some_and(|f| f.announce) {
            return;
        }
        let title = format!("{} {}", spec.id, kind.label());
        self.push(&spec.namespace, &spec.id, kind, title, detail, now);
    }

    /// Publish an operational issue — if, and only if, the spec opted in with
    /// `feed.issues`.
    pub fn issue(&self, spec: &DeploymentSpec, title: String, detail: String, now: u64) {
        if !spec.feed.as_ref().is_some_and(|f| f.issues) {
            return;
        }
        self.push(&spec.namespace, &spec.id, FeedEventKind::Issue, title, detail, now);
    }

    fn push(
        &self,
        namespace: &str,
        deployment: &str,
        kind: FeedEventKind,
        title: String,
        detail: String,
        now: u64,
    ) {
        let mut rings = self.rings.lock().expect("feed lock");
        let ring = rings.entry(namespace.to_string()).or_default();

        // Fold a repeat of the same open issue rather than appending: a VM
        // that fails to boot every two seconds is one story, not a hundred
        // items pushing everything else off the feed. Only the newest entry is
        // considered, so an *alternating* pair of issues still reads as the
        // sequence it was.
        if kind == FeedEventKind::Issue
            && let Some(last) = ring.back_mut()
            && last.kind == FeedEventKind::Issue
            && last.deployment == deployment
            && last.title == title
            && now.saturating_sub(last.last_ts) < SUPPRESS_SECS
        {
            last.count += 1;
            last.last_ts = now;
            last.detail = detail;
            return;
        }

        if ring.len() == RING_CAP {
            ring.pop_front();
        }
        ring.push_back(FeedEvent {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            ts: now,
            last_ts: now,
            count: 1,
            namespace: namespace.to_string(),
            deployment: deployment.to_string(),
            kind,
            title,
            detail,
        });
    }

    /// The newest `limit` events for a namespace, newest first. An unknown
    /// namespace is an empty feed, not an error — feeds are polled by readers
    /// that were configured once and should keep quietly working when the last
    /// deployment in a namespace goes away.
    pub fn recent(&self, namespace: &str, limit: usize) -> Vec<FeedEvent> {
        let rings = self.rings.lock().expect("feed lock");
        match rings.get(namespace) {
            Some(ring) => ring.iter().rev().take(limit).cloned().collect(),
            None => Vec::new(),
        }
    }

    /// The namespaces that have ever had an event this process, sorted.
    pub fn namespaces(&self) -> Vec<String> {
        let rings = self.rings.lock().expect("feed lock");
        let mut out: Vec<String> = rings.keys().cloned().collect();
        out.sort();
        out
    }
}

/// Render a namespace's events as an RSS 2.0 document.
///
/// `link` is where this feed is being served from — the channel's `<link>` is
/// required by the spec, and the honest value is "here".
pub fn rss(namespace: &str, link: &str, events: &[FeedEvent]) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(512 + events.len() * 256);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<rss version=\"2.0\">\n<channel>\n");
    let _ = write!(
        out,
        "<title>{} — deployment events</title>\n<link>{}</link>\n\
         <description>Lifecycle and issue events for deployments in the \
         {} namespace</description>\n",
        xml_escape(namespace),
        xml_escape(link),
        xml_escape(namespace),
    );
    if let Some(newest) = events.first() {
        let _ = write!(out, "<lastBuildDate>{}</lastBuildDate>\n", rfc822(newest.last_ts));
    }

    for e in events {
        let description = if e.count > 1 {
            format!("{} (repeated {} times)", e.detail, e.count)
        } else {
            e.detail.clone()
        };
        let _ = write!(
            out,
            "<item>\n<title>{}</title>\n<description>{}</description>\n\
             <guid isPermaLink=\"false\">applb:{}:{}</guid>\n\
             <category>{}</category>\n<pubDate>{}</pubDate>\n</item>\n",
            xml_escape(&e.title),
            xml_escape(&description),
            xml_escape(&e.namespace),
            e.id,
            e.kind.label(),
            rfc822(e.ts),
        );
    }

    out.push_str("</channel>\n</rss>\n");
    out
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Unix seconds to the RFC 822 shape RSS requires: `Mon, 11 Aug 2026 18:38:00
/// +0000`. Hand-rolled because it is the one date this crate ever formats, and
/// a calendar dependency for one format is a poor trade.
fn rfc822(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let secs = ts % 86_400;
    let (h, m, s) = (secs / 3600, (secs / 60) % 60, secs % 60);

    // Civil-from-days (Howard Hinnant's algorithm), days since 1970-01-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let weekday = WEEKDAYS[days.rem_euclid(7) as usize];
    format!(
        "{weekday}, {day:02} {} {year} {h:02}:{m:02}:{s:02} +0000",
        MONTHS[(month - 1) as usize],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FeedSpec;

    fn spec(id: &str, namespace: &str, feed: Option<FeedSpec>) -> DeploymentSpec {
        DeploymentSpec {
            ingress: None,
            account_id: None,
            user_id: None,
            namespace: namespace.into(),
            feed,
            id: id.into(),
            routes: vec![],
            vm: Some(crate::config::VmSpec {
                correlated_creates: false,
                env_from: vec![],
                workspace_archive: None,
                image_download_url: None,
                image_size_bytes: None,
                image_sha256: None,
                driver: crate::config::Driver::Firecracker,
                image: None,
                rootfs: Default::default(),
                port: 8080,
                start_command: None,
                size_class: None,
                disk_size_gb: None,
                working_directory: None,
                env_vars: None,
                setup_hooks: None,
                open_ports: vec![],
                mounts: vec![],
                workspace: None,
                ttl_seconds: 3600,
            }),
            scaling: Default::default(),
            maintenance: false,
            health: Default::default(),
            upstreams: vec![],
            discovery: None,
            gateway: None,
            build: None,
            artifact: None,
            site: None,
            update: None,
            auth: None,
        }
    }

    fn announcing() -> Option<FeedSpec> {
        Some(FeedSpec { announce: true, issues: true, expose: None })
    }

    #[test]
    fn a_spec_that_says_nothing_publishes_nothing() {
        let f = Feed::new();
        f.announce(&spec("web", "team-a", None), FeedEventKind::Deployed, "up".into(), 100);
        f.issue(&spec("web", "team-a", None), "boot failed".into(), "…".into(), 100);
        // Even a spec with a feed block publishes only what it switched on.
        let expose_only = Some(FeedSpec { announce: false, issues: false, expose: Some("/feed.xml".into()) });
        f.announce(&spec("web", "team-a", expose_only.clone()), FeedEventKind::Deployed, "up".into(), 100);
        f.issue(&spec("web", "team-a", expose_only), "boot failed".into(), "…".into(), 100);

        assert!(f.recent("team-a", 10).is_empty(), "the feed defaults to silence");
        assert!(f.namespaces().is_empty());
    }

    #[test]
    fn events_land_in_their_own_namespace_newest_first() {
        let f = Feed::new();
        f.announce(&spec("web", "team-a", announcing()), FeedEventKind::Deployed, "v1".into(), 100);
        f.announce(&spec("api", "team-b", announcing()), FeedEventKind::Deployed, "v1".into(), 150);
        f.announce(&spec("web", "team-a", announcing()), FeedEventKind::Updated, "v2".into(), 200);

        let a = f.recent("team-a", 10);
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].title, "web updated");
        assert_eq!(a[1].title, "web deployed");
        assert_eq!(f.recent("team-b", 10).len(), 1);
        assert!(f.recent("nobody", 10).is_empty(), "an unknown namespace is an empty feed");
        assert_eq!(f.namespaces(), vec!["team-a", "team-b"]);
    }

    #[test]
    fn a_flapping_issue_folds_instead_of_flooding() {
        let f = Feed::new();
        let s = spec("web", "team-a", announcing());
        for i in 0..50 {
            f.issue(&s, "VM failed to boot".into(), format!("attempt {i}"), 100 + i);
        }
        let events = f.recent("team-a", 10);
        assert_eq!(events.len(), 1, "fifty repeats are one story");
        assert_eq!(events[0].count, 50);
        assert_eq!(events[0].ts, 100);
        assert_eq!(events[0].last_ts, 149);
        assert_eq!(events[0].detail, "attempt 49", "the entry carries the latest detail");

        // Past the window it is a new entry — an issue that comes back hours
        // later is news again.
        f.issue(&s, "VM failed to boot".into(), "again".into(), 149 + SUPPRESS_SECS);
        assert_eq!(f.recent("team-a", 10).len(), 2);

        // Lifecycle events never fold: deploying twice is two events.
        f.announce(&s, FeedEventKind::Deployed, "v1".into(), 1000);
        f.announce(&s, FeedEventKind::Deployed, "v1".into(), 1001);
        assert_eq!(f.recent("team-a", 10).len(), 4);
    }

    #[test]
    fn the_ring_is_bounded() {
        let f = Feed::new();
        let s = spec("web", "team-a", announcing());
        for i in 0..(RING_CAP as u64 + 50) {
            f.announce(&s, FeedEventKind::Updated, format!("v{i}"), i);
        }
        let events = f.recent("team-a", usize::MAX);
        assert_eq!(events.len(), RING_CAP);
        assert_eq!(events[0].detail, format!("v{}", RING_CAP + 49), "newest survives");
    }

    #[test]
    fn the_rss_document_is_well_formed_and_escaped() {
        let f = Feed::new();
        let s = spec("web", "team-a", announcing());
        f.announce(&s, FeedEventKind::Deployed, "shipped <v1> & \"friends\"".into(), 1_722_400_000);
        let events = f.recent("team-a", 10);
        let doc = rss("team-a", "https://lb.example/feeds/team-a", &events);

        assert!(doc.starts_with("<?xml"));
        assert!(doc.contains("<rss version=\"2.0\">"));
        assert!(doc.contains("<title>web deployed</title>"));
        assert!(doc.contains("shipped &lt;v1&gt; &amp; &quot;friends&quot;"));
        assert!(!doc.contains("<v1>"), "unescaped payload text would break readers");
        assert!(doc.contains("<guid isPermaLink=\"false\">applb:team-a:1</guid>"));
        assert!(doc.ends_with("</channel>\n</rss>\n"));
    }

    /// Pinned against `date -u -R -d @…`, including a leap year and both sides
    /// of a year boundary — the formatter is hand-rolled, so the calendar math
    /// is only as good as what pins it.
    #[test]
    fn rfc822_matches_the_calendar() {
        assert_eq!(rfc822(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(rfc822(951_782_400), "Tue, 29 Feb 2000 00:00:00 +0000");
        assert_eq!(rfc822(1_722_400_000), "Wed, 31 Jul 2024 04:26:40 +0000");
        assert_eq!(rfc822(1_735_689_599), "Tue, 31 Dec 2024 23:59:59 +0000");
        assert_eq!(rfc822(1_735_689_600), "Wed, 01 Jan 2025 00:00:00 +0000");
    }
}
