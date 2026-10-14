//! Response actions: the rules that turn a finding into an intervention.
//!
//! [`crate::siem`] decides that something is an attack. This is what an operator
//! can *do* about it without leaving app-lb — block an address, block a pattern
//! of traffic, and take it back off again. The two halves are deliberately
//! separate: detection is advisory and runs off the request path on its own
//! task, while enforcement is authoritative and runs *on* the request path, so
//! everything here is written to a different standard of cost and blast radius.
//!
//! ## What a rule can say
//!
//! One [`RuleMatch`] is a conjunction of literal conditions — a client prefix, a
//! hostname, a deployment, a path prefix or substring, a method, a user-agent
//! substring. Every condition that is present must hold. Absent conditions are
//! not wildcards to be evaluated; they are simply not checked.
//!
//! **No regular expressions, deliberately.** A rule is authored during an
//! incident, by someone under time pressure, and evaluated on every request to
//! the data plane. A pathological pattern would turn a mitigation into the
//! outage it was meant to prevent, and there is no expressive gap worth that:
//! the signatures that need regex live in the SIEM, which runs off the hot path
//! and can afford one.
//!
//! ## The three things that keep this from becoming the incident
//!
//! * **An empty match is refused.** `{}` is a conjunction of nothing, which is
//!   true of every request — one click from the dashboard would take the whole
//!   data plane down. [`RuleSpec::build`] rejects it rather than trusting the
//!   caller to have meant it.
//! * **The admin plane is never guarded.** Rules are consulted by
//!   [`crate::proxy`] and nowhere else, so however badly an operator blocks
//!   themselves out of the data plane, the dashboard that removes the rule is
//!   still reachable. This is the escape hatch and it must stay one.
//! * **Rules can expire.** Every suggested action the SIEM offers carries a
//!   bounded lifetime, because the realistic failure is not a missing block, it
//!   is a permanent one that outlives the attack and quietly breaks a customer
//!   six weeks later.
//!
//! `APP_LB_GUARD_ENFORCE=0` is a fourth: rules still match and still count, but
//! nothing is refused. That is how a broad rule gets deployed sanely — watch
//! what it would have caught for an hour first.
//!
//! ## Storage
//!
//! [`ArcSwap`], unlike [`crate::siem::AlertRing`]'s mutex, and the contrast is
//! the point: this list is read on every single request and written by hand a
//! few times a week, and a write replaces it wholesale rather than mutating an
//! entry. Hit counters are atomics *inside* the `Arc<Rule>`, so counting a match
//! costs one relaxed add and never a swap.
//!
//! Rules are persisted, because a restart that silently unblocks an active
//! attacker is a worse failure than any of the above.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::fleet_store::{Document, Expect, FileDocument, FileOptions};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// How many rules the data plane will carry.
///
/// Every one of them is scanned on every request that gets past the ACME
/// carve-out, so this is a latency bound as much as a memory one. A fleet that
/// genuinely needs hundreds of literal rules needs a WAF in front, not a longer
/// list here.
pub const MAX_RULES: usize = 256;

const MAX_PATTERN: usize = 256;
const MAX_HOST: usize = 253;
const MAX_UA: usize = 128;
const MAX_NOTE: usize = 256;

/// What a matching rule does to the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Refuse the request with a 403.
    Block,
    /// Exempt it. Checked against every rule before any block takes effect, so
    /// an allow always wins regardless of the order the two were created in —
    /// which is what makes "block that /16, except our own health checker" a
    /// thing an operator can express without thinking about precedence.
    Allow,
}

/// An address or a CIDR block.
///
/// Hand-rolled rather than pulling in an IP-network crate: this is two fields
/// and a masked comparison, and the dependency would exist for one call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPrefix {
    addr: IpAddr,
    bits: u8,
}

impl IpPrefix {
    /// `203.0.113.9`, `203.0.113.0/24`, `2001:db8::/32`. A bare address is the
    /// host route (`/32`, `/128`).
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (addr, bits) = match s.split_once('/') {
            Some((a, b)) => (a.trim(), Some(b.trim().parse::<u8>().ok()?)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = bits.unwrap_or(max);
        (bits <= max).then_some(Self { addr, bits })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.bits)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.bits)
            }
            // A dual-stack listener reports an IPv4 client as `::ffff:a.b.c.d`.
            // Without these two arms, blocking `203.0.113.9` would silently do
            // nothing on exactly the socket configuration most hosts run — a
            // rule that reads as applied, counts no hits, and stops nothing.
            (IpAddr::V4(_), IpAddr::V6(ip)) => ip
                .to_ipv4_mapped()
                .is_some_and(|v4| self.contains(IpAddr::V4(v4))),
            // The mirror case, and narrower on purpose: only a prefix inside
            // `::ffff:0:0/96` describes v4 space, and only at /96 or longer does
            // it still name a v4 prefix. Anything shorter is a v6 rule that
            // happens to contain the mapped range, and treating it as "all of
            // IPv4" would be a much broader block than its author wrote.
            (IpAddr::V6(net), IpAddr::V4(ip)) => {
                self.bits >= 96
                    && net.to_ipv4_mapped().is_some_and(|net| {
                        prefix_eq(&net.octets(), &ip.octets(), self.bits - 96)
                    })
            }
        }
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = matches!(
            (self.addr, self.bits),
            (IpAddr::V4(_), 32) | (IpAddr::V6(_), 128)
        );
        if host {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.bits)
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], bits: u8) -> bool {
    let whole = (bits / 8) as usize;
    if a[..whole] != b[..whole] {
        return false;
    }
    let rest = bits % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    (a[whole] & mask) == (b[whole] & mask)
}

/// The conditions, as they arrive over the wire.
///
/// Every field optional, all present ones ANDed. Kept separate from the
/// normalized [`RuleMatch`] so the parsing, casing and length rules happen once
/// at creation rather than per request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchSpec {
    /// An address or CIDR: `203.0.113.9`, `203.0.113.0/24`, `2001:db8::/32`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_contains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent_contains: Option<String>,
}

/// The same conditions, normalized: parsed prefix, lowercased host, uppercased
/// method. Nothing here allocates when a request is checked against it.
#[derive(Debug, Clone, Default)]
pub struct RuleMatch {
    client: Option<IpPrefix>,
    host: Option<String>,
    deployment: Option<String>,
    path_prefix: Option<String>,
    path_contains: Option<String>,
    method: Option<String>,
    /// Already lowercase; the request's header is compared without allocating.
    user_agent_contains: Option<String>,
}

impl RuleMatch {
    fn conditions(&self) -> usize {
        [
            self.client.is_some(),
            self.host.is_some(),
            self.deployment.is_some(),
            self.path_prefix.is_some(),
            self.path_contains.is_some(),
            self.method.is_some(),
            self.user_agent_contains.is_some(),
        ]
        .iter()
        .filter(|c| **c)
        .count()
    }

    fn matches(&self, f: &RequestFacts<'_>) -> bool {
        // Cheapest and most selective first: an address compare is a few masked
        // bytes, and a rule that names a client is the common shape.
        if let Some(net) = &self.client {
            match f.client {
                Some(ip) if net.contains(ip) => {}
                // A rule keyed on an address cannot be satisfied by a request
                // whose address is unknown. Failing open here is the right way
                // round: the alternative blocks everything the moment a peer
                // address is unavailable.
                _ => return false,
            }
        }
        if let Some(h) = &self.host
            && f.host != Some(h.as_str())
        {
            return false;
        }
        if let Some(d) = &self.deployment
            && f.deployment != Some(d.as_str())
        {
            return false;
        }
        if let Some(p) = &self.path_prefix
            && !f.path.starts_with(p.as_str())
        {
            return false;
        }
        if let Some(p) = &self.path_contains
            && !f.path.contains(p.as_str())
        {
            return false;
        }
        if let Some(m) = &self.method
            && !f.method.eq_ignore_ascii_case(m)
        {
            return false;
        }
        if let Some(ua) = &self.user_agent_contains {
            match f.user_agent {
                Some(h) if contains_ignore_ascii_case(h, ua) => {}
                _ => return false,
            }
        }
        true
    }

    fn to_spec(&self) -> MatchSpec {
        MatchSpec {
            client: self.client.map(|c| c.to_string()),
            host: self.host.clone(),
            deployment: self.deployment.clone(),
            path_prefix: self.path_prefix.clone(),
            path_contains: self.path_contains.clone(),
            method: self.method.clone(),
            user_agent_contains: self.user_agent_contains.clone(),
        }
    }

    /// A short human phrase, for the dashboard and for log lines.
    fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(c) = &self.client {
            parts.push(format!("from {c}"));
        }
        if let Some(d) = &self.deployment {
            parts.push(format!("to {d}"));
        }
        if let Some(h) = &self.host {
            parts.push(format!("host {h}"));
        }
        if let Some(m) = &self.method {
            parts.push(format!("method {m}"));
        }
        if let Some(p) = &self.path_prefix {
            parts.push(format!("path under {p}"));
        }
        if let Some(p) = &self.path_contains {
            parts.push(format!("path containing {p}"));
        }
        if let Some(u) = &self.user_agent_contains {
            parts.push(format!("user-agent containing {u}"));
        }
        if parts.is_empty() {
            // Unreachable while `build` refuses an empty match, but a rule that
            // described itself as "everything" would be worth reading twice.
            return "any request".into();
        }
        parts.join(", ")
    }
}

/// Case-insensitive substring search that allocates nothing.
///
/// `needle` must already be lowercase, and is capped at [`MAX_UA`] when the rule
/// is built. Naive, and that is fine: it only runs for rules that actually carry
/// a user-agent condition, and the proxy caps the header it passes in.
fn contains_ignore_ascii_case(haystack: &str, needle_lower: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle_lower.as_bytes());
    if n.is_empty() {
        return true;
    }
    if h.len() < n.len() {
        return false;
    }
    h.windows(n.len())
        .any(|w| w.iter().zip(n).all(|(a, b)| a.eq_ignore_ascii_case(b)))
}

/// What a caller sends to `POST /security/rules`.
///
/// `Serialize` too, because [`crate::siem`] hands one back on every alert: the
/// dashboard's action button posts exactly the body it was shown, so what the
/// operator reads and what the server applies cannot drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSpec {
    #[serde(default = "default_action")]
    pub action: RuleAction,
    #[serde(rename = "match")]
    pub match_: MatchSpec,
    /// Seconds from now. `null` is permanent, which is a real choice and has to
    /// be spelled out — the SIEM's own suggestions always set one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
    /// Why. Free text, kept so a rule found six months later can be explained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

fn default_action() -> RuleAction {
    RuleAction::Block
}

#[derive(Debug)]
pub enum GuardError {
    /// A conjunction of nothing matches everything.
    EmptyMatch,
    BadClient(String),
    TooLong(&'static str),
    Full,
    NoRule(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyMatch => write!(
                f,
                "a rule needs at least one condition — an empty match would apply to \
                 every request to the data plane"
            ),
            Self::BadClient(c) => write!(
                f,
                "match.client {c:?} is not an address or CIDR block (203.0.113.9, \
                 203.0.113.0/24, 2001:db8::/32)"
            ),
            Self::TooLong(field) => write!(f, "{field} is too long"),
            Self::Full => write!(f, "at the {MAX_RULES}-rule limit; remove one first"),
            Self::NoRule(id) => write!(f, "no rule \"{id}\""),
            Self::Io(e) => write!(f, "{e}"),
            Self::Json(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GuardError {}

impl RuleSpec {
    /// Normalize and validate. The only way a [`Rule`] is made.
    fn build(self, now: u64) -> Result<Rule, GuardError> {
        fn cap(v: Option<String>, max: usize, field: &'static str) -> Result<Option<String>, GuardError> {
            match v {
                Some(s) if s.trim().is_empty() => Ok(None),
                Some(s) if s.len() > max => Err(GuardError::TooLong(field)),
                Some(s) => Ok(Some(s.trim().to_string())),
                None => Ok(None),
            }
        }

        let m = self.match_;
        let client = match m.client.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
            Some(c) => Some(IpPrefix::parse(c).ok_or_else(|| GuardError::BadClient(c.to_string()))?),
            None => None,
        };
        let match_ = RuleMatch {
            client,
            host: cap(m.host, MAX_HOST, "match.host")?.map(|h| h.to_ascii_lowercase()),
            deployment: cap(m.deployment, MAX_HOST, "match.deployment")?,
            path_prefix: cap(m.path_prefix, MAX_PATTERN, "match.path_prefix")?,
            path_contains: cap(m.path_contains, MAX_PATTERN, "match.path_contains")?,
            method: cap(m.method, 16, "match.method")?.map(|s| s.to_ascii_uppercase()),
            user_agent_contains: cap(m.user_agent_contains, MAX_UA, "match.user_agent_contains")?
                .map(|s| s.to_ascii_lowercase()),
        };
        if match_.conditions() == 0 {
            return Err(GuardError::EmptyMatch);
        }

        Ok(Rule {
            id: rule_id(self.action, &match_),
            action: self.action,
            match_,
            note: cap(self.note, MAX_NOTE, "note")?,
            created_at: now,
            expires_at: self.expires_in_secs.map(|s| now.saturating_add(s)),
            hits: AtomicU64::new(0),
            last_hit: AtomicU64::new(0),
            series: HitSeries::new(now),
        })
    }
}

/// Content-addressed, so creating the same rule twice replaces it rather than
/// stacking two copies that both have to be found and removed later. The
/// dashboard's action buttons are one click and get clicked twice.
fn rule_id(action: RuleAction, m: &RuleMatch) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(match action {
        RuleAction::Block => b"block\0".as_slice(),
        RuleAction::Allow => b"allow\0".as_slice(),
    });
    // Field-tagged and length-prefixed: without it, `{host: "ab", path: "c"}`
    // and `{host: "a", path: "bc"}` would hash the same and one would silently
    // overwrite the other.
    let mut field = |tag: u8, v: Option<&str>| {
        h.update([tag]);
        match v {
            Some(s) => {
                h.update((s.len() as u32).to_le_bytes());
                h.update(s.as_bytes());
            }
            None => h.update([0xff]),
        }
    };
    let client = m.client.map(|c| c.to_string());
    field(1, client.as_deref());
    field(2, m.host.as_deref());
    field(3, m.deployment.as_deref());
    field(4, m.path_prefix.as_deref());
    field(5, m.path_contains.as_deref());
    field(6, m.method.as_deref());
    field(7, m.user_agent_contains.as_deref());
    let digest = h.finalize();
    digest[..6].iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Buckets in a [`HitSeries`], and how wide each one is.
///
/// An hour at one-minute resolution. The question this answers is "is this rule
/// still earning the branch it costs on every request?", which is a
/// tens-of-minutes question — a two-second sparkline cannot distinguish a rule
/// that fired twice this morning from one that has never fired at all, and a
/// week of history would need real storage. Sixty `u32`s is 240 bytes per rule.
pub const HIT_BUCKETS: usize = 60;
pub const HIT_BUCKET_SECS: u64 = 60;

/// A rolling count of hits per minute over the last hour.
///
/// Atomics rather than a mutex because this is written from the request path,
/// under exactly the conditions where a lock is worst: a rule matching every
/// request from an address that is currently flooding the LB.
struct HitSeries {
    buckets: [AtomicU32; HIT_BUCKETS],
    /// The absolute bucket index (`epoch_secs / HIT_BUCKET_SECS`) whose count is
    /// currently at slot `head % HIT_BUCKETS`. Monotonic.
    head: AtomicU64,
}

impl HitSeries {
    fn new(now: u64) -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU32::new(0)),
            head: AtomicU64::new(now / HIT_BUCKET_SECS),
        }
    }

    fn record(&self, now: u64) {
        let bucket = now / HIT_BUCKET_SECS;
        self.roll_to(bucket);
        self.buckets[(bucket % HIT_BUCKETS as u64) as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Advance the ring to `bucket`, zeroing whatever it laps.
    ///
    /// One writer wins the CAS and does the zeroing. A hit landing in the
    /// window between that CAS and the store it clears is lost — which is
    /// accepted, deliberately: this drives a chart, and paying for exactness
    /// here would mean a lock on the request path. The cumulative `hits` counter
    /// is the number to trust, and it is never touched by this.
    fn roll_to(&self, bucket: u64) {
        loop {
            let head = self.head.load(Ordering::Acquire);
            if bucket <= head {
                return;
            }
            if self
                .head
                .compare_exchange(head, bucket, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // Capped at one lap: a rule idle for a day must not cost a
                // 1,440-iteration loop on its next hit.
                let lapped = (bucket - head).min(HIT_BUCKETS as u64);
                for step in 1..=lapped {
                    let slot = ((head + step) % HIT_BUCKETS as u64) as usize;
                    self.buckets[slot].store(0, Ordering::Relaxed);
                }
                return;
            }
        }
    }

    /// Copy the ring, rolled to `now`.
    ///
    /// For [`Guard::set_expiry`], which rebuilds a rule rather than mutating one
    /// behind an `ArcSwap`. Without this the chart would reset every time an
    /// operator extended a block — losing exactly the evidence that justified
    /// extending it.
    fn clone_from_now(&self, now: u64) -> Self {
        self.roll_to(now / HIT_BUCKET_SECS);
        Self {
            buckets: std::array::from_fn(|i| {
                AtomicU32::new(self.buckets[i].load(Ordering::Relaxed))
            }),
            head: AtomicU64::new(self.head.load(Ordering::Acquire)),
        }
    }

    /// The last [`HIT_BUCKETS`] buckets, oldest first, as of `now`.
    ///
    /// Rolls first, so a rule that stopped firing half an hour ago reports the
    /// zeroes it has earned since rather than a frozen tail of old counts.
    fn snapshot(&self, now: u64) -> Vec<u32> {
        let bucket = now / HIT_BUCKET_SECS;
        self.roll_to(bucket);
        let head = self.head.load(Ordering::Acquire);
        (0..HIT_BUCKETS)
            .map(|i| {
                // Oldest first: the slot holding bucket `head - (BUCKETS-1-i)`.
                //
                // `checked_sub`, not `wrapping_sub`: a bucket older than the
                // series itself never existed, and wrapping would send the
                // modulo to an arbitrary live slot and report that slot's count
                // twice. Only reachable when `head < HIT_BUCKETS` — i.e. within
                // the first hour of the epoch the ring was seeded from, which
                // real clocks never are and tests always are.
                let age = (HIT_BUCKETS - 1 - i) as u64;
                match head.checked_sub(age) {
                    Some(bucket) => {
                        let idx = (bucket % HIT_BUCKETS as u64) as usize;
                        self.buckets[idx].load(Ordering::Relaxed)
                    }
                    None => 0,
                }
            })
            .collect()
    }
}

/// One live rule.
pub struct Rule {
    pub id: String,
    pub action: RuleAction,
    match_: RuleMatch,
    pub note: Option<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    hits: AtomicU64,
    /// Epoch seconds, `0` for never.
    last_hit: AtomicU64,
    /// Hits per minute over the last hour, for the console's per-rule chart.
    /// In-memory only: it is telemetry about the running process, and restoring
    /// an hour of counts from a file written days ago would be a lie.
    series: HitSeries,
}

impl Rule {
    fn expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|e| now >= e)
    }

    fn record_hit(&self, now: u64) {
        self.hits.fetch_add(1, Ordering::Relaxed);
        self.last_hit.store(now, Ordering::Relaxed);
        self.series.record(now);
    }

    pub fn describe(&self) -> String {
        self.match_.describe()
    }

    pub fn view(&self, enforcing: bool) -> RuleView {
        let last = self.last_hit.load(Ordering::Relaxed);
        RuleView {
            id: self.id.clone(),
            action: self.action,
            match_: self.match_.to_spec(),
            summary: self.match_.describe(),
            note: self.note.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            hits: self.hits.load(Ordering::Relaxed),
            last_hit: (last != 0).then_some(last),
            // Per rule rather than only on the guard, so a dashboard row can say
            // "would block" on the row itself instead of in a banner somewhere
            // else on the page.
            enforcing: enforcing || self.action == RuleAction::Allow,
            // Left empty here on purpose — see `report`.
            hits_recent: Vec::new(),
        }
    }

    /// [`view`](Self::view) plus the rolling hit series.
    ///
    /// A second constructor rather than a flag on `view`, because `RuleView` is
    /// *also* the persisted form: `Guard::persist` writes exactly what `view`
    /// produces. An hour of per-minute counts has no business in that file — it
    /// describes this process, not the rule — and this split is what keeps it
    /// out without anyone having to remember to clear it before writing.
    pub fn report(&self, enforcing: bool, now: u64) -> RuleView {
        RuleView {
            hits_recent: self.series.snapshot(now),
            ..self.view(enforcing)
        }
    }

    /// Which deployment this rule concerns, for narrowing a scoped caller's view.
    pub fn deployment(&self) -> Option<&str> {
        self.match_.deployment.as_deref()
    }
}

impl std::fmt::Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rule")
            .field("id", &self.id)
            .field("action", &self.action)
            .field("match", &self.match_)
            .finish()
    }
}

/// One rule, as `GET /security` and the persisted file carry it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleView {
    pub id: String,
    pub action: RuleAction,
    #[serde(rename = "match")]
    pub match_: MatchSpec,
    /// The conditions in a phrase, so a client does not have to render them.
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub hits: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_hit: Option<u64>,
    #[serde(default = "yes")]
    pub enforcing: bool,
    /// Hits per minute over the last hour, oldest first. Populated only by
    /// [`Rule::report`], so it is present on `GET /security` and absent from the
    /// persisted file — hence `skip_serializing_if`, which is what keeps a
    /// restored rule from carrying a stale hour of somebody else's traffic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hits_recent: Vec<u32>,
}

fn yes() -> bool {
    true
}

/// What the proxy knows about a request when the guard runs.
pub struct RequestFacts<'a> {
    pub client: Option<IpAddr>,
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub method: &'a str,
    pub deployment: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// The verdict for one request.
pub enum Decision {
    Pass,
    Block(Arc<Rule>),
    /// Matched a blocking rule while `APP_LB_GUARD_ENFORCE=0`. Counted and
    /// logged, then allowed through — the dry run that makes a broad rule
    /// deployable.
    WouldBlock(Arc<Rule>),
}

#[derive(Debug, Clone, Serialize)]
pub struct GuardStats {
    pub rules: usize,
    pub blocked: u64,
    pub exempted: u64,
    pub enforcing: bool,
    /// Requests refused per minute over the last hour, oldest first. The
    /// headline the console charts: a flat line at zero with rules in force is
    /// the "paying for nothing" case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_recent: Vec<u32>,
    /// The same for requests an `allow` rule exempted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exempted_recent: Vec<u32>,
    /// How to read the two series above, so a client does not hard-code it.
    pub hits_bucket_secs: u64,
    pub hits_window_secs: u64,
}

/// The rule set, and the file it survives a restart in.
pub struct Guard {
    rules: ArcSwap<Vec<Arc<Rule>>>,
    /// Serializes read-modify-write on `rules`. Two concurrent `POST`s would
    /// otherwise each swap in a list built from the same starting point and one
    /// rule would vanish.
    write: Mutex<()>,
    path: PathBuf,
    file: Arc<dyn Document>,
    enforce: bool,
    blocked: AtomicU64,
    exempted: AtomicU64,
    /// Fleet-level counterparts to each rule's own series, so the console can
    /// chart "requests refused" without summing every rule client-side — and so
    /// the total survives the rule that produced it being removed.
    blocked_series: HitSeries,
    exempted_series: HitSeries,
}

impl Guard {
    pub fn new(path: impl Into<PathBuf>, enforce: bool) -> Self {
        let path = path.into();
        let file = Arc::new(FileDocument::new(&path, FileOptions::PLAIN));
        Self::with_document(path, file, enforce)
    }

    /// The same guard over another backend. `path` is only reported.
    pub fn with_document(path: impl Into<PathBuf>, file: Arc<dyn Document>, enforce: bool) -> Self {
        Self {
            rules: ArcSwap::from_pointee(Vec::new()),
            write: Mutex::new(()),
            path: path.into(),
            file,
            enforce,
            blocked: AtomicU64::new(0),
            exempted: AtomicU64::new(0),
            // Zero rather than "now": `Guard::new` runs at startup, and seeding
            // the ring from a clock read here vs. at the first hit makes no
            // difference to a series that rolls on read.
            blocked_series: HitSeries::new(0),
            exempted_series: HitSeries::new(0),
        }
    }

    pub fn from_env(path: impl Into<PathBuf>) -> Self {
        Self::new(path, crate::obs::env_flag("APP_LB_GUARD_ENFORCE", true))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn enforcing(&self) -> bool {
        self.enforce
    }

    /// The hot path. One `ArcSwap` load, and an early return the moment there is
    /// nothing to check — which is the state every app-lb is in until somebody
    /// clicks a button.
    pub fn decide(&self, f: &RequestFacts<'_>, now: u64) -> Decision {
        let rules = self.rules.load();
        if rules.is_empty() {
            return Decision::Pass;
        }

        // One pass, but an allow anywhere in the list beats a block anywhere
        // else. Scanning for the block first and returning early would make the
        // outcome depend on creation order, which is not something an operator
        // should have to reason about while an attack is in progress.
        let mut blocked: Option<&Arc<Rule>> = None;
        for rule in rules.iter() {
            if rule.expired(now) || !rule.match_.matches(f) {
                continue;
            }
            match rule.action {
                RuleAction::Allow => {
                    rule.record_hit(now);
                    self.exempted.fetch_add(1, Ordering::Relaxed);
                    self.exempted_series.record(now);
                    return Decision::Pass;
                }
                RuleAction::Block if blocked.is_none() => blocked = Some(rule),
                RuleAction::Block => {}
            }
        }

        match blocked {
            None => Decision::Pass,
            Some(rule) => {
                rule.record_hit(now);
                self.blocked.fetch_add(1, Ordering::Relaxed);
                // Counted in the dry run too: the whole point of
                // `APP_LB_GUARD_ENFORCE=0` is to see what a rule *would* refuse
                // before arming it, and a flat chart would defeat that.
                self.blocked_series.record(now);
                if self.enforce {
                    Decision::Block(rule.clone())
                } else {
                    Decision::WouldBlock(rule.clone())
                }
            }
        }
    }

    pub fn list(&self) -> Vec<Arc<Rule>> {
        self.rules.load().as_ref().clone()
    }

    /// Counters plus the rolling series, as of `now`.
    ///
    /// Takes the clock because the series must be *rolled* before it is read —
    /// otherwise a guard that stopped refusing anything half an hour ago still
    /// reports the counts it earned before that, and the chart says the rules
    /// are working when they have not fired since.
    pub fn stats(&self, now: u64) -> GuardStats {
        GuardStats {
            rules: self.rules.load().len(),
            blocked: self.blocked.load(Ordering::Relaxed),
            exempted: self.exempted.load(Ordering::Relaxed),
            enforcing: self.enforce,
            blocked_recent: self.blocked_series.snapshot(now),
            exempted_recent: self.exempted_series.snapshot(now),
            hits_bucket_secs: HIT_BUCKET_SECS,
            hits_window_secs: HIT_BUCKET_SECS * HIT_BUCKETS as u64,
        }
    }

    /// Add a rule, replacing any existing one with the same conditions.
    ///
    /// Replacement rather than rejection: re-issuing a block is how an operator
    /// extends one that is about to expire, and a duplicate-id error in the
    /// middle of an incident is an obstacle rather than a safeguard. The hit
    /// counter starts again, which is the honest reading — it counts what *this*
    /// rule stopped.
    pub fn insert(&self, spec: RuleSpec, now: u64) -> Result<Arc<Rule>, GuardError> {
        let rule = Arc::new(spec.build(now)?);
        let _w = self.write.lock().expect("guard write lock");
        let mut next: Vec<Arc<Rule>> = self
            .rules
            .load()
            .iter()
            .filter(|r| r.id != rule.id && !r.expired(now))
            .cloned()
            .collect();
        if next.len() >= MAX_RULES {
            return Err(GuardError::Full);
        }
        next.push(rule.clone());
        self.rules.store(Arc::new(next));
        Ok(rule)
    }

    pub fn remove(&self, id: &str, now: u64) -> Result<(), GuardError> {
        let _w = self.write.lock().expect("guard write lock");
        let current = self.rules.load();
        if !current.iter().any(|r| r.id == id) {
            return Err(GuardError::NoRule(id.to_string()));
        }
        let next: Vec<Arc<Rule>> = current
            .iter()
            .filter(|r| r.id != id && !r.expired(now))
            .cloned()
            .collect();
        self.rules.store(Arc::new(next));
        Ok(())
    }

    /// Change when a rule expires — including never.
    ///
    /// `expires_in_secs: None` makes it permanent, which is the point: a rule
    /// authored during an incident carries a bounded lifetime by design (see the
    /// module docs), and the operator who has since decided that address is
    /// simply not welcome should be able to say so without re-authoring the
    /// match and losing its hit history.
    ///
    /// A rebuild rather than a mutation, because `expires_at` is a plain field
    /// on a rule behind an `ArcSwap` — the hot path reads it without a lock, so
    /// it is not something to change in place. The counters and the hit series
    /// are carried across: this is the same rule, with a new deadline.
    pub fn set_expiry(
        &self,
        id: &str,
        expires_in_secs: Option<u64>,
        now: u64,
    ) -> Result<RuleView, GuardError> {
        let _w = self.write.lock().expect("guard write lock");
        let current = self.rules.load();
        let Some(existing) = current.iter().find(|r| r.id == id && !r.expired(now)) else {
            return Err(GuardError::NoRule(id.to_string()));
        };

        let replacement = Arc::new(Rule {
            id: existing.id.clone(),
            action: existing.action,
            match_: existing.match_.clone(),
            note: existing.note.clone(),
            created_at: existing.created_at,
            expires_at: expires_in_secs.map(|s| now.saturating_add(s)),
            // Carried over, so extending a rule does not reset the evidence that
            // it is working.
            hits: AtomicU64::new(existing.hits.load(Ordering::Relaxed)),
            last_hit: AtomicU64::new(existing.last_hit.load(Ordering::Relaxed)),
            series: existing.series.clone_from_now(now),
        });

        let view = replacement.report(self.enforce, now);
        let next: Vec<Arc<Rule>> = current
            .iter()
            .filter(|r| r.id != id && !r.expired(now))
            .cloned()
            .chain(std::iter::once(replacement))
            .collect();
        self.rules.store(Arc::new(next));
        Ok(view)
    }

    /// Drop expired rules. Returns how many went.
    ///
    /// Expiry is enforced in [`Self::decide`] regardless, so this is bookkeeping
    /// rather than correctness: it keeps the list — and the page that shows it —
    /// from filling with rules that stopped doing anything days ago.
    pub fn sweep(&self, now: u64) -> usize {
        let _w = self.write.lock().expect("guard write lock");
        let current = self.rules.load();
        let next: Vec<Arc<Rule>> = current.iter().filter(|r| !r.expired(now)).cloned().collect();
        let dropped = current.len() - next.len();
        if dropped > 0 {
            self.rules.store(Arc::new(next));
        }
        dropped
    }

    /// Write the rule set out, atomically.
    pub fn persist(&self) -> Result<(), GuardError> {
        let rules: Vec<RuleView> = self
            .rules
            .load()
            .iter()
            .map(|r| r.view(self.enforce))
            .collect();
        let json = serde_json::to_vec_pretty(&StoredRules { version: 1, rules })
            .map_err(GuardError::Json)?;
        self.file
            .write(&json, Expect::Any)
            .map_err(|e| GuardError::Io(e.into()))?;
        Ok(())
    }

    /// Load the rule set, dropping anything that expired while the process was
    /// down. Returns how many were loaded. A missing file is not an error.
    pub fn load(&self, now: u64) -> Result<usize, GuardError> {
        let bytes = match self.file.read().map_err(GuardError::Io)? {
            Some((b, _)) => b,
            None => return Ok(0),
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(0);
        }
        let stored: StoredRules = serde_json::from_slice(&bytes).map_err(GuardError::Json)?;

        let mut rules = Vec::new();
        for view in stored.rules {
            if view.expires_at.is_some_and(|e| now >= e) {
                continue;
            }
            // Rebuilt through `build`, not trusted from the file: the normalizing
            // and the empty-match refusal have to hold for a hand-edited file
            // exactly as they do for the API. Hit counts are restored after,
            // since they are history rather than configuration.
            let spec = RuleSpec {
                action: view.action,
                match_: view.match_,
                expires_in_secs: None,
                note: view.note,
            };
            let mut rule = spec.build(view.created_at)?;
            rule.expires_at = view.expires_at;
            rule.hits = AtomicU64::new(view.hits);
            rule.last_hit = AtomicU64::new(view.last_hit.unwrap_or(0));
            rules.push(Arc::new(rule));
            if rules.len() >= MAX_RULES {
                break;
            }
        }
        let n = rules.len();
        self.rules.store(Arc::new(rules));
        Ok(n)
    }
}

#[derive(Serialize, Deserialize)]
struct StoredRules {
    #[serde(default)]
    version: u32,
    rules: Vec<RuleView>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts<'a>(client: &str, path: &'a str) -> RequestFacts<'a> {
        RequestFacts {
            client: client.parse().ok(),
            host: Some("demo.local"),
            path,
            method: "GET",
            deployment: Some("demo"),
            user_agent: Some("Mozilla/5.0 (curl)"),
        }
    }

    fn spec(m: MatchSpec) -> RuleSpec {
        RuleSpec {
            action: RuleAction::Block,
            match_: m,
            expires_in_secs: None,
            note: None,
        }
    }

    fn client(c: &str) -> MatchSpec {
        MatchSpec {
            client: Some(c.into()),
            ..Default::default()
        }
    }

    fn blocked(d: &Decision) -> bool {
        matches!(d, Decision::Block(_))
    }

    #[test]
    fn a_bare_address_blocks_exactly_that_address() {
        let g = Guard::new("", true);
        g.insert(spec(client("203.0.113.9")), 100).unwrap();
        assert!(blocked(&g.decide(&facts("203.0.113.9", "/"), 100)));
        assert!(!blocked(&g.decide(&facts("203.0.113.10", "/"), 100)));
    }

    #[test]
    fn a_cidr_blocks_the_whole_range_and_nothing_past_it() {
        let g = Guard::new("", true);
        g.insert(spec(client("203.0.113.0/24")), 100).unwrap();
        assert!(blocked(&g.decide(&facts("203.0.113.1", "/"), 100)));
        assert!(blocked(&g.decide(&facts("203.0.113.255", "/"), 100)));
        assert!(!blocked(&g.decide(&facts("203.0.114.1", "/"), 100)));
    }

    /// A `/26` exercises the partial-byte mask, which is the half of
    /// `prefix_eq` a byte-aligned prefix never reaches.
    #[test]
    fn a_prefix_that_is_not_byte_aligned_masks_correctly() {
        let g = Guard::new("", true);
        g.insert(spec(client("10.0.0.0/26")), 100).unwrap();
        assert!(blocked(&g.decide(&facts("10.0.0.63", "/"), 100)));
        assert!(!blocked(&g.decide(&facts("10.0.0.64", "/"), 100)));
    }

    /// Regression: a dual-stack listener reports IPv4 peers as `::ffff:a.b.c.d`,
    /// so without the mapped-address arms an IPv4 rule would count zero hits and
    /// stop nothing on the socket configuration most hosts actually run.
    #[test]
    fn an_ipv4_rule_still_catches_a_v4_mapped_v6_client() {
        let g = Guard::new("", true);
        g.insert(spec(client("203.0.113.0/24")), 100).unwrap();
        assert!(blocked(&g.decide(&facts("::ffff:203.0.113.7", "/"), 100)));
        assert!(!blocked(&g.decide(&facts("::ffff:198.51.100.7", "/"), 100)));
    }

    #[test]
    fn an_ipv6_prefix_blocks_a_whole_64() {
        let g = Guard::new("", true);
        g.insert(spec(client("2001:db8:1:2::/64")), 100).unwrap();
        assert!(blocked(&g.decide(&facts("2001:db8:1:2:dead:beef::1", "/"), 100)));
        assert!(!blocked(&g.decide(&facts("2001:db8:1:3::1", "/"), 100)));
    }

    #[test]
    fn conditions_are_anded_not_ored() {
        let g = Guard::new("", true);
        g.insert(
            spec(MatchSpec {
                client: Some("203.0.113.9".into()),
                path_prefix: Some("/admin".into()),
                ..Default::default()
            }),
            100,
        )
        .unwrap();
        assert!(blocked(&g.decide(&facts("203.0.113.9", "/admin/x"), 100)));
        // Right address, wrong path.
        assert!(!blocked(&g.decide(&facts("203.0.113.9", "/public"), 100)));
        // Right path, wrong address.
        assert!(!blocked(&g.decide(&facts("198.51.100.1", "/admin/x"), 100)));
    }

    /// The single most dangerous input this API can receive: a match that names
    /// nothing is true of every request, and one click would take the data plane
    /// down.
    #[test]
    fn an_empty_match_is_refused() {
        let g = Guard::new("", true);
        let e = g.insert(spec(MatchSpec::default()), 100).unwrap_err();
        assert!(matches!(e, GuardError::EmptyMatch), "{e}");
        assert!(g.list().is_empty());
        // Whitespace is not a condition either.
        assert!(g
            .insert(
                spec(MatchSpec {
                    host: Some("   ".into()),
                    ..Default::default()
                }),
                100
            )
            .is_err());
    }

    #[test]
    fn an_allow_beats_a_block_whichever_was_created_first() {
        for allow_first in [true, false] {
            let g = Guard::new("", true);
            let block = spec(client("10.0.0.0/8"));
            let allow = RuleSpec {
                action: RuleAction::Allow,
                match_: client("10.1.2.3"),
                expires_in_secs: None,
                note: None,
            };
            if allow_first {
                g.insert(allow, 100).unwrap();
                g.insert(block, 100).unwrap();
            } else {
                g.insert(block, 100).unwrap();
                g.insert(allow, 100).unwrap();
            }
            assert!(!blocked(&g.decide(&facts("10.1.2.3", "/"), 100)), "allow_first={allow_first}");
            assert!(blocked(&g.decide(&facts("10.1.2.4", "/"), 100)), "allow_first={allow_first}");
        }
    }

    #[test]
    fn an_expired_rule_stops_matching_without_being_swept() {
        let g = Guard::new("", true);
        g.insert(
            RuleSpec {
                action: RuleAction::Block,
                match_: client("203.0.113.9"),
                expires_in_secs: Some(60),
                note: None,
            },
            100,
        )
        .unwrap();
        assert!(blocked(&g.decide(&facts("203.0.113.9", "/"), 159)));
        assert!(!blocked(&g.decide(&facts("203.0.113.9", "/"), 160)));
        assert_eq!(g.list().len(), 1, "still listed until swept");
        assert_eq!(g.sweep(160), 1);
        assert!(g.list().is_empty());
    }

    /// What a rule set costs the request path.
    ///
    /// `#[ignore]`d: it is a measurement, not an assertion, and a timing check
    /// in CI is a flake waiting to happen. Run it deliberately:
    ///
    /// ```sh
    /// cargo test --release --bin app-lb guard_cost -- --ignored --nocapture
    /// ```
    ///
    /// The number that matters is the *miss* path — normal traffic matching no
    /// rule — because `decide` never exits early: an `allow` anywhere in the
    /// list beats a `block` anywhere else, so every request scans every rule.
    mod guard_cost {
        use super::*;
        use std::hint::black_box;
        use std::time::Instant;

        const ITERS: u32 = 200_000;

        fn bench(label: &str, g: &Guard, f: &RequestFacts<'_>) {
            // Warm the branch predictor and the cache lines the scan walks.
            for _ in 0..10_000 {
                black_box(g.decide(black_box(f), 1_000));
            }
            let t0 = Instant::now();
            for _ in 0..ITERS {
                black_box(g.decide(black_box(f), 1_000));
            }
            let per = t0.elapsed().as_nanos() as f64 / ITERS as f64;
            println!(
                "  {label:<52} {per:>8.1} ns/request  ({:.2} µs per 1k req)",
                per * 1000.0 / 1000.0,
            );
        }

        fn ua() -> &'static str {
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        }

        #[test]
        #[ignore = "measurement, not an assertion"]
        fn scan_cost_by_rule_count_and_shape() {
            println!("\nmiss path — the cost every ordinary request pays:\n");

            for n in [0usize, 16, 64, 256] {
                // The common shape: blocking addresses. Each rule fails on the
                // first check, an masked address compare.
                let g = Guard::new("", true);
                for i in 0..n {
                    let _ = g.insert(
                        spec(client(&format!("10.{}.{}.0/24", i / 256, i % 256))),
                        0,
                    );
                }
                let f = facts("203.0.113.9", "/api/v1/things");
                bench(&format!("{n:>3} client rules, no match"), &g, &f);
            }

            println!();
            for n in [16usize, 64, 256] {
                // The expensive shape: two substring searches per rule against a
                // realistic user-agent, none of which match.
                let g = Guard::new("", true);
                for i in 0..n {
                    let _ = g.insert(
                        spec(MatchSpec {
                            path_contains: Some(format!("/probe-{i}")),
                            user_agent_contains: Some(format!("scanner-{i}")),
                            ..Default::default()
                        }),
                        0,
                    );
                }
                let f = RequestFacts {
                    user_agent: Some(ua()),
                    ..facts("203.0.113.9", "/api/v1/things")
                };
                bench(&format!("{n:>3} path+user-agent substring rules"), &g, &f);
            }

            println!();
            // The worst realistic case: a rule that matches, so the scan runs to
            // completion *and* records a hit into the ring.
            let g = Guard::new("", true);
            for i in 0..255 {
                let _ = g.insert(spec(client(&format!("10.{}.0.0/16", i % 256))), 0);
            }
            let _ = g.insert(spec(client("203.0.113.9")), 0);
            let f = facts("203.0.113.9", "/api/v1/things");
            bench("256 client rules, last one matches (blocked)", &g, &f);
            println!();
        }
    }

    /// The per-rule hit chart. Its whole job is to distinguish a rule that is
    /// still catching traffic from one that is costing a comparison on every
    /// request and refusing nothing.
    mod hit_series {
        use super::*;

        fn hit_at(g: &Guard, t: u64) {
            assert!(blocked(&g.decide(&facts("203.0.113.9", "/"), t)));
        }

        #[test]
        fn hits_land_in_the_bucket_for_their_minute() {
            let g = Guard::new("", true);
            g.insert(spec(client("203.0.113.9")), 0).unwrap();

            hit_at(&g, 0);
            hit_at(&g, 30); // same minute
            hit_at(&g, 60); // the next one

            let s = g.list()[0].report(true, 60).hits_recent;
            assert_eq!(s.len(), HIT_BUCKETS);
            assert_eq!(s[HIT_BUCKETS - 1], 1, "newest bucket is `now`");
            assert_eq!(s[HIT_BUCKETS - 2], 2, "the two from the minute before");
            assert_eq!(s.iter().sum::<u32>(), 3);
        }

        /// The failure this replaces: reading a stale ring. A rule that stopped
        /// firing must report zeroes, not the counts it earned an hour ago.
        #[test]
        fn a_rule_that_went_quiet_reports_zeroes() {
            let g = Guard::new("", true);
            g.insert(spec(client("203.0.113.9")), 0).unwrap();
            hit_at(&g, 0);

            let rule = &g.list()[0];
            assert_eq!(rule.report(true, 0).hits_recent.iter().sum::<u32>(), 1);

            // An hour later, with nothing in between.
            let later = HIT_BUCKET_SECS * HIT_BUCKETS as u64;
            assert_eq!(
                rule.report(true, later).hits_recent.iter().sum::<u32>(),
                0,
                "the window rolled past that hit",
            );
            // The cumulative counter is the one that must not move.
            assert_eq!(rule.report(true, later).hits, 1);
        }

        /// A rule idle for a week must not cost a bucket-per-minute loop, and
        /// must not resurrect counts from whatever slot the modulo lands on.
        #[test]
        fn a_long_silence_clears_the_whole_ring_exactly_once() {
            let g = Guard::new("", true);
            g.insert(spec(client("203.0.113.9")), 0).unwrap();
            for minute in 0..HIT_BUCKETS as u64 {
                hit_at(&g, minute * HIT_BUCKET_SECS);
            }
            let rule = &g.list()[0];
            assert_eq!(rule.report(true, 3599).hits_recent.iter().sum::<u32>(), 60);

            let week = 7 * 24 * 3600;
            let s = rule.report(true, week).hits_recent;
            assert!(s.iter().all(|&v| v == 0), "stale counts survived a lap: {s:?}");
        }

        /// The guard-wide series is what answers "is enforcement doing anything
        /// at all", so it has to count in the dry run too — that is the mode you
        /// watch before arming a broad rule.
        #[test]
        fn the_fleet_series_counts_refusals_including_a_dry_run() {
            for enforce in [true, false] {
                let g = Guard::new("", enforce);
                g.insert(spec(client("203.0.113.9")), 0).unwrap();
                let _ = g.decide(&facts("203.0.113.9", "/"), 0);
                let stats = g.stats(0);
                assert_eq!(
                    stats.blocked_recent.iter().sum::<u32>(),
                    1,
                    "enforce={enforce}",
                );
                assert_eq!(stats.hits_bucket_secs, HIT_BUCKET_SECS);
                assert_eq!(stats.hits_window_secs, HIT_BUCKET_SECS * HIT_BUCKETS as u64);
            }
        }

        #[test]
        fn an_allow_feeds_the_exempted_series_not_the_blocked_one() {
            let g = Guard::new("", true);
            g.insert(spec(client("203.0.113.9")), 0).unwrap();
            g.insert(
                RuleSpec {
                    action: RuleAction::Allow,
                    match_: client("203.0.113.9"),
                    expires_in_secs: None,
                    note: None,
                },
                0,
            )
            .unwrap();

            assert!(!blocked(&g.decide(&facts("203.0.113.9", "/"), 0)));
            let stats = g.stats(0);
            assert_eq!(stats.exempted_recent.iter().sum::<u32>(), 1);
            assert_eq!(stats.blocked_recent.iter().sum::<u32>(), 0);
        }

        /// `RuleView` doubles as the persisted form. An hour of per-minute
        /// counts describes this process, not the rule, and writing it would
        /// mean a restored rule showing traffic it never saw.
        #[test]
        fn the_series_is_reported_but_never_persisted() {
            let g = Guard::new("", true);
            g.insert(spec(client("203.0.113.9")), 0).unwrap();
            hit_at(&g, 0);

            let rule = &g.list()[0];
            assert!(!rule.report(true, 0).hits_recent.is_empty(), "the API sees it");
            assert!(rule.view(true).hits_recent.is_empty(), "the file does not");

            let stored = serde_json::to_string(&rule.view(true)).unwrap();
            assert!(!stored.contains("hits_recent"), "{stored}");
        }
    }

    /// Making a rule permanent, and the history that has to survive it.
    mod set_expiry {
        use super::*;

        fn timed(secs: u64) -> RuleSpec {
            RuleSpec {
                expires_in_secs: Some(secs),
                ..spec(client("203.0.113.9"))
            }
        }

        #[test]
        fn a_timed_rule_can_be_made_permanent() {
            let g = Guard::new("", true);
            let id = g.insert(timed(60), 100).unwrap().id.clone();
            assert!(g.list()[0].expires_at.is_some());

            let view = g.set_expiry(&id, None, 100).unwrap();
            assert_eq!(view.expires_at, None);
            assert_eq!(g.list().len(), 1, "replaced, not added");
            assert!(g.list()[0].expires_at.is_none());
            // And it is still enforced long past when it would have lapsed.
            assert!(blocked(&g.decide(&facts("203.0.113.9", "/"), 10_000_000)));
        }

        /// Extending a rule must not reset the evidence that justified
        /// extending it.
        #[test]
        fn the_hit_history_carries_across() {
            let g = Guard::new("", true);
            let id = g.insert(spec(client("203.0.113.9")), 0).unwrap().id.clone();
            assert!(blocked(&g.decide(&facts("203.0.113.9", "/"), 0)));

            let view = g.set_expiry(&id, None, 0).unwrap();
            assert_eq!(view.hits, 1, "cumulative count survived");
            assert_eq!(view.hits_recent.iter().sum::<u32>(), 1, "and so did the chart");
        }

        #[test]
        fn a_permanent_rule_can_be_given_a_deadline_again() {
            let g = Guard::new("", true);
            let id = g.insert(spec(client("203.0.113.9")), 100).unwrap().id.clone();
            assert!(g.list()[0].expires_at.is_none(), "starts permanent");

            g.set_expiry(&id, Some(60), 100).unwrap();
            assert_eq!(g.list()[0].expires_at, Some(160));
            assert!(!blocked(&g.decide(&facts("203.0.113.9", "/"), 160)));
        }

        #[test]
        fn an_unknown_or_expired_rule_is_not_found() {
            let g = Guard::new("", true);
            let id = g.insert(timed(60), 100).unwrap().id.clone();
            assert!(matches!(
                g.set_expiry("nope", None, 100),
                Err(GuardError::NoRule(_))
            ));
            // Already lapsed: reviving it would resurrect a block the operator
            // watched expire.
            assert!(matches!(
                g.set_expiry(&id, None, 10_000),
                Err(GuardError::NoRule(_))
            ));
        }
    }

    /// `APP_LB_GUARD_ENFORCE=0`: the rule matches and counts, and the request
    /// still goes through. Without the count the dry run tells you nothing.
    #[test]
    fn a_dry_run_counts_what_it_would_have_blocked_and_blocks_nothing() {
        let g = Guard::new("", false);
        g.insert(spec(client("203.0.113.9")), 100).unwrap();
        assert!(matches!(
            g.decide(&facts("203.0.113.9", "/"), 100),
            Decision::WouldBlock(_)
        ));
        assert_eq!(g.stats(100).blocked, 1);
        assert!(!g.stats(100).enforcing);
        assert_eq!(g.list()[0].view(false).hits, 1);
    }

    #[test]
    fn the_same_conditions_replace_rather_than_stack() {
        let g = Guard::new("", true);
        let a = g.insert(spec(client("203.0.113.9")), 100).unwrap();
        let b = g.insert(spec(client("203.0.113.9")), 200).unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(g.list().len(), 1);
        assert_eq!(g.list()[0].created_at, 200);
    }

    /// Different rules must not collide onto one id, or creating the second
    /// would silently delete the first.
    #[test]
    fn distinct_conditions_get_distinct_ids() {
        let g = Guard::new("", true);
        g.insert(
            spec(MatchSpec {
                host: Some("ab".into()),
                path_prefix: Some("c".into()),
                ..Default::default()
            }),
            100,
        )
        .unwrap();
        g.insert(
            spec(MatchSpec {
                host: Some("a".into()),
                path_prefix: Some("bc".into()),
                ..Default::default()
            }),
            100,
        )
        .unwrap();
        assert_eq!(g.list().len(), 2);
        // An allow and a block over the same conditions are also distinct.
        g.insert(
            RuleSpec {
                action: RuleAction::Allow,
                match_: MatchSpec {
                    host: Some("ab".into()),
                    path_prefix: Some("c".into()),
                    ..Default::default()
                },
                expires_in_secs: None,
                note: None,
            },
            100,
        )
        .unwrap();
        assert_eq!(g.list().len(), 3);
    }

    #[test]
    fn a_user_agent_condition_is_case_insensitive_and_allocation_free() {
        let g = Guard::new("", true);
        g.insert(
            spec(MatchSpec {
                user_agent_contains: Some("SQLMap".into()),
                ..Default::default()
            }),
            100,
        )
        .unwrap();
        let mut f = facts("203.0.113.9", "/");
        f.user_agent = Some("sqlmap/1.7#stable");
        assert!(blocked(&g.decide(&f, 100)));
        f.user_agent = Some("Mozilla/5.0");
        assert!(!blocked(&g.decide(&f, 100)));
        f.user_agent = None;
        assert!(!blocked(&g.decide(&f, 100)));
    }

    /// Failing open on an unknown peer is the deliberate direction: the other
    /// way round, one socket that cannot report an address blocks everything.
    #[test]
    fn a_client_rule_cannot_match_a_request_with_no_client_address() {
        let g = Guard::new("", true);
        g.insert(spec(client("0.0.0.0/0")), 100).unwrap();
        let mut f = facts("203.0.113.9", "/");
        assert!(blocked(&g.decide(&f, 100)));
        f.client = None;
        assert!(!blocked(&g.decide(&f, 100)));
    }

    #[test]
    fn nothing_is_scanned_when_no_rule_exists() {
        let g = Guard::new("", true);
        assert!(matches!(g.decide(&facts("203.0.113.9", "/"), 100), Decision::Pass));
        assert_eq!(g.stats(100).rules, 0);
    }

    #[test]
    fn rules_survive_a_restart_and_expired_ones_do_not() {
        let dir = std::env::temp_dir().join(format!(
            "app-lb-guard-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("guard.json");

        let g = Guard::new(&path, true);
        g.insert(
            RuleSpec {
                action: RuleAction::Block,
                match_: client("203.0.113.9"),
                expires_in_secs: Some(60),
                note: Some("from an alert".into()),
            },
            100,
        )
        .unwrap();
        g.insert(spec(client("198.51.100.0/24")), 100).unwrap();
        // Give the first rule a hit so the count has something to restore.
        let _ = g.decide(&facts("203.0.113.9", "/"), 100);
        g.persist().unwrap();

        let reloaded = Guard::new(&path, true);
        assert_eq!(reloaded.load(120).unwrap(), 2);
        // Read the hit count before exercising the rule again — `decide` bumps
        // it, so the order of these two lines is the assertion.
        let restored = reloaded
            .list()
            .into_iter()
            .find(|r| r.note.as_deref() == Some("from an alert"))
            .expect("the noted rule came back");
        assert_eq!(restored.view(true).hits, 1, "hit history survived the restart");
        assert!(blocked(&reloaded.decide(&facts("203.0.113.9", "/"), 120)));
        assert_eq!(restored.view(true).hits, 2);

        // Past the expiry, the timed rule is gone and the permanent one is not.
        let later = Guard::new(&path, true);
        assert_eq!(later.load(500).unwrap(), 1);
        assert!(blocked(&later.decide(&facts("198.51.100.5", "/"), 500)));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let g = Guard::new("/nonexistent/app-lb-guard-does-not-exist.json", true);
        assert_eq!(g.load(100).unwrap(), 0);
    }

    #[test]
    fn removing_an_unknown_rule_says_so() {
        let g = Guard::new("", true);
        assert!(matches!(g.remove("deadbeef", 100), Err(GuardError::NoRule(_))));
        let r = g.insert(spec(client("203.0.113.9")), 100).unwrap();
        assert!(g.remove(&r.id, 100).is_ok());
        assert!(g.list().is_empty());
    }

    #[test]
    fn the_rule_list_is_capped() {
        let g = Guard::new("", true);
        for i in 0..MAX_RULES {
            g.insert(spec(client(&format!("10.0.{}.{}", i / 256, i % 256))), 100)
                .unwrap();
        }
        let e = g.insert(spec(client("172.16.0.1")), 100).unwrap_err();
        assert!(matches!(e, GuardError::Full), "{e}");
    }

    #[test]
    fn a_bad_cidr_is_rejected_with_a_usable_message() {
        let g = Guard::new("", true);
        for bad in ["not-an-ip", "203.0.113.0/33", "2001:db8::/129", "203.0.113.0/x"] {
            let e = g.insert(spec(client(bad)), 100).unwrap_err();
            assert!(matches!(e, GuardError::BadClient(_)), "{bad}: {e}");
            assert!(e.to_string().contains("203.0.113.0/24"), "{e}");
        }
    }

    #[test]
    fn a_rule_describes_itself_in_words() {
        let g = Guard::new("", true);
        let r = g
            .insert(
                spec(MatchSpec {
                    client: Some("203.0.113.0/24".into()),
                    path_prefix: Some("/wp-".into()),
                    ..Default::default()
                }),
                100,
            )
            .unwrap();
        assert_eq!(r.describe(), "from 203.0.113.0/24, path under /wp-");
        // A host route drops the redundant /32.
        let r = g.insert(spec(client("203.0.113.9")), 100).unwrap();
        assert_eq!(r.describe(), "from 203.0.113.9");
    }
}
