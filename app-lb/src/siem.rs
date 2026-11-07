//! Detecting attacks in what app-lb already sees.
//!
//! [`crate::obs`] records *what happened*. Nothing there decides whether what
//! happened was an attack, and three things follow from that which this module
//! exists to fix:
//!
//! * **Authentication failure was invisible.** The admin gate answered a bad
//!   credential with a 401 and logged nothing at all, so a password spray against
//!   `/dashboard` left no trace anywhere.
//! * **Scanner traffic was noticed and thrown away.** `/wp-login.php` probes
//!   already accumulate in the unrouted access log; nothing read them.
//! * **Anomalies were only visible to somebody watching.** `crate::metrics`
//!   would show a 5xx surge on the dashboard, to whoever happened to be looking.
//!
//! # Shape
//!
//! A second, independent pipeline beside [`crate::obs`] — not a tee inside
//! [`crate::obs::LogSink`]. That is deliberate: `obs::from_env` returns `None`
//! whenever `APP_LB_OBS_URL` is unset, so a SIEM living inside it would silently
//! not exist on every host without a log collector, which is the opposite of what
//! a security control should do. This one is on unless `APP_LB_SIEM=0`.
//!
//! ```text
//! proxy::logging ─┐
//! admin::authorize├─→ SecuritySink ──try_send──→ Engine ──→ AlertRing ──→ GET /security
//! auth sign-in   ─┘   (bounded queue)            │          (in memory)
//!                                                └────────→ obs::LogSink → app-obs
//!                                                           source="security"
//! ```
//!
//! # This must never become a dependency of the data plane
//!
//! The same invariant [`crate::obs`] holds, for the same reason and by the same
//! means: recording is a `try_send` into a bounded queue and nothing else. No
//! lock, no await, no I/O, no `SiemLog` construction on the request path. A SIEM
//! that can add latency to a request is a SIEM that gets switched off. When the
//! queue is full, observations are dropped and counted — and because *that*
//! failure mode makes a busy network look quiet, [`SiemSnapshot::dropped`] and
//! [`SiemSnapshot::clients_at_capacity`] are reported on `/metrics`, on
//! `/security` and on the dashboard rather than hidden in a counter.
//!
//! # What is borrowed from `u-siem`, and what is not
//!
//! The crate supplies the *vocabulary*: [`SiemLog`] as an ECS-shaped field bag,
//! [`SiemField`], the field-name constants, and the [`LogParser`] /
//! [`LogEnrichment`] traits. Normalizing through them is what makes an app-lb
//! security log indexable next to anything else ECS-shaped, and it keeps these
//! parsers liftable into a real u-siem kernel later without a rewrite.
//!
//! It does **not** supply windowing. `SiemRule::matches` sees one log and no
//! history, so "5 auth failures from one address in 60 seconds" — two of the
//! three detection categories here — is not expressible in it. Those are plain
//! Rust in [`Windows`]. Rule state in u-siem is fed by kernel-side machinery
//! behind `SiemDatasetManager`, which app-lb deliberately does not run. Signature
//! matching also uses one [`RegexSet`] pass rather than `RuleOperator::Matches`
//! per subrule, because it sits on a per-request path.
//!
//! # Bounded by construction
//!
//! Unbounded per-client state is how a detector becomes the vulnerability. Two
//! rules, both load-bearing, both tested:
//!
//! * Every window is a fixed ring of time buckets and distinct-path counting is
//!   a 64-bit sketch — never a `Vec` of timestamps or a set of strings. Cost per
//!   tracked client is constant, and no attacker-controlled string is retained.
//! * At [`SiemConfig::max_clients`] the table sweeps expired entries and then
//!   *drops the new observation* rather than evicting a live one. Evicting the
//!   least-recently-seen is precisely what an attacker engineers, by flooding
//!   fresh addresses to push their own activity out of the table.

use async_trait::async_trait;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::mpsc;

use usiem::components::dataset::holder::DatasetHolder;
use usiem::components::enrichment::LogEnrichment;
use usiem::components::parsing::{GeneratorConfig, LogGenerator, LogParser, LogParsingError};
use usiem::events::field::SiemField;
use usiem::events::field_dictionary as fd;
use usiem::events::ip::SiemIp;
use usiem::events::schema::{FieldSchema, FieldType};
use usiem::events::SiemLog;

use crate::bots::{AGENTS, Agent, BotClass, Classifier, RangeBook, Verification};
use crate::obs::{self, Access, LogSink, Record};

/// The `source` every alert record carries into app-obs, beside the existing
/// `access`, `app-lb` and `job`.
pub const SECURITY_SOURCE: &str = "security";

/// The origin every [`SiemLog`] this module builds is stamped with.
const ORIGIN: &str = "app-lb";

/// Ceiling on the path handed to the signature matcher. Deliberately four times
/// [`crate::obs`]'s `MAX_PATH`: truncating at 512 would cut the tail off a long
/// injection payload and blind the matcher to exactly the requests worth
/// catching. What reaches an *alert* is re-truncated to [`MAX_ALERT_PATH`].
const MAX_SCAN_PATH: usize = 2048;
const MAX_ALERT_PATH: usize = 512;

/// Ceiling on a query-parameter *name* recorded in an alert. Names are short;
/// anything longer is someone probing the alert store itself.
const MAX_PARAM_NAME: usize = 64;

/// Ceiling on the `User-Agent` handed to the bot classifier — the same 512
/// bytes the guard scans.
const MAX_USER_AGENT: usize = 512;

/// Buckets per detection window. Twelve is a five-second resolution on the
/// default sixty-second window — fine enough that a burst is not smeared across
/// the whole window, coarse enough to stay in 48 bytes.
const BUCKETS: usize = 12;

// -- configuration ---------------------------------------------------------

/// Thresholds and caps, all environment-only like the rest of app-lb's
/// process-level configuration.
///
/// Defaults are **on**. app-lb's other optional subsystems (`APP_LB_OBS_URL`,
/// `APP_LB_ACME_EMAIL`) are opt-in because they need external configuration — an
/// endpoint, a contact address. This needs none, and a security feature somebody
/// has to remember to enable protects nobody. `APP_LB_SIEM=0` is the escape
/// hatch rather than `=1` being the entry.
#[derive(Debug, Clone)]
pub struct SiemConfig {
    pub queue_capacity: usize,
    pub alert_capacity: usize,
    /// Seconds. Every rate-based rule counts within this.
    pub window: i64,
    pub max_clients: usize,
    pub auth_threshold: u32,
    pub scan_threshold: u32,
    pub rate_threshold: u32,
    /// Seconds. A repeat inside this folds into the open alert.
    pub suppress: i64,
    /// Ceiling on *new* (unfolded) alerts per minute.
    pub max_alerts_per_min: u32,
    /// Match signatures against the query string as well as the path. See
    /// [`AccessObs::scan_query`] for why this is safe and what it costs.
    pub scan_query: bool,
    /// Ship alerts to app-obs as `source="security"` records.
    pub ship: bool,
    /// Classify automated clients by `User-Agent` (`APP_LB_BOTS`).
    pub bots: bool,
    /// Fetch operators' published crawler ranges to verify claims
    /// (`APP_LB_BOTS_RANGES`). Off means no outbound requests, and every claim
    /// stays `claimed` or `unverifiable`.
    pub bot_ranges: bool,
    /// Seconds between range refreshes.
    pub bot_refresh: u64,
    /// Seconds the bot-traffic table counts over. Longer than the detection
    /// window on purpose: "who crawled this in the last hour" is the question.
    pub bot_window: i64,
}

impl SiemConfig {
    fn from_env() -> Self {
        Self {
            queue_capacity: obs::env_usize("APP_LB_SIEM_QUEUE_CAPACITY", 4096),
            alert_capacity: obs::env_usize("APP_LB_SIEM_ALERT_CAPACITY", 512),
            window: obs::env_usize("APP_LB_SIEM_WINDOW_SECS", 60) as i64,
            max_clients: obs::env_usize("APP_LB_SIEM_MAX_CLIENTS", 16384),
            auth_threshold: obs::env_usize("APP_LB_SIEM_AUTH_THRESHOLD", 8) as u32,
            scan_threshold: obs::env_usize("APP_LB_SIEM_SCAN_THRESHOLD", 30) as u32,
            rate_threshold: obs::env_usize("APP_LB_SIEM_RATE_THRESHOLD", 600) as u32,
            suppress: obs::env_usize("APP_LB_SIEM_SUPPRESS_SECS", 300) as i64,
            max_alerts_per_min: obs::env_usize("APP_LB_SIEM_MAX_ALERTS_PER_MIN", 60) as u32,
            scan_query: obs::env_flag("APP_LB_SIEM_SCAN_QUERY", true),
            ship: obs::env_flag("APP_LB_SIEM_SHIP", true),
            bots: obs::env_flag("APP_LB_BOTS", true),
            bot_ranges: obs::env_flag("APP_LB_BOTS_RANGES", true),
            bot_refresh: obs::env_usize("APP_LB_BOTS_REFRESH_SECS", 86_400).max(60) as u64,
            bot_window: obs::env_usize("APP_LB_BOTS_WINDOW_SECS", 3_600).max(60) as i64,
        }
    }
}

// -- what the sources hand over --------------------------------------------

/// One thing worth analysing.
///
/// Flat, owned, `Copy`-where-it-matters data — never a [`SiemLog`]. Building one
/// of those is a dozen allocations and two tree inserts, which is fine in the
/// background task and not fine on a request path.
#[derive(Debug)]
pub enum Observation {
    Access(Box<AccessObs>),
    Auth(Box<AuthObs>),
}

/// One proxied request, as [`crate::proxy`] saw it.
#[derive(Debug)]
pub struct AccessObs {
    pub ts: i64,
    /// Parsed once, here, so every downstream map keys on 17 bytes of `Copy`
    /// data instead of a `String`. A pingora unix-socket peer stringifies to a
    /// path and fails to parse, which correctly excludes it from IP-keyed
    /// detection rather than inventing a key for it.
    pub client: Option<IpAddr>,
    pub deployment: Option<Box<str>>,
    pub method: Box<str>,
    pub path: Box<str>,
    pub host: Option<Box<str>>,
    /// Present only under `APP_LB_SIEM_SCAN_QUERY`, and **consumed by the
    /// matcher, never stored**.
    ///
    /// This is the one place app-lb's "the query string is never logged" rule is
    /// bent, and the bend is structural rather than promised: the raw query
    /// arrives here as its own field, is read by [`Signatures::scan`], and dies
    /// with the observation. It is not on [`Access`], so no code path exists that
    /// could carry it into a [`Record`] and out to app-obs. On a match the alert
    /// records the parameter *name* only — `web.sqli in query parameter "id"` —
    /// never the value. Most SQLi and XSS payloads live in a parameter value; a
    /// path-only detector is blind to them, and this is the narrowest way to see
    /// them that keeps the credential in an OAuth callback out of the log store.
    pub scan_query: Option<Box<str>>,
    /// Clipped to [`MAX_USER_AGENT`]. Read by the bot classifier and **never
    /// stored**: an alert carries the catalog name it matched, not this text.
    pub user_agent: Option<Box<str>>,
    pub status: Option<u16>,
    pub duration_nanos: u64,
    pub bytes: u64,
}

/// One rejected credential.
#[derive(Debug)]
pub struct AuthObs {
    pub ts: i64,
    pub client: Option<IpAddr>,
    pub deployment: Option<Box<str>>,
    pub path: Box<str>,
    pub action: AuthAction,
    /// The credential *scheme* only — never the credential.
    pub scheme: AuthScheme,
    /// Set only for [`AuthAction::SigninRefused`], where the address is already
    /// in a `tracing::info!` and the rule that needs it counts *distinct*
    /// addresses from one source to spot enumeration.
    pub subject: Option<Box<str>>,
}

/// Which gate said no. Becomes `event.action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAction {
    /// Admin API: no usable credential.
    AdminRejected,
    /// Admin API: the credential was good and the scope was not.
    AdminScope,
    /// Data-plane app-token gate: a bearer was presented and rejected.
    GateToken,
    /// Data-plane JWT gate: a token was presented and did not verify or did not
    /// satisfy the gate's claims.
    GateJwt,
    /// Sign-in: the state/nonce did not match the flow cookie. CSRF-shaped.
    SigninState,
    /// Sign-in: the OAuth token exchange failed.
    SigninExchange,
    /// Sign-in: the id token was rejected.
    SigninToken,
    /// Sign-in: a valid identity the allow-list refused.
    SigninRefused,
}

impl AuthAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::AdminRejected => "admin-rejected",
            Self::AdminScope => "admin-scope",
            Self::GateToken => "gate-token",
            Self::GateJwt => "gate-jwt",
            Self::SigninState => "signin-state",
            Self::SigninExchange => "signin-exchange",
            Self::SigninToken => "signin-token",
            Self::SigninRefused => "signin-refused",
        }
    }

    /// Whether this counts toward the brute-force window. A provider-side token
    /// exchange failure is usually a hiccup rather than an attempt, and counting
    /// it would let a flaky IdP raise a brute-force alert.
    fn counts_as_attempt(self) -> bool {
        !matches!(self, Self::SigninExchange)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    None,
    Basic,
    Bearer,
}

impl AuthScheme {
    /// Read the scheme off an `Authorization` header without decoding it.
    ///
    /// Deliberately not parsing the credential: `DashboardAuth::accepts` is one
    /// constant-time compare against a precomputed header precisely so no base64
    /// decode happens per request, and decoding on the *failure* path would
    /// reintroduce parsing of unauthenticated attacker input for no detection
    /// gain — the detector keys on address, not on username.
    pub fn of(header: Option<&str>) -> Self {
        match header {
            Some(h) if h.len() >= 6 && h[..6].eq_ignore_ascii_case("basic ") => Self::Basic,
            Some(h) if h.len() >= 7 && h[..7].eq_ignore_ascii_case("bearer ") => Self::Bearer,
            _ => Self::None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Basic => "basic",
            Self::Bearer => "bearer",
        }
    }
}

// -- the write end ---------------------------------------------------------

/// Cloned to every source. Cheap to clone and safe to hold anywhere.
#[derive(Clone)]
pub struct SecuritySink {
    tx: mpsc::Sender<Observation>,
    stats: Arc<SiemStats>,
    scan_query: bool,
}

impl SecuritySink {
    /// Queue one proxied request.
    ///
    /// Borrows rather than consuming, because [`crate::obs::LogSink::send_access`]
    /// still needs to move the same [`Access`] afterwards. `Access` is not
    /// `Clone`, so if anyone ever reorders those two calls it stops compiling —
    /// which is the good outcome.
    pub fn observe_access(
        &self,
        access: &Access<'_>,
        query: Option<&str>,
        user_agent: Option<&str>,
    ) {
        let obs = AccessObs {
            ts: obs::now_millis(),
            client: access.client.as_deref().and_then(|c| c.parse().ok()),
            deployment: access.deployment.map(Box::from),
            method: Box::from(access.method),
            path: Box::from(clip(access.path, MAX_SCAN_PATH)),
            host: access.host.map(Box::from),
            scan_query: match (self.scan_query, query) {
                (true, Some(q)) if !q.is_empty() => Some(Box::from(clip(q, MAX_SCAN_PATH))),
                _ => None,
            },
            user_agent: user_agent
                .filter(|ua| !ua.is_empty())
                .map(|ua| Box::from(clip(ua, MAX_USER_AGENT))),
            status: access.status,
            duration_nanos: access.duration.as_nanos().min(u64::MAX as u128) as u64,
            bytes: access.bytes as u64,
        };
        self.offer(Observation::Access(Box::new(obs)));
    }

    /// Queue one rejected credential.
    pub fn observe_auth(&self, auth: AuthObs) {
        self.offer(Observation::Auth(Box::new(auth)));
    }

    /// The only `try_send`. Never blocks, never awaits, never does I/O — see the
    /// module header, and [`crate::obs::LogSink::send`], whose discipline this
    /// copies exactly.
    fn offer(&self, o: Observation) {
        let counter = match self.tx.try_send(o) {
            Ok(()) => &self.stats.observed,
            Err(_) => &self.stats.dropped,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Truncate on a char boundary without allocating when it is not needed.
fn clip(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// -- counters --------------------------------------------------------------

/// Counters for the pipeline itself.
#[derive(Debug, Default)]
pub struct SiemStats {
    observed: AtomicU64,
    dropped: AtomicU64,
    analyzed: AtomicU64,
    raised: AtomicU64,
    suppressed: AtomicU64,
    tracked_clients: AtomicU64,
    clients_at_capacity: AtomicBool,
}

impl SiemStats {
    pub fn snapshot(&self) -> SiemSnapshot {
        SiemSnapshot {
            observed: self.observed.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            analyzed: self.analyzed.load(Ordering::Relaxed),
            raised: self.raised.load(Ordering::Relaxed),
            suppressed: self.suppressed.load(Ordering::Relaxed),
            tracked_clients: self.tracked_clients.load(Ordering::Relaxed),
            clients_at_capacity: self.clients_at_capacity.load(Ordering::Relaxed),
        }
    }
}

/// What `/metrics` and `/security` report about the engine.
///
/// `dropped` and `clients_at_capacity` are the two worth watching: both mean the
/// SIEM has stopped seeing part of the traffic, and a SIEM that has quietly
/// stopped looking is indistinguishable from a quiet network.
#[derive(Debug, Clone, Serialize)]
pub struct SiemSnapshot {
    pub observed: u64,
    pub dropped: u64,
    pub analyzed: u64,
    pub raised: u64,
    pub suppressed: u64,
    pub tracked_clients: u64,
    pub clients_at_capacity: bool,
}

// -- client identity -------------------------------------------------------

/// A source address, normalized to the unit worth counting: IPv4 to /32, IPv6 to
/// /64.
///
/// Keying on the full IPv6 address would be free to defeat — a /64 is the
/// standard end-site allocation, so an attacker rotates the low 64 bits at no
/// cost and every per-source rule counts one attempt per address forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ClientKey(u128);

impl ClientKey {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self(u32::from(v4) as u128),
            // Mark the v6 side so a v4 address can never collide with a v6 /64.
            IpAddr::V6(v6) => Self((u128::from(v6) >> 64) | (1 << 127)),
        }
    }
}

// -- bounded windows -------------------------------------------------------

/// A sliding count with no allocation and no timestamp list.
///
/// `BUCKETS` fixed slots advanced by zeroing whatever was skipped past. A
/// `VecDeque<Instant>` per client would be an allocation per request and an
/// unbounded one under exactly the load where it matters.
#[derive(Debug, Default, Clone)]
struct RingCounter {
    slots: [u32; BUCKETS],
    /// Epoch millis at which the current head bucket started.
    head_start: i64,
    head: u8,
}

impl RingCounter {
    fn advance(&mut self, now: i64, window: i64) {
        let bucket = (window * 1000 / BUCKETS as i64).max(1);
        if self.head_start == 0 {
            self.head_start = now;
            return;
        }
        let steps = (now - self.head_start) / bucket;
        if steps <= 0 {
            return;
        }
        if steps >= BUCKETS as i64 {
            self.slots = [0; BUCKETS];
        } else {
            for i in 1..=steps {
                let idx = (self.head as i64 + i) as usize % BUCKETS;
                self.slots[idx] = 0;
            }
        }
        self.head = ((self.head as i64 + steps) % BUCKETS as i64) as u8;
        self.head_start += steps * bucket;
    }

    fn record(&mut self, now: i64, window: i64) {
        self.advance(now, window);
        self.slots[self.head as usize] = self.slots[self.head as usize].saturating_add(1);
    }

    fn total(&self) -> u32 {
        self.slots.iter().copied().fold(0u32, u32::saturating_add)
    }
}

/// Everything tracked about one source address. Fixed size, ~120 bytes.
#[derive(Debug, Default, Clone)]
struct ClientWindow {
    requests: RingCounter,
    auth_failures: RingCounter,
    /// 401/403/404 — the responses a scanner collects.
    client_errors: RingCounter,
    /// Distinctness sketch over paths: set bit `hash(path) % 64`. A scanner
    /// walking a wordlist lights many bits; a client retrying one broken URL
    /// lights one. `count_ones()` separates them without storing a single
    /// attacker-controlled string.
    path_sketch: u64,
    /// The same trick over deployment ids, for a credential spray across the
    /// fleet rather than against one host.
    deployment_sketch: u64,
    /// And over sign-in subjects, for account enumeration.
    subject_sketch: u64,
    last_seen: i64,
}

fn sketch_bit(s: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    1u64 << (h.finish() % 64)
}

/// The per-client table, with the cap policy that keeps it from becoming the
/// vulnerability.
struct Windows {
    clients: HashMap<ClientKey, ClientWindow>,
    window: i64,
    max_clients: usize,
    at_capacity: bool,
}

impl Windows {
    fn new(window: i64, max_clients: usize) -> Self {
        Self {
            clients: HashMap::new(),
            window,
            max_clients,
            at_capacity: false,
        }
    }

    /// Borrow the window for `key`, or `None` when the table is full.
    ///
    /// At capacity: sweep whatever has aged out, and if that frees nothing,
    /// refuse the *new* entry. Evicting the least-recently-seen instead would
    /// hand an attacker a way to erase their own history — flood fresh addresses
    /// and the entry counting your attempts is the one that goes.
    fn entry(&mut self, key: ClientKey, now: i64) -> Option<&mut ClientWindow> {
        if !self.clients.contains_key(&key) && self.clients.len() >= self.max_clients {
            self.prune(now);
            if self.clients.len() >= self.max_clients {
                self.at_capacity = true;
                return None;
            }
        }
        let w = self.clients.entry(key).or_default();
        w.last_seen = now;
        Some(w)
    }

    /// Drop entries with nothing left inside the window. Also runs on a timer, so
    /// an idle LB releases its table instead of holding the last burst forever.
    fn prune(&mut self, now: i64) {
        let horizon = self.window * 1000;
        self.clients
            .retain(|_, w| w.last_seen != 0 && now - w.last_seen < horizon);
        if self.clients.len() < self.max_clients {
            self.at_capacity = false;
        }
    }
}

// -- automated traffic -----------------------------------------------------

/// Cap on rows in the bot-traffic table. The key space is already bounded —
/// catalog entries × deployments × four verification states, none of it an
/// attacker-chosen string — but a table without a cap is a promise, not a
/// bound.
const MAX_BOT_ROWS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BotKey {
    deployment: Option<Box<str>>,
    agent: usize,
    verification: Verification,
}

#[derive(Debug, Default, Clone)]
struct BotRow {
    recent: RingCounter,
    total: u64,
    /// Distinct sources, as a sketch over [`ClientKey`]s: a rough "how many
    /// addresses", not a list of them.
    sources: u64,
    first_ts: i64,
    last_ts: i64,
}

/// Who is crawling what: requests per (deployment, agent, verification).
pub struct BotBoard {
    rows: Mutex<(HashMap<BotKey, BotRow>, bool)>,
    window: i64,
}

impl BotBoard {
    fn new(window: i64) -> Self {
        Self {
            rows: Mutex::new((HashMap::new(), false)),
            window,
        }
    }

    /// Count one request. Returns whether this is the first sighting of the
    /// key — the moment a `bot.*` sighting alert is worth raising.
    fn record(&self, key: BotKey, client: Option<IpAddr>, now: i64) -> bool {
        let mut guard = self.rows.lock().expect("bot board lock");
        let (rows, at_capacity) = &mut *guard;
        if !rows.contains_key(&key) && rows.len() >= MAX_BOT_ROWS {
            let horizon = self.window * 1000;
            rows.retain(|_, r| now - r.last_ts < horizon);
            if rows.len() >= MAX_BOT_ROWS {
                *at_capacity = true;
                return false;
            }
        }
        let new = !rows.contains_key(&key);
        let row = rows.entry(key).or_default();
        row.recent.record(now, self.window);
        row.total += 1;
        if let Some(ip) = client {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            ClientKey::of(ip).hash(&mut h);
            row.sources |= 1u64 << (h.finish() % 64);
        }
        if row.first_ts == 0 {
            row.first_ts = now;
        }
        row.last_ts = now;
        new
    }

    fn prune(&self, now: i64) {
        let horizon = self.window * 1000;
        let mut guard = self.rows.lock().expect("bot board lock");
        guard.0.retain(|_, r| now - r.last_ts < horizon);
        if guard.0.len() < MAX_BOT_ROWS {
            guard.1 = false;
        }
    }

    fn rows(&self, now: i64) -> (Vec<BotTrafficRow>, bool) {
        let mut guard = self.rows.lock().expect("bot board lock");
        let (rows, at_capacity) = &mut *guard;
        let mut out: Vec<BotTrafficRow> = rows
            .iter_mut()
            .map(|(k, r)| {
                r.recent.advance(now, self.window);
                let agent = &AGENTS[k.agent];
                let action = match (k.deployment.as_deref(), agent.guard_token()) {
                    // A spoofer is a set of addresses, not a token: the
                    // `bot.spoofed` alert carries the per-address block.
                    (Some(d), Some(token)) if k.verification != Verification::Spoofed => Some(
                        block_agent(agent, token, d, format!("bot traffic, {}", agent.name)),
                    ),
                    _ => None,
                };
                BotTrafficRow {
                    deployment: k.deployment.as_deref().map(str::to_string),
                    bot: BotTag::of(agent, k.verification),
                    requests: r.recent.total() as u64,
                    total: r.total,
                    sources: r.sources.count_ones(),
                    first_ts: r.first_ts,
                    last_ts: r.last_ts,
                    action,
                }
            })
            .collect();
        out.sort_by(|a, b| b.requests.cmp(&a.requests).then(b.last_ts.cmp(&a.last_ts)));
        (out, *at_capacity)
    }
}

/// One row of `/security`'s `bots.rows`.
#[derive(Debug, Clone, Serialize)]
pub struct BotTrafficRow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment: Option<String>,
    #[serde(flatten)]
    pub bot: BotTag,
    /// Requests inside the window.
    pub requests: u64,
    /// Requests since the row appeared.
    pub total: u64,
    /// Approximate distinct sources (a 64-bit sketch, so it saturates).
    pub sources: u32,
    pub first_ts: i64,
    pub last_ts: i64,
    /// "Block this agent on this deployment", ready to post.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<SuggestedAction>,
}

/// `/security`'s `bots` object.
#[derive(Debug, Clone, Serialize)]
pub struct BotTrafficView {
    pub window_secs: u64,
    /// Busiest first.
    pub rows: Vec<BotTrafficRow>,
    /// The published range lists and whether each has loaded.
    pub ranges: Vec<crate::bots::RangeStatus>,
    /// Whether range verification is switched on at all.
    pub verifying: bool,
    pub at_capacity: bool,
}

/// What the analyzer, the engine and `/security` share about automated traffic.
pub struct BotState {
    classifier: Classifier,
    pub ranges: Arc<RangeBook>,
    board: BotBoard,
    verifying: bool,
}

impl BotState {
    fn new(cfg: &SiemConfig) -> Self {
        Self {
            classifier: Classifier::new(),
            ranges: Arc::new(RangeBook::default()),
            board: BotBoard::new(cfg.bot_window),
            verifying: cfg.bot_ranges,
        }
    }

    pub fn view(&self, now: i64) -> BotTrafficView {
        let (rows, at_capacity) = self.board.rows(now);
        BotTrafficView {
            window_secs: self.board.window as u64,
            rows,
            ranges: self.ranges.status(),
            verifying: self.verifying,
            at_capacity,
        }
    }
}

// -- normalization ---------------------------------------------------------

/// Field names we add that `u-siem`'s dictionary has no constant for.
///
/// `event.duration` is written as a literal deliberately: the dictionary has
/// `NETWORK_DURATION` (`network.duration`) and no `EVENT_DURATION`, and the
/// former is *not* a substitute — in ECS it means flow duration at the network
/// layer, not request handling time. `FieldSchema::allow_unknown_fields` carries
/// these, and the golden-field test pins them.
const F_DURATION: &str = "event.duration";
const F_BYTES: &str = "http.response.body.bytes";
const F_SERVICE: &str = "service.name";
const F_SCHEME: &str = "http.request.authorization.scheme";
const F_EXTENSION: &str = "url.extension";
/// ECS `user_agent.name`, set to the *catalog* name the UA matched — never
/// `user_agent.original`, which would carry the raw header into app-obs.
const F_UA_NAME: &str = "user_agent.name";
const F_BOT_CLASS: &str = "heyo.bot.class";
const F_BOT_OPERATOR: &str = "heyo.bot.operator";
const F_BOT_VERIFICATION: &str = "heyo.bot.verification";

/// `url.query` is in the dictionary and we never set it. See
/// [`AccessObs::scan_query`].
fn access_schema() -> &'static FieldSchema {
    static SCHEMA: OnceLock<FieldSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let mut s = FieldSchema::new();
        s.allow_unknown_fields = true;
        s.fields
            .insert(fd::SOURCE_IP, FieldType::Ip("Client address as seen on the socket"));
        s.fields.insert(
            fd::HTTP_REQUEST_METHOD,
            FieldType::Text("HTTP method"),
        );
        s.fields.insert(fd::URL_PATH, FieldType::Text("Request path, never the query"));
        s.fields.insert(fd::URL_DOMAIN, FieldType::Text("Host header"));
        s.fields.insert(
            fd::HTTP_RESPONSE_STATUS_CODE,
            FieldType::Numeric("Response status, absent when nothing was written"),
        );
        s.fields
            .insert(F_DURATION, FieldType::Numeric("Request handling time, nanoseconds"));
        s.fields.insert(F_BYTES, FieldType::Numeric("Response body bytes"));
        s.fields
            .insert(F_SERVICE, FieldType::Text("Deployment that served the request"));
        s.fields
            .insert(F_EXTENSION, FieldType::Text("Lowercased path extension"));
        s
    })
}

fn control_schema() -> &'static FieldSchema {
    static SCHEMA: OnceLock<FieldSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let mut s = FieldSchema::new();
        s.allow_unknown_fields = true;
        s.fields
            .insert(fd::SOURCE_IP, FieldType::Ip("Client address as seen on the socket"));
        s.fields.insert(fd::URL_PATH, FieldType::Text("Request path"));
        s.fields
            .insert(fd::USER_NAME, FieldType::Text("Refused sign-in subject"));
        s.fields
            .insert(F_SCHEME, FieldType::Text("Credential scheme, never the credential"));
        s.fields
            .insert(F_SERVICE, FieldType::Text("Deployment the credential was for"));
        s
    })
}

/// `LogParser::generator` exists for synthetic-log testing we do not do.
///
/// A local type rather than `usiem::testing::parsers::DummyLogGenerator`: naming
/// a `testing` module from production code is a smell, and its shape is not a
/// stability promise.
#[derive(Clone)]
struct NoGenerator;

impl LogGenerator for NoGenerator {
    fn configure(&mut self, _config: GeneratorConfig) {}
    fn log(&self) -> String {
        String::new()
    }
    fn weight(&self) -> u8 {
        0
    }
}

/// Whether a source address is inside the network.
///
/// `SiemIp::is_local` covers RFC1918 and the RFC6598 CGN range but **not
/// loopback** — 127.0.0.1 comes back `false`. That is a real problem here rather
/// than a nitpick: the admin listener defaults to `127.0.0.1`, so every alert
/// raised against the control plane would be tagged `external`, which is exactly
/// backwards and is the kind of thing an operator reasonably acts on.
fn is_internal(ip: &SiemIp) -> bool {
    if ip.is_local() {
        return true;
    }
    match ip {
        SiemIp::V4(v4) => std::net::Ipv4Addr::from(*v4).is_loopback(),
        SiemIp::V6(v6) => std::net::Ipv6Addr::from(*v6).is_loopback(),
    }
}

fn siem_ip(ip: IpAddr) -> SiemIp {
    match ip {
        IpAddr::V4(v4) => SiemIp::V4(u32::from(v4)),
        IpAddr::V6(v6) => SiemIp::V6(u128::from(v6)),
    }
}

/// Borrow the eight standard methods instead of allocating for them.
fn method_field(m: &str) -> SiemField {
    match m {
        "GET" => SiemField::from_str_slice("GET"),
        "POST" => SiemField::from_str_slice("POST"),
        "PUT" => SiemField::from_str_slice("PUT"),
        "DELETE" => SiemField::from_str_slice("DELETE"),
        "HEAD" => SiemField::from_str_slice("HEAD"),
        "PATCH" => SiemField::from_str_slice("PATCH"),
        "OPTIONS" => SiemField::from_str_slice("OPTIONS"),
        "CONNECT" => SiemField::from_str_slice("CONNECT"),
        other => SiemField::Text(other.to_string().into()),
    }
}

/// Normalizes a proxied request into ECS.
#[derive(Clone)]
struct AccessParser;

impl LogParser for AccessParser {
    fn parse_log(
        &self,
        mut log: SiemLog,
        _datasets: &DatasetHolder,
    ) -> Result<SiemLog, LogParsingError> {
        // The dispatch idiom: hand the log back untouched so the next parser can
        // try it, rather than cloning it per candidate.
        if !log.has_tag("access") {
            return Err(LogParsingError::NoValidParser(log));
        }
        log.set_product(ORIGIN);
        log.set_vendor(ORIGIN);
        log.set_service("proxy");
        log.set_category("webserver");
        log.add_field(fd::EVENT_CATEGORY, SiemField::from_str_slice("web"));
        log.add_field(fd::EVENT_ACTION, SiemField::from_str_slice("http-request"));
        log.add_field(fd::OBSERVER_NAME, SiemField::from_str_slice(ORIGIN));
        Ok(log)
    }
    fn name(&self) -> &'static str {
        "app-lb-access"
    }
    fn description(&self) -> &'static str {
        "app-lb proxy access records"
    }
    fn schema(&self) -> &FieldSchema {
        access_schema()
    }
    fn generator(&self) -> Box<dyn LogGenerator> {
        Box::new(NoGenerator)
    }
}

/// Normalizes a rejected credential into ECS.
#[derive(Clone)]
struct ControlPlaneParser;

impl LogParser for ControlPlaneParser {
    fn parse_log(
        &self,
        mut log: SiemLog,
        _datasets: &DatasetHolder,
    ) -> Result<SiemLog, LogParsingError> {
        if !log.has_tag("auth-failure") {
            return Err(LogParsingError::NoValidParser(log));
        }
        log.set_product(ORIGIN);
        log.set_vendor(ORIGIN);
        log.set_category("authentication");
        log.add_field(fd::EVENT_CATEGORY, SiemField::from_str_slice("authentication"));
        log.add_field(fd::EVENT_OUTCOME, SiemField::from_str_slice("failure"));
        log.add_field(fd::OBSERVER_NAME, SiemField::from_str_slice(ORIGIN));
        Ok(log)
    }
    fn name(&self) -> &'static str {
        "app-lb-control-plane"
    }
    fn description(&self) -> &'static str {
        "app-lb admin, app-token and sign-in gate rejections"
    }
    fn schema(&self) -> &FieldSchema {
        control_schema()
    }
    fn generator(&self) -> Box<dyn LogGenerator> {
        Box::new(NoGenerator)
    }
}

/// Three dataset-free enrichments, so the impl is honest rather than a stub.
///
/// app-lb ships no GeoIP or IOC feed — populating [`DatasetHolder`] would mean
/// the `slow_geoip` feature and a `sled` dependency for a lookup nothing here
/// needs — so this does what can be derived from the log itself.
#[derive(Clone)]
struct LbEnrichment;

impl LogEnrichment for LbEnrichment {
    fn enrich(&self, mut log: SiemLog, _datasets: &DatasetHolder) -> SiemLog {
        // 1. Is the source inside the network? "600 requests a minute" from a
        //    private address is a health check; from a public one it may not be.
        if let Some(SiemField::IP(ip)) = log.field(fd::SOURCE_IP) {
            let tag = if is_internal(ip) { "internal" } else { "external" };
            log.add_tag(tag);
        }
        // 2. Extension, which is a scanner tell and lets signatures match one
        //    short field instead of rescanning the whole path.
        if let Some(SiemField::Text(path)) = log.field(fd::URL_PATH)
            && let Some(ext) = path
                .rsplit('/')
                .next()
                .and_then(|seg| seg.rsplit_once('.'))
                .map(|(_, e)| e.to_ascii_lowercase())
                .filter(|e| !e.is_empty() && e.len() <= 8)
        {
            log.add_field(F_EXTENSION, SiemField::Text(ext.into()));
        }
        // 3. Outcome, when the access parser had a status and left it unset.
        if !log.has_field(fd::EVENT_OUTCOME)
            && let Some(SiemField::U64(status)) = log.field(fd::HTTP_RESPONSE_STATUS_CODE)
        {
            let outcome = if *status < 400 { "success" } else { "failure" };
            log.add_field(fd::EVENT_OUTCOME, SiemField::from_str_slice(outcome));
        }
        log
    }
    fn name(&self) -> &'static str {
        "app-lb-enrichment"
    }
    fn description(&self) -> &'static str {
        "locality tag, url extension and outcome, without datasets"
    }
}

// -- signatures ------------------------------------------------------------

/// One stateless signature.
struct Signature {
    rule: &'static str,
    severity: Severity,
    technique: &'static str,
    what: &'static str,
}

/// Index-aligned with the patterns handed to [`RegexSet::new`].
const SIGNATURES: &[Signature] = &[
    Signature {
        rule: "web.traversal",
        severity: Severity::High,
        technique: "T1083",
        what: "path traversal",
    },
    Signature {
        rule: "web.sqli",
        severity: Severity::High,
        technique: "T1190",
        what: "SQL injection",
    },
    Signature {
        rule: "web.xss",
        severity: Severity::Medium,
        technique: "T1190",
        what: "cross-site scripting",
    },
    Signature {
        rule: "web.rce",
        severity: Severity::Critical,
        technique: "T1190",
        what: "remote code execution",
    },
    Signature {
        rule: "web.secret-probe",
        severity: Severity::Medium,
        technique: "T1595_002",
        what: "sensitive-file probe",
    },
];

const PATTERNS: &[&str] = &[
    r"(?i)(\.\./|\.\.%2f|%2e%2e[/\\]|\.\.\\)",
    r"(?i)(union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|;\s*drop\s+table|\bsleep\(\s*\d|\bbenchmark\()",
    r"(?i)(<script|%3cscript|javascript:|\bon(error|load)\s*=)",
    r"(?i)(\$\{jndi:|/bin/(ba)?sh\b|;\s*(cat|curl|wget)\s|\bexec\()",
    r"(?i)^/(\.env|\.git/|\.aws/|\.ssh/|wp-login\.php|wp-admin|phpmyadmin|xmlrpc\.php|server-status|config\.json)",
];

/// Matches the stateless rules in one pass.
///
/// One [`RegexSet`] rather than a regex per rule: this runs per request, and the
/// set evaluates every pattern in a single scan of the input.
struct Signatures {
    set: usiem::regex::RegexSet,
}

impl Signatures {
    fn new() -> Self {
        Self {
            set: usiem::regex::RegexSet::new(PATTERNS).expect("signature patterns must compile"),
        }
    }

    /// Highest-severity match against the path, then the query if scanning it.
    ///
    /// Returns the parameter name on a query hit so the alert can say *where*
    /// without ever recording *what*.
    fn scan(&self, path: &str, query: Option<&str>) -> Option<(&'static Signature, Option<String>)> {
        if allowlisted(path) {
            return None;
        }
        let best = |hay: &str| {
            self.set
                .matches(hay)
                .into_iter()
                .map(|i| &SIGNATURES[i])
                .max_by_key(|s| s.severity)
        };
        if let Some(sig) = best(path) {
            return Some((sig, None));
        }
        let query = query?;
        // Match per parameter value, so the alert can name the parameter. The
        // value itself is read here and goes no further.
        for (name, value) in form_urlencoded::parse(query.as_bytes()) {
            if let Some(sig) = best(&value) {
                let name = obs::truncate(name.into_owned(), MAX_PARAM_NAME);
                return Some((sig, Some(name)));
            }
        }
        None
    }
}

/// Paths app-lb legitimately serves that would otherwise trip a signature.
///
/// This is where the false positives come from, and every entry is a real path
/// this process answers:
///
/// * `/.well-known/acme-challenge/<token>` is answered before routing by
///   [`crate::proxy`], with an opaque CA-supplied token, and matches
///   `web.secret-probe`'s dotted-directory pattern.
/// * A static site serves whatever is on disk, so minified JS containing
///   `javascript:` in a string literal matches `web.xss`.
/// * The sign-in callback carries provider state that has matched `web.sqli`'s
///   quote patterns in the wild.
fn allowlisted(path: &str) -> bool {
    path.starts_with("/.well-known/acme-challenge/")
        || path.starts_with("/.well-known/")
        || path.starts_with("/__applb/auth/")
}

// -- alerts ----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Parse the `?severity=` filter. Unknown values are `None`, which reads as
    /// "no floor" rather than "match nothing" — a typo should not silently blank
    /// a security console.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    fn level(self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warn",
            _ => "info",
        }
    }
    fn index(self) -> usize {
        self as usize
    }
}

/// One finding.
///
/// app-lb's own type rather than `usiem::prelude::SiemAlert`, for three reasons
/// worth stating: `SiemAlert` embeds the whole triggering [`SiemLog`], which is
/// the *log* and not the alert and would republish the raw message through
/// `/security`; it has no id, so the dashboard could not key rows across polls;
/// and it has no occurrence count, so folding would be invisible. Owning the
/// wire type is also what keeps `testdata/wire/security-response.json` stable
/// across a u-siem version bump.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub id: u64,
    /// Epoch millis of the first occurrence folded into this alert.
    pub ts: i64,
    pub last_ts: i64,
    pub rule: &'static str,
    pub severity: Severity,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment: Option<String>,
    /// Truncated, and never carrying a query string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// MITRE ATT&CK technique id, as a plain string: it is part of app-lb's wire
    /// contract, so it must not move when u-siem's `MitreTechniques` enum does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technique: Option<&'static str>,
    /// Occurrences folded in. A scanner produces one alert whose count climbs,
    /// not ten thousand alerts.
    pub count: u64,
    /// The triggering event, normalized to ECS field names.
    ///
    /// This is what the `u-siem` dependency is *for*: an alert stored in app-obs
    /// carries `source.ip` and `url.path` under the names any ECS-shaped store
    /// already indexes, so a security query spans app-lb's alerts and anything
    /// else without a translation layer. Built from the enriched [`SiemLog`], so
    /// it can only contain fields a parser set — and no parser sets `url.query`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecs: Option<serde_json::Value>,
    /// The automated client this finding is about, for the `bot.*` rules.
    /// Catalog names only — never the raw `User-Agent`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot: Option<BotTag>,
}

/// Which catalog entry a request claimed to be, and whether it checked out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BotTag {
    pub agent: &'static str,
    pub operator: &'static str,
    pub class: BotClass,
    pub verification: Verification,
}

impl BotTag {
    fn of(agent: &'static Agent, verification: Verification) -> Self {
        Self {
            agent: agent.name,
            operator: agent.operator,
            class: agent.class,
            verification,
        }
    }
}

/// Project an enriched [`SiemLog`] onto JSON for storage.
///
/// Only the field bag and tags: the message duplicates [`Alert::title`], and the
/// envelope (product, vendor) is constant for everything app-lb emits.
fn ecs_fields(log: &SiemLog) -> serde_json::Value {
    // `SiemLog::fields` includes the envelope `SiemLog::new` sets — the message,
    // origin, product, vendor and the two received/created stamps. Every one of
    // those is either constant for anything app-lb emits or already a field on
    // the alert, and repeating them on every record is bytes app-obs stores
    // forever for no query anyone will run.
    const ENVELOPE: &[&str] = &[
        "message",
        "origin",
        "product",
        "vendor",
        "service",
        "category",
        "tenant",
        "event.type",
        "event.created",
        "event.received",
    ];

    let mut out = serde_json::Map::new();
    for (name, field) in log.fields() {
        if ENVELOPE.contains(&name.as_ref()) {
            continue;
        }
        let value = match field {
            SiemField::Text(t) => serde_json::Value::from(t.to_string()),
            SiemField::IP(ip) => serde_json::Value::from(ip.to_string()),
            SiemField::U64(n) => serde_json::Value::from(*n),
            SiemField::I64(n) => serde_json::Value::from(*n),
            SiemField::F64(n) => serde_json::Value::from(*n),
            SiemField::Date(n) => serde_json::Value::from(*n),
            SiemField::User(u) => serde_json::Value::from(u.clone()),
            SiemField::Domain(d) => serde_json::Value::from(d.clone()),
            _ => continue,
        };
        out.insert(name.to_string(), value);
    }
    let tags: Vec<String> = log.tags().iter().map(|t| t.to_string()).collect();
    if !tags.is_empty() {
        out.insert("tags".into(), serde_json::Value::from(tags));
    }
    serde_json::Value::Object(out)
}

// -- response actions -------------------------------------------------------

/// What an operator can do about one finding.
///
/// A finding with no answer to "and now what?" is a notification, not a
/// security control. This is the runbook half of an alert: a couple of things
/// worth checking before acting, and — where one exists — a [`RuleSpec`] that is
/// already filled in, so the dashboard's button posts *exactly* the body it
/// showed and what the operator read cannot drift from what the server applies.
///
/// Derived at read time from the alert rather than stored on it. The ring holds
/// hundreds of alerts and app-obs holds them forever; neither should carry a
/// paragraph of advice that is a pure function of three fields.
#[derive(Debug, Clone, Serialize)]
pub struct AlertResponse {
    /// What to check first. Ordered, and deliberately short — a list nobody
    /// finishes reading is the same as no list.
    pub investigate: Vec<&'static str>,
    /// Rules that would mitigate this, ready to post.
    pub actions: Vec<SuggestedAction>,
    /// Where the obvious action does *not* do what it looks like it does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveat: Option<&'static str>,
}

/// One ready-to-apply rule, with the sentence that explains what it will and
/// will not stop.
#[derive(Debug, Clone, Serialize)]
pub struct SuggestedAction {
    /// Stable identifier for the kind of action, so a client can style or
    /// confirm on it without parsing the label.
    pub kind: &'static str,
    /// The button.
    pub label: String,
    /// What it does, and what it leaves alone. Shown next to the button, not
    /// behind it: this is the last thing read before traffic is refused.
    pub effect: String,
    /// The exact body for `POST /security/rules`.
    pub rule: crate::guard::RuleSpec,
}

/// Signatures reused for [`respond`], so "is this path itself the payload?" is
/// answered by the same patterns that raised the alert instead of a second,
/// drifting copy of them.
fn path_signatures() -> &'static Signatures {
    static S: OnceLock<Signatures> = OnceLock::new();
    S.get_or_init(Signatures::new)
}

/// A client block lasts hours; a path block lasts a week.
///
/// Not symmetry for its own sake. An address is a lease — behind CGNAT or a
/// mobile carrier it belongs to somebody else by tomorrow, so a long block
/// punishes a stranger for what its previous holder did. A path pattern never
/// changes hands: `/wp-login.php` is a probe today and a probe next month.
const CLIENT_BLOCK_SECS: u64 = 3_600;
const CLIENT_BLOCK_LONG_SECS: u64 = 86_400;
const PATH_BLOCK_SECS: u64 = 604_800;
/// An agent block is a policy decision rather than an incident response, so it
/// lasts the longest — but still expires, like every block here.
const AGENT_BLOCK_SECS: u64 = 2_592_000;

fn secs_phrase(secs: u64) -> &'static str {
    match secs {
        3_600 => "1 hour",
        86_400 => "24 hours",
        604_800 => "7 days",
        2_592_000 => "30 days",
        _ => "a while",
    }
}

fn block_client(client: &str, secs: u64, note: String) -> SuggestedAction {
    SuggestedAction {
        kind: "block-client",
        label: format!("Block {client} for {}", secs_phrase(secs)),
        effect: format!(
            "Every request from {client} to the data plane is refused with a 403 \
             for {}, then the rule expires on its own. The admin API is not affected.",
            secs_phrase(secs)
        ),
        rule: crate::guard::RuleSpec {
            action: crate::guard::RuleAction::Block,
            match_: crate::guard::MatchSpec {
                client: Some(client.to_string()),
                ..Default::default()
            },
            expires_in_secs: Some(secs),
            note: Some(note),
        },
    }
}

/// The narrower sibling: block one address, but only against the deployment it
/// was caught attacking. The right choice when the address is a shared egress
/// and only one of the things behind it is misbehaving.
fn block_client_on(client: &str, deployment: &str, secs: u64, note: String) -> SuggestedAction {
    SuggestedAction {
        kind: "block-client-deployment",
        label: format!("Block {client} on {deployment} only"),
        effect: format!(
            "Refuses {client} for {} where it is routed to {deployment}, and leaves \
             the rest of the fleet reachable from that address.",
            secs_phrase(secs)
        ),
        rule: crate::guard::RuleSpec {
            action: crate::guard::RuleAction::Block,
            match_: crate::guard::MatchSpec {
                client: Some(client.to_string()),
                deployment: Some(deployment.to_string()),
                ..Default::default()
            },
            expires_in_secs: Some(secs),
            note: Some(note),
        },
    }
}

fn block_path(path: &str, deployment: Option<&str>, note: String) -> SuggestedAction {
    let scope = match deployment {
        Some(d) => format!(" on {d}"),
        None => String::new(),
    };
    SuggestedAction {
        kind: "block-path",
        label: format!("Block {path}{scope} for 7 days"),
        effect: format!(
            "Refuses every request whose path starts with {path}{scope}, from any \
             address — which stops the whole population probing it, not just this one. \
             Check first that nothing legitimate lives under that prefix.",
        ),
        rule: crate::guard::RuleSpec {
            action: crate::guard::RuleAction::Block,
            match_: crate::guard::MatchSpec {
                path_prefix: Some(path.to_string()),
                deployment: deployment.map(str::to_string),
                ..Default::default()
            },
            expires_in_secs: Some(PATH_BLOCK_SECS),
            note: Some(note),
        },
    }
}

fn exempt_client(client: &str, note: String) -> SuggestedAction {
    SuggestedAction {
        kind: "exempt-client",
        label: format!("Exempt {client}"),
        effect: format!(
            "Marks {client} as never-block, so no current or future rule refuses it. \
             Does not stop it being alerted on — this is for a monitor or a load test \
             you recognise, not for silencing the finding.",
        ),
        rule: crate::guard::RuleSpec {
            action: crate::guard::RuleAction::Allow,
            match_: crate::guard::MatchSpec {
                client: Some(client.to_string()),
                ..Default::default()
            },
            // Permanent on purpose, and the one action here that is: an
            // exemption that quietly expires re-exposes the thing it protects,
            // and the failure would show up as an outage in a monitor rather
            // than as anything anyone connects back to this button.
            expires_in_secs: None,
            note: Some(note),
        },
    }
}

/// A block on an agent's own token, on one deployment. Matches what the client
/// *says* it is, so it stops an honest crawler and any spoofer using its name —
/// which is the point — and nothing that does not send the token.
fn block_agent(agent: &Agent, token: &str, deployment: &str, note: String) -> SuggestedAction {
    SuggestedAction {
        kind: "block-agent",
        label: format!("Block {} on {deployment}", agent.name),
        effect: format!(
            "Refuses every request to {deployment} whose User-Agent contains {token:?} \
             with a 403 for {}. Other deployments, and clients that do not send the \
             token, are unaffected.",
            secs_phrase(AGENT_BLOCK_SECS)
        ),
        rule: crate::guard::RuleSpec {
            action: crate::guard::RuleAction::Block,
            match_: crate::guard::MatchSpec {
                user_agent_contains: Some(token.to_string()),
                deployment: Some(deployment.to_string()),
                ..Default::default()
            },
            expires_in_secs: Some(AGENT_BLOCK_SECS),
            note: Some(note),
        },
    }
}

/// Turn a finding into a runbook.
///
/// Pure and total: every rule name gets an answer, including one it has never
/// seen, so adding a detection can never produce an alert the console has
/// nothing to say about.
pub fn respond(alert: &Alert) -> AlertResponse {
    // Only an address app-lb parsed itself is offered as a rule. Anything else
    // would put a string the guard will reject into a button that looks like it
    // works.
    let client = alert
        .client
        .as_deref()
        .filter(|c| c.parse::<IpAddr>().is_ok());
    let note = format!("{} alert #{}", alert.rule, alert.id);
    let mut actions = Vec::new();
    let mut caveat = None;

    let investigate: Vec<&'static str> = match alert.rule {
        r if r.starts_with("auth.") => {
            // The guard is not consulted on the admin listener — that is what
            // keeps a bad rule from locking an operator out of the page that
            // removes it. Which means for an admin-plane spray the honest answer
            // is "not from here", and saying so beats a button that appears to
            // work.
            caveat = Some(
                "app-lb never applies these rules to its own admin API, so that a bad rule \
                 cannot lock you out of the page that deletes it. If this address is \
                 probing the admin plane, block it at the firewall or bind \
                 APP_LB_ADMIN_ADDR to loopback and reach it over SSH.",
            );
            if let Some(c) = client {
                let secs = if r == "auth.brute-force" || r == "auth.scope-denied" {
                    CLIENT_BLOCK_SECS
                } else {
                    CLIENT_BLOCK_LONG_SECS
                };
                actions.push(block_client(c, secs, note.clone()));
            }
            match alert.rule {
                "auth.scope-denied" => vec![
                    "This is a valid credential reaching past its scope — treat it as a \
                     possibly-leaked app-token, not as guessing.",
                    "Find it in GET /tokens by its scope and last-used time, and revoke it \
                     with DELETE /tokens/:id.",
                    "Rotate whatever held it before deciding the incident is over.",
                ],
                "auth.enumeration" | "auth.spray" => vec![
                    "Many identities from one address is credential stuffing, so a single \
                     account lockout will not touch it.",
                    "Narrow the sign-in gate: allowed_domains to your Workspace domain, or \
                     allowed_emails to the list that should actually get in.",
                    "Check whether any attempt succeeded — a `security` record with \
                     event.outcome=success from this address is the one that matters.",
                ],
                "auth.signin-state" => vec![
                    "A mismatched sign-in state is usually a stale bookmark or a cookie \
                     dropped by a SameSite policy, not an attack — check the volume before \
                     acting.",
                    "If it is one user in a loop, have them clear the app-lb cookie for \
                     that hostname and try again.",
                ],
                _ => vec![
                    "Confirm this is not your own automation retrying with a stale \
                     credential — that is the common cause and blocking it makes an \
                     outage.",
                    "If it is genuine, blocking the address buys time; rotating the \
                     credential it is guessing at is the fix.",
                    "Check whether any attempt succeeded before treating the block as the \
                     end of it.",
                ],
            }
        }

        r if r.starts_with("web.") => {
            if let Some(c) = client {
                actions.push(block_client(c, CLIENT_BLOCK_LONG_SECS, note.clone()));
                if let Some(d) = alert.deployment.as_deref() {
                    actions.push(block_client_on(c, d, CLIENT_BLOCK_LONG_SECS, note.clone()));
                }
            }
            // Offer the path block only when the *path* is what tripped the
            // signature. When the payload was in a query value the path is an
            // ordinary endpoint — `/search`, `/api/items` — and blocking it
            // would take a working feature offline to stop one probe.
            if let Some(p) = alert.path.as_deref()
                && path_signatures().scan(p, None).is_some()
            {
                actions.push(block_path(p, alert.deployment.as_deref(), note.clone()));
            }
            vec![
                "Check the status this got: a 404 means it found nothing, a 200 means it \
                 did and the block is the second thing to do.",
                "The alert names the parameter, never the value — app-lb does not store \
                 query strings. The upstream's own log is where the payload is.",
                "One probe is a scanner and needs no response; a sequence of them from one \
                 address is worth blocking.",
            ]
        }

        "traffic.scanner" => {
            if let Some(c) = client {
                actions.push(block_client(c, CLIENT_BLOCK_LONG_SECS, note.clone()));
                actions.push(exempt_client(c, format!("recognised source, {note}")));
            }
            vec![
                "Distinct paths, not repeats — this is somebody mapping the surface rather \
                 than a client retrying.",
                "Check it against your own vulnerability scanner's source before blocking.",
                "If the paths are all 404s it has found nothing yet, which makes this the \
                 cheap moment to act.",
            ]
        }

        "traffic.rate-spike" => {
            if let Some(c) = client {
                actions.push(block_client(c, CLIENT_BLOCK_SECS, note.clone()));
                actions.push(exempt_client(c, format!("recognised source, {note}")));
            }
            caveat = Some(
                "Rate alone does not distinguish an attack from a launch. Check the \
                 deployment's error rate on the dashboard before refusing traffic — if it \
                 is serving all of this successfully, the answer is more replicas, not a \
                 block.",
            );
            vec![
                "Identify the source first: a CDN or corporate NAT presents thousands of \
                 users as one address, and blocking it takes all of them out.",
                "Compare against the deployment's 5xx rate — a spike that is being served \
                 fine is capacity, not abuse.",
                "If it is abuse, an hour is usually enough; re-issue the rule if it comes \
                 back.",
            ]
        }

        "bot.spoofed" => {
            if let Some(c) = client {
                actions.push(block_client(c, CLIENT_BLOCK_LONG_SECS, note.clone()));
                if let Some(d) = alert.deployment.as_deref() {
                    actions.push(block_client_on(c, d, CLIENT_BLOCK_LONG_SECS, note.clone()));
                }
            }
            vec![
                "The User-Agent names an operator that publishes its crawler ranges, and \
                 this address is outside them: it is borrowing the name, usually to get \
                 past rules that let that crawler in.",
                "Check the range list's status on the security page — a list that loaded \
                 long ago may predate a range the operator added since.",
                "Treat what it requested as you would any unknown client's traffic.",
            ]
        }

        "bot.ai-crawler" | "bot.ai-agent" => {
            if let (Some(tag), Some(d)) = (alert.bot, alert.deployment.as_deref())
                && let Some(agent) = crate::bots::agent(tag.agent)
                && let Some(token) = agent.guard_token()
            {
                actions.push(block_agent(agent, token, d, note.clone()));
            }
            if alert.rule == "bot.ai-agent" {
                caveat = Some(
                    "This agent fetches pages because a person asked an assistant to read \
                     them. Blocking it stops those people, not a crawler.",
                );
                vec![
                    "This is user-triggered traffic: someone asked an AI assistant about \
                     this deployment's pages.",
                    "Decide as a policy, not as an incident — most sites want to be \
                     readable by assistants their users rely on.",
                    "If the claim is not verified, it may be a spoofer; a spoofed claim \
                     raises bot.spoofed separately.",
                ]
            } else {
                vec![
                    "An AI lab's crawler is collecting this deployment's pages, for \
                     training or for an AI search index.",
                    "Well-behaved crawlers honour robots.txt — a Disallow for the agent's \
                     token is the polite opt-out and keeps working wherever it is served.",
                    "Blocking here is the enforced one: it refuses the request whatever \
                     robots.txt says.",
                ]
            }
        }

        _ => vec![
            "No standing runbook for this rule — read the ECS fields on the alert for the \
             request that raised it.",
        ],
    };

    AlertResponse {
        investigate,
        actions,
        caveat,
    }
}

/// An alert as `GET /security` serves it: the finding plus what to do about it.
///
/// A separate type rather than fields on [`Alert`], so the record that goes to
/// app-obs and the entries in the ring stay exactly what they were.
#[derive(Debug, Clone, Serialize)]
pub struct AlertView {
    #[serde(flatten)]
    pub alert: Alert,
    pub response: AlertResponse,
}

impl From<Alert> for AlertView {
    fn from(alert: Alert) -> Self {
        Self {
            response: respond(&alert),
            alert,
        }
    }
}

/// The in-memory ring `GET /security` serves.
///
/// A `Mutex`, not `ArcSwap` — worth saying, because `ArcSwap` is the house
/// pattern elsewhere ([`crate::acme::ChallengeTable`], `Deployment::backends`).
/// It is the wrong tool here: `ArcSwap` suits read-mostly values replaced
/// *wholesale*, and this ring is mutated in place when a repeat folds into an
/// existing entry, so every push would clone the whole deque. A lock held for
/// microseconds, taken only when an alert fires (rare by construction) and once
/// per ten-second dashboard poll, is correct and simpler. The counters stay
/// atomics so `/metrics` never takes the lock at all.
pub struct AlertRing {
    alerts: Mutex<VecDeque<Alert>>,
    capacity: usize,
    window: i64,
    suppress: i64,
    max_per_min: u32,
    next_id: AtomicU64,
    stats: Arc<SiemStats>,
    by_severity: [AtomicU64; 5],
    /// Ceiling state: new alerts in the current minute.
    minute: Mutex<(i64, u32)>,
    /// The same, for informational bot sightings.
    bot_minute: Mutex<(i64, u32)>,
    /// Automated-traffic state, when `APP_LB_BOTS` is on.
    bots: Option<Arc<BotState>>,
}

impl AlertRing {
    fn new(cfg: &SiemConfig, stats: Arc<SiemStats>) -> Self {
        Self {
            alerts: Mutex::new(VecDeque::with_capacity(cfg.alert_capacity.min(1024))),
            capacity: cfg.alert_capacity,
            window: cfg.window,
            suppress: cfg.suppress,
            max_per_min: cfg.max_alerts_per_min,
            next_id: AtomicU64::new(1),
            stats,
            by_severity: Default::default(),
            minute: Mutex::new((0, 0)),
            bot_minute: Mutex::new((0, 0)),
            bots: None,
        }
    }

    /// The automated-traffic table, or `None` when `APP_LB_BOTS=0`.
    pub fn bot_traffic(&self, now: i64) -> Option<BotTrafficView> {
        self.bots.as_ref().map(|b| b.view(now))
    }

    /// Fold or raise. Returns the alert only when it is genuinely new, which is
    /// what decides whether a [`Record`] goes to app-obs.
    fn raise(&self, mut alert: Alert, now: i64) -> Option<Alert> {
        let mut alerts = self.alerts.lock().expect("alert ring lock");

        // Layer 1: fold a repeat into the open alert. Scanning the deque is
        // cheaper than a side index that can fall out of sync with eviction, and
        // this path is rare by construction.
        for existing in alerts.iter_mut().rev() {
            if existing.rule == alert.rule
                && existing.client == alert.client
                && existing.deployment == alert.deployment
                && existing.bot.map(|b| b.agent) == alert.bot.map(|b| b.agent)
                && now - existing.last_ts <= self.suppress * 1000
            {
                existing.count += 1;
                existing.last_ts = now;
                self.stats.suppressed.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }

        // Layer 2: a hard ceiling on *new* alerts. Layer 1 cannot fold a
        // distributed attack, where every source has a distinct key — this is
        // what bounds the record rate app-obs sees in that case.
        //
        // Sightings of AI crawlers and agents are informational and draw on a
        // budget of their own, so a busy crawl day cannot crowd an attack out of
        // the ring.
        {
            let sighting = alert.severity == Severity::Info && alert.rule.starts_with("bot.");
            let budget = if sighting {
                &self.bot_minute
            } else {
                &self.minute
            };
            let mut minute = budget.lock().expect("alert minute lock");
            let this_minute = now / 60_000;
            if minute.0 != this_minute {
                *minute = (this_minute, 0);
            }
            if minute.1 >= self.max_per_min {
                self.stats.suppressed.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            minute.1 += 1;
        }

        alert.id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.by_severity[alert.severity.index()].fetch_add(1, Ordering::Relaxed);
        self.stats.raised.fetch_add(1, Ordering::Relaxed);
        while alerts.len() >= self.capacity {
            alerts.pop_front();
        }
        alerts.push_back(alert.clone());
        Some(alert)
    }

    /// Newest first, which is the order the dashboard renders.
    pub fn recent(&self, limit: usize) -> Vec<Alert> {
        let alerts = self.alerts.lock().expect("alert ring lock");
        alerts.iter().rev().take(limit).cloned().collect()
    }

    pub fn totals(&self) -> SeverityTotals {
        SeverityTotals {
            info: self.by_severity[0].load(Ordering::Relaxed),
            low: self.by_severity[1].load(Ordering::Relaxed),
            medium: self.by_severity[2].load(Ordering::Relaxed),
            high: self.by_severity[3].load(Ordering::Relaxed),
            critical: self.by_severity[4].load(Ordering::Relaxed),
        }
    }

    pub fn len(&self) -> usize {
        self.alerts.lock().expect("alert ring lock").len()
    }

    /// Reported on `/security` so a reader knows what "8 failures" is counted
    /// over without having to know the server's environment.
    pub fn window_secs(&self) -> u64 {
        self.window as u64
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SeverityTotals {
    pub info: u64,
    pub low: u64,
    pub medium: u64,
    pub high: u64,
    pub critical: u64,
}

/// One alert, as app-obs stores it.
///
/// The deployment falls back the same way [`Access::into_record`] does: app-obs
/// rejects a record naming no deployment, so an admin-plane alert has to land
/// under the LB's own id.
fn alert_record(a: &Alert, lb_deployment: &str) -> Record {
    let mut fields = serde_json::Map::new();
    fields.insert("rule".into(), a.rule.into());
    fields.insert(
        "severity".into(),
        serde_json::to_value(a.severity).unwrap_or(serde_json::Value::Null),
    );
    fields.insert("count".into(), a.count.into());
    if let Some(client) = &a.client {
        fields.insert("client".into(), client.clone().into());
    }
    if let Some(path) = &a.path {
        fields.insert("path".into(), path.clone().into());
    }
    if let Some(t) = a.technique {
        fields.insert("technique".into(), t.into());
    }
    // The normalized event, flattened alongside the alert's own fields so a
    // query in app-obs can filter on `source.ip` or `url.path` directly. Our
    // keys win a collision — `rule`/`severity`/`count` describe the alert, not
    // the event.
    if let Some(serde_json::Value::Object(ecs)) = &a.ecs {
        for (k, v) in ecs {
            fields.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    Record {
        ts: a.ts,
        deployment: a
            .deployment
            .clone()
            .unwrap_or_else(|| lb_deployment.to_string()),
        backend: None,
        source: SECURITY_SOURCE,
        level: a.severity.level(),
        message: obs::truncate(a.title.clone(), obs::MAX_MESSAGE),
        fields: Some(serde_json::Value::Object(fields)),
    }
}

// -- the analyzer ----------------------------------------------------------

/// Owns every piece of mutable detection state. Separated from [`Engine`] so the
/// tests can drive it with an injected clock instead of sleeping.
struct Analyzer {
    cfg: SiemConfig,
    windows: Windows,
    signatures: Signatures,
    access_parser: AccessParser,
    control_parser: ControlPlaneParser,
    enrichment: LbEnrichment,
    /// Required by the trait signatures. Every lookup returns `None`, which is
    /// correct: app-lb ships no GeoIP or IOC feed.
    datasets: DatasetHolder,
    /// `None` when `APP_LB_BOTS=0`.
    bots: Option<Arc<BotState>>,
}

impl Analyzer {
    #[cfg(test)]
    fn new(cfg: SiemConfig) -> Self {
        let bots = cfg.bots.then(|| Arc::new(BotState::new(&cfg)));
        Self::with_bots(cfg, bots)
    }

    fn with_bots(cfg: SiemConfig, bots: Option<Arc<BotState>>) -> Self {
        Self {
            bots,
            windows: Windows::new(cfg.window, cfg.max_clients),
            signatures: Signatures::new(),
            access_parser: AccessParser,
            control_parser: ControlPlaneParser,
            enrichment: LbEnrichment,
            datasets: DatasetHolder::default(),
            cfg,
        }
    }

    /// Normalize, enrich, then detect. `now` is a parameter rather than read from
    /// the clock so every window test is deterministic.
    fn analyze(&mut self, o: Observation, now: i64) -> Vec<Alert> {
        let (mut alerts, log) = match o {
            Observation::Access(a) => self.access(*a, now),
            Observation::Auth(a) => self.auth(*a, now),
        };
        // Attached once and shared: every alert from one observation describes
        // the same event.
        if !alerts.is_empty() {
            let ecs = ecs_fields(&log);
            for a in &mut alerts {
                a.ecs = Some(ecs.clone());
            }
        }
        alerts
    }

    fn normalize(&self, mut log: SiemLog, parser: Which) -> SiemLog {
        let parsed = match parser {
            Which::Access => self.access_parser.parse_log(log, &self.datasets),
            Which::Control => self.control_parser.parse_log(log, &self.datasets),
        };
        log = match parsed {
            Ok(l) => l,
            // The parser hands the log back rather than cloning it. Nothing here
            // dispatches across candidates — the source told us which shape it
            // is — so an unparsed log still gets enriched and analyzed.
            Err(LogParsingError::NoValidParser(l))
            | Err(LogParsingError::ParserError(l, _))
            | Err(LogParsingError::NotImplemented(l))
            | Err(LogParsingError::FormatError(l, _)) => l,
            Err(LogParsingError::Discard) => return SiemLog::new("", 0, ORIGIN),
        };
        self.enrichment.enrich(log, &self.datasets)
    }

    fn access(&mut self, o: AccessObs, now: i64) -> (Vec<Alert>, SiemLog) {
        let mut log = SiemLog::new(
            format!("{} {} {}", o.method, o.path, status_text(o.status)),
            o.ts,
            ORIGIN,
        );
        log.add_tag("access");
        if o.deployment.is_none() {
            log.add_tag("unrouted");
        }
        // What the UA claims to be, and whether the claim checked out.
        let bot = match (&self.bots, o.user_agent.as_deref()) {
            (Some(b), Some(ua)) => b
                .classifier
                .classify(ua)
                .map(|i| (i, b.ranges.verify(&AGENTS[i], o.client))),
            _ => None,
        };
        if let Some((i, v)) = bot {
            let a = &AGENTS[i];
            log.add_tag("bot");
            log.add_field(F_UA_NAME, SiemField::from_str_slice(a.name));
            log.add_field(F_BOT_CLASS, SiemField::from_str_slice(a.class.as_str()));
            log.add_field(F_BOT_OPERATOR, SiemField::from_str_slice(a.operator));
            log.add_field(F_BOT_VERIFICATION, SiemField::from_str_slice(v.as_str()));
        }
        if let Some(ip) = o.client {
            log.add_field(fd::SOURCE_IP, SiemField::IP(siem_ip(ip)));
        }
        log.add_field(fd::HTTP_REQUEST_METHOD, method_field(&o.method));
        log.add_field(fd::URL_PATH, SiemField::Text(o.path.to_string().into()));
        if let Some(host) = &o.host {
            log.add_field(fd::URL_DOMAIN, SiemField::Text(host.to_string().into()));
        }
        if let Some(s) = o.status {
            log.add_field(fd::HTTP_RESPONSE_STATUS_CODE, SiemField::U64(s as u64));
        }
        log.add_field(F_DURATION, SiemField::U64(o.duration_nanos));
        log.add_field(F_BYTES, SiemField::U64(o.bytes));
        if let Some(d) = &o.deployment {
            log.set_service(d.to_string());
            log.add_field(F_SERVICE, SiemField::Text(d.to_string().into()));
        }
        let log = self.normalize(log, Which::Access);

        let mut out = Vec::new();

        // Stateless: signatures over the path, then the query values.
        if let Some((sig, param)) = self.signatures.scan(&o.path, o.scan_query.as_deref()) {
            let where_ = match &param {
                Some(p) => format!("query parameter {p:?}"),
                None => "path".to_string(),
            };
            out.push(Alert {
                id: 0,
                ts: o.ts,
                last_ts: o.ts,
                rule: sig.rule,
                severity: sig.severity,
                title: format!(
                    "{} attempt in {} from {}",
                    sig.what,
                    where_,
                    o.client.map(|c| c.to_string()).unwrap_or("an unknown source".into())
                ),
                client: o.client.map(|c| c.to_string()),
                deployment: o.deployment.as_ref().map(|d| d.to_string()),
                path: Some(obs::truncate(o.path.to_string(), MAX_ALERT_PATH)),
                technique: Some(sig.technique),
                count: 1,
                ecs: None,
                bot: None,
            });
        }

        // Automated traffic: count it, and raise the findings worth a look.
        if let (Some((i, v)), Some(b)) = (bot, self.bots.as_ref()) {
            let agent = &AGENTS[i];
            let tag = BotTag::of(agent, v);
            b.board.record(
                BotKey {
                    deployment: o.deployment.clone(),
                    agent: i,
                    verification: v,
                },
                o.client,
                now,
            );
            let deployment = o.deployment.as_ref().map(|d| d.to_string());
            if v == Verification::Spoofed
                && let Some(ip) = o.client
            {
                out.push(Alert {
                    id: 0,
                    ts: o.ts,
                    last_ts: o.ts,
                    rule: "bot.spoofed",
                    severity: Severity::Medium,
                    title: format!(
                        "{ip} claims to be {} but is outside {}'s published ranges",
                        agent.name, agent.operator
                    ),
                    client: Some(ip.to_string()),
                    deployment,
                    path: Some(obs::truncate(o.path.to_string(), MAX_ALERT_PATH)),
                    technique: Some("T1036"),
                    count: 1,
                    ecs: None,
                    bot: Some(tag),
                });
            } else if let Some(d) = deployment
                && matches!(
                    agent.class,
                    BotClass::AiAgent | BotClass::AiCrawler | BotClass::AiSearch
                )
            {
                let (rule, doing) = if agent.class == BotClass::AiAgent {
                    ("bot.ai-agent", "is fetching pages for its users from")
                } else {
                    ("bot.ai-crawler", "is crawling")
                };
                // Unattributed on purpose: one crawler is many addresses, and
                // folding by agent is what keeps it to one alert.
                out.push(Alert {
                    id: 0,
                    ts: o.ts,
                    last_ts: o.ts,
                    rule,
                    severity: Severity::Info,
                    title: format!("{} ({}) {doing} {d}", agent.name, agent.operator),
                    client: None,
                    deployment: Some(d),
                    path: None,
                    technique: None,
                    count: 1,
                    ecs: None,
                    bot: Some(tag),
                });
            }
        }

        // Stateful: per-source rates.
        let Some(ip) = o.client else {
            return (out, log);
        };
        let key = ClientKey::of(ip);
        let (rate, scan) = {
            let window = self.cfg.window;
            let scan_threshold = self.cfg.scan_threshold;
            let rate_threshold = self.cfg.rate_threshold;
            let Some(w) = self.windows.entry(key, now) else {
                return (out, log);
            };
            w.requests.record(now, window);
            if let Some(d) = &o.deployment {
                w.deployment_sketch |= sketch_bit(d);
            }
            let mut scan = false;
            if matches!(o.status, Some(401) | Some(403) | Some(404)) {
                w.client_errors.record(now, window);
                w.path_sketch |= sketch_bit(&o.path);
                // The distinctness gate is what separates enumeration from one
                // broken client retrying a single dead URL.
                scan = w.client_errors.total() >= scan_threshold
                    && w.path_sketch.count_ones() >= 8;
            }
            (w.requests.total() >= rate_threshold, scan)
        };

        if scan {
            out.push(Alert {
                id: 0,
                ts: o.ts,
                last_ts: o.ts,
                rule: "traffic.scanner",
                severity: Severity::Medium,
                title: format!("{ip} is probing for unserved paths"),
                client: Some(ip.to_string()),
                deployment: o.deployment.as_ref().map(|d| d.to_string()),
                path: Some(obs::truncate(o.path.to_string(), MAX_ALERT_PATH)),
                technique: Some("T1595"),
                count: 1,
                ecs: None,
                bot: None,
            });
        }
        if rate {
            out.push(Alert {
                id: 0,
                ts: o.ts,
                last_ts: o.ts,
                rule: "traffic.rate-spike",
                severity: Severity::Medium,
                title: format!("{ip} is sending an unusual volume of requests"),
                client: Some(ip.to_string()),
                deployment: o.deployment.as_ref().map(|d| d.to_string()),
                path: None,
                technique: Some("T1498"),
                count: 1,
                ecs: None,
                bot: None,
            });
        }
        (out, log)
    }

    fn auth(&mut self, o: AuthObs, now: i64) -> (Vec<Alert>, SiemLog) {
        let mut log = SiemLog::new(
            format!("{} rejected at {}", o.action.as_str(), o.path),
            o.ts,
            ORIGIN,
        );
        log.add_tag("auth-failure");
        log.set_service(match o.action {
            AuthAction::AdminRejected | AuthAction::AdminScope => "admin",
            _ => "auth-gate",
        });
        if let Some(ip) = o.client {
            log.add_field(fd::SOURCE_IP, SiemField::IP(siem_ip(ip)));
        }
        log.add_field(fd::URL_PATH, SiemField::Text(o.path.to_string().into()));
        log.add_field(fd::EVENT_ACTION, SiemField::from_str_slice(o.action.as_str()));
        log.add_field(F_SCHEME, SiemField::from_str_slice(o.scheme.as_str()));
        if let Some(d) = &o.deployment {
            log.add_field(F_SERVICE, SiemField::Text(d.to_string().into()));
        }
        if let Some(s) = &o.subject {
            log.add_field(fd::USER_NAME, SiemField::User(s.to_string()));
        }
        let log = self.normalize(log, Which::Control);

        let mut out = Vec::new();

        // A state/nonce mismatch is CSRF-shaped and never benign, so it is worth
        // an alert on its own rather than after a threshold.
        if o.action == AuthAction::SigninState {
            out.push(Alert {
                id: 0,
                ts: o.ts,
                last_ts: o.ts,
                rule: "auth.signin-state",
                severity: Severity::Medium,
                title: "sign-in state did not match the flow cookie".into(),
                client: o.client.map(|c| c.to_string()),
                deployment: o.deployment.as_ref().map(|d| d.to_string()),
                path: Some(obs::truncate(o.path.to_string(), MAX_ALERT_PATH)),
                technique: Some("T1190"),
                count: 1,
                ecs: None,
                bot: None,
            });
        }

        let Some(ip) = o.client else {
            return (out, log);
        };
        if !o.action.counts_as_attempt() {
            return (out, log);
        }
        let key = ClientKey::of(ip);
        let (brute, spray, enumerating) = {
            let window = self.cfg.window;
            let threshold = self.cfg.auth_threshold;
            let Some(w) = self.windows.entry(key, now) else {
                return (out, log);
            };
            w.auth_failures.record(now, window);
            if let Some(d) = &o.deployment {
                w.deployment_sketch |= sketch_bit(d);
            }
            if let Some(s) = &o.subject {
                w.subject_sketch |= sketch_bit(s);
            }
            let over = w.auth_failures.total() >= threshold;
            (
                over,
                over && w.deployment_sketch.count_ones() >= 4,
                over && w.subject_sketch.count_ones() >= 4,
            )
        };

        if enumerating {
            out.push(Alert {
                id: 0,
                ts: o.ts,
                last_ts: o.ts,
                rule: "auth.enumeration",
                severity: Severity::High,
                title: format!("{ip} is trying many identities against the sign-in gate"),
                client: Some(ip.to_string()),
                deployment: o.deployment.as_ref().map(|d| d.to_string()),
                path: None,
                technique: Some("T1110_003"),
                count: 1,
                ecs: None,
                bot: None,
            });
        } else if spray {
            out.push(Alert {
                id: 0,
                ts: o.ts,
                last_ts: o.ts,
                rule: "auth.spray",
                severity: Severity::High,
                title: format!("{ip} is spraying credentials across several deployments"),
                client: Some(ip.to_string()),
                deployment: None,
                path: None,
                technique: Some("T1110_003"),
                count: 1,
                ecs: None,
                bot: None,
            });
        } else if brute {
            let (rule, severity, what) = match o.action {
                // A *valid* credential reaching past its scope is a
                // compromised-token signal, not a guessing attack.
                AuthAction::AdminScope => (
                    "auth.scope-denied",
                    Severity::Medium,
                    "is using a credential beyond its scope",
                ),
                _ => (
                    "auth.brute-force",
                    Severity::High,
                    "is failing authentication repeatedly",
                ),
            };
            out.push(Alert {
                id: 0,
                ts: o.ts,
                last_ts: o.ts,
                rule,
                severity,
                title: format!("{ip} {what}"),
                client: Some(ip.to_string()),
                deployment: o.deployment.as_ref().map(|d| d.to_string()),
                path: Some(obs::truncate(o.path.to_string(), MAX_ALERT_PATH)),
                technique: Some("T1110"),
                count: 1,
                ecs: None,
                bot: None,
            });
        }
        (out, log)
    }
}

enum Which {
    Access,
    Control,
}

fn status_text(s: Option<u16>) -> String {
    match s {
        Some(s) => s.to_string(),
        None => "-".into(),
    }
}

// -- the background service ------------------------------------------------

/// Drains the queue, analyses, and publishes.
pub struct Engine {
    rx: Mutex<Option<mpsc::Receiver<Observation>>>,
    cfg: SiemConfig,
    ring: Arc<AlertRing>,
    stats: Arc<SiemStats>,
    /// `None` when app-obs is not configured. Alerts still reach `/security`.
    obs: Option<LogSink>,
    lb_deployment: Arc<str>,
    bots: Option<Arc<BotState>>,
}

#[async_trait]
impl BackgroundService for Engine {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let Some(mut rx) = self.rx.lock().expect("siem receiver lock").take() else {
            tracing::error!("siem engine started twice");
            return;
        };
        let mut analyzer = Analyzer::with_bots(self.cfg.clone(), self.bots.clone());
        // The one outbound dependency, and an optional one: without it every
        // claim is reported as `claimed` rather than verified or spoofed.
        if let Some(b) = &self.bots
            && self.cfg.bot_ranges
        {
            tokio::spawn(crate::bots::refresh(
                b.ranges.clone(),
                Duration::from_secs(self.cfg.bot_refresh),
            ));
        }
        // Releases per-client state on an LB that has gone quiet, so an idle
        // process does not hold the last burst forever.
        let mut prune = tokio::time::interval(Duration::from_secs(
            (self.cfg.window as u64 / 2).max(5),
        ));
        prune.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut warned_dropped = false;

        tracing::info!(
            window_secs = self.cfg.window,
            max_clients = self.cfg.max_clients,
            scan_query = self.cfg.scan_query,
            "security monitoring active",
        );

        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                _ = prune.tick() => {
                    let now = obs::now_millis();
                    analyzer.windows.prune(now);
                    if let Some(b) = &self.bots {
                        b.board.prune(now);
                    }
                    self.stats
                        .tracked_clients
                        .store(analyzer.windows.clients.len() as u64, Ordering::Relaxed);
                    self.stats
                        .clients_at_capacity
                        .store(analyzer.windows.at_capacity, Ordering::Relaxed);

                    // A SIEM that has silently stopped seeing traffic looks
                    // exactly like a quiet network, so say so once.
                    if !warned_dropped && self.stats.dropped.load(Ordering::Relaxed) > 0 {
                        warned_dropped = true;
                        tracing::warn!(
                            "the security queue is dropping observations, so detection is \
                             now sampling rather than complete; raise \
                             APP_LB_SIEM_QUEUE_CAPACITY",
                        );
                    }
                }
                got = rx.recv() => {
                    let Some(o) = got else { break };
                    let now = obs::now_millis();
                    self.stats.analyzed.fetch_add(1, Ordering::Relaxed);
                    for alert in analyzer.analyze(o, now) {
                        // `raise` must run unconditionally — it is what puts the
                        // alert in the ring `GET /security` serves. Only the
                        // shipping is optional; folding these into one `&&`
                        // chain would empty the dashboard whenever
                        // `APP_LB_SIEM_SHIP=0`.
                        if let Some(raised) = self.ring.raise(alert, now)
                            && self.cfg.ship
                            && let Some(sink) = &self.obs
                        {
                            sink.send(alert_record(&raised, &self.lb_deployment));
                        }
                    }
                }
            }
        }
    }
}

// -- wiring ----------------------------------------------------------------

/// The pieces `main` wires up. Mirrors [`crate::obs::Obs`].
pub struct Siem {
    /// Cloned into the proxy, the admin API and the sign-in gate.
    pub sink: SecuritySink,
    /// Shared with the admin API for `GET /security`.
    pub ring: Arc<AlertRing>,
    /// Registered as a pingora background service.
    pub engine: Engine,
    /// Read by `/metrics`.
    pub stats: Arc<SiemStats>,
}

/// Build the pipeline, unless `APP_LB_SIEM=0`.
///
/// Allocates a channel and nothing else — `main` calls this before
/// `run_forever`, which may fork to daemonize, so nothing here may own a thread
/// or a connection.
///
/// `obs` is the *events* sink, used only to ship alerts; the SIEM is fully
/// functional without it.
pub fn from_env(obs_sink: Option<LogSink>, lb_deployment: Arc<str>) -> Option<Siem> {
    if !obs::env_flag("APP_LB_SIEM", true) {
        return None;
    }
    let cfg = SiemConfig::from_env();
    let stats = Arc::new(SiemStats::default());
    let bots = cfg.bots.then(|| Arc::new(BotState::new(&cfg)));
    let mut ring = AlertRing::new(&cfg, stats.clone());
    ring.bots = bots.clone();
    let ring = Arc::new(ring);
    let (tx, rx) = mpsc::channel(cfg.queue_capacity.max(1));

    Some(Siem {
        sink: SecuritySink {
            tx,
            stats: stats.clone(),
            scan_query: cfg.scan_query,
        },
        ring: ring.clone(),
        engine: Engine {
            rx: Mutex::new(Some(rx)),
            cfg,
            ring,
            stats: stats.clone(),
            obs: obs_sink,
            lb_deployment,
            bots,
        },
        stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    fn cfg() -> SiemConfig {
        SiemConfig {
            queue_capacity: 64,
            alert_capacity: 16,
            window: 60,
            max_clients: 8,
            auth_threshold: 5,
            scan_threshold: 10,
            rate_threshold: 100,
            suppress: 300,
            max_alerts_per_min: 1000,
            scan_query: true,
            ship: true,
            bots: true,
            bot_ranges: false,
            bot_refresh: 86_400,
            bot_window: 3_600,
        }
    }

    fn access(path: &str, status: Option<u16>, client: &str) -> AccessObs {
        AccessObs {
            ts: 1_700_000_000_000,
            client: client.parse().ok(),
            deployment: Some(Box::from("demo")),
            method: Box::from("GET"),
            path: Box::from(path),
            host: Some(Box::from("demo.local")),
            scan_query: None,
            user_agent: None,
            status,
            duration_nanos: 1_400_000,
            bytes: 254,
        }
    }

    fn auth(client: &str, action: AuthAction) -> AuthObs {
        AuthObs {
            ts: 1_700_000_000_000,
            client: client.parse().ok(),
            deployment: None,
            path: Box::from("/metrics"),
            action,
            scheme: AuthScheme::Basic,
            subject: None,
        }
    }

    /// The invariant the whole module is built around, mirroring obs.rs.
    #[tokio::test]
    async fn a_full_queue_drops_instead_of_blocking() {
        let stats = Arc::new(SiemStats::default());
        let (tx, _rx) = mpsc::channel(1);
        let sink = SecuritySink {
            tx,
            stats: stats.clone(),
            scan_query: false,
        };
        for _ in 0..2 {
            sink.observe_auth(auth("1.2.3.4", AuthAction::AdminRejected));
        }
        let s = stats.snapshot();
        assert_eq!((s.observed, s.dropped), (1, 1));
    }

    /// The most important test here: the query string is matched and never kept.
    #[test]
    fn the_query_string_never_reaches_a_field_an_alert_or_a_record() {
        let mut a = Analyzer::new(cfg());
        let mut o = access("/items", Some(200), "203.0.113.9");
        o.scan_query = Some(Box::from("code=SUPERSECRET&id=1' or '1'='1"));

        let alerts = a.analyze(Observation::Access(Box::new(o)), 1_700_000_000_000);
        let alert = alerts
            .iter()
            .find(|x| x.rule == "web.sqli")
            .expect("sqli must be detected in a parameter value");

        // It names where, not what.
        assert!(
            alert.title.contains("query parameter \"id\""),
            "alert should name the parameter: {}",
            alert.title
        );

        let as_alert = serde_json::to_string(alert).unwrap();
        let as_record = serde_json::to_string(&alert_record(alert, "_lb")).unwrap();
        for rendered in [&as_alert, &as_record] {
            assert!(
                !rendered.contains("SUPERSECRET"),
                "a credential from the query reached the log store: {rendered}"
            );
            assert!(
                !rendered.contains("'1'='1"),
                "a parameter *value* reached the log store: {rendered}"
            );
        }
    }

    #[test]
    fn an_access_log_parses_into_the_ecs_field_names_app_obs_expects() {
        let a = Analyzer::new(cfg());
        let mut log = SiemLog::new("GET /x 200", 1, ORIGIN);
        log.add_tag("access");
        log.add_field(fd::SOURCE_IP, SiemField::IP(SiemIp::V4(0x0100_0001)));
        log.add_field(fd::URL_PATH, SiemField::Text("/a/b.php".into()));
        log.add_field(fd::HTTP_RESPONSE_STATUS_CODE, SiemField::U64(404));
        let log = a.normalize(log, Which::Access);

        // Assert against the dictionary constants, so a u-siem bump that renames
        // one fails here instead of silently reshaping every stored log.
        assert_eq!(log.field(fd::EVENT_CATEGORY).is_some(), true);
        assert!(matches!(
            log.field(fd::EVENT_OUTCOME),
            Some(SiemField::Text(o)) if o == "failure"
        ));
        assert!(matches!(
            log.field(F_EXTENSION),
            Some(SiemField::Text(e)) if e == "php"
        ));
        assert_eq!(log.product(), ORIGIN);
        // Never set, by construction.
        assert!(log.field(fd::URL_QUERY).is_none());
    }

    /// `SiemIp::is_local` returns false for 127.0.0.1, and the admin listener
    /// binds loopback by default — so without the override every control-plane
    /// alert would claim an external attacker.
    #[test]
    fn loopback_is_internal_even_though_the_crate_says_otherwise() {
        assert!(
            !SiemIp::V4(u32::from(std::net::Ipv4Addr::LOCALHOST)).is_local(),
            "upstream behaviour changed; the override in `is_internal` may be redundant now",
        );
        for ip in ["127.0.0.1", "::1", "10.1.2.3", "192.168.0.9"] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(is_internal(&siem_ip(parsed)), "{ip} must be internal");
        }
        for ip in ["203.0.113.9", "2001:db8::1"] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(!is_internal(&siem_ip(parsed)), "{ip} must be external");
        }
    }

    /// The envelope is constant or already on the alert; repeating it on every
    /// record is storage app-obs keeps forever for no query.
    #[test]
    fn the_ecs_block_carries_the_event_and_not_the_envelope() {
        let mut a = Analyzer::new(cfg());
        let alerts = a.analyze(
            Observation::Access(Box::new(access("/wp-login.php", Some(404), "203.0.113.9"))),
            1_700_000_000_000,
        );
        let ecs = alerts[0].ecs.as_ref().expect("an alert carries its event");
        let obj = ecs.as_object().unwrap();
        for gone in ["message", "product", "vendor", "origin", "event.received"] {
            assert!(!obj.contains_key(gone), "{gone} is envelope, not event");
        }
        for kept in [fd::SOURCE_IP, fd::URL_PATH, fd::HTTP_RESPONSE_STATUS_CODE] {
            assert!(obj.contains_key(kept), "{kept} is the event itself");
        }
    }

    #[test]
    fn the_wrong_parser_hands_the_log_back_intact() {
        let a = Analyzer::new(cfg());
        let mut log = SiemLog::new("something", 1, ORIGIN);
        log.add_tag("auth-failure");
        match a.access_parser.parse_log(log, &a.datasets) {
            Err(LogParsingError::NoValidParser(back)) => {
                assert_eq!(back.message(), "something");
            }
            _ => panic!("access parser must decline an auth-failure log"),
        }
    }

    #[test]
    fn brute_force_fires_at_the_threshold_and_not_before() {
        let c = cfg();
        let mut a = Analyzer::new(c.clone());
        let now = 1_700_000_000_000;
        for _ in 0..c.auth_threshold - 1 {
            let out = a.analyze(
                Observation::Auth(Box::new(auth("198.51.100.7", AuthAction::AdminRejected))),
                now,
            );
            assert!(out.is_empty(), "must not alert below the threshold");
        }
        let out = a.analyze(
            Observation::Auth(Box::new(auth("198.51.100.7", AuthAction::AdminRejected))),
            now,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule, "auth.brute-force");
    }

    #[test]
    fn a_window_that_has_slid_past_forgets() {
        let c = cfg();
        let mut a = Analyzer::new(c.clone());
        let now = 1_700_000_000_000;
        for _ in 0..c.auth_threshold - 1 {
            a.analyze(
                Observation::Auth(Box::new(auth("198.51.100.8", AuthAction::AdminRejected))),
                now,
            );
        }
        // Past the whole window, so every bucket is stale.
        let later = now + (c.window + 1) * 1000;
        for _ in 0..c.auth_threshold - 1 {
            let out = a.analyze(
                Observation::Auth(Box::new(auth("198.51.100.8", AuthAction::AdminRejected))),
                later,
            );
            assert!(out.is_empty(), "attempts from a lapsed window must not count");
        }
    }

    /// The highest-value line in the detector: a /64 is one attacker.
    #[test]
    fn an_ipv6_attacker_cannot_rotate_within_a_64_to_escape() {
        let c = cfg();
        let mut a = Analyzer::new(c.clone());
        let now = 1_700_000_000_000;
        let mut fired = None;
        for i in 0..c.auth_threshold {
            let addr = format!("2001:db8:1:2::{:x}", i + 1);
            let out = a.analyze(
                Observation::Auth(Box::new(auth(&addr, AuthAction::AdminRejected))),
                now,
            );
            if let Some(alert) = out.into_iter().next() {
                fired = Some(alert);
            }
        }
        assert!(
            fired.is_some(),
            "rotating the low 64 bits must not reset the counter"
        );
    }

    /// The bound that keeps this from being the vulnerability.
    #[test]
    fn the_client_table_is_capped_and_prefers_dropping_new_over_evicting_live() {
        let c = cfg();
        let mut w = Windows::new(c.window, c.max_clients);
        let now = 1_700_000_000_000;

        // A source with live, in-window activity.
        let live = ClientKey::of("203.0.113.1".parse().unwrap());
        w.entry(live, now).unwrap().requests.record(now, c.window);

        // Flood with fresh sources, all inside the window.
        for i in 0..1000u32 {
            let ip: IpAddr = format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256)
                .parse()
                .unwrap();
            w.entry(ClientKey::of(ip), now);
        }

        assert!(
            w.clients.len() <= c.max_clients,
            "the table must stay bounded, got {}",
            w.clients.len()
        );
        assert!(w.at_capacity, "saturation must be reported");
        assert!(
            w.clients.contains_key(&live),
            "a live entry must not be evicted to make room for a flood",
        );
    }

    #[test]
    fn a_scanner_produces_one_alert_not_ten_thousand() {
        let stats = Arc::new(SiemStats::default());
        let ring = AlertRing::new(&cfg(), stats.clone());
        let now = 1_700_000_000_000;
        let mut shipped = 0;
        for _ in 0..5000 {
            let a = Alert {
                id: 0,
                ts: now,
                last_ts: now,
                rule: "traffic.scanner",
                severity: Severity::Medium,
                title: "probing".into(),
                client: Some("203.0.113.9".into()),
                deployment: Some("demo".into()),
                path: None,
                technique: Some("T1595"),
                count: 1,
                ecs: None,
                bot: None,
            };
            if ring.raise(a, now).is_some() {
                shipped += 1;
            }
        }
        assert_eq!(shipped, 1, "only the first occurrence ships to app-obs");
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.recent(10)[0].count, 5000);
        assert_eq!(stats.snapshot().suppressed, 4999);
    }

    /// `APP_LB_SIEM_SHIP=0` must stop records reaching app-obs and nothing else.
    /// Collapsing the ship check into the same condition as `raise` would empty
    /// `GET /security`, which is a silent way to lose the whole feature.
    #[test]
    fn not_shipping_still_records_the_alert_locally() {
        let mut c = cfg();
        c.ship = false;
        let stats = Arc::new(SiemStats::default());
        let ring = AlertRing::new(&c, stats.clone());
        let now = 1_700_000_000_000;

        // What the engine loop does: raise first, ship second.
        let raised = ring.raise(
            Alert {
                id: 0,
                ts: now,
                last_ts: now,
                rule: "auth.brute-force",
                severity: Severity::High,
                title: "x".into(),
                client: Some("203.0.113.9".into()),
                deployment: None,
                path: None,
                technique: None,
                count: 1,
                ecs: None,
                bot: None,
            },
            now,
        );
        assert!(raised.is_some(), "a new alert is always raised");
        assert_eq!(ring.len(), 1, "and is held for GET /security regardless of shipping");
        assert_eq!(stats.snapshot().raised, 1);
    }

    #[test]
    fn the_ring_never_exceeds_its_capacity() {
        let c = cfg();
        let stats = Arc::new(SiemStats::default());
        let ring = AlertRing::new(&c, stats);
        let now = 1_700_000_000_000;
        for i in 0..c.alert_capacity * 3 {
            ring.raise(
                Alert {
                    id: 0,
                    ts: now,
                    last_ts: now,
                    rule: "web.sqli",
                    // A distinct key each time, so nothing folds.
                    client: Some(format!("203.0.113.{}", i % 250)),
                    severity: Severity::High,
                    title: "x".into(),
                    deployment: Some(format!("d{i}")),
                    path: None,
                    technique: None,
                    count: 1,
                    ecs: None,
                    bot: None,
                },
                now,
            );
        }
        assert_eq!(ring.len(), c.alert_capacity);
    }

    /// app-lb serves these itself; matching them would make the feature unusable.
    #[test]
    fn app_lbs_own_paths_are_not_attacks() {
        let s = Signatures::new();
        for path in [
            "/.well-known/acme-challenge/tok3n-with-.-dots",
            "/.well-known/openid-configuration",
        ] {
            assert!(
                s.scan(path, None).is_none(),
                "{path} must not be reported as an attack"
            );
        }
    }

    #[test]
    fn ordinary_traffic_raises_nothing() {
        let s = Signatures::new();
        for path in [
            "/",
            "/health",
            "/api/v1/users",
            "/static/app.1f2e3d.js",
            "/assets/logo.svg",
            "/images/photo.jpeg",
            "/docs/getting-started",
            "/v2/items/42",
            "/favicon.ico",
        ] {
            assert!(s.scan(path, None).is_none(), "{path} must be clean");
        }
        // A benign query, including a base64 value with padding.
        assert!(
            s.scan("/api/v1/users", Some("limit=50&cursor=YWJjZGVm==")).is_none(),
            "an ordinary query must be clean"
        );
    }

    #[test]
    fn the_signatures_catch_what_they_are_for() {
        let s = Signatures::new();
        for (path, rule) in [
            ("/files/../../etc/passwd", "web.traversal"),
            ("/wp-login.php", "web.secret-probe"),
            ("/.env", "web.secret-probe"),
            ("/search/<script>alert(1)</script>", "web.xss"),
        ] {
            let hit = s.scan(path, None);
            assert_eq!(
                hit.map(|(sig, _)| sig.rule),
                Some(rule),
                "{path} should match {rule}"
            );
        }
    }

    #[test]
    fn an_alert_becomes_a_record_app_obs_can_store() {
        let a = Alert {
            id: 7,
            ts: 1_700_000_000_000,
            last_ts: 1_700_000_000_000,
            rule: "auth.brute-force",
            severity: Severity::High,
            title: "1.2.3.4 is failing authentication repeatedly".into(),
            client: Some("1.2.3.4".into()),
            // Admin-plane: no deployment of its own.
            deployment: None,
            path: Some("/metrics".into()),
            technique: Some("T1110"),
            count: 9,
            ecs: None,
            bot: None,
        };
        let r = alert_record(&a, "_lb");
        assert_eq!(r.source, SECURITY_SOURCE);
        assert_eq!(r.level, "error");
        // app-obs rejects a record naming no deployment, taking the whole batch
        // with it, so the fallback is load-bearing.
        assert_eq!(r.deployment, "_lb");
    }

    /// The dashboard switches on these strings.
    #[test]
    fn severity_serializes_as_the_string_the_dashboard_switches_on() {
        for (sev, want) in [
            (Severity::Critical, "\"critical\""),
            (Severity::High, "\"high\""),
            (Severity::Medium, "\"medium\""),
            (Severity::Low, "\"low\""),
            (Severity::Info, "\"info\""),
        ] {
            assert_eq!(serde_json::to_string(&sev).unwrap(), want);
        }
    }

    #[test]
    fn a_ring_counter_slides_without_allocating() {
        let mut c = RingCounter::default();
        let now = 1_700_000_000_000;
        for i in 0..5 {
            c.record(now + i * 100, 60);
        }
        assert_eq!(c.total(), 5);
        // A full window later, everything has aged out.
        c.advance(now + 61_000, 60);
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn the_path_sketch_separates_a_wordlist_from_a_retry_loop() {
        let mut retry = 0u64;
        for _ in 0..500 {
            retry |= sketch_bit("/missing");
        }
        assert_eq!(retry.count_ones(), 1, "one path lights one bit");

        let mut walk = 0u64;
        for i in 0..500 {
            walk |= sketch_bit(&format!("/admin{i}"));
        }
        assert!(
            walk.count_ones() >= 8,
            "a wordlist must light many bits, got {}",
            walk.count_ones()
        );
    }

    #[test]
    fn a_scheme_is_read_without_decoding_the_credential() {
        assert_eq!(AuthScheme::of(Some("Basic aGk6dGhlcmU=")), AuthScheme::Basic);
        assert_eq!(AuthScheme::of(Some("bearer applb_x")), AuthScheme::Bearer);
        assert_eq!(AuthScheme::of(Some("weird")), AuthScheme::None);
        assert_eq!(AuthScheme::of(None), AuthScheme::None);
    }

    #[test]
    fn an_unparseable_peer_is_excluded_rather_than_given_a_key() {
        let stats = Arc::new(SiemStats::default());
        let (tx, mut rx) = mpsc::channel(4);
        let sink = SecuritySink {
            tx,
            stats,
            scan_query: false,
        };
        sink.observe_access(
            &Access {
                deployment: Some("demo"),
                backend: None,
                method: "GET",
                path: "/",
                host: None,
                status: Some(200),
                duration: StdDuration::from_millis(1),
                bytes: 0,
                // A unix-socket peer stringifies to a path.
                client: Some("/var/run/app.sock".into()),
                error: None,
            },
            None,
            None,
        );
        match rx.try_recv() {
            Ok(Observation::Access(a)) => assert!(a.client.is_none()),
            _ => panic!("expected an access observation"),
        }
    }

    #[test]
    fn scanning_the_query_is_off_when_configured_off() {
        let stats = Arc::new(SiemStats::default());
        let (tx, mut rx) = mpsc::channel(4);
        let sink = SecuritySink {
            tx,
            stats,
            scan_query: false,
        };
        sink.observe_access(
            &Access {
                deployment: Some("demo"),
                backend: None,
                method: "GET",
                path: "/",
                host: None,
                status: Some(200),
                duration: StdDuration::from_millis(1),
                bytes: 0,
                client: Some("1.2.3.4".into()),
                error: None,
            },
            Some("id=1' or '1'='1"),
            None,
        );
        match rx.try_recv() {
            Ok(Observation::Access(a)) => assert!(
                a.scan_query.is_none(),
                "the query must not be captured when scanning is off"
            ),
            _ => panic!("expected an access observation"),
        }
    }

    // -- automated traffic -------------------------------------------------

    mod bots {
        use super::*;
        use crate::guard::IpPrefix;

        const GPTBOT: &str = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)";
        const GPTBOT_RANGES: &str = "https://openai.com/gptbot.json";

        fn from(ua: &str, client: &str) -> Observation {
            let mut a = access("/docs", Some(200), client);
            a.user_agent = Some(Box::from(ua));
            Observation::Access(Box::new(a))
        }

        fn rules(alerts: &[Alert]) -> Vec<&'static str> {
            alerts.iter().map(|a| a.rule).collect()
        }

        #[test]
        fn a_browser_raises_nothing_and_is_not_counted() {
            let mut an = Analyzer::new(cfg());
            let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15";
            assert!(an.analyze(from(ua, "198.51.100.7"), 1_000).is_empty());
            assert!(an.bots.as_ref().unwrap().view(1_000).rows.is_empty());
        }

        #[test]
        fn an_ai_crawler_from_many_addresses_is_one_alert_on_its_deployment() {
            let mut an = Analyzer::new(cfg());
            let ring = AlertRing::new(&cfg(), Arc::new(SiemStats::default()));
            let mut shipped = 0;
            for i in 0..50 {
                for a in an.analyze(from(GPTBOT, &format!("20.171.207.{i}")), 1_000 + i) {
                    assert_eq!(a.rule, "bot.ai-crawler");
                    assert_eq!(a.severity, Severity::Info);
                    assert!(a.client.is_none(), "one crawler is many addresses");
                    let tag = a.bot.unwrap();
                    assert_eq!(
                        (tag.agent, tag.operator, tag.class),
                        ("GPTBot", "OpenAI", BotClass::AiCrawler)
                    );
                    assert_eq!(
                        tag.verification,
                        Verification::Claimed,
                        "ranges never loaded here"
                    );
                    shipped += ring.raise(a, 1_000 + i).is_some() as u32;
                }
            }
            assert_eq!(shipped, 1);
            assert_eq!(ring.recent(10)[0].count, 50);
            let rows = an.bots.as_ref().unwrap().view(2_000).rows;
            assert_eq!(rows.len(), 1);
            assert_eq!((rows[0].requests, rows[0].total), (50, 50));
            assert!(rows[0].sources > 1);
            let action = rows[0]
                .action
                .as_ref()
                .expect("a row offers the agent block");
            assert_eq!(action.kind, "block-agent");
            assert_eq!(
                action.rule.match_.user_agent_contains.as_deref(),
                Some("GPTBot")
            );
            assert_eq!(action.rule.match_.deployment.as_deref(), Some("demo"));
        }

        #[test]
        fn a_user_triggered_agent_is_its_own_finding() {
            let mut an = Analyzer::new(cfg());
            let ua = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot";
            assert_eq!(
                rules(&an.analyze(from(ua, "23.98.142.180"), 1_000)),
                ["bot.ai-agent"]
            );
        }

        #[test]
        fn a_search_engine_is_counted_but_not_alerted_on() {
            let mut an = Analyzer::new(cfg());
            let ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
            assert!(an.analyze(from(ua, "66.249.64.9"), 1_000).is_empty());
            let rows = an.bots.as_ref().unwrap().view(1_000).rows;
            assert_eq!(rows[0].bot.class, BotClass::SearchCrawler);
        }

        #[test]
        fn a_claim_from_outside_the_published_ranges_is_spoofed_and_inside_is_verified() {
            let mut an = Analyzer::new(cfg());
            an.bots.as_ref().unwrap().ranges.install(
                GPTBOT_RANGES,
                vec![IpPrefix::parse("20.171.207.0/24").unwrap()],
                1,
            );
            let inside = an.analyze(from(GPTBOT, "20.171.207.5"), 1_000);
            assert_eq!(rules(&inside), ["bot.ai-crawler"]);
            assert_eq!(inside[0].bot.unwrap().verification, Verification::Verified);

            let outside = an.analyze(from(GPTBOT, "198.51.100.7"), 1_001);
            assert_eq!(
                rules(&outside),
                ["bot.spoofed"],
                "a spoofer is not reported as the crawler"
            );
            assert_eq!(outside[0].client.as_deref(), Some("198.51.100.7"));
            assert_eq!(outside[0].technique, Some("T1036"));
            let ecs = outside[0].ecs.as_ref().unwrap();
            assert_eq!(ecs["heyo.bot.verification"], "spoofed");
            assert_eq!(ecs["user_agent.name"], "GPTBot");

            let rows = an.bots.as_ref().unwrap().view(1_002).rows;
            assert_eq!(rows.len(), 2, "verified and spoofed are separate rows");
            let spoofed = rows
                .iter()
                .find(|r| r.bot.verification == Verification::Spoofed)
                .unwrap();
            assert!(
                spoofed.action.is_none(),
                "blocking the token is not the answer to a spoofer"
            );
        }

        #[test]
        fn the_raw_user_agent_never_reaches_an_alert_or_a_record() {
            let mut an = Analyzer::new(cfg());
            let ua = format!("{GPTBOT} token=hunter2-SECRET");
            let alerts = an.analyze(from(&ua, "20.171.207.5"), 1_000);
            assert!(!alerts.is_empty());
            for a in &alerts {
                let wire = serde_json::to_string(a).unwrap();
                let record = serde_json::to_string(&alert_record(a, "lb")).unwrap();
                assert!(
                    !wire.contains("hunter2") && !record.contains("hunter2"),
                    "{wire}"
                );
            }
        }

        #[test]
        fn bot_sightings_cannot_crowd_an_attack_out_of_the_alert_budget() {
            let mut c = cfg();
            c.max_alerts_per_min = 2;
            let ring = AlertRing::new(&c, Arc::new(SiemStats::default()));
            let mut an = Analyzer::new(c.clone());
            for (i, ua) in ["GPTBot/1.0", "ClaudeBot/1.0", "CCBot/2.0", "Bytespider"]
                .iter()
                .enumerate()
            {
                for a in an.analyze(from(ua, "198.51.100.1"), 1_000 + i as i64) {
                    ring.raise(a, 1_000);
                }
            }
            let attack = an.analyze(
                Observation::Access(Box::new(access(
                    "/../../etc/passwd",
                    Some(404),
                    "203.0.113.9",
                ))),
                1_010,
            );
            assert_eq!(rules(&attack), ["web.traversal"]);
            assert!(
                ring.raise(attack[0].clone(), 1_010).is_some(),
                "the attack still gets an alert"
            );
        }

        #[test]
        fn the_traffic_table_is_bounded() {
            let board = BotBoard::new(3_600);
            for i in 0..MAX_BOT_ROWS {
                let key = BotKey {
                    deployment: Some(format!("d{i}").into()),
                    agent: 0,
                    verification: Verification::Claimed,
                };
                board.record(key, None, 1_000);
            }
            let extra = BotKey {
                deployment: Some("one-too-many".into()),
                agent: 0,
                verification: Verification::Claimed,
            };
            board.record(extra, None, 1_000);
            let (rows, at_capacity) = board.rows(1_000);
            assert_eq!(rows.len(), MAX_BOT_ROWS);
            assert!(at_capacity);
            board.prune(1_000 + 3_600_000);
            assert!(board.rows(1_000 + 3_600_000).0.is_empty());
        }

        #[test]
        fn off_means_off() {
            let mut c = cfg();
            c.bots = false;
            let mut an = Analyzer::new(c);
            assert!(an.analyze(from(GPTBOT, "20.171.207.5"), 1_000).is_empty());
        }
    }

    // -- response actions --------------------------------------------------

    mod response {
        use super::*;

        /// Every rule the analyzer can raise, so a new detection cannot ship
        /// without an answer to "and now what?".
        const EVERY_RULE: &[&str] = &[
            "web.traversal",
            "web.sqli",
            "web.xss",
            "web.rce",
            "web.secret-probe",
            "traffic.scanner",
            "traffic.rate-spike",
            "auth.signin-state",
            "auth.enumeration",
            "auth.spray",
            "auth.scope-denied",
            "auth.brute-force",
            "bot.spoofed",
            "bot.ai-crawler",
            "bot.ai-agent",
        ];

        fn alert(rule: &'static str, client: Option<&str>, path: Option<&str>) -> Alert {
            Alert {
                id: 7,
                ts: 1_700_000_000_000,
                last_ts: 1_700_000_000_000,
                rule,
                severity: Severity::High,
                title: "something happened".into(),
                client: client.map(str::to_string),
                deployment: Some("demo".into()),
                path: path.map(str::to_string),
                technique: None,
                count: 1,
                ecs: None,
                bot: rule.starts_with("bot.").then(|| {
                    BotTag::of(
                        crate::bots::agent("GPTBot").unwrap(),
                        Verification::Verified,
                    )
                }),
            }
        }

        /// An agent block is offered for a sighting, and it refuses exactly the
        /// agent on exactly that deployment.
        #[test]
        fn an_ai_crawler_finding_offers_a_block_that_stops_that_crawler_there() {
            let r = respond(&alert("bot.ai-crawler", None, None));
            let action = r
                .actions
                .iter()
                .find(|a| a.kind == "block-agent")
                .unwrap_or_else(|| panic!("no block-agent action: {r:?}"));
            let g = crate::guard::Guard::new("", true);
            g.insert(action.rule.clone(), 1_000).unwrap();
            let facts = |ua, deployment| crate::guard::RequestFacts {
                client: "20.171.207.5".parse().ok(),
                host: Some("demo.local"),
                path: "/",
                method: "GET",
                deployment: Some(deployment),
                user_agent: Some(ua),
            };
            let gptbot = "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)";
            assert!(matches!(
                g.decide(&facts(gptbot, "demo"), 1_001),
                crate::guard::Decision::Block(_)
            ));
            assert!(matches!(
                g.decide(&facts(gptbot, "other"), 1_001),
                crate::guard::Decision::Pass
            ));
            assert!(matches!(
                g.decide(&facts("Mozilla/5.0 Safari/605", "demo"), 1_001),
                crate::guard::Decision::Pass
            ));
            let agent = respond(&alert("bot.ai-agent", None, None));
            assert!(
                agent.caveat.is_some_and(|c| c.contains("person")),
                "{agent:?}"
            );
        }

        /// The load-bearing one. A button that posts a body the server refuses
        /// is worse than no button: it is discovered mid-incident, by someone
        /// who believed they had just blocked an attacker.
        #[test]
        fn every_suggested_rule_is_one_the_guard_accepts() {
            let g = crate::guard::Guard::new("", true);
            for rule in EVERY_RULE {
                let a = alert(rule, Some("203.0.113.9"), Some("/wp-login.php"));
                let r = respond(&a);
                for action in &r.actions {
                    g.insert(action.rule.clone(), 1_000).unwrap_or_else(|e| {
                        panic!("{rule} suggested a rule the guard refuses: {e}")
                    });
                }
            }
        }

        #[test]
        fn every_rule_has_something_to_say_including_one_that_does_not_exist_yet() {
            for rule in EVERY_RULE.iter().chain(std::iter::once(&"future.rule")) {
                let r = respond(&alert(rule, Some("203.0.113.9"), None));
                assert!(!r.investigate.is_empty(), "{rule} has no runbook");
            }
        }

        /// A block that never lifts is the failure this design expects: it
        /// outlives the attack and breaks somebody months later. Only the
        /// exemption is permanent, and deliberately.
        #[test]
        fn every_suggested_block_expires_and_only_the_exemption_does_not() {
            for rule in EVERY_RULE {
                for action in respond(&alert(rule, Some("203.0.113.9"), Some("/.env"))).actions {
                    let permanent = action.rule.expires_in_secs.is_none();
                    assert_eq!(
                        permanent,
                        action.kind == "exempt-client",
                        "{rule}/{} has the wrong lifetime",
                        action.kind
                    );
                }
            }
        }

        /// Blocking `/search` because a payload arrived in `?q=` takes a working
        /// feature offline to stop one probe. The path block is offered only
        /// when the path is itself what tripped the signature.
        #[test]
        fn a_path_block_is_offered_for_a_probe_path_and_not_for_an_ordinary_one() {
            let probe = respond(&alert("web.secret-probe", Some("203.0.113.9"), Some("/.env")));
            assert!(probe.actions.iter().any(|a| a.kind == "block-path"), "{probe:?}");

            let query_hit = respond(&alert("web.sqli", Some("203.0.113.9"), Some("/search")));
            assert!(
                !query_hit.actions.iter().any(|a| a.kind == "block-path"),
                "an ordinary endpoint must not be offered up for blocking: {query_hit:?}"
            );
            // The client block is still there — there is always something to do.
            assert!(query_hit.actions.iter().any(|a| a.kind == "block-client"));
        }

        /// The guard is not consulted on the admin listener, so an admin-plane
        /// brute force cannot be stopped from here. Saying so beats a button
        /// that looks like it worked.
        #[test]
        fn an_auth_finding_admits_that_a_rule_will_not_cover_the_admin_plane() {
            let r = respond(&alert("auth.brute-force", Some("198.51.100.7"), None));
            let caveat = r.caveat.expect("auth findings carry the admin-plane caveat");
            assert!(caveat.contains("admin"), "{caveat}");
        }

        /// Anything that is not an address app-lb parsed itself would be
        /// refused by the guard, so it is never offered as a rule.
        #[test]
        fn an_unattributed_finding_offers_no_client_rule() {
            for client in [None, Some("not-an-address")] {
                let r = respond(&alert("web.sqli", client, Some("/x")));
                assert!(
                    !r.actions.iter().any(|a| a.kind.contains("client")),
                    "{client:?} must not become a rule: {r:?}"
                );
                assert!(!r.investigate.is_empty(), "there is still advice");
            }
        }

        /// Serialized onto `/security`, so the console can post it back
        /// verbatim. A field renamed here silently breaks the buttons.
        #[test]
        fn a_suggested_rule_serializes_as_the_post_body_the_api_takes() {
            let r = respond(&alert("auth.brute-force", Some("203.0.113.9"), None));
            let body = serde_json::to_value(&r.actions[0].rule).unwrap();
            assert_eq!(body["action"], "block");
            assert_eq!(body["match"]["client"], "203.0.113.9");
            assert_eq!(body["expires_in_secs"], 3600);
            // And it round-trips back into the type the handler deserializes.
            let parsed: crate::guard::RuleSpec = serde_json::from_value(body).unwrap();
            crate::guard::Guard::new("", true).insert(parsed, 1_000).unwrap();
        }
    }
}
