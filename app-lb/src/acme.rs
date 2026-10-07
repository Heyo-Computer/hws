//! Automatic Let's Encrypt certificates for deployment hostnames.
//!
//! Runs as a pingora `BackgroundService` shaped like the
//! [`Autoscaler`](crate::autoscale::Autoscaler): a slow ticker for renewal
//! sweeps, plus a [`Notify`] the admin API nudges when a deployment is
//! registered, so a new hostname gets its certificate in seconds rather than at
//! the next tick.
//!
//! Validation is HTTP-01, answered by the proxy itself out of
//! [`ChallengeTable`] — see `proxy::request_filter`. That means **the plaintext
//! proxy listener must be reachable on port 80**, which is where Let's Encrypt
//! sends the validation request; there is no way to point it elsewhere.
//!
//! Two kinds of certificate are issued, over two different challenges:
//!
//! - **Per exact `host` route rule**, over HTTP-01. The default, and right for a
//!   handful of named services.
//! - **Per configured domain in `APP_LB_ACME_WILDCARD`**, over DNS-01, covering
//!   `<domain>` and `*.<domain>`. Required for anything at fleet scale: Let's
//!   Encrypt allows 50 certificates per registered domain per week, so a
//!   thousand sandbox hostnames cannot each have their own. Publishing the
//!   challenge record is [`crate::dns`]'s job.
//!
//! Hosts a configured wildcard covers are **excluded** from per-host issuance —
//! that exclusion is the whole point, and without it the first sweep of a large
//! fleet would exhaust the account's weekly quota.
//!
//! A `host_suffix` rule still gets no certificate of its own; it names a subtree,
//! and the certificate for a subtree is the wildcard. One that no configured
//! wildcard covers is warned about once and served the static fallback.

use crate::deployment::now_secs;
use crate::registry::Registry;
use crate::tls::CertStore;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

/// How often to sweep for certificates approaching expiry. Renewal starts 30
/// days out (`tls::RENEW_BEFORE_DAYS`), so twice a day leaves an enormous margin
/// while keeping the CA traffic negligible.
const TICK: Duration = Duration::from_secs(12 * 60 * 60);

/// First retry delay after a failed issuance, doubling up to [`BACKOFF_MAX`].
/// Let's Encrypt's failed-validation limit is low enough that a tight retry loop
/// gets the account throttled for an hour, which would block *every* hostname —
/// so backoff here protects the deployments that are working, not just this one.
const BACKOFF_START: Duration = Duration::from_secs(60);
const BACKOFF_MAX: Duration = Duration::from_secs(6 * 60 * 60);

/// How long to wait for the CA to validate a challenge and issue. The library
/// default (30s) is tight for HTTP-01 under load.
const POLL: RetryPolicy = RetryPolicy::new().timeout(Duration::from_secs(120));

/// Live HTTP-01 challenge responses, keyed by token.
///
/// Written by the ACME manager, read by the proxy on every request that hits
/// `/.well-known/acme-challenge/`. `ArcSwap` for the same reason the registry
/// uses one: reads are on the request path, writes happen a few times a year.
#[derive(Default)]
pub struct ChallengeTable(ArcSwap<HashMap<String, String>>);

impl ChallengeTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// The key authorization to serve for `token`, if one is outstanding.
    pub fn get(&self, token: &str) -> Option<String> {
        self.0.load().get(token).cloned()
    }

    pub(crate) fn publish(&self, token: String, key_authorization: String) {
        self.0.rcu(|current| {
            let mut next = HashMap::clone(current);
            next.insert(token.clone(), key_authorization.clone());
            next
        });
    }

    /// Retract tokens once the order is done. Left in place they would be a
    /// small, permanent, publicly-readable leak of past challenge responses.
    fn retract(&self, tokens: &[String]) {
        if tokens.is_empty() {
            return;
        }
        self.0.rcu(|current| {
            let mut next = HashMap::clone(current);
            for token in tokens {
                next.remove(token);
            }
            next
        });
    }
}

#[derive(Debug)]
pub enum AcmeError {
    Acme(instant_acme::Error),
    Cert(crate::tls::CertError),
    Io(std::io::Error),
    /// The CA offered no HTTP-01 challenge for an authorization.
    NoHttp01,
    /// The CA offered no DNS-01 challenge for a wildcard authorization.
    NoDns01,
    /// A wildcard was asked for with no DNS provider configured.
    NoDnsProvider,
    /// Publishing or checking the challenge record failed.
    Dns(crate::dns::DnsError),
    /// The order finished in a state other than valid.
    Order(OrderStatus),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Acme(e) => write!(f, "{e}"),
            Self::Cert(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::NoHttp01 => write!(f, "CA offered no http-01 challenge"),
            Self::NoDns01 => write!(f, "CA offered no dns-01 challenge"),
            Self::NoDnsProvider => write!(
                f,
                "a wildcard certificate needs a DNS-01 challenge, and no DNS provider is \
                 configured — set APP_LB_ROUTE53_ZONE_ID"
            ),
            Self::Dns(e) => write!(f, "{e}"),
            Self::Order(s) => write!(f, "order ended in state {s:?}"),
        }
    }
}

impl From<instant_acme::Error> for AcmeError {
    fn from(e: instant_acme::Error) -> Self {
        Self::Acme(e)
    }
}

impl From<crate::tls::CertError> for AcmeError {
    fn from(e: crate::tls::CertError) -> Self {
        Self::Cert(e)
    }
}

impl From<std::io::Error> for AcmeError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Per-host retry state after a failure.
///
/// Wall-clock seconds rather than `Instant`, because this is persisted: a
/// monotonic clock is meaningless across a restart, and a restart resetting the
/// backoff is exactly the failure this guards against. A supervisor restart loop
/// with in-memory backoff re-attempts issuance on every boot and can exhaust the
/// CA's failed-validation budget in a couple of minutes.
#[derive(Clone, Serialize, Deserialize)]
struct Backoff {
    next_attempt_secs: u64,
    delay_secs: u64,
}

impl Backoff {
    /// `true` once the cooldown has passed.
    ///
    /// A `next_attempt` implausibly far in the future means the clock moved
    /// backwards since it was written (or the file was tampered with); treat
    /// that as expired rather than stranding the host forever.
    fn expired(&self, now: u64) -> bool {
        now >= self.next_attempt_secs
            || self.next_attempt_secs > now.saturating_add(BACKOFF_MAX.as_secs())
    }
}

pub struct AcmeConfig {
    /// Account contact address. Its presence is what enables ACME at all.
    pub email: String,
    /// Account key and issued certificates live here. Should be `0700`.
    pub dir: PathBuf,
    /// ACME directory URL. Point at Let's Encrypt *staging* for any testing —
    /// production rate limits are per-account-per-week and unforgiving.
    pub directory_url: String,
    /// The plaintext proxy address, used to confirm the listener is actually up
    /// before the first issuance. Not otherwise used.
    pub proxy_addr: String,
    /// Domains to cover with a wildcard certificate (`APP_LB_ACME_WILDCARD`).
    /// Each yields one certificate for `<domain>` **and** `*.<domain>`, issued
    /// over DNS-01.
    pub wildcards: Vec<String>,
    /// Route 53, for the DNS-01 challenge. `None` when no wildcards are
    /// configured — or when they are but the zone id is not, which is a
    /// misconfiguration `main` warns about at startup.
    pub dns: Option<crate::dns::Route53>,
}

impl AcmeConfig {
    pub fn production_directory() -> String {
        LetsEncrypt::Production.url().to_string()
    }
}

/// The file recording which ACME directory the cached state belongs to.
const DIRECTORY_STAMP: &str = "directory";

/// Discard cached ACME state when the configured directory URL changes.
///
/// Certificates and the account are directory-specific, and nothing in either
/// carries that association: an account restored from `account.json` reconnects
/// to the URL baked into *its* credentials, ignoring `APP_LB_ACME_DIRECTORY`
/// entirely (see `instant_acme::AccountBuilder::from_credentials`). So switching
/// from staging to production without clearing state silently keeps talking to
/// staging, and the still-valid staging certificate isn't due for renewal, so
/// nothing reissues. The result is untrusted certificates served indefinitely
/// with no error anywhere.
///
/// Runs before the cert store loads, so a stale certificate never reaches it.
/// Returns `true` if state was discarded.
///
/// A missing stamp means state predates this check; that is an upgrade, not a
/// change, so it is recorded rather than acted on — wiping a working production
/// setup on upgrade would be far worse than the problem being solved.
pub fn reset_if_directory_changed(dir: &Path, directory_url: &str) -> bool {
    let stamp = dir.join(DIRECTORY_STAMP);
    let previous = std::fs::read_to_string(&stamp).ok();
    let previous = previous.as_deref().map(str::trim);

    let changed = match previous {
        Some(prev) if prev == directory_url => false,
        Some(prev) => {
            tracing::warn!(
                from = %prev,
                to = %directory_url,
                "ACME directory changed; discarding the cached account and every \
                 certificate issued by the previous directory (they would otherwise \
                 be served until expiry, and the saved account would keep talking to \
                 the old directory)",
            );
            for path in [dir.join("account.json"), dir.join("backoff.json")] {
                if let Err(e) = std::fs::remove_file(&path)
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    tracing::error!(path = %path.display(), error = %e, "could not remove stale ACME state");
                }
            }
            if let Err(e) = std::fs::remove_dir_all(dir.join("certs"))
                && e.kind() != std::io::ErrorKind::NotFound
            {
                tracing::error!(error = %e, "could not remove stale certificates");
            }
            true
        }
        None => false, // first run, or an upgrade from before the stamp existed
    };

    if previous.is_none_or(|prev| prev != directory_url)
        && let Err(e) =
            crate::tls::create_dir_private(dir).and_then(|()| std::fs::write(&stamp, directory_url))
    {
        tracing::error!(error = %e, "could not record the ACME directory; a future \
                                     change to it will not be detected");
    }
    changed
}

/// Wait until the plaintext proxy is accepting connections, up to `timeout`.
///
/// ACME starts before the proxy service binds, so without this the first sweep
/// can publish challenges and tell the CA they are ready while nothing is
/// listening — spending the failed-validation budget on a listener that may
/// never come up. Returns `false` on timeout, in which case issuance is skipped
/// rather than attempted blind.
async fn wait_for_proxy(addr: &str, timeout: Duration) -> bool {
    // Probe loopback on the configured port: the listener is typically bound to
    // 0.0.0.0, which is not itself a connectable address on every platform.
    let port = match addr.rsplit_once(':') {
        Some((_, port)) => port,
        None => {
            tracing::warn!(addr, "could not parse a port from the proxy address");
            return false;
        }
    };
    let target = format!("127.0.0.1:{port}");

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(&target).await.is_ok() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// How long to wait for the proxy at startup before giving up on the first
/// sweep. Generous: the cost of waiting is a delayed certificate, the cost of
/// not waiting is a wasted validation attempt.
const PROXY_WAIT: Duration = Duration::from_secs(30);

pub struct AcmeManager {
    registry: Arc<Registry>,
    certs: Arc<CertStore>,
    challenges: Arc<ChallengeTable>,
    config: AcmeConfig,
    /// Nudged by the admin API when a deployment is registered or updated.
    signal: Arc<Notify>,
    /// Built lazily on first use, so a configured-but-idle app-lb never talks to
    /// the CA. `tokio` mutex because construction is async.
    account: tokio::sync::Mutex<Option<Arc<Account>>>,
    backoff: Mutex<HashMap<String, Backoff>>,
    /// Hostnames already warned about as unsupported, so the wildcard warning
    /// doesn't repeat on every sweep.
    warned: Mutex<HashSet<String>>,
}

impl AcmeManager {
    pub fn new(
        registry: Arc<Registry>,
        certs: Arc<CertStore>,
        challenges: Arc<ChallengeTable>,
        config: AcmeConfig,
    ) -> Self {
        Self {
            registry,
            certs,
            challenges,
            signal: Arc::new(Notify::new()),
            account: tokio::sync::Mutex::new(None),
            backoff: Mutex::new(Self::load_backoff(&config.dir)),
            warned: Mutex::new(HashSet::new()),
            config,
        }
    }

    /// Handle the admin API uses to ask for an immediate sweep.
    pub fn signal(&self) -> Arc<Notify> {
        self.signal.clone()
    }

    fn account_path(&self) -> PathBuf {
        self.config.dir.join("account.json")
    }

    /// Load the saved ACME account, or register a new one and save it.
    ///
    /// Reusing the account matters: a new account per restart would burn through
    /// the new-registrations rate limit and lose the CA-side validation cache
    /// that lets a re-issue skip the challenge entirely.
    async fn account(&self) -> Result<Arc<Account>, AcmeError> {
        let mut guard = self.account.lock().await;
        if let Some(account) = guard.as_ref() {
            return Ok(account.clone());
        }

        let path = self.account_path();
        let account = match std::fs::read(&path) {
            Ok(bytes) => {
                let credentials: AccountCredentials = serde_json::from_slice(&bytes)
                    .map_err(|e| AcmeError::Io(std::io::Error::other(e)))?;
                tracing::info!(path = %path.display(), "restored ACME account");
                Account::builder()?.from_credentials(credentials).await?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let contact = format!("mailto:{}", self.config.email);
                let (account, credentials) = Account::builder()?
                    .create(
                        &NewAccount {
                            contact: &[contact.as_str()],
                            terms_of_service_agreed: true,
                            only_return_existing: false,
                        },
                        self.config.directory_url.clone(),
                        None,
                    )
                    .await?;

                let json = serde_json::to_vec_pretty(&credentials)
                    .map_err(|e| AcmeError::Io(std::io::Error::other(e)))?;
                save_secret(&path, &json)?;
                tracing::info!(path = %path.display(), "registered new ACME account");
                account
            }
            Err(e) => return Err(AcmeError::Io(e)),
        };

        let account = Arc::new(account);
        *guard = Some(account.clone());
        Ok(account)
    }

    /// Every hostname across all deployments that needs a certificate of its
    /// own, with the ones a configured wildcard already covers removed.
    ///
    /// That removal is what makes a fleet viable rather than merely wasteful: a
    /// thousand sandbox deployments each contribute an exact `host` rule, and
    /// without this the first sweep would queue a thousand orders and exhaust
    /// Let's Encrypt's 50-per-registered-domain-per-week limit before the
    /// twentieth.
    ///
    /// `host_suffix` rules still get no certificate of their own — they name a
    /// subtree, and a certificate for a subtree *is* the wildcard — but they are
    /// only warned about when no configured wildcard covers them.
    fn desired_hosts(&self) -> Vec<String> {
        let mut hosts = HashSet::new();
        let mut unsupported = Vec::new();

        for deployment in self.registry.deployments().values() {
            for rule in &deployment.spec.routes {
                if let Some(host) = &rule.host {
                    let host = host.trim().to_ascii_lowercase();
                    if self.covering_wildcard(&host).is_none() {
                        hosts.insert(host);
                    }
                }
                if let Some(suffix) = &rule.host_suffix {
                    let suffix = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
                    if self.covering_wildcard(&suffix).is_none() && !self.certifies(&suffix) {
                        unsupported.push((deployment.spec.id.clone(), suffix));
                    }
                }
            }
        }

        if let Ok(mut warned) = self.warned.lock() {
            for (id, suffix) in unsupported {
                if warned.insert(suffix.clone()) {
                    tracing::warn!(
                        deployment = %id,
                        host_suffix = %suffix,
                        "no ACME certificate: a wildcard hostname needs a wildcard \
                         certificate, which is issued over DNS-01 — add this domain to \
                         APP_LB_ACME_WILDCARD (with APP_LB_ROUTE53_ZONE_ID). Until then \
                         this deployment is served the static fallback certificate",
                    );
                }
            }
        }

        let mut hosts: Vec<_> = hosts.into_iter().filter(|h| !h.is_empty()).collect();
        hosts.sort();
        hosts
    }

    /// Whether `domain` is one of the domains we issue a wildcard for.
    fn certifies(&self, domain: &str) -> bool {
        self.config.wildcards.iter().any(|w| w == domain)
    }

    /// The configured wildcard covering `host`, if any.
    ///
    /// A wildcard covers exactly one label — `*.sb.example.com` matches
    /// `a.sb.example.com` but not `a.b.sb.example.com` — so this checks the
    /// immediate parent and nothing further up. Being generous here would skip
    /// issuing for a host the wildcard cannot actually serve, and the failure
    /// would only show up as a name mismatch at somebody's TLS handshake.
    fn covering_wildcard(&self, host: &str) -> Option<&String> {
        let parent = host.split_once('.')?.1;
        self.config.wildcards.iter().find(|w| *w == parent)
    }

    /// `true` if this host is not in a post-failure cooldown.
    fn may_attempt(&self, host: &str) -> bool {
        let Ok(backoff) = self.backoff.lock() else {
            return true;
        };
        let now = now_secs();
        backoff.get(host).is_none_or(|b| b.expired(now))
    }

    fn record_failure(&self, host: &str) {
        let Ok(mut backoff) = self.backoff.lock() else {
            return;
        };
        let entry = backoff.entry(host.to_string()).or_insert(Backoff {
            next_attempt_secs: 0,
            delay_secs: BACKOFF_START.as_secs(),
        });
        entry.next_attempt_secs = now_secs().saturating_add(entry.delay_secs);
        entry.delay_secs = (entry.delay_secs * 2).min(BACKOFF_MAX.as_secs());
        tracing::debug!(host, retry_in_secs = entry.delay_secs, "backing off");
        let snapshot = backoff.clone();
        drop(backoff);
        self.persist_backoff(&snapshot);
    }

    fn record_success(&self, host: &str) {
        let Ok(mut backoff) = self.backoff.lock() else {
            return;
        };
        if backoff.remove(host).is_none() {
            return; // nothing recorded; no need to rewrite the file
        }
        let snapshot = backoff.clone();
        drop(backoff);
        self.persist_backoff(&snapshot);
    }

    fn backoff_path(&self) -> PathBuf {
        self.config.dir.join("backoff.json")
    }

    /// Best-effort: losing the backoff file degrades to the old in-memory
    /// behaviour, which is worth a log line but not a failed issuance.
    fn persist_backoff(&self, backoff: &HashMap<String, Backoff>) {
        let write = || -> std::io::Result<()> {
            crate::tls::create_dir_private(&self.config.dir)?;
            let json = serde_json::to_vec_pretty(backoff)?;
            let path = self.backoff_path();
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, json)?;
            std::fs::rename(&tmp, &path)
        };
        if let Err(e) = write() {
            tracing::warn!(error = %e, "could not persist ACME backoff state");
        }
    }

    /// Restore the cooldowns a previous run recorded. A missing or unreadable
    /// file is a normal first run.
    fn load_backoff(dir: &Path) -> HashMap<String, Backoff> {
        let path = dir.join("backoff.json");
        let Ok(bytes) = std::fs::read(&path) else {
            return HashMap::new();
        };
        match serde_json::from_slice(&bytes) {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!(error = %e, "ignoring unreadable ACME backoff state");
                HashMap::new()
            }
        }
    }

    /// Issue or renew every hostname that needs it, one at a time.
    ///
    /// Sequential on purpose: orders against one account share rate limits, and
    /// a burst of parallel orders is the fastest way to get throttled.
    async fn reconcile(&self) {
        // Wildcards first and unconditionally: they are configured, not derived
        // from what is registered, so one has to be issued before the first
        // sandbox that needs it exists — otherwise the first request to a new
        // hostname is served the fallback certificate.
        let wildcards: Vec<String> = self
            .certs
            .needing_renewal(self.config.wildcards.iter().map(String::as_str))
            .into_iter()
            .filter(|d| self.may_attempt(d))
            .collect();

        let wanted = self.desired_hosts();
        let due: Vec<String> = self
            .certs
            .needing_renewal(wanted.iter().map(String::as_str))
            .into_iter()
            .filter(|h| self.may_attempt(h))
            .collect();

        if due.is_empty() && wildcards.is_empty() {
            return;
        }

        let account = match self.account().await {
            Ok(a) => a,
            Err(e) => {
                // Every host is blocked by this, so back them all off rather
                // than hammering a CA that just refused us.
                tracing::error!(error = %e, "could not obtain ACME account; deferring issuance");
                for host in due.iter().chain(wildcards.iter()) {
                    self.record_failure(host);
                }
                return;
            }
        };

        for domain in wildcards {
            tracing::info!(domain = %domain, "issuing a wildcard certificate");
            match self.issue_wildcard(&account, &domain).await {
                Ok(()) => {
                    tracing::info!(domain = %domain, "wildcard certificate installed");
                    self.record_success(&domain);
                }
                Err(e) => {
                    tracing::error!(domain = %domain, error = %e, "wildcard issuance failed");
                    self.record_failure(&domain);
                }
            }
        }

        if due.is_empty() {
            return;
        }
        tracing::info!(count = due.len(), "issuing certificates");
        for host in due {
            match self.issue(&account, &host).await {
                Ok(()) => {
                    tracing::info!(host = %host, "certificate installed");
                    self.record_success(&host);
                }
                Err(e) => {
                    tracing::error!(host = %host, error = %e, "certificate issuance failed");
                    self.record_failure(&host);
                }
            }
        }
    }

    /// Run one wildcard order end to end, over DNS-01, and install the result.
    ///
    /// The certificate covers `domain` **and** `*.domain`, ordered together
    /// because they are both wanted and one order is one rate-limit unit. Both
    /// authorizations resolve to the same challenge record —
    /// `_acme-challenge.<domain>` — so their digests are published as two values
    /// of one TXT RRset, not two records that would overwrite each other.
    ///
    /// Stored under the bare `domain`. `CertStore::lookup` finds it from any
    /// subdomain by checking the parent, and serves it only because the
    /// certificate itself carries the `*.` SAN.
    async fn issue_wildcard(&self, account: &Account, domain: &str) -> Result<(), AcmeError> {
        let Some(dns) = self.config.dns.as_ref() else {
            return Err(AcmeError::NoDnsProvider);
        };

        let identifiers = [
            Identifier::Dns(domain.to_string()),
            Identifier::Dns(format!("*.{domain}")),
        ];
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

        // Two passes over the authorizations, and that is the point. Every
        // digest has to be *published* before any challenge is marked ready:
        // both authorizations answer at the same name, so a per-authorization
        // publish would have the second UPSERT replace the first and whichever
        // the CA checked second would fail. A challenge handle borrows the
        // order, so collecting them all and publishing in between is not an
        // option — hence collect, publish, then walk them again to mark ready.
        let mut digests = Vec::new();
        {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization = authorization?;
                // The CA caches successful validations; a re-issue inside that
                // window arrives already valid with nothing to answer.
                if authorization.status == AuthorizationStatus::Valid {
                    continue;
                }
                let Some(challenge) = authorization.challenge(ChallengeType::Dns01) else {
                    return Err(AcmeError::NoDns01);
                };
                digests.push(challenge.key_authorization().dns_value());
            }
        }

        if digests.is_empty() {
            // Everything was already valid — nothing to publish, straight to
            // finalization.
            return self.finish_order(&mut order, domain).await;
        }
        digests.sort();
        digests.dedup();

        tracing::info!(
            domain = %domain,
            values = digests.len(),
            "publishing the DNS-01 challenge and waiting for it to become answerable",
        );
        dns.publish_challenge(domain, &digests)
            .await
            .map_err(AcmeError::Dns)?;

        // Everything past here must retract the record, so the result is held
        // rather than propagated with `?`.
        let result = async {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization = authorization?;
                if authorization.status == AuthorizationStatus::Valid {
                    continue;
                }
                if let Some(mut challenge) = authorization.challenge(ChallengeType::Dns01) {
                    challenge.set_ready().await?;
                }
            }
            Ok(())
        }
        .await;

        let result = match result {
            Ok(()) => self.finish_order(&mut order, domain).await,
            Err(e) => Err(e),
        };
        dns.retract_challenge(domain, &digests).await;
        result
    }

    /// Run one HTTP-01 order end to end and install the result.
    async fn issue(&self, account: &Account, host: &str) -> Result<(), AcmeError> {
        let identifiers = [Identifier::Dns(host.to_string())];
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

        // Publish each challenge response before telling the CA it's ready,
        // otherwise validation races the proxy and fails.
        let mut tokens = Vec::new();
        let published = async {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization = authorization?;
                // The CA caches successful validations; a re-issue inside that
                // window arrives already valid with nothing to answer.
                if authorization.status == AuthorizationStatus::Valid {
                    continue;
                }

                let Some(mut challenge) = authorization.challenge(ChallengeType::Http01) else {
                    return Err(AcmeError::NoHttp01);
                };
                let token = challenge.token.clone();
                self.challenges
                    .publish(token.clone(), challenge.key_authorization().as_str().to_string());
                tokens.push(token);
                challenge.set_ready().await?;
            }
            Ok(())
        }
        .await;

        // From here every exit path must retract the tokens, so the result is
        // held rather than propagated with `?`.
        let result = match published {
            Ok(()) => self.finish_order(&mut order, host).await,
            Err(e) => Err(e),
        };
        self.challenges.retract(&tokens);
        result
    }

    /// Wait for validation, finalize, and install the issued chain.
    async fn finish_order(
        &self,
        order: &mut instant_acme::Order,
        host: &str,
    ) -> Result<(), AcmeError> {
        let status = order.poll_ready(&POLL).await?;
        if status != OrderStatus::Ready {
            return Err(AcmeError::Order(status));
        }

        // `finalize` generates the keypair and CSR and hands back the private
        // key as PEM — the only copy, so it goes straight to the store.
        let key_pem = order.finalize().await?;
        let chain_pem = order.poll_certificate(&POLL).await?;

        self.certs
            .insert(host, chain_pem.as_bytes(), key_pem.as_bytes())?;
        Ok(())
    }
}

/// Write a secret with a restrictive mode, via a temp file so a crash can't
/// leave a half-written key behind.
fn save_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        crate::tls::create_dir_private(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    crate::tls::restrict(&tmp)?;
    std::fs::rename(&tmp, path)
}

#[async_trait]
impl BackgroundService for AcmeManager {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        tracing::info!(
            directory = %self.config.directory_url,
            dir = %self.config.dir.display(),
            "ACME enabled",
        );

        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Issue for anything already registered (restored from persisted state)
        // without waiting out the first tick — but only once the proxy is
        // actually accepting, since it answers the http-01 challenge and this
        // service starts before it binds.
        if wait_for_proxy(&self.config.proxy_addr, PROXY_WAIT).await {
            self.reconcile().await;
        } else {
            tracing::error!(
                proxy = %self.config.proxy_addr,
                timeout_secs = PROXY_WAIT.as_secs(),
                "proxy is not accepting connections; skipping the startup certificate \
                 sweep rather than failing http-01 validation against a listener that \
                 is not there. Check for a bind failure in the error log.",
            );
        }

        loop {
            tokio::select! {
                _ = ticker.tick() => self.reconcile().await,
                _ = self.signal.notified() => self.reconcile().await,
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("ACME manager shutting down");
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeploymentSpec, RouteRule};

    fn registry_with(routes: Vec<RouteRule>) -> Arc<Registry> {
        let registry = Arc::new(Registry::new("/dev/null"));
        registry.upsert(DeploymentSpec {
            ingress: None,
            account_id: None,
            user_id: None,
            namespace: "default".into(),
            feed: None,
            id: "test".into(),
            routes,
            vm: None,
            scaling: Default::default(),
            maintenance: false,
            health: Default::default(),
            upstreams: vec!["127.0.0.1:8080".into()],
            discovery: None,
            gateway: None,
            build: None,
            artifact: None,
            site: None,
            update: None,
            auth: None,
        });
        registry
    }

    /// A per-test directory, since backoff state is now persisted and shared
    /// directories would let tests see each other's writes.
    fn tmpdir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("app-lb-acme-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn manager_in(dir: &Path, registry: Arc<Registry>) -> AcmeManager {
        manager_with_wildcards(dir, registry, Vec::new())
    }

    fn manager_with_wildcards(
        dir: &Path,
        registry: Arc<Registry>,
        wildcards: Vec<String>,
    ) -> AcmeManager {
        AcmeManager::new(
            registry,
            Arc::new(CertStore::new(dir.join("certs"), None)),
            Arc::new(ChallengeTable::new()),
            AcmeConfig {
                email: "test@example.com".into(),
                dir: dir.to_path_buf(),
                directory_url: LetsEncrypt::Staging.url().to_string(),
                proxy_addr: "127.0.0.1:0".into(),
                wildcards,
                // Never reached: these tests exercise which hosts are selected,
                // never an order.
                dns: None,
            },
        )
    }

    fn manager(tag: &str, registry: Arc<Registry>) -> AcmeManager {
        manager_in(&tmpdir(tag), registry)
    }

    /// The single most important consequence of configuring a wildcard: hosts
    /// it covers must stop being ordered individually. Let's Encrypt allows 50
    /// certificates per registered domain per week, so a fleet of a thousand
    /// sandboxes would exhaust the quota — and lock out every other hostname on
    /// the account — within the first sweep.
    #[test]
    fn a_wildcard_suppresses_per_host_issuance_underneath_it() {
        let dir = tmpdir("wildcard-suppress");
        let registry = registry_with(vec![
            RouteRule {
                host: Some("sb-1.sb.example.com".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
                redirect: None,
            },
            RouteRule {
                host: Some("sb-2.sb.example.com".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
                redirect: None,
            },
            // A different domain: not covered, so it still gets its own.
            RouteRule {
                host: Some("web.example.com".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
                redirect: None,
            },
        ]);
        let manager = manager_with_wildcards(&dir, registry, vec!["sb.example.com".into()]);

        assert_eq!(
            manager.desired_hosts(),
            vec!["web.example.com".to_string()],
            "only the host no wildcard covers",
        );
    }

    /// A wildcard covers exactly one label. Treating it as covering the whole
    /// subtree would skip issuing for a host the certificate cannot serve, and
    /// the only symptom would be a name mismatch at somebody's handshake.
    #[test]
    fn a_wildcard_covers_one_label_and_no_more() {
        let dir = tmpdir("wildcard-depth");
        let registry = registry_with(vec![
            RouteRule {
                host: Some("a.sb.example.com".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
                redirect: None,
            },
            RouteRule {
                host: Some("a.b.sb.example.com".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
                redirect: None,
            },
        ]);
        let manager = manager_with_wildcards(&dir, registry, vec!["sb.example.com".into()]);

        assert_eq!(
            manager.desired_hosts(),
            vec!["a.b.sb.example.com".to_string()],
            "the two-label-deep host is not covered and still needs its own cert",
        );
    }

    /// A `host_suffix` route is exactly what a wildcard is for, so configuring
    /// one must silence the "no certificate for this" warning rather than
    /// leaving an operator to wonder whether it took effect.
    #[test]
    fn a_configured_wildcard_is_not_warned_about() {
        let dir = tmpdir("wildcard-warn");
        let registry = registry_with(vec![RouteRule {
            host: None,
            host_suffix: Some("sb.example.com".into()),
            path_prefix: None,
            strip_prefix: false,
            redirect: None,
        }]);
        let manager = manager_with_wildcards(&dir, registry, vec!["sb.example.com".into()]);

        assert!(manager.desired_hosts().is_empty());
        assert!(
            manager.warned.lock().unwrap().is_empty(),
            "a covered suffix is served, not unsupported",
        );
    }

    #[test]
    fn desired_hosts_collects_exact_hosts_only() {
        let manager = manager("desired", registry_with(vec![
            RouteRule {
                host: Some("A.example.com".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
                redirect: None,
            },
            RouteRule {
                host: Some("b.example.com".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
                redirect: None,
            },
            // Wildcards need DNS-01; must not appear.
            RouteRule {
                host: None,
                host_suffix: Some("apps.example.com".into()),
                path_prefix: None,
                strip_prefix: false,
                redirect: None,
            },
            // Path-only routes have no hostname to certify.
            RouteRule {
                host: None,
                host_suffix: None,
                path_prefix: Some("/api".into()),
                strip_prefix: false,
                redirect: None,
            },
        ]));

        assert_eq!(
            manager.desired_hosts(),
            vec!["a.example.com".to_string(), "b.example.com".to_string()],
            "lowercased, sorted, exact hosts only",
        );
    }

    #[test]
    fn wildcard_warning_is_logged_once_per_suffix() {
        let manager = manager("wildcard", registry_with(vec![RouteRule {
            host: None,
            host_suffix: Some("apps.example.com".into()),
            path_prefix: None,
            strip_prefix: false,
            redirect: None,
        }]));

        manager.desired_hosts();
        let warned_after_first = manager.warned.lock().unwrap().len();
        manager.desired_hosts();
        let warned_after_second = manager.warned.lock().unwrap().len();

        assert_eq!(warned_after_first, 1);
        assert_eq!(warned_after_second, 1, "the sweep must not re-warn");
    }

    #[test]
    fn challenge_table_publishes_and_retracts() {
        let table = ChallengeTable::new();
        assert_eq!(table.get("tok"), None);

        table.publish("tok".into(), "tok.thumbprint".into());
        assert_eq!(table.get("tok").as_deref(), Some("tok.thumbprint"));

        table.retract(&["tok".to_string()]);
        assert_eq!(table.get("tok"), None, "tokens must not outlive the order");
    }

    #[test]
    fn backoff_grows_and_clears_on_success() {
        let manager = manager("grows", registry_with(vec![]));
        assert!(manager.may_attempt("a.example.com"), "no history, no wait");

        manager.record_failure("a.example.com");
        assert!(!manager.may_attempt("a.example.com"), "cooling down");

        let first = manager.backoff.lock().unwrap()["a.example.com"].delay_secs;
        manager.record_failure("a.example.com");
        let second = manager.backoff.lock().unwrap()["a.example.com"].delay_secs;
        assert!(second > first, "delay must grow");

        manager.record_success("a.example.com");
        assert!(manager.may_attempt("a.example.com"), "success clears backoff");
        let _ = std::fs::remove_dir_all(&manager.config.dir);
    }

    #[test]
    fn backoff_is_capped() {
        let manager = manager("capped", registry_with(vec![]));
        for _ in 0..50 {
            manager.record_failure("a.example.com");
        }
        assert_eq!(
            manager.backoff.lock().unwrap()["a.example.com"].delay_secs,
            BACKOFF_MAX.as_secs(),
            "unbounded growth would strand a host forever",
        );
        let _ = std::fs::remove_dir_all(&manager.config.dir);
    }

    #[test]
    fn backoff_survives_a_restart() {
        // The whole point: a supervisor restart loop must not reset the
        // cooldown and re-attempt issuance on every boot.
        let dir = tmpdir("restart");
        {
            let manager = manager_in(&dir, registry_with(vec![]));
            manager.record_failure("a.example.com");
            manager.record_failure("a.example.com");
            assert!(!manager.may_attempt("a.example.com"));
        }

        // A fresh manager over the same directory is what a restart produces.
        let restarted = manager_in(&dir, registry_with(vec![]));
        assert!(
            !restarted.may_attempt("a.example.com"),
            "restart must not clear the cooldown",
        );
        assert_eq!(
            restarted.backoff.lock().unwrap()["a.example.com"].delay_secs,
            BACKOFF_START.as_secs() * 4,
            "the accumulated delay must survive too, not just the fact of a failure",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backoff_ignores_a_clock_that_moved_backwards() {
        let entry = Backoff {
            next_attempt_secs: 1_000_000,
            delay_secs: 60,
        };
        // Normal case: still cooling down.
        assert!(!entry.expired(999_000));
        // Cooldown elapsed.
        assert!(entry.expired(1_000_001));
        // "Now" is implausibly far behind the recorded time — a backwards clock
        // must not strand the host until that timestamp arrives for real.
        assert!(entry.expired(1));
    }

    #[test]
    fn changing_the_acme_directory_discards_cached_state() {
        let dir = tmpdir("dirchange");
        std::fs::create_dir_all(dir.join("certs")).unwrap();
        std::fs::write(dir.join("account.json"), b"{}").unwrap();
        std::fs::write(dir.join("backoff.json"), b"{}").unwrap();
        std::fs::write(dir.join("certs/demo.example.com.crt.pem"), b"cert").unwrap();

        // First call records the directory without touching anything: state that
        // predates the stamp is an upgrade, not a change.
        assert!(!reset_if_directory_changed(&dir, "https://staging.example/dir"));
        assert!(dir.join("account.json").exists(), "upgrade must not wipe");
        assert!(dir.join("certs/demo.example.com.crt.pem").exists());

        // Same directory again: still a no-op.
        assert!(!reset_if_directory_changed(&dir, "https://staging.example/dir"));
        assert!(dir.join("account.json").exists());

        // A different directory invalidates the account and every certificate.
        assert!(reset_if_directory_changed(&dir, "https://production.example/dir"));
        assert!(
            !dir.join("account.json").exists(),
            "a staging account would keep talking to staging",
        );
        assert!(!dir.join("backoff.json").exists());
        assert!(
            !dir.join("certs/demo.example.com.crt.pem").exists(),
            "a staging cert is valid for months and would never come up for renewal",
        );

        // The new directory is now the recorded one.
        assert!(!reset_if_directory_changed(&dir, "https://production.example/dir"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wait_for_proxy_detects_a_listening_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        assert!(
            wait_for_proxy(&addr, Duration::from_secs(2)).await,
            "a bound port must be detected",
        );
    }

    #[tokio::test]
    async fn wait_for_proxy_times_out_when_nothing_is_listening() {
        // Bind to claim a port, then drop it so nothing is accepting.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);

        assert!(
            !wait_for_proxy(&addr, Duration::from_millis(400)).await,
            "a dead listener must time out, so issuance is skipped rather than \
             validated against nothing",
        );
    }

    #[tokio::test]
    async fn wait_for_proxy_rejects_an_unparseable_address() {
        assert!(!wait_for_proxy("no-port-here", Duration::from_millis(100)).await);
    }
}
