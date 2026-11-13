//! Recognising automated clients: AI agents, AI labs' crawlers, search engines
//! and the long tail of scripts, scanners and link previewers.
//!
//! Two questions, answered separately because they have very different costs:
//!
//! * **What does it claim to be?** [`Classifier`] maps a `User-Agent` onto one
//!   [`Agent`] in the [`AGENTS`] catalog. A `User-Agent` is self-asserted, so
//!   this is a claim and nothing more.
//! * **Is the claim true?** [`RangeBook`] holds the IP ranges operators publish
//!   for their crawlers (OpenAI, Google, Bing, Apple, Perplexity). A claim from
//!   inside them is [`Verification::Verified`]; one from outside a list that has
//!   loaded is [`Verification::Spoofed`]. An operator that publishes nothing is
//!   [`Verification::Unverifiable`], and a list that has not loaded yet leaves
//!   the claim [`Verification::Claimed`] — missing data is never evidence of
//!   spoofing.
//!
//! Everything here runs on the SIEM engine's task, never on the request path.
//! Web Bot Auth (`Signature-Agent` HTTP message signatures) is not verified yet.

use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::guard::IpPrefix;

/// What kind of client an [`Agent`] is. Serialized kebab-case on `/security`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BotClass {
    /// Fetches a page because a person asked an assistant to (ChatGPT-User,
    /// Claude-User). Blocking it blocks that person.
    AiAgent,
    /// Collects pages to train models (GPTBot, ClaudeBot, CCBot).
    AiCrawler,
    /// Indexes pages for an AI search product (OAI-SearchBot, PerplexityBot).
    AiSearch,
    /// A conventional search engine (Googlebot, Bingbot).
    SearchCrawler,
    /// SEO and backlink crawlers (AhrefsBot, SemrushBot).
    Seo,
    /// Fetches a link to render a preview card (Slackbot, Twitterbot).
    Preview,
    /// Uptime and synthetic monitoring.
    Monitor,
    /// An HTTP library or headless browser with no bot identity of its own.
    Scripted,
    /// A vulnerability or internet-wide scanner.
    Scanner,
    /// Says it is a bot and matches nothing more specific.
    OtherBot,
}

impl BotClass {
    pub const ALL: [BotClass; 10] = [
        Self::AiAgent,
        Self::AiCrawler,
        Self::AiSearch,
        Self::SearchCrawler,
        Self::Seo,
        Self::Preview,
        Self::Monitor,
        Self::Scripted,
        Self::Scanner,
        Self::OtherBot,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AiAgent => "ai-agent",
            Self::AiCrawler => "ai-crawler",
            Self::AiSearch => "ai-search",
            Self::SearchCrawler => "search-crawler",
            Self::Seo => "seo",
            Self::Preview => "preview",
            Self::Monitor => "monitor",
            Self::Scripted => "scripted",
            Self::Scanner => "scanner",
            Self::OtherBot => "other-bot",
        }
    }

    /// Parse the `?class=` filter. Unknown values are `None`, read as "no
    /// filter", the same way an unknown `?severity=` is.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        Self::ALL
            .into_iter()
            .find(|c| c.as_str().eq_ignore_ascii_case(s))
    }
}

/// Whether a claimed identity checked out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verification {
    /// The client address is inside the operator's published ranges.
    Verified,
    /// The operator publishes ranges, but they have not loaded (yet, or the
    /// fetch is failing), or the client address is unknown.
    Claimed,
    /// The operator's ranges have loaded and the address is outside them.
    Spoofed,
    /// The operator publishes no machine-readable ranges.
    Unverifiable,
}

impl Verification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Claimed => "claimed",
            Self::Spoofed => "spoofed",
            Self::Unverifiable => "unverifiable",
        }
    }
}

/// One known client.
#[derive(Debug)]
pub struct Agent {
    /// The product token it sends, e.g. `GPTBot`. Also its display name.
    pub name: &'static str,
    pub operator: &'static str,
    pub class: BotClass,
    /// Case-insensitive substrings of the `User-Agent`. The first is the one a
    /// suggested guard rule matches on.
    pub tokens: &'static [&'static str],
    /// The operator's published range lists for this agent, if any.
    pub ranges: &'static [&'static str],
}

impl Agent {
    /// The substring a "block this agent" guard rule matches on. `None` for the
    /// generic catch-all, which has no token worth blocking on.
    pub fn guard_token(&self) -> Option<&'static str> {
        (self.class != BotClass::OtherBot).then(|| self.tokens[0])
    }
}

const OPENAI_GPTBOT: &str = "https://openai.com/gptbot.json";
const OPENAI_CHATGPT_USER: &str = "https://openai.com/chatgpt-user.json";
const OPENAI_SEARCHBOT: &str = "https://openai.com/searchbot.json";
const GOOGLEBOT: &str = "https://developers.google.com/static/search/apis/ipranges/googlebot.json";
const GOOGLE_SPECIAL: &str =
    "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json";
const BINGBOT: &str = "https://www.bing.com/toolbox/bingbot.json";
const APPLEBOT: &str = "https://search.developer.apple.com/applebot.json";
const PERPLEXITYBOT: &str = "https://www.perplexity.com/perplexitybot.json";
const PERPLEXITY_USER: &str = "https://www.perplexity.com/perplexity-user.json";

macro_rules! agent {
    ($name:literal, $op:literal, $class:ident) => {
        agent!($name, $op, $class, [$name], [])
    };
    ($name:literal, $op:literal, $class:ident, [$($tok:expr),+]) => {
        agent!($name, $op, $class, [$($tok),+], [])
    };
    ($name:literal, $op:literal, $class:ident, [$($tok:expr),+], [$($r:expr),*]) => {
        Agent { name: $name, operator: $op, class: BotClass::$class, tokens: &[$($tok),+], ranges: &[$($r),*] }
    };
}

/// The catalog. **Order is precedence**: the first entry whose token matches
/// wins, so specific identities come before generic ones and the catch-all is
/// last. Robots-only tokens (`Google-Extended`, `Applebot-Extended`) are absent
/// on purpose: they are read from robots.txt and never sent as a User-Agent.
pub static AGENTS: &[Agent] = &[
    // AI agents: user-triggered fetches.
    agent!(
        "ChatGPT-User",
        "OpenAI",
        AiAgent,
        ["ChatGPT-User"],
        [OPENAI_CHATGPT_USER]
    ),
    agent!("Claude-User", "Anthropic", AiAgent),
    agent!(
        "Perplexity-User",
        "Perplexity",
        AiAgent,
        ["Perplexity-User"],
        [PERPLEXITY_USER]
    ),
    agent!("MistralAI-User", "Mistral AI", AiAgent),
    agent!("DuckAssistBot", "DuckDuckGo", AiAgent),
    agent!(
        "Meta-ExternalFetcher",
        "Meta",
        AiAgent,
        ["meta-externalfetcher"]
    ),
    // AI search indexers.
    agent!(
        "OAI-SearchBot",
        "OpenAI",
        AiSearch,
        ["OAI-SearchBot"],
        [OPENAI_SEARCHBOT]
    ),
    agent!("Claude-SearchBot", "Anthropic", AiSearch),
    agent!(
        "PerplexityBot",
        "Perplexity",
        AiSearch,
        ["PerplexityBot"],
        [PERPLEXITYBOT]
    ),
    agent!("YouBot", "You.com", AiSearch),
    // AI training crawlers.
    agent!("GPTBot", "OpenAI", AiCrawler, ["GPTBot"], [OPENAI_GPTBOT]),
    agent!("ClaudeBot", "Anthropic", AiCrawler),
    agent!(
        "anthropic-ai",
        "Anthropic",
        AiCrawler,
        ["anthropic-ai", "Claude-Web"]
    ),
    agent!(
        "Google-CloudVertexBot",
        "Google",
        AiCrawler,
        ["Google-CloudVertexBot"],
        [GOOGLE_SPECIAL]
    ),
    agent!("CCBot", "Common Crawl", AiCrawler),
    agent!("Bytespider", "ByteDance", AiCrawler),
    agent!(
        "Meta-ExternalAgent",
        "Meta",
        AiCrawler,
        ["meta-externalagent"]
    ),
    agent!("FacebookBot", "Meta", AiCrawler),
    agent!("Amazonbot", "Amazon", AiCrawler),
    agent!("Applebot", "Apple", SearchCrawler, ["Applebot"], [APPLEBOT]),
    agent!(
        "cohere-ai",
        "Cohere",
        AiCrawler,
        ["cohere-ai", "cohere-training-data-crawler"]
    ),
    agent!("AI2Bot", "Allen Institute for AI", AiCrawler, ["AI2Bot"]),
    agent!("Diffbot", "Diffbot", AiCrawler),
    agent!("Timpibot", "Timpi", AiCrawler),
    agent!("ImagesiftBot", "ImageSift", AiCrawler),
    agent!("omgili", "Webz.io", AiCrawler, ["omgili"]),
    // Search engines.
    agent!(
        "Googlebot",
        "Google",
        SearchCrawler,
        ["Googlebot", "GoogleOther", "Google-InspectionTool"],
        [GOOGLEBOT]
    ),
    agent!(
        "bingbot",
        "Microsoft",
        SearchCrawler,
        ["bingbot", "BingPreview"],
        [BINGBOT]
    ),
    agent!("DuckDuckBot", "DuckDuckGo", SearchCrawler),
    agent!(
        "YandexBot",
        "Yandex",
        SearchCrawler,
        ["YandexBot", "YandexImages"]
    ),
    agent!("Baiduspider", "Baidu", SearchCrawler),
    agent!("PetalBot", "Huawei", SearchCrawler),
    // SEO.
    agent!("AhrefsBot", "Ahrefs", Seo),
    agent!("SemrushBot", "Semrush", Seo),
    agent!("MJ12bot", "Majestic", Seo),
    agent!("DotBot", "Moz", Seo),
    // Link previews.
    agent!("facebookexternalhit", "Meta", Preview),
    agent!("Twitterbot", "X", Preview),
    agent!("Slackbot", "Slack", Preview),
    agent!("Discordbot", "Discord", Preview),
    agent!("LinkedInBot", "LinkedIn", Preview),
    agent!("WhatsApp", "Meta", Preview, ["WhatsApp/"]),
    agent!("TelegramBot", "Telegram", Preview),
    // Monitoring.
    agent!("UptimeRobot", "UptimeRobot", Monitor),
    agent!("Pingdom", "SolarWinds", Monitor, ["Pingdom.com_bot"]),
    agent!(
        "Datadog Synthetics",
        "Datadog",
        Monitor,
        ["DatadogSynthetics", "Datadog/Synthetics"]
    ),
    agent!("StatusCake", "StatusCake", Monitor),
    agent!("kube-probe", "Kubernetes", Monitor, ["kube-probe/"]),
    // Scanners.
    agent!("Nuclei", "ProjectDiscovery", Scanner, ["Nuclei"]),
    agent!("sqlmap", "sqlmap", Scanner, ["sqlmap/"]),
    agent!("Nikto", "Nikto", Scanner),
    agent!("zgrab", "ZMap", Scanner),
    agent!("masscan", "masscan", Scanner),
    agent!("Nmap", "Nmap", Scanner, ["Nmap Scripting Engine"]),
    agent!("CensysInspect", "Censys", Scanner),
    agent!(
        "Expanse",
        "Palo Alto Networks",
        Scanner,
        ["Expanse, a Palo Alto Networks"]
    ),
    agent!("LeakIX", "LeakIX", Scanner, ["l9explore", "l9tcpid"]),
    // Scripted clients. After everything with a bot identity, which often
    // embeds a library name too.
    agent!(
        "HeadlessChrome",
        "headless browser",
        Scripted,
        ["HeadlessChrome/"]
    ),
    agent!("curl", "curl", Scripted, ["curl/"]),
    agent!("Wget", "GNU Wget", Scripted, ["Wget/"]),
    agent!("python-requests", "Python", Scripted, ["python-requests/"]),
    agent!("python-httpx", "Python", Scripted, ["python-httpx/"]),
    agent!("aiohttp", "Python", Scripted, ["aiohttp/"]),
    agent!("Python-urllib", "Python", Scripted, ["Python-urllib/"]),
    agent!("Scrapy", "Scrapy", Scripted, ["Scrapy/"]),
    agent!("Go-http-client", "Go", Scripted, ["Go-http-client/"]),
    agent!("node-fetch", "Node.js", Scripted, ["node-fetch"]),
    agent!("axios", "Node.js", Scripted, ["axios/"]),
    agent!("undici", "Node.js", Scripted, ["undici"]),
    agent!("okhttp", "OkHttp", Scripted, ["okhttp/"]),
    agent!("Java", "Java", Scripted, ["Java/"]),
    agent!("libwww-perl", "Perl", Scripted, ["libwww-perl/"]),
    // The catch-all. Its token is a regex, not a literal; see `Classifier::new`.
    Agent {
        name: "unidentified bot",
        operator: "unknown",
        class: BotClass::OtherBot,
        tokens: &[GENERIC_BOT],
        ranges: &[],
    },
];

/// A versioned bot token (`FooBot/1.2`), or a bot word followed by the
/// `+https://…` contact link the crawler convention puts in the UA. Narrow on
/// purpose: a bare `bot` substring matches phone models (`CUBOT_X30`).
const GENERIC_BOT: &str = r"(?i)(?:bot|crawler|spider|scraper)(?:/|[^)]*\+?https?://)";

/// Look an agent up by its catalog name.
pub fn agent(name: &str) -> Option<&'static Agent> {
    AGENTS.iter().find(|a| a.name == name)
}

/// Maps a `User-Agent` onto the catalog in one [`RegexSet`] pass.
pub struct Classifier {
    set: usiem::regex::RegexSet,
    /// Pattern index → agent index.
    owner: Vec<usize>,
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Classifier {
    pub fn new() -> Self {
        let mut patterns = Vec::new();
        let mut owner = Vec::new();
        for (i, a) in AGENTS.iter().enumerate() {
            for t in a.tokens {
                patterns.push(if a.class == BotClass::OtherBot {
                    (*t).to_string()
                } else {
                    format!("(?i){}", usiem::regex::escape(t))
                });
                owner.push(i);
            }
        }
        Self {
            set: usiem::regex::RegexSet::new(&patterns).expect("bot catalog patterns must compile"),
            owner,
        }
    }

    /// The highest-precedence agent this UA names, as an index into [`AGENTS`].
    pub fn classify(&self, user_agent: &str) -> Option<usize> {
        if user_agent.is_empty() {
            return None;
        }
        self.set
            .matches(user_agent)
            .into_iter()
            .map(|p| self.owner[p])
            .min()
    }
}

// -- published ranges -------------------------------------------------------

/// Ceiling on a range file. The largest (Google's) is tens of KB.
const MAX_RANGE_BYTES: usize = 4 << 20;
const MAX_PREFIXES: usize = 100_000;
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
/// How soon a failed fetch is retried.
const RETRY: Duration = Duration::from_secs(900);

#[derive(Debug, Default)]
struct RangeList {
    prefixes: Vec<IpPrefix>,
    /// Epoch millis of the last successful fetch. `0` until one succeeds.
    fetched_at: i64,
    error: Option<String>,
    checked_at: i64,
}

/// The ranges each operator publishes, keyed by URL.
#[derive(Debug, Default)]
pub struct RangeBook {
    lists: RwLock<HashMap<&'static str, RangeList>>,
}

/// One range list as `/security` reports it.
#[derive(Debug, Clone, Serialize)]
pub struct RangeStatus {
    pub url: &'static str,
    pub operator: &'static str,
    pub agents: Vec<&'static str>,
    pub loaded: bool,
    pub prefixes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Every distinct range URL in the catalog.
pub fn range_urls() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for a in AGENTS {
        for r in a.ranges {
            if !out.contains(r) {
                out.push(r);
            }
        }
    }
    out
}

impl RangeBook {
    /// Judge one claim. Only the claimed agent's lists are consulted.
    pub fn verify(&self, agent: &Agent, client: Option<IpAddr>) -> Verification {
        if agent.ranges.is_empty() {
            return Verification::Unverifiable;
        }
        let Some(ip) = client else {
            return Verification::Claimed;
        };
        let lists = self.lists.read().expect("range book lock");
        let mut all_loaded = true;
        for url in agent.ranges {
            match lists.get(url) {
                Some(l) if l.fetched_at > 0 => {
                    if l.prefixes.iter().any(|p| p.contains(ip)) {
                        return Verification::Verified;
                    }
                }
                _ => all_loaded = false,
            }
        }
        if all_loaded {
            Verification::Spoofed
        } else {
            Verification::Claimed
        }
    }

    /// Install a freshly fetched list.
    pub fn install(&self, url: &'static str, prefixes: Vec<IpPrefix>, now: i64) {
        let mut lists = self.lists.write().expect("range book lock");
        let l = lists.entry(url).or_default();
        l.prefixes = prefixes;
        l.fetched_at = now;
        l.checked_at = now;
        l.error = None;
    }

    /// Record a failed fetch. The last good copy stays in force: a list that
    /// worked yesterday is better evidence than none.
    pub fn failed(&self, url: &'static str, error: String, now: i64) {
        let mut lists = self.lists.write().expect("range book lock");
        let l = lists.entry(url).or_default();
        l.error = Some(error);
        l.checked_at = now;
    }

    pub fn status(&self) -> Vec<RangeStatus> {
        let lists = self.lists.read().expect("range book lock");
        range_urls()
            .into_iter()
            .map(|url| {
                let owners: Vec<&Agent> =
                    AGENTS.iter().filter(|a| a.ranges.contains(&url)).collect();
                let l = lists.get(url);
                RangeStatus {
                    url,
                    operator: owners.first().map(|a| a.operator).unwrap_or("unknown"),
                    agents: owners.iter().map(|a| a.name).collect(),
                    loaded: l.is_some_and(|l| l.fetched_at > 0),
                    prefixes: l.map_or(0, |l| l.prefixes.len()),
                    fetched_at: l.map(|l| l.fetched_at).filter(|t| *t > 0),
                    error: l.and_then(|l| l.error.clone()),
                }
            })
            .collect()
    }
}

/// Parse a published range file.
///
/// Every operator here uses the shape Google introduced,
/// `{"prefixes":[{"ipv4Prefix":"…"},{"ipv6Prefix":"…"}]}`, with small
/// variations in envelope. Rather than one adapter per file, collect every
/// string under a prefix-shaped key anywhere in the document. An empty result
/// is an error: installing it would mark every claim spoofed.
pub fn parse_ranges(body: &[u8]) -> Result<Vec<IpPrefix>, String> {
    const KEYS: &[&str] = &[
        "ipv4Prefix",
        "ipv6Prefix",
        "ipv4_prefix",
        "ipv6_prefix",
        "prefix",
        "ip_prefix",
        "cidr",
    ];
    fn walk(v: &serde_json::Value, key: Option<&str>, out: &mut Vec<IpPrefix>, bad: &mut usize) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, v) in m {
                    walk(v, Some(k), out, bad);
                }
            }
            serde_json::Value::Array(a) => {
                for v in a {
                    walk(v, key, out, bad);
                }
            }
            serde_json::Value::String(s) if key.is_some_and(|k| KEYS.contains(&k)) => {
                if out.len() >= MAX_PREFIXES {
                    return;
                }
                match IpPrefix::parse(s) {
                    Some(p) => out.push(p),
                    None => *bad += 1,
                }
            }
            _ => {}
        }
    }
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("not JSON: {e}"))?;
    let mut out = Vec::new();
    let mut bad = 0;
    walk(&v, None, &mut out, &mut bad);
    if out.is_empty() {
        return Err(if bad > 0 {
            format!("no parseable prefixes ({bad} unparseable)")
        } else {
            "no prefixes in the document".into()
        });
    }
    Ok(out)
}

async fn fetch(http: &reqwest::Client, url: &str) -> Result<Vec<IpPrefix>, String> {
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| format!("fetch failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    if resp
        .content_length()
        .is_some_and(|n| n as usize > MAX_RANGE_BYTES)
    {
        return Err("range file too large".into());
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| format!("read failed: {e}"))?;
    if body.len() > MAX_RANGE_BYTES {
        return Err("range file too large".into());
    }
    parse_ranges(&body)
}

/// Keep every list fresh: fetch all, then wait `every` (or [`RETRY`] if any
/// fetch failed) and do it again. Runs until the process exits.
pub async fn refresh(book: Arc<RangeBook>, every: Duration) {
    let http = match reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent(concat!(
            "app-lb/",
            env!("CARGO_PKG_VERSION"),
            " (bot range verification)"
        ))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "bot range verification is off: no HTTP client");
            return;
        }
    };
    loop {
        let mut failed = false;
        for url in range_urls() {
            let now = crate::obs::now_millis();
            match fetch(&http, url).await {
                Ok(prefixes) => {
                    tracing::debug!(url, prefixes = prefixes.len(), "bot ranges loaded");
                    book.install(url, prefixes, now);
                }
                Err(error) => {
                    failed = true;
                    tracing::warn!(url, %error, "could not refresh a bot range list; claims stay unverified");
                    book.failed(url, error, now);
                }
            }
        }
        tokio::time::sleep(if failed { RETRY.min(every) } else { every }).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(ua: &str) -> Option<&'static str> {
        Classifier::new().classify(ua).map(|i| AGENTS[i].name)
    }

    #[test]
    fn the_catalog_compiles_and_every_token_finds_its_entry_or_an_earlier_one() {
        let c = Classifier::new();
        for (i, a) in AGENTS.iter().enumerate() {
            if a.class == BotClass::OtherBot {
                continue;
            }
            for t in a.tokens {
                let got = c.classify(&format!("Mozilla/5.0 (compatible; {t}1.0)"));
                assert_eq!(
                    got,
                    Some(i),
                    "{t} is shadowed by {:?}",
                    got.map(|j| AGENTS[j].name)
                );
            }
        }
    }

    #[test]
    fn real_user_agents_land_where_they_should() {
        let cases = [
            (
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
                "GPTBot",
            ),
            (
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
                "ChatGPT-User",
            ),
            (
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
                "ClaudeBot",
            ),
            (
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)",
                "Claude-User",
            ),
            (
                "Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)",
                "OAI-SearchBot",
            ),
            (
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Googlebot",
            ),
            (
                "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
                "bingbot",
            ),
            ("CCBot/2.0 (https://commoncrawl.org/faq/)", "CCBot"),
            (
                "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
                "Meta-ExternalAgent",
            ),
            (
                "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
                "facebookexternalhit",
            ),
            (
                "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
                "Slackbot",
            ),
            ("curl/8.5.0", "curl"),
            ("python-requests/2.31.0", "python-requests"),
            (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
                "HeadlessChrome",
            ),
            (
                "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
                "Nmap",
            ),
            (
                "Mozilla/5.0 (compatible; FooCrawler/3.1; +https://foo.example/bot)",
                "unidentified bot",
            ),
        ];
        for (ua, want) in cases {
            assert_eq!(classify(ua), Some(want), "{ua}");
        }
    }

    #[test]
    fn browsers_and_phone_models_are_not_bots() {
        for ua in [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Linux; Android 10; CUBOT_X30) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Mobile Safari/537.36",
            "",
        ] {
            assert_eq!(classify(ua), None, "{ua}");
        }
    }

    #[test]
    fn a_class_parses_from_its_wire_name_and_nothing_else() {
        for c in BotClass::ALL {
            assert_eq!(BotClass::parse(c.as_str()), Some(c));
            assert_eq!(serde_json::to_value(c).unwrap(), c.as_str());
        }
        assert_eq!(BotClass::parse("robots"), None);
    }

    #[test]
    fn range_files_in_the_published_shapes_parse() {
        let google = br#"{"creationTime":"2026-11-01T00:00:00","prefixes":[{"ipv6Prefix":"2001:4860:4801:10::/64"},{"ipv4Prefix":"66.249.64.0/27"}]}"#;
        let p = parse_ranges(google).unwrap();
        assert_eq!(p.len(), 2);
        assert!(p[1].contains("66.249.64.9".parse().unwrap()));
        assert!(
            parse_ranges(br#"{"prefixes":[]}"#).is_err(),
            "empty must not install"
        );
        assert!(parse_ranges(b"<html>").is_err());
        assert!(parse_ranges(br#"{"prefixes":[{"ipv4Prefix":"nope"}]}"#).is_err());
    }

    #[test]
    fn verification_never_calls_missing_data_spoofing() {
        let book = RangeBook::default();
        let gptbot = agent("GPTBot").unwrap();
        let inside: IpAddr = "20.171.207.5".parse().unwrap();
        let outside: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(
            book.verify(gptbot, Some(outside)),
            Verification::Claimed,
            "not loaded yet"
        );
        book.failed(OPENAI_GPTBOT, "HTTP 503".into(), 1);
        assert_eq!(
            book.verify(gptbot, Some(outside)),
            Verification::Claimed,
            "fetch failing"
        );
        book.install(
            OPENAI_GPTBOT,
            vec![IpPrefix::parse("20.171.207.0/24").unwrap()],
            2,
        );
        assert_eq!(book.verify(gptbot, Some(inside)), Verification::Verified);
        assert_eq!(book.verify(gptbot, Some(outside)), Verification::Spoofed);
        assert_eq!(book.verify(gptbot, None), Verification::Claimed);
        // A later failure keeps the good list in force.
        book.failed(OPENAI_GPTBOT, "timeout".into(), 3);
        assert_eq!(book.verify(gptbot, Some(outside)), Verification::Spoofed);
        assert_eq!(
            book.verify(agent("ClaudeBot").unwrap(), Some(outside)),
            Verification::Unverifiable
        );
        let st = book
            .status()
            .into_iter()
            .find(|s| s.url == OPENAI_GPTBOT)
            .unwrap();
        assert!(st.loaded && st.prefixes == 1 && st.error.as_deref() == Some("timeout"));
    }

    #[test]
    fn every_range_url_is_https_and_every_token_is_blockable() {
        for url in range_urls() {
            assert!(url.starts_with("https://"), "{url}");
        }
        for a in AGENTS {
            if let Some(t) = a.guard_token() {
                assert!(!t.trim().is_empty() && t.len() <= 128, "{}", a.name);
            }
        }
    }
}
