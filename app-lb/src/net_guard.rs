//! Outbound URL vetting, for URLs a *tenant* writes and app-lb then calls.
//!
//! The alerting plugin posts webhooks to URLs a namespace administrator
//! configures. app-lb sits on the host's private network, next to the
//! daemon's API, every guest's tap address, the fleet database and — on a
//! cloud VM — the instance metadata service. A webhook URL is therefore a
//! server-side request forgery primitive unless every send is checked:
//!
//! - **Scheme.** `https` only, unless the operator opts into plain `http`.
//! - **Address.** The host is resolved and *every* address it resolves to is
//!   checked: loopback, RFC 1918, link-local (the metadata service at
//!   `169.254.169.254` among them), CGNAT `100.64/10`, IPv6 ULA `fc00::/7`,
//!   multicast, unspecified, and the IPv4-mapped / -compatible / NAT64 /
//!   6to4 spellings of any of those are refused. One bad answer refuses the
//!   whole name: a resolver that returns a public and a private address is
//!   exactly what a rebinding attack looks like.
//! - **Pinning.** The request is then made to the address that was vetted
//!   ([`client_for`] uses `ClientBuilder::resolve_to_addrs`), so a second
//!   lookup by the HTTP client cannot be answered differently. Redirects are
//!   off and so is any proxy from the environment, either of which would
//!   send the request somewhere that was never checked.
//!
//! The operator can relax the first two checks — for a receiver on the
//! private network, or a test — with `APP_LB_ALERTING_ALLOW_INSECURE` and
//! `APP_LB_ALERTING_ALLOW_PRIVATE`, or the alerting plugin's own
//! configuration, which outranks the environment. The cloud metadata
//! addresses, multicast, broadcast and the unspecified address stay refused
//! regardless: nothing legitimate receives a webhook there.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// What the operator allows beyond the defaults.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Policy {
    /// Plain `http://` URLs.
    pub allow_insecure: bool,
    /// Loopback, RFC 1918, link-local, CGNAT and ULA destinations.
    pub allow_private: bool,
}

pub const ALLOW_INSECURE_ENV: &str = "APP_LB_ALERTING_ALLOW_INSECURE";
pub const ALLOW_PRIVATE_ENV: &str = "APP_LB_ALERTING_ALLOW_PRIVATE";

impl Policy {
    /// The policy from configuration, falling back to the environment, then
    /// to the safe default — app-lb's precedence everywhere.
    pub fn resolve(allow_insecure: Option<bool>, allow_private: Option<bool>) -> Self {
        Self {
            allow_insecure: allow_insecure
                .unwrap_or_else(|| crate::obs::env_flag(ALLOW_INSECURE_ENV, false)),
            allow_private: allow_private
                .unwrap_or_else(|| crate::obs::env_flag(ALLOW_PRIVATE_ENV, false)),
        }
    }
}

/// Why an address is refused, or `None` for a public one. `policy` decides
/// whether the private ranges count; the always-refused ones do regardless.
pub fn refused(ip: IpAddr, policy: Policy) -> Option<&'static str> {
    let class = classify(ip)?;
    match class {
        Class::Always(why) => Some(why),
        Class::Private(why) => (!policy.allow_private).then_some(why),
    }
}

enum Class {
    /// Refused even with `allow_private`.
    Always(&'static str),
    /// Refused unless the operator allows private destinations.
    Private(&'static str),
}

fn classify(ip: IpAddr) -> Option<Class> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> Option<Class> {
    let o = ip.octets();
    if ip == Ipv4Addr::new(169, 254, 169, 254) || ip == Ipv4Addr::new(169, 254, 170, 2) {
        return Some(Class::Always("a cloud metadata address"));
    }
    if o[0] == 0 {
        return Some(Class::Always("an unspecified (0.0.0.0/8) address"));
    }
    if ip.is_broadcast() {
        return Some(Class::Always("the broadcast address"));
    }
    if ip.is_multicast() {
        return Some(Class::Always("a multicast address"));
    }
    if o[0] >= 240 {
        return Some(Class::Always("a reserved (240.0.0.0/4) address"));
    }
    if ip.is_loopback() {
        return Some(Class::Private("a loopback address"));
    }
    if ip.is_private() {
        return Some(Class::Private("a private (RFC 1918) address"));
    }
    if ip.is_link_local() {
        return Some(Class::Private("a link-local address"));
    }
    if o[0] == 100 && (o[1] & 0xc0) == 64 {
        return Some(Class::Private("a carrier-grade NAT (100.64.0.0/10) address"));
    }
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return Some(Class::Private("an IETF protocol (192.0.0.0/24) address"));
    }
    if o[0] == 198 && (o[1] & 0xfe) == 18 {
        return Some(Class::Private("a benchmarking (198.18.0.0/15) address"));
    }
    None
}

fn classify_v6(ip: Ipv6Addr) -> Option<Class> {
    let s = ip.segments();
    if ip.is_unspecified() {
        return Some(Class::Always("the unspecified address"));
    }
    if ip.is_multicast() {
        return Some(Class::Always("a multicast address"));
    }
    // AWS's IPv6 metadata endpoint.
    if s == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254] {
        return Some(Class::Always("a cloud metadata address"));
    }
    // An IPv4 address in IPv6 clothing is judged as the IPv4 address.
    if let Some(v4) = embedded_v4(ip) {
        return classify_v4(v4);
    }
    if ip.is_loopback() {
        return Some(Class::Private("a loopback address"));
    }
    if (s[0] & 0xfe00) == 0xfc00 {
        return Some(Class::Private("a unique local (fc00::/7) address"));
    }
    if (s[0] & 0xffc0) == 0xfe80 {
        return Some(Class::Private("a link-local address"));
    }
    if (s[0] & 0xffc0) == 0xfec0 {
        return Some(Class::Private("a site-local address"));
    }
    None
}

/// The IPv4 address inside an IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible
/// (`::a.b.c.d`), NAT64 (`64:ff9b::a.b.c.d`) or 6to4 (`2002:aabb:ccdd::`)
/// address. Any of them reaches the IPv4 host on a dual-stack box.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let tail = || Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    if s[..5] == [0, 0, 0, 0, 0] && (s[5] == 0xffff || (s[5] == 0 && !ip.is_loopback())) {
        return Some(tail());
    }
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(tail());
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8));
    }
    None
}

/// Check a URL's shape without touching DNS: scheme, a host, no credentials,
/// and — when the host is an IP literal — the address. For validating a
/// configuration; [`vet`] repeats all of it with DNS at every send.
pub fn check_syntax(raw: &str, policy: Policy) -> Result<url::Url, String> {
    if raw.len() > 2048 {
        return Err("the URL is longer than 2048 bytes".into());
    }
    let url = url::Url::parse(raw).map_err(|e| format!("{raw:?} is not a URL: {e}"))?;
    match url.scheme() {
        "https" => {}
        "http" if policy.allow_insecure => {}
        "http" => {
            return Err(format!(
                "{raw:?} is plain http; webhooks must use https (an operator can allow http with {ALLOW_INSECURE_ENV})"
            ));
        }
        other => return Err(format!("{raw:?}: scheme {other:?} is not http(s)")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "{raw:?} carries credentials; put a signing secret on the receiver instead"
        ));
    }
    match url.host() {
        None => return Err(format!("{raw:?} has no host")),
        Some(url::Host::Ipv4(ip)) => check_ip(IpAddr::V4(ip), policy)?,
        Some(url::Host::Ipv6(ip)) => check_ip(IpAddr::V6(ip), policy)?,
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            if !policy.allow_private
                && (d == "localhost" || d.ends_with(".localhost") || d.ends_with(".internal"))
            {
                return Err(format!(
                    "{raw:?} names a host-local name; webhooks must reach a public address \
                     (an operator can allow private ones with {ALLOW_PRIVATE_ENV})"
                ));
            }
        }
    }
    Ok(url)
}

fn check_ip(ip: IpAddr, policy: Policy) -> Result<(), String> {
    match refused(ip, policy) {
        None => Ok(()),
        Some(why) => Err(format!(
            "{ip} is {why}; webhooks must reach a public address{}",
            if matches!(classify(ip), Some(Class::Private(_))) {
                format!(" (an operator can allow private ones with {ALLOW_PRIVATE_ENV})")
            } else {
                String::new()
            }
        )),
    }
}

/// A URL that passed every check, with the addresses it may be reached at.
#[derive(Debug, Clone)]
pub struct Vetted {
    pub url: url::Url,
    /// `Some` for a domain name: the vetted addresses to pin it to.
    domain: Option<String>,
    pub addrs: Vec<SocketAddr>,
}

/// Check `raw` fully, resolving its host. Every resolved address must pass.
pub async fn vet(raw: &str, policy: Policy) -> Result<Vetted, String> {
    let url = check_syntax(raw, policy)?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("{raw:?} has no port"))?;
    match url.host() {
        Some(url::Host::Ipv4(ip)) => Ok(Vetted {
            addrs: vec![SocketAddr::new(IpAddr::V4(ip), port)],
            url,
            domain: None,
        }),
        Some(url::Host::Ipv6(ip)) => Ok(Vetted {
            addrs: vec![SocketAddr::new(IpAddr::V6(ip), port)],
            url,
            domain: None,
        }),
        Some(url::Host::Domain(d)) => {
            let domain = d.to_string();
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((domain.as_str(), port))
                .await
                .map_err(|e| format!("{domain} did not resolve: {e}"))?
                .collect();
            if addrs.is_empty() {
                return Err(format!("{domain} resolved to no addresses"));
            }
            for a in &addrs {
                check_ip(a.ip(), policy).map_err(|e| format!("{domain} resolves to {e}"))?;
            }
            Ok(Vetted {
                url,
                domain: Some(domain),
                addrs,
            })
        }
        None => Err(format!("{raw:?} has no host")),
    }
}

/// An HTTP client that can only reach `vetted`'s addresses: pinned DNS, no
/// redirects, no proxy, and a whole-request deadline.
pub fn client_for(vetted: &Vetted, timeout: Duration) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent("app-lb-alerting/1");
    if let Some(domain) = &vetted.domain {
        b = b.resolve_to_addrs(domain, &vetted.addrs);
    }
    b.build().map_err(|e| format!("building the HTTP client: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRICT: Policy = Policy {
        allow_insecure: false,
        allow_private: false,
    };
    const OPEN: Policy = Policy {
        allow_insecure: true,
        allow_private: true,
    };

    #[test]
    fn private_loopback_metadata_and_mapped_addresses_are_refused() {
        for ip in [
            "127.0.0.1",
            "127.8.9.10",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::10.0.0.1",
            "2002:7f00:1::",
            "2002:a9fe:a9fe::",
            "fd00:ec2::254",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(refused(ip, STRICT).is_some(), "{ip} should be refused");
        }
    }

    #[test]
    fn public_addresses_pass() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.1",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            "2002:0808:0808::",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(refused(ip, STRICT), None, "{ip} should pass");
        }
    }

    #[test]
    fn the_private_override_does_not_open_metadata_multicast_or_unspecified() {
        for ip in ["127.0.0.1", "10.0.0.1", "fd00::1", "::ffff:192.168.0.1"] {
            assert_eq!(refused(ip.parse().unwrap(), OPEN), None, "{ip}");
        }
        for ip in [
            "169.254.169.254",
            "::ffff:169.254.169.254",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "fd00:ec2::254",
        ] {
            assert!(refused(ip.parse().unwrap(), OPEN).is_some(), "{ip}");
        }
    }

    #[test]
    fn syntax_checks_scheme_credentials_and_literal_hosts() {
        assert!(check_syntax("https://hooks.example.com/x", STRICT).is_ok());
        assert!(check_syntax("http://hooks.example.com/x", STRICT).is_err());
        assert!(
            check_syntax(
                "http://hooks.example.com/x",
                Policy {
                    allow_insecure: true,
                    ..STRICT
                }
            )
            .is_ok()
        );
        assert!(check_syntax("ftp://hooks.example.com/x", OPEN).is_err());
        assert!(check_syntax("https://user:pw@hooks.example.com/x", STRICT).is_err());
        assert!(check_syntax("https://127.0.0.1/x", STRICT).is_err());
        assert!(check_syntax("https://[::ffff:10.0.0.1]/x", STRICT).is_err());
        assert!(check_syntax("https://169.254.169.254/latest", OPEN).is_err());
        assert!(check_syntax("https://localhost/x", STRICT).is_err());
        assert!(check_syntax("https://localhost/x", OPEN).is_ok());
        assert!(check_syntax("https://1.1.1.1/x", STRICT).is_ok());
        assert!(check_syntax("not a url", OPEN).is_err());
    }

    #[tokio::test]
    async fn vetting_resolves_and_pins_names() {
        // `localhost` resolves without a network, and only to loopback.
        let e = vet("https://localhost:9/x", STRICT).await.unwrap_err();
        assert!(e.contains("localhost") || e.contains("loopback"), "{e}");
        let v = vet("http://localhost:9/x", OPEN).await.unwrap();
        assert!(v.addrs.iter().all(|a| a.ip().is_loopback()));
        assert_eq!(v.domain.as_deref(), Some("localhost"));
        let v = vet("https://1.1.1.1/x", STRICT).await.unwrap();
        assert_eq!(v.addrs, vec!["1.1.1.1:443".parse().unwrap()]);
        assert!(v.domain.is_none());
    }

    #[test]
    fn configuration_outranks_the_environment() {
        assert!(Policy::resolve(Some(true), Some(true)).allow_insecure);
        assert!(!Policy::resolve(Some(false), Some(false)).allow_private);
    }
}
