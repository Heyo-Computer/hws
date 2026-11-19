//! The fleet hop (`docs/design/fleet-shared-state.md` § 5): a request that
//! reaches a host for a deployment placed on another is forwarded there, once.
//!
//! **The ingress host** runs every edge check it always runs — guard, gateway
//! admission, maintenance, the auth gate, redirects — against the fleet's copy
//! of the spec, so a refusal never costs a hop. Then, instead of picking a
//! local backend, it forwards over HTTPS to the home host's public address
//! (`APP_LB_FLEET_ADDRESS`), with the original `Host` as SNI: every host holds
//! every certificate, so the home host answers with the same one a client
//! would see. It adds:
//! - `x-heyo-fleet-hop: <this host>` and `x-heyo-fleet-token: <peer token>`;
//! - `X-Forwarded-For` (the client's address, replacing anything the client
//!   sent) and `X-Forwarded-Proto`.
//!
//! **The receiving host** admits the hop only with the fleet's peer token,
//! compared in constant time, and refuses a hop header without it. It takes
//! the client address from `X-Forwarded-For` for its guard and auth gate,
//! re-runs its own auth gate, strips `x-auth-request-*`, and serves only from
//! its own backends. It never forwards a hop again: a request for a deployment
//! it does not run answers 503, never a bounce.
//!
//! A hop is never replayed: once bytes may have reached the peer, a failure
//! is the client's. Forwarding is off unless `APP_LB_FLEET_FORWARD=1`;
//! accepting hops needs only fleet mode and the token.

use crate::fleet_sync::Fleet;
use arc_swap::ArcSwap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub const HOP: &str = "x-heyo-fleet-hop";
pub const TOKEN: &str = "x-heyo-fleet-token";
/// Beside `x-heyo-fleet-client` on a request this host's ingress passes to
/// its own admin listener: proof that the ingress, not the caller, named the
/// client ([`FleetHop::seal_client`]).
pub const CLIENT_SEAL: &str = "x-heyo-fleet-client-seal";
pub const FORWARD_ENV: &str = "APP_LB_FLEET_FORWARD";
pub const ADDRESS_ENV: &str = "APP_LB_FLEET_ADDRESS";
/// How a forwarded request names its backend: the home host picks the VM.
pub const BACKEND_PREFIX: &str = "fleet-hop:";
/// Peers' ingress: the public HTTPS listener.
const PEER_PORT: u16 = 443;

/// What a request's hop headers say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    /// Not a hop.
    None,
    /// A hop with the fleet's token.
    Valid {
        origin: String,
        /// The client, as the ingress host saw it.
        client: Option<IpAddr>,
    },
    /// A hop header without the token, or with the wrong one.
    Refused,
}

pub struct FleetHop {
    host: String,
    fleet: Arc<Fleet>,
    token: ArcSwap<Option<Arc<str>>>,
    forward: bool,
}

impl std::fmt::Debug for FleetHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the token.
        f.debug_struct("FleetHop")
            .field("host", &self.host)
            .field("forward", &self.forward)
            .finish_non_exhaustive()
    }
}

impl FleetHop {
    pub fn new(host: &str, fleet: Arc<Fleet>, forward: bool) -> Self {
        Self {
            host: host.to_string(),
            fleet,
            token: ArcSwap::from_pointee(None),
            forward,
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// Whether this host forwards requests for other hosts' deployments.
    pub fn forwards(&self) -> bool {
        self.forward
    }

    pub fn set_token(&self, token: Option<String>) {
        self.token.store(Arc::new(token.map(Arc::from)));
    }

    pub fn token(&self) -> Option<Arc<str>> {
        (**self.token.load()).clone()
    }

    /// The seal this host's ingress puts beside the client it names to its
    /// own admin listener: HMAC-SHA256 of the address under the peer token.
    ///
    /// The admin listener forwards that client to a peer as `X-Forwarded-For`,
    /// where it may meet IP-based gates. Anything reaching the admin listener
    /// some other way — a process on the host, a non-loopback admin address —
    /// could otherwise name any client it liked. Keyed by the peer token, not a
    /// per-process secret, because the ingress may run in a forwarding worker.
    pub fn seal_client(&self, client: &str) -> Option<String> {
        let token = self.token()?;
        Some(client_seal(token.as_bytes(), client))
    }

    /// The client a request's `x-heyo-fleet-client` names, if its seal is this
    /// fleet's for exactly that value.
    pub fn vouched_client<'a>(&self, headers: &'a http::HeaderMap) -> Option<&'a http::HeaderValue> {
        let client = headers.get(crate::fleet_admin::CLIENT)?;
        let presented = headers.get(CLIENT_SEAL)?.as_bytes();
        let expected = self.seal_client(client.to_str().ok()?)?;
        (presented.len() == expected.len() && openssl::memcmp::eq(presented, expected.as_bytes())).then_some(client)
    }
}

pub(crate) fn client_seal(key: &[u8], client: &str) -> String {
    use std::fmt::Write;
    let pkey = openssl::pkey::PKey::hmac(key).expect("an HMAC key from any bytes");
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).expect("an HMAC signer");
    signer.update(b"x-heyo-fleet-client\n").expect("hmac update");
    signer.update(client.as_bytes()).expect("hmac update");
    let mac = signer.sign_to_vec().expect("hmac");
    mac.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl FleetHop {
    pub fn inbound(&self, headers: &http::HeaderMap) -> Inbound {
        let Some(origin) = headers.get(HOP) else {
            return Inbound::None;
        };
        let Some(expected) = self.token() else {
            return Inbound::Refused;
        };
        let presented = headers.get(TOKEN).map(|v| v.as_bytes()).unwrap_or_default();
        if presented.len() != expected.len() || !openssl::memcmp::eq(presented, expected.as_bytes())
        {
            return Inbound::Refused;
        }
        Inbound::Valid {
            origin: origin.to_str().unwrap_or_default().to_string(),
            client: headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .and_then(|v| v.trim().parse().ok()),
        }
    }

    /// Where to reach `home`'s ingress, while it is a live member with an
    /// address.
    pub async fn address_of(&self, home: &str) -> Result<SocketAddr, &'static str> {
        let member = self
            .fleet
            .live_member(home)
            .ok_or("the deployment's home host is not a live fleet member")?;
        let address = member
            .address
            .ok_or("the deployment's home host takes no fleet hops (no APP_LB_FLEET_ADDRESS)")?;
        tokio::net::lookup_host((address.as_str(), PEER_PORT))
            .await
            .ok()
            .and_then(|mut a| a.next())
            .ok_or("the home host's address does not resolve")
    }
}

/// Generate a peer token: 32 random bytes, hex.
pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    openssl::rand::rand_bytes(&mut bytes).expect("entropy for a fleet peer token");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(token: Option<&str>) -> FleetHop {
        let pg = crate::fleet_pg::PgStore::open_in(
            "postgres://u@127.0.0.1:9/x",
            "us4",
            std::time::Duration::from_secs(1),
            "fleet",
        )
        .unwrap();
        let h = FleetHop::new(
            "us4",
            crate::fleet_sync::Fleet::new(pg, "/nonexistent/m.json", vec![0; 32]),
            true,
        );
        h.set_token(token.map(str::to_string));
        h
    }

    fn headers(pairs: &[(&'static str, &str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, v.parse().unwrap());
        }
        h
    }

    /// Only a client named with this fleet's seal for exactly that address is
    /// believed; a claimed one — no seal, a wrong seal, another address's
    /// seal, another fleet's — is not.
    #[test]
    fn only_a_sealed_client_is_vouched_for() {
        let h = hop(Some("0123456789abcdef0123456789abcdef"));
        let client = crate::fleet_admin::CLIENT;
        let seal = h.seal_client("198.51.100.7").unwrap();
        assert_eq!(seal.len(), 64);
        let good = headers(&[(client, "198.51.100.7"), (CLIENT_SEAL, &seal)]);
        assert_eq!(h.vouched_client(&good).unwrap(), "198.51.100.7");

        assert!(h.vouched_client(&headers(&[(client, "198.51.100.7")])).is_none(), "no seal");
        assert!(h.vouched_client(&headers(&[(client, "10.0.0.1"), (CLIENT_SEAL, &seal)])).is_none(), "another address");
        assert!(h.vouched_client(&headers(&[(client, "198.51.100.7"), (CLIENT_SEAL, "00")])).is_none(), "a forged seal");
        let other = hop(Some("ffffffffffffffffffffffffffffffff"));
        assert!(other.vouched_client(&good).is_none(), "another fleet's seal");
        assert!(hop(None).vouched_client(&good).is_none(), "no token, nothing vouched");
    }

    #[test]
    fn a_hop_is_admitted_only_with_the_token() {
        let h = hop(Some("s3cret"));
        assert_eq!(h.inbound(&headers(&[])), Inbound::None);
        assert_eq!(
            h.inbound(&headers(&[(HOP, "us5")])),
            Inbound::Refused,
            "forged: no token"
        );
        assert_eq!(
            h.inbound(&headers(&[(HOP, "us5"), (TOKEN, "s3creT")])),
            Inbound::Refused
        );
        assert_eq!(
            h.inbound(&headers(&[
                (HOP, "us5"),
                (TOKEN, "s3cret"),
                ("x-forwarded-for", "203.0.113.9, 10.0.0.1")
            ])),
            Inbound::Valid {
                origin: "us5".into(),
                client: Some("203.0.113.9".parse().unwrap())
            }
        );
        // A host that has no token yet admits no hop at all.
        assert_eq!(
            hop(None).inbound(&headers(&[(HOP, "us5"), (TOKEN, "")])),
            Inbound::Refused
        );
    }

    #[test]
    fn tokens_are_long_and_fresh() {
        let (a, b) = (new_token(), new_token());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert!(
            !format!("{:?}", hop(Some(&a))).contains(&a),
            "never in Debug"
        );
    }

    #[tokio::test]
    async fn a_home_that_is_not_a_live_member_has_no_address() {
        assert!(hop(Some("t")).address_of("us5").await.is_err());
    }
}
