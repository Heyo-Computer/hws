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
pub const FORWARD_ENV: &str = "APP_LB_FLEET_FORWARD";
pub const ADDRESS_ENV: &str = "APP_LB_FLEET_ADDRESS";
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
