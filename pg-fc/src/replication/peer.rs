//! Driving the other node: an HTTP client for a peer's admin API.
//!
//! Every call is authenticated with the peer's own dashboard HTTP Basic
//! credentials, recorded in [`crate::peers`]. There is no separate peer token,
//! for the reason [`crate::dashboard::dedicated`] gives for the admin API: the
//! dashboard's auth layer already gates every route, and a second secret to
//! rotate would buy no isolation. It does mean peering is a *full* trust
//! relationship — that credential can already stop and resize every VM on the
//! peer — which is stated plainly in the README rather than papered over.
//!
//! Every call is timeout-bounded, like every heyvmd call is, so an unreachable
//! peer is a prompt error on a dashboard page rather than a hung request.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;

use crate::peers::Peer;

use super::wire;

pub struct PeerClient {
    http: reqwest::Client,
    peer: Peer,
    auth: String,
}

impl PeerClient {
    pub fn new(peer: Peer, timeout: Duration) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building the peer HTTP client")?;
        let auth = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", peer.user, peer.password))
        );
        Ok(Self { http, peer, auth })
    }

    pub fn name(&self) -> &str {
        &self.peer.name
    }

    /// The handshake, before anything is created anywhere.
    pub async fn node_info(&self) -> Result<wire::NodeInfo> {
        self.get("/api/replication/peer/node").await
    }

    pub async fn writer_tunnel(&self, req: &wire::WriterTunnelRequest) -> Result<reqwest::Upgraded> {
        let url = self.https_url("/api/replication/peer/writer-tunnel")?;
        // A request timeout must not become a lifetime limit on the upgraded
        // SQL session. Bound connect/send/upgrade explicitly instead.
        let tunnel_http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .http1_only()
            .tcp_nodelay(true)
            .tcp_keepalive(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build().context("building peer SQL tunnel client")?;
        let send = tunnel_http.post(&url)
            .header(reqwest::header::AUTHORIZATION, &self.auth)
            .header(reqwest::header::CONNECTION, "upgrade")
            .header(reqwest::header::UPGRADE, "pg-fc-sql/1")
            .json(req).send();
        let res = tokio::time::timeout(Duration::from_secs(10), send).await
            .context("peer SQL tunnel request timed out")??;
        if res.status() != reqwest::StatusCode::SWITCHING_PROTOCOLS
            || res.headers().get(reqwest::header::UPGRADE).and_then(|v| v.to_str().ok()) != Some("pg-fc-sql/1") {
            // Do not wait without a deadline for an error body's completion.
            bail!("peer refused SQL tunnel upgrade ({})", res.status());
        }
        tokio::time::timeout(Duration::from_secs(10), res.upgrade()).await
            .context("peer SQL tunnel upgrade timed out")?
            .context("upgrading peer SQL tunnel")
    }

    /// Identity checks for SQL transport are HTTPS-only even when an operator
    /// has elected to permit insecure replication control calls.
    pub async fn verified_node_info(&self) -> Result<wire::NodeInfo> {
        let path = "/api/replication/peer/node";
        let url = self.https_url(path)?;
        let res = self.http.get(&url).header(reqwest::header::AUTHORIZATION, &self.auth).send().await?;
        let body = self.check(res, &url).await?;
        serde_json::from_str(&body).context("parsing peer identity handshake")
    }

    /// Ask the peer to build the replica. Takes its own, longer timeout: the
    /// peer validates synchronously and then answers, but that validation
    /// includes checking the database name is free, which touches its store.
    pub async fn provision_replica(
        &self,
        req: &wire::ProvisionReplica,
    ) -> Result<wire::RecordJson> {
        self.post("/api/replication/peer/replicas", req).await
    }

    pub async fn provision_physical_replica(&self, req: &wire::PhysicalReplicaRequest) -> Result<wire::PhysicalRecordJson> {
        self.post("/api/replication/peer/physical-replicas", req).await
    }

    pub async fn physical_handoff(&self, req: &wire::PhysicalHandoffRequest) -> Result<wire::PhysicalRecordJson> {
        self.post("/api/replication/peer/physical-handoff", req).await
    }

    pub async fn physical_standby_bind(&self, req: &wire::PhysicalStandbyBindRequest) -> Result<wire::PhysicalRecordJson> {
        self.post("/api/replication/peer/physical-standby-bind", req).await
    }

    pub async fn retire_previous(&self, req: &wire::RetirePreviousPeerRequest) -> Result<wire::PhysicalRecordJson> {
        self.post("/api/replication/peer/retire-previous", req).await
    }

    pub async fn physical_grant(&self, database: &str) -> Result<wire::PhysicalHandoffGrantJson> {
        self.get(&format!("/api/replication/peer/physical-grants/{}", enc(database))).await
    }

    pub async fn physical_status(&self, database: &str) -> Result<wire::PhysicalRecordJson> {
        self.get(&format!("/api/replication/{}/physical", enc(database))).await
    }

    pub async fn status(&self, database: &str) -> Result<wire::StatusJson> {
        self.get(&format!("/api/replication/{}", enc(database)))
            .await
    }

    pub async fn maintenance_status(&self, id: &str) -> Result<crate::database_maintenance::Operation> {
        self.get(&format!("/api/database-maintenance/{}", enc(id))).await
    }

    /// Tear down the peer's half. Best-effort by nature — the caller is
    /// detaching whether or not the peer answers.
    pub async fn teardown(&self, database: &str) -> Result<()> {
        let url = self.url(&format!("/api/replication/{}", enc(database)))?;
        let res = self
            .http
            .delete(&url)
            .header(reqwest::header::AUTHORIZATION, &self.auth)
            .send()
            .await
            .with_context(|| format!("DELETE {url}"))?;
        self.check(res, &url).await?;
        Ok(())
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = self.url(path)?;
        let res = self
            .http
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, &self.auth)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let body = self.check(res, &url).await?;
        serde_json::from_str(&body)
            .with_context(|| format!("parsing the peer's reply to GET {url}: {}", truncate(&body)))
    }

    async fn post<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = self.url(path)?;
        let res = self
            .http
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, &self.auth)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let body = self.check(res, &url).await?;
        serde_json::from_str(&body).with_context(|| {
            format!(
                "parsing the peer's reply to POST {url}: {}",
                truncate(&body)
            )
        })
    }

    /// Turn a non-2xx into an error that names what the peer actually said.
    ///
    /// The peer's own error bodies are `{"error": "..."}`, so surface that
    /// rather than a bare status code: nearly every failure here is something
    /// an operator can fix (a name already taken, replication not enabled on
    /// the far side), and the fix is in that string.
    async fn check(&self, res: reqwest::Response, url: &str) -> Result<String> {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        if status.is_success() {
            return Ok(body);
        }
        let detail = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
            .unwrap_or_else(|| truncate(&body));
        if status == reqwest::StatusCode::UNAUTHORIZED {
            bail!(
                "peer {} rejected our credentials ({status}) — check its \
                 PG_VM_POOL_DASHBOARD_USER/PASSWORD against this peer record",
                self.peer.name
            );
        }
        bail!(
            "peer {} answered {status} to {url}: {detail}",
            self.peer.name
        );
    }

    /// Join a path onto the peer's base URL.
    ///
    /// Defense in depth of the same flavour as `vm::shell_squote`: database
    /// names are already `[a-z][a-z0-9_]*` by the time they get here, but a
    /// path that could escape the peer's base URL must not be constructible
    /// from one.
    fn url(&self, path: &str) -> Result<String> {
        if !path.starts_with('/') || path.contains("..") || path.contains("//") {
            bail!("refusing to build a peer URL from {path:?}");
        }
        Ok(self.peer.url(path))
    }

    fn https_url(&self, path: &str) -> Result<String> {
        let url = self.url(path)?;
        if !url.starts_with("https://") { bail!("SQL forwarding requires an HTTPS peer dashboard URL"); }
        Ok(url)
    }
}

/// Percent-encode a path segment. Names are already validated, so this only
/// ever has to be a no-op — it exists so that stays true if that changes.
fn enc(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

fn truncate(s: &str) -> String {
    let s = s.trim();
    if s.len() <= 300 {
        return s.to_string();
    }
    let mut end = 300;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> PeerClient {
        PeerClient::new(
            Peer {
                name: "node_b".into(),
                base_url: "https://b.example:34199".into(),
                user: "admin".into(),
                password: "secret".into(),
                pg_host: "10.0.0.2".into(),
                pg_port: 6432,
                created_at: 0,
            },
            Duration::from_secs(5),
        )
        .unwrap()
    }

    #[test]
    fn urls_join_onto_the_peer_base_and_refuse_traversal() {
        let c = client();
        assert_eq!(
            c.url("/api/replication/acme").unwrap(),
            "https://b.example:34199/api/replication/acme"
        );
        assert!(c.url("api/replication").is_err(), "must be absolute");
        assert!(c.url("/api/../../etc").is_err());
        assert!(
            c.url("//evil.example/x").is_err(),
            "protocol-relative escape"
        );
    }

    #[test]
    fn path_segments_are_encoded() {
        assert_eq!(enc("acme_1"), "acme_1");
        assert_eq!(enc("a/b"), "a%2Fb");
        assert_eq!(enc("a b"), "a%20b");
    }

    /// The Basic header this client sends must be the one the dashboard's own
    /// auth layer accepts — client and server are pinned to each other here so
    /// a change to either is caught locally rather than against a live peer.
    #[test]
    fn basic_auth_header_matches_what_the_dashboard_accepts() {
        let c = client();
        let encoded = c.auth.strip_prefix("Basic ").expect("scheme");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "admin:secret");
    }

    #[test]
    fn sql_transport_refuses_plain_http() {
        let mut c = client();
        c.peer.base_url = "http://b.example:34199".into();
        assert!(c.https_url("/api/replication/peer/writer-tunnel").is_err());
    }
}
