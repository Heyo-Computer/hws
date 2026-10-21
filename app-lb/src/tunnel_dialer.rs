//! The public side of a namespace tunnel (`docs/design/app-lb-namespace-tunnels.md`):
//! this app-lb dials each `tunnel` deployment's remote app-lb over iroh and
//! bridges requests to it.
//!
//! The forwarding worker only speaks TCP to upstreams, so each live tunnel
//! gets a loopback listener here in the manager, and that listener is the
//! deployment's one backend. A connection to it becomes a bi-stream on the
//! one QUIC connection kept to the remote node, which is redialed when it
//! drops. Everything else — routes, certificates, the auth gate, health
//! probes, failover — is the ordinary static-deployment machinery: the
//! autoscaler's probe of the loopback address reaches the remote's own
//! health path ([`crate::proxy::TUNNEL_HEALTH_PATH`]) through the bridge.
//!
//! A tunnel whose lease lapsed has no backend, so it answers like a static
//! deployment with nothing healthy, until its remote registers again.
//!
//! The dialer's key is kept beside the state file, per host: its id is what a
//! remote app-lb lets in, handed out at registration.

use crate::deployment::{VmBackend, now_secs};
use crate::registry::Registry;
use async_trait::async_trait;
use iroh::endpoint::Connection;
use iroh::endpoint::presets::N0;
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayUrl, SecretKey};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How often tunnels are reconciled against the registry.
const TICK: Duration = Duration::from_secs(1);
/// How long a dial or a stream open may take before the request fails.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// `app-lb-state.json` → `app-lb-tunnel-dialer.key`, beside it.
pub fn key_path(state_path: &str) -> PathBuf {
    let p = Path::new(state_path);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("app-lb-state");
    let base = stem.strip_suffix("-state").unwrap_or(stem);
    p.with_file_name(format!("{base}-tunnel-dialer.key"))
}

struct Bridge {
    node_id: String,
    relay_url: Option<String>,
    /// The loopback `host:port` the deployment's backend points at.
    address: String,
    accept: tokio::task::JoinHandle<()>,
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

pub struct TunnelDialer {
    secret: SecretKey,
    registry: Arc<Registry>,
    endpoint: tokio::sync::OnceCell<Endpoint>,
    /// One per tunnel deployment this host serves, by deployment id.
    bridges: Mutex<HashMap<String, Bridge>>,
    /// One QUIC connection per remote node, shared by its bridges.
    connections: tokio::sync::Mutex<HashMap<String, Connection>>,
}

impl TunnelDialer {
    pub fn open(key_path: &Path, registry: Arc<Registry>) -> Result<Arc<Self>, String> {
        let secret = crate::plugins::tunnel::load_or_create_key(key_path)?;
        Ok(Arc::new(Self {
            secret,
            registry,
            endpoint: tokio::sync::OnceCell::new(),
            bridges: Mutex::new(HashMap::new()),
            connections: tokio::sync::Mutex::new(HashMap::new()),
        }))
    }

    /// The id a remote app-lb must accept streams from.
    pub fn id(&self) -> String {
        self.secret.public().to_string()
    }

    async fn endpoint(&self) -> Result<&Endpoint, String> {
        self.endpoint
            .get_or_try_init(|| async {
                let ep = Endpoint::builder(N0)
                    .secret_key(self.secret.clone())
                    .relay_mode(crate::plugins::tunnel::relay_mode())
                    .bind()
                    .await
                    .map_err(|e| format!("binding the tunnel dialer's endpoint: {e}"))?;
                tracing::info!(dialer = %ep.id(), "tunnel dialer online");
                Ok(ep)
            })
            .await
    }

    fn addr_for(node_id: &str, relay_url: Option<&str>) -> Result<EndpointAddr, String> {
        let id: PublicKey = node_id
            .parse()
            .map_err(|e| format!("tunnel node id {node_id:?} is invalid: {e}"))?;
        let mut addr = EndpointAddr::new(id);
        if let Some(relay) = relay_url.filter(|r| !r.is_empty()) {
            match relay.parse::<RelayUrl>() {
                Ok(url) => addr = addr.with_relay_url(url),
                Err(e) => tracing::warn!(node = node_id, "ignoring unparseable tunnel relay {relay:?}: {e}"),
            }
        }
        Ok(addr)
    }

    async fn connection(&self, node_id: &str, relay_url: Option<&str>) -> Result<Connection, String> {
        let mut conns = self.connections.lock().await;
        if let Some(conn) = conns.get(node_id)
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }
        conns.remove(node_id);
        let endpoint = self.endpoint().await?;
        let addr = Self::addr_for(node_id, relay_url)?;
        let conn = tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(addr, crate::plugins::tunnel::ALPN))
            .await
            .map_err(|_| format!("timed out dialing tunnel node {node_id}"))?
            .map_err(|e| format!("dialing tunnel node {node_id}: {e}"))?;
        tracing::info!(node = node_id, "tunnel connected");
        conns.insert(node_id.to_string(), conn.clone());
        Ok(conn)
    }

    async fn evict(&self, node_id: &str) {
        if let Some(conn) = self.connections.lock().await.remove(node_id) {
            conn.close(0u32.into(), b"evicted");
        }
    }

    /// Carry one loopback connection over a fresh stream to the node.
    async fn bridge(self: Arc<Self>, mut tcp: tokio::net::TcpStream, node_id: String, relay_url: Option<String>) {
        let conn = match self.connection(&node_id, relay_url.as_deref()).await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(node = %node_id, error = %e, "tunnel unreachable");
                return;
            }
        };
        let (send, recv) = match tokio::time::timeout(DIAL_TIMEOUT, conn.open_bi()).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                tracing::warn!(node = %node_id, error = %e, "opening a tunnel stream failed; redialing next time");
                self.evict(&node_id).await;
                return;
            }
            Err(_) => {
                tracing::warn!(node = %node_id, "timed out opening a tunnel stream; redialing next time");
                self.evict(&node_id).await;
                return;
            }
        };
        let mut stream = tokio::io::join(recv, send);
        if let Err(e) = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await {
            tracing::debug!(node = %node_id, error = %e, "tunnel stream ended");
        }
    }

    fn start_bridge(self: &Arc<Self>, node_id: &str, relay_url: Option<&str>) -> std::io::Result<Bridge> {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        std_listener.set_nonblocking(true)?;
        let address = std_listener.local_addr()?.to_string();
        let listener = tokio::net::TcpListener::from_std(std_listener)?;
        let me = Arc::downgrade(self);
        let (node, relay) = (node_id.to_string(), relay_url.map(str::to_string));
        let accept = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { continue };
                let Some(me) = me.upgrade() else { return };
                tokio::spawn(me.bridge(tcp, node.clone(), relay.clone()));
            }
        });
        Ok(Bridge { node_id: node_id.to_string(), relay_url: relay_url.map(str::to_string), address, accept })
    }

    /// Bring bridges and backends in line with the registry: a bridge per
    /// tunnel deployment here, its address the one backend while the lease is
    /// live, nothing once it lapses.
    pub fn sync(self: &Arc<Self>) {
        let now = now_secs();
        let deployments = self.registry.deployments();
        let mut bridges = self.bridges.lock().unwrap_or_else(|e| e.into_inner());
        bridges.retain(|id, b| {
            deployments.get(id.as_str()).and_then(|d| d.spec.tunnel.as_ref()).is_some_and(|t| {
                t.node_id == b.node_id && t.relay_url == b.relay_url
            })
        });
        for d in deployments.values() {
            let Some(tunnel) = &d.spec.tunnel else { continue };
            let id = d.spec.id.clone();
            if !bridges.contains_key(&id) {
                match self.start_bridge(&tunnel.node_id, tunnel.relay_url.as_deref()) {
                    Ok(b) => {
                        tracing::info!(deployment = %id, node = %tunnel.node_id, bridge = %b.address, "tunnel bridge listening");
                        bridges.insert(id.clone(), b);
                    }
                    Err(e) => {
                        tracing::error!(deployment = %id, error = %e, "cannot open a tunnel bridge");
                        continue;
                    }
                }
            }
            let address = &bridges[&id].address;
            let backends = d.backends();
            if tunnel.live(now) {
                if !(backends.len() == 1 && &backends[0].peer == address) {
                    d.set_backends(vec![Arc::new(VmBackend::for_upstream(address.clone()))]);
                }
            } else if !backends.is_empty() {
                tracing::warn!(deployment = %id, node = %tunnel.node_id, "tunnel lease lapsed; offline until it registers again");
                d.set_backends(Vec::new());
            }
        }
    }
}

/// How far a registration's timestamp may be from this host's clock.
pub const PROOF_SKEW_SECS: u64 = 300;

/// What a registering node signs: which tunnel it claims, where, and when.
/// The public app-lb's own hostname is in it so a proof sent to one app-lb
/// cannot be replayed at another.
pub fn proof_message(namespace: &str, name: &str, node_id: &str, ts: u64, remote_host: &str) -> Vec<u8> {
    format!("heyo-applb-tunnel/1\n{namespace}\n{name}\n{node_id}\n{ts}\n{remote_host}").into_bytes()
}

/// A proof's signature, as it travels: base64url of the 64 signature bytes.
pub fn sign_proof(key: &SecretKey, message: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.sign(message).to_bytes())
}

/// That `node_id`'s key signed `message`.
pub fn verify_proof(node_id: &str, message: &[u8], signature: &str) -> Result<(), String> {
    use base64::Engine;
    let key: PublicKey = node_id.parse().map_err(|_| "node_id is not an iroh endpoint id".to_string())?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature.trim())
        .map_err(|_| "proof.sig is not base64url".to_string())?;
    let bytes: [u8; iroh::Signature::LENGTH] = bytes.try_into().map_err(|_| "proof.sig is not a signature".to_string())?;
    key.verify(message, &iroh::Signature::from_bytes(&bytes))
        .map_err(|_| "proof.sig was not made by node_id's key".to_string())
}

/// Runs [`TunnelDialer::sync`] on a tick, and binds the endpoint up front so
/// the first request does not wait for it.
pub struct Service(pub Arc<TunnelDialer>);

#[async_trait]
impl BackgroundService for Service {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if let Err(e) = self.0.endpoint().await {
            tracing::error!(error = %e, "tunnel dialer offline; tunnels will not be served");
        }
        let mut tick = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                _ = tick.tick() => self.0.sync(),
                _ = shutdown.changed() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proof_binds_the_node_to_one_claim_at_one_app_lb() {
        let key = SecretKey::generate();
        let id = key.public().to_string();
        let msg = proof_message("sam", "desktop", &id, 100, "admin.us2.heyo.work");
        let sig = sign_proof(&key, &msg);
        assert_eq!(verify_proof(&id, &msg, &sig), Ok(()));
        let elsewhere = proof_message("sam", "desktop", &id, 100, "admin.eu1.heyo.work");
        assert!(verify_proof(&id, &elsewhere, &sig).is_err());
        let other = SecretKey::generate().public().to_string();
        assert!(verify_proof(&other, &msg, &sig).is_err(), "someone else's node");
    }

    #[test]
    fn the_key_sits_beside_the_state() {
        assert_eq!(key_path("/var/lib/app-lb/app-lb-state.json"), PathBuf::from("/var/lib/app-lb/app-lb-tunnel-dialer.key"));
    }
}
