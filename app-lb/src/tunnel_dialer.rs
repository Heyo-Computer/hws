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

/// Forwarding workers alternate between this many dialer keys, so the worker
/// draining after a takeover and the one replacing it never share an iroh
/// identity.
const WORKER_SLOTS: usize = 2;

fn worker_key_path(worker_dir: &Path, slot: usize) -> PathBuf {
    worker_dir.join(format!("tunnel-w{slot}.key"))
}

/// The workers' dialer ids, creating their keys (and the worker directory)
/// on first use, so they are fixed before any worker runs.
fn worker_ids(worker_dir: &Path) -> Result<Vec<String>, String> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(worker_dir)
        .map_err(|e| format!("creating {}: {e}", worker_dir.display()))?;
    (0..WORKER_SLOTS)
        .map(|slot| crate::plugins::tunnel::load_or_create_key(&worker_key_path(worker_dir, slot)).map(|k| k.public().to_string()))
        .collect()
}

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
    /// The manager's dialer reconciles tunnel deployments from the registry.
    /// A forwarding worker's has none: it bridges whatever node a request
    /// names, on demand ([`TunnelDialer::address_for`]).
    registry: Option<Arc<Registry>>,
    /// The ids of the forwarding workers' dialers, which a node must also let
    /// in; advertised beside this one's.
    worker_ids: Vec<String>,
    /// A worker's bridges, by node id.
    by_node: Mutex<HashMap<String, Bridge>>,
    endpoint: tokio::sync::OnceCell<Endpoint>,
    /// One per tunnel deployment this host serves, by deployment id.
    bridges: Mutex<HashMap<String, Bridge>>,
    /// One QUIC connection per remote node, shared by its bridges.
    connections: tokio::sync::Mutex<HashMap<String, Connection>>,
    /// Tests dial loopback endpoints by their direct address, with no relay
    /// or discovery to find them.
    #[cfg(test)]
    direct: Mutex<HashMap<String, EndpointAddr>>,
}

impl TunnelDialer {
    pub fn open(key_path: &Path, registry: Arc<Registry>) -> Result<Arc<Self>, String> {
        Self::build(key_path, Some(registry), Vec::new())
    }

    /// The manager's dialer, advertising the workers' ids too.
    pub fn open_with_workers(key_path: &Path, registry: Arc<Registry>, worker_dir: &Path) -> Result<Arc<Self>, String> {
        let ids = worker_ids(worker_dir)?;
        Self::build(key_path, Some(registry), ids)
    }

    /// A forwarding worker's dialer, from the key slot this generation of
    /// worker takes.
    pub fn open_for_worker(worker_dir: &Path) -> Result<Arc<Self>, String> {
        let slot_file = worker_dir.join("tunnel-slot");
        let previous = std::fs::read_to_string(&slot_file).ok().and_then(|s| s.trim().parse::<usize>().ok());
        let slot = previous.map_or(0, |p| (p + 1) % WORKER_SLOTS);
        std::fs::write(&slot_file, slot.to_string()).map_err(|e| format!("recording the tunnel key slot: {e}"))?;
        let dialer = Self::build(&worker_key_path(worker_dir, slot), None, Vec::new())?;
        tracing::info!(slot, dialer = %dialer.id(), "worker tunnel dialer ready");
        Ok(dialer)
    }

    fn build(key_path: &Path, registry: Option<Arc<Registry>>, worker_ids: Vec<String>) -> Result<Arc<Self>, String> {
        let secret = crate::plugins::tunnel::load_or_create_key(key_path)?;
        Ok(Arc::new(Self {
            secret,
            registry,
            worker_ids,
            by_node: Mutex::new(HashMap::new()),
            endpoint: tokio::sync::OnceCell::new(),
            bridges: Mutex::new(HashMap::new()),
            connections: tokio::sync::Mutex::new(HashMap::new()),
            #[cfg(test)]
            direct: Mutex::new(HashMap::new()),
        }))
    }

    /// A dialer on an endpoint the test bound, reaching `direct` nodes by
    /// address.
    #[cfg(test)]
    pub fn for_test(registry: Arc<Registry>, endpoint: Endpoint, direct: Vec<EndpointAddr>) -> Arc<Self> {
        Arc::new(Self {
            secret: endpoint.secret_key().clone(),
            registry: Some(registry),
            worker_ids: Vec::new(),
            by_node: Mutex::new(HashMap::new()),
            endpoint: tokio::sync::OnceCell::new_with(Some(endpoint)),
            bridges: Mutex::new(HashMap::new()),
            connections: tokio::sync::Mutex::new(HashMap::new()),
            direct: Mutex::new(direct.into_iter().map(|a| (a.id.to_string(), a)).collect()),
        })
    }

    /// The id a remote app-lb must accept streams from.
    pub fn id(&self) -> String {
        self.secret.public().to_string()
    }

    /// Every id that may dial a node for this host: this one, and each
    /// forwarding-worker slot's.
    pub fn ids(&self) -> Vec<String> {
        std::iter::once(self.id()).chain(self.worker_ids.iter().cloned()).collect()
    }

    /// A worker's loopback bridge to `node_id`, opened the first time it is
    /// asked for.
    pub fn address_for(self: &Arc<Self>, node_id: &str, relay_url: Option<&str>) -> std::io::Result<std::net::SocketAddr> {
        let mut bridges = self.by_node.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(b) = bridges.get(node_id)
            && b.relay_url.as_deref() == relay_url
        {
            return b.address.parse().map_err(std::io::Error::other);
        }
        let b = self.start_bridge(node_id, relay_url)?;
        let address = b.address.parse().map_err(std::io::Error::other)?;
        tracing::info!(node = node_id, bridge = %b.address, "worker tunnel bridge listening");
        bridges.insert(node_id.to_string(), b);
        Ok(address)
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
        #[cfg(test)]
        let addr = self.direct.lock().unwrap().get(node_id).cloned().unwrap_or(addr);
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
    /// A fresh stream to the node. A connection that turns out to be dead
    /// when the stream is opened — the node restarted, and its old connection
    /// is gone — is dropped and dialed again once: nothing has been sent on it,
    /// so a retry cannot repeat anything.
    pub async fn open_stream(
        &self,
        node_id: &str,
        relay_url: Option<&str>,
    ) -> Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream), String> {
        let mut last = String::new();
        for attempt in 0..2 {
            let conn = match self.connection(node_id, relay_url).await {
                Ok(conn) => conn,
                Err(e) => return Err(e),
            };
            match tokio::time::timeout(DIAL_TIMEOUT, conn.open_bi()).await {
                Ok(Ok(pair)) => return Ok(pair),
                Ok(Err(e)) => last = format!("opening a tunnel stream: {e}"),
                Err(_) => last = "timed out opening a tunnel stream".into(),
            }
            self.evict(node_id).await;
            if attempt == 0 {
                tracing::info!(node = node_id, error = %last, "tunnel connection was stale; dialing again");
            }
        }
        Err(last)
    }

    /// Carry one loopback connection over a fresh stream to the node.
    async fn bridge(self: Arc<Self>, mut tcp: tokio::net::TcpStream, node_id: String, relay_url: Option<String>) {
        let (send, recv) = match self.open_stream(&node_id, relay_url.as_deref()).await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(node = %node_id, error = %e, "tunnel unreachable");
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
        let Some(registry) = &self.registry else { return };
        let now = now_secs();
        let deployments = registry.deployments();
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

pub const TUNNELS_PER_NAMESPACE_ENV: &str = "APP_LB_TUNNELS_PER_NAMESPACE";
const DEFAULT_TUNNELS_PER_NAMESPACE: usize = 10;

/// How many tunnels one namespace may register.
pub fn per_namespace_limit() -> usize {
    std::env::var(TUNNELS_PER_NAMESPACE_ENV)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_TUNNELS_PER_NAMESPACE)
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
    fn consecutive_workers_dial_from_different_keys_and_the_manager_names_them_all() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(Registry::new(dir.path().join("state.json")));
        let workers = dir.path().join("worker.d");
        let manager = TunnelDialer::open_with_workers(&dir.path().join("m.key"), registry, &workers).unwrap();
        let first = TunnelDialer::open_for_worker(&workers).unwrap();
        let second = TunnelDialer::open_for_worker(&workers).unwrap();
        let third = TunnelDialer::open_for_worker(&workers).unwrap();
        assert_ne!(first.id(), second.id(), "a takeover's old and new worker never share an identity");
        assert_eq!(first.id(), third.id(), "two slots, alternating");
        let ids = manager.ids();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&manager.id()) && ids.contains(&first.id()) && ids.contains(&second.id()));
    }

    /// A worker reaches a node through a bridge of its own, made on demand.
    #[tokio::test]
    async fn a_worker_bridges_a_node_it_is_asked_for() {
        use iroh::endpoint::presets::Minimal;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let bind = |alpn: bool| async move {
            let mut b = Endpoint::builder(Minimal).relay_mode(iroh::RelayMode::Disabled);
            if alpn {
                b = b.alpns(vec![crate::plugins::tunnel::ALPN.to_vec()]);
            }
            b.bind().await.unwrap()
        };
        let node = bind(true).await;
        let serving = node.clone();
        tokio::spawn(async move {
            while let Some(incoming) = serving.accept().await {
                let Ok(conn) = incoming.await else { continue };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let mut buf = [0u8; 64];
                    let _ = recv.read(&mut buf).await;
                    let _ = send.write_all(b"from the node").await;
                    let _ = send.finish();
                }
            }
        });
        let endpoint = bind(false).await;
        let dialer = Arc::new(TunnelDialer {
            secret: endpoint.secret_key().clone(),
            registry: None,
            worker_ids: Vec::new(),
            by_node: Mutex::new(HashMap::new()),
            endpoint: tokio::sync::OnceCell::new_with(Some(endpoint)),
            bridges: Mutex::new(HashMap::new()),
            connections: tokio::sync::Mutex::new(HashMap::new()),
            direct: Mutex::new([(node.id().to_string(), node.addr())].into_iter().collect()),
        });
        let node_id = node.id().to_string();
        let address = dialer.address_for(&node_id, None).unwrap();
        assert_eq!(dialer.address_for(&node_id, None).unwrap(), address, "one bridge per node");
        let mut tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        tcp.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut got = String::new();
        tokio::time::timeout(Duration::from_secs(10), tcp.read_to_string(&mut got)).await.unwrap().unwrap();
        assert_eq!(got, "from the node");
    }

    #[test]
    fn the_key_sits_beside_the_state() {
        assert_eq!(key_path("/var/lib/app-lb/app-lb-state.json"), PathBuf::from("/var/lib/app-lb/app-lb-tunnel-dialer.key"));
    }
}
