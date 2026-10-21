//! The data plane.
//!
//! One `ProxyHttp` serves every deployment, because pingora fixes its service
//! set at startup — `Server::run_forever(self)` consumes the server, so there is
//! no way to add a service per deployment at runtime. Dynamic registration
//! therefore lives in the `Registry` this reads on each request.
//!
//! Nothing here may block: VM boots happen only in the autoscaler. The one wait
//! is the cold-start `Notify`, which yields.

#[cfg(test)]
use crate::deployment::{Deployment, VmBackend};
#[cfg(test)]
use crate::metrics::Metrics;
use crate::worker_rpc::{Client, Completion, RemoteDecision, RemoteRequest};
use async_trait::async_trait;
use pingora_core::prelude::HttpPeer;
use pingora_core::protocols::TcpKeepalive;
use pingora_core::{Error, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
#[cfg(test)]
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Ctx {
    request: Option<RemoteRequest>,
    /// The request as first read, kept so it can be begun again if the
    /// manager that began it is replaced before it is forwarded.
    head: Option<crate::request_control::RequestHead>,
    /// When the request entered the proxy, for latency. Set in `request_filter`
    /// so the measured span covers cold-start waits too, and `None` before then
    /// so a request rejected pre-routing simply isn't timed.
    started_at: Option<Instant>,
}

pub struct LbProxy {
    control: Client,
    /// True for the instance that serves streams arriving over an app-lb
    /// tunnel (see `plugins::tunnel`), which runs in the manager rather than
    /// the forwarding worker. Those have no socket peer — the cloud edge is
    /// the far end of the stream — so the visitor's address comes from the
    /// edge's [`TUNNEL_CLIENT_IP`] instead, and the edge terminated TLS.
    tunnel_ingress: bool,
    /// On tunnel ingress, the hostnames this app-lb registered. A stream from
    /// an allowed dialer is served only for these: whoever can register a
    /// tunnel at the same dialer could otherwise point their own hostname at
    /// this node and reach its catch-all routes.
    tunnel_hosts: crate::plugins::tunnel::ExternalTlsHosts,
    /// The forwarding worker's own tunnel dialer: a tunnel peer is reached
    /// through it rather than the manager's bridge.
    tunnels: Option<std::sync::Arc<crate::tunnel_dialer::TunnelDialer>>,
}

/// Answered by tunnel ingress itself, before routing, so the dialer can tell
/// a live tunnel from a dead one without knowing any of its hostnames.
pub const TUNNEL_HEALTH_PATH: &str = "/.well-known/heyo-tunnel/health";

/// The header the cloud edge sets on tunnel ingress: the visitor's address as
/// the edge's own proxy saw it. Trusted only on tunnel ingress, and removed
/// before every upstream request on every ingress.
pub const TUNNEL_CLIENT_IP: &str = "x-heyo-client-ip";

impl LbProxy {
    pub fn new(control: Client) -> Self {
        Self { control, tunnel_ingress: false, tunnel_hosts: Default::default(), tunnels: None }
    }

    pub fn with_tunnels(mut self, dialer: Option<std::sync::Arc<crate::tunnel_dialer::TunnelDialer>>) -> Self {
        self.tunnels = dialer;
        self
    }

    /// The proxy for streams that arrived over an app-lb tunnel, serving only
    /// `hosts`.
    pub fn for_tunnel_ingress(control: Client, hosts: crate::plugins::tunnel::ExternalTlsHosts) -> Self {
        Self { control, tunnel_ingress: true, tunnel_hosts: hosts, tunnels: None }
    }

    /// Tunnel ingress only: answer what is not this app-lb's to serve, before
    /// anything is decided. `Some` when the request was answered.
    async fn tunnel_gate(&self, session: &mut Session) -> Result<Option<bool>> {
        if !self.tunnel_ingress {
            return Ok(None);
        }
        let req = session.req_header();
        if req.uri.path() == TUNNEL_HEALTH_PATH {
            write_plain(session, 200, "ok\n").await?;
            return Ok(Some(true));
        }
        let host = req
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .or_else(|| req.uri.host())
            .map(|h| h.rsplit_once(':').filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit())).map_or(h, |(h, _)| h))
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase());
        let served = host.as_deref().is_some_and(|h| {
            self.tunnel_hosts.read().is_ok_and(|hosts| hosts.contains(h))
        });
        if !served {
            tracing::warn!(host = ?host, "tunnel request for a hostname this app-lb did not register; answering 421");
            write_plain(session, 421, "this hostname is not served here\n").await?;
            return Ok(Some(true));
        }
        Ok(None)
    }

    /// The address the request came from: the socket peer, never a
    /// client-settable header — except on tunnel ingress, where there is no
    /// socket peer and the edge (the only party that can open a tunnel
    /// stream) vouches for the visitor.
    fn peer(&self, session: &Session) -> Option<std::net::SocketAddr> {
        if self.tunnel_ingress {
            return session
                .req_header()
                .headers
                .get(TUNNEL_CLIENT_IP)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
                .map(|ip| std::net::SocketAddr::new(ip, 0));
        }
        session.client_addr().and_then(|a| a.as_inet().copied())
    }

    /// The manager that began this request has gone (a restart) before the
    /// request was forwarded: begin it again with the next one. Refused when
    /// that manager still answers — then the failure is its, and is handled
    /// as before — or when the next manager would not simply proxy it.
    async fn begin_again(&self, ctx: &mut Ctx) -> std::result::Result<(), String> {
        // Tunnel ingress runs in the manager: nothing replaces it mid-request.
        if self.tunnel_ingress {
            return Err("tunnel ingress is served by the manager itself".into());
        }
        let manager = ctx.request.as_ref().and_then(RemoteRequest::manager);
        if manager.is_none() || crate::worker::current_manager().await == manager {
            return Err("the manager that began this request still answers".into());
        }
        let head = ctx.head.clone().ok_or("the request head was not kept")?;
        match self.control.begin(head).await {
            Ok((request, RemoteDecision::Proxy)) => {
                tracing::info!("began a request again with the manager that replaced the one that began it");
                ctx.request = Some(request);
                Ok(())
            }
            Ok(_) => Err("the next manager decided this request differently".into()),
            Err(crate::worker_rpc::BeginError::Control(e) | crate::worker_rpc::BeginError::Unavailable(e)) => Err(e),
            Err(crate::worker_rpc::BeginError::HeadersTooLarge) => Err("request headers exceed the control transport".into()),
        }
    }
}

/// Keepalive on every upstream connection, so a backend that vanishes without
/// a word is noticed. A destroyed Firecracker VM takes its tap device with it:
/// no RST ever arrives, and a request waiting on a response has nothing
/// unacknowledged in flight, so without probes the socket sits in ESTABLISHED
/// forever — holding the caller, the backend's `in_flight` slot, and anything
/// queued behind that caller. Probes are answered by a live peer's kernel, so a
/// slow response or a long-lived stream is unaffected; a dead peer is dropped
/// within about a minute of its last word.
const UPSTREAM_KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const UPSTREAM_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const UPSTREAM_KEEPALIVE_COUNT: usize = 3;
/// `TCP_USER_TIMEOUT`: the same bound for data that was sent and never
/// acknowledged — a pooled keep-alive connection reused after its VM died.
#[cfg(target_os = "linux")]
const UPSTREAM_USER_TIMEOUT: Duration = Duration::from_secs(60);

fn http_peer(selected: crate::request_control::Peer) -> HttpPeer {
    let mut peer = HttpPeer::new(selected.address, selected.tls, selected.sni);
    peer.options.tcp_keepalive = Some(TcpKeepalive {
        idle: UPSTREAM_KEEPALIVE_IDLE,
        interval: UPSTREAM_KEEPALIVE_INTERVAL,
        count: UPSTREAM_KEEPALIVE_COUNT,
        #[cfg(target_os = "linux")]
        user_timeout: UPSTREAM_USER_TIMEOUT,
    });
    peer
}

/// 503 with `Retry-After`: no manager answered while app-lb restarted.
async fn write_unavailable(session: &mut Session) -> Result<()> {
    let message = "app-lb is restarting; retry shortly\n";
    let mut header = ResponseHeader::build(503, Some(3))?;
    header.insert_header(http::header::CONTENT_LENGTH, message.len().to_string())?;
    header.insert_header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")?;
    header.insert_header(http::header::RETRY_AFTER, "1")?;
    session.write_response_header(Box::new(header), false).await?;
    session
        .write_response_body(Some(bytes::Bytes::copy_from_slice(message.as_bytes())), true)
        .await
}

async fn write_plain(session: &mut Session, code: u16, message: &str) -> Result<()> {
    let mut header = ResponseHeader::build(code, Some(2))?;
    header.insert_header(http::header::CONTENT_LENGTH, message.len().to_string())?;
    header.insert_header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")?;
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(
            Some(bytes::Bytes::copy_from_slice(message.as_bytes())),
            true,
        )
        .await
}

async fn write_control_response(
    session: &mut Session,
    status: u16,
    body: String,
    content_type: String,
    headers: Vec<(String, String)>,
    cache_control: Option<String>,
) -> Result<()> {
    let mut header = ResponseHeader::build(status, Some(8))?;
    header.insert_header(http::header::CONTENT_LENGTH, body.len().to_string())?;
    header.insert_header(http::header::CONTENT_TYPE, content_type)?;
    if let Some(cache) = cache_control {
        header.insert_header(http::header::CACHE_CONTROL, cache)?;
    }
    for (name, value) in headers {
        header.append_header(name, value)?;
    }
    session.write_response_header(Box::new(header), false).await?;
    session.write_response_body(Some(bytes::Bytes::from(body)), true).await
}

/// The newest events an exposed or admin-served feed returns. Half the ring:
/// a reader wants "recent", and the full ring is the debugging view.
pub use crate::request_control::FEED_PAGE;

/// Answer a request routed to a `site` deployment, out of its directory.
///
/// Everything about *which* file is `site::resolve`'s decision; this is the HTTP
/// around it — status, headers, conditional requests, ranges, and getting the
/// bytes onto the wire without reading a large file into memory.
async fn serve_site(session: &mut Session, spec: &crate::config::SiteSpec, path: &str) -> Result<()> {
    use crate::site::{self, Resolved};

    let (file, status) = match site::resolve(spec, path) {
        Resolved::File(f) => (f, 200),
        Resolved::Redirect(to) => {
            let mut header = ResponseHeader::build(301, Some(3))?;
            header.insert_header(http::header::LOCATION, &to)?;
            header.insert_header(http::header::CONTENT_LENGTH, "0")?;
            session.write_response_header(Box::new(header), true).await?;
            return Ok(());
        }
        Resolved::NotFound(Some(page)) => (page, 404),
        Resolved::NotFound(None) => {
            // A root with nothing in it 404s every path. Say so (to the
            // operator in the log and the header, not the path to visitors),
            // since "not found" for `/` is otherwise indistinguishable from a
            // typo in the URL.
            let health = site::root_status(spec);
            if health.status != "ok" {
                tracing::warn!(root = %spec.root, status = health.status, "site root cannot serve");
                let mut header = ResponseHeader::build(404, Some(3))?;
                let body = "not found: this site has no files deployed yet\n";
                header.insert_header("x-applb-site", format!("root-{}", health.status.replace('_', "-")))?;
                header.insert_header(http::header::CONTENT_LENGTH, body.len().to_string())?;
                header.insert_header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")?;
                session.write_response_header(Box::new(header), false).await?;
                return session
                    .write_response_body(Some(bytes::Bytes::from_static(body.as_bytes())), true)
                    .await;
            }
            return write_plain(session, 404, "not found\n").await;
        }
    };

    let mut handle = match tokio::fs::File::open(&file).await {
        Ok(f) => f,
        Err(e) => {
            // Resolved a moment ago, so this is a deploy landing mid-request or
            // a permissions problem — either way not the client's fault.
            tracing::warn!(path = %file.display(), error = %e, "could not open a site file");
            return write_plain(session, 404, "not found\n").await;
        }
    };
    let Ok(meta) = handle.metadata().await else {
        return write_plain(session, 404, "not found\n").await;
    };
    let len = meta.len();
    let etag = site::etag(&meta);

    // A cached client gets a 304 and no body. Only for a 200 — a 404 page is
    // not a representation of the requested URL, so it must not be revalidated
    // as one.
    if status == 200
        && session
            .req_header()
            .headers
            .get(http::header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| site::etag_matches(v, &etag))
    {
        let mut header = ResponseHeader::build(304, Some(3))?;
        header.insert_header(http::header::ETAG, &etag)?;
        header.insert_header(http::header::CACHE_CONTROL, &spec.cache_control)?;
        session.write_response_header(Box::new(header), true).await?;
        return Ok(());
    }

    // Ranges, so a paused download or a seeking `<video>` works. Only on a 200:
    // a range of an error page is meaningless.
    let mut offset = 0u64;
    let mut count = len;
    let mut status = status;
    if status == 200 {
        let range = session
            .req_header()
            .headers
            .get(http::header::RANGE)
            .and_then(|v| v.to_str().ok());
        if let Some(raw) = range {
            match site::parse_range(raw, len) {
                Ok(Some((first, last))) => {
                    offset = first;
                    count = last - first + 1;
                    status = 206;
                }
                Ok(None) => {} // unsupported form; the whole file is a valid answer
                Err(()) => {
                    let mut header = ResponseHeader::build(416, Some(3))?;
                    header.insert_header(http::header::CONTENT_RANGE, format!("bytes */{len}"))?;
                    header.insert_header(http::header::CONTENT_LENGTH, "0")?;
                    session.write_response_header(Box::new(header), true).await?;
                    return Ok(());
                }
            }
        }
    }

    let mut header = ResponseHeader::build(status, Some(6))?;
    header.insert_header(http::header::CONTENT_TYPE, site::content_type(&file))?;
    header.insert_header(http::header::CONTENT_LENGTH, count.to_string())?;
    header.insert_header(http::header::ETAG, &etag)?;
    header.insert_header(http::header::CACHE_CONTROL, &spec.cache_control)?;
    // Advertised whether or not this request used one, so a client knows it can
    // resume rather than restarting a large download.
    header.insert_header(http::header::ACCEPT_RANGES, "bytes")?;
    if status == 206 {
        let last = offset + count - 1;
        header.insert_header(
            http::header::CONTENT_RANGE,
            format!("bytes {offset}-{last}/{len}"),
        )?;
    }
    let head_only = session.req_header().method == http::Method::HEAD;
    session
        .write_response_header(Box::new(header), head_only)
        .await?;
    if head_only {
        return Ok(());
    }

    if offset > 0 {
        use tokio::io::AsyncSeekExt;
        if handle.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
            return Ok(()); // header is already out; nothing better to say
        }
    }

    // Streamed in chunks rather than read whole: a fleet of sites serving large
    // assets would otherwise hold every concurrent response's full size in
    // memory at once.
    use tokio::io::AsyncReadExt;
    let mut remaining = count;
    let mut buf = vec![0u8; site::STREAM_CHUNK.min(count.max(1) as usize)];
    while remaining > 0 {
        let want = (buf.len() as u64).min(remaining) as usize;
        let read = match handle.read(&mut buf[..want]).await {
            Ok(0) => break, // truncated under us; stop rather than pad
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(path = %file.display(), error = %e, "site file read failed mid-response");
                break;
            }
        };
        remaining -= read as u64;
        session
            .write_response_body(Some(bytes::Bytes::copy_from_slice(&buf[..read])), remaining == 0)
            .await?;
    }
    Ok(())
}

#[async_trait]
impl ProxyHttp for LbProxy {
    type CTX = Ctx;

    fn new_ctx(&self) -> Self::CTX {
        Ctx::default()
    }

    /// Resolve the deployment up front so an unroutable request is rejected
    /// before any upstream work.
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // Start the latency clock before anything else so the span reflects the
        // whole time app-lb held the request, cold-start wait included.
        ctx.started_at = Some(Instant::now());

        if let Some(answered) = self.tunnel_gate(session).await? {
            return Ok(answered);
        }

        let req = session.req_header();
        let head = crate::request_control::RequestHead {
            method: req.method.clone(),
            uri: req.uri.clone(),
            headers: req.headers.clone(),
            peer: self.peer(session),
            // The edge terminates a tunnel's TLS.
            tls_terminated: self.tunnel_ingress
                || session.digest().is_some_and(|d| d.ssl_digest.is_some()),
        };
        ctx.head = Some(head.clone());
        let (request, mut decision) = match self.control.begin(head).await {
            Ok(result) => result,
            Err(crate::worker_rpc::BeginError::HeadersTooLarge) => {
                write_plain(session, 431, "request headers exceed control transport limit\n").await?;
                return Ok(true);
            }
            // In the manager, a broken control link is this request's
            // failure, not a reason to stop the process serving everything.
            Err(crate::worker_rpc::BeginError::Control(error)) if self.tunnel_ingress => {
                tracing::warn!(%error, "tunnel request: request control failed; answering 502");
                write_plain(session, 502, "app-lb could not decide this request\n").await?;
                return Ok(true);
            }
            Err(crate::worker_rpc::BeginError::Control(error)) => crate::worker::control_lost(&error),
            // No manager within the wait: app-lb is restarting, or stopped.
            // Say so and let the client retry, rather than drop it.
            Err(crate::worker_rpc::BeginError::Unavailable(error)) => {
                tracing::warn!(%error, "no manager answered within the wait; answering 503");
                write_unavailable(session).await?;
                return Ok(true);
            }
        };
        ctx.request = Some(request);
        if matches!(decision, RemoteDecision::ReadLoginBody) {
            let mut body = Vec::new();
            while let Some(chunk) = session.read_request_body().await? {
                if body.len() + chunk.len() > crate::request_control::MAX_LOGIN_BODY {
                    body.resize(crate::request_control::MAX_LOGIN_BODY + 1, 0);
                    break;
                }
                body.extend_from_slice(&chunk);
            }
            let request = ctx.request.as_mut().expect("request admitted");
            decision = request.continue_login(&body).await
                .map_err(|error| control_error(request, error))?;
        }
        // Pingora tracks header names separately; preserve its bookkeeping in
        // this transport adapter even though authority evaluated owned headers.
        // The edge's word about the visitor is for app-lb, never for an
        // upstream — and on any other ingress it is only a client's claim.
        for name in crate::gateway::HEADERS.into_iter().chain([
            crate::regional::GENERATION, crate::regional::ENVIRONMENT,
            crate::regional::PROBE, crate::regional::ACTIVE_PROBE,
            TUNNEL_CLIENT_IP,
        ]) {
            session.req_header_mut().remove_header(name);
        }
        match decision {
            RemoteDecision::Respond { status, body, content_type, headers, cache_control } => {
                write_control_response(session, status, body, content_type, headers, cache_control).await?;
                return Ok(true);
            }
            RemoteDecision::ServeSite { spec, path } => {
                serve_site(session, &spec, &path).await?;
                return Ok(true);
            }
            RemoteDecision::Proxy => return Ok(false),
            RemoteDecision::ReadLoginBody => unreachable!("login continuation returns a terminal decision"),
        }
    }

    /// Attach the caller's identity for a gated deployment — and strip the same
    /// headers when there is none, so a client cannot present its own.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let request = ctx.request.as_mut().expect("request admitted");
        let modifications = match request.forwarding_modifications(&upstream.uri).await {
            Ok(m) => m,
            // The link dropped, not an answer: if a restart took the manager,
            // begin again with the next one and ask it.
            Err(error) if !request.connected() && self.begin_again(ctx).await.is_ok() => {
                let request = ctx.request.as_mut().expect("begun again");
                let again = async {
                    request.next_peer().await?;
                    request.forwarding_modifications(&upstream.uri).await
                };
                match again.await {
                    Ok(m) => m,
                    Err(_) => return Err(control_error(ctx.request.as_ref().expect("begun again"), error)),
                }
            }
            Err(error) => return Err(control_error(ctx.request.as_ref().expect("request admitted"), error)),
        };
        for modification in modifications {
            match modification {
                crate::request_control::HeaderModification::Remove(name) => {
                    upstream.remove_header(&name);
                }
                crate::request_control::HeaderModification::Set(name, value) => {
                    upstream.insert_header(name, value)?;
                }
                crate::request_control::HeaderModification::RewriteUri(rewritten) => {
                    let mut parts = upstream.uri.clone().into_parts();
                    parts.path_and_query = Some(rewritten.parse().map_err(|error| Error::explain(ErrorType::InternalError, format!("failed to rewrite upstream path: {error}")))?);
                    upstream.set_uri(http::Uri::from_parts(parts).map_err(|error| Error::explain(ErrorType::InternalError, format!("failed to build rewritten upstream URI: {error}")))?);
                }
            }
        }
        Ok(())
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let request = ctx.request.as_mut().expect("request admitted");
        let selected = match request.next_peer().await {
            Ok(selected) => selected,
            // The link dropped, not an answer: if a restart took the manager,
            // begin again with the next one and ask it.
            Err(_) if !request.connected() && self.begin_again(ctx).await.is_ok() => {
                let request = ctx.request.as_mut().expect("begun again");
                request.next_peer().await.map_err(|e| control_error(request, e))?
            }
            Err(error) => return Err(control_error(ctx.request.as_ref().expect("request admitted"), error)),
        };
        let mut selected_peer = selected.peer;
        if let (Some(target), Some(dialer)) = (&selected_peer.tunnel, &self.tunnels) {
            match dialer.address_for(&target.node_id, target.relay_url.as_deref()) {
                Ok(address) => selected_peer.address = address,
                Err(e) => tracing::warn!(node = %target.node_id, error = %e, "worker tunnel bridge unavailable; using the manager's"),
            }
        }
        let mut peer = http_peer(selected_peer);
        // Pingora 0.9 otherwise strips this authenticated PostgreSQL tunnel's
        // handshake as a non-WebSocket upgrade. Keep the default sanitization
        // for all other requests and unsupported upgrade protocols.
        if session.req_header().headers.get(http::header::UPGRADE)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"pg-fc-sql/1")) {
            peer.options.http_upstream_request_policy.h1_upgrade =
                pingora_core::upstreams::peer::H1UpgradePolicy::Preserve;
        }
        Ok(Box::new(peer))
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // A successfully upgraded SQL stream can legitimately be idle. Keep
        // the HTTP body deadline until the backend accepts this exact protocol;
        // an Upgrade request alone must not disable slow-client protection.
        if session.is_upgrade(upstream_response) == Some(true)
            && session.req_header().headers.get(http::header::UPGRADE)
                .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"pg-fc-sql/1"))
            && upstream_response.headers.get(http::header::UPGRADE)
                .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"pg-fc-sql/1"))
        {
            session.set_read_timeout(None);
        }
        // Makes it possible to see which VM served a request, which is how the
        // load-spreading and retry behaviour get verified.
        // A hop's home host has already named its own VM.
        if let Some(id) = ctx.request.as_ref().and_then(RemoteRequest::backend_id)
            .filter(|id| !id.starts_with(crate::fleet_hop::BACKEND_PREFIX))
        {
            upstream_response.insert_header("x-vm-id", id)?;
        }
        Ok(())
    }

    /// A VM we couldn't reach is dead to us: drop it from selection, mark the
    /// error retryable, and let `upstream_peer` run again against another VM.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        tracing::warn!(peer = %peer, "upstream connect failed");
        if ctx.request.as_mut().is_some_and(RemoteRequest::connection_failed) {
            e.set_retry(true);
        }
        e
    }

    /// Runs on every request, success or failure. If this ever misses a path,
    /// `in_flight` leaks upward and the deployment pins at max replicas.
    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        if let Some(request) = ctx.request.as_mut() {
            let completion = Completion {
                status: session.response_written().map(|r| r.status.as_u16()),
                duration_micros: ctx.started_at.map(|s| s.elapsed().as_micros().min(u64::MAX as u128) as u64).unwrap_or(0),
                bytes: session.body_bytes_sent(),
                error: e.map(ToString::to_string),
            };
            if let Err(error) = request.complete(completion).await {
                crate::worker::control_interrupted(request.manager(), &error);
            }
        }
    }
}

fn control_error(request: &RemoteRequest, error: String) -> Box<Error> {
    if !request.connected() { crate::worker::control_interrupted(request.manager(), &error); }
    Error::explain(ErrorType::ConnectProxyFailure, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeploymentSpec, HealthCheck, RouteRule, ScalingPolicy, VmSpec};
    use crate::deployment::PendingVm;
    use crate::config::Driver;

    #[test]
    fn https_backend_builds_a_tls_peer_with_url_hostname_as_sni() {
        let backend = VmBackend::for_upstream("https://ci.eu1.heyo.work:443".into());
        let peer = http_peer(crate::request_control::Peer {
            address: "127.0.0.1:443".parse().unwrap(), tls: backend.tls, sni: backend.sni.clone(), tunnel: None,
        });
        assert!(peer.is_tls());
        assert_eq!(peer.sni, "ci.eu1.heyo.work");
        assert!(peer.options.verify_cert);
        assert!(peer.options.verify_hostname);
    }

    #[test]
    fn upstream_peers_probe_for_a_vanished_backend() {
        let backend = backend("172.25.128.50:8080");
        let peer = http_peer(crate::request_control::Peer {
            address: "172.25.128.50:8080".parse().unwrap(), tls: backend.tls, sni: backend.sni.clone(), tunnel: None,
        });
        let ka = peer
            .options
            .tcp_keepalive
            .as_ref()
            .expect("keepalive is set on every upstream");
        let detect = ka.idle + ka.interval * ka.count as u32;
        assert!(
            detect <= Duration::from_secs(90),
            "a dead VM should be dropped well inside cold-start budgets, got {detect:?}"
        );
        #[cfg(target_os = "linux")]
        assert!(
            !ka.user_timeout.is_zero(),
            "unacknowledged writes to a dead VM must time out too"
        );
    }

    fn deployment(scaling: ScalingPolicy) -> Arc<Deployment> {
        Arc::new(Deployment::new(DeploymentSpec { tunnel: None,
            placement: None,
            ingress: None,
            account_id: None,
            user_id: None,
            namespace: "default".into(),
            feed: None,
            id: "demo".into(),
            routes: vec![RouteRule {
                host: Some("demo.local".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
                redirect: None,
            }],
            vm: Some(VmSpec {
                correlated_creates: false,
                env_from: vec![],
                workspace_archive: None,
                image_download_url: None,
                image_size_bytes: None,
                image_sha256: None,
                driver: Driver::Firecracker,
                image: None,
                rootfs: Default::default(),
                port: 8080,
                start_command: None,
                size_class: None,
                disk_size_gb: None,
                working_directory: None,
                env_vars: None,
                setup_hooks: None,
                open_ports: vec![],
                mounts: vec![],
                workspace: None,
                ttl_seconds: 3600,
            }),
            scaling,
            maintenance: false,
            health: HealthCheck::default(),
            upstreams: vec![],
            discovery: None,
            gateway: None,
            build: None,
            artifact: None,
            site: None,
            update: None,
            auth: None,
        }))
    }

    fn backend(addr: &str) -> Arc<VmBackend> {
        Arc::new(VmBackend::new("sb-1".into(), addr.parse().unwrap()))
    }

    #[tokio::test]
    async fn wait_for_capacity_gives_up_when_at_max_replicas() {
        let d = deployment(ScalingPolicy {
            max_replicas: 1,
            cold_start_timeout_secs: 30,
            ..Default::default()
        });
        // At max with an unhealthy VM: booting more is impossible, so this must
        // fail fast rather than burn the cold-start budget.
        let b = backend("10.0.0.1:80");
        b.set_healthy(false);
        d.set_backends(vec![b]);

        let started = std::time::Instant::now();
        assert!(crate::request_control::wait_for_capacity(&d, &[], &Metrics::new(), &crate::feed::Feed::new()).await.is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn wait_for_capacity_times_out_when_no_vm_arrives() {
        let d = deployment(ScalingPolicy {
            max_replicas: 2,
            cold_start_timeout_secs: 1,
            ..Default::default()
        });
        assert!(crate::request_control::wait_for_capacity(&d, &[], &Metrics::new(), &crate::feed::Feed::new()).await.is_none());
    }

    #[tokio::test]
    async fn wait_for_capacity_returns_a_vm_that_becomes_ready() {
        let d = deployment(ScalingPolicy {
            max_replicas: 2,
            cold_start_timeout_secs: 30,
            ..Default::default()
        });
        d.set_pending(vec![PendingVm::new("sb-1".into())]);

        let d2 = d.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            d2.set_backends(vec![backend("10.0.0.1:80")]);
            d2.ready_signal.notify_waiters();
        });

        let got = crate::request_control::wait_for_capacity(&d, &[], &Metrics::new(), &crate::feed::Feed::new()).await;
        assert_eq!(got.unwrap().peer, "10.0.0.1:80");
    }

    /// The pool can fill between the availability check and the wait; the
    /// re-check inside the loop must catch that rather than hanging.
    #[tokio::test]
    async fn wait_for_capacity_sees_a_vm_that_was_already_ready() {
        let d = deployment(ScalingPolicy {
            max_replicas: 2,
            cold_start_timeout_secs: 30,
            ..Default::default()
        });
        d.set_backends(vec![backend("10.0.0.1:80")]);
        assert!(crate::request_control::wait_for_capacity(&d, &[], &Metrics::new(), &crate::feed::Feed::new()).await.is_some());
    }
}
