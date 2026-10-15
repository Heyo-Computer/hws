//! Process boundary between the manager and one replaceable forwarding worker.
//!
//! A connection is a request.  In particular it is not a reconnectable session:
//! losing it leaves the manager's admission state pinned until the manager has
//! observed that worker exit.
//!
//! The manager may be replaced under a running worker (see `worker.rs`). A
//! request waits for a manager to begin it, and its handshake names the manager
//! that answered, so a broken link can be told apart: the same manager still
//! answering means a fault, a different one (or none) means a restart.
//!
//! **Compatibility.** A worker and a manager from adjacent releases talk to
//! each other across a takeover, so a change to these messages must be one an
//! older peer can read: add fields with defaults, never repurpose one.

use crate::config::SiteSpec;
use crate::metrics::Metrics;
use crate::obs::{Access, LogSink};
use crate::request_control::{HeaderModification, RequestControl, RequestDecision, RequestHead, RequestState};
use crate::siem::SecuritySink;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

const VERSION: u16 = 1;
const MAX_FRAME: usize = 1024 * 1024;

fn check_version(version: u16) -> Result<(), String> {
    (version == VERSION).then_some(()).ok_or_else(|| {
        format!("unsupported request control protocol version {version}")
    })
}

#[derive(Clone)]
pub struct Client {
    path: PathBuf,
    /// How long a request waits for a manager to answer.
    wait: Duration,
}

pub enum BeginError {
    HeadersTooLarge,
    Control(String),
    /// No manager answered within the wait: app-lb is restarting, or stopped.
    Unavailable(String),
}
impl From<String> for BeginError {
    fn from(error: String) -> Self { Self::Control(error) }
}

impl Client {
    pub fn new(path: PathBuf) -> Self {
        Self::with_wait(path, crate::worker::wait_budget())
    }

    pub fn with_wait(path: PathBuf, wait: Duration) -> Self { Self { path, wait } }

    /// Begin a request with whichever manager answers, waiting up to the
    /// budget for one. A manager that goes away mid-begin took whatever it
    /// started with it, so the next one is simply asked again.
    pub async fn begin(&self, head: RequestHead) -> Result<(RemoteRequest, RemoteDecision), BeginError> {
        let begin = ClientMessage::Begin(WireHead::from_head(&head)?);
        if serde_json::to_vec(&begin).map_err(|e| e.to_string())?.len() > MAX_FRAME {
            return Err(BeginError::HeadersTooLarge);
        }
        let deadline = tokio::time::Instant::now() + self.wait;
        loop {
            let error = match handshake(&self.path).await {
                Ok((stream, manager)) => {
                    let mut request = RemoteRequest { stream: Some(stream), backend_id: None, retry_allowed: false, failure_pending: false, completed: false, manager };
                    match request.call(begin.clone()).await {
                        Ok(reply) => {
                            let (decision, backend_id, retry_allowed) = response(reply)?;
                            request.backend_id = backend_id;
                            request.retry_allowed = retry_allowed;
                            return Ok((request, decision));
                        }
                        Err(error) => error,
                    }
                }
                Err(Handshake::Refused(message)) => return Err(BeginError::Control(message)),
                Err(Handshake::Absent(error)) => error,
            };
            if tokio::time::Instant::now() >= deadline {
                return Err(BeginError::Unavailable(error));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

enum Handshake {
    /// Nothing answered, or the answer broke off: worth waiting for.
    Absent(String),
    /// A manager answered and refused: waiting will not change it.
    Refused(String),
}

async fn handshake(path: &std::path::Path) -> Result<(UnixStream, Option<u64>), Handshake> {
    let absent = |e: String| Handshake::Absent(e);
    let mut stream = UnixStream::connect(path).await.map_err(|e| absent(format!("request control connect failed: {e}")))?;
    write_frame(&mut stream, &ClientMessage::Hello { version: VERSION }).await.map_err(absent)?;
    match read_frame::<ServerMessage>(&mut stream).await.map_err(absent)? {
        ServerMessage::Hello { version: VERSION, manager } => Ok((stream, manager)),
        ServerMessage::Hello { version, .. } => Err(Handshake::Refused(format!("request control protocol version mismatch: manager={version}, worker={VERSION}"))),
        ServerMessage::Error { message } => Err(Handshake::Refused(message)),
        _ => Err(Handshake::Refused("request control protocol error: expected handshake".into())),
    }
}

/// The id of the manager answering at `path`. `Ok(None)` from a manager too
/// old to say.
pub async fn hello(path: &std::path::Path) -> Result<Option<u64>, String> {
    match handshake(path).await {
        Ok((_, manager)) => Ok(manager),
        Err(Handshake::Absent(e) | Handshake::Refused(e)) => Err(e),
    }
}

pub struct RemoteRequest {
    stream: Option<UnixStream>,
    backend_id: Option<String>,
    retry_allowed: bool,
    failure_pending: bool,
    completed: bool,
    /// The manager that began this request.
    manager: Option<u64>,
}

impl RemoteRequest {
    pub fn backend_id(&self) -> Option<&str> { self.backend_id.as_deref() }
    pub fn manager(&self) -> Option<u64> { self.manager }
    pub fn connected(&self) -> bool { self.stream.is_some() }

    pub fn connection_failed(&mut self) -> bool {
        self.failure_pending = true;
        self.retry_allowed
    }

    pub async fn continue_login(&mut self, body: &[u8]) -> Result<RemoteDecision, String> {
        let reply = self.call(ClientMessage::ContinueLogin { body: body.to_vec() }).await?;
        let (decision, backend, retry) = response(reply)?;
        self.backend_id = backend;
        self.retry_allowed = retry;
        Ok(decision)
    }

    pub async fn next_peer(&mut self) -> Result<RemotePeer, String> {
        let reply = self.call(ClientMessage::NextPeer).await?;
        match reply {
            ServerMessage::Peer { peer, sandbox_id, retry_allowed } => {
                self.backend_id = Some(sandbox_id.clone());
                self.retry_allowed = retry_allowed;
                Ok(RemotePeer { peer: peer.into_peer()?, sandbox_id })
            }
            ServerMessage::Error { message } => Err(message),
            _ => Err("request control protocol error: expected peer".into()),
        }
    }

    pub async fn forwarding_modifications(&mut self, uri: &http::Uri) -> Result<Vec<HeaderModification>, String> {
        let reply = self.call(ClientMessage::ForwardingModifications { uri: uri.to_string() }).await?;
        match reply {
            ServerMessage::Modifications(values) => values.into_iter().map(WireModification::into_modification).collect(),
            ServerMessage::Error { message } => Err(message),
            _ => Err("request control protocol error: expected forwarding modifications".into()),
        }
    }

    pub async fn complete(&mut self, completion: Completion) -> Result<(), String> {
        if self.completed { return Ok(()); }
        let reply = self.call(ClientMessage::Complete(completion)).await?;
        match reply {
            ServerMessage::Ack => { self.completed = true; self.stream.take(); Ok(()) }
            ServerMessage::Error { message } => Err(message),
            _ => Err("request control protocol error: expected completion acknowledgement".into()),
        }
    }

    async fn call(&mut self, message: ClientMessage) -> Result<ServerMessage, String> {
        let mut stream = self.stream.take().ok_or_else(|| "request control request is closed".to_string())?;
        let failed = std::mem::take(&mut self.failure_pending);
        let terminal = matches!(&message, ClientMessage::Complete(_) | ClientMessage::Cancel);
        let manager = self.manager;
        let (tx, rx) = tokio::sync::oneshot::channel();
        // Frame I/O must survive cancellation of the HTTP future. Otherwise
        // Drop could append Cancel inside a partially written frame or mistake
        // the previous response for the cancellation acknowledgement.
        tokio::spawn(async move {
            let result = async {
                if failed {
                    write_frame(&mut stream, &ClientMessage::ConnectionFailed).await?;
                    match read_frame(&mut stream).await? {
                        ServerMessage::FailureRecorded { .. } => {},
                        _ => return Err("request control protocol error: expected failure acknowledgement".into()),
                    }
                }
                write_frame(&mut stream, &message).await?;
                read_frame(&mut stream).await
            }.await;
            let _ = tx.send(Exchange { stream: Some(stream), result: Some(result), terminal, manager });
        });
        let mut exchange = rx.await.map_err(|_| "request control exchange task lost".to_string())?;
        let result = exchange.result.take().expect("exchange result present");
        if result.is_ok() { self.stream = exchange.stream.take(); }
        result
    }
}

// Cancellation may happen after the sender delivered the response but before
// the HTTP future consumes it. The channel value must own cancellation too.
struct Exchange {
    stream: Option<UnixStream>,
    result: Option<Result<ServerMessage, String>>,
    terminal: bool,
    manager: Option<u64>,
}
impl Drop for Exchange {
    fn drop(&mut self) {
        match self.result.take() {
            Some(Ok(_)) if !self.terminal => {
                if let Some(stream) = self.stream.take() { cancel_owned(stream, false, self.manager); }
            }
            Some(Err(error)) => crate::worker::control_interrupted(self.manager, &error),
            _ => {}
        }
    }
}

impl Drop for RemoteRequest {
    fn drop(&mut self) {
        if self.completed { return; }
        if let Some(stream) = self.stream.take() { cancel_owned(stream, self.failure_pending, self.manager); }
    }
}

fn cancel_owned(mut stream: UnixStream, failed: bool, manager: Option<u64>) {
    // Move ownership into the task; it survives the HTTP context's destructor.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            if failed {
                let recorded = async {
                    write_frame(&mut stream, &ClientMessage::ConnectionFailed).await?;
                    match read_frame::<ServerMessage>(&mut stream).await? {
                        ServerMessage::FailureRecorded { .. } => Ok(()),
                        _ => Err("connection failure was not acknowledged".to_string()),
                    }
                }.await;
                if let Err(error) = recorded {
                    crate::worker::control_interrupted(manager, &error);
                    return;
                }
            }
            if let Err(error) = cancel(&mut stream).await { crate::worker::control_interrupted(manager, &error); }
        });
    }
}

async fn cancel(stream: &mut UnixStream) -> Result<(), String> {
    write_frame(stream, &ClientMessage::Cancel).await?;
    match read_frame::<ServerMessage>(stream).await? {
        ServerMessage::Ack => Ok(()),
        _ => Err("request cancellation was not acknowledged".into()),
    }
}

pub struct RemotePeer {
    pub peer: crate::request_control::Peer,
    pub sandbox_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Completion {
    pub status: Option<u16>,
    pub duration_micros: u64,
    pub bytes: usize,
    pub error: Option<String>,
}

#[derive(Debug)]
pub enum RemoteDecision {
    Respond { status: u16, body: String, content_type: String, headers: Vec<(String, String)>, cache_control: Option<String> },
    ReadLoginBody,
    ServeSite { spec: SiteSpec, path: String },
    Proxy,
}

#[derive(Clone, Serialize, Deserialize)]
enum ClientMessage {
    Hello { version: u16 },
    Begin(WireHead),
    ContinueLogin { body: Vec<u8> },
    NextPeer,
    ConnectionFailed,
    ForwardingModifications { uri: String },
    Complete(Completion),
    Cancel,
}

#[derive(Serialize, Deserialize)]
enum ServerMessage {
    Hello {
        version: u16,
        /// Which manager answered. Absent from a manager older than takeover.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manager: Option<u64>,
    },
    Decision { decision: WireDecision, backend_id: Option<String>, retry_allowed: bool },
    Peer { peer: WirePeer, sandbox_id: String, retry_allowed: bool },
    FailureRecorded { retry_allowed: bool },
    Modifications(Vec<WireModification>),
    Ack,
    Error { message: String },
}

#[derive(Clone, Serialize, Deserialize)]
struct WireHead {
    method: String,
    uri: String,
    headers: Vec<(String, Vec<u8>)>,
    peer: Option<String>,
    tls_terminated: bool,
}

impl WireHead {
    fn from_head(head: &RequestHead) -> Result<Self, String> {
        Ok(Self {
            method: head.method.to_string(), uri: head.uri.to_string(),
            headers: head.headers.iter().map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec())).collect(),
            peer: head.peer.map(|p| p.to_string()), tls_terminated: head.tls_terminated,
        })
    }

    fn into_head(self) -> Result<RequestHead, String> {
        let method = self.method.parse().map_err(|e| format!("invalid request method: {e}"))?;
        let uri = self.uri.parse().map_err(|e| format!("invalid request URI: {e}"))?;
        let mut headers = http::HeaderMap::new();
        for (name, value) in self.headers {
            let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|e| format!("invalid header name: {e}"))?;
            let value = http::HeaderValue::from_bytes(&value).map_err(|e| format!("invalid header value: {e}"))?;
            headers.append(name, value);
        }
        let peer = self.peer.map(|p| p.parse::<SocketAddr>().map_err(|e| format!("invalid peer address: {e}"))).transpose()?;
        Ok(RequestHead { method, uri, headers, peer, tls_terminated: self.tls_terminated })
    }
}

#[derive(Serialize, Deserialize)]
enum WireDecision {
    Respond { status: u16, body: String, content_type: String, headers: Vec<(String, String)>, cache_control: Option<String> },
    ReadLoginBody,
    ServeSite { spec: SiteSpec, path: String },
    Proxy,
}

impl WireDecision {
    fn from_decision(value: RequestDecision) -> Self {
        match value {
            RequestDecision::Respond(r) => Self::Respond { status: r.status, body: r.body, content_type: r.content_type.into(), headers: r.headers.into_iter().map(|(n, v)| (n.to_string(), v)).collect(), cache_control: r.cache_control.map(str::to_string) },
            RequestDecision::ReadLoginBody => Self::ReadLoginBody,
            RequestDecision::ServeSite { spec, path } => Self::ServeSite { spec, path },
            RequestDecision::Proxy => Self::Proxy,
        }
    }

    fn into_remote(self) -> RemoteDecision {
        match self {
            Self::Respond { status, body, content_type, headers, cache_control } => RemoteDecision::Respond { status, body, content_type, headers, cache_control },
            Self::ReadLoginBody => RemoteDecision::ReadLoginBody,
            Self::ServeSite { spec, path } => RemoteDecision::ServeSite { spec, path },
            Self::Proxy => RemoteDecision::Proxy,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct WirePeer { address: String, tls: bool, sni: String }
impl WirePeer {
    fn into_peer(self) -> Result<crate::request_control::Peer, String> {
        Ok(crate::request_control::Peer { address: self.address.parse().map_err(|e| format!("invalid manager peer address: {e}"))?, tls: self.tls, sni: self.sni })
    }
}

#[derive(Serialize, Deserialize)]
enum WireModification { Remove(String), Set(String, Vec<u8>), RewriteUri(String) }
impl WireModification {
    fn from_modification(value: HeaderModification) -> Self {
        match value {
            HeaderModification::Remove(n) => Self::Remove(n.to_string()),
            HeaderModification::Set(n, v) => Self::Set(n.to_string(), v.as_bytes().to_vec()),
            HeaderModification::RewriteUri(v) => Self::RewriteUri(v),
        }
    }
    fn into_modification(self) -> Result<HeaderModification, String> {
        match self {
            Self::Remove(n) => Ok(HeaderModification::Remove(n.parse().map_err(|e| format!("invalid manager header name: {e}"))?)),
            Self::Set(n, v) => Ok(HeaderModification::Set(n.parse().map_err(|e| format!("invalid manager header name: {e}"))?, http::HeaderValue::from_bytes(&v).map_err(|e| format!("invalid manager header value: {e}"))?)),
            Self::RewriteUri(v) => Ok(HeaderModification::RewriteUri(v)),
        }
    }
}

fn response(message: ServerMessage) -> Result<(RemoteDecision, Option<String>, bool), String> {
    match message {
        ServerMessage::Decision { decision, backend_id, retry_allowed } => Ok((decision.into_remote(), backend_id, retry_allowed)),
        ServerMessage::Error { message } => Err(message),
        _ => Err("request control protocol error: expected decision".into()),
    }
}

pub async fn serve(
    mut stream: UnixStream,
    control: Arc<RequestControl>,
    metrics: Arc<Metrics>,
    access_log: Option<LogSink>,
    security: Option<SecuritySink>,
    mut worker_exited: watch::Receiver<bool>,
    manager: u64,
) -> Result<(), String> {
    match read_frame::<ClientMessage>(&mut stream).await? {
        ClientMessage::Hello { version: VERSION } => write_frame(&mut stream, &ServerMessage::Hello { version: VERSION, manager: Some(manager) }).await?,
        ClientMessage::Hello { version } => {
            let error = check_version(version).unwrap_err();
            let _ = write_frame(&mut stream, &ServerMessage::Error { message: error.clone() }).await;
            return Err(error);
        }
        _ => return Err("request control protocol error: handshake required".into()),
    }
    let head = match read_frame::<ClientMessage>(&mut stream).await {
        Ok(ClientMessage::Begin(head)) => head.into_head()?,
        // A worker asking who the manager is, and nothing else.
        Err(_) => return Ok(()),
        Ok(_) => return Err("request control protocol error: Begin required".into()),
    };
    let mut state = RequestState::default();
    let decision = control.decide(&head, &mut state).await;
    if let Err(error) = send_decision(&mut stream, decision, &state).await {
        hold_until_exit(&mut worker_exited, state).await;
        return Err(error);
    }

    // Any failed response write is just as uncertain as a failed read: the
    // worker may have acted on an earlier reply. Keep manager state until its
    // supervisor confirms this exact worker incarnation has exited.
    macro_rules! send {
        ($message:expr) => {
            if let Err(error) = write_frame(&mut stream, &$message).await {
                hold_until_exit(&mut worker_exited, state).await;
                return Err(error);
            }
        };
    }

    loop {
        let message = match read_frame::<ClientMessage>(&mut stream).await {
            Ok(message) => message,
            Err(error) => {
                hold_until_exit(&mut worker_exited, state).await;
                return Err(error);
            }
        };
        match message {
            ClientMessage::ContinueLogin { body } => {
                let decision = control.continue_login(&mut state, &body).await;
                if let Err(error) = send_decision(&mut stream, decision, &state).await {
                    hold_until_exit(&mut worker_exited, state).await;
                    return Err(error);
                }
            }
            ClientMessage::NextPeer => match control.next_peer(&mut state).await {
                Ok(peer) => {
                    // A fleet hop reserves nothing here: its backend is the home
                    // host's, named so access logs say where it went.
                    let sandbox_id = state.backend().map(|b| b.sandbox_id.clone())
                        .or_else(|| state.hop_target().map(|home| format!("{}{home}", crate::fleet_hop::BACKEND_PREFIX)))
                        .ok_or_else(|| "selected peer has no reserved backend".to_string())?;
                    let wire = WirePeer { address: peer.address.to_string(), tls: peer.tls, sni: peer.sni };
                    send!(ServerMessage::Peer { peer: wire, sandbox_id, retry_allowed: state.retry_allowed() });
                }
                Err(error) => send!(ServerMessage::Error { message: error.message.into() }),
            },
            ClientMessage::ConnectionFailed => {
                state.connection_failed();
                send!(ServerMessage::FailureRecorded { retry_allowed: state.retry_allowed() });
            }
            ClientMessage::ForwardingModifications { uri } => {
                let result = uri.parse::<http::Uri>().map_err(|e| format!("invalid forwarding URI: {e}")).and_then(|uri| state.forwarding_modifications(&uri));
                match result {
                    Ok(values) => send!(ServerMessage::Modifications(values.into_iter().map(WireModification::from_modification).collect())),
                    Err(message) => send!(ServerMessage::Error { message }),
                }
            }
            ClientMessage::Complete(completion) => {
                finish(&head, &mut state, &metrics, access_log.as_ref(), security.as_ref(), completion);
                return write_frame(&mut stream, &ServerMessage::Ack).await;
            }
            ClientMessage::Cancel => {
                state.complete();
                return write_frame(&mut stream, &ServerMessage::Ack).await;
            }
            ClientMessage::Hello { .. } | ClientMessage::Begin(_) => {
                let error = protocol_fail(&mut stream, "unexpected request-control message").await.unwrap_err();
                hold_until_exit(&mut worker_exited, state).await;
                return Err(error);
            }
        }
    }
}

async fn send_decision(stream: &mut UnixStream, decision: RequestDecision, state: &RequestState) -> Result<(), String> {
    let mut message = ServerMessage::Decision { decision: WireDecision::from_decision(decision), backend_id: state.backend().map(|b| b.sandbox_id.clone()), retry_allowed: state.retry_allowed() };
    if serde_json::to_vec(&message).map_err(|e| e.to_string())?.len() > MAX_FRAME {
        message = ServerMessage::Decision {
            decision: WireDecision::Respond { status: 500, body: "control response exceeds transport limit\n".into(), content_type: "text/plain; charset=utf-8".into(), headers: vec![], cache_control: Some("no-store".into()) },
            backend_id: None, retry_allowed: false,
        };
    }
    write_frame(stream, &message).await
}

fn finish(head: &RequestHead, state: &mut RequestState, metrics: &Metrics, access_log: Option<&LogSink>, security: Option<&SecuritySink>, completion: Completion) {
    let deployment = state.deployment().map(|d| d.spec.id.clone());
    let backend = state.backend().map(|b| b.sandbox_id.clone());
    state.complete(); // Admission is released before any telemetry is emitted.
    let duration = Duration::from_micros(completion.duration_micros);
    if let Some(id) = deployment.as_deref() { metrics.record_request(id, completion.status, duration); }
    if access_log.is_none() && security.is_none() { return; }
    let method = head.method.as_str();
    let host = head.host();
    let access = Access { deployment: deployment.as_deref(), backend, method, path: head.uri.path(), host: host.as_deref(), status: completion.status, duration, bytes: completion.bytes, client: head.peer.map(|p| p.ip().to_string()), error: completion.error };
    if let Some(sink) = security { sink.observe_access(&access, head.uri.query()); }
    if let Some(sink) = access_log { sink.send_access(access); }
}

async fn hold_until_exit(worker_exited: &mut watch::Receiver<bool>, state: RequestState) {
    while !*worker_exited.borrow() {
        if worker_exited.changed().await.is_err() {
            // Losing the supervisor is not evidence that its worker exited.
            std::future::pending::<()>().await;
        }
    }
    drop(state);
}

async fn protocol_fail(stream: &mut UnixStream, message: &str) -> Result<(), String> {
    let _ = write_frame(stream, &ServerMessage::Error { message: message.into() }).await;
    Err(message.into())
}

pub(crate) async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), String> {
    let body = serde_json::to_vec(value).map_err(|e| format!("request control encode failed: {e}"))?;
    if body.len() > MAX_FRAME { return Err("request control frame exceeds limit".into()); }
    stream.write_all(&(body.len() as u32).to_be_bytes()).await.map_err(|e| format!("request control write failed: {e}"))?;
    stream.write_all(&body).await.map_err(|e| format!("request control write failed: {e}"))
}

pub(crate) async fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<T, String> {
    let length = stream.read_u32().await.map_err(|e| format!("request control read failed: {e}"))? as usize;
    if length > MAX_FRAME { return Err("request control frame exceeds limit".into()); }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.map_err(|e| format!("request control read failed: {e}"))?;
    serde_json::from_slice(&body).map_err(|e| format!("invalid request control frame: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::VmBackend;

    #[tokio::test]
    async fn oversized_headers_are_rejected_before_control_connection() {
        let dir = tempfile::tempdir().unwrap();
        let client = Client::with_wait(dir.path().join("absent"), Duration::ZERO);
        let mut head = RequestHead { method: http::Method::GET, uri: "/".parse().unwrap(), headers: http::HeaderMap::new(), peer: None, tls_terminated: false };
        head.headers.insert("x-large", http::HeaderValue::from_bytes(&vec![b'x'; 300_000]).unwrap());
        assert!(matches!(client.begin(head.clone()).await, Err(BeginError::HeadersTooLarge)));
        head.headers.insert("x-large", http::HeaderValue::from_bytes(&vec![b'x'; 200_000]).unwrap());
        assert!(matches!(client.begin(head).await, Err(BeginError::Unavailable(_))));
    }

    fn head() -> RequestHead {
        RequestHead { method: http::Method::GET, uri: "http://app.example/".parse().unwrap(), headers: http::HeaderMap::new(), peer: None, tls_terminated: false }
    }

    /// A manager that answers one request with a local response.
    async fn answer_one(listener: tokio::net::UnixListener, id: Option<u64>) {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(read_frame::<ClientMessage>(&mut stream).await.unwrap(), ClientMessage::Hello { .. }));
        write_frame(&mut stream, &ServerMessage::Hello { version: VERSION, manager: id }).await.unwrap();
        assert!(matches!(read_frame::<ClientMessage>(&mut stream).await.unwrap(), ClientMessage::Begin(_)));
        let decision = WireDecision::Respond { status: 204, body: String::new(), content_type: "text/plain".into(), headers: vec![], cache_control: None };
        write_frame(&mut stream, &ServerMessage::Decision { decision, backend_id: None, retry_allowed: false }).await.unwrap();
        let _ = read_frame::<ClientMessage>(&mut stream).await;
        let _ = write_frame(&mut stream, &ServerMessage::Ack).await;
    }

    #[tokio::test]
    async fn a_request_waits_for_the_next_manager() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("requests");
        let client = Client::with_wait(path.clone(), Duration::from_secs(5));
        let late = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            answer_one(tokio::net::UnixListener::bind(&path).unwrap(), Some(9)).await;
        });
        let started = std::time::Instant::now();
        let (request, decision) = client.begin(head()).await.ok().expect("begun once a manager answered");
        assert!(started.elapsed() >= Duration::from_millis(300), "it waited");
        assert!(matches!(decision, RemoteDecision::Respond { status: 204, .. }));
        assert_eq!(request.manager(), Some(9));
        drop(request);
        late.await.unwrap();
    }

    #[tokio::test]
    async fn with_no_manager_a_request_is_unavailable_after_the_wait() {
        let dir = tempfile::tempdir().unwrap();
        let client = Client::with_wait(dir.path().join("requests"), Duration::from_millis(300));
        let started = std::time::Instant::now();
        assert!(matches!(client.begin(head()).await, Err(BeginError::Unavailable(_))));
        assert!(started.elapsed() >= Duration::from_millis(300));
    }

    #[tokio::test]
    async fn hello_names_the_manager_and_old_peers_still_read_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("requests");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_frame::<ClientMessage>(&mut stream).await.unwrap();
            write_frame(&mut stream, &ServerMessage::Hello { version: VERSION, manager: Some(42) }).await.unwrap();
        });
        assert_eq!(hello(&path).await.unwrap(), Some(42));
        server.await.unwrap();

        // A worker from before takeover reads a new manager's hello…
        #[derive(Deserialize)]
        enum OldServerMessage { Hello { version: u16 } }
        let new = serde_json::to_vec(&ServerMessage::Hello { version: VERSION, manager: Some(42) }).unwrap();
        assert!(matches!(serde_json::from_slice::<OldServerMessage>(&new).unwrap(), OldServerMessage::Hello { version: VERSION }));
        // …and a new worker reads an old manager's, which names nobody.
        let old = br#"{"Hello":{"version":1}}"#;
        assert!(matches!(serde_json::from_slice::<ServerMessage>(old).unwrap(), ServerMessage::Hello { manager: None, .. }));
    }

    #[tokio::test]
    async fn oversized_local_response_fails_only_that_request() {
        let (mut manager, mut client) = UnixStream::pair().unwrap();
        let response = crate::request_control::ResponseData { status: 200, body: "x".repeat(MAX_FRAME), content_type: "text/plain", headers: vec![], cache_control: None };
        send_decision(&mut manager, RequestDecision::Respond(response), &RequestState::default()).await.unwrap();
        assert!(matches!(read_frame::<ServerMessage>(&mut client).await.unwrap(),
            ServerMessage::Decision { decision: WireDecision::Respond { status: 500, .. }, .. }));
    }

    #[tokio::test]
    async fn drop_records_pending_connect_failure_before_cancellation() {
        let (client, mut manager) = UnixStream::pair().unwrap();
        let mut request = RemoteRequest { stream: Some(client), backend_id: None, retry_allowed: true, failure_pending: false, completed: false, manager: None };
        assert!(request.connection_failed());
        drop(request);
        assert!(matches!(read_frame::<ClientMessage>(&mut manager).await.unwrap(), ClientMessage::ConnectionFailed));
        write_frame(&mut manager, &ServerMessage::FailureRecorded { retry_allowed: true }).await.unwrap();
        assert!(matches!(read_frame::<ClientMessage>(&mut manager).await.unwrap(), ClientMessage::Cancel));
        write_frame(&mut manager, &ServerMessage::Ack).await.unwrap();
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn rejects_oversized_frame_before_allocating_body() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&((MAX_FRAME + 1) as u32).to_be_bytes()).await.unwrap();
        let error = match read_frame::<ClientMessage>(&mut reader).await { Err(error) => error, Ok(_) => panic!("oversized frame accepted") };
        assert!(error.contains("exceeds limit"));
    }

    #[tokio::test]
    async fn unsupported_protocol_version_is_rejected() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        write_frame(&mut writer, &ClientMessage::Hello { version: VERSION + 1 }).await.unwrap();
        let version = match read_frame(&mut reader).await.unwrap() { ClientMessage::Hello { version } => version, _ => panic!("hello not decoded") };
        assert!(check_version(version).unwrap_err().contains("unsupported"));
    }

    #[tokio::test]
    async fn cancelled_exchange_finishes_its_frame_then_acknowledges_cancel() {
        let (client, mut manager) = UnixStream::pair().unwrap();
        let (observed, waiting) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            assert!(matches!(read_frame::<ClientMessage>(&mut manager).await.unwrap(), ClientMessage::NextPeer));
            observed.send(()).unwrap();
            released.await.unwrap();
            write_frame(&mut manager, &ServerMessage::Error { message: "no backend".into() }).await.unwrap();
            assert!(matches!(read_frame::<ClientMessage>(&mut manager).await.unwrap(), ClientMessage::Cancel));
            write_frame(&mut manager, &ServerMessage::Ack).await.unwrap();
        });
        let request = tokio::spawn(async move {
            let mut remote = RemoteRequest { stream: Some(client), backend_id: None, retry_allowed: false, failure_pending: false, completed: false, manager: None };
            remote.next_peer().await
        });
        waiting.await.unwrap();
        request.abort();
        assert!(matches!(request.await, Err(error) if error.is_cancelled()));
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), server).await.unwrap().unwrap();
    }

    #[test]
    fn wire_head_preserves_duplicate_and_non_utf8_headers() {
        let mut headers = http::HeaderMap::new();
        headers.append("cookie", "a=1".parse().unwrap());
        headers.append("cookie", "b=2".parse().unwrap());
        headers.insert("x-bytes", http::HeaderValue::from_bytes(&[0xff]).unwrap());
        let head = RequestHead { method: http::Method::POST, uri: "/x?q=1".parse().unwrap(), headers, peer: Some("[::1]:123".parse().unwrap()), tls_terminated: true };
        let copy = WireHead::from_head(&head).unwrap().into_head().unwrap();
        assert_eq!(copy.headers.get_all("cookie").iter().collect::<Vec<_>>(), vec!["a=1", "b=2"]);
        assert_eq!(copy.headers["x-bytes"].as_bytes(), &[0xff]);
        assert_eq!(copy.peer, head.peer);
        assert_eq!(copy.uri, head.uri);
    }

    #[tokio::test]
    async fn cancellation_after_channel_delivery_still_notifies_manager() {
        let (client, mut manager) = UnixStream::pair().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        assert!(tx.send(Exchange { stream: Some(client), result: Some(Ok(ServerMessage::Error { message: "no backend".into() })), terminal: false, manager: None }).is_ok());
        drop(rx);
        let message = tokio::time::timeout(Duration::from_secs(2), read_frame::<ClientMessage>(&mut manager)).await.unwrap().unwrap();
        assert!(matches!(message, ClientMessage::Cancel));
        write_frame(&mut manager, &ServerMessage::Ack).await.unwrap();
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn disconnected_rpc_keeps_real_reservation_until_child_exit() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(crate::registry::Registry::new(dir.path().join("state")));
        let deployment = registry.upsert(serde_json::from_value(serde_json::json!({
            "id":"app", "routes":[{"host":"app.example"}], "upstreams":["127.0.0.1:8080"]
        })).unwrap());
        let backend = deployment.select(&[]).unwrap();
        let secrets = Arc::new(crate::secrets::SecretStore::new(dir.path().join("secrets"), None));
        let metrics = Arc::new(Metrics::new());
        let control = Arc::new(RequestControl::new(
            registry, metrics.clone(), Arc::new(crate::acme::ChallengeTable::new()),
            Arc::new(crate::auth::Authenticator::new(vec![7; 32], secrets.clone(), None, None)),
            Arc::new(crate::guard::Guard::new(dir.path().join("guard"), true)),
            Arc::new(crate::feed::Feed::new()),
            Arc::new(crate::auth_providers::AuthProviderStore::new(dir.path().join("providers"))), secrets,
        ));
        let (mut client, manager) = UnixStream::pair().unwrap();
        let (exited, witness) = watch::channel(false);
        let server = tokio::spawn(serve(manager, control, metrics, None, None, witness, 7));
        write_frame(&mut client, &ClientMessage::Hello { version: VERSION }).await.unwrap();
        assert!(matches!(read_frame::<ServerMessage>(&mut client).await.unwrap(), ServerMessage::Hello { manager: Some(7), .. }));
        let head = RequestHead { method: http::Method::GET, uri: "http://app.example/".parse().unwrap(), headers: http::HeaderMap::new(), peer: None, tls_terminated: false };
        write_frame(&mut client, &ClientMessage::Begin(WireHead::from_head(&head).unwrap())).await.unwrap();
        assert!(matches!(read_frame::<ServerMessage>(&mut client).await.unwrap(), ServerMessage::Decision { decision: WireDecision::Proxy, .. }));
        write_frame(&mut client, &ClientMessage::NextPeer).await.unwrap();
        assert!(matches!(read_frame::<ServerMessage>(&mut client).await.unwrap(), ServerMessage::Peer { .. }));
        assert_eq!(backend.in_flight(), 1);
        drop(client);
        tokio::task::yield_now().await;
        assert!(!server.is_finished());
        assert_eq!(backend.in_flight(), 1, "control EOF is not drain evidence");
        exited.send(true).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(2), server).await.unwrap().unwrap().is_err());
        assert_eq!(backend.in_flight(), 0);
    }

    #[tokio::test]
    async fn reservation_is_retained_until_confirmed_worker_exit() {
        let backend = Arc::new(VmBackend::new("test".into(), "127.0.0.1:80".parse().unwrap()));
        assert!(backend.try_acquire());
        assert!(backend.try_acquire()); // Another request must remain counted.
        let (tx, mut rx) = watch::channel(false);
        let mut state = RequestState::default();
        state.set_reserved_backend(backend.clone());
        let waiter = tokio::spawn(async move {
            hold_until_exit(&mut rx, state).await;
        });
        tokio::task::yield_now().await;
        assert_eq!(backend.in_flight(), 2);
        tx.send(true).unwrap();
        waiter.await.unwrap();
        assert_eq!(backend.in_flight(), 1);
        backend.release();
    }

    #[tokio::test]
    async fn losing_supervisor_does_not_confirm_exit() {
        let backend = Arc::new(VmBackend::new("test".into(), "127.0.0.1:80".parse().unwrap()));
        assert!(backend.try_acquire());
        let (tx, mut rx) = watch::channel(false);
        let mut state = RequestState::default();
        state.set_reserved_backend(backend.clone());
        let waiter = tokio::spawn(async move { hold_until_exit(&mut rx, state).await; });
        drop(tx);
        tokio::task::yield_now().await;
        assert_eq!(backend.in_flight(), 1);
        assert!(!waiter.is_finished());
        waiter.abort(); // End this test's synthetic supervisor lifetime.
        let _ = waiter.await;
    }
}
