//! The seam between the API surface and an actual socket.
//!
//! Everything above this file — the endpoint methods, the wait helpers, the
//! read-modify-write spec logic — is a pure function of what comes back through
//! [`Transport`]. That is what makes it testable: the CLI this crate grew out of
//! had 3,300 lines of command logic with **zero** tests, because exercising any
//! of it meant constructing a client, which meant opening a socket.
//!
//! [`Stub`] is the other implementation, behind `cfg(test)` and the `test-util`
//! feature.

use crate::error::{Credential, Error, Result};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// One request, fully formed. `path` is absolute and already percent-encoded.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    pub path: String,
    /// JSON body. `None` sends no body and no content-type — which matters:
    /// app-lb's build/pull routes take an *optional* body, and axum silently
    /// swallows a malformed one rather than rejecting it.
    pub body: Option<serde_json::Value>,
    /// Overrides the client's default deadline. `exec` needs this: its wall
    /// clock is the command timeout *plus* a possible cold start.
    pub timeout: Option<Duration>,
    /// A plain-text body, for the few routes that take one (moving an
    /// artifact tag sends the digest as text). Ignored when `body` is set.
    pub text: Option<String>,
}

impl Request {
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            body: None,
            timeout: None,
            text: None,
        }
    }

    pub fn json(mut self, body: serde_json::Value) -> Self {
        self.body = Some(body);
        self
    }

    /// Send `body` as `text/plain`.
    pub fn text(mut self, body: impl Into<String>) -> Self {
        self.text = Some(body.into());
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }
}

/// A response, read to the end. Bodies here are small — the largest is a
/// `/metrics` page, and paging is what keeps that bounded.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Somewhere to send a [`Request`].
pub trait Transport: Send + Sync + std::fmt::Debug {
    fn send(&self, req: Request) -> BoxFuture<'_, Result<Response>>;
    /// What credential this transport presents, so a `401` can say something
    /// useful about it.
    fn credential(&self) -> Credential;
}

/// How to authenticate.
#[derive(Debug, Clone, Default)]
pub enum Auth {
    #[default]
    None,
    /// The operator credential. Unscoped, and the one that mints tokens.
    Basic { user: String, password: String },
    /// An app-token. Scoped, revocable, and what an SDK client normally holds.
    Token(String),
}

impl Auth {
    /// The exact `Authorization` header value, or `None`.
    ///
    /// app-lb compares the Basic header **byte for byte** against a string it
    /// precomputed at startup — it never base64-decodes it. So this must be
    /// standard base64 *with* padding, one space after `Basic`, and that
    /// capitalisation. A re-encoded-but-equivalent header is rejected.
    pub fn header(&self) -> Option<String> {
        use base64::Engine;
        match self {
            Self::None => None,
            Self::Basic { user, password } => Some(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
            )),
            Self::Token(t) => Some(format!("Bearer {t}")),
        }
    }

    pub fn credential(&self) -> Credential {
        match self {
            Self::None => Credential::None,
            Self::Basic { .. } => Credential::Basic,
            Self::Token(_) => Credential::Token,
        }
    }
}

/// The real one.
pub struct HttpTransport {
    client: reqwest::Client,
    base: String,
    auth: Auth,
}

impl std::fmt::Debug for HttpTransport {
    /// Hand-written so a `{:?}` of a client cannot print a credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("base", &self.base)
            .field("auth", &self.auth.credential())
            .finish()
    }
}

impl HttpTransport {
    pub fn new(base: impl Into<String>, auth: Auth, timeout: Duration, insecure: bool) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(insecure)
            .build()
            .map_err(Error::Transport)?;
        Ok(Self {
            client,
            base: normalize_base(&base.into()),
            auth,
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn auth(&self) -> &Auth {
        &self.auth
    }
}

impl Transport for HttpTransport {
    fn send(&self, req: Request) -> BoxFuture<'_, Result<Response>> {
        Box::pin(async move {
            let url = format!("{}{}", self.base, req.path);
            let mut b = self
                .client
                .request(
                    reqwest::Method::from_bytes(req.method.as_str().as_bytes())
                        .expect("a fixed set of valid methods"),
                    &url,
                );
            if let Some(h) = self.auth.header() {
                b = b.header(reqwest::header::AUTHORIZATION, h);
            }
            if let Some(body) = &req.body {
                b = b.json(body);
            } else if let Some(text) = &req.text {
                b = b
                    .header(reqwest::header::CONTENT_TYPE, "text/plain")
                    .body(text.clone());
            }
            if let Some(t) = req.timeout {
                b = b.timeout(t);
            }
            let r = b.send().await.map_err(Error::Transport)?;
            let status = r.status().as_u16();
            let body = r.text().await.map_err(Error::Transport)?;
            Ok(Response { status, body })
        })
    }

    fn credential(&self) -> Credential {
        self.auth.credential()
    }
}

/// Accept `host:port` as well as a full URL, and drop a trailing slash so paths
/// don't end up doubled.
pub fn normalize_base(server: &str) -> String {
    let s = server.trim().trim_end_matches('/');
    if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("http://{s}")
    }
}

/// A transport that answers from a script instead of a socket.
///
/// Available to downstream callers under the `test-util` feature, because the
/// thing most worth testing in a program that drives app-lb is what it does when
/// app-lb says no — and that is hard to arrange against a real server.
#[cfg(any(test, feature = "test-util"))]
pub mod stub {
    use super::*;
    use std::sync::Mutex;

    /// A request the stub saw.
    #[derive(Debug, Clone, PartialEq)]
    pub struct Seen {
        pub method: Method,
        pub path: String,
        pub body: Option<serde_json::Value>,
        pub text: Option<String>,
    }

    /// Answers queued replies in order, recording what it was asked.
    #[derive(Debug)]
    pub struct Stub {
        queued: Mutex<std::collections::VecDeque<Response>>,
        pub seen: Mutex<Vec<Seen>>,
        credential: Credential,
    }

    impl Default for Stub {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Stub {
        pub fn new() -> Self {
            Self {
                queued: Mutex::new(Default::default()),
                seen: Mutex::new(Vec::new()),
                credential: Credential::Token,
            }
        }

        /// Queue a reply. Chainable, so a test reads as a transcript.
        pub fn reply(self, status: u16, body: impl Into<String>) -> Self {
            self.queued.lock().unwrap().push_back(Response {
                status,
                body: body.into(),
            });
            self
        }

        pub fn json(self, status: u16, body: serde_json::Value) -> Self {
            self.reply(status, body.to_string())
        }

        /// Every request seen so far, in order.
        pub fn calls(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }

        pub fn call_count(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
    }

    impl Transport for Stub {
        fn send(&self, req: Request) -> BoxFuture<'_, Result<Response>> {
            self.seen.lock().unwrap().push(Seen {
                method: req.method,
                path: req.path.clone(),
                body: req.body.clone(),
                text: req.text.clone(),
            });
            let next = self.queued.lock().unwrap().pop_front();
            Box::pin(async move {
                next.ok_or_else(|| {
                    Error::Invalid(format!(
                        "the stub had no reply queued for {} {}",
                        req.method.as_str(),
                        req.path
                    ))
                })
            })
        }

        fn credential(&self) -> Credential {
            self.credential
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_host_and_port_becomes_a_url() {
        assert_eq!(normalize_base("127.0.0.1:9090"), "http://127.0.0.1:9090");
        assert_eq!(normalize_base("http://x:1/"), "http://x:1");
        assert_eq!(normalize_base("https://x:1///"), "https://x:1");
        assert_eq!(normalize_base("  x:1  "), "http://x:1");
    }

    /// app-lb never decodes this header — it compares the bytes. So the encoding
    /// has to match exactly, and a test that re-derives it independently is the
    /// only thing that would catch a change here.
    #[test]
    fn the_basic_header_is_byte_exact() {
        let a = Auth::Basic {
            user: "admin".into(),
            password: "hunter2".into(),
        };
        assert_eq!(a.header().unwrap(), "Basic YWRtaW46aHVudGVyMg==");
        assert!(a.header().unwrap().starts_with("Basic "), "one space, that case");
    }

    #[test]
    fn a_password_containing_a_colon_still_round_trips() {
        use base64::Engine;
        let a = Auth::Basic {
            user: "admin".into(),
            password: "pass:word".into(),
        };
        let encoded = a.header().unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded.strip_prefix("Basic ").unwrap())
            .unwrap();
        // The *first* colon separates them, so a password may contain more.
        assert_eq!(String::from_utf8(raw).unwrap(), "admin:pass:word");
    }

    #[test]
    fn a_token_rides_as_a_bearer() {
        let a = Auth::Token("applb_7f3a9c2b1e4d_secret".into());
        assert_eq!(a.header().unwrap(), "Bearer applb_7f3a9c2b1e4d_secret");
        assert_eq!(a.credential(), Credential::Token);
    }

    #[test]
    fn no_auth_sends_no_header() {
        assert!(Auth::None.header().is_none());
        assert_eq!(Auth::None.credential(), Credential::None);
    }

    /// A `{:?}` of a client ends up in logs and panic messages.
    #[test]
    fn debug_output_never_contains_a_credential() {
        let t = HttpTransport::new(
            "127.0.0.1:9090",
            Auth::Basic {
                user: "admin".into(),
                password: "hunter2".into(),
            },
            Duration::from_secs(1),
            false,
        )
        .unwrap();
        let rendered = format!("{t:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("YWRtaW4"), "{rendered}");

        let t = HttpTransport::new(
            "127.0.0.1:9090",
            Auth::Token("applb_abc_supersecret".into()),
            Duration::from_secs(1),
            false,
        )
        .unwrap();
        let rendered = format!("{t:?}");
        assert!(!rendered.contains("supersecret"), "{rendered}");
    }
}
