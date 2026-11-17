//! Guest readiness probing.
//!
//! The daemon has no event stream or boot-complete signal we can subscribe to
//! (its Firecracker driver watches the serial console for a `HEYVM_READY`
//! marker, but never surfaces that over HTTP). Combined with `wait_for_ready`
//! being unreliable, that leaves probing the guest ourselves as the only honest
//! way to know a VM can serve.

use crate::config::HealthCheck;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Probe `addr`, returning whether the guest is serving.
///
/// With `check.path` set this does a minimal HTTP GET and requires a non-5xx
/// status; otherwise a successful TCP connect is enough. `expected_header`
/// instead requires 2xx and one exact identity header, within 16 KiB. Any error is just
/// "not ready" — a booting VM refuses connections, which is expected, so this
/// deliberately doesn't distinguish failure modes.
pub async fn probe(addr: SocketAddr, check: &HealthCheck) -> bool {
    let target = match check.port {
        Some(p) => SocketAddr::new(addr.ip(), p),
        None => addr,
    };
    let timeout = Duration::from_secs(check.timeout_secs.max(1));

    match tokio::time::timeout(timeout, probe_inner(target, check.path.as_deref(), check.expected_header.as_ref())).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            tracing::trace!(%target, error = %e, "health probe failed");
            false
        }
        Err(_) => {
            tracing::trace!(%target, "health probe timed out");
            false
        }
    }
}

/// Probe an HTTPS static upstream by hostname, retaining normal CA/hostname
/// verification (and therefore using `host` as TLS SNI). Unlike the plaintext
/// probe, DNS must not be replaced with a resolved IP or certificate checking
/// would verify the wrong identity.
pub async fn probe_https(address: &str, host: &str, check: &HealthCheck) -> bool {
    let port = check.port.unwrap_or_else(|| {
        address.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(443)
    });
    let path = check.path.as_deref().unwrap_or("/");
    let host = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    let url = format!("https://{host}:{port}{path}");
    let timeout = Duration::from_secs(check.timeout_secs.max(1));
    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };
    match client.get(url).send().await {
        Ok(response) => match &check.expected_header {
            None => response.status().as_u16() < 500,
            Some(expected) => response.status().is_success() && {
                let values: Vec<_> = response.headers().get_all(&expected.name).iter().collect();
                values.len() == 1 && values[0].as_bytes() == expected.value.as_bytes()
            },
        },
        Err(error) => {
            tracing::trace!(%address, %error, "HTTPS health probe failed");
            false
        }
    }
}

/// One plain-HTTP `GET path` against `target`, returning the status code (or
/// why there was none) rather than a verdict. For callers that judge the
/// status themselves — the alerting plugin's checks, which may expect a
/// particular code. No redirects are followed: the request is one exchange.
pub async fn probe_status(target: SocketAddr, path: &str, timeout: Duration) -> Result<u16, String> {
    let exchange = async {
        let mut stream = TcpStream::connect(target).await?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: app-lb/health\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await?;
        parse_status(&buf[..n]).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed or empty HTTP response")
        })
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok(code)) => Ok(code),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("timed out after {}s", timeout.as_secs())),
    }
}

/// [`probe_status`] for an HTTPS static upstream, verified as [`probe_https`]
/// verifies one.
pub async fn probe_https_status(address: &str, host: &str, path: &str, timeout: Duration) -> Result<u16, String> {
    let port = address.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).unwrap_or(443);
    let host = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    client
        .get(format!("https://{host}:{port}{path}"))
        .send()
        .await
        .map(|r| r.status().as_u16())
        .map_err(|e| e.without_url().to_string())
}

async fn probe_inner(target: SocketAddr, path: Option<&str>, expected: Option<&crate::config::ExpectedHeader>) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(target).await?;
    let Some(path) = path else {
        if expected.is_some() { return Err(std::io::Error::other("identity assertion requires HTTP")); }
        return Ok(()); // TCP connect was the whole check.
    };

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: app-lb/health\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    if let Some(expected) = expected {
        let mut head = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 { return Err(std::io::Error::other("incomplete readiness headers")); }
            head.extend_from_slice(&chunk[..n]);
            if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                if end + 4 > 16 * 1024 { return Err(std::io::Error::other("readiness headers exceed 16 KiB")); }
                return if expected_response(&head[..end + 4], expected) { Ok(()) }
                    else { Err(std::io::Error::other("readiness identity or status mismatch")) };
            }
            if head.len() >= 16 * 1024 { return Err(std::io::Error::other("readiness headers exceed 16 KiB")); }
        }
    }

    // The status line is all we need, and it arrives in the first packet.
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "guest closed connection without responding",
        ));
    }

    match parse_status(&buf[..n]) {
        Some(code) if code < 500 => Ok(()),
        Some(code) => Err(std::io::Error::other(format!("unhealthy status {code}"))),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed HTTP response",
        )),
    }
}

fn expected_response(head: &[u8], expected: &crate::config::ExpectedHeader) -> bool {
    if !head.starts_with(b"HTTP/1.1 ") && !head.starts_with(b"HTTP/1.0 ") { return false; }
    if !parse_status(head).is_some_and(|code| (200..300).contains(&code)) { return false; }
    if http::HeaderName::from_bytes(expected.name.as_bytes()).is_err() || http::HeaderValue::from_str(&expected.value).is_err() { return false; }
    let Ok(text) = std::str::from_utf8(head) else { return false; };
    let mut matched = false;
    for line in text.split("\r\n").skip(1).take_while(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else { return false; };
        if http::HeaderName::from_bytes(name.as_bytes()).is_err() { return false; }
        if name.eq_ignore_ascii_case(&expected.name) {
            if matched || value.trim() != expected.value { return false; }
            matched = true;
        }
    }
    matched
}

/// Pull the status code out of an HTTP status line: `HTTP/1.1 200 OK`.
fn parse_status(buf: &[u8]) -> Option<u16> {
    let head = std::str::from_utf8(buf).ok()?;
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parses_status_lines() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.0 404 Not Found\r\n"), Some(404));
        assert_eq!(
            parse_status(b"HTTP/1.1 503 Service Unavailable\r\n"),
            Some(503)
        );
        assert_eq!(parse_status(b"garbage"), None);
        assert_eq!(parse_status(b"NOTHTTP 200 OK"), None);
    }

    #[tokio::test]
    async fn tcp_only_probe_passes_on_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let check = HealthCheck {
            expected_header: None,
            path: None,
            port: None,
            timeout_secs: 2,
        };
        assert!(probe(addr, &check).await);
    }

    #[tokio::test]
    async fn probe_fails_when_nothing_is_listening() {
        // Bind then drop to get a port nothing is on.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let check = HealthCheck::default();
        assert!(!probe(addr, &check).await);
    }

    async fn serve_once(response: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(response.as_bytes()).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn http_probe_accepts_2xx() {
        let addr = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        assert!(probe(addr, &HealthCheck::default()).await);
    }

    #[tokio::test]
    async fn http_probe_accepts_non_5xx() {
        // A 404 still proves the guest's HTTP stack is up and serving.
        let addr = serve_once("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
        assert!(probe(addr, &HealthCheck::default()).await);
    }

    #[tokio::test]
    async fn http_probe_rejects_5xx() {
        let addr =
            serve_once("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n").await;
        assert!(!probe(addr, &HealthCheck::default()).await);
    }

    #[tokio::test]
    async fn http_probe_rejects_a_silent_guest() {
        // Accepts the connection but never responds: a TCP-only check would
        // pass here, which is exactly why the HTTP path exists.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _keep = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let check = HealthCheck {
            expected_header: None,
            path: Some("/".into()),
            port: None,
            timeout_secs: 1,
        };
        assert!(!probe(addr, &check).await);
    }

    #[tokio::test]
    async fn rollout_identity_requires_exact_header_2xx_and_complete_bounded_headers() {
        let check = HealthCheck { expected_header: Some(crate::config::ExpectedHeader {
            name: "x-heyo-revision".into(), value: "abc123".into(),
        }), ..Default::default() };
        for (response, expected) in [
            ("HTTP/1.1 200 OK\r\nX-Heyo-Revision: abc123\r\n\r\n".to_string(), true),
            ("HTTP/1.1 204 OK\r\nx-heyo-revision: abc123\r\n\r\n".into(), true),
            ("HTTP/1.1 200 OK\r\n\r\n".into(), false), // old baked-in listener
            ("HTTP/1.1 200 OK\r\nx-heyo-revision: old\r\n\r\n".into(), false),
            ("HTTP/1.1 404 Missing\r\nx-heyo-revision: abc123\r\n\r\n".into(), false),
            ("HTTP/1.1 302 Found\r\nx-heyo-revision: abc123\r\n\r\n".into(), false),
            ("HTTP/1.1 503 Error\r\nx-heyo-revision: abc123\r\n\r\n".into(), false),
            ("HTTP/1.1 200 OK\r\nx-heyo-revision: abc123\r\nx-heyo-revision: abc123\r\n\r\n".into(), false),
            ("HTTP/1.1 200 OK\r\nx-heyo-revision: abc123".into(), false),
            (format!("HTTP/1.1 200 OK\r\nx-pad: {}\r\nx-heyo-revision: abc123\r\n\r\n", "x".repeat(17 * 1024)), false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut req = [0; 1024]; let _ = socket.read(&mut req).await;
                for fragment in response.as_bytes().chunks(7) {
                    if socket.write_all(fragment).await.is_err() { break; }
                    tokio::task::yield_now().await;
                }
            });
            assert_eq!(probe(addr, &check).await, expected);
            server.await.unwrap();
        }
    }
}
