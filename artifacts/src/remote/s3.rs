//! The remote tier on S3 (or anything that speaks its API: R2, MinIO).
//!
//! Every request is a presigned URL from [`super::sigv4`] — the signer pg-fc
//! uses — sent by this process, so the secret never leaves it. Conditional
//! headers ride unsigned, which S3 permits for headers outside `x-amz-*`.
//!
//! A bucket in a different region than configured answers with its real region
//! in `x-amz-bucket-region`; that is latched for the life of the process and
//! the request retried once, the way pg-fc does it.

use super::sigv4::{self, PresignParams};
use super::{Cond, Fetched, ObjectInfo, Reader, SMALL_OBJECT_LIMIT};
use crate::error::{Error, Result};
use std::io::Read;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Defaults for a multipart upload. Four 32 MiB parts in flight is 128 MiB of
/// buffer, which a store VM can afford and which keeps a link busy.
pub const DEFAULT_PART_SIZE: u64 = 32 * 1024 * 1024;
pub const DEFAULT_CONCURRENCY: usize = 4;
/// S3's floor for every part but the last.
const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
/// S3's ceiling on parts per upload.
const MAX_PARTS: u64 = 10_000;

#[derive(Clone)]
pub struct S3Settings {
    pub bucket: String,
    /// Joined in front of every key; empty or ending in `/`.
    pub prefix: String,
    pub region: String,
    /// `https://host[:port]` of an S3-compatible store; path-style when set.
    pub endpoint: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub part_size: u64,
    pub concurrency: usize,
}

impl std::fmt::Debug for S3Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the secret.
        f.debug_struct("S3Settings")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("part_size", &self.part_size)
            .field("concurrency", &self.concurrency)
            .finish_non_exhaustive()
    }
}

pub struct S3Remote {
    cfg: S3Settings,
    discovered_region: Arc<OnceLock<String>>,
    http: reqwest::Client,
}

/// A request to send: method, key (relative), extra signed query, headers.
struct Req<'a> {
    method: reqwest::Method,
    key: &'a str,
    query: Vec<(&'a str, String)>,
    headers: Vec<(&'static str, String)>,
    body: Option<Vec<u8>>,
    timeout: Duration,
}

impl<'a> Req<'a> {
    fn new(method: reqwest::Method, key: &'a str) -> Req<'a> {
        Req {
            method,
            key,
            query: Vec::new(),
            headers: Vec::new(),
            body: None,
            timeout: Duration::from_secs(60),
        }
    }
}

impl S3Remote {
    pub fn new(mut cfg: S3Settings) -> Result<S3Remote> {
        if !cfg.prefix.is_empty() && !cfg.prefix.ends_with('/') {
            cfg.prefix.push('/');
        }
        cfg.part_size = cfg.part_size.max(MIN_PART_SIZE);
        cfg.concurrency = cfg.concurrency.max(1);
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| Error::Remote(format!("building the HTTP client: {e}")))?;
        Ok(S3Remote {
            cfg,
            discovered_region: Arc::new(OnceLock::new()),
            http,
        })
    }

    pub fn describe(&self) -> String {
        format!("s3://{}/{}", self.cfg.bucket, self.cfg.prefix)
    }

    fn region(&self) -> &str {
        self.discovered_region
            .get()
            .map(String::as_str)
            .unwrap_or(&self.cfg.region)
    }

    /// `(scheme, host, canonical_uri)` for a full key. An empty key addresses
    /// the bucket itself, which is what a listing asks.
    fn address(&self, full_key: &str) -> (String, String, String) {
        let path = sigv4::encode_uri_path(full_key);
        match &self.cfg.endpoint {
            Some(ep) => {
                let (scheme, host) = sigv4::split_scheme_host(ep.trim_end_matches('/'));
                let uri = if full_key.is_empty() {
                    format!("/{}", self.cfg.bucket)
                } else {
                    format!("/{}/{path}", self.cfg.bucket)
                };
                (scheme.to_string(), host.to_string(), uri)
            }
            None => (
                "https".to_string(),
                format!("{}.s3.{}.amazonaws.com", self.cfg.bucket, self.region()),
                format!("/{path}"),
            ),
        }
    }

    fn url(&self, method: &str, full_key: &str, query: &[(&str, String)]) -> String {
        let (scheme, host, uri) = self.address(full_key);
        let q: Vec<(&str, &str)> = query.iter().map(|(k, v)| (*k, v.as_str())).collect();
        sigv4::presign_core(PresignParams {
            method,
            scheme: &scheme,
            host: &host,
            canonical_uri: &uri,
            region: self.region(),
            access_key: &self.cfg.access_key_id,
            secret_key: &self.cfg.secret_access_key,
            unix_secs: sigv4::now_unix(),
            expires: 900,
            extra_query: &q,
        })
    }

    fn full_key(&self, key: &str) -> String {
        format!("{}{key}", self.cfg.prefix)
    }

    /// Send one request, following a region redirect once.
    async fn send(&self, req: Req<'_>) -> Result<reqwest::Response> {
        let full = if req.key.is_empty() {
            String::new()
        } else {
            self.full_key(req.key)
        };
        for attempt in 0..2 {
            let url = self.url(req.method.as_str(), &full, &req.query);
            let mut b = self
                .http
                .request(req.method.clone(), &url)
                .timeout(req.timeout);
            for (k, v) in &req.headers {
                b = b.header(*k, v);
            }
            if let Some(body) = &req.body {
                b = b.body(body.clone());
            }
            let resp = b.send().await.map_err(|e| {
                Error::Remote(format!("{} {}: {e}", req.method, self.show(req.key)))
            })?;
            let real = resp
                .headers()
                .get("x-amz-bucket-region")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            if attempt == 0
                && self.cfg.endpoint.is_none()
                && let Some(real) = real
                && real != self.region()
                && (resp.status().is_redirection()
                    || resp.status() == reqwest::StatusCode::FORBIDDEN
                    || resp.status() == reqwest::StatusCode::BAD_REQUEST)
            {
                tracing::warn!(
                    bucket = %self.cfg.bucket,
                    configured = %self.region(),
                    actual = %real,
                    "bucket is in another region; using it from now on (set ART_S3_REGION to skip this)"
                );
                let _ = self.discovered_region.set(real);
                continue;
            }
            return Ok(resp);
        }
        unreachable!("the loop returns on its second pass")
    }

    fn show(&self, key: &str) -> String {
        format!("s3://{}/{}{key}", self.cfg.bucket, self.cfg.prefix)
    }

    async fn fail(&self, what: &str, key: &str, resp: reqwest::Response) -> Error {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Error::Remote(format!(
            "{what} {} returned {status}: {}",
            self.show(key),
            truncate(body.trim(), 400)
        ))
    }

    pub async fn head(&self, key: &str) -> Result<Option<ObjectInfo>> {
        let resp = self.send(Req::new(reqwest::Method::HEAD, key)).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(self.fail("HEAD", key, resp).await);
        }
        let h = resp.headers();
        let get = |n: &str| h.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
        Ok(Some(ObjectInfo {
            key: key.to_string(),
            // The header, never `content_length()`: a HEAD has no body, and
            // reqwest reports the body's length.
            size: get("content-length")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0),
            etag: get("etag").unwrap_or_default(),
            modified: get("last-modified").and_then(|v| super::parse_http_date(&v)),
        }))
    }

    pub async fn get(&self, key: &str, if_none_match: Option<&str>) -> Result<Fetched> {
        let mut req = Req::new(reqwest::Method::GET, key);
        if let Some(etag) = if_none_match {
            req.headers.push(("if-none-match", etag.to_string()));
        }
        let resp = self.send(req).await?;
        match resp.status() {
            reqwest::StatusCode::NOT_FOUND => return Ok(Fetched::NotFound),
            reqwest::StatusCode::NOT_MODIFIED => return Ok(Fetched::NotModified),
            s if !s.is_success() => return Err(self.fail("GET", key, resp).await),
            _ => {}
        }
        if resp
            .content_length()
            .is_some_and(|n| n > SMALL_OBJECT_LIMIT)
        {
            return Err(Error::Remote(format!(
                "{} is too large to read whole",
                self.show(key)
            )));
        }
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::Remote(format!("GET {}: {e}", self.show(key))))?;
        Ok(Fetched::Found {
            body: body.to_vec(),
            etag,
        })
    }

    pub async fn open(&self, key: &str) -> Result<Option<Reader>> {
        let mut req = Req::new(reqwest::Method::GET, key);
        // A body may be gigabytes; the timeout covers the whole transfer.
        req.timeout = Duration::from_secs(6 * 3600);
        let resp = self.send(req).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(self.fail("GET", key, resp).await);
        }
        use futures_util::TryStreamExt;
        let stream = resp.bytes_stream().map_err(std::io::Error::other);
        Ok(Some(Box::new(tokio_util::io::StreamReader::new(stream))))
    }

    pub async fn put(&self, key: &str, body: Vec<u8>, cond: Cond) -> Result<String> {
        let mut req = Req::new(reqwest::Method::PUT, key);
        match &cond {
            Cond::Always => {}
            Cond::IfAbsent => req.headers.push(("if-none-match", "*".into())),
            Cond::IfMatch(etag) => req.headers.push(("if-match", etag.clone())),
        }
        req.body = Some(body);
        req.timeout = Duration::from_secs(300);
        let resp = self.send(req).await?;
        match resp.status() {
            // 409 is S3's answer to two conditional writes racing on one key;
            // the loser should behave exactly as if it had seen a 412.
            reqwest::StatusCode::PRECONDITION_FAILED | reqwest::StatusCode::CONFLICT => Err(
                Error::PreconditionFailed(format!("{} has changed", self.show(key))),
            ),
            // `If-Match` on an object that is not there.
            reqwest::StatusCode::NOT_FOUND if matches!(cond, Cond::IfMatch(_)) => Err(
                Error::PreconditionFailed(format!("{} does not exist", self.show(key))),
            ),
            s if s.is_success() => Ok(resp
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()),
            _ => Err(self.fail("PUT", key, resp).await),
        }
    }

    pub async fn upload(&self, key: &str, reader: Box<dyn Read + Send>, len: u64) -> Result<()> {
        let part_size = self
            .cfg
            .part_size
            .max(len.div_ceil(MAX_PARTS))
            .max(MIN_PART_SIZE);
        if len <= part_size {
            let body = read_part(reader, len).await?.1;
            self.put(key, body, Cond::Always).await?;
            return Ok(());
        }

        let upload_id = self.initiate(key).await?;
        match self
            .upload_parts(key, &upload_id, reader, len, part_size)
            .await
        {
            Ok(parts) => {
                if let Err(e) = self.complete(key, &upload_id, &parts).await {
                    self.abort(key, &upload_id).await;
                    return Err(e);
                }
                Ok(())
            }
            Err(e) => {
                self.abort(key, &upload_id).await;
                Err(e)
            }
        }
    }

    async fn upload_parts(
        &self,
        key: &str,
        upload_id: &str,
        mut reader: Box<dyn Read + Send>,
        len: u64,
        part_size: u64,
    ) -> Result<Vec<(u32, String)>> {
        let mut inflight = tokio::task::JoinSet::new();
        let mut parts = Vec::new();
        let mut sent = 0u64;
        let mut number = 0u32;
        while sent < len {
            let want = part_size.min(len - sent);
            let (r, body) = read_part(reader, want).await?;
            reader = r;
            sent += want;
            number += 1;
            let url = self.url(
                "PUT",
                &self.full_key(key),
                &[
                    ("partNumber", number.to_string()),
                    ("uploadId", upload_id.to_string()),
                ],
            );
            let http = self.http.clone();
            let shown = self.show(key);
            inflight.spawn(async move {
                let resp = http
                    .put(&url)
                    .body(body)
                    .timeout(Duration::from_secs(1800))
                    .send()
                    .await
                    .map_err(|e| Error::Remote(format!("part {number} of {shown}: {e}")))?;
                if !resp.status().is_success() {
                    return Err(Error::Remote(format!(
                        "part {number} of {shown} returned {}",
                        resp.status()
                    )));
                }
                let etag = resp
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
                    .ok_or_else(|| {
                        Error::Remote(format!(
                            "part {number} of {shown} came back without an ETag"
                        ))
                    })?;
                Ok::<_, Error>((number, etag))
            });
            if inflight.len() >= self.cfg.concurrency
                && let Some(done) = inflight.join_next().await
            {
                parts.push(joined(done)?);
            }
        }
        while let Some(done) = inflight.join_next().await {
            parts.push(joined(done)?);
        }
        parts.sort_by_key(|(n, _)| *n);
        Ok(parts)
    }

    async fn initiate(&self, key: &str) -> Result<String> {
        let mut req = Req::new(reqwest::Method::POST, key);
        req.query.push(("uploads", String::new()));
        let resp = self.send(req).await?;
        if !resp.status().is_success() {
            return Err(self.fail("initiating multipart upload of", key, resp).await);
        }
        let body = resp.text().await.unwrap_or_default();
        xml_text(&body, "UploadId").map(unescape).ok_or_else(|| {
            Error::Remote(format!(
                "multipart initiate for {} carried no UploadId",
                self.show(key)
            ))
        })
    }

    async fn complete(&self, key: &str, upload_id: &str, parts: &[(u32, String)]) -> Result<()> {
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (n, etag) in parts {
            xml.push_str(&format!(
                "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
            ));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let mut req = Req::new(reqwest::Method::POST, key);
        req.query.push(("uploadId", upload_id.to_string()));
        req.body = Some(xml.into_bytes());
        req.timeout = Duration::from_secs(600);
        let resp = self.send(req).await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        // A 200 can still carry an <Error>: S3 streams whitespace while it
        // assembles the parts and reports failure inside the body.
        if !status.is_success() || !body.contains("CompleteMultipartUploadResult") {
            return Err(Error::Remote(format!(
                "completing multipart upload of {} failed ({status}): {}",
                self.show(key),
                truncate(body.trim(), 400)
            )));
        }
        Ok(())
    }

    /// Best effort: a failed abort leaves parts the bucket's lifecycle rule
    /// ("abort incomplete multipart uploads after a day") cleans up.
    async fn abort(&self, key: &str, upload_id: &str) {
        let mut req = Req::new(reqwest::Method::DELETE, key);
        req.query.push(("uploadId", upload_id.to_string()));
        if let Err(e) = self.send(req).await {
            tracing::warn!(key = %self.show(key), error = %e, "aborting a multipart upload failed");
        }
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        let resp = self.send(Req::new(reqwest::Method::DELETE, key)).await?;
        if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        Err(self.fail("DELETE", key, resp).await)
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<ObjectInfo>> {
        let full_prefix = self.full_key(prefix);
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut req = Req::new(reqwest::Method::GET, "");
            req.query.push(("list-type", "2".into()));
            req.query.push(("prefix", full_prefix.clone()));
            if let Some(t) = &token {
                req.query.push(("continuation-token", t.clone()));
            }
            let resp = self.send(req).await?;
            if !resp.status().is_success() {
                return Err(self.fail("listing", prefix, resp).await);
            }
            let body = resp
                .text()
                .await
                .map_err(|e| Error::Remote(format!("listing {}: {e}", self.show(prefix))))?;
            for c in xml_blocks(&body, "Contents") {
                let Some(key) = xml_text(c, "Key").map(unescape) else {
                    continue;
                };
                let Some(rel) = key.strip_prefix(&self.cfg.prefix) else {
                    continue;
                };
                out.push(ObjectInfo {
                    key: rel.to_string(),
                    size: xml_text(c, "Size")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0),
                    etag: xml_text(c, "ETag").map(unescape).unwrap_or_default(),
                    modified: xml_text(c, "LastModified").and_then(super::parse_iso8601),
                });
            }
            if xml_text(&body, "IsTruncated") == Some("true") {
                token = xml_text(&body, "NextContinuationToken").map(unescape);
                if token.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(out)
    }
}

/// Read exactly `len` bytes from a blocking reader without blocking the
/// runtime. The reader comes back so the next part can continue from it.
async fn read_part(
    mut reader: Box<dyn Read + Send>,
    len: u64,
) -> Result<(Box<dyn Read + Send>, Vec<u8>)> {
    crate::store::run_blocking(move || {
        let mut buf = vec![0u8; len as usize];
        reader
            .read_exact(&mut buf)
            .map_err(|e| Error::Remote(format!("reading the upload: {e}")))?;
        Ok((reader, buf))
    })
    .await
}

fn joined(
    r: std::result::Result<Result<(u32, String)>, tokio::task::JoinError>,
) -> Result<(u32, String)> {
    r.map_err(|e| Error::Remote(format!("upload task: {e}")))?
}

/// First text content of `<tag>…</tag>`. S3's responses are flat enough that
/// a substring scan beats an XML dependency — the same call pg-fc made.
fn xml_text<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(body[start..end].trim())
}

/// Every `<tag>…</tag>` block, in order.
fn xml_blocks<'a>(body: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(s) = rest.find(&open) {
        let after = &rest[s + open.len()..];
        let Some(e) = after.find(&close) else { break };
        out.push(&after[..e]);
        rest = &after[e + close.len()..];
    }
    out
}

/// The five predefined XML entities. ETags arrive as `&quot;…&quot;`.
fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn truncate(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(endpoint: Option<&str>) -> S3Settings {
        S3Settings {
            bucket: "wb".into(),
            prefix: "art".into(),
            region: "us-east-1".into(),
            endpoint: endpoint.map(str::to_string),
            access_key_id: "AK".into(),
            secret_access_key: "sk".into(),
            part_size: DEFAULT_PART_SIZE,
            concurrency: DEFAULT_CONCURRENCY,
        }
    }

    #[test]
    fn addresses_keys_with_the_prefix_and_keeps_colons_signable() {
        let r = S3Remote::new(settings(None)).unwrap();
        let (scheme, host, uri) = r.address(&r.full_key("tags/heyo/postgres:16"));
        assert_eq!(scheme, "https");
        assert_eq!(host, "wb.s3.us-east-1.amazonaws.com");
        // ':' is not unreserved, so it is percent-encoded in the canonical URI
        // and the URL alike — the signature covers the same bytes S3 sees.
        assert_eq!(uri, "/art/tags/heyo/postgres%3A16");

        let r = S3Remote::new(settings(Some("http://minio:9000/"))).unwrap();
        let (scheme, host, uri) = r.address("");
        assert_eq!(
            (scheme.as_str(), host.as_str(), uri.as_str()),
            ("http", "minio:9000", "/wb")
        );
        assert_eq!(r.address("art/x").2, "/wb/art/x");
    }

    #[test]
    fn listing_xml_parses_keys_etags_and_pages() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult><Name>wb</Name><Prefix>art/tags/</Prefix><KeyCount>2</KeyCount>
<IsTruncated>true</IsTruncated><NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>
<Contents><Key>art/tags/a&amp;b</Key><LastModified>2024-02-29T13:37:11.000Z</LastModified><ETag>&quot;9b2cf535f27731c974343645a3985328&quot;</ETag><Size>65</Size></Contents>
<Contents><Key>art/tags/heyo/pg:16</Key><LastModified>2024-02-29T13:37:12.000Z</LastModified><ETag>&quot;x&quot;</ETag><Size>65</Size></Contents>
</ListBucketResult>"#;
        let blocks = xml_blocks(body, "Contents");
        assert_eq!(blocks.len(), 2);
        assert_eq!(
            xml_text(blocks[0], "Key").map(unescape).unwrap(),
            "art/tags/a&b"
        );
        assert_eq!(
            xml_text(blocks[0], "ETag").map(unescape).unwrap(),
            "\"9b2cf535f27731c974343645a3985328\""
        );
        assert_eq!(xml_text(body, "IsTruncated"), Some("true"));
        assert!(xml_text(body, "NextContinuationToken").is_some());
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let s = format!("{:?}", settings(None));
        assert!(!s.contains("sk"), "{s}");
    }
}
