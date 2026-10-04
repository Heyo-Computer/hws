//! AWS Signature Version 4, query-string form, for S3.
//!
//! Copied from `pg-fc/src/s3.rs` (the presigner pg-vm-pool archives with) and
//! trimmed to the signing core, so the two services sign identically and the
//! same AWS test vector pins both. Only `host` is signed; `If-Match` and
//! `If-None-Match` are ordinary headers that need no signature, which is what
//! lets conditional writes ride on a presigned URL. Do not add an `x-amz-*`
//! header to a request without signing it — S3 rejects those unsigned.
//!
//! A shared copy for both services is a follow-up; until then, a fix here
//! belongs in pg-fc as well.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct PresignParams<'a> {
    pub(crate) method: &'a str,
    pub(crate) scheme: &'a str,
    pub(crate) host: &'a str,
    pub(crate) canonical_uri: &'a str,
    pub(crate) region: &'a str,
    pub(crate) access_key: &'a str,
    pub(crate) secret_key: &'a str,
    pub(crate) unix_secs: u64,
    pub(crate) expires: u64,
    /// Additional query params signed into the URL (multipart's `uploads`,
    /// `partNumber`, `uploadId`). Merged and sorted with the `X-Amz-*` set —
    /// SigV4 requires the canonical query in byte order regardless of origin.
    pub(crate) extra_query: &'a [(&'a str, &'a str)],
}

/// The SigV4 signing procedure, decoupled from `S3Config`/wall-clock so a fixed
/// input yields a fixed signature the tests can assert (see AWS's documented
/// example). Service is always `s3`; signed headers are always `host`.
pub(crate) fn presign_core(p: PresignParams) -> String {
    let (date, amz_date) = format_amz_time(p.unix_secs);
    let scope = format!("{date}/{}/s3/aws4_request", p.region);
    let credential = format!("{}/{scope}", p.access_key);

    // Query params that participate in the signature, sorted by key — S3
    // requires the canonical query in byte order, which the sort guarantees
    // even after merging in the caller's extra params.
    let mut query: Vec<(String, String)> = vec![
        ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
        ("X-Amz-Credential".into(), credential),
        ("X-Amz-Date".into(), amz_date.clone()),
        ("X-Amz-Expires".into(), p.expires.to_string()),
        ("X-Amz-SignedHeaders".into(), "host".into()),
    ];
    query.extend(
        p.extra_query
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string())),
    );
    query.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{}={}", encode_uri_component(k), encode_uri_component(v)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_headers = format!("host:{}\n", p.host);
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\nhost\nUNSIGNED-PAYLOAD",
        p.method, p.canonical_uri, canonical_query, canonical_headers
    );

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(sha256(canonical_request.as_bytes()))
    );

    let signing_key = signing_key(p.secret_key, &date, p.region, "s3");
    let signature = hex::encode(hmac(&signing_key, string_to_sign.as_bytes()));

    format!(
        "{}://{}{}?{}&X-Amz-Signature={}",
        p.scheme, p.host, p.canonical_uri, canonical_query, signature
    )
}

/// Derive the SigV4 signing key: HMAC chain over date → region → service →
/// `aws4_request`, seeded with `"AWS4" + secret`.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    hmac(&k_service, b"aws4_request")
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Split `scheme://host[:port]` into `("https"|"http", "host[:port]")`.
/// Defaults to `https` and treats the whole string as host if no scheme.
pub(crate) fn split_scheme_host(url: &str) -> (&str, &str) {
    if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        ("https", url)
    }
}

/// RFC 3986 encode a URI **path**: unreserved chars pass through, `/` is
/// preserved (segment separators), everything else is `%XX`.
pub(crate) fn encode_uri_path(s: &str) -> String {
    encode(s, true)
}

/// RFC 3986 encode a query component: like [`encode_uri_path`] but `/` is also
/// escaped (`%2F`) — required for the slashes inside `X-Amz-Credential`.
fn encode_uri_component(s: &str) -> String {
    encode(s, false)
}

fn encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Format a UNIX timestamp as SigV4's `(YYYYMMDD, YYYYMMDDTHHMMSSZ)` pair, in
/// UTC, with no external date crate. Uses Howard Hinnant's civil-from-days.
pub(crate) fn format_amz_time(secs: u64) -> (String, String) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // days since 1970-01-01 → (year, month, day), Gregorian.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = year + i64::from(month <= 2);

    let date = format!("{year:04}{month:02}{day:02}");
    let datetime = format!("{date}T{hour:02}{min:02}{sec:02}Z");
    (date, datetime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_aws_documented_example() {
        // 2013-05-24T00:00:00Z.
        let unix = 1_369_353_600;
        let url = presign_core(PresignParams {
            method: "GET",
            scheme: "https",
            host: "examplebucket.s3.amazonaws.com",
            canonical_uri: "/test.txt",
            region: "us-east-1",
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            unix_secs: unix,
            expires: 86_400,
            extra_query: &[],
        });
        assert!(
            url.ends_with(
                "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            ),
            "unexpected presigned URL: {url}"
        );
        // Sanity on the non-signature portions.
        assert!(url.starts_with("https://examplebucket.s3.amazonaws.com/test.txt?"));
        assert!(url.contains(
            "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"
        ));
        assert!(url.contains("X-Amz-Date=20130524T000000Z"));
        assert!(url.contains("X-Amz-Expires=86400"));
        assert!(url.contains("X-Amz-SignedHeaders=host"));
    }

    #[test]
    fn head_is_signed_as_its_own_method() {
        let unix = 1_369_353_600;
        let params = |method| PresignParams {
            method,
            scheme: "https",
            host: "examplebucket.s3.amazonaws.com",
            canonical_uri: "/test.txt",
            region: "us-east-1",
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            unix_secs: unix,
            expires: 60,
            extra_query: &[],
        };
        let head = presign_core(params("HEAD"));
        let get = presign_core(params("GET"));
        assert_ne!(
            head, get,
            "HEAD and GET must not share a signature — the method is signed"
        );
        // Everything but the signature is identical, so the difference is the
        // signature itself rather than some incidental URL change.
        let strip = |u: &str| u.split("&X-Amz-Signature=").next().unwrap().to_string();
        assert_eq!(strip(&head), strip(&get));
    }

    #[test]
    fn civil_time_formats_utc() {
        assert_eq!(
            format_amz_time(1_369_353_600),
            ("20130524".into(), "20130524T000000Z".into())
        );
        // Epoch.
        assert_eq!(
            format_amz_time(0),
            ("19700101".into(), "19700101T000000Z".into())
        );
        // A leap-year date with non-zero time: 2024-02-29T13:37:11Z.
        assert_eq!(
            format_amz_time(1_709_213_831),
            ("20240229".into(), "20240229T133711Z".into())
        );
    }

    #[test]
    fn extra_query_params_are_signed_in_sorted_order() {
        let params = |extra: &'static [(&'static str, &'static str)]| PresignParams {
            method: "POST",
            scheme: "https",
            host: "examplebucket.s3.amazonaws.com",
            canonical_uri: "/big.img.zst",
            region: "us-east-1",
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            unix_secs: 1_369_353_600,
            expires: 600,
            extra_query: extra,
        };
        let url = presign_core(params(&[("partNumber", "2"), ("uploadId", "a/b=c")]));
        // Lowercase keys sort after the X-Amz-* block; values are
        // component-encoded (the uploadId's `/` and `=` must not survive raw).
        assert!(
            url.contains("X-Amz-SignedHeaders=host&partNumber=2&uploadId=a%2Fb%3Dc"),
            "unexpected query order/encoding: {url}"
        );
        // A bare `uploads` param canonicalizes as `uploads=`.
        let url = presign_core(params(&[("uploads", "")]));
        assert!(
            url.contains("&uploads=&X-Amz-Signature="),
            "bare uploads param must appear as uploads=: {url}"
        );
        // And the extra params change the signature (they are signed).
        let plain = presign_core(params(&[]));
        let strip = |u: &str| u.split("&X-Amz-Signature=").nth(1).unwrap().to_string();
        assert_ne!(
            strip(&plain),
            strip(&presign_core(params(&[("uploads", "")])))
        );
    }

    #[test]
    fn query_component_escapes_slash_but_path_keeps_it() {
        assert_eq!(encode_uri_component("a/b"), "a%2Fb");
        assert_eq!(encode_uri_path("a/b"), "a/b");
        // Unreserved set is preserved verbatim.
        assert_eq!(encode_uri_component("Az9-_.~"), "Az9-_.~");
    }
}
