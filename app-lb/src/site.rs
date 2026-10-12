//! Serving a static site off disk.
//!
//! The third backend kind: no VM, no upstream, no pool. A request routed to a
//! `site` deployment is answered here, out of a directory on the app-lb host —
//! what nginx's `root` or a CloudFront origin does.
//!
//! Deliberately small. There are no rewrites, no per-location blocks and no
//! directory listings; a site that needs those wants a real web server behind a
//! `proxy_pass` deployment. What is here is what a static host cannot be correct
//! without: safe path resolution, an index, a 404, content types, conditional
//! requests, and byte ranges.
//!
//! The security property that matters is in [`resolve`]: **nothing outside the
//! configured root is ever served**, including through `..`, an encoded `..`, an
//! absolute path, or a symlink pointing out of the tree.

use crate::config::SiteSpec;
use std::path::{Component, Path, PathBuf};

/// How much of a file is read and written at a time.
///
/// Everything is streamed rather than read whole: with a fleet of sites serving
/// large assets, reading each response fully into memory would hold every
/// concurrent download's full size in RSS at once.
pub const STREAM_CHUNK: usize = 64 * 1024;

/// Whether a site's root can serve anything, as the admin API reports it.
///
/// The root is a directory on the app-lb host. A site registered from
/// somewhere else (an agent's sandbox, a laptop) names a path that exists
/// *there*, so the spec validates, the deployment registers, and every request
/// 404s with nothing to say why. This status is what says why.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RootStatus {
    pub root: String,
    /// `ok`, `missing`, `not_a_directory`, `unreadable` or `empty`.
    pub status: &'static str,
    /// Whether `index` is a file in the root; `None` when no index is set or
    /// the root cannot be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

const FILL_HINT: &str = "site.root is a directory on the app-lb host, not on the machine that \
    registered this deployment. Put files there with `build` (a git repo, copied in by \
    POST /deployments/:id/build), `artifact` (a bundle from an art store, POST …/pull) or \
    `update` (commands run on this host, POST …/update)";

pub fn root_status(spec: &SiteSpec) -> RootStatus {
    let root = Path::new(spec.root.trim());
    let mk = |status, index_present, hint: Option<String>| RootStatus {
        root: spec.root.clone(),
        status,
        index_present,
        hint,
    };
    let meta = match std::fs::metadata(root) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return mk("missing", None, Some(format!("{} does not exist. {FILL_HINT}", spec.root)));
        }
        Err(e) => return mk("unreadable", None, Some(format!("{}: {e}", spec.root))),
    };
    if !meta.is_dir() {
        return mk("not_a_directory", None, Some(format!("{} is not a directory", spec.root)));
    }
    let mut entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(e) => {
            return mk(
                "unreadable",
                None,
                Some(format!("{}: {e} (app-lb runs as {})", spec.root, crate::jobs::whoami())),
            );
        }
    };
    if entries.next().is_none() {
        return mk("empty", None, Some(format!("{} is empty. {FILL_HINT}", spec.root)));
    }
    let index = spec.index.trim();
    if index.is_empty() {
        return mk("ok", None, None);
    }
    let present = root.join(index).is_file();
    let hint = (!present).then(|| {
        format!(
            "{index} is not at the top of {}, so `/` will 404{}",
            spec.root,
            if spec.spa { " (and so will every SPA fallback)" } else { "" }
        )
    });
    mk("ok", Some(present), hint)
}

/// What a request to a site resolved to.
#[derive(Debug)]
pub enum Resolved {
    /// Serve this file with a 200 (or a 304, if the validators match).
    File(PathBuf),
    /// Nothing matched. Carries the custom 404 body to serve, if the site
    /// configures one and it exists.
    NotFound(Option<PathBuf>),
    /// The path named a directory but the request had no trailing slash.
    /// Relative links inside the page would otherwise resolve one level up.
    Redirect(String),
}

/// Turn a request path into a file inside the site root, or say why not.
///
/// Every component is validated *before* touching the filesystem, and the
/// result is then confirmed to still be under the root after symlinks are
/// followed. Both halves are necessary: the first rejects `..` that never
/// existed on disk, and the second catches a symlink inside the root pointing
/// outside it — which no amount of lexical checking can see.
pub fn resolve(spec: &SiteSpec, request_path: &str) -> Resolved {
    let root = Path::new(&spec.root);
    let not_found = || Resolved::NotFound(existing_page(root, spec.not_found.as_deref()));

    // The path arrives percent-encoded; a decoded `%2e%2e` is a `..` that a
    // check on the raw string would miss entirely.
    let Some(decoded) = percent_decode(request_path) else {
        return not_found();
    };

    let Some(relative) = safe_relative(&decoded) else {
        return not_found();
    };

    let candidate = root.join(&relative);
    let canonical = match candidate.canonicalize() {
        Ok(p) => p,
        // Missing, or a path that cannot be resolved. For a single-page app an
        // unknown path is the router's business, so fall back to the index.
        Err(_) => {
            if spec.spa
                && let Some(index) = existing_page(root, Some(&spec.index))
            {
                return Resolved::File(index);
            }
            return not_found();
        }
    };

    // The check that makes symlinks safe. `canonicalize` has resolved every
    // link, so if the answer is still under the root it is genuinely inside.
    let Ok(root_canonical) = root.canonicalize() else {
        return not_found();
    };
    if !canonical.starts_with(&root_canonical) {
        return not_found();
    }

    if canonical.is_dir() {
        // `/docs` must become `/docs/` before serving its index, or every
        // relative link on the page resolves against `/` instead of `/docs/`.
        if !request_path.ends_with('/') {
            return Resolved::Redirect(format!("{request_path}/"));
        }
        let index = spec.index.trim();
        if index.is_empty() {
            return not_found();
        }
        let file = canonical.join(index);
        return if file.is_file() {
            Resolved::File(file)
        } else {
            not_found()
        };
    }

    if canonical.is_file() {
        Resolved::File(canonical)
    } else {
        not_found()
    }
}

/// A page inside the root, if it is configured and actually present.
fn existing_page(root: &Path, page: Option<&str>) -> Option<PathBuf> {
    let page = page.map(str::trim).filter(|p| !p.is_empty())?;
    let path = root.join(page);
    path.is_file().then_some(path)
}

/// Reduce a decoded request path to a relative path with no way out of the root.
///
/// Rejects — rather than sanitises — anything suspicious. Silently dropping a
/// `..` would turn a traversal attempt into a *successful* request for a
/// different file, which is a worse answer than a 404.
fn safe_relative(path: &str) -> Option<PathBuf> {
    // A NUL would truncate the path at the syscall boundary, so what the
    // filesystem opens would not be what was checked here.
    if path.contains('\0') {
        return None;
    }
    let mut out = PathBuf::new();
    for component in Path::new(path.trim_start_matches('/')).components() {
        match component {
            Component::Normal(part) => out.push(part),
            // `.` is harmless but pointless; skip it.
            Component::CurDir => {}
            // Everything else is either an escape (`..`), or absolute, or a
            // Windows prefix — none of which a request path may contain.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// Decode `%XX` escapes. `None` if the encoding is malformed or decodes to
/// invalid UTF-8, both of which are a bad request rather than a filename.
pub(crate) fn percent_decode(s: &str) -> Option<String> {
    if !s.contains('%') {
        return Some(s.to_string());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hi = (hex[0] as char).to_digit(16)?;
            let lo = (hex[1] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `Content-Type` for a filename.
///
/// A short table rather than a mime database: this is a static file server for
/// a build output, and the long tail of types is not worth a dependency. The
/// default is `application/octet-stream`, which browsers download rather than
/// guess at — the safe direction to be wrong in.
pub fn content_type(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "map" => "application/json; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "csv" => "text/csv; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// A weak-ish validator built from what `stat` already told us.
///
/// Size and mtime rather than a content hash: hashing every file on every
/// request would be the most expensive thing this module does, and for a build
/// output — where a changed file means a changed mtime — it buys nothing.
pub fn etag(meta: &std::fs::Metadata) -> String {
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("\"{:x}-{:x}\"", meta.len(), mtime)
}

/// Whether the client's `If-None-Match` already has this version.
///
/// `*` matches anything, and a list is comma-separated. A `W/` prefix is
/// ignored on both sides: these tags are only ever compared for equality, so
/// weak and strong comparison coincide.
pub fn etag_matches(if_none_match: &str, etag: &str) -> bool {
    let want = etag.trim().trim_start_matches("W/");
    if_none_match
        .split(',')
        .map(|t| t.trim())
        .any(|t| t == "*" || t.trim_start_matches("W/") == want)
}

/// The byte range a `Range` header asks for, clamped to the file.
///
/// Returns `None` for anything this does not handle — multiple ranges, a
/// non-`bytes` unit, a malformed header — which the caller answers with the
/// whole file. That is always a valid response to a `Range` request, and it is
/// the right way to decline rather than misinterpret one.
///
/// `Err(())` means the range is syntactically fine but unsatisfiable, which has
/// to be a 416 rather than a silent 200 with the wrong bytes.
#[allow(clippy::result_unit_err)]
pub fn parse_range(header: &str, len: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return Ok(None);
    };
    if spec.contains(',') {
        return Ok(None); // multipart ranges: decline, serve the whole file
    }
    // No byte of an empty file can be satisfied, and every arm below computes
    // against `len - 1`.
    if len == 0 {
        return Err(());
    }
    let (start, end) = spec.split_once('-').ok_or(())?;
    let (start, end) = (start.trim(), end.trim());

    let (first, last) = match (start.is_empty(), end.is_empty()) {
        // `-N`: the final N bytes.
        (true, false) => {
            let n: u64 = end.parse().map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            (len.saturating_sub(n), len - 1)
        }
        // `N-`: from N to the end.
        (false, true) => (start.parse().map_err(|_| ())?, len - 1),
        // `N-M`.
        (false, false) => (
            start.parse().map_err(|_| ())?,
            end.parse::<u64>().map_err(|_| ())?.min(len - 1),
        ),
        (true, true) => return Err(()),
    };
    if len == 0 || first > last || first >= len {
        return Err(());
    }
    Ok(Some((first, last)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(root: &str) -> SiteSpec {
        SiteSpec {
            root: root.to_string(),
            index: "index.html".into(),
            not_found: None,
            spa: false,
            cache_control: "public, max-age=300".into(),
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("app-lb-site-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The whole point of the module: a request can only ever name a file under
    /// the configured root.
    mod traversal {
        use super::*;

        #[test]
        fn dot_dot_never_escapes_however_it_is_written() {
            for path in [
                "/../etc/passwd",
                "/a/../../etc/passwd",
                "/%2e%2e/etc/passwd",
                "/%2E%2E%2Fetc/passwd",
                "/..%2f..%2fetc/passwd",
                "/a/b/../../../etc/passwd",
            ] {
                let decoded = percent_decode(path).unwrap_or_default();
                assert!(
                    safe_relative(&decoded).is_none(),
                    "{path:?} decoded to {decoded:?} and was not rejected",
                );
            }
        }

        /// A `..` is refused outright rather than dropped. Sanitising it would
        /// turn an attack into a successful read of a *different* file.
        #[test]
        fn a_traversal_is_refused_not_sanitised() {
            assert!(safe_relative("a/../b").is_none());
            assert_eq!(safe_relative("a/./b").unwrap(), PathBuf::from("a/b"));
            assert_eq!(safe_relative("/a/b").unwrap(), PathBuf::from("a/b"));
        }

        /// A NUL truncates the path at the syscall boundary, so what gets opened
        /// would not be what was checked.
        #[test]
        fn a_nul_byte_is_rejected() {
            assert!(safe_relative("a\0b").is_none());
            assert!(percent_decode("/a%00b").map(|d| safe_relative(&d).is_none()).unwrap());
        }

        #[test]
        fn malformed_percent_encoding_is_rejected() {
            assert!(percent_decode("/a%zz").is_none());
            assert!(percent_decode("/a%2").is_none());
            assert!(percent_decode("/a%").is_none());
            // Valid but not UTF-8.
            assert!(percent_decode("/%ff%fe").is_none());
        }

        /// The check no amount of string handling can make: a symlink *inside*
        /// the root pointing outside it.
        #[cfg(unix)]
        #[test]
        fn a_symlink_out_of_the_root_is_not_served() {
            let dir = tmpdir("symlink");
            let root = dir.join("public");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(dir.join("secret.txt"), b"secret").unwrap();
            std::fs::write(root.join("ok.txt"), b"ok").unwrap();
            std::os::unix::fs::symlink(dir.join("secret.txt"), root.join("escape.txt")).unwrap();

            let s = spec(root.to_str().unwrap());
            assert!(matches!(resolve(&s, "/ok.txt"), Resolved::File(_)));
            assert!(
                matches!(resolve(&s, "/escape.txt"), Resolved::NotFound(_)),
                "a symlink pointing out of the root must not be served",
            );

            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A symlink that stays inside the root is ordinary and should work.
        #[cfg(unix)]
        #[test]
        fn a_symlink_within_the_root_is_fine() {
            let dir = tmpdir("symlink-ok");
            std::fs::write(dir.join("real.txt"), b"hi").unwrap();
            std::os::unix::fs::symlink(dir.join("real.txt"), dir.join("link.txt")).unwrap();

            let s = spec(dir.to_str().unwrap());
            assert!(matches!(resolve(&s, "/link.txt"), Resolved::File(_)));

            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn a_directory_serves_its_index_but_only_with_a_trailing_slash() {
        let dir = tmpdir("index");
        std::fs::create_dir_all(dir.join("docs")).unwrap();
        std::fs::write(dir.join("docs/index.html"), b"<h1>docs</h1>").unwrap();
        let s = spec(dir.to_str().unwrap());

        // Without the slash, relative links on the page would resolve one level
        // up — so redirect rather than serve.
        match resolve(&s, "/docs") {
            Resolved::Redirect(to) => assert_eq!(to, "/docs/"),
            other => panic!("expected a redirect, got {other:?}"),
        }
        assert!(matches!(resolve(&s, "/docs/"), Resolved::File(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_is_a_404_with_the_configured_page() {
        let dir = tmpdir("404");
        std::fs::write(dir.join("404.html"), b"nope").unwrap();
        let mut s = spec(dir.to_str().unwrap());

        assert!(matches!(resolve(&s, "/nothing"), Resolved::NotFound(None)));
        s.not_found = Some("404.html".into());
        match resolve(&s, "/nothing") {
            Resolved::NotFound(Some(p)) => assert!(p.ends_with("404.html")),
            other => panic!("expected the custom page, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A single-page app owns its own URL space, so an unknown path is the
    /// router's problem and must reach the index with a 200.
    #[test]
    fn spa_mode_falls_back_to_the_index() {
        let dir = tmpdir("spa");
        std::fs::write(dir.join("index.html"), b"<div id=app>").unwrap();
        std::fs::write(dir.join("app.js"), b"//").unwrap();
        let mut s = spec(dir.to_str().unwrap());
        s.spa = true;

        match resolve(&s, "/settings/profile") {
            Resolved::File(p) => assert!(p.ends_with("index.html")),
            other => panic!("expected the index, got {other:?}"),
        }
        // A real file still wins over the fallback.
        match resolve(&s, "/app.js") {
            Resolved::File(p) => assert!(p.ends_with("app.js")),
            other => panic!("expected the real file, got {other:?}"),
        }
        // And the fallback must not rescue a traversal.
        assert!(matches!(resolve(&s, "/../etc/passwd"), Resolved::NotFound(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn content_types_cover_what_a_build_emits() {
        for (name, want) in [
            ("index.html", "text/html; charset=utf-8"),
            ("app.js", "text/javascript; charset=utf-8"),
            ("app.css", "text/css; charset=utf-8"),
            ("logo.svg", "image/svg+xml"),
            ("font.woff2", "font/woff2"),
            ("app.wasm", "application/wasm"),
            ("data.json", "application/json; charset=utf-8"),
            // Unknown types download rather than being guessed at.
            ("thing.bin", "application/octet-stream"),
            ("noext", "application/octet-stream"),
            // Case is not significant in an extension.
            ("PHOTO.JPG", "image/jpeg"),
        ] {
            assert_eq!(content_type(Path::new(name)), want, "for {name}");
        }
    }

    #[test]
    fn etag_comparison_handles_lists_wildcards_and_weak_tags() {
        assert!(etag_matches("\"abc\"", "\"abc\""));
        assert!(etag_matches("*", "\"abc\""));
        assert!(etag_matches("\"x\", \"abc\" , \"y\"", "\"abc\""));
        assert!(etag_matches("W/\"abc\"", "\"abc\""));
        assert!(!etag_matches("\"abd\"", "\"abc\""));
        assert!(!etag_matches("", "\"abc\""));
    }

    mod ranges {
        use super::*;

        #[test]
        fn the_three_forms_all_parse() {
            assert_eq!(parse_range("bytes=0-99", 1000), Ok(Some((0, 99))));
            assert_eq!(parse_range("bytes=500-", 1000), Ok(Some((500, 999))));
            assert_eq!(parse_range("bytes=-100", 1000), Ok(Some((900, 999))));
        }

        /// An end past the file is clamped, not refused — that is what the spec
        /// says, and refusing would break resumed downloads.
        #[test]
        fn an_overlong_end_is_clamped() {
            assert_eq!(parse_range("bytes=0-99999", 1000), Ok(Some((0, 999))));
            assert_eq!(parse_range("bytes=-99999", 1000), Ok(Some((0, 999))));
        }

        #[test]
        fn an_unsatisfiable_range_is_an_error_not_a_whole_file() {
            assert_eq!(parse_range("bytes=1000-", 1000), Err(()));
            assert_eq!(parse_range("bytes=5-3", 1000), Err(()));
            assert_eq!(parse_range("bytes=-0", 1000), Err(()));
            assert_eq!(parse_range("bytes=0-0", 0), Err(()));
        }

        /// Declining is a 200 with the whole file, which is always valid.
        #[test]
        fn unsupported_forms_decline_rather_than_guess() {
            assert_eq!(parse_range("items=0-99", 1000), Ok(None));
            assert_eq!(parse_range("bytes=0-10,20-30", 1000), Ok(None));
        }
    }

    #[test]
    fn root_status_says_why_a_site_cannot_serve() {
        let dir = std::env::temp_dir().join(format!("app-lb-site-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let spec = |root: &Path| SiteSpec {
            root: root.display().to_string(),
            index: "index.html".into(),
            not_found: None,
            spa: false,
            cache_control: String::new(),
        };
        let missing = root_status(&spec(&dir));
        assert_eq!(missing.status, "missing");
        assert!(missing.hint.unwrap().contains("app-lb host"));

        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(root_status(&spec(&dir)).status, "empty");

        std::fs::write(dir.join("other.html"), "x").unwrap();
        let no_index = root_status(&spec(&dir));
        assert_eq!((no_index.status, no_index.index_present), ("ok", Some(false)));
        assert!(no_index.hint.is_some());

        std::fs::write(dir.join("index.html"), "x").unwrap();
        assert_eq!(
            root_status(&spec(&dir)),
            RootStatus { root: dir.display().to_string(), status: "ok", index_present: Some(true), hint: None }
        );
        assert_eq!(root_status(&spec(&dir.join("other.html"))).status, "not_a_directory");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
