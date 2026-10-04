//! First-run help for a namespace user: the hosted MCP endpoint to point
//! Claude Code at, how long a token they mint for it may live, and a fastcar
//! deployment spec they can paste.
//!
//! A namespace user arrives from Heyo (`POST /login/handoff`) holding nothing
//! but a one-hour session. To work from Claude Code they need a credential of
//! their own, the MCP server's address, and something worth deploying. The
//! dashboard's "Get started" card walks them through those three steps, reading
//! everything it shows from `GET /onboarding`.
//!
//! The fastcar spec is built here rather than in the page because two of its
//! fields are facts only a server can vouch for: the catalog download the
//! daemon verifies the image against (`vm.image_download_url`, `_size_bytes`,
//! `_sha256`), and the hostname this fleet will give the deployment. Cloud's
//! namespace door fills the first for specs that come through it. A spec pasted
//! into Claude Code goes through the MCP server straight to this API, so it has
//! to carry them itself.
//!
//! Configuration, all optional:
//!
//! | variable | default | meaning |
//! | --- | --- | --- |
//! | `APP_LB_ONBOARDING_MCP_URL` | unset | the hosted MCP endpoint; without it the card leaves that step out |
//! | `APP_LB_TENANT_TOKEN_MAX_TTL_SECS` | 90 days | the longest a namespace-confined caller may mint a token for |
//! | `APP_LB_PUBLIC_IMAGE_CATALOG_URL` | unset | cloud's base URL, serving `/public-images/{name}/meta` |
//! | `APP_LB_ONBOARDING_FASTCAR_IMAGE` | `fastcar` | the catalog name the fastcar spec deploys |

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The longest a namespace-confined caller may mint a token for, unless
/// `APP_LB_TENANT_TOKEN_MAX_TTL_SECS` says otherwise. A tenant's tokens always
/// expire: one that never does is a credential nobody remembers to revoke.
pub const DEFAULT_TENANT_TOKEN_MAX_TTL_SECS: u64 = 90 * 86_400;

/// The catalog image the fastcar spec deploys, unless
/// `APP_LB_ONBOARDING_FASTCAR_IMAGE` names another.
const DEFAULT_FASTCAR_IMAGE: &str = "fastcar";

/// The name a namespace's Heyo sign-in provider has. Cloud creates it beside
/// the namespace (see `AUTH_PROVIDERS.md`, "Giving a customer a namespace").
pub const HEYO_PROVIDER: &str = "heyo";

/// A deployment's generated hostname is `<id>.<base>`, and a DNS label stops
/// at 63 characters.
const MAX_LABEL: usize = 63;

pub struct Onboarding {
    pub mcp_url: Option<String>,
    pub tenant_token_max_ttl_secs: u64,
    catalog_url: Option<reqwest::Url>,
    pub fastcar_image: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for Onboarding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Onboarding")
            .field("mcp_url", &self.mcp_url)
            .field("tenant_token_max_ttl_secs", &self.tenant_token_max_ttl_secs)
            .field(
                "catalog_url",
                &self.catalog_url.as_ref().map(reqwest::Url::as_str),
            )
            .field("fastcar_image", &self.fastcar_image)
            .finish()
    }
}

impl Default for Onboarding {
    fn default() -> Self {
        Self::from_lookup(|_| None)
    }
}

/// An absolute `https://` URL (or `http://` to loopback, for local testing).
/// Anything else is ignored with a warning: both URLs this module reads end up
/// in a page or in a request this process makes, and neither should go
/// somewhere a typo sent it.
fn https_url(var: &str, raw: Option<String>) -> Option<reqwest::Url> {
    let raw = raw?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    match reqwest::Url::parse(raw) {
        Ok(u) if u.scheme() == "https" => Some(u),
        Ok(u)
            if u.scheme() == "http"
                && matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")) =>
        {
            Some(u)
        }
        _ => {
            tracing::warn!(variable = var, value = %raw, "ignoring: not an absolute https:// URL");
            None
        }
    }
}

impl Onboarding {
    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let ttl = get("APP_LB_TENANT_TOKEN_MAX_TTL_SECS")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_TENANT_TOKEN_MAX_TTL_SECS);
        let fastcar_image = get("APP_LB_ONBOARDING_FASTCAR_IMAGE")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_FASTCAR_IMAGE.to_string());
        Self {
            mcp_url: https_url(
                "APP_LB_ONBOARDING_MCP_URL",
                get("APP_LB_ONBOARDING_MCP_URL"),
            )
            .map(String::from),
            tenant_token_max_ttl_secs: ttl,
            catalog_url: https_url(
                "APP_LB_PUBLIC_IMAGE_CATALOG_URL",
                get("APP_LB_PUBLIC_IMAGE_CATALOG_URL"),
            ),
            fastcar_image,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
        }
    }

    /// Where the catalog serves `image`'s bytes. The daemon accepts a download
    /// only from its own configured catalog origin, under `/public-images/`.
    fn download_url(&self, base: &reqwest::Url, id: &str) -> Option<String> {
        let mut url = base.clone();
        url.path_segments_mut()
            .ok()?
            .pop_if_empty()
            .extend(["public-images", id]);
        Some(url.into())
    }

    /// Look the fastcar image up in the public catalog.
    pub async fn fastcar_image(&self) -> ImageLookup {
        let Some(base) = &self.catalog_url else {
            return ImageLookup::Unconfigured;
        };
        let mut url = base.clone();
        let Ok(mut segments) = url.path_segments_mut() else {
            return ImageLookup::Failed("the catalog URL cannot take a path".into());
        };
        segments
            .pop_if_empty()
            .extend(["public-images", &self.fastcar_image, "meta"]);
        drop(segments);
        url.query_pairs_mut().append_pair("backend", "firecracker");

        let resp = match self.http.get(url).send().await {
            Ok(r) => r,
            Err(e) => return ImageLookup::Failed(format!("the image catalog did not answer: {e}")),
        };
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return ImageLookup::NotFound;
        }
        if !resp.status().is_success() {
            return ImageLookup::Failed(format!("the image catalog answered {}", resp.status()));
        }
        let meta: CatalogMeta = match resp.json().await {
            Ok(m) => m,
            Err(e) => {
                return ImageLookup::Failed(format!(
                    "the image catalog's answer was unreadable: {e}"
                ));
            }
        };
        match self.download_url(base, &meta.id) {
            Some(download_url) => ImageLookup::Found(CatalogImage {
                name: meta
                    .name
                    .filter(|n| !n.trim().is_empty())
                    .unwrap_or_else(|| self.fastcar_image.clone()),
                download_url,
                size_bytes: meta.size_bytes.max(0) as u64,
                sha256: meta.sha256.filter(|s| !s.trim().is_empty()),
            }),
            None => ImageLookup::Failed("the catalog URL cannot take a path".into()),
        }
    }
}

/// What cloud's `GET /public-images/{id-or-name}/meta` answers, as far as a
/// deployment needs it.
#[derive(Debug, Deserialize)]
struct CatalogMeta {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    size_bytes: i64,
    #[serde(default)]
    sha256: Option<String>,
}

/// A catalog image, resolved to what the daemon needs to fetch and verify it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogImage {
    /// The name the daemon caches the download under, which `vm.image` must
    /// match so a second replica finds it on disk.
    pub name: String,
    pub download_url: String,
    pub size_bytes: u64,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageLookup {
    Found(CatalogImage),
    /// The catalog answered and has no such image.
    NotFound,
    /// `APP_LB_PUBLIC_IMAGE_CATALOG_URL` is unset.
    Unconfigured,
    Failed(String),
}

impl ImageLookup {
    /// The status the card shows beside the spec, and why.
    pub fn status(&self) -> (&'static str, Option<String>) {
        match self {
            Self::Found(_) => ("ok", None),
            Self::NotFound => (
                "not_found",
                Some("the public image catalog has no fastcar image yet; this spec deploys only on a host that already holds one".into()),
            ),
            Self::Unconfigured => (
                "unconfigured",
                Some("this load balancer has no public image catalog configured; this spec deploys only on a host that already holds the image".into()),
            ),
            Self::Failed(why) => ("error", Some(why.clone())),
        }
    }
}

/// The deployment id the onboarding spec uses: `fastcar-<ns>`, cut to fit a
/// DNS label because the generated hostname is `<id>.<base>`. Ids are global,
/// so the namespace is what keeps two tenants' first deployments apart.
pub fn fastcar_id(namespace: &str) -> String {
    let mut id = format!("fastcar-{}", namespace.to_ascii_lowercase());
    id.retain(|c| c.is_ascii_alphanumeric() || c == '-');
    id.truncate(MAX_LABEL);
    id.trim_end_matches('-').to_string()
}

/// A fastcar deployment for `namespace`, in mock mode so it boots without any
/// model keys or an outside database (the image carries its own Postgres).
///
/// - `image`: the catalog record, when there is one. Without it the spec names
///   the image alone and works only on a host that already holds it.
/// - `host`: the hostname the fleet will route, when it generates them. The
///   spec then pins it, so `FASTCAR_PUBLIC_URL` can be filled in. Without one
///   the route is path-only and the fleet's own host rules apply.
/// - `gated`: the namespace has the `heyo` sign-in provider. fastcar is an
///   agent with a shell, so a public URL without a gate in front of it would
///   hand that shell to anyone who finds the name.
pub fn fastcar_spec(
    namespace: &str,
    image_name: &str,
    image: Option<&CatalogImage>,
    host: Option<&str>,
    gated: bool,
) -> Value {
    let id = fastcar_id(namespace);
    let mut env = json!({
        "FASTCAR_MOCK": "1",
        "PORT": "3000",
    });
    if let Some(host) = host {
        env["FASTCAR_PUBLIC_URL"] = json!(format!("https://{host}"));
    }

    let mut vm = json!({
        "driver": "firecracker",
        "image": image.map_or(image_name, |i| i.name.as_str()),
        "port": 3000,
        "start_command": "/opt/fastcar/start.sh",
        "size_class": "medium",
        "disk_size_gb": 10,
        "env_vars": env,
    });
    if let Some(image) = image {
        vm["image_download_url"] = json!(image.download_url);
        vm["image_size_bytes"] = json!(image.size_bytes);
        if let Some(sha) = &image.sha256 {
            vm["image_sha256"] = json!(sha);
        }
    }

    let route = match host {
        Some(host) => json!({ "host": host }),
        None => json!({ "path_prefix": "/" }),
    };

    let mut spec = json!({
        "id": id,
        "namespace": namespace,
        "routes": [route],
        "vm": vm,
        // One VM at most, and none while nobody is using it: this is a first
        // deployment to look at, not a service to keep warm.
        "scaling": {
            "min_replicas": 0,
            "max_replicas": 1,
            "scale_to_zero_after_secs": 1800,
            "cold_start_timeout_secs": 240,
            "boot_timeout_secs": 300,
        },
        "health": { "path": "/api/health", "timeout_secs": 2 },
    });
    if gated {
        spec["auth"] = json!({
            "provider_ref": HEYO_PROVIDER,
            "public_paths": [{ "path": "/api/health", "scope": "public" }],
        });
    }
    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> CatalogImage {
        CatalogImage {
            name: "fastcar".into(),
            download_url: "https://cloud.example/public-images/im-1".into(),
            size_bytes: 1_234,
            sha256: Some("ab".repeat(32)),
        }
    }

    fn parse(v: Value) -> crate::config::DeploymentSpec {
        serde_json::from_value(v).expect("the onboarding spec must parse as a DeploymentSpec")
    }

    #[test]
    fn the_spec_is_a_valid_deployment() {
        for (img, host, gated) in [
            (Some(image()), Some("fastcar-acme.us2.heyo.work"), true),
            (None, None, false),
            (Some(image()), None, true),
        ] {
            let spec = parse(fastcar_spec("acme", "fastcar", img.as_ref(), host, gated));
            spec.validate().expect("the onboarding spec must validate");
            assert_eq!(spec.namespace, "acme");
            assert_eq!(spec.id, "fastcar-acme");
        }
    }

    #[test]
    fn a_catalog_image_carries_its_download_and_digest() {
        let v = fastcar_spec("acme", "fastcar", Some(&image()), None, false);
        assert_eq!(
            v["vm"]["image_download_url"],
            "https://cloud.example/public-images/im-1"
        );
        assert_eq!(v["vm"]["image_size_bytes"], 1_234);
        assert_eq!(v["vm"]["image_sha256"], "ab".repeat(32));

        let bare = fastcar_spec("acme", "fastcar", None, None, false);
        assert!(bare["vm"].get("image_download_url").is_none());
        assert_eq!(bare["vm"]["image"], "fastcar");
    }

    #[test]
    fn a_known_host_is_pinned_and_becomes_the_public_url() {
        let v = fastcar_spec(
            "acme",
            "fastcar",
            None,
            Some("fastcar-acme.us2.heyo.work"),
            false,
        );
        assert_eq!(v["routes"][0]["host"], "fastcar-acme.us2.heyo.work");
        assert_eq!(
            v["vm"]["env_vars"]["FASTCAR_PUBLIC_URL"],
            "https://fastcar-acme.us2.heyo.work"
        );

        let v = fastcar_spec("acme", "fastcar", None, None, false);
        assert_eq!(v["routes"][0]["path_prefix"], "/");
        assert!(v["vm"]["env_vars"].get("FASTCAR_PUBLIC_URL").is_none());
    }

    #[test]
    fn the_gate_is_the_namespace_heyo_provider_with_health_left_open() {
        let v = fastcar_spec("acme", "fastcar", None, None, true);
        assert_eq!(v["auth"]["provider_ref"], "heyo");
        assert_eq!(v["auth"]["public_paths"][0]["path"], "/api/health");
        assert_eq!(v["auth"]["public_paths"][0]["scope"], "public");
        assert!(
            fastcar_spec("acme", "fastcar", None, None, false)
                .get("auth")
                .is_none()
        );
    }

    #[test]
    fn the_id_fits_a_dns_label() {
        let long = "n".repeat(63);
        let id = fastcar_id(&long);
        assert!(id.len() <= 63);
        assert!(id.starts_with("fastcar-"));
        assert_eq!(fastcar_id("Team.A"), "fastcar-teama");
        // Truncation never leaves a trailing hyphen.
        let id = fastcar_id(&format!("{}-x", "a".repeat(54)));
        assert!(!id.ends_with('-'));
    }

    #[test]
    fn config_reads_and_rejects() {
        let o = Onboarding::from_lookup(|k| match k {
            "APP_LB_ONBOARDING_MCP_URL" => Some("https://mcp.example/mcp".into()),
            "APP_LB_TENANT_TOKEN_MAX_TTL_SECS" => Some("3600".into()),
            "APP_LB_PUBLIC_IMAGE_CATALOG_URL" => Some("http://catalog.example".into()),
            "APP_LB_ONBOARDING_FASTCAR_IMAGE" => Some(" fastcar-v2 ".into()),
            _ => None,
        });
        assert_eq!(o.mcp_url.as_deref(), Some("https://mcp.example/mcp"));
        assert_eq!(o.tenant_token_max_ttl_secs, 3600);
        // Plain http to anything but loopback is refused.
        assert!(o.catalog_url.is_none());
        assert_eq!(o.fastcar_image, "fastcar-v2");

        let d = Onboarding::default();
        assert_eq!(d.mcp_url, None);
        assert_eq!(
            d.tenant_token_max_ttl_secs,
            DEFAULT_TENANT_TOKEN_MAX_TTL_SECS
        );
        assert_eq!(d.fastcar_image, "fastcar");

        let zero = Onboarding::from_lookup(|k| {
            (k == "APP_LB_TENANT_TOKEN_MAX_TTL_SECS").then(|| "0".into())
        });
        assert_eq!(
            zero.tenant_token_max_ttl_secs,
            DEFAULT_TENANT_TOKEN_MAX_TTL_SECS
        );
    }

    #[test]
    fn the_download_url_sits_under_the_catalog_path() {
        let o = Onboarding::default();
        let base = reqwest::Url::parse("https://cloud.example/").unwrap();
        assert_eq!(
            o.download_url(&base, "im-7").as_deref(),
            Some("https://cloud.example/public-images/im-7")
        );
        let nested = reqwest::Url::parse("https://cloud.example/api/").unwrap();
        assert_eq!(
            o.download_url(&nested, "im-7").as_deref(),
            Some("https://cloud.example/api/public-images/im-7")
        );
    }
}
