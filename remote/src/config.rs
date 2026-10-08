//! Everything is `REMOTE_*` environment, read once at startup.
//!
//! The git hook (`remote hook pre-receive`) is this same binary started by
//! `git receive-pack`. It rebuilds its store from the environment the service
//! hands it, which is why [`StoreConfig::hook_env`] exists: S3 keys read from
//! heyosecret are not in the service's own environment, so they are passed
//! down explicitly instead.

use std::path::PathBuf;

use crate::store::{FsStore, S3, Store};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: String,
    /// What clone URLs start with: how clients and app-lb reach this service.
    pub public_url: String,
    /// The Heyo auth service: Heyo JWTs and `heyo_api_*` keys resolve here.
    pub auth_url: Option<String>,
    /// An app-lb admin API: `applb_*` tokens are resolved by its `/whoami`, so
    /// the one token an agent already has works here too.
    pub applb_url: Option<String>,
    pub auth_cache_secs: u64,
    pub auth_timeout_secs: u64,
    /// A static unconfined credential, for the operator and for bootstrapping.
    pub admin_token: Option<String>,
    /// The account a namespace is billed to when no credential can name one.
    /// For self-hosted fleets with no Heyo auth service.
    pub default_account: Option<String>,
    pub cache_dir: PathBuf,
    pub store: StoreConfig,
    pub bucket_prefix: String,
    pub control_bucket: String,
    pub max_push_bytes: u64,
    pub git_bin: String,
    pub allow_force_push: bool,
    pub max_token_ttl_secs: u64,
    /// Serve the web UI (`REMOTE_WEB`, on unless `0`/`false`/`off`).
    pub web: bool,
    /// app-lb's `remote` plugin's bearer (`REMOTE_PLUGIN_API_TOKEN`). Without
    /// it the plugin surface (`crate::plugin`) is not mounted.
    pub plugin_api_token: Option<String>,
}

#[derive(Clone, Debug)]
pub enum StoreConfig {
    Fs(PathBuf),
    S3 {
        region: String,
        endpoint: Option<String>,
        harden: Option<bool>,
        access_key: Option<String>,
        secret_key: Option<String>,
        /// A heyosecret path holding `{"access_key_id", "secret_access_key"}`,
        /// read when the keys are not in the environment.
        heyosecret_path: Option<String>,
    },
}

impl Config {
    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let listen = get("REMOTE_LISTEN").unwrap_or_else(|| "0.0.0.0:9700".into());
        let public_url = get("REMOTE_PUBLIC_URL")
            .unwrap_or_else(|| format!("http://{}", listen.replace("0.0.0.0", "127.0.0.1")))
            .trim_end_matches('/')
            .to_string();
        let num = |k: &str, d: u64| get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
        let bucket_prefix = get("REMOTE_BUCKET_PREFIX").unwrap_or_else(|| "heyo-git".into());
        let store = match get("REMOTE_STORE").as_deref() {
            Some(s) if s.starts_with("fs:") => StoreConfig::Fs(PathBuf::from(&s[3..])),
            _ => StoreConfig::S3 {
                region: get("REMOTE_S3_REGION")
                    .or_else(|| get("AWS_REGION"))
                    .unwrap_or_else(|| "us-east-1".into()),
                endpoint: get("REMOTE_S3_ENDPOINT"),
                harden: get("REMOTE_S3_HARDEN").map(|v| v == "1" || v == "true"),
                access_key: get("REMOTE_S3_ACCESS_KEY_ID").or_else(|| get("AWS_ACCESS_KEY_ID")),
                secret_key: get("REMOTE_S3_SECRET_ACCESS_KEY")
                    .or_else(|| get("AWS_SECRET_ACCESS_KEY")),
                heyosecret_path: get("REMOTE_S3_HEYOSECRET_PATH"),
            },
        };
        Self {
            public_url,
            auth_url: get("REMOTE_AUTH_URL").map(|u| u.trim_end_matches('/').to_string()),
            applb_url: get("REMOTE_APPLB_URL").map(|u| u.trim_end_matches('/').to_string()),
            auth_cache_secs: num("REMOTE_AUTH_CACHE_SECS", 60),
            auth_timeout_secs: num("REMOTE_AUTH_TIMEOUT_SECS", 5),
            admin_token: get("REMOTE_ADMIN_TOKEN"),
            default_account: get("REMOTE_DEFAULT_ACCOUNT"),
            cache_dir: PathBuf::from(
                get("REMOTE_CACHE_DIR").unwrap_or_else(|| "/var/lib/remote/cache".into()),
            ),
            store,
            control_bucket: get("REMOTE_CONTROL_BUCKET")
                .unwrap_or_else(|| format!("{bucket_prefix}-control")),
            bucket_prefix,
            max_push_bytes: num("REMOTE_MAX_PUSH_MB", 512) * 1024 * 1024,
            git_bin: get("REMOTE_GIT_BIN").unwrap_or_else(|| "git".into()),
            allow_force_push: get("REMOTE_ALLOW_FORCE_PUSH")
                .is_some_and(|v| v == "1" || v == "true"),
            max_token_ttl_secs: num("REMOTE_MAX_TOKEN_TTL_SECS", 30 * 86_400),
            web: !get("REMOTE_WEB")
                .is_some_and(|v| matches!(v.as_str(), "0" | "false" | "off" | "no")),
            plugin_api_token: get("REMOTE_PLUGIN_API_TOKEN"),
            listen,
        }
    }

    /// Problems that make the service unusable, reported before it binds.
    pub fn validate(&self) -> Result<(), String> {
        let p = &self.bucket_prefix;
        // `<prefix>-<24 hex>` must fit S3's 63, and be a legal bucket name.
        if p.is_empty()
            || p.len() > 38
            || !p
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || p.starts_with('-')
        {
            return Err(format!(
                "REMOTE_BUCKET_PREFIX {p:?} must be 1-38 lowercase letters, digits or '-'"
            ));
        }
        Ok(())
    }
}

/// S3 credentials as resolved at startup (environment, else heyosecret).
#[derive(Clone)]
pub struct ResolvedStore {
    pub store: Store,
    hook_env: Vec<(String, String)>,
}

impl ResolvedStore {
    pub fn fs(root: PathBuf) -> Self {
        Self {
            hook_env: vec![("REMOTE_STORE".into(), format!("fs:{}", root.display()))],
            store: Store::Fs(FsStore::new(root)),
        }
    }

    /// What a child `git receive-pack` needs so its hook reaches the same
    /// store. Secret values included: the child is this service's own process
    /// tree, which already holds them.
    pub fn hook_env(&self) -> &[(String, String)] {
        &self.hook_env
    }
}

impl StoreConfig {
    pub async fn resolve(&self) -> Result<ResolvedStore, String> {
        match self {
            StoreConfig::Fs(root) => Ok(ResolvedStore::fs(root.clone())),
            StoreConfig::S3 {
                region,
                endpoint,
                harden,
                access_key,
                secret_key,
                heyosecret_path,
            } => {
                let (ak, sk) = match (access_key, secret_key, heyosecret_path) {
                    (Some(a), Some(s), _) => (a.clone(), s.clone()),
                    (_, _, Some(path)) => read_heyosecret(path).await?,
                    _ => {
                        return Err("no S3 credentials: set REMOTE_S3_ACCESS_KEY_ID and \
                                    REMOTE_S3_SECRET_ACCESS_KEY, or REMOTE_S3_HEYOSECRET_PATH, \
                                    or REMOTE_STORE=fs:<dir> for development"
                            .into());
                    }
                };
                let mut hook_env = vec![
                    ("REMOTE_STORE".to_string(), "s3".to_string()),
                    ("REMOTE_S3_REGION".into(), region.clone()),
                    ("REMOTE_S3_ACCESS_KEY_ID".into(), ak.clone()),
                    ("REMOTE_S3_SECRET_ACCESS_KEY".into(), sk.clone()),
                ];
                if let Some(e) = endpoint {
                    hook_env.push(("REMOTE_S3_ENDPOINT".into(), e.clone()));
                }
                let mut s3 = S3::new(endpoint.clone(), region.clone(), ak, sk);
                if let Some(h) = harden {
                    s3.harden = *h;
                }
                Ok(ResolvedStore {
                    store: Store::S3(s3),
                    hook_env,
                })
            }
        }
    }
}

async fn read_heyosecret(path: &str) -> Result<(String, String), String> {
    let client = heyosecret_client::HeyoSecretClient::from_env().map_err(|e| {
        format!("REMOTE_S3_HEYOSECRET_PATH is set but heyosecret is not configured: {e}")
    })?;
    let secret = client
        .read_active(path)
        .await
        .map_err(|e| format!("reading S3 credentials from heyosecret {path}: {e}"))?;
    #[derive(serde::Deserialize)]
    struct Keys {
        access_key_id: String,
        secret_access_key: String,
    }
    let keys: Keys = serde_json::from_slice(&secret.value).map_err(|e| {
        format!("heyosecret {path} must hold {{\"access_key_id\", \"secret_access_key\"}}: {e}")
    })?;
    Ok((keys.access_key_id, keys.secret_access_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> Config {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn defaults_and_fallbacks() {
        let c = cfg(&[("AWS_ACCESS_KEY_ID", "a"), ("AWS_SECRET_ACCESS_KEY", "s")]);
        assert_eq!(c.control_bucket, "heyo-git-control");
        assert_eq!(c.public_url, "http://127.0.0.1:9700");
        assert!(matches!(
            c.store,
            StoreConfig::S3 { access_key: Some(ref a), ref region, .. } if a == "a" && region == "us-east-1"
        ));
        assert!(c.validate().is_ok());

        let c = cfg(&[
            ("REMOTE_STORE", "fs:/tmp/x"),
            ("REMOTE_BUCKET_PREFIX", "Bad_Prefix"),
        ]);
        assert!(matches!(c.store, StoreConfig::Fs(ref p) if p == &PathBuf::from("/tmp/x")));
        assert!(c.validate().is_err());
    }
}
