//! Secrets and variables, from heyosecret.
//!
//! ## This process is the policy layer, because heyosecret has none
//!
//! heyosecret authenticates with **one shared bearer that can read, write and
//! revoke every secret at every path**. `readAccess`/`writeAccess` exist on the
//! row, are returned by the API, and are never enforced — its own README says
//! so. So there is no configuration of heyosecret that makes it safe to hand its
//! token to a build. The orchestrator holds the token, resolves the paths a
//! workflow is entitled to, and injects only the resulting values.
//!
//! A build therefore sees `${{ secrets.FOO }}` and never `HEYOSECRET_*`.
//!
//! ## Secrets and variables are the same store
//!
//! heyosecret makes no distinction, so the convention is its `tags[]`: an entry
//! tagged `public` becomes `vars.*` and is left in plain text; everything else
//! becomes `secrets.*` and is masked. `tags` comes back from `list`, which means
//! the classification is known *before* any value is fetched — the alternative
//! would be reading every value to decide whether it was safe to read.
//!
//! ## Resolution is per job, not per step
//!
//! heyosecret has no batch read: N secrets is N POSTs. One `list` by prefix
//! yields the names, and the values are fetched concurrently, once, and held for
//! the job's lifetime.

use crate::config::Config;
#[cfg(test)]
use axum::response::IntoResponse;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

/// Tag marking an entry as a non-sensitive variable.
const PUBLIC_TAG: &str = "public";

/// Below this length a value is not masked.
///
/// Redacting every occurrence of a one- or two-character secret would turn a log
/// into confetti, and a secret that short is not a secret. Three is the shortest
/// length where masking is more use than noise.
const MIN_MASK_LEN: usize = 4;

/// What a build gets: `secrets.*` and `vars.*`.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    pub secrets: BTreeMap<String, String>,
    pub vars: BTreeMap<String, String>,
}

impl Resolved {
    /// The masker for this set. Only `secrets` are masked; `vars` are public by
    /// declaration.
    pub fn masker(&self) -> Masker {
        Masker::new(self.secrets.values().map(String::as_str))
    }

    /// Expression scopes, for `${{ secrets.X }}` and `${{ vars.X }}`.
    pub fn scopes(&self) -> (serde_json::Value, serde_json::Value) {
        let to_obj = |m: &BTreeMap<String, String>| {
            serde_json::Value::Object(
                m.iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect(),
            )
        };
        (to_obj(&self.secrets), to_obj(&self.vars))
    }
}

/// Redacts known secret values from text.
///
/// Applied on the **write** path, before a log line is persisted or streamed, so
/// a secret never exists in a stored log to leak later. Masking at render time
/// would leave the plain text on disk and only hide it from one reader.
#[derive(Debug, Clone, Default)]
pub struct Masker {
    /// Longest first: masking `abc` before `abcdef` would leave `***def`
    /// behind, which reveals both the tail and the fact that it was a prefix.
    values: Vec<String>,
}

pub const REDACTED: &str = "***";

impl Masker {
    pub fn new<'a>(values: impl Iterator<Item = &'a str>) -> Self {
        let mut values: Vec<String> = values
            .filter(|v| v.len() >= MIN_MASK_LEN)
            .map(str::to_string)
            .collect();
        values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        values.dedup();
        Self { values }
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn mask(&self, text: &str) -> String {
        if self.values.is_empty() {
            return text.to_string();
        }
        let mut out = text.to_string();
        for v in &self.values {
            if out.contains(v.as_str()) {
                out = out.replace(v.as_str(), REDACTED);
            }
        }
        out
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretMetadata {
    path: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    #[serde(default)]
    secrets: Vec<SecretMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretValue {
    #[serde(default)]
    value_base64: String,
}

/// A heyosecret client scoped to this orchestrator.
#[derive(Clone)]
pub struct Secrets {
    http: reqwest::Client,
    base_url: Option<String>,
    token: Option<String>,
}

impl Secrets {
    #[cfg(test)]
    pub fn unconfigured() -> Self {
        Self { http: reqwest::Client::new(), base_url: None, token: None }
    }

    pub fn new(config: &Config) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
            base_url: config.heyosecret_url.clone(),
            token: config.heyosecret_token.clone(),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.base_url.is_some() && self.token.is_some()
    }

    /// The path prefix a workflow's secrets live under.
    ///
    /// heyosecret's `list` prefix match is `path = $1 OR path LIKE $1 || '/%'`,
    /// so a prefix matches whole segments — `ci/app` does not match `ci/app2`.
    /// The convention is `ci/<workflow>/<environment>`.
    pub fn prefix(workflow_id: &str, environment: &str) -> String {
        format!("ci/{}/{}", sanitize(workflow_id), sanitize(environment))
    }

    /// The prefix a run's secrets live under, wherever it came from.
    ///
    /// A fleet run is [`Self::prefix`]. A tenant run is forced under
    /// `ci/ns/<namespace>/<workflow>/<environment>`, whatever its workflow is
    /// called: a tenant registration's workflow id is a name the tenant chose,
    /// and without the namespace segment a repository named after a fleet
    /// workflow would read that workflow's deploy credentials.
    pub fn prefix_for(run: &crate::store::Run, environment: &str) -> String {
        Self::prefix_in(&run.namespace, &run.workflow_id, environment)
    }

    /// [`Self::prefix_for`] from its parts, for a caller holding a namespace
    /// and a workflow id rather than a whole run.
    pub fn prefix_in(namespace: &str, workflow_id: &str, environment: &str) -> String {
        if namespace.is_empty() {
            Self::prefix(workflow_id, environment)
        } else {
            format!(
                "ci/ns/{}/{}/{}",
                sanitize(namespace),
                sanitize(workflow_id),
                sanitize(environment)
            )
        }
    }

    /// Resolve every secret and variable under a prefix.
    ///
    /// Returns an empty set when heyosecret is not configured: a workflow that
    /// uses no secrets must still run on an installation that has no secret
    /// store, and failing here would make heyosecret a hard dependency of every
    /// build.
    pub async fn resolve(&self, prefix: &str) -> Result<Resolved, SecretsError> {
        let (Some(base), Some(token)) = (&self.base_url, &self.token) else {
            return Ok(Resolved::default());
        };

        let list: ListResponse = self
            .http
            .get(format!("{base}/v1/secrets"))
            .query(&[("prefix", prefix)])
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| SecretsError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| SecretsError::Api(e.to_string()))?
            .json()
            .await
            .map_err(|e| SecretsError::Decode(e.to_string()))?;

        // Fetched concurrently because heyosecret has no batch read and a job
        // with twenty secrets would otherwise pay twenty serial round trips
        // before its first step.
        let futures: Vec<_> = list
            .secrets
            .iter()
            .map(|meta| async move {
                let value = self.read(meta).await?;
                Ok::<_, SecretsError>((meta, value))
            })
            .collect();
        let fetched = futures::future::try_join_all(futures).await?;

        let mut out = Resolved::default();
        for (meta, value) in fetched {
            let Some(name) = leaf_name(&meta.path, prefix) else {
                continue;
            };
            if meta.tags.iter().any(|t| t == PUBLIC_TAG) {
                out.vars.insert(name, value);
            } else {
                out.secrets.insert(name, value);
            }
        }
        Ok(out)
    }

    /// Operator configuration is outside every workflow's secret prefix.
    pub async fn host_app_lb_targets(&self) -> Result<String, SecretsError> {
        self.read(&SecretMetadata {
            path: "ci-controller/host-app-lb-targets".into(),
            tags: Vec::new(),
        }).await
    }

    /// Private host-daemon mappings are operator configuration, never workflow
    /// secrets. Keeping the fixed path here prevents a repository from
    /// authorizing itself to replace a runner's daemon.
    pub async fn host_maintenance_targets(&self) -> Result<String, SecretsError> {
        self.read(&SecretMetadata {
            path: "ci-controller/host-maintenance-targets".into(),
            tags: Vec::new(),
        }).await
    }

    pub async fn host_heyvm_bootstrap_targets(&self) -> Result<String, SecretsError> {
        self.read(&SecretMetadata {
            path: "ci-controller/host-heyvm-bootstrap-targets".into(),
            tags: Vec::new(),
        }).await
    }

    async fn read(&self, meta: &SecretMetadata) -> Result<String, SecretsError> {
        let (Some(base), Some(token)) = (&self.base_url, &self.token) else {
            return Ok(String::new());
        };
        let response: SecretValue = self
            .http
            .post(format!("{base}/v1/secrets/read"))
            .bearer_auth(token)
            .json(&serde_json::json!({ "path": meta.path }))
            .send()
            .await
            .map_err(|e| SecretsError::Transport(e.to_string()))?
            .error_for_status()
            // heyosecret answers 404 for *every* read failure — no such path, no
            // active version, decrypt failed — so the path is named here or the
            // error says nothing usable.
            .map_err(|e| SecretsError::Unreadable {
                path: meta.path.clone(),
                reason: e.to_string(),
            })?
            .json()
            .await
            .map_err(|e| SecretsError::Decode(e.to_string()))?;

        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(response.value_base64.as_bytes())
            .map_err(|e| SecretsError::Decode(format!("{}: {e}", meta.path)))?;
        String::from_utf8(bytes).map_err(|_| SecretsError::NotText(meta.path.clone()))
    }
}

/// The last path segment, which is the name a workflow refers to.
fn leaf_name(path: &str, prefix: &str) -> Option<String> {
    let rest = path.strip_prefix(prefix)?.trim_start_matches('/');
    if rest.is_empty() {
        return None;
    }
    // Only the leaf: `ci/app/prod/db/URL` is `URL`, not `db/URL`, because an
    // expression name cannot contain a slash.
    Some(rest.rsplit('/').next()?.to_string())
}

/// Reduce a component to heyosecret's path charset (`[A-Za-z0-9]` plus
/// `/ - _ . : @`), minus the separator.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '@') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

#[derive(Debug)]
pub enum SecretsError {
    Transport(String),
    Api(String),
    Decode(String),
    NotText(String),
    Unreadable { path: String, reason: String },
}

impl fmt::Display for SecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "could not reach heyosecret: {e}"),
            Self::Api(e) => write!(f, "heyosecret rejected the request: {e}"),
            Self::Decode(e) => write!(f, "heyosecret returned something unreadable: {e}"),
            Self::NotText(p) => write!(
                f,
                "the secret at {p:?} is not UTF-8, so it cannot be injected as an \
                 environment variable"
            ),
            Self::Unreadable { path, reason } => write!(
                f,
                "could not read the secret at {path:?}: {reason}. heyosecret answers \
                 404 for every read failure, so this may be a missing path, no active \
                 version, or a decryption failure."
            ),
        }
    }
}

impl std::error::Error for SecretsError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved() -> Resolved {
        let mut r = Resolved::default();
        r.secrets.insert("TOKEN".into(), "s3cr3t-value-here".into());
        r.secrets.insert("SHORT".into(), "ab".into());
        r.vars.insert("REGION".into(), "eu-west-1".into());
        r
    }

    #[test]
    fn a_secret_is_redacted_wherever_it_appears() {
        let m = resolved().masker();
        assert_eq!(
            m.mask("connecting with s3cr3t-value-here now"),
            format!("connecting with {REDACTED} now")
        );
        // Twice on one line, and mid-word.
        assert_eq!(
            m.mask("s3cr3t-value-heres3cr3t-value-here"),
            format!("{REDACTED}{REDACTED}")
        );
    }

    /// A variable is public by declaration — masking it would make a log
    /// useless for no benefit.
    #[test]
    fn a_variable_is_not_masked() {
        let m = resolved().masker();
        assert_eq!(m.mask("region is eu-west-1"), "region is eu-west-1");
    }

    /// Redacting every `ab` would turn a build log into confetti, and a
    /// two-character secret is not a secret.
    #[test]
    fn a_very_short_value_is_not_masked() {
        let m = resolved().masker();
        assert_eq!(m.mask("about a table"), "about a table");
    }

    /// Masking the shorter value first leaves `***def` behind, which reveals
    /// both the tail and that it was a prefix.
    #[test]
    fn overlapping_secrets_are_masked_longest_first() {
        let m = Masker::new(["abcd", "abcdefgh"].into_iter());
        assert_eq!(m.mask("abcdefgh"), REDACTED);
        assert_eq!(m.mask("abcd"), REDACTED);
        assert!(!m.mask("abcdefgh").contains("efgh"));
    }

    #[test]
    fn an_empty_masker_is_a_pass_through() {
        let m = Masker::new(std::iter::empty());
        assert!(m.is_empty());
        assert_eq!(m.mask("nothing to hide"), "nothing to hide");
    }

    /// The classification comes from `tags[]`, which `list` returns — so it is
    /// known before any value is read.
    #[test]
    fn scopes_separate_secrets_from_vars() {
        let (secrets, vars) = resolved().scopes();
        assert_eq!(secrets["TOKEN"], "s3cr3t-value-here");
        assert!(
            !secrets.as_object().unwrap().contains_key("REGION"),
            "REGION is a var, not a secret"
        );
        assert_eq!(vars["REGION"], "eu-west-1");
        assert!(!vars.as_object().unwrap().contains_key("TOKEN"));
    }

    /// heyosecret's prefix match is segment-wise, and the convention has to line
    /// up with that or `ci/app` would pull in `ci/app2`.
    #[test]
    fn a_prefix_is_segment_shaped_and_sanitized() {
        assert_eq!(Secrets::prefix("myapp", "prod"), "ci/myapp/prod");
        assert_eq!(
            Secrets::prefix("my app/../x", "pro d"),
            "ci/my-app-..-x/pro-d"
        );
        // `/` is the separator and must not survive from a component.
        assert!(!Secrets::prefix("a/b", "c")[3..].starts_with("a/b"));
    }

    /// A tenant's secrets live under its namespace whatever its workflow is
    /// called, so a tenant repository named after a fleet workflow — `deploy`
    /// here — reads `ci/ns/team-a/deploy/prod`, never `ci/deploy/prod`.
    #[test]
    fn a_tenant_prefix_is_under_its_namespace_and_cannot_collide_with_the_fleet() {
        assert_eq!(Secrets::prefix_in("", "deploy", "prod"), "ci/deploy/prod");
        assert_eq!(Secrets::prefix_in("team-a", "deploy", "prod"), "ci/ns/team-a/deploy/prod");
        assert_ne!(Secrets::prefix_in("team-a", "deploy", "prod"), Secrets::prefix("deploy", "prod"));
        // A namespace cannot climb out of its segment either.
        assert_eq!(Secrets::prefix_in("a/b", "w", "e"), "ci/ns/a-b/w/e");
    }

    #[test]
    fn a_name_is_the_leaf_of_its_path() {
        let p = "ci/app/prod";
        assert_eq!(
            leaf_name("ci/app/prod/DATABASE_URL", p).unwrap(),
            "DATABASE_URL"
        );
        assert_eq!(leaf_name("ci/app/prod/db/URL", p).unwrap(), "URL");
        // The prefix itself is not a secret.
        assert_eq!(leaf_name("ci/app/prod", p), None);
        // Something outside the prefix never became ours.
        assert_eq!(leaf_name("ci/other/prod/X", p), None);
    }

    /// An installation with no secret store must still run workflows that use
    /// no secrets.
    #[tokio::test]
    async fn an_unconfigured_store_resolves_to_nothing_rather_than_failing() {
        let s = Secrets {
            http: reqwest::Client::new(),
            base_url: None,
            token: None,
        };
        assert!(!s.is_configured());
        let r = s
            .resolve("ci/app/prod")
            .await
            .expect("no store is not an error");
        assert!(r.secrets.is_empty() && r.vars.is_empty());
    }

    /// The masker must survive a value containing regex or format
    /// metacharacters — it is a literal replace, and this pins that.
    #[test]
    fn a_secret_full_of_metacharacters_is_still_masked() {
        let m = Masker::new([r"$1.*+?[](){}\^"].into_iter());
        assert_eq!(m.mask(r"x $1.*+?[](){}\^ y"), format!("x {REDACTED} y"));
    }

    // ---- against a stub heyosecret ---------------------------------------
    //
    // A local server speaking heyosecret's exact wire shape, so the real client
    // is exercised: the two route spellings, the camelCase `valueBase64`, the
    // base64 decode, and the `tags[]` classification. A hand-rolled fake of the
    // *client* would only test the fake.

    #[tokio::test]
    async fn host_targets_only_read_operator_path() {
        let base = stub_heyosecret(vec![
            ("ci-controller/host-app-lb-targets", vec![], "operator mapping"),
            ("ci-controller/host-maintenance-targets", vec![], "maintenance mapping"),
            ("ci-controller/host-heyvm-bootstrap-targets", vec![], "bootstrap mapping"),
            ("ci/heyo-public/default/CI_HOST_APP_LB_TARGETS", vec![], "workflow spoof"),
            ("ci/heyo-public/default/CI_HOST_MAINTENANCE_TARGETS", vec![], "maintenance spoof"),
            ("ci/heyo-public/default/CI_HOST_HEYVM_BOOTSTRAP_TARGETS", vec![], "bootstrap spoof"),
        ]).await;
        let secrets = Secrets {
            http: reqwest::Client::new(), base_url: Some(base), token: Some("test".into()),
        };
        assert_eq!(secrets.host_app_lb_targets().await.unwrap(), "operator mapping");
        assert_eq!(secrets.host_maintenance_targets().await.unwrap(), "maintenance mapping");
        assert_eq!(secrets.host_heyvm_bootstrap_targets().await.unwrap(), "bootstrap mapping");
        let workflow = secrets.resolve("ci/heyo-public/default").await.unwrap();
        assert_eq!(workflow.secrets.len(), 3);
        assert_eq!(workflow.secrets["CI_HOST_APP_LB_TARGETS"], "workflow spoof");
        assert_eq!(workflow.secrets["CI_HOST_MAINTENANCE_TARGETS"], "maintenance spoof");
        assert_eq!(workflow.secrets["CI_HOST_HEYVM_BOOTSTRAP_TARGETS"], "bootstrap spoof");

        let base = stub_heyosecret(vec![
            ("ci/heyo-public/default/CI_HOST_APP_LB_TARGETS", vec![], "workflow spoof"),
            ("ci/heyo-public/default/CI_HOST_MAINTENANCE_TARGETS", vec![], "maintenance spoof"),
            ("ci/heyo-public/default/CI_HOST_HEYVM_BOOTSTRAP_TARGETS", vec![], "bootstrap spoof"),
        ]).await;
        let secrets = Secrets {
            http: reqwest::Client::new(), base_url: Some(base), token: Some("test".into()),
        };
        assert!(secrets.host_app_lb_targets().await.is_err());
        assert!(secrets.host_maintenance_targets().await.is_err());
        assert!(secrets.host_heyvm_bootstrap_targets().await.is_err());
    }

    async fn stub_heyosecret(
        entries: Vec<(&'static str, Vec<&'static str>, &'static str)>,
    ) -> String {
        use axum::routing::{get, post};
        use base64::Engine;

        let listing: Vec<serde_json::Value> = entries
            .iter()
            .map(|(path, tags, _)| serde_json::json!({ "path": path, "tags": tags }))
            .collect();
        let values: std::collections::HashMap<String, String> = entries
            .iter()
            .map(|(path, _, value)| {
                (
                    path.to_string(),
                    base64::engine::general_purpose::STANDARD.encode(value),
                )
            })
            .collect();

        let app = axum::Router::new()
            .route(
                "/v1/secrets",
                get({
                    let listing = listing.clone();
                    move |axum::extract::Query(q): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >| {
                        let prefix = q.get("prefix").cloned().unwrap_or_default();
                        // heyosecret's own match: the prefix itself, or a child
                        // segment under it. `ci/app` must not match `ci/app2`.
                        let filtered: Vec<_> = listing
                            .iter()
                            .filter(|e| {
                                let p = e["path"].as_str().unwrap_or("");
                                p == prefix || p.starts_with(&format!("{prefix}/"))
                            })
                            .cloned()
                            .collect();
                        async move { axum::Json(serde_json::json!({ "secrets": filtered })) }
                    }
                }),
            )
            .route(
                "/v1/secrets/read",
                post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                    let values = values.clone();
                    async move {
                        let path = body["path"].as_str().unwrap_or("");
                        match values.get(path) {
                            Some(v) => axum::Json(serde_json::json!({
                                "path": path, "version": 1, "status": "active",
                                "valueBase64": v, "createdAt": "2026-01-01T00:00:00Z"
                            }))
                            .into_response(),
                            // heyosecret answers 404 for every read failure.
                            None => (
                                axum::http::StatusCode::NOT_FOUND,
                                axum::Json(serde_json::json!({"error": "not found"})),
                            )
                                .into_response(),
                        }
                    }
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    fn client(base: &str) -> Secrets {
        Secrets {
            http: reqwest::Client::new(),
            base_url: Some(base.to_string()),
            token: Some("test-token".into()),
        }
    }

    #[tokio::test]
    async fn secrets_and_vars_are_split_by_the_public_tag() {
        let base = stub_heyosecret(vec![
            ("ci/app/prod/DATABASE_URL", vec![], "postgres://real"),
            ("ci/app/prod/REGION", vec!["public"], "eu-west-1"),
            ("ci/app/prod/API_KEY", vec!["rotate-me"], "k-12345678"),
        ])
        .await;

        let r = client(&base).resolve("ci/app/prod").await.unwrap();
        assert_eq!(r.secrets.get("DATABASE_URL").unwrap(), "postgres://real");
        assert_eq!(r.secrets.get("API_KEY").unwrap(), "k-12345678");
        assert_eq!(r.vars.get("REGION").unwrap(), "eu-west-1");
        assert!(
            !r.secrets.contains_key("REGION"),
            "a public tag makes it a var"
        );
        assert!(!r.vars.contains_key("DATABASE_URL"));

        // And the masker built from them hides exactly the secrets.
        let m = r.masker();
        assert_eq!(
            m.mask("url=postgres://real region=eu-west-1"),
            "url=*** region=eu-west-1"
        );
    }

    /// heyosecret's prefix match is segment-wise. If this app ever assumed a
    /// plain `starts_with`, `ci/app` would silently pull in `ci/app2`'s secrets.
    #[tokio::test]
    async fn a_prefix_does_not_leak_from_a_neighbouring_path() {
        let base = stub_heyosecret(vec![
            ("ci/app/prod/MINE", vec![], "mine"),
            ("ci/app2/prod/THEIRS", vec![], "theirs"),
        ])
        .await;
        let r = client(&base).resolve("ci/app/prod").await.unwrap();
        assert_eq!(
            r.secrets.len(),
            1,
            "{:?}",
            r.secrets.keys().collect::<Vec<_>>()
        );
        assert!(r.secrets.contains_key("MINE"));
    }

    /// A secret that lists but cannot be read is an error, not a silently empty
    /// value — an empty `${{ secrets.TOKEN }}` in a deploy step is worse than a
    /// failed build.
    #[tokio::test]
    async fn a_listed_but_unreadable_secret_fails_the_resolve() {
        use axum::routing::{get, post};
        let app = axum::Router::new()
            .route(
                "/v1/secrets",
                get(|| async {
                    axum::Json(serde_json::json!({
                        "secrets": [{"path": "ci/app/prod/GONE", "tags": []}]
                    }))
                }),
            )
            .route(
                "/v1/secrets/read",
                post(|| async {
                    (
                        axum::http::StatusCode::NOT_FOUND,
                        axum::Json(serde_json::json!({"error": "not found"})),
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let err = client(&format!("http://{addr}"))
            .resolve("ci/app/prod")
            .await
            .unwrap_err();
        assert!(matches!(err, SecretsError::Unreadable { .. }), "{err:?}");
        // The message has to name the path, because heyosecret's 404 does not.
        assert!(err.to_string().contains("ci/app/prod/GONE"), "{err}");
    }
}
