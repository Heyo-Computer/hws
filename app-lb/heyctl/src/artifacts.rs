//! A namespace's corner of the global artifact store, through app-lb's
//! `artifacts` plugin.
//!
//! The store is where a deployment's `artifact` image comes from. app-lb holds
//! its key and walls every request to the namespace's own `<ns>/` tags and
//! repositories (blobs and manifests by digest), so a namespace token is all a
//! caller needs. The operator names the store by enabling the plugin; it
//! installs itself into each namespace.
//!
//! This client covers what a program asks of the store: which tags exist,
//! moving and removing them, reading manifests, and a repository's visibility.
//! Pushing an image (hashing and uploading a multi-gigabyte rootfs, then
//! writing its manifest) is `heyctl artifact push`, or
//! [`crate::artifact::RegistryClient`] with the `artifact` feature.
//!
//! ```no_run
//! # async fn f() -> hws::Result<()> {
//! use hws::Client;
//!
//! let lb = Client::builder("https://admin.example.com")
//!     .token(std::env::var("APP_LB_TOKEN").unwrap())
//!     .build()?;
//!
//! let store = lb.artifacts("team-a");
//! for t in store.tags().await? {
//!     println!("{} → {}", t.tag, t.digest);
//! }
//! // Promote: point `latest` where `v2` points, then publish the repository.
//! let v2 = store.tag("team-a/web:v2").await?;
//! store.set_tag("team-a/web:latest", &v2.digest).await?;
//! store.set_repo("team-a/web", true, Some("The web image")).await?;
//! # Ok(()) }
//! ```

use crate::api::{Client, seg};
use crate::error::Result;
use crate::transport::{Method, Request};
use crate::types::*;
use serde_json::{Value, json};

/// The plugin id of the artifact store plugin.
pub const ARTIFACTS_PLUGIN: &str = "artifacts";

impl Client {
    /// One namespace's corner of the global artifact store, through app-lb's
    /// `artifacts` plugin.
    ///
    /// Cheap: it borrows nothing and makes no request until a method is
    /// called.
    pub fn artifacts(&self, namespace: impl Into<String>) -> ArtifactsClient {
        ArtifactsClient {
            client: self.clone(),
            namespace: namespace.into(),
        }
    }
}

/// One namespace's artifacts. See [`Client::artifacts`].
///
/// A reference outside `<namespace>/` is a [`crate::Error::Forbidden`] whose
/// message says what the namespace may reach. Every method answers
/// [`crate::Error::Conflict`] when the plugin is not installed in the
/// namespace (or is switched off for the fleet). Writes need `admin` over the
/// whole namespace.
#[derive(Debug, Clone)]
pub struct ArtifactsClient {
    client: Client,
    namespace: String,
}

/// A reference in a path: each segment encoded, the `/`s between them kept,
/// as the store's routes expect `<ns>/<repo>:<tag>`.
fn reference(r: &str) -> String {
    r.split('/').map(seg).collect::<Vec<_>>().join("/")
}

impl ArtifactsClient {
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    fn path(&self, rest: &str) -> String {
        let base = format!(
            "/namespaces/{}/plugins/{ARTIFACTS_PLUGIN}/api",
            seg(&self.namespace)
        );
        if rest.is_empty() {
            base
        } else {
            format!("{base}/{rest}")
        }
    }

    /// Whether there is a store, whether the namespace can publish to it,
    /// and the prefix its tags must carry.
    pub async fn info(&self) -> Result<ArtifactStoreInfo> {
        self.client
            .read(
                Request::new(Method::Get, self.path("")),
                "namespace",
                &self.namespace,
            )
            .await
    }

    /// Every tag under `<namespace>/`.
    pub async fn tags(&self) -> Result<Vec<ArtifactTag>> {
        self.client
            .read(
                Request::new(Method::Get, self.path("tags")),
                "namespace",
                &self.namespace,
            )
            .await
    }

    /// What one tag (`<ns>/<repo>:<tag>`) points at.
    pub async fn tag(&self, tag: &str) -> Result<ArtifactTag> {
        self.client
            .read(
                Request::new(Method::Get, self.path(&format!("tags/{}", reference(tag)))),
                "artifact",
                tag,
            )
            .await
    }

    /// Point `tag` at `digest` (a manifest already in the store), creating
    /// or moving it. Needs `admin`.
    pub async fn set_tag(&self, tag: &str, digest: &str) -> Result<()> {
        self.client
            .unit(
                Request::new(Method::Put, self.path(&format!("tags/{}", reference(tag))))
                    .text(digest),
                "artifact",
                tag,
            )
            .await
    }

    /// Remove a tag. What it pointed at stays until the store's GC finds it
    /// unreferenced. Needs `admin`.
    pub async fn delete_tag(&self, tag: &str) -> Result<()> {
        self.client
            .unit(
                Request::new(
                    Method::Delete,
                    self.path(&format!("tags/{}", reference(tag))),
                ),
                "artifact",
                tag,
            )
            .await
    }

    /// A manifest, by an owned tag or by digest, as the store wrote it.
    pub async fn manifest(&self, tag_or_digest: &str) -> Result<Value> {
        self.client
            .read(
                Request::new(
                    Method::Get,
                    self.path(&format!("manifests/{}", reference(tag_or_digest))),
                ),
                "artifact",
                tag_or_digest,
            )
            .await
    }

    /// A repository (`<ns>/<repo>`) and its tags.
    pub async fn repo(&self, repo: &str) -> Result<ArtifactRepo> {
        self.client
            .read(
                Request::new(
                    Method::Get,
                    self.path(&format!("repos/{}", reference(repo))),
                ),
                "artifact",
                repo,
            )
            .await
    }

    /// Set whether a repository is public — on the hub, pullable without a
    /// credential — and its description. Replaces both. Needs `admin`.
    pub async fn set_repo(
        &self,
        repo: &str,
        public: bool,
        description: Option<&str>,
    ) -> Result<ArtifactRepo> {
        self.client
            .read(
                Request::new(
                    Method::Put,
                    self.path(&format!("repos/{}", reference(repo))),
                )
                .json(json!({"public": public, "description": description})),
                "artifact",
                repo,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::stub::Stub;
    use std::sync::Arc;

    const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn client(stub: Stub) -> (Client, Arc<Stub>) {
        let stub = Arc::new(stub);
        (Client::with_transport(stub.clone()), stub)
    }

    #[tokio::test]
    async fn the_store_is_reached_through_the_namespace_plugin_prefix() {
        let (c, stub) = client(
            Stub::new()
                .json(200, json!({"namespace": "team-a", "available": true, "writable": true, "prefix": "team-a/"}))
                .json(200, json!([{"tag": "team-a/web:v2", "digest": D}]))
                .json(200, json!({"tag": "team-a/web:v2", "digest": D}))
                .reply(204, "")
                .reply(204, "")
                .json(200, json!({"kind": "heyvm.rootfs.v1"}))
                .json(200, json!({"repo": "team-a/web", "public": false, "tags": [{"tag": "team-a/web:v2", "name": "v2", "digest": D}]}))
                .json(200, json!({"repo": "team-a/web", "public": true, "description": "web", "updated": 5})),
        );
        let store = c.artifacts("team-a");
        assert!(store.info().await.unwrap().writable);
        assert_eq!(store.tags().await.unwrap()[0].digest, D);
        let v2 = store.tag("team-a/web:v2").await.unwrap();
        store
            .set_tag("team-a/web:latest", &v2.digest)
            .await
            .unwrap();
        store.delete_tag("team-a/web:old").await.unwrap();
        assert_eq!(store.manifest(D).await.unwrap()["kind"], "heyvm.rootfs.v1");
        assert_eq!(store.repo("team-a/web").await.unwrap().tags[0].name, "v2");
        assert!(
            store
                .set_repo("team-a/web", true, Some("web"))
                .await
                .unwrap()
                .public
        );

        let calls = stub.calls();
        let seen: Vec<String> = calls
            .iter()
            .map(|c| format!("{} {}", c.method.as_str(), c.path))
            .collect();
        let base = "/namespaces/team-a/plugins/artifacts/api";
        assert_eq!(
            seen,
            [
                format!("GET {base}"),
                format!("GET {base}/tags"),
                format!("GET {base}/tags/team-a/web%3Av2"),
                format!("PUT {base}/tags/team-a/web%3Alatest"),
                format!("DELETE {base}/tags/team-a/web%3Aold"),
                format!("GET {base}/manifests/{D}"),
                format!("GET {base}/repos/team-a/web"),
                format!("PUT {base}/repos/team-a/web"),
            ]
        );
        assert_eq!(calls[3].text.as_deref(), Some(D), "the digest goes as text");
        assert_eq!(calls[3].body, None);
        assert_eq!(
            calls[7].body,
            Some(json!({"public": true, "description": "web"}))
        );
    }

    #[tokio::test]
    async fn outside_the_namespace_is_forbidden_and_says_why() {
        let (c, _) = client(Stub::new().json(
            403,
            json!({"error": "namespace team-a may only reach artifacts under team-a/; other/web:v1 is outside it. Publish under a namespaced tag such as team-a/app:latest"}),
        ));
        let e = c.artifacts("team-a").tag("other/web:v1").await.unwrap_err();
        assert!(matches!(e, crate::Error::Forbidden { .. }), "{e:?}");
        assert!(e.to_string().contains("team-a/"), "{e}");
    }
}
