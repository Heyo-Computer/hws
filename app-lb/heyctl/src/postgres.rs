//! A namespace's Postgres databases, through app-lb's `postgres` plugin.
//!
//! The operator switches the plugin on for the fleet, pointing it at the
//! region's pg-fc pool; a namespace administrator installs it into their
//! namespace ([`Client::install_plugin`]). Each database then gets its own
//! role and password, and by default its credentials are also written to the
//! namespace secret `pg-<name>` (`url`, `host`, `port`, `database`, `user`,
//! `password`), where a deployment's `env_from` can read them.
//!
//! ```no_run
//! # async fn f() -> hws::Result<()> {
//! use hws::{Client, NewDatabase};
//!
//! let lb = Client::builder("https://admin.example.com")
//!     .token(std::env::var("APP_LB_TOKEN").unwrap())
//!     .build()?;
//!
//! lb.install_plugin("team-a", "postgres", None).await?;
//!
//! let pg = lb.postgres("team-a");
//! let db = pg.create_database(&NewDatabase::new("app")).await?;
//! // The password is returned this once; it is also in the secret `pg-app`.
//! println!("{} → secret {:?}", db.database, db.secret);
//! for d in pg.databases().await?.databases {
//!     println!("{} ({})", d.name, d.database);
//! }
//! pg.delete_database("app").await?;
//! # Ok(()) }
//! ```

use crate::api::{Client, Raw, seg};
use crate::error::Result;
use crate::transport::{Method, Request};
use crate::types::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// The plugin id of the Postgres plugin.
pub const POSTGRES_PLUGIN: &str = "postgres";

impl Client {
    /// One namespace's Postgres databases, through app-lb's `postgres`
    /// plugin.
    ///
    /// Cheap: it borrows nothing and makes no request until a method is
    /// called.
    pub fn postgres(&self, namespace: impl Into<String>) -> PostgresClient {
        PostgresClient {
            client: self.clone(),
            namespace: namespace.into(),
        }
    }
}

/// What [`PostgresClient::create_database`] asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDatabase {
    /// 1–31 lowercase letters, digits or `_`, starting with a letter.
    pub name: String,
    /// Also write the credentials to the namespace secret `pg-<name>`.
    /// On by default.
    pub secret: bool,
}

impl NewDatabase {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            secret: true,
        }
    }

    /// Return the credentials only, without writing the `pg-<name>` secret.
    pub fn without_secret(mut self) -> Self {
        self.secret = false;
        self
    }
}

/// One namespace's Postgres databases. See [`Client::postgres`].
///
/// Every method answers [`crate::Error::Conflict`] when the `postgres`
/// plugin is not installed in the namespace (or is switched off for the
/// fleet); the error's message says which, and how to fix it.
#[derive(Debug, Clone)]
pub struct PostgresClient {
    client: Client,
    namespace: String,
}

impl PostgresClient {
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    fn path(&self, rest: &str) -> String {
        format!(
            "/namespaces/{}/plugins/{POSTGRES_PLUGIN}/api/{rest}",
            seg(&self.namespace)
        )
    }

    /// The namespace's databases, and where they are reached. Never carries
    /// a password.
    pub async fn databases(&self) -> Result<PostgresDatabases> {
        self.databases_as().await
    }

    async fn databases_as<T: DeserializeOwned>(&self) -> Result<T> {
        self.client
            .read(
                Request::new(Method::Get, self.path("databases")),
                "namespace",
                &self.namespace,
            )
            .await
    }

    /// Create a database with its own role and password. Needs `admin` in
    /// the namespace.
    ///
    /// The password comes back this once. A name the namespace already
    /// uses, a `pg-<name>` secret that already exists, or a namespace at the
    /// host's limit is a [`crate::Error::Conflict`].
    pub async fn create_database(&self, new: &NewDatabase) -> Result<CreatedPostgresDatabase> {
        self.client
            .read(
                Request::new(Method::Post, self.path("databases"))
                    .json(json!({"name": new.name, "secret": new.secret})),
                "database",
                &new.name,
            )
            .await
    }

    /// Revoke a database's credential and forget it. Needs `admin` in the
    /// namespace. Its data stays on pg-fc until an operator purges it, and
    /// its `pg-<name>` secret is left in place.
    pub async fn delete_database(&self, name: &str) -> Result<DeletedPostgresDatabase> {
        self.client
            .read(
                Request::new(
                    Method::Delete,
                    self.path(&format!("databases/{}", seg(name))),
                ),
                "database",
                name,
            )
            .await
    }
}

/// The same read, unparsed — for printing a response without losing what
/// this build does not name. See [`Client::raw`].
impl Raw<'_> {
    pub async fn postgres_databases(&self, namespace: &str) -> Result<Value> {
        self.0.postgres(namespace).databases_as().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::stub::Stub;
    use std::sync::Arc;

    fn client(stub: Stub) -> (Client, Arc<Stub>) {
        let stub = Arc::new(stub);
        (Client::with_transport(stub.clone()), stub)
    }

    #[tokio::test]
    async fn databases_are_managed_through_the_namespace_plugin_prefix() {
        let (c, stub) = client(
            Stub::new()
                .json(
                    201,
                    json!({"name": "app", "database": "ns_team_a_app", "user": "ns_team_a_app",
                        "password": "hunter2", "host": "pg.example", "port": 6432,
                        "sslmode": "require", "url": "postgres://ns_team_a_app:hunter2@pg.example:6432/ns_team_a_app?sslmode=require",
                        "secret": "pg-app", "secret_error": null, "status": "provisioning", "note": "once"}),
                )
                .json(
                    201,
                    json!({"name": "scratch", "database": "ns_team_a_scratch", "password": "x",
                        "secret": null}),
                )
                .json(
                    200,
                    json!({"namespace": "team a", "host": "pg.example", "port": 6432, "limit": 10,
                        "databases": [{"name": "app", "database": "ns_team_a_app", "live": true}],
                        "error": null}),
                )
                .json(
                    200,
                    json!({"deleted": "app", "database": "ns_team_a_app", "secret_kept": "pg-app"}),
                ),
        );
        let pg = c.postgres("team a");
        let db = pg.create_database(&NewDatabase::new("app")).await.unwrap();
        assert_eq!(db.password, "hunter2");
        assert_eq!(db.secret.as_deref(), Some("pg-app"));
        let shown = format!("{db:?}");
        assert!(
            !shown.contains("hunter2"),
            "Debug leaks the credential: {shown}"
        );
        let bare = pg
            .create_database(&NewDatabase::new("scratch").without_secret())
            .await
            .unwrap();
        assert!(bare.secret.is_none());
        let list = pg.databases().await.unwrap();
        assert_eq!(list.databases[0].name, "app");
        assert_eq!(list.databases[0].live, Some(true));
        assert_eq!(list.limit, 10);
        let gone = pg.delete_database("app").await.unwrap();
        assert_eq!(gone.secret_kept.as_deref(), Some("pg-app"));

        let calls = stub.calls();
        let seen: Vec<(Method, &str)> = calls.iter().map(|c| (c.method, c.path.as_str())).collect();
        assert_eq!(
            seen,
            [
                (
                    Method::Post,
                    "/namespaces/team%20a/plugins/postgres/api/databases"
                ),
                (
                    Method::Post,
                    "/namespaces/team%20a/plugins/postgres/api/databases"
                ),
                (
                    Method::Get,
                    "/namespaces/team%20a/plugins/postgres/api/databases"
                ),
                (
                    Method::Delete,
                    "/namespaces/team%20a/plugins/postgres/api/databases/app"
                ),
            ]
        );
        assert_eq!(calls[0].body, Some(json!({"name": "app", "secret": true})));
        assert_eq!(
            calls[1].body,
            Some(json!({"name": "scratch", "secret": false}))
        );
    }

    #[tokio::test]
    async fn not_installed_is_a_conflict_that_says_how_to_install() {
        let (c, _) = client(Stub::new().json(
            409,
            json!({"error": "the postgres plugin is not installed in namespace \"a\"; install it with `heyctl plugins install postgres -n a`",
                "code": "plugin_not_installed"}),
        ));
        let e = c.postgres("a").databases().await.unwrap_err();
        assert!(matches!(e, crate::Error::Conflict { .. }), "{e:?}");
        assert!(e.to_string().contains("plugins install postgres"), "{e}");
    }
}
