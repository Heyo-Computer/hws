//! The shared fleet store: one PostgreSQL that every app-lb in a fleet reads
//! and writes (`docs/design/fleet-shared-state.md` § 2).
//!
//! Used only when `APP_LB_FLEET_DATABASE_URL` is set. A single-server app-lb
//! never opens a connection and never links a line of this into its behaviour.
//!
//! **One table.** Every kind of record lives in `fleet.records`, keyed by
//! `(kind, key)`, rather than a table per kind: the change feed is then one
//! ordered index scan, and a transaction spanning kinds needs no union. Bodies
//! are `bytea`, the exact bytes the stores write to their files, so the local
//! snapshot is byte-for-byte what a single server would have written.
//!
//! **Revisions** come from one sequence. Every write transaction first takes
//! one advisory lock and holds it to commit, so revisions become visible in the
//! order they were allocated: a reader that has seen revision N can never later
//! find a committed N-1. Without that, a slow transaction's change would be
//! skipped by every feed that had already moved past it. Writes are admin
//! mutations, so serializing them costs nothing that matters.
//!
//! **Deletes are tombstones** (`body IS NULL`) carrying a revision of their
//! own, so the feed reports them. They are kept seven days; a host away longer
//! than that resynchronizes in full when it starts, which it does anyway.
//!
//! **Calls from synchronous code.** The stores are synchronous and are called
//! from async handlers, from startup before any runtime exists, and from the
//! proxy. A dedicated thread owns a small runtime and the connection pool; a
//! call hands it a job and waits, bounded by `APP_LB_FLEET_TIMEOUT_MS`. On a
//! multi-thread runtime the wait goes through `block_in_place`, so a worker
//! thread is handed off rather than stalled.

use crate::fleet_store::{Change, Expect, Revision, StoreError, Transactional, Write};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const URL_ENV: &str = "APP_LB_FLEET_DATABASE_URL";
pub const TIMEOUT_ENV: &str = "APP_LB_FLEET_TIMEOUT_MS";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// The schema every host shares. Tests use their own.
pub const SCHEMA: &str = "fleet";

/// Taken by every write transaction; see the module docs. Arbitrary, but
/// fixed: every app-lb in a fleet must agree on it.
const WRITE_LOCK: i64 = 0x6170_706c_6266_6c74; // "applbflt"
/// Taken while migrating, so two hosts starting together do not both try.
const MIGRATE_LOCK: i64 = 0x6170_706c_626d_6967; // "applbmig"
/// How long a tombstone outlives the delete it records.
pub const TOMBSTONE_DAYS: i32 = 7;

/// `{s}` is the schema.
const MIGRATIONS: &[(i32, &str)] = &[(
    1,
    r#"
CREATE SEQUENCE {s}.revision;
CREATE TABLE {s}.records (
    kind       text        NOT NULL,
    key        text        NOT NULL,
    body       bytea,
    revision   bigint      NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text        NOT NULL,
    PRIMARY KEY (kind, key)
);
CREATE INDEX records_by_revision ON {s}.records (revision);
CREATE TABLE {s}.leases (
    name       text        PRIMARY KEY,
    holder     text        NOT NULL,
    epoch      bigint      NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE TABLE {s}.meta (
    name       text        PRIMARY KEY,
    value      text        NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION {s}.notify_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('{s}_changes', NEW.revision::text);
    RETURN NULL;
END $$;
CREATE TRIGGER records_notify AFTER INSERT OR UPDATE ON {s}.records
    FOR EACH ROW EXECUTE FUNCTION {s}.notify_change();
"#,
)];

const UPSERT_ANY: &str = "INSERT INTO {s}.records (kind, key, body, revision, updated_by)
     VALUES ($1, $2, $3, nextval('{s}.revision'), $4)
     ON CONFLICT (kind, key) DO UPDATE
     SET body = EXCLUDED.body, revision = EXCLUDED.revision,
         updated_at = now(), updated_by = EXCLUDED.updated_by
     RETURNING revision";
const UPSERT_ABSENT: &str = "INSERT INTO {s}.records (kind, key, body, revision, updated_by)
     VALUES ($1, $2, $3, nextval('{s}.revision'), $4)
     ON CONFLICT (kind, key) DO UPDATE
     SET body = EXCLUDED.body, revision = EXCLUDED.revision,
         updated_at = now(), updated_by = EXCLUDED.updated_by
     WHERE {s}.records.body IS NULL
     RETURNING revision";
const UPDATE_AT: &str = "UPDATE {s}.records
     SET body = $3, revision = nextval('{s}.revision'), updated_at = now(), updated_by = $4
     WHERE kind = $1 AND key = $2 AND revision = $5 AND body IS NOT NULL
     RETURNING revision";
const TOMBSTONE_ANY: &str = "UPDATE {s}.records
     SET body = NULL, revision = nextval('{s}.revision'), updated_at = now(), updated_by = $3
     WHERE kind = $1 AND key = $2 AND body IS NOT NULL
     RETURNING revision";
const TOMBSTONE_AT: &str = "UPDATE {s}.records
     SET body = NULL, revision = nextval('{s}.revision'), updated_at = now(), updated_by = $3
     WHERE kind = $1 AND key = $2 AND revision = $4 AND body IS NOT NULL
     RETURNING revision";
const CURRENT: &str =
    "SELECT revision FROM {s}.records WHERE kind = $1 AND key = $2 AND body IS NOT NULL";
const GET: &str =
    "SELECT body, revision FROM {s}.records WHERE kind = $1 AND key = $2 AND body IS NOT NULL";
#[cfg_attr(not(test), allow(dead_code))]
const LIST: &str =
    "SELECT key, body, revision FROM {s}.records WHERE kind = $1 AND body IS NOT NULL";
const CHANGES: &str = "SELECT revision, kind, key, body FROM {s}.records
     WHERE revision > $1 ORDER BY revision LIMIT $2";
const FENCE: &str = "SELECT 1 FROM {s}.leases
     WHERE name = $1 AND holder = $2 AND epoch = $3 AND expires_at > now() FOR SHARE";
const ACQUIRE: &str = "INSERT INTO {s}.leases (name, holder, epoch, expires_at)
     VALUES ($1, $2, 1, now() + $3 * interval '1 millisecond')
     ON CONFLICT (name) DO UPDATE
     SET holder = EXCLUDED.holder, epoch = {s}.leases.epoch + 1, expires_at = EXCLUDED.expires_at
     WHERE {s}.leases.expires_at <= now()
     RETURNING epoch";
const RENEW: &str = "UPDATE {s}.leases SET expires_at = now() + $4 * interval '1 millisecond'
     WHERE name = $1 AND holder = $2 AND epoch = $3 AND expires_at > now()
     RETURNING epoch";
const RELEASE: &str = "UPDATE {s}.leases SET expires_at = now()
     WHERE name = $1 AND holder = $2 AND epoch = $3";
const GC: &str = "DELETE FROM {s}.records
     WHERE body IS NULL AND updated_at < now() - make_interval(days => $1)";

/// Every record of every kind, read in one consistent snapshot, with the
/// revision a feed should continue from.
#[derive(Debug, Default)]
pub struct Snapshot {
    pub cursor: Revision,
    /// `(kind, key, body, revision)`.
    pub records: Vec<(String, String, Vec<u8>, Revision)>,
    /// Whether some host has already seeded this database.
    pub seeded: Option<String>,
}

/// Why a call failed.
#[derive(Debug)]
pub enum PgFailure {
    /// The database could not be reached, or did not answer in time.
    Unavailable(String),
    /// A compare-and-swap or a fence did not hold.
    Store(StoreError),
    /// The database answered with an error: a bug, or a schema this binary
    /// does not understand.
    Query(String),
}

impl std::fmt::Display for PgFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(m) => write!(f, "fleet store unavailable: {m}"),
            Self::Store(e) => e.fmt(f),
            Self::Query(m) => write!(f, "fleet store query failed: {m}"),
        }
    }
}

/// The error a store sees when the database is out of reach. Recognisable with
/// [`is_unavailable`], so a handler can answer 503 rather than 500.
#[derive(Debug)]
pub struct Unavailable(pub String);

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fleet store unavailable: {}", self.0)
    }
}

impl std::error::Error for Unavailable {}

#[cfg_attr(not(test), allow(dead_code))]
pub fn is_unavailable(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<Unavailable>())
}

impl From<PgFailure> for StoreError {
    fn from(f: PgFailure) -> Self {
        match f {
            PgFailure::Store(e) => e,
            PgFailure::Unavailable(m) => StoreError::Io(io::Error::other(Unavailable(m))),
            PgFailure::Query(m) => StoreError::Io(io::Error::other(m)),
        }
    }
}

impl From<PgFailure> for io::Error {
    fn from(f: PgFailure) -> Self {
        StoreError::from(f).into()
    }
}

fn classify(e: tokio_postgres::Error) -> PgFailure {
    match e.as_db_error() {
        // Connection exceptions, operator intervention (shutdown, restart) and
        // too many connections are the database being away, not a bad query.
        Some(db) => {
            let code = db.code().code();
            if code.starts_with("08") || code.starts_with("57") || code == "53300" {
                PgFailure::Unavailable(db.to_string())
            } else {
                PgFailure::Query(db.to_string())
            }
        }
        None => PgFailure::Unavailable(e.to_string()),
    }
}

type Job = Box<dyn FnOnce(Pool) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// A connection to the fleet database. Cheap to share; every call goes through
/// one worker thread's pool.
pub struct PgStore {
    jobs: tokio::sync::mpsc::UnboundedSender<Job>,
    config: tokio_postgres::Config,
    tls: postgres_openssl::MakeTlsConnector,
    schema: String,
    /// `updated_by` on every write, and the lease holder's name.
    host: String,
    timeout: Duration,
    /// Whether the last call reached the database. Read by the admin API to
    /// refuse mutations up front, and reported by `/whoami`.
    up: AtomicBool,
    last_error: Mutex<Option<String>>,
}

impl std::fmt::Debug for PgStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the config: it holds the password.
        f.debug_struct("PgStore")
            .field("schema", &self.schema)
            .field("host", &self.host)
            .field("up", &self.up.load(Ordering::Relaxed))
            .finish()
    }
}

impl PgStore {
    /// Parse the URL and start the worker. Connects nothing yet: the first
    /// call does, so a database that is down at startup is a failed call, not
    /// a failed start.
    pub fn open(url: &str, host: &str, timeout: Duration) -> io::Result<Arc<Self>> {
        Self::open_in(url, host, timeout, SCHEMA)
    }

    pub fn open_in(
        url: &str,
        host: &str,
        timeout: Duration,
        schema: &str,
    ) -> io::Result<Arc<Self>> {
        let mut config: tokio_postgres::Config = url.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{URL_ENV} is not a PostgreSQL URL: {e}"),
            )
        })?;
        if config.get_connect_timeout().is_none() {
            config.connect_timeout(timeout);
        }
        config.application_name(format!("app-lb {host}"));
        let connector = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
            .map_err(io::Error::other)?
            .build();
        let tls = postgres_openssl::MakeTlsConnector::new(connector);
        let manager = Manager::from_config(
            config.clone(),
            tls.clone(),
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(4)
            .wait_timeout(Some(timeout))
            .create_timeout(Some(timeout))
            .recycle_timeout(Some(timeout))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .build()
            .map_err(io::Error::other)?;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Job>();
        std::thread::Builder::new()
            .name("fleet-store".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("the fleet store's runtime");
                rt.block_on(async move {
                    while let Some(job) = rx.recv().await {
                        tokio::spawn(job(pool.clone()));
                    }
                });
            })?;
        Ok(Arc::new(Self {
            jobs: tx,
            config,
            tls,
            schema: schema.to_string(),
            host: host.to_string(),
            timeout,
            up: AtomicBool::new(false),
            last_error: Mutex::new(None),
        }))
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// The `LISTEN` channel the change trigger notifies.
    pub fn channel(&self) -> String {
        format!("{}_changes", self.schema)
    }

    pub fn available(&self) -> bool {
        self.up.load(Ordering::Relaxed)
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn sql(&self, template: &str) -> String {
        template.replace("{s}", &self.schema)
    }

    fn observe<T>(&self, r: &Result<T, PgFailure>) {
        match r {
            Err(PgFailure::Unavailable(m)) => {
                if self.up.swap(false, Ordering::Relaxed) {
                    tracing::warn!(error = %m, "fleet store unreachable; serving from the local snapshot, mutations refused");
                }
                *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(m.clone());
            }
            _ => {
                if !self.up.swap(true, Ordering::Relaxed) {
                    tracing::info!("fleet store reachable");
                }
            }
        }
    }

    fn submit<T, F, Fut>(&self, f: F, reply: impl FnOnce(Result<T, PgFailure>) + Send + 'static)
    where
        T: Send + 'static,
        F: FnOnce(Pool) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, PgFailure>> + Send + 'static,
    {
        let timeout = self.timeout;
        let job: Job = Box::new(move |pool| {
            Box::pin(async move {
                let r = match tokio::time::timeout(timeout, f(pool)).await {
                    Ok(r) => r,
                    Err(_) => Err(PgFailure::Unavailable(format!(
                        "no answer within {} ms",
                        timeout.as_millis()
                    ))),
                };
                reply(r);
            })
        });
        // A send that fails drops the job, and the reply with it, which the
        // caller reads as the worker being gone.
        let _ = self.jobs.send(job);
    }

    /// Run `f` on the worker and wait for it, from any thread.
    pub fn call_blocking<T, F, Fut>(&self, f: F) -> Result<T, PgFailure>
    where
        T: Send + 'static,
        F: FnOnce(Pool) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, PgFailure>> + Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.submit(f, move |r| {
            let _ = tx.send(r);
        });
        let deadline = self.timeout + Duration::from_secs(1);
        let wait = || rx.recv_timeout(deadline);
        let r = match tokio::runtime::Handle::try_current() {
            Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(wait)
            }
            _ => wait(),
        };
        let r = r.unwrap_or_else(|_| {
            Err(PgFailure::Unavailable(
                "the fleet store worker did not answer".into(),
            ))
        });
        self.observe(&r);
        r
    }

    /// Run `f` on the worker and await it.
    pub async fn call<T, F, Fut>(&self, f: F) -> Result<T, PgFailure>
    where
        T: Send + 'static,
        F: FnOnce(Pool) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, PgFailure>> + Send + 'static,
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.submit(f, move |r| {
            let _ = tx.send(r);
        });
        let r = rx.await.unwrap_or_else(|_| {
            Err(PgFailure::Unavailable(
                "the fleet store worker did not answer".into(),
            ))
        });
        self.observe(&r);
        r
    }

    /// Create the schema, or bring it up to this binary's version.
    pub fn migrate(&self) -> Result<(), PgFailure> {
        let schema = self.schema.clone();
        self.call_blocking(move |pool| async move {
            let mut c = pool.get().await.map_err(pool_failure)?;
            let tx = c.transaction().await.map_err(classify)?;
            tx.execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATE_LOCK])
                .await
                .map_err(classify)?;
            tx.batch_execute(&format!(
                "CREATE SCHEMA IF NOT EXISTS {schema};
                 CREATE TABLE IF NOT EXISTS {schema}.migrations (
                     version    integer     PRIMARY KEY,
                     applied_at timestamptz NOT NULL DEFAULT now())"
            ))
            .await
            .map_err(classify)?;
            let applied: Vec<i32> = tx
                .query(&format!("SELECT version FROM {schema}.migrations"), &[])
                .await
                .map_err(classify)?
                .iter()
                .map(|r| r.get(0))
                .collect();
            for (version, sql) in MIGRATIONS {
                if applied.contains(version) {
                    continue;
                }
                tx.batch_execute(&sql.replace("{s}", &schema))
                    .await
                    .map_err(classify)?;
                tx.execute(
                    &format!("INSERT INTO {schema}.migrations (version) VALUES ($1)"),
                    &[version],
                )
                .await
                .map_err(classify)?;
                tracing::info!(version, schema = %schema, "fleet store migrated");
            }
            let newest = MIGRATIONS.last().map_or(0, |(v, _)| *v);
            if let Some(ahead) = applied.iter().copied().filter(|v| *v > newest).max() {
                tracing::warn!(
                    schema = %schema,
                    database = ahead,
                    binary = newest,
                    "the fleet store was migrated by a newer app-lb; this one only writes what it knows"
                );
            }
            tx.commit().await.map_err(classify)?;
            Ok(())
        })
    }

    pub fn get(&self, kind: &str, key: &str) -> Result<Option<(Vec<u8>, Revision)>, PgFailure> {
        let (sql, kind, key) = (self.sql(GET), kind.to_string(), key.to_string());
        self.call_blocking(move |pool| async move {
            let c = pool.get().await.map_err(pool_failure)?;
            let row = c.query_opt(&sql, &[&kind, &key]).await.map_err(classify)?;
            Ok(row.map(|r| (r.get::<_, Vec<u8>>(0), r.get::<_, i64>(1) as Revision)))
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn list(&self, kind: &str) -> Result<Vec<(String, Vec<u8>, Revision)>, PgFailure> {
        let (sql, kind) = (self.sql(LIST), kind.to_string());
        self.call_blocking(move |pool| async move {
            let c = pool.get().await.map_err(pool_failure)?;
            let rows = c.query(&sql, &[&kind]).await.map_err(classify)?;
            Ok(rows
                .iter()
                .map(|r| (r.get(0), r.get(1), r.get::<_, i64>(2) as Revision))
                .collect())
        })
    }

    pub fn put(
        &self,
        kind: &str,
        key: &str,
        body: &[u8],
        expect: Expect,
        fence: Option<(&str, u64)>,
    ) -> Result<Revision, PgFailure> {
        let write = Write::Put {
            kind: kind.to_string(),
            key: key.to_string(),
            body: body.to_vec(),
            expect,
        };
        Ok(self.write_all(vec![write], fence)?[0])
    }

    /// The revision of the tombstone, or `None` when there was nothing to delete.
    pub fn delete(
        &self,
        kind: &str,
        key: &str,
        expect: Expect,
        fence: Option<(&str, u64)>,
    ) -> Result<Option<Revision>, PgFailure> {
        let write = Write::Delete {
            kind: kind.to_string(),
            key: key.to_string(),
            expect,
        };
        let rev = self.write_all(vec![write], fence)?[0];
        Ok((rev != 0).then_some(rev))
    }

    fn write_all(
        &self,
        writes: Vec<Write>,
        fence: Option<(&str, u64)>,
    ) -> Result<Vec<Revision>, PgFailure> {
        let ctx = WriteCtx::new(self);
        let fence = fence.map(|(n, e)| (n.to_string(), e as i64));
        self.call_blocking(move |pool| async move {
            let mut c = pool.get().await.map_err(pool_failure)?;
            let tx = c.transaction().await.map_err(classify)?;
            tx.execute("SELECT pg_advisory_xact_lock($1)", &[&WRITE_LOCK])
                .await
                .map_err(classify)?;
            if let Some((lease, epoch)) = &fence {
                let held = tx
                    .query_opt(&ctx.fence, &[lease, &ctx.host, epoch])
                    .await
                    .map_err(classify)?;
                if held.is_none() {
                    return Err(PgFailure::Store(StoreError::Fenced {
                        lease: lease.clone(),
                    }));
                }
            }
            let mut revisions = Vec::with_capacity(writes.len());
            for w in &writes {
                revisions.push(ctx.apply(&tx, w).await?);
            }
            tx.commit().await.map_err(classify)?;
            Ok(revisions)
        })
    }

    /// Every live record in one consistent read, with the cursor to follow
    /// changes from.
    pub fn snapshot(&self) -> Result<Snapshot, PgFailure> {
        let schema = self.schema.clone();
        self.call_blocking(move |pool| async move {
            let mut c = pool.get().await.map_err(pool_failure)?;
            let tx = c
                .build_transaction()
                .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
                .read_only(true)
                .start()
                .await
                .map_err(classify)?;
            let cursor: i64 = tx
                .query_one(
                    &format!("SELECT coalesce(max(revision), 0) FROM {schema}.records"),
                    &[],
                )
                .await
                .map_err(classify)?
                .get(0);
            let records = tx
                .query(
                    &format!(
                        "SELECT kind, key, body, revision FROM {schema}.records WHERE body IS NOT NULL"
                    ),
                    &[],
                )
                .await
                .map_err(classify)?
                .iter()
                .map(|r| (r.get(0), r.get(1), r.get(2), r.get::<_, i64>(3) as Revision))
                .collect();
            let seeded = tx
                .query_opt(
                    &format!("SELECT value FROM {schema}.meta WHERE name = 'seeded'"),
                    &[],
                )
                .await
                .map_err(classify)?
                .map(|r| r.get(0));
            tx.commit().await.map_err(classify)?;
            Ok(Snapshot {
                cursor: cursor as Revision,
                records,
                seeded,
            })
        })
    }

    /// Write a host's records into a database nobody has seeded yet, and mark
    /// it seeded, in one transaction. `Ok(false)` when another host got there
    /// first, in which case nothing was written.
    pub fn seed(&self, writes: Vec<Write>) -> Result<bool, PgFailure> {
        let ctx = WriteCtx::new(self);
        let schema = self.schema.clone();
        self.call_blocking(move |pool| async move {
            let mut c = pool.get().await.map_err(pool_failure)?;
            let tx = c.transaction().await.map_err(classify)?;
            tx.execute("SELECT pg_advisory_xact_lock($1)", &[&WRITE_LOCK])
                .await
                .map_err(classify)?;
            let claimed = tx
                .query_opt(
                    &format!(
                        "INSERT INTO {schema}.meta (name, value) VALUES ('seeded', $1)
                         ON CONFLICT (name) DO NOTHING RETURNING name"
                    ),
                    &[&ctx.host],
                )
                .await
                .map_err(classify)?;
            if claimed.is_none() {
                return Ok(false);
            }
            for w in &writes {
                ctx.apply(&tx, w).await?;
            }
            tx.commit().await.map_err(classify)?;
            Ok(true)
        })
    }

    pub async fn changes_after(
        &self,
        cursor: Revision,
        limit: usize,
    ) -> Result<Vec<Change>, PgFailure> {
        let sql = self.sql(CHANGES);
        self.call(move |pool| async move {
            let c = pool.get().await.map_err(pool_failure)?;
            let rows = c
                .query(&sql, &[&(cursor as i64), &(limit as i64)])
                .await
                .map_err(classify)?;
            Ok(rows.iter().map(change_from_row).collect())
        })
        .await
    }

    /// Take the lease if it is free or expired. `Some(epoch)` on success.
    pub async fn acquire(&self, lease: &str, ttl: Duration) -> Result<Option<u64>, PgFailure> {
        let (sql, lease, holder) = (self.sql(ACQUIRE), lease.to_string(), self.host.clone());
        let ms = ttl.as_millis() as f64;
        self.call(move |pool| async move {
            let c = pool.get().await.map_err(pool_failure)?;
            let row = c
                .query_opt(&sql, &[&lease, &holder, &ms])
                .await
                .map_err(classify)?;
            Ok(row.map(|r| r.get::<_, i64>(0) as u64))
        })
        .await
    }

    /// Extend a lease still held at `epoch`. `false` when it was lost.
    pub async fn renew(&self, lease: &str, epoch: u64, ttl: Duration) -> Result<bool, PgFailure> {
        let (sql, lease, holder) = (self.sql(RENEW), lease.to_string(), self.host.clone());
        let ms = ttl.as_millis() as f64;
        self.call(move |pool| async move {
            let c = pool.get().await.map_err(pool_failure)?;
            let row = c
                .query_opt(&sql, &[&lease, &holder, &(epoch as i64), &ms])
                .await
                .map_err(classify)?;
            Ok(row.is_some())
        })
        .await
    }

    pub async fn release(&self, lease: &str, epoch: u64) -> Result<(), PgFailure> {
        let (sql, lease, holder) = (self.sql(RELEASE), lease.to_string(), self.host.clone());
        self.call(move |pool| async move {
            let c = pool.get().await.map_err(pool_failure)?;
            c.execute(&sql, &[&lease, &holder, &(epoch as i64)])
                .await
                .map_err(classify)?;
            Ok(())
        })
        .await
    }

    /// Drop tombstones older than [`TOMBSTONE_DAYS`]. Returns how many.
    pub async fn collect_tombstones(&self) -> Result<u64, PgFailure> {
        let sql = self.sql(GC);
        self.call(move |pool| async move {
            let c = pool.get().await.map_err(pool_failure)?;
            c.execute(&sql, &[&TOMBSTONE_DAYS]).await.map_err(classify)
        })
        .await
    }

    /// A connection of its own that hears the change trigger. The receiver
    /// yields once per notification and ends when the connection does. Runs
    /// on the caller's runtime, not the worker's: it lives as long as the feed.
    pub async fn listen(
        &self,
    ) -> Result<
        (
            tokio_postgres::Client,
            tokio::sync::mpsc::UnboundedReceiver<()>,
        ),
        PgFailure,
    > {
        use futures::StreamExt;
        let (client, mut conn) =
            tokio::time::timeout(self.timeout, self.config.connect(self.tls.clone()))
                .await
                .map_err(|_| PgFailure::Unavailable("LISTEN connection timed out".into()))?
                .map_err(classify)?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut messages = futures::stream::poll_fn(move |cx| conn.poll_message(cx));
            while let Some(message) = messages.next().await {
                match message {
                    Ok(tokio_postgres::AsyncMessage::Notification(_)) => {
                        if tx.send(()).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        client
            .batch_execute(&format!("LISTEN {}", self.channel()))
            .await
            .map_err(classify)?;
        Ok((client, rx))
    }
}

impl Transactional for PgStore {
    fn transaction(
        &self,
        writes: &[Write],
        fence: Option<(&str, u64)>,
    ) -> Result<Vec<Revision>, StoreError> {
        Ok(self.write_all(writes.to_vec(), fence)?)
    }

    fn changes_since(&self, cursor: Revision, limit: usize) -> io::Result<Vec<Change>> {
        let sql = self.sql(CHANGES);
        Ok(self.call_blocking(move |pool| async move {
            let c = pool.get().await.map_err(pool_failure)?;
            let rows = c
                .query(&sql, &[&(cursor as i64), &(limit as i64)])
                .await
                .map_err(classify)?;
            Ok(rows.iter().map(change_from_row).collect())
        })?)
    }
}

fn change_from_row(r: &tokio_postgres::Row) -> Change {
    Change {
        revision: r.get::<_, i64>(0) as Revision,
        kind: r.get(1),
        key: r.get(2),
        body: r.get(3),
    }
}

fn pool_failure(e: deadpool_postgres::PoolError) -> PgFailure {
    match e {
        deadpool_postgres::PoolError::Backend(e) => classify(e),
        other => PgFailure::Unavailable(other.to_string()),
    }
}

/// The SQL and identity a write transaction needs, moved onto the worker.
struct WriteCtx {
    host: String,
    upsert_any: String,
    upsert_absent: String,
    update_at: String,
    tombstone_any: String,
    tombstone_at: String,
    current: String,
    fence: String,
}

impl WriteCtx {
    fn new(store: &PgStore) -> Self {
        Self {
            host: store.host.clone(),
            upsert_any: store.sql(UPSERT_ANY),
            upsert_absent: store.sql(UPSERT_ABSENT),
            update_at: store.sql(UPDATE_AT),
            tombstone_any: store.sql(TOMBSTONE_ANY),
            tombstone_at: store.sql(TOMBSTONE_AT),
            current: store.sql(CURRENT),
            fence: store.sql(FENCE),
        }
    }

    async fn apply(
        &self,
        tx: &deadpool_postgres::Transaction<'_>,
        w: &Write,
    ) -> Result<Revision, PgFailure> {
        let revision =
            |row: Option<tokio_postgres::Row>| row.map(|r| r.get::<_, i64>(0) as Revision);
        match w {
            Write::Put {
                kind,
                key,
                body,
                expect,
            } => {
                let row = match expect {
                    Expect::Any => {
                        tx.query_opt(&self.upsert_any, &[kind, key, body, &self.host])
                            .await
                    }
                    Expect::Absent => {
                        tx.query_opt(&self.upsert_absent, &[kind, key, body, &self.host])
                            .await
                    }
                    Expect::Revision(r) => {
                        tx.query_opt(
                            &self.update_at,
                            &[kind, key, body, &self.host, &(*r as i64)],
                        )
                        .await
                    }
                }
                .map_err(classify)?;
                match revision(row) {
                    Some(r) => Ok(r),
                    None => Err(self.conflict(tx, kind, key).await),
                }
            }
            Write::Delete { kind, key, expect } => match expect {
                Expect::Any => {
                    let row = tx
                        .query_opt(&self.tombstone_any, &[kind, key, &self.host])
                        .await
                        .map_err(classify)?;
                    Ok(revision(row).unwrap_or(0))
                }
                Expect::Absent => match self.current_revision(tx, kind, key).await? {
                    Some(_) => Err(self.conflict(tx, kind, key).await),
                    None => Ok(0),
                },
                Expect::Revision(r) => {
                    let row = tx
                        .query_opt(&self.tombstone_at, &[kind, key, &self.host, &(*r as i64)])
                        .await
                        .map_err(classify)?;
                    match revision(row) {
                        Some(r) => Ok(r),
                        None => Err(self.conflict(tx, kind, key).await),
                    }
                }
            },
        }
    }

    async fn current_revision(
        &self,
        tx: &deadpool_postgres::Transaction<'_>,
        kind: &str,
        key: &str,
    ) -> Result<Option<Revision>, PgFailure> {
        let row = tx
            .query_opt(&self.current, &[&kind, &key])
            .await
            .map_err(classify)?;
        Ok(row.map(|r| r.get::<_, i64>(0) as Revision))
    }

    async fn conflict(
        &self,
        tx: &deadpool_postgres::Transaction<'_>,
        kind: &str,
        key: &str,
    ) -> PgFailure {
        match self.current_revision(tx, kind, key).await {
            Ok(current) => PgFailure::Store(StoreError::Conflict {
                key: format!("{kind}/{key}"),
                current,
            }),
            Err(e) => e,
        }
    }
}

/// The timeout from the environment, or the default.
pub fn timeout_from_env() -> Duration {
    std::env::var(TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_TIMEOUT)
}

#[cfg(test)]
pub(crate) mod tests {
    //! Against a real PostgreSQL, when `APP_LB_FLEET_TEST_DATABASE_URL` names
    //! one; skipped otherwise. Each test works in a schema of its own, so they
    //! run concurrently against one database.
    use super::*;

    pub(crate) const TEST_URL_ENV: &str = "APP_LB_FLEET_TEST_DATABASE_URL";

    pub(crate) fn test_store(name: &str, host: &str) -> Option<Arc<PgStore>> {
        let url = std::env::var(TEST_URL_ENV).ok()?;
        let schema = format!(
            "t_{name}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        );
        let store = PgStore::open_in(&url, host, Duration::from_secs(5), &schema).unwrap();
        store.migrate().unwrap();
        Some(store)
    }

    /// A second host on the same schema.
    pub(crate) fn peer(store: &PgStore, host: &str) -> Arc<PgStore> {
        let url = std::env::var(TEST_URL_ENV).unwrap();
        let peer = PgStore::open_in(&url, host, Duration::from_secs(5), store.schema()).unwrap();
        peer.migrate().unwrap();
        peer
    }

    macro_rules! store_or_skip {
        ($name:expr) => {
            match test_store($name, "host-a") {
                Some(s) => s,
                None => {
                    eprintln!("skipped: {TEST_URL_ENV} is not set");
                    return;
                }
            }
        };
    }

    #[test]
    fn put_get_list_delete_round_trip() {
        let s = store_or_skip!("rt");
        let r1 = s.put("ns", "a", b"one", Expect::Absent, None).unwrap();
        assert_eq!(s.get("ns", "a").unwrap(), Some((b"one".to_vec(), r1)));
        let r2 = s
            .put("ns", "a", b"two", Expect::Revision(r1), None)
            .unwrap();
        assert!(r2 > r1);
        s.put("ns", "b", b"bee", Expect::Any, None).unwrap();
        s.put("other", "a", b"x", Expect::Any, None).unwrap();
        let mut keys: Vec<_> = s.list("ns").unwrap().into_iter().map(|(k, ..)| k).collect();
        keys.sort();
        assert_eq!(keys, ["a", "b"]);
        assert!(
            s.delete("ns", "a", Expect::Revision(r2), None)
                .unwrap()
                .is_some()
        );
        assert_eq!(s.get("ns", "a").unwrap(), None);
        assert_eq!(
            s.delete("ns", "a", Expect::Any, None).unwrap(),
            None,
            "already gone"
        );
        // A tombstone is absent: it can be created again.
        s.put("ns", "a", b"three", Expect::Absent, None).unwrap();
        assert!(s.available());
    }

    #[test]
    fn a_stale_revision_is_a_conflict_that_names_the_current_one() {
        let s = store_or_skip!("cas");
        let r1 = s.put("ns", "a", b"one", Expect::Any, None).unwrap();
        let r2 = s
            .put("ns", "a", b"two", Expect::Revision(r1), None)
            .unwrap();
        match s.put("ns", "a", b"lost", Expect::Revision(r1), None) {
            Err(PgFailure::Store(StoreError::Conflict { current, .. })) => {
                assert_eq!(current, Some(r2))
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
        match s.put("ns", "a", b"dup", Expect::Absent, None) {
            Err(PgFailure::Store(StoreError::Conflict { .. })) => {}
            other => panic!("expected a conflict, got {other:?}"),
        }
        assert_eq!(s.get("ns", "a").unwrap().unwrap().0, b"two");
    }

    #[test]
    fn a_transaction_lands_whole_or_not_at_all() {
        let s = store_or_skip!("txn");
        let r = s.put("ns", "a", b"one", Expect::Any, None).unwrap();
        let writes = vec![
            Write::Put {
                kind: "ns".into(),
                key: "b".into(),
                body: b"bee".to_vec(),
                expect: Expect::Absent,
            },
            Write::Put {
                kind: "ns".into(),
                key: "a".into(),
                body: b"stale".to_vec(),
                expect: Expect::Revision(r + 100),
            },
        ];
        assert!(s.transaction(&writes, None).is_err());
        assert_eq!(
            s.get("ns", "b").unwrap(),
            None,
            "the first write rolled back"
        );
        let ok = vec![
            Write::Put {
                kind: "ns".into(),
                key: "b".into(),
                body: b"bee".to_vec(),
                expect: Expect::Absent,
            },
            Write::Delete {
                kind: "ns".into(),
                key: "a".into(),
                expect: Expect::Revision(r),
            },
        ];
        let revs = s.transaction(&ok, None).unwrap();
        assert_eq!(revs.len(), 2);
        assert!(s.get("ns", "a").unwrap().is_none());
    }

    #[test]
    fn the_feed_reports_puts_and_deletes_in_revision_order() {
        let s = store_or_skip!("feed");
        let base = s.snapshot().unwrap().cursor;
        let a = s.put("ns", "a", b"one", Expect::Any, None).unwrap();
        let b = s.put("ns", "b", b"bee", Expect::Any, None).unwrap();
        let gone = s.delete("ns", "a", Expect::Any, None).unwrap().unwrap();
        let changes = s.changes_since(base, 100).unwrap();
        // `a` changed twice and appears once, as its tombstone.
        assert_eq!(
            changes
                .iter()
                .map(|c| (c.key.as_str(), c.revision, c.body.is_some()))
                .collect::<Vec<_>>(),
            [("b", b, true), ("a", gone, false)]
        );
        assert!(a < b && b < gone);
        assert!(s.changes_since(gone, 100).unwrap().is_empty());
        assert_eq!(s.changes_since(base, 1).unwrap().len(), 1, "limit holds");
    }

    #[test]
    fn seeding_happens_once() {
        let s = store_or_skip!("seed");
        let write = |key: &str| Write::Put {
            kind: "ns".into(),
            key: key.into(),
            body: b"x".to_vec(),
            expect: Expect::Absent,
        };
        assert!(s.seed(vec![write("a")]).unwrap());
        let other = peer(&s, "host-b");
        assert!(!other.seed(vec![write("b")]).unwrap(), "already seeded");
        let snap = other.snapshot().unwrap();
        assert_eq!(snap.seeded.as_deref(), Some("host-a"));
        assert_eq!(snap.records.len(), 1);
        assert_eq!(snap.cursor, snap.records[0].3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lease_has_one_holder_and_fences_the_last_one() {
        let Some(a) = test_store("lease", "host-a") else {
            eprintln!("skipped: {TEST_URL_ENV} is not set");
            return;
        };
        let b = peer(&a, "host-b");
        let ttl = Duration::from_millis(400);
        let epoch = a.acquire("acme", ttl).await.unwrap().expect("free lease");
        assert_eq!(b.acquire("acme", ttl).await.unwrap(), None, "held by a");
        assert!(a.renew("acme", epoch, ttl).await.unwrap());
        a.put("certs", "x", b"chain", Expect::Any, Some(("acme", epoch)))
            .unwrap();

        // a stops renewing; b takes over once it lapses, under a new epoch.
        tokio::time::sleep(Duration::from_millis(600)).await;
        let next = b
            .acquire("acme", ttl)
            .await
            .unwrap()
            .expect("expired lease");
        assert!(next > epoch);
        assert!(!a.renew("acme", epoch, ttl).await.unwrap(), "a lost it");
        match a.put("certs", "x", b"stale", Expect::Any, Some(("acme", epoch))) {
            Err(PgFailure::Store(StoreError::Fenced { lease })) => assert_eq!(lease, "acme"),
            other => panic!("the old holder must be fenced, got {other:?}"),
        }
        b.put("certs", "x", b"fresh", Expect::Any, Some(("acme", next)))
            .unwrap();
        assert_eq!(a.get("certs", "x").unwrap().unwrap().0, b"fresh");
        b.release("acme", next).await.unwrap();
        assert!(a.acquire("acme", ttl).await.unwrap().is_some(), "released");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn listen_hears_a_write() {
        let Some(s) = test_store("listen", "host-a") else {
            eprintln!("skipped: {TEST_URL_ENV} is not set");
            return;
        };
        let (_client, mut rx) = s.listen().await.unwrap();
        s.put("ns", "a", b"one", Expect::Any, None).unwrap();
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a notification")
            .expect("the channel is open");
    }

    #[test]
    fn an_unreachable_database_is_unavailable_not_a_crash() {
        // Port 9 (discard) is closed on any test machine worth the name.
        let s = PgStore::open_in(
            "postgres://u:p@127.0.0.1:9/db?connect_timeout=1",
            "host-a",
            Duration::from_secs(2),
            "fleet",
        )
        .unwrap();
        match s.get("ns", "a") {
            Err(PgFailure::Unavailable(_)) => {}
            other => panic!("expected unavailable, got {other:?}"),
        }
        assert!(!s.available());
        let e: io::Error = s
            .put("ns", "a", b"x", Expect::Any, None)
            .unwrap_err()
            .into();
        assert!(is_unavailable(&e));
    }
}
