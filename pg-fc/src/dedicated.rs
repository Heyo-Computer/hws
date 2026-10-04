//! Dedicated databases: a fixed database name bound to its own Postgres role
//! and password, served — like every other schema — by its own microVM.
//!
//! The pooler's default contract is *schema routing*: whatever database name a
//! client puts in its startup packet becomes a schema, and the pooler lazily
//! builds a VM for it. One shared password ([`crate::config::Config::pg_password`])
//! gates the whole namespace, so any client holding it can mint an unbounded
//! number of VMs just by connecting with new names.
//!
//! A *dedicated* database inverts that. An operator provisions
//! `(database, role, password)` up front — over the admin API or the dashboard —
//! and the resulting credential is scoped to exactly one database:
//!
//!   * the role authenticates with **its own** password, never the shared one;
//!   * it may open **only** the database it was created for — asking for any
//!     other name is refused at the pooler, so these credentials can never
//!     provision a second VM (see [`Credentials::authorize`]);
//!   * conversely a dedicated database is reachable *only* through its own
//!     role, so shared-password clients can't wander into a tenant's data.
//!
//! Everything below the routing decision is unchanged: the database name is
//! still the schema key, so the VM is still `pg-<database>`, and the idle
//! reaper, the frozen/compacted/archived tiers, disk growth and the orphan
//! sweeps all treat it exactly like any other schema.
//!
//! Format: one `database\trole\tpassword\tcreated_at_unix` line per record,
//! written atomically (temp file + rename) at mode `0600` — it holds cleartext
//! passwords, the same way `PG_VM_POOL_PASSWORD` lives in cleartext in the
//! process environment. Validation guarantees no field can contain a tab or a
//! newline, so nothing needs escaping.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use tracing::info;

/// Sanity cap on provisioned records — a runaway caller can't grow the file (or
/// the fleet it implies) unboundedly. Far above any plausible single-host fleet.
pub const MAX_RECORDS: usize = 512;

/// Length of a generated password, in characters drawn from [`ALPHABET`]
/// (6 bits each) — 144 bits of entropy.
const GENERATED_PASSWORD_LEN: usize = 24;

/// Exactly 64 characters, so bytes from `/dev/urandom` map to it without the
/// modulo bias a non-power-of-two alphabet would introduce.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Accepted password length range. The floor keeps an operator-supplied
/// password from being trivially guessable; the ceiling keeps one startup
/// PasswordMessage bounded.
const MIN_PASSWORD_LEN: usize = 12;
const MAX_PASSWORD_LEN: usize = 128;

/// Database names the pooler must never hand out: Postgres' own catalog
/// databases (the pooler's admin pool connects to `postgres`, and the templates
/// are not connectable in the normal sense).
const RESERVED_DATABASES: &[&str] = &["postgres", "template0", "template1"];

/// Role names that would collide with the pooler's own access. `postgres` is
/// the role the pooler uses for every bootstrap/probe/dump query
/// ([`crate::config::Config::pg_user`]), and handing a tenant a superuser login
/// would defeat the whole point.
const RESERVED_ROLES: &[&str] = &["postgres", "root"];

/// One provisioned database and the credential that owns it.
#[derive(Clone)]
pub struct Credential {
    /// The database name. Doubles as the pooler's schema key, so the VM
    /// backing it is `pg-<database>`.
    pub database: String,
    /// The Postgres login role created inside the VM, owner of `database`.
    /// Unique across all records, so a startup packet's `user` resolves to at
    /// most one credential.
    pub role: String,
    /// Cleartext, because the pooler must (a) compare it against the client's
    /// `AuthenticationCleartextPassword` reply and (b) re-apply it to the guest
    /// role every time the database is materialized into a *fresh* VM — a
    /// restore from the frozen or archived tier rebuilds the cluster, and a
    /// per-database `pg_dump` carries no roles.
    pub password: String,
    pub created_at: u64,
}

/// A record without its password, for listings that must not carry secrets
/// (the JSON API's `GET`, the dashboard table).
#[derive(Clone)]
pub struct CredentialInfo {
    pub database: String,
    pub role: String,
    pub created_at: u64,
}

impl Credential {
    fn info(&self) -> CredentialInfo {
        CredentialInfo {
            database: self.database.clone(),
            role: self.role.clone(),
            created_at: self.created_at,
        }
    }
}

/// The provisioned-credential set, keyed by database name.
pub struct Credentials {
    path: PathBuf,
    by_database: Mutex<HashMap<String, Credential>>,
}

impl Credentials {
    /// Load from `path`. A missing file starts empty. Unlike the schema
    /// registry, a *corrupt* line here is dropped silently-but-loudly (warned):
    /// keeping a half-parsed credential would be worse than losing it, since
    /// the client would then fail auth against a mangled password.
    pub fn load(path: PathBuf) -> Self {
        let by_database = match std::fs::read_to_string(&path) {
            Ok(s) => parse(&s),
            Err(_) => HashMap::new(),
        };
        if !by_database.is_empty() {
            info!(
                "loaded {} dedicated database credential(s) from {}",
                by_database.len(),
                path.display()
            );
        }
        Self {
            path,
            by_database: Mutex::new(by_database),
        }
    }

    /// Every record, password-free, sorted by database name for a stable render.
    pub fn list(&self) -> Vec<CredentialInfo> {
        let mut out: Vec<_> = self
            .by_database
            .lock()
            .unwrap()
            .values()
            .map(Credential::info)
            .collect();
        out.sort_by(|a, b| a.database.cmp(&b.database));
        out
    }

    /// The credential owning `database`, if it is a dedicated one.
    pub fn by_database(&self, database: &str) -> Option<Credential> {
        self.by_database.lock().unwrap().get(database).cloned()
    }

    /// The credential whose login role is `role`. Roles are unique across
    /// records (enforced by [`Self::create`]), so this is unambiguous.
    pub fn by_role(&self, role: &str) -> Option<Credential> {
        self.by_database
            .lock()
            .unwrap()
            .values()
            .find(|c| c.role == role)
            .cloned()
    }

    /// True when `database` is provisioned — i.e. it is off-limits to ordinary
    /// schema routing.
    pub fn is_dedicated(&self, database: &str) -> bool {
        self.by_database.lock().unwrap().contains_key(database)
    }

    /// The password for `role`, if it is a provisioned dedicated login.
    ///
    /// Deliberately keyed on the **role** alone: doing it this way means the
    /// handshake looks identical whether or not the requested database happens
    /// to be dedicated, so a prober cannot enumerate the provisioned names by
    /// watching which connections get challenged. [`Self::authorize`] is what
    /// applies the routing rule, after the password has already been proven.
    ///
    /// The shared-password fallback lives one level up, in
    /// `SchemaRegistry::challenge_password_for`, which composes this with the
    /// replication logins so all three live in one ordering.
    pub fn password_for_role(&self, role: &str) -> Option<String> {
        self.by_role(role).map(|c| c.password)
    }

    /// Decide whether an *authenticated* client may route to `database`. This
    /// is the rule that makes a dedicated credential single-purpose.
    ///
    /// Two directions, both enforced here:
    ///   * a dedicated role may open only the database it was created for —
    ///     any other name is refused rather than provisioned, so these
    ///     credentials cannot create VMs;
    ///   * a non-dedicated client (one that authenticated with the shared
    ///     password) may not open a dedicated database — otherwise the shared
    ///     credential would be a master key over every tenant.
    ///
    /// `Err` carries a message safe to hand back to the client verbatim.
    pub fn authorize(&self, role: &str, database: &str) -> Result<(), String> {
        match self.by_role(role) {
            Some(c) if c.database == database => Ok(()),
            Some(c) => Err(format!(
                "role \"{role}\" is provisioned for database \"{}\" only and cannot \
                 open or create any other database",
                c.database
            )),
            None if self.is_dedicated(database) => Err(format!(
                "database \"{database}\" is dedicated and can only be opened by \
                 its own role"
            )),
            None => Ok(()),
        }
    }

    /// Provision `(database, role, password)` and persist. Validates every
    /// field, refuses a database or role that is already taken, and returns the
    /// stored record (the only time the password is handed back).
    ///
    /// Caller-enforced preconditions this does *not* know about — notably that
    /// no ordinary schema already owns `database` — live in
    /// [`crate::registry::SchemaRegistry::create_dedicated`], which holds the
    /// schema registry too.
    pub fn create(&self, database: &str, role: &str, password: &str) -> Result<Credential> {
        let database = validate_identifier(database, "database")?;
        let role = validate_identifier(role, "role")?;
        if RESERVED_DATABASES.contains(&database.as_str()) {
            bail!("database name {database:?} is reserved by Postgres");
        }
        if RESERVED_ROLES.contains(&role.as_str()) {
            bail!("role name {role:?} is reserved by the pooler");
        }
        validate_password(password)?;

        let record = Credential {
            database: database.clone(),
            role: role.clone(),
            password: password.to_string(),
            created_at: now_unix(),
        };
        let snapshot = {
            let mut map = self.by_database.lock().unwrap();
            if map.contains_key(&database) {
                bail!("database {database:?} is already provisioned");
            }
            if map.len() >= MAX_RECORDS {
                bail!("too many dedicated databases (max {MAX_RECORDS})");
            }
            // Roles must be unique so `by_role` — the auth path's lookup — has
            // exactly one answer. Without this, two records sharing a role
            // would make the password that opens one of them open the other.
            if let Some(other) = map.values().find(|c| c.role == role) {
                bail!(
                    "role {role:?} is already used by database {:?}",
                    other.database
                );
            }
            map.insert(database.clone(), record.clone());
            serialize(&map)
        };
        // Persist before returning: the caller hands the password to a human
        // (or an API client) that will expect it to keep working, so a record
        // that only ever lived in memory would be a lost credential after the
        // next restart.
        if let Err(e) = write_atomic(&self.path, &snapshot) {
            // Roll the in-memory insert back so the process doesn't serve a
            // credential the next restart will have forgotten.
            self.by_database.lock().unwrap().remove(&database);
            return Err(e).with_context(|| {
                format!("persisting dedicated credentials to {}", self.path.display())
            });
        }
        info!("provisioned dedicated database {database} for role {role}");
        Ok(record)
    }

    /// Revoke `database`'s credential and persist. Returns `false` if it wasn't
    /// provisioned.
    ///
    /// Deliberately **non-destructive**: the VM, its disk and its data are left
    /// exactly as they are. Only the credential goes away — the database drops
    /// back to ordinary schema routing (so the shared password can reach it
    /// again, which is how an operator rescues the data), and re-provisioning
    /// the same name later reattaches to that same VM through the schema
    /// registry. Reclaiming the storage is the existing reap/purge machinery's
    /// job, not this one's.
    pub fn remove(&self, database: &str) -> Result<bool> {
        let snapshot = {
            let mut map = self.by_database.lock().unwrap();
            if map.remove(database).is_none() {
                return Ok(false);
            }
            serialize(&map)
        };
        write_atomic(&self.path, &snapshot).with_context(|| {
            format!("persisting dedicated credentials to {}", self.path.display())
        })?;
        info!("revoked the dedicated credential for database {database}");
        Ok(true)
    }

    /// Durably move one credential to a new database key without changing
    /// its login identity or creation metadata.
    pub fn rename_database(&self, old: &str, new: &str) -> Result<()> {
        let new = validate_identifier(new, "database")?;
        if RESERVED_DATABASES.contains(&new.as_str()) {
            bail!("database name {new:?} is reserved by Postgres");
        }
        let mut map = self.by_database.lock().unwrap();
        if map.contains_key(&new) {
            if !map.contains_key(old) {
                return Ok(());
            }
            bail!("cannot rename database {old:?}: {new:?} is already provisioned");
        }
        let mut next = map.clone();
        let mut record = next
            .remove(old)
            .with_context(|| format!("no dedicated credential for database {old:?}"))?;
        record.database = new.clone();
        next.insert(new, record);
        write_atomic(&self.path, &serialize(&next)).with_context(|| {
            format!(
                "persisting dedicated credentials to {}",
                self.path.display()
            )
        })?;
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent)?.sync_all().with_context(|| {
            format!(
                "syncing dedicated credential directory {}",
                parent.display()
            )
        })?;
        *map = next;
        Ok(())
    }
}

/// A fresh random password, drawn from `/dev/urandom`.
///
/// The alphabet is exactly 64 characters wide so each byte contributes 6
/// unbiased bits — no rejection sampling, no modulo skew. Used when a caller
/// provisions a database without supplying one.
pub fn generate_password() -> Result<String> {
    let mut buf = [0u8; GENERATED_PASSWORD_LEN];
    std::fs::File::open("/dev/urandom")
        .context("opening /dev/urandom to generate a password")?
        .read_exact(&mut buf)
        .context("reading /dev/urandom")?;
    Ok(buf
        .iter()
        .map(|b| ALPHABET[(b & 0x3f) as usize] as char)
        .collect())
}

/// Shared shape check for a database or role name.
///
/// Also used by [`crate::peers`] for a peer's name and by
/// [`crate::replication`] for a replication login, because every one of those
/// becomes a Postgres identifier, a replication slot name, or both — and a
/// second copy of these rules would drift.
///
/// Much stricter than [`crate::is_valid_schema`] (which has to keep accepting
/// whatever existing clients already send): these names are chosen by an
/// operator at provisioning time, and each one becomes a Postgres identifier, a
/// VM name (`pg-<name>`), a local dump/image filename, and an S3 key. Lowercase
/// only, because an unquoted identifier folds to lowercase in Postgres and a
/// name that changes case between the client and the catalog is a support
/// ticket waiting to happen.
pub(crate) fn validate_identifier(s: &str, what: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty() {
        bail!("{what} name is required");
    }
    // Postgres truncates identifiers past 63 bytes, which would silently make
    // two distinct provisioned names the same database.
    if s.len() > 63 {
        bail!("{what} name {s:?} is longer than Postgres' 63-byte identifier limit");
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        bail!("{what} name {s:?} must start with a lowercase ASCII letter");
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        bail!("{what} name {s:?} may contain only lowercase letters, digits and underscores");
    }
    // `pg_` is Postgres' reserved prefix for system catalogs and roles;
    // `spare_`/`spare-` would collide with the warm-spare pool's naming.
    if s.starts_with("pg_") || s.starts_with("spare") {
        bail!("{what} name {s:?} uses a reserved prefix (pg_, spare)");
    }
    Ok(s.to_string())
}

/// Passwords go into a tab-separated file, a Postgres string literal, and a
/// cleartext PasswordMessage — so: printable ASCII, no whitespace, no control
/// characters. That rules out a tab or newline corrupting the store by
/// construction, which is why nothing in this module escapes anything.
pub(crate) fn validate_password(p: &str) -> Result<()> {
    if p.len() < MIN_PASSWORD_LEN {
        bail!("password must be at least {MIN_PASSWORD_LEN} characters");
    }
    if p.len() > MAX_PASSWORD_LEN {
        bail!("password must be at most {MAX_PASSWORD_LEN} characters");
    }
    if !p.chars().all(|c| c.is_ascii_graphic()) {
        bail!("password must be printable ASCII with no spaces or control characters");
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse(s: &str) -> HashMap<String, Credential> {
    let mut map = HashMap::new();
    for line in s.lines().filter(|l| !l.trim().is_empty()) {
        let mut f = line.split('\t');
        let (Some(database), Some(role), Some(password)) = (f.next(), f.next(), f.next()) else {
            tracing::warn!("skipping malformed dedicated-credential line (too few fields)");
            continue;
        };
        if database.is_empty() || role.is_empty() || password.is_empty() {
            tracing::warn!("skipping dedicated-credential line with an empty field");
            continue;
        }
        let created_at = f.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        map.insert(
            database.to_string(),
            Credential {
                database: database.to_string(),
                role: role.to_string(),
                password: password.to_string(),
                created_at,
            },
        );
    }
    map
}

fn serialize(map: &HashMap<String, Credential>) -> String {
    // Sorted so the file is stable across writes (a HashMap's iteration order
    // is not) and diffs when something actually changed.
    let mut records: Vec<_> = map.values().collect();
    records.sort_by(|a, b| a.database.cmp(&b.database));
    let mut out = String::new();
    for c in records {
        out.push_str(&c.database);
        out.push('\t');
        out.push_str(&c.role);
        out.push('\t');
        out.push_str(&c.password);
        out.push('\t');
        out.push_str(&c.created_at.to_string());
        out.push('\n');
    }
    out
}

/// Temp file + rename, like [`crate::store`], so a crash mid-write can't leave
/// a truncated credential file. Both the temp file and (therefore) the final
/// file are created `0600`: this is the one pooler-owned file holding
/// cleartext tenant passwords.
fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
    }
    // `mode()` above only applies when the file is *created*, so an existing
    // temp file from a previous run keeps its old mode — set it unconditionally.
    std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .with_context(|| format!("tightening permissions on {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Credentials {
        let path = std::env::temp_dir().join(format!(
            "pgvmpool-dedicated-{}-{:?}.tsv",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        Credentials::load(path)
    }

    #[test]
    fn create_lookup_and_revoke_round_trip_through_disk() {
        let s = store();
        let rec = s.create("acme", "acme_app", "hunter2hunter2").unwrap();
        assert_eq!(rec.database, "acme");
        assert_eq!(s.by_role("acme_app").unwrap().database, "acme");
        assert!(s.is_dedicated("acme"));
        assert!(!s.is_dedicated("other"));

        // Reload from disk: the credential survives a restart.
        let reloaded = Credentials::load(s.path.clone());
        assert_eq!(reloaded.by_database("acme").unwrap().password, "hunter2hunter2");
        assert_eq!(reloaded.list().len(), 1);
        // Listings carry no secrets.
        assert_eq!(reloaded.list()[0].role, "acme_app");

        assert!(s.remove("acme").unwrap());
        assert!(!s.remove("acme").unwrap());
        assert!(!s.is_dedicated("acme"));
        assert!(Credentials::load(s.path.clone()).list().is_empty());
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn rename_is_durable_preserves_credentials_and_rejects_collision() {
        let s = store();
        let original = s.create("old_db", "app_role", "hunter2hunter2").unwrap();
        s.rename_database("old_db", "new_db").unwrap();
        s.rename_database("old_db", "new_db").unwrap();
        let loaded = Credentials::load(s.path.clone());
        let renamed = loaded.by_database("new_db").unwrap();
        assert_eq!(renamed.role, original.role);
        assert_eq!(renamed.password, original.password);
        assert_eq!(renamed.created_at, original.created_at);
        loaded
            .create("occupied", "other_role", "hunter2hunter2")
            .unwrap();
        assert!(loaded.rename_database("new_db", "occupied").is_err());
        assert!(loaded.by_database("new_db").is_some());
        assert!(
            Credentials::load(s.path.clone())
                .by_database("new_db")
                .is_some()
        );
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn credential_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let s = store();
        s.create("acme", "acme_app", "hunter2hunter2").unwrap();
        let mode = std::fs::metadata(&s.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "cleartext passwords must not be group/world readable");
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn rejects_duplicate_database_or_role() {
        let s = store();
        s.create("acme", "acme_app", "hunter2hunter2").unwrap();
        assert!(s.create("acme", "other_app", "hunter2hunter2").is_err());
        // A shared role would make one password open two databases.
        assert!(s.create("beta", "acme_app", "hunter2hunter2").is_err());
        s.create("beta", "beta_app", "hunter2hunter2").unwrap();
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn dedicated_role_is_pinned_to_its_own_database() {
        let s = store();
        s.create("acme", "acme_app", "hunter2hunter2").unwrap();

        // Its own database: allowed.
        assert!(s.authorize("acme_app", "acme").is_ok());
        // Any other name — the default "create a VM per schema" behavior — is
        // refused, which is the whole point of the feature.
        let err = s.authorize("acme_app", "somethingelse").unwrap_err();
        assert!(err.contains("cannot open or create any other database"), "{err}");
        // Including another tenant's dedicated database.
        s.create("beta", "beta_app", "hunter2hunter2").unwrap();
        assert!(s.authorize("acme_app", "beta").is_err());

        // And the shared-password path can't reach a dedicated database.
        let err = s.authorize("postgres", "acme").unwrap_err();
        assert!(err.contains("dedicated"), "{err}");
        // ...but is untouched for ordinary schemas.
        assert!(s.authorize("postgres", "tenant1").is_ok());
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn a_dedicated_record_resolves_to_its_own_password() {
        let s = store();
        s.create("acme", "acme_app", "hunter2hunter2").unwrap();
        assert_eq!(s.password_for_role("acme_app").as_deref(), Some("hunter2hunter2"));
        // An unknown role resolves to nothing *here*; the shared-password
        // fallback is composed one level up, in the registry, together with the
        // replication logins — see `registry::auth_composition_tests`.
        assert_eq!(s.password_for_role("postgres"), None);
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn validates_names_and_passwords() {
        let s = store();
        // Reserved / catalog names.
        assert!(s.create("postgres", "app_one", "hunter2hunter2").is_err());
        assert!(s.create("template1", "app_two", "hunter2hunter2").is_err());
        assert!(s.create("acme", "postgres", "hunter2hunter2").is_err());
        // Reserved prefixes (system catalogs, the warm-spare pool).
        assert!(s.create("pg_stuff", "app_three", "hunter2hunter2").is_err());
        assert!(s.create("spare_pg", "app_four", "hunter2hunter2").is_err());
        // Shape: must start with a lowercase letter, no uppercase, no dashes,
        // no spaces, and nothing that could break the TSV.
        assert!(s.create("9acme", "app_five", "hunter2hunter2").is_err());
        assert!(s.create("Acme", "app_six", "hunter2hunter2").is_err());
        assert!(s.create("ac-me", "app_seven", "hunter2hunter2").is_err());
        assert!(s.create("ac me", "app_eight", "hunter2hunter2").is_err());
        assert!(s.create("ac\tme", "app_nine", "hunter2hunter2").is_err());
        assert!(s.create(&"a".repeat(64), "app_ten", "hunter2hunter2").is_err());
        // Passwords: length bounds and no whitespace/control characters.
        assert!(s.create("acme", "acme_app", "short").is_err());
        assert!(s.create("acme", "acme_app", &"x".repeat(129)).is_err());
        assert!(s.create("acme", "acme_app", "has a space!").is_err());
        assert!(s.create("acme", "acme_app", "has\tatab12345").is_err());
        // Nothing above should have landed.
        assert!(s.list().is_empty());
        // The valid shape does.
        assert!(s.create("acme_1", "acme_app", "hunter2hunter2").is_ok());
        let _ = std::fs::remove_file(&s.path);
    }

    #[test]
    fn generated_passwords_are_long_valid_and_distinct() {
        let a = generate_password().unwrap();
        let b = generate_password().unwrap();
        assert_eq!(a.chars().count(), GENERATED_PASSWORD_LEN);
        assert_ne!(a, b);
        // A generated password must always pass our own validation.
        validate_password(&a).unwrap();
    }

    #[test]
    fn parse_skips_corrupt_lines() {
        let map = parse("acme\tacme_app\tsecret\t1700000000\ngarbage\n\tempty\tfields\t1\nbeta\tbeta_app\tsecret2\n");
        assert_eq!(map.len(), 2);
        assert_eq!(map["acme"].created_at, 1_700_000_000);
        // A missing created_at column (hand-edited file) still loads.
        assert_eq!(map["beta"].created_at, 0);
    }

    #[test]
    fn serialize_round_trips() {
        let map = parse("beta\tbeta_app\ts2\t2\nacme\tacme_app\ts1\t1\n");
        let text = serialize(&map);
        // Sorted, so the file is stable across writes.
        assert!(text.starts_with("acme\t"));
        let reparsed = parse(&text);
        assert_eq!(reparsed["acme"].password, "s1");
        assert_eq!(reparsed["beta"].role, "beta_app");
    }
}
