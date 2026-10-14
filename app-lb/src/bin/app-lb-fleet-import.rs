//! `app-lb-fleet-import`: carry one app-lb host's tenant state into a fleet.
//!
//! A separate binary, never an `app-lb` subcommand: running `app-lb` with an
//! argument it did not understand once started a second server whose orphan
//! sweep destroyed every VM on the host (2026-09-29). This program cannot
//! start a server, reach heyvm, or take the instance lock, whatever arguments
//! it is given.
//!
//! Three modes (`docs/design/fleet-shared-state.md` § Phase 3):
//!
//! - `--dry-run`: report what the host's state holds. Reads only.
//! - `--export`: on the source host, read its state and write one bundle,
//!   **encrypted to the fleet host's public key** (RSA-OAEP wrapping an
//!   AES-256-GCM key). Reads the state directory only; the one file it writes
//!   is the bundle. It needs no fleet credential, and the bundle is ciphertext
//!   wherever it travels.
//! - `--apply`: on a fleet host, decrypt a bundle with that host's private key
//!   and write it into the fleet store in one transaction.
//!
//! What is carried is tenant identity: namespaces, auth providers,
//! deployments (pinned to the source host), secrets, tokens, guard rules and
//! the session signing key. Not plugin records, workflows, postgres ownership
//! or ACME state: those would have the fleet host act on the source host's
//! behalf, which a shadow must never do.
//!
//! Nothing prints a secret value, token hash or key: counts, kinds and
//! deployment ids only.

#[allow(dead_code)]
#[path = "../fleet_pg.rs"]
mod fleet_pg;
#[allow(dead_code)]
#[path = "../fleet_seal.rs"]
mod fleet_seal;
#[allow(dead_code)]
#[path = "../fleet_split.rs"]
mod fleet_split;
#[allow(dead_code)]
#[path = "../fleet_store.rs"]
mod fleet_store;
#[allow(dead_code)]
#[path = "../secrets_seal.rs"]
mod secrets_seal;

use fleet_store::{
    Collection, DOC_KEY, Document, Expect, FileCollection, FileDocument, FileOptions, Layout,
    Transactional, Write,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const HELP: &str = "\
app-lb-fleet-import — carry an app-lb host's tenant state into a fleet

Usage:
  app-lb-fleet-import --dry-run [paths]
  app-lb-fleet-import --export --from-host NAME --to-key PUB.pem --out BUNDLE [paths]
  app-lb-fleet-import --apply BUNDLE --key PRIVATE.pem [--dry-run]

--dry-run (alone) reads the APP_LB_* paths app-lb does and reports counts.
--export reads them too, and writes one bundle encrypted to PUB.pem. It never
writes the state, and needs no fleet credential.
--apply decrypts BUNDLE with PRIVATE.pem and writes it into the fleet store at
APP_LB_FLEET_DATABASE_URL in one transaction, sealing with APP_LB_SECRET_KEY.
With --dry-run it only reports what it would write.

Paths (default to app-lb's variables and defaults):
      --state-path <path>    APP_LB_STATE_PATH
      --secrets-path <path>  APP_LB_SECRETS_PATH
      --tokens-path <path>   APP_LB_TOKENS_PATH
      --guard-path <path>    APP_LB_GUARD_PATH
      --acme-dir <path>      APP_LB_ACME_DIR
      --auth-key <path>      APP_LB_AUTH_KEY (default app-lb-auth-key)
  -h, --help                 Print this help and exit

Exit status: 0 on success, 1 when something could not be read or written, 2 on
a usage error.
";

#[derive(Debug, Default)]
struct Args {
    layout: Option<Layout>,
    auth_key: Option<PathBuf>,
    dry_run: bool,
    export: bool,
    from_host: Option<String>,
    to_key: Option<PathBuf>,
    out: Option<PathBuf>,
    apply: Option<PathBuf>,
    key: Option<PathBuf>,
}

fn parse(argv: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut a = Args {
        layout: Some(Layout::from_env()),
        ..Default::default()
    };
    let mut args = argv.into_iter();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        let layout = a.layout.as_mut().expect("set above");
        match arg.as_str() {
            "--dry-run" => a.dry_run = true,
            "--export" => a.export = true,
            "--from-host" => a.from_host = Some(value(&arg)?),
            "--to-key" => a.to_key = Some(value(&arg)?.into()),
            "--out" => a.out = Some(value(&arg)?.into()),
            "--apply" => a.apply = Some(value(&arg)?.into()),
            "--key" => a.key = Some(value(&arg)?.into()),
            "--state-path" => layout.state_path = value(&arg)?.into(),
            "--secrets-path" => layout.secrets_path = value(&arg)?.into(),
            "--tokens-path" => layout.tokens_path = value(&arg)?.into(),
            "--guard-path" => layout.guard_path = value(&arg)?.into(),
            "--acme-dir" => layout.acme_dir = value(&arg)?.into(),
            "--auth-key" => a.auth_key = Some(value(&arg)?.into()),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let modes = [a.export, a.apply.is_some()].iter().filter(|m| **m).count();
    if modes > 1 {
        return Err("--export and --apply are separate runs, on separate hosts".into());
    }
    if a.export {
        if a.dry_run {
            return Err("--export writes only the bundle; there is nothing to dry-run".into());
        }
        let host = a.from_host.as_deref().ok_or("--export needs --from-host")?;
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(
                "--from-host must be a fleet host name: letters, digits, `-`, `_` and `.`".into(),
            );
        }
        if a.to_key.is_none() || a.out.is_none() {
            return Err("--export needs --to-key and --out".into());
        }
    } else if a.apply.is_some() {
        if a.key.is_none() {
            return Err("--apply needs --key".into());
        }
    } else if !a.dry_run {
        return Err("choose --dry-run, --export or --apply".into());
    }
    Ok(a)
}

fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) if e.is_empty() => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{e}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    let layout = args.layout.clone().expect("parse sets it");
    let auth_key = args.auth_key.clone().unwrap_or_else(|| {
        std::env::var("APP_LB_AUTH_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("app-lb-auth-key"))
    });
    let result = if args.export {
        export(
            &layout,
            &auth_key,
            args.from_host.as_deref().expect("checked"),
            args.to_key.as_deref().expect("checked"),
            args.out.as_deref().expect("checked"),
        )
    } else if let Some(bundle) = &args.apply {
        apply(bundle, args.key.as_deref().expect("checked"), args.dry_run)
    } else {
        let report = survey(&layout);
        print!("{}", report.render());
        return if report.unreadable() == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

// ---- export ------------------------------------------------------------------

/// The kinds a bundle carries, in the order they are written.
const KINDS: &[&str] = &[
    "namespaces",
    "auth-providers",
    "secrets",
    "tokens",
    "guard",
    "auth-key",
    "deployments",
];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Record {
    kind: String,
    key: String,
    #[serde(with = "b64")]
    body: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Bundle {
    version: u32,
    /// The host the records were read from, which every deployment is pinned
    /// to and every record is written as (`import:<from>`).
    from: String,
    created_at: u64,
    records: Vec<Record>,
}

mod b64 {
    use base64::Engine;
    pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

/// Every record the bundle should carry, read from the host's files. An
/// unreadable record is an error: a bundle that silently lacks a deployment
/// would have `--apply` delete it from the fleet.
fn read_records(layout: &Layout, auth_key: &Path, from: &str) -> Result<Vec<Record>, String> {
    let mut out = Vec::new();
    let mut collection = |kind: &str,
                          dir: PathBuf,
                          f: &dyn Fn(Vec<u8>) -> Result<Vec<u8>, String>|
     -> Result<(), String> {
        let store = FileCollection::new(&dir, ".json", FileOptions::PLAIN);
        for entry in store
            .list()
            .map_err(|e| format!("{}: {e}", dir.display()))?
        {
            let body = entry.body.map_err(|e| format!("{}: {e}", entry.location))?;
            let body = f(body).map_err(|e| format!("{}: {e}", entry.location))?;
            out.push(Record {
                kind: kind.into(),
                key: entry.key,
                body,
            });
        }
        Ok(())
    };
    let json = |b: Vec<u8>| -> Result<Vec<u8>, String> {
        serde_json::from_slice::<serde_json::Value>(&b).map_err(|e| format!("not JSON: {e}"))?;
        Ok(b)
    };
    collection("namespaces", layout.namespace_dir(), &json)?;
    collection("auth-providers", layout.auth_provider_dir(), &json)?;
    collection("deployments", layout.registry_dir(), &|b| {
        let half = fleet_split::fleet_half(&b).map_err(|e| e.to_string())?;
        fleet_split::pin_to(&half, from).map_err(|e| e.to_string())
    })?;
    for (kind, path) in [
        ("secrets", layout.secrets_path.clone()),
        ("tokens", layout.tokens_path.clone()),
        ("guard", layout.guard_path.clone()),
        ("auth-key", auth_key.to_path_buf()),
    ] {
        let doc = FileDocument::new(&path, FileOptions::PLAIN);
        if let Some((body, _)) = doc.read().map_err(|e| format!("{}: {e}", path.display()))? {
            if kind != "auth-key" && !body.iter().all(u8::is_ascii_whitespace) {
                serde_json::from_slice::<serde_json::Value>(&body)
                    .map_err(|e| format!("{}: not JSON: {e}", path.display()))?;
            }
            if kind == "auth-key" && body.len() < 32 {
                return Err(format!(
                    "{} is too short to be a signing key",
                    path.display()
                ));
            }
            out.push(Record {
                kind: kind.into(),
                key: DOC_KEY.into(),
                body,
            });
        }
    }
    Ok(out)
}

fn export(
    layout: &Layout,
    auth_key: &Path,
    from: &str,
    to_key: &Path,
    out: &Path,
) -> Result<(), String> {
    let records = read_records(layout, auth_key, from)?;
    let bundle = Bundle {
        version: 1,
        from: from.to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        records,
    };
    let plaintext = serde_json::to_vec(&bundle).map_err(|e| e.to_string())?;
    let public = std::fs::read(to_key).map_err(|e| format!("{}: {e}", to_key.display()))?;
    let sealed = envelope::seal(&public, &plaintext).map_err(|e| e.to_string())?;
    write_private(out, &sealed).map_err(|e| format!("{}: {e}", out.display()))?;
    println!("exported from {from}, encrypted to {}:", to_key.display());
    print!("{}", counts(&bundle.records));
    println!("bundle: {} ({} bytes)", out.display(), sealed.len());
    Ok(())
}

fn counts(records: &[Record]) -> String {
    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    for r in records {
        *by_kind.entry(r.kind.as_str()).or_default() += 1;
    }
    KINDS
        .iter()
        .map(|k| format!("  {k:<15} {}\n", by_kind.get(k).copied().unwrap_or(0)))
        .collect()
}

/// `0600` from the first byte, like every credential app-lb writes.
fn write_private(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(path)?;
    f.write_all(body)?;
    f.sync_all()
}

/// Hybrid encryption to an RSA public key: a fresh AES-256-GCM key encrypts
/// the bundle and RSA-OAEP (SHA-256) wraps that key.
mod envelope {
    use openssl::md::Md;
    use openssl::pkey::PKey;
    use openssl::pkey_ctx::PkeyCtx;
    use openssl::rsa::Padding;
    use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
    use std::io;

    const MAGIC: &[u8] = b"applb-fleet-bundle-v1\n";
    const AAD: &[u8] = b"applb-fleet-bundle-v1";

    fn oaep<T>(ctx: &mut PkeyCtx<T>) -> Result<(), openssl::error::ErrorStack> {
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        ctx.set_rsa_oaep_md(Md::sha256())?;
        ctx.set_rsa_mgf1_md(Md::sha256())
    }

    pub fn seal(public_pem: &[u8], plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let key = PKey::public_key_from_pem(public_pem).map_err(io::Error::other)?;
        let mut aes = [0u8; 32];
        let mut nonce = [0u8; 12];
        openssl::rand::rand_bytes(&mut aes).map_err(io::Error::other)?;
        openssl::rand::rand_bytes(&mut nonce).map_err(io::Error::other)?;
        let mut tag = [0u8; 16];
        let ct = encrypt_aead(
            Cipher::aes_256_gcm(),
            &aes,
            Some(&nonce),
            AAD,
            plaintext,
            &mut tag,
        )
        .map_err(io::Error::other)?;
        let mut ctx = PkeyCtx::new(&key).map_err(io::Error::other)?;
        ctx.encrypt_init().map_err(io::Error::other)?;
        oaep(&mut ctx).map_err(io::Error::other)?;
        let mut wrapped = Vec::new();
        ctx.encrypt_to_vec(&aes, &mut wrapped)
            .map_err(io::Error::other)?;
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(wrapped.len() as u32).to_be_bytes());
        out.extend_from_slice(&wrapped);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(private_pem: &[u8], sealed: &[u8]) -> io::Result<Vec<u8>> {
        let bad = |why: &str| io::Error::new(io::ErrorKind::InvalidData, why.to_string());
        let rest = sealed
            .strip_prefix(MAGIC)
            .ok_or_else(|| bad("not a fleet bundle"))?;
        if rest.len() < 4 {
            return Err(bad("truncated bundle"));
        }
        let (len, rest) = rest.split_at(4);
        let len = u32::from_be_bytes(len.try_into().expect("4 bytes")) as usize;
        if rest.len() < len + 12 + 16 {
            return Err(bad("truncated bundle"));
        }
        let (wrapped, rest) = rest.split_at(len);
        let (nonce, rest) = rest.split_at(12);
        let (tag, ct) = rest.split_at(16);
        let key = PKey::private_key_from_pem(private_pem).map_err(io::Error::other)?;
        let mut ctx = PkeyCtx::new(&key).map_err(io::Error::other)?;
        ctx.decrypt_init().map_err(io::Error::other)?;
        oaep(&mut ctx).map_err(io::Error::other)?;
        let mut aes = Vec::new();
        ctx.decrypt_to_vec(wrapped, &mut aes)
            .map_err(|_| bad("this bundle was not encrypted to this key"))?;
        decrypt_aead(Cipher::aes_256_gcm(), &aes, Some(nonce), AAD, ct, tag)
            .map_err(|_| bad("the bundle is corrupt or was altered"))
    }
}

// ---- apply -------------------------------------------------------------------

/// Kinds where the source host's record replaces whatever the fleet holds:
/// its values are the fleet's values (design § Credentials). Deployments are
/// the exception — a fleet host's own deployment under the same id (each
/// host's admin route, say) is that host's, and is reported, not replaced.
fn source_wins(kind: &str) -> bool {
    kind != "deployments"
}

#[derive(Debug, Default)]
struct Plan {
    writes: Vec<Write>,
    /// kind → (written, unchanged, deleted)
    tally: BTreeMap<String, (usize, usize, usize)>,
    /// Ids the fleet already holds under another writer.
    collisions: Vec<(String, String, String)>,
}

/// A record as the fleet store holds it now.
struct Current {
    body: Vec<u8>,
    revision: u64,
    writer: String,
}

/// Decide what to write. `stored` turns a bundle body into what the store
/// keeps (sealing), `same` compares a stored body with a bundle body.
fn plan(
    bundle: &Bundle,
    current: &BTreeMap<String, BTreeMap<String, Current>>,
    stored: &dyn Fn(&Record) -> Result<Vec<u8>, String>,
    same: &dyn Fn(&Record, &[u8]) -> bool,
) -> Result<Plan, String> {
    let writer = format!("import:{}", bundle.from);
    let mut p = Plan::default();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let empty = BTreeMap::new();
    for r in &bundle.records {
        seen.insert((r.kind.clone(), r.key.clone()));
        let tally = p.tally.entry(r.kind.clone()).or_default();
        match current.get(&r.kind).unwrap_or(&empty).get(&r.key) {
            None => {
                p.writes.push(Write::Put {
                    kind: r.kind.clone(),
                    key: r.key.clone(),
                    body: stored(r)?,
                    expect: Expect::Absent,
                });
                tally.0 += 1;
            }
            Some(c) if same(r, &c.body) => tally.1 += 1,
            Some(c) if c.writer == writer || source_wins(&r.kind) => {
                p.writes.push(Write::Put {
                    kind: r.kind.clone(),
                    key: r.key.clone(),
                    body: stored(r)?,
                    expect: Expect::Revision(c.revision),
                });
                tally.0 += 1;
            }
            Some(c) => p
                .collisions
                .push((r.kind.clone(), r.key.clone(), c.writer.clone())),
        }
    }
    // What this source wrote before and no longer has: gone at the source.
    for kind in KINDS {
        for (key, c) in current.get(*kind).unwrap_or(&empty) {
            if c.writer == writer && !seen.contains(&(kind.to_string(), key.clone())) {
                p.writes.push(Write::Delete {
                    kind: kind.to_string(),
                    key: key.clone(),
                    expect: Expect::Revision(c.revision),
                });
                p.tally.entry(kind.to_string()).or_default().2 += 1;
            }
        }
    }
    Ok(p)
}

fn apply(bundle_path: &Path, private_key: &Path, dry_run: bool) -> Result<(), String> {
    let sealed =
        std::fs::read(bundle_path).map_err(|e| format!("{}: {e}", bundle_path.display()))?;
    let pem = std::fs::read(private_key).map_err(|e| format!("{}: {e}", private_key.display()))?;
    let plaintext = envelope::open(&pem, &sealed).map_err(|e| e.to_string())?;
    let bundle: Bundle = serde_json::from_slice(&plaintext).map_err(|e| format!("bundle: {e}"))?;
    if bundle.version != 1 {
        return Err(format!(
            "bundle version {} is newer than this importer",
            bundle.version
        ));
    }
    let url = std::env::var(fleet_pg::URL_ENV)
        .ok()
        .filter(|u| !u.trim().is_empty())
        .ok_or_else(|| format!("{} is not set", fleet_pg::URL_ENV))?;
    let secret_key = std::env::var("APP_LB_SECRET_KEY")
        .ok()
        .filter(|k| !k.trim().is_empty())
        .map(|k| secrets_seal::derive_key(&k))
        .ok_or(
            "APP_LB_SECRET_KEY is not set: the fleet seals secrets and the signing key with it",
        )?;
    let writer = format!("import:{}", bundle.from);
    let pg = fleet_pg::PgStore::open(&url, &writer, fleet_pg::timeout_from_env())
        .map_err(|e| e.to_string())?;
    let report = apply_to(&pg, &bundle, &secret_key, dry_run)?;
    print!("{report}");
    Ok(())
}

/// Write `bundle` into the fleet store behind `pg`, whose writer name must be
/// `import:<bundle.from>`. Returns the report.
fn apply_to(
    pg: &fleet_pg::PgStore,
    bundle: &Bundle,
    secret_key: &[u8],
    dry_run: bool,
) -> Result<String, String> {
    use std::fmt::Write as _;
    let writer = format!("import:{}", bundle.from);
    if pg.host() != writer {
        return Err(format!(
            "internal: writing as {} for a bundle from {}",
            pg.host(),
            bundle.from
        ));
    }
    pg.migrate().map_err(|e| e.to_string())?;
    if pg.snapshot().map_err(|e| e.to_string())?.seeded.is_none() {
        return Err(
            "the fleet store has never been seeded: start an app-lb in fleet mode against it first"
                .into(),
        );
    }
    let mut current: BTreeMap<String, BTreeMap<String, Current>> = BTreeMap::new();
    for kind in KINDS {
        for (key, body, revision, writer) in pg.list_records(kind).map_err(|e| e.to_string())? {
            current.entry(kind.to_string()).or_default().insert(
                key,
                Current {
                    body,
                    revision,
                    writer,
                },
            );
        }
    }
    let stored = |r: &Record| -> Result<Vec<u8>, String> {
        match r.kind.as_str() {
            "secrets" => secrets_seal::seal_file(secret_key, &r.body).map_err(|e| e.to_string()),
            "auth-key" => {
                fleet_seal::seal(secret_key, "auth-key", &r.key, &r.body).map_err(|e| e.to_string())
            }
            _ => Ok(r.body.clone()),
        }
    };
    let same = |r: &Record, held: &[u8]| -> bool {
        match r.kind.as_str() {
            "secrets" => matches!(
                (secrets_seal::open_file(secret_key, held), secrets_seal::open_file(secret_key, &r.body)),
                (Ok(a), Ok(b)) if a == b
            ),
            "auth-key" => {
                fleet_seal::unseal(secret_key, "auth-key", &r.key, held).is_ok_and(|k| k == r.body)
            }
            _ => held == r.body.as_slice(),
        }
    };
    let p = plan(bundle, &current, &stored, &same)?;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} bundle from {} ({} records){}:",
        if dry_run { "would apply" } else { "applying" },
        bundle.from,
        bundle.records.len(),
        if dry_run {
            " — dry run, nothing written"
        } else {
            ""
        }
    );
    let _ = writeln!(
        out,
        "  {:<15} {:>7} {:>9} {:>7}",
        "kind", "written", "unchanged", "deleted"
    );
    for kind in KINDS {
        let (w, u, d) = p.tally.get(*kind).copied().unwrap_or_default();
        let _ = writeln!(out, "  {kind:<15} {w:>7} {u:>9} {d:>7}");
    }
    for (kind, key, other) in &p.collisions {
        let _ = writeln!(
            out,
            "  kept {kind}/{key}: the fleet's copy was written by {other}, not {writer}"
        );
    }
    if dry_run || p.writes.is_empty() {
        return Ok(out);
    }
    let revisions = pg.transaction(&p.writes, None).map_err(|e| e.to_string())?;
    let _ = writeln!(
        out,
        "applied {} writes in one transaction, up to revision {}",
        p.writes.len(),
        revisions.iter().max().copied().unwrap_or(0)
    );
    Ok(out)
}

// ---- dry run (survey) ----------------------------------------------------------

/// One kind of record and what was found.
#[derive(Debug, Default)]
struct Kind {
    name: &'static str,
    location: String,
    records: usize,
    bytes: usize,
    unreadable: Vec<String>,
    notes: Vec<String>,
}

#[derive(Debug, Default)]
struct Report {
    kinds: Vec<Kind>,
}

impl Report {
    fn unreadable(&self) -> usize {
        self.kinds.iter().map(|k| k.unreadable.len()).sum()
    }

    fn render(&self) -> String {
        let mut out = String::from("dry run: nothing was written\n\n");
        for k in &self.kinds {
            out.push_str(&format!(
                "{:<16} {:>5} record(s) {:>9} bytes  {}\n",
                k.name, k.records, k.bytes, k.location
            ));
            for n in &k.notes {
                out.push_str(&format!("{:<16} note: {n}\n", ""));
            }
            for u in &k.unreadable {
                out.push_str(&format!("{:<16} UNREADABLE: {u}\n", ""));
            }
        }
        out.push_str(&format!("\n{} unreadable record(s)\n", self.unreadable()));
        out
    }
}

fn survey(layout: &Layout) -> Report {
    let mut kinds = vec![
        collection("deployments", &layout.registry_dir(), ".json"),
        collection("namespaces", &layout.namespace_dir(), ".json"),
        collection("auth-providers", &layout.auth_provider_dir(), ".json"),
        collection("workflows", &layout.workflow_dir(), ".json"),
        collection("plugins", &layout.plugin_dir(), ".json"),
    ];
    if layout.state_path.exists() {
        kinds[0].notes.push(format!(
            "{} is a pre-directory state file; app-lb imports it on its next start",
            layout.state_path.display()
        ));
    }
    kinds.push(document("secrets", &layout.secrets_path, |v, k| {
        match v["encryption"].as_str() {
            Some("none") => {
                k.records = v["secrets"].as_array().map_or(0, Vec::len);
                k.notes.push("plaintext at rest".into());
            }
            Some(sealed) => {
                k.records = 1;
                k.notes.push(format!(
                    "sealed ({sealed}); entries are counted once unsealed with APP_LB_SECRET_KEY"
                ));
            }
            None => k.notes.push("no encryption field".into()),
        }
    }));
    kinds.push(document("tokens", &layout.tokens_path, |v, k| {
        k.records = v["tokens"].as_array().map_or(0, Vec::len);
    }));
    kinds.push(document("guard-rules", &layout.guard_path, |v, k| {
        k.records = v["rules"].as_array().map_or(0, Vec::len);
    }));
    kinds.push(document(
        "pg-ownership",
        &layout.postgres_ownership_path(),
        |v, k| {
            k.records = v["databases"].as_object().map_or(0, |m| m.len());
        },
    ));
    kinds.push(document(
        "acme-account",
        &layout.acme_dir.join("account.json"),
        |_, k| {
            k.records = 1;
        },
    ));
    kinds.push(document(
        "acme-backoff",
        &layout.acme_dir.join("backoff.json"),
        |v, k| {
            k.records = v.as_object().map_or(0, |m| m.len());
        },
    ));
    kinds.push(certificates(&layout.acme_certs_dir()));
    Report { kinds }
}

fn collection(name: &'static str, dir: &std::path::Path, suffix: &'static str) -> Kind {
    let store = FileCollection::new(dir, suffix, FileOptions::PLAIN);
    let mut kind = Kind {
        name,
        location: dir.display().to_string(),
        ..Default::default()
    };
    match store.list() {
        Ok(entries) => {
            for e in entries {
                match e.body {
                    Ok(b) if serde_json::from_slice::<serde_json::Value>(&b).is_ok() => {
                        kind.records += 1;
                        kind.bytes += b.len();
                    }
                    Ok(_) => kind.unreadable.push(format!("{} (not JSON)", e.location)),
                    Err(err) => kind.unreadable.push(format!("{} ({err})", e.location)),
                }
            }
        }
        Err(err) => kind.unreadable.push(format!("{} ({err})", dir.display())),
    }
    kind
}

fn document(
    name: &'static str,
    path: &std::path::Path,
    count: impl FnOnce(&serde_json::Value, &mut Kind),
) -> Kind {
    let store = FileDocument::new(path, FileOptions::PLAIN);
    let mut kind = Kind {
        name,
        location: path.display().to_string(),
        ..Default::default()
    };
    match store.read() {
        Ok(None) => kind.notes.push("absent".into()),
        Ok(Some((bytes, _))) => {
            kind.bytes = bytes.len();
            match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(v) => count(&v, &mut kind),
                // The guard treats an all-whitespace file as empty.
                Err(_) if bytes.iter().all(u8::is_ascii_whitespace) => {
                    kind.notes.push("empty".into())
                }
                Err(_) => kind
                    .unreadable
                    .push(format!("{} (not JSON)", path.display())),
            }
        }
        Err(err) => kind.unreadable.push(format!("{} ({err})", path.display())),
    }
    kind
}

fn certificates(dir: &std::path::Path) -> Kind {
    let chains = FileCollection::new(dir, ".crt.pem", FileOptions::PLAIN);
    let keys = FileCollection::new(dir, ".key.pem", FileOptions::PLAIN);
    let mut kind = Kind {
        name: "certificates",
        location: dir.display().to_string(),
        ..Default::default()
    };
    match chains.list() {
        Ok(entries) => {
            for e in entries {
                match (e.body, keys.get(&e.key)) {
                    (Ok(chain), Ok(Some((key, _)))) => {
                        kind.records += 1;
                        kind.bytes += chain.len() + key.len();
                    }
                    (Ok(_), Ok(None)) => kind
                        .unreadable
                        .push(format!("{} (no private key beside it)", e.location)),
                    (Err(err), _) | (_, Err(err)) => {
                        kind.unreadable.push(format!("{} ({err})", e.location))
                    }
                }
            }
        }
        Err(err) => kind.unreadable.push(format!("{} ({err})", dir.display())),
    }
    kind
}

#[cfg(test)]
mod import_tests {
    use super::*;

    struct Dir(PathBuf);
    impl Dir {
        fn new(name: &str) -> Self {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fleet-import-{name}-{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn layout(&self) -> Layout {
            Layout {
                state_path: self.0.join("app-lb-state.json"),
                secrets_path: self.0.join("app-lb-secrets.json"),
                tokens_path: self.0.join("app-lb-tokens.json"),
                guard_path: self.0.join("app-lb-guard.json"),
                acme_dir: self.0.join("acme"),
            }
        }
        fn put(&self, rel: &str, body: &[u8]) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A source host's state: two deployments, a namespace, plaintext
    /// secrets, tokens and a signing key — and things a bundle never carries.
    fn source() -> Dir {
        let d = Dir::new("src");
        d.put("app-lb-state.d/web.json", br#"{"spec":{"id":"web","routes":[{"host":"web.us5"}],"upstreams":["127.0.0.1:1"]},"state":{"suspended":["sb-1"],"discovery_version":4}}"#);
        d.put("app-lb-state.d/app-lb-admin.json", br#"{"spec":{"id":"app-lb-admin","routes":[{"host":"admin.us5"}],"upstreams":["127.0.0.1:9090"]}}"#);
        d.put(
            "app-lb-namespaces.d/sam.json",
            br#"{"name":"sam","created_at":1}"#,
        );
        d.put("app-lb-secrets.json", br#"{"version":1,"encryption":"none","secrets":[{"id":"github","data":{"token":"t0ken"},"updated_at":3}]}"#);
        d.put("app-lb-tokens.json", br#"{"version":1,"tokens":[]}"#);
        d.put("app-lb-auth-key", &[7u8; 32]);
        d.put("app-lb-plugins.d/ci.json", br#"{"enabled":true}"#);
        d.put("app-lb-workflows.d/build.json", br#"{"id":"build"}"#);
        d
    }

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        (
            rsa.public_key_to_pem().unwrap(),
            rsa.private_key_to_pem().unwrap(),
        )
    }

    #[test]
    fn the_modes_take_their_own_arguments() {
        let p = |a: &[&str]| parse(a.iter().map(|s| s.to_string()));
        assert!(p(&[]).is_err(), "a mode is required");
        assert!(p(&["--dry-run"]).is_ok());
        assert!(
            p(&["--export", "--to-key", "k", "--out", "o"]).is_err(),
            "--from-host"
        );
        assert!(
            p(&[
                "--export",
                "--from-host",
                "us 5",
                "--to-key",
                "k",
                "--out",
                "o"
            ])
            .is_err()
        );
        assert!(
            p(&[
                "--export",
                "--from-host",
                "us5",
                "--to-key",
                "k",
                "--out",
                "o"
            ])
            .is_ok()
        );
        assert!(
            p(&[
                "--export",
                "--dry-run",
                "--from-host",
                "us5",
                "--to-key",
                "k",
                "--out",
                "o"
            ])
            .is_err()
        );
        assert!(p(&["--apply", "b"]).is_err(), "--key");
        assert!(p(&["--apply", "b", "--key", "k", "--dry-run"]).is_ok());
        assert!(p(&["--apply", "b", "--key", "k", "--export"]).is_err());
        assert!(p(&["--serve"]).is_err());
    }

    #[test]
    fn a_bundle_opens_only_with_its_key_and_only_unaltered() {
        let (public, private) = keypair();
        let sealed = envelope::seal(&public, b"tenant state").unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"tenant"));
        assert_eq!(envelope::open(&private, &sealed).unwrap(), b"tenant state");
        let (_, other) = keypair();
        assert!(envelope::open(&other, &sealed).is_err());
        let mut altered = sealed.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(envelope::open(&private, &altered).is_err());
    }

    #[test]
    fn export_carries_tenant_identity_pinned_to_its_source_and_nothing_else() {
        let src = source();
        let records = read_records(&src.layout(), &src.0.join("app-lb-auth-key"), "us5").unwrap();
        let kinds: BTreeSet<&str> = records.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(
            kinds,
            BTreeSet::from(["auth-key", "deployments", "namespaces", "secrets", "tokens"])
        );
        let web = records.iter().find(|r| r.key == "web").unwrap();
        let web: serde_json::Value = serde_json::from_slice(&web.body).unwrap();
        assert_eq!(
            web["spec"]["placement"],
            serde_json::json!({"mode": "pinned", "home": "us5"})
        );
        assert_eq!(web["state"]["discovery_version"], 4);
        assert!(
            web["state"].get("suspended").is_none(),
            "host state stays at the source"
        );

        // An unreadable record stops the export rather than vanish from it.
        src.put("app-lb-namespaces.d/broken.json", b"not json");
        assert!(read_records(&src.layout(), &src.0.join("app-lb-auth-key"), "us5").is_err());
    }

    fn bundle_of(records: Vec<Record>) -> Bundle {
        Bundle {
            version: 1,
            from: "us5".into(),
            created_at: 0,
            records,
        }
    }

    fn rec(kind: &str, key: &str, body: &str) -> Record {
        Record {
            kind: kind.into(),
            key: key.into(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn the_plan_writes_new_and_changed_keeps_a_hosts_own_and_deletes_what_left() {
        let cur = |body: &str, revision: u64, writer: &str| Current {
            body: body.as_bytes().to_vec(),
            revision,
            writer: writer.into(),
        };
        let current = BTreeMap::from([
            (
                "namespaces".to_string(),
                BTreeMap::from([
                    ("same".to_string(), cur("1", 1, "import:us5")),
                    ("changed".to_string(), cur("old", 2, "us4/12")),
                    ("gone".to_string(), cur("x", 3, "import:us5")),
                    ("us4-only".to_string(), cur("x", 4, "us4/12")),
                ]),
            ),
            (
                "deployments".to_string(),
                BTreeMap::from([("app-lb-admin".to_string(), cur("us4's", 5, "us4/12"))]),
            ),
        ]);
        let b = bundle_of(vec![
            rec("namespaces", "same", "1"),
            rec("namespaces", "changed", "new"),
            rec("namespaces", "new", "n"),
            rec("deployments", "app-lb-admin", "us5's"),
        ]);
        let p = plan(&b, &current, &|r| Ok(r.body.clone()), &|r, held| {
            held == r.body.as_slice()
        })
        .unwrap();
        assert_eq!(p.tally["namespaces"], (2, 1, 1));
        assert_eq!(
            p.collisions,
            [("deployments".into(), "app-lb-admin".into(), "us4/12".into())]
        );
        let described: Vec<String> = p
            .writes
            .iter()
            .map(|w| match w {
                Write::Put { key, expect, .. } => format!("put {key} {expect:?}"),
                Write::Delete { key, expect, .. } => format!("delete {key} {expect:?}"),
            })
            .collect();
        assert_eq!(
            described,
            [
                "put changed Revision(2)",
                "put new Absent",
                "delete gone Revision(3)"
            ]
        );
    }

    #[test]
    fn apply_writes_one_transaction_seals_credentials_and_repeats_as_a_no_op() {
        let Ok(url) = std::env::var("APP_LB_FLEET_TEST_DATABASE_URL") else {
            eprintln!("skipped: APP_LB_FLEET_TEST_DATABASE_URL is not set");
            return;
        };
        let schema = format!("t_import_{}", std::process::id());
        let host =
            fleet_pg::PgStore::open_in(&url, "us4/1", std::time::Duration::from_secs(5), &schema)
                .unwrap();
        host.migrate().unwrap();
        let src = source();
        let bundle =
            bundle_of(read_records(&src.layout(), &src.0.join("app-lb-auth-key"), "us5").unwrap());
        let pg = fleet_pg::PgStore::open_in(
            &url,
            "import:us5",
            std::time::Duration::from_secs(5),
            &schema,
        )
        .unwrap();
        let key = secrets_seal::derive_key("fleet");
        assert!(
            apply_to(&pg, &bundle, &key, false).is_err(),
            "an unseeded store is refused"
        );

        // us4 seeded the fleet with its own admin route.
        host.seed(
            vec![Write::Put {
                kind: "deployments".into(),
                key: "app-lb-admin".into(),
                body: b"{}".to_vec(),
                expect: Expect::Absent,
            }],
            vec!["deployments".into()],
        )
        .unwrap();
        let report = apply_to(&pg, &bundle, &key, false).unwrap();
        assert!(report.contains("kept deployments/app-lb-admin"), "{report}");
        assert!(!report.contains("t0ken"));
        let (secrets, _) = pg.get("secrets", DOC_KEY).unwrap().unwrap();
        assert!(
            !String::from_utf8_lossy(&secrets).contains("t0ken"),
            "sealed in the store"
        );
        assert_eq!(
            secrets_seal::open_file(&key, &secrets).unwrap()[0]["id"],
            "github"
        );
        let (auth, _) = pg.get("auth-key", DOC_KEY).unwrap().unwrap();
        assert_eq!(
            fleet_seal::unseal(&key, "auth-key", DOC_KEY, &auth).unwrap(),
            [7u8; 32]
        );
        assert_eq!(
            pg.get("deployments", "app-lb-admin").unwrap().unwrap().0,
            b"{}",
            "us4's own"
        );
        assert!(pg.get("deployments", "web").unwrap().is_some());

        // Again, unchanged: nothing written.
        let again = apply_to(&pg, &bundle, &key, false).unwrap();
        assert!(!again.contains("applied"), "{again}");

        // The source deregisters `web`: the next bundle deletes it.
        std::fs::remove_file(src.0.join("app-lb-state.d/web.json")).unwrap();
        let bundle =
            bundle_of(read_records(&src.layout(), &src.0.join("app-lb-auth-key"), "us5").unwrap());
        let dry = apply_to(&pg, &bundle, &key, true).unwrap();
        assert!(dry.contains("dry run"));
        assert!(
            pg.get("deployments", "web").unwrap().is_some(),
            "a dry run writes nothing"
        );
        apply_to(&pg, &bundle, &key, false).unwrap();
        assert!(pg.get("deployments", "web").unwrap().is_none());
    }
}
