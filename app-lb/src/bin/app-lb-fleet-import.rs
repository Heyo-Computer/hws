//! `app-lb-fleet-import`: read a host's app-lb state and report what a fleet
//! store would receive from it.
//!
//! A separate binary, never an `app-lb` subcommand: running `app-lb` with an
//! argument it did not understand once started a second server whose orphan
//! sweep destroyed every VM on the host (2026-09-29). This program compiles
//! only `fleet_store`, so it cannot start a server, reach heyvm, or take the
//! instance lock, whatever arguments it is given.
//!
//! Phase 1 (see `docs/design/fleet-shared-state.md`) only reads: `--dry-run` is
//! required, nothing is written anywhere, and no secret value, token hash or
//! key is printed — only counts and the locations of records that could not be
//! read.

#[allow(dead_code)]
#[path = "../fleet_store.rs"]
mod fleet_store;

use fleet_store::{Collection, Document, FileCollection, FileDocument, FileOptions, Layout};
use std::path::PathBuf;
use std::process::ExitCode;

const HELP: &str = "\
app-lb-fleet-import — report what a host's app-lb state holds, for a fleet store

Usage: app-lb-fleet-import --dry-run [options]

Reads the same APP_LB_* paths app-lb does. Writes nothing, prints no secret.

Options:
      --dry-run              Required: read and report only
      --state-path <path>    Overrides APP_LB_STATE_PATH
      --secrets-path <path>  Overrides APP_LB_SECRETS_PATH
      --tokens-path <path>   Overrides APP_LB_TOKENS_PATH
      --guard-path <path>    Overrides APP_LB_GUARD_PATH
      --acme-dir <path>      Overrides APP_LB_ACME_DIR
  -h, --help                 Print this help and exit

Exit status: 0 when every record could be read, 1 when any could not, 2 on a
usage error.
";

fn main() -> ExitCode {
    let mut layout = Layout::from_env();
    let mut dry_run = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut path = |name: &str| -> Option<PathBuf> {
            let v = args.next().map(PathBuf::from);
            if v.is_none() {
                eprintln!("{name} needs a path");
            }
            v
        };
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--state-path" => match path(&arg) {
                Some(p) => layout.state_path = p,
                None => return ExitCode::from(2),
            },
            "--secrets-path" => match path(&arg) {
                Some(p) => layout.secrets_path = p,
                None => return ExitCode::from(2),
            },
            "--tokens-path" => match path(&arg) {
                Some(p) => layout.tokens_path = p,
                None => return ExitCode::from(2),
            },
            "--guard-path" => match path(&arg) {
                Some(p) => layout.guard_path = p,
                None => return ExitCode::from(2),
            },
            "--acme-dir" => match path(&arg) {
                Some(p) => layout.acme_dir = p,
                None => return ExitCode::from(2),
            },
            "-h" | "--help" => {
                print!("{HELP}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument {other:?}\n\n{HELP}");
                return ExitCode::from(2);
            }
        }
    }
    if !dry_run {
        eprintln!(
            "only --dry-run is supported: this version reads and reports, and never writes\n\n{HELP}"
        );
        return ExitCode::from(2);
    }

    let report = survey(&layout);
    print!("{}", report.render());
    if report.unreadable() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

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
