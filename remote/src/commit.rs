//! Commits made on the server, for agents that have files but no `git`.
//!
//! The files are written into a scratch bare repo that borrows the cache's
//! objects (`objects/info/alternates`). They are committed with git plumbing
//! (`hash-object`, `update-index --index-info`, `write-tree`, `commit-tree`)
//! and the commit is then `git push`ed into the cache. That last step runs the
//! same receive-pack and pre-receive hook a client push does, so this path has
//! no S3 logic of its own: the authority sees an ordinary push.

use std::io::Read;
use std::path::Path;
use std::process::Stdio;

use axum::http::StatusCode;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::git::{GitError, GitService, RepoRef};

/// Sum of file contents one commit request may carry.
pub const MAX_COMMIT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_FILES: usize = 10_000;

#[derive(Debug, Clone, Deserialize)]
pub struct FileChange {
    pub path: String,
    #[serde(default)]
    pub content: Option<String>,
    /// `utf8` (default) or `base64`.
    #[serde(default)]
    pub encoding: Option<String>,
    #[serde(default)]
    pub executable: bool,
    #[serde(default)]
    pub delete: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommitRequest {
    #[serde(default)]
    pub branch: Option<String>,
    pub message: String,
    #[serde(default)]
    pub files: Vec<FileChange>,
    /// The commit the caller believes the branch is at. A mismatch is a 409
    /// instead of silently committing on top of somebody else's work.
    #[serde(default)]
    pub base: Option<String>,
    /// Start from an empty tree: the files given are the whole repo.
    #[serde(default)]
    pub replace: bool,
    #[serde(default)]
    pub author_name: Option<String>,
    #[serde(default)]
    pub author_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CommitResult {
    pub commit: String,
    pub branch: String,
    pub parent: Option<String>,
    pub tree: String,
    pub files_written: usize,
    pub files_deleted: usize,
    /// False when the tree did not change and no commit was made.
    pub changed: bool,
}

/// A file, decoded and checked, ready to hash.
pub struct Entry {
    pub path: String,
    pub bytes: Vec<u8>,
    pub executable: bool,
}

fn bad(msg: impl Into<String>) -> GitError {
    GitError::new(StatusCode::BAD_REQUEST, msg)
}

/// Repo-relative, forward-slash, nothing that escapes or touches `.git`.
pub fn valid_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 4096
        && !p.starts_with('/')
        && !p.ends_with('/')
        && !p.contains('\0')
        && !p.contains('\\')
        && !p.contains('\n')
        && p.split('/').all(|seg| {
            !seg.is_empty() && seg != "." && seg != ".." && !seg.eq_ignore_ascii_case(".git")
        })
}

pub fn valid_branch(b: &str) -> bool {
    !b.is_empty()
        && b.len() <= 200
        && !b.starts_with(['-', '/'])
        && !b.ends_with(['/', '.'])
        && !b.contains("..")
        && !b.contains("//")
        && !b.ends_with(".lock")
        && b.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_./".contains(&c))
}

/// Decode a JSON change list into entries and deletions.
pub fn decode(files: &[FileChange]) -> Result<(Vec<Entry>, Vec<String>), GitError> {
    if files.len() > MAX_FILES {
        return Err(bad(format!("at most {MAX_FILES} files per commit")));
    }
    let mut entries = Vec::new();
    let mut deletes = Vec::new();
    let mut total = 0usize;
    for f in files {
        if !valid_path(&f.path) {
            return Err(bad(format!(
                "invalid path {:?}: paths are relative, use '/', and may not contain '..' or '.git'",
                f.path
            )));
        }
        if f.delete {
            deletes.push(f.path.clone());
            continue;
        }
        let content = f.content.as_deref().ok_or_else(|| {
            bad(format!(
                "{}: content is required unless delete is true",
                f.path
            ))
        })?;
        let bytes = match f.encoding.as_deref().unwrap_or("utf8") {
            "utf8" | "utf-8" | "text" => content.as_bytes().to_vec(),
            "base64" => base64::engine::general_purpose::STANDARD
                .decode(content.trim())
                .map_err(|e| bad(format!("{}: bad base64: {e}", f.path)))?,
            other => {
                return Err(bad(format!(
                    "{}: unknown encoding {other:?} (utf8 or base64)",
                    f.path
                )));
            }
        };
        total += bytes.len();
        if total > MAX_COMMIT_BYTES {
            return Err(bad(format!(
                "files total more than {} MiB; push with git instead",
                MAX_COMMIT_BYTES >> 20
            )));
        }
        entries.push(Entry {
            path: f.path.clone(),
            bytes,
            executable: f.executable,
        });
    }
    Ok((entries, deletes))
}

/// Unpack a `.tar.gz` (or plain `.tar`) into entries. Directories are implied;
/// links and devices are refused rather than followed.
pub fn decode_tarball(bytes: &[u8]) -> Result<Vec<Entry>, GitError> {
    let gz = bytes.starts_with(&[0x1f, 0x8b]);
    let reader: Box<dyn Read> = if gz {
        Box::new(flate2::read::GzDecoder::new(bytes))
    } else {
        Box::new(bytes)
    };
    let mut archive = tar::Archive::new(reader);
    let mut out = Vec::new();
    let mut total = 0usize;
    for entry in archive
        .entries()
        .map_err(|e| bad(format!("bad tarball: {e}")))?
    {
        let mut entry = entry.map_err(|e| bad(format!("bad tarball: {e}")))?;
        let kind = entry.header().entry_type();
        let raw = entry
            .path()
            .map_err(|e| bad(format!("bad tarball path: {e}")))?;
        let path = raw.to_string_lossy().trim_start_matches("./").to_string();
        if kind.is_dir() || path.is_empty() {
            continue;
        }
        // pax/GNU extension headers carry metadata, not files.
        if matches!(
            kind,
            tar::EntryType::XGlobalHeader | tar::EntryType::XHeader | tar::EntryType::GNULongName
        ) {
            continue;
        }
        if !kind.is_file() {
            return Err(bad(format!(
                "{path}: only regular files are accepted in a tarball"
            )));
        }
        if !valid_path(&path) {
            return Err(bad(format!("invalid path {path:?} in tarball")));
        }
        let executable = entry.header().mode().is_ok_and(|m| m & 0o111 != 0);
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| bad(format!("{path}: {e}")))?;
        total += buf.len();
        if total > MAX_COMMIT_BYTES || out.len() >= MAX_FILES {
            return Err(bad(format!(
                "tarball exceeds {} MiB or {MAX_FILES} files; push with git instead",
                MAX_COMMIT_BYTES >> 20
            )));
        }
        out.push(Entry {
            path,
            bytes: buf,
            executable,
        });
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub async fn commit(
    git: &GitService,
    r: &RepoRef,
    branch: &str,
    message: &str,
    entries: Vec<Entry>,
    deletes: Vec<String>,
    base: Option<&str>,
    replace: bool,
    author: (&str, &str),
) -> Result<CommitResult, GitError> {
    if !valid_branch(branch) {
        return Err(bad(format!("invalid branch name {branch:?}")));
    }
    if message.trim().is_empty() {
        return Err(bad("a commit message is required"));
    }
    let refname = format!("refs/heads/{branch}");
    let ex = git.exclusive(r).await?;
    let parent = ex.state.refs.get(&refname).cloned();
    if let Some(expected) = base
        && parent.as_deref() != Some(expected)
    {
        return Err(GitError::new(
            StatusCode::CONFLICT,
            format!(
                "{branch} is at {} but this commit was based on {expected}; re-read the branch and retry",
                parent
                    .as_deref()
                    .unwrap_or("nothing (the branch does not exist)")
            ),
        ));
    }

    let scratch = tempfile::Builder::new()
        .prefix("commit-")
        .tempdir_in(ensure_dir(&git.cache_dir.join("tmp")).await?)
        .map_err(|e| GitError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let gd = scratch.path().join("repo.git");
    let mut init = git.git();
    init.args(["init", "--bare", "-q"]).arg(&gd);
    git.run(init).await?;
    tokio::fs::write(
        gd.join("objects/info/alternates"),
        format!(
            "{}\n",
            ex.path
                .join("objects")
                .canonicalize()
                .map_err(io)?
                .display()
        ),
    )
    .await
    .map_err(io)?;
    let index = scratch.path().join("index");
    let g = |args: &[&str]| {
        let mut c = git.git();
        c.arg("--git-dir")
            .arg(&gd)
            .env("GIT_INDEX_FILE", &index)
            .args(args);
        c
    };

    match (&parent, replace) {
        (Some(p), false) => git.run(g(&["read-tree", p])).await?,
        _ => git.run(g(&["read-tree", "--empty"])).await?,
    };

    // Contents go to disk so hash-object can take them all in one process.
    let files_dir = scratch.path().join("files");
    let mut paths = String::new();
    for (i, e) in entries.iter().enumerate() {
        let p = files_dir.join(i.to_string());
        if i == 0 {
            ensure_dir(&files_dir).await?;
        }
        tokio::fs::write(&p, &e.bytes).await.map_err(io)?;
        paths.push_str(&format!("{}\n", p.display()));
    }
    let shas: Vec<String> = if entries.is_empty() {
        vec![]
    } else {
        piped(
            g(&["hash-object", "-w", "--no-filters", "--stdin-paths"]),
            paths.as_bytes(),
        )
        .await?
        .lines()
        .map(String::from)
        .collect()
    };
    if shas.len() != entries.len() {
        return Err(GitError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "hash-object returned the wrong count",
        ));
    }
    let mut info = String::new();
    for d in &deletes {
        info.push_str(&format!("0 {}\t{d}\n", crate::git::ZERO_ID));
    }
    for (e, sha) in entries.iter().zip(&shas) {
        let mode = if e.executable { "100755" } else { "100644" };
        info.push_str(&format!("{mode} {sha}\t{}\n", e.path));
    }
    piped(g(&["update-index", "--index-info"]), info.as_bytes()).await?;
    let tree = git.run(g(&["write-tree"])).await?.trim().to_string();

    let unchanged = match &parent {
        Some(p) => {
            git.run(g(&["rev-parse", &format!("{p}^{{tree}}")]))
                .await?
                .trim()
                == tree
        }
        None => false,
    };
    if unchanged {
        let p = parent.clone().unwrap_or_default();
        return Ok(CommitResult {
            commit: p.clone(),
            branch: branch.into(),
            parent: Some(p),
            tree,
            files_written: 0,
            files_deleted: 0,
            changed: false,
        });
    }

    let mut ct = g(&["commit-tree", &tree, "-F", "-"]);
    if let Some(p) = &parent {
        ct.args(["-p", p]);
    }
    ct.env("GIT_AUTHOR_NAME", author.0)
        .env("GIT_AUTHOR_EMAIL", author.1)
        .env("GIT_COMMITTER_NAME", "heyo remote")
        .env("GIT_COMMITTER_EMAIL", "remote@heyo.computer");
    let commit = piped(ct, message.as_bytes()).await?.trim().to_string();

    // Into the cache through receive-pack, so the hook records it.
    let mut push = git.git();
    push.arg("--git-dir")
        .arg(&gd)
        .args(["push", "--porcelain", "--quiet"])
        .arg(&ex.path)
        .arg(format!("{commit}:{refname}"))
        .envs(git.hook_env(r, ex.etag.as_deref()));
    git.run(push).await.map_err(|e| {
        let m = e.message;
        if m.contains("landed first") || m.contains("moved on the server") {
            GitError::new(
                StatusCode::CONFLICT,
                format!("{branch} changed while committing; retry ({m})"),
            )
        } else {
            GitError::new(StatusCode::INTERNAL_SERVER_ERROR, m)
        }
    })?;
    drop(ex);
    git.wrote(r);

    Ok(CommitResult {
        commit,
        branch: branch.into(),
        parent,
        tree,
        files_written: entries.len(),
        files_deleted: deletes.len(),
        changed: true,
    })
}

fn io(e: std::io::Error) -> GitError {
    GitError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

async fn ensure_dir(p: &Path) -> Result<&Path, GitError> {
    tokio::fs::create_dir_all(p).await.map_err(io)?;
    Ok(p)
}

/// Run git with `input` on stdin; stdout on success.
async fn piped(mut cmd: tokio::process::Command, input: &[u8]) -> Result<String, GitError> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(io)?;
    let mut stdin = child.stdin.take().expect("piped");
    let input = input.to_vec();
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(&input).await;
    });
    let out = child.wait_with_output().await.map_err(io)?;
    let _ = writer.await;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(GitError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "git failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_branches() {
        for ok in ["index.html", "src/main.rs", "a/.github/x.yml", ".gitignore"] {
            assert!(valid_path(ok), "{ok}");
        }
        for bad in [
            "",
            "/etc/passwd",
            "a/../b",
            "./a",
            ".git/config",
            "a/.GIT/x",
            "a//b",
            "a/",
            "a\\b",
        ] {
            assert!(!valid_path(bad), "{bad}");
        }
        assert!(valid_branch("main") && valid_branch("feat/x-1"));
        for bad in ["", "-x", "a..b", "a/", "x.lock", "a b", "refs/../x"] {
            assert!(!valid_branch(bad), "{bad}");
        }
    }

    #[test]
    fn decode_handles_encodings_and_deletes() {
        let files = vec![
            FileChange {
                path: "a.txt".into(),
                content: Some("hi".into()),
                encoding: None,
                executable: false,
                delete: false,
            },
            FileChange {
                path: "b.bin".into(),
                content: Some("AAE=".into()),
                encoding: Some("base64".into()),
                executable: true,
                delete: false,
            },
            FileChange {
                path: "old".into(),
                content: None,
                encoding: None,
                executable: false,
                delete: true,
            },
        ];
        let (entries, deletes) = decode(&files).unwrap();
        assert_eq!(entries[1].bytes, vec![0, 1]);
        assert!(entries[1].executable);
        assert_eq!(deletes, vec!["old"]);
        let missing = vec![FileChange {
            path: "x".into(),
            content: None,
            encoding: None,
            executable: false,
            delete: false,
        }];
        assert!(decode(&missing).is_err());
    }

    #[test]
    fn tarballs_are_read_and_links_refused() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(2);
        h.set_mode(0o755);
        h.set_cksum();
        b.append_data(&mut h, "./bin/run", &b"hi"[..]).unwrap();
        let tar = b.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        let entries = decode_tarball(&gz.finish().unwrap()).unwrap();
        assert_eq!(entries[0].path, "bin/run");
        assert!(entries[0].executable);

        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_cksum();
        b.append_link(&mut h, "link", "/etc/passwd").unwrap();
        assert!(decode_tarball(&b.into_inner().unwrap()).is_err());
    }
}
