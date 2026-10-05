//! Read-only views of a hydrated cache, for the web UI: refs, trees, blobs,
//! history and diffs.
//!
//! Every function here runs plain `git` against a [`ReadView`]'s bare cache,
//! so what a browser sees is exactly what a clone would get. Inputs from a URL
//! (a ref, a path) are checked before they reach a git argument: a path is
//! only ever the part after `<commit>:`, and a commit is only ever an object
//! id this module resolved itself.

use std::collections::HashMap;
use std::path::Path;

use futures_util::StreamExt;

use crate::git::{GitError, GitService, ReadView};

/// Bytes of a blob shown inline; past this the page links to raw.
pub const MAX_INLINE: u64 = 1024 * 1024;
/// Bytes of a blob served raw. Bigger files are a clone's job.
pub const MAX_RAW: u64 = 25 * 1024 * 1024;
/// Bytes of a commit's patch rendered before it is cut off.
const MAX_PATCH: usize = 1024 * 1024;
/// Tree entries whose last commit is looked up (one `git log` each).
const MAX_LAST_COMMITS: usize = 100;

const FIELD: char = '\u{1f}';
const RECORD: char = '\u{1e}';
const SUMMARY_FORMAT: &str = "--format=%H%x1f%an%x1f%ae%x1f%at%x1f%s%x1e";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSummary {
    pub id: String,
    pub author: String,
    pub email: String,
    pub time: i64,
    pub subject: String,
}

impl CommitSummary {
    pub fn short(&self) -> &str {
        &self.id[..self.id.len().min(7)]
    }
}

#[derive(Debug, Clone)]
pub struct Commit {
    pub summary: CommitSummary,
    pub parents: Vec<String>,
    pub committer: String,
    /// The message after the subject line.
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Tree,
    Blob,
    /// A submodule: a commit id, not something in this repo.
    Commit,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    Branch,
    Tag,
}

/// What the `<ref>/<path>` tail of a URL named.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// As the URL spells it: `main`, `feature/x`, `v1.0`, or an object id.
    pub name: String,
    pub commit: String,
    pub path: String,
}

pub struct Blob {
    pub size: u64,
    /// `None` when the blob is over the limit asked for.
    pub bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineKind {
    Context,
    Add,
    Del,
    Hunk,
}

#[derive(Debug, Clone)]
pub struct FileDiff {
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub binary: bool,
    pub additions: usize,
    pub deletions: usize,
    pub lines: Vec<(LineKind, String)>,
}

impl FileDiff {
    pub fn path(&self) -> &str {
        self.new_path
            .as_deref()
            .or(self.old_path.as_deref())
            .unwrap_or("")
    }

    pub fn status(&self) -> &'static str {
        match (&self.old_path, &self.new_path) {
            (None, Some(_)) => "added",
            (Some(_), None) => "deleted",
            (Some(a), Some(b)) if a != b => "renamed",
            _ => "modified",
        }
    }
}

pub struct Diff {
    pub files: Vec<FileDiff>,
    pub truncated: bool,
}

fn git_in(git: &GitService, dir: &Path) -> tokio::process::Command {
    let mut c = git.git();
    c.arg("--git-dir").arg(dir);
    c
}

/// A path from a URL, as git names it inside a tree: no leading or trailing
/// slash, no empty, `.` or `..` segment.
pub fn clean_path(raw: &str) -> Option<String> {
    let p = raw.trim_matches('/');
    if p.is_empty() {
        return Some(String::new());
    }
    p.split('/')
        .all(|s| !s.is_empty() && s != "." && s != ".." && !s.contains('\0'))
        .then(|| p.to_string())
}

fn is_object_id(s: &str) -> bool {
    (7..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The commit an object id or a ref's target peels to.
async fn peel(git: &GitService, v: &ReadView, id: &str) -> Option<String> {
    let mut c = git_in(git, &v.path);
    c.args(["rev-parse", "--verify", "--quiet", "--end-of-options"])
        .arg(format!("{id}^{{commit}}"));
    let out = git.run(c).await.ok()?;
    let id = out.trim();
    (id.len() >= 40).then(|| id.to_string())
}

/// The longest branch or tag that `rest` starts with, then an object id; the
/// remainder is the path. `feature/x/src` with a branch `feature/x` is that
/// branch and `src`, as on GitHub.
pub async fn resolve(git: &GitService, v: &ReadView, rest: &str) -> Option<Resolved> {
    let rest = rest.trim_matches('/');
    let mut best: Option<(&str, &str)> = None;
    for (name, id) in &v.state.refs {
        let Some(short) = name
            .strip_prefix("refs/heads/")
            .or_else(|| name.strip_prefix("refs/tags/"))
        else {
            continue;
        };
        let hit = rest == short
            || rest
                .strip_prefix(short)
                .is_some_and(|tail| tail.starts_with('/'));
        if hit && best.is_none_or(|(b, _)| short.len() > b.len()) {
            best = Some((short, id));
        }
    }
    let (name, target) = match best {
        Some((n, id)) => (n.to_string(), id.to_string()),
        None => {
            let first = rest.split('/').next().unwrap_or("");
            if !is_object_id(first) {
                return None;
            }
            (first.to_string(), first.to_string())
        }
    };
    let path = clean_path(&rest[name.len().min(rest.len())..])?;
    let commit = peel(git, v, &target).await?;
    Some(Resolved { name, commit, path })
}

/// The branch HEAD names, if it exists yet.
pub fn head_branch(v: &ReadView) -> Option<String> {
    let short = v.state.head.strip_prefix("refs/heads/")?;
    v.state
        .refs
        .contains_key(&v.state.head)
        .then(|| short.to_string())
}

pub fn branches(v: &ReadView) -> Vec<String> {
    v.state
        .refs
        .keys()
        .filter_map(|r| r.strip_prefix("refs/heads/"))
        .map(String::from)
        .collect()
}

pub fn tags(v: &ReadView) -> Vec<String> {
    v.state
        .refs
        .keys()
        .filter_map(|r| r.strip_prefix("refs/tags/"))
        .map(String::from)
        .collect()
}

/// What `<commit>:<path>` is, or `None` when it is not there.
pub async fn kind_at(
    git: &GitService,
    v: &ReadView,
    commit: &str,
    path: &str,
) -> Option<EntryKind> {
    if path.is_empty() {
        return Some(EntryKind::Tree);
    }
    let mut c = git_in(git, &v.path);
    c.args(["cat-file", "-t"]).arg(format!("{commit}:{path}"));
    match git.run(c).await.ok()?.trim() {
        "tree" => Some(EntryKind::Tree),
        "blob" => Some(EntryKind::Blob),
        "commit" => Some(EntryKind::Commit),
        _ => None,
    }
}

/// A directory's entries, directories first, then by name.
pub async fn tree(
    git: &GitService,
    v: &ReadView,
    commit: &str,
    path: &str,
) -> Result<Vec<Entry>, GitError> {
    let mut c = git_in(git, &v.path);
    c.args(["ls-tree", "-z"]).arg(format!("{commit}:{path}"));
    let out = git.run(c).await?;
    let mut entries: Vec<Entry> = out
        .split('\0')
        .filter_map(|line| {
            let (meta, name) = line.split_once('\t')?;
            let mut f = meta.split_whitespace();
            let _mode = f.next()?;
            let kind = match f.next()? {
                "tree" => EntryKind::Tree,
                "blob" => EntryKind::Blob,
                "commit" => EntryKind::Commit,
                _ => return None,
            };
            Some(Entry {
                name: name.to_string(),
                kind,
            })
        })
        .collect();
    entries.sort_by(|a, b| {
        (a.kind != EntryKind::Tree)
            .cmp(&(b.kind != EntryKind::Tree))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(entries)
}

/// The last commit to touch each entry of a directory, as GitHub's file list
/// shows. One `git log` per entry, a few at a time; past
/// [`MAX_LAST_COMMITS`] entries none are looked up.
pub async fn last_commits(
    git: &GitService,
    v: &ReadView,
    commit: &str,
    dir: &str,
    entries: &[Entry],
) -> HashMap<String, CommitSummary> {
    if entries.len() > MAX_LAST_COMMITS {
        return HashMap::new();
    }
    let paths: Vec<(String, String)> = entries
        .iter()
        .map(|e| {
            let path = if dir.is_empty() {
                e.name.clone()
            } else {
                format!("{dir}/{}", e.name)
            };
            (e.name.clone(), path)
        })
        .collect();
    futures_util::stream::iter(paths)
        .map(|(name, path)| async move {
            let found = log(git, v, commit, Some(&path), 0, 1).await.ok()?;
            Some((name, found.into_iter().next()?))
        })
        .buffer_unordered(8)
        .filter_map(|x| async move { x })
        .collect()
        .await
}

fn parse_summary(rec: &str) -> Option<CommitSummary> {
    let mut f = rec.trim_start_matches('\n').splitn(5, FIELD);
    Some(CommitSummary {
        id: f.next()?.to_string(),
        author: f.next()?.to_string(),
        email: f.next()?.to_string(),
        time: f.next()?.parse().ok()?,
        subject: f.next()?.trim_end().to_string(),
    })
}

/// History from `commit`, newest first, optionally only commits touching
/// `path`.
pub async fn log(
    git: &GitService,
    v: &ReadView,
    commit: &str,
    path: Option<&str>,
    skip: usize,
    limit: usize,
) -> Result<Vec<CommitSummary>, GitError> {
    let mut c = git_in(git, &v.path);
    c.arg("log")
        .arg(SUMMARY_FORMAT)
        .arg(format!("--skip={skip}"))
        .arg(format!("--max-count={limit}"))
        .arg(commit);
    if let Some(p) = path.filter(|p| !p.is_empty()) {
        c.arg("--").arg(p);
    }
    let out = git.run(c).await?;
    Ok(out.split(RECORD).filter_map(parse_summary).collect())
}

pub async fn count(git: &GitService, v: &ReadView, commit: &str) -> Option<u64> {
    let mut c = git_in(git, &v.path);
    c.args(["rev-list", "--count"]).arg(commit);
    git.run(c).await.ok()?.trim().parse().ok()
}

pub async fn blob(
    git: &GitService,
    v: &ReadView,
    commit: &str,
    path: &str,
    max: u64,
) -> Result<Blob, GitError> {
    let spec = format!("{commit}:{path}");
    let mut c = git_in(git, &v.path);
    c.args(["cat-file", "-s"]).arg(&spec);
    let size: u64 = git
        .run(c)
        .await?
        .trim()
        .parse()
        .map_err(|_| GitError::new(axum::http::StatusCode::BAD_GATEWAY, "bad blob size"))?;
    if size > max {
        return Ok(Blob { size, bytes: None });
    }
    let mut c = git_in(git, &v.path);
    c.args(["cat-file", "blob"]).arg(&spec);
    Ok(Blob {
        size,
        bytes: Some(git.run_bytes(c).await?),
    })
}

/// A commit named by an object id, or `None` if there is no such commit.
pub async fn commit(git: &GitService, v: &ReadView, id: &str) -> Option<Commit> {
    if !is_object_id(id) {
        return None;
    }
    let id = peel(git, v, id).await?;
    let mut c = git_in(git, &v.path);
    c.args([
        "log",
        "-1",
        "--format=%H%x1f%an%x1f%ae%x1f%at%x1f%s%x1f%P%x1f%cn%x1f%b",
    ])
    .arg(&id);
    let out = git.run(c).await.ok()?;
    let mut f = out.splitn(8, FIELD);
    let summary = CommitSummary {
        id: f.next()?.to_string(),
        author: f.next()?.to_string(),
        email: f.next()?.to_string(),
        time: f.next()?.parse().ok()?,
        subject: f.next()?.to_string(),
    };
    Some(Commit {
        summary,
        parents: f.next()?.split_whitespace().map(String::from).collect(),
        committer: f.next()?.to_string(),
        body: f.next().unwrap_or("").trim().to_string(),
    })
}

/// What `id` changed against its first parent (or, for a root commit,
/// against nothing).
pub async fn diff(git: &GitService, v: &ReadView, id: &str) -> Result<Diff, GitError> {
    let mut c = git_in(git, &v.path);
    c.args([
        "show",
        "--format=",
        "--patch",
        "-M",
        "--no-color",
        "--no-ext-diff",
        "--diff-merges=first-parent",
    ])
    .arg(id);
    let mut out = git.run_bytes(c).await?;
    let truncated = out.len() > MAX_PATCH;
    out.truncate(MAX_PATCH);
    Ok(Diff {
        files: parse_patch(&String::from_utf8_lossy(&out)),
        truncated,
    })
}

fn unquote(p: &str) -> String {
    p.trim().trim_matches('"').to_string()
}

pub fn parse_patch(patch: &str) -> Vec<FileDiff> {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut in_hunk = false;
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            in_hunk = false;
            // `a/x b/x` — only a fallback; `---`/`+++` and rename lines are
            // authoritative and handle spaces.
            let (a, b) = rest.split_once(" b/").unwrap_or((rest, ""));
            let a = a.strip_prefix("a/").unwrap_or(a);
            files.push(FileDiff {
                old_path: Some(unquote(a)),
                new_path: Some(unquote(b)),
                binary: false,
                additions: 0,
                deletions: 0,
                lines: vec![],
            });
            continue;
        }
        let Some(f) = files.last_mut() else { continue };
        if in_hunk {
            match line.as_bytes().first() {
                Some(b'+') => {
                    f.additions += 1;
                    f.lines.push((LineKind::Add, line[1..].to_string()));
                    continue;
                }
                Some(b'-') => {
                    f.deletions += 1;
                    f.lines.push((LineKind::Del, line[1..].to_string()));
                    continue;
                }
                Some(b' ') => {
                    f.lines.push((LineKind::Context, line[1..].to_string()));
                    continue;
                }
                Some(b'\\') => continue,
                _ => {}
            }
        }
        if line.starts_with("@@") {
            in_hunk = true;
            f.lines.push((LineKind::Hunk, line.to_string()));
        } else if line.starts_with("new file mode") {
            f.old_path = None;
        } else if line.starts_with("deleted file mode") {
            f.new_path = None;
        } else if let Some(p) = line.strip_prefix("rename from ") {
            f.old_path = Some(unquote(p));
        } else if let Some(p) = line.strip_prefix("rename to ") {
            f.new_path = Some(unquote(p));
        } else if let Some(p) = line.strip_prefix("--- ") {
            if p != "/dev/null" {
                f.old_path = Some(unquote(p.strip_prefix("a/").unwrap_or(p)));
            }
        } else if let Some(p) = line.strip_prefix("+++ ") {
            if p != "/dev/null" {
                f.new_path = Some(unquote(p.strip_prefix("b/").unwrap_or(p)));
            }
        } else if line.starts_with("Binary files") {
            f.binary = true;
        }
    }
    files
}

/// A README in a directory listing, GitHub's order of preference.
pub fn readme(entries: &[Entry]) -> Option<&Entry> {
    let rank = |n: &str| -> Option<u8> {
        match n.to_ascii_lowercase().as_str() {
            "readme.md" | "readme.markdown" => Some(0),
            "readme" | "readme.txt" => Some(1),
            "readme.rst" | "readme.adoc" => Some(2),
            _ => None,
        }
    };
    entries
        .iter()
        .filter(|e| e.kind == EntryKind::Blob)
        .filter_map(|e| Some((rank(&e.name)?, e)))
        .min_by_key(|(r, _)| *r)
        .map(|(_, e)| e)
}

pub fn is_markdown(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    l.ends_with(".md") || l.ends_with(".markdown")
}

/// A raster image a browser can show from `<img>`. SVG is deliberately not
/// one: served from this origin it is a document that can run script.
pub fn image_type(path: &str) -> Option<&'static str> {
    let ext = path.rsplit_once('.')?.1.to_ascii_lowercase();
    Some(match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        _ => return None,
    })
}

/// git's own heuristic: a NUL in the first 8000 bytes.
pub fn is_binary(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(8000)].contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_from_urls_are_confined() {
        assert_eq!(clean_path("/src/main.rs/").as_deref(), Some("src/main.rs"));
        assert_eq!(clean_path("").as_deref(), Some(""));
        for bad in ["../x", "a/../b", "a//b", "./a"] {
            assert!(clean_path(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn patches_parse_into_files() {
        let patch = "\
diff --git a/README.md b/README.md
index 1..2 100644
--- a/README.md
+++ b/README.md
@@ -1,2 +1,2 @@
 keep
-old
+new
diff --git a/new.txt b/new.txt
new file mode 100644
--- /dev/null
+++ b/new.txt
@@ -0,0 +1 @@
+hello
diff --git a/a.txt b/b.txt
similarity index 100%
rename from a.txt
rename to b.txt
diff --git a/img.png b/img.png
Binary files a/img.png and b/img.png differ
";
        let f = parse_patch(patch);
        assert_eq!(f.len(), 4);
        assert_eq!((f[0].additions, f[0].deletions), (1, 1));
        assert_eq!(f[0].status(), "modified");
        assert_eq!(f[1].status(), "added");
        assert_eq!(f[1].path(), "new.txt");
        assert_eq!(f[2].status(), "renamed");
        assert_eq!(f[2].old_path.as_deref(), Some("a.txt"));
        assert!(f[3].binary);
        assert_eq!(
            f[0].lines
                .iter()
                .map(|(k, _)| k.clone())
                .collect::<Vec<_>>(),
            vec![
                LineKind::Hunk,
                LineKind::Context,
                LineKind::Del,
                LineKind::Add
            ]
        );
    }

    #[test]
    fn readme_preference() {
        let e = |n: &str| Entry {
            name: n.into(),
            kind: EntryKind::Blob,
        };
        let list = vec![e("readme.txt"), e("README.md"), e("main.rs")];
        assert_eq!(readme(&list).unwrap().name, "README.md");
        assert!(readme(&[e("main.rs")]).is_none());
        assert_eq!(image_type("logo.PNG"), Some("image/png"));
        assert_eq!(image_type("logo.svg"), None);
    }
}
