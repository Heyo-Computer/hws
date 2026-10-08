//! Exact-base semantic release publication.
//!
//! Preparation never checks out files: it constructs the release tree with a
//! private index and Git plumbing, making it safe to use beside running jobs.

use base64::Engine as _;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{Duration, timeout};
use toml_edit::{DocumentMut, value};

const GIT_TIMEOUT: Duration = Duration::from_secs(45);

/// Freeze a merged revision and its build definitions without checking out or
/// executing repository files. An explicit cutoff must belong to the operator's
/// branch; an omitted cutoff means the branch tip observed by this fetch.
pub async fn build_source(
    repository: &str, git_ref: &str, revision: Option<&str>, paths: &[String],
    token: &str, max_bytes: usize,
) -> Result<crate::trigger::GitPatchSource, String> {
    Ok(build_source_scoped(repository, git_ref, revision, paths, token, max_bytes).await?.0)
}

/// Identity includes Git modes, object IDs and names, including deletions and
/// symlink/submodule changes. Unsupported filters deliberately use the full tree.
pub async fn build_source_scoped(
    repository: &str, git_ref: &str, revision: Option<&str>, paths: &[String],
    token: &str, max_bytes: usize,
) -> Result<(crate::trigger::GitPatchSource, String, String), String> {
    validate_repository(repository)?;
    validate_ref(git_ref)?;
    if let Some(sha) = revision { validate_sha(sha)?; }
    for path in paths {
        if path.is_empty() || path.contains(':') || Path::new(path).components().any(|c| !matches!(c, Component::Normal(_))) {
            return Err("build workflow must be a repository-relative file path".into());
        }
    }
    let dir = TempDir::new().map_err(|e| e.to_string())?;
    let home = TempDir::new().map_err(|e| e.to_string())?;
    let home_s = home.path().to_string_lossy();
    let key = format!("http.{repository}.extraHeader");
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
    let auth = format!("Authorization: Basic {basic}");
    let env = [("HOME", home_s.as_ref()), ("XDG_CONFIG_HOME", home_s.as_ref()),
        ("GIT_CONFIG_NOSYSTEM", "1"), ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_TERMINAL_PROMPT", "0"), ("GIT_CONFIG_COUNT", "3"),
        ("GIT_CONFIG_KEY_0", "credential.helper"), ("GIT_CONFIG_VALUE_0", ""),
        ("GIT_CONFIG_KEY_1", "protocol.ext.allow"), ("GIT_CONFIG_VALUE_1", "never"),
        ("GIT_CONFIG_KEY_2", key.as_str()), ("GIT_CONFIG_VALUE_2", auth.as_str())];
    let safe = |e| redact_git_error(e, token);
    git(dir.path(), &env, &["init", "--quiet"], None).await.map_err(safe)?;
    git(dir.path(), &env, &["fetch", "--quiet", "--no-tags", repository, git_ref], None).await.map_err(safe)?;
    let tip = git(dir.path(), &env, &["rev-parse", "FETCH_HEAD^{commit}"], None).await.map_err(safe)?;
    let sha = revision.unwrap_or(tip.trim()).to_lowercase();
    git(dir.path(), &env, &["merge-base", "--is-ancestor", &sha, tip.trim()], None).await
        .map_err(|_| "build cutoff is not a merged ancestor of the configured branch".to_string())?;
    let tree = git(dir.path(), &env, &["rev-parse", &format!("{sha}^{{tree}}")], None).await.map_err(safe)?;
    let mut workflows = BTreeMap::new();
    let mut size = 0;
    for path in paths {
        let text = git(dir.path(), &env, &["show", &format!("{sha}:{path}")], None).await.map_err(safe)?;
        size += text.len();
        if size > max_bytes { return Err("release build definitions exceed source limit".into()); }
        workflows.insert(path.clone(), text);
    }
    let entries = git(dir.path(), &env, &["ls-tree", "-r", "-z", &sha], None).await.map_err(safe)?;
    let identity = input_identity(&workflows, &entries);
    let message = git(dir.path(), &env, &["show", "-s", "--format=%B", &sha], None).await.map_err(safe)?;
    let message: String = message.trim().chars().take(8000).collect();
    Ok((crate::trigger::GitPatchSource { base_revision: sha, target_tree: tree.trim().into(),
        patch_base64: String::new(), workflows,
        changes: crate::paths::Changes::unknown("full release build; path filters do not select components") }, identity, message))
}

fn input_identity(workflows: &BTreeMap<String, String>, entries: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut patterns = Vec::new();
    let scoped = workflows.iter().all(|(path, text)| {
        let Ok(workflow) = crate::workflow::Workflow::parse(path, text) else { return false };
        let filters = workflow.on_submit.paths;
        if filters.is_empty() || filters.iter().any(|p| {
            crate::paths::validate(p).is_err()
                || p.contains(['[', ']', '{', '}', '(', ')', '+', '\\'])
                || p.split('/').any(|s| s.contains("**") && s != "**")
        }) { return false; }
        patterns.extend(filters);
        true
    });
    let mut hash = Sha256::new();
    hash.update(b"release-input-v1\0");
    for entry in entries.split('\0').filter(|e| !e.is_empty()) {
        let path = entry.split_once('\t').map(|(_, p)| p);
        if !scoped || path.is_some_and(|p| workflows.contains_key(p) || patterns.iter().any(|pat| crate::paths::matches(pat, p))) {
            hash.update(entry.as_bytes());
            hash.update([0]);
        }
    }
    hex::encode(hash.finalize())
}

/// Materialize source only for the controller's authorized release operation.
pub async fn materialize(repository:&str,descriptor:&crate::trigger::GitPatchSource,token:&str)->Result<TempDir,String>{
    validate_repository(repository)?;validate_sha(&descriptor.base_revision)?;
    let dir=TempDir::new().map_err(|e|format!("create release checkout: {e}"))?;
    let home=TempDir::new().map_err(|e|format!("create isolated Git home: {e}"))?;
    let home_s=home.path().to_string_lossy().into_owned();
    let basic=base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
    let key=format!("http.{repository}.extraHeader");
    let auth=format!("Authorization: Basic {basic}");
    let env=[("HOME",home_s.as_str()),("XDG_CONFIG_HOME",home_s.as_str()),("GIT_CONFIG_NOSYSTEM","1"),("GIT_CONFIG_GLOBAL","/dev/null"),("GIT_TERMINAL_PROMPT","0"),("GCM_INTERACTIVE","Never"),("GIT_CONFIG_COUNT","3"),("GIT_CONFIG_KEY_0","credential.helper"),("GIT_CONFIG_VALUE_0",""),("GIT_CONFIG_KEY_1","protocol.ext.allow"),("GIT_CONFIG_VALUE_1","never"),("GIT_CONFIG_KEY_2",key.as_str()),("GIT_CONFIG_VALUE_2",auth.as_str())];
    let safe=|e|redact_git_error(e,token);
    git(dir.path(),&env,&["init","--quiet"],None).await.map_err(safe)?;
    git(dir.path(),&env,&["remote","add","origin",repository],None).await.map_err(safe)?;
    git(dir.path(),&env,&["fetch","--quiet","--tags","origin","+refs/heads/*:refs/remotes/origin/*"],None).await.map_err(safe)?;
    if git(dir.path(),&env,&["cat-file","-e",&format!("{}^{{commit}}",descriptor.base_revision)],None).await.is_err(){git(dir.path(),&env,&["fetch","--quiet","origin",&descriptor.base_revision],None).await.map_err(safe)?;}
    git(dir.path(),&env,&["-c","core.hooksPath=/dev/null","checkout","--quiet","--detach",&descriptor.base_revision],None).await.map_err(safe)?;
    let patch=descriptor.patch().map_err(|e|e.to_string())?;
    if !patch.is_empty(){return Err("release publication requires an exact published source commit, not a patched submission".into())}
    let tree=git(dir.path(),&env,&["write-tree"],None).await.map_err(safe)?;
    if tree.trim()!=descriptor.target_tree{return Err("release checkout tree does not match validated descriptor".into())}
    Ok(dir)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct PreparedRelease {
    pub source_sha: String,
    pub release_sha: String,
    pub git_ref: String,
    pub versions: Value,
    /// Full lightweight tag refs to publish at `release_sha`.
    #[serde(default)]
    pub tags: Vec<String>,
}

pub async fn prepare(
    source: &Path,
    base: &str,
    head: &str,
    git_ref: &str,
    manifests: &[String],
    tag_policy: &BTreeMap<String, String>,
) -> Result<PreparedRelease, String> {
    validate_sha(base)?;
    validate_sha(head)?;
    validate_ref(git_ref)?;
    let manifest_set: HashSet<&str> = manifests.iter().map(String::as_str).collect();
    for path in tag_policy.keys() {
        if !manifest_set.contains(path.as_str()) {
            return Err(format!("tag manifest is not declared in with.manifests: {path}"));
        }
    }
    let actual_head = git(
        source,
        &[],
        &["rev-parse", "--verify", "HEAD^{commit}"],
        None,
    )
    .await?;
    if actual_head.trim() != head {
        return Err("materialized checkout HEAD does not equal the validated source head".into());
    }
    let actual_base = git(
        source,
        &[],
        &["rev-parse", "--verify", &format!("{base}^{{commit}}")],
        None,
    )
    .await?;
    if actual_base.trim() != base {
        return Err("base is not an available commit object".into());
    }
    git(
        source,
        &[],
        &["merge-base", "--is-ancestor", base, head],
        None,
    )
    .await
    .map_err(|_| "validated base is not an ancestor of source HEAD".to_string())?;

    let changed = git(
        source,
        &[],
        &["diff", "--name-only", "-z", base, head],
        None,
    )
    .await?;
    let changed: Vec<&str> = changed.split('\0').filter(|s| !s.is_empty()).collect();
    let messages = git(
        source,
        &[],
        &["log", "--format=%B%x00", &format!("{base}..{head}")],
        None,
    )
    .await?;
    let bump = bump_kind(&messages);

    // Keep both the index and its containing directory private for the entire
    // preparation. Dropping the TempDir cleans up on every early return.
    let index_dir = TempDir::new().map_err(|e| format!("create release index: {e}"))?;
    let index_path = index_dir
        .path()
        .join("index")
        .to_string_lossy()
        .into_owned();
    let env = [("GIT_INDEX_FILE", index_path.as_str())];
    git(source, &env, &["read-tree", head], None).await?;

    let mut versions = Map::new();
    for requested in manifests {
        let path = safe_manifest(source, requested)?;
        let component = path.parent().unwrap_or_else(|| Path::new(""));
        if !changed
            .iter()
            .any(|p| component.as_os_str().is_empty() || Path::new(p).starts_with(component))
        {
            continue;
        }
        let path_text = path.to_str().ok_or("manifest path is not UTF-8")?;
        let mode = git(source, &[], &["ls-tree", head, "--", path_text], None).await?;
        if !mode.starts_with("100644 ") && !mode.starts_with("100755 ") {
            return Err(format!("manifest is not a regular file: {requested}"));
        }
        let raw = git_bytes(source, &[], &["show", &format!("{head}:{path_text}")], None).await?;
        let (updated, name, old, new) =
            if path.file_name().and_then(|x| x.to_str()) == Some("package.json") {
                bump_package_json(&raw, bump)?
            } else if path.file_name().and_then(|x| x.to_str()) == Some("Cargo.toml") {
                bump_cargo_toml(&raw, bump)?
            } else {
                return Err(format!("unsupported release manifest: {requested}"));
            };
        let file_mode = mode
            .split_whitespace()
            .next()
            .ok_or("malformed Git tree entry")?;
        put_blob(source, &env, file_mode, path_text, &updated).await?;
        versions.insert(path_text.to_string(), json!(new));

        let lock_name = if path_text.ends_with("package.json") {
            "package-lock.json"
        } else {
            "Cargo.lock"
        };
        let lock = component.join(lock_name);
        let lock_text = lock.to_str().ok_or("lock path is not UTF-8")?;
        if tree_has(source, head, lock_text).await? {
            let lock_raw =
                git_bytes(source, &[], &["show", &format!("{head}:{lock_text}")], None).await?;
            let lock_updated = if lock_name == "package-lock.json" {
                bump_package_lock(&lock_raw, &old, &new)?
            } else {
                bump_cargo_lock(&lock_raw, &name, &old, &new)?
            };
            let lock_mode = git(source, &[], &["ls-tree", head, "--", lock_text], None).await?;
            let lock_mode = lock_mode
                .split_whitespace()
                .next()
                .ok_or("malformed lockfile tree entry")?;
            if lock_mode != "100644" && lock_mode != "100755" {
                return Err(format!("lockfile is not a regular file: {lock_text}"));
            }
            put_blob(source, &env, lock_mode, lock_text, &lock_updated).await?;
        }
    }
    if versions.is_empty() {
        return Ok(empty(head, git_ref));
    }
    let mut tags = Vec::new();
    let mut unique = HashSet::new();
    for (path, prefix) in tag_policy {
        let Some(version) = versions.get(path).and_then(Value::as_str) else {
            continue;
        };
        let tag = format!("refs/tags/{prefix}{version}");
        validate_tag_ref(&tag)?;
        if !unique.insert(tag.clone()) {
            return Err(format!("release tag collision: {tag}"));
        }
        tags.push(tag);
    }
    let tree = git(source, &env, &["write-tree"], None).await?;
    let source_date = git(source, &[], &["show", "-s", "--format=%aI", head], None).await?;
    let message = format!("chore(release): bump packages\n\nHeyo-Release-Source: {head}\n");
    let deterministic = [
        ("GIT_AUTHOR_NAME", "Heyo CI"),
        ("GIT_AUTHOR_EMAIL", "ci@heyo.computer"),
        ("GIT_COMMITTER_NAME", "Heyo CI"),
        ("GIT_COMMITTER_EMAIL", "ci@heyo.computer"),
        ("GIT_AUTHOR_DATE", source_date.trim()),
        ("GIT_COMMITTER_DATE", source_date.trim()),
    ];
    let release_sha = git(
        source,
        &deterministic,
        &["commit-tree", tree.trim(), "-p", head],
        Some(message.as_bytes()),
    )
    .await?;
    Ok(PreparedRelease {
        source_sha: head.into(),
        release_sha: release_sha.trim().into(),
        git_ref: git_ref.into(),
        versions: Value::Object(versions),
        tags,
    })
}

pub async fn publish(
    source: &Path,
    repository: &str,
    token: &str,
    base: &str,
    prepared: &PreparedRelease,
) -> Result<(), String> {
    validate_sha(base)?;
    validate_sha(&prepared.source_sha)?;
    validate_sha(&prepared.release_sha)?;
    validate_ref(&prepared.git_ref)?;
    for tag in &prepared.tags {
        validate_tag_ref(tag)?;
    }
    if prepared.tags.iter().collect::<HashSet<_>>().len() != prepared.tags.len() {
        return Err("release contains duplicate tags".into());
    }
    validate_repository(repository)?;
    if repository.starts_with("https://")
        && repository[8..]
            .split('/')
            .next()
            .is_some_and(|authority| authority.contains('@'))
    {
        return Err("repository URL must not contain embedded credentials".into());
    }
    let home = TempDir::new().map_err(|e| format!("create isolated Git home: {e}"))?;
    let home_s = home.path().to_string_lossy().into_owned();
    let mut owned = vec![
        ("HOME".to_string(), home_s.clone()),
        ("XDG_CONFIG_HOME".into(), home_s),
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
        ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
        ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        ("GCM_INTERACTIVE".into(), "Never".into()),
        (
            "GIT_CONFIG_COUNT".into(),
            if repository.starts_with("https://") {
                "3"
            } else {
                "1"
            }
            .into(),
        ),
        ("GIT_CONFIG_KEY_0".into(), "credential.helper".into()),
        ("GIT_CONFIG_VALUE_0".into(), "".into()),
    ];
    if repository.starts_with("https://") {
        let auth =
            base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
        owned.extend([
            ("GIT_CONFIG_KEY_1".into(), "protocol.ext.allow".into()),
            ("GIT_CONFIG_VALUE_1".into(), "never".into()),
            ("GIT_CONFIG_KEY_2".into(), format!("http.{repository}.extraHeader")),
            (
                "GIT_CONFIG_VALUE_2".into(),
                format!("Authorization: Basic {auth}"),
            ),
        ]);
    }
    let env: Vec<(&str, &str)> = owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    // Validate the complete candidate chain even on an idempotent retry.
    git(
        source,
        &[],
        &["merge-base", "--is-ancestor", base, &prepared.source_sha],
        None,
    )
    .await
    .map_err(|_| "release source is not descended from the validated base".to_string())?;
    if prepared.release_sha != prepared.source_sha {
        let parents = git(
            source,
            &[],
            &["show", "-s", "--format=%P", &prepared.release_sha],
            None,
        )
        .await?;
        if parents.split_whitespace().collect::<Vec<_>>() != [prepared.source_sha.as_str()] {
            return Err(
                "release candidate must have exactly the validated source as parent".into(),
            );
        }
    }
    let mut requested_refs = vec![prepared.git_ref.as_str()];
    requested_refs.extend(prepared.tags.iter().map(String::as_str));
    let mut ls_args = vec!["ls-remote", "--refs", repository];
    ls_args.extend(requested_refs.iter().copied());
    let remote = git(
        source,
        &env,
        &ls_args,
        None,
    )
    .await
    .map_err(|e| redact_git_error(e, token))?;
    let refs = parse_remote_refs(&remote);
    let remote_sha = refs.get(&prepared.git_ref).ok_or("remote release ref does not exist")?;
    if *remote_sha != base && *remote_sha != prepared.release_sha {
        return Err("remote release ref moved from the validated base".into());
    }
    for tag in &prepared.tags {
        if refs.get(tag).is_some_and(|sha| *sha != prepared.release_sha) {
            return Err(format!("release tag already exists at another commit: {tag}"));
        }
    }
    if *remote_sha == prepared.release_sha
        && prepared.tags.iter().all(|tag| refs.get(tag) == Some(&prepared.release_sha))
    {
        return Ok(());
    }
    let mut push_args = vec!["push".to_string(), "--no-verify".into(), "--porcelain".into(), "--atomic".into()];
    push_args.push(format!("--force-with-lease={}:{}", prepared.git_ref, remote_sha));
    for tag in &prepared.tags {
        if !refs.contains_key(tag) {
            push_args.push(format!("--force-with-lease={tag}:"));
        }
    }
    push_args.push(repository.into());
    if *remote_sha != prepared.release_sha {
        push_args.push(format!("{}:{}", prepared.release_sha, prepared.git_ref));
    }
    for tag in &prepared.tags {
        if !refs.contains_key(tag) {
            push_args.push(format!("{}:{tag}", prepared.release_sha));
        }
    }
    let push_refs: Vec<&str> = push_args.iter().map(String::as_str).collect();
    if git(
        source,
        &env,
        &push_refs,
        None,
    )
    .await
    .map_err(|e| redact_git_error(e, token))
    .is_ok()
    {
        return Ok(());
    }
    // A transport failure may have lost the acknowledgement. Never regenerate or replay.
    let after = git(
        source,
        &env,
        &ls_args,
        None,
    )
    .await
    .map_err(|e| redact_git_error(e, token))?;
    let after = parse_remote_refs(&after);
    if after.get(&prepared.git_ref) == Some(&prepared.release_sha)
        && prepared.tags.iter().all(|tag| after.get(tag) == Some(&prepared.release_sha))
    {
        Ok(())
    } else {
        Err("exact-base release push failed and the remote does not contain the candidate".into())
    }
}

fn empty(head: &str, git_ref: &str) -> PreparedRelease {
    PreparedRelease {
        source_sha: head.into(),
        release_sha: head.into(),
        git_ref: git_ref.into(),
        versions: json!({}),
        tags: vec![],
    }
}

#[derive(Clone, Copy)]
enum Bump {
    Major,
    Minor,
    Patch,
}
fn bump_kind(messages: &str) -> Bump {
    let commits = messages
        .split('\0')
        .filter(|message| !message.trim().is_empty());
    let mut minor = false;
    for message in commits {
        let mut lines = message.lines();
        let subject = lines.next().unwrap_or_default().trim();
        let conventional_prefix = conventional_prefix(subject);
        if conventional_prefix.is_some_and(|prefix| prefix.ends_with('!'))
            || lines.any(|line| {
                let line = line.trim_start();
                line.starts_with("BREAKING CHANGE:") || line.starts_with("BREAKING-CHANGE:")
            })
        {
            return Bump::Major;
        }
        minor |= conventional_prefix
            .and_then(|prefix| prefix.strip_suffix('!').or(Some(prefix)))
            .is_some_and(|prefix| prefix == "feat" || prefix.starts_with("feat("));
    }
    if minor { Bump::Minor } else { Bump::Patch }
}
fn conventional_prefix(subject: &str) -> Option<&str> {
    let (prefix, description) = subject.split_once(": ")?;
    if description.is_empty() {
        return None;
    }
    let core = prefix.strip_suffix('!').unwrap_or(prefix);
    let valid = if let Some((kind, scope)) = core.split_once('(') {
        !kind.is_empty()
            && kind.bytes().all(|b| b.is_ascii_lowercase())
            && scope.ends_with(')')
            && scope.len() > 1
    } else {
        !core.is_empty() && core.bytes().all(|b| b.is_ascii_lowercase())
    };
    valid.then_some(prefix)
}

fn bump_version(old: &str, bump: Bump) -> Result<String, String> {
    let core = old.split(['-', '+']).next().unwrap_or_default();
    let suffix = &old[core.len()..];
    if !valid_semver_suffix(suffix) {
        return Err(format!("unsupported semantic version: {old}"));
    }
    let mut p = core.split('.').map(|x| {
        if x.len() > 1 && x.starts_with('0') {
            return Err(format!("unsupported semantic version: {old}"));
        }
        x.parse::<u64>()
            .map_err(|_| format!("unsupported semantic version: {old}"))
    });
    let (mut a, mut b, mut c) = (
        p.next().ok_or("invalid version")??,
        p.next().ok_or("invalid version")??,
        p.next().ok_or("invalid version")??,
    );
    if p.next().is_some() {
        return Err(format!("unsupported semantic version: {old}"));
    }
    match bump {
        Bump::Major => {
            a = a
                .checked_add(1)
                .ok_or_else(|| format!("semantic version overflow: {old}"))?;
            b = 0;
            c = 0
        }
        Bump::Minor => {
            b = b
                .checked_add(1)
                .ok_or_else(|| format!("semantic version overflow: {old}"))?;
            c = 0
        }
        Bump::Patch => {
            c = c
                .checked_add(1)
                .ok_or_else(|| format!("semantic version overflow: {old}"))?
        }
    }
    Ok(format!("{a}.{b}.{c}"))
}

fn valid_semver_suffix(suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    let (pre, build) = if let Some(rest) = suffix.strip_prefix('-') {
        match rest.split_once('+') {
            Some((pre, build)) => (Some(pre), Some(build)),
            None => (Some(rest), None),
        }
    } else if let Some(build) = suffix.strip_prefix('+') {
        (None, Some(build))
    } else {
        return false;
    };
    let identifiers_valid = pre.into_iter().chain(build).all(|part| {
        !part.is_empty()
            && part.split('.').all(|identifier| {
                !identifier.is_empty()
                    && identifier
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
    });
    let prerelease_numbers_valid = pre.is_none_or(|part| {
        part.split('.').all(|identifier| {
            !identifier.bytes().all(|b| b.is_ascii_digit())
                || identifier.len() == 1
                || !identifier.starts_with('0')
        })
    });
    identifiers_valid && prerelease_numbers_valid
}

fn bump_package_json(raw: &[u8], bump: Bump) -> Result<(Vec<u8>, String, String, String), String> {
    let mut doc: Value =
        serde_json::from_slice(raw).map_err(|e| format!("invalid package.json: {e}"))?;
    let obj = doc
        .as_object_mut()
        .ok_or("package.json root is not an object")?;
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .ok_or("package.json has no string name")?
        .to_string();
    let old = obj
        .get("version")
        .and_then(Value::as_str)
        .ok_or("package.json has no string version")?
        .to_string();
    let new = bump_version(&old, bump)?;
    obj.insert("version".into(), json!(new));
    let mut out = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
    out.push(b'\n');
    Ok((out, name, old, new))
}
fn bump_cargo_toml(raw: &[u8], bump: Bump) -> Result<(Vec<u8>, String, String, String), String> {
    let text = std::str::from_utf8(raw).map_err(|_| "Cargo.toml is not UTF-8")?;
    let mut doc = text
        .parse::<DocumentMut>()
        .map_err(|e| format!("invalid Cargo.toml: {e}"))?;
    let package = doc
        .get_mut("package")
        .and_then(|x| x.as_table_like_mut())
        .ok_or("Cargo.toml has no [package]")?;
    let name = package
        .get("name")
        .and_then(|x| x.as_str())
        .ok_or("Cargo package has no name")?
        .to_string();
    let old = package
        .get("version")
        .and_then(|x| x.as_str())
        .ok_or("inherited/non-string Cargo versions are unsupported")?
        .to_string();
    let new = bump_version(&old, bump)?;
    package.insert("version", value(&new));
    Ok((doc.to_string().into_bytes(), name, old, new))
}
fn bump_package_lock(raw: &[u8], old: &str, new: &str) -> Result<Vec<u8>, String> {
    let mut d: Value =
        serde_json::from_slice(raw).map_err(|e| format!("invalid package-lock.json: {e}"))?;
    let o = d
        .as_object_mut()
        .ok_or("package lock root is not an object")?;
    let mut count = 0;
    if o.get("version").and_then(Value::as_str) == Some(old) {
        o.insert("version".into(), json!(new));
        count += 1
    }
    if let Some(root) = o
        .get_mut("packages")
        .and_then(Value::as_object_mut)
        .and_then(|p| p.get_mut(""))
        .and_then(Value::as_object_mut)
    {
        if root.get("version").and_then(Value::as_str) == Some(old) {
            root.insert("version".into(), json!(new));
            count += 1
        }
    }
    if count == 0 {
        return Err("package-lock.json has no matching root version".into());
    }
    let mut out = serde_json::to_vec_pretty(&d).map_err(|e| e.to_string())?;
    out.push(b'\n');
    Ok(out)
}
fn bump_cargo_lock(raw: &[u8], name: &str, old: &str, new: &str) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "Cargo.lock is not UTF-8")?;
    let mut d = text
        .parse::<DocumentMut>()
        .map_err(|e| format!("invalid Cargo.lock: {e}"))?;
    let arr = d
        .get_mut("package")
        .and_then(|x| x.as_array_of_tables_mut())
        .ok_or("Cargo.lock lacks [[package]]")?;
    let mut n = 0;
    for p in arr.iter_mut() {
        if p.get("name").and_then(|x| x.as_str()) == Some(name)
            && p.get("version").and_then(|x| x.as_str()) == Some(old)
        {
            p.insert("version", value(new));
            n += 1
        }
    }
    if n != 1 {
        return Err(format!(
            "Cargo.lock must contain exactly one matching root package; found {n}"
        ));
    }
    Ok(d.to_string().into_bytes())
}

fn safe_manifest(source: &Path, requested: &str) -> Result<PathBuf, String> {
    let p = Path::new(requested);
    if p.is_absolute() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(format!("unsafe manifest path: {requested}"));
    }
    if !matches!(
        p.file_name().and_then(|x| x.to_str()),
        Some("package.json" | "Cargo.toml")
    ) {
        return Err(format!("unsupported release manifest: {requested}"));
    }
    let mut cur = source.to_path_buf();
    for c in p.components() {
        if let Component::Normal(x) = c {
            cur.push(x);
            if std::fs::symlink_metadata(&cur).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(format!("manifest path traverses a symlink: {requested}"));
            }
        }
    }
    Ok(p.to_path_buf())
}
fn validate_sha(s: &str) -> Result<(), String> {
    if s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("revision must be a full 40-character hexadecimal SHA".into())
    }
}
fn validate_ref(s: &str) -> Result<(), String> {
    if s.starts_with("refs/heads/")
        && !s.contains("..")
        && !s.bytes().any(|b| {
            b <= b' '
                || b == b'~'
                || b == b'^'
                || b == b':'
                || b == b'?'
                || b == b'*'
                || b == b'['
                || b == b'\\'
        })
    {
        Ok(())
    } else {
        Err("release ref must be a valid full refs/heads/... ref".into())
    }
}

fn validate_tag_ref(s: &str) -> Result<(), String> {
    let name = s.strip_prefix("refs/tags/").ok_or("release tag must be a full refs/tags/... ref")?;
    if name.is_empty() || name.ends_with(['.', '/']) || name.contains("..") || name.contains("@{")
        || name.split('/').any(|part| part.is_empty() || part.starts_with('.') || part.ends_with(".lock"))
        || name.bytes().any(|b| b <= b' ' || matches!(b, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\'))
    {
        Err("release tag is not a valid Git ref".into())
    } else {
        Ok(())
    }
}

fn parse_remote_refs(output: &str) -> HashMap<String, String> {
    output.lines().filter_map(|line| {
        let (sha, name) = line.split_once('\t')?;
        Some((name.to_string(), sha.to_string()))
    }).collect()
}

fn validate_repository(repository: &str) -> Result<(), String> {
    #[cfg(test)]
    if Path::new(repository).is_absolute() {
        return Ok(());
    }
    let url = reqwest::Url::parse(repository)
        .map_err(|_| "repository must be a valid HTTPS URL".to_string())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("repository must be HTTPS without credentials, query, or fragment".into());
    }
    Ok(())
}

fn redact_git_error(error: String, token: &str) -> String {
    if token.is_empty() {
        error
    } else {
        let auth =
            base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
        error
            .replace(token, "[REDACTED]")
            .replace(&auth, "[REDACTED]")
    }
}
async fn tree_has(source: &Path, rev: &str, path: &str) -> Result<bool, String> {
    Ok(git(
        source,
        &[],
        &["cat-file", "-e", &format!("{rev}:{path}")],
        None,
    )
    .await
    .is_ok())
}
async fn put_blob(
    source: &Path,
    env: &[(&str, &str)],
    mode: &str,
    path: &str,
    data: &[u8],
) -> Result<(), String> {
    let oid = git(source, &[], &["hash-object", "-w", "--stdin"], Some(data)).await?;
    git(
        source,
        env,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            mode,
            oid.trim(),
            path,
        ],
        None,
    )
    .await?;
    Ok(())
}
async fn git(
    source: &Path,
    env: &[(&str, &str)],
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<String, String> {
    String::from_utf8(git_bytes(source, env, args, stdin).await?)
        .map_err(|_| "Git returned non-UTF-8 output".into())
}
async fn git_bytes(
    source: &Path,
    env: &[(&str, &str)],
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let mut c = Command::new("git");
    c.current_dir(source)
        .args(args)
        .envs(env.iter().copied())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = c.spawn().map_err(|e| format!("start Git: {e}"))?;
    if let Some(data) = stdin {
        child
            .stdin
            .take()
            .ok_or("open Git stdin")?
            .write_all(data)
            .await
            .map_err(|e| format!("write Git stdin: {e}"))?
    }
    let out = timeout(GIT_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| "Git command timed out".to_string())?
        .map_err(|e| format!("wait for Git: {e}"))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(format!("Git command failed: {}", stderr.trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command as SyncCommand;

    #[tokio::test]
    async fn service_inputs_ignore_unrelated_changes_but_include_shared_inputs_and_definition() {
        let repo = TempDir::new().unwrap();
        run(repo.path(), &["init", "-b", "main"]);
        let definition = "on:\n  submit:\n    paths: ['api/**', 'shared/**']\njobs:\n  build:\n    steps:\n      - run: echo build\n";
        fs::write(repo.path().join("api.yml"), definition).unwrap();
        fs::create_dir(repo.path().join("api")).unwrap();
        fs::create_dir(repo.path().join("shared")).unwrap();
        fs::write(repo.path().join("api/code"), "api").unwrap();
        fs::write(repo.path().join("shared/code"), "shared").unwrap();
        commit(repo.path(), "initial");
        let paths = vec!["api.yml".into()];
        let load = || build_source_scoped(repo.path().to_str().unwrap(), "refs/heads/main", None, &paths, "", 10000);
        let (original, identity, message) = load().await.unwrap();
        assert_eq!(message, "initial");
        fs::write(repo.path().join("worker"), "unrelated service").unwrap();
        commit(repo.path(), "worker only");
        let (unrelated, unchanged, message) = load().await.unwrap();
        assert_eq!(message, "worker only");
        let (_, _, original_message) = build_source_scoped(repo.path().to_str().unwrap(), "refs/heads/main", Some(&original.base_revision), &paths, "", 10000).await.unwrap();
        assert_eq!(original_message, "initial");
        assert_ne!(original.base_revision, unrelated.base_revision);
        assert_eq!(identity, unchanged);
        fs::write(repo.path().join("shared/code"), "new shared dependency").unwrap();
        commit(repo.path(), "shared dependency");
        let (_, shared, _) = load().await.unwrap();
        assert_ne!(identity, shared);
        fs::write(repo.path().join("api.yml"), format!("{definition}# new definition\n")).unwrap();
        commit(repo.path(), "definition");
        let (_, changed_definition, _) = load().await.unwrap();
        assert_ne!(shared, changed_definition);
        fs::remove_file(repo.path().join("api/code")).unwrap();
        commit(repo.path(), "delete input");
        assert_ne!(changed_definition, load().await.unwrap().1);
    }

    #[test]
    fn absent_or_unsupported_filters_fingerprint_the_entire_tree() {
        let before = "100644 blob aaa\tapi.yml\0";
        let after = format!("{before}100644 blob bbb\tworker/code\0");
        for header in ["on: submit", "on:\n  submit:\n    paths: ['api/[ab]/**']", "on:\n  submit:\n    paths: ['api/foo**bar']", "on:\n  submit:\n    paths-ignore: ['worker/**']"] {
            let workflows = BTreeMap::from([("api.yml".into(), format!("{header}\njobs:\n  build:\n    steps:\n      - run: echo ok\n"))]);
            assert_ne!(input_identity(&workflows, before), input_identity(&workflows, &after), "{header}");
        }
    }

    fn run(at: &Path, args: &[&str]) -> String {
        let out = SyncCommand::new("git")
            .current_dir(at)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }
    fn commit(repo: &Path, message: &str) -> String {
        run(repo, &["add", "."]);
        run(
            repo,
            &[
                "-c",
                "user.name=T",
                "-c",
                "user.email=t@example.test",
                "commit",
                "-m",
                message,
            ],
        );
        run(repo, &["rev-parse", "HEAD"])
    }

    #[tokio::test]
    async fn release_build_freezes_merged_cutoff_not_unmerged_branch_or_new_tip() {
        let repo = TempDir::new().unwrap();
        run(repo.path(), &["init", "-b", "main"]);
        fs::write(repo.path().join("build.yml"), "old definition\n").unwrap();
        let old = commit(repo.path(), "initial");
        run(repo.path(), &["checkout", "-b", "unmerged"]);
        fs::write(repo.path().join("build.yml"), "unmerged definition\n").unwrap();
        let unmerged = commit(repo.path(), "unmerged");
        run(repo.path(), &["checkout", "main"]);
        fs::write(repo.path().join("build.yml"), "new definition\n").unwrap();
        let new = commit(repo.path(), "new main");
        let paths = vec!["build.yml".into()];
        let pinned = build_source(repo.path().to_str().unwrap(), "refs/heads/main", Some(&old), &paths, "", 1000).await.unwrap();
        assert_eq!(pinned.base_revision, old);
        assert_eq!(pinned.workflows["build.yml"], "old definition\n");
        assert_eq!(pinned.target_tree, run(repo.path(), &["rev-parse", &format!("{old}^{{tree}}") ]));
        assert!(pinned.patch().unwrap().is_empty());
        let latest = build_source(repo.path().to_str().unwrap(), "refs/heads/main", None, &paths, "", 1000).await.unwrap();
        assert_eq!(latest.base_revision, new);
        assert_eq!(latest.workflows["build.yml"], "new definition\n");
        assert!(build_source(repo.path().to_str().unwrap(), "refs/heads/main", Some(&unmerged), &paths, "", 1000).await.is_err());
        assert!(build_source(repo.path().to_str().unwrap(), "refs/heads/main", None, &paths, "", 3).await.is_err());
        assert_eq!(run(repo.path(), &["rev-parse", "HEAD"]), new, "reading must never publish or modify the branch");
    }

    #[tokio::test]
    async fn prepares_and_publishes_exact_candidate() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("work");
        fs::create_dir(&repo).unwrap();
        run(&repo, &["init", "-b", "main"]);
        fs::create_dir(repo.join("app")).unwrap();
        fs::write(
            repo.join("app/package.json"),
            "{\n  \"name\": \"app\",\n  \"version\": \"1.2.3\",\n  \"private\": true\n}\n",
        )
        .unwrap();
        fs::write(repo.join("app/package-lock.json"), "{\"name\":\"app\",\"version\":\"1.2.3\",\"lockfileVersion\":3,\"packages\":{\"\":{\"name\":\"app\",\"version\":\"1.2.3\"}}}\n").unwrap();
        fs::create_dir(repo.join("worker")).unwrap();
        fs::write(repo.join("worker/Cargo.toml"), "[package]\nname = \"worker\"\nversion = \"4.5.6\"\n").unwrap();
        fs::write(repo.join("README"), "unchanged\n").unwrap();
        let base = commit(&repo, "initial");
        fs::write(repo.join("app/code.js"), "feature\n").unwrap();
        fs::write(repo.join("worker/code.rs"), "feature\n").unwrap();
        let head = commit(&repo, "feat(app): useful");
        let manifests = vec!["app/package.json".to_string(), "worker/Cargo.toml".to_string()];
        let tags = BTreeMap::from([
            ("app/package.json".into(), "app-v".into()),
            ("worker/Cargo.toml".into(), "worker-v".into()),
        ]);
        let first = prepare(&repo, &base, &head, "refs/heads/main", &manifests, &tags)
            .await
            .unwrap();
        let second = prepare(&repo, &base, &head, "refs/heads/main", &manifests, &tags)
            .await
            .unwrap();
        assert_eq!(first, second, "release object must be deterministic");
        assert_eq!(first.versions["app/package.json"], "1.3.0");
        assert_eq!(first.versions["worker/Cargo.toml"], "4.6.0");
        assert_eq!(first.tags, ["refs/tags/app-v1.3.0", "refs/tags/worker-v4.6.0"]);
        assert_eq!(
            run(&repo, &["diff", "--name-only", &head, &first.release_sha]),
            "app/package-lock.json\napp/package.json\nworker/Cargo.toml"
        );
        assert_eq!(
            run(&repo, &["show", "-s", "--format=%P", &first.release_sha]),
            head
        );
        assert_eq!(run(&repo, &["status", "--porcelain"]), "");
        assert!(
            fs::read_to_string(repo.join("app/package.json"))
                .unwrap()
                .contains("\"version\": \"1.2.3\"")
        );

        let bare = temp.path().join("remote.git");
        run(temp.path(), &["init", "--bare", bare.to_str().unwrap()]);
        run(
            &repo,
            &[
                "push",
                bare.to_str().unwrap(),
                &format!("{base}:refs/heads/main"),
            ],
        );
        run(&repo, &["branch", "feature", &head]);
        run(
            &repo,
            &[
                "push",
                bare.to_str().unwrap(),
                &format!("{head}:refs/heads/feature"),
            ],
        );
        publish(&repo, bare.to_str().unwrap(), "unused", &base, &first)
            .await
            .unwrap();
        assert_eq!(
            run(
                &repo,
                &["ls-remote", bare.to_str().unwrap(), "refs/heads/main"]
            )
            .split_whitespace()
            .next(),
            Some(first.release_sha.as_str())
        );
        assert_eq!(
            run(
                &repo,
                &["ls-remote", bare.to_str().unwrap(), "refs/heads/feature"]
            )
            .split_whitespace()
            .next(),
            Some(head.as_str()),
            "publishing the release must not move the submitted feature branch"
        );
        for tag in &first.tags {
            assert_eq!(run(&repo, &["--git-dir", bare.to_str().unwrap(), "rev-parse", tag]), first.release_sha);
        }
        // Published retry is idempotent and cannot double-bump.
        publish(&repo, bare.to_str().unwrap(), "unused", &base, &first)
            .await
            .unwrap();
        // Reconcile the exact persisted candidate rather than treating branch-only
        // publication as success or preparing another version bump.
        run(&repo, &["push", bare.to_str().unwrap(), &format!(":{}", first.tags[0])]);
        publish(&repo, bare.to_str().unwrap(), "unused", &base, &first)
            .await
            .unwrap();
        assert_eq!(
            run(&repo, &["--git-dir", bare.to_str().unwrap(), "rev-parse", &first.tags[0]]),
            first.release_sha
        );

        run(
            &repo,
            &[
                "push",
                bare.to_str().unwrap(),
                &format!("{head}:refs/heads/stale"),
            ],
        );
        let mut stale = first.clone();
        stale.git_ref = "refs/heads/stale".into();
        assert!(
            publish(&repo, bare.to_str().unwrap(), "unused", &base, &stale)
                .await
                .unwrap_err()
                .contains("moved")
        );

        assert!(
            prepare(
                &repo,
                &base,
                &head,
                "refs/heads/main",
                &["../package.json".into()],
                &BTreeMap::new()
            )
            .await
            .unwrap_err()
            .contains("unsafe")
        );
    }

    #[tokio::test]
    async fn tag_collision_prevents_atomic_branch_movement() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("work");
        fs::create_dir(&repo).unwrap();
        run(&repo, &["init", "-b", "main"]);
        fs::write(repo.join("package.json"), r#"{"name":"app","version":"1.0.0"}"#).unwrap();
        let base = commit(&repo, "initial");
        fs::write(repo.join("code"), "new").unwrap();
        let head = commit(&repo, "fix: change");
        let prepared = prepare(
            &repo, &base, &head, "refs/heads/main", &["package.json".into()],
            &BTreeMap::from([("package.json".into(), "app-v".into())]),
        ).await.unwrap();
        let bare = temp.path().join("remote.git");
        run(temp.path(), &["init", "--bare", bare.to_str().unwrap()]);
        run(&repo, &["push", bare.to_str().unwrap(), &format!("{base}:refs/heads/main")]);
        run(&repo, &["push", bare.to_str().unwrap(), &format!("{head}:{}", prepared.tags[0])]);
        assert!(publish(&repo, bare.to_str().unwrap(), "unused", &base, &prepared).await.unwrap_err().contains("already exists"));
        assert_eq!(run(&repo, &["--git-dir", bare.to_str().unwrap(), "rev-parse", "refs/heads/main"]), base);
    }

    #[tokio::test]
    async fn no_bump_fast_forwards_but_rejects_a_stale_remote() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("work");
        fs::create_dir(&repo).unwrap();
        run(&repo, &["init", "-b", "main"]);
        fs::write(repo.join("README"), "base\n").unwrap();
        let base = commit(&repo, "initial");
        fs::write(repo.join("README"), "head\n").unwrap();
        let head = commit(&repo, "fix: docs");
        let prepared = prepare(&repo, &base, &head, "refs/heads/main", &[], &BTreeMap::new())
            .await
            .unwrap();
        assert_eq!(prepared.release_sha, head);

        let bare = temp.path().join("remote.git");
        run(temp.path(), &["init", "--bare", bare.to_str().unwrap()]);
        run(
            &repo,
            &[
                "push",
                bare.to_str().unwrap(),
                &format!("{base}:refs/heads/main"),
            ],
        );
        publish(&repo, bare.to_str().unwrap(), "unused", &base, &prepared)
            .await
            .unwrap();
        publish(&repo, bare.to_str().unwrap(), "unused", &base, &prepared)
            .await
            .unwrap();
        assert_eq!(
            run(
                &repo,
                &["ls-remote", bare.to_str().unwrap(), "refs/heads/main"]
            )
            .split_whitespace()
            .next(),
            Some(head.as_str())
        );

        run(
            &repo,
            &[
                "push",
                bare.to_str().unwrap(),
                &format!("{base}:refs/heads/stale"),
            ],
        );
        let mut stale = prepared.clone();
        stale.git_ref = "refs/heads/stale".into();
        fs::write(repo.join("README"), "concurrent trunk update\n").unwrap();
        let advanced = commit(&repo, "fix: concurrent update");
        run(
            &repo,
            &[
                "push",
                bare.to_str().unwrap(),
                &format!("{advanced}:refs/heads/stale"),
            ],
        );
        assert!(
            publish(&repo, bare.to_str().unwrap(), "unused", &base, &stale)
                .await
                .unwrap_err()
                .contains("moved")
        );
        assert_eq!(run(&repo, &["status", "--porcelain"]), "");
    }

    #[test]
    fn conventional_messages_and_version_policy() {
        assert!(matches!(
            bump_kind("fix: mention feat: only in body\n\nfeat: not a subject\0"),
            Bump::Patch
        ));
        assert!(matches!(
            bump_kind("feat(api): add endpoint\n\0fix: follow-up\n\0"),
            Bump::Minor
        ));
        assert!(matches!(
            bump_kind("fix: migrate\n\nBREAKING CHANGE: schema changed\n\0"),
            Bump::Major
        ));
        assert!(matches!(bump_kind("feat!: replace API\n\0"), Bump::Major));
        assert_eq!(
            bump_version("1.2.3-beta.1+build-7", Bump::Minor).unwrap(),
            "1.3.0"
        );
        assert_eq!(bump_version("1.2.3+build.7", Bump::Patch).unwrap(), "1.2.4");
        assert!(bump_version("1.2.3-", Bump::Patch).is_err());
        assert!(bump_version("01.2.3", Bump::Patch).is_err());
        assert!(bump_version(&format!("{}.0.0", u64::MAX), Bump::Major).is_err());
    }
}
