//! Working with deployment specs as JSON.
//!
//! The admin API's `PUT /deployments/:id` replaces the *whole* spec, so every
//! in-place change here is a read-modify-write: fetch the live spec, edit the
//! `Value`, put it back. Editing the `Value` (rather than a typed struct) is
//! what makes that safe — a field this CLI has never heard of survives the trip.

use crate::error::{Error, Result};
#[cfg(feature = "cli")]
use serde::Deserialize;
use serde_json::{Map, Value};
#[cfg(feature = "cli")]
use std::path::Path;

/// A local stand-in for `anyhow::Context`.
///
/// This module moved out of the CLI, where every fallible call ended in
/// `.context("…")`. A library cannot return `anyhow::Error`, but the *messages*
/// were the useful part — so the trait comes along and only the error type
/// underneath changed.
trait Context<T> {
    fn context(self, msg: impl std::fmt::Display) -> Result<T>;
    fn with_context<S: std::fmt::Display>(self, f: impl FnOnce() -> S) -> Result<T>;
}

impl<T, E: std::fmt::Display> Context<T> for std::result::Result<T, E> {
    fn context(self, msg: impl std::fmt::Display) -> Result<T> {
        self.map_err(|e| Error::Invalid(format!("{msg}: {e}")))
    }
    fn with_context<S: std::fmt::Display>(self, f: impl FnOnce() -> S) -> Result<T> {
        self.map_err(|e| Error::Invalid(format!("{}: {e}", f())))
    }
}

impl<T> Context<T> for Option<T> {
    fn context(self, msg: impl std::fmt::Display) -> Result<T> {
        self.ok_or_else(|| Error::Invalid(msg.to_string()))
    }
    fn with_context<S: std::fmt::Display>(self, f: impl FnOnce() -> S) -> Result<T> {
        self.ok_or_else(|| Error::Invalid(f().to_string()))
    }
}

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::error::Error::Invalid(format!($($arg)*)))
    };
}

/// One `--env` argument: `KEY=VALUE` to set, `KEY-` to remove (kubectl's syntax
/// for `set env`).
#[derive(Debug, PartialEq, Eq)]
pub enum EnvChange {
    Set(String, String),
    Remove(String),
}

pub fn parse_env(arg: &str) -> Result<EnvChange> {
    if let Some((key, value)) = arg.split_once('=') {
        if key.is_empty() {
            bail!("{arg:?} has an empty variable name");
        }
        return Ok(EnvChange::Set(key.to_string(), value.to_string()));
    }
    if let Some(key) = arg.strip_suffix('-')
        && !key.is_empty()
    {
        return Ok(EnvChange::Remove(key.to_string()));
    }
    bail!("{arg:?} is not KEY=VALUE (to set) or KEY- (to remove)")
}

/// One `--route` argument.
///
/// Either a comma-separated key list — `host=a.example.com,path=/api` — or a
/// bare value whose shape says what it is: a leading `/` is a path prefix, a
/// leading `*.` or `.` is a subdomain match, anything else an exact host.
/// `redirect=URL` (with `status=` and `keep-path=false`) makes the rule answer
/// with a redirect instead of serving.
pub fn parse_route(arg: &str) -> Result<Value> {
    let mut rule = Map::new();
    for part in arg.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = match part.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None if part.starts_with('/') => ("path", part),
            None if part.starts_with("*.") => ("suffix", part.trim_start_matches("*.")),
            None if part.starts_with('.') => ("suffix", part),
            None => ("host", part),
        };
        if value.is_empty() {
            bail!("route {arg:?} has an empty value for {key:?}");
        }
        let field = match key {
            "redirect" | "redirect-to" | "to" => {
                redirect_mut(&mut rule).insert("to".into(), Value::String(value.to_string()));
                continue;
            }
            "status" | "redirect-status" => {
                let Ok(status) = value.parse::<u16>() else {
                    bail!("route {arg:?}: status {value:?} is not a number");
                };
                redirect_mut(&mut rule).insert("status".into(), Value::from(status));
                continue;
            }
            "keep-path" | "keep_path" => {
                let Ok(keep) = value.parse::<bool>() else {
                    bail!("route {arg:?}: keep-path is true or false");
                };
                redirect_mut(&mut rule).insert("keep_path".into(), Value::Bool(keep));
                continue;
            }
            "host" => "host",
            "suffix" | "host-suffix" | "host_suffix" | "wildcard" => "host_suffix",
            "path" | "path-prefix" | "path_prefix" | "prefix" => "path_prefix",
            other => bail!(
                "unknown route key {other:?} in {arg:?} — expected host=, suffix=, path= or redirect="
            ),
        };
        // `host_suffix` accepts a leading dot server-side and ignores it; strip
        // the `*.` form here so both spellings land on the same value.
        let value = if field == "host_suffix" {
            value.trim_start_matches("*.")
        } else {
            value
        };
        rule.insert(field.to_string(), Value::String(value.to_string()));
    }
    if let Some(redirect) = rule.get("redirect")
        && redirect.get("to").is_none()
    {
        bail!("route {arg:?} sets status= or keep-path= without redirect=URL");
    }
    if rule.keys().all(|k| k == "redirect") {
        bail!("route {arg:?} is empty");
    }
    if rule.contains_key("host") && rule.contains_key("host_suffix") {
        bail!("route {arg:?} sets both host= and suffix=; a rule needs one or the other");
    }
    Ok(Value::Object(rule))
}

fn redirect_mut(rule: &mut Map<String, Value>) -> &mut Map<String, Value> {
    rule.entry("redirect")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("redirect is only ever inserted as an object")
}

/// Build a route rule from the shorthand flags. All of them describe a *single*
/// rule together, which is what makes `--host x --path-prefix /api` mean "that
/// host under that path" rather than two independent rules.
pub fn route_from_parts(
    host: Option<&str>,
    host_suffix: Option<&str>,
    path_prefix: Option<&str>,
) -> Option<Value> {
    let mut rule = Map::new();
    if let Some(h) = host {
        rule.insert("host".into(), Value::String(h.to_string()));
    }
    if let Some(s) = host_suffix {
        rule.insert(
            "host_suffix".into(),
            Value::String(s.trim_start_matches("*.").to_string()),
        );
    }
    if let Some(p) = path_prefix {
        rule.insert("path_prefix".into(), Value::String(p.to_string()));
    }
    (!rule.is_empty()).then_some(Value::Object(rule))
}

/// Read specs from a file (or `-` for stdin).
///
/// Behind `cli` because it is a file-and-terminal concern, and because YAML
/// support is the only reason this crate would link a YAML parser at all.
#[cfg(feature = "cli")]
///
/// Accepts JSON or YAML, a single document or many: a JSON array, a multi-doc
/// YAML stream, or one object. A `GET /deployments` response is unwrapped too,
/// so `heyctl get deployment web -o json | heyctl apply -f -` round-trips.
pub fn read_specs(path: &Path) -> Result<Vec<Value>> {
    let text = if path == Path::new("-") {
        std::io::read_to_string(std::io::stdin())
            .context("reading a spec from stdin")?
    } else {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?
    };
    if text.trim().is_empty() {
        bail!("{} is empty", display_path(path));
    }

    let docs: Vec<Value> = match serde_json::from_str::<Value>(&text) {
        Ok(v) => vec![v],
        // Not JSON: try YAML, which may hold several `---`-separated documents.
        Err(json_err) => {
            let mut docs = Vec::new();
            for doc in serde_yaml::Deserializer::from_str(&text) {
                let v = Value::deserialize(doc).map_err(|yaml_err| {
                    Error::Invalid(format!(
                        "{} is neither JSON ({json_err}) nor YAML ({yaml_err})",
                        display_path(path)
                    ))
                })?;
                docs.push(v);
            }
            docs
        }
    };

    let mut specs = Vec::new();
    for doc in docs {
        match doc {
            Value::Array(items) => specs.extend(items.into_iter().map(unwrap_envelope)),
            Value::Null => {} // an empty YAML document, e.g. a trailing `---`
            other => specs.push(unwrap_envelope(other)),
        }
    }
    if specs.is_empty() {
        bail!("{} contained no deployment specs", display_path(path));
    }
    for spec in &specs {
        if !spec.is_object() {
            bail!("{} contains a {} where a deployment spec was expected", display_path(path), kind_of(spec));
        }
    }
    Ok(specs)
}

#[cfg(feature = "cli")]
fn display_path(path: &Path) -> String {
    if path == Path::new("-") {
        "stdin".into()
    } else {
        path.display().to_string()
    }
}

#[cfg(feature = "cli")]
fn kind_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "list",
        Value::Object(_) => "object",
    }
}

/// A `GET /deployments` entry wraps the spec in status fields; a spec file does
/// not. Accept both by unwrapping the envelope when we see one.
#[cfg(feature = "cli")]
fn unwrap_envelope(v: Value) -> Value {
    match &v {
        Value::Object(map) if map.contains_key("spec") && map.contains_key("kind") => {
            map.get("spec").cloned().unwrap_or(v)
        }
        _ => v,
    }
}

/// Pull the spec out of a `GET /deployments/:id` response.
pub fn spec_of(deployment: &Value) -> Result<Value> {
    deployment
        .get("spec")
        .cloned()
        .context("the server's deployment response had no `spec` field")
}

pub fn spec_id(spec: &Value) -> Option<&str> {
    spec.get("id")?.as_str()
}

pub fn is_static(spec: &Value) -> bool {
    spec.get("upstreams")
        .and_then(Value::as_array)
        .is_some_and(|u| !u.is_empty())
        || spec.get("discovery").is_some_and(|value| !value.is_null())
}

/// Serves files off disk. Neither `vm` nor `upstreams` applies.
pub fn is_site(spec: &Value) -> bool {
    spec.get("site").is_some_and(|s| !s.is_null())
}

/// The `vm` block of a managed deployment, for editing.
pub fn vm_mut<'a>(spec: &'a mut Value, id: &str) -> Result<&'a mut Map<String, Value>> {
    if is_site(spec) {
        bail!(
            "deployment {id:?} is a static site and has no VM template — it serves \
             files off disk. Edit its `site` block with `heyctl edit deployment {id}`."
        );
    }
    if is_static(spec) {
        bail!(
            "deployment {id:?} is static (proxy_pass) and has no VM template — \
             change where it points with `heyctl set upstreams {id} <addr>...`"
        );
    }
    spec.get_mut("vm")
        .and_then(Value::as_object_mut)
        .with_context(|| format!("deployment {id:?} has no `vm` block to edit"))
}

/// Apply `KEY=VALUE` / `KEY-` changes to a managed deployment's `env_vars`.
pub fn apply_env(spec: &mut Value, id: &str, changes: &[EnvChange]) -> Result<Vec<String>> {
    let vm = vm_mut(spec, id)?;
    let env = vm
        .entry("env_vars")
        .or_insert_with(|| Value::Object(Map::new()));
    if env.is_null() {
        *env = Value::Object(Map::new());
    }
    let env = env
        .as_object_mut()
        .with_context(|| format!("deployment {id:?} has a non-object `vm.env_vars`"))?;

    let mut applied = Vec::new();
    for change in changes {
        match change {
            EnvChange::Set(k, v) => {
                env.insert(k.clone(), Value::String(v.clone()));
                applied.push(format!("{k}="));
            }
            EnvChange::Remove(k) => {
                if env.remove(k).is_none() {
                    // Not an error: `set env FOO-` is idempotent, like kubectl.
                    applied.push(format!("{k} (not set)"));
                } else {
                    applied.push(format!("{k} (removed)"));
                }
            }
        }
    }
    Ok(applied)
}

/// The `build` block, created if the deployment has none.
///
/// A static deployment is refused for the same reason the server refuses it:
/// there is no guest image to build, only upstreams somebody else runs.
pub fn build_mut<'a>(spec: &'a mut Value, id: &str) -> Result<&'a mut Map<String, Value>> {
    if is_static(spec) {
        bail!(
            "deployment {id:?} is static (proxy_pass) and has no image to build — \
             a build produces a guest rootfs, and a static deployment has no guest"
        );
    }
    let entry = spec
        .as_object_mut()
        .with_context(|| format!("deployment {id:?} spec is not an object"))?
        .entry("build")
        .or_insert_with(|| Value::Object(Map::new()));
    if entry.is_null() {
        *entry = Value::Object(Map::new());
    }
    entry
        .as_object_mut()
        .with_context(|| format!("deployment {id:?} has a non-object `build`"))
}

/// The `artifact` block of a managed deployment *or a site*, created if it has
/// none.
///
/// Refused only on a static (`upstreams`) deployment: a VM pulls a guest rootfs
/// and a site pulls a bundle to unpack into `site.root`, but what a `proxy_pass`
/// deployment forwards to is somebody else's process, with nowhere for either to
/// land. It also refuses to sit next to a `build`: app-lb rejects a spec holding
/// both, and catching it here means the error names the flag that caused it
/// instead of arriving as a validation failure on `PUT`.
///
/// The narrower rules — `grow_gb`/`image_name` are VM-only, `strip_components`
/// is site-only, and a site takes `update` or `artifact` but not both — are left
/// to app-lb, which is the authority on them and answers with a message naming
/// the field.
pub fn artifact_mut<'a>(spec: &'a mut Value, id: &str) -> Result<&'a mut Map<String, Value>> {
    if is_static(spec) {
        bail!(
            "deployment {id:?} is static (proxy_pass) and has no image to pull a rootfs \
             into — it forwards to upstreams somebody else runs"
        );
    }
    if spec.get("build").is_some_and(|b| !b.is_null()) {
        bail!(
            "deployment {id:?} already builds its image from git; a deployment cannot both \
             build and pull. Drop the build source first with \
             `heyctl set build {id} --clear`"
        );
    }
    let entry = spec
        .as_object_mut()
        .with_context(|| format!("deployment {id:?} spec is not an object"))?
        .entry("artifact")
        .or_insert_with(|| Value::Object(Map::new()));
    if entry.is_null() {
        *entry = Value::Object(Map::new());
    }
    entry
        .as_object_mut()
        .with_context(|| format!("deployment {id:?} has a non-object `artifact`"))
}

/// The `update` block of a static deployment, created if it has none.
///
/// The mirror of [`build_mut`], and refused on a managed deployment for the
/// mirror-image reason: a working directory on the app-lb host has nothing to do
/// with a microVM's rootfs.
pub fn update_mut<'a>(spec: &'a mut Value, id: &str) -> Result<&'a mut Map<String, Value>> {
    if !is_static(spec) {
        bail!(
            "deployment {id:?} is a managed VM pool, not a static (proxy_pass) one — its \
             backends are microVMs, so there is no working directory on this host to update. \
             Use `heyctl set build {id} --repo <url>` instead"
        );
    }
    let entry = spec
        .as_object_mut()
        .with_context(|| format!("deployment {id:?} spec is not an object"))?
        .entry("update")
        .or_insert_with(|| Value::Object(Map::new()));
    if entry.is_null() {
        *entry = Value::Object(Map::new());
    }
    entry
        .as_object_mut()
        .with_context(|| format!("deployment {id:?} has a non-object `update`"))
}

/// The `auth` block, created if the deployment has none.
///
/// Unlike `build` and `update` there is no backend-kind check: the gate runs in
/// the proxy, ahead of whichever backend the deployment has, so both kinds can
/// carry one.
pub fn auth_mut(spec: &mut Value) -> Result<&mut Map<String, Value>> {
    let entry = spec
        .as_object_mut()
        .context("the deployment spec is not an object")?
        .entry("auth")
        .or_insert_with(|| Value::Object(Map::new()));
    if entry.is_null() {
        *entry = Value::Object(Map::new());
    }
    entry
        .as_object_mut()
        .context("the deployment has a non-object `auth`")
}

/// One `--secret-env` argument: `NAME/KEY` (the variable is the key, upper-cased,
/// as the server defaults it) or `ENV=NAME/KEY` to name it.
pub fn parse_secret_env(arg: &str) -> Result<Value> {
    let (env, reference) = match arg.split_once('=') {
        Some((e, r)) => (Some(e.trim()), r.trim()),
        None => (None, arg.trim()),
    };
    let mut value = parse_secret_ref(reference)?;
    if reference.split_once('/').is_none() {
        bail!(
            "--secret-env {arg:?} needs a key: use NAME/KEY, or ENV=NAME/KEY to choose the \
             variable name"
        );
    }
    if let Some(env) = env {
        if env.is_empty() {
            bail!("--secret-env {arg:?} has an empty variable name");
        }
        if let Some(map) = value.as_object_mut() {
            map.insert("as".into(), Value::String(env.to_string()));
        }
    }
    Ok(value)
}

/// One `--secret` argument: `NAME` (key defaults to `token`, as the API does) or
/// `NAME/KEY`.
pub fn parse_secret_ref(arg: &str) -> Result<Value> {
    let (name, key) = match arg.split_once('/') {
        Some((n, k)) => (n.trim(), k.trim()),
        None => (arg.trim(), "token"),
    };
    if name.is_empty() {
        bail!("{arg:?} has an empty secret name — expected NAME or NAME/KEY");
    }
    if key.is_empty() {
        bail!("{arg:?} has an empty key — expected NAME or NAME/KEY");
    }
    Ok(serde_json::json!({ "secret": name, "key": key }))
}

/// Merge only the fields that were given onto a partial scaling patch. The API
/// keeps every field it isn't sent, so an empty patch is a no-op rather than a
/// reset to defaults.
pub fn scaling_patch(entries: &[(&str, Option<u64>)]) -> Map<String, Value> {
    let mut patch = Map::new();
    for (key, value) in entries {
        if let Some(v) = value {
            patch.insert((*key).to_string(), Value::from(*v));
        }
    }
    patch
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn env_arguments_set_and_remove() {
        assert_eq!(
            parse_env("RUST_LOG=debug").unwrap(),
            EnvChange::Set("RUST_LOG".into(), "debug".into())
        );
        // A value containing '=' survives: only the first one splits.
        assert_eq!(
            parse_env("URL=postgres://u:p@h/db?a=b").unwrap(),
            EnvChange::Set("URL".into(), "postgres://u:p@h/db?a=b".into())
        );
        assert_eq!(parse_env("RUST_LOG-").unwrap(), EnvChange::Remove("RUST_LOG".into()));
        // An empty value is legitimate; an empty name is not.
        assert_eq!(parse_env("EMPTY=").unwrap(), EnvChange::Set("EMPTY".into(), String::new()));
        assert!(parse_env("=x").is_err());
        assert!(parse_env("bare").is_err());
    }

    #[test]
    fn routes_parse_from_keys_and_from_shape() {
        assert_eq!(parse_route("host=a.example.com").unwrap(), json!({"host": "a.example.com"}));
        assert_eq!(parse_route("a.example.com").unwrap(), json!({"host": "a.example.com"}));
        assert_eq!(parse_route("/api").unwrap(), json!({"path_prefix": "/api"}));
        assert_eq!(
            parse_route("*.apps.example.com").unwrap(),
            json!({"host_suffix": "apps.example.com"})
        );
        assert_eq!(
            parse_route("suffix=.apps.example.com,path=/api").unwrap(),
            json!({"host_suffix": ".apps.example.com", "path_prefix": "/api"})
        );
    }

    #[test]
    fn a_route_cannot_be_both_exact_and_wildcard() {
        assert!(parse_route("host=a.example.com,suffix=example.com").is_err());
        assert!(parse_route("nope=1").is_err());
        assert_eq!(
            parse_route("host=docs.example.com,redirect=https://example.com/docs").unwrap(),
            json!({"host": "docs.example.com", "redirect": {"to": "https://example.com/docs"}})
        );
        assert_eq!(
            parse_route("old.example.com,redirect=https://example.com/,status=302,keep-path=false").unwrap(),
            json!({"host": "old.example.com", "redirect": {"to": "https://example.com/", "status": 302, "keep_path": false}})
        );
        assert!(parse_route("a.example.com,status=302").is_err());
        assert!(parse_route("redirect=https://example.com/").is_err());
    }

    #[test]
    fn shorthand_flags_make_one_combined_rule() {
        assert_eq!(
            route_from_parts(Some("a.example.com"), None, Some("/api")).unwrap(),
            json!({"host": "a.example.com", "path_prefix": "/api"})
        );
        assert!(route_from_parts(None, None, None).is_none());
    }

    #[cfg(feature = "cli")]
    #[test]
    fn a_get_response_unwraps_back_into_a_spec() {
        let envelope = json!({"spec": {"id": "web"}, "kind": "vm", "ready": 1});
        assert_eq!(unwrap_envelope(envelope), json!({"id": "web"}));
        // A bare spec is left alone.
        let bare = json!({"id": "web", "kind": "not-an-envelope-field"});
        assert_eq!(unwrap_envelope(bare.clone()), bare);
    }

    #[test]
    fn env_is_created_when_the_template_has_none() {
        let mut spec = json!({"id": "web", "vm": {"port": 8080}});
        apply_env(&mut spec, "web", &[EnvChange::Set("A".into(), "1".into())]).unwrap();
        assert_eq!(spec["vm"]["env_vars"], json!({"A": "1"}));
    }

    #[test]
    fn editing_the_vm_of_a_static_deployment_is_refused() {
        let mut spec = json!({"id": "proxy", "upstreams": ["10.0.0.9:8080"]});
        let err = vm_mut(&mut spec, "proxy").unwrap_err().to_string();
        assert!(err.contains("static"), "{err}");
    }

    #[test]
    fn a_build_block_is_created_on_a_deployment_that_has_none() {
        let mut spec = json!({"id": "web", "vm": {"port": 8080}});
        let build = build_mut(&mut spec, "web").unwrap();
        build.insert("repo".into(), json!("https://example.com/acme/web.git"));
        assert_eq!(spec["build"]["repo"], json!("https://example.com/acme/web.git"));

        // An existing block is edited in place, not replaced.
        let build = build_mut(&mut spec, "web").unwrap();
        build.insert("ref".into(), json!("main"));
        assert_eq!(spec["build"]["repo"], json!("https://example.com/acme/web.git"));
        assert_eq!(spec["build"]["ref"], json!("main"));
    }

    #[test]
    fn a_static_deployment_has_nothing_to_build() {
        let mut spec = json!({"id": "proxy", "upstreams": ["10.0.0.9:8080"]});
        let err = build_mut(&mut spec, "proxy").unwrap_err().to_string();
        assert!(err.contains("static"), "{err}");
    }

    #[test]
    fn an_update_block_is_created_on_a_static_deployment() {
        let mut spec = json!({"id": "obs", "upstreams": ["127.0.0.1:9600"]});
        let update = update_mut(&mut spec, "obs").unwrap();
        update.insert("working_dir".into(), json!("/srv/app-obs"));
        update.insert("commands".into(), json!(["git pull"]));
        assert_eq!(spec["update"]["working_dir"], json!("/srv/app-obs"));

        // Edited in place, not replaced.
        let update = update_mut(&mut spec, "obs").unwrap();
        update.insert("verify_timeout_secs".into(), json!(90));
        assert_eq!(spec["update"]["commands"], json!(["git pull"]));
    }

    /// The two update paths are exclusive, and each refusal names the other —
    /// reaching for the wrong verb is the obvious mistake.
    #[test]
    fn a_managed_deployment_has_no_working_directory_on_this_host() {
        let mut spec = json!({"id": "web", "vm": {"port": 8080}});
        let err = update_mut(&mut spec, "web").unwrap_err().to_string();
        assert!(err.contains("managed"), "{err}");
        assert!(err.contains("set build"), "{err}");

        let mut spec = json!({"id": "obs", "upstreams": ["10.0.0.9:80"]});
        let err = build_mut(&mut spec, "obs").unwrap_err().to_string();
        assert!(err.contains("static"), "{err}");
    }

    #[test]
    fn secret_env_takes_a_reference_and_an_optional_name() {
        assert_eq!(
            parse_secret_env("obs/ingest_token").unwrap(),
            json!({"secret": "obs", "key": "ingest_token"}),
            "unnamed: the server upper-cases the key"
        );
        assert_eq!(
            parse_secret_env("APP_OBS_TOKEN=obs/ingest_token").unwrap(),
            json!({"secret": "obs", "key": "ingest_token", "as": "APP_OBS_TOKEN"})
        );
        // A bare secret name is ambiguous here — unlike --secret, which defaults
        // to the `token` key, this decides a variable name too.
        assert!(parse_secret_env("obs").is_err());
        assert!(parse_secret_env("=obs/token").is_err());
    }

    #[test]
    fn a_secret_reference_defaults_to_the_token_key() {
        assert_eq!(
            parse_secret_ref("github").unwrap(),
            json!({"secret": "github", "key": "token"})
        );
        assert_eq!(
            parse_secret_ref("forge/ci_pat").unwrap(),
            json!({"secret": "forge", "key": "ci_pat"})
        );
        assert!(parse_secret_ref("/token").is_err());
        assert!(parse_secret_ref("github/").is_err());
    }

    #[test]
    fn a_scaling_patch_carries_only_what_was_asked_for() {
        let patch = scaling_patch(&[("min_replicas", Some(2)), ("max_replicas", None)]);
        assert_eq!(patch.len(), 1);
        assert_eq!(patch["min_replicas"], json!(2));
    }
}
