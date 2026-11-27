//! One-job registrations on a persistent VM. Journal intent before GitHub or
//! guest writes, and keep launch credentials in the namespace SecretStore.
use super::*;
use crate::operations::{self, OpState};
use base64::Engine as _;
use std::collections::HashMap;

#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Managed {
    pub labels: Vec<String>,
    pub runner_directory: String,
    pub user: String,
}

impl Managed {
    pub fn validate(&self) -> Result<(), String> {
        if self.labels.is_empty()
            || self.labels.len() > 100
            || self.labels.iter().any(|s| s.is_empty() || s.len() > 100)
            || !segment(&self.user)
            || self.user.starts_with('-')
            || self.user == "root"
            || !self.runner_directory.starts_with('/')
            || self.runner_directory.split('/').any(|p| p == "..")
            || !self
                .runner_directory
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"/_-.".contains(&c))
        {
            return Err("managed requires labels, a non-root user and an absolute runner_directory containing only letters, digits, /, _, -, .".into());
        }
        Ok(())
    }

    fn command(&self) -> String {
        format!(
            "sudo -u '{}' --preserve-env=HEYO_GITHUB_JIT sh -c 'cd {} && exec ./run.sh --jitconfig \"$HEYO_GITHUB_JIT\"'",
            self.user, self.runner_directory
        )
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Session {
    operation_id: String,
    sandbox_id: String,
    boot_id: String,
    created_at: u64,
    pub(super) runner_id: Option<u64>,
}

impl Session {
    pub(super) fn name(&self) -> String {
        format!("heyo-{}", self.operation_id)
    }
    fn secret(&self) -> String {
        format!("github-jit-{}", self.operation_id)
    }
}

// The lock covers the check and fork. A retried request (including after an
// app-lb restart) observes the same pid/exit files instead of launching again.
// No credential is interpolated into this script or an operation record.
fn launch_script(session: &Session, command: &str) -> String {
    let inner = format!(
        "if [ ! -f \"$D/pid\" ] && [ ! -f \"$D/exit\" ]; then {}; fi",
        operations::start_script(&session.operation_id, command, None)
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(inner);
    format!(
        "test \"$(cat /proc/sys/kernel/random/boot_id)\" = '{}' || exit 75; \
         B=/var/tmp/heyo-ops; if grep -qs ' /workspace ' /proc/mounts; then B=/workspace/.heyo/ops; fi; \
         D=\"$B/{}\"; export D; mkdir -p \"$D\" || exit 70; \
         flock -n -E 73 \"$D/launch.lock\" sh -c 'printf %s {} | base64 -d | sh'; R=$?; \
         if [ \"$R\" != 0 ] && [ \"$R\" != 73 ]; then exit \"$R\"; fi; \
         echo \"dir=$D\"; echo \"boot=$(cat /proc/sys/kernel/random/boot_id)\"",
        session.boot_id, session.operation_id, encoded
    )
}

impl GithubRunnersPlugin {
    fn save_session(&self, d: &Deployment, session: Option<Session>) -> Result<(), String> {
        d.mutate_state(|s| s.github_runner_session = session);
        self.registry
            .persist_one(&d.spec.id)
            .map_err(|_| "cannot persist managed runner session".into())
    }

    async fn github_write(
        &self,
        b: &Binding,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        let token = self
            .secrets
            .resolve(&b.token)
            .map_err(|_| "GitHub token unavailable")?;
        let mut request = self
            .http
            .request(method, format!("{}/repos/{}{path}", self.api, b.repository))
            .bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| "GitHub registration request failed")?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(Value::Null);
        }
        if !response.status().is_success() {
            return Err(format!(
                "GitHub registration returned HTTP {}",
                response.status().as_u16()
            ));
        }
        response
            .json()
            .await
            .map_err(|_| "invalid GitHub registration response".into())
    }

    async fn registration(&self, b: &Binding, session: &Session) -> Result<Option<Runner>, String> {
        let token = self
            .secrets
            .resolve(&b.token)
            .map_err(|_| "GitHub token unavailable")?;
        let rows = self
            .pages(
                &format!("/repos/{}/actions/runners", b.repository),
                "runners",
                &token,
            )
            .await?;
        let runners: Vec<Runner> =
            serde_json::from_value(json!(rows)).map_err(|_| "invalid runner response")?;
        Ok(runners.into_iter().find(|r| r.name == session.name()))
    }

    pub(super) async fn reconcile_managed(
        &self,
        ns: &str,
        b: &Binding,
        d: &Arc<Deployment>,
        runner: &Runner,
        jobs: &[Job],
    ) -> Result<bool, String> {
        let managed = b.managed.as_ref().unwrap();
        let ops = self
            .operations
            .read()
            .unwrap()
            .clone()
            .ok_or("runner operations are not ready")?;
        let mut session = d.state().github_runner_session.clone();
        if session.is_none() && !needs_runner(runner, jobs) {
            return Ok(true);
        }
        // Persist fail-awake demand before any external side effect.
        self.permission(d, 0)?;
        let backends = d.backends();
        let Some(backend) = backends.first() else {
            return Ok(false);
        };
        let _slot = backend.try_hold().ok_or("runner VM is draining")?;
        if session.is_none() {
            let boot = ops
                .vms()
                .exec(
                    &backend.sandbox_id,
                    "cat /proc/sys/kernel/random/boot_id",
                    heyo_sdk::CommandRunOptions {
                        timeout: Some(Duration::from_secs(20)),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|_| "could not read runner VM boot identity")?;
            let boot_id = boot.stdout.trim().to_owned();
            if boot.exit_code != 0
                || boot_id.len() != 36
                || !boot_id.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-')
            {
                return Err("invalid runner VM boot identity".into());
            }
            session = Some(Session {
                operation_id: operations::new_id(),
                sandbox_id: backend.sandbox_id.clone(),
                boot_id,
                created_at: now_secs(),
                runner_id: None,
            });
            self.save_session(d, session.clone())?;
        }
        let mut session = session.unwrap();
        if session.sandbox_id != backend.sandbox_id {
            return Err("managed runner VM was replaced; refusing to replay its session".into());
        }
        let command = managed.command();
        if let Some(op) = ops.get(&d.spec.id, &session.operation_id) {
            let (op, _, stale) = ops.read(&op, None, 0).await;
            if stale || !op.state.finished() {
                return Ok(false);
            }
            if let Some(r) = self.registration(b, &session).await? {
                if r.busy {
                    return Ok(false);
                }
                self.github_write(
                    b,
                    reqwest::Method::DELETE,
                    &format!("/actions/runners/{}", r.id),
                    None,
                )
                .await?;
                return Ok(false); // Confirm absence on the next observation.
            }
            self.secrets.remove(ns, &session.secret());
            self.secrets
                .persist()
                .map_err(|_| "could not remove JIT credential")?;
            self.save_session(d, None)?;
            if op.state != OpState::Succeeded {
                return Err("managed runner operation failed; inspect its operation log".into());
            }
            return Ok(false); // Fresh queue inventory before another registration or sleep.
        }

        if session.runner_id.is_none() {
            // A timed-out mint may have succeeded. No launch is possible until
            // its credentials and runner id are durable; remove only that
            // exact, journalled orphan before trying again.
            if let Some(r) = self.registration(b, &session).await? {
                if r.busy {
                    return Err("unlaunched managed registration unexpectedly busy".into());
                }
                self.github_write(
                    b,
                    reqwest::Method::DELETE,
                    &format!("/actions/runners/{}", r.id),
                    None,
                )
                .await?;
                return Ok(false);
            }
            let config = self
                .github_write(
                    b,
                    reqwest::Method::POST,
                    "/actions/runners/generate-jitconfig",
                    Some(json!({
                        "name": session.name(), "runner_group_id": 1,
                        "labels": managed.labels, "work_folder": "_work"
                    })),
                )
                .await?;
            let id = config["runner"]["id"]
                .as_u64()
                .filter(|id| *id != 0)
                .ok_or("missing JIT runner id")?;
            let encoded = config["encoded_jit_config"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or("missing JIT configuration")?;
            self.secrets.put(
                serde_json::from_value(
                    json!({"id":session.secret(),"namespace":ns,"data":{"token":encoded}}),
                )
                .map_err(|_| "invalid JIT secret")?,
            );
            self.secrets
                .persist()
                .map_err(|_| "could not persist JIT credential")?;
            session.runner_id = Some(id);
            self.save_session(d, Some(session.clone()))?;
        }
        let credential = self
            .secrets
            .resolve(&SecretRef {
                secret: session.secret(),
                key: "token".into(),
                username: None,
                namespace: Some(ns.into()),
            })
            .map_err(|_| "managed JIT credential unavailable")?;
        let result = ops
            .vms()
            .exec(
                &session.sandbox_id,
                &launch_script(&session, &command),
                heyo_sdk::CommandRunOptions {
                    env: Some(HashMap::from([("HEYO_GITHUB_JIT".into(), credential)])),
                    timeout: Some(Duration::from_secs(20)),
                    ..Default::default()
                },
            )
            .await
            .map_err(|_| "managed runner launch uncertain; will reconcile the same operation")?;
        if result.exit_code != 0 {
            return Err(
                "managed runner launch failed; no replacement session will be started".into(),
            );
        }
        let (dir, boot) = operations::parse_start(&result.stdout)
            .map_err(|_| "invalid managed runner launch receipt")?;
        if boot != session.boot_id {
            return Err("managed runner VM rebooted during launch".into());
        }
        let mut op = operations::record(
            session.operation_id.clone(),
            &d.spec.id,
            &session.sandbox_id,
            boot,
            dir,
            &command,
            None,
            vec!["HEYO_GITHUB_JIT".into()],
            operations::MAX_RUNTIME_SECS,
        );
        op.created_at = session.created_at;
        ops.insert(op, d);
        Ok(false)
    }
}
