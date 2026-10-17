//! Background commands in a sandbox: start one, page its output, cancel it.
//!
//! `POST /deployments/:id/exec` holds the admin connection, and the guest's only
//! serial console, until the command ends. An agent's coding session runs for
//! ten minutes to an hour, past every caller's HTTP timeout, and while it runs
//! nothing else can be executed on that VM. An operation is the same command
//! started detached instead: one short exec launches it under `setsid` with its
//! output going to a file, and every later look at it is another short exec.
//! Several can run on one VM at once, which is the parallelism the console
//! cannot give.
//!
//! Everything about a running operation lives in the guest, in one directory:
//! the command, its output, its pid, and — once it ends — its exit code. That
//! directory is on `/workspace` when the VM has a data disk, so the output
//! survives a stop and can still be read after a start. What app-lb keeps is
//! the record of which VM holds it, persisted so a restart picks the watch up
//! again.
//!
//! While any operation runs on a VM, app-lb holds an in-flight slot on it, the
//! same one an open exec or shell holds: that is demand, so the pool neither
//! scales the VM to zero nor stops it under an operation, and releasing the slot
//! when the last one ends is what starts the idle clock.
//!
//! The scripts are built and parsed by pure functions, so the guest side is
//! testable without a guest. They are written for whatever `sh` the image has
//! and for the serial line they arrive over: no backslashes, no bash, every line
//! of output newline-terminated.

use crate::deployment::{BackendSlot, Deployment, now_secs};
use crate::registry::Registry;
use crate::vm::VmManager;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Running operations one deployment may have at once.
pub const MAX_RUNNING_PER_DEPLOYMENT: usize = 16;
/// Default and ceiling for how long an operation may run before it is
/// cancelled and reported `timed_out`.
pub const DEFAULT_MAX_RUNTIME_SECS: u64 = 3600;
pub const MAX_RUNTIME_SECS: u64 = 21_600;
/// Most output one `GET` returns.
pub const MAX_PAGE_BYTES: u64 = 256 * 1024;
pub const DEFAULT_PAGE_BYTES: u64 = 64 * 1024;
/// How often the watcher looks at running operations.
pub const TICK: Duration = Duration::from_secs(15);
/// Bound on each exec the operations make. They are all short; one that takes
/// longer is waiting behind a blocking `exec` on the same console.
const EXEC_TIMEOUT: Duration = Duration::from_secs(20);
/// How long after SIGTERM a cancelled operation gets before SIGKILL.
const CANCEL_GRACE_SECS: u64 = 10;
/// How long a VM with running operations may be missing from its pool before
/// they are reported lost.
const MISSING_GRACE_SECS: u64 = 45;
/// How long a started operation may go without recording its pid before it is
/// reported as never having started.
const START_GRACE_SECS: u64 = 60;
/// Finished records are kept this long, and at most this many per deployment.
const KEEP_FINISHED_SECS: u64 = 86_400;
const KEEP_FINISHED_PER_DEPLOYMENT: usize = 50;
/// Characters of the command kept in the record, for listing.
const COMMAND_PREVIEW: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpState {
    Running,
    /// Asked to stop; SIGTERM sent, SIGKILL follows if it does not.
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
    /// Ran past `max_runtime_secs` and was stopped.
    TimedOut,
    /// Its VM was restarted or replaced, or the process vanished without
    /// recording an exit code. Whatever it wrote is still in its directory
    /// when that is on `/workspace`.
    Lost,
}

impl OpState {
    pub fn finished(self) -> bool {
        !matches!(self, OpState::Running | OpState::Cancelling)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    pub id: String,
    pub deployment: String,
    /// The VM it runs in. An operation never moves.
    pub sandbox_id: String,
    /// The guest's boot id when it started: a different one means the VM was
    /// restarted under it.
    pub boot_id: String,
    /// Its directory in the guest: `cmd`, `out`, `pid`, `exit`.
    pub dir: String,
    /// The first characters of the command.
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Names only: values are never recorded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_keys: Vec<String>,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
    pub max_runtime_secs: u64,
    pub state: OpState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Bytes of output so far, as of the last look.
    #[serde(default)]
    pub output_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_requested_at: Option<u64>,
    /// Cancelled for running past `max_runtime_secs`, not by a caller.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub timed_out: bool,
}

/// A page of an operation's output.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OutputPage {
    pub offset: u64,
    pub bytes: u64,
    /// Where the next page starts. Equal to `total_bytes` once caught up; a
    /// running operation's output keeps growing past it.
    pub next_offset: u64,
    pub total_bytes: u64,
    /// `utf-8` when `data` is the bytes as text, `base64` when they were not
    /// valid UTF-8 (a page can split a multibyte character; ask again from a
    /// slightly different offset, or take the base64).
    pub encoding: &'static str,
    pub data: String,
}

// -- guest scripts ---------------------------------------------------------

/// Single-quote for `sh`. Callers refuse values containing a quote or a
/// newline before they get here: the escaped form needs a backslash, which the
/// serial console does not carry faithfully.
fn quote(s: &str) -> String {
    format!("'{s}'")
}

/// Launch `command` detached and report where it lives.
///
/// The command travels base64-encoded, so its own quoting never meets the
/// shell's. It runs as `sh <dir>/cmd` in a new session (`setsid`, so a cancel
/// can signal the whole process group; `nohup` where there is no `setsid`),
/// with stdin from `/dev/null` and stdout and stderr appended to `<dir>/out`.
/// The inner shell records its pid first and its exit code last, through a
/// rename so a half-written code is never read.
pub fn start_script(op_id: &str, command: &str, cwd: Option<&str>) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(command);
    let cwd = cwd.map(quote).unwrap_or_else(|| "''".into());
    format!(
        "B=/var/tmp/heyo-ops; if grep -qs ' /workspace ' /proc/mounts; then B=/workspace/.heyo/ops; fi; \
         D=\"$B/{op_id}\"; mkdir -p \"$D\" || {{ echo 'error=cannot create the operation directory'; exit 70; }}; \
         printf %s '{encoded}' | base64 -d > \"$D/cmd\" || {{ echo 'error=the guest has no base64'; exit 71; }}; \
         C={cwd}; if [ -z \"$C\" ]; then if [ \"$B\" = /workspace/.heyo/ops ]; then C=/workspace; else C=/; fi; fi; \
         if command -v setsid >/dev/null 2>&1; then S=setsid; else S=nohup; fi; \
         ($S sh -c 'echo $$ > \"$1/pid\"; cd \"$2\" >> \"$1/out\" 2>&1 && sh \"$1/cmd\" >> \"$1/out\" 2>&1 < /dev/null; \
         echo $? > \"$1/exit.tmp\"; mv \"$1/exit.tmp\" \"$1/exit\"' heyo-op \"$D\" \"$C\" < /dev/null > /dev/null 2>&1 &); \
         echo \"dir=$D\"; echo \"boot=$(cat /proc/sys/kernel/random/boot_id)\""
    )
}

/// What [`start_script`] reported: the directory and the boot id.
pub fn parse_start(stdout: &str) -> Result<(String, String), String> {
    let field = |k: &str| {
        stdout
            .lines()
            .find_map(|l| l.trim().strip_prefix(k).and_then(|v| v.strip_prefix('=')))
            .map(str::to_string)
    };
    if let Some(e) = field("error") {
        return Err(e);
    }
    match (field("dir"), field("boot")) {
        (Some(dir), Some(boot)) if !dir.is_empty() => Ok((dir, boot)),
        _ => Err(format!(
            "the guest did not report where it started the operation: {}",
            stdout.trim()
        )),
    }
}

/// One look at every listed operation directory on a VM, and the VM's boot id.
pub fn status_script(dirs: &[&str]) -> String {
    let list = dirs.iter().map(|d| quote(d)).collect::<Vec<_>>().join(" ");
    format!(
        "echo \"boot=$(cat /proc/sys/kernel/random/boot_id)\"; \
         for D in {list}; do \
         m=0; [ -d \"$D\" ] && m=1; \
         p=$(cat \"$D/pid\" 2>/dev/null); a=x; \
         if [ -n \"$p\" ]; then st=$(sed 's/.*) //' /proc/$p/stat 2>/dev/null | cut -d' ' -f1); \
         if [ -n \"$st\" ] && [ \"$st\" != Z ]; then a=1; else a=0; fi; fi; \
         e=$(cat \"$D/exit\" 2>/dev/null); \
         s=$({{ wc -c < \"$D/out\"; }} 2>/dev/null | tr -d ' '); \
         c=0; [ -f \"$D/cancelled\" ] && c=1; \
         echo \"op=$D dir=$m alive=$a exit=$e size=${{s:-0}} cancelled=$c\"; \
         done"
    )
}

/// What the guest said about one operation directory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Probe {
    pub dir_exists: bool,
    /// `None` before the pid is recorded.
    pub alive: Option<bool>,
    pub exit_code: Option<i32>,
    pub size: u64,
    pub cancelled: bool,
}

/// The boot id and one [`Probe`] per directory [`status_script`] listed.
pub fn parse_status(stdout: &str) -> (Option<String>, HashMap<String, Probe>) {
    let mut boot = None;
    let mut probes = HashMap::new();
    for line in stdout.lines().map(str::trim) {
        if let Some(b) = line.strip_prefix("boot=") {
            boot = Some(b.to_string());
            continue;
        }
        let Some(rest) = line.strip_prefix("op=") else {
            continue;
        };
        let mut fields = rest.split(' ');
        let Some(dir) = fields.next() else { continue };
        let mut probe = Probe::default();
        for f in fields {
            let Some((k, v)) = f.split_once('=') else {
                continue;
            };
            match k {
                "dir" => probe.dir_exists = v == "1",
                "alive" => {
                    probe.alive = match v {
                        "1" => Some(true),
                        "0" => Some(false),
                        _ => None,
                    }
                }
                "exit" => probe.exit_code = v.parse().ok(),
                "size" => probe.size = v.parse().unwrap_or(0),
                "cancelled" => probe.cancelled = v == "1",
                _ => {}
            }
        }
        probes.insert(dir.to_string(), probe);
    }
    (boot, probes)
}

/// `len` bytes of `<dir>/out` from `from`, base64, after its total size and
/// where the page starts. `None` pages the last `len` bytes, measured in the
/// guest at the moment of reading: an offset worked out from the last known
/// size would lag whatever was written since.
pub fn page_script(dir: &str, from: Option<u64>, len: u64) -> String {
    let start = match from {
        Some(offset) => offset.to_string(),
        None => format!("$(( s > {len} ? s - {len} : 0 ))"),
    };
    format!(
        "D={d}; s=$({{ wc -c < \"$D/out\"; }} 2>/dev/null | tr -d ' '); s=${{s:-0}}; o={start}; \
         echo \"size=$s\"; echo \"from=$o\"; printf 'data='; \
         tail -c +$((o + 1)) \"$D/out\" 2>/dev/null | head -c {len} | base64 | tr -d '[:space:]'; echo",
        d = quote(dir),
    )
}

/// The total size, where the page starts and the decoded bytes
/// [`page_script`] printed.
pub fn parse_page(stdout: &str) -> Result<(u64, u64, Vec<u8>), String> {
    let mut size = None;
    let mut from = 0;
    let mut data = None;
    for line in stdout.lines().map(str::trim) {
        if let Some(f) = line.strip_prefix("from=") {
            from = f.parse().unwrap_or(0);
        } else if let Some(s) = line.strip_prefix("size=") {
            size = s.parse().ok();
        } else if let Some(d) = line.strip_prefix("data=") {
            data = Some(d.to_string());
        }
    }
    let size = size.ok_or_else(|| {
        format!(
            "the guest did not report the output size: {}",
            stdout.trim()
        )
    })?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data.unwrap_or_default())
        .map_err(|e| format!("the guest's output page was not valid base64: {e}"))?;
    Ok((size, from, bytes))
}

/// Mark `dir` cancelled and send `signal` to its process group (or, where the
/// operation was started with `nohup` and has no group of its own, its shell).
pub fn cancel_script(dir: &str, signal: &str) -> String {
    format!(
        "D={d}; touch \"$D/cancelled\"; p=$(cat \"$D/pid\" 2>/dev/null); \
         if [ -n \"$p\" ]; then kill -s {signal} -- -$p 2>/dev/null || kill -s {signal} $p 2>/dev/null; fi; echo ok",
        d = quote(dir),
    )
}

pub fn purge_script(dir: &str) -> String {
    format!("rm -rf {}; echo ok", quote(dir))
}

/// The page as the API returns it: text when it is text.
pub fn output_page(offset: u64, total: u64, bytes: Vec<u8>) -> OutputPage {
    let n = bytes.len() as u64;
    let (encoding, data) = match String::from_utf8(bytes) {
        Ok(text) => ("utf-8", text),
        Err(e) => (
            "base64",
            base64::engine::general_purpose::STANDARD.encode(e.into_bytes()),
        ),
    };
    OutputPage {
        offset,
        bytes: n,
        next_offset: offset + n,
        total_bytes: total.max(offset + n),
        encoding,
        data,
    }
}

// -- state ---------------------------------------------------------------

/// What one look means for an operation: its new state, exit code and error,
/// and whether it now needs a signal sent (`TERM` past its runtime, `KILL`
/// past the cancel grace).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub state: OpState,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub signal: Option<&'static str>,
    pub timed_out: bool,
}

/// Decide an operation's state from what the guest reported. Pure.
pub fn judge(op: &Operation, boot_now: Option<&str>, probe: Option<&Probe>, now: u64) -> Verdict {
    let keep = |state, signal| Verdict {
        state,
        exit_code: op.exit_code,
        error: op.error.clone(),
        signal,
        timed_out: op.timed_out,
    };
    let lost = |why: &str| Verdict {
        state: OpState::Lost,
        exit_code: None,
        error: Some(why.to_string()),
        signal: None,
        timed_out: op.timed_out,
    };
    if boot_now.is_some_and(|b| b != op.boot_id) {
        return lost("the VM was restarted while the operation ran");
    }
    let Some(probe) = probe else {
        return keep(op.state, None);
    };
    if !probe.dir_exists {
        return lost("the operation's directory is gone from the guest");
    }
    let cancelled = probe.cancelled || op.cancel_requested_at.is_some();
    if let Some(code) = probe.exit_code {
        let state = if op.timed_out {
            OpState::TimedOut
        } else if cancelled {
            OpState::Cancelled
        } else if code == 0 {
            OpState::Succeeded
        } else {
            OpState::Failed
        };
        return Verdict {
            state,
            exit_code: Some(code),
            error: op.error.clone(),
            signal: None,
            timed_out: op.timed_out,
        };
    }
    match probe.alive {
        Some(false) if op.timed_out => keep(OpState::TimedOut, None),
        Some(false) if cancelled => keep(OpState::Cancelled, None),
        Some(false) => lost("the process ended without recording an exit code"),
        None if now.saturating_sub(op.created_at) > START_GRACE_SECS => {
            lost("the operation never started")
        }
        None => keep(op.state, None),
        Some(true) => {
            if let Some(asked) = op.cancel_requested_at {
                let signal = (now.saturating_sub(asked) >= CANCEL_GRACE_SECS).then_some("KILL");
                return keep(OpState::Cancelling, signal);
            }
            if now.saturating_sub(op.created_at) >= op.max_runtime_secs {
                return Verdict {
                    state: OpState::Cancelling,
                    exit_code: None,
                    error: Some(format!(
                        "ran past max_runtime_secs ({})",
                        op.max_runtime_secs
                    )),
                    signal: Some("TERM"),
                    timed_out: true,
                };
            }
            keep(OpState::Running, None)
        }
    }
}

/// A new operation id: `op_` and 16 hex characters.
pub fn new_id() -> String {
    let mut bytes = [0u8; 8];
    openssl::rand::rand_bytes(&mut bytes).expect("entropy for an operation id");
    format!(
        "op_{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// The record a new operation starts with.
#[allow(clippy::too_many_arguments)]
pub fn record(
    id: String,
    deployment: &str,
    sandbox_id: &str,
    boot_id: String,
    dir: String,
    command: &str,
    cwd: Option<String>,
    env_keys: Vec<String>,
    max_runtime_secs: u64,
) -> Operation {
    Operation {
        id,
        deployment: deployment.to_string(),
        sandbox_id: sandbox_id.to_string(),
        boot_id,
        dir,
        command: command.chars().take(COMMAND_PREVIEW).collect(),
        cwd,
        env_keys,
        created_at: now_secs(),
        finished_at: None,
        max_runtime_secs,
        state: OpState::Running,
        exit_code: None,
        output_bytes: 0,
        error: None,
        cancel_requested_at: None,
        timed_out: false,
    }
}

/// Every operation app-lb knows about, and the slots that keep their VMs up.
pub struct Operations {
    path: PathBuf,
    registry: Arc<Registry>,
    vms: VmManager,
    ops: Mutex<BTreeMap<String, Operation>>,
    /// One in-flight slot per VM with a running operation, keyed by sandbox.
    holds: Mutex<HashMap<String, BackendSlot>>,
    /// When each VM with running operations was first seen missing from its
    /// pool. A VM is only given up on after [`MISSING_GRACE_SECS`].
    missing_since: Mutex<HashMap<String, u64>>,
}

impl Operations {
    /// Load the records persisted at `path`. A missing file is no operations;
    /// an unreadable one is logged and treated the same, since the guest still
    /// has everything the records pointed at.
    pub fn open(path: PathBuf, registry: Arc<Registry>, vms: VmManager) -> Arc<Self> {
        let ops = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Vec<Operation>>(&bytes)
                .map(|list| list.into_iter().map(|o| (o.id.clone(), o)).collect())
                .unwrap_or_else(|e| {
                    tracing::warn!(path = %path.display(), error = %e, "could not read the operations file; starting empty");
                    BTreeMap::new()
                }),
            Err(_) => BTreeMap::new(),
        };
        Arc::new(Self {
            path,
            registry,
            vms,
            ops: Mutex::new(ops),
            holds: Mutex::new(HashMap::new()),
            missing_since: Mutex::new(HashMap::new()),
        })
    }

    pub fn vms(&self) -> &VmManager {
        &self.vms
    }

    fn persist(&self) {
        let list: Vec<Operation> = self.ops.lock().unwrap().values().cloned().collect();
        let tmp = self.path.with_extension("json.tmp");
        let result = serde_json::to_vec_pretty(&list)
            .map_err(std::io::Error::other)
            .and_then(|bytes| std::fs::write(&tmp, bytes))
            .and_then(|()| std::fs::rename(&tmp, &self.path));
        if let Err(e) = result {
            tracing::error!(path = %self.path.display(), error = %e, "could not persist operations");
        }
    }

    pub fn get(&self, deployment: &str, id: &str) -> Option<Operation> {
        self.ops
            .lock()
            .unwrap()
            .get(id)
            .filter(|o| o.deployment == deployment)
            .cloned()
    }

    /// A deployment's operations, newest first.
    pub fn list(&self, deployment: &str) -> Vec<Operation> {
        let mut list: Vec<Operation> = self
            .ops
            .lock()
            .unwrap()
            .values()
            .filter(|o| o.deployment == deployment)
            .cloned()
            .collect();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        list
    }

    pub fn running(&self, deployment: &str) -> usize {
        self.ops
            .lock()
            .unwrap()
            .values()
            .filter(|o| o.deployment == deployment && !o.state.finished())
            .count()
    }

    pub fn insert(&self, op: Operation, deployment: &Arc<Deployment>) {
        let sandbox = op.sandbox_id.clone();
        self.ops.lock().unwrap().insert(op.id.clone(), op);
        self.persist();
        self.hold(deployment, &sandbox);
    }

    fn update(&self, id: &str, f: impl FnOnce(&mut Operation)) -> Option<Operation> {
        let updated = {
            let mut ops = self.ops.lock().unwrap();
            let op = ops.get_mut(id)?;
            f(op);
            op.clone()
        };
        self.persist();
        Some(updated)
    }

    /// Take an in-flight slot on the VM, if there is a ready one and no slot is
    /// held yet. A VM still booting has no backend to hold; the next tick tries
    /// again.
    fn hold(&self, deployment: &Arc<Deployment>, sandbox_id: &str) {
        let mut holds = self.holds.lock().unwrap();
        if holds.contains_key(sandbox_id) {
            return;
        }
        if let Some(slot) = deployment
            .backends()
            .iter()
            .find(|b| b.sandbox_id == sandbox_id)
            .and_then(|b| b.try_hold())
        {
            holds.insert(sandbox_id.to_string(), slot);
        }
    }

    async fn exec(
        &self,
        sandbox_id: &str,
        script: String,
    ) -> Result<heyo_sdk::CommandResult, String> {
        let run = self.vms.exec(
            sandbox_id,
            &script,
            heyo_sdk::CommandRunOptions {
                cwd: None,
                env: None,
                timeout: Some(EXEC_TIMEOUT),
            },
        );
        match tokio::time::timeout(EXEC_TIMEOUT + Duration::from_secs(5), run).await {
            Ok(Ok(out)) => Ok(out),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err(
                "the guest's console did not answer in time; it may be busy with a blocking exec"
                    .into(),
            ),
        }
    }

    /// Look at the operation in the guest now and page its output. On a busy
    /// or unreachable console, the last known record, marked stale.
    pub async fn read(
        &self,
        op: &Operation,
        from: Option<u64>,
        max_bytes: u64,
    ) -> (Operation, Option<OutputPage>, bool) {
        // A finished operation's record is final; only its output is read.
        // Judging it again would rewrite why it ended.
        if op.state.finished() {
            let script = page_script(&op.dir, from, max_bytes.min(MAX_PAGE_BYTES));
            return match self.exec(&op.sandbox_id, script).await {
                Ok(out) => {
                    let page = parse_page(&out.stdout)
                        .ok()
                        .map(|(total, start, bytes)| output_page(start, total, bytes));
                    (op.clone(), page, false)
                }
                Err(_) => (op.clone(), None, true),
            };
        }
        let mut script = status_script(&[&op.dir]);
        script.push_str("; ");
        script.push_str(&page_script(&op.dir, from, max_bytes.min(MAX_PAGE_BYTES)));
        let out = match self.exec(&op.sandbox_id, script).await {
            Ok(out) => out,
            Err(e) => {
                tracing::debug!(op = %op.id, error = %e, "operation read fell back to the cached record");
                return (op.clone(), None, true);
            }
        };
        let (boot, probes) = parse_status(&out.stdout);
        let updated = self.apply(op, boot.as_deref(), probes.get(&op.dir)).await;
        let page = parse_page(&out.stdout)
            .ok()
            .map(|(total, start, bytes)| output_page(start, total, bytes));
        (updated, page, false)
    }

    /// Record what one look said, sending any signal the verdict calls for.
    async fn apply(&self, op: &Operation, boot: Option<&str>, probe: Option<&Probe>) -> Operation {
        let now = now_secs();
        let verdict = judge(op, boot, probe, now);
        if let Some(signal) = verdict.signal
            && let Err(e) = self
                .exec(&op.sandbox_id, cancel_script(&op.dir, signal))
                .await
        {
            tracing::warn!(op = %op.id, signal, error = %e, "could not signal the operation");
        }
        let size = probe.map(|p| p.size);
        self.update(&op.id, |o| {
            if verdict.timed_out && o.cancel_requested_at.is_none() {
                o.cancel_requested_at = Some(now);
            }
            o.timed_out = verdict.timed_out;
            o.state = verdict.state;
            o.exit_code = verdict.exit_code;
            o.error = verdict.error.clone();
            if let Some(size) = size {
                o.output_bytes = size;
            }
            if o.state.finished() && o.finished_at.is_none() {
                o.finished_at = Some(now);
            }
        })
        .unwrap_or_else(|| op.clone())
    }

    /// Ask an operation to stop: mark it, SIGTERM its group. The watcher sends
    /// SIGKILL if it outlives the grace period.
    pub async fn cancel(&self, op: &Operation) -> Result<Operation, String> {
        if op.state.finished() {
            return Ok(op.clone());
        }
        self.exec(&op.sandbox_id, cancel_script(&op.dir, "TERM"))
            .await?;
        Ok(self
            .update(&op.id, |o| {
                o.state = OpState::Cancelling;
                o.cancel_requested_at.get_or_insert(now_secs());
            })
            .unwrap_or_else(|| op.clone()))
    }

    /// Forget a finished operation, deleting its directory in the guest when
    /// the VM is up.
    pub async fn purge(&self, op: &Operation) -> Result<(), String> {
        if !op.state.finished() {
            return Err("cancel the operation before purging it".into());
        }
        if let Err(e) = self.exec(&op.sandbox_id, purge_script(&op.dir)).await {
            tracing::info!(op = %op.id, error = %e, "operation directory not removed; forgetting the record anyway");
        }
        self.ops.lock().unwrap().remove(&op.id);
        self.persist();
        Ok(())
    }

    /// Mark a deployment's running operations lost and release their VMs:
    /// `stop {"force": true}` is about to take the VM away from under them.
    /// Their output stays in the guest (on `/workspace` when there is a data
    /// disk). Returns how many there were.
    pub fn abandon(&self, deployment: &str, why: &str) -> usize {
        let ids: Vec<String> = self
            .ops
            .lock()
            .unwrap()
            .values()
            .filter(|o| o.deployment == deployment && !o.state.finished())
            .map(|o| o.id.clone())
            .collect();
        for id in &ids {
            self.update(id, |o| {
                o.state = OpState::Lost;
                o.error = Some(why.to_string());
                o.finished_at = Some(now_secs());
            });
        }
        self.release_idle();
        ids.len()
    }

    /// Drop the slot on every VM with no running operation left.
    fn release_idle(&self) {
        let busy: std::collections::HashSet<String> = self
            .ops
            .lock()
            .unwrap()
            .values()
            .filter(|o| !o.state.finished())
            .map(|o| o.sandbox_id.clone())
            .collect();
        self.holds
            .lock()
            .unwrap()
            .retain(|sandbox, _| busy.contains(sandbox));
    }

    /// Drop finished records past their keep.
    fn prune(&self) {
        let now = now_secs();
        let mut ops = self.ops.lock().unwrap();
        let mut finished: BTreeMap<&str, Vec<(u64, String)>> = BTreeMap::new();
        for o in ops.values().filter(|o| o.state.finished()) {
            finished
                .entry(o.deployment.as_str())
                .or_default()
                .push((o.finished_at.unwrap_or(o.created_at), o.id.clone()));
        }
        let mut stale: Vec<String> = Vec::new();
        for (_, mut list) in finished {
            list.sort_by_key(|entry| std::cmp::Reverse(entry.0));
            for (i, (at, id)) in list.into_iter().enumerate() {
                if i >= KEEP_FINISHED_PER_DEPLOYMENT || now.saturating_sub(at) > KEEP_FINISHED_SECS
                {
                    stale.push(id);
                }
            }
        }
        let changed = !stale.is_empty();
        for id in stale {
            ops.remove(&id);
        }
        drop(ops);
        if changed {
            self.persist();
        }
    }

    /// One pass over every running operation: hold its VM, keep the VM's
    /// activity clock fresh, look at the guest once per VM, and record what
    /// changed.
    pub async fn tick(&self) {
        let running: Vec<Operation> = self
            .ops
            .lock()
            .unwrap()
            .values()
            .filter(|o| !o.state.finished())
            .cloned()
            .collect();
        let mut by_vm: BTreeMap<String, Vec<Operation>> = BTreeMap::new();
        for op in running {
            by_vm.entry(op.sandbox_id.clone()).or_default().push(op);
        }
        for (sandbox, ops) in by_vm {
            let deployment = ops[0].deployment.clone();
            let Some(d) = self.registry.get(&deployment) else {
                for op in &ops {
                    self.update(&op.id, |o| {
                        o.state = OpState::Lost;
                        o.error = Some("the deployment was removed".into());
                        o.finished_at = Some(now_secs());
                    });
                }
                continue;
            };
            let backend = d
                .backends()
                .iter()
                .find(|b| b.sandbox_id == sandbox)
                .cloned();
            match &backend {
                Some(b) => {
                    self.missing_since.lock().unwrap().remove(&sandbox);
                    self.hold(&d, &sandbox);
                    // A slot held for an hour leaves `last_active` an hour old,
                    // and a drain's force-kill deadline counts from it. Keep it
                    // fresh while the operation runs, but not once the VM is
                    // draining: then the deadline is the point.
                    if !b.is_draining() {
                        b.touch();
                    }
                }
                None => {
                    let booting = d.pending().iter().any(|p| p.sandbox_id == sandbox);
                    // Missing for a moment is not gone: across an app-lb
                    // restart the VM is back only once the autoscaler adopts
                    // it again.
                    let now = now_secs();
                    let since = *self
                        .missing_since
                        .lock()
                        .unwrap()
                        .entry(sandbox.clone())
                        .or_insert(now);
                    if !booting && now.saturating_sub(since) >= MISSING_GRACE_SECS {
                        self.missing_since.lock().unwrap().remove(&sandbox);
                        for op in &ops {
                            self.update(&op.id, |o| {
                                o.state = OpState::Lost;
                                o.error = Some(
                                    "its VM is no longer running (stopped, replaced or evicted)"
                                        .into(),
                                );
                                o.finished_at = Some(now_secs());
                            });
                        }
                    }
                    continue;
                }
            }
            let dirs: Vec<&str> = ops.iter().map(|o| o.dir.as_str()).collect();
            let out = match self.exec(&sandbox, status_script(&dirs)).await {
                Ok(out) => out,
                Err(e) => {
                    tracing::debug!(sandbox = %sandbox, error = %e, "operation watch skipped this tick");
                    continue;
                }
            };
            let (boot, probes) = parse_status(&out.stdout);
            for op in &ops {
                self.apply(op, boot.as_deref(), probes.get(&op.dir)).await;
            }
        }
        self.release_idle();
        self.prune();
    }

}

/// The watcher, as a pingora background service: it runs on the server's
/// runtime and stops with it. `main` has no runtime of its own to spawn it on.
impl Operations {
    /// Pretend `sandbox` went missing `secs` ago.
    #[cfg(test)]
    pub fn backdate_missing(&self, sandbox: &str, secs: u64) {
        self.missing_since
            .lock()
            .unwrap()
            .insert(sandbox.to_string(), now_secs().saturating_sub(secs));
    }
}

pub struct Watcher(pub Arc<Operations>, pub tokio::sync::watch::Receiver<bool>);

#[async_trait::async_trait]
impl pingora_core::services::background::BackgroundService for Watcher {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        // Not before the autoscaler has adopted the VMs already running: until
        // then every pool is empty, and each running operation would look as
        // if its VM had gone.
        let mut adopted = self.1.clone();
        tokio::select! {
            _ = adopted.wait_for(|done| *done) => {}
            _ = shutdown.changed() => return,
        }
        let mut interval = tokio::time::interval(TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => self.0.tick().await,
                _ = shutdown.changed() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op() -> Operation {
        let mut o = record(
            "op_1".into(),
            "sb",
            "sb-1",
            "boot-a".into(),
            "/workspace/.heyo/ops/op_1".into(),
            "npm test",
            None,
            vec![],
            100,
        );
        o.created_at = 1_000;
        o
    }

    fn probe(alive: Option<bool>, exit: Option<i32>) -> Probe {
        Probe {
            dir_exists: true,
            alive,
            exit_code: exit,
            size: 5,
            cancelled: false,
        }
    }

    #[test]
    fn a_recorded_exit_code_decides_success() {
        let o = op();
        assert_eq!(
            judge(
                &o,
                Some("boot-a"),
                Some(&probe(Some(false), Some(0))),
                1_010
            )
            .state,
            OpState::Succeeded
        );
        let v = judge(
            &o,
            Some("boot-a"),
            Some(&probe(Some(false), Some(2))),
            1_010,
        );
        assert_eq!((v.state, v.exit_code), (OpState::Failed, Some(2)));
    }

    #[test]
    fn a_restarted_vm_or_a_vanished_process_is_lost() {
        let o = op();
        assert_eq!(
            judge(&o, Some("boot-b"), Some(&probe(Some(true), None)), 1_010).state,
            OpState::Lost
        );
        assert_eq!(
            judge(&o, Some("boot-a"), Some(&probe(Some(false), None)), 1_010).state,
            OpState::Lost
        );
        let gone = Probe {
            dir_exists: false,
            ..probe(None, None)
        };
        assert_eq!(
            judge(&o, Some("boot-a"), Some(&gone), 1_010).state,
            OpState::Lost
        );
    }

    #[test]
    fn no_pid_yet_is_running_until_the_start_grace_ends() {
        let o = op();
        assert_eq!(
            judge(&o, Some("boot-a"), Some(&probe(None, None)), 1_010).state,
            OpState::Running
        );
        assert_eq!(
            judge(
                &o,
                Some("boot-a"),
                Some(&probe(None, None)),
                1_000 + START_GRACE_SECS + 1
            )
            .state,
            OpState::Lost
        );
    }

    #[test]
    fn running_past_the_limit_is_signalled_then_timed_out() {
        let o = op();
        let v = judge(&o, Some("boot-a"), Some(&probe(Some(true), None)), 1_100);
        assert_eq!(
            (v.state, v.signal, v.timed_out),
            (OpState::Cancelling, Some("TERM"), true)
        );
        let mut o = o;
        o.timed_out = true;
        o.cancel_requested_at = Some(1_100);
        assert_eq!(
            judge(&o, Some("boot-a"), Some(&probe(Some(false), None)), 1_105).state,
            OpState::TimedOut
        );
        assert_eq!(
            judge(
                &o,
                Some("boot-a"),
                Some(&probe(Some(false), Some(143))),
                1_105
            )
            .state,
            OpState::TimedOut
        );
    }

    #[test]
    fn a_cancel_escalates_to_kill_after_the_grace() {
        let mut o = op();
        o.cancel_requested_at = Some(1_010);
        let v = judge(&o, Some("boot-a"), Some(&probe(Some(true), None)), 1_012);
        assert_eq!((v.state, v.signal), (OpState::Cancelling, None));
        let v = judge(
            &o,
            Some("boot-a"),
            Some(&probe(Some(true), None)),
            1_010 + CANCEL_GRACE_SECS,
        );
        assert_eq!(v.signal, Some("KILL"));
        assert_eq!(
            judge(&o, Some("boot-a"), Some(&probe(Some(false), None)), 1_030).state,
            OpState::Cancelled
        );
    }

    #[test]
    fn status_lines_parse_per_directory() {
        let out = "boot=abc\nop=/w/op_1 dir=1 alive=1 exit= size=12 cancelled=0\n\
                   op=/w/op_2 dir=1 alive=0 exit=3 size=0 cancelled=1\nop=/w/op_3 dir=0 alive=x exit= size=0 cancelled=0\n";
        let (boot, probes) = parse_status(out);
        assert_eq!(boot.as_deref(), Some("abc"));
        assert_eq!(
            probes["/w/op_1"],
            Probe {
                dir_exists: true,
                alive: Some(true),
                exit_code: None,
                size: 12,
                cancelled: false
            }
        );
        assert_eq!(probes["/w/op_2"].exit_code, Some(3));
        assert!(probes["/w/op_2"].cancelled);
        assert_eq!(probes["/w/op_3"].alive, None);
        assert!(!probes["/w/op_3"].dir_exists);
    }

    #[test]
    fn pages_decode_and_text_stays_text() {
        let (size, from, bytes) = parse_page("size=11\nfrom=6\ndata=aGVsbG8=\n").unwrap();
        assert_eq!(from, 6);
        assert_eq!((size, bytes.as_slice()), (11, b"hello".as_slice()));
        let page = output_page(from, size, bytes);
        assert_eq!(
            (
                page.encoding,
                page.data.as_str(),
                page.next_offset,
                page.total_bytes
            ),
            ("utf-8", "hello", 11, 11)
        );
        assert_eq!(output_page(0, 1, vec![0xff]).encoding, "base64");
        assert!(parse_page("data=\n").is_err());
    }

    #[test]
    fn scripts_carry_no_backslash_and_quote_what_they_name() {
        for script in [
            start_script(
                "op_1",
                "echo 'hi' && printf '%s\\n' x",
                Some("/workspace/app"),
            ),
            status_script(&["/workspace/.heyo/ops/op_1"]),
            cancel_script("/workspace/.heyo/ops/op_1", "TERM"),
            page_script("/workspace/.heyo/ops/op_1", Some(0), 100),
            page_script("/workspace/.heyo/ops/op_1", None, 100),
            purge_script("/workspace/.heyo/ops/op_1"),
        ] {
            assert!(!script.contains('\\'), "{script}");
        }
        assert!(start_script("op_1", "x", Some("/w a")).contains("C='/w a'"));
    }

    #[test]
    fn start_output_is_read_or_refused() {
        assert_eq!(
            parse_start("dir=/workspace/.heyo/ops/op_1\nboot=abc\n").unwrap(),
            ("/workspace/.heyo/ops/op_1".to_string(), "abc".to_string())
        );
        assert_eq!(
            parse_start("error=the guest has no base64\n").unwrap_err(),
            "the guest has no base64"
        );
        assert!(parse_start("").is_err());
    }
}
