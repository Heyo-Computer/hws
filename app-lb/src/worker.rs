//! One management process supervises a forwarding-only worker, and a
//! restarted manager takes over the worker it finds rather than closing the
//! listeners (`docs/design/fleet-shared-state.md` § Phase 4).
//!
//! **The control directory** (`app-lb-worker.d/`, beside the state) is fixed,
//! so the next manager finds what the last one left:
//! - `requests`: the request-control socket the current manager serves;
//! - `bootstrap`: listener addresses and the certificate snapshot;
//! - `upgrade`: where a new worker receives the old one's listening sockets;
//! - `worker.json`: the running worker's pid and start time.
//!
//! **A restart drops nothing.** The worker runs in its own session, so the
//! manager's stop (supervisor signals the manager's process group) does not
//! reach it, and it keeps its listeners. Requests that need a decision while no
//! manager answers wait for the next one, up to `APP_LB_WORKER_WAIT_SECS`;
//! requests already forwarding finish without one. The next manager binds the
//! sockets, finds the worker alive, starts a worker from its own binary, and
//! once that worker waits on `upgrade` sends the old one `SIGQUIT`: pingora
//! hands the listening sockets across, and the old worker drains for
//! `APP_LB_DRAIN_SECS` before it exits. A held stream survives as long as that.
//!
//! **One manager at a time** is unchanged: the instance lock still keeps a
//! second app-lb off the daemon (the 2026-09-29 incident). Only the worker
//! outlives a manager, and it never touches the daemon.
//!
//! **A worker nobody comes back for** — a real stop, not a restart — drains and
//! exits after `APP_LB_WORKER_ORPHAN_SECS` (default 120). Setting it to `0`
//! turns all of this off: the worker dies with its manager, as before.
//!
//! **Admission state** a request holds in the manager is released when the
//! request completes, or — if its connection breaks first — when the worker
//! that held it exits. Which worker is the connection's peer pid
//! (`SO_PEERCRED`), since a taken-over worker is not the manager's child.

use crate::metrics::Metrics;
use crate::obs::LogSink;
use crate::request_control::RequestControl;
use crate::siem::SecuritySink;
use crate::tls::{CertSnapshot, CertStore, SniResolver};
use crate::worker_rpc::{self, Client};
use async_trait::async_trait;
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_core::server::{Server, ShutdownWatch};
use pingora_core::services::background::{BackgroundService, background_service};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::task::JoinSet;

const VERSION: u16 = 1;

pub const ORPHAN_ENV: &str = "APP_LB_WORKER_ORPHAN_SECS";
pub const WAIT_ENV: &str = "APP_LB_WORKER_WAIT_SECS";
pub const DRAIN_ENV: &str = "APP_LB_DRAIN_SECS";
const DEFAULT_ORPHAN: Duration = Duration::from_secs(120);
const DEFAULT_WAIT: Duration = Duration::from_secs(60);
/// How long an old worker keeps serving what it holds after a takeover: the
/// longest a held stream survives a restart.
const DEFAULT_DRAIN: u64 = 300;
/// Between an old worker's last accept and pingora dropping its connections
/// that have not sent a request yet: long enough for one accepted at the last
/// moment to send it.
const LINGER: Duration = Duration::from_secs(3);
/// After the drain, how long the old worker's runtimes get to finish.
const SHUTDOWN_TIMEOUT: u64 = 60;
/// How long a new worker waits for the old one's sockets, in pingora's
/// one-second retries.
const TAKEOVER_RETRIES: usize = 30;

fn env_secs(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

/// How long a worker waits for a manager before draining and exiting.
/// `None` when handoff is off: the worker dies with its manager.
pub fn orphan_timeout() -> Option<Duration> {
    match env_secs(ORPHAN_ENV) {
        Some(0) => None,
        Some(secs) => Some(Duration::from_secs(secs)),
        None => Some(DEFAULT_ORPHAN),
    }
}

pub fn handoff_enabled() -> bool {
    orphan_timeout().is_some()
}

/// How long a request waits for a manager to decide it.
pub fn wait_budget() -> Duration {
    env_secs(WAIT_ENV)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_WAIT)
}

/// `app-lb-state.json` → `app-lb-worker.d/`, beside it.
pub fn worker_dir(state_path: &str) -> PathBuf {
    crate::fleet_store::sibling_dir(state_path, "worker")
}

async fn stopped(shutdown: &mut ShutdownWatch) {
    // Drop watch::Ref before returning: select branches may await child exit.
    let _ = shutdown.wait_for(|stop| *stop).await;
}

#[derive(Serialize, Deserialize)]
struct Bootstrap {
    version: u16,
    proxy_addr: String,
    tls_addr: Option<String>,
    certificates: CertSnapshot,
}

/// The running worker, as the manager that started it recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct WorkerRecord {
    pid: i32,
    start_time: u64,
}

// ---- processes -----------------------------------------------------------------

/// A process's start time in clock ticks since boot (`/proc/<pid>/stat`
/// field 22), which tells a pid from a later reuse of it. `None` when it is
/// gone or a zombie.
fn start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name is parenthesized and may contain spaces.
    let rest = &stat[stat.rfind(')')? + 2..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.first() == Some(&"Z") {
        return None;
    }
    fields.get(19)?.parse().ok()
}

fn alive(record: WorkerRecord) -> bool {
    start_time(record.pid) == Some(record.start_time)
}

/// Whether `pid` is a forwarding worker for `dir`.
fn is_worker_for(pid: i32, dir: &Path) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
    args.contains(&&b"--forwarding-worker"[..])
        && args.contains(&dir.as_os_str().as_encoded_bytes())
}

/// The pid of a forwarding worker still serving from `dir`, left by the last
/// manager. The next manager takes its listeners over rather than binding
/// them, so it must not treat them as taken.
pub fn live_worker(dir: &Path) -> Option<i32> {
    let record: WorkerRecord =
        serde_json::from_slice(&std::fs::read(dir.join("worker.json")).ok()?).ok()?;
    (alive(record) && is_worker_for(record.pid, dir)).then_some(record.pid)
}

/// The worker's log, in the control directory. Not the manager's stdout: a
/// supervisor closes that pipe when the manager it ran exits, and a worker
/// that outlives its manager would go on logging into nothing.
const LOG_ROTATE_BYTES: u64 = 50 * 1024 * 1024;

fn worker_log(dir: &Path) -> std::io::Result<std::fs::File> {
    let path = dir.join("worker.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > LOG_ROTATE_BYTES) {
        let _ = std::fs::rename(&path, dir.join("worker.log.1"));
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// Fires once per worker process when it exits, so a request's admission
/// state is released when the worker that held it is gone.
#[derive(Default)]
struct Exits {
    watched: Mutex<HashMap<WorkerRecord, watch::Sender<bool>>>,
}

impl Exits {
    fn subscribe(&self, pid: Option<i32>) -> watch::Receiver<bool> {
        let Some(record) = pid.and_then(|pid| {
            Some(WorkerRecord {
                pid,
                start_time: start_time(pid)?,
            })
        }) else {
            // Gone already, or unknowable: nothing can still be forwarding.
            return watch::channel(true).1;
        };
        let mut watched = self.watched.lock().unwrap_or_else(|e| e.into_inner());
        watched
            .entry(record)
            .or_insert_with(|| watch::channel(false).0)
            .subscribe()
    }

    fn poll(&self) {
        self.watched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|record, tx| {
                if alive(*record) {
                    true
                } else {
                    let _ = tx.send(true);
                    false
                }
            });
    }
}

// ---- the manager's side ------------------------------------------------------------

pub struct Supervisor {
    pub control: Arc<RequestControl>,
    pub metrics: Arc<Metrics>,
    pub access_log: Option<LogSink>,
    pub security: Option<SecuritySink>,
    pub certs: Arc<CertStore>,
    pub proxy_addr: String,
    pub tls_addr: Option<String>,
    /// The fixed control directory ([`worker_dir`]).
    pub dir: PathBuf,
}

/// The worker this manager is responsible for.
enum Current {
    /// Started by this manager.
    Child(Child),
    /// Left by the previous manager and not (yet) replaced.
    Inherited(WorkerRecord),
}

impl Supervisor {
    fn prepare(&self) -> Result<(UnixListener, UnixListener), String> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(|e| format!("{}: {e}", self.dir.display()))?;
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        // A previous manager's sockets. The instance lock makes this the only
        // manager, so nothing else is serving them.
        for name in ["requests", "bootstrap"] {
            let _ = std::fs::remove_file(self.dir.join(name));
        }
        let requests = UnixListener::bind(self.dir.join("requests")).map_err(|e| e.to_string())?;
        let bootstrap =
            UnixListener::bind(self.dir.join("bootstrap")).map_err(|e| e.to_string())?;
        Ok((requests, bootstrap))
    }

    fn record_path(&self) -> PathBuf {
        self.dir.join("worker.json")
    }

    fn inherited(&self) -> Option<WorkerRecord> {
        let pid = live_worker(&self.dir)?;
        let record: WorkerRecord =
            serde_json::from_slice(&std::fs::read(self.record_path()).ok()?).ok()?;
        (record.pid == pid).then_some(record)
    }

    fn write_record(&self, record: WorkerRecord) {
        let tmp = self.dir.join("worker.json.tmp");
        let written = serde_json::to_vec(&record)
            .map_err(std::io::Error::other)
            .and_then(|b| std::fs::write(&tmp, b))
            .and_then(|()| std::fs::rename(&tmp, self.record_path()));
        if let Err(error) = written {
            tracing::warn!(%error, "could not record the forwarding worker; the next manager will not take it over");
        }
    }

    fn spawn(&self, takeover: bool) -> Result<(Child, WorkerRecord), String> {
        // This binary, even if the file it was started from has since been
        // replaced: the worker must speak this manager's protocol.
        let mut command = Command::new("/proc/self/exe");
        command.arg("--forwarding-worker").arg(&self.dir);
        if takeover {
            command.arg("--takeover");
        }
        let handoff = handoff_enabled();
        command.kill_on_drop(!handoff);
        if handoff {
            let log = worker_log(&self.dir).map_err(|e| format!("worker log: {e}"))?;
            command
                .stdout(log.try_clone().map_err(|e| e.to_string())?)
                .stderr(log);
        }
        #[cfg(target_os = "linux")]
        unsafe {
            let parent = libc::getpid();
            command.pre_exec(move || {
                if handoff {
                    // Out of the manager's process group, so a supervisor
                    // stopping the manager does not stop the listeners.
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else {
                    // A manager killed without a shutdown callback must not
                    // leave a forwarding child serving with abandoned
                    // admission ownership.
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::getppid() != parent {
                        return Err(std::io::Error::other("manager exited before worker exec"));
                    }
                }
                Ok(())
            });
        }
        let child = command.spawn().map_err(|e| e.to_string())?;
        let pid = child.id().ok_or("the worker exited at once")? as i32;
        let record = WorkerRecord {
            pid,
            start_time: start_time(pid).unwrap_or(0),
        };
        self.write_record(record);
        tracing::info!(worker_pid = pid, takeover, "forwarding worker started");
        Ok((child, record))
    }

    /// Replace a worker this manager inherited: a new one waits for its
    /// listening sockets, then the old one is told to hand them over and
    /// drain. Falls back to keeping the old one if the new one never gets as
    /// far as waiting.
    async fn take_over(&self, old: WorkerRecord) -> Current {
        let upgrade = self.dir.join("upgrade");
        let _ = std::fs::remove_file(&upgrade);
        let (mut child, record) = match self.spawn(true) {
            Ok(spawned) => spawned,
            Err(error) => {
                tracing::error!(%error, "could not start a worker to take over from the last one; keeping it");
                self.write_record(old);
                return Current::Inherited(old);
            }
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                tracing::error!(%status, "the new worker exited before taking over; keeping the old one");
                self.write_record(old);
                return Current::Inherited(old);
            }
            if upgrade.exists() {
                break;
            }
            if Instant::now() >= deadline {
                tracing::error!(
                    "the new worker never waited for the old one's sockets; keeping the old one"
                );
                let _ = child.start_kill();
                let _ = child.wait().await;
                self.write_record(old);
                return Current::Inherited(old);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if alive(old) {
            // Not our child, but ours to direct: pingora sends its listening
            // sockets to `upgrade`, keeps serving briefly, then drains.
            unsafe {
                libc::kill(old.pid, libc::SIGQUIT);
            }
            tracing::info!(
                old_pid = old.pid,
                new_pid = record.pid,
                "forwarding worker taking over the listeners"
            );
        }
        Current::Child(child)
    }

    async fn supervise(&self, shutdown: &mut ShutdownWatch) {
        let mut current = match self.inherited() {
            Some(old) => {
                tracing::info!(
                    worker_pid = old.pid,
                    "found the last manager's forwarding worker still serving"
                );
                self.take_over(old).await
            }
            None => match self.spawn(false) {
                Ok((child, _)) => Current::Child(child),
                Err(error) => {
                    tracing::error!(%error, "could not start the forwarding worker; stopping manager");
                    std::process::exit(1);
                }
            },
        };
        loop {
            let exited = async {
                match &mut current {
                    Current::Child(child) => child
                        .wait()
                        .await
                        .map(|s| s.to_string())
                        .unwrap_or_else(|e| e.to_string()),
                    Current::Inherited(record) => {
                        while alive(*record) {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                        "exited".into()
                    }
                }
            };
            tokio::select! {
                status = exited => {
                    tracing::warn!(%status, "forwarding worker exited; starting another");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    current = match self.spawn(false) {
                        Ok((child, _)) => Current::Child(child),
                        Err(error) => {
                            tracing::error!(%error, "could not restart the forwarding worker; stopping manager");
                            std::process::exit(1);
                        }
                    };
                }
                _ = stopped(shutdown) => {
                    if handoff_enabled() {
                        // Left serving for the next manager.
                        tracing::info!("manager stopping; the forwarding worker keeps its listeners for the next one");
                        return;
                    }
                    if let Current::Child(child) = &mut current {
                        if let Some(pid) = child.id() {
                            unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM); }
                        }
                        if tokio::time::timeout(Duration::from_secs(30), child.wait()).await.is_err() {
                            let _ = child.start_kill();
                            let _ = child.wait().await;
                        }
                    }
                    return;
                }
            }
        }
    }
}

#[async_trait]
impl BackgroundService for Supervisor {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let (requests, snapshots) = self.prepare().unwrap_or_else(|error| {
            tracing::error!(%error, "cannot open the worker control directory; stopping manager");
            std::process::exit(1);
        });
        let manager_id = {
            let mut id = [0u8; 8];
            openssl::rand::rand_bytes(&mut id).expect("entropy for a manager id");
            u64::from_le_bytes(id)
        };
        let exits = Arc::new(Exits::default());
        let mut tasks = JoinSet::new();
        {
            let exits = exits.clone();
            tasks.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    exits.poll();
                }
            });
        }
        {
            let (control, metrics, access, security, exits) = (
                self.control.clone(),
                self.metrics.clone(),
                self.access_log.clone(),
                self.security.clone(),
                exits.clone(),
            );
            tasks.spawn(async move {
                loop {
                    let Ok((stream, _)) = requests.accept().await else {
                        continue;
                    };
                    let pid = stream.peer_cred().ok().and_then(|c| c.pid());
                    let exited = exits.subscribe(pid);
                    let (control, metrics, access, security) = (
                        control.clone(),
                        metrics.clone(),
                        access.clone(),
                        security.clone(),
                    );
                    tokio::spawn(async move {
                        if let Err(error) = worker_rpc::serve(
                            stream, control, metrics, access, security, exited, manager_id,
                        )
                        .await
                        {
                            tracing::debug!(%error, "worker request control ended");
                        }
                    });
                }
            });
        }
        {
            let (certs, proxy_addr, tls_addr) = (
                self.certs.clone(),
                self.proxy_addr.clone(),
                self.tls_addr.clone(),
            );
            tasks.spawn(async move {
                loop {
                    let Ok((mut stream, _)) = snapshots.accept().await else {
                        continue;
                    };
                    let bootstrap = Bootstrap {
                        version: VERSION,
                        proxy_addr: proxy_addr.clone(),
                        tls_addr: tls_addr.clone(),
                        certificates: certs
                            .snapshot()
                            .unwrap_or_else(|e| supervision_failed(&e.to_string())),
                    };
                    tokio::spawn(async move {
                        if let Err(error) = worker_rpc::write_frame(&mut stream, &bootstrap).await {
                            tracing::debug!(%error, "worker bootstrap connection ended");
                        }
                    });
                }
            });
        }
        self.supervise(&mut shutdown).await;
        tasks.abort_all();
    }
}

// ---- the worker's side --------------------------------------------------------------

/// The request-control socket, for asking who the manager is now.
static REQUESTS: OnceLock<PathBuf> = OnceLock::new();

/// The id of the manager answering now, if any answers.
async fn current_manager() -> Option<u64> {
    let path = REQUESTS.get()?;
    tokio::time::timeout(Duration::from_secs(2), worker_rpc::hello(path))
        .await
        .ok()?
        .ok()?
}

/// A request lost its link to the manager that began it. If that manager is
/// still the one answering, the link failed under it — a protocol fault — and
/// the worker exits as it always has, which is what releases the admission
/// state that request holds. If that manager is gone, this is a restart: the
/// state went with it, and the worker carries on.
pub fn control_interrupted(manager: Option<u64>, error: &str) {
    let Some(id) = manager else {
        control_lost(error)
    };
    if !handoff_enabled() {
        control_lost(error);
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        control_lost(error)
    };
    let error = error.to_string();
    handle.spawn(async move {
        if current_manager().await == Some(id) {
            control_lost(&error);
        }
        tracing::debug!(%error, "the manager that began a request has gone; carrying on");
    });
}

async fn bootstrap(dir: &Path) -> Result<Bootstrap, String> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = UnixStream::connect(dir.join("bootstrap"))
            .await
            .map_err(|e| e.to_string())?;
        let value: Bootstrap = worker_rpc::read_frame(&mut stream).await?;
        if value.version != VERSION {
            return Err("worker bootstrap protocol mismatch".into());
        }
        Ok(value)
    })
    .await
    .map_err(|_| "worker bootstrap timed out".to_string())?
}

/// Refreshes certificates from the manager, and notices when no manager has
/// answered for too long.
struct CertificateWatch {
    dir: PathBuf,
    certs: Arc<CertStore>,
}
#[async_trait]
impl BackgroundService for CertificateWatch {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let orphan = orphan_timeout();
        let mut unanswered_since: Option<Instant> = None;
        loop {
            tokio::select! {
                _ = stopped(&mut shutdown) => return,
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
            match bootstrap(&self.dir).await {
                Ok(snapshot) => {
                    if unanswered_since.take().is_some() {
                        tracing::info!("a manager answers again");
                    }
                    self.certs
                        .replace_snapshot(snapshot.certificates)
                        .unwrap_or_else(|error| control_lost(&error.to_string()));
                }
                Err(error) => {
                    let Some(orphan) = orphan else {
                        control_lost(&error)
                    };
                    let since = *unanswered_since.get_or_insert_with(|| {
                        tracing::warn!(%error, "no manager answers; serving on and waiting for the next one");
                        Instant::now()
                    });
                    if since.elapsed() >= orphan {
                        tracing::warn!(
                            secs = orphan.as_secs(),
                            "no manager came back; draining and exiting"
                        );
                        // pingora's graceful terminate: stop accepting, drain, exit.
                        unsafe {
                            libc::kill(libc::getpid(), libc::SIGTERM);
                        }
                        return;
                    }
                }
            }
        }
    }
}

/// Called before any persistent management store is opened.
pub fn run(dir: PathBuf, takeover: bool) -> ! {
    crate::init_tracing(None);
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let _ = REQUESTS.set(dir.join("requests"));
    let initial = {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("worker bootstrap runtime");
        runtime
            .block_on(bootstrap(&dir))
            .unwrap_or_else(|error| control_lost(&error))
    };
    let certs = Arc::new(
        CertStore::from_snapshot(initial.certificates)
            .unwrap_or_else(|error| control_lost(&error.to_string())),
    );
    // The configuration `Server::new(None)` builds, with the handover socket
    // and the drain. On SIGQUIT (a takeover) and SIGTERM alike: stop
    // accepting, keep serving what is open for the drain, then give the
    // runtimes a minute.
    let mut conf = ServerConf::new().expect("pingora's default configuration");
    conf.upgrade_sock = dir.join("upgrade").to_string_lossy().into_owned();
    conf.grace_period_seconds = Some(env_secs(DRAIN_ENV).unwrap_or(DEFAULT_DRAIN));
    conf.graceful_shutdown_timeout_seconds = Some(SHUTDOWN_TIMEOUT);
    conf.upgrade_sock_connect_accept_max_retries = Some(TAKEOVER_RETRIES);
    let opt = Opt {
        upgrade: takeover,
        ..Opt::default()
    };
    let mut server = Server::new_with_opt_and_conf(Some(opt), conf);
    server.bootstrap();
    if takeover {
        tracing::info!("received the listening sockets from the previous worker");
    }
    let mut app = pingora_proxy::HttpProxy::new(
        crate::proxy::LbProxy::new(Client::new(dir.join("requests"))),
        server.configuration.clone(),
    );
    app.handle_init_modules();
    let mut proxy = pingora_core::services::listening::Service::new(
        "Pingora HTTP Proxy Service".to_string(),
        Lingering {
            inner: Arc::new(app),
        },
    );
    proxy.add_tcp(&initial.proxy_addr);
    if let Some(addr) = initial.tls_addr {
        let settings = pingora_core::listeners::tls::TlsSettings::with_callbacks(Box::new(
            SniResolver::new(certs.clone()),
        ))
        .expect("worker TLS settings");
        proxy.add_tls_with_settings(&addr, None, settings);
    }
    server.add_service(background_service(
        "worker-certificates",
        CertificateWatch { dir, certs },
    ));
    server.add_service(proxy);
    server.run_forever();
}

/// The proxy, with pingora's shutdown cleanup deferred by [`LINGER`].
///
/// On shutdown pingora stops accepting and, in the same instant, drops every
/// connection still waiting for its request — idle keep-alives, but also one
/// accepted a moment ago whose request is still in flight. In a takeover the
/// old worker accepts until that instant, so that second kind is a request
/// lost to the restart. Cleanup runs only after the accept loops have ended,
/// so waiting here lets those requests arrive and be served; only connections
/// idle for the whole wait are closed.
struct Lingering<T> {
    inner: Arc<T>,
}

#[async_trait]
impl<T> pingora_core::apps::HttpServerApp for Lingering<T>
where
    T: pingora_core::apps::HttpServerApp + Send + Sync + 'static,
{
    async fn process_new_http(
        self: &Arc<Self>,
        session: pingora_core::protocols::http::ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<pingora_core::apps::ReusedHttpStream> {
        self.inner.process_new_http(session, shutdown).await
    }

    fn h2_options(&self) -> Option<pingora_core::protocols::http::v2::server::H2Options> {
        self.inner.h2_options()
    }

    fn server_options(&self) -> Option<&pingora_core::apps::HttpServerOptions> {
        self.inner.server_options()
    }

    async fn http_cleanup(&self) {
        tokio::time::sleep(LINGER).await;
        self.inner.http_cleanup().await;
    }
}

pub fn control_lost(error: &str) -> ! {
    tracing::error!(%error, "worker lost management authority; exiting before replacement");
    std::process::exit(1)
}

fn supervision_failed(error: &str) -> ! {
    tracing::error!(%error, "worker supervision failed; stopping management authority");
    std::process::exit(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_process_is_known_by_pid_and_start_time() {
        let me = std::process::id() as i32;
        let started = start_time(me).expect("this process has a start time");
        assert!(alive(WorkerRecord {
            pid: me,
            start_time: started
        }));
        assert!(
            !alive(WorkerRecord {
                pid: me,
                start_time: started + 1
            }),
            "a reused pid is another process"
        );
        assert!(start_time(i32::MAX).is_none());
    }

    #[test]
    fn only_a_worker_for_this_directory_is_taken_over() {
        let me = std::process::id() as i32;
        assert!(
            !is_worker_for(me, Path::new("/nowhere")),
            "a test binary is no worker"
        );
    }

    #[tokio::test]
    async fn exits_fire_when_the_process_goes() {
        let exits = Exits::default();
        assert!(
            *exits.subscribe(None).borrow(),
            "unknown peer: nothing to wait for"
        );
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut rx = exits.subscribe(Some(child.id() as i32));
        exits.poll();
        assert!(!*rx.borrow());
        child.kill().unwrap();
        child.wait().unwrap();
        exits.poll();
        tokio::time::timeout(Duration::from_secs(2), rx.wait_for(|e| *e))
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn handoff_is_on_unless_the_orphan_timeout_is_zero() {
        // Read through the same parser the worker uses; the env is shared, so
        // only the parsing is tested here.
        assert_eq!(env_secs("APP_LB_TEST_UNSET_VARIABLE"), None);
        assert_eq!(DEFAULT_ORPHAN, Duration::from_secs(120));
    }

    #[test]
    fn the_control_directory_sits_beside_the_state() {
        assert_eq!(
            worker_dir("/var/lib/app-lb/app-lb-state.json"),
            Path::new("/var/lib/app-lb/app-lb-worker.d")
        );
    }
}
