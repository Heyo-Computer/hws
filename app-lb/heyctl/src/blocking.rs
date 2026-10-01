//! The same surface, without `await`.
//!
//! For callers with no runtime — a CLI, a build script, a test. Every method
//! forwards to the async client on a private current-thread runtime.
//!
//! ```no_run
//! # fn f() -> hws::Result<()> {
//! use hws::blocking::Client;
//! use hws::ExecRequest;
//!
//! let lb = Client::builder("127.0.0.1:9090").token("applb_…").build()?;
//! let out = lb.exec("sb-7f3a9c", &ExecRequest::new("uname -a"))?;
//! println!("{}", out.stdout);
//! # Ok(()) }
//! ```
//!
//! **Do not call these from inside an async context.** `block_on` inside a
//! runtime panics in tokio; this crate detects that and returns
//! [`Error::Invalid`] instead, because a panic from a library that only says
//! "cannot block the current thread" is a bad way to learn you wanted
//! [`crate::Client`].

use crate::api::{ExecRequest, Gates, MetricsQuery, NewToken};
use crate::error::{Error, Result};
use crate::shell::{ShellEvent, ShellExit, ShellOptions};
use crate::transport::Auth;
use crate::types::*;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

/// The private runtime, shut down without blocking.
///
/// A plain `Runtime` panics when dropped from a thread where blocking is not
/// allowed — which is exactly where a caller who built one inside
/// `spawn_blocking` will drop it. `shutdown_background` detaches instead, so
/// letting a blocking client fall out of scope is never the thing that panics.
struct Rt(Option<tokio::runtime::Runtime>);

impl Drop for Rt {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
}

impl std::ops::Deref for Rt {
    type Target = tokio::runtime::Runtime;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("the runtime outlives every use of it")
    }
}

/// Runs one future to completion, refusing rather than panicking when there is
/// already a runtime on this thread.
fn block_on<F: std::future::Future>(rt: &Rt, f: F) -> Result<F::Output> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(Error::Invalid(
            "hws::blocking cannot be used inside an async runtime — use \
             hws::Client instead"
                .into(),
        ));
    }
    Ok(rt.block_on(f))
}

/// A blocking client for one app-lb.
pub struct Client {
    inner: crate::Client,
    rt: Arc<Rt>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

/// `let x = self.run(self.inner.foo(a, b))?;` with the double-Result flattened.
macro_rules! run {
    ($self:expr, $call:expr) => {
        block_on(&$self.rt, $call)?
    };
}

impl Client {
    pub fn new(server: impl Into<String>, auth: Auth) -> Result<Self> {
        Self::builder(server).auth(auth).build()
    }

    pub fn builder(server: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            inner: crate::Client::builder(server),
        }
    }

    /// The async client underneath, for a caller that acquires a runtime later.
    pub fn into_async(self) -> crate::Client {
        self.inner
    }

    // -- health and discovery ----------------------------------------------

    /// Connect with an optional username and password — the shape a CLI has
    /// after merging flags, environment and a saved context, where either half
    /// may be absent.
    pub fn connect(
        server: &str,
        user: Option<&str>,
        password: Option<&str>,
        token: Option<&str>,
        insecure: bool,
        timeout: Duration,
    ) -> Result<Self> {
        let auth = match (token, user, password) {
            // A bearer outranks the pair: it is the only credential Cloud's
            // namespace door accepts, and a context that has one meant it.
            (Some(t), _, _) => Auth::Token(t.to_string()),
            (None, Some(u), Some(p)) => Auth::Basic {
                user: u.to_string(),
                password: p.to_string(),
            },
            // A username with no password cannot authenticate anything, so it is
            // no credential at all rather than half of one.
            _ => Auth::None,
        };
        Self::builder(server)
            .auth(auth)
            .insecure(insecure)
            .timeout(timeout)
            .build()
    }

    /// Connect with an app-token.
    pub fn connect_with_token(
        server: &str,
        token: &str,
        insecure: bool,
        timeout: Duration,
    ) -> Result<Self> {
        Self::builder(server)
            .token(token)
            .insecure(insecure)
            .timeout(timeout)
            .build()
    }

    pub fn server(&self) -> &str {
        self.inner.server().unwrap_or_default()
    }

    pub fn has_credentials(&self) -> bool {
        self.inner.has_credentials()
    }

    /// The status a `GET` answers with, without treating 4xx as an error.
    pub fn status_of(&self, path: &str) -> Result<u16> {
        run!(self, self.inner.probe(path))
    }

    /// The status and the server's own explanation, when it gave one.
    pub fn status_detail_of(&self, path: &str) -> Result<(u16, Option<String>)> {
        run!(self, self.inner.probe_detail(path))
    }

    pub fn healthz(&self) -> Result<()> {
        run!(self, self.inner.healthz())
    }

    /// Which tiers a server is gating, probed anonymously.
    pub fn gates(server: &str, insecure: bool, timeout: Duration) -> Result<Gates> {
        let probe = Self::builder(server).insecure(insecure).timeout(timeout).build()?;
        block_on(&probe.rt, crate::Client::gates(server, insecure))?
    }

    /// Which tiers the server this client points at is gating.
    ///
    /// Probes anonymously even though this client holds a credential — the
    /// question is what an *unauthenticated* caller is refused, which is what
    /// says whether the gate is on at all.
    pub fn gates_of(client: &Self) -> Result<Gates> {
        block_on(&client.rt, crate::Client::gates(client.server(), false))?
    }

    // -- deployments --------------------------------------------------------

    pub fn deployments(&self) -> Result<Vec<DeploymentStatus>> {
        run!(self, self.inner.deployments())
    }

    pub fn deployment(&self, id: &str) -> Result<DeploymentStatus> {
        run!(self, self.inner.deployment(id))
    }

    pub fn deployment_with_timeout(
        &self,
        id: &str,
        timeout: std::time::Duration,
    ) -> Result<DeploymentStatus> {
        run!(self, self.inner.deployment_with_timeout(id, timeout))
    }

    pub fn deployment_exists(&self, id: &str) -> Result<bool> {
        run!(self, self.inner.deployment_exists(id))
    }

    pub fn create_deployment(&self, spec: &Value) -> Result<DeploymentStatus> {
        run!(self, self.inner.create_deployment(spec))
    }

    pub fn replace_deployment(&self, id: &str, spec: &Value) -> Result<DeploymentStatus> {
        run!(self, self.inner.replace_deployment(id, spec))
    }

    pub fn patch_scaling(&self, id: &str, patch: &Value) -> Result<DeploymentStatus> {
        run!(self, self.inner.patch_scaling(id, patch))
    }

    pub fn delete_deployment(&self, id: &str) -> Result<()> {
        run!(self, self.inner.delete_deployment(id))
    }

    pub fn evict_vm(&self, id: &str, sandbox: &str, force: bool) -> Result<EvictOutcome> {
        run!(self, self.inner.evict_vm(id, sandbox, force))
    }

    pub fn cordon_upstream(
        &self,
        id: &str,
        upstream: &str,
        force: bool,
        reason: Option<&str>,
    ) -> Result<UpstreamTrafficStatus> {
        run!(
            self,
            self.inner.cordon_upstream(id, upstream, force, reason)
        )
    }

    pub fn uncordon_upstream(&self, id: &str, upstream: &str) -> Result<UpstreamTrafficStatus> {
        run!(self, self.inner.uncordon_upstream(id, upstream))
    }

    pub fn deployment_ids(&self, page: usize) -> Result<Vec<String>> {
        run!(self, self.inner.deployment_ids(page))
    }

    // -- running things inside a VM ----------------------------------------

    pub fn exec(&self, id: &str, req: &ExecRequest) -> Result<ExecOutput> {
        run!(self, self.inner.exec(id, req))
    }

    /// Attach an interactive shell.
    pub fn shell(&self, id: &str, opts: &ShellOptions) -> Result<Shell> {
        let inner = run!(self, self.inner.shell(id, opts))?;
        Ok(Shell {
            inner,
            rt: self.rt.clone(),
        })
    }

    // -- workflows ----------------------------------------------------------

    pub fn workflows(&self) -> Result<Vec<WorkflowView>> {
        run!(self, self.inner.workflows())
    }

    pub fn workflow(&self, id: &str) -> Result<WorkflowView> {
        run!(self, self.inner.workflow(id))
    }

    pub fn create_workflow(&self, spec: &Value) -> Result<WorkflowView> {
        run!(self, self.inner.create_workflow(spec))
    }

    pub fn replace_workflow(&self, id: &str, spec: &Value) -> Result<WorkflowView> {
        run!(self, self.inner.replace_workflow(id, spec))
    }

    pub fn delete_workflow(&self, id: &str) -> Result<()> {
        run!(self, self.inner.delete_workflow(id))
    }

    // -- secrets ------------------------------------------------------------

    pub fn secrets(&self) -> Result<Vec<SecretSummary>> {
        run!(self, self.inner.secrets())
    }

    pub fn secrets_in(&self, namespace: Option<&str>) -> Result<Vec<SecretSummary>> {
        run!(self, self.inner.secrets_in(namespace))
    }

    pub fn secret(&self, id: &str) -> Result<SecretSummary> {
        run!(self, self.inner.secret(id))
    }

    pub fn secret_in(&self, namespace: Option<&str>, id: &str) -> Result<SecretSummary> {
        run!(self, self.inner.secret_in(namespace, id))
    }

    pub fn secret_exists(&self, id: &str) -> Result<bool> {
        run!(self, self.inner.secret_exists(id))
    }

    pub fn secret_exists_in(&self, namespace: Option<&str>, id: &str) -> Result<bool> {
        run!(self, self.inner.secret_exists_in(namespace, id))
    }

    pub fn put_secret(&self, spec: &Value) -> Result<SecretSummary> {
        run!(self, self.inner.put_secret(spec))
    }

    pub fn patch_secret(&self, id: &str, patch: &Value) -> Result<SecretSummary> {
        run!(self, self.inner.patch_secret(id, patch))
    }

    pub fn patch_secret_in(
        &self,
        namespace: Option<&str>,
        id: &str,
        patch: &Value,
    ) -> Result<SecretSummary> {
        run!(self, self.inner.patch_secret_in(namespace, id, patch))
    }

    pub fn delete_secret(&self, id: &str, force: bool) -> Result<()> {
        run!(self, self.inner.delete_secret(id, force))
    }

    pub fn delete_secret_in(&self, namespace: Option<&str>, id: &str, force: bool) -> Result<()> {
        run!(self, self.inner.delete_secret_in(namespace, id, force))
    }

    // -- auth providers ------------------------------------------------------

    pub fn auth_providers(&self, namespace: Option<&str>) -> Result<Vec<AuthProviderView>> {
        run!(self, self.inner.auth_providers(namespace))
    }

    pub fn auth_provider(&self, namespace: &str, name: &str) -> Result<AuthProviderView> {
        run!(self, self.inner.auth_provider(namespace, name))
    }

    pub fn auth_provider_exists(&self, namespace: &str, name: &str) -> Result<bool> {
        run!(self, self.inner.auth_provider_exists(namespace, name))
    }

    pub fn create_auth_provider(&self, spec: &Value) -> Result<AuthProviderView> {
        run!(self, self.inner.create_auth_provider(spec))
    }

    pub fn delete_auth_provider(&self, namespace: &str, name: &str) -> Result<()> {
        run!(self, self.inner.delete_auth_provider(namespace, name))
    }

    // -- app-tokens ---------------------------------------------------------

    /// Mint a token. The secret in the reply is shown once.
    pub fn mint_token(&self, req: &NewToken) -> Result<MintedToken> {
        run!(self, self.inner.mint_token(req))
    }

    pub fn tokens(&self) -> Result<Vec<TokenSummary>> {
        run!(self, self.inner.tokens())
    }

    pub fn token(&self, id: &str) -> Result<TokenSummary> {
        run!(self, self.inner.token(id))
    }

    pub fn patch_token(&self, id: &str, patch: &Value) -> Result<TokenSummary> {
        run!(self, self.inner.patch_token(id, patch))
    }

    pub fn revoke_token(&self, id: &str) -> Result<()> {
        run!(self, self.inner.revoke_token(id))
    }

    // -- the event feed ------------------------------------------------------

    pub fn namespaces(&self) -> Result<Vec<NamespaceEntry>> {
        run!(self, self.inner.namespaces())
    }

    pub fn create_namespace(&self, spec: &Value) -> Result<Value> {
        run!(self, self.inner.create_namespace(spec))
    }

    pub fn delete_namespace(&self, name: &str) -> Result<()> {
        run!(self, self.inner.delete_namespace(name))
    }

    pub fn feeds(&self) -> Result<Vec<FeedIndexEntry>> {
        run!(self, self.inner.feeds())
    }

    pub fn feed_events(&self, namespace: &str) -> Result<Vec<FeedEvent>> {
        run!(self, self.inner.feed_events(namespace))
    }

    pub fn feed_rss(&self, namespace: &str) -> Result<String> {
        run!(self, self.inner.feed_rss(namespace))
    }

    // -- jobs ---------------------------------------------------------------

    pub fn start_build(&self, id: &str, git_ref: Option<&str>) -> Result<JobRecord> {
        run!(self, self.inner.start_build(id, git_ref))
    }

    pub fn start_pull(&self, id: &str, artifact_ref: Option<&str>, force: bool) -> Result<JobRecord> {
        run!(self, self.inner.start_pull(id, artifact_ref, force))
    }

    pub fn start_mount_pull(&self, id: &str, force: bool) -> Result<JobRecord> {
        run!(self, self.inner.start_mount_pull(id, force))
    }

    pub fn start_update(&self, id: &str) -> Result<JobRecord> {
        run!(self, self.inner.start_update(id))
    }

    pub fn jobs(&self) -> Result<Vec<JobRecord>> {
        run!(self, self.inner.jobs())
    }

    pub fn deployment_jobs(&self, id: &str) -> Result<Vec<JobRecord>> {
        run!(self, self.inner.deployment_jobs(id))
    }

    pub fn job(&self, job_id: &str) -> Result<JobRecord> {
        run!(self, self.inner.job(job_id))
    }

    /// Poll a job until it finishes, reporting new log lines as they arrive.
    pub fn wait_for_job(
        &self,
        job_id: &str,
        timeout: Duration,
        on_progress: impl FnMut(crate::wait::JobProgress<'_>) + Send,
    ) -> Result<JobRecord> {
        run!(
            self,
            self.inner
                .wait_for_job(job_id)
                .timeout(timeout)
                .on_progress(on_progress)
                .await_done()
        )
    }

    /// Poll a deployment until its pool has converged.
    pub fn wait_for_ready(
        &self,
        id: &str,
        timeout: Duration,
        on_progress: impl FnMut(crate::wait::PoolProgress) + Send,
    ) -> Result<DeploymentStatus> {
        run!(
            self,
            self.inner
                .wait_for_ready(id)
                .timeout(timeout)
                .on_progress(on_progress)
                .await_ready()
        )
    }

    // -- observability ------------------------------------------------------

    pub fn metrics(&self, query: &MetricsQuery) -> Result<MetricsResponse> {
        run!(self, self.inner.metrics(query))
    }

    pub fn certs(&self) -> Result<Vec<CertStatus>> {
        run!(self, self.inner.certs())
    }

    pub fn disks(&self) -> Result<DiskInventory> {
        run!(self, self.inner.disks())
    }

    // -- plugins ------------------------------------------------------------

    pub fn plugins(&self) -> Result<Vec<PluginView>> {
        run!(self, self.inner.plugins())
    }

    pub fn plugin(&self, id: &str) -> Result<PluginView> {
        run!(self, self.inner.plugin(id))
    }

    pub fn set_plugin(&self, id: &str, enabled: bool, config: Option<&Value>) -> Result<PluginView> {
        run!(self, self.inner.set_plugin(id, enabled, config))
    }
}

pub struct ClientBuilder {
    inner: crate::ClientBuilder,
}

impl ClientBuilder {
    pub fn auth(mut self, auth: Auth) -> Self {
        self.inner = self.inner.auth(auth);
        self
    }

    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.inner = self.inner.token(token);
        self
    }

    pub fn basic(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.inner = self.inner.basic(user, password);
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.inner = self.inner.timeout(d);
        self
    }

    pub fn insecure(mut self, yes: bool) -> Self {
        self.inner = self.inner.insecure(yes);
        self
    }

    pub fn build(self) -> Result<Client> {
        // Current-thread: this runtime serves one caller making one request at a
        // time, which is the whole reason to be using the blocking facade.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Invalid(format!("could not start a runtime: {e}")))?;
        Ok(Client {
            inner: self.inner.build()?,
            rt: Arc::new(Rt(Some(rt))),
        })
    }
}

/// A blocking shell session.
pub struct Shell {
    inner: crate::Shell,
    rt: Arc<Rt>,
}

impl Shell {
    pub fn sandbox_id(&self) -> &str {
        self.inner.sandbox_id()
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        block_on(&self.rt, self.inner.write(bytes))?
    }

    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        block_on(&self.rt, self.inner.resize(cols, rows))?
    }

    /// Like [`Iterator::next`] but gives up after `d` so a caller can do something
    /// else — check for stdin, redraw, notice a signal — and come back.
    pub fn next_timeout(&mut self, d: Duration) -> Option<ShellEvent> {
        block_on(&self.rt, async {
            tokio::time::timeout(d, self.inner.next()).await.ok().flatten()
        })
        .ok()
        .flatten()
    }

    pub fn exit(&self) -> Option<&ShellExit> {
        self.inner.exit()
    }

    pub fn close(&mut self) -> Result<()> {
        block_on(&self.rt, self.inner.close())?
    }
}

/// A session *is* a sequence of events that ends, so it iterates.
///
/// ```no_run
/// # fn f(shell: &mut hws::blocking::Shell) {
/// use hws::ShellEvent;
/// for event in shell.by_ref() {
///     if let ShellEvent::Output(bytes) = event {
///         // …
///     }
/// }
/// # }
/// ```
///
/// Each call blocks until something happens, so a caller that also needs to send
/// stdin wants a thread per direction — which is what a terminal does anyway, or
/// [`Shell::next_timeout`] to interleave on one.
impl Iterator for Shell {
    type Item = ShellEvent;

    fn next(&mut self) -> Option<ShellEvent> {
        block_on(&self.rt, self.inner.next()).ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_can_be_built_and_answers_without_a_runtime() {
        // Nothing to connect to; the point is that constructing one and calling
        // a method does not need the caller to have a runtime.
        let c = Client::builder("127.0.0.1:1").timeout(Duration::from_millis(50)).build().unwrap();
        let e = c.healthz().unwrap_err();
        assert!(matches!(e, Error::Transport(_)), "{e:?}");
    }

    /// tokio panics on a nested `block_on`. A panic from a library that only
    /// says "cannot block the current thread" is a bad way to find out you
    /// wanted the async client, so this is an error instead.
    #[tokio::test]
    async fn calling_it_from_inside_a_runtime_is_refused_not_a_panic() {
        let c = tokio::task::spawn_blocking(|| {
            Client::builder("127.0.0.1:1")
                .timeout(Duration::from_millis(50))
                .build()
                .unwrap()
        })
        .await
        .unwrap();

        let e = c.healthz().unwrap_err();
        assert!(matches!(&e, Error::Invalid(m) if m.contains("async runtime")), "{e:?}");
        assert!(e.to_string().contains("hws::Client"), "it should name the fix: {e}");
    }
}

/// Unparsed reads. See [`crate::api::Client::raw`].
pub struct Raw<'a> {
    client: &'a Client,
}

impl Client {
    /// The same reads, as unparsed JSON — for printing a response without
    /// losing whatever this build does not name, and for the read half of a
    /// read-modify-write.
    pub fn raw(&self) -> Raw<'_> {
        Raw { client: self }
    }
}

macro_rules! raw_blocking {
    ($($name:ident),* $(,)?) => {
        $(
            pub fn $name(&self) -> Result<Value> {
                block_on(&self.client.rt, self.client.inner.raw().$name())?
            }
        )*
    };
}

macro_rules! raw_blocking_id {
    ($($name:ident),* $(,)?) => {
        $(
            pub fn $name(&self, id: &str) -> Result<Value> {
                block_on(&self.client.rt, self.client.inner.raw().$name(id))?
            }
        )*
    };
}

impl Raw<'_> {
    raw_blocking!(deployments, secrets, tokens, jobs, certs, workflows, feeds, disks, namespaces, plugins);

    /// Deployments in one namespace. See [`crate::api::Raw::deployments_in`].
    pub fn deployments_in(&self, namespace: &str) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().deployments_in(namespace))?
    }
    raw_blocking_id!(deployment, secret, token, job, deployment_jobs, spec, workflow);

    pub fn metrics(&self, query: &MetricsQuery) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().metrics(query))?
    }

    pub fn create_deployment(&self, spec: &Value) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().create_deployment(spec))?
    }

    pub fn replace_deployment(&self, id: &str, spec: &Value) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().replace_deployment(id, spec))?
    }

    pub fn patch_scaling(&self, id: &str, patch: &Value) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().patch_scaling(id, patch))?
    }

    pub fn put_secret(&self, spec: &Value) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().put_secret(spec))?
    }

    pub fn patch_secret(&self, id: &str, patch: &Value) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().patch_secret(id, patch))?
    }

    pub fn patch_secret_in(
        &self,
        namespace: Option<&str>,
        id: &str,
        patch: &Value,
    ) -> Result<Value> {
        block_on(
            &self.client.rt,
            self.client.inner.raw().patch_secret_in(namespace, id, patch),
        )?
    }

    pub fn feed_events(&self, namespace: &str) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().feed_events(namespace))?
    }

    pub fn secrets_in(&self, namespace: Option<&str>) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().secrets_in(namespace))?
    }

    pub fn secret_in(&self, namespace: Option<&str>, id: &str) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().secret_in(namespace, id))?
    }

    pub fn auth_providers(&self, namespace: Option<&str>) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().auth_providers(namespace))?
    }

    pub fn auth_provider(&self, namespace: &str, name: &str) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().auth_provider(namespace, name))?
    }

    pub fn mint_token(&self, req: &NewToken) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().mint_token(req))?
    }

    pub fn patch_token(&self, id: &str, patch: &Value) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().patch_token(id, patch))?
    }

    pub fn evict_vm(&self, id: &str, sandbox: &str, force: bool) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().evict_vm(id, sandbox, force))?
    }

    pub fn cordon_upstream(
        &self,
        id: &str,
        upstream: &str,
        force: bool,
        reason: Option<&str>,
    ) -> Result<Value> {
        block_on(
            &self.client.rt,
            self.client
                .inner
                .raw()
                .cordon_upstream(id, upstream, force, reason),
        )?
    }

    pub fn uncordon_upstream(&self, id: &str, upstream: &str) -> Result<Value> {
        block_on(
            &self.client.rt,
            self.client.inner.raw().uncordon_upstream(id, upstream),
        )?
    }

    pub fn start_build(&self, id: &str, git_ref: Option<&str>) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().start_build(id, git_ref))?
    }

    pub fn start_pull(&self, id: &str, r: Option<&str>, force: bool) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().start_pull(id, r, force))?
    }

    pub fn start_mount_pull(&self, id: &str, force: bool) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().start_mount_pull(id, force))?
    }

    pub fn start_update(&self, id: &str) -> Result<Value> {
        block_on(&self.client.rt, self.client.inner.raw().start_update(id))?
    }
}
