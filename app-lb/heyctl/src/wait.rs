//! Waiting for things to converge.
//!
//! app-lb answers `POST /deployments/:id/build` with `202` and a job id. It
//! answers a spec change immediately, while the pool it describes takes a
//! minute to exist. Both leave the caller holding a promise and a polling
//! problem, and both predicates are fiddly enough that everyone gets them
//! slightly wrong:
//!
//! - a job is done when its `status` stops being `running` — but its `log` grows
//!   while it runs, so a caller that wants progress has to track how much it has
//!   already seen;
//! - a pool has converged when nothing is pending, enough backends are
//!   *healthy*, and nothing is still draining. Counting `ready` alone reports
//!   success while a VM is still failing its health check, because `ready` is
//!   the size of the pool, not the healthy part of it.
//!
//! Both live here, with callbacks in place of the `println!`s they had while
//! they were CLI code.

use crate::api::{Client, MetricsQuery};
use crate::error::{Error, Result};
use crate::types::{DeploymentStatus, JobRecord};
use std::time::{Duration, Instant};

/// How often to ask about a job. Builds and host updates run for minutes.
pub const JOB_POLL: Duration = Duration::from_secs(3);
/// How often to ask about a pool. A boot is tens of seconds.
pub const POOL_POLL: Duration = Duration::from_secs(2);

/// A job's state at one poll.
#[derive(Debug, Clone)]
pub struct JobProgress<'a> {
    pub job: &'a JobRecord,
    /// Log lines that appeared since the previous callback — not the whole log,
    /// so a caller can print them as they arrive without deduplicating.
    pub new_log: &'a [String],
}

/// A pool's state at one poll.
#[derive(Debug, Clone, Copy)]
pub struct PoolProgress {
    pub desired: u32,
    pub healthy: usize,
    pub pending: usize,
    pub draining: usize,
}

impl PoolProgress {
    /// Nothing booting, enough healthy backends, nothing draining.
    ///
    /// `healthy` rather than `ready`: `ready` counts every backend in the pool,
    /// including one whose health check is failing, so waiting on it reports
    /// success for a deployment that cannot serve a request.
    pub fn converged(&self) -> bool {
        self.pending == 0 && self.healthy >= self.desired as usize && self.draining == 0
    }
}

impl Client {
    /// Poll a job until it finishes.
    ///
    /// Returns the finished record whether it succeeded or failed — a failed job
    /// is an answer, not an error, and its `log` and `error` are the point. Only
    /// being unable to *ask* is an `Err`.
    ///
    /// ```no_run
    /// # async fn f(lb: &hws::Client) -> hws::Result<()> {
    /// let job = lb.start_build("api", None).await?;
    /// let done = lb.wait_for_job(&job.id)
    ///     .on_progress(|p| for line in p.new_log { println!("{line}"); })
    ///     .await?;
    /// if done.status != "succeeded" { eprintln!("{:?}", done.error); }
    /// # Ok(()) }
    /// ```
    pub fn wait_for_job<'a>(&'a self, job_id: &'a str) -> JobWaiter<'a> {
        JobWaiter {
            client: self,
            job_id,
            poll: JOB_POLL,
            timeout: Duration::from_secs(1800),
            on_progress: None,
        }
    }

    /// Poll a deployment until its pool has converged.
    ///
    /// A `site` or `upstreams` deployment has no pool to converge, so this
    /// returns as soon as it sees one — there is nothing to wait for.
    pub fn wait_for_ready<'a>(&'a self, id: &'a str) -> PoolWaiter<'a> {
        PoolWaiter {
            client: self,
            id,
            poll: POOL_POLL,
            timeout: Duration::from_secs(300),
            on_progress: None,
        }
    }
}

/// Builder for [`Client::wait_for_job`].
pub struct JobWaiter<'a> {
    client: &'a Client,
    job_id: &'a str,
    poll: Duration,
    timeout: Duration,
    #[allow(clippy::type_complexity)]
    on_progress: Option<Box<dyn FnMut(JobProgress<'_>) + Send + 'a>>,
}

impl<'a> JobWaiter<'a> {
    pub fn poll_every(mut self, d: Duration) -> Self {
        self.poll = d;
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    /// Called once per poll, with whatever log lines are new.
    pub fn on_progress(mut self, f: impl FnMut(JobProgress<'_>) + Send + 'a) -> Self {
        self.on_progress = Some(Box::new(f));
        self
    }

    pub async fn await_done(mut self) -> Result<JobRecord> {
        let started = Instant::now();
        let mut seen = 0usize;
        loop {
            let job = self.client.job(self.job_id).await?;

            if let Some(f) = self.on_progress.as_mut() {
                // Only the tail is new. app-lb keeps a bounded log, so if it
                // truncated from the front, `seen` can exceed the current
                // length — report nothing rather than panicking on the slice.
                let new = job.log.get(seen.min(job.log.len())..).unwrap_or(&[]);
                f(JobProgress {
                    job: &job,
                    new_log: new,
                });
            }
            seen = job.log.len();

            if job.status != "running" {
                return Ok(job);
            }
            if started.elapsed() >= self.timeout {
                return Err(Error::Timeout {
                    what: format!("job {}", self.job_id),
                    after: self.timeout,
                });
            }
            tokio::time::sleep(self.poll).await;
        }
    }
}

impl<'a> std::future::IntoFuture for JobWaiter<'a> {
    type Output = Result<JobRecord>;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.await_done())
    }
}

/// Builder for [`Client::wait_for_ready`].
pub struct PoolWaiter<'a> {
    client: &'a Client,
    id: &'a str,
    poll: Duration,
    timeout: Duration,
    #[allow(clippy::type_complexity)]
    on_progress: Option<Box<dyn FnMut(PoolProgress) + Send + 'a>>,
}

impl<'a> PoolWaiter<'a> {
    pub fn poll_every(mut self, d: Duration) -> Self {
        self.poll = d;
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    pub fn on_progress(mut self, f: impl FnMut(PoolProgress) + Send + 'a) -> Self {
        self.on_progress = Some(Box::new(f));
        self
    }

    pub async fn await_ready(mut self) -> Result<DeploymentStatus> {
        let started = Instant::now();
        loop {
            let status = self.client.deployment(self.id).await?;

            // Nothing to converge for a deployment with no VM pool.
            if status.kind != "vm" {
                return Ok(status);
            }

            let healthy = status.vms.iter().filter(|v| v.healthy && !v.draining).count();
            let draining = status.vms.iter().filter(|v| v.draining).count();
            let progress = PoolProgress {
                desired: status.desired_replicas,
                healthy,
                pending: status.pending,
                draining,
            };
            if let Some(f) = self.on_progress.as_mut() {
                f(progress);
            }
            if progress.converged() {
                return Ok(status);
            }
            if started.elapsed() >= self.timeout {
                return Err(Error::Timeout {
                    what: format!("deployment {}", self.id),
                    after: self.timeout,
                });
            }
            tokio::time::sleep(self.poll).await;
        }
    }
}

impl<'a> std::future::IntoFuture for PoolWaiter<'a> {
    type Output = Result<DeploymentStatus>;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.await_ready())
    }
}

impl Client {
    /// Every deployment, a page at a time.
    ///
    /// `GET /deployments` is unpaged and returns whole specs; at fleet scale
    /// that is megabytes. This walks `/metrics` instead, which pages, and
    /// asks for the summary form so per-VM detail is left behind.
    pub async fn deployment_ids(&self, page: usize) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut offset = 0;
        loop {
            let m = self
                .metrics(&MetricsQuery::new().summary(true).page(offset, page))
                .await?;
            out.extend(m.deployments.iter().map(|d| d.id.clone()));
            offset += page;
            if offset >= m.matched || m.deployments.is_empty() {
                return Ok(out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Client;
    use crate::transport::stub::Stub;
    use serde_json::json;
    use std::sync::Arc;

    fn job(status: &str, log: &[&str]) -> serde_json::Value {
        json!({
            "id": "j1", "deployment": "api", "kind": "image-build",
            "status": status, "started_at": 0,
            "log": log.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        })
    }

    #[tokio::test]
    async fn a_job_is_polled_until_it_stops_running() {
        let stub = Arc::new(
            Stub::new()
                .json(200, job("running", &["cloning"]))
                .json(200, job("running", &["cloning", "building"]))
                .json(200, job("succeeded", &["cloning", "building", "done"])),
        );
        let c = Client::with_transport(stub.clone());

        let mut seen: Vec<String> = Vec::new();
        let done = c
            .wait_for_job("j1")
            .poll_every(Duration::from_millis(1))
            .on_progress(|p| seen.extend(p.new_log.iter().cloned()))
            .await
            .unwrap();

        assert_eq!(done.status, "succeeded");
        // Each line reported exactly once, in order — the caller does not have
        // to deduplicate a growing log.
        assert_eq!(seen, ["cloning", "building", "done"]);
        assert_eq!(stub.call_count(), 3);
    }

    /// A failed job is an answer. Turning it into an `Err` would throw away the
    /// log and the error message, which are the only reason to have waited.
    #[tokio::test]
    async fn a_failed_job_returns_rather_than_erroring() {
        let stub = Arc::new(Stub::new().json(
            200,
            json!({"id": "j1", "deployment": "api", "kind": "image-build",
                   "status": "failed", "started_at": 0, "error": "exit 1",
                   "log": ["boom"]}),
        ));
        let done = Client::with_transport(stub)
            .wait_for_job("j1")
            .await
            .unwrap();
        assert_eq!(done.status, "failed");
        assert_eq!(done.error.as_deref(), Some("exit 1"));
    }

    /// app-lb keeps a bounded log, so it can shrink between polls.
    #[tokio::test]
    async fn a_truncated_log_does_not_panic_the_waiter() {
        let stub = Arc::new(
            Stub::new()
                .json(200, job("running", &["a", "b", "c", "d"]))
                .json(200, job("succeeded", &["d"])),
        );
        let mut seen = Vec::new();
        Client::with_transport(stub)
            .wait_for_job("j1")
            .poll_every(Duration::from_millis(1))
            .on_progress(|p| seen.push(p.new_log.len()))
            .await
            .unwrap();
        assert_eq!(seen, [4, 0], "a shrunken log yields nothing new, not a panic");
    }

    #[tokio::test]
    async fn a_job_that_never_finishes_times_out() {
        let stub = Arc::new(Stub::new().json(200, job("running", &[])));
        let e = Client::with_transport(stub)
            .wait_for_job("j1")
            .poll_every(Duration::from_millis(1))
            .timeout(Duration::from_millis(0))
            .await
            .unwrap_err();
        assert!(matches!(e, Error::Timeout { .. }), "{e:?}");
    }

    fn pool(desired: u32, pending: usize, vms: serde_json::Value) -> serde_json::Value {
        json!({"spec": {"id": "api"}, "kind": "vm", "desired_replicas": desired,
               "ready": vms.as_array().unwrap().len(), "pending": pending,
               "total_in_flight": 0, "vms": vms})
    }

    #[tokio::test]
    async fn a_pool_converges_only_when_its_vms_are_healthy() {
        let unhealthy = json!([{"sandbox_id": "a", "healthy": false, "draining": false}]);
        let healthy = json!([{"sandbox_id": "a", "healthy": true, "draining": false}]);
        let stub = Arc::new(
            Stub::new()
                .json(200, pool(1, 1, json!([])))       // still booting
                .json(200, pool(1, 0, unhealthy))       // in the pool, failing its check
                .json(200, pool(1, 0, healthy)),        // actually serving
        );
        let c = Client::with_transport(stub.clone());
        let mut ticks = Vec::new();
        c.wait_for_ready("api")
            .poll_every(Duration::from_millis(1))
            .on_progress(|p| ticks.push((p.healthy, p.pending)))
            .await
            .unwrap();
        assert_eq!(ticks, [(0, 1), (0, 0), (1, 0)]);
        assert_eq!(
            stub.call_count(),
            3,
            "a VM in the pool but failing its health check is not convergence"
        );
    }

    #[tokio::test]
    async fn a_draining_vm_holds_convergence_open() {
        let mixed = json!([
            {"sandbox_id": "a", "healthy": true, "draining": false},
            {"sandbox_id": "b", "healthy": true, "draining": true},
        ]);
        let settled = json!([{"sandbox_id": "a", "healthy": true, "draining": false}]);
        let stub = Arc::new(
            Stub::new()
                .json(200, pool(1, 0, mixed))
                .json(200, pool(1, 0, settled)),
        );
        Client::with_transport(stub.clone())
            .wait_for_ready("api")
            .poll_every(Duration::from_millis(1))
            .await
            .unwrap();
        assert_eq!(stub.call_count(), 2);
    }

    /// A site serves off disk and a static deployment proxies to fixed
    /// addresses; neither has a pool, so waiting for one would never return.
    #[tokio::test]
    async fn a_deployment_with_no_pool_is_immediately_ready() {
        for kind in ["site", "static"] {
            let stub = Arc::new(Stub::new().json(
                200,
                json!({"spec": {"id": "docs"}, "kind": kind, "desired_replicas": 0,
                       "ready": 0, "pending": 0, "total_in_flight": 0, "vms": []}),
            ));
            let c = Client::with_transport(stub.clone());
            c.wait_for_ready("docs")
                .poll_every(Duration::from_millis(1))
                .await
                .unwrap();
            assert_eq!(stub.call_count(), 1, "{kind} should not be waited on");
        }
    }

    #[test]
    fn convergence_is_a_conjunction() {
        let p = |healthy, pending, draining, desired| PoolProgress {
            desired,
            healthy,
            pending,
            draining,
        };
        assert!(p(2, 0, 0, 2).converged());
        assert!(p(3, 0, 0, 2).converged(), "more than asked for is still converged");
        assert!(!p(1, 0, 0, 2).converged(), "not enough healthy");
        assert!(!p(2, 1, 0, 2).converged(), "something still booting");
        assert!(!p(2, 0, 1, 2).converged(), "something still draining");
        assert!(p(0, 0, 0, 0).converged(), "scaled to zero has converged");
    }

    #[tokio::test]
    async fn listing_ids_walks_every_page() {
        let page = |ids: &[&str], matched: usize| {
            json!({"generated_at": 0, "uptime_secs": 0, "matched": matched,
                   "tracked_deployments": matched,
                   "deployments": ids.iter().map(|i| json!({"id": i})).collect::<Vec<_>>()})
        };
        let stub = Arc::new(
            Stub::new()
                .json(200, page(&["a", "b"], 5))
                .json(200, page(&["c", "d"], 5))
                .json(200, page(&["e"], 5)),
        );
        let c = Client::with_transport(stub.clone());
        assert_eq!(c.deployment_ids(2).await.unwrap(), ["a", "b", "c", "d", "e"]);
        assert!(stub.calls()[1].path.contains("offset=2"), "{:?}", stub.calls()[1].path);
        assert!(stub.calls().iter().all(|c| c.path.contains("summary=true")));
    }
}
