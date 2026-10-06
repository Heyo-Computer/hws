/**
 * Waiting for things to converge.
 *
 * app-lb answers a build with `202` and a job id, and a spec change immediately
 * while the pool it describes takes a minute to exist. Both predicates are
 * fiddly enough that everyone gets them slightly wrong:
 *
 *  - a job is done when `status` stops being `running` — but its `log` grows
 *    while it runs, so progress means tracking what you have already seen;
 *  - a pool has converged when nothing is pending, enough backends are
 *    *healthy*, and nothing is draining. Counting `ready` alone reports success
 *    while a VM is still failing its health check, because `ready` is the size
 *    of the pool, not the healthy part of it.
 */

import type { Heyctl } from "./client.js";
import { NotFoundError, TimeoutError } from "./errors.js";
import type { DeploymentStatus, JobRecord } from "./types.js";

export const JOB_POLL_MS = 3_000;
export const POOL_POLL_MS = 2_000;
/**
 * Where polling starts unless `pollMs` fixes it. It doubles from here up to
 * {@link JOB_POLL_MS} / {@link POOL_POLL_MS}, so a VM that is ready in half a
 * second is seen in about that, and a long build is still asked about politely.
 */
export const FIRST_POLL_MS = 100;

export interface JobProgress {
  job: JobRecord;
  /** Lines that appeared since the last call — not the whole log. */
  newLog: string[];
}

export interface PoolProgress {
  desired: number;
  healthy: number;
  pending: number;
  draining: number;
  converged: boolean;
}

export interface WaitForJobOptions {
  /**
   * Poll through this deployment's job list (`GET /deployments/:id/jobs`)
   * rather than `GET /jobs/:id`. A namespace token can read the former;
   * app-lb releases before the namespace-scoped `GET /jobs/:id` refuse it
   * the latter. Pass `job.deployment` from the record a `start*` call returned.
   */
  deployment?: string;
  pollMs?: number;
  timeoutMs?: number;
  onProgress?: (p: JobProgress) => void;
  signal?: AbortSignal;
}

export interface WaitForReadyOptions {
  pollMs?: number;
  timeoutMs?: number;
  onProgress?: (p: PoolProgress) => void;
  signal?: AbortSignal;
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(signal.reason);
      },
      { once: true },
    );
  });

/**
 * Poll a job until it finishes.
 *
 * Resolves whether it succeeded or failed — a failed job is an answer, not an
 * error, and its `log` and `error` are the point. Only being unable to *ask*
 * rejects.
 */
export async function waitForJob(
  client: Heyctl,
  jobId: string,
  opts: WaitForJobOptions = {},
): Promise<JobRecord> {
  const capMs = opts.pollMs ?? JOB_POLL_MS;
  let pollMs = opts.pollMs ?? Math.min(FIRST_POLL_MS, capMs);
  const timeoutMs = opts.timeoutMs ?? 1_800_000;
  const deadline = Date.now() + timeoutMs;
  let seen = 0;

  for (;;) {
    const job = opts.deployment
      ? (await client.deploymentJobs(opts.deployment, opts.signal)).find((j) => j.id === jobId)
      : await client.job(jobId, opts.signal);
    if (!job) throw new NotFoundError("job", `${jobId} (in deployment ${opts.deployment})`);
    const log = job.log ?? [];
    if (opts.onProgress) {
      // Only the tail is new. app-lb keeps a bounded log, so if it truncated
      // from the front `seen` can exceed the length — report nothing rather
      // than a negative slice.
      opts.onProgress({ job, newLog: log.slice(Math.min(seen, log.length)) });
    }
    seen = log.length;

    if (job.status !== "running") return job;
    if (Date.now() >= deadline) throw new TimeoutError(`job ${jobId}`, timeoutMs);
    await sleep(pollMs, opts.signal);
    pollMs = Math.min(pollMs * 2, capMs);
  }
}

/**
 * Poll a deployment until its pool has converged.
 *
 * A `site` or `upstreams` deployment has no pool, so this returns as soon as it
 * sees one — there is nothing to wait for.
 */
export async function waitForReady(
  client: Heyctl,
  id: string,
  opts: WaitForReadyOptions = {},
): Promise<DeploymentStatus> {
  const capMs = opts.pollMs ?? POOL_POLL_MS;
  let pollMs = opts.pollMs ?? Math.min(FIRST_POLL_MS, capMs);
  const timeoutMs = opts.timeoutMs ?? 300_000;
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    const status = await client.deployment(id, opts.signal);
    if (status.kind !== "vm") return status;

    const vms = status.vms ?? [];
    const healthy = vms.filter((v) => v.healthy && !v.draining).length;
    const draining = vms.filter((v) => v.draining).length;
    const progress: PoolProgress = {
      desired: status.desired_replicas,
      healthy,
      pending: status.pending,
      draining,
      converged:
        status.pending === 0 && healthy >= status.desired_replicas && draining === 0,
    };
    opts.onProgress?.(progress);
    if (progress.converged) return status;
    if (Date.now() >= deadline) throw new TimeoutError(`deployment ${id}`, timeoutMs);
    await sleep(pollMs, opts.signal);
    pollMs = Math.min(pollMs * 2, capMs);
  }
}
