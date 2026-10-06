/**
 * `@heyocomputer/hws` — the TypeScript twin of the `hws` crate: a client for
 * the app-lb admin API.
 *
 * app-lb is a load balancer for heyvm Firecracker/KVM microVMs. This package
 * drives it: register deployments, scale pools, run commands inside a VM, and
 * attach an interactive shell.
 *
 * ```ts
 * import { Hws } from "@heyocomputer/hws";
 *
 * const lb = new Hws({ server: "127.0.0.1:9090", token: process.env.APP_LB_TOKEN });
 * const { stdout } = await lb.exec("sb-7f3a9c", "uname -a");
 * ```
 *
 * # Authentication
 *
 * Prefer an **app-token**: scoped to particular deployments, revocable without
 * restarting app-lb, optionally expiring. Basic auth also works and is unscoped
 * — it is the operator credential, and the one that mints tokens.
 *
 * # Runtimes
 *
 * Node 18+, Bun, Deno and browsers. Everything uses `fetch`. Shells use `ws` on
 * the server and the native `WebSocket` in a browser — and because a browser
 * cannot set headers on an upgrade, a browser shell needs an **app-token**,
 * which travels in the query string. Mint a short-lived one for that.
 *
 * # What this package does not smooth over
 *
 * - A non-zero exit code from {@link Heyctl.exec} resolves, it does not
 *   reject. The command ran; it failed.
 * - `exec`'s timeout does not kill anything. It bounds app-lb's call to the
 *   daemon — on expiry you get an `UpstreamError` and the command **keeps
 *   running in the guest**.
 * - A shell socket has no resume. If it drops the session is gone; reconnecting
 *   gives a *new* shell.
 */

export { Heyctl, normalizeServer, ASSUMED_COLD_START_MS } from "./client.js";
/**
 * The client under the package's name. `Heyctl` stays exported for code
 * written against the earlier name; they are the same class.
 */
export { Heyctl as Hws } from "./client.js";
export type {
  Auth,
  ExecOptions,
  Gates,
  MetricsQuery,
  NewToken,
  HeyctlOptions,
  HeyctlOptions as HwsOptions,
} from "./client.js";

export { ObsClient, OBS_PLUGIN, logQueryString } from "./obs.js";
export type { LogQuery, NewAlert } from "./obs.js";

export { Shell, PING_INTERVAL_MS } from "./shell.js";
export type { ShellExit, ShellOptions } from "./shell.js";

export { waitForJob, waitForReady, JOB_POLL_MS, POOL_POLL_MS, FIRST_POLL_MS } from "./wait.js";
export type {
  JobProgress,
  PoolProgress,
  WaitForJobOptions,
  WaitForReadyOptions,
} from "./wait.js";

export {
  ApiError,
  ColdStartTimeoutError,
  ConflictError,
  ForbiddenError,
  InvalidRequestError,
  MalformedResponseError,
  NoRunningVmError,
  NotFoundError,
  HeyctlError,
  ShellError,
  TimeoutError,
  TransportError,
  UnauthorizedError,
  UpstreamError,
} from "./errors.js";
export type { Credential } from "./errors.js";

export type * from "./types.js";
