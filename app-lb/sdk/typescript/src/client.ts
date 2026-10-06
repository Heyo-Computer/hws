import {
  type Credential,
  InvalidRequestError,
  HeyctlError,
  TransportError,
  fromResponse,
} from "./errors.js";
import { ObsClient } from "./obs.js";
import type {
  AdminScope,
  AuthProviderView,
  CertStatus,
  DiscoveryStatus,
  DiskInventory,
  NamespaceEntry,
  NamespacePlugin,
  PluginInstalls,
  RolloutOperation,
  UpstreamTrafficStatus,
  WhoAmI,
  WorkflowList,
  WorkflowSpec,
  DeploymentSpec,
  DeploymentStatus,
  EvictOutcome,
  ExecOutput,
  JobRecord,
  MetricsResponse,
  MintedToken,
  PluginView,
  Ingress,
  SecretSummary,
  TokenSummary,
  FeedEvent,
  FeedIndexEntry,
} from "./types.js";
import type { Shell, ShellOptions } from "./shell.js";
import type { WaitForJobOptions, WaitForReadyOptions } from "./wait.js";

/** app-lb's own default `cold_start_timeout_secs`. */
export const ASSUMED_COLD_START_MS = 120_000;
/** Margin so the client is never the one that gives up first. */
const EXEC_MARGIN_MS = 15_000;
const DEFAULT_TIMEOUT_MS = 30_000;

/** How to authenticate. */
export type Auth =
  | { kind: "none" }
  /** The operator credential. Unscoped, and the one that mints tokens. */
  | { kind: "basic"; user: string; password: string }
  /** An app-token. Scoped, revocable — the normal choice for a program. */
  | { kind: "token"; token: string };

export interface HeyctlOptions {
  /** A URL, or a bare `host:port`. */
  server: string;
  /** Shorthand for `auth: { kind: "token", token }`. */
  token?: string;
  user?: string;
  password?: string;
  auth?: Auth;
  /** Per-request deadline. `exec` computes its own, larger, one. */
  timeoutMs?: number;
  /** Swapped in for tests. Defaults to the global `fetch`. */
  fetch?: typeof globalThis.fetch;
}

/** Which admin routes a server is gating. */
export interface Gates {
  view: boolean;
  crud: boolean;
}

export interface ExecOptions {
  cwd?: string;
  env?: Record<string, string>;
  /** Bounds app-lb's call to the daemon. Clamped server-side to 1..3600. */
  timeoutSecs?: number;
  /** Boot or resume a VM if none is running. Default true. */
  wake?: boolean;
  /** Override the client-side deadline. */
  patienceMs?: number;
  signal?: AbortSignal;
}

export interface MetricsQuery {
  deployment?: string;
  prefix?: string;
  /** Drop per-VM detail, which is most of the payload. */
  summary?: boolean;
  limit?: number;
  offset?: number;
}

export interface NewToken {
  name: string;
  admin?: AdminScope;
  /**
   * Confine the token to one namespace. With no `deployments` it reaches
   * every deployment in the namespace — and nothing outside it, ever.
   */
  namespace?: string;
  /** Deployment ids, or `["*"]`. Defaults to none, which can reach nothing. */
  deployments?: string[];
  expiresInSecs?: number;
  /**
   * Valid on every server that mirrors this control plane's tokens, not only
   * the one minting it. Only a control-plane app-lb (one with gateways
   * configured) accepts it; anywhere else the mint is refused with 409.
   */
  allServers?: boolean;
}

/** Percent-encode one path segment. */
/** `?namespace=…` for the secret routes, or nothing for the default namespace. */
function nsQuery(namespace?: string): string {
  return namespace ? `?namespace=${encodeURIComponent(namespace)}` : "";
}

function seg(s: string): string {
  return encodeURIComponent(s);
}

/** Accept `host:port` as well as a URL, and drop a trailing slash. */
export function normalizeServer(server: string): string {
  const s = server.trim().replace(/\/+$/, "");
  return /^https?:\/\//.test(s) ? s : `http://${s}`;
}

/**
 * A client for one app-lb.
 *
 * ```ts
 * const lb = new Heyctl({ server: "127.0.0.1:9090", token: process.env.APP_LB_TOKEN });
 * const { stdout } = await lb.exec("sb-7f3a9c", "uname -a");
 * ```
 */
export class Heyctl {
  readonly server: string;
  /** @internal */ readonly auth: Auth;
  private readonly timeoutMs: number;
  private readonly doFetch: typeof globalThis.fetch;

  constructor(opts: HeyctlOptions) {
    this.server = normalizeServer(opts.server);
    this.auth =
      opts.auth ??
      (opts.token
        ? { kind: "token", token: opts.token }
        : opts.user && opts.password
          ? { kind: "basic", user: opts.user, password: opts.password }
          : { kind: "none" });
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.doFetch = opts.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!this.doFetch) {
      throw new InvalidRequestError(
        "no global fetch — pass one via `fetch`, or run on Node 18+, Bun or Deno",
      );
    }
  }

  /**
   * The exact `Authorization` header, or undefined.
   *
   * @internal app-lb compares the Basic header **byte for byte** against a
   * string it precomputed at startup — it never base64-decodes it. So this must
   * be standard base64 with padding, one space after `Basic`, that
   * capitalisation. A re-encoded-but-equivalent header is rejected.
   */
  authHeader(): string | undefined {
    switch (this.auth.kind) {
      case "none":
        return undefined;
      case "token":
        return `Bearer ${this.auth.token}`;
      case "basic":
        return `Basic ${base64(`${this.auth.user}:${this.auth.password}`)}`;
    }
  }

  /** @internal */
  credential(): Credential {
    return this.auth.kind;
  }

  private async send(
    method: string,
    path: string,
    opts: {
      body?: unknown;
      kind?: string;
      name?: string;
      timeoutMs?: number;
      signal?: AbortSignal;
    } = {},
  ): Promise<{ status: number; text: string }> {
    const headers: Record<string, string> = {};
    const auth = this.authHeader();
    if (auth) headers.authorization = auth;
    if (opts.body !== undefined) headers["content-type"] = "application/json";

    // A caller's own signal *and* our deadline: whichever fires first wins.
    const timer = new AbortController();
    const ms = opts.timeoutMs ?? this.timeoutMs;
    const timeout = setTimeout(() => timer.abort(), ms);
    const onAbort = () => timer.abort();
    opts.signal?.addEventListener("abort", onAbort, { once: true });

    try {
      const res = await this.doFetch(`${this.server}${path}`, {
        method,
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        signal: timer.signal,
      });
      return { status: res.status, text: await res.text() };
    } catch (cause) {
      if (opts.signal?.aborted) throw cause;
      throw new TransportError(`could not reach ${this.server}${path}`, cause);
    } finally {
      clearTimeout(timeout);
      opts.signal?.removeEventListener("abort", onAbort);
    }
  }

  /** @internal Raw JSON for a route, with failures raised as typed errors. */
  async request<T>(
    method: string,
    path: string,
    opts: {
      body?: unknown;
      kind?: string;
      name?: string;
      timeoutMs?: number;
      signal?: AbortSignal;
      /**
       * Whether a success carries JSON. Not every route does: `/healthz`
       * answers `ok\n` as plain text, and a `204` has no body at all — parsing
       * those would turn a perfectly good response into a syntax error.
       */
      expect?: "json" | "nothing";
    } = {},
  ): Promise<T> {
    const { status, text } = await this.send(method, path, opts);
    if (status < 200 || status >= 300) {
      throw fromResponse(
        status,
        text,
        opts.kind ?? "resource",
        opts.name ?? "",
        this.credential(),
      );
    }
    if (opts.expect === "nothing" || !text.trim()) return undefined as T;
    try {
      return JSON.parse(text) as T;
    } catch (cause) {
      throw new HeyctlError(`could not read the response from ${path}: ${String(cause)}`);
    }
  }

  // -- health and discovery ------------------------------------------------

  /** Never gated, so this proves reachability without a credential. */
  async healthz(): Promise<void> {
    await this.request<void>("GET", "/healthz", { kind: "server", expect: "nothing" });
  }

  /**
   * Which tiers this server gates, probed **anonymously** — the question is
   * what an unauthenticated caller is refused, which is what says whether the
   * gate is on at all.
   */
  async gates(): Promise<Gates> {
    const anon = new Heyctl({ server: this.server, fetch: this.doFetch });
    const refused = async (path: string) => (await anon.send("GET", path)).status === 401;
    return { view: await refused("/metrics"), crud: await refused("/deployments") };
  }

  /**
   * What the server makes of this client's credential: its tier, whether it is
   * confined, and to which namespace. Needs no tier, so it answers even for a
   * token every other route refuses.
   */
  whoami(signal?: AbortSignal): Promise<WhoAmI> {
    return this.request("GET", "/whoami", { kind: "server", signal });
  }

  /**
   * The status a `GET` answers with, treating a 4xx as an answer rather than an
   * error, plus whatever the server said about it (`error — detail`).
   */
  async probe(path: string, signal?: AbortSignal): Promise<{ status: number; detail?: string }> {
    const { status, text } = await this.send("GET", path, { signal });
    let detail: string | undefined;
    try {
      const v = JSON.parse(text);
      const field = (k: string) =>
        typeof v?.[k] === "string" && v[k].trim() ? (v[k] as string).trim() : undefined;
      const e = field("error");
      const d = field("detail");
      detail = e && d ? `${e} — ${d}` : (e ?? d);
    } catch {
      // Not JSON: no detail to report.
    }
    return { status, detail };
  }

  // -- deployments ---------------------------------------------------------

  deployments(signal?: AbortSignal): Promise<DeploymentStatus[]> {
    return this.request("GET", "/deployments", { kind: "deployment", signal });
  }

  deployment(id: string, signal?: AbortSignal): Promise<DeploymentStatus> {
    return this.request("GET", `/deployments/${seg(id)}`, {
      kind: "deployment",
      name: id,
      signal,
    });
  }

  /** Whether a deployment exists, without treating absence as an error. */
  async deploymentExists(id: string): Promise<boolean> {
    try {
      await this.deployment(id);
      return true;
    } catch (e) {
      if (e instanceof HeyctlError && e.status === 404) return false;
      throw e;
    }
  }

  /**
   * Register or replace a deployment.
   *
   * app-lb answers `201` even when this replaced an existing one, so the status
   * does not distinguish create from update. Certificate issuance is
   * asynchronous: success here does not mean a certificate exists yet.
   */
  createDeployment(spec: DeploymentSpec, signal?: AbortSignal): Promise<DeploymentStatus> {
    return this.request("POST", "/deployments", {
      body: spec,
      kind: "deployment",
      name: spec.id,
      signal,
    });
  }

  /**
   * Replace a whole spec.
   *
   * `PUT` replaces everything, so read with {@link deployment}, edit
   * `status.spec`, and pass that back — anything dropped in between is
   * genuinely dropped.
   */
  replaceDeployment(
    id: string,
    spec: DeploymentSpec,
    signal?: AbortSignal,
  ): Promise<DeploymentStatus> {
    return this.request("PUT", `/deployments/${seg(id)}`, {
      body: spec,
      kind: "deployment",
      name: id,
      signal,
    });
  }

  /** A shallow merge onto the current scaling policy. Managed pools only. */
  patchScaling(
    id: string,
    patch: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<DeploymentStatus> {
    return this.request("PATCH", `/deployments/${seg(id)}/scaling`, {
      body: patch,
      kind: "deployment",
      name: id,
      signal,
    });
  }

  async deleteDeployment(id: string, signal?: AbortSignal): Promise<void> {
    await this.request<void>("DELETE", `/deployments/${seg(id)}`, {
      kind: "deployment",
      name: id,
      signal,
      expect: "nothing",
    });
  }

  /** Evict one VM. `force` kills immediately; otherwise it drains. */
  evictVm(
    id: string,
    sandboxId: string,
    force = false,
    signal?: AbortSignal,
  ): Promise<EvictOutcome> {
    // app-lb parses query booleans with Rust's `str::parse::<bool>()`, which
    // takes only `true`/`false` — `?force=1` is a 400, not a truthy value.
    return this.request(
      "DELETE",
      `/deployments/${seg(id)}/vms/${seg(sandboxId)}?force=${force ? "true" : "false"}`,
      { kind: "vm", name: sandboxId, signal },
    );
  }

  /**
   * Stop new requests to one static upstream. Existing requests finish; watch
   * `in_flight` on the result to observe the drain.
   */
  cordonUpstream(
    id: string,
    upstream: string,
    opts: { force?: boolean; reason?: string; signal?: AbortSignal } = {},
  ): Promise<UpstreamTrafficStatus> {
    const body: Record<string, unknown> = { force: opts.force ?? false };
    if (opts.reason !== undefined) body.reason = opts.reason;
    return this.request("PUT", `/deployments/${seg(id)}/upstreams/${seg(upstream)}/drain`, {
      body,
      kind: "upstream",
      name: upstream,
      signal: opts.signal,
    });
  }

  /** Remove an administrative drain. An unhealthy upstream stays excluded until it recovers. */
  uncordonUpstream(id: string, upstream: string, signal?: AbortSignal): Promise<UpstreamTrafficStatus> {
    return this.request("DELETE", `/deployments/${seg(id)}/upstreams/${seg(upstream)}/drain`, {
      kind: "upstream",
      name: upstream,
      signal,
    });
  }

  /**
   * Replace a managed deployment's spec by rolling a fresh pool beside the old
   * one, verifying it, and only then draining the old one.
   *
   * `expectedRevision` is the deployment's `rollout_revision` as last read; the
   * rollout is refused (409) if anything changed it since. `operationId` makes
   * the call idempotent — retry a lost reply with the same id. Answers `202`;
   * poll {@link rollout} until `status` is no longer `running`.
   */
  startRollout(
    id: string,
    req: { operationId: string; expectedRevision: string; spec: DeploymentSpec | Record<string, unknown> },
    signal?: AbortSignal,
  ): Promise<RolloutOperation> {
    return this.request("POST", `/deployments/${seg(id)}/rollouts`, {
      body: {
        operation_id: req.operationId,
        expected_revision: req.expectedRevision,
        spec: req.spec,
      },
      kind: "deployment",
      name: id,
      signal,
    });
  }

  rollout(id: string, operationId: string, signal?: AbortSignal): Promise<RolloutOperation> {
    return this.request("GET", `/deployments/${seg(id)}/rollouts/${seg(operationId)}`, {
      kind: "rollout",
      name: operationId,
      signal,
    });
  }

  /**
   * What this gateway publishes for the deployment to discovery. `staged` asks
   * about the spec a pending change would publish instead of the live one.
   */
  discoveryStatus(
    id: string,
    opts: { staged?: boolean; signal?: AbortSignal } = {},
  ): Promise<DiscoveryStatus> {
    const q = opts.staged ? "?staged=true" : "";
    return this.request("GET", `/deployments/${seg(id)}/discovery-status${q}`, {
      kind: "deployment",
      name: id,
      signal: opts.signal,
    });
  }

  // -- running things inside a VM ------------------------------------------

  /**
   * Run a command in the deployment's VM and wait for it to finish.
   *
   * Two things to know:
   *
   * - **A non-zero exit resolves.** The command ran; it failed. Only an
   *   inability to run it rejects. Check `exitCode`.
   * - **The timeout does not kill anything.** `timeoutSecs` bounds app-lb's own
   *   call to the daemon; when it expires you get an {@link UpstreamError} and
   *   the command **keeps running in the guest**. The daemon offers no
   *   streaming and no cancellation, so output is buffered until it exits.
   */
  exec(id: string, command: string, opts: ExecOptions = {}): Promise<ExecOutput> {
    if (!command.trim()) {
      throw new InvalidRequestError("a command to exec must not be blank");
    }
    const wake = opts.wake ?? true;
    const body: Record<string, unknown> = { command, wake };
    if (opts.cwd) body.cwd = opts.cwd;
    if (opts.env) body.env = opts.env;
    if (opts.timeoutSecs !== undefined) body.timeout_secs = opts.timeoutSecs;

    // Must outlast the server's worst case, which is the command timeout plus a
    // cold start when waking — otherwise the client abandons a request app-lb is
    // still serving and the caller gets a transport error instead of an answer.
    // A deployment's real `cold_start_timeout_secs` is not knowable without
    // another round trip, so this assumes app-lb's default.
    const commandMs = Math.min(Math.max(opts.timeoutSecs ?? 60, 1), 3600) * 1000;
    const patienceMs =
      opts.patienceMs ?? commandMs + (wake ? ASSUMED_COLD_START_MS : 0) + EXEC_MARGIN_MS;

    return this.request("POST", `/deployments/${seg(id)}/exec`, {
      body,
      kind: "deployment",
      name: id,
      timeoutMs: patienceMs,
      signal: opts.signal,
    });
  }

  // -- workflows ------------------------------------------------------------

  /** Every CI workflow object. */
  async workflows(signal?: AbortSignal): Promise<WorkflowSpec[]> {
    const list = await this.request<WorkflowList>("GET", "/workflows", { kind: "workflow", signal });
    return list?.workflows ?? [];
  }

  workflow(id: string, signal?: AbortSignal): Promise<WorkflowSpec> {
    return this.request("GET", `/workflows/${seg(id)}`, { kind: "workflow", name: id, signal });
  }

  /** Create or replace. Sends the object as given, unknown fields included. */
  createWorkflow(spec: WorkflowSpec | Record<string, unknown>, signal?: AbortSignal): Promise<WorkflowSpec> {
    return this.request("POST", "/workflows", {
      body: spec,
      kind: "workflow",
      name: String((spec as { id?: unknown }).id ?? ""),
      signal,
    });
  }

  replaceWorkflow(
    id: string,
    spec: WorkflowSpec | Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<WorkflowSpec> {
    return this.request("PUT", `/workflows/${seg(id)}`, { body: spec, kind: "workflow", name: id, signal });
  }

  async deleteWorkflow(id: string, signal?: AbortSignal): Promise<void> {
    await this.request<void>("DELETE", `/workflows/${seg(id)}`, {
      kind: "workflow",
      name: id,
      signal,
      expect: "nothing",
    });
  }

  // -- auth providers -------------------------------------------------------

  /**
   * The declared auth providers this credential can see, or those of one
   * namespace. Narrows itself server-side rather than refusing.
   */
  authProviders(namespace?: string, signal?: AbortSignal): Promise<AuthProviderView[]> {
    return this.request("GET", `/auth-providers${nsQuery(namespace)}`, { kind: "auth provider", signal });
  }

  /** One provider. Unique within its namespace, so both halves are required. */
  authProvider(namespace: string, name: string, signal?: AbortSignal): Promise<AuthProviderView> {
    return this.request("GET", `/auth-providers/${seg(namespace)}/${seg(name)}`, {
      kind: "auth provider",
      name,
      signal,
    });
  }

  async authProviderExists(namespace: string, name: string): Promise<boolean> {
    try {
      await this.authProvider(namespace, name);
      return true;
    } catch (e) {
      if (e instanceof HeyctlError && e.status === 404) return false;
      throw e;
    }
  }

  /**
   * Declare or replace a provider (upserts, keeping `created_at`). The body may
   * carry request-only `preset`/`secret` conveniences the server expands.
   */
  createAuthProvider(spec: Record<string, unknown>, signal?: AbortSignal): Promise<AuthProviderView> {
    return this.request("POST", "/auth-providers", {
      body: spec,
      kind: "auth provider",
      name: String(spec.name ?? ""),
      signal,
    });
  }

  /** Refused (409) while a deployment's gate still inherits it. */
  async deleteAuthProvider(namespace: string, name: string, signal?: AbortSignal): Promise<void> {
    await this.request<void>("DELETE", `/auth-providers/${seg(namespace)}/${seg(name)}`, {
      kind: "auth provider",
      name,
      signal,
      expect: "nothing",
    });
  }

  // -- namespaces -----------------------------------------------------------

  /** The namespaces this credential can see, narrowed server-side. */
  namespaces(signal?: AbortSignal): Promise<NamespaceEntry[]> {
    return this.request("GET", "/namespaces", { kind: "namespace", signal });
  }

  /** Declare a namespace. Idempotent; fleet scope and `admin` server-side. */
  createNamespace(
    spec: { name: string; description?: string; [extra: string]: unknown },
    signal?: AbortSignal,
  ): Promise<unknown> {
    return this.request("POST", "/namespaces", { body: spec, kind: "namespace", name: spec.name, signal });
  }

  /** Undeclare a namespace. Refused while deployments are still in it. */
  async deleteNamespace(name: string, signal?: AbortSignal): Promise<void> {
    await this.request<void>("DELETE", `/namespaces/${seg(name)}`, {
      kind: "namespace",
      name,
      signal,
      expect: "nothing",
    });
  }

  // -- namespace plugins and telemetry --------------------------------------

  /**
   * The plugins that install per namespace, and whether each is switched on for
   * the fleet (`enabled`) and installed here (`installed`).
   */
  namespacePlugins(namespace: string, signal?: AbortSignal): Promise<NamespacePlugin[]> {
    return this.request("GET", `/namespaces/${seg(namespace)}/plugins`, {
      kind: "namespace",
      name: namespace,
      signal,
    });
  }

  /**
   * Install a plugin into a namespace, or replace its per-namespace config.
   * Idempotent. Needs `admin` over the whole namespace; a `ConflictError` with
   * `code: "plugin_disabled"` while the operator has it off for the fleet.
   */
  installPlugin(
    namespace: string,
    id: string,
    config?: unknown,
    signal?: AbortSignal,
  ): Promise<NamespacePlugin> {
    const body: Record<string, unknown> = {};
    if (config !== undefined) body.config = config;
    return this.request("PUT", `/namespaces/${seg(namespace)}/plugins/${seg(id)}`, {
      body,
      kind: "plugin",
      name: id,
      signal,
    });
  }

  /** Uninstall. For `obs` this stops collection; what was collected ages out. */
  uninstallPlugin(namespace: string, id: string, signal?: AbortSignal): Promise<NamespacePlugin> {
    return this.request("DELETE", `/namespaces/${seg(namespace)}/plugins/${seg(id)}`, {
      kind: "plugin",
      name: id,
      signal,
    });
  }

  /** Every namespace a plugin is installed in. Fleet scope only. */
  pluginInstalls(id: string, signal?: AbortSignal): Promise<PluginInstalls> {
    return this.request("GET", `/api/plugins/${seg(id)}/installs`, { kind: "plugin", name: id, signal });
  }

  /** One namespace's telemetry through the `obs` plugin. Makes no request. */
  obs(namespace: string): ObsClient {
    return new ObsClient(this, namespace);
  }

  // -- secrets --------------------------------------------------------------

  /**
   * The secrets the credential may see: one namespace when `namespace` is
   * given, else every namespace within its reach. Secrets are walled by
   * namespace exactly as deployments are.
   */
  secrets(namespace?: string, signal?: AbortSignal): Promise<SecretSummary[]> {
    const q = namespace ? `?namespace=${encodeURIComponent(namespace)}` : "";
    return this.request("GET", `/secrets${q}`, { kind: "secret", signal });
  }

  secret(id: string, namespace?: string, signal?: AbortSignal): Promise<SecretSummary> {
    return this.request("GET", `/secrets/${seg(id)}${nsQuery(namespace)}`, {
      kind: "secret",
      name: id,
      signal,
    });
  }

  /**
   * Values enter here and are never readable again. `namespace` defaults to
   * `default`; a confined credential must reach it as an admin.
   */
  putSecret(
    spec: { id: string; namespace?: string; description?: string; data: Record<string, string> },
    signal?: AbortSignal,
  ): Promise<SecretSummary> {
    return this.request("POST", "/secrets", {
      body: spec,
      kind: "secret",
      name: spec.id,
      signal,
    });
  }

  /** `null` for a value deletes that key; absent keys are left alone. */
  patchSecret(
    id: string,
    patch: { data?: Record<string, string | null>; description?: string },
    namespace?: string,
    signal?: AbortSignal,
  ): Promise<SecretSummary> {
    return this.request("PATCH", `/secrets/${seg(id)}${nsQuery(namespace)}`, {
      body: patch,
      kind: "secret",
      name: id,
      signal,
    });
  }

  async deleteSecret(
    id: string,
    force = false,
    namespace?: string,
    signal?: AbortSignal,
  ): Promise<void> {
    const q = nsQuery(namespace);
    await this.request<void>(
      "DELETE",
      `/secrets/${seg(id)}${q ? `${q}&` : "?"}force=${force ? "true" : "false"}`,
      { kind: "secret", name: id, signal, expect: "nothing" },
    );
  }

  // -- ingress --------------------------------------------------------------

  /** Where DNS should point a deployment's hostname — this LB's public addresses. */
  ingress(signal?: AbortSignal): Promise<Ingress> {
    return this.request("GET", "/ingress", { kind: "ingress", signal });
  }

  // -- app-tokens -----------------------------------------------------------

  /**
   * Mint a token.
   *
   * **The secret in the reply is shown once** — app-lb keeps only its hash and
   * no endpoint reads it back. Store it now or mint another.
   *
   * Both scope fields default to nothing: a token minted with no scope can do
   * nothing, which is a harmless mistake. The other default would turn a
   * forgotten field into fleet-wide credentials.
   */
  mintToken(req: NewToken, signal?: AbortSignal): Promise<MintedToken> {
    if (!req.name.trim()) {
      throw new InvalidRequestError(
        "a token needs a name — it is how you know what to revoke",
      );
    }
    const body: Record<string, unknown> = {
      name: req.name,
      admin: req.admin ?? "none",
      deployments: req.deployments ?? [],
    };
    if (req.namespace !== undefined) body.namespace = req.namespace;
    if (req.expiresInSecs !== undefined) body.expires_in_secs = req.expiresInSecs;
    if (req.allServers) body.fleet = true;
    return this.request("POST", "/tokens", {
      body,
      kind: "token",
      name: req.name,
      signal,
    });
  }

  // -- plugins ---------------------------------------------------------------

  plugins(signal?: AbortSignal): Promise<PluginView[]> {
    return this.request("GET", "/api/plugins", { kind: "plugin", signal });
  }

  plugin(id: string, signal?: AbortSignal): Promise<PluginView> {
    return this.request("GET", `/api/plugins/${seg(id)}`, { kind: "plugin", name: id, signal });
  }

  /**
   * Write a plugin's record. Omit `config` to keep the stored one. Resolves
   * when the record is saved even if applying it failed — check `last_error`.
   */
  setPlugin(id: string, enabled: boolean, config?: unknown, signal?: AbortSignal): Promise<PluginView> {
    const body: Record<string, unknown> = { enabled };
    if (config !== undefined) body.config = config;
    return this.request("PUT", `/api/plugins/${seg(id)}`, { body, kind: "plugin", name: id, signal });
  }

  tokens(signal?: AbortSignal): Promise<TokenSummary[]> {
    return this.request("GET", "/tokens", { kind: "token", signal });
  }

  token(id: string, signal?: AbortSignal): Promise<TokenSummary> {
    return this.request("GET", `/tokens/${seg(id)}`, { kind: "token", name: id, signal });
  }

  /**
   * Re-scope a token **without changing its secret**, so narrowing a credential
   * does not mean redistributing it. Pass `expires_at: null` to clear an expiry.
   */
  patchToken(
    id: string,
    patch: {
      name?: string;
      admin?: AdminScope;
      /** `null` lifts the namespace wall; a string moves it. */
      namespace?: string | null;
      deployments?: string[];
      expires_at?: number | null;
    },
    signal?: AbortSignal,
  ): Promise<TokenSummary> {
    return this.request("PATCH", `/tokens/${seg(id)}`, {
      body: patch,
      kind: "token",
      name: id,
      signal,
    });
  }

  /** Effective on the next request — verification is a lookup, not a signature. */
  async revokeToken(id: string, signal?: AbortSignal): Promise<void> {
    await this.request<void>("DELETE", `/tokens/${seg(id)}`, {
      kind: "token",
      name: id,
      signal,
      expect: "nothing",
    });
  }

  // -- the event feed --------------------------------------------------------

  /** The namespaces that have feed events, narrowed to this credential. */
  feeds(signal?: AbortSignal): Promise<FeedIndexEntry[]> {
    return this.request("GET", "/feeds", { signal });
  }

  /** A namespace's feed events as structured data, newest first. */
  feedEvents(namespace: string, signal?: AbortSignal): Promise<FeedEvent[]> {
    return this.request("GET", `/feeds/${seg(namespace)}?format=json`, {
      kind: "feed",
      name: namespace,
      signal,
    });
  }

  /** A namespace's feed as the RSS document a reader would fetch, verbatim. */
  async feedRss(namespace: string, signal?: AbortSignal): Promise<string> {
    const { status, text } = await this.send("GET", `/feeds/${seg(namespace)}`, { signal });
    if (status < 200 || status >= 300) {
      throw fromResponse(status, text, "feed", namespace, this.credential());
    }
    return text;
  }

  // -- jobs -----------------------------------------------------------------

  startBuild(id: string, ref?: string, signal?: AbortSignal): Promise<JobRecord> {
    // Always a body with a content-type, even when empty: app-lb takes these as
    // an optional JSON body, and axum silently swallows a malformed or untyped
    // one into the default rather than rejecting it.
    return this.request("POST", `/deployments/${seg(id)}/build`, {
      body: ref ? { ref } : {},
      kind: "deployment",
      name: id,
      signal,
    });
  }

  startPull(id: string, ref?: string, force = false, signal?: AbortSignal): Promise<JobRecord> {
    const body: Record<string, unknown> = { force };
    if (ref) body.ref = ref;
    return this.request("POST", `/deployments/${seg(id)}/pull`, {
      body,
      kind: "deployment",
      name: id,
      signal,
    });
  }

  /**
   * Unpack a managed deployment's guest mounts and roll the pool onto them.
   * One job covers every mount, so there is no `ref` override.
   */
  startMountPull(id: string, force = false, signal?: AbortSignal): Promise<JobRecord> {
    return this.request("POST", `/deployments/${seg(id)}/mounts/pull`, {
      body: { force },
      kind: "deployment",
      name: id,
      signal,
    });
  }

  startUpdate(id: string, signal?: AbortSignal): Promise<JobRecord> {
    return this.request("POST", `/deployments/${seg(id)}/update`, {
      body: {},
      kind: "deployment",
      name: id,
      signal,
    });
  }

  jobs(signal?: AbortSignal): Promise<JobRecord[]> {
    return this.request("GET", "/jobs", { kind: "job", signal });
  }

  deploymentJobs(id: string, signal?: AbortSignal): Promise<JobRecord[]> {
    return this.request("GET", `/deployments/${seg(id)}/jobs`, {
      kind: "deployment",
      name: id,
      signal,
    });
  }

  /** A 404 can mean the job aged out of the bounded history, not that it never existed. */
  job(jobId: string, signal?: AbortSignal): Promise<JobRecord> {
    return this.request("GET", `/jobs/${seg(jobId)}`, { kind: "job", name: jobId, signal });
  }

  // -- observability --------------------------------------------------------

  /**
   * The unfiltered response is megabytes at fleet scale, so prefer `summary`
   * and paging. `fleet`, `global` and `host` always describe everything the
   * credential can see, never the page.
   */
  metrics(query: MetricsQuery = {}, signal?: AbortSignal): Promise<MetricsResponse> {
    const parts: string[] = [];
    if (query.deployment) parts.push(`deployment=${seg(query.deployment)}`);
    if (query.prefix) parts.push(`prefix=${seg(query.prefix)}`);
    // Only `true`/`false` parse server-side.
    if (query.summary) parts.push("summary=true");
    if (query.limit !== undefined) parts.push(`limit=${query.limit}`);
    if (query.offset) parts.push(`offset=${query.offset}`);
    const qs = parts.length ? `?${parts.join("&")}` : "";
    return this.request("GET", `/metrics${qs}`, { kind: "server", signal });
  }

  /**
   * Attach an interactive shell.
   *
   * Everything that can fail with a status does so *before* the upgrade, so a
   * socket that opens is a shell that attached: a 404, 403, 409 or 503 arrives
   * as a typed error, never as an unexplained close.
   */
  async shell(id: string, opts: ShellOptions = {}): Promise<Shell> {
    // Imported here rather than at the top so that a runtime with no WebSocket
    // can still use every HTTP route in this file.
    const { Shell: S } = await import("./shell.js");
    return S.open(this, id, opts);
  }

  /** Poll a job until it finishes. See {@link waitForJob}. */
  async waitForJob(jobId: string, opts?: WaitForJobOptions): Promise<JobRecord> {
    const { waitForJob } = await import("./wait.js");
    return waitForJob(this, jobId, opts);
  }

  /** Poll a deployment until its pool has converged. See {@link waitForReady}. */
  async waitForReady(id: string, opts?: WaitForReadyOptions): Promise<DeploymentStatus> {
    const { waitForReady } = await import("./wait.js");
    return waitForReady(this, id, opts);
  }

  certs(signal?: AbortSignal): Promise<CertStatus[]> {
    return this.request("GET", "/certs", { kind: "certificate", signal });
  }

  /**
   * The host's disk inventory. Check `complete` before acting on it: an
   * incomplete inventory classified nothing.
   */
  disks(signal?: AbortSignal): Promise<DiskInventory> {
    return this.request("GET", "/disks", { kind: "disk", signal });
  }

  /**
   * Every deployment id, a page at a time.
   *
   * Walks `/metrics` rather than `GET /deployments`, which is unpaged and
   * returns whole specs — megabytes at fleet scale.
   */
  async deploymentIds(pageSize = 200, signal?: AbortSignal): Promise<string[]> {
    const out: string[] = [];
    let offset = 0;
    for (;;) {
      const page = await this.metrics({ summary: true, limit: pageSize, offset }, signal);
      out.push(...page.deployments.map((d) => d.id));
      offset += pageSize;
      if (offset >= page.matched || page.deployments.length === 0) return out;
    }
  }
}

/** base64 that works in Node, Bun, Deno and browsers. */
function base64(s: string): string {
  if (typeof globalThis.btoa === "function") {
    // btoa is latin1-only; encode first so non-ASCII passwords survive.
    return globalThis.btoa(String.fromCharCode(...new TextEncoder().encode(s)));
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (globalThis as any).Buffer.from(s, "utf8").toString("base64");
}
