/**
 * Where the services are, and what proves us to them.
 *
 * There are four: **app-lb** (deployments, and sandboxes — a sandbox is an
 * app-lb deployment with no route, driven through its exec, operations, files
 * and transfer routes), and the three that answer operational questions about a
 * fleet — app-obs, ci and the git remote. (A namespace's artifacts are reached
 * through app-lb, with the same credential.) Nothing here talks to the Heyo
 * cloud API: everything a sandbox needs, app-lb serves. All of them speak
 * `Authorization: Bearer`, so this is mostly uniform. Two asymmetries are
 * load-bearing enough to state here rather than leave to a 401.
 *
 * **The minimal configuration is `APPLB_URL` and a token.** `APPLB_URL` is
 * app-lb's admin API (`https://admin.us5.heyo.work`, or a self-hosted
 * listener), and `APPLB_TOKEN` an app-lb token (`applb_…`). A namespace token's
 * namespace comes from app-lb's own `/whoami` (see `clients/index.ts`).
 *
 * **`ci` behind an app-lb gate admits browsers and *almost* nothing else.** The
 * gate splits on `Accept: text/html`, and only `/healthz`, `/api/submit`,
 * `/api/runs/`, `/api/stream/` and `/__ui/` are in its `public_paths`. The
 * pages — runs, jobs, networks, runners, vms, repos — are outside that list, so
 * a token-carrying client is refused there no matter which token it carries,
 * and `CI_URL` wants ci's own listener for them: reach it from the box it runs
 * on, or through an SSH tunnel. Pointing it at the gated host is a supported
 * mistake — {@link CI_GATE_HINT} turns the resulting 401 into that sentence
 * instead of an authentication red herring.
 *
 * `/api/runs/` is the exception and the reason `ci_run_status` works against
 * the public hostname: it is a machine route with its own credential, so `git
 * submit`'s repository token in `CI_TOKEN` is enough. Without it, "did my
 * deploy work" had no answer at all for a programmatic client — a slow run and
 * a dead one were the same silence.
 */

export interface ServiceConfig {
  readonly baseUrl: string;
  /** `Authorization` header value, already assembled, or undefined. */
  readonly auth?: string;
  /**
   * Headers sent with every request to this service, beside `Authorization`.
   * Never `authorization` itself, which is {@link auth}.
   */
  readonly headers?: Readonly<Record<string, string>>;
  /**
   * The namespace this app-lb config works in (`APPLB_NAMESPACE`), for tools
   * that must name one. Without it, a namespace token's own namespace is asked
   * of app-lb's `/whoami`.
   */
  readonly namespace?: string;
}

export interface Config {
  readonly applb?: ServiceConfig;
  readonly obs?: ServiceConfig;
  readonly ci?: ServiceConfig;
  /**
   * The git remote service (`remote/`): repos on S3 that agents create and
   * push to, and that app-lb builds from. It accepts the same credentials
   * app-lb does (an `applb_…` token is resolved by app-lb's `/whoami`, a
   * `heyo_api_*` key by the Heyo auth service) plus its own `hrm_…` tokens.
   */
  readonly remote?: ServiceConfig;
  /** The namespace repo tools default to (`REMOTE_NAMESPACE`). */
  readonly remoteNamespace?: string;
  /**
   * `HEYO_API_KEY` is set. Nothing uses it any more — sandboxes are app-lb's —
   * so a configuration still carrying one is reported, not obeyed.
   */
  readonly legacyCloudKey?: boolean;
  readonly timeoutMs: number;
  /**
   * Whether this process serves over HTTP rather than stdio.
   *
   * It changes what one tool may do. Over stdio the caller *is* the machine this
   * runs on, so `art_publish` reading a local `path` reads the caller's own file.
   * Over HTTP the caller is somewhere else, and the same read would be a remote
   * request for this server's disk — the more so behind a gate whose `/mcp` path
   * is public. Survives `withForwardedAuth`, which spreads the config it is given.
   */
  readonly http?: boolean;
}

function trimUrl(raw: string): string {
  return raw.trim().replace(/\/+$/, "");
}

/**
 * Bearer, or Basic when a username:password pair is given instead.
 *
 * app-lb compares a Basic header **byte for byte** against a value it was
 * configured with, so it is passed through exactly as supplied rather than
 * re-encoded — an equivalent-but-differently-encoded header is rejected.
 */
function authHeader(token?: string, basic?: string): string | undefined {
  if (basic) {
    return basic.startsWith("Basic ") ? basic : `Basic ${Buffer.from(basic).toString("base64")}`;
  }
  if (token) return token.startsWith("Bearer ") ? token : `Bearer ${token}`;
  return undefined;
}

function service(url?: string, token?: string, basic?: string): ServiceConfig | undefined {
  if (!url || !url.trim()) return undefined;
  return { baseUrl: trimUrl(url), auth: authHeader(token, basic) };
}

/**
 * Where app-lb is: its admin API, with every path appended to `APPLB_URL`.
 * `namespace` is informational — the namespace tools name when the caller does
 * not — and never part of the URL.
 */
export function applbService(
  url?: string,
  namespace?: string,
  token?: string,
  basic?: string,
): ServiceConfig | undefined {
  const base = service(url, token, basic);
  if (!base) return undefined;
  const ns = namespace?.trim();
  return ns ? { ...base, namespace: ns } : base;
}

/**
 * Prefix on a token app-lb minted for itself (`applb_<id>_<secret>`).
 *
 * The prefix is load-bearing, not cosmetic: it is what distinguishes a
 * credential **app-lb issued and will scope-check** from every other bearer a
 * caller might present — a `heyo_api_*` cloud key, or a JWT from some other
 * issuer. See {@link withForwardedAuth}.
 */
export const APPLB_TOKEN_PREFIX = "applb_";

/**
 * The bearer's value, without the scheme, or undefined if it isn't a bearer.
 *
 * Looser than app-lb's own `strip_prefix("Bearer ")` — case-insensitive, any
 * run of spaces — on purpose. The two ways of being wrong here are not
 * symmetric: a header this accepts that app-lb will not parse ends in a 401,
 * while one app-lb would accept and this missed falls back to the configured
 * credential, which is exactly the escalation {@link withForwardedAuth} exists
 * to prevent. So the detector errs wide and the strict parser downstream
 * decides.
 */
export function bearerToken(header: string): string | undefined {
  const match = /^Bearer[ \t]+(\S.*)$/i.exec(header.trim());
  return match?.[1]?.trim();
}

/**
 * Whether a bearer header carries a token app-lb minted.
 *
 * Exported because the same test answers two different questions. For a header
 * a *caller* sent, it decides whose credential speaks at app-lb — see
 * {@link withForwardedAuth}. Takes a full header rather than a bare token.
 */
export function isApplbToken(header: string): boolean {
  return bearerToken(header)?.startsWith(APPLB_TOKEN_PREFIX) ?? false;
}

/**
 * The config to serve one HTTP request with.
 *
 * Three rules. Each exists because the one before it is not sufficient.
 *
 * **A service with no credential of its own borrows the caller's.** That is
 * what lets one hosted instance serve every tenant, each under their own token
 * and therefore their own namespace's deployments and sandboxes.
 *
 * **An app-lb-minted token always speaks for itself at app-lb, configured
 * credential or not.** A token carries a scope — an `admin` level and a
 * `deployments` list — and app-lb enforces it on every route. Falling back to
 * this process's own `APPLB_TOKEN` for a caller who presented one would hand a
 * token scoped to a single deployment the reach of whatever fleet-wide
 * credential the operator configured. That is a confused deputy: the gate in
 * front authenticated a narrow principal and the process would then act for it
 * with broad authority. The caller's token is therefore preferred over the
 * configured one whenever it is app-lb's own kind, so a scope is never widened
 * by passing through here. Unconditional for app-lb because app-lb is always
 * the authenticator for app-lb: its admin listener verifies an `applb_…` bearer
 * against the same store the gate does, whatever else is configured — including
 * `APPLB_BASIC`, which is unscoped and is exactly what must not be borrowed.
 *
 * **app-obs and ci follow the same rule, but only when app-lb is what stands in
 * front of them.** Reached directly on loopback they authenticate themselves,
 * with their own service tokens, and an `applb_…` bearer means nothing to them
 * — forwarding one there would turn every working deployment's obs and ci tools
 * into 401s. Reached through an app-lb gate the credential *is* an app-lb
 * token, and then the caller's must win for the same reason it does at app-lb:
 * a caller whose token does not admit `app-obs` must not read app-obs on this
 * process's ticket. What separates the two shapes is the shape of what is
 * configured — an `applb_…` value means the gate is the authenticator — so no
 * new switch is needed to tell them apart, and an instance that configures
 * nothing for them acts purely as the caller.
 *
 * The prefix test is what keeps all of this from breaking the other gate
 * shapes. A `heyo_api_*` key or a JWT is not an app-lb token — it means nothing
 * to app-lb's admin API — so those still fall to the configured credential and
 * a JWT-gated deployment behaves exactly as before. And preferring a caller's
 * `applb_…` is never an escalation in the other direction either: it is a
 * credential they already hold, and app-lb re-checks its scope regardless of
 * who relayed it.
 *
 *  * Returns the same object when nothing applies, so the per-process tool set can
 * be reused.
 */
export function withForwardedAuth(
  config: Config,
  headers: Record<string, string | string[] | undefined>,
): Config {
  const raw = headers["authorization"];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (!value || !value.trim()) return config;

  const fromApplb = isApplbToken(value);

  /**
   * Whether a service behind an app-lb gate should be reached as the caller.
   *
   * Deliberately narrower than the rule for app-lb itself: an app-lb token is
   * the *only* credential that can mean anything to app-obs or ci other than
   * their own, so a caller presenting anything else leaves them untouched. What
   * is configured then decides — nothing at all, or another `applb_…`, both of
   * which say the gate is doing the authenticating; a service's own token says
   * it is not, and is left alone.
   */
  const gated = (service?: ServiceConfig): boolean =>
    Boolean(service && fromApplb && (!service.auth || isApplbToken(service.auth)));

  // Either app-lb has nothing of its own, or the caller presented a credential
  // that carries its own scope and must not be traded up for this one's.
  const needsApplb = Boolean(config.applb && (!config.applb.auth || fromApplb));
  const needsObs = gated(config.obs);
  const needsCi = gated(config.ci);
  // The git remote resolves every kind of bearer a caller can hold (its own
  // `hrm_…`, app-lb's `applb_…`, a `heyo_api_*` key or a Heyo JWT), and each is
  // scoped. So the caller's always speaks for itself there, for the same
  // confused-deputy reason as app-lb: a narrow credential must not be traded
  // up for whatever this process was configured with.
  const needsRemote = Boolean(config.remote);
  if (!needsApplb && !needsObs && !needsCi && !needsRemote) {
    return config;
  }

  return {
    ...config,
    applb: needsApplb ? { ...config.applb!, auth: value } : config.applb,
    obs: needsObs ? { ...config.obs!, auth: value } : config.obs,
    ci: needsCi ? { ...config.ci!, auth: value } : config.ci,
    remote: needsRemote ? { ...config.remote!, auth: value } : config.remote,
  };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const timeout = Number(env.HEYO_MCP_TIMEOUT_MS ?? "30000");
  return {
    applb: applbService(env.APPLB_URL, env.APPLB_NAMESPACE, env.APPLB_TOKEN, env.APPLB_BASIC),
    obs: service(env.APP_OBS_URL, env.APP_OBS_API_TOKEN),
    ci: service(env.CI_URL, env.CI_TOKEN),
    // Falls back to the app-lb token: the remote resolves `applb_…` tokens
    // through app-lb, so the credential an agent already has is enough.
    remote: service(env.REMOTE_URL, env.REMOTE_TOKEN?.trim() || env.APPLB_TOKEN),
    remoteNamespace: env.REMOTE_NAMESPACE?.trim() || env.APPLB_NAMESPACE?.trim() || undefined,
    legacyCloudKey: Boolean(env.HEYO_API_KEY?.trim()),
    // The same test `index.ts` uses to decide which transport to start.
    http: Number(env.HEYO_MCP_HTTP_PORT ?? "") > 0,
    // Generous, but bounded. Every call here is a diagnostic or a sandbox
    // operation, and a hung one is worse than a failed one: it stalls the
    // conversation with no output at all.
    timeoutMs: Number.isFinite(timeout) && timeout > 0 ? timeout : 30_000,
  };
}

/** Which services are usable, for the startup banner and for `heyo_status`. */
export function configured(config: Config): string[] {
  const on: string[] = [];
  if (config.applb) {
    on.push(config.applb.namespace ? `app-lb (namespace ${config.applb.namespace})` : "app-lb");
  }
  if (config.obs) on.push("app-obs");
  if (config.ci) on.push("ci");
  if (config.remote) on.push(`git remote (${config.remote.baseUrl})`);
  return on;
}

/**
 * A configuration that is present and cannot work, with the fix.
 *
 * `summary` is one line for a banner; `detail` names the variable and the
 * configuration that works. Neither ever contains a token.
 */
export interface CredentialFault {
  readonly service: "app-lb";
  readonly summary: string;
  readonly detail: string;
}

/**
 * What is left over from when this server reached sandboxes through the Heyo
 * cloud API and app-lb through cloud's per-namespace door. Both are gone, and
 * a configuration that still relies on them would otherwise fail one call at a
 * time with nothing saying why. Loud, never fatal.
 */
export function credentialFaults(config: Config): CredentialFault[] {
  const faults: CredentialFault[] = [];
  const migrate =
    "Set APPLB_URL to app-lb's admin API (for example https://admin.us5.heyo.work) and " +
    "APPLB_TOKEN to an app-lb token (`applb_…`, minted from the app-lb dashboard). Sandboxes " +
    "are app-lb deployments now, so that one credential reaches every tool.";
  if (config.applb && /\/namespaces\/[^/]+\/lb$/.test(config.applb.baseUrl)) {
    faults.push({
      service: "app-lb",
      summary: `APPLB_URL (${config.applb.baseUrl}) is the Heyo cloud's namespace door, which this server no longer uses`,
      detail: `APPLB_URL points at a /namespaces/<ns>/lb door on the Heyo cloud. ${migrate}`,
    });
  }
  if (config.legacyCloudKey && !config.applb) {
    faults.push({
      service: "app-lb",
      summary: "HEYO_API_KEY is set but no longer used, and APPLB_URL is not set",
      detail: `This server no longer calls the Heyo cloud API, so HEYO_API_KEY configures nothing. ${migrate}`,
    });
  }
  return faults;
}

/**
 * The fault report both entrypoints print at boot, or "" when there is none.
 *
 * Shared so the two transports cannot diverge on what counts as worth saying.
 * stderr in both cases: on stdio, stdout is the protocol channel.
 */
export function faultBanner(config: Config): string {
  const faults = credentialFaults(config);
  if (faults.length === 0) return "";
  return faults
    .map((f) => `heyo-mcp: CREDENTIAL FAULT — ${f.summary}.\n${f.detail}`)
    .join("\n\n");
}

export const CI_GATE_HINT =
  "ci returned 401 for a machine request. Which fix applies depends on the path:\n\n" +
  "• /api/runs/… — these are in ci's public_paths, so the gate is not what refused " +
  "you. They take a repository submit token, the same one `git submit` uses: set " +
  "CI_TOKEN to it (`git config ci.token`), or sign the request path with " +
  "CI_WEBHOOK_SECRET. A token for another repository reads as 404, not 401.\n\n" +
  "• anything else (/runs, /jobs, /runners, /vms, /repos) — that is the gate, and no " +
  "token will fix it: app-lb admits browsers only there, splitting on " +
  "`Accept: text/html`. Point CI_URL at ci's own listener instead — from the host it " +
  "runs on, or through an SSH tunnel.";
