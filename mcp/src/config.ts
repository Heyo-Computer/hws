/**
 * Where the services are, and what proves us to them.
 *
 * There are four: **heyo cloud** (the sandbox control plane — create a VM, run
 * a command in it, read and write its files) and the three that answer
 * operational questions about a fleet — app-lb, app-obs and ci. (A namespace's
 * artifacts are reached through app-lb, with the same credential.) All of them speak
 * `Authorization: Bearer`, so this is mostly uniform. Three asymmetries are
 * load-bearing enough to state here rather than leave to a 401.
 *
 * **The minimal configuration is two API keys and nothing else.**
 * `HEYO_API_KEY` reaches cloud at its default base, and `APPLB_TOKEN` reaches
 * the managed app-lb through cloud's per-namespace door — whose namespace is
 * discovered from the key when it is not named (see `clients/index.ts`). Every
 * URL below has a working default or is genuinely optional; a self-hosted
 * app-lb, app-obs or ci is the case that needs one. Through cloud's door the
 * app-lb credential *is* a heyo API key, so a single `HEYO_API_KEY` configures
 * both — `APPLB_TOKEN` exists for the deployment that wants them separate, and
 * for a self-hosted app-lb where they are genuinely different credentials.
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

/** Cloud's public base. The default for both cloud and the managed app-lb. */
export const CLOUD_BASE_URL = "https://server.heyo.computer";

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
   * The managed namespace this app-lb config is confined to, when it reaches
   * app-lb through heyo cloud's `/namespaces/{ns}/lb` door rather than an
   * admin listener. Informational — the base URL already carries it.
   */
  readonly namespace?: string;
  /**
   * Set when `baseUrl` is cloud's root and no namespace was named: the door is
   * not yet complete, and the first app-lb call resolves it from the key's own
   * namespace list. Kept as a flag rather than resolved here because that is a
   * network call and this function is not allowed to be one.
   */
  readonly discoverNamespace?: boolean;
}

export interface Config {
  readonly cloud?: ServiceConfig;
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
 * Where heyo cloud is. `HEYO_BASE_URL` exists for a staging or local cloud;
 * everyone else gets {@link CLOUD_BASE_URL} without saying so.
 *
 * Unlike the three fleet services, an absent key does not make this
 * unconfigured in every mode: a hosted instance may carry no key of its own and
 * act as whoever calls it, exactly as app-lb does below. What makes cloud
 * unconfigured is having neither a key nor a caller to borrow one from, which
 * only {@link withForwardedAuth} can decide.
 */
export function cloudService(url?: string, apiKey?: string): ServiceConfig {
  return { baseUrl: trimUrl(url?.trim() ? url : CLOUD_BASE_URL), auth: authHeader(apiKey) };
}

/**
 * Where app-lb is, in either of its two shapes.
 *
 * Self-hosted, `APPLB_URL` is app-lb's own admin listener and every path is
 * appended to it. Managed, the same tools reach the platform's single app-lb
 * through heyo cloud, which exposes it per namespace at
 * `/namespaces/{ns}/lb/…` and forwards the caller's `heyo_api_*` key to be
 * resolved into that namespace's grant. Nothing downstream knows which shape it
 * is talking to: the difference is entirely in the base URL, which is why this
 * is the only place that mentions it.
 *
 * With no `APPLB_URL` at all the managed shape is assumed, because that is the
 * one a customer has: cloud's base, and the key already in hand. A URL that
 * already ends in `/lb` is taken as spelled out by hand
 * (`…/namespaces/team-a/lb`) and is not rewritten, so the two ways of saying it
 * cannot compound into `…/lb/namespaces/team-a/lb`.
 *
 * A namespace that was not named is left to be discovered rather than guessed —
 * but only against cloud, because an admin listener has no `/namespaces` to
 * ask.
 */
export function applbService(
  url?: string,
  namespace?: string,
  token?: string,
  basic?: string,
  cloud?: ServiceConfig,
): ServiceConfig | undefined {
  const explicit = service(url, token, basic);
  // No URL: the managed door, with app-lb's own credential if it has one and
  // cloud's otherwise — through that door they are the same kind of key.
  const base =
    explicit ??
    (cloud && (token?.trim() || basic?.trim() || cloud.auth)
      ? { baseUrl: cloud.baseUrl, auth: authHeader(token, basic) ?? cloud.auth }
      : undefined);
  if (!base) return undefined;

  const ns = namespace?.trim();
  if (base.baseUrl.endsWith("/lb")) return ns ? { ...base, namespace: ns } : base;
  if (!ns) {
    const cloudRooted = base.baseUrl === (cloud?.baseUrl ?? CLOUD_BASE_URL);
    return cloudRooted ? { ...base, discoverNamespace: true } : base;
  }
  return {
    ...base,
    baseUrl: `${base.baseUrl}/namespaces/${encodeURIComponent(ns)}/lb`,
    namespace: ns,
  };
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
 * {@link withForwardedAuth}. For a credential this process was *configured*
 * with, it decides whether that credential can work at all: cloud has never
 * heard of an `applb_…` token, so one in `HEYO_API_KEY` can only ever 401.
 * Takes a full header rather than a bare token so both callers pass what they
 * already hold.
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
 * what lets one hosted instance serve every tenant, each under their own key
 * and therefore their own sandboxes and namespace grant.
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
 * Cloud is left out of the second rule and, for an app-lb token, out of the
 * first one too. An `applb_…` token is not a cloud credential: cloud has never
 * heard of it, so forwarding one could only produce a 401 on every sandbox call.
 * So a configured `HEYO_API_KEY` is kept (every caller admitted by an app-token
 * gate shares that one cloud account), and where there is no key the caller's
 * app-lb token is *not* substituted for one — cloud stays unconfigured, and
 * `buildTools` lists no sandbox tools rather than a set that always fails.
 *
 * Only that prefix is excluded. A `heyo_api_*` key is exactly what cloud wants
 * and is still forwarded, which is what makes managed mode multi-tenant; a JWT
 * is left alone as before.
 *
 * Returns the same object when nothing applies, so the per-process tool set can
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

  // An app-lb token is the one bearer that must not stand in for a cloud key:
  // see above. Every other credential keeps the borrow-when-empty rule.
  const needsCloud = Boolean(config.cloud && !config.cloud.auth && !fromApplb);
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
  if (!needsCloud && !needsApplb && !needsObs && !needsCi && !needsRemote) {
    return config;
  }

  return {
    ...config,
    cloud: needsCloud ? { ...config.cloud!, auth: value } : config.cloud,
    applb: needsApplb ? { ...config.applb!, auth: value } : config.applb,
    obs: needsObs ? { ...config.obs!, auth: value } : config.obs,
    ci: needsCi ? { ...config.ci!, auth: value } : config.ci,
    remote: needsRemote ? { ...config.remote!, auth: value } : config.remote,
  };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const timeout = Number(env.HEYO_MCP_TIMEOUT_MS ?? "30000");
  const cloud = cloudService(env.HEYO_BASE_URL, env.HEYO_API_KEY);
  return {
    cloud,
    applb: applbService(
      env.APPLB_URL,
      env.APPLB_NAMESPACE,
      env.APPLB_TOKEN,
      env.APPLB_BASIC,
      cloud,
    ),
    obs: service(env.APP_OBS_URL, env.APP_OBS_API_TOKEN),
    ci: service(env.CI_URL, env.CI_TOKEN),
    // Falls back to the app-lb token: the remote resolves `applb_…` tokens
    // through app-lb, so the credential an agent already has is enough.
    remote: service(env.REMOTE_URL, env.REMOTE_TOKEN?.trim() || env.APPLB_TOKEN || env.HEYO_API_KEY),
    remoteNamespace: env.REMOTE_NAMESPACE?.trim() || env.APPLB_NAMESPACE?.trim() || undefined,
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
  if (config.cloud?.auth) {
    // "cloud is configured" is not the useful fact when the key it is
    // configured with is one cloud will refuse, so that is said here.
    on.push(
      cloudUsable(config)
        ? `heyo cloud (${config.cloud.baseUrl})`
        : `heyo cloud (${config.cloud.baseUrl}) — NO usable key: HEYO_API_KEY holds an applb_… token`,
    );
  }
  if (config.applb) {
    on.push(
      config.applb.namespace
        ? `app-lb (namespace ${config.applb.namespace})`
        : config.applb.discoverNamespace
          ? "app-lb (managed; namespace discovered on first use)"
          : "app-lb",
    );
  }
  if (config.obs) on.push("app-obs");
  if (config.ci) on.push("ci");
  if (config.remote) on.push(`git remote (${config.remote.baseUrl})`);
  return on;
}

/**
 * A credential that is present, well-formed, and cannot possibly work.
 *
 * The gap this closes: {@link configured} answers "is there a credential", and
 * every consumer treated that as "is there a *usable* credential". They are not
 * the same question, and the difference is a whole class of failure that this
 * server can detect at load and instead lets the user discover one 401 at a
 * time.
 *
 * `summary` is one line for a banner. `detail` explains the fix in
 * {@link NotConfigured}'s register: name the variable, then name the
 * configuration that works. Neither ever contains the token.
 */
export interface CredentialFault {
  readonly service: "heyo cloud" | "app-lb";
  readonly summary: string;
  readonly detail: string;
}

/**
 * Whether cloud has a credential it could actually authenticate with.
 *
 * The predicate `makeClients` and `buildTools` must agree on, which is why it
 * is a function rather than a test written twice. Disagreement is worse than
 * either answer: list the sandbox tools on a config that cannot reach cloud and
 * every one of them answers `NotConfigured`; withhold them from a config that
 * can and the caller is told a capability does not exist.
 */
export function cloudUsable(config: Config): boolean {
  return Boolean(config.cloud?.auth && !isApplbToken(config.cloud.auth));
}

/** How much of a token may be shown: enough to recognise, not enough to use. */
function redact(header?: string): string {
  const token = header ? bearerToken(header) : undefined;
  return token ? `${token.slice(0, APPLB_TOKEN_PREFIX.length + 4)}…` : "(none)";
}

/**
 * Credentials that are configured and cannot work, with the fix for each.
 *
 * Both faults are the same mistake seen from two sides: an `applb_…` token
 * where a `heyo_api_*` key is required. It is an easy mistake to make, because
 * an app-lb token is a real credential that a customer is legitimately given —
 * it is simply not a *cloud* credential, and cloud is what both of these
 * variables reach. {@link withForwardedAuth} already treats this as settled for
 * a token a caller *sends*; this applies the same law to the token this process
 * was *configured* with, which is the direction nothing checked.
 *
 * Loud, never fatal. A fleet-operations instance with a bad `HEYO_API_KEY` and
 * a good `APPLB_TOKEN` is still a useful server, and refusing to start would
 * take away the tools that do work.
 */
export function credentialFaults(config: Config): CredentialFault[] {
  const faults: CredentialFault[] = [];

  if (config.cloud?.auth && isApplbToken(config.cloud.auth)) {
    faults.push({
      service: "heyo cloud",
      summary: `HEYO_API_KEY holds an app-lb token (${redact(config.cloud.auth)}), which cloud cannot accept`,
      detail:
        "HEYO_API_KEY is a heyo cloud API key and must start with `heyo_api_`. It holds a " +
        "token app-lb minted for itself instead. Cloud has never heard of app-lb's tokens, so " +
        "every sandbox call — and every managed-namespace lookup — can only answer 401.\n\n" +
        "An `applb_…` token is a real credential; it just belongs somewhere else. Put it in " +
        "APPLB_TOKEN and set APPLB_URL to app-lb's own admin listener, then leave HEYO_API_KEY " +
        "unset: the app-lb tools work, and the sandbox tools are correctly not listed rather " +
        "than listed and failing. Over HTTP, send it as the request's own `Authorization` " +
        "header and this process needs no credential at all.",
    });
  }

  const cloudBase = config.cloud?.baseUrl ?? CLOUD_BASE_URL;
  const applb = config.applb;
  if (applb?.auth && isApplbToken(applb.auth) && applb.baseUrl.startsWith(cloudBase)) {
    faults.push({
      service: "app-lb",
      summary: `app-lb is reached through cloud's managed door with an app-lb token (${redact(applb.auth)}), which that door cannot resolve`,
      detail:
        `app-lb is configured at ${applb.baseUrl}, which is heyo cloud's managed door, but its ` +
        "credential is a token app-lb minted. That door forwards a `heyo_api_*` key for cloud " +
        "to resolve into a namespace grant; it cannot resolve an app-token, so namespace " +
        "discovery answers 401 before any deployment call is even attempted.\n\n" +
        // Where the credential came from, when it was not named directly. With
        // no APPLB_TOKEN the managed door borrows cloud's key, so the variable
        // the user actually set is HEYO_API_KEY and saying only "set
        // APPLB_TOKEN" would leave them fixing half of it.
        (applb.auth === config.cloud?.auth
          ? "This credential is not APPLB_TOKEN — none is set, so the managed door borrowed " +
            "HEYO_API_KEY, which through that door is meant to be the same kind of key. " +
            "Fixing HEYO_API_KEY therefore fixes both halves at once.\n\n"
          : "") +
        "Set APPLB_URL to app-lb's own admin listener and keep this token in APPLB_TOKEN — " +
        "reached directly, app-lb scope-checks it itself. Or supply a `heyo_api_*` key and " +
        "reach app-lb through the managed door as before.",
    });
  }

  return faults;
}

/**
 * What a 401 from cloud means when the key is an app-lb token.
 *
 * The third hint, and the one that catches what config-load cannot: a hosted
 * instance carries no credential of its own, so the offending key can arrive on
 * the request itself via {@link withForwardedAuth} and never pass through
 * {@link credentialFaults} at all. Stated here so every cloud call site carries
 * it, exactly as the two hints below are.
 */
export const CLOUD_KEY_HINT =
  "The key used for this call is an app-lb token (`applb_…`), and heyo cloud has never " +
  "heard of app-lb's tokens — this 401 is the credential being the wrong kind, not the " +
  "wrong value, and no retry will change it. Cloud wants a `heyo_api_*` key. An " +
  "`applb_…` token reaches app-lb directly: set APPLB_URL to app-lb's own admin listener " +
  "with APPLB_TOKEN, or send it as the request's own Authorization header. Run " +
  "`heyo_status` to see every credential this server holds and what each one can reach.";

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

/**
 * What a 503 from cloud means, said once here rather than guessed at each call
 * site. It is a *placement* answer — "no host in this region runs that driver
 * and has room" — not a fault, so it is retryable in the sense that capacity
 * comes back, and not retryable in the sense that hammering it changes nothing.
 */
export const CLOUD_CAPACITY_HINT =
  "cloud answered 503: this is region capacity, not a fault. No backend in the " +
  "requested region could take the sandbox — usually every host that runs the " +
  "requested driver is full, or none runs it at all. Retrying the same request " +
  "immediately will fail the same way; retry with backoff (a few seconds, " +
  "doubling, ~5 attempts), and call heyo_capacity first to see whether any " +
  "daemon is online at all. Naming a driver the fleet actually runs " +
  "(driver: \"firecracker\") or the other region often succeeds where the " +
  "default did not.";
