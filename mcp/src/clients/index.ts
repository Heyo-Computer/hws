/**
 * Thin typed accessors over the four HTTP APIs.
 *
 * Deliberately not a full model of each response: these services evolve, and a
 * client that parses every field breaks on additions it does not care about.
 * Tools reach into what they need and pass the rest through.
 */

import { bind, request, ServiceError, type Requester, type ServiceSource } from "../http.js";
import { checkArtRequest, filterTags, type ArtScope } from "../artscope.js";
import { cloudUsable, credentialFaults, type Config, type ServiceConfig } from "../config.js";

export interface Clients {
  /** heyo cloud — sandboxes, archives, daemons. */
  cloud: Requester;
  applb: Requester;
  obs: Requester;
  ci: Requester;
  /** The artifact store — the bytes a `site` or `vm` deployment runs from. */
  art: Requester;
  /** The git remote — repos agents push to and app-lb builds from. */
  remote: Requester;
  /**
   * The managed namespace app-lb calls are confined to, discovering it if that
   * has not happened yet. Tools that must *name* the namespace rather than just
   * reach it — the feed is served at `/feeds/:namespace` — ask here instead of
   * re-deriving it, so one discovery serves them all. `undefined` for a
   * self-hosted app-lb, which has no namespace.
   */
  applbNamespace: () => Promise<string | undefined>;
}

export const CLOUD_SERVICE = "heyo cloud";

export function makeClients(config: Config): Clients {
  // Cloud with no *usable* credential is not a usable service: unlike app-lb's
  // self-hosted shape, there is no unauthenticated cloud to talk to. Say so as
  // "not configured" rather than letting every call come back 401 — which is
  // also why the test is `cloudUsable` and not mere presence. An `applb_…`
  // token is present and cannot work, and letting it through here is what made
  // one wrong variable look like a total outage.
  const cloud = cloudUsable(config) ? config.cloud : undefined;
  const applb = applbSource(config);
  return {
    cloud: bind(CLOUD_SERVICE, cloud, "HEYO_API_KEY", config),
    applb: bind("app-lb", applb, "APPLB_URL or APPLB_TOKEN", config),
    obs: bind("app-obs", config.obs, "APP_OBS_URL", config),
    ci: bind("ci", config.ci, "CI_URL", config),
    art: confineArt(bind("artifacts", config.art, "ART_URL (plus ART_API_KEY)", config), config.artScope),
    remote: bind("git remote", config.remote, "REMOTE_URL", config),
    applbNamespace: async () =>
      typeof applb === "function" ? (await applb()).namespace : applb?.namespace,
  };
}

/**
 * The store requester held to the caller's scope. Every art tool, `art_request`
 * included, goes through here, so this is the one place the rule is enforced.
 */
function confineArt(art: Requester, scope: ArtScope | undefined): Requester {
  if (!scope) return art;
  return async (opts) => {
    const verdict = checkArtRequest(scope, opts.method ?? "GET", opts.path);
    if (verdict.refused) throw new Error(verdict.refused);
    const out = await art(opts);
    return verdict.filterTagsTo === undefined ? out : filterTags(out, verdict.filterTagsTo);
  };
}

/**
 * app-lb's base, resolving the namespace on first use when none was named.
 *
 * The managed door is `/namespaces/{ns}/lb`, so a namespace is not optional —
 * but making the operator supply one when their key reaches exactly one is
 * asking them to repeat something the key already knows. So this reads
 * `GET /namespaces`, and:
 *
 * - one namespace is the answer, and the common case;
 * - several is genuinely ambiguous, and picking one would silently point every
 *   tool at the wrong room, so it fails naming them;
 * - none means there is nothing to point at yet, and says how to make one.
 *
 * Memoized across calls, and across the failures that a retry cannot change.
 *
 * Not memoizing *any* failure was the original rule, justified by one case: a
 * namespace created a minute after the first attempt should work without a
 * restart. That reasoning is sound and still applies — to a lookup that
 * succeeded and found nothing.
 *
 * It does not apply to a credential cloud refuses. Nothing about the next call
 * differs, so every tool in the process re-issued `GET /namespaces` and
 * re-collected the same 401: one wrong environment variable turned into a
 * network round-trip per tool call, each printing the same paragraph. So the
 * split is by what a retry could possibly fix — a refused credential and a
 * detected fault are held; everything else (5xx, timeouts, transport, and a key
 * that reaches no namespace *yet*) is retried as before.
 */
function applbSource(config: Config): ServiceSource | undefined {
  const cfg = config.applb;
  if (!cfg) return undefined;
  if (!cfg.discoverNamespace) return cfg;

  let pending: Promise<ServiceConfig> | undefined;
  return () => {
    pending ??= discoverNamespace(cfg, config).catch((e) => {
      if (!isPermanent(e)) pending = undefined;
      throw e;
    });
    return pending;
  };
}

/** Whether re-running namespace discovery could plausibly answer differently. */
function isPermanent(e: unknown): boolean {
  if (e instanceof ServiceError) return e.status === 401 || e.status === 403;
  // The pre-flight fault: the configuration is wrong, and it cannot become
  // right while this process runs.
  return e instanceof Error && e.name === "CredentialFaultError";
}

interface NamespaceRow {
  name?: unknown;
  scope?: unknown;
}

async function discoverNamespace(cfg: ServiceConfig, config: Config): Promise<ServiceConfig> {
  // Before the round-trip, not after it. This lookup is the first thing every
  // app-lb tool does when no namespace was named, so a credential that cannot
  // work here surfaces as ~20 tools failing against `/namespaces` — a cloud
  // path the user never asked about, for a question they asked app-lb. Naming
  // the real fault first is the difference between "app-lb is down" and "this
  // token goes in a different variable".
  const fault = credentialFaults(config).find((f) => f.service === "app-lb");
  if (fault) {
    const e = new Error(`${fault.summary}.\n\n${fault.detail}`);
    e.name = "CredentialFaultError";
    throw e;
  }

  const body = await request(CLOUD_SERVICE, cfg, config.timeoutMs, {
    path: "/namespaces",
    // Said out loud because the label above is `heyo cloud` and the caller
    // asked app-lb something: this call is cloud resolving which app-lb the
    // managed door means, and it happens because APPLB_NAMESPACE is unset.
    hint:
      "This was namespace discovery for the managed app-lb door, not a call you " +
      "made: with APPLB_NAMESPACE unset, cloud is asked which namespace this key " +
      "reaches before any app-lb path is built. Set APPLB_NAMESPACE to skip it, or " +
      "APPLB_URL to reach a self-hosted app-lb that has no namespaces at all.",
  });
  const rows: NamespaceRow[] = Array.isArray(body)
    ? body
    : Array.isArray((body as { namespaces?: unknown })?.namespaces)
      ? ((body as { namespaces: NamespaceRow[] }).namespaces)
      : [];
  const names = rows
    .map((r) => (typeof r?.name === "string" ? r.name : undefined))
    .filter((n): n is string => !!n);

  if (names.length === 1) {
    return {
      ...cfg,
      baseUrl: `${cfg.baseUrl}/namespaces/${encodeURIComponent(names[0]!)}/lb`,
      namespace: names[0],
      discoverNamespace: false,
    };
  }
  if (names.length === 0) {
    throw new Error(
      "This key reaches no app-lb namespace, so there is no managed app-lb to " +
        "address. Create one — `heyo_request POST /namespaces {\"name\":\"…\"}`, the " +
        "SDK's Namespaces.create, or the dashboard — or set APPLB_URL to a " +
        "self-hosted app-lb's own admin listener. Sandbox tools do not need this " +
        "and are unaffected.",
    );
  }
  throw new Error(
    `This key reaches ${names.length} app-lb namespaces (${names.join(", ")}), so ` +
      "which one the app-lb tools mean cannot be inferred. Set APPLB_NAMESPACE to " +
      "one of them.",
  );
}

/**
 * Run several reads and keep the failures as values.
 *
 * A cross-service tool must not lose every answer because one service is down —
 * "app-lb says X, app-obs is unreachable" is a diagnosis; a single thrown error
 * is not. This is what lets the tools below join four services without making
 * the weakest one fatal.
 */
export async function settle<T extends Record<string, Promise<unknown>>>(
  jobs: T,
): Promise<{ [K in keyof T]: { ok: true; value: unknown } | { ok: false; error: string } }> {
  const keys = Object.keys(jobs) as (keyof T)[];
  const results = await Promise.allSettled(keys.map((k) => jobs[k]));
  const out = {} as { [K in keyof T]: { ok: true; value: unknown } | { ok: false; error: string } };
  keys.forEach((k, i) => {
    const r = results[i]!;
    out[k] =
      r.status === "fulfilled"
        ? { ok: true, value: r.value }
        : { ok: false, error: r.reason instanceof Error ? r.reason.message : String(r.reason) };
  });
  return out;
}
