/**
 * Which door a telemetry read goes through, and whose credential opens it.
 *
 * app-obs is one collector per region, and its own API has one service token
 * that reads every namespace. That token is the operator's. A caller confined
 * to a namespace must never read app-obs on it — that would hand a token scoped
 * to one room the contents of every room, the confused deputy
 * `withForwardedAuth` exists to close for app-lb itself.
 *
 * So a confined caller reads app-obs the way the dashboard does: through
 * app-lb's per-namespace plugin surface, `/namespaces/{ns}/plugins/obs/…`,
 * with *its own* credential. app-lb checks that the caller reaches `{ns}`, and
 * then calls app-obs with the service token and the namespace pinned in the
 * path — so what comes back is that namespace's rows and nothing else, and the
 * service token never leaves app-lb.
 *
 * The direct door (`APP_OBS_URL`) is kept for the one caller it was built for:
 * somebody app-lb itself says is unconfined — the operator, a fleet token —
 * asking about the whole fleet.
 */

import type { Clients } from "./clients/index.js";
import type { Config } from "./config.js";
import { NotConfigured, ServiceError, type RequestOptions } from "./http.js";

/** Where one telemetry read goes. */
export type TelemetryRoute =
  | { via: "applb"; namespace: string }
  | { via: "obs" };

/** The app-lb path prefix that fronts app-obs for one namespace. */
export function obsPluginPrefix(ns: string): string {
  return `/namespaces/${encodeURIComponent(ns)}/plugins/obs`;
}

interface Whoami {
  confined?: unknown;
  namespace?: unknown;
  namespaces?: unknown;
}

/**
 * The namespace `/whoami` confines this credential to, `null` when it is not
 * confined, or a thrown error when it is confined to several and none was
 * named — picking one would silently read the wrong room.
 */
function confinedNamespace(body: unknown): string | null {
  const who = (body ?? {}) as Whoami;
  if (who.confined !== true) return null;
  if (typeof who.namespace === "string" && who.namespace) return who.namespace;
  const several =
    who.namespaces && typeof who.namespaces === "object"
      ? Object.keys(who.namespaces as Record<string, unknown>)
      : [];
  if (several.length === 1) return several[0]!;
  throw new Error(
    several.length === 0
      ? "app-lb says this credential is confined but names no namespace, so there is no " +
          "telemetry to read. Run heyo_whoami."
      : `This credential reaches ${several.length} namespaces (${several.join(", ")}); ` +
          "pass `namespace` to say which one's telemetry you mean.",
  );
}

/**
 * Decide the route for one telemetry read.
 *
 * In order:
 *
 * 1. A namespace the caller named goes through app-lb. app-lb, not this
 *    server, decides whether they reach it.
 * 2. The managed door already knows its namespace (configured or discovered),
 *    and every caller of it is confined by construction.
 * 3. Otherwise app-lb is asked who this credential is. Confined → app-lb.
 *    Unconfined → app-obs directly when it is configured; with no app-obs
 *    configured there is no fleet-wide door, so the caller has to name a
 *    namespace.
 *
 * Over stdio the operator wired both credentials into this process
 * themselves, so a `/whoami` that fails (app-lb down, say) falls back to the
 * direct door rather than costing them their logs. Over HTTP the credential is
 * a caller's, and a failure to prove them unconfined is a refusal.
 */
export async function telemetryRoute(
  clients: Clients,
  config: Config,
  namespace?: string,
): Promise<TelemetryRoute> {
  const named = namespace?.trim();
  if (named) {
    if (!config.applb) throw new NotConfigured("app-lb", "APPLB_URL or APPLB_TOKEN");
    return { via: "applb", namespace: named };
  }
  // One answer per client set: a client set is one credential (per process
  // over stdio, per request over HTTP), and who it is does not change between
  // two tool calls. A failure is not kept, so a transient one is retried.
  let pending = resolved.get(clients);
  if (!pending) {
    pending = resolveRoute(clients, config);
    resolved.set(clients, pending);
    pending.catch(() => resolved.delete(clients));
  }
  return pending;
}

const resolved = new WeakMap<Clients, Promise<TelemetryRoute>>();

async function resolveRoute(clients: Clients, config: Config): Promise<TelemetryRoute> {
  if (!config.applb) {
    if (config.obs) return { via: "obs" };
    throw new NotConfigured("app-obs", "APP_OBS_URL, or APPLB_URL to read it through app-lb");
  }

  const managed = await clients.applbNamespace();
  if (managed) return { via: "applb", namespace: managed };

  let who: unknown;
  try {
    who = await clients.applb({ path: "/whoami" });
  } catch (e) {
    if (!config.http && config.obs) return { via: "obs" };
    throw e;
  }
  const ns = confinedNamespace(who);
  if (ns) return { via: "applb", namespace: ns };
  // Unconfined is not the same as fleet-wide: a token scoped to a list of
  // deployments is neither, and app-obs's own token would hand it every
  // deployment's telemetry. Only a credential app-lb says covers the fleet
  // may use the direct door.
  if ((who as { fleet?: unknown } | null)?.fleet !== true) {
    throw new Error(
      "This credential is scoped to specific deployments rather than a namespace or the " +
        "fleet, so app-obs cannot be narrowed to it. Use a namespace token to read that " +
        "namespace's telemetry through app-lb's obs plugin.",
    );
  }
  if (config.obs) return { via: "obs" };
  throw new Error(
    "This credential is not confined to a namespace and no APP_OBS_URL is configured, so " +
      "there is no fleet-wide telemetry door. Pass `namespace` to read one namespace's " +
      "telemetry through app-lb's obs plugin.",
  );
}

/**
 * One read (or, for alerts, write) against app-obs along `route`. `opts.path`
 * is app-obs's own API path, e.g. `/api/fleet` — the prefix is added here.
 */
export async function telemetry(
  clients: Clients,
  route: TelemetryRoute,
  opts: RequestOptions,
): Promise<unknown> {
  if (route.via === "obs") return clients.obs(opts);
  try {
    return await clients.applb({ ...opts, path: `${obsPluginPrefix(route.namespace)}${opts.path}` });
  } catch (e) {
    throw explainPluginRefusal(e, route.namespace);
  }
}

/**
 * app-lb's 409s on the plugin surface carry a `code`; turn the two that mean
 * "nothing is being collected" into what to do about it. Everything else is
 * passed through untouched — its body already says what it means.
 */
export function explainPluginRefusal(e: unknown, ns: string): unknown {
  if (!(e instanceof ServiceError) || e.status !== 409) return e;
  let code: unknown;
  try {
    code = (JSON.parse(e.body) as { code?: unknown }).code;
  } catch {
    return e;
  }
  if (code === "plugin_not_installed") {
    return new Error(
      `The obs plugin is not installed in namespace "${ns}", so no telemetry is being ` +
        "collected for its deployments. A namespace admin installs it with " +
        `\`heyctl plugins install obs -n ${ns}\` (or PUT /namespaces/${ns}/plugins/obs). ` +
        "Collection starts from that moment; nothing from before it is backfilled.",
    );
  }
  if (code === "plugin_disabled") {
    return new Error(
      "The obs plugin is switched off for this whole app-lb. That is an operator setting " +
        "(`heyctl plugins enable obs`), not one a namespace can change — ask whoever runs " +
        "the fleet.",
    );
  }
  return e;
}
