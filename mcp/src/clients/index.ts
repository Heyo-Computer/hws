/**
 * Thin typed accessors over the HTTP APIs: app-lb, app-obs, ci and the git
 * remote. None of them is the Heyo cloud: sandboxes are app-lb's.
 *
 * Deliberately not a full model of each response: these services evolve, and a
 * client that parses every field breaks on additions it does not care about.
 * Tools reach into what they need and pass the rest through.
 */

import { bind, ServiceError, type Requester } from "../http.js";
import type { Config } from "../config.js";

export interface Clients {
  /** app-lb's admin API: deployments, and the sandboxes that are deployments. */
  applb: Requester;
  obs: Requester;
  ci: Requester;
  /**
   * The caller's namespace's artifacts, through app-lb: paths here are
   * relative to `/namespaces/{ns}/artifacts` on the app-lb admin API, and the
   * caller's own app-lb credential is what app-lb checks. The bytes a `site`
   * or `vm` deployment runs from.
   */
  artifacts: Requester;
  /**
   * The namespace {@link artifacts} addresses: the managed namespace when
   * there is one, else the namespace app-lb's `GET /whoami` puts the
   * credential in. Throws when neither names one.
   */
  artifactNamespace: () => Promise<string>;
  /** The git remote — repos agents push to and app-lb builds from. */
  remote: Requester;
  /**
   * The namespace configured for app-lb (`APPLB_NAMESPACE`), if any. Tools that
   * must *name* a namespace ask {@link callerNamespace}, which falls back to
   * app-lb's `/whoami`.
   */
  applbNamespace: () => Promise<string | undefined>;
  /**
   * The namespace the caller works in: the managed one, else the one app-lb's
   * `GET /whoami` confines the credential to. `undefined` when neither names
   * one (a self-hosted app-lb, a fleet token). What tools that would
   * otherwise make a namespace-token caller repeat their namespace ask.
   */
  callerNamespace: () => Promise<string | undefined>;
}

export function makeClients(config: Config): Clients {
  const applbRequest = bind("app-lb", config.applb, "APPLB_URL", config);
  const applbNamespace = async () => config.applb?.namespace;
  const artifactNamespace = artifactNamespaceOf(applbRequest, applbNamespace);
  return {
    applb: applbRequest,
    obs: bind("app-obs", config.obs, "APP_OBS_URL", config),
    ci: bind("ci", config.ci, "CI_URL", config),
    artifacts: artifactsRequester(applbRequest, artifactNamespace),
    artifactNamespace,
    remote: bind("git remote", config.remote, "REMOTE_URL", config),
    applbNamespace,
    callerNamespace: () => artifactNamespace().catch(() => undefined),
  };
}

/**
 * Which namespace's artifacts the caller means. Memoized on success only: a
 * namespace that does not resolve now may after the operator names one.
 */
function artifactNamespaceOf(
  applb: Requester,
  applbNamespace: () => Promise<string | undefined>,
): () => Promise<string> {
  let pending: Promise<string> | undefined;
  return () => {
    pending ??= (async () => {
      const managed = await applbNamespace();
      if (managed) return managed;
      const who = (await applb({ path: "/whoami" })) as { namespace?: unknown } | null;
      if (typeof who?.namespace === "string" && who.namespace.trim()) return who.namespace.trim();
      throw new Error(
        "artifacts are per namespace, and this credential names none (app-lb's /whoami " +
          "reports no namespace). Set APPLB_NAMESPACE, or use a namespace's app-lb token.",
      );
    })().catch((e) => {
      pending = undefined;
      throw e;
    });
    return pending;
  };
}

/**
 * app-lb's namespace-scoped artifact API. app-lb enforces who may read and
 * write; this only builds the path and turns the two statuses whose meaning
 * is not obvious from app-lb's body into a sentence.
 */
function artifactsRequester(applb: Requester, namespace: () => Promise<string>): Requester {
  return async (opts) => {
    const ns = await namespace();
    try {
      return await applb({ ...opts, path: `/namespaces/${encodeURIComponent(ns)}/artifacts${opts.path}` });
    } catch (e) {
      if (!(e instanceof ServiceError)) throw e;
      const extra =
        e.status === 503
          ? "This app-lb has no artifact store configured, so there are no artifacts to reach here."
          : e.status === 403
            ? `app-lb refused this credential for namespace ${ns}'s artifacts: tags must start with ` +
              `"${ns}/", reads need the view tier there and writes the admin tier over the whole ` +
              "namespace (not a token narrowed to particular deployments). heyo_whoami shows yours."
            : e.status === 502
              ? "app-lb could not reach its artifact store; retry later."
              : undefined;
      if (!extra) throw e;
      throw new ServiceError(e.service, e.status, e.path, e.body, extra);
    }
  };
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
