/**
 * One HTTP helper for all three services.
 *
 * Two decisions worth naming, both learned from debugging these services rather
 * than guessed:
 *
 * **Every request is bounded.** A service that accepts a connection and then
 * answers nothing is the failure mode this fleet actually has — a tunnel whose
 * QUIC connection is up and whose data path is dead, a database behind a pool
 * that suspends idle instances. An unbounded fetch turns that into a tool call
 * that never returns.
 *
 * **The body is kept on failure.** These APIs put the useful sentence in the
 * response body, and a bare status code discards exactly the part worth
 * reading.
 */

import type { Config, ServiceConfig } from "./config.js";
import { CI_GATE_HINT, CLOUD_CAPACITY_HINT, CLOUD_KEY_HINT, isApplbToken } from "./config.js";

export class ServiceError extends Error {
  constructor(
    readonly service: string,
    readonly status: number,
    readonly path: string,
    readonly body: string,
    hint?: string,
  ) {
    const detail = body.trim().slice(0, 600);
    super(
      `${service} ${status} on ${path}` +
        (detail ? `: ${detail}` : "") +
        (hint ? `\n\n${hint}` : ""),
    );
    this.name = "ServiceError";
  }
}

export class NotConfigured extends Error {
  constructor(service: string, envVar: string) {
    super(
      `${service} is not configured — set ${envVar}. ` +
        `Run the \`heyo_status\` tool to see which services are reachable.`,
    );
    this.name = "NotConfigured";
  }
}

export interface RequestOptions {
  method?: string;
  path: string;
  query?: Record<string, string | number | undefined>;
  body?: unknown;
  /**
   * Sent verbatim instead of `body`, for an API that takes bytes rather than
   * JSON. app-lb's `PUT …/artifacts/blobs/{digest}` is the case: the body is
   * the blob, and JSON-encoding it would both corrupt it and change its digest
   * — which is its name.
   */
  rawBody?: Uint8Array | string;
  /** Content type for `rawBody`. Ignored when `body` is used, which is JSON. */
  contentType?: string;
  /**
   * Return the response body as text rather than parsing it.
   *
   * For an endpoint whose success answer is not JSON and must not be guessed
   * at.
   */
  expectText?: boolean;
  /**
   * Return the response body as raw bytes. For artifact blob downloads,
   * which are arbitrary binary and would be corrupted by a text
   * decode.
   */
  expectBytes?: boolean;
  /**
   * A sentence attached to any error from this call, on top of whatever the
   * status alone implies.
   *
   * For a call the *user* did not make. Namespace discovery is the case: it
   * runs inside the first app-lb tool of the process, against cloud, on a path
   * nobody asked for, so its failures need to say what they were for before
   * they say what went wrong.
   */
  hint?: string;
}

function withQuery(path: string, query?: RequestOptions["query"]): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== "") params.set(k, String(v));
  }
  const qs = params.toString();
  return qs ? `${path}${path.includes("?") ? "&" : "?"}${qs}` : path;
}

export async function request(
  service: string,
  cfg: ServiceConfig,
  timeoutMs: number,
  opts: RequestOptions,
): Promise<unknown> {
  const path = withQuery(opts.path, opts.query);
  const headers: Record<string, string> = { accept: "application/json" };
  if (cfg.auth) headers.authorization = cfg.auth;
  // Before the per-request ones, so a service that carries a second credential
  // cannot have it silently dropped, and after `authorization`, which is the
  // one header a service config never puts here. See `ServiceConfig.headers`.
  Object.assign(headers, cfg.headers ?? {});
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  if (opts.rawBody !== undefined) {
    headers["content-type"] = opts.contentType ?? "application/octet-stream";
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res: Response;
  try {
    res = await fetch(`${cfg.baseUrl}${path}`, {
      method: opts.method ?? "GET",
      headers,
      body:
        opts.rawBody !== undefined
          ? opts.rawBody
          : opts.body === undefined
            ? undefined
            : JSON.stringify(opts.body),
      signal: controller.signal,
    });
  } catch (e) {
    const reason = e instanceof Error && e.name === "AbortError"
      ? `no response within ${timeoutMs}ms — the service accepted the connection and did not answer`
      : e instanceof Error
        ? e.message
        : String(e);
    throw new Error(`${service} ${path}: ${reason}`);
  } finally {
    clearTimeout(timer);
  }

  const raw = new Uint8Array(await res.arrayBuffer());
  const text = opts.expectBytes && res.ok ? "" : new TextDecoder().decode(raw);
  if (!res.ok) {
    // Two statuses mean something more specific than they look, and both are
    // read wrong by default: a 401 from ci is the documented gate behaviour far
    // more often than it is a bad token, and a 503 from cloud is region
    // capacity rather than a fault. Attaching the sentence here means every
    // call site carries it, including the ones that only pass a body through.
    const status =
      service === "ci" && res.status === 401
        ? CI_GATE_HINT
        : service === "heyo cloud" && res.status === 503
          ? CLOUD_CAPACITY_HINT
          : // A cloud 401 or 403 with an app-lb token is not a bad password, it
            // is the wrong *kind* of credential, and the difference decides
            // whether retrying is pointless. Checked here rather than only at
            // config load because a hosted instance holds no key of its own and
            // takes the caller's — see `withForwardedAuth`, which can install
            // this credential long after `credentialFaults` has run.
            (res.status === 401 || res.status === 403) &&
              service === "heyo cloud" &&
              isApplbToken(cfg.auth ?? "")
            ? CLOUD_KEY_HINT
            : undefined;
    const hint = [opts.hint, status].filter(Boolean).join("\n\n") || undefined;
    throw new ServiceError(service, res.status, path, text, hint);
  }
  if (opts.expectBytes) return raw;
  if (!text.trim()) return null;
  if (opts.expectText) return text;
  try {
    return JSON.parse(text);
  } catch {
    // /metrics and some app-lb consoles answer text, not JSON. Returning the
    // string is more useful than failing on a successful response.
    return text;
  }
}

/**
 * A service's address, either known now or resolvable later.
 *
 * app-lb's managed base is the second case: reaching it means naming a
 * namespace, and a namespace that was not configured has to be read from the
 * key — a network call, which config loading is not allowed to make. The
 * resolver is called on each request and is expected to memoize itself.
 */
export type ServiceSource = ServiceConfig | (() => Promise<ServiceConfig>);

/** Bound a service to the config, so tools do not each re-check it. */
export function bind(service: string, cfg: ServiceSource | undefined, envVar: string, config: Config) {
  return async (opts: RequestOptions): Promise<unknown> => {
    if (!cfg) throw new NotConfigured(service, envVar);
    const resolved = typeof cfg === "function" ? await cfg() : cfg;
    return request(service, resolved, config.timeoutMs, opts);
  };
}

export type Requester = ReturnType<typeof bind>;
