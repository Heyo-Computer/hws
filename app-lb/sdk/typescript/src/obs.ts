/**
 * One namespace's telemetry, read through app-lb's `obs` plugin. Mirrors the
 * `hws` crate's `ObsClient`.
 *
 * Installing `obs` into a namespace makes app-obs collect metrics and logs for
 * every deployment in it. A namespace-scoped credential reads them through
 * app-lb, which checks the caller reaches the namespace and talks to app-obs on
 * its behalf — nothing here needs to know where app-obs lives.
 *
 * ```ts
 * await lb.installPlugin("team-a", "obs");
 * const obs = lb.obs("team-a");
 * for (const row of (await obs.fleet({ window: "1h" })).deployments) {
 *   console.log(row.id, row.log_lines, row.error_logs);
 * }
 * const page = await obs.logs("web", { level: "error", limit: 50 });
 * ```
 *
 * Every method rejects with a `ConflictError` whose `code` is
 * `plugin_not_installed` or `plugin_disabled` when the plugin is not usable in
 * the namespace.
 */

import type { Heyctl } from "./client.js";
import type { ObsAlert, ObsDeployment, ObsFleet, ObsLogs } from "./types.js";

/** The plugin id of the telemetry plugin. */
export const OBS_PLUGIN = "obs";

/** Which log lines {@link ObsClient.logs} returns. Every filter is optional. */
export interface LogQuery {
  /** `15m`, `1h`, `6h`, `1d`, `7d`, … */
  window?: string;
  /** Range start, epoch milliseconds. Overrides `window`'s start. */
  from?: number;
  /** Range end, epoch milliseconds. */
  to?: number;
  level?: string;
  /** One VM (sandbox id) or upstream. */
  backend?: string;
  /** Case-insensitive substring of the message. Sent as `q`. */
  search?: string;
  limit?: number;
  /** Page boundary, epoch milliseconds, inclusive — a page's `next_before_ms`. */
  before?: number;
}

/** The body of {@link ObsClient.createAlert}. */
export interface NewAlert {
  deployment: string;
  threshold: number;
  webhook_url: string;
  /** `errors` when omitted — currently the only metric. */
  metric?: string;
}

/** `?window=…&level=…` in the order the crate writes it, or `""`. */
export function logQueryString(q: LogQuery = {}): string {
  const parts: string[] = [];
  const text = (k: string, v?: string) => {
    if (v) parts.push(`${k}=${encodeURIComponent(v)}`);
  };
  text("window", q.window);
  text("level", q.level);
  text("backend", q.backend);
  text("q", q.search);
  for (const [k, v] of [["from", q.from], ["to", q.to], ["before", q.before]] as const) {
    if (v !== undefined) parts.push(`${k}=${v}`);
  }
  if (q.limit !== undefined) parts.push(`limit=${q.limit}`);
  return parts.length ? `?${parts.join("&")}` : "";
}

const seg = encodeURIComponent;

export class ObsClient {
  constructor(
    private readonly client: Heyctl,
    readonly namespace: string,
  ) {}

  private path(rest: string): string {
    return `/namespaces/${seg(this.namespace)}/plugins/${OBS_PLUGIN}/api/${rest}`;
  }

  /** Every deployment with telemetry in the window, with series and log counts. */
  fleet(opts: { window?: string; signal?: AbortSignal } = {}): Promise<ObsFleet> {
    const q = opts.window ? `?window=${seg(opts.window)}` : "";
    return this.client.request("GET", this.path(`fleet${q}`), {
      kind: "namespace",
      name: this.namespace,
      signal: opts.signal,
    });
  }

  /**
   * One deployment's metrics and log volume. A deployment outside this
   * namespace is a `NotFoundError`, exactly as one that does not exist.
   */
  deployment(
    id: string,
    opts: { window?: string; signal?: AbortSignal } = {},
  ): Promise<ObsDeployment> {
    const q = opts.window ? `?window=${seg(opts.window)}` : "";
    return this.client.request("GET", this.path(`deployments/${seg(id)}${q}`), {
      kind: "deployment",
      name: id,
      signal: opts.signal,
    });
  }

  /**
   * One page of a deployment's logs, newest first. To page back, pass
   * `next_before_ms` as `before` until it comes back `null`.
   */
  logs(id: string, query: LogQuery = {}, signal?: AbortSignal): Promise<ObsLogs> {
    return this.client.request(
      "GET",
      `${this.path(`deployments/${seg(id)}/logs`)}${logQueryString(query)}`,
      { kind: "deployment", name: id, signal },
    );
  }

  /** The namespace's alert rules. */
  alerts(signal?: AbortSignal): Promise<ObsAlert[]> {
    return this.client.request("GET", this.path("alerts"), { kind: "alert", signal });
  }

  /**
   * POST `webhook_url` whenever `deployment` logs more than `threshold` errors
   * in a minute. Needs `admin` in the namespace.
   */
  createAlert(alert: NewAlert, signal?: AbortSignal): Promise<ObsAlert> {
    const body: Record<string, unknown> = {
      deployment: alert.deployment,
      threshold: alert.threshold,
      webhook_url: alert.webhook_url,
    };
    if (alert.metric) body.metric = alert.metric;
    return this.client.request("POST", this.path("alerts"), {
      body,
      kind: "alert",
      name: alert.deployment,
      signal,
    });
  }

  /** Delete a rule. Deleting one that does not exist succeeds. */
  async deleteAlert(id: string, signal?: AbortSignal): Promise<void> {
    await this.client.request<void>("DELETE", this.path(`alerts/${seg(id)}`), {
      kind: "alert",
      name: id,
      signal,
      expect: "nothing",
    });
  }
}
