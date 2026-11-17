/**
 * One namespace's alerts, through app-lb's `alerting` plugin. Mirrors the
 * `hws` crate's `AlertingClient`.
 *
 * The operator switches the plugin on for the fleet; a namespace
 * administrator installs it with the namespace's receivers, rules and checks
 * as the install configuration. app-lb then evaluates the rules against the
 * namespace's own deployments and posts signed webhooks when an alert fires
 * and when it resolves. This client reads what it found and acknowledges,
 * silences and tests.
 *
 * ```ts
 * const alerting = lb.alerting("team-a");
 * const { active } = await alerting.alerts();
 * for (const a of active) await alerting.ack(a.fingerprint, "looking");
 * await alerting.silence({ deployment: "web", until: Math.floor(Date.now() / 1000) + 3600 });
 * ```
 *
 * Every method rejects with a `ConflictError` whose `code` is
 * `plugin_not_installed` or `plugin_disabled` when the plugin is not usable in
 * the namespace.
 */

import type { Heyctl } from "./client.js";
import type {
  AlertingAlert,
  AlertingAlerts,
  AlertingChecks,
  AlertingDeliveries,
  AlertingSilence,
  AlertingSilences,
  AlertingStatus,
  AlertingTestDelivery,
  DeletedAlertingSilence,
} from "./types.js";

/** The plugin id of the alerting plugin. */
export const ALERTING_PLUGIN = "alerting";

/** The body of {@link AlertingClient.silence}. An unset matcher matches anything. */
export interface NewSilence {
  rule?: string;
  deployment?: string;
  /** `info`, `warning` or `critical`. */
  severity?: string;
  /** Unix seconds, or an RFC 3339 time; at most 90 days ahead. */
  until: number | string;
  comment?: string;
}

const seg = encodeURIComponent;

export class AlertingClient {
  constructor(
    private readonly client: Heyctl,
    readonly namespace: string,
  ) {}

  private path(rest: string): string {
    return `/namespaces/${seg(this.namespace)}/plugins/${ALERTING_PLUGIN}/api/${rest}`;
  }

  private get<T>(rest: string, signal?: AbortSignal): Promise<T> {
    return this.client.request("GET", this.path(rest), {
      kind: "namespace",
      name: this.namespace,
      signal,
    });
  }

  /** Receivers, rules and counts. */
  status(signal?: AbortSignal): Promise<AlertingStatus> {
    return this.get("status", signal);
  }

  /** Pending and firing alerts, and the recently resolved (newest first). */
  alerts(signal?: AbortSignal): Promise<AlertingAlerts> {
    return this.get("alerts", signal);
  }

  /** Acknowledge an alert: no repeat notifications until it resolves. Needs `admin`. */
  ack(fingerprint: string, comment?: string, signal?: AbortSignal): Promise<AlertingAlert> {
    return this.client.request("POST", this.path(`alerts/${seg(fingerprint)}/ack`), {
      body: comment === undefined ? {} : { comment },
      kind: "alert",
      name: fingerprint,
      signal,
    });
  }

  /** The silences in force. */
  silences(signal?: AbortSignal): Promise<AlertingSilences> {
    return this.get("silences", signal);
  }

  /** Hold notifications for matching alerts until `until`. Needs `admin`. */
  silence(s: NewSilence, signal?: AbortSignal): Promise<AlertingSilence> {
    const matchers: Record<string, string> = {};
    if (s.rule !== undefined) matchers.rule = s.rule;
    if (s.deployment !== undefined) matchers.deployment = s.deployment;
    if (s.severity !== undefined) matchers.severity = s.severity;
    return this.client.request("POST", this.path("silences"), {
      body: { matchers, until: s.until, comment: s.comment ?? "" },
      kind: "namespace",
      name: this.namespace,
      signal,
    });
  }

  /** Remove a silence. Needs `admin`. */
  unsilence(id: string, signal?: AbortSignal): Promise<DeletedAlertingSilence> {
    return this.client.request("DELETE", this.path(`silences/${seg(id)}`), {
      kind: "silence",
      name: id,
      signal,
    });
  }

  /** Each check and its last result. */
  checks(signal?: AbortSignal): Promise<AlertingChecks> {
    return this.get("checks", signal);
  }

  /** The last webhooks sent, newest first. */
  deliveries(signal?: AbortSignal): Promise<AlertingDeliveries> {
    return this.get("deliveries", signal);
  }

  /** Queue an `alert.test` webhook to a receiver. Needs `admin`. */
  testReceiver(receiver: string, signal?: AbortSignal): Promise<AlertingTestDelivery> {
    return this.client.request("POST", this.path(`receivers/${seg(receiver)}/test`), {
      kind: "receiver",
      name: receiver,
      signal,
    });
  }
}
