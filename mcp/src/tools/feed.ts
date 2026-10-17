/**
 * The per-namespace event feed — "what happened to my deployments".
 *
 * app-lb keeps a ring of lifecycle and issue events per namespace and serves it
 * as RSS at `GET /feeds/:namespace`, with `?format=json` for anything that
 * would rather not parse XML. Three properties decide how a client should use
 * it, and none of them is obvious from the URL:
 *
 * **It is a pull, not a push.** Nothing is delivered; something has to ask. A
 * client that wants event-driven behaviour polls, and the ring is sized for a
 * reader that polls occasionally rather than constantly (200 events, and
 * repeats of the same issue fold into one entry inside a 5-minute window rather
 * than appending — so a flapping deployment cannot flood a poller).
 *
 * **No subscription state is held anywhere.** app-lb does not track who has
 * read what; there is no per-reader watermark and no "unread". The cursor is
 * the caller's to keep — which is why {@link feedTools} takes `since_id` and
 * hands back `latest_id`, so keeping it is one field rather than a design.
 *
 * **The ring is in memory.** An app-lb restart empties it and event ids start
 * again from zero, so a saved `since_id` can be *higher* than anything in a
 * fresh feed. That is not an error and must not read as one: the tool detects
 * it and says the feed was reset, rather than silently returning nothing for
 * ever. Timestamps are the durable ordering; the record of what actually
 * happened is app-obs and the job history, not this.
 *
 * **Nothing publishes by default.** A deployment contributes only if its spec
 * says `feed.announce` or `feed.issues`. An empty feed usually means no
 * deployment opted in, not that nothing happened.
 */

import { z } from "zod";
import { num } from "./schema.js";
import type { Clients } from "../clients/index.js";
import { json, report } from "../format.js";
import type { Tool } from "./diagnose.js";

/**
 * Where else a feed can be read, said once here: outside the admin API, a feed
 * is served only where a deployment's spec carries `feed.expose`.
 */
const MANAGED_DOOR_NOTE =
  "A feed is reachable from outside the admin API only where a deployment's spec " +
  "carries `feed.expose`, which serves it on that deployment's own routes behind " +
  "that deployment's own auth gate.";

interface FeedEvent {
  id?: number;
  ts?: number;
  last_ts?: number;
  count?: number;
  namespace?: string;
  deployment?: string;
  kind?: string;
  title?: string;
  detail?: string;
}

function eventsFrom(body: unknown): FeedEvent[] {
  return Array.isArray(body) ? (body as FeedEvent[]) : [];
}

export function feedTools(clients: Clients): Tool[] {
  /**
   * Which namespace to read when the caller did not name one: the one app-lb
   * calls are already confined to, or — for a self-hosted app-lb, which has no
   * namespace of its own — the only one with events. Two candidates is
   * genuinely ambiguous and says so rather than picking.
   */
  async function resolveNamespace(given: unknown): Promise<string> {
    if (typeof given === "string" && given.trim()) return given.trim();
    const configured = await clients.applbNamespace();
    if (configured) return configured;
    const index = await clients.applb({ path: "/feeds" });
    const names = Array.isArray(index)
      ? index.map((r) => (r as { namespace?: unknown })?.namespace).filter((n): n is string => typeof n === "string")
      : [];
    if (names.length === 1) return names[0]!;
    if (names.length === 0) {
      throw new Error(
        "No namespace has any events, so there is nothing to read. Pass `namespace` " +
          "explicitly, or set APPLB_NAMESPACE. Remember that a deployment publishes " +
          "only if its spec sets feed.announce or feed.issues.",
      );
    }
    throw new Error(`Several namespaces have events (${names.join(", ")}) — pass one as \`namespace\`.`);
  }

  return [
    {
      name: "applb_feeds",
      description:
        "Which namespaces have deployment events, and how many. A discovery aid, not " +
        "the feed itself — applb_feed reads one.\n\n" + MANAGED_DOOR_NOTE,
      schema: {},
      handler: async () => json(await clients.applb({ path: "/feeds" })),
    },

    {
      name: "applb_feed",
      description:
        "Deployment events for one namespace, newest first: deployed, updated, removed, " +
        "and operational issues. Pass `since_id` — the `latest_id` from the previous " +
        "call — to get only what is new, because nothing server-side remembers what you " +
        "have seen. There is no push and no subscription: this is polled, and the " +
        "cursor is yours to keep.\n\n" +
        "app-lb holds the ring in memory, so a restart empties it and ids restart at " +
        "zero. When `since_id` is higher than anything present this says the feed was " +
        "reset and returns everything, rather than reporting an empty new-events list " +
        "for ever.\n\n" + MANAGED_DOOR_NOTE,
      schema: {
        namespace: z.string().optional().describe("defaults to the configured namespace"),
        since_id: num().optional().describe("the previous call's latest_id"),
        limit: num().optional().describe("most recent N after filtering"),
        kind: z
          .enum(["deployed", "updated", "removed", "issue"])
          .optional()
          .describe("only this kind of event"),
      },
      handler: async (a) => {
        const ns = await resolveNamespace(a.namespace);
        const all = eventsFrom(
          await clients.applb({ path: `/feeds/${encodeURIComponent(ns)}`, query: { format: "json" } }),
        );
        const latest = all.reduce((m, e) => Math.max(m, Number(e.id ?? 0)), 0);

        const since = Number(a.since_id ?? 0);
        // A cursor from before a restart is ahead of every id in the ring. Treat
        // that as a reset and show everything: the alternative is a client that
        // never sees another event and cannot tell why.
        const reset = since > 0 && latest > 0 && since > latest;
        let events = all;
        if (a.kind) events = events.filter((e) => e.kind === a.kind);
        if (since > 0 && !reset) events = events.filter((e) => Number(e.id ?? 0) > since);
        const limit = Number(a.limit ?? 0);
        if (limit > 0) events = events.slice(0, limit);

        return report(`${ns}: ${events.length} event(s), latest_id ${latest}`, [
          ...(reset
            ? [
                {
                  title: "Feed reset",
                  body:
                    `since_id ${since} is past the newest id in the feed (${latest}), which ` +
                    "means app-lb restarted and the in-memory ring began again. Everything " +
                    `it now holds is below; store latest_id ${latest} as the new cursor.`,
                },
              ]
            : []),
          { title: "Events (newest first)", body: events },
          { title: "Next cursor", body: { latest_id: latest } },
        ]);
      },
    },
  ];
}
