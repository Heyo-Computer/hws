/**
 * Who may use this server's artifact-store key, and for what.
 *
 * A hosted server holds no credentials of its own (deploy/vm.md), so every
 * upstream call runs as the caller. The store is the exception: it answers to
 * one key (`ART_API_KEY`), not to the caller's token, so a server configured
 * with that key acts *as the store's owner* on every art call it makes. Its
 * `/mcp` path is public at app-lb's gate, so tenants confined to any namespace
 * can reach it. Without the checks here, any caller — no credential at all —
 * could publish over, delete or make public any tag in the global store.
 *
 * So, per request, in HTTP mode, when the key is configured:
 *
 * 1. Only an `applb_…` bearer that app-lb's own `GET /whoami` vouches for gets
 *    the key. Anyone else reaches the store without it, which leaves them what
 *    the store gives anybody: anonymous reads of public blobs.
 * 2. A fleet token gets the store, read-only if its admin tier is `view`.
 * 3. A namespace token gets its own corner of it: refs under `<ns>/` (art's
 *    namespaced repositories), content-addressed reads and writes by digest, and
 *    a tag listing filtered to its prefix. Nothing store-wide.
 *
 * Every art call goes through one requester and the `/art` gateway, and both
 * check {@link checkArtRequest}, so `art_request`'s raw HTTP is held to the same
 * rules as the dedicated tools.
 */

import { createHash } from "node:crypto";
import { request } from "./http.js";
import { isApplbToken, type Config, type ServiceConfig } from "./config.js";

export type ArtScope =
  | { readonly kind: "fleet"; readonly write: boolean }
  | { readonly kind: "namespace"; readonly namespace: string; readonly write: boolean };

const NAMESPACE = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

/**
 * app-lb's `GET /whoami` answer for an app-token, reduced to its reach into the
 * store. `undefined` is "no key": anything that is not a verified app-token, a
 * token with no admin tier, or one confined to no usable namespace.
 */
export function scopeFromWhoami(body: unknown): ArtScope | undefined {
  const b = body as Record<string, unknown> | null;
  if (!b || b.caller !== "app-token") return undefined;
  const tier = b.admin_scope;
  if (tier !== "admin" && tier !== "view") return undefined;
  // A token confined to particular deployments was minted for those, not for
  // the store; like the git remote, it may read but not change anything.
  const deployments = Array.isArray(b.deployments) ? b.deployments : [];
  const narrowed = deployments.length > 0 && !(deployments.length === 1 && deployments[0] === "*");
  const write = tier === "admin" && !narrowed;
  if (b.fleet === true) return { kind: "fleet", write };
  const ns = b.namespace;
  if (typeof ns !== "string" || !NAMESPACE.test(ns)) return undefined;
  return { kind: "namespace", namespace: ns, write };
}

export interface ArtVerdict {
  /** Why the request is refused; `undefined` when it may go. */
  readonly refused?: string;
  /** A tag listing that must be cut down to this prefix before it is returned. */
  readonly filterTagsTo?: string;
}

const WRITES = new Set(["PUT", "POST", "PATCH", "DELETE"]);

/** Whether `scope` may make this request of the store. */
export function checkArtRequest(scope: ArtScope, method: string, rawPath: string): ArtVerdict {
  const m = method.toUpperCase();
  if (WRITES.has(m) && !scope.write) {
    return { refused: "this token is read-only for the artifact store (its admin tier is `view`, or it is confined to particular deployments)" };
  }
  if (scope.kind === "fleet") return {};

  const prefix = `${scope.namespace}/`;
  const refusal = (what: string): ArtVerdict => ({
    refused:
      `a token confined to namespace ${scope.namespace} may only reach ${prefix}… in the artifact store; ${what}. ` +
      `Publish under a namespaced tag such as ${prefix}app:latest.`,
  });

  const path = rawPath.split("?")[0] ?? "";
  if (!path.startsWith("/")) return refusal("the path must begin with '/'");
  const segments = path.slice(1).split("/");
  const top = segments[0] ?? "";
  let ref: string;
  try {
    ref = decodeURIComponent(segments.slice(1).join("/"));
  } catch {
    return refusal("the path is not valid percent-encoding");
  }
  if (ref.split("/").some((s) => s === ".." || s === ".")) return refusal("dot segments are not allowed");
  const ownRef = ref.startsWith(prefix) && ref.length > prefix.length;
  const digest = DIGEST.test(ref);
  const read = m === "GET" || m === "HEAD";

  switch (top) {
    case "blobs":
      // Content-addressed: a digest names the bytes, and publishing has to put
      // and check them. Listing every blob is store-wide.
      if (digest && (read || m === "PUT")) return {};
      return refusal(ref ? "blobs are addressed by sha256 digest" : "the store-wide blob listing is not available");
    case "manifests":
      if (!ref) return m === "PUT" ? {} : refusal("the store-wide manifest listing is not available");
      if (read && (digest || ownRef)) return {};
      return refusal(`${ref} is outside it`);
    case "tags":
      if (!ref) return read ? { filterTagsTo: prefix } : refusal("tags are changed one at a time");
      return ownRef ? {} : refusal(`${ref} is outside it`);
    case "labels":
    case "public":
      if (ownRef || (read && digest)) return {};
      return refusal(`${ref || "that"} is outside it`);
    case "repos":
      return ownRef ? {} : refusal(ref ? `${ref} is outside it` : "the store-wide repository listing is not available");
    default:
      return refusal(`/${top} is store-wide`);
  }
}

/** Keep only the listing entries under `prefix`, whatever shape the listing has. */
export function filterTags(body: unknown, prefix: string): unknown {
  const keep = (t: unknown) =>
    typeof (t as { tag?: unknown })?.tag === "string" && (t as { tag: string }).tag.startsWith(prefix);
  if (Array.isArray(body)) return body.filter(keep);
  const tags = (body as { tags?: unknown } | null)?.tags;
  if (Array.isArray(tags)) return { ...(body as object), tags: tags.filter(keep) };
  return [];
}

/** The store config with its key removed: what an unverified caller is sent with. */
function withoutStoreKey(art: ServiceConfig): ServiceConfig {
  const headers = Object.fromEntries(
    Object.entries(art.headers ?? {}).filter(([k]) => k.toLowerCase() !== "x-api-key"),
  );
  return { ...art, headers: Object.keys(headers).length ? headers : undefined };
}

export function holdsStoreKey(art?: ServiceConfig): boolean {
  return Object.keys(art?.headers ?? {}).some((k) => k.toLowerCase() === "x-api-key");
}

const WHOAMI_TTL_MS = 30_000;
const whoamiCache = new Map<string, { at: number; scope: ArtScope | undefined }>();

/** app-lb's verdict on a bearer, cached briefly so a burst of tool calls is one lookup. */
async function verify(base: Config, bearer: string): Promise<ArtScope | undefined> {
  const applb = base.applb;
  if (!applb) return undefined;
  const key = createHash("sha256").update(bearer).digest("hex");
  const hit = whoamiCache.get(key);
  if (hit && Date.now() - hit.at < WHOAMI_TTL_MS) return hit.scope;
  let scope: ArtScope | undefined;
  try {
    const body = await request("app-lb", { baseUrl: applb.baseUrl, auth: bearer }, base.timeoutMs, {
      path: "/whoami",
    });
    scope = scopeFromWhoami(body);
  } catch {
    // Refused, expired, revoked or unreachable: no key either way. Not cached,
    // so a transient failure does not outlive itself.
    return undefined;
  }
  whoamiCache.set(key, { at: Date.now(), scope });
  if (whoamiCache.size > 10_000) whoamiCache.clear();
  return scope;
}

/**
 * The per-request config's art half, decided by who is asking. `base` is the
 * process config (where the key and app-lb's URL live); `cfg` is the request's
 * config after {@link withForwardedAuth}.
 */
export async function authorizeArtCaller(
  base: Config,
  cfg: Config,
  headers: Record<string, string | string[] | undefined>,
): Promise<Config> {
  if (!cfg.art || !holdsStoreKey(cfg.art)) return cfg;
  const raw = headers["authorization"];
  const value = (Array.isArray(raw) ? raw[0] : raw)?.trim();
  const scope = value && isApplbToken(value) ? await verify(base, value) : undefined;
  if (!scope) return { ...cfg, art: withoutStoreKey(cfg.art), artScope: undefined };
  return { ...cfg, artScope: scope };
}

/** @internal for tests */
export function clearWhoamiCache(): void {
  whoamiCache.clear();
}
