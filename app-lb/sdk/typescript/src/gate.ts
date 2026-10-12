/**
 * Putting a deployment behind sign-in, from a program. Mirrors the `hws`
 * crate's `Gate`.
 *
 * Who may sign in is a namespace **auth provider**: `heyo` from the
 * `auth-heyo` plugin (on by default), `google` from `auth-google`, or one
 * declared with `createAuthProvider`. A deployment's gate *inherits* one by
 * name and keeps only what is its own: which paths skip sign-in, how long a
 * session lasts, where the sign-in endpoints live.
 *
 * ```ts
 * await lb.setAuth("reports", { provider: "heyo", publicPaths: [{ path: "/healthz" }] });
 * await lb.clearAuth("reports");
 * ```
 */

/** A path prefix that skips sign-in, and what app-lb requires there instead. */
export interface GatePath {
  path: string;
  /** `public` (no credential at all; the default), `none`, `view` or `admin`. */
  scope?: string;
}

/**
 * A sign-in gate inheriting its identity from a namespace auth provider. A
 * field left out keeps what the deployment's gate already has.
 */
export interface Gate {
  /** The auth provider's name in the deployment's namespace: `heyo`, `google`, … */
  provider: string;
  /** Replaces the list when set. */
  publicPaths?: GatePath[];
  sessionTtlSecs?: number;
  /** Default `/__applb/auth`; set it under the deployment's path prefix if routed by one. */
  basePath?: string;
  cookieName?: string;
  /** Send the signed-in identity upstream as `x-auth-request-*` headers. On by default. */
  forwardIdentity?: boolean;
}

const IDENTITY = ["provider", "client_id", "client_secret", "allowed_domains", "allowed_emails", "jwt", "cookie_domain"];

/**
 * Write `gate` onto a deployment spec's `auth` block: the reference, the
 * route-scoped fields that are set, and none of the inline identity fields,
 * which app-lb refuses beside a reference. Mutates and returns `spec`.
 */
export function applyGate<T extends Record<string, unknown>>(spec: T, gate: Gate): T {
  const current = spec.auth;
  const auth: Record<string, unknown> =
    current && typeof current === "object" && !Array.isArray(current) ? { ...(current as Record<string, unknown>) } : {};
  auth.provider_ref = gate.provider;
  for (const k of IDENTITY) delete auth[k];
  if (gate.publicPaths) auth.public_paths = gate.publicPaths.map((p) => ({ path: p.path, scope: p.scope ?? "public" }));
  if (gate.sessionTtlSecs !== undefined) auth.session_ttl_secs = gate.sessionTtlSecs;
  if (gate.basePath !== undefined) auth.base_path = gate.basePath;
  if (gate.cookieName !== undefined) auth.cookie_name = gate.cookieName;
  if (gate.forwardIdentity !== undefined) auth.forward_identity = gate.forwardIdentity;
  (spec as Record<string, unknown>).auth = auth;
  return spec;
}

/** The plugin that declares provider `name` by default, if one does. */
export function pluginFor(name: string): string | undefined {
  return ({ heyo: "auth-heyo", google: "auth-google" } as Record<string, string>)[name];
}
