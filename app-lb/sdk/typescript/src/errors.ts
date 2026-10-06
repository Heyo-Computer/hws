/**
 * What can go wrong, as something a caller can branch on.
 *
 * app-lb answers a failed request in one of two ways and a client has to handle
 * both:
 *
 *  - `{"error": "…"}` — every handler-level 4xx/5xx.
 *  - **plain text** — the `401`, and every axum extractor rejection: `415` for a
 *    missing content-type, `400` for malformed JSON, `422` for well-formed JSON
 *    of the wrong shape.
 *
 * So {@link fromResponse} tries the envelope, falls back to the body as text,
 * and falls back again to the status. It never assumes JSON.
 */

/** What was presented, so a 401 can say something useful about it. */
export type Credential = "none" | "basic" | "token";

export class HeyctlError extends Error {
  /** The HTTP status behind this, when there was one. */
  readonly status?: number;
  /**
   * The machine-readable reason app-lb put beside `error`, when it gave one —
   * e.g. `plugin_not_installed` or `plugin_disabled` on a namespace plugin's
   * 409. Branch on this rather than on the message.
   */
  code?: string;

  constructor(message: string, status?: number) {
    super(message);
    this.name = new.target.name;
    this.status = status;
    // Required for `instanceof` to work on a subclassed Error when the package
    // is transpiled down to ES5 — without it every subclass collapses to Error.
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /** Whether retrying the identical request could plausibly succeed. */
  get retryable(): boolean {
    return false;
  }

  /** Whether this is a credential problem rather than a request problem. */
  get isAuth(): boolean {
    return false;
  }
}

/**
 * `401`. Missing, wrong, revoked or expired — app-lb does not distinguish
 * those, deliberately, so token ids cannot be enumerated by watching which
 * failure comes back.
 */
export class UnauthorizedError extends HeyctlError {
  readonly presented: Credential;
  constructor(presented: Credential) {
    super(
      {
        none: "authentication required, and no credential was sent — supply a username and password, or an app-token",
        basic: "the username or password was not accepted",
        token:
          "the app-token was not accepted — it may be wrong, revoked or expired (app-lb does not say which)",
      }[presented],
      401,
    );
    this.presented = presented;
  }
  override get isAuth(): boolean {
    return true;
  }
}

/** `403`. The credential was good and its scope was not. */
export class ForbiddenError extends HeyctlError {
  constructor(message: string) {
    super(message, 403);
  }
  override get isAuth(): boolean {
    return true;
  }
}

export class NotFoundError extends HeyctlError {
  readonly kind: string;
  readonly name_: string;
  constructor(kind: string, name: string) {
    super(`no ${kind} ${JSON.stringify(name)}`, 404);
    this.kind = kind;
    this.name_ = name;
  }
}

/** `409` — a job is already running, or a secret is still referenced. */
export class ConflictError extends HeyctlError {
  constructor(message: string) {
    super(message, 409);
  }
}

/**
 * `409` from exec/shell with `wake: false` and nothing running. Separate from
 * {@link ConflictError} because the remedy is specific: retry with `wake`.
 */
export class NoRunningVmError extends HeyctlError {
  readonly deployment: string;
  constructor(deployment: string) {
    super(`deployment ${JSON.stringify(deployment)} has no running VM (retry with wake)`, 409);
    this.deployment = deployment;
  }
}

/** `503` — asked for a VM, none appeared inside `cold_start_timeout_secs`. */
export class ColdStartTimeoutError extends HeyctlError {
  readonly deployment: string;
  constructor(deployment: string) {
    super(
      `deployment ${JSON.stringify(deployment)} had no VM ready within its cold-start timeout`,
      503,
    );
    this.deployment = deployment;
  }
  override get retryable(): boolean {
    return true;
  }
}

/**
 * `502` — app-lb reached the daemon and the daemon failed.
 *
 * For `exec` this includes app-lb's own call timing out, in which case **the
 * command is still running in the guest**.
 */
export class UpstreamError extends HeyctlError {
  constructor(message: string) {
    super(message, 502);
  }
  override get retryable(): boolean {
    return true;
  }
}

/** Any other `{"error": …}` this package has no specific class for. */
export class ApiError extends HeyctlError {}

/**
 * A response that could not be interpreted: an extractor rejection, an
 * empty-bodied router 404/405, or an intermediary's error page.
 */
export class MalformedResponseError extends HeyctlError {
  readonly body: string;
  constructor(status: number, body: string) {
    super(body ? `unexpected HTTP ${status}: ${body}` : `unexpected HTTP ${status}`, status);
    this.body = body;
  }
}

/** The request never got an answer. */
export class TransportError extends HeyctlError {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
  }
  override get retryable(): boolean {
    return true;
  }
}

/** The WebSocket carrying a shell failed. */
export class ShellError extends HeyctlError {}

/** A `wait*` helper gave up. */
export class TimeoutError extends HeyctlError {
  constructor(what: string, afterMs: number) {
    super(`${what} did not finish within ${Math.round(afterMs / 1000)}s`);
  }
}

/** Bad input, caught before anything was sent. */
export class InvalidRequestError extends HeyctlError {}

/**
 * Turn a failed response into a typed error.
 *
 * `kind`/`name` describe what was addressed, so a 404 can say
 * `no deployment "demo"` rather than `HTTP 404`.
 */
export function fromResponse(
  status: number,
  body: string,
  kind: string,
  name: string,
  presented: Credential,
): HeyctlError {
  // The envelope if there is one; otherwise the body verbatim, which is where
  // the plain-text rejections live.
  let message: string | undefined;
  let code: string | undefined;
  try {
    const parsed = JSON.parse(body);
    if (parsed && typeof parsed.error === "string" && parsed.error.trim()) {
      message = parsed.error;
    }
    if (parsed && typeof parsed.code === "string" && parsed.code) {
      code = parsed.code;
    }
  } catch {
    // Not JSON. Normal — see the module comment.
  }
  const hadEnvelope = message !== undefined;
  if (message === undefined) {
    const trimmed = body.trim();
    message = trimmed || undefined;
  }
  const err = classify(status, message, hadEnvelope, kind, name, presented);
  if (code !== undefined) err.code = code;
  return err;
}

function classify(
  status: number,
  message: string | undefined,
  hadEnvelope: boolean,
  kind: string,
  name: string,
  presented: Credential,
): HeyctlError {

  switch (status) {
    case 401:
      return new UnauthorizedError(presented);
    case 403:
      return new ForbiddenError(message ?? "forbidden");
    case 404:
      // A router-level 404 (an unknown *path*) has no envelope and no useful
      // body; a handler-level one names the thing. Reporting the former as a
      // missing object sends people looking for the wrong bug.
      if (message === undefined || message.startsWith("no ")) {
        return new NotFoundError(kind, name);
      }
      return new MalformedResponseError(status, message);
    case 409:
      // Both shapes are 409 and the remedies differ, so the message is what
      // tells them apart. If app-lb rewords it the fallback is ConflictError,
      // which is less specific rather than wrong.
      return message?.includes("no running VM")
        ? new NoRunningVmError(name)
        : new ConflictError(message ?? "conflict");
    case 503:
      return new ColdStartTimeoutError(name);
    case 502:
      return new UpstreamError(message ?? "the daemon did not answer");
    case 400:
    case 415:
    case 422:
      // Without an envelope these are extractor rejections: the request was
      // malformed before a handler saw it.
      if (!hadEnvelope) return new MalformedResponseError(status, message ?? "");
      return new ApiError(message!, status);
    default:
      return message === undefined
        ? new MalformedResponseError(status, "")
        : new ApiError(message, status);
  }
}
