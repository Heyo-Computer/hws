/**
 * The HTTP transport, for running this as an app-lb deployment.
 *
 * Stateless — a new `Server` and a new transport per request, with no session
 * id. app-lb balances across a pool, so a session pinned to one backend works
 * until the pool scales and then fails for whichever requests land elsewhere.
 * Statelessness costs a little per-request setup and removes an entire class of
 * bug that only shows up under load.
 */

import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import type { Config } from "./config.js";
import { configured, credentialFaults, faultBanner, withForwardedAuth } from "./config.js";
import { authorizeArtCaller, checkArtRequest } from "./artscope.js";
import { buildTools, createServer } from "./server.js";
import { identityFrom, identityRequired, Unauthenticated } from "./identity.js";

const MCP_PATH = "/mcp";

/**
 * The artifact-store gateway: `/art/<store path>` is forwarded to the store
 * with this server's store key (`x-api-key`) and the caller's own bearer for
 * the gate, exactly as the `art_*` tools send them. It exists for bytes too
 * large to pass through a tool call: an agent with `curl` uploads a bundle
 * with `PUT /art/blobs/<hex digest>` and then tags it with `art_*` tools (or
 * more gateway requests), without base64 in the conversation.
 *
 * Only the store's API paths are forwarded, never its dashboard, and only
 * the methods the API uses. It grants nothing the `art_*` tools on `/mcp` do
 * not already grant the same caller.
 */
const ART_PATH = "/art";
const ART_ROUTES = /^\/(blobs|manifests|tags|labels|public|usage)(\/|$)/;
const ART_METHODS = new Set(["GET", "HEAD", "PUT", "DELETE"]);
const FORWARDED_RESPONSE_HEADERS = ["content-type", "content-length", "etag", "last-modified", "cache-control"];

async function forwardToArt(config: Config, req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const scoped = await authorizeArtCaller(config, withForwardedAuth(config, req.headers), req.headers);
  const art = scoped.art;
  if (!art) {
    json(res, 503, { error: "the artifact store is not configured on this server (ART_URL)" });
    return;
  }
  const rest = url.pathname.slice(ART_PATH.length);
  const method = (req.method ?? "GET").toUpperCase();
  if (!ART_ROUTES.test(rest) || rest.split("/").includes("..")) {
    json(res, 404, { error: "the gateway forwards /art/{blobs,manifests,tags,labels,public,usage}… only" });
    return;
  }
  if (!ART_METHODS.has(method)) {
    json(res, 405, { error: `${method} is not forwarded; GET, HEAD, PUT and DELETE are` });
    return;
  }
  if (scoped.artScope) {
    const verdict = checkArtRequest(scoped.artScope, method, rest);
    // A listing would have to be buffered to filter it; `art_list_tags` does that.
    const refused =
      verdict.refused ?? (verdict.filterTagsTo !== undefined ? "list tags with art_list_tags, which filters to your namespace" : undefined);
    if (refused) {
      json(res, 403, { error: refused });
      return;
    }
  }
  const headers: Record<string, string> = { ...(art.headers ?? {}) };
  if (art.auth) headers.authorization = art.auth;
  for (const h of ["content-type", "content-length", "accept", "range"]) {
    const v = req.headers[h];
    if (typeof v === "string") headers[h] = v;
  }
  const hasBody = method === "PUT";
  let upstream: Response;
  try {
    upstream = await fetch(`${art.baseUrl}${rest}${url.search}`, {
      method,
      headers,
      body: hasBody ? (Readable.toWeb(req) as ReadableStream) : undefined,
      // Required by fetch for a streamed request body.
      ...(hasBody ? { duplex: "half" } : {}),
    } as RequestInit);
  } catch (e) {
    json(res, 502, { error: `artifact store unreachable: ${e instanceof Error ? e.message : String(e)}` });
    return;
  }
  const out: Record<string, string> = {};
  for (const h of FORWARDED_RESPONSE_HEADERS) {
    const v = upstream.headers.get(h);
    if (v) out[h] = v;
  }
  res.writeHead(upstream.status, out);
  if (!upstream.body || method === "HEAD") {
    res.end();
    return;
  }
  Readable.fromWeb(upstream.body as import("node:stream/web").ReadableStream).pipe(res);
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text) });
  res.end(text);
}

export async function serveHttp(config: Config, port: number, host: string): Promise<HttpServer> {
  const tools = buildTools(config);

  const http = createHttpServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

    // Open, and answered without touching a client. app-lb polls this to decide
    // whether a backend is in rotation, so it must not queue behind anything.
    if (url.pathname === "/healthz") {
      json(res, 200, {
        ok: true,
        tools: tools.length,
        configured: configured(config),
        // Named here too: an operator watching a health endpoint should not
        // have to read process logs to learn that a credential cannot work.
        faults: credentialFaults(config).map((f) => f.summary),
      });
      return;
    }

    const isArt = url.pathname === ART_PATH || url.pathname.startsWith(`${ART_PATH}/`);
    if (url.pathname !== MCP_PATH && !isArt) {
      json(res, 404, { error: `no such path; MCP is served at ${MCP_PATH}` });
      return;
    }

    let who = "anonymous";
    if (identityRequired()) {
      try {
        who = identityFrom(req.headers).who;
      } catch (e) {
        if (e instanceof Unauthenticated) {
          json(res, 401, { error: e.message });
          return;
        }
        throw e;
      }
    }

    // Logged per call, on stderr, because every tool behind this can change
    // production and "who asked for that" must be answerable afterwards.
    console.error(`[${new Date().toISOString()}] ${req.method} ${isArt ? url.pathname : MCP_PATH} by ${who}`);

    if (isArt) {
      try {
        await forwardToArt(config, req, res, url);
      } catch (e) {
        console.error("art gateway failed:", e);
        if (!res.headersSent) json(res, 500, { error: "internal error" });
      }
      return;
    }

    // A hosted instance without an app-lb credential of its own acts as the
    // caller: their bearer goes upstream, and the tool set is rebuilt for it.
    // With a configured credential this is the shared config and shared tools.
    const requestConfig = await authorizeArtCaller(config, withForwardedAuth(config, req.headers), req.headers);
    const requestTools = requestConfig === config ? tools : buildTools(requestConfig);
    const server = createServer(requestConfig, requestTools);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    // Both are per-request; without this the sockets accumulate.
    res.on("close", () => {
      void transport.close();
      void server.close();
    });

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res);
    } catch (e) {
      console.error("request failed:", e);
      if (!res.headersSent) json(res, 500, { error: "internal error" });
    }
  });

  await new Promise<void>((resolve) => http.listen(port, host, resolve));
  console.error(
    `heyo-mcp on http://${host}:${port}${MCP_PATH} — ${tools.length} tools; ` +
      `upstreams: ${configured(config).join(", ") || "nothing"}; ` +
      `identity ${identityRequired() ? "required" : "NOT REQUIRED (testing)"}`,
  );
  const faults = faultBanner(config);
  if (faults) console.error(`\n${faults}`);
  return http;
}
