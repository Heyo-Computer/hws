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
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import type { Config } from "./config.js";
import { configured, credentialFaults, faultBanner, withForwardedAuth } from "./config.js";
import { buildTools, createServer } from "./server.js";
import { identityFrom, identityRequired, Unauthenticated } from "./identity.js";

const MCP_PATH = "/mcp";

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

    if (url.pathname !== MCP_PATH) {
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
    console.error(`[${new Date().toISOString()}] ${req.method} ${MCP_PATH} by ${who}`);

    // A hosted instance without an app-lb credential of its own acts as the
    // caller: their bearer goes upstream, and the tool set is rebuilt for it.
    // With a configured credential this is the shared config and shared tools.
    const requestConfig = withForwardedAuth(config, req.headers);
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
