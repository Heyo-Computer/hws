#!/usr/bin/env node
/**
 * Entrypoint. Stdio by default; HTTP when a port is given.
 *
 * Stdio is the right default: the host launches the process, credentials stay in
 * the host's environment, and there is nothing to deploy or secure. HTTP exists
 * for the shared case — one instance behind app-lb's JWT gate, reachable by
 * anyone the Heyo auth API will issue a token to. See deploy/heyo-mcp.json.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { loadConfig, configured, faultBanner } from "./config.js";
import { buildTools, createServer } from "./server.js";
import { serveHttp } from "./serve-http.js";

const config = loadConfig();
const port = Number(process.env.HEYO_MCP_HTTP_PORT ?? "");

if (Number.isFinite(port) && port > 0) {
  await serveHttp(config, port, process.env.HEYO_MCP_HTTP_HOST ?? "127.0.0.1");
} else {
  const tools = buildTools(config);
  const server = createServer(config, tools);
  await server.connect(new StdioServerTransport());
  // stderr, never stdout: stdout is the protocol channel and a stray line on it
  // corrupts the session.
  console.error(
    `heyo-mcp ready — ${tools.length} tools; configured: ${configured(config).join(", ") || "nothing"}`,
  );
  // After the ready line so it is the last thing on the screen, and never
  // fatal: a leftover setting is worth reporting, and refusing to start would
  // take away every tool that does work.
  const faults = faultBanner(config);
  if (faults) console.error(`\n${faults}`);
}
