/**
 * What changes when this server is reached over HTTP instead of stdio.
 *
 * One thing, deliberately: `art_publish` stops taking a `path`. Over stdio the
 * caller is the machine this process runs on, so a path names the caller's own
 * file. Over HTTP the caller is elsewhere and the same parameter would name
 * this server's disk on their behalf — and since 2026-09-11 the hosted
 * instance's `/mcp` path is public at its gate, so "their behalf" includes
 * anyone. The bytes still had nowhere to go without a credential, but the read
 * itself, and the error text distinguishing a missing file from an unreadable
 * one, were available to a stranger.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { loadConfig, withForwardedAuth } from "./config.js";
import { buildTools, toolListing } from "./server.js";
import { serveHttp, UPLOAD_TIMEOUT_MS } from "./serve-http.js";

const ART = { ART_URL: "http://127.0.0.1:8080", ART_API_KEY: "k" };
const overHttp = () => buildTools(loadConfig({ ...ART, HEYO_MCP_HTTP_PORT: "9650" }));
const overStdio = () => buildTools(loadConfig(ART));

function stubFetch() {
  const calls: string[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request) => {
    calls.push(String(input));
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { calls, restore: () => void (globalThis.fetch = original) };
}

test("the config knows which transport it is serving", () => {
  assert.equal(loadConfig({ HEYO_MCP_HTTP_PORT: "9650" }).http, true);
  assert.equal(loadConfig({}).http, false);
  assert.equal(loadConfig({ HEYO_MCP_HTTP_PORT: "0" }).http, false);
  assert.equal(loadConfig({ HEYO_MCP_HTTP_PORT: "not-a-port" }).http, false);
});

test("a per-request config keeps the transport", () => {
  // serve-http rebuilds the tool set per request from `withForwardedAuth`'s
  // result, so a flag that did not survive the spread would quietly reopen
  // `path` on every forwarded call.
  const base = loadConfig({ ...ART, APPLB_URL: "http://127.0.0.1:9090", HEYO_MCP_HTTP_PORT: "9650" });
  const perRequest = withForwardedAuth(base, { authorization: "Bearer applb_abc_def" });
  assert.notEqual(perRequest, base, "the forwarding path was not exercised");
  assert.equal(perRequest.http, true);
});

test("over HTTP, art_publish does not advertise a path", () => {
  const props = (t: ReturnType<typeof toolListing>[number] | undefined) =>
    Object.keys((t?.inputSchema as { properties?: object })?.properties ?? {});

  const http = props(toolListing(overHttp()).find((t) => t.name === "art_publish"));
  assert.ok(!http.includes("path"), `path is still advertised over HTTP: ${http.join(", ")}`);
  assert.ok(http.includes("content_base64"));

  const stdio = props(toolListing(overStdio()).find((t) => t.name === "art_publish"));
  assert.ok(stdio.includes("path"), "stdio lost the path it legitimately needs");
});

test("over HTTP, a path is never read, and the error says what to send", async () => {
  const stub = stubFetch();
  try {
    const publish = overHttp().find((t) => t.name === "art_publish")!;
    await assert.rejects(
      () => publish.handler({ tag: "t", path: "/etc/hostname" }),
      (e: Error) => {
        assert.match(e.message, /content_base64/);
        // The file-existence oracle: an HTTP caller must not be able to tell a
        // missing file from an unreadable one by the wording of the refusal.
        assert.doesNotMatch(e.message, /ENOENT|EACCES|could not read/);
        return true;
      },
    );
    assert.equal(stub.calls.length, 0, "a refused publish still went to the store");
  } finally {
    stub.restore();
  }
});

test("the server lets a large upload through /art run past Node's 5-minute default", async () => {
  const server = await serveHttp(loadConfig({ ...ART, HEYO_MCP_HTTP_PORT: "1" }), 0, "127.0.0.1");
  try {
    assert.equal(server.requestTimeout, UPLOAD_TIMEOUT_MS);
    assert.ok(server.requestTimeout >= 60 * 60 * 1000, "a multi-GB push needs at least an hour");
    assert.ok(server.headersTimeout <= 60_000, "slow headers are still cut off quickly");
  } finally {
    server.close();
  }
});

// us5's shape: app-lb, the git remote and the store, but no ci and no app-obs.
const HOSTED_US5 = {
  APPLB_URL: "https://admin.us5.example",
  REMOTE_URL: "https://git.us5.example",
  ART_URL: "https://hub.example",
  HEYO_MCP_HTTP_PORT: "9650",
};

test("the create-a-repo-and-deploy-it workflow fits a client that keeps only 40 tools", async () => {
  const { WORKFLOW_FIRST } = await import("./server.js");
  for (const env of [HOSTED_US5, { ...HOSTED_US5, CI_URL: "https://ci.example", APP_OBS_URL: "https://obs.example" }]) {
    const names = buildTools(loadConfig(env)).map((t) => t.name);
    const first40 = new Set(names.slice(0, 40));
    for (const n of ["repo_create", "repo_write_files", "repo_deploy", "applb_spec_schema", "applb_deploy", "art_publish_files"]) {
      assert.ok(first40.has(n), `${n} is at ${names.indexOf(n) + 1} of ${names.length}`);
    }
    // The leading block is exactly the workflow list, in order, for what exists.
    const expected = WORKFLOW_FIRST.filter((n) => names.includes(n));
    assert.deepEqual(names.slice(0, expected.length), expected);
  }
});

test("a hosted server lists no tools for services it cannot reach; stdio keeps them", () => {
  const hosted = buildTools(loadConfig(HOSTED_US5)).map((t) => t.name);
  for (const n of ["ci_run_status", "ci_request", "diagnose_ci_job"]) {
    assert.ok(!hosted.includes(n), `${n} listed with no ci`);
  }
  // app-obs is reachable through app-lb's per-namespace obs plugin, so the
  // telemetry tools stay listed wherever app-lb is — with or without APP_OBS_URL.
  for (const n of ["obs_request", "deployment_logs", "namespace_telemetry"]) {
    assert.ok(hosted.includes(n), `${n} dropped although app-lb can reach app-obs`);
  }
  const nothing = buildTools(loadConfig({ REMOTE_URL: "https://git.example", HEYO_MCP_HTTP_PORT: "9650" })).map(
    (t) => t.name,
  );
  for (const n of ["obs_request", "deployment_logs", "namespace_telemetry"]) {
    assert.ok(!nothing.includes(n), `${n} listed with neither app-obs nor app-lb`);
  }
  assert.ok(hosted.includes("repo_create") && hosted.includes("applb_deploy"));

  const withCi = buildTools(loadConfig({ ...HOSTED_US5, CI_URL: "https://ci.example" })).map((t) => t.name);
  assert.ok(withCi.includes("ci_run_status"));

  const stdio = buildTools(loadConfig({ APPLB_URL: "https://admin.example" })).map((t) => t.name);
  assert.ok(stdio.includes("ci_run_status"), "stdio keeps the tool that explains what to configure");
});

test("initialize carries the workflow instructions", async () => {
  const prev = process.env.HEYO_MCP_REQUIRE_IDENTITY;
  process.env.HEYO_MCP_REQUIRE_IDENTITY = "0";
  const server = await serveHttp(loadConfig({ ...HOSTED_US5, HEYO_MCP_HTTP_PORT: "1" }), 0, "127.0.0.1");
  try {
    const port = (server.address() as { port: number }).port;
    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } },
      }),
    });
    const text = await res.text();
    const line = text.split("\n").find((l) => l.startsWith("data: ")) ?? text;
    const instructions = JSON.parse(line.replace(/^data: /, "")).result?.instructions as string;
    assert.match(instructions, /repo_create/);
    assert.match(instructions, /Static site/);
  } finally {
    if (prev === undefined) delete process.env.HEYO_MCP_REQUIRE_IDENTITY;
    else process.env.HEYO_MCP_REQUIRE_IDENTITY = prev;
    server.close();
  }
});
