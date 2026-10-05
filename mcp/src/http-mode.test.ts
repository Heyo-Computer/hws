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
