/**
 * Configuration left over from when this server called the Heyo cloud.
 *
 * `HEYO_API_KEY` used to be the whole configuration: it reached cloud for
 * sandboxes and app-lb through cloud's per-namespace door. Both are gone, and
 * sandboxes are app-lb's. These tests pin what such a configuration now gets:
 * a fault that says what to set instead, app-lb tools that name `APPLB_URL`,
 * and not a single request to the cloud host.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { credentialFaults, faultBanner, loadConfig } from "./config.js";
import { buildTools } from "./server.js";
import type { Tool } from "./tools/diagnose.js";

interface Call {
  url: string;
  method: string;
}

function stubFetch(responder: (c: Call) => { status?: number; body?: unknown }) {
  const calls: Call[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const call: Call = { url: String(input), method: init?.method ?? "GET" };
    calls.push(call);
    const { status = 200, body = {} } = responder(call);
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { calls, restore: () => void (globalThis.fetch = original) };
}

function tool(tools: Tool[], name: string): Tool {
  const found = tools.find((t) => t.name === name);
  assert.ok(found, `no such tool: ${name}`);
  return found;
}

const legacy = () => loadConfig({ HEYO_API_KEY: "heyo_api_x" });
const good = () => loadConfig({ APPLB_URL: "https://admin.us5.heyo.work", APPLB_TOKEN: "applb_1_x" });

test("a leftover HEYO_API_KEY is a fault that says what to set instead", () => {
  const [fault] = credentialFaults(legacy());
  assert.equal(fault?.service, "app-lb");
  assert.match(fault!.detail, /APPLB_URL/);
  assert.match(fault!.detail, /APPLB_TOKEN/);
  assert.ok(!fault!.detail.includes("heyo_api_x"), "a fault never prints a credential");
  assert.match(faultBanner(legacy()), /CREDENTIAL FAULT/);
});

test("a working configuration produces no faults and no banner", () => {
  assert.deepEqual(credentialFaults(good()), []);
  assert.equal(faultBanner(good()), "");
});

test("without APPLB_URL every sandbox and app-lb tool names it, and nothing is fetched", async () => {
  const stub = stubFetch(() => ({}));
  try {
    const tools = buildTools(legacy());
    for (const name of ["sandbox_list", "sandbox_exec", "applb_list_deployments"]) {
      await assert.rejects(tool(tools, name).handler({ id: "sb", command: "true" }), /APPLB_URL/, name);
    }
    assert.deepEqual(stub.calls, [], "no request goes anywhere, least of all the cloud");
  } finally {
    stub.restore();
  }
});

test("heyo_status asks app-lb, never the cloud", async () => {
  const stub = stubFetch(() => ({ body: { kind: "app", namespace: "team-a" } }));
  try {
    const out = await tool(buildTools(good()), "heyo_status").handler({});
    assert.match(out, /app-lb \/whoami — the credential is good/);
    assert.ok(stub.calls.every((c) => c.url.startsWith("https://admin.us5.heyo.work/")), JSON.stringify(stub.calls));
    assert.ok(stub.calls.some((c) => c.url.endsWith("/whoami")));
  } finally {
    stub.restore();
  }
});

test("heyo_status leads with a leftover-configuration fault", async () => {
  const stub = stubFetch(() => ({}));
  try {
    const out = await tool(buildTools(legacy()), "heyo_status").handler({});
    assert.ok(out.indexOf("CREDENTIAL FAULT") < out.indexOf("app-lb /healthz"), out);
    assert.deepEqual(stub.calls, []);
  } finally {
    stub.restore();
  }
});
