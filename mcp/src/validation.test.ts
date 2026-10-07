/**
 * Arguments are checked against the schema before a handler sees them.
 *
 * They were not, until now. `createServer` passed `arguments` straight through
 * and every handler coerced by hand, which made a schema advertisement rather
 * than contract — fine while the most consequential input on the server was an
 * untyped blob, and untenable once the deployment spec became something worth
 * trusting.
 *
 * The risk this introduces is not that validation is wrong; it is that
 * validation is *pedantic*. Arguments are written by a language model, and a
 * model told `limit` is a number still sends `"100"`. Rejecting a call the
 * server has always accepted, over a difference nothing downstream cares about,
 * would be a worse tool surface than the one this replaces. So most of what is
 * pinned below is leniency.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { loadConfig } from "./config.js";
import { buildTools } from "./server.js";
import type { Tool } from "./tools/diagnose.js";

interface Call {
  url: string;
  method: string;
  body?: unknown;
}

function stubFetch(responder: (c: Call) => { status?: number; body?: unknown } = () => ({})) {
  const calls: Call[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    });
    const { status = 200, body = {} } = responder(calls[calls.length - 1]!);
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { calls, restore: () => void (globalThis.fetch = original) };
}

const tools = () =>
  buildTools(
    loadConfig({
      HEYO_API_KEY: "heyo_api_x",
      APPLB_NAMESPACE: "team-a",
      CI_URL: "http://127.0.0.1:9555",
      CI_TOKEN: "t",
    }),
  );

function tool(name: string): Tool {
  const found = tools().find((t) => t.name === name);
  assert.ok(found, `no such tool: ${name}`);
  return found;
}

test("a number written as a string is accepted", async () => {
  const stub = stubFetch(() => ({ body: { steps: [] } }));
  try {
    // What a model actually sends. Before parsing this reached the query
    // builder as a string and worked; a bare z.number() would now refuse it.
    await tool("ci_run_logs").handler({ run_id: "r1", tail: "500" });
    assert.match(stub.calls[0]?.url ?? "", /tail=500/);
  } finally {
    stub.restore();
  }
});

test('a boolean written as "true" is accepted', async () => {
  const stub = stubFetch(() => ({ body: { steps: [] } }));
  try {
    await tool("ci_run_logs").handler({ run_id: "r1", failed_only: "true" });
    assert.match(stub.calls[0]?.url ?? "", /failed_only=true/);
  } finally {
    stub.restore();
  }
});

test("a client-side numeric filter also takes a string", async () => {
  // `applb_feed` applies `limit` in the handler rather than in a query string,
  // so this is the same leniency proved through behaviour rather than a URL.
  const stub = stubFetch(() => ({
    body: [
      { id: 3, kind: "deployed" },
      { id: 2, kind: "deployed" },
      { id: 1, kind: "deployed" },
    ],
  }));
  try {
    const out = await tool("applb_feed").handler({ limit: "2" });
    assert.match(out, /2 event\(s\)/, `limit was not applied: ${out.slice(0, 80)}`);
  } finally {
    stub.restore();
  }
});

test("a string that is not a number is refused, rather than becoming zero", async () => {
  const stub = stubFetch();
  try {
    await assert.rejects(
      () => tool("applb_feed").handler({ limit: "lots" }),
      (e: Error) => {
        assert.match(e.message, /applb_feed/, "the message does not name the tool");
        assert.match(e.message, /limit/, "the message does not name the argument");
        return true;
      },
    );
    assert.equal(stub.calls.length, 0, "a rejected call must not reach the network");
  } finally {
    stub.restore();
  }
});

test("null is refused rather than silently coerced", async () => {
  // The reason `num()` is not `z.coerce.number()`, which turns null into 0.
  // A caller who sent null meant "no value", and answering with the results
  // for zero is a wrong answer rather than an error.
  const stub = stubFetch();
  try {
    await assert.rejects(() => tool("applb_feed").handler({ limit: null }), /limit/);
    assert.equal(stub.calls.length, 0);
  } finally {
    stub.restore();
  }
});

test("an unknown argument is dropped, not rejected", async () => {
  const stub = stubFetch(() => ({ body: [] }));
  try {
    // A model that guesses one extra parameter is otherwise right, and refusing
    // the whole call over it is hostile. Zod's default `.strip()` is what makes
    // this pass; `.strict()` would not.
    await tool("applb_list_deployments").handler({ verbose: true, page: 2 });
    assert.equal(stub.calls.length, 1, "the call was refused over an extra argument");
    assert.doesNotMatch(stub.calls[0]?.url ?? "", /verbose|page/, "the extra was forwarded");
  } finally {
    stub.restore();
  }
});

test("a missing required argument names the tool and the argument", async () => {
  const stub = stubFetch();
  try {
    await assert.rejects(
      () => tool("applb_get_deployment").handler({}),
      (e: Error) => {
        assert.match(e.message, /applb_get_deployment: the arguments do not match/);
        assert.match(e.message, /\bid\b/);
        return true;
      },
    );
    assert.equal(stub.calls.length, 0);
  } finally {
    stub.restore();
  }
});

test("a bad deployment spec is told where the real schema lives", async () => {
  const stub = stubFetch();
  try {
    await assert.rejects(
      () => tool("applb_create_deployment").handler({ spec: "a string, not an object" }),
      (e: Error) => {
        assert.match(e.message, /applb_spec_schema/, "the best moment to teach the input was missed");
        return true;
      },
    );
    assert.equal(stub.calls.length, 0);
  } finally {
    stub.restore();
  }
});

test("a valid spec is passed through untouched, unknown fields and all", async () => {
  const stub = stubFetch(() => ({ body: { id: "web" } }));
  try {
    // The permissive half of the design: app-lb accepts unknown fields, so a
    // client that stripped them would silently send a different deployment than
    // the caller wrote. `z.record(z.unknown())` keeps the object whole.
    const spec = {
      id: "web",
      routes: [{ host: "web.example.com" }],
      vm: { driver: "firecracker", port: 8080, start_command: "setsid nohup /srv/web </dev/null &" },
      a_field_added_after_this_client_shipped: { nested: true },
    };
    await tool("applb_create_deployment").handler({ spec });
    const sent = stub.calls.find((c) => c.method === "POST");
    assert.deepEqual(sent?.body, spec, "the spec did not arrive byte-for-byte");
  } finally {
    stub.restore();
  }
});

test("a raw request takes the method in any case, and defaults to GET", async () => {
  const stub = stubFetch(() => ({ body: {} }));
  try {
    await tool("heyo_request").handler({ path: "/me", method: "get" });
    await tool("heyo_request").handler({ path: "/me" });
    assert.deepEqual(
      stub.calls.map((c) => c.method),
      ["GET", "GET"],
      "case or the default was lost when the enum began to be enforced",
    );
    await assert.rejects(() => tool("heyo_request").handler({ path: "/me", method: "TRACE" }));
  } finally {
    stub.restore();
  }
});
