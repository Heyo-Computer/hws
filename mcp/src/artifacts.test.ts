/**
 * The publish sequence, and the two credentials that reach the store.
 *
 * These exist because both are things a caller gets wrong by hand and neither
 * fails loudly. A tag pointing at a blob digest is *accepted* by the store and
 * then resolves for nobody; a request carrying one of the two credentials is
 * refused by whichever layer it missed, with a 401 that names the other one.
 * Asserting on the requests this server builds is the only place either can be
 * pinned, since the store agrees with both mistakes at the time they are made.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { loadConfig, withForwardedAuth, artService } from "./config.js";
import { buildTools } from "./server.js";
import type { Tool } from "./tools/diagnose.js";

/** `sha256("hello")`, computed outside this codebase so the test is a check. */
const HELLO_SHA = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
const HELLO_B64 = "aGVsbG8=";

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  /** The body as text, whether it was sent as a string or as bytes. */
  body?: string;
}

/**
 * Like `tools.test.ts`'s stub, but keeps the headers and does not assume the
 * body is JSON — both of which are the point here.
 */
function stubFetch(responder: (call: Call) => { status?: number; body?: unknown }): {
  calls: Call[];
  restore: () => void;
} {
  const calls: Call[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const raw = init?.body;
    const call: Call = {
      url: String(input),
      method: init?.method ?? "GET",
      headers: Object.fromEntries(
        Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [
          k.toLowerCase(),
          v,
        ]),
      ),
      body:
        raw === undefined || raw === null
          ? undefined
          : typeof raw === "string"
            ? raw
            : Buffer.from(raw as Uint8Array).toString("utf8"),
    };
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

const withArt = () =>
  buildTools(
    loadConfig({
      HEYO_API_KEY: "heyo_api_x",
      ART_URL: "https://art.us2.heyo.work",
      ART_API_KEY: "art-secret",
      ART_GATE_TOKEN: "applb_1_gate",
    }),
  );

/** A store that answers a manifest PUT the way the real one does. */
const storeResponder = (manifestDigest = "sha256:" + "m".repeat(64)) =>
  stubFetch((c) => (c.method === "PUT" && c.url.endsWith("/manifests") ? { body: { digest: manifestDigest } } : {}));

test("a publish is three requests, and the tag names the manifest, never the blob", async () => {
  const manifest = "sha256:" + "m".repeat(64);
  const stub = storeResponder(manifest);
  try {
    await tool(withArt(), "art_publish").handler({
      tag: "marketing-site",
      content_base64: HELLO_B64,
    });

    assert.deepEqual(
      stub.calls.map((c) => `${c.method} ${c.url}`),
      [
        // The blob at its own hash, then the manifest, then the tag. Any other
        // order publishes a tag pointing at bytes that are not there yet.
        `PUT https://art.us2.heyo.work/blobs/${encodeURIComponent(HELLO_SHA)}`,
        "PUT https://art.us2.heyo.work/manifests",
        "PUT https://art.us2.heyo.work/tags/marketing-site",
      ],
    );

    // The whole reason this is one tool: the tag body is the digest the
    // *manifest* PUT answered with, not the blob's. Tagging the blob digest is
    // accepted by the store and resolves for no reader.
    assert.equal(stub.calls[2]?.body, manifest);
    assert.notEqual(stub.calls[2]?.body, HELLO_SHA);
    assert.equal(stub.calls[2]?.headers["content-type"], "text/plain");
  } finally {
    stub.restore();
  }
});

test("the blob goes to the store as bytes, at the digest that names it", async () => {
  const stub = storeResponder();
  try {
    await tool(withArt(), "art_publish").handler({ tag: "t", content_base64: HELLO_B64 });

    const blob = stub.calls[0]!;
    // Not JSON-wrapped: encoding the body would change the bytes and therefore
    // the digest they are being stored under.
    assert.equal(blob.body, "hello");
    assert.equal(blob.headers["content-type"], "application/octet-stream");
    assert.ok(blob.url.includes(encodeURIComponent(HELLO_SHA)), blob.url);

    // And the manifest entry describes those same bytes.
    const manifest = JSON.parse(stub.calls[1]!.body!);
    assert.deepEqual(manifest.entries, [{ name: "t", digest: HELLO_SHA, size: 5 }]);
    assert.equal(manifest.schema, 1);
    assert.equal(manifest.kind, "generic");
  } finally {
    stub.restore();
  }
});

/**
 * The finding that read as structural: two authenticators stacked in front of
 * one service, both reached through `Authorization`. They are not — the store
 * takes `x-api-key` too, so one request satisfies both doors.
 */
test("one request carries the gate's bearer and the store's own key", async () => {
  const stub = storeResponder();
  try {
    await tool(withArt(), "art_publish").handler({ tag: "t", content_base64: HELLO_B64 });

    for (const call of stub.calls) {
      assert.equal(call.headers.authorization, "Bearer applb_1_gate", `gate: ${call.url}`);
      assert.equal(call.headers["x-api-key"], "art-secret", `store: ${call.url}`);
    }
  } finally {
    stub.restore();
  }
});

test("the gate token falls back to APPLB_TOKEN, and an absent store key sends no header", () => {
  const shared = artService("https://art.example", "k", undefined, "applb_1_shared");
  assert.equal(shared?.auth, "Bearer applb_1_shared");

  // No key configured: no header at all. An empty `x-api-key` is a value the
  // store compares and refuses, which is worse than not sending one to a store
  // that has none configured.
  const keyless = artService("https://art.example", "", undefined, "applb_1_shared");
  assert.equal(keyless?.headers, undefined);

  // On its own listener, inside the network: no gate, so no bearer, and the
  // store key is the only credential. This shape needs no extra configuration.
  const direct = artService("http://127.0.0.1:8080", "k");
  assert.equal(direct?.auth, undefined);
  assert.deepEqual(direct?.headers, { "x-api-key": "k" });
});

/**
 * A hosted instance acts as its caller at the gate — and only at the gate. The
 * store key is this process's own: it carries no scope, so there is nothing in
 * it to widen, and a caller has no way to present one.
 */
test("a caller's app-token replaces the gate credential but never the store key", () => {
  const base = loadConfig({
    ART_URL: "https://art.us2.heyo.work",
    ART_API_KEY: "art-secret",
    ART_GATE_TOKEN: "applb_1_server",
  });
  const forwarded = withForwardedAuth(base, { authorization: "Bearer applb_2_caller" });

  assert.equal(forwarded.art?.auth, "Bearer applb_2_caller");
  assert.deepEqual(forwarded.art?.headers, { "x-api-key": "art-secret" });

  // A cloud key means nothing to an app-lb gate, so it is not substituted —
  // sending it would produce a 401 that reads as "the store is down".
  const cloudKey = withForwardedAuth(base, { authorization: "Bearer heyo_api_x" });
  assert.equal(cloudKey.art?.auth, "Bearer applb_1_server");
});

test("a manifest answer with no digest aborts before anything is tagged", async () => {
  const stub = stubFetch((c) =>
    c.method === "PUT" && c.url.endsWith("/manifests") ? { body: { ok: true } } : {},
  );
  try {
    await assert.rejects(
      () => tool(withArt(), "art_publish").handler({ tag: "t", content_base64: HELLO_B64 }),
      /did not answer with its digest/,
    );
    // Two requests, not three: refusing beats moving a tag onto "something".
    assert.equal(stub.calls.length, 2);
    assert.ok(!stub.calls.some((c) => c.url.includes("/tags/")), "a tag was written anyway");
  } finally {
    stub.restore();
  }
});

test("content that is not base64 is refused before anything is stored", async () => {
  const stub = storeResponder();
  try {
    await assert.rejects(
      () => tool(withArt(), "art_publish").handler({ tag: "t", content_base64: "not base64!!" }),
      /not valid base64/,
    );
    // `Buffer.from` drops what it cannot decode rather than throwing, so
    // without the round-trip check this would have published real bytes under
    // a digest naming something the caller never sent.
    assert.equal(stub.calls.length, 0, "nothing was sent");
  } finally {
    stub.restore();
  }
});

test("a publish with no tag and a publish with no bytes are both refused locally", async () => {
  const stub = storeResponder();
  try {
    await assert.rejects(
      () => tool(withArt(), "art_publish").handler({ content_base64: HELLO_B64 }),
      /`tag` is required/,
    );
    await assert.rejects(() => tool(withArt(), "art_publish").handler({ tag: "t" }), /no bytes/);
    await assert.rejects(
      () => tool(withArt(), "art_publish").handler({ tag: "t", path: "/x", content_base64: HELLO_B64 }),
      /not both/,
    );
    assert.equal(stub.calls.length, 0);
  } finally {
    stub.restore();
  }
});

test("an unconfigured store names both variables rather than failing at the first door", async () => {
  await assert.rejects(
    () => tool(buildTools(loadConfig({ HEYO_API_KEY: "heyo_api_x" })), "art_publish").handler({
      tag: "t",
      content_base64: HELLO_B64,
    }),
    /ART_URL.*ART_API_KEY/s,
  );
});

test("ci_run_status and ci_run_logs go to the public read API", async () => {
  const stub = stubFetch(() => ({ body: { run: { id: "r1", finished: true } } }));
  try {
    const tools = buildTools(loadConfig({ CI_URL: "https://ci.us2.heyo.work", CI_TOKEN: "repo-token" }));
    await tool(tools, "ci_run_status").handler({ run_id: "r1" });
    await tool(tools, "ci_run_logs").handler({ run_id: "r1", job: "build", failed_only: true });

    assert.deepEqual(
      stub.calls.map((c) => c.url),
      [
        "https://ci.us2.heyo.work/api/runs/r1",
        "https://ci.us2.heyo.work/api/runs/r1/logs?job=build&failed_only=true",
      ],
    );
    // The repository submit token, which is what these routes take — they are
    // in ci's public_paths, so the gate is not what authorizes them.
    assert.equal(stub.calls[0]?.headers.authorization, "Bearer repo-token");
  } finally {
    stub.restore();
  }
});

/**
 * The hint on a ci 401 used to say one thing: "the gate admits browsers only,
 * point CI_URL elsewhere". That is still true of the pages and is now wrong for
 * `/api/runs/`, where the gate is not the refuser — so the hint has to name
 * both cases or it sends people to move a URL that was already right.
 */
test("a ci 401 explains the read API and the pages differently", async () => {
  const stub = stubFetch(() => ({ status: 401, body: { error: "authentication required" } }));
  try {
    const tools = buildTools(loadConfig({ CI_URL: "https://ci.us2.heyo.work" }));
    await assert.rejects(
      () => tool(tools, "ci_run_status").handler({ run_id: "r1" }),
      (e: Error) => {
        assert.match(e.message, /\/api\/runs/);
        assert.match(e.message, /submit token/);
        assert.match(e.message, /CI_TOKEN/);
        return true;
      },
    );
  } finally {
    stub.restore();
  }
});

test("heyo_whoami asks app-lb about the presenting credential", async () => {
  const stub = stubFetch(() => ({ body: { caller: "app-token", admin_scope: "none" } }));
  try {
    const tools = buildTools(loadConfig({ APPLB_URL: "http://127.0.0.1:9090", APPLB_TOKEN: "applb_1_x" }));
    const out = await tool(tools, "heyo_whoami").handler({});
    assert.equal(stub.calls[0]?.url, "http://127.0.0.1:9090/whoami");
    assert.match(out, /admin_scope/);
  } finally {
    stub.restore();
  }
});
