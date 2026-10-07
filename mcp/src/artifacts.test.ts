/**
 * The publish sequence, and where it goes: the caller's namespace's artifacts
 * on app-lb, with the caller's own app-lb credential.
 *
 * A tag pointing at a blob digest is *accepted* and then resolves for nobody,
 * so asserting on the requests this server builds is the only place that
 * mistake can be pinned.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { loadConfig, withForwardedAuth } from "./config.js";
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

/** The managed app-lb door for namespace `acme`, as `loadConfig` builds it. */
const LB = "https://server.heyo.computer/namespaces/acme/lb";
/** Where `acme`'s artifacts live on that app-lb. */
const ART = `${LB}/namespaces/acme/artifacts`;

const withArt = () =>
  buildTools(loadConfig({ HEYO_API_KEY: "heyo_api_x", APPLB_NAMESPACE: "acme" }));

/** app-lb answering a manifest PUT the way it does. */
const storeResponder = (manifestDigest = "m".repeat(64)) =>
  stubFetch((c) => (c.method === "PUT" && c.url.endsWith("/manifests") ? { body: { digest: manifestDigest } } : {}));

test("a publish is three requests to app-lb, and the tag names the manifest, never the blob", async () => {
  const manifest = "m".repeat(64);
  const stub = storeResponder(manifest);
  try {
    const out = String(
      await tool(withArt(), "art_publish").handler({ tag: "acme/marketing-site", content_base64: HELLO_B64 }),
    );

    assert.deepEqual(
      stub.calls.map((c) => `${c.method} ${c.url}`),
      [
        // The blob at its own hash, then the manifest, then the tag. Any other
        // order publishes a tag pointing at bytes that are not there yet.
        `PUT ${ART}/blobs/${HELLO_SHA}`,
        `PUT ${ART}/manifests`,
        `PUT ${ART}/tags/${encodeURIComponent("acme/marketing-site")}`,
      ],
    );

    // The whole reason this is one tool: the tag body is the digest the
    // *manifest* PUT answered with, not the blob's.
    assert.equal(stub.calls[2]?.body, manifest);
    assert.notEqual(stub.calls[2]?.body, HELLO_SHA);
    assert.equal(stub.calls[2]?.headers["content-type"], "text/plain");
    // What to deploy is the ref alone.
    assert.match(out, /"artifact":\s*\{\s*"ref":\s*"acme\/marketing-site"\s*\}/);
    assert.doesNotMatch(out, /store"?\s*:/);
  } finally {
    stub.restore();
  }
});

test("the blob goes to app-lb as bytes, at the digest that names it", async () => {
  const stub = storeResponder();
  try {
    await tool(withArt(), "art_publish").handler({ tag: "acme/t", content_base64: HELLO_B64 });

    const blob = stub.calls[0]!;
    // Not JSON-wrapped: encoding the body would change the bytes and therefore
    // the digest they are being stored under.
    assert.equal(blob.body, "hello");
    assert.equal(blob.headers["content-type"], "application/octet-stream");
    assert.ok(blob.url.endsWith(`/blobs/${HELLO_SHA}`), blob.url);

    // And the manifest entry describes those same bytes.
    const manifest = JSON.parse(stub.calls[1]!.body!);
    assert.deepEqual(manifest.entries, [{ name: "t", digest: HELLO_SHA, size: 5 }]);
    assert.equal(manifest.schema, 1);
    assert.equal(manifest.kind, "generic");
  } finally {
    stub.restore();
  }
});

test("every artifact request carries the caller's own app-lb bearer and no store key", async () => {
  const base = loadConfig({ APPLB_URL: "https://lb.example", APPLB_NAMESPACE: "acme", HEYO_MCP_HTTP_PORT: "8090" });
  const cfg = withForwardedAuth(base, { authorization: "Bearer applb_2_caller" });
  const stub = storeResponder();
  try {
    await tool(buildTools(cfg), "art_publish").handler({ tag: "acme/t", content_base64: HELLO_B64 });
    await tool(buildTools(cfg), "art_list_tags").handler({});
    assert.equal(stub.calls.length, 4);
    for (const call of stub.calls) {
      assert.ok(call.url.startsWith("https://lb.example/namespaces/acme/lb/namespaces/acme/artifacts/"), call.url);
      assert.equal(call.headers.authorization, "Bearer applb_2_caller", call.url);
      assert.equal(call.headers["x-api-key"], undefined, call.url);
    }
  } finally {
    stub.restore();
  }
});

test("each art tool hits its app-lb route under /namespaces/<ns>/artifacts", async () => {
  const digest = "a".repeat(64);
  const stub = stubFetch((c) =>
    c.url.includes("/manifests/") ? { body: { kind: "generic", entries: [{ name: "x", digest, size: 1 }] } } : { body: {} },
  );
  try {
    const tools = withArt();
    await tool(tools, "art_list_tags").handler({});
    await tool(tools, "art_get_tag").handler({ tag: "acme/site:v1" });
    await tool(tools, "art_get_manifest").handler({ reference: `sha256:${digest}` });
    await tool(tools, "art_delete_tag").handler({ tag: "acme/site:v1" });
    await tool(tools, "art_set_public").handler({ repo: "acme/site:v1", public: true });
    assert.deepEqual(
      stub.calls.map((c) => `${c.method} ${c.url.slice(ART.length)}`),
      [
        "GET /tags",
        `GET /tags/${encodeURIComponent("acme/site:v1")}`,
        `GET /manifests/${digest}`,
        `DELETE /tags/${encodeURIComponent("acme/site:v1")}`,
        `PUT /repos/${encodeURIComponent("acme/site")}`,
      ],
    );
    assert.deepEqual(JSON.parse(stub.calls[4]!.body!), { public: true });
  } finally {
    stub.restore();
  }
});

test("a tag outside the namespace is refused before any bytes move", async () => {
  const stub = storeResponder();
  try {
    await assert.rejects(
      () => tool(withArt(), "art_publish").handler({ tag: "other/site:v1", content_base64: HELLO_B64 }),
      /must start with "acme\/"/,
    );
    assert.equal(stub.calls.length, 0);
  } finally {
    stub.restore();
  }
});

test("app-lb's 503 and 403 on artifacts are explained", async () => {
  let status = 503;
  const stub = stubFetch(() => ({ status, body: { error: "nope" } }));
  try {
    await assert.rejects(() => tool(withArt(), "art_list_tags").handler({}), /no artifact store configured/);
    status = 403;
    await assert.rejects(() => tool(withArt(), "art_list_tags").handler({}), /admin tier over the whole namespace/);
  } finally {
    stub.restore();
  }
});

test("with no managed namespace, the artifact namespace comes from app-lb's /whoami", async () => {
  const stub = stubFetch((c) => (c.url.endsWith("/whoami") ? { body: { namespace: "team" } } : { body: [] }));
  try {
    await tool(buildTools(loadConfig({ APPLB_URL: "https://lb.example", APPLB_TOKEN: "applb_1_x" })), "art_list_tags").handler({});
    assert.deepEqual(
      stub.calls.map((c) => c.url),
      ["https://lb.example/whoami", "https://lb.example/namespaces/team/artifacts/tags"],
    );
  } finally {
    stub.restore();
  }
});

test("a manifest answer with no digest aborts before anything is tagged", async () => {
  const stub = stubFetch((c) =>
    c.method === "PUT" && c.url.endsWith("/manifests") ? { body: { ok: true } } : {},
  );
  try {
    await assert.rejects(
      () => tool(withArt(), "art_publish").handler({ tag: "acme/t", content_base64: HELLO_B64 }),
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
      () => tool(withArt(), "art_publish").handler({ tag: "acme/t", content_base64: "not base64!!" }),
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
    await assert.rejects(() => tool(withArt(), "art_publish").handler({ tag: "acme/t" }), /no bytes/);
    await assert.rejects(
      () => tool(withArt(), "art_publish").handler({ tag: "acme/t", path: "/x", content_base64: HELLO_B64 }),
      /not both/,
    );
    assert.equal(stub.calls.length, 0);
  } finally {
    stub.restore();
  }
});

/**
 * Nothing an agent reads may steer it at the artifact store itself: no store
 * URL, no store key, no gateway on this server. Artifacts are the namespace's,
 * on app-lb.
 */
test("no tool, instruction or guide text points an agent at the artifact store", async () => {
  const { INSTRUCTIONS } = await import("./server.js");
  const { GUIDES } = await import("./tools/guide.js");
  const banned = [/ART_API_KEY/, /ART_URL/, /ART_GATE_TOKEN/, /art\.us\d/, /artifact\.store/, /\/art\b(?!ifact)/, /x-api-key/i, /art_request|art_usage|art_list_blobs|art_list_manifests/];
  for (const http of [false, true]) {
    const tools = buildTools(
      loadConfig({ HEYO_API_KEY: "heyo_api_x", APPLB_NAMESPACE: "acme", ...(http ? { HEYO_MCP_HTTP_PORT: "8090" } : {}) }),
    );
    for (const t of tools) {
      const schemaText = JSON.stringify(
        Object.fromEntries(Object.entries(t.schema).map(([k, v]) => [k, (v as { description?: string }).description ?? ""])),
      );
      for (const re of banned) {
        assert.doesNotMatch(t.description, re, `${t.name} description`);
        assert.doesNotMatch(schemaText, re, `${t.name} parameter descriptions`);
      }
    }
  }
  const guideText = GUIDES.map((g) => [...g.steps, ...(g.pitfalls ?? [])].join("\n")).join("\n");
  for (const re of banned) {
    assert.doesNotMatch(INSTRUCTIONS, re, "INSTRUCTIONS");
    assert.doesNotMatch(guideText, re, "guides");
  }
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
