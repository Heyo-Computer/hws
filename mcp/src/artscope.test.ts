/**
 * The artifact-store key on a hosted server is the store owner's key, and the
 * hosted `/mcp` path is public. These tests pin who gets to use it: nobody
 * anonymous, nobody app-lb does not vouch for, and a namespace token only
 * inside its own `<ns>/` corner of the store.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { loadConfig } from "./config.js";
import { checkArtRequest, clearWhoamiCache, filterTags, scopeFromWhoami, type ArtScope } from "./artscope.js";
import { serveHttp } from "./serve-http.js";

const FOO: ArtScope = { kind: "namespace", namespace: "foo", write: true };
const DIGEST = `sha256:${"a".repeat(64)}`;
const enc = encodeURIComponent;

test("whoami: only a verified app-token with an admin tier reaches the store", () => {
  assert.equal(scopeFromWhoami({ caller: "ungated" }), undefined);
  assert.equal(scopeFromWhoami({ caller: "federated", admin_scope: "admin", fleet: true }), undefined);
  assert.equal(scopeFromWhoami({ caller: "app-token", admin_scope: "none", namespace: "foo" }), undefined);
  assert.equal(scopeFromWhoami({ caller: "app-token", admin_scope: "admin", namespace: "../x" }), undefined);
  assert.deepEqual(scopeFromWhoami({ caller: "app-token", admin_scope: "admin", fleet: true }), {
    kind: "fleet",
    write: true,
  });
  assert.deepEqual(scopeFromWhoami({ caller: "app-token", admin_scope: "view", namespace: "foo" }), {
    kind: "namespace",
    namespace: "foo",
    write: false,
  });
  // Confined to particular deployments: read, never write.
  assert.deepEqual(
    scopeFromWhoami({ caller: "app-token", admin_scope: "admin", namespace: "foo", deployments: ["web"] }),
    { kind: "namespace", namespace: "foo", write: false },
  );
});

test("a namespace token reaches its own refs and content-addressed objects only", () => {
  const ok = (m: string, p: string) => assert.equal(checkArtRequest(FOO, m, p).refused, undefined, `${m} ${p}`);
  const no = (m: string, p: string) => assert.ok(checkArtRequest(FOO, m, p).refused, `${m} ${p} was allowed`);

  ok("PUT", `/blobs/${enc(DIGEST)}`);
  ok("HEAD", `/blobs/${DIGEST}`);
  ok("PUT", "/manifests");
  ok("GET", `/manifests/${enc(DIGEST)}`);
  ok("GET", `/manifests/${enc("foo/app:1")}`);
  ok("PUT", `/tags/${enc("foo/app:1")}`);
  ok("DELETE", `/tags/${enc("foo/app:1")}`);
  ok("PUT", `/public/${enc("foo/app:1")}`);
  ok("GET", "/tags?x=1");

  no("DELETE", `/tags/${enc("marketing-live")}`);
  no("PUT", `/tags/${enc("bar/app:1")}`);
  no("PUT", `/tags/${enc("foo/")}`);
  no("PUT", `/tags/${enc("foo/../bar/app:1")}`);
  no("PUT", `/public/${enc(DIGEST)}`);
  no("GET", `/manifests/${enc("marketing-live")}`);
  no("GET", "/manifests");
  no("GET", "/blobs");
  no("GET", "/usage");
  no("GET", "/repos");
  no("DELETE", "/tags");
  no("GET", "/tags%2F..%2Fusage");
  no("GET", "usage");

  assert.equal(checkArtRequest(FOO, "GET", "/tags").filterTagsTo, "foo/");
});

test("a read-only token writes nothing, fleet or not", () => {
  for (const scope of [
    { kind: "fleet", write: false },
    { kind: "namespace", namespace: "foo", write: false },
  ] as ArtScope[]) {
    assert.ok(checkArtRequest(scope, "PUT", `/tags/${enc("foo/app:1")}`).refused);
    assert.ok(checkArtRequest(scope, "DELETE", `/blobs/${DIGEST}`).refused);
  }
  assert.equal(checkArtRequest({ kind: "fleet", write: false }, "GET", "/usage").refused, undefined);
  assert.equal(checkArtRequest({ kind: "fleet", write: true }, "DELETE", "/tags/marketing-live").refused, undefined);
});

test("a tag listing is cut down to the prefix", () => {
  const all = [{ tag: "foo/a:1" }, { tag: "marketing-live" }, { tag: "foobar/x:1" }];
  assert.deepEqual(filterTags(all, "foo/"), [{ tag: "foo/a:1" }]);
  assert.deepEqual(filterTags({ tags: all }, "foo/"), { tags: [{ tag: "foo/a:1" }] });
  assert.deepEqual(filterTags("nonsense", "foo/"), []);
});

// ---------------------------------------------------------------------------
// End to end: the real HTTP server, a fake store and a fake app-lb.
// ---------------------------------------------------------------------------

interface Seen {
  method: string;
  path: string;
  key: boolean;
}

const seen: Seen[] = [];
let store: Server;
let applb: Server;
let mcp: Server;
let mcpUrl = "";

const WHOAMI: Record<string, object> = {
  "Bearer applb_ns_foo": { caller: "app-token", admin_scope: "admin", namespace: "foo", fleet: false, deployments: [] },
  "Bearer applb_fleet_x": { caller: "app-token", admin_scope: "admin", fleet: true, deployments: ["*"] },
};

function listen(s: Server): Promise<string> {
  return new Promise((r) => s.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(s.address() as AddressInfo).port}`)));
}

function body(req: IncomingMessage): Promise<void> {
  return new Promise((r) => {
    req.resume();
    req.on("end", () => r());
  });
}

before(async () => {
  store = createServer(async (req, res) => {
    await body(req);
    const key = req.headers["x-api-key"] === "store-key";
    seen.push({ method: req.method ?? "", path: req.url ?? "", key });
    res.setHeader("content-type", "application/json");
    if (!key) {
      res.writeHead(401).end(JSON.stringify({ error: "unauthorized" }));
    } else if (req.method === "PUT" && req.url === "/manifests") {
      res.end(JSON.stringify({ digest: DIGEST }));
    } else if (req.url === "/tags") {
      res.end(JSON.stringify([{ tag: "foo/app:1", digest: DIGEST }, { tag: "marketing-live", digest: DIGEST }]));
    } else {
      res.end("{}");
    }
  });
  applb = createServer(async (req, res) => {
    await body(req);
    const who = WHOAMI[String(req.headers.authorization)];
    res.setHeader("content-type", "application/json");
    if (req.url === "/whoami" && who) res.end(JSON.stringify(who));
    else res.writeHead(401).end(JSON.stringify({ error: "unknown token" }));
  });
  const storeUrl = await listen(store);
  const applbUrl = await listen(applb);
  process.env.HEYO_MCP_REQUIRE_IDENTITY = "0";
  const config = loadConfig({
    ART_URL: storeUrl,
    ART_API_KEY: "store-key",
    APPLB_URL: applbUrl,
    HEYO_MCP_HTTP_PORT: "1",
    HEYO_MCP_PUBLIC_URL: "http://mcp.test",
  });
  mcp = await serveHttp(config, 0, "127.0.0.1");
  mcpUrl = `http://127.0.0.1:${(mcp.address() as AddressInfo).port}`;
});

after(() => {
  for (const s of [mcp, store, applb]) s?.close();
});

async function call(name: string, args: object, bearer?: string): Promise<string> {
  const res = await fetch(`${mcpUrl}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(bearer ? { authorization: bearer } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
  const text = await res.text();
  const line = text.split("\n").find((l) => l.startsWith("data: ")) ?? text;
  const msg = JSON.parse(line.replace(/^data: /, "")) as {
    result?: { content?: { text?: string }[] };
    error?: unknown;
  };
  return (msg.result?.content ?? []).map((c) => c.text ?? "").join("\n") || JSON.stringify(msg.error);
}

function fresh(): void {
  seen.length = 0;
  clearWhoamiCache();
}

test("an anonymous caller never sends the store key", async () => {
  fresh();
  await call("art_usage", {});
  await call("art_delete_tag", { tag: "marketing-live" });
  await call("art_request", { method: "DELETE", path: "/tags/marketing-live" });
  assert.ok(seen.length > 0, "nothing reached the store");
  assert.ok(seen.every((s) => !s.key), `the key was sent: ${JSON.stringify(seen)}`);
});

test("a token app-lb does not vouch for never sends the store key", async () => {
  fresh();
  await call("art_delete_tag", { tag: "marketing-live" }, "Bearer applb_forged_token");
  await call("art_delete_tag", { tag: "marketing-live" }, "Bearer heyo_api_whatever");
  assert.ok(seen.every((s) => !s.key), `the key was sent: ${JSON.stringify(seen)}`);
});

test("a namespace token publishes in its namespace and nowhere else", async () => {
  fresh();
  const files = [{ path: "index.html", content: "hi" }];
  const out = await call("art_publish_files", { tag: "foo/site:1", files }, "Bearer applb_ns_foo");
  assert.doesNotMatch(out, /may only reach/, out);
  assert.ok(seen.some((s) => s.key && s.method === "PUT" && s.path === `/tags/${enc("foo/site:1")}`), JSON.stringify(seen));

  fresh();
  const refused = await call("art_publish_files", { tag: "bar/site:1", files }, "Bearer applb_ns_foo");
  assert.match(refused, /namespace foo may only reach foo\//);
  assert.ok(!seen.some((s) => s.path.startsWith("/tags/")), "a refused tag write reached the store");

  fresh();
  assert.match(await call("art_delete_tag", { tag: "marketing-live" }, "Bearer applb_ns_foo"), /may only reach/);
  assert.match(await call("art_usage", {}, "Bearer applb_ns_foo"), /may only reach/);
  assert.match(await call("art_request", { method: "GET", path: "/blobs" }, "Bearer applb_ns_foo"), /may only reach/);
  assert.equal(seen.length, 0, `refused calls reached the store: ${JSON.stringify(seen)}`);

  const listed = await call("art_list_tags", {}, "Bearer applb_ns_foo");
  assert.match(listed, /foo\/app:1/);
  assert.doesNotMatch(listed, /marketing-live/);
});

test("a fleet token keeps the whole store", async () => {
  fresh();
  await call("art_delete_tag", { tag: "marketing-live" }, "Bearer applb_fleet_x");
  assert.ok(seen.some((s) => s.key && s.method === "DELETE" && s.path === "/tags/marketing-live"), JSON.stringify(seen));
});

test("the /art gateway applies the same rules", async () => {
  fresh();
  const anon = await fetch(`${mcpUrl}/art/tags/marketing-live`, { method: "DELETE" });
  assert.equal(anon.status, 401, "the store should have refused a keyless request");
  assert.ok(seen.every((s) => !s.key), "the gateway sent the key for an anonymous caller");

  fresh();
  const other = await fetch(`${mcpUrl}/art/tags/${enc("bar/x:1")}`, {
    method: "DELETE",
    headers: { authorization: "Bearer applb_ns_foo" },
  });
  assert.equal(other.status, 403);
  const list = await fetch(`${mcpUrl}/art/tags`, { headers: { authorization: "Bearer applb_ns_foo" } });
  assert.equal(list.status, 403);
  assert.equal(seen.length, 0, `refused gateway calls reached the store: ${JSON.stringify(seen)}`);

  const own = await fetch(`${mcpUrl}/art/tags/${enc("foo/x:1")}`, {
    method: "DELETE",
    headers: { authorization: "Bearer applb_ns_foo" },
  });
  assert.equal(own.status, 200);
  assert.ok(seen.some((s) => s.key && s.method === "DELETE"), JSON.stringify(seen));
});
