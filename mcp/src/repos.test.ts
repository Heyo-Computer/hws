/**
 * The git remote tools, the artifact-store gateway tools, and the `/art`
 * HTTP gateway.
 *
 * Asserted on the requests this server builds, as `artifacts.test.ts` does,
 * because the mistakes worth catching are ones the services accept: a deploy
 * whose build credential expires, a site spec with a root on the wrong
 * machine, a bundle that is not a tar the site pull can unpack.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

import { loadConfig, withForwardedAuth } from "./config.js";
import { buildTools } from "./server.js";
import { serveHttp } from "./serve-http.js";
import { tarGz, validPath, readDirectory } from "./files.js";
import type { Tool } from "./tools/diagnose.js";

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  bytes?: Uint8Array;
}

function stubFetch(responder: (call: Call) => { status?: number; body?: unknown; raw?: Uint8Array }) {
  const calls: Call[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const raw = init?.body;
    const bytes =
      raw === undefined || raw === null
        ? undefined
        : typeof raw === "string"
          ? new TextEncoder().encode(raw)
          : new Uint8Array(raw as Uint8Array);
    const call: Call = {
      url: String(input),
      method: init?.method ?? "GET",
      headers: Object.fromEntries(
        Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]),
      ),
      body: bytes ? Buffer.from(bytes).toString("utf8") : undefined,
      bytes,
    };
    calls.push(call);
    const { status = 200, body = {}, raw: out } = responder(call);
    if (out) return new Response(out, { status });
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { calls, restore: () => void (globalThis.fetch = original) };
}

const tools = (env: Record<string, string> = {}) =>
  buildTools(
    loadConfig({
      APPLB_URL: "http://lb:9090",
      APPLB_TOKEN: "applb_1_agent",
      REMOTE_URL: "http://remote:9700",
      REMOTE_NAMESPACE: "team-a",
      ART_URL: "http://art:8080",
      ART_API_KEY: "art-key",
      ...env,
    }),
  );

function tool(list: Tool[], name: string): Tool {
  const t = list.find((x) => x.name === name);
  assert.ok(t, `no tool ${name}`);
  return t;
}

const parse = (s: string) => JSON.parse(s) as Record<string, unknown>;

test("repo_create reuses an existing repo and hands back a scoped write token", async () => {
  const stub = stubFetch((c) => {
    if (c.method === "POST" && c.url.endsWith("/api/repos/team-a")) return { status: 409, body: { error: "exists" } };
    if (c.url.endsWith("/api/repos/team-a/site"))
      return { body: { clone_url: "http://remote:9700/team-a/site.git", default_branch: "main" } };
    if (c.url.endsWith("/api/tokens")) return { status: 201, body: { token: "hrm_ab_cd", id: "ab" } };
    return {};
  });
  try {
    const out = parse(await tool(tools(), "repo_create").handler({ name: "site.git" }));
    assert.equal(out.created, false);
    assert.equal(out.token, "hrm_ab_cd");
    assert.match(String(out.push), /extraHeader="Authorization: Bearer hrm_ab_cd" push http:\/\/remote:9700\/team-a\/site.git HEAD:main/);
    const mint = stub.calls.find((c) => c.url.endsWith("/api/tokens"))!;
    assert.deepEqual(JSON.parse(mint.body!), {
      namespace: "team-a",
      repos: ["site"],
      access: "write",
      ttl_secs: 86400,
      name: "mcp-site",
    });
    // The agent's own app-lb token speaks at the remote, which resolves it.
    assert.equal(mint.headers.authorization, "Bearer applb_1_agent");
  } finally {
    stub.restore();
  }
});

test("repo_write_files sends a directory as the whole tree, without .git", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-repo-"));
  mkdirSync(join(dir, ".git"));
  mkdirSync(join(dir, "assets"));
  writeFileSync(join(dir, ".git", "HEAD"), "x");
  writeFileSync(join(dir, "index.html"), "<h1>hi</h1>");
  writeFileSync(join(dir, "assets", "a.bin"), Buffer.from([0, 1, 2]));
  const stub = stubFetch(() => ({ body: { commit: "c".repeat(40), changed: true } }));
  try {
    await tool(tools(), "repo_write_files").handler({ repo: "site", message: "upload", directory: dir });
    const body = JSON.parse(stub.calls[0]!.body!);
    assert.equal(stub.calls[0]!.url, "http://remote:9700/api/repos/team-a/site/commits");
    assert.equal(body.replace, true);
    assert.deepEqual(
      body.files.map((f: { path: string }) => f.path).sort(),
      ["assets/a.bin", "index.html"],
    );
    const bin = body.files.find((f: { path: string }) => f.path === "assets/a.bin");
    assert.deepEqual([...Buffer.from(bin.content, "base64")], [0, 1, 2]);
  } finally {
    stub.restore();
  }
});

test("repo_write_files refuses paths that escape, and directories over HTTP", async () => {
  await assert.rejects(
    tool(tools(), "repo_write_files").handler({
      repo: "site",
      message: "x",
      files: [{ path: "../etc/passwd", content: "x" }],
    }),
    /invalid path/,
  );
  // Over HTTP the parameter is not offered, so it is stripped before the handler.
  const http = tools({ HEYO_MCP_HTTP_PORT: "9650" });
  await assert.rejects(
    tool(http, "repo_write_files").handler({ repo: "site", message: "x", directory: "/etc" }),
    /no files/,
  );
  for (const bad of ["", "/a", "a/../b", ".git/config", "a//b"]) assert.ok(!validPath(bad), bad);
});

test("repo_deploy stores a non-expiring read token and registers a site built from the repo", async () => {
  const stub = stubFetch((c) => {
    if (c.url === "http://remote:9700/api/repos/team-a/site")
      return { body: { clone_url: "http://remote:9700/team-a/site.git", default_branch: "main", empty: false } };
    if (c.url.endsWith("/api/tokens")) return { status: 201, body: { token: "hrm_rd_xx", id: "rd" } };
    if (c.method === "GET" && c.url === "http://lb:9090/deployments/site") return { status: 404, body: { error: "no" } };
    if (c.url.endsWith("/build")) return { body: { id: "job-1" } };
    if (c.url.includes("/jobs/")) return { body: { status: "succeeded" } };
    return {};
  });
  try {
    await tool(tools(), "repo_deploy").handler({ repo: "site", host: "site.example.com", context: "dist", wait_seconds: 1 });
    const mint = JSON.parse(stub.calls.find((c) => c.url.endsWith("/api/tokens"))!.body!);
    assert.equal(mint.access, "read");
    assert.equal(mint.ttl_secs, 0, "a build credential must outlive the first build");

    const secret = JSON.parse(stub.calls.find((c) => c.url === "http://lb:9090/secrets")!.body!);
    assert.deepEqual(secret.data, { token: "hrm_rd_xx" });
    assert.equal(secret.id, "git-site");

    const reg = stub.calls.find((c) => c.method === "POST" && c.url === "http://lb:9090/deployments")!;
    const spec = JSON.parse(reg.body!);
    assert.equal(spec.site.root, undefined, "app-lb assigns the root; the caller never names one");
    assert.deepEqual(spec.build, {
      repo: "http://remote:9700/team-a/site.git",
      ref: "main",
      context: "dist",
      auth: { secret: "git-site", key: "token", username: "x-access-token" },
    });
    assert.deepEqual(spec.routes, [{ host: "site.example.com" }]);
    assert.ok(
      stub.calls.some((c) => c.method === "POST" && c.url === "http://lb:9090/deployments/site/build"),
      "the build is what fills the root, so it must be started",
    );
  } finally {
    stub.restore();
  }
});

test("art_publish_files publishes a tar.gz that tar itself can read", async () => {
  let blob: Uint8Array | undefined;
  const stub = stubFetch((c) => {
    if (c.method === "PUT" && c.url.includes("/blobs/")) blob = c.bytes;
    if (c.method === "PUT" && c.url.endsWith("/manifests")) return { body: { digest: "sha256:" + "m".repeat(64) } };
    return {};
  });
  try {
    const long = `${"d".repeat(60)}/${"e".repeat(60)}/page.html`;
    const out = parse(
      await tool(tools(), "art_publish_files").handler({
        tag: "site-live",
        files: [
          { path: "index.html", content: "<h1>hi</h1>" },
          { path: long, content: "deep" },
          { path: "run.sh", content: "#!/bin/sh\n", executable: true },
        ],
      }),
    );
    assert.equal(out.files, 3);
    const dir = mkdtempSync(join(tmpdir(), "mcp-tar-"));
    writeFileSync(join(dir, "b.tgz"), blob!);
    const listing = execFileSync("tar", ["-tzvf", join(dir, "b.tgz")]).toString();
    assert.match(listing, /index\.html/);
    assert.match(listing, /-rwxr-xr-x.*run\.sh/);
    execFileSync("tar", ["-xzf", join(dir, "b.tgz"), "-C", dir]);
    assert.equal(readFileSync(join(dir, long), "utf8"), "deep");
    const tag = stub.calls.find((c) => c.url.endsWith("/tags/site-live"))!;
    assert.equal(tag.body, "sha256:" + "m".repeat(64), "the tag names the manifest");
  } finally {
    stub.restore();
  }
});

test("art_fetch resolves a tag to its entry, verifies the digest, and returns text", async () => {
  const bytes = new TextEncoder().encode("hello world");
  const digest = createHash("sha256").update(bytes).digest("hex");
  let serve = bytes;
  const stub = stubFetch((c) => {
    if (c.url.includes("/manifests/")) return { body: { kind: "generic", entries: [{ name: "x", digest, size: 11 }] } };
    if (c.url.includes("/blobs/")) return { raw: serve };
    return {};
  });
  try {
    const out = parse(await tool(tools(), "art_fetch").handler({ reference: "my-tag" }));
    assert.equal(out.text, "hello world");
    assert.equal(out.digest, digest);
    serve = new TextEncoder().encode("tampered!!!");
    await assert.rejects(tool(tools(), "art_fetch").handler({ reference: "my-tag" }), /hashing to [0-9a-f]{64}, not [0-9a-f]{64}; nothing was kept/);
  } finally {
    stub.restore();
  }
});

test("a directory read refuses symlinks and finds nothing in an empty tree", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-dir-"));
  await assert.rejects(readDirectory(dir), /has no files/);
  execFileSync("ln", ["-s", "/etc/passwd", join(dir, "link")]);
  await assert.rejects(readDirectory(dir), /symlink/);
  assert.ok(tarGz([]).byteLength > 0, "an empty archive is still a valid gzip");
});

test("the remote is reached as the caller, whatever kind of credential they hold", () => {
  const base = loadConfig({ REMOTE_URL: "http://remote:9700", REMOTE_TOKEN: "hrm_operator_x" });
  for (const header of ["Bearer applb_1_x", "Bearer heyo_api_y", "Basic eDp5"]) {
    assert.equal(withForwardedAuth(base, { authorization: header }).remote?.auth, header);
  }
  assert.equal(withForwardedAuth(base, {}).remote?.auth, "Bearer hrm_operator_x");
});

test("the /art gateway forwards the store API, with the store key only for a caller app-lb vouches for", async () => {
  const seen: { method: string; url: string; key?: string; auth?: string; body: string }[] = [];
  const store = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({
        method: req.method!,
        url: req.url!,
        key: req.headers["x-api-key"] as string,
        auth: req.headers.authorization,
        body,
      });
      res.writeHead(200, { "content-type": "text/plain", etag: '"e1"' });
      res.end(req.method === "GET" ? "blob-bytes" : "ok");
    });
  });
  await new Promise<void>((r) => store.listen(0, "127.0.0.1", r));
  const storePort = (store.address() as { port: number }).port;
  // app-lb's /whoami, which is what lets the gateway hand this caller the key.
  const applb = createServer((req, res) => {
    const ok = req.url === "/whoami" && req.headers.authorization === "Bearer applb_1_caller";
    res.writeHead(ok ? 200 : 401, { "content-type": "application/json" });
    res.end(JSON.stringify(ok ? { caller: "app-token", admin_scope: "admin", fleet: true } : { error: "no" }));
  });
  await new Promise<void>((r) => applb.listen(0, "127.0.0.1", r));
  const applbPort = (applb.address() as { port: number }).port;
  const gwPort = 19_000 + Math.floor(Math.random() * 1000);
  const prev = process.env.HEYO_MCP_REQUIRE_IDENTITY;
  process.env.HEYO_MCP_REQUIRE_IDENTITY = "0";
  const gateway = await serveHttp(
    loadConfig({
      ART_URL: `http://127.0.0.1:${storePort}`,
      ART_API_KEY: "store-key",
      APPLB_URL: `http://127.0.0.1:${applbPort}`,
      HEYO_MCP_HTTP_PORT: String(gwPort),
    }),
    gwPort,
    "127.0.0.1",
  );
  try {
    const base = `http://127.0.0.1:${gwPort}`;
    const put = await fetch(`${base}/art/blobs/sha256:${"a".repeat(64)}`, {
      method: "PUT",
      headers: { authorization: "Bearer applb_1_caller", "content-type": "application/octet-stream" },
      body: "payload",
    });
    assert.equal(put.status, 200);
    const got = await fetch(`${base}/art/blobs/sha256:${"a".repeat(64)}`);
    assert.equal(await got.text(), "blob-bytes");
    assert.equal(got.headers.get("etag"), '"e1"');

    assert.equal(seen[0]!.method, "PUT");
    assert.equal(seen[0]!.body, "payload");
    assert.equal(seen[0]!.key, "store-key");
    assert.equal(seen[0]!.auth, "Bearer applb_1_caller", "the caller's app-token goes to the gate");
    // The anonymous GET went without the key: the store decides what an
    // anonymous caller may read (public blobs), not this server's key.
    assert.equal(seen[1]!.key, undefined, "an anonymous caller was sent with the store key");

    assert.equal((await fetch(`${base}/art/dashboard`)).status, 404, "the dashboard is not forwarded");
    assert.equal((await fetch(`${base}/art/tags/x`, { method: "POST" })).status, 405);
    assert.equal(seen.length, 2, "refused requests never reached the store");
  } finally {
    if (prev === undefined) delete process.env.HEYO_MCP_REQUIRE_IDENTITY;
    else process.env.HEYO_MCP_REQUIRE_IDENTITY = prev;
    store.close();
    applb.close();
    gateway.close();
  }
});
