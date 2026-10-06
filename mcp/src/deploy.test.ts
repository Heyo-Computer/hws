/**
 * The composite, the resources and the prompt — the entry point the field
 * report asked for.
 *
 * `artifacts.ts` states the house rule: a composite tool beats a documented
 * sequence when a step is easy to get wrong. Two steps in this sequence were
 * demonstrably easy to get wrong, because this server got both of them wrong —
 * it exposed only the register path that recycles the VM pool, and it named a
 * job tool that refuses the main case. `applb_deploy` makes each of those
 * unrepresentable rather than merely documented: the method follows from
 * whether the deployment exists, and the job follows from what the spec
 * contains.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { loadConfig } from "./config.js";
import { buildTools, createServer } from "./server.js";
import type { Tool } from "./tools/diagnose.js";

interface Call {
  url: string;
  method: string;
  body?: unknown;
}

/** Fake app-lb: `existing` decides whether GET /deployments/:id is a 404. */
function stubApplb({ existing }: { existing?: Record<string, unknown> } = {}) {
  const calls: Call[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    calls.push({
      url,
      method,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    });
    const reply = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });

    if (method === "GET" && /\/deployments\/[^/]+$/.test(url)) {
      return existing ? reply(200, existing) : reply(404, { error: "not found" });
    }
    if (/\/jobs\//.test(url)) return reply(200, { id: "job-1", status: "succeeded" });
    if (method === "POST" && /(build|pull|update)$/.test(url)) {
      return reply(202, { id: "job-1", status: "queued" });
    }
    return reply(200, { id: "web" });
  }) as typeof fetch;
  return { calls, restore: () => void (globalThis.fetch = original) };
}

const cfg = () => loadConfig({ APPLB_URL: "http://127.0.0.1:9090", APPLB_TOKEN: "applb_x" });

function tool(name: string): Tool {
  const found = buildTools(cfg()).find((t) => t.name === name);
  assert.ok(found, `no such tool: ${name}`);
  return found;
}

const VM_SPEC = {
  id: "web",
  routes: [{ host: "web.example.com" }],
  vm: { driver: "firecracker", port: 8080 },
  artifact: { store: "http://127.0.0.1:8080", ref: "web" },
};

test("a spec that breaks a rule is never sent, and the rule is named", async () => {
  const stub = stubApplb();
  try {
    const out = await tool("applb_deploy").handler({
      spec: { id: "web", routes: [], vm: { driver: "firecracker", port: 8080 }, upstreams: ["a:1"] },
    });
    assert.match(out, /Two backends/, `did not name the rule: ${out.slice(0, 200)}`);
    assert.equal(stub.calls.length, 0, "a spec known to be invalid still went to app-lb");
  } finally {
    stub.restore();
  }
});

test("a new deployment is POSTed; an existing one is PUT", async () => {
  for (const [existing, method, path] of [
    [undefined, "POST", "/deployments"],
    [{ spec: VM_SPEC }, "PUT", "/deployments/web"],
  ] as const) {
    const stub = stubApplb({ existing: existing as Record<string, unknown> | undefined });
    try {
      await tool("applb_deploy").handler({ spec: VM_SPEC, wait_seconds: 0 });
      const write = stub.calls.find((c) => c.method === "POST" || c.method === "PUT");
      assert.equal(write?.method, method);
      assert.ok(write?.url.endsWith(path), `expected ${path}, got ${write?.url}`);
    } finally {
      stub.restore();
    }
  }
});

test("an edit says whether the pool survives it", async () => {
  const stub = stubApplb({ existing: { spec: VM_SPEC } });
  try {
    // Unchanged `vm` keeps the pool; this is the fact the register-only path
    // could never report, because registering always recycles.
    const same = await tool("applb_deploy").handler({ spec: VM_SPEC, wait_seconds: 0 });
    assert.match(same, /preserved/);

    const changed = await tool("applb_deploy").handler({
      spec: { ...VM_SPEC, vm: { driver: "firecracker", port: 9090 } },
      wait_seconds: 0,
    });
    assert.match(changed, /REBUILDING/);
  } finally {
    stub.restore();
  }
});

test("the job started follows from the backend, so the wrong one cannot be picked", async () => {
  const cases: [Record<string, unknown>, string][] = [
    [VM_SPEC, "/pull"],
    [
      {
        id: "web",
        routes: [{ host: "w.example.com" }],
        vm: { driver: "firecracker", port: 8080 },
        build: { repo: "https://example.com/x.git" },
      },
      "/build",
    ],
    [
      {
        id: "web",
        routes: [{ host: "w.example.com" }],
        upstreams: ["127.0.0.1:3000"],
        update: { working_dir: "/srv/web", commands: ["make"] },
      },
      "/update",
    ],
  ];
  for (const [spec, expected] of cases) {
    const stub = stubApplb();
    try {
      await tool("applb_deploy").handler({ spec, wait_seconds: 0 });
      const job = stub.calls.find((c) => c.method === "POST" && /(build|pull|update)$/.test(c.url));
      assert.ok(job?.url.endsWith(expected), `expected ${expected}, got ${job?.url}`);
    } finally {
      stub.restore();
    }
  }
});

test("a static deployment with no update block starts no job and says why", async () => {
  const stub = stubApplb();
  try {
    const out = await tool("applb_deploy").handler({
      spec: { id: "web", routes: [{ host: "w.example.com" }], upstreams: ["127.0.0.1:3000"] },
      wait_seconds: 0,
    });
    assert.match(out, /No job started/);
    assert.ok(
      !stub.calls.some((c) => /(build|pull|update)$/.test(c.url)),
      "started a job for a deployment that has nothing to roll onto",
    );
  } finally {
    stub.restore();
  }
});

test("a host_suffix route is warned about, because it never gets its own certificate", async () => {
  const stub = stubApplb();
  try {
    const out = await tool("applb_deploy").handler({
      spec: {
        id: "web",
        routes: [{ host_suffix: "apps.example.com" }],
        vm: { driver: "firecracker", port: 8080 },
      },
      wait_seconds: 0,
    });
    assert.match(out, /TLS warning/);
    assert.match(out, /apps\.example\.com/);
  } finally {
    stub.restore();
  }
});

test("an exact host route is not warned about", async () => {
  const stub = stubApplb();
  try {
    const out = await tool("applb_deploy").handler({ spec: VM_SPEC, wait_seconds: 0 });
    assert.doesNotMatch(out, /TLS warning/, "an exact host is issued automatically");
  } finally {
    stub.restore();
  }
});

// ---- resources and prompts, over the real protocol -------------------------

async function connected() {
  const config = cfg();
  const server = createServer(config, buildTools(config));
  const client = new Client({ name: "test", version: "0" }, { capabilities: {} });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), client.connect(a)]);
  return { client, close: async () => void (await Promise.all([client.close(), server.close()])) };
}

test("the reference material is listed and readable", async () => {
  const { client, close } = await connected();
  try {
    const { resources } = await client.listResources();
    const uris = resources.map((r) => r.uri);
    for (const u of [
      "heyo://applb/deployment-spec",
      "heyo://applb/deploy-guide",
      "heyo://applb/tls",
    ]) {
      assert.ok(uris.includes(u), `${u} is not listed`);
    }
    assert.ok(
      uris.some((u) => u.startsWith("heyo://applb/examples/")),
      "no examples are listed",
    );

    const guide = await client.readResource({ uri: "heyo://applb/deploy-guide" });
    const text = String((guide.contents[0] as { text: string }).text);
    // The mapping that was wrong on the tool surface has to be right here.
    assert.match(text, /applb_pull/);
    assert.match(text, /applb_host_update/);
  } finally {
    await close();
  }
});

test("an example resource comes back with its spec and its notes", async () => {
  const { client, close } = await connected();
  try {
    const res = await client.readResource({ uri: "heyo://applb/examples/git-build.json" });
    const text = String((res.contents[0] as { text: string }).text);
    assert.match(text, /"driver": "firecracker"/, "the spec itself is missing");
    assert.match(text, /git-build\.json/);

    const { resourceTemplates } = await client.listResourceTemplates();
    assert.ok(resourceTemplates.some((t) => t.uriTemplate.includes("{name}")));

    await assert.rejects(() => client.readResource({ uri: "heyo://applb/examples/nope.json" }));
  } finally {
    await close();
  }
});

test("the deploy prompt names the tools for the kind it was asked about", async () => {
  const { client, close } = await connected();
  try {
    const { prompts } = await client.listPrompts();
    assert.ok(prompts.some((p) => p.name === "deploy_a_service"));

    const vm = await client.getPrompt({
      name: "deploy_a_service",
      arguments: { kind: "vm", id: "web", host: "web.example.com" },
    });
    const text = String((vm.messages[0]!.content as { text: string }).text);
    assert.match(text, /applb_deploy/);
    assert.match(text, /applb_job/);
    assert.match(text, /web\.example\.com/);

    // A static deployment must not be told to use the VM job tools.
    const stat = await client.getPrompt({
      name: "deploy_a_service",
      arguments: { kind: "static", id: "api" },
    });
    const statText = String((stat.messages[0]!.content as { text: string }).text);
    assert.match(statText, /applb_host_update/);
    assert.match(statText, /do NOT apply to a\s+static deployment/);
  } finally {
    await close();
  }
});

test("a build.repo on the Heyo git remote gets a build credential; other repos do not", async () => {
  const config = loadConfig({
    APPLB_URL: "http://127.0.0.1:9090",
    APPLB_TOKEN: "applb_x",
    REMOTE_URL: "https://git.us5.example.com",
  });
  const deploy = buildTools(config).find((t) => t.name === "applb_deploy");
  assert.ok(deploy);
  for (const [repo, expectAuth] of [
    ["https://git.us5.example.com/us5/newsfeed-app.git", true],
    ["https://github.com/someone/public.git", false],
  ] as const) {
    const calls: Call[] = [];
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
      calls.push({ url, method, body });
      const reply = (status: number, b: unknown) =>
        new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
      if (url.endsWith("/api/tokens")) return reply(201, { token: "hrm_1_s", id: "t1" });
      if (method === "GET" && /\/deployments\/[^/]+$/.test(url)) return reply(404, { error: "not found" });
      if (method === "POST" && /\/build$/.test(url)) return reply(202, { id: "job-1", status: "queued" });
      return reply(200, { id: "newsfeed-app" });
    }) as typeof fetch;
    try {
      const out = await deploy.handler({
        spec: {
          id: "newsfeed-app",
          namespace: "us5",
          routes: [{ host: "newsfeed.example.com" }],
          vm: { driver: "firecracker", port: 8080 },
          build: { repo, dockerfile: "Dockerfile" },
        },
        wait_seconds: 0,
      });
      const register = calls.find((c) => c.method === "POST" && c.url.endsWith("/deployments"));
      const auth = (register?.body as { build?: { auth?: unknown } })?.build?.auth;
      if (expectAuth) {
        const mint = calls.find((c) => c.url.endsWith("/api/tokens"));
        assert.deepEqual((mint?.body as { repos: string[] }).repos, ["newsfeed-app"]);
        assert.equal((mint?.body as { namespace: string }).namespace, "us5");
        const secret = calls.find((c) => c.url.endsWith("/secrets"));
        assert.equal((secret?.body as { id: string }).id, "git-newsfeed-app");
        assert.deepEqual(auth, { secret: "git-newsfeed-app", key: "token", username: "x-access-token" });
        assert.match(out, /Build credential/);
      } else {
        assert.equal(auth, undefined);
        assert.ok(!calls.some((c) => c.url.endsWith("/api/tokens")), "minted for a repo elsewhere");
      }
    } finally {
      globalThis.fetch = original;
    }
  }
});
