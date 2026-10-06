/**
 * A VM never runs its image's CMD/ENTRYPOINT. The us5 newsfeed-api deployment
 * (2026-10-06) had no vm.start_command: it built, booted, and timed out every
 * boot, and the customer's CMD fix "did nothing". These pin the MCP so an
 * agent cannot deploy that shape by accident.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { loadConfig } from "./config.js";
import { buildTools } from "./server.js";

const DOCKERFILE =
  "FROM node:18-alpine\nWORKDIR /app\nCOPY package.json ./\nRUN npm install --production\n" +
  "COPY . .\nEXPOSE 8080\nCMD [\"node\", \"server.js\"]\n";

async function run(
  toolName: string,
  args: Record<string, unknown>,
  opts: { existing?: Record<string, unknown>; dockerfile?: string } = {},
) {
  const config = loadConfig({
    APPLB_URL: "http://127.0.0.1:9090",
    APPLB_TOKEN: "applb_x",
    APPLB_NAMESPACE: "us5",
    REMOTE_URL: "https://git.us5.example.com",
  });
  const tool = buildTools(config).find((t) => t.name === toolName)!;
  const writes: { method: string; url: string; body: any }[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    if (method !== "GET") writes.push({ method, url, body });
    const reply = (status: number, b: unknown) =>
      new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
    if (url.includes("/api/repos/")) {
      return reply(200, { clone_url: "https://git.us5.example.com/us5/newsfeed-api.git", default_branch: "main", empty: false });
    }
    if (url.endsWith("/api/tokens")) return reply(201, { token: "hrm_1_s", id: "t1" });
    if (url.includes("/raw/")) {
      return opts.dockerfile && url.endsWith("/Dockerfile")
        ? new Response(opts.dockerfile, { status: 200, headers: { "content-type": "text/plain" } })
        : reply(404, { error: "not found" });
    }
    if (method === "GET" && /\/deployments\/[^/?]+$/.test(url)) {
      return opts.existing ? reply(200, { spec: opts.existing }) : reply(404, { error: "not found" });
    }
    if (method === "POST" && /\/(build|pull)$/.test(url)) return reply(202, { id: "job-1", status: "queued" });
    return reply(200, { id: "newsfeed-api" });
  }) as typeof fetch;
  try {
    const out = await tool.handler({ ...args, wait_seconds: 0 });
    const reg = writes.find(
      (w) => /\/deployments(\/newsfeed-api)?$/.test(w.url) && (w.method === "POST" || w.method === "PUT"),
    );
    return { out, spec: reg?.body };
  } finally {
    globalThis.fetch = original;
  }
}

const buildSpec = (vm: Record<string, unknown> = {}) => ({
  id: "newsfeed-api",
  namespace: "us5",
  routes: [{ host: "api.us5.example.com" }],
  vm: { driver: "firecracker", port: 8080, ...vm },
  build: { repo: "https://git.us5.example.com/us5/newsfeed-api.git", ref: "main", dockerfile: "Dockerfile" },
  health: { path: "/" },
});

test("applb_deploy derives start_command from a Heyo-remote Dockerfile", async () => {
  const { out, spec } = await run("applb_deploy", { spec: buildSpec() }, { dockerfile: DOCKERFILE });
  assert.equal(spec?.vm?.start_command, "cd /app && setsid nohup node server.js </dev/null &");
  assert.match(out, /start_command \(from the Dockerfile\)/);
});

test("applb_deploy refuses a VM spec it cannot give a start_command — the newsfeed-api shape", async () => {
  const { out, spec } = await run("applb_deploy", { spec: buildSpec() }, { dockerfile: "FROM node:18-alpine\nRUN true\n" });
  assert.equal(spec, undefined, "nothing was registered");
  assert.match(out, /not sent — no start_command/);
  assert.match(out, /never runs its image's CMD/);

  const artifact = { ...buildSpec(), build: undefined, artifact: { store: "https://hub.example.com", ref: "x:1" } };
  const pulled = await run("applb_deploy", { spec: artifact });
  assert.equal(pulled.spec, undefined, "an artifact VM with no start_command is refused too");
});

test("applb_deploy keeps an existing start_command a resubmitted spec dropped", async () => {
  const existing = buildSpec({ start_command: "cd /app && setsid nohup node index.js </dev/null &" });
  const { spec, out } = await run("applb_deploy", { spec: buildSpec() }, { existing });
  assert.equal(spec?.vm?.start_command, "cd /app && setsid nohup node index.js </dev/null &");
  assert.match(out, /start_command \(kept\)/);
});

test("applb_deploy accepts no start_command when the image owns /init.sh, or when told to", async () => {
  // An image that copies in its own init and declares no CMD starts its app
  // from that init, so it needs no start_command.
  const quiet = "FROM alpine\nCOPY init.sh /init.sh\n";
  const owns = await run("applb_deploy", { spec: buildSpec() }, { dockerfile: quiet });
  assert.ok(owns.spec, "registered");
  assert.equal(owns.spec.vm.start_command, undefined);

  const told = await run("applb_deploy", { spec: buildSpec(), no_start_command: true }, { dockerfile: "FROM alpine\n" });
  assert.ok(told.spec, "registered when acknowledged");
  assert.match(told.out, /no_start_command/);
});

test("repo_deploy says when a kept start_command no longer matches the Dockerfile's CMD", async () => {
  const existing = buildSpec({ start_command: "cd /app && setsid nohup npm start </dev/null &" });
  const { out, spec } = await run(
    "repo_deploy",
    { repo: "newsfeed-api", kind: "vm", deployment: "newsfeed-api" },
    { existing, dockerfile: DOCKERFILE },
  );
  assert.ok(spec);
  assert.match(out, /start_command kept \(differs from the Dockerfile\)/);
  assert.match(out, /node server\.js/);
});
