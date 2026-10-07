/**
 * diagnose_vm_boot: the farm-backend case from us5 (2026-10-06) end to end —
 * a Node app whose server.js uses require() under "type": "module", started
 * with its output redirected to a file, so every VM booted, never answered
 * /health, and nothing outside the guest said why.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { loadConfig } from "./config.js";
import { buildTools } from "./server.js";
import {
  backoffFinding,
  foregroundScript,
  healthyPeers,
  interpret,
  lintVmSpec,
  noVmFinding,
  parseStartCommand,
  peerFinding,
  probeScript,
} from "./tools/vmboot.js";

const FARM =
  "cd /app && export NODE_ENV=production && export PORT=3001 && export HOST=0.0.0.0 && " +
  "setsid nohup node server.js </dev/null >/var/log/app.log 2>&1 &";

const CRASH =
  "file:///app/server.js:1\nconst express = require(\"express\");\n" +
  "ReferenceError: require is not defined in ES module scope, you can use import instead\n" +
  "This file is being treated as an ES module because it has a '.js' file extension and " +
  "'/app/package.json' contains \"type\": \"module\".";

test("a start_command is read for its workdir, redirects and foreground form", () => {
  const p = parseStartCommand(FARM);
  assert.equal(p.workdir, "/app");
  assert.deepEqual(p.redirects, ["/var/log/app.log"]);
  assert.equal(p.backgrounded, true);
  assert.equal(
    p.foreground,
    "cd /app && export NODE_ENV=production && export PORT=3001 && export HOST=0.0.0.0 && node server.js",
  );
  const plain = parseStartCommand("cd /app && setsid nohup node server.js </dev/null &");
  assert.deepEqual(plain.redirects, []);
  assert.equal(parseStartCommand("node server.js").backgrounded, false);
  assert.equal(parseStartCommand("a && b &&").backgrounded, false);
});

test("the spec lint names a hidden-output redirect, a foreground command and loopback", () => {
  const titles = (vm: Record<string, unknown>) => lintVmSpec(vm).map((f) => f.title);
  assert.deepEqual(titles({ start_command: FARM }), ["start_command hides the app's output"]);
  assert.deepEqual(titles({ start_command: "cd /app && setsid nohup node server.js </dev/null &" }), []);
  assert.ok(titles({ start_command: "node server.js" }).includes("start_command does not return"));
  assert.ok(titles({ start_command: "HOST=127.0.0.1 node s.js &" }).includes("App bound to loopback"));
  assert.deepEqual(titles({}), ["No start_command"]);
});

test("the probe reads heyvm's capture, the redirect target, sockets and the health path", () => {
  const script = probeScript({ port: 3001, healthPath: "/health", parts: parseStartCommand(FARM) });
  for (const want of [
    "/var/log/heyvm-start.log",
    "/var/log/heyvm-start.err.log",
    "tail -n 80 '/var/log/app.log'",
    "ss -ltn",
    "http://127.0.0.1:3001/health",
    "'/app/package.json'",
  ]) {
    assert.ok(script.includes(want), `probe lacks ${want}`);
  }
  assert.ok(!script.includes("\\"), "no backslashes: the exec channel mangles them");
  assert.ok(!script.includes("$("), "no command substitution: the exec channel drops it");
  assert.match(foregroundScript(parseStartCommand(FARM)), /^echo .*timeout 15 sh -c '.*node server\.js' 2>&1; echo "exit=\$\?"$/);
});

test("known crash signatures turn into fixes", () => {
  assert.match(interpret(CRASH)[0]?.title ?? "", /module-type mismatch/);
  assert.match(interpret("Error: Cannot find module 'express'")[0]?.title ?? "", /module is missing/);
  assert.match(interpret("Error: listen EADDRINUSE: address already in use")[0]?.title ?? "", /Port already in use/);
  const loop = interpret("LISTEN 0 511 127.0.0.1:3001 0.0.0.0:*", 3001);
  assert.ok(loop.some((f) => f.title === "Listening on loopback only"));
  assert.ok(!interpret("LISTEN 0 511 0.0.0.0:3001 0.0.0.0:*", 3001).some((f) => /loopback/.test(f.title)));
  assert.deepEqual(interpret("all quiet"), []);
  // What the probe printed in the real farm-backend guest on us5.
  const refused = interpret("wget: can't connect to remote host (127.0.0.1): Connection refused", 3001);
  assert.ok(refused.some((f) => f.title === "Nothing is listening on :3001"));
  assert.match(
    noVmFinding('deployment "farm-backend" has no VM and none became available within cold_start_timeout_secs')?.title ?? "",
    /No VM to probe/,
  );
  assert.equal(noVmFinding("connection reset"), undefined);
});

test("diagnose_vm_boot probes a booting VM and names the farm-backend crash", async () => {
  const calls: Array<{ url: string; method: string; body?: Record<string, unknown> }> = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ url, method, body });
    let reply: unknown = {};
    if (url.endsWith("/deployments/farm-backend")) {
      reply = {
        spec: {
          id: "farm-backend",
          vm: { port: 3001, start_command: FARM },
          health: { path: "/health" },
        },
      };
    } else if (url.includes("/metrics")) {
      reply = {
        deployments: [
          {
            id: "farm-backend",
            pool: { ready: 0, pending: 1 },
            pending_vms: [{ sandbox_id: "sb-1", waiting_on: "the guest is up but has not answered GET /health" }],
            metrics: { autoscale: { vms_created: 33, boot_timeouts: 26 } },
          },
        ],
      };
    } else if (url.endsWith("/exec")) {
      const fg = String(body?.command).includes("timeout 15");
      reply = {
        sandbox_id: "sb-1",
        exit_code: 0,
        output: fg ? `${CRASH}\nexit=1` : "== heyvm-start.log\n== listening sockets\nLISTEN 0 4096 0.0.0.0:22",
      };
    }
    return new Response(JSON.stringify(reply), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  try {
    const tools = buildTools(loadConfig({ APPLB_URL: "http://127.0.0.1:9090", APPLB_BASIC: "admin:pw" }));
    const t = tools.find((x) => x.name === "diagnose_vm_boot");
    assert.ok(t);
    const out = await t.handler({ id: "farm-backend", foreground: true });
    assert.match(out, /module-type mismatch/);
    assert.match(out, /start_command hides the app's output/);
    assert.match(out, /boot_timeouts/);

    const execs = calls.filter((c) => c.url.endsWith("/deployments/farm-backend/exec"));
    assert.equal(execs.length, 2, "one probe, one foreground run");
    assert.equal(execs[0]?.body?.wake, true);
    assert.equal(execs[1]?.body?.sandbox_id, "sb-1", "the foreground run stays in the probed VM");
    assert.equal(execs[1]?.body?.wake, false);
    assert.ok(calls.every((c) => c.method === "GET" || c.url.endsWith("/exec")), "nothing but reads and exec");
  } finally {
    globalThis.fetch = original;
  }
});

// us5, 2026-10-06: newsfeed-api and farm-backend sat at the hour-long backoff
// ceiling with `pending: 0`, and the agent reported a platform-wide outage while
// newsfeed-app, heyo-mcp and remote served from the same host.
test("a held-off pool says so, with the wait and the way out", () => {
  const held = backoffFinding({ boot_failures: 24, boot_backoff_secs: 3120 });
  assert.match(held?.title ?? "", /Boot backoff/);
  assert.match(held?.detail ?? "", /24 boots in a row/);
  assert.match(held?.detail ?? "", /52 min/);
  assert.match(held?.detail ?? "", /applb_scale/);
  assert.equal(backoffFinding({ boot_failures: 0, boot_backoff_secs: null }), undefined);
  assert.equal(backoffFinding(undefined), undefined, "an app-lb that predates the fields says nothing");

  const noVm = noVmFinding("deployment \"x\" had no VM ready within its cold-start timeout", { boot_backoff_secs: 600 });
  assert.match(noVm?.detail ?? "", /next VM in 10 min/);
  assert.doesNotMatch(noVmFinding("x has no VM")?.detail ?? "", /16 minutes/, "the ceiling is an hour");
  assert.match(noVmFinding("x has no VM")?.detail ?? "", /up to an hour/);
});

test("healthy peers come only from the /metrics the caller was given", () => {
  const metrics = {
    deployments: [
      { id: "newsfeed-api", kind: "vm", pool: { ready: 0, draining: 0 } },
      { id: "newsfeed-app", kind: "vm", pool: { ready: 1, draining: 0 } },
      { id: "heyo-mcp", kind: "vm", pool: { ready: 1, draining: 0 } },
      { id: "draining-out", kind: "vm", pool: { ready: 1, draining: 1 } },
      { id: "app-lb-admin", kind: "static", pool: { ready: 1, draining: 0 } },
    ],
  };
  assert.deepEqual(healthyPeers(metrics, "newsfeed-api"), ["newsfeed-app", "heyo-mcp"]);
  assert.deepEqual(healthyPeers({ deployments: [] }, "x"), [], "a caller who sees nothing else is told nothing");
  assert.match(peerFinding(["newsfeed-app", "heyo-mcp"])?.detail ?? "", /newsfeed-app, heyo-mcp have VMs/);
  assert.match(peerFinding(["newsfeed-app"])?.detail ?? "", /the deployments you can see/);
  assert.equal(peerFinding([]), undefined);
});
