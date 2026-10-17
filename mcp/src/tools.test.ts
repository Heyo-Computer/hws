/**
 * The behaviour that is not obvious from a route table: the requests the
 * sandbox tools make of app-lb, what the server refuses to send, and what it
 * makes of a feed cursor that has outlived the feed.
 *
 * `fetch` is stubbed rather than a live app-lb reached, so these assert the
 * shapes this server produces — the request it builds and the text it hands
 * back — not that app-lb agrees with them.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { loadConfig, withForwardedAuth } from "./config.js";
import { buildTools } from "./server.js";
import type { Tool } from "./tools/diagnose.js";

interface Call {
  url: string;
  method: string;
  body?: unknown;
  headers?: Record<string, string>;
  raw?: string;
}

type Reply = { status?: number; body?: unknown };

/** Stub `fetch` with a per-URL responder, and record what was asked. */
function stubFetch(responder: (call: Call) => Reply): { calls: Call[]; restore: () => void } {
  const calls: Call[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const call: Call = {
      url: String(input),
      method: init?.method ?? "GET",
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
      headers: (init?.headers ?? {}) as Record<string, string>,
      raw: init?.body instanceof Uint8Array ? Buffer.from(init.body).toString("utf8") : undefined,
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

const LB = "https://admin.us5.heyo.work";
const teamA = () =>
  buildTools(loadConfig({ APPLB_URL: LB, APPLB_TOKEN: "applb_1_x", APPLB_NAMESPACE: "team-a" }));

test("sandbox_create registers a route-less hub VM, create-only, then waits for it", async () => {
  let registered = false;
  const stub = stubFetch((c) => {
    if (c.method === "POST" && c.url === `${LB}/deployments`) registered = true;
    if (c.method === "GET" && c.url === `${LB}/deployments/sb-1` && !registered) {
      return { status: 404, body: { error: "no" } };
    }
    if (c.url.endsWith("/whoami")) return { body: { namespace: "team-a" } };
    if (c.url.endsWith("/pull")) return { body: { id: "job-1", status: "succeeded" } };
    if (c.url.includes("/jobs")) return { body: { id: "job-1", status: "succeeded" } };
    if (c.url.endsWith("/start")) return { body: { state: "running", sandbox_id: "applb-sb-1-a" } };
    return { body: { spec: { id: "sb-1" } } };
  });
  try {
    const out = await tool(teamA(), "sandbox_create").handler({ name: "sb-1", wait_seconds: 5 });
    const register = stub.calls.find((c) => c.method === "POST" && c.url === `${LB}/deployments`);
    const spec = register?.body as Record<string, any>;
    assert.equal(spec.id, "sb-1");
    assert.deepEqual(spec.routes, []);
    assert.equal(spec.namespace, "team-a", "the token's namespace is filled in");
    assert.deepEqual(spec.artifact, { store: "https://hub.heyo.work", ref: "heyo/debian:latest" });
    assert.equal(spec.scaling.idle_action, "retain");
    assert.equal(spec.vm.disk_size_gb, 10);
    const start = stub.calls.find((c) => c.url === `${LB}/deployments/sb-1/start`);
    assert.deepEqual(start?.body, { wait_secs: 5 });
    assert.match(out, /applb-sb-1-a/);
    assert.ok(stub.calls.every((c) => c.url.startsWith(LB)), "app-lb only");
  } finally {
    stub.restore();
  }
});

test("sandbox_create never overwrites an existing deployment", async () => {
  const stub = stubFetch(() => ({ body: { spec: { id: "sb-1" } } }));
  try {
    const out = await tool(teamA(), "sandbox_create").handler({ name: "sb-1" });
    assert.match(out, /already exists/);
    assert.ok(stub.calls.every((c) => c.method === "GET"));
  } finally {
    stub.restore();
  }
});

test("each sandbox tool makes the app-lb request it names", async () => {
  const stub = stubFetch(() => ({ body: { ok: true, state: "ready", upload_url: "u", download_url: "d" } }));
  const tools = teamA();
  const cases: [string, Record<string, unknown>, string, string, unknown?][] = [
    ["sandbox_list", {}, "GET", "/deployments"],
    ["sandbox_info", { id: "sb" }, "GET", "/deployments/sb"],
    ["sandbox_exec", { id: "sb", command: "ls" }, "POST", "/deployments/sb/exec", { command: "ls" }],
    ["sandbox_exec_start", { id: "sb", command: "npm test", max_runtime_secs: 60 }, "POST", "/deployments/sb/operations",
      { command: "npm test", max_runtime_secs: 60 }],
    ["sandbox_exec_status", { id: "sb", operation: "op_1", offset: 10 }, "GET",
      "/deployments/sb/operations/op_1?offset=10&max_bytes=65536"],
    ["sandbox_exec_cancel", { id: "sb", operation: "op_1" }, "DELETE", "/deployments/sb/operations/op_1"],
    ["sandbox_read_file", { id: "sb", path: "/workspace/a b" }, "GET", "/deployments/sb/files?path=%2Fworkspace%2Fa+b"],
    ["sandbox_write_file", { id: "sb", path: "/w/f", content: "hi", append: true }, "PUT",
      "/deployments/sb/files?path=%2Fw%2Ff&append=true"],
    ["sandbox_upload", { id: "sb", path: "/workspace/app" }, "POST", "/deployments/sb/transfers",
      { direction: "in", path: "/workspace/app", extract: "auto" }],
    ["sandbox_download", { id: "sb", path: "/workspace/dist" }, "POST", "/deployments/sb/transfers",
      { direction: "out", path: "/workspace/dist", wait_secs: 50 }],
    ["sandbox_transfer_status", { id: "sb", transfer: "tr_1" }, "GET", "/deployments/sb/transfers/tr_1"],
    ["sandbox_stop", { id: "sb" }, "POST", "/deployments/sb/stop", { wait_secs: 30, force: false }],
    ["sandbox_stop", { id: "sb", force: true }, "POST", "/deployments/sb/stop", { wait_secs: 30, force: true }],
    ["sandbox_start", { id: "sb" }, "POST", "/deployments/sb/start", { wait_secs: 60 }],
    ["sandbox_restart", { id: "sb", fresh: true }, "POST", "/deployments/sb/restart", { wait_secs: 60, fresh: true, force: false }],
    ["sandbox_kill", { id: "sb" }, "DELETE", "/deployments/sb"],
    ["heyo_capacity", {}, "GET", "/capacity"],
  ];
  try {
    for (const [name, args, method, path, body] of cases) {
      stub.calls.length = 0;
      await tool(tools, name).handler(args);
      const call = stub.calls[0];
      assert.equal(call?.method, method, name);
      assert.equal(call?.url, `${LB}${path}`, name);
      if (body !== undefined) assert.deepEqual(call?.body, body, name);
    }
  } finally {
    stub.restore();
  }
});

test("sandbox_write_file sends the bytes, not JSON, and decodes base64 first", async () => {
  const stub = stubFetch(() => ({ body: { wrote: 2 } }));
  try {
    await tool(teamA(), "sandbox_write_file").handler({ id: "sb", path: "/f", content: "aGk=", encoding: "base64" });
    assert.equal(stub.calls[0]?.raw, "hi");
    assert.equal(stub.calls[0]?.headers?.["content-type"], "application/octet-stream");
  } finally {
    stub.restore();
  }
});

test("sandbox_upload hands back a curl line for the one-time URL", async () => {
  const stub = stubFetch(() => ({ body: { id: "tr_1", upload_url: `${LB}/transfers/tok` } }));
  try {
    const out = await tool(teamA(), "sandbox_upload").handler({ id: "sb", path: "/workspace/app" });
    assert.match(out, /curl -sS -T <file> 'https:\/\/admin\.us5\.heyo\.work\/transfers\/tok'/);
  } finally {
    stub.restore();
  }
});

test("the feed cursor is the caller's, and one from before a restart reads as a reset", async () => {
  const events = [
    { id: 7, kind: "issue", title: "web: cold start timed out" },
    { id: 6, kind: "deployed", title: "web deployed" },
  ];
  const stub = stubFetch((c) =>
    c.url.endsWith("/namespaces") ? { body: { namespaces: [{ name: "team-a" }] } } : { body: events },
  );
  try {
    const feed = tool(teamA(), "applb_feed");

    const fresh = await feed.handler({});
    assert.match(fresh, /latest_id 7/);
    // The namespace came from the discovery app-lb already did — the feed is
    // served at /feeds/:namespace, so it has to be named, not merely reached.
    assert.equal(
      stub.calls[0]?.url,
      `${LB}/feeds/team-a?format=json`,
    );

    const incremental = await feed.handler({ since_id: 6 });
    assert.match(incremental, /cold start timed out/);
    assert.doesNotMatch(incremental, /web deployed/);

    // app-lb restarted: the ring is empty of everything the caller saw, and its
    // ids began again. Silence here would be permanent, so it says so instead.
    const afterRestart = await feed.handler({ since_id: 4_000 });
    assert.match(afterRestart, /Feed reset/);
    assert.match(afterRestart, /web deployed/);
  } finally {
    stub.restore();
  }
});

test("an app-lb URL alone lists the sandbox tools, and no tool or config points at the cloud", () => {
  const tools = buildTools(loadConfig({ APPLB_URL: "http://127.0.0.1:8080" }));
  const names = tools.map((t) => t.name);
  for (const n of ["sandbox_create", "sandbox_exec", "sandbox_exec_start", "sandbox_upload", "heyo_capacity"]) {
    assert.ok(names.includes(n), n);
  }
  assert.ok(!names.includes("heyo_request"), "the raw cloud tool is gone");
  // Hosted, as the caller: an app-lb token is all a sandbox needs.
  const hosted = withForwardedAuth(loadConfig({ APPLB_URL: "http://127.0.0.1:8080", HEYO_MCP_HTTP_PORT: "8090" }), {
    authorization: "Bearer applb_abc123_secret",
  });
  assert.ok(buildTools(hosted).some((t) => t.name === "sandbox_create"));
  const text = JSON.stringify(tools.map((t) => [t.name, t.description]));
  assert.ok(!text.includes("server.heyo.computer"), "no tool mentions the cloud host");
});

/**
 * app-obs's own token reads every namespace, so a namespace-confined caller
 * must never be served on it. Such a caller reads through app-lb's obs plugin
 * for its namespace, with its own credential — app-lb decides reach, and pins
 * the namespace before app-obs is asked.
 */
test("a namespace-configured caller reads logs through its namespace's obs plugin, never app-obs's token", async () => {
  const stub = stubFetch((c) => {
    if (c.url.endsWith("/namespaces")) {
      return { body: { namespaces: [{ name: "team-a", scope: "admin" }] } };
    }
    return { body: { rows: [{ ts: 1, level: "error", message: "giving up on VM" }] } };
  });
  try {
    const tools = buildTools(
      loadConfig({
        APPLB_URL: LB,
        APPLB_NAMESPACE: "team-a",
        APPLB_TOKEN: "applb_1_x",
        APP_OBS_URL: "https://obs.example.com",
        APP_OBS_API_TOKEN: "applb_obs",
      }),
    );
    const out = await tool(tools, "deployment_logs").handler({ id: "web", limit: 5 });

    const urls = stub.calls.map((c) => c.url);
    assert.ok(
      urls.some((u) =>
        u.startsWith(
          `${LB}/namespaces/team-a/plugins/obs/api/deployments/web/logs?`,
        ),
      ),
      `not read through the plugin: ${urls.join(", ")}`,
    );
    assert.ok(!urls.some((u) => u.startsWith("https://obs.example.com")), "app-obs's own door was used");
    assert.match(out, /giving up on VM/);
  } finally {
    stub.restore();
  }
});

test("deployment_logs refuses a deployment app-lb will not show this credential", async () => {
  const stub = stubFetch((c) => {
    if (c.url.endsWith("/namespaces")) {
      return { body: { namespaces: [{ name: "team-a", scope: "admin" }] } };
    }
    // Another namespace's deployment: the plugin answers 404, exactly as it
    // does for a name that does not exist at all.
    if (c.url.includes("/plugins/obs/")) return { status: 404, body: { error: "not found" } };
    return { body: { rows: [{ ts: 1, message: "someone else's logs" }] } };
  });
  try {
    const tools = buildTools(
      loadConfig({
        APPLB_URL: LB,
        APPLB_NAMESPACE: "team-a",
        APPLB_TOKEN: "applb_1_x",
        APP_OBS_URL: "https://obs.example.com",
        APP_OBS_API_TOKEN: "applb_obs",
      }),
    );
    const out = await tool(tools, "deployment_logs").handler({ id: "other-ns-app" });

    assert.match(out, /is visible to this credential, so its logs are not either/);
    assert.doesNotMatch(out, /someone else's logs/);
    assert.ok(
      !stub.calls.some((c) => c.url.startsWith("https://obs.example.com")),
      "obs must not be asked directly for a confined caller",
    );
  } finally {
    stub.restore();
  }
});

test("an applb_ namespace token over HTTP reads through the plugin with its own token", async () => {
  // The hosted shape: this process holds an operator-wide app-obs token, and
  // the caller presents a namespace token. `/whoami` says confined, so the
  // read goes to app-lb's plugin surface carrying the caller's bearer — the
  // service token is never spent on their behalf.
  const stub = stubFetch((c) => {
    if (c.url.endsWith("/whoami")) return { body: { caller: "app-token", confined: true, namespace: "team-b" } };
    return { body: { deployments: [{ id: "api", requests: 10 }] } };
  });
  const seen: (string | undefined)[] = [];
  const original = globalThis.fetch;
  const recording = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    seen.push((init?.headers as Record<string, string> | undefined)?.authorization);
    return recording(input, init);
  }) as typeof fetch;
  try {
    const config = withForwardedAuth(
      loadConfig({
        APPLB_URL: "http://127.0.0.1:9090",
        APPLB_BASIC: "admin:pw",
        APP_OBS_URL: "http://127.0.0.1:9600",
        APP_OBS_API_TOKEN: "obs-service-token",
        HEYO_MCP_HTTP_PORT: "9650",
      }),
      { authorization: "Bearer applb_abc_secret" },
    );
    const out = await tool(buildTools(config), "namespace_telemetry").handler({});
    const urls = stub.calls.map((c) => c.url);
    assert.ok(urls.includes("http://127.0.0.1:9090/namespaces/team-b/plugins/obs/api/fleet?window=1h"), urls.join(", "));
    assert.ok(!urls.some((u) => u.startsWith("http://127.0.0.1:9600")), "app-obs's own door was used");
    assert.ok(seen.every((a) => a === "Bearer applb_abc_secret"), `credentials sent: ${seen.join(", ")}`);
    assert.match(out, /Namespace team-b/);
  } finally {
    globalThis.fetch = original;
    stub.restore();
  }
});

test("an unconfined operator still reads app-obs directly, after app-lb's reach check", async () => {
  const stub = stubFetch((c) => {
    if (c.url.endsWith("/whoami")) return { body: { caller: "operator", confined: false, fleet: true } };
    if (c.url.includes("/deployments/web") && c.url.startsWith("http://127.0.0.1:9090")) {
      return { body: { spec: { id: "web" } } };
    }
    return { body: { rows: [{ ts: 1, message: "operator view" }] } };
  });
  try {
    const tools = buildTools(
      loadConfig({
        APPLB_URL: "http://127.0.0.1:9090",
        APPLB_BASIC: "admin:pw",
        APP_OBS_URL: "http://127.0.0.1:9600",
        APP_OBS_API_TOKEN: "t",
      }),
    );
    const out = await tool(tools, "deployment_logs").handler({ id: "web" });
    const urls = stub.calls.map((c) => c.url);
    const reachAt = urls.indexOf("http://127.0.0.1:9090/deployments/web");
    const obsAt = urls.findIndex((u) => u.startsWith("http://127.0.0.1:9600/api/deployments/web/logs"));
    assert.ok(reachAt >= 0 && obsAt > reachAt, `obs must be asked after app-lb: ${urls.join(", ")}`);
    assert.match(out, /operator view/);
  } finally {
    stub.restore();
  }
});

test("a deployment-scoped token never reaches app-obs on the server's own token", async () => {
  const stub = stubFetch((c) => {
    if (c.url.endsWith("/whoami")) return { body: { caller: "app-token", confined: false, fleet: false } };
    return { body: { rows: [{ ts: 1, message: "every tenant's logs" }] } };
  });
  try {
    const tools = buildTools(
      loadConfig({
        APPLB_URL: "http://127.0.0.1:9090",
        APPLB_TOKEN: "applb_dep_secret",
        APP_OBS_URL: "http://127.0.0.1:9600",
        APP_OBS_API_TOKEN: "t",
      }),
    );
    const out = await tool(tools, "namespace_telemetry").handler({}).catch((e: Error) => e.message);
    assert.ok(
      !stub.calls.some((c) => c.url.startsWith("http://127.0.0.1:9600")),
      "app-obs's own door was used",
    );
    assert.doesNotMatch(String(out), /every tenant's logs/);
  } finally {
    stub.restore();
  }
});

test("a namespace without the obs plugin is told how to install it", async () => {
  const stub = stubFetch((c) => {
    if (c.url.endsWith("/namespaces")) return { body: { namespaces: [{ name: "team-a", scope: "admin" }] } };
    if (c.url.includes("/plugins/obs/")) {
      return {
        status: 409,
        body: {
          error: 'the obs plugin is not installed in namespace "team-a"',
          code: "plugin_not_installed",
        },
      };
    }
    return { body: [] };
  });
  try {
    await assert.rejects(
      tool(teamA(), "deployment_logs").handler({ id: "web" }),
      /heyctl plugins install obs -n team-a/,
    );
    const out = await tool(teamA(), "namespace_telemetry").handler({});
    assert.match(out, /heyctl plugins install obs -n team-a/);
  } finally {
    stub.restore();
  }
});

test("fleet_overview turns a confined caller away before app-obs is asked", async () => {
  const stub = stubFetch((c) =>
    c.url.endsWith("/namespaces")
      ? { body: { namespaces: [{ name: "team-a", scope: "admin" }] } }
      : { body: { deployments: ["everyone's"] } },
  );
  try {
    const tools = buildTools(
      loadConfig({
        APPLB_URL: LB,
        APPLB_NAMESPACE: "team-a",
        APPLB_TOKEN: "applb_1_x",
        APP_OBS_URL: "https://obs.example.com",
        APP_OBS_API_TOKEN: "t",
      }),
    );
    const out = await tool(tools, "fleet_overview").handler({});
    assert.match(out, /namespace_telemetry/);
    assert.ok(!stub.calls.some((c) => c.url.startsWith("https://obs.example.com")));
  } finally {
    stub.restore();
  }
});

test("applb_security_events passes the /security query filters through unchanged", async () => {
  // The five filters `/security` accepts are the tool's whole input, and the
  // tool's job is to forward them verbatim — it must not invent a default for
  // `namespace` (managed mode narrows server-side) nor drop an omitted one
  // into the query string. What the caller sends is what app-lb gets.
  const stub = stubFetch((c) =>
    c.url.endsWith("/namespaces")
      ? { body: { namespaces: [{ name: "team-a", scope: "admin" }] } }
      : { body: { enabled: true, alerts: [], totals: {}, rules: [], guard: {} } },
  );
  try {
    const out = await tool(teamA(), "applb_security_events").handler({
      severity: "high",
      rule: "auth.brute-force",
      deployment: "web",
      namespace: "team-a",
      limit: 20,
    });
    assert.match(out, /"enabled": true/);
    assert.equal(stub.calls.length, 1, "only /security");
    const security = stub.calls[0]!.url;
    assert.ok(security.startsWith(`${LB}/security?`), `hit /security: ${security}`);
    assert.ok(security.includes("severity=high"));
    assert.ok(security.includes("rule=auth.brute-force"));
    // 'auth.brute-force' has a '+', not a literal '-' in URLSearchParams.
    assert.ok(security.includes("deployment=web"));
    assert.ok(security.includes("namespace=team-a"));
    assert.ok(security.includes("limit=20"));
  } finally {
    stub.restore();
  }
});

test("applb_security_events sends nothing when no filter is given", async () => {
  // An empty call must not synthesize a `namespace=` query param: app-lb
  // narrows a confined credential's answer itself, and an operator's returns
  // everything. Adding a default here would silently widen or narrow what the
  // caller asked for.
  const stub = stubFetch(() => ({ body: { enabled: false, alerts: [], rules: [] } }));
  try {
    const tools = buildTools(loadConfig({ APPLB_URL: "http://127.0.0.1:8090" }));
    await tool(tools, "applb_security_events").handler({});
    const security = stub.calls.find((c) => c.url.includes("/security"))!.url;
    assert.ok(!security.includes("namespace="), `no namespace synthesized: ${security}`);
    assert.ok(!security.includes("severity="), `no severity synthesized: ${security}`);
  } finally {
    stub.restore();
  }
});
