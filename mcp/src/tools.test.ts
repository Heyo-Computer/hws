/**
 * The behaviour that is not obvious from a route table: what the server infers
 * when it was told two API keys and nothing else, what it refuses to send, and
 * what it makes of a feed cursor that has outlived the feed.
 *
 * `fetch` is stubbed rather than a live cloud reached, so these assert the
 * shapes this server produces — the request it builds and the text it hands
 * back — not that cloud agrees with them.
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

const twoKeys = () => buildTools(loadConfig({ HEYO_API_KEY: "heyo_api_x", APPLB_TOKEN: "heyo_api_lb" }));

test("the managed namespace is discovered from the key, once, and reused", async () => {
  const stub = stubFetch((c) =>
    c.url.endsWith("/namespaces")
      ? { body: { namespaces: [{ name: "team-a", scope: "admin" }] } }
      : { body: [{ id: "web" }] },
  );
  try {
    const tools = twoKeys();
    await tool(tools, "applb_list_deployments").handler({});
    await tool(tools, "applb_list_deployments").handler({});

    assert.deepEqual(
      stub.calls.map((c) => c.url),
      [
        "https://server.heyo.computer/namespaces",
        "https://server.heyo.computer/namespaces/team-a/lb/deployments",
        "https://server.heyo.computer/namespaces/team-a/lb/deployments",
      ],
    );
  } finally {
    stub.restore();
  }
});

test("several namespaces are named in the error rather than guessed between", async () => {
  const stub = stubFetch(() => ({ body: { namespaces: [{ name: "team-a" }, { name: "team-b" }] } }));
  try {
    await assert.rejects(
      () => tool(twoKeys(), "applb_list_deployments").handler({}),
      /team-a, team-b.*APPLB_NAMESPACE/s,
    );
  } finally {
    stub.restore();
  }
});

test("sandbox_write_file refuses what the 1 MB body limit would reject", async () => {
  const stub = stubFetch(() => ({ body: {} }));
  try {
    const write = tool(twoKeys(), "sandbox_write_file");
    // 512 KiB is the measured ceiling: it encodes to ~683 KB and lands.
    await write.handler({ id: "sb-1", file_path: "a.bin", content: "x".repeat(512 * 1024) });
    assert.equal(stub.calls.length, 1);

    // One byte more and the round trip is spent to be told 413, so it is not
    // spent — the refusal names the route that has no such limit.
    await assert.rejects(
      () => write.handler({ id: "sb-1", file_path: "a.bin", content: "x".repeat(512 * 1024 + 1) }),
      /sandbox_upload_url/,
    );
    assert.equal(stub.calls.length, 1, "nothing was sent");
  } finally {
    stub.restore();
  }
});

test("sandbox_create sends the SDK's own defaults", async () => {
  const stub = stubFetch((c) =>
    c.url.endsWith("/sandbox-deploy") ? { body: { id: "sb-9" } } : { body: { id: "sb-9", status: "running" } },
  );
  try {
    await tool(twoKeys(), "sandbox_create").handler({ ttl_seconds: 900 });
    assert.deepEqual(stub.calls[0]?.body, {
      region: "US",
      image: "ubuntu:24.04",
      size_class: "small",
      open_ports: [],
      ttl_seconds: 900,
    });
    // Then it polls the sandbox rather than returning something still provisioning.
    assert.equal(stub.calls[1]?.url, "https://server.heyo.computer/deployed-sandboxes/sb-9");
  } finally {
    stub.restore();
  }
});

test("a 503 is retried as capacity; a rejected spec is not retried at all", async () => {
  let creates = 0;
  const stub = stubFetch((c) => {
    if (!c.url.endsWith("/sandbox-deploy")) return { body: { id: "sb-9", status: "running" } };
    creates += 1;
    return creates === 1
      ? { status: 503, body: { error: "No available backend in region US supports libvirt" } }
      : { body: { id: "sb-9" } };
  });
  try {
    const create = tool(twoKeys(), "sandbox_create");
    await create.handler({ retries: 1, wait_seconds: 0 });
    assert.equal(creates, 2, "capacity was waited out");

    creates = 0;
    stub.restore();
  } finally {
    stub.restore();
  }

  const rejected = stubFetch(() => ({ status: 422, body: { error: "unknown size_class" } }));
  try {
    await assert.rejects(
      () => tool(twoKeys(), "sandbox_create").handler({ retries: 3, size_class: "small" }),
      /422/,
    );
    assert.equal(rejected.calls.length, 1, "a bad spec is only rejected once");
  } finally {
    rejected.restore();
  }
});

test("a 503 from cloud arrives carrying what it means", async () => {
  const stub = stubFetch(() => ({ status: 503, body: { error: "No available backend in region US" } }));
  try {
    await assert.rejects(
      () => tool(twoKeys(), "sandbox_create").handler({ retries: 0 }),
      /region capacity, not a fault[\s\S]*heyo_capacity/,
    );
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
    const feed = tool(twoKeys(), "applb_feed");

    const fresh = await feed.handler({});
    assert.match(fresh, /latest_id 7/);
    // The namespace came from the discovery app-lb already did — the feed is
    // served at /feeds/:namespace, so it has to be named, not merely reached.
    assert.equal(
      stub.calls[1]?.url,
      "https://server.heyo.computer/namespaces/team-a/lb/feeds/team-a?format=json",
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

test("a fleet-operations instance lists no sandbox tools at all", () => {
  // Behind an app-token gate there is no cloud credential and no way to acquire
  // one, so the sandbox tools are not missing — they are not part of this
  // deployment. Listing them would advertise a set of operations whose only
  // possible outcome is an auth error.
  const withCloud = buildTools(
    loadConfig({ APPLB_URL: "http://127.0.0.1:8080", HEYO_API_KEY: "heyo_api_x" }),
  );
  const fleetOps = buildTools(loadConfig({ APPLB_URL: "http://127.0.0.1:8080" }));

  const names = (tools: Tool[]) => tools.map((t) => t.name);
  assert.ok(names(withCloud).includes("sandbox_create"));
  assert.ok(!names(fleetOps).includes("sandbox_create"));
  assert.ok(!names(fleetOps).includes("heyo_capacity"));
  assert.equal(names(fleetOps).filter((n) => n.startsWith("sandbox_")).length, 0);

  // Everything else survives, including the app-lb tools this instance exists
  // for and `heyo_status` — which is what keeps "why are there no sandbox
  // tools" an answerable question rather than a silent gap.
  assert.ok(names(fleetOps).includes("applb_list_deployments"));
  assert.ok(names(fleetOps).includes("heyo_status"));
  const dropped = names(withCloud).filter((n) => !names(fleetOps).includes(n));
  assert.equal(dropped.length, withCloud.length - fleetOps.length);
  assert.ok(dropped.length > 0, "the cloud-keyed set must be the larger one");

  // A caller's own cloud key restores them per request, which is what keeps this
  // gate on the credential rather than on a deployment-wide switch.
  const hosted = loadConfig({ APPLB_URL: "http://127.0.0.1:8080" });
  const asCaller = withForwardedAuth(hosted, { authorization: "Bearer heyo_api_caller" });
  assert.ok(names(buildTools(asCaller)).includes("sandbox_create"));
  // But an app-lb token does not conjure them: cloud cannot consume it.
  const asToken = withForwardedAuth(hosted, { authorization: "Bearer applb_abc123_secret" });
  assert.ok(!names(buildTools(asToken)).includes("sandbox_create"));
});

/**
 * app-obs's own token reads every namespace, so a namespace-confined caller
 * must never be served on it. Such a caller reads through app-lb's obs plugin
 * for its namespace, with its own credential — app-lb decides reach, and pins
 * the namespace before app-obs is asked.
 */
test("a managed-door caller reads logs through its namespace's obs plugin, never app-obs's token", async () => {
  const stub = stubFetch((c) => {
    if (c.url.endsWith("/namespaces")) {
      return { body: { namespaces: [{ name: "team-a", scope: "admin" }] } };
    }
    return { body: { rows: [{ ts: 1, level: "error", message: "giving up on VM" }] } };
  });
  try {
    const tools = buildTools(
      loadConfig({
        HEYO_API_KEY: "heyo_api_x",
        APPLB_TOKEN: "heyo_api_lb",
        APP_OBS_URL: "https://obs.example.com",
        APP_OBS_API_TOKEN: "applb_obs",
      }),
    );
    const out = await tool(tools, "deployment_logs").handler({ id: "web", limit: 5 });

    const urls = stub.calls.map((c) => c.url);
    assert.ok(
      urls.some((u) =>
        u.startsWith(
          "https://server.heyo.computer/namespaces/team-a/lb/namespaces/team-a/plugins/obs/api/deployments/web/logs?",
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
        HEYO_API_KEY: "heyo_api_x",
        APPLB_TOKEN: "heyo_api_lb",
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
      tool(twoKeys(), "deployment_logs").handler({ id: "web" }),
      /heyctl plugins install obs -n team-a/,
    );
    const out = await tool(twoKeys(), "namespace_telemetry").handler({});
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
        HEYO_API_KEY: "heyo_api_x",
        APPLB_TOKEN: "heyo_api_lb",
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
    const out = await tool(twoKeys(), "applb_security_events").handler({
      severity: "high",
      rule: "auth.brute-force",
      deployment: "web",
      namespace: "team-a",
      limit: 20,
    });
    assert.match(out, /"enabled": true/);
    assert.equal(stub.calls.length, 2, "namespace discovery then /security");
    const security = stub.calls[1]!.url;
    assert.ok(security.includes("/lb/security"), `hit /security: ${security}`);
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
  // An empty call must not synthesize a `namespace=` query param: through the
  // managed door the response is narrowed server-side, and a self-hosted app-lb
  // returns everything. Adding a default here would silently widen or narrow
  // what the caller asked for. A self-hosted config (APPLB_URL) skips namespace
  // discovery, so the only request is the one to /security.
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
