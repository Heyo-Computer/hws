// The 0.2.0 surface — parity with the hws crate. Each test pins the method,
// path and body the crate sends for the same call, so the two clients cannot
// drift on the wire.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ConflictError, Hws, Heyctl, ObsClient, logQueryString } from "../dist/index.js";

function stub(...replies) {
  const seen = [];
  const fetch = async (url, init) => {
    seen.push({
      url: url.replace("http://x:1", ""),
      method: init.method,
      body: init.body ? JSON.parse(init.body) : undefined,
    });
    const r = replies.shift() ?? { status: 200, body: {} };
    const status = r.status ?? 200;
    // A 204 must have no body at all, not an empty one.
    const body = status === 204 ? null : typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {});
    return new Response(body, { status });
  };
  return { fetch, seen };
}

const lb = (s) => new Hws({ server: "http://x:1", fetch: s.fetch });

/** Run `call` against a fresh stub and return the one request it made. */
async function one(call, reply) {
  const s = stub(reply);
  await call(lb(s));
  assert.equal(s.seen.length, 1);
  return s.seen[0];
}

test("Hws is the client under the package's name, and Heyctl still works", () => {
  assert.equal(Hws, Heyctl);
});

test("whoami", async () => {
  assert.deepEqual(await one((c) => c.whoami()), { url: "/whoami", method: "GET", body: undefined });
});

test("rollouts send the crate's body and read the operation", async () => {
  const r = await one((c) =>
    c.startRollout("api/v1", { operationId: "op-1", expectedRevision: "rev-9", spec: { id: "api/v1" } }),
  );
  assert.deepEqual(r, {
    url: "/deployments/api%2Fv1/rollouts",
    method: "POST",
    body: { operation_id: "op-1", expected_revision: "rev-9", spec: { id: "api/v1" } },
  });
  const g = await one((c) => c.rollout("api", "op 1"));
  assert.equal(g.url, "/deployments/api/rollouts/op%201");
  assert.equal(g.method, "GET");
});

test("discovery status, live and staged", async () => {
  assert.equal((await one((c) => c.discoveryStatus("api"))).url, "/deployments/api/discovery-status");
  assert.equal(
    (await one((c) => c.discoveryStatus("api", { staged: true }))).url,
    "/deployments/api/discovery-status?staged=true",
  );
});

test("cordon and uncordon an upstream", async () => {
  const c1 = await one((c) => c.cordonUpstream("web", "10.0.0.1:80", { reason: "patching" }));
  assert.deepEqual(c1, {
    url: "/deployments/web/upstreams/10.0.0.1%3A80/drain",
    method: "PUT",
    body: { force: false, reason: "patching" },
  });
  const c2 = await one((c) => c.uncordonUpstream("web", "10.0.0.1:80"));
  assert.equal(c2.method, "DELETE");
  assert.equal(c2.url, "/deployments/web/upstreams/10.0.0.1%3A80/drain");
});

test("namespace plugins: list, install, uninstall, fleet installs", async () => {
  assert.deepEqual(await one((c) => c.namespacePlugins("team-a"), { body: [] }), {
    url: "/namespaces/team-a/plugins", method: "GET", body: undefined,
  });
  assert.deepEqual(await one((c) => c.installPlugin("team-a", "obs")), {
    url: "/namespaces/team-a/plugins/obs", method: "PUT", body: {},
  });
  assert.deepEqual((await one((c) => c.installPlugin("team-a", "obs", { retain: 7 }))).body, {
    config: { retain: 7 },
  });
  const u = await one((c) => c.uninstallPlugin("team-a", "obs"));
  assert.equal(u.method, "DELETE");
  assert.equal(u.url, "/namespaces/team-a/plugins/obs");
  assert.equal((await one((c) => c.pluginInstalls("obs"))).url, "/api/plugins/obs/installs");
});

test("a plugin 409 carries app-lb's code", async () => {
  const s = stub({
    status: 409,
    body: { error: 'the obs plugin is not installed in namespace "team-a"', code: "plugin_not_installed" },
  });
  await assert.rejects(
    () => lb(s).obs("team-a").fleet(),
    (e) => e instanceof ConflictError && e.code === "plugin_not_installed",
  );
  const s2 = stub({ status: 409, body: { error: "a build is already running" } });
  await assert.rejects(() => lb(s2).startBuild("d"), (e) => e instanceof ConflictError && e.code === undefined);
});

test("obs reads go through the namespace's plugin route", async () => {
  const s = stub(
    { body: { deployments: [] } },
    { body: {} },
    { body: { rows: [], next_before_ms: null } },
    { body: [] },
    { body: {} },
    { status: 204, body: "" },
  );
  const obs = lb(s).obs("team a");
  assert.ok(obs instanceof ObsClient);
  assert.equal(obs.namespace, "team a");
  await obs.fleet({ window: "1h" });
  await obs.deployment("web", { window: "15m" });
  await obs.logs("web", { level: "error", search: "boom x", before: 1760000000000, limit: 50 });
  await obs.alerts();
  await obs.createAlert({ deployment: "web", threshold: 5, webhook_url: "https://hooks.example/x" });
  await obs.deleteAlert("a1");
  const base = "/namespaces/team%20a/plugins/obs/api";
  assert.deepEqual(
    s.seen.map((r) => `${r.method} ${r.url}`),
    [
      `GET ${base}/fleet?window=1h`,
      `GET ${base}/deployments/web?window=15m`,
      `GET ${base}/deployments/web/logs?level=error&q=boom%20x&before=1760000000000&limit=50`,
      `GET ${base}/alerts`,
      `POST ${base}/alerts`,
      `DELETE ${base}/alerts/a1`,
    ],
  );
  assert.deepEqual(s.seen[4].body, { deployment: "web", threshold: 5, webhook_url: "https://hooks.example/x" });
});

test("the log query is written in the crate's order and skips what is unset", () => {
  assert.equal(logQueryString(), "");
  assert.equal(logQueryString({ level: "" }), "");
  assert.equal(
    logQueryString({ limit: 10, before: 5, to: 4, from: 3, search: "s", backend: "b", level: "l", window: "1h" }),
    "?window=1h&level=l&backend=b&q=s&from=3&to=4&before=5&limit=10",
  );
});

test("workflows", async () => {
  const s = stub({ body: { workflows: [{ id: "w" }] } });
  assert.deepEqual(await lb(s).workflows(), [{ id: "w" }]);
  assert.equal(s.seen[0].url, "/workflows");
  assert.equal((await one((c) => c.workflow("w"))).url, "/workflows/w");
  assert.deepEqual(await one((c) => c.createWorkflow({ id: "w", repo: "r", future: 1 })), {
    url: "/workflows", method: "POST", body: { id: "w", repo: "r", future: 1 },
  });
  assert.equal((await one((c) => c.replaceWorkflow("w", { id: "w" }))).method, "PUT");
  const d = await one((c) => c.deleteWorkflow("w"), { status: 204, body: "" });
  assert.deepEqual([d.method, d.url], ["DELETE", "/workflows/w"]);
});

test("auth providers", async () => {
  assert.equal((await one((c) => c.authProviders(), { body: [] })).url, "/auth-providers");
  assert.equal((await one((c) => c.authProviders("team-a"), { body: [] })).url, "/auth-providers?namespace=team-a");
  assert.equal((await one((c) => c.authProvider("team-a", "corp"))).url, "/auth-providers/team-a/corp");
  assert.deepEqual(await one((c) => c.createAuthProvider({ name: "corp", namespace: "team-a", preset: "heyo" })), {
    url: "/auth-providers", method: "POST", body: { name: "corp", namespace: "team-a", preset: "heyo" },
  });
  const d = await one((c) => c.deleteAuthProvider("team-a", "corp"), { status: 204, body: "" });
  assert.deepEqual([d.method, d.url], ["DELETE", "/auth-providers/team-a/corp"]);
  const s = stub({ status: 404, body: { error: 'no auth provider "corp"' } });
  assert.equal(await lb(s).authProviderExists("team-a", "corp"), false);
});

test("namespaces", async () => {
  assert.equal((await one((c) => c.namespaces(), { body: [] })).url, "/namespaces");
  assert.deepEqual(await one((c) => c.createNamespace({ name: "team-a", description: "A" })), {
    url: "/namespaces", method: "POST", body: { name: "team-a", description: "A" },
  });
  const d = await one((c) => c.deleteNamespace("team-a"), { status: 204, body: "" });
  assert.deepEqual([d.method, d.url], ["DELETE", "/namespaces/team-a"]);
});

test("mount pull, disks, feed RSS and probe", async () => {
  assert.deepEqual(await one((c) => c.startMountPull("web", true)), {
    url: "/deployments/web/mounts/pull", method: "POST", body: { force: true },
  });
  assert.equal((await one((c) => c.disks())).url, "/disks");

  const s = stub({ status: 200, body: "<rss/>" });
  assert.equal(await lb(s).feedRss("team-a"), "<rss/>");
  assert.equal(s.seen[0].url, "/feeds/team-a");

  const p = stub({ status: 403, body: { error: "authentication required", detail: "mint an admin token" } });
  assert.deepEqual(await lb(p).probe("/deployments"), {
    status: 403,
    detail: "authentication required — mint an admin token",
  });
  const p2 = stub({ status: 200, body: "ok" });
  assert.deepEqual(await lb(p2).probe("/healthz"), { status: 200, detail: undefined });
});

test("a job is waited on through its deployment when told which", async () => {
  const rec = (status) => [
    { id: "job-other", deployment: "web", kind: "artifact-pull", status: "succeeded", started_at: 1, log: [] },
    { id: "job-1", deployment: "web", kind: "artifact-pull", status, started_at: 1, log: ["pulling"] },
  ];
  const s = stub({ body: rec("running") }, { body: rec("succeeded") });
  const done = await lb(s).waitForJob("job-1", { deployment: "web", pollMs: 1 });
  assert.equal(done.status, "succeeded");
  assert.deepEqual(
    s.seen.map((r) => `${r.method} ${r.url}`),
    ["GET /deployments/web/jobs", "GET /deployments/web/jobs"],
  );
  await assert.rejects(lb(stub({ body: [] })).waitForJob("job-9", { deployment: "web" }), /no job/);
});
