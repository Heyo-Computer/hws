/**
 * Which call rolls a deployment onto new bytes, and which one refuses.
 *
 * app-lb has four job kinds and each applies to a subset of backends
 * (`JobKind::applies_to`, `app-lb/src/jobs.rs`). `HostUpdate` runs a static
 * deployment's own commands on the app-lb host and is refused for a managed
 * (`vm`) deployment; `ArtifactPull` is what rolls a `vm` or `site` onto bytes
 * from a store. This server had a tool for the first, named `applb_start_update`
 * and described as "this rolls its VMs", and no tool at all for the second.
 *
 * `art_publish` — the one composite on the server, written because "a composite
 * beats a documented sequence when a step is easy to get wrong" — then handed
 * back that tool as the next step. For the main case, publishing an image for a
 * managed deployment, following its own instruction produced a refusal.
 *
 * These tests pin the routes, so the mapping from tool to job kind cannot drift
 * back.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { loadConfig } from "./config.js";
import { buildTools, toolListing } from "./server.js";
import type { Tool } from "./tools/diagnose.js";

interface Call {
  url: string;
  method: string;
  body?: unknown;
  hadBody: boolean;
}

function stubFetch(body: unknown = {}) {
  const calls: Call[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
      hadBody: init?.body !== undefined,
    });
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { calls, restore: () => void (globalThis.fetch = original) };
}

const all = () =>
  buildTools(loadConfig({ APPLB_URL: "http://127.0.0.1:9090", APPLB_TOKEN: "applb_x" }));

function tool(name: string): Tool {
  const found = all().find((t) => t.name === name);
  assert.ok(found, `no such tool: ${name}`);
  return found;
}

test("each job tool posts to the route its job kind actually applies to", async () => {
  const stub = stubFetch({ id: "job-1" });
  try {
    await tool("applb_build").handler({ id: "web" });
    await tool("applb_pull").handler({ id: "web" });
    await tool("applb_pull_mounts").handler({ id: "web" });
    await tool("applb_host_update").handler({ id: "web" });
    assert.deepEqual(
      stub.calls.map((c) => `${c.method} ${c.url.replace(/^.*9090/, "")}`),
      [
        "POST /deployments/web/build",
        "POST /deployments/web/pull",
        "POST /deployments/web/mounts/pull",
        "POST /deployments/web/update",
      ],
    );
  } finally {
    stub.restore();
  }
});

test("applb_host_update sends no body, because the route takes none", async () => {
  const stub = stubFetch({ id: "job-1" });
  try {
    await tool("applb_host_update").handler({ id: "web" });
    assert.equal(
      stub.calls[0]?.hadBody,
      false,
      "app-lb's start_update has no Json extractor; sending a body was always meaningless",
    );
  } finally {
    stub.restore();
  }
});

test("a one-off ref is sent as `ref`, and omitted entirely when not given", async () => {
  const stub = stubFetch({ id: "job-1" });
  try {
    // `ref` overrides the version for this job only and must not become the
    // deployment's default — which is what makes it a rollback rather than an
    // edit. Sending `{}` when it was not asked for keeps that true.
    await tool("applb_build").handler({ id: "web", git_ref: "hotfix" });
    await tool("applb_pull").handler({ id: "web", artifact_ref: "sha256:abc" });
    await tool("applb_pull").handler({ id: "web" });
    assert.deepEqual(stub.calls[0]?.body, { ref: "hotfix" });
    assert.deepEqual(stub.calls[1]?.body, { ref: "sha256:abc" });
    assert.deepEqual(stub.calls[2]?.body, {});
  } finally {
    stub.restore();
  }
});

test("editing a deployment uses PUT, which preserves the pool", async () => {
  const stub = stubFetch({ id: "web" });
  try {
    // The only exposed way to change a spec was POST /deployments, which
    // re-registers and recycles the VM pool. PUT keeps it whenever the `vm`
    // template is unchanged, so a scaling or route edit stopped costing a
    // full roll.
    const spec = { id: "web", routes: [{ host: "web.example.com" }], upstreams: ["127.0.0.1:3000"] };
    await tool("applb_update_deployment").handler({ id: "web", spec });
    const writes = stub.calls.filter((c) => c.method !== "GET");
    assert.equal(writes.length, 1);
    assert.equal(writes[0]?.method, "PUT");
    assert.match(writes[0]?.url ?? "", /\/deployments\/web$/);
    assert.deepEqual(writes[0]?.body, spec);
  } finally {
    stub.restore();
  }
});

test("applb_exec puts the command in the arguments, not inside a blob", async () => {
  const stub = stubFetch({ output: "" });
  try {
    // The point is not the wire format — it is that a host rendering an
    // approval prompt from the schema can show what is about to run on a
    // production VM. It used to show a parameter named `body` of type object.
    const listed = toolListing(all()).find((t) => t.name === "applb_exec");
    const props = Object.keys(
      (listed?.inputSchema as { properties?: object })?.properties ?? {},
    );
    assert.ok(props.includes("command"), `applb_exec still hides the command: ${props.join(", ")}`);
    assert.ok(!props.includes("body"), "the untyped blob is still there");

    await tool("applb_exec").handler({ id: "web", command: "cat /var/log/heyvm-start.log" });
    assert.deepEqual(stub.calls[0]?.body, { command: "cat /var/log/heyvm-start.log" });
  } finally {
    stub.restore();
  }
});

test("applb_exec passes through only what was given", async () => {
  const stub = stubFetch({ output: "" });
  try {
    // `wake` defaults to true server-side, so sending it unasked would be this
    // client deciding a default that is app-lb's to decide.
    await tool("applb_exec").handler({ id: "web", command: "ls", wake: false, cwd: "/tmp" });
    assert.deepEqual(stub.calls[0]?.body, { command: "ls", cwd: "/tmp", wake: false });
  } finally {
    stub.restore();
  }
});

test("applb_scale advertises the policy fields instead of an untyped body", () => {
  const listed = toolListing(all()).find((t) => t.name === "applb_scale");
  const scaling = (
    listed?.inputSchema as unknown as {
      properties: { scaling: { properties?: Record<string, unknown> } };
    }
  ).properties.scaling;
  const fields = Object.keys(scaling.properties ?? {});
  for (const f of ["min_replicas", "max_replicas", "warm_pool", "idle_action"]) {
    assert.ok(fields.includes(f), `applb_scale never mentions \`${f}\`: ${fields.join(", ")}`);
  }
  // A patch body: nothing is required, because omitting a field keeps it.
  assert.equal(
    (scaling as { required?: string[] }).required,
    undefined,
    "a partial policy must not require anything",
  );
});

test("art_publish's next step names a tool that will accept it", async () => {
  const tools = buildTools(
    loadConfig({ APPLB_URL: "http://127.0.0.1:9090" }),
  );
  const publish = tools.find((t) => t.name === "art_publish");
  assert.ok(publish);
  // The prose and the machine-readable `next` both used to name a tool that
  // refuses a managed deployment. Assert against the name, not the wording.
  assert.doesNotMatch(publish.description, /applb_start_update|applb_host_update to roll/);
  assert.match(publish.description, /applb_pull/);
});

test("the renamed tools are gone, deliberately", () => {
  const names = all().map((t) => t.name);
  for (const old of ["applb_start_build", "applb_start_update"]) {
    assert.ok(!names.includes(old), `${old} still exists — the rename was meant to be breaking`);
  }
  for (const now of ["applb_build", "applb_pull", "applb_host_update", "applb_job"]) {
    assert.ok(names.includes(now), `${now} is missing`);
  }
});
