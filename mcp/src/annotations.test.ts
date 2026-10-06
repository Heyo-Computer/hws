/**
 * The hints a host's approval UI reads, and whether they are true.
 *
 * Two representations of the same fact, for two audiences. The model reads the
 * `DESTRUCTIVE.` sentence at the front of a description — the SDK is explicit
 * that "clients should never make tool use decisions based on ToolAnnotations",
 * so the prose has to carry it. A host's approval dialog reads the annotations.
 *
 * `destructiveHint` is *derived* from the prose rather than declared beside it,
 * so the two cannot disagree; the test for it is therefore short. `readOnlyHint`
 * cannot be derived from anything, and it is the one hint where being wrong is a
 * safety problem rather than a cosmetic one — a host may auto-approve what it
 * believes is a read. So the list is checked the only way that means anything:
 * by running each tool on it and watching what it sends.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { loadConfig } from "./config.js";
import { buildTools, toolListing } from "./server.js";
import { DESTRUCTIVE_PREFIX } from "./tools/schema.js";

const CONFIG = {
  HEYO_API_KEY: "heyo_api_x",
  APPLB_NAMESPACE: "team-a",
  APP_OBS_URL: "http://127.0.0.1:9600",
  APP_OBS_API_TOKEN: "t",
  CI_URL: "http://127.0.0.1:9555",
  CI_TOKEN: "t",
  ART_URL: "http://127.0.0.1:8080",
  ART_API_KEY: "k",
  REMOTE_URL: "http://127.0.0.1:9700",
};

const listing = () => toolListing(buildTools(loadConfig(CONFIG)));

/** Read-only tools that answer from compiled-in text and send nothing. */
const OFFLINE = new Set(["applb_spec_schema", "heyo_guide"]);

/**
 * Read-only tools that refuse CONFIG's credential before sending anything.
 * `fleet_overview` is the whole fleet and CONFIG is the managed door, which is
 * confined to `team-a` by construction — so it is turned away locally. It is
 * driven under an unconfined credential below instead, so it is still checked.
 */
const REFUSED_HERE = new Set(["fleet_overview"]);

/** An unconfined, self-hosted operator: app-lb's own listener and app-obs. */
const OPERATOR = {
  APPLB_URL: "http://127.0.0.1:9090",
  APPLB_BASIC: "admin:pw",
  APP_OBS_URL: "http://127.0.0.1:9600",
  APP_OBS_API_TOKEN: "t",
};

/**
 * Arguments plausible enough for each read-only tool to reach the network.
 *
 * A tool that fails on missing arguments never issues a request, and would pass
 * the mutation check by doing nothing — which is exactly the false negative this
 * test exists to avoid. Anything not listed here takes none.
 */
const ARGS: Record<string, Record<string, unknown>> = {
  applb_get_deployment: { id: "web" },
  applb_deployment_jobs: { id: "web" },
  applb_job: { job_id: "job-1" },
  diagnose_deployment: { id: "web" },
  diagnose_empty_pool: { id: "web" },
  diagnose_ci_job: { run_id: "r1" },
  deployment_logs: { id: "web" },
  namespace_telemetry: { deployment: "web" },
  ci_run_status: { run_id: "r1" },
  ci_run_logs: { run_id: "r1" },
  art_get_tag: { tag: "t" },
  art_get_manifest: { reference: "sha256:abc" },
  repo_get: { repo: "site" },
  applb_spec_schema: { block: "VmSpec" },
  applb_security_events: { severity: "high", limit: 20 },
};

test("every tool is annotated, and destructiveness matches its own prose", () => {
  for (const t of listing()) {
    const a = t.annotations as Record<string, boolean | undefined>;
    assert.ok(a, `${t.name} carries no annotations`);

    if (t.description.startsWith(DESTRUCTIVE_PREFIX)) {
      assert.equal(a.destructiveHint, true, `${t.name} says DESTRUCTIVE and is not flagged`);
    } else if (a.readOnlyHint) {
      // `destructiveHint` is documented as meaningful only when readOnlyHint is
      // false, so stating it here would be noise.
      assert.equal(a.destructiveHint, undefined, `${t.name} is read-only; the hint is meaningless`);
    } else {
      // The one that must never be left to the default, which is `true`.
      assert.equal(
        a.destructiveHint,
        false,
        `${t.name} is not destructive, and silence would say it is`,
      );
    }

    // Omitted throughout: `true` is the default and every tool here is
    // open-world. Emitting it would be 64 copies of the default.
    assert.equal(a.openWorldHint, undefined, `${t.name} restates the openWorldHint default`);
  }
});

test("a tool marked read-only never sends anything but a GET", async () => {
  // The check that makes the list worth having. Each read-only tool is driven
  // against a stubbed transport and every request it makes is inspected: one
  // POST, PUT, PATCH or DELETE and the annotation is a lie a host may act on.
  const readOnly = listing().filter(
    (t) => (t.annotations as { readOnlyHint?: boolean }).readOnlyHint,
  );
  assert.ok(readOnly.length > 15, `only ${readOnly.length} tools are marked read-only`);

  const tools = buildTools(loadConfig(CONFIG));
  const original = globalThis.fetch;
  const offenders: string[] = [];
  const silent: string[] = [];

  try {
    for (const listed of readOnly) {
      const methods: string[] = [];
      globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        methods.push(`${init?.method ?? "GET"} ${String(input)}`);
        // Shapes broad enough that a handler reading `.deployments`, `.events`
        // or a bare array gets something rather than throwing before its
        // second request.
        return new Response(
          JSON.stringify({ id: "x", status: "succeeded", deployments: [], events: [], steps: [] }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }) as typeof fetch;

      const tool = tools.find((t) => t.name === listed.name)!;
      try {
        await tool.handler(ARGS[listed.name] ?? {});
      } catch {
        // A handler that throws on this synthetic body is fine; what it *sent*
        // before throwing is still recorded and still counts.
      }
      const mutating = methods.filter((m) => !m.startsWith("GET "));
      if (mutating.length > 0) offenders.push(`${listed.name}: ${mutating.join(", ")}`);
      if (methods.length === 0 && !OFFLINE.has(listed.name) && !REFUSED_HERE.has(listed.name)) {
        silent.push(listed.name);
      }
    }
  } finally {
    globalThis.fetch = original;
  }

  assert.deepEqual(offenders, [], "these are marked read-only and mutate");
  // A tool that sent nothing proved nothing; only these are legitimately
  // offline: they answer from compiled-in text (the schema, the guides).
  assert.deepEqual(silent, [], "these sent no request, so the check did not exercise them");
});

test("the destructive set is the one app-lb's own routes imply", () => {
  const destructive = listing()
    .filter((t) => (t.annotations as { destructiveHint?: boolean }).destructiveHint)
    .map((t) => t.name)
    .sort();

  // Named rather than counted, so adding a destructive tool is a deliberate
  // edit here instead of a number that gets bumped without being read.
  assert.deepEqual(destructive, [
    "applb_delete_deployment",
    "applb_drain_upstream",
    "applb_evict_vm",
    "applb_exec",
    "applb_purge_disk",
    "applb_purge_orphan_disks",
    "applb_sweep_disks",
    // A tag's removal strands every deployment that pulls it.
    "art_delete_tag",
    "ci_cancel_run",
    "ci_cleanup_failed_vms",
    "ci_destroy_vm",
    "sandbox_kill",
  ]);
});

test("the three disk tools agree about what they do", () => {
  // `applb_sweep_disks` deletes disks by the same mechanism as the other two and
  // was the only one that did not say so. app-lb's own route table groups all
  // three under "Disk mutations" and calls them the most destructive it exposes.
  const disks = listing().filter((t) => t.name.includes("disk") && t.name !== "applb_disks");
  assert.equal(disks.length, 3);
  for (const t of disks) {
    assert.equal(
      (t.annotations as { destructiveHint?: boolean }).destructiveHint,
      true,
      `${t.name} deletes disks and must say so`,
    );
  }
  // And the read-only one is not caught up in it.
  const read = listing().find((t) => t.name === "applb_disks");
  assert.equal((read?.annotations as { readOnlyHint?: boolean }).readOnlyHint, true);
});

test("the read-only tools a confined credential is refused still only GET for an operator", async () => {
  const tools = buildTools(loadConfig(OPERATOR));
  const original = globalThis.fetch;
  try {
    for (const name of REFUSED_HERE) {
      const methods: string[] = [];
      globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        methods.push(`${init?.method ?? "GET"} ${String(input)}`);
        // `/whoami` says unconfined, so the tool goes on to app-obs.
        return new Response(JSON.stringify({ caller: "operator", confined: false, fleet: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }) as typeof fetch;
      await tools.find((t) => t.name === name)!.handler({});
      assert.ok(methods.length > 1, `${name} sent ${methods.length} request(s) for an operator`);
      assert.deepEqual(methods.filter((m) => !m.startsWith("GET ")), [], `${name} mutates`);
    }
  } finally {
    globalThis.fetch = original;
  }
});
