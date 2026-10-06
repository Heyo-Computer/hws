/**
 * The deployment spec surface: that it is current, and that it is never
 * stricter than the server.
 *
 * `src/applb/spec.schema.ts` is generated twice over — app-lb derives a JSON
 * Schema from its own Rust types, and `scripts/prune-schema.mjs` cuts that down
 * to what `tools/list` can afford. Neither step is hand-written, which is the
 * whole design: the three hand-written mirrors of this spec all drifted, and two
 * are wrong today (the TypeScript SDK still offers a driver the server rejects
 * and omits a field it accepts).
 *
 * Generated does not mean current, though. A regenerated app-lb schema with no
 * corresponding `npm run schema` leaves this package describing last week's API,
 * so the first test here is the staleness check, and it runs whenever app-lb is
 * checked out beside this package.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { DEPLOYMENT_SPEC_FULL, DEPLOYMENT_SPEC_SCHEMA } from "./applb/spec.schema.js";
import { rulesFor, SPEC_RULES } from "./applb/rules.js";
import { buildTools, toolListing } from "./server.js";
import { loadConfig } from "./config.js";
import type { Tool } from "./tools/diagnose.js";

// dist/ at runtime, so the package root is two levels up.
const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const applbRoot = join(pkgRoot, "..", "app-lb");
const hasApplb = existsSync(join(applbRoot, "schema", "deployment-spec.json"));

function tool(name: string): Tool {
  const tools = buildTools(loadConfig({ HEYO_API_KEY: "heyo_api_x", APPLB_TOKEN: "heyo_api_lb" }));
  const found = tools.find((t) => t.name === name);
  assert.ok(found, `no such tool: ${name}`);
  return found;
}

/** Recursively collect `[path, value]` for every occurrence of a key. */
function findAll(node: unknown, key: string, at = "#", out: [string, unknown][] = []) {
  if (Array.isArray(node)) {
    node.forEach((x, i) => findAll(x, key, `${at}/${i}`, out));
  } else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (k === key) out.push([at, v]);
      findAll(v, key, `${at}/${k}`, out);
    }
  }
  return out;
}

test(
  "the advertised schema is regenerated from app-lb's current types",
  { skip: hasApplb ? false : "app-lb is not checked out beside this package" },
  () => {
    // Runs the real generator and compares. A diff here means somebody changed
    // a Rust type and did not run `npm run schema`, so every client reading
    // this package is describing a spec the server no longer has.
    const before = readFileSync(join(pkgRoot, "src", "applb", "spec.schema.ts"), "utf8");
    execFileSync("node", [join(pkgRoot, "scripts", "prune-schema.mjs")], { cwd: pkgRoot });
    const after = readFileSync(join(pkgRoot, "src", "applb", "spec.schema.ts"), "utf8");
    assert.equal(
      before,
      after,
      "src/applb/spec.schema.ts is stale — run `npm run schema` and commit the result. " +
        "app-lb's types have moved and this package is still describing the old ones.",
    );
  },
);

test("the advertised schema is never stricter than the server", () => {
  // `DeploymentSpec` carries no `deny_unknown_fields`, and heyctl deliberately
  // edits specs as untyped JSON so a field it has never heard of survives the
  // trip. If pruning ever closed an object, a client would refuse to send a
  // spec app-lb would accept — turning "we haven't documented that field yet"
  // into "your valid spec is rejected", which is much the worse failure.
  for (const [path, value] of findAll(DEPLOYMENT_SPEC_SCHEMA, "additionalProperties")) {
    assert.notEqual(value, false, `${path} forbids unknown keys`);
  }
});

test("pruning removes description and interior, never a constraint", () => {
  const full = DEPLOYMENT_SPEC_FULL as Record<string, unknown>;
  const pruned = DEPLOYMENT_SPEC_SCHEMA as Record<string, unknown>;

  // No top-level field may be dropped: this is the map of the whole spec, and a
  // caller who cannot see `artifact` will reach for `build` and be wrong.
  assert.deepEqual(
    Object.keys(pruned.properties as object).sort(),
    Object.keys(full.properties as object).sort(),
    "pruning dropped a top-level field",
  );
  assert.deepEqual(pruned.required, full.required, "pruning changed what is required");

  // Nor may it drop a `required` from any block it kept.
  const fullDefs = (full.$defs ?? {}) as Record<string, { required?: string[] }>;
  const prunedDefs = (pruned.$defs ?? {}) as Record<string, { required?: string[] }>;
  for (const [name, def] of Object.entries(prunedDefs)) {
    const wanted = fullDefs[name]?.required;
    if (!wanted) continue;
    assert.deepEqual(def.required ?? wanted, wanted, `${name} lost a required field`);
  }
});

test("every collapsed block says where to get the rest", () => {
  const defs = DEPLOYMENT_SPEC_SCHEMA.$defs as Record<string, Record<string, unknown>>;
  const fullDefs = DEPLOYMENT_SPEC_FULL.$defs as Record<string, Record<string, unknown>>;

  const collapsed = Object.entries(defs).filter(
    ([name, d]) => !d.properties && (fullDefs[name] as { properties?: unknown })?.properties,
  );
  assert.ok(collapsed.length > 0, "nothing was collapsed — did the pruner stop running?");

  for (const [name, d] of collapsed) {
    assert.match(
      String(d.description),
      /applb_spec_schema/,
      `${name} was collapsed without saying where its fields went`,
    );
  }
});

test("applb_spec_schema answers for every block the surface summarises", async () => {
  const spec = tool("applb_spec_schema");
  const defs = DEPLOYMENT_SPEC_SCHEMA.$defs as Record<string, Record<string, unknown>>;

  for (const name of Object.keys(defs)) {
    const out = await spec.handler({ block: name });
    assert.doesNotMatch(out, /no block named/, `applb_spec_schema cannot explain ${name}`);
    const parsed = JSON.parse(out) as { block: string; schema: unknown };
    assert.equal(parsed.block, name);
    assert.ok(parsed.schema, `${name} came back with no schema`);
  }
});

test("applb_spec_schema takes the name a caller would actually type", async () => {
  const spec = tool("applb_spec_schema");
  for (const asked of ["vmspec", "VmSpec", "vm"]) {
    const parsed = JSON.parse(await spec.handler({ block: asked })) as { block?: string };
    assert.equal(parsed.block, "VmSpec", `asking for ${asked} did not reach VmSpec`);
  }
  // An unknown block lists what exists rather than failing blankly.
  const miss = JSON.parse(await spec.handler({ block: "nonsense" })) as { blocks?: string[] };
  assert.ok(Array.isArray(miss.blocks) && miss.blocks.length > 0);
});

test("the cross-field rules reach the blocks they constrain", () => {
  // Every rule names at least one real block (or "*"), so a renamed type
  // cannot silently orphan the rule that explains it.
  const known = new Set(Object.keys(DEPLOYMENT_SPEC_FULL.$defs as object));
  for (const r of SPEC_RULES) {
    for (const b of r.blocks) {
      assert.ok(b === "*" || known.has(b), `rule names unknown block ${b}: ${r.rule.slice(0, 60)}`);
    }
  }
  // And the blocks most often got wrong actually carry one.
  for (const block of ["VmSpec", "BuildSpec", "HealthCheck", "AuthGate", "Driver"]) {
    assert.ok(rulesFor(block).length > 0, `${block} has no cross-field rule`);
  }
});

test(
  "every shipped example is fully described by the advertised schema",
  { skip: hasApplb ? false : "app-lb is not checked out beside this package" },
  () => {
    // Not validation — that would need a JSON Schema library this package does
    // not have. The weaker, cheaper property: a spec somebody actually wrote
    // uses no top-level field the advertised schema fails to mention. That is
    // the one that would send a caller back to reading our source.
    const dir = join(applbRoot, "examples");
    const files: string[] = [];
    const walk = (d: string) => {
      for (const entry of readdirSync(d)) {
        const p = join(d, entry);
        if (statSync(p).isDirectory()) walk(p);
        else if (entry.endsWith(".json")) files.push(p);
      }
    };
    walk(dir);
    assert.ok(files.length > 0, "no examples found");

    const described = new Set(Object.keys(DEPLOYMENT_SPEC_SCHEMA.properties as object));
    for (const file of files) {
      const spec = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
      for (const key of Object.keys(spec)) {
        assert.ok(described.has(key), `${file} uses \`${key}\`, which the schema never mentions`);
      }
    }
  },
);

test("the deploy tool advertises every spec field, and the blocks are one call away", async () => {
  // Top-level fields only: the nested tree was ~4,000 tokens on every request
  // for the minority of sessions that hand-write a spec. Every field must
  // still be named, and every block must still be reachable.
  const tools = buildTools(loadConfig({ HEYO_API_KEY: "heyo_api_x", APPLB_TOKEN: "heyo_api_lb" }));
  const listed = toolListing(tools).find((t) => t.name === "applb_deploy");
  assert.ok(listed);

  const spec = (listed.inputSchema as unknown as { properties: { spec: Record<string, unknown> } })
    .properties.spec;
  const props = spec.properties as Record<string, { description?: string }>;
  assert.deepEqual(
    Object.keys(props).sort(),
    Object.keys(DEPLOYMENT_SPEC_SCHEMA.properties as object).sort(),
    "the advertised spec must name every top-level field",
  );
  const source = DEPLOYMENT_SPEC_SCHEMA.properties as Record<string, { description?: string }>;
  for (const [key, v] of Object.entries(props)) {
    if (!source[key]?.description) continue; // app-lb gives none (user_id)
    assert.ok(v.description && v.description.length > 0, `\`${key}\` lost its description`);
  }
  assert.match(String(spec.description), /applb_spec_schema/);

  const schema = tools.find((t) => t.name === "applb_spec_schema")!;
  const vm = await schema.handler({ block: "VmSpec" });
  for (const key of ["size_class", "start_command", "driver", "port"]) {
    assert.ok(vm.includes(key), `applb_spec_schema VmSpec never mentions \`${key}\``);
  }
});

test("no tool embeds the nested spec tree", () => {
  // The budget rule, asserted rather than trusted to a comment: the full tree
  // lives behind applb_spec_schema, not in tools/list.
  const listing = toolListing(
    buildTools(loadConfig({ HEYO_API_KEY: "heyo_api_x", APPLB_TOKEN: "heyo_api_lb" })),
  );
  const carriers = listing.filter((t) => JSON.stringify(t.inputSchema).includes('"$defs"') &&
    JSON.stringify(t.inputSchema).includes("VmSpec"));
  assert.deepEqual(carriers.map((t) => t.name), [], "a tool embeds the deployment spec tree");
});
