/**
 * What a client learns before its first call.
 *
 * `tools/list` is the entire tool surface as far as a model is concerned — every
 * name, every description, every schema — and until `toolListing` was split out
 * of `createServer` nothing could assert it. These are the invariants that hold
 * regardless of what any individual tool does, plus the one number that has to
 * be watched rather than merely asserted: how many bytes the listing costs.
 *
 * That budget is not bureaucracy. The listing is re-sent on every connect, and
 * the deployment spec alone is a ~126-field tree; inlining it into a tool schema
 * is a real and easy-to-miss increase in what every client pays. When the budget
 * fires, raise it deliberately, in its own commit, and write the new measured
 * number in — do not round it up to make room.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";

import { loadConfig } from "./config.js";
import { buildTools, toolListing } from "./server.js";
import type { Tool } from "./tools/diagnose.js";

/** The full surface: cloud configured, so the sandbox tools are listed too. */
const everything = (): Tool[] =>
  buildTools(loadConfig({ HEYO_API_KEY: "heyo_api_x", APPLB_TOKEN: "heyo_api_lb" }));

/** The fleet-operations shape: no cloud credential, so no sandbox tools. */
const fleetOnly = (): Tool[] => buildTools(loadConfig({ APPLB_URL: "http://127.0.0.1:9090" }));

/**
 * Every prefix a tool name may carry, and the two that carry none.
 *
 * The prefix names the upstream a tool speaks to, which is what makes a
 * 56-name list navigable at all. The exceptions are deliberate: a tool named
 * after the *question* it answers rather than the service it happens to hit.
 */
const PREFIXES = ["applb_", "sandbox_", "art_", "repo_", "ci_", "obs_", "heyo_", "diagnose_"];
const UNPREFIXED = ["fleet_overview", "deployment_logs"];

test("every listed tool is well formed", () => {
  const listing = toolListing(everything());
  assert.ok(listing.length > 0, "the listing is empty");

  for (const t of listing) {
    assert.ok(t.description.trim().length > 0, `${t.name} has no description`);
    assert.equal(
      t.inputSchema.type,
      "object",
      `${t.name} advertises a non-object input schema, which some hosts refuse`,
    );
    assert.ok(
      PREFIXES.some((p) => t.name.startsWith(p)) || UNPREFIXED.includes(t.name),
      `${t.name} carries no known service prefix — add one, or add it to UNPREFIXED deliberately`,
    );
  }
});

test("tool names are unique", () => {
  const names = toolListing(everything()).map((t) => t.name);
  const seen = new Set<string>();
  const duplicated = names.filter((n) => (seen.has(n) ? true : (seen.add(n), false)));
  assert.deepEqual(duplicated, [], "a duplicate name shadows a tool in the byName map");
});

test("the sandbox tools are gated on a cloud credential", () => {
  const withCloud = toolListing(everything()).map((t) => t.name);
  const without = toolListing(fleetOnly()).map((t) => t.name);

  // Asserted rather than named in a comment. The doc comment on `buildTools`
  // used to say "sixteen" when the real number was fifteen.
  const gated = withCloud.filter((n) => !without.includes(n));
  assert.equal(gated.length, 16, `expected 16 gated tools, got ${gated.length}: ${gated.join(", ")}`);
  assert.ok(gated.includes("sandbox_create"));
  assert.ok(
    gated.includes("heyo_capacity"),
    "heyo_capacity hits cloud despite its name and must be gated with the sandbox tools",
  );
  assert.ok(
    gated.includes("heyo_request"),
    "heyo_request targets cloud and must be gated with the tools that share its credential",
  );
  assert.ok(without.includes("applb_list_deployments"), "app-lb tools survive without cloud");
});

// The destructive set moved to `annotations.test.ts`, which names it rather than
// counting it and checks the prose against the derived hint. A count here would
// be a second thing to bump and no stronger.

test("a tool that advertises its own schema still agrees with the one that validates", () => {
  // Two descriptions of one input, at different resolutions: `inputSchema` is
  // generated from app-lb's types and teaches; `schema` is deliberately
  // permissive and admits. They are allowed to differ in depth — that is the
  // whole point — but not about what the arguments ARE. A tool advertising
  // `spec` while validating `body` would reject every call a client made
  // correctly from the schema it was shown.
  for (const t of everything()) {
    if (!t.inputSchema) continue;
    const advertised = t.inputSchema as { properties?: object; required?: string[] };
    const validating = zodToJsonSchema(z.object(t.schema), { $refStrategy: "none" }) as {
      properties?: object;
      required?: string[];
    };
    assert.deepEqual(
      Object.keys(advertised.properties ?? {}).sort(),
      Object.keys(validating.properties ?? {}).sort(),
      `${t.name} advertises different arguments than it validates`,
    );
    assert.deepEqual(
      [...(advertised.required ?? [])].sort(),
      [...(validating.required ?? [])].sort(),
      `${t.name} disagrees with itself about which arguments are required`,
    );
  }
});

test("the listing stays within its size budget", () => {
  // Measured 2026-10-06: 65,628 bytes across 77 tools, down from 76,926.
  //
  // applb_deploy stopped embedding the nested spec tree (~11 KB): it now
  // advertises each top-level field with its first sentence, and
  // applb_spec_schema returns any block in full. heyo_guide (~900 bytes) and
  // the tenant notes are inside that figure.
  //
  // Earlier, 2026-10-03: 75,796 bytes across 76 tools, up from 66,069 across 65.
  //
  // The +9,727 is eleven new tools and one schema doc paragraph. Six are the
  // `repo_*` tools (~5.9 KB) for the Heyo git remote, which is how a generated
  // project gets somewhere app-lb can build it; five are artifact-store gateway
  // tools (~3.4 KB): fetch, publish-files, list-manifests, delete-tag and
  // set-public. The inline-file schema appears in two of them
  // (`repo_write_files`, `art_publish_files`) because both accept the same
  // input; about 600 bytes is the price of not making either point at the other.
  //
  // Earlier, 2026-09-15: 66,069 bytes across 65 tools, up from 62,691 across 64.
  //
  // The +3,378 is one new tool, `applb_security_events`, and nothing else. Its
  // description is long because the SIEM has three non-obvious properties a
  // reader needs before the first call — the ring is in memory and bounded, so
  // a restart empties it; repeats fold into one row whose count climbs; and
  // `enabled: false` means detection is off, not that nothing happened — and
  // the alert's own `response` block is the runbook, so 'and now what?' is in
  // the answer. The schema carries the five `/security` query parameters
  // verbatim, which is the cheapest correct description of them.
  //
  // The headroom below is for ordinary description edits. It is deliberately
  // NOT enough to bring the nested spec tree back: applb_deploy advertises
  // top-level fields only (measured 65,628 bytes after that cut, from 76,926),
  // and applb_spec_schema serves any block on demand.
  const BUDGET = 67_000;
  const bytes = JSON.stringify(toolListing(everything())).length;
  assert.ok(
    bytes <= BUDGET,
    `tools/list is ${bytes} bytes, over the ${BUDGET} budget. ` +
      `Raise it in its own commit with the measured number, or cut what grew.`,
  );
});
