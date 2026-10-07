#!/usr/bin/env node
/**
 * Turn app-lb's generated deployment schema into the one the tool surface can
 * afford to advertise.
 *
 *   node scripts/prune-schema.mjs [path/to/app-lb]
 *
 * Writes `src/applb/spec.schema.ts`. Run it after regenerating
 * `app-lb/schema/deployment-spec.json`; `spec.test.ts` fails when the checked-in
 * output is stale, so CI catches a forgotten run.
 *
 * ## Why prune at all
 *
 * The generated schema is ~61 KB, three quarters of it doc comments, and
 * `tools/list` is re-sent on every connect. Inlining it whole would nearly
 * triple what every client pays to learn this server exists, to describe one
 * tool. So two reductions, in this order:
 *
 * 1. **First paragraph only.** app-lb's doc comments open with what the field
 *    *is* and continue with why it is that way. The first paragraph is the part
 *    a caller filling in a spec needs; the rest is for whoever changes it. The
 *    full text stays one `applb_spec_schema` call away.
 * 2. **Cold blocks collapse to an open object.** A block nobody hand-writes —
 *    the auth gate, JWT verification, mounts, the managed workspace — keeps its
 *    summary and loses its interior. `additionalProperties` stays true, so a
 *    collapsed block still accepts everything it did before: it is
 *    under-*described*, never restricted.
 *
 * ## What must not happen
 *
 * Nothing here may make the schema stricter than app-lb. A collapsed block that
 * forbade unknown keys, or a `required` this dropped, would turn a spec the
 * server accepts into one a client refuses to send. The pruner only ever
 * removes description text and interior structure — never a constraint, and
 * never a field from `required`.
 */

import { readFileSync, readdirSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const applbRoot = resolve(process.argv[2] ?? join(here, "..", "..", "app-lb"));
const source = join(applbRoot, "schema", "deployment-spec.json");
const out = join(here, "..", "src", "applb", "spec.schema.ts");

/**
 * Blocks that keep their summary and lose their interior.
 *
 * Chosen by who writes them, not by size. Each of these is either configured
 * once and copied thereafter (the auth gate, JWT), assembled by a feature
 * rather than by hand (mounts, the managed workspace), or filled in by cloud
 * and refused when hand-written (`workspace_archive`). They are also, not
 * coincidentally, the blocks carrying the shapes a transcription gets wrong —
 * so collapsing them removes the interior most likely to be described badly and
 * leaves it to the one place that generates it faithfully.
 */
const KEEP_FULL = new Set([
  // The decisions every spec makes.
  "RouteRule",
  "VmSpec",
  "ScalingPolicy",
  "HealthCheck",
  // The two answers to "where do the bytes come from", which is the question
  // most often got wrong, and the enums the hot fields point at.
  "BuildSpec",
  "ArtifactSpec",
  "Driver",
  "IdleAction",
  "SandboxSize",
  "SecretRef",
]);

/**
 * `VmSpec` fields worth advertising.
 *
 * The rest are real and still accepted — they are simply not what someone
 * writing a spec by hand reaches for. `mounts` and `workspace` belong to
 * features that assemble them; `image_download_url`, `image_size_bytes` and
 * `image_sha256` are filled in by cloud and a hand-written value is refused.
 * Listing all of them costs more than it teaches.
 */
const VM_FIELDS = new Set([
  "driver",
  "image",
  "port",
  "start_command",
  "size_class",
  "disk_size_gb",
  "working_directory",
  "env_vars",
  "open_ports",
  "ttl_seconds",
]);

/**
 * How much of a doc comment survives, in characters.
 *
 * Enough for a sentence that says what the field is. app-lb's comments are
 * unusually good and it is tempting to keep them whole — but they are written
 * for someone changing the field, and this budget is spent on everyone who ever
 * connects. `applb_spec_schema` returns them in full.
 */
const DESC_CHARS = 180;

/** Trim a doc comment to its first sentence, and then to a hard budget. */
function summarize(text) {
  const para = text.split("\n\n")[0].replace(/\s*\n\s*/g, " ").trim();
  // Sentence end: a period followed by a space and a capital, so `heyo_api_*`
  // keys, `v1.2` and `e.g.` do not split the line in the wrong place.
  const cut = para.search(/\.\s+[A-Z`(]/);
  const first = cut > 0 ? para.slice(0, cut + 1) : para;
  return first.length <= DESC_CHARS ? first : `${first.slice(0, DESC_CHARS).trimEnd()}…`;
}

/** Recursively shorten every `description`, leaving all else untouched. */
function shorten(node) {
  if (Array.isArray(node)) return node.map(shorten);
  if (node && typeof node === "object") {
    return Object.fromEntries(
      Object.entries(node).map(([k, v]) =>
        k === "description" && typeof v === "string" ? [k, summarize(v)] : [k, shorten(v)],
      ),
    );
  }
  return node;
}

/** Every `#/$defs/X` reachable from a node, so unused blocks can be dropped. */
function refsIn(node, found = new Set()) {
  if (Array.isArray(node)) {
    for (const x of node) refsIn(x, found);
  } else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (k === "$ref" && typeof v === "string" && v.startsWith("#/$defs/")) {
        found.add(v.slice("#/$defs/".length));
      } else {
        refsIn(v, found);
      }
    }
  }
  return found;
}

const generated = JSON.parse(readFileSync(source, "utf8"));
// Kept whole, for `applb_spec_schema` to hand back a block at a time. It never
// enters `tools/list`, so its size costs nothing until somebody asks for it —
// which is what makes pruning the advertised copy an affordable trade rather
// than a loss.
const full = JSON.stringify(generated, null, 2);

const schema = shorten(JSON.parse(readFileSync(source, "utf8")));
const defs = schema.$defs ?? {};

for (const name of KEEP_FULL) {
  if (!defs[name]) {
    console.error(`prune-schema: ${name} is not in the schema — has it been renamed?`);
    process.exit(1);
  }
}

const pointer = (name) =>
  `Call applb_spec_schema with block "${name}" for the full shape; everything it ` +
  `accepted is still accepted.`;

for (const [name, original] of Object.entries(defs)) {
  if (KEEP_FULL.has(name)) continue;
  defs[name] = {
    type: "object",
    additionalProperties: true,
    description: `${original.description ?? name} (${pointer(name)})`,
  };
}

// `VmSpec` stays typed but not exhaustive: the fields people write, described,
// and the rest reachable through the pointer. `required` is untouched, so this
// cannot refuse a spec app-lb would take.
{
  const vm = defs.VmSpec;
  const dropped = Object.keys(vm.properties).filter((k) => !VM_FIELDS.has(k));
  vm.properties = Object.fromEntries(
    Object.entries(vm.properties).filter(([k]) => VM_FIELDS.has(k)),
  );
  vm.additionalProperties = true;
  vm.description =
    `${vm.description} (${dropped.length} more fields — ${dropped.join(", ")} — ` +
    `omitted here for size. ${pointer("VmSpec")})`;
}

// Drop what nothing points at any more. Collapsing the auth gate, for instance,
// orphans the four types only it referenced.
let live = refsIn({ properties: schema.properties, $defs: defs });
let size;
do {
  size = live.size;
  for (const name of [...live]) live = refsIn(defs[name] ?? {}, live);
} while (live.size !== size);
for (const name of Object.keys(defs)) if (!live.has(name)) delete defs[name];

const rendered = JSON.stringify(schema, null, 2);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(
  out,
  `/**
 * The deployment spec, as advertised to a client. GENERATED — DO NOT EDIT.
 *
 * Produced by \`scripts/prune-schema.mjs\` from app-lb's
 * \`schema/deployment-spec.json\`, which app-lb generates from the Rust types
 * themselves. Nothing here was transcribed by hand, which is the point: the
 * three mirrors that were transcribed all drifted, and two of them are wrong
 * today.
 *
 * Descriptions are trimmed to their opening paragraph and a few blocks are
 * collapsed to keep \`tools/list\` affordable. The full schema for any block is
 * one \`applb_spec_schema\` call away.
 *
 * Regenerate: \`npm run schema\` (with app-lb checked out alongside).
 */

export const DEPLOYMENT_SPEC_SCHEMA = ${rendered};

/**
 * The same schema with nothing removed: every field, every doc comment.
 *
 * Returned by \`applb_spec_schema\`, never advertised. This is what makes the
 * pruning above a trade rather than a loss — the detail is one call away
 * instead of on every connect.
 */
export const DEPLOYMENT_SPEC_FULL = ${full};
`,
);

// ---- the examples, compiled in --------------------------------------------
//
// Read at build time, never at runtime. `mcp/tsconfig.json` has no
// `resolveJsonModule` and `tsc` does not copy JSON into `dist`, so a runtime
// read would work in a checkout and fail everywhere else — and this package has
// to stand alone once installed. Compiling them in also means the drift check
// in `spec.test.ts` is the only thing that has to care whether app-lb is here.
const examplesDir = join(applbRoot, "examples");
const exampleFiles = [];
const walkExamples = (dir) => {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walkExamples(full);
    else if (entry.endsWith(".json")) exampleFiles.push(full);
  }
};
walkExamples(examplesDir);
exampleFiles.sort();

// Specs for *running* an artifact store. That is the operator's
// infrastructure: a namespace publishes through app-lb's
// `/namespaces/:name/artifacts` with its own credential and never deploys,
// addresses or holds the key to a store, so an agent shown these would be
// steered toward exactly the thing it should not touch.
const OPERATOR_ONLY = new Set([
  "artifacts.json",
  "artifacts-gated.json",
  "artifacts-hub.json",
  // Heyo's own release site, which names the store and a secret holding its key.
  "releases-site.json",
]);
exampleFiles.splice(
  0,
  exampleFiles.length,
  ...exampleFiles.filter((f) => !OPERATOR_ONLY.has(f.split("/").pop())),
);

// `examples/README.md` documents most of them under `## \`name.json\` — title`.
// Pairing the prose with the spec is the whole value: the JSON says what to
// send and the section says why it is shaped that way.
const readme = readFileSync(join(examplesDir, "README.md"), "utf8");
const sections = new Map();
for (const block of readme.split(/^## /m).slice(1)) {
  const name = /^`([^`]+\.json)`/.exec(block)?.[1];
  if (name) sections.set(name, `## ${block}`.trimEnd());
}

const examples = exampleFiles.map((file) => {
  const name = file.slice(examplesDir.length + 1);
  return {
    name,
    spec: readFileSync(file, "utf8").trimEnd(),
    notes: sections.get(name.split("/").pop()) ?? null,
  };
});

writeFileSync(
  join(here, "..", "src", "applb", "examples.ts"),
  `/**
 * app-lb's shipped deployment examples. GENERATED — DO NOT EDIT.
 *
 * Copied by \`scripts/prune-schema.mjs\` from \`app-lb/examples/\`, each paired
 * with its section of that directory's README. Every one of them is parsed and
 * run through \`DeploymentSpec::validate\` by a test in app-lb, so these are
 * specs the server would actually accept rather than illustrations.
 *
 * Regenerate: \`npm run schema\`.
 */

export interface DeploymentExample {
  /** Path within \`app-lb/examples/\`, e.g. \`git-build.json\`. */
  readonly name: string;
  /** The spec, exactly as it ships. */
  readonly spec: string;
  /** Its section of \`examples/README.md\`, when it has one. */
  readonly notes: string | null;
}

export const DEPLOYMENT_EXAMPLES: readonly DeploymentExample[] = ${JSON.stringify(examples, null, 2)};
`,
);

const bytes = Buffer.byteLength(JSON.stringify(schema));
console.log(
  `prune-schema: src/applb/spec.schema.ts — ${bytes} bytes advertised (compact), ` +
    `${Object.keys(defs).length} definitions (${KEEP_FULL.size} kept in full); ` +
    `${examples.length} examples`,
);
