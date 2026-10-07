/**
 * The README's tool catalogue is current.
 *
 * It was hand-maintained until 2026-09-10 and had drifted exactly the way every
 * other hand-maintained mirror in this repository drifted: the largest group —
 * app-lb's whole lifecycle surface — was a single sentence instead of a table,
 * and the destructive list named eight tools when there were eleven. That last
 * one was a contradiction with `annotations.test.ts`, which already asserted the
 * set by name; nothing compared the two.
 *
 * So the catalogue is generated from `toolListing` — the same function that
 * answers `tools/list` — and this test fails when the checked-in README is
 * behind it. Adding a tool without running `npm run catalogue` is a failing
 * test rather than a stale document.
 *
 * ## Why these tests skip in the image build
 *
 * `deploy/image/Dockerfile` copies `src/` and the package manifests into the
 * builder and nothing else, so neither the README nor `scripts/` exists there.
 * That is the right place for this check to be absent: it asserts that a
 * document agrees with the code, and a stale README should fail CI, not stop a
 * production image from building.
 *
 * The generator is therefore imported lazily. A static import of a file the
 * build context does not contain fails the whole module at load time, before any
 * `skip` can run — which is what failed `heyctl build heyo-mcp` on 2026-09-11,
 * reported as one failing test in place of these three.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { loadConfig } from "./config.js";
import { buildTools, toolListing } from "./server.js";
import { DESTRUCTIVE_PREFIX } from "./tools/schema.js";

// dist/ at runtime, so the package root is one level up.
const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const readmePath = join(pkgRoot, "README.md");
const generatorPath = join(pkgRoot, "scripts", "gen-catalogue.mjs");

const skip =
  existsSync(readmePath) && existsSync(generatorPath)
    ? false
    : "README.md or scripts/ is not in this build context — the image build copies src/ only";

/** The generator's exports, loaded only when it is actually there. */
const generator = () =>
  import(pathToFileURL(generatorPath).href) as Promise<{
    BEGIN: string;
    END: string;
    catalogueBlock: () => string;
    spliceCatalogue: (readme: string, block: string) => string;
  }>;

const readme = () => readFileSync(readmePath, "utf8");

/** The generated block, markers included, as it stands in the README. */
async function block(): Promise<string> {
  const { BEGIN, END } = await generator();
  const text = readme();
  return text.slice(text.indexOf(BEGIN), text.indexOf(END));
}

test("the checked-in catalogue matches the server's own listing", { skip }, async () => {
  const { catalogueBlock, spliceCatalogue } = await generator();
  const current = readme();
  assert.equal(
    current,
    spliceCatalogue(current, catalogueBlock()),
    "README.md's tool catalogue is stale — run `npm run build && npm run catalogue` " +
      "and commit the result.",
  );
});

test("every tool appears in the catalogue exactly once", { skip }, async () => {
  const text = await block();
  const tools = buildTools(
    loadConfig({
      HEYO_API_KEY: "heyo_api_x",
      APPLB_TOKEN: "heyo_api_lb",
      APP_OBS_URL: "http://o",
      CI_URL: "http://c",
    }),
  );
  for (const t of tools) {
    const rows = text.split("\n").filter((l) => l.startsWith(`| \`${t.name}\` |`));
    assert.equal(rows.length, 1, `${t.name} appears ${rows.length} times in the catalogue`);
  }
});

test("the catalogue marks exactly the tools that call themselves destructive", { skip }, async () => {
  // The contradiction that used to exist: prose in one place, a different set in
  // another, and nothing comparing them. Here they are compared.
  const marked = new Set(
    (await block())
      .split("\n")
      .filter((l) => l.includes("**destructive**"))
      .map((l) => /^\| `([^`]+)`/.exec(l)?.[1])
      .filter((n): n is string => !!n),
  );
  const destructive = new Set(
    toolListing(buildTools(loadConfig({ HEYO_API_KEY: "heyo_api_x", APPLB_TOKEN: "heyo_api_lb" })))
      .filter((t) => t.description.startsWith(DESTRUCTIVE_PREFIX))
      .map((t) => t.name),
  );
  assert.deepEqual([...marked].sort(), [...destructive].sort());
});
