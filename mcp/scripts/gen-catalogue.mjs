#!/usr/bin/env node
/**
 * Write the tool catalogue into README.md, between markers.
 *
 *   npm run build && npm run catalogue
 *
 * The README's tool section was hand-maintained, and drifted the way every
 * hand-maintained mirror in this repository has: the largest group — all of
 * app-lb's lifecycle tools — was one sentence rather than a table, and the list
 * of destructive tools named eight when there were eleven. `annotations.test.ts`
 * already asserts that set by name, so a README disagreeing with it was a
 * contradiction nothing caught.
 *
 * So the catalogue is generated from `toolListing`, which is the same function
 * that answers `tools/list`. It cannot describe a tool the server does not have,
 * or miss one it does. `catalogue.test.ts` fails when the checked-in README is
 * stale.
 *
 * Only the block between the markers is written. Everything around it — the
 * prose about what the feed is, why publishing is one composite, what the tools
 * cannot see — stays hand-written, because none of that is derivable from a
 * tool list.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadConfig } from "../dist/config.js";
import { buildTools, toolListing } from "../dist/server.js";
import { DESTRUCTIVE_PREFIX } from "../dist/tools/schema.js";

const here = dirname(fileURLToPath(import.meta.url));
const readmePath = join(here, "..", "README.md");

export const BEGIN = "<!-- BEGIN GENERATED CATALOGUE -->";
export const END = "<!-- END GENERATED CATALOGUE -->";

/**
 * Every tool, with every service configured.
 *
 * The catalogue documents what the server *can* serve, not what one deployment
 * happens to have credentials for — a reader looking up `sandbox_exec` should
 * find it whether or not the instance they are pointed at lists it.
 */
function everyTool() {
  return toolListing(
    buildTools(
      loadConfig({
        HEYO_API_KEY: "heyo_api_x",
        APPLB_TOKEN: "heyo_api_lb",
        APP_OBS_URL: "http://app-obs",
        CI_URL: "http://ci",
        ART_URL: "http://art",
      }),
    ),
  );
}

/**
 * Groups, in the order a reader meets them.
 *
 * `match` rather than a prefix, because the useful grouping is by the question a
 * tool answers and three of them are named for that rather than for a service.
 */
const GROUPS = [
  {
    title: "Start here",
    blurb: "Step-by-step plans for common tasks and failures, and what this server can reach.",
    match: (n) => n === "heyo_guide",
  },
  {
    title: "Diagnostics",
    blurb: "Cross-service, shaped like the question rather than the endpoint.",
    match: (n) =>
      n.startsWith("diagnose_") ||
      ["heyo_status", "heyo_whoami", "fleet_overview", "namespace_telemetry", "deployment_logs"].includes(n),
  },
  {
    title: "Deploying",
    blurb:
      "`applb_deploy` is the entry point and does the whole sequence; the rest are the " +
      "primitives underneath it. Which job tool applies depends on the backend, and " +
      "picking wrong is refused rather than ignored — `applb_build` for a Dockerfile, " +
      "`applb_pull` for bytes from a store, `applb_host_update` for a static deployment's " +
      "own commands.",
    // Listed in the order someone meets them rather than the order they are
    // registered: the entry point first, then editing, then the job tools.
    names: [
      "applb_deploy",
      "applb_spec_schema",
      "applb_create_deployment",
      "applb_update_deployment",
      "applb_delete_deployment",
      "applb_scale",
      "applb_build",
      "applb_pull",
      "applb_pull_mounts",
      "applb_host_update",
      "applb_job",
      "applb_deployment_jobs",
    ],
  },
  {
    title: "Fleet and pools",
    blurb: "Reads over app-lb's topology, plus the operations that move VMs and disks.",
    match: (n) =>
      n.startsWith("applb_") && !n.endsWith("_request") && !n.startsWith("applb_feed"),
  },
  {
    title: "The event feed",
    blurb: "app-lb's per-namespace RSS, as data.",
    match: (n) => n.startsWith("applb_feed"),
  },
  {
    title: "Sandboxes",
    blurb: "heyo cloud. Listed only when a usable cloud API key is configured.",
    match: (n) => n.startsWith("sandbox_") || n === "heyo_capacity",
  },
  {
    title: "Git repos",
    blurb:
      "Repos on the Heyo git remote: somewhere a generated project can live, and what app-lb builds from.",
    match: (n) => n.startsWith("repo_"),
  },
  {
    title: "The artifact store",
    blurb: "Where a deployment's bytes come from.",
    match: (n) => n.startsWith("art_") && n !== "art_request",
  },
  {
    title: "ci",
    blurb: "Build status and VM pool control.",
    match: (n) => n.startsWith("ci_") && n !== "ci_request",
  },
  {
    title: "Raw escape hatches",
    blurb:
      "Everything without a dedicated tool. Prefer a named tool when one exists — a raw " +
      "call's intent cannot be read without reading its arguments.",
    match: (n) => n.endsWith("_request"),
  },
];

/** The first sentence of a description, without the DESTRUCTIVE marker. */
function summarize(description) {
  const body = description.startsWith(DESTRUCTIVE_PREFIX)
    ? description.slice(DESTRUCTIVE_PREFIX.length)
    : description;
  const para = body.split("\n\n")[0].replace(/\s*\n\s*/g, " ").trim();
  const cut = para.search(/\.\s+[A-Z`(*]/);
  const first = (cut > 0 ? para.slice(0, cut + 1) : para).trim();
  // Table cells: a pipe would end the column, and a newline the row.
  return first.replace(/\|/g, "\\|");
}

function render(tools) {
  const claimed = new Set();
  const lines = [BEGIN, ""];

  for (const group of GROUPS) {
    // A group may name its members, which also fixes their order; otherwise it
    // matches by shape and keeps registration order.
    const members = group.names
      ? group.names
          .map((n) => tools.find((t) => t.name === n && !claimed.has(n)))
          .filter((t) => t !== undefined)
      : tools.filter((t) => !claimed.has(t.name) && group.match(t.name));
    if (members.length === 0) continue;
    for (const t of members) claimed.add(t.name);

    lines.push(`### ${group.title}`, "", group.blurb, "");
    lines.push("| Tool | | Does |", "| --- | --- | --- |");
    for (const t of members) {
      const a = t.annotations ?? {};
      // A glyph rather than a word: the column exists to be scanned, and the
      // description already says DESTRUCTIVE in words for anything that is.
      const mark = a.destructiveHint ? "**destructive**" : a.readOnlyHint ? "read-only" : "";
      lines.push(`| \`${t.name}\` | ${mark} | ${summarize(t.description)} |`);
    }
    lines.push("");
  }

  for (const group of GROUPS) {
    for (const name of group.names ?? []) {
      if (!tools.some((t) => t.name === name)) {
        throw new Error(`gen-catalogue: group "${group.title}" names ${name}, which no longer exists`);
      }
    }
  }

  const missed = tools.filter((t) => !claimed.has(t.name));
  if (missed.length > 0) {
    throw new Error(
      `gen-catalogue: no group matches ${missed.map((t) => t.name).join(", ")} — ` +
        "add one rather than letting a tool go undocumented",
    );
  }

  lines.push(
    `_${tools.length} tools. Generated from the server's own listing by ` +
      "`scripts/gen-catalogue.mjs`; run `npm run catalogue` after adding one._",
    "",
    END,
  );
  return lines.join("\n");
}

/** Replace the marked block, leaving everything around it untouched. */
export function spliceCatalogue(readme, block) {
  const start = readme.indexOf(BEGIN);
  const end = readme.indexOf(END);
  if (start === -1 || end === -1) {
    throw new Error(`gen-catalogue: markers not found in README.md — expected ${BEGIN}`);
  }
  return readme.slice(0, start) + block + readme.slice(end + END.length);
}

export function catalogueBlock() {
  return render(everyTool());
}

// Only when run directly; `catalogue.test.ts` imports the functions above.
//
// An argument names another markdown file carrying the same markers, so the
// public docs in the marketing site are regenerated by the same command rather
// than copied by hand. A cross-repo staleness test is not practical, which is
// exactly why the copy should not be manual.
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop())) {
  const target = process.argv[2] ? resolve(process.argv[2]) : readmePath;
  const before = readFileSync(target, "utf8");
  writeFileSync(target, spliceCatalogue(before, catalogueBlock()));
  console.log(`gen-catalogue: ${target} — ${everyTool().length} tools`);
}
