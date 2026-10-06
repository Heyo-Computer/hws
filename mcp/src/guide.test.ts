/**
 * `heyo_guide` and the failure hints: what an agent holding only this server
 * is told at the point it would otherwise guess. Each case here is a step an
 * outside user's agent got wrong.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { checkSpec } from "./applb/rules.js";
import { loadConfig } from "./config.js";
import { buildTools, withHint } from "./server.js";
import { GUIDES, explainFailure, matchGuide } from "./tools/guide.js";

const tools = () => buildTools(loadConfig({ APPLB_URL: "http://127.0.0.1:9090", APPLB_TOKEN: "applb_x" }));

test("heyo_guide is listed first, so no tool-list cap drops it", () => {
  assert.equal(tools()[0]?.name, "heyo_guide");
});

test("goals in an agent's own words reach the right plan", () => {
  const cases: [string, string][] = [
    ["deploy my static site, I have the built files in dist", "deploy-static-site"],
    ["deploy my node api with a Dockerfile as a vm", "deploy-vm-from-source"],
    ["I created a repo with repo_create, now deploy it", "deploy-existing-repo"],
    ["publish these files as an artifact", "publish-files-as-artifact"],
    ["fatal: could not read Username for 'https://git.us5.heyo.work': terminal prompts disabled", "fix-git-auth"],
    ["the site status is empty and every page is 404", "fix-empty-site"],
    ["my vm pool never becomes ready", "fix-vm-not-ready"],
    ["403 forbidden: a namespace credential may not use update", "fix-forbidden"],
  ];
  for (const [goal, id] of cases) assert.equal(matchGuide(goal)?.id, id, goal);
});

test("the tool answers a topic, a goal, and nothing with the catalogue", async () => {
  const guide = tools().find((t) => t.name === "heyo_guide")!;
  const all = await guide.handler({});
  for (const g of GUIDES) assert.ok(all.includes(g.id), `catalogue lacks ${g.id}`);
  const site = await guide.handler({ topic: "deploy-static-site" });
  assert.match(site, /repo_create/);
  assert.match(site, /Do NOT set `site.root`/);
  assert.match(await guide.handler({ goal: "deploy my static website" }), /guide: deploy-static-site/);
  assert.match(await guide.handler({ topic: "nope" }), /No guide "nope"/);
});

test("failure text an agent is holding names the plan that gets it out", () => {
  const job = JSON.stringify({
    id: "job-1",
    status: "failed",
    error: "git clone: fatal: could not read Username for 'https://git.us5.heyo.work': terminal prompts disabled",
  });
  assert.match(withHint("applb_job", job), /Hint: .*build\.auth.*fix-git-auth/s);
  assert.match(withHint("applb_get_deployment", '{"site":{"status":"empty"}}'), /fix-empty-site/);
  assert.match(
    withHint("applb_deploy", "app-lb 403: site.root must be under /var/lib/app-lb/sites/us5/"),
    /fix-forbidden/,
  );
  assert.equal(withHint("applb_job", '{"status":"succeeded"}'), '{"status":"succeeded"}');
  // The guide itself describes these failures; it must not hint at itself.
  assert.equal(withHint("heyo_guide", "could not read Username"), "could not read Username");
  assert.equal(explainFailure("all good"), undefined);
});

test("a tenant's spec is told the alternative before it is sent", () => {
  const site = { id: "web", routes: [{ host: "w.example.com" }] };
  const confined = (spec: Record<string, unknown>) => checkSpec(spec, { confined: true }).join("\n");
  assert.match(
    confined({ ...site, site: { root: "/var/lib/app-lb/sites/us5/web" }, update: { working_dir: "/tmp", commands: ["mkdir x"] } }),
    /Leave out `site.root`[\s\S]*`update` is operator-only/,
  );
  assert.match(
    confined({ ...site, vm: { driver: "firecracker", port: 8080 }, build: { repo: "git@github.com:x/y.git" } }),
    /must be an https:\/\/ URL/,
  );
  // A site nothing fills is flagged for everyone.
  assert.match(checkSpec({ ...site, site: {} }).join("\n"), /never filled/);
  // The operator keeps `update` and a root.
  assert.equal(
    checkSpec({ ...site, site: { root: "/srv/www" }, update: { working_dir: "/srv", commands: ["make"] } }).join("\n"),
    "",
  );
});

test("applb_job with a namespace token falls back to the deployment's job list", async () => {
  const job = tools().find((t) => t.name === "applb_job")!;
  const original = globalThis.fetch;
  const seen: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    seen.push(url);
    const reply = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.includes("/jobs/job-1")) return reply(403, { error: "fleet-wide route" });
    return reply(200, [{ id: "job-0", status: "failed" }, { id: "job-1", status: "succeeded" }]);
  }) as typeof fetch;
  try {
    await assert.rejects(job.handler({ job_id: "job-1" }), /with `deployment` set/);
    const out = await job.handler({ job_id: "job-1", deployment: "web" });
    assert.match(out, /"succeeded"/);
    assert.ok(seen.some((u) => u.endsWith("/deployments/web/jobs")));
  } finally {
    globalThis.fetch = original;
  }
});
