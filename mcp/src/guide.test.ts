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
import { readStartInfo, startCommand } from "./tools/dockerfile.js";

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

test("the advertised spec fields carry the tenant notes where they invite mistakes", () => {
  const deploy = tools().find((t) => t.name === "applb_deploy")!;
  const spec = (deploy.inputSchema as { properties: { spec: Record<string, any> } }).properties.spec;
  assert.match(spec.properties.site.description, /^Omit `root`/);
  assert.match(spec.properties.update.description, /^Operators only/);
  assert.match(spec.properties.build.description, /^Namespace credentials: https:\/\//);
  assert.match(spec.properties.vm.description, /must return/);
});

/** repo_deploy against a stub app-lb + remote; returns the spec it registered. */
async function repoDeploy(args: Record<string, unknown>, existing?: Record<string, unknown>, dockerfile?: string) {
  const config = loadConfig({
    APPLB_URL: "http://127.0.0.1:9090",
    APPLB_TOKEN: "applb_x",
    APPLB_NAMESPACE: "us5",
    REMOTE_URL: "https://git.us5.example.com",
  });
  const tool = buildTools(config).find((t) => t.name === "repo_deploy")!;
  const writes: { method: string; url: string; body: any }[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    if (method !== "GET") writes.push({ method, url, body });
    const reply = (status: number, b: unknown) =>
      new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
    if (url.includes("/api/repos/")) {
      return reply(200, { clone_url: "https://git.us5.example.com/us5/app.git", default_branch: "main", empty: false });
    }
    if (url.endsWith("/api/tokens")) return reply(201, { token: "hrm_1_s", id: "t1" });
    if (url.includes("/raw/")) {
      return dockerfile && url.endsWith("/Dockerfile")
        ? new Response(dockerfile, { status: 200, headers: { "content-type": "text/plain" } })
        : reply(404, { error: "not found" });
    }
    if (url.includes("/onboarding")) return reply(200, { fastcar: { url: "https://fastcar-us5.us5.example.com" } });
    if (method === "GET" && /\/deployments\/[^/?]+$/.test(url)) {
      return existing ? reply(200, { spec: existing }) : reply(404, { error: "not found" });
    }
    if (method === "POST" && /\/build$/.test(url)) return reply(202, { id: "job-1", status: "queued" });
    return reply(200, { id: "app" });
  }) as typeof fetch;
  try {
    const out = await tool.handler({ ...args, wait_seconds: 0 });
    const reg = writes.find((w) => /\/deployments(\/app)?$/.test(w.url) && (w.method === "POST" || w.method === "PUT"));
    return { out, spec: reg?.body };
  } finally {
    globalThis.fetch = original;
  }
}

test("repo_deploy names a host from app-lb's base domain when none is given", async () => {
  const { out, spec } = await repoDeploy({ repo: "app", kind: "site" });
  assert.deepEqual(spec.routes, [{ host: "app.us5.example.com" }]);
  assert.match(out, /using app\.us5\.example\.com/);
});

test("a corrected port wins over the existing spec on redeploy", async () => {
  const existing = {
    id: "app", namespace: "us5", routes: [{ host: "app.example.com" }],
    vm: { driver: "firecracker", port: 3000, start_command: "node server.js" },
  };
  const { spec } = await repoDeploy({ repo: "app", kind: "vm", port: 8080 }, existing);
  assert.equal(spec.vm.port, 8080);
  assert.equal(spec.vm.start_command, "node server.js", "the rest of the vm block is kept");
  const kept = await repoDeploy({ repo: "app", kind: "vm" }, existing);
  assert.equal(kept.spec.vm.port, 3000, "no port given keeps the existing one");
});

test("a Dockerfile's CMD, WORKDIR, ENV and EXPOSE become a start_command that returns", () => {
  const info = readStartInfo(
    "FROM node:20 AS build\nWORKDIR /src\nRUN npm ci\n\n" +
      "FROM node:20-slim\nWORKDIR /app\nENV NODE_ENV=production PATH=/app/bin:$PATH\n" +
      "COPY --from=build /src .\nEXPOSE 3001/tcp\nCMD [\"node\", \"server.js\"]\n",
  );
  assert.equal(info.workdir, "/app", "the final stage's WORKDIR, not the builder's");
  assert.equal(info.port, 3001);
  assert.equal(
    startCommand(info),
    'cd /app && export NODE_ENV=production && export PATH="/app/bin:$PATH" && ' +
      "setsid nohup node server.js </dev/null &",
  );
  assert.equal(
    readStartInfo('FROM python:3\nENTRYPOINT ["python", "-m"]\nCMD ["app.main"]').command,
    "python -m app.main",
  );
  assert.equal(readStartInfo("FROM alpine\nCMD ./run.sh --port 80").command, "./run.sh --port 80");
  assert.equal(startCommand(readStartInfo("FROM alpine\nRUN true")), undefined, "no CMD, no command");
});

test("repo_deploy kind vm with no start_command derives it from the Dockerfile", async () => {
  const { out, spec } = await repoDeploy(
    { repo: "app", kind: "vm" },
    undefined,
    "FROM node:20-slim\nWORKDIR /app\nCOPY . .\nEXPOSE 3001\nCMD [\"node\", \"server.js\"]\n",
  );
  assert.equal(spec.vm.start_command, "cd /app && setsid nohup node server.js </dev/null &");
  assert.equal(spec.vm.port, 3001, "EXPOSE supplies the port when none is given");
  assert.match(out, /start_command \(from the Dockerfile\)/);

  // With nothing to derive and none given, the VM would never start its app,
  // so it is refused rather than registered.
  const none = await repoDeploy({ repo: "app", kind: "vm" }, undefined, "FROM alpine\nRUN true\n");
  assert.equal(none.spec, undefined, "not registered");
  assert.match(none.out, /No start_command/);
  assert.match(none.out, /not sent — no start_command/);
});

test("applb_deploy warns that a hand-written artifact store with no auth will 401, and says to omit it", async () => {
  const config = loadConfig({
    APPLB_URL: "http://127.0.0.1:9090",
    APPLB_TOKEN: "applb_x",
  });
  const deploy = buildTools(config).find((t) => t.name === "applb_deploy")!;
  const original = globalThis.fetch;
  const sent: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    sent.push(`${init?.method ?? "GET"} ${String(input)}`);
    const missing = (init?.method ?? "GET") === "GET";
    return new Response("{}", { status: missing ? 404 : 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  try {
    const out = await deploy.handler({
      spec: {
        id: "farm-rsvp",
        routes: [{ host: "farm-rsvp.example.com" }],
        vm: { driver: "firecracker", port: 8080, start_command: "x &" },
        artifact: { store: "https://art.us5.example.com", ref: "us5/farm-rsvp" },
      },
    });
    assert.match(out, /Artifact access/);
    assert.match(out, /no `auth`, so app-lb pulls it anonymously and a private tag fails with 401/);
    assert.match(out, /Leave `store` out/);
    // Warned, not refused: a public repo on another store is legitimate.
    assert.ok(sent.some((r) => r.startsWith("POST") || r.startsWith("PUT")), "the spec was not sent");
  } finally {
    globalThis.fetch = original;
  }
});
