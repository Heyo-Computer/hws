// Live end-to-end: five firecracker VMs on a real app-lb, through
// @heyocomputer/hws. The twin of app-lb/heyctl/tests/e2e_live.rs; keep the
// two doing the same steps so their latency reports compare.
//
// Skipped unless HWS_E2E_URL and HWS_E2E_TOKEN are set; it creates real VMs.
//
//   HWS_E2E_URL=https://admin.us5.heyo.work HWS_E2E_TOKEN=applb_… \
//   HWS_E2E_NAMESPACE=e2e HWS_E2E_DOMAIN=us5.heyo.work npm run e2e
//
// | Variable            | Default                 |                                                |
// | HWS_E2E_URL         | —                       | app-lb admin API                               |
// | HWS_E2E_TOKEN       | —                       | an admin token for the namespace               |
// | HWS_E2E_NAMESPACE   | e2e                     | where the deployments go                       |
// | HWS_E2E_DOMAIN      | —                       | base domain for the last VM's route; omitted skips the public fetch |
// | HWS_E2E_STORE       | https://hub.heyo.work   | where the image is pulled from                 |
// | HWS_E2E_IMAGE       | heyo/alpine:3.24        | the public alpine image                        |
// | HWS_E2E_REPORT      | —                       | write the latency report here as JSON          |

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";

import { Hws } from "../dist/index.js";

const VMS = 5;
const PORT = 8080;
const HTML = "<!doctype html><title>Heyo World</title><h1>Heyo World</h1>";

// One connection: read the request head, answer with the page. `nc -lk -e`
// runs it per connection with the socket on stdin/stdout.
const SERVE_SH =
  "#!/bin/sh\n" +
  "while IFS= read -r line; do line=$(printf '%s' \"$line\" | tr -d '\\r'); [ -z \"$line\" ] && break; done\n" +
  "body=$(cat /srv/heyo/index.html)\n" +
  "printf 'HTTP/1.1 200 OK\\r\\nContent-Type: text/html; charset=utf-8\\r\\nContent-Length: %s\\r\\nConnection: close\\r\\n\\r\\n%s' \"${#body}\" \"$body\"\n";

// Commands run in every VM, with what their output must contain.
const COMMANDS = [
  ["true", ""],
  ["echo heyo", "heyo"],
  ["cat /etc/alpine-release", "3."],
  ["uname -s", "Linux"],
  ["ls /", "etc"],
];

const env = (k, d) => (process.env[k] ? process.env[k] : d);
const E = {
  url: env("HWS_E2E_URL"),
  token: env("HWS_E2E_TOKEN"),
  namespace: env("HWS_E2E_NAMESPACE", "e2e"),
  domain: env("HWS_E2E_DOMAIN"),
  store: env("HWS_E2E_STORE", "https://hub.heyo.work"),
  image: env("HWS_E2E_IMAGE", "heyo/alpine:3.24"),
  report: env("HWS_E2E_REPORT"),
};

const ms = (t0) => Math.round((performance.now() - t0) * 10) / 10;
const sleep = (n) => new Promise((r) => setTimeout(r, n));

function spec(id) {
  return {
    id,
    namespace: E.namespace,
    routes: [],
    vm: { driver: "firecracker", port: PORT, size_class: "small" },
    artifact: { store: E.store, ref: E.image },
    // The image runs only sshd; a TCP connect to it is readiness.
    health: { path: null, port: 22 },
    scaling: {
      // Zero until the image is pulled: a pool asked for a VM before then
      // boots the default image instead, fails, and backs off.
      min_replicas: 0,
      max_replicas: 1,
      warm_pool: 0,
      boot_timeout_secs: 180,
      scale_to_zero_after_secs: 900,
    },
  };
}

// Register, pull, and wait for the first healthy VM, timing each.
async function create(lb, id) {
  const t0 = performance.now();
  await lb.createDeployment(spec(id));
  const register_ms = ms(t0);

  // An artifact deployment boots nothing until its image is pulled.
  const job = await lb.startPull(id);
  const done = await lb.waitForJob(job.id, { deployment: id, timeoutMs: 300_000 });
  assert.equal(done.status, "succeeded", `${id}: pull ${done.status}: ${done.error}`);
  const pulled = ms(t0);

  await lb.patchScaling(id, { min_replicas: 1 });
  const status = await lb.waitForReady(id, { timeoutMs: 240_000 });
  const total_ms = ms(t0);
  return {
    id,
    register_ms,
    pull_ms: Math.round((pulled - register_ms) * 10) / 10,
    boot_ms: Math.round((total_ms - pulled) * 10) / 10,
    total_ms,
    sandbox_id: status.vms?.[0]?.sandbox_id ?? "",
  };
}

function summary(label, values) {
  if (!values.length) return;
  const v = [...values].sort((a, b) => a - b);
  const mean = v.reduce((a, b) => a + b, 0) / v.length;
  const f = (n) => `${n.toFixed(1).padStart(9)}ms`;
  console.log(
    `${label.padEnd(22)} n=${String(v.length).padEnd(3)} min=${f(v[0])} p50=${f(v[Math.floor(v.length / 2)])} mean=${f(mean)} max=${f(v[v.length - 1])}`,
  );
}

async function exercise(lb, ids, report) {
  // Step 1: create all five at once, each timed on its own.
  report.creations = await Promise.all(ids.map((id) => create(lb, id)));

  // Step 2: exec latency, every command in every VM.
  for (const id of ids) {
    for (const [command, want] of COMMANDS) {
      const t0 = performance.now();
      const out = await lb.exec(id, command, { timeoutSecs: 20 });
      const took = ms(t0);
      assert.equal(out.exit_code, 0, `${id}: ${command} exited ${out.exit_code}: ${out.output}`);
      assert.ok(out.stdout.includes(want), `${id}: ${command} printed ${JSON.stringify(out.stdout)}`);
      report.execs.push({ id, command, ms: took });
    }
  }

  // Step 3: serve "Heyo World" from the last VM.
  const last = ids[ids.length - 1];
  const start =
    `mkdir -p /srv/heyo && printf '%s' "$SERVE" > /srv/heyo/serve.sh && chmod +x /srv/heyo/serve.sh ` +
    `&& printf '%s' "$HTML" > /srv/heyo/index.html ` +
    `&& (setsid nohup nc -lk -p ${PORT} -e /srv/heyo/serve.sh </dev/null >/dev/null 2>&1 &) ` +
    `&& sleep 1 && curl -s http://127.0.0.1:${PORT}/`;
  const served = await lb.exec(last, start, { env: { SERVE: SERVE_SH, HTML }, timeoutSecs: 20 });
  assert.ok(served.stdout.includes("Heyo World"), `${last}: no answer in the guest: ${served.output}`);

  if (!E.domain) {
    console.log("HWS_E2E_DOMAIN unset: served in the guest, public fetch skipped");
    return;
  }
  const host = `${last}.${E.domain}`;
  // The live spec, not the one registered: the pull filled in `vm.image`, and
  // a `vm` that differs would recycle the pool and the server with it.
  const current = await lb.deployment(last);
  const before = current.vms?.[0]?.sandbox_id;
  const replaced = await lb.replaceDeployment(last, { ...current.spec, routes: [{ host }] });
  assert.equal(replaced.vms?.[0]?.sandbox_id, before, `${last}: adding a route recycled the pool`);

  const url = `https://${host}/`;
  const t0 = performance.now();
  let lastErr = "";
  // A new exact host gets its certificate within seconds; allow two minutes.
  while (performance.now() - t0 < 120_000) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(10_000) });
      const body = await r.text();
      if (r.ok && body.includes("Heyo World")) {
        report.heyo_world_url = url;
        report.heyo_world_first_200_ms = ms(t0);
        return;
      }
      lastErr = `HTTP ${r.status}: ${body.slice(0, 120)}`;
    } catch (e) {
      lastErr = String(e?.cause ?? e);
    }
    await sleep(3_000);
  }
  assert.fail(`${url}: never served Heyo World: ${lastErr}`);
}

test(
  "five alpine VMs: create, exec, and Heyo World",
  { skip: !(E.url && E.token) && "HWS_E2E_URL / HWS_E2E_TOKEN unset", timeout: 15 * 60_000 },
  async () => {
    const lb = new Hws({ server: E.url, token: E.token, timeoutMs: 60_000 });
    const run = (Date.now() % 0xffffff).toString(16);
    const ids = Array.from({ length: VMS }, (_, i) => `e2e-ts-${run}-${i + 1}`);
    const report = { app_lb: E.url, image: `${E.store}/${E.image}`, creations: [], execs: [] };

    let failure;
    try {
      await exercise(lb, ids, report);
    } catch (e) {
      failure = e;
    } finally {
      // Step 4, unconditionally.
      for (const id of ids) {
        await lb.deleteDeployment(id).catch((e) => console.error(`cleanup: ${id}: ${e}`));
      }
    }

    console.log(`\n== @heyocomputer/hws e2e against ${report.app_lb} (${report.image})`);
    for (const c of report.creations) {
      console.log(
        `create ${c.id.padEnd(22)} register=${c.register_ms.toFixed(1)}ms pull=${c.pull_ms.toFixed(1)}ms boot=${c.boot_ms.toFixed(1)}ms total=${c.total_ms.toFixed(1)}ms ${c.sandbox_id}`,
      );
    }
    summary("create total", report.creations.map((c) => c.total_ms));
    summary("create boot", report.creations.map((c) => c.boot_ms));
    summary("exec", report.execs.map((e) => e.ms));
    if (report.heyo_world_url) {
      console.log(`heyo world             ${report.heyo_world_url} first 200 after ${report.heyo_world_first_200_ms}ms`);
    }
    if (E.report) writeFileSync(E.report, JSON.stringify(report, null, 2));

    if (failure) throw failure;
    assert.equal(report.creations.length, VMS);
    assert.equal(report.execs.length, VMS * COMMANDS.length);
  },
);
