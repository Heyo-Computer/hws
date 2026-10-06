/**
 * The task-oriented half: tools shaped like the questions people actually ask.
 *
 * Each one joins across services, because the answers do. "Why is nothing
 * running" is app-lb's topology *and* app-obs's logs *and* ci's queue, and a
 * tool per endpoint leaves that join to be redone by hand every time. The
 * descriptions carry what took a week to learn — which endpoint answers which
 * question, and which one looks like it should and does not.
 */

import { z } from "zod";
import { bool, num } from "./schema.js";
import { foregroundScript, interpret, lintVmSpec, noVmFinding, parseStartCommand, probeScript, type Finding } from "./vmboot.js";
import type { Clients } from "../clients/index.js";
import { settle } from "../clients/index.js";
import { report, section, json, type Section } from "../format.js";
import { configured, credentialFaults, type Config } from "../config.js";
import { obsPluginPrefix, telemetry, telemetryRoute } from "../telemetry.js";

export interface Tool {
  name: string;
  description: string;
  schema: z.ZodRawShape;
  /**
   * A pre-built JSON Schema to advertise instead of converting `schema`.
   *
   * For an input whose real shape is defined somewhere other than here. The
   * deployment spec is the case: it is app-lb's, it is generated from app-lb's
   * own types, and every attempt to restate it in a client's own vocabulary has
   * drifted — the TypeScript SDK still lists a driver the server rejects and
   * omits a field it accepts. Handing the generated schema through untouched is
   * the only version of this that cannot go stale.
   *
   * `schema` is still required and still what validates: it stays deliberately
   * permissive for such an input, because app-lb accepts unknown fields and a
   * client that refused them would reject specs the server would take. So the
   * two describe the same input at different resolutions — this one teaches,
   * `schema` admits — and they must agree on the top-level keys, which
   * `listing.test.ts` checks.
   */
  inputSchema?: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<string>;
}

export function diagnosticTools(clients: Clients, config: Config): Tool[] {
  return [
    {
      name: "heyo_status",
      description:
        "Which of heyo cloud, app-lb, app-obs, ci and the artifact store this server can " +
        "reach, and what each says about itself. Start here when a tool fails with a " +
        "connection or auth error — it distinguishes 'not configured' from 'configured and " +
        "refusing'. The cloud probe doubles as an API-key check, and the app-lb one resolves " +
        "the managed namespace, so a namespace that cannot be worked out surfaces here rather " +
        "than inside a later call. For 'which credential am I' rather than 'what can I " +
        "reach', use heyo_whoami.",
      schema: {},
      handler: async () => {
        const r = await settle({
          cloud: clients.cloud({ path: "/me/daemons" }),
          applb: clients.applb({ path: "/metrics" }),
          obs: clients.obs({ path: "/healthz" }),
          ci: clients.ci({ path: "/healthz" }),
          // `/usage` rather than `/healthz`: the store leaves `/healthz` outside
          // its own auth layer, so it answers `ok` whether or not either
          // credential is right — a green probe that proves nothing about the
          // thing that actually fails. `/usage` goes through both doors.
          art: clients.art({ path: "/usage" }),
        });
        // Above every probe, because a credential that cannot work explains
        // all of them at once. Without it the reader has to infer one cause
        // from five separate 401s, which is the inference that sent a customer
        // into our source.
        const faults = credentialFaults(config).map(
          (f): Section => ({
            title: `${f.service} — CREDENTIAL FAULT`,
            body: null,
            error: `${f.summary}.\n\n${f.detail}`,
          }),
        );
        return report(`Configured: ${configured(config).join(", ") || "nothing"}`, [
          ...faults,
          section(
            "heyo cloud /me/daemons — reachable, and the key is good",
            r.cloud,
            "heyo cloud /me/daemons — FAILED. This is where a bad HEYO_API_KEY shows up.",
          ),
          section("app-lb /metrics", r.applb),
          section("app-obs /healthz", r.obs),
          section("ci /healthz", r.ci),
          section(
            "artifacts /usage — passes the gate AND the store's own key",
            r.art,
            "artifacts /usage — FAILED at the gate or at the store's own key; " +
              "the Configured line above says which credential is missing.",
          ),
        ]);
      },
    },

    {
      name: "heyo_whoami",
      description:
        "What this server's credential is and what it may do: admin scope, namespace, " +
        "deployment scope and expiry.\n\n" +
        "Run this FIRST on any 401 or 403 from an applb_* tool. Scope problems and " +
        "authentication problems look identical from the outside — a token minted without " +
        "admin scope, or scoped to the wrong namespace, produces a refusal that reads as a " +
        "broken connection — and this is the one call that tells them apart. Before it " +
        "existed the answer needed a SECOND, wider credential on another machine to list " +
        "tokens with, which is why a scope problem cost a dozen probes.\n\n" +
        "Two scopes decide everything and they are checked in different places: the ADMIN " +
        "TIER (none / view / admin) is what the admin API requires, and the DEPLOYMENT " +
        "SCOPE is what a deployment's own gate requires. A token can pass a gate and still " +
        "be refused by the admin API, and the reverse — so read both fields, not just the " +
        "tier.",
      schema: {},
      handler: async () => {
        const r = await settle({
          applb: clients.applb({ path: "/whoami" }),
          namespace: clients.applbNamespace(),
        });
        return report("This server's credential, as app-lb sees it", [
          section("app-lb /whoami", r.applb),
          section("Namespace these app-lb tools are confined to", r.namespace),
        ]);
      },
    },

    {
      name: "fleet_overview",
      description:
        "The whole managed fleet in one call: app-obs's per-deployment rows with host CPU " +
        "and memory, app-lb's current topology with health and drain state, and app-obs's " +
        "ingest counters. Use this before drilling into one deployment — it is the only view " +
        "that shows a problem affecting several at once. The topology also lists " +
        "`host_sandboxes`: VMs on the host that no deployment owns (made through heyvm, the " +
        "cloud API or the desktop). They share the host's CPU and memory with every pool, so " +
        "a loaded host beside idle pools is usually explained there; their logs live under " +
        "the app-obs deployment `_unmanaged`, filtered by `backend`. Unconfined credentials " +
        "only; a namespace-confined one uses namespace_telemetry.",
      schema: { window: z.string().optional().describe("app-obs window, e.g. '15m', '1h', '24h'") },
      handler: async (args) => {
        const window = (args.window as string) ?? "1h";
        // The whole fleet is the operator's view. A confined caller must not
        // be shown it on this server's app-obs token, so it is turned away
        // before app-obs is asked anything.
        const route = await telemetryRoute(clients, config);
        if (route.via === "applb") {
          return json({
            error:
              `this credential is confined to namespace ${JSON.stringify(route.namespace)}, ` +
              "and fleet_overview is the whole fleet — use namespace_telemetry for that " +
              "namespace's deployments",
          });
        }
        const r = await settle({
          fleet: clients.obs({ path: "/api/fleet", query: { window } }),
          platform: clients.obs({ path: "/api/platform-status" }),
          stats: clients.obs({ path: "/stats" }),
        });
        return report(`Fleet over ${window}`, [
          section("Deployments and host resources (app-obs /api/fleet)", r.fleet),
          section("app-lb topology as app-obs last saw it", r.platform),
          section("Ingest counters — dropped rows mean the collector fell behind", r.stats),
        ]);
      },
    },

    {
      name: "diagnose_deployment",
      description:
        "Everything about one deployment at once: app-lb's record and its VM pool, app-obs's " +
        "bucketed series, and the most recent error-level logs. This is the first call for " +
        "'deployment X is unhealthy'.\n\n" +
        "Note what this cannot show. A guest whose `start_command` fails writes to the guest's " +
        "own /var/log/heyvm-start.log and that never reaches app-obs, so an empty log section " +
        "next to a pool that will not fill is a signal, not an absence of one.",
      schema: {
        id: z.string().describe("app-lb deployment id"),
        window: z.string().optional().describe("app-obs window, default '1h'"),
        namespace: z
          .string()
          .optional()
          .describe("read telemetry through this namespace's obs plugin; inferred from the credential when omitted"),
      },
      handler: async (args) => {
        const id = String(args.id);
        const window = (args.window as string) ?? "1h";
        // Resolved once and shared by both telemetry reads. A failure to
        // resolve is a section of the report, not the end of it: app-lb's
        // record is still worth showing.
        const route = telemetryRoute(clients, config, args.namespace as string | undefined);
        const r = await settle({
          deployment: clients.applb({ path: `/deployments/${encodeURIComponent(id)}` }),
          jobs: clients.applb({ path: `/deployments/${encodeURIComponent(id)}/jobs` }),
          series: route.then((rt) =>
            telemetry(clients, rt, { path: `/api/deployments/${encodeURIComponent(id)}`, query: { window } }),
          ),
          errors: route.then((rt) =>
            telemetry(clients, rt, {
              path: `/api/deployments/${encodeURIComponent(id)}/logs`,
              query: { window, level: "error", limit: 50 },
            }),
          ),
        });
        return report(`Deployment ${id} over ${window}`, [
          section("app-lb record", r.deployment),
          section("Recent jobs (builds, pulls, updates)", r.jobs),
          section("Series and summary (app-obs)", r.series),
          section("Most recent error logs", r.errors),
        ]);
      },
    },

    {
      name: "deployment_logs",
      description:
        "Log lines for one deployment, newest first, with the filters app-obs supports: " +
        "time window or explicit from/to, level, backend, a substring query, and a cursor for " +
        "paging. Collected from the daemon's native tail of each sandbox's console and its " +
        "start_command's stdout/stderr, so no shipper inside the guest is required — and " +
        "including app-lb's own events for the deployment, which is where a VM that never " +
        "booted says why, since a guest that panics has no console to tail.\n\n" +
        "A namespace-confined credential reads through that namespace's obs plugin on " +
        "app-lb, which must be installed there; an unconfined one reads APP_OBS_URL.",
      schema: {
        id: z.string().describe("app-lb deployment id"),
        window: z.string().optional().describe("e.g. '15m'; ignored when from/to are given"),
        from: z.string().optional(),
        to: z.string().optional(),
        level: z.string().optional().describe("e.g. 'error', 'warn'"),
        backend: z.string().optional().describe("restrict to one backend/sandbox"),
        q: z.string().optional().describe("substring match on the message"),
        limit: num().optional().describe("default 100"),
        before: z.string().optional().describe("cursor from a previous page"),
        namespace: z
          .string()
          .optional()
          .describe("read through this namespace's obs plugin; inferred from the credential when omitted"),
      },
      handler: async (args) => {
        const id = String(args.id);
        const route = await telemetryRoute(clients, config, args.namespace as string | undefined);
        const notVisible = (e: unknown) =>
          json({
            error:
              `no deployment ${JSON.stringify(id)} is visible to this credential, ` +
              "so its logs are not either",
            detail: e instanceof Error ? e.message : String(e),
          });
        if (route.via === "obs") {
          // The direct door reads every namespace on app-obs's own token, so
          // the wall a caller is behind has to be checked against app-lb first
          // — with the caller's own credential — before app-obs is asked.
          // Through the plugin that check is app-lb's own, on every request.
          try {
            await clients.applb({ path: `/deployments/${encodeURIComponent(id)}` });
          } catch (e) {
            return notVisible(e);
          }
        }
        const query = {
          window: args.window as string | undefined,
          from: args.from as string | undefined,
          to: args.to as string | undefined,
          level: args.level as string | undefined,
          backend: args.backend as string | undefined,
          q: args.q as string | undefined,
          limit: (args.limit as number | undefined) ?? 100,
          before: args.before as string | undefined,
        };
        try {
          return json(
            await telemetry(clients, route, {
              path: `/api/deployments/${encodeURIComponent(id)}/logs`,
              query,
            }),
          );
        } catch (e) {
          // Another namespace's deployment and one that does not exist are
          // the same 404 behind the plugin, and are said the same way here.
          if (route.via === "applb" && (e as { status?: number }).status === 404) return notVisible(e);
          throw e;
        }
      },
    },

    {
      name: "namespace_telemetry",
      description:
        "One namespace's telemetry: each deployment's requests, errors, latency, CPU and " +
        "memory over a window, plus one deployment's series and recent errors when " +
        "`deployment` is given. fleet_overview for a namespace-confined credential — call " +
        "it first for 'how are my apps doing'. Read through app-lb's obs plugin with the " +
        "caller's own credential; the plugin must be installed in the namespace, and " +
        "nothing is collected before it is.",
      schema: {
        namespace: z
          .string()
          .optional()
          .describe("namespace to read; inferred from the credential when it reaches exactly one"),
        deployment: z.string().optional().describe("also show this deployment's series and recent errors"),
        window: z.string().optional().describe("e.g. '15m', '1h', '24h'; default '1h'"),
      },
      handler: async (args) => {
        const window = (args.window as string) ?? "1h";
        const route = await telemetryRoute(clients, config, args.namespace as string | undefined);
        if (route.via !== "applb") {
          return json({
            error:
              "this credential is not confined to a namespace, so there is no namespace to " +
              "infer — pass `namespace`, or use fleet_overview for the whole fleet",
          });
        }
        const ns = route.namespace;
        const dep = args.deployment ? String(args.deployment) : undefined;
        const r = await settle({
          plugins: clients.applb({ path: `/namespaces/${encodeURIComponent(ns)}/plugins` }),
          fleet: telemetry(clients, route, { path: "/api/fleet", query: { window } }),
          series: dep
            ? telemetry(clients, route, { path: `/api/deployments/${encodeURIComponent(dep)}`, query: { window } })
            : Promise.resolve(null),
          errors: dep
            ? telemetry(clients, route, {
                path: `/api/deployments/${encodeURIComponent(dep)}/logs`,
                query: { window, level: "error", limit: 20 },
              })
            : Promise.resolve(null),
        });
        const sections: Section[] = [
          section(`Deployments in ${ns} (app-obs via ${obsPluginPrefix(ns)}/api/fleet)`, r.fleet),
          section(`Plugins installed in ${ns}`, r.plugins),
        ];
        if (dep) {
          sections.push(section(`${dep}: series and summary`, r.series));
          sections.push(section(`${dep}: most recent error logs`, r.errors));
        }
        return report(`Namespace ${ns} over ${window}`, sections);
      },
    },

    {
      name: "diagnose_vm_boot",
      description:
        "Why a VM deployment boots but never passes its health check (ready 0, boot " +
        "timeouts). Lints start_command, reads the boot counters, then runs a read-only probe " +
        "INSIDE a booting VM (waking one if needed): the start_command's captured output, any " +
        "file it redirects to, processes, listening sockets, the health path, package.json. " +
        "foreground: true also runs the start command for 15s to capture the crash. Names " +
        "known causes with the fix (Node ESM/CommonJS mismatch, missing module, port in use, " +
        "loopback bind, unwritable data path); fix the repo or spec, then redeploy.",
      schema: {
        id: z.string().describe("app-lb deployment id"),
        foreground: bool()
          .optional()
          .describe("also run the start command in the foreground for 15s to capture its crash; default false"),
        wake: bool().optional().describe("start a VM to probe if none is running; default true"),
        sandbox_id: z.string().optional().describe("probe this VM of the pool"),
      },
      handler: async (args) => {
        const id = String(args.id);
        const path = `/deployments/${encodeURIComponent(id)}`;
        const r = await settle({
          deployment: clients.applb({ path }),
          metrics: clients.applb({ path: "/metrics", query: { deployment: id, summary: "false" } }),
        });
        if (!r.deployment.ok) {
          return report(`VM boot diagnosis for ${id}`, [section("app-lb record", r.deployment)]);
        }
        const record = r.deployment.value as Record<string, unknown>;
        const spec = (record.spec ?? record) as Record<string, unknown>;
        const vm = spec.vm as Record<string, unknown> | undefined;
        if (!vm) {
          return json({ error: `deployment ${JSON.stringify(id)} is not a VM deployment` });
        }
        const port = typeof vm.port === "number" ? vm.port : undefined;
        const health = spec.health as { path?: string } | undefined;
        const parts =
          typeof vm.start_command === "string" ? parseStartCommand(vm.start_command) : undefined;

        let pool: unknown = r.metrics.ok ? r.metrics.value : undefined;
        if (r.metrics.ok) {
          const deps = (r.metrics.value as { deployments?: Array<Record<string, unknown>> }).deployments ?? [];
          const mine = deps.find((d) => d.id === id);
          if (mine) {
            pool = {
              pool: mine.pool,
              vms: mine.vms,
              pending_vms: mine.pending_vms,
              autoscale: (mine.metrics as Record<string, unknown> | undefined)?.autoscale,
            };
          }
        }

        const exec = (command: string, timeout_secs: number) =>
          clients.applb({
            method: "POST",
            path: `${path}/exec`,
            body: {
              command,
              timeout_secs,
              wake: args.wake === undefined ? true : Boolean(args.wake),
              ...(args.sandbox_id ? { sandbox_id: String(args.sandbox_id) } : {}),
            },
          });
        const probe = await settle({
          guest: exec(probeScript({ port, healthPath: health?.path, parts }), 25),
        });
        let fg: { ok: true; value: unknown } | { ok: false; error: string } | undefined;
        if (args.foreground && parts?.foreground) {
          const sandbox = probe.guest.ok
            ? (probe.guest.value as { sandbox_id?: string }).sandbox_id
            : undefined;
          fg = (
            await settle({
              run: clients.applb({
                method: "POST",
                path: `${path}/exec`,
                body: {
                  command: foregroundScript(parts),
                  timeout_secs: 25,
                  wake: false,
                  ...(sandbox ? { sandbox_id: sandbox } : {}),
                },
              }),
            })
          ).run;
        }

        const text = (x: typeof fg) =>
          x && x.ok
            ? ["output", "stdout", "stderr"]
                .map((k) => (x.value as Record<string, unknown>)[k])
                .filter((v): v is string => typeof v === "string")
                .join("\n")
            : "";
        const findings: Finding[] = [
          ...lintVmSpec(vm),
          ...interpret(`${text(probe.guest)}\n${text(fg)}`, port),
        ];
        const noVm = probe.guest.ok ? undefined : noVmFinding(probe.guest.error);
        if (noVm) findings.push(noVm);
        const seen = new Set<string>();
        const unique = findings.filter((f) => !seen.has(f.title) && seen.add(f.title));

        const sections = [
          {
            title: unique.length ? "Findings — fix these" : "Findings",
            body: unique.length
              ? unique
              : "No known signature matched. Read the guest output below; with foreground: false, " +
                "try foreground: true to capture the crash itself.",
          },
          { title: "start_command", body: vm.start_command ?? null },
          r.metrics.ok
            ? { title: "Pool and boot counters (app-lb /metrics)", body: pool }
            : section("Pool and boot counters (app-lb /metrics)", r.metrics),
          section("Inside the guest (read-only probe)", probe.guest),
        ];
        if (fg) sections.push(section("Foreground run (15s)", fg));
        return report(`VM boot diagnosis for ${id}`, sections);
      },
    },

    {
      name: "diagnose_empty_pool",
      description:
        "Why a deployment's VM pool is empty or will not fill.\n\n" +
        "Reads app-lb's /metrics, which is the endpoint that answers this — it carries the " +
        "per-deployment pool counters and the create/boot outcomes. /disks looks like it " +
        "should answer it and cannot: it describes storage, not pool state. Both are included " +
        "because a full disk is one of the two common causes, the other being scale-to-zero " +
        "churn.\n\n" +
        "If the counters show creates attempted and zero booted, the failure is inside the " +
        "guest and app-obs will not have it: a start_command that exits non-zero writes to the " +
        "guest's /var/log/heyvm-start.log, which needs a shell on the VM to read.",
      schema: { id: z.string().optional().describe("deployment id; omitted shows every pool") },
      handler: async (args) => {
        const id = args.id ? String(args.id) : undefined;
        const r = await settle({
          metrics: clients.applb({ path: "/metrics" }),
          disks: clients.applb({ path: "/disks" }),
          deployment: id
            ? clients.applb({ path: `/deployments/${encodeURIComponent(id)}` })
            : Promise.resolve(null),
        });
        return report(id ? `Pool diagnosis for ${id}` : "Pool diagnosis (all deployments)", [
          section("app-lb /metrics — the pool counters that answer this", r.metrics),
          section("app-lb /disks — storage, for the full-disk case only", r.disks),
          section("Deployment record", r.deployment),
        ]);
      },
    },

    {
      name: "diagnose_ci_job",
      description:
        "Why a ci job is not running. Joins the run and its jobs with the runner pool and the " +
        "per-subject queue depths, which is the combination that distinguishes the cases: a " +
        "job waiting on a network whose queue has no consumer, a job pinned to an offline " +
        "host, a healthy pool whose queue was consumed by something else, and a message that " +
        "was never published at all.\n\n" +
        "Requires CI_URL to reach ci's own listener. Behind an app-lb gate these routes answer " +
        "401 to any machine client regardless of token.",
      schema: { run_id: z.string().optional(), job_key: z.string().optional() },
      handler: async (args) => {
        const runId = args.run_id ? String(args.run_id) : undefined;
        const r = await settle({
          run: runId ? clients.ci({ path: `/runs/${encodeURIComponent(runId)}` }) : Promise.resolve(null),
          runners: clients.ci({ path: "/runners" }),
          vms: clients.ci({ path: "/vms" }),
        });
        return report(runId ? `ci run ${runId}` : "ci runner and pool state", [
          section("Run and its jobs", r.run),
          section("Networks, hosts, and queue depth per subject", r.runners),
          section("Warm VM pool", r.vms),
        ]);
      },
    },
  ];
}
