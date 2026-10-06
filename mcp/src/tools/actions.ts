/**
 * The mutating half, plus raw access for full coverage.
 *
 * **Destructive operations get their own named tools.** Folding them into a
 * generic `request` tool would hide a `DELETE` inside a parameter, where it is
 * invisible in a transcript and in an approval prompt. `applb_delete_deployment`
 * cannot be misread; `applb_request({method:"DELETE", ...})` can. The raw tools
 * exist below for coverage of everything not named here, and they say what they
 * are.
 *
 * Nothing here asks for confirmation on its own: MCP has no such affordance, and
 * approval belongs to the host. What this file can do is make the name and the
 * description tell the truth about what the call does, which it does.
 */

import { z } from "zod";
import { bool, num , DESTRUCTIVE_PREFIX } from "./schema.js";
import type { Clients } from "../clients/index.js";
import { json, report, type Section } from "../format.js";
import { remoteRepoOf, storeBuildCredential } from "./remote-auth.js";
import { ServiceError } from "../http.js";
import type { Tool } from "./diagnose.js";
import { cloudUsable, type Config } from "../config.js";
import { DEPLOYMENT_SPEC_FULL, DEPLOYMENT_SPEC_SCHEMA } from "../applb/spec.schema.js";
import { checkSpec, rulesFor, suffixRoutesWithoutCerts } from "../applb/rules.js";

const DESTRUCTIVE = DESTRUCTIVE_PREFIX;

/**
 * Whether a lookup of a deployment says "you cannot see one by that id".
 *
 * A 404, or the 403 app-lb gives a namespace-confined token for an id outside
 * its reach, which it also gives for an id that does not exist yet: a
 * confined token is never told whether a deployment it cannot reach exists.
 * For a register-or-edit that means "register"; if the id is taken in
 * another namespace, the POST is what refuses it.
 */
/**
 * The spec as `applb_deploy` advertises it: every top-level field and its
 * one-line description, without the nested block definitions.
 *
 * The full generated schema (`applb/spec.schema.ts`) was ~4,000 tokens of a
 * ~18,000-token tools/list, re-sent on every request, for the minority of
 * sessions that hand-write a spec (repo_deploy and heyo_guide cover the common
 * paths). applb_spec_schema returns any block in full, one call away. The
 * notes below are prepended where a field's own description invites what a
 * namespace credential may not do.
 */
export const TENANT_NOTES: Record<string, string> = {
  site: "Omit `root`; fill via `build` or `artifact`.",
  update: "Operators only: a namespace credential is refused.",
  build: "Namespace credentials: https:// repos and stores only.",
  vm: "`start_command` must return (setsid nohup … &).",
};

function topLevelSpec(full: typeof DEPLOYMENT_SPEC_SCHEMA): Record<string, unknown> {
  const props = full.properties as Record<string, { description?: string }>;
  const firstSentence = (d?: string) => (d ?? "").split(/(?<=\.)\s/)[0]?.replace(/\s+/g, " ").trim() ?? "";
  return {
    type: "object",
    description:
      "A deployment spec. Fields only; applb_spec_schema returns any block (e.g. VmSpec, SiteSpec) in full.",
    properties: Object.fromEntries(
      Object.entries(props).map(([k, v]) => {
        const d = firstSentence(v.description);
        const note = TENANT_NOTES[k];
        return [k, { description: note ? `${note} ${d}` : d }];
      }),
    ),
    required: (full as { required?: string[] }).required ?? [],
  };
}

const ADVERTISED_SPEC = topLevelSpec(DEPLOYMENT_SPEC_SCHEMA);

export function notVisible(e: ServiceError): boolean {
  return e.status === 404 || (e.status === 403 && /not scoped to deployment/.test(e.body));
}

export function actionTools(clients: Clients, config: Config): Tool[] {
  const enc = encodeURIComponent;

  return [
    // ---- app-lb reads -------------------------------------------------
    {
      name: "applb_list_deployments",
      description: "Every deployment app-lb manages, with its backends and current state.",
      schema: {},
      handler: async () => json(await clients.applb({ path: "/deployments" })),
    },
    {
      name: "applb_get_deployment",
      description:
        "One deployment in full: its spec, desired and ready replica counts, and every VM " +
        "with its health. The record to read before scaling, updating or deleting it.",
      schema: { id: z.string() },
      handler: async (a) => json(await clients.applb({ path: `/deployments/${enc(String(a.id))}` })),
    },
    {
      name: "applb_metrics",
      description:
        "app-lb's live metrics: per-deployment pool counters, request stats, and create/boot " +
        "outcomes. The endpoint that answers 'why is this pool empty'.",
      schema: {},
      handler: async () => json(await clients.applb({ path: "/metrics" })),
    },
    {
      name: "applb_disks",
      description:
        "Disk inventory and usage. Answers 'what is using space' and 'are there orphans'; " +
        "does not answer pool questions — use applb_metrics for those.",
      schema: {},
      handler: async () => json(await clients.applb({ path: "/disks" })),
    },
    {
      name: "applb_certs",
      description:
        "TLS certificates app-lb holds, with their hostname, issuer and expiry.\n\n" +
        "Read-only, and there is no endpoint that requests a certificate — so this answers " +
        "'did it arrive' and never 'please issue one'. For an exact `host` route it should: " +
        "registering nudges ACME, issuance is HTTP-01, and certificates are chosen " +
        "per-handshake from SNI, so one issued seconds ago serves without a restart.\n\n" +
        "The trap: **a `host_suffix` route never gets its own certificate.** It names a " +
        "subtree, and a subtree is covered by a fleet wildcard issued over DNS-01. A suffix " +
        "no wildcard covers is warned about once and then served a fallback certificate that " +
        "will not validate — which from outside is indistinguishable from TLS being broken, " +
        "and is not something this list will show you as an error.\n\n" +
        "Requires port 80 to reach app-lb's plaintext listener. Failures back off to a 6h " +
        "cap, so a fixed cause is not retried quickly. See the heyo://applb/tls resource.",
      schema: {},
      handler: async () => json(await clients.applb({ path: "/certs" })),
    },
    {
      name: "applb_security_events",
      description:
        "app-lb's SIEM findings: authentication abuse, attack signatures and traffic " +
        "anomalies, newest first, plus any block rules in force and the guard's counters. " +
        "This is the same data the `/siem` console renders, as JSON, behind the same gate " +
        "(`/security` is `view` tier, like `/metrics`).\n\n" +
        "Each alert carries its own `response` — a runbook (`investigate`) and the rules " +
        "ready to post to `/security/rules` (`actions`) — so 'and now what?' is in the answer " +
        "rather than something to derive. This tool only reads; acting on a finding means " +
        "POSTing a rule, which is a mutation and has no dedicated tool here — use " +
        "`applb_request` with `method: POST`, `path: /security/rules` and the `rule` object " +
        "from an alert's `actions`.\n\n" +
        "Three things that decide how to read it. The ring is in memory and bounded " +
        "(`APP_LB_SIEM_ALERT_CAPACITY`, default 512), so an app-lb restart empties it and " +
        "ids begin again — a momentary gap, not a loss, because the durable record is app-obs " +
        "and the job history. Repeats of the same finding fold into one alert whose `count` " +
        "climbs within a suppress window, so a flapping source is one row, not thousands. " +
        "And `enabled: false` with an empty list means detection is off (`APP_LB_SIEM=0`); " +
        "the `rules` still come back, because enforcement does not depend on detection.\n\n" +
        "Through the managed service the response is narrowed to the caller's namespace, so " +
        "omit `namespace` there. A self-hosted app-lb sees every alert; pass `namespace` to " +
        "filter, or `deployment` for one deployment's findings. `severity` accepts " +
        "info/low/medium/high/critical and returns that tier and above.",
      schema: {
        severity: z
          .enum(["info", "low", "medium", "high", "critical"])
          .optional()
          .describe("only alerts at or above this severity"),
        rule: z
          .string()
          .optional()
          .describe("only this rule, e.g. 'auth.brute-force' or 'traffic.scanner'"),
        deployment: z
          .string()
          .optional()
          .describe("only alerts attributed to this deployment"),
        namespace: z
          .string()
          .optional()
          .describe(
            "only alerts for deployments in this namespace; defaults to the configured " +
              "namespace in managed mode",
          ),
        limit: num().optional().describe("most recent N alerts after filtering"),
      },
      handler: async (a) =>
        json(
          await clients.applb({
            path: "/security",
            query: {
              severity: a.severity as string | undefined,
              rule: a.rule as string | undefined,
              deployment: a.deployment as string | undefined,
              namespace: a.namespace as string | undefined,
              limit: a.limit as number | undefined,
            },
          }),
        ),
    },

    // ---- app-lb lifecycle ---------------------------------------------
    {
      name: "applb_create_deployment",
      description:
        "Register a deployment from a full spec, REPLACING any deployment with the same id " +
        "and recycling its VM pool. **Prefer applb_deploy**, which carries the spec's schema, " +
        "checks the cross-field rules before app-lb has to, chooses between registering and " +
        "editing, and starts the right job afterwards. This is the primitive underneath it, " +
        "for when you want exactly a POST and nothing else.\n\n" +
        "Through the managed service the namespace is the configured one and need not be " +
        "given. A POST whose `id` already exists REPLACES that deployment and recycles its " +
        "VM pool — use applb_get_deployment first if unsure, and applb_scale for a " +
        "scaling-only change.\n\n" +
        "What the schema cannot state, because it is a relationship between fields rather " +
        "than a field: exactly one of `vm`, `upstreams` or `site`; `build` and `artifact` " +
        "are mutually exclusive; `vm.workspace` forces max_replicas 1, warm_pool 0 and the " +
        "firecracker driver. **applb_spec_schema returns every such rule**, plus the full " +
        "detail of any block this tool summarises. TLS for an exact `host` route is " +
        "automatic and needs no second call; a `host_suffix` route never gets its own " +
        "certificate.",
      // Deliberately permissive, and deliberately *not* a transcription of the
      // schema above. app-lb accepts unknown fields — `DeploymentSpec` has no
      // `deny_unknown_fields`, and heyctl edits specs as untyped JSON so a field
      // it has never heard of survives the trip. A client that validated
      // strictly here would reject specs the server would happily take, which is
      // a worse failure than an under-described one.
      schema: { spec: z.record(z.unknown()).describe("the deployment spec; see inputSchema") },
      handler: async (a) =>
        json(await clients.applb({ method: "POST", path: "/deployments", body: a.spec })),
    },
    {
      name: "applb_spec_schema",
      description:
        "The deployment spec in full: every field of a named block with its complete " +
        "documentation, plus the cross-field rules that apply to it. Read this when " +
        "applb_deploy's schema summarises a block you need to write — `auth`, " +
        "`jwt`, `mounts`, `workspace` — or when a spec was refused and the reason names a " +
        "rule rather than a field.\n\n" +
        "Generated from app-lb's own types, so it cannot disagree with what the server " +
        "accepts. With no `block`, returns the list of blocks and every rule.",
      schema: {
        block: z
          .string()
          .optional()
          .describe(
            'a block name such as "VmSpec", "AuthGate", "JwtSpec", "MountSpec", ' +
              '"ScalingPolicy" or "BuildSpec"; omit for the index and all rules',
          ),
      },
      handler: async (a) => {
        const defs = (DEPLOYMENT_SPEC_FULL.$defs ?? {}) as Record<string, unknown>;
        const block = typeof a.block === "string" ? a.block.trim() : "";
        if (!block) {
          return json({
            blocks: Object.keys(defs).sort(),
            top_level: DEPLOYMENT_SPEC_FULL.properties,
            required: DEPLOYMENT_SPEC_FULL.required,
            rules: rulesFor().map((r) => r.rule),
          });
        }
        // Case-insensitively, because a caller reading `vm.workspace` in a spec
        // is more likely to ask for "workspace" than for "WorkspaceSpec".
        const key =
          Object.keys(defs).find((k) => k.toLowerCase() === block.toLowerCase()) ??
          Object.keys(defs).find((k) => k.toLowerCase().startsWith(block.toLowerCase()));
        if (!key) {
          return json({
            error: `no block named ${block}`,
            blocks: Object.keys(defs).sort(),
          });
        }
        return json({ block: key, schema: defs[key], rules: rulesFor(key).map((r) => r.rule) });
      },
    },
    {
      name: "applb_deploy",
      description:
        "Just files, no spec? repo_deploy fits better; see heyo_guide.\n\n" +
        "Takes a full spec and does the whole sequence: " +
        "checks the rules a schema cannot express, registers or edits as appropriate, starts " +
        "the job that matches the backend, waits for it, and reports what TLS will do.\n\n" +
        "The `spec` parameter carries app-lb's own generated schema — every field, type and " +
        "default — so a spec can be written from this tool alone. applb_spec_schema returns " +
        "any block in full, plus the rules that constrain it.\n\n" +
        "Three things it gets right that are easy to get wrong by hand. It uses PUT for an " +
        "existing deployment, which **preserves the VM pool** when the `vm` block is " +
        "unchanged, where a plain register recycles it. It picks the job by backend — " +
        "`build` for a Dockerfile, `pull` for bytes from a store, `host_update` for a static " +
        "deployment's own commands — where choosing wrong is refused rather than ignored. " +
        "And it tells you when a `host_suffix` route will not get its own certificate.\n\n" +
        "If your token is confined to a namespace, set `namespace` in the spec to it: " +
        "registering does not fill it in, and the default is `default`, which such a token " +
        "cannot reach.\n\n" +
        "`wait_seconds` bounds the poll only; the job continues regardless and applb_job " +
        "reports it.",
      // The one tool carrying the spec schema. A second copy would be ~12 KB on
      // every connect for every client, so the primitives point here instead.
      inputSchema: {
        type: "object",
        properties: {
          spec: ADVERTISED_SPEC,
          wait_seconds: {
            type: "number",
            description: "how long to poll the job before returning; default 120, 0 to skip",
          },
        },
        required: ["spec"],
      },
      schema: {
        spec: z.record(z.unknown()).describe("the deployment spec; see inputSchema"),
        wait_seconds: num().optional().describe("poll the job for this long; default 120"),
      },
      handler: async (a) => {
        const spec = a.spec as Record<string, unknown>;
        const id = String(spec?.id ?? "");
        const sections: Section[] = [];

        // Locally first. app-lb would refuse these too, but its answer is a
        // SpecError in a 400 body after a round trip; naming the rule in the
        // caller's own vocabulary before spending that is the point of a
        // composite.
        // A namespace token's own namespace: fill it in when the spec leaves it
        // out (app-lb refuses a spec it cannot place), and check the spec as a
        // tenant's.
        const ownNs = await clients.applbNamespace().catch(() => undefined);
        if (ownNs && spec && typeof spec === "object" && !spec.namespace) {
          spec.namespace = ownNs;
          sections.push({ title: "Namespace", body: `\`namespace\` was not set; using your token's, ${ownNs}.` });
        }
        // A tenant's site root is app-lb's to assign. A spec copied from
        // applb_get_deployment carries the assigned one; drop it rather than
        // refuse a spec that only echoes what app-lb said.
        const site = spec?.site as Record<string, unknown> | undefined;
        if (ownNs && site && site.root !== undefined) {
          delete site.root;
          sections.push({ title: "site.root", body: "removed: app-lb assigns a namespace's site roots itself." });
        }
        // A tenant's tags are private and a namespace cannot hold the store's
        // key, so a pull with no `auth` is refused unless the repo is public.
        const art = spec?.artifact as Record<string, unknown> | undefined;
        if (ownNs && art && !art.auth) {
          sections.push({
            title: "Artifact access",
            body:
              "app-lb pulls this tag without a credential, so it fails with 401 unless the tag's repo " +
              "is public. To keep it private, deploy from a repo instead (heyo_guide deploy-static-site).",
          });
        }
        const problems = checkSpec(spec, { confined: Boolean(ownNs) });
        // An artifact store this server does not know is almost always a
        // guessed URL (a region with no store of its own); the pull fails
        // with nothing to retry.
        const artStore = (spec?.artifact as { store?: unknown } | undefined)?.store;
        if (typeof artStore === "string" && config.art && /^https?:\/\//.test(artStore)) {
          const want = new URL(config.art.baseUrl).host;
          let got = "";
          try {
            got = new URL(artStore).host;
          } catch {
            /* checkSpec reports a malformed URL */
          }
          if (got && got !== want) {
            problems.push(
              `\`artifact.store\` is ${artStore}, but this region's store is ${config.art.baseUrl}. ` +
                "Use that URL (art_publish_files' result gives the exact block).",
            );
          }
        }
        if (problems.length > 0) {
          return report(`${id || "spec"}: not sent — ${problems.length} rule(s) broken`, [
            { title: "Rules this spec breaks", body: problems },
            {
              title: "Next",
              body: "Fix these and call again. applb_spec_schema returns the full schema for " +
                "any block, with the rules that apply to it.",
            },
          ]);
        }
        if (!id) return "The spec has no `id`, so there is nothing to register.";

        // A repo on this server's git remote is private: without
        // `build.auth`, app-lb clones it anonymously and the build dies at
        // "could not read Username". Add the credential `repo_deploy` would.
        const build = spec.build as Record<string, unknown> | undefined;
        const onRemote = build && !build.auth ? remoteRepoOf(config, build.repo) : undefined;
        if (build && onRemote) {
          const ns =
            (typeof spec.namespace === "string" && spec.namespace) ||
            (await clients.applbNamespace().catch(() => undefined));
          const cred = await storeBuildCredential(clients, onRemote, id, ns || undefined);
          build.auth = cred.auth;
          sections.push({
            title: "Build credential",
            body:
              `build.repo is on the Heyo git remote, so a read token (${cred.tokenId}) for ` +
              `${onRemote.namespace}/${onRemote.repo} was stored as app-lb secret ${cred.secretId} ` +
              "and set as build.auth.",
          });
        }

        // Exists or not decides POST vs PUT, and that decides whether the pool
        // survives. A 404 here is the normal create path, not an error.
        let exists = false;
        let previousVm: unknown;
        try {
          const current = (await clients.applb({ path: `/deployments/${enc(id)}` })) as {
            spec?: { vm?: unknown };
            vm?: unknown;
          };
          exists = true;
          previousVm = current?.spec?.vm ?? current?.vm;
        } catch (e) {
          if (!(e instanceof ServiceError && notVisible(e))) throw e;
        }

        const registered = await clients.applb({
          method: exists ? "PUT" : "POST",
          path: exists ? `/deployments/${enc(id)}` : "/deployments",
          body: spec,
        });
        const vmChanged =
          exists && JSON.stringify(previousVm ?? null) !== JSON.stringify(spec.vm ?? null);
        sections.push({
          title: exists ? "Edited (PUT)" : "Registered (POST)",
          body: exists
            ? {
                pool: vmChanged
                  ? "REBUILDING — the `vm` template changed, so the running VMs are replaced"
                  : "preserved — the `vm` template is unchanged, so running VMs are untouched",
                deployment: registered,
              }
            : registered,
        });

        // The job that matches the backend. Picking by what the spec contains
        // is what makes the wrong choice unrepresentable.
        const backend = spec.vm ? "vm" : spec.site ? "site" : "upstreams";
        const job =
          spec.build && (backend === "vm" || backend === "site")
            ? { path: "build", tool: "applb_build" }
            : spec.artifact && (backend === "vm" || backend === "site")
              ? { path: "pull", tool: "applb_pull" }
              : spec.update && (backend === "upstreams" || backend === "site")
                ? { path: "update", tool: "applb_host_update" }
                : undefined;

        // `/jobs/:id` is a fleet-wide route a namespace token may not use;
        // the deployment's own job list is not, and holds the same record.
        let jobsByDeployment = false;
        const readJob = async (dep: string, jid: string): Promise<Record<string, unknown> | undefined> => {
          if (!jobsByDeployment) {
            try {
              return (await clients.applb({ path: `/jobs/${enc(jid)}` })) as Record<string, unknown>;
            } catch (e) {
              if (!(e instanceof ServiceError && e.status === 403)) throw e;
              jobsByDeployment = true;
            }
          }
          const list = (await clients.applb({ path: `/deployments/${enc(dep)}/jobs` })) as unknown;
          const rows = Array.isArray(list) ? (list as Record<string, unknown>[]) : [];
          return rows.find((r) => r.id === jid);
        };

        let jobId: string | undefined;
        if (job) {
          const started = (await clients.applb({
            method: "POST",
            path: `/deployments/${enc(id)}/${job.path}`,
            ...(job.path === "update" ? {} : { body: {} }),
          })) as { id?: unknown };
          jobId = typeof started?.id === "string" ? started.id : undefined;
          sections.push({ title: `Started ${job.tool}`, body: started });
        } else {
          sections.push({
            title: "No job started",
            body:
              `A ${backend} deployment with no ` +
              (backend === "upstreams" ? "`update`" : "`build`, `artifact` or `update`") +
              " block has nothing to roll onto; app-lb serves it as registered.",
          });
        }

        const wait = a.wait_seconds === undefined ? 120 : Number(a.wait_seconds);
        if (jobId && wait > 0) {
          const deadline = Date.now() + wait * 1000;
          let last: Record<string, unknown> | undefined;
          while (Date.now() < deadline) {
            last = await readJob(id, jobId);
            const status = String(last?.status ?? "");
            if (status && !["queued", "running", "pending"].includes(status)) break;
            await new Promise((r) => setTimeout(r, 3000));
          }
          sections.push({ title: `Job ${jobId}`, body: last ?? "no status read" });
        }

        // A site whose root cannot serve registers fine and then 404s every
        // request, because the root is read on the app-lb host. app-lb says so
        // in `site`; repeat it where it will be read. Re-read after the job,
        // which is what fills the root.
        if (backend === "site") {
          const now = (await clients
            .applb({ path: `/deployments/${enc(id)}` })
            .catch(() => registered)) as { site?: { status?: string; hint?: string } } | undefined;
          if (now?.site && (now.site.status !== "ok" || now.site.hint)) {
            sections.push({
              title: `Site root: ${now.site.status}`,
              body:
                (now.site.hint ?? "") +
                " \"missing\": nothing has written the root yet; \"empty\": it exists with no files." +
                (spec.build || spec.artifact
                  ? " If the job above failed, fix it and run it again."
                  : " With no `build` or `artifact`, nothing will fill it: repo_deploy (kind site) " +
                    "puts a repo's files there, or art_publish_files with `deployment` puts a bundle there."),
            });
          }
        }

        // A VM whose image comes from a build or a pull runs nothing unless
        // start_command says so: the rootfs drops the image's CMD.
        const vmBlock = spec.vm as Record<string, unknown> | undefined;
        if (vmBlock && (spec.build || spec.artifact) && !vmBlock.start_command) {
          sections.push({
            title: "No start_command",
            body:
              "A VM does not run the image's CMD or ENTRYPOINT, so with no `vm.start_command` the app " +
              "never starts and the pool never becomes ready. Add one that returns " +
              "(`cd /app && setsid nohup node server.js </dev/null >/var/log/app.log 2>&1 &`); " +
              "repo_deploy derives it from the Dockerfile.",
          });
        }

        // TLS, which nothing else on the surface would have told them.
        const suffixes = suffixRoutesWithoutCerts(spec);
        if (suffixes.length > 0) {
          sections.push({
            title: "TLS warning",
            body:
              `These are host_suffix routes and NEVER get their own certificate: ` +
              `${suffixes.join(", ")}. A subtree's certificate is a fleet wildcard; one no ` +
              `wildcard covers is served a fallback that will not validate. Exact host ` +
              `routes are issued automatically within seconds. See heyo://applb/tls.`,
          });
        }

        sections.push({
          title: "Next",
          body: [
            jobId
              ? `applb_job {job_id: "${jobId}", deployment: "${id}"} — the job continues whether or not this waited`
              : null,
            "applb_metrics — whether replicas became healthy",
            "applb_certs — whether app-lb holds a certificate for each exact host",
            config.obs ? "deployment_logs — what the application itself said" : "diagnose_deployment — the record and its jobs in one call",
          ].filter(Boolean),
        });

        return report(`${id}: ${exists ? "edited" : "registered"}`, sections);
      },
    },
    {
      name: "applb_drain_upstream",
      description:
        DESTRUCTIVE +
        "Take one upstream of a STATIC (`upstreams`) deployment out of rotation. In-flight " +
        "requests finish; no new ones are routed to it.\n\n" +
        "For taking a backend out to work on it without editing the spec — an edit would have " +
        "to be undone, and forgetting to undo it is how an upstream stays missing. " +
        "applb_uncordon_upstream puts it back. The upstream is named exactly as it appears in " +
        "the spec, `host:port`.",
      schema: {
        id: z.string(),
        upstream: z.string().describe("`host:port`, exactly as the spec spells it"),
      },
      handler: async (a) =>
        json(
          await clients.applb({
            method: "PUT",
            path: `/deployments/${enc(String(a.id))}/upstreams/${enc(String(a.upstream))}/drain`,
          }),
        ),
    },
    {
      name: "applb_uncordon_upstream",
      description:
        "Put a drained upstream back into rotation. The inverse of applb_drain_upstream; it " +
        "starts taking traffic again once it passes its health check.",
      schema: {
        id: z.string(),
        upstream: z.string().describe("`host:port`, exactly as the spec spells it"),
      },
      handler: async (a) =>
        json(
          await clients.applb({
            method: "DELETE",
            path: `/deployments/${enc(String(a.id))}/upstreams/${enc(String(a.upstream))}/drain`,
          }),
        ),
    },
    {
      name: "applb_update_deployment",
      description:
        "Edit an existing deployment in place, replacing its whole spec.\n\n" +
        "**The distinction that matters: this PRESERVES the VM pool when the `vm` block is " +
        "unchanged.** A scaling, route, health or auth edit never disturbs running VMs; only " +
        "a change to `vm` reboots them, because the existing machines were built from the old " +
        "template. applb_create_deployment re-registers and recycles the pool regardless, so " +
        "for an edit this is the tool and that one is not.\n\n" +
        "The whole spec is replaced, not merged — read applb_get_deployment first and send it " +
        "back changed. The path id wins, so the body cannot retarget another deployment. The " +
        "spec's schema is on applb_deploy; applb_spec_schema has it in full.",
      schema: {
        id: z.string(),
        spec: z
          .record(z.unknown())
          .describe(
            "the complete replacement spec — see applb_deploy's schema, or " +
              "applb_spec_schema for any block in full",
          ),
      },
      handler: async (a) =>
        json(
          await clients.applb({
            method: "PUT",
            path: `/deployments/${enc(String(a.id))}`,
            body: a.spec,
          }),
        ),
    },
    {
      name: "applb_scale",
      description:
        "Change a deployment's scaling parameters. Takes effect on the next reconcile; " +
        "scaling to zero lets the pool drain, which is not instant.\n\n" +
        "A PARTIAL policy: only the fields you send are changed and the rest are kept, so " +
        "`{min_replicas: 2}` does not reset the timeouts it does not mention. Never touches " +
        "the VM template, so the pool is always preserved — which is why this is the tool for " +
        "a scaling-only change rather than applb_update_deployment.",
      // The generated `ScalingPolicy`, straight from app-lb's own type. Every
      // field defaults there, so it has no `required` and is already the right
      // shape for a patch body.
      inputSchema: {
        type: "object",
        properties: {
          id: { type: "string" },
          scaling: {
            ...(DEPLOYMENT_SPEC_SCHEMA.$defs as Record<string, object>).ScalingPolicy,
            description: "the fields to change; anything omitted is left as it is",
          },
        },
        required: ["id", "scaling"],
      },
      schema: {
        id: z.string(),
        scaling: z.record(z.unknown()).describe("the fields to change; see inputSchema"),
      },
      handler: async (a) =>
        json(
          await clients.applb({
            method: "PATCH",
            path: `/deployments/${enc(String(a.id))}/scaling`,
            body: a.scaling,
          }),
        ),
    },
    {
      name: "applb_build",
      description:
        "Build a managed (`vm`) deployment's image from its `build` block and roll the pool " +
        "onto it. Returns a job immediately; poll applb_job with the id it returns.\n\n" +
        "The recipe is the deployment's own `build` block — a git checkout or a Dockerfile " +
        "manifest in a store — not this call. `ref` overrides the version for THIS build only " +
        "and does not become the deployment's default, which is what a hotfix build looks " +
        "like. It is checked against whichever source the spec names, so a git ref given to a " +
        "store-backed deployment is refused here rather than minutes into a build.\n\n" +
        "For a deployment whose image comes from an artifact store rather than a Dockerfile, " +
        "the tool is applb_pull. A site with a `build` block also uses this tool; " +
        "applb_host_update is only for operator `update` blocks.",
      schema: {
        id: z.string(),
        git_ref: z
          .string()
          .optional()
          .describe("branch, commit, tag or digest to build instead of the spec's; one-off"),
      },
      handler: async (a) =>
        json(
          await clients.applb({
            method: "POST",
            path: `/deployments/${enc(String(a.id))}/build`,
            body: a.git_ref === undefined ? {} : { ref: a.git_ref },
          }),
        ),
    },
    {
      name: "applb_pull",
      description:
        "Materialize a `vm` or `site` deployment's bytes from an artifact store and roll it " +
        "onto them. Returns a job; poll applb_job.\n\n" +
        "**This is what rolls a managed deployment onto a new image**, and the usual next " +
        "step after art_publish. It reads the deployment's `artifact` block; `ref` overrides " +
        "the reference for this pull only and does not become the default, so " +
        "`{ref: \"<digest>\"}` is what a rollback to known bytes looks like.\n\n" +
        "`force` re-fetches something already on disk. Rarely wanted — the filename IS the " +
        "digest, so the file being there is proof the bytes are right — and it exists for a " +
        "file damaged after it was written.\n\n" +
        "Does not apply to a static (`upstreams`) deployment, which has no image; that is " +
        "applb_host_update. A deployment whose image comes from a Dockerfile wants applb_build.",
      schema: {
        id: z.string(),
        artifact_ref: z
          .string()
          .optional()
          .describe("tag or digest to pull instead of the spec's; one-off, not stored"),
        force: bool().optional().describe("re-fetch even when the image is already on disk"),
      },
      handler: async (a) =>
        json(
          await clients.applb({
            method: "POST",
            path: `/deployments/${enc(String(a.id))}/pull`,
            body: {
              ...(a.artifact_ref === undefined ? {} : { ref: a.artifact_ref }),
              ...(a.force === undefined ? {} : { force: a.force }),
            },
          }),
        ),
    },
    {
      name: "applb_pull_mounts",
      description:
        "Re-unpack the guest mounts a `vm` deployment declares, from their artifact stores. " +
        "Returns a job; poll applb_job, whose `mounts` array reports each tree separately.\n\n" +
        "Registration already starts this automatically, so this is for re-fetching after a " +
        "mount's tag moved. `force` re-fetches trees already on this host, which is rarely " +
        "wanted for the same reason a pull's `force` is.",
      schema: {
        id: z.string(),
        force: bool().optional().describe("re-fetch trees already present on the host"),
      },
      handler: async (a) =>
        json(
          await clients.applb({
            method: "POST",
            path: `/deployments/${enc(String(a.id))}/mounts/pull`,
            body: a.force === undefined ? {} : { force: a.force },
          }),
        ),
    },
    {
      name: "applb_host_update",
      description:
        "Run a STATIC (`upstreams`) or `site` deployment's own `update.commands` on the app-lb " +
        "host, then re-probe its upstreams. Returns a job; poll applb_job.\n\n" +
        "**It does not roll VMs, and a managed (`vm`) deployment is refused.** The commands run " +
        "on this host in `update.working_dir` — `git pull && cargo build && systemctl restart` " +
        "is the shape — so what moves is the code answering on upstreams that do not change. " +
        "A deployment with no `update` block has nothing to run and is refused too.\n\n" +
        "For a managed deployment the tool you want is applb_pull (new bytes from a store) or " +
        "applb_build (a new image from a Dockerfile). This tool was previously named " +
        "applb_start_update and described as rolling VMs, which it has never done.",
      schema: { id: z.string() },
      handler: async (a) =>
        json(
          await clients.applb({
            method: "POST",
            path: `/deployments/${enc(String(a.id))}/update`,
          }),
        ),
    },
    {
      name: "applb_job",
      description:
        "One job by its id — what applb_build, applb_pull, applb_pull_mounts and " +
        "applb_host_update each return. THE call to make after starting any of them: they " +
        "answer as soon as the work is scheduled, not when it is done.\n\n" +
        "For every job on one deployment rather than one job by id, use applb_deployment_jobs.",
      schema: {
        job_id: z.string(),
        deployment: z
          .string()
          .optional()
          .describe("its deployment; needed with a namespace token"),
      },
      handler: async (a) => {
        const jid = String(a.job_id);
        try {
          return json(await clients.applb({ path: `/jobs/${enc(jid)}` }));
        } catch (e) {
          // `/jobs/:id` is fleet-wide; a namespace token reads the same record
          // from its deployment's job list.
          if (!(e instanceof ServiceError && e.status === 403)) throw e;
          if (!a.deployment) {
            throw new Error(
              `${e.message}\n\nThis token may not read jobs by id alone. Call applb_job again ` +
                "with `deployment` set to the job's deployment id, or use applb_deployment_jobs.",
            );
          }
          const list = (await clients.applb({ path: `/deployments/${enc(String(a.deployment))}/jobs` })) as unknown;
          const row = (Array.isArray(list) ? (list as Record<string, unknown>[]) : []).find((r) => r.id === jid);
          if (!row) throw new Error(`No job ${jid} on deployment ${String(a.deployment)}.`);
          return json(row);
        }
      },
    },
    {
      name: "applb_deployment_jobs",
      description: "Recent build/pull/update jobs for a deployment, with their outcomes.",
      schema: { id: z.string() },
      handler: async (a) => json(await clients.applb({ path: `/deployments/${enc(String(a.id))}/jobs` })),
    },

    // ---- app-lb destructive -------------------------------------------
    {
      name: "applb_delete_deployment",
      description:
        DESTRUCTIVE +
        "Deregisters a deployment from app-lb and tears down its backends. The deployment " +
        "stops serving immediately. Not reversible from here — it must be registered again.",
      schema: { id: z.string() },
      handler: async (a) =>
        json(await clients.applb({ method: "DELETE", path: `/deployments/${enc(String(a.id))}` })),
    },
    {
      name: "applb_evict_vm",
      description:
        DESTRUCTIVE +
        "Removes one VM from a deployment's pool and destroys it. In-flight requests on that " +
        "VM are lost. The pool replaces it only if scaling allows.",
      schema: { id: z.string(), sandbox_id: z.string() },
      handler: async (a) =>
        json(
          await clients.applb({
            method: "DELETE",
            path: `/deployments/${enc(String(a.id))}/vms/${enc(String(a.sandbox_id))}`,
          }),
        ),
    },
    {
      name: "applb_purge_disk",
      description:
        DESTRUCTIVE + "Permanently deletes one disk and everything on it. There is no undo.",
      schema: { disk_id: z.string() },
      handler: async (a) =>
        json(await clients.applb({ method: "DELETE", path: `/disks/${enc(String(a.disk_id))}` })),
    },
    {
      name: "applb_purge_orphan_disks",
      description:
        DESTRUCTIVE +
        "Deletes every disk app-lb considers orphaned, in one call. Read applb_disks first and " +
        "confirm the list is what you expect — 'orphaned' is app-lb's inference, not a fact, " +
        "and a disk belonging to something app-lb has lost track of looks identical.",
      schema: {},
      handler: async () => json(await clients.applb({ method: "POST", path: "/disks/purge-orphans" })),
    },
    {
      name: "applb_sweep_disks",
      description:
        DESTRUCTIVE +
        "Runs the disk expiry sweep now instead of waiting for the next tick, deleting every " +
        "disk past its TTL. Its two siblings — applb_purge_disk and applb_purge_orphan_disks " +
        "— were marked destructive and this was not, although it deletes gigabytes by the " +
        "same mechanism and with no undo. Holds are respected: a claimed or retained disk is " +
        "skipped and counted.",
      schema: {},
      handler: async () => json(await clients.applb({ method: "POST", path: "/disks/sweep" })),
    },
    {
      name: "applb_exec",
      description:
        DESTRUCTIVE +
        "Runs a command inside a deployment's guest and returns its output. Arbitrary code " +
        "execution on a production VM — the same power as a shell. Useful for reading a guest " +
        "file nothing exports, notably /var/log/heyvm-start.log when a start_command fails and " +
        "app-obs has nothing.",
      // Flattened out of a `body` blob, which mattered more here than anywhere
      // else on this server: this is arbitrary code execution on a production
      // VM, and while the command lived inside an untyped object it was
      // invisible in the schema, in the transcript, and in whatever approval
      // prompt a host renders from the schema — which showed a parameter named
      // `body` of type `object`. What is about to be run should be readable
      // before it is approved. The shape also now matches sandbox_exec.
      schema: {
        id: z.string(),
        command: z.string().describe("run through `sh -c` in the guest"),
        cwd: z.string().optional(),
        env: z.record(z.string()).optional(),
        timeout_secs: num().optional(),
        wake: bool()
          .optional()
          .describe(
            "boot or resume a VM if none is running; default true. false asks for a 409 " +
              "instead of waiting",
          ),
        sandbox_id: z
          .string()
          .optional()
          .describe("run in THIS VM of the pool rather than whichever is offered"),
      },
      handler: async (a) =>
        json(
          await clients.applb({
            method: "POST",
            path: `/deployments/${enc(String(a.id))}/exec`,
            body: {
              command: a.command,
              ...(a.cwd === undefined ? {} : { cwd: a.cwd }),
              ...(a.env === undefined ? {} : { env: a.env }),
              ...(a.timeout_secs === undefined ? {} : { timeout_secs: a.timeout_secs }),
              ...(a.wake === undefined ? {} : { wake: a.wake }),
              ...(a.sandbox_id === undefined ? {} : { sandbox_id: a.sandbox_id }),
            },
          }),
        ),
    },

    // ---- ci reads --------------------------------------------------------
    {
      name: "ci_run_status",
      description:
        "Whether a ci run has finished and whether it worked, with every job and step. THE " +
        "call to make after submitting a build — without it, a run in progress and a run " +
        "that died look identical, and silence reads as failure when it usually means " +
        "'still going'.\n\n" +
        "Read `run.finished` rather than interpreting `run.status`: 'queued' and 'running' " +
        "are both not-yet, and a status this client has never heard of is deliberately not " +
        "finished. A run that is not finished is not a failed run, however long it has been " +
        "— builds here routinely take tens of minutes.\n\n" +
        "Each job carries `queue_wait_secs`, which separates the two diagnoses a stuck run " +
        "has: a large and growing wait means nothing ever claimed the job (check " +
        "diagnose_ci_job for a queue with no consumer), while a job that started and is " +
        "still running is simply slow.\n\n" +
        "Works against ci's public hostname: this route is in public_paths and takes the " +
        "repository submit token, so CI_TOKEN should be the value `git submit` uses " +
        "(`git config ci.token`). A token for a different repository answers 404, not 401.",
      schema: { run_id: z.string() },
      handler: async (a) => json(await clients.ci({ path: `/api/runs/${enc(String(a.run_id))}` })),
    },
    {
      name: "ci_run_logs",
      description:
        "What a run printed, per job and step. The follow-up to ci_run_status when a run " +
        "failed and the question is why.\n\n" +
        "Returns the TAIL of each step's log — a failure is at the end — capped, with " +
        "`truncated` saying whether anything was cut. `failed_only` narrows to the steps that " +
        "did not succeed, and `job` to one job by its key.\n\n" +
        "The two steps at negative indices are the executor's own and are where a job that " +
        "failed before its first declared step explains itself: 'VM console' (-2) and " +
        "'checkout' (-1). A run whose logs have been swept returns its rows with `log` null " +
        "and the byte counts intact, which is not the same as a run that printed nothing.",
      schema: {
        run_id: z.string(),
        job: z.string().optional().describe("one job by key; default every job"),
        tail: num().optional().describe("bytes per step from the end; default 16384"),
        failed_only: bool().optional().describe("only steps that did not succeed"),
      },
      handler: async (a) =>
        json(
          await clients.ci({
            path: `/api/runs/${enc(String(a.run_id))}/logs`,
            query: {
              job: a.job as string | undefined,
              tail: a.tail as number | undefined,
              failed_only: a.failed_only === undefined ? undefined : String(a.failed_only),
            },
          }),
        ),
    },

    // ---- ci mutations ----------------------------------------------------
    {
      name: "ci_cancel_run",
      description:
        DESTRUCTIVE +
        "Cancels a ci run and every unfinished job in it. Work already running is stopped at " +
        "its next step boundary.",
      schema: { run_id: z.string() },
      handler: async (a) =>
        json(await clients.ci({ method: "POST", path: `/runs/${enc(String(a.run_id))}/cancel` })),
    },
    {
      name: "ci_destroy_vm",
      description: DESTRUCTIVE + "Destroys one pooled ci VM. A claimed VM is refused.",
      schema: { sandbox_id: z.string() },
      handler: async (a) =>
        json(await clients.ci({ method: "POST", path: `/vms/${enc(String(a.sandbox_id))}/destroy` })),
    },
    {
      name: "ci_cleanup_failed_vms",
      description:
        DESTRUCTIVE + "Destroys every idle ci VM whose last run failed. Claimed VMs are refused.",
      schema: {},
      handler: async () => json(await clients.ci({ method: "POST", path: "/vms/cleanup-failed" })),
    },

    // ---- raw, for everything not named above ---------------------------
    ...(
      [
        // Gated with the sandbox tools it shares a credential with. It was
        // listed unconditionally while targeting cloud, so on a
        // fleet-operations instance it advertised a door that could only ever
        // answer `NotConfigured` — the same thing `buildTools` withholds the
        // sandbox tools to avoid.
        ...(cloudUsable(config)
          ? ([{ key: "cloud", tool: "heyo_request", label: "heyo cloud" }] as const)
          : []),
        { key: "applb", tool: "applb_request", label: "app-lb" },
        { key: "obs", tool: "obs_request", label: "app-obs" },
        { key: "ci", tool: "ci_request", label: "ci" },
      ] as const
    ).map(({ key, tool, label }) => ({
      name: tool,
      description:
        `Raw HTTP against ${label}, for endpoints without a dedicated tool above. Full ` +
        "surface, including methods that destroy things — prefer a named tool when one " +
        "exists, because this one's intent is invisible until the arguments are read.",
      schema: {
        // Upper-cased before the enum sees it. Until arguments were parsed a
        // lowercase `get` reached `fetch` and worked, so validating the enum
        // alone would start refusing calls that have always been fine — for a
        // difference no HTTP server cares about. `preprocess` rather than
        // `.transform`, which runs *after* the check it would need to help.
        method: z
          .preprocess(
            (v) => (typeof v === "string" ? v.toUpperCase() : v),
            z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
          )
          .default("GET"),
        path: z.string().describe("path beginning with '/'"),
        query: z.record(z.string()).optional(),
        body: z.unknown().optional(),
      },
      handler: async (a: Record<string, unknown>) =>
        json(
          await clients[key]({
            method: a.method as string,
            path: String(a.path),
            query: a.query as Record<string, string> | undefined,
            body: a.body,
          }),
        ),
    })),
  ];
}
