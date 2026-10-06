/**
 * The server definition, independent of how it is reached.
 *
 * Split from the entrypoints because the same tools serve two transports:
 * stdio, where the host launches the process and identity is whoever ran it,
 * and HTTP, where app-lb's gate has already decided who the caller is.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { zodToJsonSchema } from "zod-to-json-schema";
import { z } from "zod";

import { cloudUsable, type Config } from "./config.js";
import { makeClients } from "./clients/index.js";
import { registerResources } from "./resources.js";
import { diagnosticTools, type Tool } from "./tools/diagnose.js";
import { DESTRUCTIVE_PREFIX } from "./tools/schema.js";
import { actionTools } from "./tools/actions.js";
import { sandboxTools } from "./tools/sandbox.js";
import { feedTools } from "./tools/feed.js";
import { artifactTools } from "./tools/artifacts.js";
import { repoTools } from "./tools/repos.js";
import { explainFailure, guideTool } from "./tools/guide.js";

/**
 * The tools this configuration can actually serve.
 *
 * Every group but one is unconditional: an unreachable app-lb, app-obs or ci
 * still gets its tools listed, because `bind` turns the absence into a
 * `NotConfigured` error naming the variable to set, and that is a better answer
 * than a tool that silently does not exist.
 *
 * The sandbox tools are the exception, and the reason is that their absence is
 * a *deployment shape* rather than a misconfiguration. An instance behind an
 * app-token gate has no cloud credential to act with and no way to get one — the
 * gate admits `applb_…` tokens, which cloud cannot consume — so listing the
 * sandbox tools there advertises capability the caller can never reach. A
 * fleet-operations instance is a complete thing, not a broken one.
 *
 * (The count is asserted in `listing.test.ts` rather than named here. It used
 * to say "sixteen" and the real number was fifteen — a number in a comment is
 * a mirror, and mirrors drift.)
 *
 * Gated on {@link cloudUsable} rather than on a switch of its own, because that
 * is exactly the condition: `makeClients` treats an unusable cloud as absent for
 * the same reason, and the two must use the same predicate or the tools are
 * listed by one and refused by the other. "Usable" means present *and* not an
 * `applb_…` token — a credential cloud cannot accept is not a credential. And because {@link withForwardedAuth} may supply it
 * per-request, this stays correct for a hosted instance carrying no key of its
 * own — a caller presenting a `heyo_api_*` key gets the sandbox tools, and one
 * presenting an app-lb token does not.
 *
 * `heyo_status` still reports cloud either way, so "this server has no sandbox
 * tools" remains an answerable question rather than a silent gap.
 */
export function buildTools(config: Config): Tool[] {
  const clients = makeClients(config);
  const actions = actionTools(clients, config);
  const all = [
    guideTool(config),
    ...diagnosticTools(clients, config),
    ...(cloudUsable(config) ? sandboxTools(clients) : []),
    ...feedTools(clients),
    ...actions,
    ...artifactTools(clients, config),
    // `repo_deploy` finishes by handing a spec to `applb_deploy`, so the two
    // cannot disagree about how a deployment is registered and built.
    ...repoTools(clients, config, actions.find((t) => t.name === "applb_deploy")),
  ];
  // A hosted server lists only what it can reach. Over stdio the operator's own
  // config decides, and a tool that explains what to set is worth keeping.
  const usable = config.http ? all.filter((t) => reachable(t.name, config)) : all;
  return workflowFirst(usable).map(validated);
}

/** Tools that do nothing but call ci, or app-obs. */
const CI_ONLY = new Set([
  "diagnose_ci_job",
  "ci_run_status",
  "ci_run_logs",
  "ci_cancel_run",
  "ci_destroy_vm",
  "ci_cleanup_failed_vms",
  "ci_request",
]);
const OBS_ONLY = new Set(["deployment_logs", "namespace_telemetry", "obs_request"]);

/**
 * app-obs is reachable two ways: directly at APP_OBS_URL, or through app-lb's
 * per-namespace obs plugin with the caller's own credential (`telemetry.ts`).
 * The second needs nothing but app-lb, which is how a hosted instance with no
 * app-obs of its own still serves a namespace its telemetry.
 */
function reachable(name: string, config: Config): boolean {
  if (CI_ONLY.has(name)) return Boolean(config.ci);
  if (OBS_ONLY.has(name)) return Boolean(config.obs || config.applb);
  return true;
}

/**
 * The tools a new user's first task needs, in the order they need them.
 *
 * Some MCP clients keep only the first N tools a server lists (Cursor keeps
 * 40). Registration order put the repo tools last, at 55-60 of 60, so on such
 * a client an agent could read about `repo_create` in `applb_spec_schema` and
 * then find no such tool: exactly the create-a-repo-and-deploy-it workflow the
 * onboarding steers people to. Listing these first keeps that workflow whole
 * under any cap of at least this many tools.
 */
export const WORKFLOW_FIRST = [
  "heyo_guide",
  "heyo_status",
  "heyo_whoami",
  "repo_create",
  "repo_write_files",
  "repo_deploy",
  "repo_list",
  "repo_get",
  "repo_token",
  "applb_spec_schema",
  "applb_deploy",
  "applb_list_deployments",
  "applb_get_deployment",
  "applb_deployment_jobs",
  "applb_job",
  "applb_build",
  "applb_pull",
  "art_publish_files",
  "art_publish",
  "art_fetch",
  "art_list_tags",
  "diagnose_deployment",
  "deployment_logs",
  "namespace_telemetry",
  "diagnose_vm_boot",
];

function workflowFirst<T extends { name: string }>(tools: T[]): T[] {
  const rank = new Map(WORKFLOW_FIRST.map((n, i) => [n, i]));
  const first = tools.filter((t) => rank.has(t.name)).sort((a, b) => rank.get(a.name)! - rank.get(b.name)!);
  return [...first, ...tools.filter((t) => !rank.has(t.name))];
}

/**
 * A failure an agent is holding, with the plan that gets it out. Applied to
 * every result here, the one place all of them pass, so the pointer arrives
 * where the failure is read: a job record, a 403, a site status. The tools
 * that *describe* failures are exempt, or every plan would hint at itself.
 */
const UNHINTED = new Set(["heyo_guide", "applb_spec_schema"]);

export function withHint(tool: string, text: string): string {
  if (UNHINTED.has(tool)) return text;
  const hint = explainFailure(text);
  return hint ? `${text}\n\n${hint}` : text;
}

/**
 * Sent to the client at `initialize`; most hosts put it in front of the model.
 * Short on purpose: the common paths, and where the details live.
 */
export const INSTRUCTIONS = `Heyo: deploy apps to app-lb from git repos or published artifacts.

Not sure how? Call heyo_guide with your goal (or an error message) for a step-by-step plan.

Your token confines you to one namespace. Pass that namespace to repo_* tools; artifact tags you publish must start with "<namespace>/".

Static site (HTML/JS/CSS, already built):
  1. repo_create  2. repo_write_files with the BUILT files  3. repo_deploy with kind "site" and a host.
  To update it, repo_write_files again, then repo_deploy again. Nothing in the repo is run.
  Alternative: art_publish_files (tag "<namespace>/<name>:<version>"), then applb_deploy a site whose artifact is {store, ref}.

App with a Dockerfile: repo_create, repo_write_files including the Dockerfile, then repo_deploy with kind "vm", port and start_command. start_command must background itself (setsid nohup ... &) and the app must listen on 0.0.0.0:<port>.

Never set site.root or an update block: app-lb assigns the root, and update is operator-only.

applb_spec_schema has the full deployment spec. On a 401 or 403 run heyo_whoami; on any other failure, heyo_guide with the error, then diagnose_deployment.

Telemetry for your namespace (requests, errors, latency, logs): namespace_telemetry, then deployment_logs. It needs the obs plugin installed in the namespace; the error says how when it is not.`;

/**
 * Check a tool's arguments against the schema it advertises, before its handler
 * sees them.
 *
 * Until this existed the schema was **advertisement only**: `createServer`
 * passed `arguments` straight through, and every handler coerced by hand
 * (`String(a.id)`, `Number(a.retries ?? 3)`). That made a schema a suggestion
 * rather than a contract — which was tolerable while the most consequential
 * input was an untyped blob, and stops being tolerable the moment a schema is
 * worth trusting.
 *
 * ## Why here and not in the dispatch handler
 *
 * `tools.test.ts` and its siblings call `tool.handler(args)` directly, bypassing
 * the protocol entirely. Validating inside the `CallToolRequestSchema` handler
 * would therefore be invisible to every existing test: the suite would stay
 * green while real clients hit a new rejection path nothing exercised. Wrapping
 * at construction puts the parse on the same path the tests already use, so
 * they all exercise it for free — and leaves dispatch as dumb as it should be.
 *
 * ## Why `.strip()` and not `.strict()`
 *
 * Zod's default drops unknown keys; `.strict()` would reject them. Every handler
 * reads only what it declared, so stripping is safe — and refusing a call
 * because a model guessed one extra parameter is a hostile way to greet a
 * caller who was otherwise right. It is also the same mistake the spec schema
 * deliberately avoids: never be stricter than the service behind you.
 */
function validated(tool: Tool): Tool {
  const shape = z.object(tool.schema);
  return {
    ...tool,
    handler: async (args) => {
      const parsed = shape.safeParse(args ?? {});
      if (!parsed.success) throw new Error(explain(tool, parsed.error));
      return tool.handler(parsed.data as Record<string, unknown>);
    },
  };
}

/**
 * A parse failure, said the way the rest of this server says things.
 *
 * Zod's own message is a JSON dump of an issue array, which is the wrong shape
 * for something a model reads and retries against. Name the tool, then one line
 * per problem, then — for the deployment spec — where the real schema lives. A
 * rejected argument is the single best moment to teach the input, because it is
 * the one moment the caller is definitely paying attention.
 */
function explain(tool: Tool, error: z.ZodError): string {
  const lines = error.issues.map((issue) => {
    const path = issue.path.join(".") || "(root)";
    return `  ${path}: ${issue.message}`;
  });
  const spec = error.issues.some((i) => String(i.path[0]) === "spec");
  return (
    `${tool.name}: the arguments do not match the tool's schema.\n${lines.join("\n")}` +
    (spec
      ? "\n\nThe deployment spec's full schema, field by field, is what " +
        "`applb_spec_schema` returns — including the cross-field rules, which are " +
        "half of what a spec gets wrong and cannot be expressed as a type."
      : "")
  );
}

/**
 * What `tools/list` answers, as a plain function of the tool set.
 *
 * Split out of {@link createServer} so it can be asserted directly. The listing
 * is the whole of what a client learns before its first call — every name,
 * every description, every schema — and it was previously reachable only by
 * standing up a server and speaking the protocol at it, so nothing tested it.
 * Two properties in particular need a test and now have somewhere to live: that
 * a schema change produces the JSON Schema it was meant to, and that the
 * listing stays within a size a client pays for on every connect.
 *
 * `$refStrategy: "none"` inlines every nested shape rather than emitting
 * `$defs`, because `$ref` support across MCP hosts is uneven. The cost is
 * duplication — a shape used five times is serialized five times — which is
 * what makes the size budget in `listing.test.ts` worth keeping.
 *
 * A tool carrying its own {@link Tool.inputSchema} bypasses the conversion and
 * is advertised verbatim. That one does use `$defs`: the deployment spec refers
 * to the same credential shape in five places, and inlining it five times costs
 * more than the compatibility risk is worth.
 */
export function toolListing(tools: Tool[]) {
  return tools.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: (t.inputSchema ??
      zodToJsonSchema(z.object(t.schema), { $refStrategy: "none" })) as {
      type: "object";
    },
    annotations: annotationsFor(t),
  }));
}

/**
 * Tools that only ever read.
 *
 * A list rather than a derivation, because there is nothing in a tool object to
 * derive it from — and `readOnlyHint` is the one annotation where being wrong is
 * a safety problem rather than a cosmetic one: a host may auto-approve what it
 * believes is a read. So the list is conservative, and `annotations.test.ts`
 * drives every tool on it against a stubbed transport and fails if any of them
 * issues anything but a GET. A tool that starts mutating stops being listed here
 * by test failure, not by review.
 */
const READ_ONLY = new Set([
  "heyo_guide",
  "heyo_status",
  "heyo_whoami",
  "heyo_capacity",
  "fleet_overview",
  "diagnose_deployment",
  "diagnose_empty_pool",
  "diagnose_ci_job",
  "deployment_logs",
  "namespace_telemetry",
  "applb_feeds",
  "applb_feed",
  "applb_list_deployments",
  "applb_get_deployment",
  "applb_metrics",
  "applb_disks",
  "applb_certs",
  "applb_security_events",
  "applb_spec_schema",
  "applb_job",
  "applb_deployment_jobs",
  "ci_run_status",
  "ci_run_logs",
  "art_list_tags",
  "art_get_tag",
  "art_get_manifest",
  "art_list_blobs",
  "art_usage",
  "art_list_manifests",
  "repo_list",
  "repo_get",
]);

/**
 * The hints a host's approval UI reads, derived rather than declared.
 *
 * Two audiences, two representations, and they must agree. The model reads the
 * `DESTRUCTIVE.` sentence at the front of a description — which is what the SDK
 * asks for, since it is explicit that "clients should never make tool use
 * decisions based on ToolAnnotations". A host's approval dialog reads these.
 *
 * Deriving `destructiveHint` from that same prose is what makes the two
 * incapable of disagreeing. The alternative — declaring it on each tool and
 * testing that the pair matches — allows a gap to open and then reports it,
 * which is strictly worse than not allowing one. `applb_sweep_disks` is the case
 * in point: it deletes disks by the same mechanism as its two siblings, both of
 * which said so, and it did not.
 *
 * ## Only what the defaults do not already say
 *
 * The MCP defaults are `readOnlyHint: false`, `destructiveHint: **true**` and
 * `openWorldHint: true`, and `destructiveHint` is documented as meaningful only
 * when `readOnlyHint` is false. Three consequences, and the middle one is a
 * safety property rather than a saving:
 *
 * - `openWorldHint` is omitted. Every tool here reaches a network service whose
 *   state this server does not own, which is already the default.
 * - **A tool that is neither read-only nor destructive must say
 *   `destructiveHint: false` out loud**, because silence means destructive.
 *   Emitting nothing would tell a host that `applb_create_deployment` and
 *   `art_publish` destroy things.
 * - A read-only tool says only that; `destructiveHint` beside it is noise the
 *   spec says carries no meaning.
 *
 * Across 64 tools the difference between this and emitting all three fields is
 * about 4 KB on every connect, but the reason to do it is that the short form is
 * the accurate one.
 */
function annotationsFor(tool: Tool): Record<string, boolean> {
  if (tool.description.startsWith(DESTRUCTIVE_PREFIX)) return { destructiveHint: true };
  if (READ_ONLY.has(tool.name)) return { readOnlyHint: true };
  return { destructiveHint: false };
}

/**
 * A fresh `Server` per call.
 *
 * The HTTP transport runs statelessly — one server and one transport per
 * request — because app-lb balances across a pool. A session pinned to one
 * backend would work until the pool scaled, then fail for whichever requests
 * landed elsewhere, which is a bug that only appears under load.
 */
export function createServer(config: Config, tools: Tool[]): Server {
  const byName = new Map(tools.map((t) => [t.name, t]));
  const server = new Server(
    { name: "heyo-mcp", version: "0.1.0" },
    // Resources and prompts alongside tools. Declaring them is what makes a
    // host start issuing `resources/list` and `prompts/list`, so the handlers
    // are registered in the same breath — see `registerResources`.
    { capabilities: { tools: {}, resources: {}, prompts: {} }, instructions: INSTRUCTIONS },
  );
  registerResources(server);

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolListing(tools) }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const tool = byName.get(req.params.name);
    if (!tool) {
      return {
        isError: true,
        content: [{ type: "text" as const, text: `No such tool: ${req.params.name}` }],
      };
    }
    try {
      const text = await tool.handler((req.params.arguments ?? {}) as Record<string, unknown>);
      return { content: [{ type: "text" as const, text: withHint(tool.name, text) }] };
    } catch (e) {
      // Returned, not thrown: a failed diagnostic is itself diagnostic, and
      // "app-obs 401" belongs in the transcript rather than in a dead call.
      const text = e instanceof Error ? e.message : String(e);
      return {
        isError: true,
        content: [{ type: "text" as const, text: withHint(tool.name, text) }],
      };
    }
  });

  return server;
}
