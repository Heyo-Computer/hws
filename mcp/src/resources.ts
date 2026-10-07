/**
 * Reference material a client fetches, and one prompt that names a sequence.
 *
 * The field report's last complaint was that ~56 flat tool names have no entry
 * point for the most common task. MCP has two primitives built for exactly that
 * and this server declared neither — only `tools`.
 *
 * The distinction that makes them worth adding: a tool description is **pushed**
 * on every connect and paid for in the listing budget, while a resource is
 * **pulled** when the model decides it needs it. That is what makes it honest to
 * summarise the auth gate in the advertised schema and keep the full thing
 * here — the detail is one fetch away rather than one repository away, and it
 * costs nothing until asked for.
 *
 * Everything below is a pure function of the compiled-in generated data. No
 * filesystem, no network, no session state — `serve-http.ts` builds a fresh
 * `Server` per request, so a handler that remembered anything would be wrong.
 */

import {
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ReadResourceRequestSchema,
  GetPromptRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";

import { DEPLOYMENT_EXAMPLES } from "./applb/examples.js";
import { DEPLOYMENT_SPEC_FULL } from "./applb/spec.schema.js";
import { SPEC_RULES } from "./applb/rules.js";

const SPEC_URI = "heyo://applb/deployment-spec";
const GUIDE_URI = "heyo://applb/deploy-guide";
const TLS_URI = "heyo://applb/tls";
const EXAMPLE_PREFIX = "heyo://applb/examples/";

/**
 * How a deployment actually gets made, end to end.
 *
 * Written because the sequence was only ever inferable from descriptions
 * scattered across the tool list — and two of those descriptions were wrong
 * until 2026-09-10, which is how a sequence spread over forty names fails.
 */
const DEPLOY_GUIDE = `# Deploying with app-lb

## 1. Pick a backend — exactly one

- **\`vm\`** — app-lb boots and autoscales microVMs from an image. Use this to run
  your own code without running a machine.
- **\`upstreams\`** — \`host:port\` addresses you already run. app-lb proxies and
  health-checks them; it does not start them. With a namespace credential they
  must be public addresses.
- **\`site\`** — static files app-lb serves from a root it assigns. Fill it with
  \`repo_deploy\` (kind site) or \`art_publish_files\`; leave \`root\` unset.

Two backends is an error, and so is none.

## 2. For a \`vm\`, decide where the image comes from

- **\`build\`** — a Dockerfile, from a git repo. app-lb builds it.
- **\`artifact\`** — a rootfs already published to your namespace's artifacts
  (\`art_publish\`). Give only \`{ref: "<namespace>/name:tag"}\`; app-lb pulls it
  and authenticates the pull itself.
- **neither** — \`vm.image\` names something the daemon already has.

\`build\` and \`artifact\` are mutually exclusive: both rewrite \`vm.image\`, and a
deployment with two sources has no answer to where its running image came from.

## 3. Register it

\`applb_deploy\` is the one call: it checks the cross-field rules first, creates or
edits as appropriate, starts the right job, and reports what TLS will do. The
primitives underneath it are \`applb_create_deployment\` (register or replace) and
\`applb_update_deployment\` (edit, **preserving the VM pool** when \`vm\` is
unchanged).

Write the spec against \`applb_deploy\`'s schema, which is generated
from app-lb's own types. \`applb_spec_schema\` returns any block in full plus the
rules that constrain it.

## 4. Move it onto new bytes, later

The job to start depends on the backend, and picking wrong is refused rather
than ignored:

| you have | you want | tool |
|---|---|---|
| \`vm\` + \`build\` | rebuild the image | \`applb_build\` |
| \`vm\` or \`site\` + \`artifact\` | roll onto new bytes | \`applb_pull\` |
| \`upstreams\` or \`site\` + \`update\` | run commands on the app-lb host (operators only; a namespace credential is refused) | \`applb_host_update\` |
| \`vm\` + \`mounts\` | re-fetch mounted trees | \`applb_pull_mounts\` |

All four answer as soon as the work is *scheduled*. Poll \`applb_job\` with the id
they return.

Publishing new bytes into your namespace's artifacts first is \`art_publish\`,
which does the three-request sequence in the order that works. Follow it with
\`applb_pull\`.

## 5. Change how much of it runs

\`applb_scale\` takes a **partial** policy — only the fields you send change — and
never touches the VM template, so the pool is preserved. Use it rather than
re-registering.

## When something is wrong

\`heyo_status\` first: it distinguishes "not configured" from "configured and
refusing", and reports a credential that cannot work before you spend a call
finding out. Then \`diagnose_deployment\`, and \`deployment_logs\` for what the
application itself said. \`namespace_telemetry\` is every deployment in your
namespace at once; it needs the obs plugin installed there
(\`heyctl plugins install obs -n <ns>\`).`;

/** The TLS answer, which is a trap rather than a sequence. */
const TLS_NOTES = `# TLS on a new deployment

**For an exact \`host\` route, it is automatic and there is no second call.**
Registering nudges ACME, issuance is HTTP-01, and certificates are selected
per-handshake from SNI — so a certificate issued seconds ago serves without a
restart. \`applb_certs\` only *reads*; there is no endpoint that requests one.

Three things decide whether it works:

1. **Port 80 must reach app-lb's plaintext listener.** HTTP-01 is the challenge,
   and there is no way to point it elsewhere.
2. **A \`host_suffix\` route never gets its own certificate.** It names a subtree,
   and a subtree's certificate is a wildcard issued over DNS-01 from the fleet's
   configured wildcard domains. A suffix no wildcard covers is warned about once
   and then served a fallback certificate that will not validate — which from
   outside is indistinguishable from TLS being broken.
3. **A host covered by a configured wildcard is deliberately excluded** from
   per-host issuance. Let's Encrypt allows 50 certificates per registered domain
   per week, and at fleet scale per-host issuance would exhaust that.

Failures back off from 60s to a 6h cap, and the renewal sweep runs every 12h. So
a misconfigured host does not retry its way out quickly: fix the cause and
expect the next attempt on that schedule.`;

interface ResourceBody {
  uri: string;
  mimeType: string;
  text: string;
}

/** Resolve a URI, or undefined when nothing answers to it. */
function read(uri: string): ResourceBody | undefined {
  if (uri === SPEC_URI) {
    return {
      uri,
      mimeType: "application/json",
      text: JSON.stringify(
        {
          schema: DEPLOYMENT_SPEC_FULL,
          cross_field_rules: SPEC_RULES.map((r) => r.rule),
        },
        null,
        2,
      ),
    };
  }
  if (uri === GUIDE_URI) return { uri, mimeType: "text/markdown", text: DEPLOY_GUIDE };
  if (uri === TLS_URI) return { uri, mimeType: "text/markdown", text: TLS_NOTES };

  if (uri.startsWith(EXAMPLE_PREFIX)) {
    const name = decodeURIComponent(uri.slice(EXAMPLE_PREFIX.length));
    const found =
      DEPLOYMENT_EXAMPLES.find((e) => e.name === name) ??
      DEPLOYMENT_EXAMPLES.find((e) => e.name === `${name}.json`);
    if (!found) return undefined;
    return {
      uri,
      mimeType: "text/markdown",
      text: `# ${found.name}\n\n\`\`\`json\n${found.spec}\n\`\`\`\n${
        found.notes ? `\n${found.notes}\n` : ""
      }`,
    };
  }
  return undefined;
}

const PROMPT_NAME = "deploy_a_service";

/** The ordered plan for one backend kind, as a prompt a host can surface. */
function deployPlan(kind: string, id: string, host?: string): string {
  const route = host ? `{ "host": "${host}" }` : `{ "host": "<hostname>" }`;
  const shared = [
    `Deployment id: \`${id}\``,
    "",
    "Read `heyo://applb/deploy-guide` first if any step below is unfamiliar.",
    "",
  ];
  const tail = [
    "",
    `4. Confirm: \`applb_get_deployment\` for the spec app-lb kept, and \`applb_metrics\` for`,
    "   whether replicas became healthy.",
    ...(host
      ? [
          "",
          `TLS for \`${host}\` is automatic — registering nudges ACME and the certificate`,
          "arrives within seconds. Check with `applb_certs`. If this were a `host_suffix`",
          "rather than an exact host it would NOT get its own certificate; see",
          "`heyo://applb/tls`.",
        ]
      : []),
  ];

  if (kind === "vm") {
    return [
      ...shared,
      "Have source and a Dockerfile? `repo_create` → `repo_write_files` → `repo_deploy` with",
      "`kind: \"vm\"` does all of this (see `heyo_guide` topic deploy-vm-from-source). By hand:",
      "1. Write the spec against `applb_deploy`'s schema:",
      `   - \`id\`, \`routes: [${route}]\``,
      "   - `vm`: `driver` (`firecracker`), `port`, and usually `start_command` and `size_class`;",
      "     `start_command` must background itself (`setsid nohup … &`) and the app must listen on 0.0.0.0",
      "   - `build` (a Dockerfile) **or** `artifact: {ref}` (bytes you published with `art_publish`) — never both",
      "   - `scaling` if the defaults (max 5, scale to zero after 300s) are wrong",
      "2. `applb_deploy` with that spec. It checks the cross-field rules, registers, and",
      "   starts the right job for whichever image source you chose.",
      "3. Poll `applb_job` with the id it returns. A build takes minutes; a pull is usually",
      "   faster but is still asynchronous.",
      ...tail,
    ].join("\n");
  }
  if (kind === "site") {
    return [
      ...shared,
      "1. Files you have (built): `repo_create` → `repo_write_files` → `repo_deploy` with",
      "   `kind: \"site\"` and a host. Or `art_publish_files`, then `applb_deploy` a `site`",
      "   with `artifact: {ref}` (no store). Leave `site.root` out (app-lb assigns it) and never",
      "   use `update` (operator-only). `spa: true` serves `index.html` for unknown paths.",
      "2. To ship new files: `repo_deploy` again, or `art_publish_files` with `deployment`.",
      "   `heyo_guide` topic deploy-static-site has the full plan.",
      ...tail,
    ].join("\n");
  }
  return [
    ...shared,
    "1. Write the spec: `id`, `routes`, and `upstreams` as `host:port` addresses you",
    "   already run. Add `health` if `/` is not the right probe — `\"path\": null` means a",
    "   bare TCP connect.",
    "2. `applb_deploy` with that spec. Nothing is booted: app-lb proxies to what you run.",
    "3. Operators only (a namespace credential is refused): an `update` block makes",
    "   app-lb rebuild the code on its own host, run by `applb_host_update`.",
    "   `applb_pull` and `applb_build` do NOT apply to a static deployment.",
    ...tail,
  ].join("\n");
}

/**
 * Register the resource and prompt handlers on a server.
 *
 * All five land together on purpose: declaring the capabilities is what makes a
 * host start issuing these calls, so a half-registered server answers
 * method-not-found to something it just advertised.
 */
export function registerResources(server: Server): void {
  server.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: [
      {
        uri: SPEC_URI,
        name: "Deployment spec (full schema)",
        description:
          "Every field of app-lb's DeploymentSpec with its full documentation, generated " +
          "from app-lb's own types, plus the cross-field rules no schema can express.",
        mimeType: "application/json",
      },
      {
        uri: GUIDE_URI,
        name: "Deploying with app-lb",
        description:
          "The sequence end to end: choosing a backend, where the image comes from, which " +
          "job tool applies to which backend, and what to poll.",
        mimeType: "text/markdown",
      },
      {
        uri: TLS_URI,
        name: "TLS on a new deployment",
        description:
          "Why an exact host gets HTTPS automatically, why a host_suffix never does, and " +
          "what to check when it does not work.",
        mimeType: "text/markdown",
      },
      ...DEPLOYMENT_EXAMPLES.map((e) => ({
        uri: `${EXAMPLE_PREFIX}${e.name}`,
        name: `Example: ${e.name}`,
        description: e.notes
          ? e.notes.split("\n")[0]!.replace(/^##\s*/, "")
          : `A working ${e.name} deployment spec.`,
        mimeType: "text/markdown",
      })),
    ],
  }));

  server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({
    resourceTemplates: [
      {
        uriTemplate: `${EXAMPLE_PREFIX}{name}`,
        name: "Deployment example by name",
        description:
          "One of app-lb's shipped example specs with its notes, e.g. " +
          "heyo://applb/examples/git-build.json. Each is parsed and validated by a test in " +
          "app-lb, so they are specs the server accepts rather than illustrations.",
        mimeType: "text/markdown",
      },
    ],
  }));

  server.setRequestHandler(ReadResourceRequestSchema, async (req) => {
    const body = read(req.params.uri);
    if (!body) throw new Error(`no such resource: ${req.params.uri}`);
    return { contents: [body] };
  });

  server.setRequestHandler(ListPromptsRequestSchema, async () => ({
    prompts: [
      {
        name: PROMPT_NAME,
        description:
          "The ordered plan for deploying one service: which spec blocks it needs, which " +
          "tool runs each step, what to poll, and what TLS will do.",
        arguments: [
          {
            name: "kind",
            description: "`vm` (app-lb runs microVMs), `site` (static files) or `static` " +
              "(upstreams you run yourself)",
            required: true,
          },
          { name: "id", description: "the deployment id to create", required: true },
          { name: "host", description: "the hostname it should serve on", required: false },
        ],
      },
    ],
  }));

  server.setRequestHandler(GetPromptRequestSchema, async (req) => {
    if (req.params.name !== PROMPT_NAME) throw new Error(`no such prompt: ${req.params.name}`);
    const args = req.params.arguments ?? {};
    const kind = String(args.kind ?? "vm");
    const id = String(args.id ?? "<id>");
    const host = args.host ? String(args.host) : undefined;
    return {
      description: `Deploy a ${kind} service as ${id}`,
      messages: [
        {
          role: "user" as const,
          content: { type: "text" as const, text: deployPlan(kind, id, host) },
        },
      ],
    };
  });
}
