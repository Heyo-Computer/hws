/**
 * `heyo_guide`: standard plans an agent can ask for, and the failure hints
 * that point back to them.
 *
 * An outside user's agent, working only from this server, deployed a static
 * site by setting `site.root` and an `update` block that ran `mkdir`, never
 * found `repo_deploy`, and hit a private-repo clone failure nothing explained.
 * Each step was locally plausible from one tool description. What it lacked was
 * the *plan*: which tools, in which order, for the job in front of it. Server
 * instructions carry the common paths, but many clients drop them, and almost
 * none surface resources or prompts. A tool is the one thing every client
 * shows, so the plans live in one, and the failure text an agent will actually
 * read (`explainFailure`) names the plan that gets it out.
 */

import { z } from "zod";

import type { Config } from "../config.js";
import type { Tool } from "./diagnose.js";

export interface Guide {
  id: string;
  title: string;
  /** Words a goal is matched on. */
  keywords: string[];
  steps: string[];
  /** What goes wrong, and what to do instead. */
  pitfalls?: string[];
}

const DAEMONIZE =
  "`start_command` must RETURN: background the app, e.g. " +
  "`cd /app && setsid nohup node server.js </dev/null >/var/log/app.log 2>&1 &`. " +
  "A foreground command never lets the VM finish booting. The app must listen on 0.0.0.0:<port>.";

export const GUIDES: readonly Guide[] = [
  {
    id: "deploy-static-site",
    title: "Deploy a static site from files you have",
    keywords: ["static", "site", "html", "css", "frontend", "spa", "react", "vite", "dist", "build", "website", "page"],
    steps: [
      "Build the site first if it needs building (dist/, build/). Nothing in the repo is run on the server.",
      "repo_create {name} — a git repo in your namespace on the Heyo remote.",
      "repo_write_files {repo, files: [{path, content, encoding?}], message} — commit the BUILT files (use encoding \"base64\" for images and other binaries).",
      "repo_deploy {repo, kind: \"site\", context?: \"dist\", spa?: true, host?} — registers the site and copies the files into a root app-lb manages. Without `host` it is <repo>.<this region's domain>; the result says which.",
      "Open https://<host>/. To change it: repo_write_files again, then repo_deploy again (pass `deployment` if its id is not the repo name).",
    ],
    pitfalls: [
      "Do NOT set `site.root`: app-lb assigns one. Do NOT use an `update` block: it runs commands on the app-lb host and is for platform operators only; a namespace credential is refused.",
      "Prefer this repo path. Serving an artifact instead only works if app-lb can read the tag (see guide publish-files-as-artifact).",
    ],
  },
  {
    id: "deploy-vm-from-source",
    title: "Run an app (API, server, worker) from source with a Dockerfile",
    keywords: ["vm", "api", "server", "node", "python", "go", "rust", "docker", "dockerfile", "backend", "service", "app", "container", "worker"],
    steps: [
      "Write a Dockerfile at the repo root that installs the app (e.g. into /app).",
      "repo_create {name}.",
      "repo_write_files {repo, files: [... source ..., Dockerfile], message}.",
      `repo_deploy {repo, kind: "vm", port, start_command, host?}. ${DAEMONIZE}`,
      "repo_deploy waits for the image build. Then applb_get_deployment {id} and applb_metrics show whether replicas are healthy.",
    ],
    pitfalls: [
      "Writing an applb_deploy spec by hand instead? Put the repo's clone URL in `build.repo` with `dockerfile`; applb_deploy adds the read credential for a repo on the Heyo remote.",
      "A pool that never becomes ready is almost always start_command (foreground, wrong port, or 127.0.0.1): see guide fix-vm-not-ready.",
    ],
  },
  {
    id: "deploy-existing-repo",
    title: "Deploy a repo you already created or pushed to",
    keywords: ["repo", "repository", "git", "push", "pushed", "existing", "clone", "remote"],
    steps: [
      "repo_list or repo_get {repo} — confirm it is not empty (an empty repo has nothing to deploy).",
      "repo_deploy {repo, kind: \"site\" | \"vm\", ...} — mints a read token, stores it as an app-lb secret, registers the deployment with `build` pointing at the repo, and builds it. Pass `deployment` to target a deployment whose id is not the repo name.",
      "To redeploy after a push: repo_deploy again (or applb_build {id}).",
    ],
    pitfalls: [
      "repo_deploy not in your tool list? Your client may hold a stale list: reconnect. Meanwhile applb_deploy with `build: {repo: <clone_url>}` works the same; it adds the credential.",
    ],
  },
  {
    id: "publish-files-as-artifact",
    title: "Publish files as an artifact (and serve them as a site)",
    keywords: ["artifact", "publish", "upload", "tarball", "bundle", "art", "tag", "files", "binary"],
    steps: [
      "art_publish_files {tag: \"<namespace>/<name>:<version>\", files: [{path, content, encoding?: \"base64\"}]} — files are passed INLINE: this server is remote and cannot read paths on your machine. Up to 64 MiB in total.",
      "A tarball you already have: art_publish {tag, content_base64}.",
      "To serve it, app-lb must be able to read the tag. Your tags are private, and a namespace cannot hold the store's key, so a site or vm that pulls one fails with 401 — unless the repo is public (anyone can then download it). For a website that is fine; otherwise deploy from a repo (guide deploy-static-site).",
      "Then: applb_deploy a site with `artifact: {store, ref: <tag>}` (art_publish_files' result gives the block), or for a site that already has `artifact`, pass `deployment` to art_publish_files.",
    ],
    pitfalls: ["The tag must start with \"<namespace>/\" (your token's namespace); heyo_whoami shows it."],
  },
  {
    id: "redeploy",
    title: "Ship a change to something already deployed",
    keywords: ["redeploy", "update", "change", "rebuild", "new version", "ship", "release"],
    steps: [
      "From a repo: repo_write_files (or git push), then repo_deploy again — or applb_build {id} for a deployment whose spec already has `build`.",
      "From an artifact: art_publish_files {tag: new version, deployment: <id>}, or applb_pull {id}.",
      "Poll applb_job {job_id, deployment: <id>} until it finishes.",
    ],
  },
  {
    id: "check-a-deployment",
    title: "See whether a deployment is working",
    keywords: ["status", "check", "health", "healthy", "working", "logs", "debug", "broken", "down", "verify"],
    steps: [
      "heyo_status — which services this server reaches, and any faults.",
      "diagnose_deployment {id} — the app-lb record, recent jobs and (when app-obs is configured) logs, in one call.",
      "applb_deployment_jobs {id} — every build/pull with its outcome; applb_job {job_id, deployment} for one.",
      "applb_metrics — whether replicas are healthy and taking traffic.",
    ],
  },
  {
    id: "fix-git-auth",
    title: "Build fails: \"could not read Username\" / authentication failed",
    keywords: ["username", "authentication", "auth", "terminal", "prompts", "clone", "128", "credential", "private"],
    steps: [
      "The build cloned a private repo with no credential: the spec's `build.auth` is missing.",
      "Fix: repo_deploy {repo, kind, deployment: <id>} again — it adds the credential. Or applb_get_deployment {id}, then applb_deploy with that spec (minus `site.root`): applb_deploy adds `build.auth` for a repo on the Heyo remote.",
      "applb_build alone will fail the same way: it rebuilds the spec as it is.",
      "For a repo hosted elsewhere (e.g. GitHub): applb_request {method: \"POST\", path: \"/secrets\", body: {id, namespace, data: {token}}}, then set `build.auth: {secret: <id>, key: \"token\", username}`.",
    ],
  },
  {
    id: "fix-empty-site",
    title: "Site status is \"empty\" or \"missing\" (every request 404s)",
    keywords: ["empty", "missing", "404", "root", "blank", "not found", "nothing", "site is empty", "site empty", "status empty", "status missing", "site missing", "no files"],
    steps: [
      "\"missing\": the site's root has never been written. \"empty\": it exists with no files. Registering a site does not put files in it.",
      "Fill it from a repo: repo_create + repo_write_files + repo_deploy {repo, kind: \"site\", deployment: <this site's id>} — it replaces the site's source (and drops any `update`/root).",
      "Only if the site already has an `artifact` block: art_publish_files with `deployment: <id>`.",
    ],
    pitfalls: ["`update` commands and a hand-set `site.root` will not fix this for a namespace credential: both are refused."],
  },
  {
    id: "fix-vm-not-ready",
    title: "VM deployment never becomes ready / pool stays empty",
    keywords: ["ready", "pool", "boot", "start", "start_command", "crash", "timeout", "unhealthy", "replicas", "port"],
    steps: [
      DAEMONIZE,
      "Check the port: the spec's `vm.port` (repo_deploy `port`) must be the one the app listens on, on 0.0.0.0.",
      "diagnose_deployment {id} and applb_deployment_jobs {id} — did the image build succeed? A failed build leaves the old image (or none).",
      "Then redeploy (repo_deploy again, or applb_deploy with the corrected spec).",
    ],
  },
  {
    id: "fix-forbidden",
    title: "403 / forbidden / \"namespace credential may not\"",
    keywords: ["403", "forbidden", "refused", "not allowed", "permission", "scope", "namespace credential", "may not"],
    steps: [
      "heyo_whoami — your namespace and tier. Everything you create must be in that namespace (repo_* tools take it; specs must say `namespace`).",
      "app-lb refuses a namespace credential anything that acts on its host. The alternatives:",
      "• `update` block → build from a repo (repo_deploy) or pull an artifact (art_publish_files).",
      "• `site.root` → leave it out; app-lb assigns one.",
      "• `upstreams` pointing at private/loopback addresses → only public addresses; run the app as a `vm` instead.",
      "• `build.repo` / stores that are not https:// (paths, ssh, s3://) → use the Heyo git remote (repo_create) or an https URL.",
      "• `vm.image_download_url`, `gateway`, `discovery` → operator-only; use `build` or `artifact`.",
      "applb_job answering 403: pass `deployment` too — the per-job route is fleet-wide.",
    ],
  },
];

/** The guide a goal best matches, by keyword overlap; `undefined` for no match. */
export function matchGuide(goal: string): Guide | undefined {
  const text = ` ${goal.toLowerCase().replace(/[^a-z0-9_.:/ -]/g, " ")} `;
  let best: { g: Guide; score: number } | undefined;
  for (const g of GUIDES) {
    let score = 0;
    for (const k of g.keywords) if (text.includes(k.includes(" ") ? k : ` ${k}`)) score += k.includes(" ") ? 2 : 1;
    if (g.id.split("-").some((w) => w.length > 3 && text.includes(w))) score += 0.5;
    // Symptoms outrank tasks: "the site is empty" is a problem with a site,
    // not a request to build one.
    if (g.id.startsWith("fix-")) score *= 1.5;
    if (score > 0 && (!best || score > best.score)) best = { g, score };
  }
  return best?.g;
}

export function renderGuide(g: Guide): string {
  const lines = [`# ${g.title}`, `guide: ${g.id}`, "", ...g.steps.map((s, i) => `${i + 1}. ${s}`)];
  if (g.pitfalls?.length) lines.push("", "Watch out:", ...g.pitfalls.map((p) => `- ${p}`));
  return lines.join("\n");
}

export function catalogue(): string {
  return [
    "Standard plans. Call heyo_guide with `topic` (an id below) or `goal` (your task in words).",
    "",
    ...GUIDES.map((g) => `- ${g.id}: ${g.title}`),
  ].join("\n");
}

/**
 * Failure text an agent is likely to be holding, mapped to the guide that gets
 * it out. Applied to every tool result by the server, so the pointer arrives
 * where the failure is read whether or not the agent ever saw the
 * instructions.
 */
const FAILURES: { pattern: RegExp; guide: string; hint: string }[] = [
  {
    pattern: /could not read Username|terminal prompts disabled|Authentication failed for 'http/i,
    guide: "fix-git-auth",
    hint: "the build cloned a private repo without `build.auth`. Re-run repo_deploy (with `deployment` if its id is not the repo name), or applb_deploy with the same spec (it adds the credential); applb_build alone fails again.",
  },
  {
    pattern: /"status"\s*:\s*"(empty|missing)"|Site root: (empty|missing)/,
    guide: "fix-empty-site",
    hint: "nothing has put files in this site's root. Fill it with repo_deploy {repo, kind: \"site\", deployment: <id>}.",
  },
  {
    pattern: /\bpull[^\n]{0,200}\b401\b|\b401\b[^\n]{0,200}\bpull/i,
    guide: "publish-files-as-artifact",
    hint: "app-lb could not read the artifact: your tags are private and a namespace cannot hold the store key. Make the repo public, or deploy from a repo instead.",
  },
  {
    pattern: /namespace credential (may not|cannot)|operators only|site\.root must be under|may only proxy to public|must be an https:\/\//i,
    guide: "fix-forbidden",
    hint: "app-lb refuses a namespace credential anything that acts on its host; heyo_guide fix-forbidden lists the alternative for each field.",
  },
];

export function explainFailure(text: string): string | undefined {
  const hits = FAILURES.filter((f) => f.pattern.test(text));
  if (hits.length === 0) return undefined;
  return hits.map((h) => `Hint: ${h.hint} (heyo_guide {topic: "${h.guide}"})`).join("\n");
}

export function guideTool(_config: Config): Tool {
  return {
    name: "heyo_guide",
    description:
      "START HERE for a task you have not done on Heyo, or with an error you do not " +
      "understand. Returns a step-by-step plan (tools, order, arguments): deploy a site or " +
      "an app from your files, deploy a repo, publish files, redeploy, check a deployment, " +
      "and fix clone errors, empty sites, VMs that never get ready and 403s. `goal` in your " +
      "words, or `topic` as a guide id; neither lists them all.",
    schema: {
      goal: z.string().optional().describe("what you are trying to do, or the error you got"),
      topic: z.string().optional().describe("a guide id from the catalogue, e.g. 'deploy-static-site'"),
    },
    handler: async (a) => {
      const topic = typeof a.topic === "string" ? a.topic.trim() : "";
      if (topic) {
        const g = GUIDES.find((x) => x.id === topic);
        return g ? renderGuide(g) : `No guide "${topic}".\n\n${catalogue()}`;
      }
      const goal = typeof a.goal === "string" ? a.goal.trim() : "";
      if (!goal) return catalogue();
      const g = matchGuide(goal);
      const explained = explainFailure(goal);
      if (!g) return `${explained ? explained + "\n\n" : ""}No plan matched "${goal}".\n\n${catalogue()}`;
      const others = GUIDES.filter((x) => x !== g).map((x) => x.id).join(", ");
      return `${renderGuide(g)}\n\nOther plans: ${others}`;
    },
  };
}
