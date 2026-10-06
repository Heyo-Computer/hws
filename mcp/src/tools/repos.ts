/**
 * Git repos on the Heyo remote: somewhere for an agent's project to live, and
 * something app-lb can build from.
 *
 * ## Why this exists
 *
 * An agent that generates a project has files and, usually, no repo and no
 * place to push one. The only deploy path left to it was a `site` whose
 * `root` named a directory on its own machine, which registers, validates,
 * and then 404s every request: the root is read on the app-lb host. These
 * tools close that gap end to end:
 *
 * 1. `repo_create`: a repo, and a short-lived write token for `git push`.
 * 2. `repo_write_files`: commit files without git (inline, or a local
 *    directory over stdio).
 * 3. `repo_deploy`: a site or vm deployment whose `build` points at the repo,
 *    with a read token stored as an app-lb secret, and the build started.
 *
 * The remote accepts the caller's own credential (an `applb_…` token is
 * resolved through app-lb, a `heyo_api_*` key through the Heyo auth service),
 * so no second credential is needed to start.
 */

import { z } from "zod";

import type { Clients } from "../clients/index.js";
import type { Config } from "../config.js";
import { ServiceError } from "../http.js";
import { json, report, type Section } from "../format.js";
import { asChanges, decodeFiles, DEFAULT_EXCLUDE, fileSchema, readDirectory } from "../files.js";
import type { Tool } from "./diagnose.js";
import { notVisible } from "./actions.js";
import { num, bool } from "./schema.js";
import { storeBuildCredential } from "./remote-auth.js";
import { readStartInfo, startCommand, type StartInfo } from "./dockerfile.js";

interface RepoInfo {
  name?: string;
  namespace?: string;
  clone_url?: string;
  default_branch?: string;
  refs?: Record<string, string>;
  empty?: boolean;
}

export function repoTools(clients: Clients, config: Config, deployTool?: Tool): Tool[] {
  const enc = encodeURIComponent;
  const http = Boolean(config.http);

  /** The namespace a call means: named, configured, or app-lb's. */
  const namespaceOf = async (a: Record<string, unknown>): Promise<string> => {
    const named = typeof a.namespace === "string" ? a.namespace.trim() : "";
    const ns = named || config.remoteNamespace || (await clients.applbNamespace().catch(() => undefined));
    if (!ns) {
      throw new Error(
        "no namespace: pass `namespace`, or set REMOTE_NAMESPACE (or APPLB_NAMESPACE). Repos " +
          "live in a namespace the same way deployments do.",
      );
    }
    return ns;
  };

  const mint = async (ns: string, repo: string | undefined, access: "read" | "write", ttl: number, name: string) =>
    (await clients.remote({
      method: "POST",
      path: "/api/tokens",
      body: { namespace: ns, repos: repo ? [repo] : [], access, ttl_secs: ttl, name },
    })) as { token: string; id: string; expires_at?: number | null };

  const pushRecipe = (cloneUrl: string, token: string, branch: string) => ({
    // extraHeader rather than a token in the URL, so nothing lands in
    // .git/config.
    push: `git -c http.extraHeader="Authorization: Bearer ${token}" push ${cloneUrl} HEAD:${branch}`,
    clone: `git -c http.extraHeader="Authorization: Bearer ${token}" clone ${cloneUrl}`,
    from_scratch: [
      "git init -b " + branch,
      "git add -A",
      'git commit -m "initial commit"',
      `git -c http.extraHeader="Authorization: Bearer ${token}" push ${cloneUrl} HEAD:${branch}`,
    ],
  });

  return [
    {
      name: "repo_create",
      description:
        "Create a git repo on the Heyo remote, the place an agent's project lives so app-lb " +
        "can build it. Returns the clone URL, a write token valid for `ttl_secs` (default one " +
        "day), and the exact git commands to push. Idempotent: an existing repo is reused and a " +
        "fresh token minted.\n\n" +
        "No git? Use repo_write_files to commit files directly. Then repo_deploy to serve it.",
      schema: {
        name: z.string().describe("repo name: letters, digits, . _ -"),
        namespace: z.string().optional().describe("defaults to REMOTE_NAMESPACE / the app-lb namespace"),
        description: z.string().optional(),
        ttl_secs: num().optional().describe("write token lifetime; default 86400"),
      },
      handler: async (a) => {
        const ns = await namespaceOf(a);
        const name = String(a.name).trim().replace(/\.git$/, "");
        let created = true;
        let repo: RepoInfo;
        try {
          repo = (await clients.remote({
            method: "POST",
            path: `/api/repos/${enc(ns)}`,
            body: { name, ...(a.description ? { description: a.description } : {}) },
          })) as RepoInfo;
        } catch (e) {
          if (!(e instanceof ServiceError && e.status === 409)) throw e;
          created = false;
          repo = (await clients.remote({ path: `/api/repos/${enc(ns)}/${enc(name)}` })) as RepoInfo;
        }
        const ttl = a.ttl_secs === undefined ? 86_400 : Number(a.ttl_secs);
        const tok = await mint(ns, name, "write", ttl, `mcp-${name}`);
        const branch = repo.default_branch ?? "main";
        return json({
          repo: `${ns}/${name}`,
          created,
          clone_url: repo.clone_url,
          default_branch: branch,
          token: tok.token,
          token_expires_at: tok.expires_at ?? null,
          ...pushRecipe(String(repo.clone_url), tok.token, branch),
          next:
            "repo_deploy once something is pushed (or applb_deploy with this clone URL as " +
            "`build.repo`); repo_write_files if git is not available.",
        });
      },
    },
    {
      name: "repo_list",
      description: "The repos in a namespace on the Heyo remote, with their clone URLs.",
      schema: { namespace: z.string().optional() },
      handler: async (a) => json(await clients.remote({ path: `/api/repos/${enc(await namespaceOf(a))}` })),
    },
    {
      name: "repo_get",
      description:
        "One repo: its clone URL, HEAD, every ref and its commit, and whether it is still " +
        "empty. The `refs` value for a branch is what repo_write_files takes as `base`.",
      schema: { repo: z.string(), namespace: z.string().optional() },
      handler: async (a) =>
        json(
          await clients.remote({
            path: `/api/repos/${enc(await namespaceOf(a))}/${enc(String(a.repo).replace(/\.git$/, ""))}`,
          }),
        ),
    },
    {
      name: "repo_token",
      description:
        "Mint a repo token: `read` to clone or let app-lb build, `write` to push. Confined to " +
        "one namespace and, if `repo` is given, to that repo. Shown once. Git sends it as " +
        "`Authorization: Bearer <token>` (http.extraHeader) or as the Basic password with any " +
        "username. `ttl_secs: 0` never expires — what a deployment's build credential wants.",
      schema: {
        repo: z.string().optional().describe("confine to this repo; omit for the whole namespace"),
        access: z.enum(["read", "write"]),
        ttl_secs: num().optional().describe("default 86400; 0 = no expiry"),
        namespace: z.string().optional(),
      },
      handler: async (a) => {
        const ns = await namespaceOf(a);
        const repo = typeof a.repo === "string" ? a.repo.replace(/\.git$/, "") : undefined;
        const ttl = a.ttl_secs === undefined ? 86_400 : Number(a.ttl_secs);
        return json(await mint(ns, repo, a.access as "read" | "write", ttl, `mcp-${repo ?? ns}`));
      },
    },
    {
      name: "repo_write_files",
      description:
        "Commit files to a repo with no git on your side. The remote writes the commit and " +
        "records it exactly as a push. " +
        (http
          ? "Give `files` inline (content as utf8 or base64). "
          : "Give `files` inline, or `directory`: a project folder on this machine, sent " +
            "whole (`.git` and `node_modules` skipped) and committed as the repo's entire tree. ") +
        "Up to 64 MiB; beyond that push with git (repo_create). `base` (the branch's current " +
        "commit from repo_get) makes the commit fail rather than overwrite a concurrent change.",
      schema: {
        repo: z.string(),
        message: z.string().describe("commit message"),
        files: z.array(fileSchema).optional(),
        ...(http
          ? {}
          : {
              directory: z.string().optional().describe("a folder on THIS machine to commit whole"),
              exclude: z.array(z.string()).optional().describe(`names skipped at any depth; default ${DEFAULT_EXCLUDE.join(", ")}`),
            }),
        branch: z.string().optional().describe("default: the repo's default branch"),
        base: z.string().optional().describe("expected current commit of the branch"),
        replace: bool()
          .optional()
          .describe("the files are the whole tree (default true for `directory`, false for `files`)"),
        namespace: z.string().optional(),
      },
      handler: async (a) => {
        const ns = await namespaceOf(a);
        const repo = String(a.repo).replace(/\.git$/, "");
        const dir = typeof a.directory === "string" ? a.directory.trim() : "";
        const inline = (a.files as z.infer<typeof fileSchema>[] | undefined) ?? [];
        if (dir && http) throw new Error("`directory` is not accepted over HTTP; send `files`.");
        if (dir && inline.length) throw new Error("give `files` or `directory`, not both.");
        let changes;
        if (dir) {
          changes = asChanges(await readDirectory(dir, (a.exclude as string[] | undefined) ?? DEFAULT_EXCLUDE));
        } else {
          if (!inline.length) throw new Error("no files: give `files`" + (http ? "." : " or `directory`."));
          const { entries, deletes } = decodeFiles(inline);
          changes = asChanges(entries, deletes);
        }
        const replace = a.replace === undefined ? Boolean(dir) : Boolean(a.replace);
        const result = await clients.remote({
          method: "POST",
          path: `/api/repos/${enc(ns)}/${enc(repo)}/commits`,
          body: {
            message: a.message,
            files: changes,
            replace,
            ...(a.branch ? { branch: a.branch } : {}),
            ...(a.base ? { base: a.base } : {}),
          },
        });
        return json({
          repo: `${ns}/${repo}`,
          ...(result as object),
          next:
            "repo_deploy builds a site or vm from this repo. (With applb_deploy instead, put the " +
            "clone URL in `build.repo`; the build credential is added for you.)",
        });
      },
    },
    {
      name: "repo_deploy",
      description:
        "Deploy a repo from the Heyo remote through app-lb, in one call: mints a read token, " +
        "stores it as an app-lb secret, registers (or edits) the deployment with `build` " +
        "pointing at the repo, and starts the build.\n\n" +
        "kind `site` (default): the files at `context` in the repo (default: the repo root; " +
        "for a built frontend usually `dist`) are copied into a root app-lb manages and served " +
        "as static files. Nothing in the repo is run, so commit the BUILT site. kind `vm`: a " +
        "Dockerfile in the repo is built into a microVM image, listening on `port`.\n\n" +
        "Redeploy after a push by calling it again, or applb_build.",
      schema: {
        repo: z.string(),
        host: z
          .string()
          .optional()
          .describe("default <deployment>.<region domain>"),
        kind: z.enum(["site", "vm"]).optional().describe("default site"),
        deployment: z
          .string()
          .optional()
          .describe("deployment id; default the repo name"),
        ref: z.string().optional().describe("branch, tag or commit; default the repo's default branch"),
        context: z.string().optional().describe("directory in the repo: the site's files, or the docker context"),
        spa: bool().optional().describe("site: serve index.html for unknown paths"),
        dockerfile: z.string().optional().describe("vm: Dockerfile path in the repo"),
        port: num().optional().describe("vm: port the app listens on; default 8080"),
        start_command: z
          .string()
          .optional()
          .describe("vm: must return (setsid nohup … &); listen on 0.0.0.0"),
        namespace: z.string().optional(),
        wait_seconds: num().optional().describe("poll the build this long; default 120"),
      },
      handler: async (a) => {
        if (!deployTool) throw new Error("app-lb tools are unavailable in this configuration.");
        const ns = await namespaceOf(a);
        const repo = String(a.repo).replace(/\.git$/, "");
        const id = String(a.deployment ?? repo).trim();
        const kind = (a.kind as string | undefined) ?? "site";
        const sections: Section[] = [];

        const info = (await clients.remote({ path: `/api/repos/${enc(ns)}/${enc(repo)}` })) as RepoInfo;
        if (info.empty) {
          return report(`${ns}/${repo}: nothing to deploy`, [
            {
              title: "The repo is empty",
              body: "Push to it (repo_create gives the commands) or commit with repo_write_files first.",
            },
          ]);
        }

        const cred = await storeBuildCredential(clients, { namespace: ns, repo }, id, ns);
        sections.push({
          title: "Build credential",
          body: `read token ${cred.tokenId} stored as app-lb secret ${cred.secretId}`,
        });

        const build: Record<string, unknown> = {
          repo: info.clone_url,
          ...(a.ref ? { ref: a.ref } : info.default_branch ? { ref: info.default_branch } : {}),
          ...(a.context ? { context: a.context } : {}),
          auth: cred.auth,
        };

        // Edit in place when it exists, so routes, auth and scaling set by
        // hand survive a redeploy.
        let existing: Record<string, unknown> | undefined;
        try {
          const cur = (await clients.applb({ path: `/deployments/${enc(id)}` })) as { spec?: Record<string, unknown> };
          existing = cur?.spec;
        } catch (e) {
          if (!(e instanceof ServiceError && notVisible(e))) throw e;
        }

        // A new deployment needs a host. Without one, use app-lb's own base
        // domain, read from its onboarding answer (the hostname it gives the
        // namespace's starter app, minus that app's label).
        let host = a.host as string | undefined;
        if (!existing?.routes && !host) {
          const ob = (await clients.applb({ path: "/onboarding", query: { namespace: ns } }).catch(() => undefined)) as
            | { fastcar?: { url?: string | null } }
            | undefined;
          const starter = ob?.fastcar?.url ? new URL(ob.fastcar.url).hostname : undefined;
          const base = starter?.split(".").slice(1).join(".");
          if (!base) {
            throw new Error(
              "Pass `host`: this app-lb does not report a base domain, so no default hostname " +
                "can be made (e.g. host: \"my-app.<region>.heyo.work\").",
            );
          }
          host = `${id}.${base}`;
          sections.push({ title: "Host", body: `no host given; using ${host}` });
        }

        let spec: Record<string, unknown>;
        if (kind === "site") {
          // No root: app-lb assigns one under its own sites dir. The caller
          // cannot know that host's filesystem, which is the whole point. A
          // namespace token drops an existing one too: app-lb refuses a
          // tenant's root outside its namespace, and reassigns the right one.
          const prev = { ...((existing?.site as Record<string, unknown> | undefined) ?? {}) };
          if (await clients.applbNamespace().catch(() => undefined)) delete prev.root;
          const site = {
            ...prev,
            ...(a.spa !== undefined ? { spa: Boolean(a.spa) } : {}),
          };
          spec = {
            ...(existing ?? {}),
            id,
            namespace: ns,
            routes: existing?.routes ?? [{ host }],
            site,
            build,
          };
          delete spec.artifact;
          delete spec.update;
        } else {
          if (a.dockerfile) build.dockerfile = a.dockerfile;
          // A VM's rootfs drops the image's CMD, ENV and WORKDIR, so with no
          // start_command nothing would ever run. Read them from the
          // Dockerfile instead (and its EXPOSE for the port).
          const prevVm = existing?.vm as Record<string, unknown> | undefined;
          if (!a.start_command && !prevVm?.start_command) {
            const ref = String(a.ref ?? info.default_branch ?? "main");
            const candidates = [
              a.dockerfile,
              a.context ? `${String(a.context).replace(/\/$/, "")}/Dockerfile` : undefined,
              "Dockerfile",
            ].filter((p): p is string => typeof p === "string" && p.length > 0);
            let derived: StartInfo | undefined;
            for (const path of candidates) {
              const text = (await clients
                .remote({ path: `/${enc(ns)}/${enc(repo)}/raw/${enc(ref)}/${path.split("/").map(enc).join("/")}`, expectText: true })
                .catch(() => undefined)) as string | undefined;
              if (typeof text === "string" && /^\s*FROM\s/im.test(text)) {
                derived = readStartInfo(text);
                break;
              }
            }
            const cmd = derived && startCommand(derived);
            if (cmd) {
              a.start_command = cmd;
              if (a.port === undefined && !prevVm?.port && derived?.port) a.port = derived.port;
              sections.push({
                title: "start_command (from the Dockerfile)",
                body:
                  `${cmd}\nA VM does not run the image's CMD/ENTRYPOINT, so this does it. Pass start_command to override.`,
              });
            } else {
              sections.push({
                title: "No start_command",
                body:
                  "Nothing tells the VM what to run: no start_command was given and the Dockerfile has no " +
                  "CMD or ENTRYPOINT. The pool will never become ready. Call again with start_command " +
                  "(background it: setsid nohup … &).",
              });
            }
          }
          spec = {
            ...(existing ?? {}),
            id,
            namespace: ns,
            routes: existing?.routes ?? [{ host }],
            vm: {
              driver: "firecracker",
              port: 8080,
              ...((existing?.vm as object | undefined) ?? {}),
              // Given now, it wins over the existing spec: a corrected port is
              // the usual reason to redeploy a VM that never became ready.
              ...(a.port !== undefined ? { port: Number(a.port) } : {}),
              ...(a.start_command ? { start_command: a.start_command } : {}),
            },
            scaling: existing?.scaling ?? { min_replicas: 1, max_replicas: 1 },
            build,
          };
          delete spec.artifact;
          delete spec.site;
          delete spec.update;
        }

        const deployed = await deployTool.handler({
          spec,
          ...(a.wait_seconds !== undefined ? { wait_seconds: a.wait_seconds } : {}),
        });
        sections.push({ title: "app-lb", body: deployed });
        return report(`${ns}/${repo} → deployment ${id} (${kind})`, sections);
      },
    },
  ];
}
