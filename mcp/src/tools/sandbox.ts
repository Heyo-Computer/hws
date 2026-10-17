/**
 * Sandboxes: VMs an agent creates, runs code in, moves files through, pauses
 * between steps and deletes — all on app-lb.
 *
 * A sandbox is an app-lb deployment with no route: one Firecracker VM from a
 * hub image, a data disk at `/workspace`, `idle_action: retain` so a stop keeps
 * that disk, and reached only through these tools. Nothing here calls the Heyo
 * cloud API, so the app-lb token that deploys apps is the only credential a
 * sandbox needs — which is what lets the hosted server offer them at all.
 *
 * # Which tool for what
 *
 * - **Short commands** (under ~30 s): `sandbox_exec`. It holds the VM's only
 *   console until the command ends, and the call times out with the server.
 * - **Long ones** (a test suite, a coding session): `sandbox_exec_start`, then
 *   `sandbox_exec_status` to page the output. They run detached, several at
 *   once, and keep the VM up while they run.
 * - **Small files** (≤1 MiB): `sandbox_read_file` / `sandbox_write_file`, over
 *   the console.
 * - **Archives**: `sandbox_upload` / `sandbox_download` hand back a one-time URL
 *   the caller `curl`s; the guest fetches or pushes the bytes over the network.
 *
 * # What is destructive
 *
 * `sandbox_kill` deletes the sandbox and its disk. `sandbox_stop` does not: the
 * disk under `/workspace` comes back on `sandbox_start` (the rest of the
 * filesystem is the image again).
 */

import { z } from "zod";
import { bool, num, DESTRUCTIVE_PREFIX } from "./schema.js";
import type { Clients } from "../clients/index.js";
import type { Config } from "../config.js";
import { json, report } from "../format.js";
import { ServiceError } from "../http.js";
import type { Tool } from "./diagnose.js";
import { compactExec, GUEST_MAX_CHARS, type GuestExec } from "./actions.js";

const DESTRUCTIVE = DESTRUCTIVE_PREFIX;

/** Where a sandbox's image comes from unless the caller names another. */
export const HUB_STORE = "https://hub.heyo.work";
export const DEFAULT_IMAGE = "heyo/debian:latest";

/** Seconds a lifecycle call may wait on app-lb, plus this, is its deadline. */
const WAIT_MARGIN_MS = 15_000;

function sandboxId(): string {
  const hex = Array.from({ length: 4 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, "0"));
  return `sbx-${hex.join("")}`;
}

/** The deployment spec a sandbox is. Exported for tests. */
export function sandboxSpec(a: Record<string, unknown>, id: string): Record<string, unknown> {
  const vm: Record<string, unknown> = {
    driver: "firecracker",
    // Health is a TCP connect to sshd, which the hub images run; the sandbox
    // takes no traffic on it.
    port: 22,
    size_class: a.size_class ?? "small",
    disk_size_gb: a.disk_size_gb ?? 10,
  };
  if (a.start_command) vm.start_command = a.start_command;
  if (a.working_directory) vm.working_directory = a.working_directory;
  if (a.env_vars) vm.env_vars = a.env_vars;
  return {
    id,
    ...(a.namespace ? { namespace: a.namespace } : {}),
    routes: [],
    artifact: { store: HUB_STORE, ref: a.image ?? DEFAULT_IMAGE },
    vm,
    health: { path: null },
    scaling: {
      min_replicas: 0,
      max_replicas: 1,
      idle_action: "retain",
      scale_to_zero_after_secs: a.idle_secs ?? 600,
    },
  };
}

function isSandbox(d: unknown): boolean {
  const spec = (d as { spec?: { routes?: unknown[]; vm?: unknown } })?.spec;
  return Boolean(spec?.vm) && Array.isArray(spec?.routes) && spec!.routes!.length === 0;
}

export function sandboxTools(clients: Clients, _config: Config, deployTool?: Tool): Tool[] {
  const enc = encodeURIComponent;
  const dep = (id: unknown, suffix = "") => `/deployments/${enc(String(id))}${suffix}`;
  const waitSecs = (v: unknown, fallback: number) => Math.max(0, Math.min(Number(v ?? fallback), 300));

  const lifecycle = (verb: string, id: unknown, body: Record<string, unknown>, wait: number) =>
    clients.applb({
      method: "POST",
      path: dep(id, `/${verb}`),
      body,
      timeoutMs: wait * 1000 + WAIT_MARGIN_MS,
    });

  return [
    {
      name: "sandbox_create",
      description:
        "Create a sandbox: a Firecracker VM from a hub image (default heyo/debian:latest) with " +
        "a /workspace disk that survives sandbox_stop. Waits for it to be ready unless " +
        "wait_seconds is 0. Then use sandbox_exec / sandbox_exec_start.",
      schema: {
        name: z.string().optional().describe("sandbox id; default sbx-<random>"),
        image: z.string().optional().describe("hub image, e.g. heyo/ubuntu:latest"),
        size_class: z.enum(["micro", "mini", "small", "medium", "large", "xlarge"]).optional(),
        disk_size_gb: num().optional().describe("/workspace disk; default 10"),
        start_command: z.string().optional(),
        working_directory: z.string().optional(),
        env_vars: z.record(z.string()).optional(),
        idle_secs: num().optional().describe("idle seconds before it stops itself; default 600"),
        namespace: z.string().optional().describe("defaults to your token's"),
        wait_seconds: num().optional().describe("default 120; 0 returns at once"),
      },
      handler: async (a) => {
        if (!deployTool) throw new Error("sandbox_create needs applb_deploy, which this server lacks");
        const id = typeof a.name === "string" && a.name.trim() ? a.name.trim() : sandboxId();
        const exists = await clients
          .applb({ path: dep(id) })
          .then(() => true)
          .catch((e) => {
            if (e instanceof ServiceError && (e.status === 404 || e.status === 403)) return false;
            throw e;
          });
        if (exists) {
          return `Sandbox ${id} already exists; use it (sandbox_info) or pick another name.`;
        }
        const wait = waitSecs(a.wait_seconds, 120);
        // The hub images start what a sandbox needs (sshd) from their own init.
        const deployed = await deployTool.handler({
          spec: sandboxSpec(a, id),
          wait_seconds: wait,
          ...(a.start_command ? {} : { no_start_command: true }),
        });
        const registered = await clients
          .applb({ path: dep(id) })
          .then(() => true)
          .catch(() => false);
        if (!registered) return deployed;
        if (wait === 0) return `${deployed}\n\nNot waited for: sandbox_start ${id} waits for its VM.`;
        const started = await lifecycle("start", id, { wait_secs: wait }, wait);
        return report(`Sandbox ${id}`, [
          { title: "State", body: started },
          { title: "Created", body: deployed },
          {
            title: "Next",
            body:
              "sandbox_exec for short commands, sandbox_exec_start for long ones; keep work " +
              "under /workspace. sandbox_stop pauses it, sandbox_kill deletes it.",
          },
        ]);
      },
    },
    {
      name: "sandbox_list",
      description: "Your sandboxes (deployments with no route), with their pool state.",
      schema: {},
      handler: async () => {
        const all = (await clients.applb({ path: "/deployments" })) as unknown;
        const list = Array.isArray(all) ? all.filter(isSandbox) : [];
        return json(
          list.map((d) => {
            const r = d as Record<string, unknown>;
            const spec = r.spec as Record<string, unknown>;
            return {
              id: spec.id,
              namespace: spec.namespace,
              ready: r.ready,
              pending: r.pending,
              stopped: (spec.scaling as Record<string, unknown> | undefined)?.max_replicas === 0,
              vms: r.vms,
            };
          }),
        );
      },
    },
    {
      name: "sandbox_info",
      description: "One sandbox: its spec, VMs and state.",
      schema: { id: z.string() },
      handler: async (a) => json(await clients.applb({ path: dep(a.id) })),
    },
    {
      name: "sandbox_exec",
      description:
        DESTRUCTIVE +
        "Run a short command (under ~30s) in the sandbox and return its output. Anything " +
        "longer: sandbox_exec_start. Each call starts in / with a fresh shell: cd first.",
      schema: {
        id: z.string(),
        command: z.string(),
        cwd: z.string().optional(),
        env: z.record(z.string()).optional(),
        timeout_secs: num().optional(),
        max_chars: num().optional().describe(`default 12000, max ${GUEST_MAX_CHARS}`),
      },
      handler: async (a) => {
        const out = json(
          compactExec(
            (await clients.applb({
              method: "POST",
              path: dep(a.id, "/exec"),
              body: {
                command: a.command,
                ...(a.cwd === undefined ? {} : { cwd: a.cwd }),
                ...(a.env === undefined ? {} : { env: a.env }),
                ...(a.timeout_secs === undefined ? {} : { timeout_secs: a.timeout_secs }),
              },
            })) as GuestExec,
          ),
          a.max_chars === undefined ? undefined : Math.min(Number(a.max_chars), GUEST_MAX_CHARS),
        );
        return out.includes("… truncated at ")
          ? `${out}\nFor all of it: run it with sandbox_exec_start and page sandbox_exec_status.`
          : out;
      },
    },
    {
      name: "sandbox_exec_start",
      description:
        DESTRUCTIVE +
        "Start a command detached in the sandbox and return at once with an operation id. For " +
        "anything over ~30s; several can run at once. Follow with sandbox_exec_status.",
      schema: {
        id: z.string(),
        command: z.string(),
        cwd: z.string().optional(),
        env: z.record(z.string()).optional(),
        max_runtime_secs: num().optional().describe("default 3600, max 21600"),
      },
      handler: async (a) =>
        json(
          await clients.applb({
            method: "POST",
            path: dep(a.id, "/operations"),
            body: {
              command: a.command,
              ...(a.cwd === undefined ? {} : { cwd: a.cwd }),
              ...(a.env === undefined ? {} : { env: a.env }),
              ...(a.max_runtime_secs === undefined ? {} : { max_runtime_secs: a.max_runtime_secs }),
            },
            timeoutMs: 150_000,
          }),
        ),
    },
    {
      name: "sandbox_exec_status",
      description:
        "An operation's state (running, succeeded, failed, cancelled, timed_out, lost), exit " +
        "code, and a page of its output from offset (next_offset continues it; tail for the end).",
      schema: {
        id: z.string(),
        operation: z.string(),
        offset: num().optional(),
        max_bytes: num().optional().describe("default 65536, max 262144"),
        tail: bool().optional(),
      },
      handler: async (a) =>
        json(
          await clients.applb({
            path: dep(a.id, `/operations/${enc(String(a.operation))}`),
            query: {
              offset: a.offset as number | undefined,
              max_bytes: (a.max_bytes as number | undefined) ?? 65_536,
              tail: a.tail ? "true" : undefined,
            },
          }),
        ),
    },
    {
      name: "sandbox_exec_cancel",
      description: "Cancel an operation: SIGTERM to its process group, SIGKILL 10s later.",
      schema: { id: z.string(), operation: z.string() },
      handler: async (a) =>
        json(
          await clients.applb({
            method: "DELETE",
            path: dep(a.id, `/operations/${enc(String(a.operation))}`),
          }),
        ),
    },
    {
      name: "sandbox_read_file",
      description:
        "Read up to 256 KiB of a file in the sandbox from offset; next_offset continues it. " +
        "Binary comes back base64. Larger: sandbox_download.",
      schema: {
        id: z.string(),
        path: z.string().describe("absolute path"),
        offset: num().optional(),
        length: num().optional(),
      },
      handler: async (a) =>
        json(
          await clients.applb({
            path: dep(a.id, "/files"),
            query: {
              path: String(a.path),
              offset: a.offset as number | undefined,
              length: a.length as number | undefined,
            },
          }),
        ),
    },
    {
      name: "sandbox_write_file",
      description:
        DESTRUCTIVE +
        "Write up to 1 MiB to a file in the sandbox (replace, or append); parent directories " +
        "are created. Larger: sandbox_upload.",
      schema: {
        id: z.string(),
        path: z.string().describe("absolute path"),
        content: z.string(),
        encoding: z.enum(["text", "base64"]).optional(),
        append: bool().optional(),
      },
      handler: async (a) => {
        const bytes =
          a.encoding === "base64" ? Buffer.from(String(a.content), "base64") : Buffer.from(String(a.content));
        return json(
          await clients.applb({
            method: "PUT",
            path: dep(a.id, "/files"),
            query: { path: String(a.path), append: a.append ? "true" : undefined },
            rawBody: new Uint8Array(bytes),
          }),
        );
      },
    },
    {
      name: "sandbox_upload",
      description:
        "Get a one-time URL to upload a file or archive into the sandbox: curl -T it there " +
        "(no credential needed) and the guest places it at path, unpacking tar/tar.gz into it.",
      schema: {
        id: z.string(),
        path: z.string().describe("destination: a file, or the directory to unpack into"),
        extract: z.enum(["none", "tar", "tar.gz", "auto"]).optional().describe("default auto"),
        strip_components: num().optional(),
        ttl_secs: num().optional(),
        max_bytes: num().optional(),
      },
      handler: async (a) => {
        const t = (await clients.applb({
          method: "POST",
          path: dep(a.id, "/transfers"),
          body: {
            direction: "in",
            path: a.path,
            extract: a.extract ?? "auto",
            ...(a.strip_components === undefined ? {} : { strip_components: a.strip_components }),
            ...(a.ttl_secs === undefined ? {} : { ttl_secs: a.ttl_secs }),
            ...(a.max_bytes === undefined ? {} : { max_bytes: a.max_bytes }),
          },
        })) as { upload_url?: string; id?: string };
        return report(`Upload ${t.id ?? ""} ready`, [
          { title: "Upload with", body: `curl -sS -T <file> '${t.upload_url}'` },
          {
            title: "Notes",
            body:
              "Single-use and expiring; the URL is the credential, so keep it out of logs. The " +
              "response to the upload says when the guest has placed it; sandbox_transfer_status " +
              "shows it later.",
          },
          { title: "Transfer", body: t },
        ]);
      },
    },
    {
      name: "sandbox_download",
      description: "Get a one-time URL to download a file, or a directory as a tar.gz, from the sandbox.",
      schema: {
        id: z.string(),
        path: z.string().describe("a file, or a directory (sent as tar.gz)"),
        wait_secs: num().optional().describe("how long to wait for the guest's push; default 50"),
      },
      handler: async (a) => {
        const wait = waitSecs(a.wait_secs, 50);
        const t = (await clients.applb({
          method: "POST",
          path: dep(a.id, "/transfers"),
          body: { direction: "out", path: a.path, wait_secs: wait },
          timeoutMs: wait * 1000 + WAIT_MARGIN_MS,
        })) as { download_url?: string; state?: string; id?: string };
        const ready = t.state === "ready";
        return report(ready ? `Download ${t.id} ready` : `Download ${t.id} still collecting`, [
          {
            title: "Download with",
            body:
              `curl -sS -o <out> '${t.download_url}'` +
              (ready ? "" : "\n(works once sandbox_transfer_status says ready)"),
          },
          { title: "Notes", body: "Up to three downloads, then the URL stops working; it is the credential." },
          { title: "Transfer", body: t },
        ]);
      },
    },
    {
      name: "sandbox_transfer_status",
      description: "One upload or download: its state, size, sha256 and any error.",
      schema: { id: z.string(), transfer: z.string() },
      handler: async (a) =>
        json(await clients.applb({ path: dep(a.id, `/transfers/${enc(String(a.transfer))}`) })),
    },
    {
      name: "sandbox_stop",
      description:
        "Pause the sandbox: its VM stops and /workspace is kept for sandbox_start. Nothing " +
        "wakes it until then. Refused while background commands run unless force: true " +
        "(they are marked lost; their output stays on /workspace).",
      schema: { id: z.string(), wait_secs: num().optional(), force: bool().optional() },
      handler: async (a) => {
        const wait = waitSecs(a.wait_secs, 30);
        return json(await lifecycle("stop", a.id, { wait_secs: wait, force: Boolean(a.force) }, wait));
      },
    },
    {
      name: "sandbox_start",
      description: "Resume a stopped sandbox with its /workspace, and wait for it.",
      schema: { id: z.string(), wait_secs: num().optional() },
      handler: async (a) => {
        const wait = waitSecs(a.wait_secs, 60);
        return json(await lifecycle("start", a.id, { wait_secs: wait }, wait));
      },
    },
    {
      name: "sandbox_restart",
      description:
        "Restart the sandbox keeping /workspace, or with fresh: true boot a new VM with an " +
        "empty disk. force: true as for sandbox_stop.",
      schema: { id: z.string(), fresh: bool().optional(), force: bool().optional() },
      handler: async (a) =>
        json(
          await lifecycle(
            "restart",
            a.id,
            { wait_secs: 60, fresh: Boolean(a.fresh), force: Boolean(a.force) },
            120,
          ),
        ),
    },
    {
      name: "sandbox_kill",
      description: DESTRUCTIVE + "Delete the sandbox, its VM and its /workspace disk. No undo.",
      schema: { id: z.string() },
      handler: async (a) => {
        await clients.applb({ method: "DELETE", path: dep(a.id) });
        return `Sandbox ${a.id} deleted.`;
      },
    },
    {
      name: "heyo_capacity",
      description: "What the host has left (CPU, memory, disk) and your sandboxes' VMs.",
      schema: {},
      handler: async () => json(await clients.applb({ path: "/capacity" })),
    },
  ];
}
