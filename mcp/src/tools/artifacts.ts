/**
 * The artifact store: where a deployment's bytes come from.
 *
 * ## Why this file exists
 *
 * Publishing a build is the most common thing anyone asks this server to do,
 * and until now it could not do it at all. `applb_*` can roll a deployment but
 * cannot get new bytes to it, so "update the `marketing` site with this build"
 * dead-ended halfway through every time — the tools covered every step except
 * the one that moves the artifact.
 *
 * ## The three-step sequence, and why it is a composite tool
 *
 * A publish is three requests, not two, and the order and the digests matter:
 *
 * 1. `PUT /blobs/{sha256}` — the bytes, at their own hash.
 * 2. `PUT /manifests` — `{schema:1, kind:"generic", entries:[{name,digest,size}]}`.
 *    Answers `{digest}`, which is the *manifest's* digest, not the blob's.
 * 3. `PUT /tags/{tag}` — that manifest digest, as `text/plain`.
 *
 * **A tag names a manifest, never a blob.** The store does not check this:
 * `set_tag` writes whatever digest it is handed, so tagging a blob digest
 * succeeds, and then every reader fails to resolve it — a tag that looks
 * correct in a listing and works for nobody. It is the single easiest thing to
 * get wrong here, which is exactly why {@link publishTool} exists as one call
 * instead of three primitives with a warning in the description. A composite
 * that always uses the manifest digest cannot make the mistake.
 *
 * The primitives are still exposed below, because the store has uses this
 * composite does not cover, and a tool set that can only do the one blessed
 * workflow is a tool set people work around.
 */

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import type { Config } from "../config.js";

import { z } from "zod";
import type { Clients } from "../clients/index.js";
import { json } from "../format.js";
import type { Tool } from "./diagnose.js";
import { DEFAULT_EXCLUDE, decodeFiles, fileSchema, readDirectory, tarGz } from "../files.js";
import { ServiceError } from "../http.js";
import { bool, DESTRUCTIVE_PREFIX } from "./schema.js";

/**
 * Inline downloads above this are refused in favour of `save_to` or the
 * gateway: a quarter MiB of base64 is already ~350k characters of context.
 */
const INLINE_LIMIT = 256 * 1024;

const DIGEST = /^(sha256:)?[0-9a-f]{64}$/;

interface Manifest {
  kind?: string;
  entries?: ManifestEntry[];
}

/**
 * The blob a reference names: a tag or manifest digest through its manifest
 * (one entry, or the one called `entry`), else a bare blob digest.
 */
async function resolveBlob(
  clients: Clients,
  reference: string,
  entry?: string,
): Promise<{ digest: string; name?: string; size?: number; manifest?: string }> {
  let m: Manifest | undefined;
  try {
    m = (await clients.art({ path: `/manifests/${encodeURIComponent(reference)}` })) as Manifest;
  } catch (e) {
    if (!(e instanceof ServiceError && (e.status === 404 || e.status === 400)) || !DIGEST.test(reference)) throw e;
  }
  if (!m) {
    const digest = reference.startsWith("sha256:") ? reference : `sha256:${reference}`;
    return { digest };
  }
  const entries = m.entries ?? [];
  const pick = entry ? entries.find((e) => e.name === entry) : entries.length === 1 ? entries[0] : undefined;
  if (!pick) {
    throw new Error(
      `${reference} is a manifest with ${entries.length} entries (${entries.map((e) => e.name).join(", ")}); ` +
        "name the one you want with `entry`.",
    );
  }
  return { digest: pick.digest, name: pick.name, size: pick.size, manifest: reference };
}

/** Whether these bytes are text a model can read as-is. */
function asText(bytes: Uint8Array): string | undefined {
  try {
    const s = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return /[\0-\x08\x0e-\x1f]/.test(s) ? undefined : s;
  } catch {
    return undefined;
  }
}

/** The manifest kind for a plain collection of files. Mirrors `KIND_GENERIC`. */
const KIND_GENERIC = "generic";

/** The schema version the store's readers accept. Mirrors `SCHEMA_VERSION`. */
const SCHEMA_VERSION = 1;

/**
 * How the caller supplied the bytes.
 *
 * Two ways, because this server runs in two shapes. Over stdio the host
 * launched the process and a path on this filesystem is the caller's own file,
 * which is both the natural way to say it and the only way that does not put a
 * whole build through the conversation. Over HTTP there is no shared
 * filesystem, so base64 is the only thing that can cross — at a real cost in
 * tokens, which the description says out loud rather than letting somebody
 * discover it with a 200 MB rootfs.
 */
async function bytesOf(args: Record<string, unknown>, http = false): Promise<Uint8Array> {
  const path = typeof args.path === "string" ? args.path.trim() : "";
  const b64 = typeof args.content_base64 === "string" ? args.content_base64.trim() : "";
  // Before anything else, and before any read. The schema already omits `path`
  // over HTTP, so a validated call never gets here with one; this is for any
  // caller that reaches the handler another way. Over HTTP the path names this
  // server's disk on behalf of someone who is not on it.
  if (path && http) {
    throw new Error(
      "`path` is not accepted over HTTP: it would name a file on this server's disk, " +
        "not yours. Send the bytes as `content_base64`.",
    );
  }
  if (path && b64) {
    throw new Error("give either `path` or `content_base64`, not both.");
  }
  if (path) {
    try {
      return new Uint8Array(await readFile(path));
    } catch (e) {
      throw new Error(
        `could not read ${path}: ${e instanceof Error ? e.message : String(e)}. ` +
          "A path is this server's filesystem, not the caller's — over HTTP those are " +
          "different machines, and `content_base64` is what crosses.",
      );
    }
  }
  if (b64) {
    const bytes = Buffer.from(b64, "base64");
    // `Buffer.from` never throws on bad base64; it silently drops what it
    // cannot decode. Round-tripping is the only way to notice, and noticing
    // matters here because the digest is the artifact's *name*: a truncated
    // decode publishes real bytes under a name nothing will ever ask for.
    if (bytes.toString("base64").replace(/=+$/, "") !== b64.replace(/\s+/g, "").replace(/=+$/, "")) {
      throw new Error(
        "`content_base64` is not valid base64 — it decoded to something that does not " +
          "re-encode to what was sent. Nothing was published; the digest would have named " +
          "bytes you did not mean.",
      );
    }
    return new Uint8Array(bytes);
  }
  throw new Error(
    http
      ? "no bytes: give `content_base64` — over HTTP it is the only way bytes reach this server."
      : "no bytes: give `path` (stdio) or `content_base64` (HTTP).",
  );
}

function sha256(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

interface ManifestEntry {
  name: string;
  digest: string;
  size: number;
}

interface Published {
  blob: { digest: string; size: number; name: string };
  manifest: { digest: string; kind: string };
}

/**
 * The three-request publish, shared by `art_publish` and `art_publish_files`
 * so there is exactly one place that orders it and one place that tags the
 * manifest digest rather than the blob's.
 */
async function publishBytes(
  clients: Clients,
  tag: string,
  bytes: Uint8Array,
  name: string,
  kind: string,
  annotations?: Record<string, string>,
): Promise<Published> {
  const digest = sha256(bytes);
  const entry: ManifestEntry = { name, digest, size: bytes.byteLength };

  // 1. The blob, at its own hash. Raw bytes: JSON-encoding the body would
  //    both corrupt it and change the digest it is being stored under.
  await clients.art({
    method: "PUT",
    path: `/blobs/${encodeURIComponent(digest)}`,
    rawBody: bytes,
    contentType: "application/octet-stream",
  });

  // 2. The manifest. Its digest is a pure function of its content, so this
  //    is idempotent too — the same manifest re-put is the same address.
  const manifest = {
    schema: SCHEMA_VERSION,
    kind,
    entries: [entry],
    ...(annotations ? { annotations } : {}),
  };
  const created = await clients.art({ method: "PUT", path: "/manifests", body: manifest });
  const manifestDigest =
    created && typeof created === "object" && typeof (created as { digest?: unknown }).digest === "string"
      ? (created as { digest: string }).digest
      : undefined;
  if (!manifestDigest) {
    // Refusing to continue is the whole point: the next request would
    // otherwise be a tag pointing at *something*, and the store would
    // accept it. Better a failed publish than a tag nothing can resolve.
    throw new Error(
      `the store accepted the manifest but did not answer with its digest ` +
        `(got ${json(created, 200)}). The blob at ${digest} is stored and the tag was NOT ` +
        "moved, so nothing is pointing at a half-finished publish.",
    );
  }

  // 3. The tag, naming the MANIFEST. `text/plain`, and the manifest digest
  //    rather than the blob's — see this module's header.
  await clients.art({
    method: "PUT",
    path: `/tags/${encodeURIComponent(tag)}`,
    rawBody: manifestDigest,
    contentType: "text/plain",
  });
  return { blob: entry, manifest: { digest: manifestDigest, kind } };
}

function publishTool(clients: Clients, http: boolean): Tool {
  return {
    name: "art_publish",
    description:
      "Publish a bundle to the artifact store and point a tag at it. THE TOOL TO USE for " +
      "'update deployment X with this build' — it is the step applb_pull cannot do, " +
      "because app-lb rolls a deployment onto bytes that must already be in the store.\n\n" +
      "Does the whole three-request sequence in the right order: PUT the blob at its sha256, " +
      "PUT a manifest naming it, then point the tag at THE MANIFEST'S digest. That last part " +
      "is the one that goes wrong by hand — a tag must name a manifest, the store does not " +
      "check it, and a tag pointing at a blob digest is accepted and then resolves for " +
      "nobody.\n\n" +
      (http
        ? "Give the bytes as `content_base64`, which costs ~4 tokens per 3 bytes — for " +
          "bundles, not rootfs images. This server is reached over HTTP, so a file path " +
          "would name its disk rather than yours, and `path` is not accepted here.\n\n"
        : "Give the bytes as `path` (a file on this server — right for stdio, where the host " +
          "launched this process) or `content_base64` (right for HTTP, where the caller's " +
          "filesystem is somewhere else; costs ~4 tokens per 3 bytes, so it is for bundles, not " +
          "rootfs images).\n\n") +
      "Idempotent: the store is content-addressed, so re-publishing identical bytes writes " +
      "nothing new and just moves the tag. Follow with applb_pull to roll the deployment " +
      "onto it — NOT applb_host_update, which runs a static deployment's own commands on the " +
      "app-lb host and refuses a managed one outright.",
    schema: {
      // The message moved here from the handler when schemas began to be
      // parsed: validation now runs first, so a check whose wording was worth
      // having has to live where the rejection happens.
      tag: z
        .string({ required_error: "`tag` is required — a publish nothing names is unreachable." })
        .min(1, "`tag` is required — a publish nothing names is unreachable.")
        .describe(
          "the tag to point at this build: flat, e.g. 'marketing-site', or namespaced " +
            "repo:tag, e.g. 'acme/site:v3' (a bare 'acme/site' means ':latest')",
        ),
      // Absent over HTTP rather than present-and-refused: advertising a parameter
      // that can only fail is the shape this server is organised against.
      ...(http
        ? {}
        : { path: z.string().optional().describe("file on THIS server's filesystem") }),
      content_base64: z.string().optional().describe("the bundle's bytes, base64"),
      name: z
        .string()
        .optional()
        .describe("entry name inside the manifest; defaults to the tag's last segment"),
      kind: z
        .string()
        .optional()
        .describe(`manifest kind; defaults to '${KIND_GENERIC}'`),
      annotations: z
        .record(z.string())
        .optional()
        .describe("free-form manifest annotations, e.g. a git sha"),
    },
    handler: async (a) => {
      const tag = String(a.tag ?? "").trim();
      if (!tag) throw new Error("`tag` is required — a publish nothing names is unreachable.");

      const bytes = await bytesOf(a, http);
      const published = await publishBytes(
        clients,
        tag,
        bytes,
        // A namespaced tag's `/` and `:` make a poor file name; a puller
        // writes the entry under this name.
        (a.name as string | undefined)?.trim() || tag.split("/").pop()!.replace(":", "-"),
        (a.kind as string | undefined)?.trim() || KIND_GENERIC,
        a.annotations as Record<string, string> | undefined,
      );
      return json({
        published: tag,
        blob: published.blob,
        manifest: published.manifest,
        tag_points_at: published.manifest.digest,
        // Named a tool that refuses the main case until 2026-09-10: `applb_pull`
        // is what rolls a `vm` deployment onto bytes from a store, and the tool
        // this used to name (then `applb_start_update`) applies to static and
        // site deployments only. A composite exists to make a sequence hard to
        // get wrong, so handing back the wrong next step was the worst
        // available bug.
        next:
          "applb_pull rolls a vm or site deployment onto this (applb_host_update instead for " +
          "a static `upstreams` deployment); poll the job it returns with applb_job.",
      });
    },
  };
}

export function artifactTools(clients: Clients, config: Config): Tool[] {
  const enc = encodeURIComponent;

  const http = Boolean(config.http);
  const gateway = config.artGatewayUrl;
  return [
    publishTool(clients, http),

    {
      name: "art_publish_files",
      description:
        "Bundle files into a .tar.gz and publish it under a tag, the format a `site` " +
        "deployment's `artifact` pull unpacks into its root. For an agent holding a built " +
        "site with no tar at hand. " +
        (http
          ? "Give `files` inline (utf8 or base64). "
          : "Give `files` inline, or `directory`: a folder on this machine (e.g. `dist`), " +
            "bundled with paths relative to it. ") +
        "Up to 64 MiB. Set `deployment` to also start applb_pull on it.",
      schema: {
        tag: z.string().min(1).describe("the tag to point at this bundle"),
        files: z.array(fileSchema).optional(),
        ...(http
          ? {}
          : {
              directory: z.string().optional().describe("a folder on THIS machine to bundle"),
              exclude: z.array(z.string()).optional().describe(`names skipped; default ${DEFAULT_EXCLUDE.join(", ")}`),
            }),
        annotations: z.record(z.string()).optional(),
        deployment: z.string().optional().describe("start an app-lb pull of this tag on that deployment"),
      },
      handler: async (a) => {
        const tag = String(a.tag).trim();
        const dir = typeof a.directory === "string" ? a.directory.trim() : "";
        const inline = (a.files as z.infer<typeof fileSchema>[] | undefined) ?? [];
        if (dir && http) throw new Error("`directory` is not accepted over HTTP; send `files`.");
        if (dir && inline.length) throw new Error("give `files` or `directory`, not both.");
        const entries = dir
          ? await readDirectory(dir, (a.exclude as string[] | undefined) ?? DEFAULT_EXCLUDE)
          : (() => {
              const d = decodeFiles(inline);
              if (d.deletes.length) throw new Error("`delete` has no meaning in a bundle.");
              if (!d.entries.length) throw new Error("no files: give `files`" + (http ? "." : " or `directory`."));
              return d.entries;
            })();
        const bundle = tarGz(entries);
        const published = await publishBytes(clients, tag, bundle, `${tag}.tar.gz`, KIND_GENERIC, a.annotations as
          | Record<string, string>
          | undefined);
        let pull: unknown;
        if (a.deployment) {
          pull = await clients.applb({
            method: "POST",
            path: `/deployments/${encodeURIComponent(String(a.deployment))}/pull`,
            body: { ref: tag },
          });
        }
        return json({
          published: tag,
          files: entries.length,
          bundle_bytes: bundle.byteLength,
          ...published,
          ...(pull ? { pull } : {}),
          next: pull
            ? "applb_job with the pull's id; the site serves the new files when it succeeds."
            : "a site deployment with `artifact: {store, ref: \"" + tag + "\"}` serves this; applb_pull rolls it.",
        });
      },
    },
    {
      name: "art_fetch",
      description:
        "Download from the store: a tag or manifest digest (its single entry, or `entry`), or " +
        "a blob digest. The digest is verified. Text comes back as text, anything else as " +
        "base64, up to 256 KiB inline" +
        (http ? "" : "; `save_to` writes it to a file on this machine at any size") +
        "." +
        (gateway ? ` Larger blobs: GET ${gateway}/blobs/<digest> with your own bearer.` : ""),
      schema: {
        reference: z.string().describe("tag, manifest digest, or blob digest"),
        entry: z.string().optional().describe("entry name, for a manifest with several"),
        ...(http ? {} : { save_to: z.string().optional().describe("write the bytes to this path") }),
      },
      handler: async (a) => {
        const ref = String(a.reference).trim();
        const target = await resolveBlob(clients, ref, a.entry as string | undefined);
        if (http && a.save_to) throw new Error("`save_to` is not accepted over HTTP.");
        if (!a.save_to && target.size !== undefined && target.size > INLINE_LIMIT) {
          throw new Error(
            `${ref} is ${target.size} bytes, over the ${INLINE_LIMIT >> 10} KiB inline limit. ` +
              (http
                ? gateway
                  ? `Download it from ${gateway}/blobs/${target.digest} with your bearer.`
                  : "Download it from the store directly."
                : "Pass `save_to`."),
          );
        }
        const bytes = (await clients.art({
          path: `/blobs/${encodeURIComponent(target.digest)}`,
          expectBytes: true,
        })) as Uint8Array;
        const got = sha256(bytes);
        if (got !== (target.digest.startsWith("sha256:") ? target.digest : `sha256:${target.digest}`)) {
          throw new Error(`the store returned bytes hashing to ${got}, not ${target.digest}; nothing was kept.`);
        }
        const meta = { reference: ref, digest: target.digest, name: target.name, size: bytes.byteLength };
        if (a.save_to) {
          await writeFile(String(a.save_to), bytes);
          return json({ ...meta, saved_to: a.save_to });
        }
        if (bytes.byteLength > INLINE_LIMIT) {
          throw new Error(`${bytes.byteLength} bytes is over the inline limit` + (http ? "." : "; pass `save_to`."));
        }
        const text = asText(bytes);
        return json(text !== undefined ? { ...meta, text } : { ...meta, base64: Buffer.from(bytes).toString("base64") }, Infinity);
      },
    },
    {
      name: "art_list_manifests",
      description: "Every manifest in the store: digest, kind and entries.",
      schema: {},
      handler: async () => json(await clients.art({ path: "/manifests" })),
    },
    {
      name: "art_delete_tag",
      description:
        DESTRUCTIVE_PREFIX +
        "Remove a tag. The manifest and blobs stay until gc; a deployment whose `artifact.ref` " +
        "names this tag can no longer pull.",
      schema: { tag: z.string() },
      handler: async (a) =>
        json(await clients.art({ method: "DELETE", path: `/tags/${encodeURIComponent(String(a.tag))}` })),
    },
    {
      name: "art_set_public",
      description:
        "Make a blob anonymously downloadable (`public: true`) or private again. Takes a tag, " +
        "a single-entry manifest, or a blob digest. Anyone with the digest can then fetch it, " +
        "so never for secrets.",
      schema: { reference: z.string(), public: bool() },
      handler: async (a) =>
        json(
          await clients.art({
            method: a.public ? "PUT" : "DELETE",
            path: `/public/${encodeURIComponent(String(a.reference))}`,
          }),
        ),
    },

    {
      name: "art_list_tags",
      description:
        "Every tag in the store and the digest it points at. The listing to read before " +
        "publishing over a tag, and after, to confirm it moved.",
      schema: {},
      handler: async () => json(await clients.art({ path: "/tags" })),
    },
    {
      name: "art_get_tag",
      description:
        "What one tag points at. Answers a bare digest, not JSON.\n\n" +
        "A 405 here rather than a digest means the store is running a build from before this " +
        "route existed — the fix is to redeploy it, not to work around it. `art_list_tags` " +
        "answers the same question on an old build.",
      schema: { tag: z.string() },
      handler: async (a) =>
        json(
          await clients.art({ path: `/tags/${enc(String(a.tag))}`, expectText: true }),
        ),
    },
    {
      name: "art_get_manifest",
      description:
        "One manifest by digest or by tag: its kind, its entries and their digests and sizes. " +
        "How to check what a tag actually resolves to — a tag pointing at a blob rather than " +
        "a manifest fails HERE, which is the fastest way to confirm that diagnosis.",
      schema: { reference: z.string().describe("a manifest digest, or a tag name") },
      handler: async (a) =>
        json(await clients.art({ path: `/manifests/${enc(String(a.reference))}` })),
    },
    {
      name: "art_list_blobs",
      description:
        "Every blob with its size, its label and the tags pointing at it. Answers 'what is in " +
        "this store' and 'what is taking up the space'.",
      schema: {},
      handler: async () => json(await clients.art({ path: "/blobs" })),
    },
    {
      name: "art_usage",
      description:
        "The store's disk usage. Worth reading before a large publish: the store refuses a " +
        "write that would take it under ART_MIN_FREE_BYTES, and that refusal at the end of " +
        "an upload is an expensive way to find out.",
      schema: {},
      handler: async () => json(await clients.art({ path: "/usage" })),
    },
    {
      name: "art_request",
      description:
        "Raw HTTP against the artifact store, for endpoints without a dedicated tool above. " +
        "Prefer art_publish for publishing — this one can perform the three steps in the " +
        "wrong order or tag a blob digest, both of which the store accepts and no reader can " +
        "resolve.",
      schema: {
        // Upper-cased before the enum sees it, as in `actions.ts`: a lowercase
        // `get` reached fetch and worked before arguments were parsed, and no
        // HTTP server cares about the difference.
        method: z
          .preprocess(
            (v) => (typeof v === "string" ? v.toUpperCase() : v),
            z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
          )
          .default("GET"),
        path: z.string().describe("path beginning with '/'"),
        query: z.record(z.string()).optional(),
        body: z.unknown().optional().describe("JSON body"),
        text_body: z.string().optional().describe("body sent verbatim as text/plain"),
      },
      handler: async (a) =>
        json(
          await clients.art({
            method: a.method as string,
            path: String(a.path),
            query: a.query as Record<string, string> | undefined,
            body: a.body,
            rawBody: a.text_body as string | undefined,
            contentType: a.text_body === undefined ? undefined : "text/plain",
          }),
        ),
    },
  ];
}
