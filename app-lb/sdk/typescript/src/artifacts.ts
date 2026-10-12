/**
 * One namespace's corner of the global artifact store, through app-lb's
 * `artifacts` plugin. Mirrors the `hws` crate's `ArtifactsClient`.
 *
 * The store is where a deployment's `artifact` image comes from. app-lb holds
 * its key and walls every request to the namespace's own `<ns>/` tags and
 * repositories (blobs and manifests by digest), so a namespace token is all a
 * caller needs.
 *
 * ```ts
 * const store = lb.artifacts("team-a");
 * const tags = await store.tags();
 * const v2 = await store.tag("team-a/web:v2");
 * await store.setTag("team-a/web:latest", v2.digest);   // promote
 * await store.setRepo("team-a/web", { public: true });  // publish on the hub
 * ```
 *
 * A reference outside `<namespace>/` rejects with a `ForbiddenError` that says
 * what the namespace may reach. Before the plugin is installed every call
 * rejects with a `ConflictError` whose `code` is `plugin_not_installed` (or
 * `plugin_disabled`). Writes need `admin` over the whole namespace. Pushing an
 * image itself is `heyctl artifact push`.
 */

import type { Heyctl } from "./client.js";
import type { ArtifactRepo, ArtifactStoreInfo, ArtifactTag } from "./types.js";

/** The plugin id of the artifact store plugin. */
export const ARTIFACTS_PLUGIN = "artifacts";

const seg = encodeURIComponent;
/** Each segment encoded, the `/`s between them kept: `<ns>/<repo>:<tag>`. */
const ref = (r: string) => r.split("/").map(seg).join("/");

export class ArtifactsClient {
  constructor(
    private readonly client: Heyctl,
    readonly namespace: string,
  ) {}

  private path(rest = ""): string {
    const base = `/namespaces/${seg(this.namespace)}/plugins/${ARTIFACTS_PLUGIN}/api`;
    return rest ? `${base}/${rest}` : base;
  }

  /** Whether there is a store, whether the namespace can publish, and its prefix. */
  info(signal?: AbortSignal): Promise<ArtifactStoreInfo> {
    return this.client.request("GET", this.path(), { kind: "namespace", name: this.namespace, signal });
  }

  /** Every tag under `<namespace>/`. */
  tags(signal?: AbortSignal): Promise<ArtifactTag[]> {
    return this.client.request("GET", this.path("tags"), { kind: "namespace", name: this.namespace, signal });
  }

  /** What one tag (`<ns>/<repo>:<tag>`) points at. */
  tag(tag: string, signal?: AbortSignal): Promise<ArtifactTag> {
    return this.client.request("GET", this.path(`tags/${ref(tag)}`), { kind: "artifact", name: tag, signal });
  }

  /** Point `tag` at `digest` (a manifest already in the store), creating or moving it. */
  async setTag(tag: string, digest: string, signal?: AbortSignal): Promise<void> {
    await this.client.request<void>("PUT", this.path(`tags/${ref(tag)}`), {
      text: digest,
      kind: "artifact",
      name: tag,
      signal,
      expect: "nothing",
    });
  }

  /** Remove a tag. What it pointed at stays until the store's GC finds it unreferenced. */
  async deleteTag(tag: string, signal?: AbortSignal): Promise<void> {
    await this.client.request<void>("DELETE", this.path(`tags/${ref(tag)}`), {
      kind: "artifact",
      name: tag,
      signal,
      expect: "nothing",
    });
  }

  /** A manifest, by an owned tag or by digest, as the store wrote it. */
  manifest(tagOrDigest: string, signal?: AbortSignal): Promise<Record<string, unknown>> {
    return this.client.request("GET", this.path(`manifests/${ref(tagOrDigest)}`), {
      kind: "artifact",
      name: tagOrDigest,
      signal,
    });
  }

  /** A repository (`<ns>/<repo>`) and its tags. */
  repo(repo: string, signal?: AbortSignal): Promise<ArtifactRepo> {
    return this.client.request("GET", this.path(`repos/${ref(repo)}`), { kind: "artifact", name: repo, signal });
  }

  /**
   * Set whether a repository is public (on the hub, pullable without a
   * credential) and its description. Replaces both.
   */
  setRepo(
    repo: string,
    settings: { public: boolean; description?: string | null },
    signal?: AbortSignal,
  ): Promise<ArtifactRepo> {
    return this.client.request("PUT", this.path(`repos/${ref(repo)}`), {
      body: { public: settings.public, description: settings.description ?? null },
      kind: "artifact",
      name: repo,
      signal,
    });
  }
}
