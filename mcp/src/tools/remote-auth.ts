/**
 * A build credential for a repo on the Heyo git remote.
 *
 * The remote is private: app-lb clones a `build.repo` there anonymously
 * unless `build.auth` names a secret, and the build dies with "could not read
 * Username … terminal prompts disabled". `repo_deploy` always set one up;
 * `applb_deploy` with a hand-written spec did not, which is how an agent
 * following the spec schema ended up with a build that could never clone.
 * Both now go through here.
 */

import type { Clients } from "../clients/index.js";
import type { Requester } from "../http.js";
import type { Config } from "../config.js";

export interface RemoteRepo {
  namespace: string;
  repo: string;
}

/** `{ns, repo}` from a `https://host/<ns>/<repo>[.git]` URL, whatever the host. */
function repoPath(url: URL): RemoteRepo | undefined {
  const [namespace, repo, ...rest] = url.pathname.split("/").filter(Boolean);
  if (!namespace || !repo || rest.length > 0) return undefined;
  return { namespace, repo: repo.replace(/\.git$/, "") };
}

/** A clone URL compared the way git would treat it: host case and `.git` aside. */
function sameCloneUrl(a: URL, b: URL): boolean {
  const norm = (u: URL) =>
    `${u.protocol}//${u.host.toLowerCase()}${u.pathname.replace(/\/+$/, "").replace(/\.git$/, "")}`;
  return norm(a) === norm(b);
}

/**
 * `ns/repo` when `url` is a clone URL on this server's git remote.
 *
 * The remote does not hand out clone URLs on the address this server reaches
 * it by: on us5 the server talks to `https://git.us5.heyo.work` while
 * `repo_create` returns `https://remote.heyo.work/us5/<repo>.git`
 * (`REMOTE_PUBLIC_URL`). A host match alone missed exactly the URL an agent
 * copies from `repo_create`, and its build cloned anonymously and failed. So
 * a URL on another host is asked about: it is on the remote when the remote
 * holds `<ns>/<repo>` and reports that very URL as its clone URL.
 */
export async function remoteRepoOf(
  config: Config,
  remote: Requester,
  url: unknown,
): Promise<RemoteRepo | undefined> {
  if (!config.remote || typeof url !== "string") return undefined;
  let u: URL;
  let base: URL;
  try {
    u = new URL(url);
    base = new URL(config.remote.baseUrl);
  } catch {
    return undefined;
  }
  const found = repoPath(u);
  if (!found) return undefined;
  if (u.host.toLowerCase() === base.host.toLowerCase()) return found;
  if (u.protocol !== "https:" && u.protocol !== "http:") return undefined;
  const info = (await remote({
    path: `/api/repos/${encodeURIComponent(found.namespace)}/${encodeURIComponent(found.repo)}`,
  }).catch(() => undefined)) as { clone_url?: unknown } | undefined;
  if (typeof info?.clone_url !== "string") return undefined;
  try {
    return sameCloneUrl(new URL(info.clone_url), u) ? found : undefined;
  } catch {
    return undefined;
  }
}

/** The app-lb secret id a deployment's build credential is stored under. */
export function buildSecretId(deployment: string): string {
  return `git-${deployment}`.toLowerCase().replace(/[^a-z0-9_.-]/g, "-").slice(0, 64);
}

/**
 * Mint a non-expiring read token for `repo` (app-lb uses it on every
 * rebuild), store it as an app-lb secret in `secretNamespace`, and return the
 * `build.auth` block that names it.
 */
export async function storeBuildCredential(
  clients: Clients,
  repo: RemoteRepo,
  deployment: string,
  secretNamespace: string | undefined,
): Promise<{ auth: Record<string, string>; secretId: string; tokenId: string }> {
  const tok = (await clients.remote({
    method: "POST",
    path: "/api/tokens",
    body: {
      namespace: repo.namespace,
      repos: [repo.repo],
      access: "read",
      ttl_secs: 0,
      name: `applb-build-${deployment}`,
    },
  })) as { token: string; id: string };
  const secretId = buildSecretId(deployment);
  await clients.applb({
    method: "POST",
    path: "/secrets",
    body: {
      id: secretId,
      ...(secretNamespace ? { namespace: secretNamespace } : {}),
      description: `read token for ${repo.namespace}/${repo.repo} on the Heyo git remote`,
      data: { token: tok.token },
    },
  });
  return {
    auth: { secret: secretId, key: "token", username: "x-access-token" },
    secretId,
    tokenId: tok.id,
  };
}
