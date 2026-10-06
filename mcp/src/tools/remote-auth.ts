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
import type { Config } from "../config.js";

export interface RemoteRepo {
  namespace: string;
  repo: string;
}

/** `ns/repo` when `url` is a clone URL on this server's git remote. */
export function remoteRepoOf(config: Config, url: unknown): RemoteRepo | undefined {
  if (!config.remote || typeof url !== "string") return undefined;
  let u: URL;
  let base: URL;
  try {
    u = new URL(url);
    base = new URL(config.remote.baseUrl);
  } catch {
    return undefined;
  }
  if (u.host.toLowerCase() !== base.host.toLowerCase()) return undefined;
  const [namespace, repo, ...rest] = u.pathname.split("/").filter(Boolean);
  if (!namespace || !repo || rest.length > 0) return undefined;
  return { namespace, repo: repo.replace(/\.git$/, "") };
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
