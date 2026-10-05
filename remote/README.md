# remote

Git repos on S3, one bucket per Heyo account, for agents.

An agent that generates a project has files and, usually, no repo and no place
to push one. Without one, the only way it could deploy was a `site` whose
`root` named a directory on its own machine. app-lb read that path on its own
host, so the deployment registered and then 404'd every request. `remote` gives
every namespace git remotes it can reach three ways:

- **git over smart HTTP**: `git push https://remote…/<ns>/<repo>.git`. There is
  no helper to install and no SSH key.
- **A server-side commit**: `POST /api/repos/<ns>/<repo>/commits` takes JSON
  files or a tarball, for an agent with no git at all.
- **An app-lb build**: set `build.repo` to the clone URL and `build.auth` to a
  read token. A `vm` builds its Dockerfile. A `site` copies `build.context` into
  its root.

The MCP server wraps all of this: `repo_create`, `repo_write_files` and
`repo_deploy`.

## How a push is stored

S3 is the authority. Local disk is only a cache.

```text
<control bucket>/namespaces/<ns>.json                   namespace → account, bucket
<control bucket>/tokens/<id>.json                       hrm_ tokens (hash only)
<account bucket>/ns/<ns>/repos/<repo>/meta.json
<account bucket>/ns/<ns>/repos/<repo>/state.json        refs + pack list
<account bucket>/ns/<ns>/repos/<repo>/packs/pack-<sha>.{pack,idx}
```

**Before every operation**, a repo's bare cache (`REMOTE_CACHE_DIR`) is
*hydrated* from `state.json`. Missing packs are downloaded and the refs are
rewritten from the state.

**A push** runs `git receive-pack` with a `pre-receive` hook, which is this
binary (`remote hook pre-receive`). While the objects are still in git's
quarantine, the hook:

1. uploads the pushed packs;
2. replaces `state.json` with `If-Match` on the ETag the cache was hydrated
   from.

If any instance in any region pushed first, that write fails and git rejects the
push. The client sees `another push to this repo landed first; fetch and push
again`. Nothing has moved anywhere. Two regional instances can therefore serve
the same repo with no lock service, and a cache can be deleted at any time.

**A server-side commit** is built in a scratch repo and `git push`ed into the
cache. That goes through the same hook, so there is one write path.

**Buckets** are created on first use:

- The name is `<REMOTE_BUCKET_PREFIX>-<24 hex of sha256(account)>`.
- On AWS, every bucket is created with a public-access block and SSE-S3
  default encryption.
- A namespace is bound to the account of whoever creates its first repo, using
  a conditional write. The first binding stands.

## Auth

The model is app-lb's (`app-lb/src/federated.rs`, `admin.rs` `decide_access`):

| bearer | resolved by |
| --- | --- |
| `REMOTE_ADMIN_TOKEN` | itself: the unconfined operator |
| `hrm_<id>_<secret>` | a token minted here: one namespace, optionally some repos, read or write |
| `applb_<id>_<secret>` | app-lb's `GET /whoami` (`REMOTE_APPLB_URL`) |
| anything else | the Heyo auth service's `GET /api/auth/scopes` (`REMOTE_AUTH_URL`) |

The tiers are:

- **read**: clone and list.
- **write**: push and commit.
- **admin**: create and delete repos, and mint tokens. Only federated and
  app-lb namespace admins have it.

git sends a token as the password of Basic auth (any username), or with
`git -c http.extraHeader="Authorization: Bearer <token>"`. app-lb builds use
username `x-access-token`, which is app-lb's default.

## Web UI

The same host serves a server-rendered UI, modelled on GitHub's:

- a dashboard of your repos and namespaces;
- a namespace page, with **New repository** and **Tokens** for admins;
- per repo: the code tab (file tree, last commit per file, rendered README,
  clone URL), file view with line anchors, raw, history, commits with diffs,
  branches, tags and settings (delete).

**Permissions come from app-lb.** The UI keeps no permission model of its own.
A browser session is a bearer in a cookie, resolved by the same providers as
the API:

- **Sign in with a Heyo email and password.** The password is posted to
  `REMOTE_AUTH_URL`'s `/api/auth/login`, as app-lb's dashboard does. The
  token's namespaces come from `/api/auth/scopes`, which are the grants app-lb
  enforces.
- **Paste a token.** An `applb_` token is resolved by app-lb's `GET /whoami`.
- **Handoff.** The Heyo front end can `POST /-/handoff` a form of `token` and
  `namespace`, like app-lb's `/login/handoff`.

A person sees only the namespaces they reach, and only the repos a repo token
is confined to. A repo they cannot read is a 404, not a 403. Writes (create,
delete, mint, revoke) need admin in the namespace.

Cookies and forms:

- The cookie is `HttpOnly` and `SameSite=Lax`. It is `__Host-heyo-git` and
  `Secure` when `REMOTE_PUBLIC_URL` is https, and `heyo_git` otherwise.
- Every form post must carry this origin. The exception is `/-/handoff`, which
  can only sign a browser in.
- READMEs are rendered with raw HTML shown as text.
- Raw files are served as `text/plain` under a `sandbox` CSP, except raster
  images.

There is no app-lb gate in front, for two reasons: git cannot pass a sign-in
page, and the gate forwards an identity but no namespaces.

The UI's own paths sit under `/-/` and `/__ui/`. `REMOTE_WEB=0` turns the UI
off. The theme cookie follows `REMOTE_UI_COOKIE_DOMAIN`, else
`HEYO_UI_COOKIE_DOMAIN` (see `ui/README.md`).

## API

| | |
| --- | --- |
| `POST /api/repos/{ns}` `{name, description?, default_branch?}` | create (admin) |
| `GET /api/repos/{ns}` | list |
| `GET /api/repos/{ns}/{repo}` | meta, HEAD, refs |
| `DELETE /api/repos/{ns}/{repo}` | delete (admin) |
| `POST /api/repos/{ns}/{repo}/commits` | JSON `{message, files:[{path, content, encoding?, executable?, delete?}], branch?, base?, replace?}`, or a `application/gzip` tarball with `?message=&branch=&replace=` |
| `POST /api/tokens` `{namespace, access, repos?, ttl_secs?, name?}` | mint; `ttl_secs: 0` never expires |
| `GET /api/tokens?namespace=` / `DELETE /api/tokens/{id}` | list / revoke (admin) |
| `GET /{ns}/{repo}.git/info/refs`, `POST …/git-upload-pack`, `POST …/git-receive-pack` | smart HTTP |
| `GET /healthz`, `GET /whoami` | |

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `REMOTE_LISTEN` | `0.0.0.0:9700` | |
| `REMOTE_PUBLIC_URL` | `http://<listen>` | what clone URLs start with; app-lb must reach it |
| `REMOTE_STORE` | `s3` | or `fs:<dir>` for development (one host's disk, not an authority two regions can share) |
| `REMOTE_S3_REGION` | `AWS_REGION`, else `us-east-1` | |
| `REMOTE_S3_ENDPOINT` | AWS | an S3-compatible endpoint, path-style |
| `REMOTE_S3_ACCESS_KEY_ID` / `REMOTE_S3_SECRET_ACCESS_KEY` | `AWS_*` | |
| `REMOTE_S3_HEYOSECRET_PATH` | | a heyosecret path holding `{"access_key_id","secret_access_key"}`, read via `HEYOSECRET_URL` when the keys are unset |
| `REMOTE_S3_HARDEN` | on for AWS | public-access block + default encryption on ensure |
| `REMOTE_BUCKET_PREFIX` | `heyo-git` | |
| `REMOTE_CONTROL_BUCKET` | `<prefix>-control` | |
| `REMOTE_AUTH_URL` | | Heyo auth service |
| `REMOTE_APPLB_URL` | | app-lb admin API, for `applb_` tokens |
| `REMOTE_ADMIN_TOKEN` | | operator bearer |
| `REMOTE_DEFAULT_ACCOUNT` | | account for namespaces no credential names one for (self-hosted) |
| `REMOTE_CACHE_DIR` | `/var/lib/remote/cache` | |
| `REMOTE_MAX_PUSH_MB` | `512` | |
| `REMOTE_ALLOW_FORCE_PUSH` | off | `receive.denyNonFastForwards` otherwise |
| `REMOTE_MAX_TOKEN_TTL_SECS` | 30 days | cap on a token's `ttl_secs`; `0` (no expiry) is allowed |
| `REMOTE_WEB` | on | `0` serves the API and git only, with no web UI |

The S3 credential needs these permissions on `<prefix>-*`:

- `s3:CreateBucket`
- `s3:PutBucketPublicAccessBlock`
- `s3:PutEncryptionConfiguration`
- object `Get`, `Put` and `Delete`
- `ListBucket`

Use one canonical `remote` credential across regions.

## Deploying

`deploy/remote.json` runs it as an app-lb managed VM, built from
`remote/Dockerfile` with the repository root as the build context (the crate
depends on `../heyosecret-client`):

```sh
heyctl create secret remote-s3 --from-env access-key-id=AK --from-env secret-access-key=SK
heyctl create secret remote --from-env admin-token=TOKEN
heyctl apply -f remote/deploy/remote.json
heyctl build remote --wait
```

The canonical values live in HeyoSecret at `remote-s3/access-key-id`,
`remote-s3/secret-access-key` and `remote/admin-token`. Every region loads
the same three into its app-lb.

The deployment has **no app-lb `auth` gate**. git clients and app-lb builds
authenticate to remote itself, and a gate in front would demand a second
credential that git cannot send.

The VM is disposable. Its `disk_size_gb` disk holds only `REMOTE_CACHE_DIR`,
which re-hydrates from the bucket, so it needs no `vm.workspace`.
`REMOTE_APPLB_URL` is the region's public admin URL, because a VM cannot reach
the host's loopback admin listener. `REMOTE_DEFAULT_ACCOUNT=heyo` lets a
namespace `applb_` token, which carries no Heyo account, create a namespace's
first repo; such namespaces share the `heyo` account's bucket. For another region, change the route,
`REMOTE_PUBLIC_URL` and `REMOTE_APPLB_URL`.

## Test

```sh
cargo test --locked --manifest-path remote/Cargo.toml
# the same end-to-end flow against S3 (MinIO, moto, …):
REMOTE_TEST_S3_ENDPOINT=http://127.0.0.1:9000 \
REMOTE_TEST_S3_ACCESS_KEY_ID=… REMOTE_TEST_S3_SECRET_ACCESS_KEY=… \
  cargo test --locked --manifest-path remote/Cargo.toml --test e2e
```

`tests/e2e.rs` runs two instances (two "regions") over one store, using the
real `git` client. It covers:

- a fresh project pushed with no prior repo, and a read token refused a push;
- a clone through the instance with the cold cache;
- a stale concurrent push refused, then landed after a rebase;
- a commit with no git, and a stale `base` refused with 409;
- delete;
- the web UI: each session sees only the namespaces a stub app-lb and auth
  service grant it, and browsing, forms, origin checks and handoff all work.

## Not done yet

- **Pack compaction.** Every push adds a pack, and nothing merges them yet.
- **Garbage collection** of packs a lost race uploaded but no state names.
- **Cache eviction.**
- **Bucket deletion** when an account goes away.
