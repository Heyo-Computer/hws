# us5

us5 is a standalone app-lb host: app-lb, `heyvm --api`, nats and queue under
supervisor, built from source at `/opt/heyo/hws`. It runs no art store of its own. Deployments here pull from the global store
through `hub.heyo.work`, anonymously for public repositories, or through
`art.us2.heyo.work` with the store key. The bucket is the system of record
either way.

`remote.json` runs a second git remote at `git.us5.heyo.work`, also served as
`remote.heyo.work` (its canonical name, so clone URLs say `remote.heyo.work`),
backed by the same buckets as git.us2:

- `applb_` tokens resolve against us5's own app-lb (`REMOTE_APPLB_URL`), so a
  us2 namespace token does not work here.
- `hrm_` tokens, which live in the control bucket, and Heyo logins, via
  `auth.us2.heyo.work`, work in both regions.

They use the canonical `remote`, `remote-s3`, `artifacts` and `github` secrets, loaded into
us5's app-lb under the same names as on us2.

us5's app-lb runs the `remote` plugin against it, so each namespace's repos
appear in app-lb's plugin console. The `remote-plugin` secret's `api-token`
is the plugin's bearer: remote reads it as `REMOTE_PLUGIN_API_TOKEN`, and
app-lb's plugin configuration references the same key. It is a role of its
own (app-lb speaking to remote), so it is not a key on `remote`.

```sh
echo '{"url": "https://git.us5.heyo.work", "api_token": {"secret": "remote-plugin", "key": "api-token"}}' | heyctl --context us5 plugins set remote -f -
heyctl --context us5 plugins enable remote
```

`heyo-mcp.json` runs the hosted MCP server at `mcp.heyo.work`. It is the same
image and gate as mcp.us2, wired to us5's own app-lb (`admin.us5`) and git
remote (`git.us5`), and to the global store through `hub.heyo.work`. It holds
the store key (`artifacts` secret, `api-key`). `mcp/src/artscope.ts` lends that
key only to an `applb_` caller that us5's app-lb vouches for, and confines a
namespace token to `<ns>/` refs (see `mcp/deploy/vm.md`). There is no app-obs
or ci on us5, so those tools report themselves unconfigured.

```sh
heyctl --context us5 apply -f .heyo/regions/us5/remote.json
heyctl --context us5 build remote --wait
heyctl --context us5 apply -f .heyo/regions/us5/heyo-mcp.json
heyctl --context us5 pull heyo-mcp --wait
```

`heyo-mcp` pulls a prebuilt image, `heyo/heyo-mcp:<sha>`, from the global
store through the hub instead of building on this host. How to release a new
one is in `mcp/deploy/vm.md`.

This does not make us5 part of the us3/eu1 two-region acceptance in
`AGENTS.md`.

## app-lb releases

app-lb on us4 and us5 is replaced by the production CI controller
(ci.us2.heyo.work) on every release that changes it. The controller runs the
operator policy `.ci/release-policies/us2-production.yml`, not the repo's
`regional-release.yml`, which the staging controller (ci.us3) coordinates
for us3 and eu1. The steps are:

1. `merge`: fast-forward main to the validated source.
2. `hub`: publish the validated tarball as `heyo/app-lb:<sha>` and `latest`
   by digest, with no transfer into the job's VM and no checkout (see the
   policy's `hub` job).
3. `us4`, then `us5`: run `ci/rollout-host-app-lb`, so each host installs
   those exact bytes, verified by digest, and is done only when its public
   healthz reports the new revision.

Each host is enrolled once, by hand. The enrollment is a root-owned
`/etc/app-lb/host-update.json` (supervisor program `app-lb`, store
`https://art.us2.heyo.work`, health `https://admin.<host>.heyo.work/healthz`,
deployment `app-lb-admin-<host>`, and every supervisor and env file listed in
`config_files`), plus `APP_LB_HOST_UPDATE_CONFIG` in `/etc/app-lb/env`. us4
and us5 were enrolled on 2026-11-21. Editing any listed file, or swapping the
binary by hand, changes the hashes a rollout checks first, so do that between
releases, never during one.

The controller needs these in its HeyoSecret (sec2.us2):

- `ci-controller/host-app-lb-targets` with entries `app-lb-us4` and
  `app-lb-us5` (repository `https://github.com/Heyo-Computer/heyo-public.git`).
- the workflow secrets `GIT_AUTH_TOKEN`, `ART_API_KEY` (the store key), and
  `APP_LB_US_FLEET_TOKEN` (one app-lb token for both hosts, which share fleet
  state, scoped to `app-lb-admin-us4` and `app-lb-admin-us5`).

On us2, the policy is `/etc/ci/release-policies.yml`, exported as
`CI_RELEASE_POLICIES` by `/usr/local/sbin/ci-with-release-policy`, which is
what supervisor's `ci` program runs.

Rollback on a host is `/usr/local/bin/app-lb` from the previous release,
which the rollout keeps as `.previous` in `/var/lib/app-lb-host-update/`.
