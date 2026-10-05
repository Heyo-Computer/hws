# us5

us5 is a standalone app-lb host: app-lb, `heyvm --api`, nats and queue under
supervisor, built from source at `/opt/heyo/hws`. It runs no art store of its own. Deployments here pull from the global store
through `hub.heyo.work`, anonymously for public repositories, or through
`art.us2.heyo.work` with the store key. The bucket is the system of record
either way.

`remote.json` runs a second git remote at `git.us5.heyo.work`, backed by the
same buckets as git.us2:

- `applb_` tokens resolve against us5's own app-lb (`REMOTE_APPLB_URL`), so a
  us2 namespace token does not work here.
- `hrm_` tokens, which live in the control bucket, and Heyo logins, via
  `auth.us2.heyo.work`, work in both regions.

They use the canonical `remote`, `remote-s3`, `artifacts` and `github` secrets, loaded into
us5's app-lb under the same names as on us2.

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
heyctl --context us5 build heyo-mcp --wait
```

This does not make us5 part of the us3/eu1 two-region acceptance in
`AGENTS.md`.
