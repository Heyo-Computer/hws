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

It uses the canonical `remote`, `remote-s3` and `github` secrets, loaded into
us5's app-lb under the same names as on us2.

```sh
heyctl --context us5 apply -f .heyo/regions/us5/remote.json
heyctl --context us5 build remote --wait
```

This does not make us5 part of the us3/eu1 two-region acceptance in
`AGENTS.md`.
