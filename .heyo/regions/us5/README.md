# us5

us5 is a standalone app-lb host: app-lb, `heyvm --api`, nats and queue under
supervisor, built from source at `/opt/heyo/hws`. These specs make it a second
region for the two services whose state lives in S3:

- `artifacts.json` runs the art store at `art.us5.heyo.work` as a **regional
  cache** of `s3://heyo-artifact-hub/art/` (us-east-2). It shares tags with
  art.us2 within `ART_TAG_TTL`. There is nothing to backfill: it starts empty
  and fills from the bucket. The public hub stays on us2 only.
- `remote.json` runs a second git remote at `git.us5.heyo.work`, backed by the
  same buckets. `applb_` tokens resolve against us5's own app-lb
  (`REMOTE_APPLB_URL`), so a us2 namespace token does not work here. `hrm_`
  tokens, which live in the control bucket, and Heyo logins, via
  `auth.us2.heyo.work`, work in both regions.

Both use the canonical secrets, loaded into us5's app-lb under the same names
as on us2: `artifacts`, `artifacts-s3`, `remote`, `remote-s3` and `github`.

```sh
heyctl --context us5 apply -f .heyo/regions/us5/artifacts.json
heyctl --context us5 build artifacts --wait
heyctl --context us5 apply -f .heyo/regions/us5/remote.json
heyctl --context us5 build remote --wait
```

This does not make us5 part of the us3/eu1 two-region acceptance in
`AGENTS.md`.
