# Onboarding

A new Heyo user goes from sign-up to a running app in three places:

1. **Heyo (retail).** On first sign-in, a user with no namespace is sent to `/welcome` and asked to create one. Cloud creates the namespace and sets it up on app-lb: it declares the namespace and adds a `heyo` sign-in provider to it (see [Authentication](app-lb-auth.md)). Heyo then opens the app-lb dashboard for that namespace (`POST /login/handoff`).
2. **The app-lb dashboard.** While the namespace is empty, the dashboard shows a **Get started** card, which can be reopened from the top bar. It has three steps:
   - **Mint a token.** This mints an `admin` token confined to the namespace, which expires within `APP_LB_TENANT_TOKEN_MAX_TTL_SECS` (90 days by default). See [Namespace admins mint their own tokens](app-lb-auth.md#namespace-admins-mint-their-own-tokens).
   - **Install the MCP server.** The card gives the endpoint (`APP_LB_ONBOARDING_MCP_URL`) and the command with the token filled in:

     ```sh
     claude mcp add --transport http heyo https://mcp.us2.heyo.work/mcp \
       --header "Authorization: Bearer applb_…"
     ```

   - **Deploy fastcar.** The card gives a deployment spec, built for this namespace by `GET /onboarding`, and a request to paste into Claude Code. The same spec also works with `heyctl apply -f`.
3. **Claude Code.** Claude deploys the spec with `applb_deploy`. The first request to the URL boots the VM.

## The fastcar spec

[fastcar](https://github.com/Heyo-Computer/fastcar) is an agent workspace. The spec runs it from the public Firecracker image named `APP_LB_ONBOARDING_FASTCAR_IMAGE` (`fastcar`):

- **Mock mode.** `FASTCAR_MOCK=1`, so it boots without model keys. The image's own Postgres holds its state on a 10 GB data disk.
- **Size and scaling.** `medium` size class, at most one VM, scaled to zero after 30 minutes idle.
- **Address.** The deployment is `fastcar-<namespace>`. When the fleet generates hostnames, it answers at `fastcar-<namespace>.<base domain>`.
- **Sign-in.** It sits behind the namespace's `heyo` provider. Only `/api/health` is public. fastcar is an agent with a shell, so it is never deployed ungated. If the namespace has no `heyo` provider, the card says so and the spec has no gate.
- **Image download.** With `APP_LB_PUBLIC_IMAGE_CATALOG_URL` set, the spec carries the catalog download URL, size and digest, which the daemon verifies the image against. Without it, the spec works only on a host that already holds the image.

To run fastcar for real, store `INCEPTION_API_KEY`, `OPENROUTER_API_KEY` and optionally `TAVILY_API_KEY` as namespace secrets. Reference them from `vm.env_from`, then set `FASTCAR_MOCK=0`.

## `GET /onboarding`

This is a view-tier route. It answers only about a namespace the caller reaches. `?namespace=` defaults to the caller's only namespace.

```json
{
  "namespace": "acme",
  "deployments": 0,
  "can_mint": true,
  "mcp": { "name": "heyo", "url": "https://mcp.us2.heyo.work/mcp" },
  "token": { "max_ttl_secs": 7776000 },
  "fastcar": {
    "id": "fastcar-acme",
    "url": "https://fastcar-acme.us2.heyo.work",
    "gated": true,
    "image": "ok",
    "note": null,
    "spec": { "id": "fastcar-acme", "namespace": "acme", "…": "…" }
  }
}
```

`fastcar.image` is one of these:

- `ok`: the catalog has the image.
- `not_found`: the catalog has no such image.
- `unconfigured`: no catalog URL is set.
- `error`: the lookup failed.

For every value but `ok`, `note` says why.
