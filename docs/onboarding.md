# Onboarding

A new Heyo user goes from sign-up to a running app in three places:

1. **Heyo (retail).** On first sign-in, a user with no namespace is sent to `/welcome` and asked to create one. Cloud creates the namespace and sets it up on app-lb: it declares the namespace and adds a `heyo` sign-in provider to it (see [Authentication](app-lb-auth.md)). Heyo then opens the app-lb dashboard for that namespace (`POST /login/handoff`).
2. **The app-lb dashboard.** While the namespace is empty, the dashboard shows a **Get started** card, which can be reopened from the top bar. It has three steps:
   - **Mint a token.** This mints an `admin` token confined to the namespace, which expires within `APP_LB_TENANT_TOKEN_MAX_TTL_SECS` (90 days by default). See [Namespace admins mint their own tokens](app-lb-auth.md#namespace-admins-mint-their-own-tokens).
   - **Add the MCP server to Claude Code.** Until a token is minted, this step tells the user to mint one first. Once it is minted, the step gives the endpoint (`APP_LB_ONBOARDING_MCP_URL`) and the command, with the token and the server name (`APP_LB_ONBOARDING_MCP_NAME`) filled in:

     ```sh
     claude mcp add --transport http heyo https://mcp.us2.heyo.work/mcp \
       --header "Authorization: Bearer applb_…"
     ```

     It then says to restart Claude Code and check `/mcp`, or to ask Claude to run `heyo_status` on the server. For other clients that take a URL and headers, it gives the same server as an `mcpServers` JSON entry. The token is the server's only authority. It reaches the app-lb tools, git repos, and artifact-store tags under `<namespace>/` (see `mcp/deploy/vm.md`). Logs and CI tools need a fleet token.
   - **Deploy fastcar.** The card gives a deployment spec, built for this namespace by `GET /onboarding`, and a request to paste into Claude Code. The same spec also works with `heyctl apply -f`.
3. **Claude Code.** Claude deploys the spec with `applb_deploy`. The first request to the URL boots the VM.

## Configuring the MCP step

An `applb_` token only works with the app-lb that minted it. Each region's MCP server checks tokens with its own app-lb, so each app-lb must point its card at the MCP server in its own region:

| app-lb | `APP_LB_ONBOARDING_MCP_URL` | `APP_LB_ONBOARDING_MCP_NAME` |
| --- | --- | --- |
| us2 (`admin.us2.heyo.work`) | `https://mcp.us2.heyo.work/mcp` | `heyo` |
| us5 (`admin.us5.heyo.work`) | `https://mcp.heyo.work/mcp` | `heyo-us5` |

Without `APP_LB_ONBOARDING_MCP_URL`, the card leaves the MCP step out and points at `heyctl`. The name defaults to `heyo`, and only letters, digits, `-` and `_` are accepted, because it is pasted into a shell command. A distinct name per region lets one person add both servers.

## The fastcar spec

[fastcar](https://github.com/Heyo-Computer/fastcar) is an agent workspace. The spec runs it from a public Firecracker image:

- **From the hub.** With `APP_LB_ONBOARDING_HUB_URL` set (`https://hub.heyo.work`), the spec carries an `artifact` block naming the public repository `APP_LB_ONBOARDING_FASTCAR_REF` (`heyo/fastcar:latest`). app-lb pulls the rootfs anonymously, verifies it by digest, and boots it as `APP_LB_ONBOARDING_FASTCAR_IMAGE` (`fastcar`). No key and no catalog are needed, and every fleet that can reach the hub gets the same bytes. Claude's `applb_deploy` starts the pull itself; with `heyctl`, run `heyctl pull fastcar-<namespace> --wait` after `apply`. Before showing the spec, the card checks anonymously that the tag is pullable.
- **From the catalog.** Without a hub, the image named `APP_LB_ONBOARDING_FASTCAR_IMAGE` comes from the public image catalog, as below.

The card also links to the hub's browsable page (`<hub>/hub`), where users can find other public images and, with the `art_*` MCP tools, publish their own under `<namespace>/…`.

The spec itself:

- **Mock mode.** `FASTCAR_MOCK=1`, so it boots without model keys. The image's own Postgres holds its state on a 10 GB data disk.
- **Size and scaling.** `medium` size class, at most one VM, scaled to zero after 30 minutes idle.
- **Address.** The deployment is `fastcar-<namespace>`. When the fleet generates hostnames, it answers at `fastcar-<namespace>.<base domain>`.
- **Sign-in.** It sits behind the namespace's `heyo` provider. Only `/api/health` is public. fastcar is an agent with a shell, so it is never deployed ungated. If the namespace has no `heyo` provider, the card says so and the spec has no gate.
- **Image download (catalog only).** With `APP_LB_PUBLIC_IMAGE_CATALOG_URL` set and no hub, the spec carries the catalog download URL, size and digest, which the daemon verifies the image against. Without either, the spec works only on a host that already holds the image.

### Publishing the fastcar image

The hub image is built from a clean checkout of a fastcar commit, never from a working tree, because the Dockerfile copies the whole repository. Push it as both a moving tag and an immutable one, then make the repository public:

```sh
git -C fastcar worktree add --detach /tmp/fastcar-src <commit>
(cd /tmp/fastcar-src && heyvm mvm build --local-only -f deploy/image/Dockerfile -c . -n fastcar-hub)
heyctl artifact push --image fastcar-hub --registry-url <store> --tag heyo/fastcar:<commit> --public
heyctl artifact push --image fastcar-hub --registry-url <store> --tag heyo/fastcar:latest
```

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
  "hub": { "url": "https://hub.heyo.work/hub" },
  "fastcar": {
    "id": "fastcar-acme",
    "url": "https://fastcar-acme.us2.heyo.work",
    "gated": true,
    "source": "hub",
    "ref": "heyo/fastcar:latest",
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
