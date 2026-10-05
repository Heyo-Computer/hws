# ui — one look, one sign-in, one theme

Seven apps in this repository serve a web UI: **app-lb**, **app-obs**, **ci**,
**heyosecret**, **artifacts**, **queue** and **remote**. They are one product and a person moves
between them in one sitting, so they share this directory.

| File | What it is |
| --- | --- |
| `heyo.css` | Tokens, base type and the primitives every dashboard was reinventing |
| `theme.js` | The theme toggle — writes a cookie, no framework, no build step |
| `ui.rs` | Rust: the assets, the theme cookie, forwarded identity, the top bar |
| `fonts/` | Silkscreen and IBM Plex Mono, latin subsets, self-hosted (OFL) |

The palette and type are not new. They are the retail app's
(`heyo/retail/src/styles/tokens.css`) and the marketing site's
(`marketing/src/styles/main.css`), which already agree to the hex digit: the
same `#0a0c10` ground, the same peach `#e4a97d`, Silkscreen for labels and IBM
Plex Mono for everything else. What this directory does is carry them into the
dashboards.

## Using it from an app

```rust
#[path = "../../ui/ui.rs"]
mod heyo_ui;                              // no Cargo.toml entry, no lockfile churn
```

Then three things:

```rust
// 1. Serve the assets. Same origin, never a CDN.
.route("/__ui/{*path}", get(ui_asset))    // axum 0.8; app-lb's 0.7 spells it /__ui/*path

// 2. Stamp the theme on <html> from the request's cookie, before sending a byte.
let attrs = state.ui_cookies.attrs(cookie_header);   // data-theme="…" data-cookie-domain="…"

// 3. Render the shared top bar.
heyo_ui::topbar_html("ci", &nav, who)
```

**It is included, not depended on.** The six apps sit on three axum versions
(0.7 through 0.8.9) and two Rust editions (2021 and 2024), so `ui.rs` names no
framework type: it takes `Option<&str>` and closures and returns plain data.
That also means no `Cargo.toml` entry and no lockfile change — which matters
because each app's CI workflow fingerprints its warm VM on its lockfile. The
cost is one compiled copy per app, and the tests at the bottom of `ui.rs`
running six times, which is six independent proofs the contract holds.

## The two cookies

A fleet on `ci.example.com`, `obs.example.com` and `secrets.example.com` is three
origins. Anything kept per origin — a session, a theme — is a thing a person
does three times. Both cookies are therefore scoped to the **parent domain**,
and the parent domain is configuration, because `us2.heyo.work` is one
installation's and this is an open source project other people deploy.

### Sign-in — app-lb's `applb_session`

Set the same realm in every deployment spec:

```json
"auth": {
  "provider": ["google"],
  "cookie_domain": "example.com",
  "forward_identity": true
}
```

One sign-in then covers every app under it. app-lb forwards the identity as
three headers, and strips them unconditionally before setting them, which is
what makes them unspoofable:

```text
x-auth-request-user     the provider's stable subject — the primary key
x-auth-request-email
x-auth-request-name
```

`heyo_ui::identity_from` reads them. **Trust follows the gate, not the header.**
An app reachable without app-lb in front sees whatever the client sent, so each
app takes an explicit opt-in before believing them:

| App | Opt-in | Without it |
| --- | --- | --- |
| ci | (always) | behind the gate by design; its README says so |
| artifacts | `ART_DASHBOARD_GATE=1` | its own user/password login |
| heyosecret | `HEYOSECRET_DASHBOARD_GATE=1` | its own admin-password login |
| app-obs | — | identity is displayed, never authorized on; `APP_OBS_API_TOKEN` gates |
| app-lb | — | it *is* the gate; its own dashboard password still applies |
| remote | — | not gated (git cannot pass a sign-in page); its own Heyo sign-in resolves namespaces through app-lb and the auth service |

Setting a gate variable *and* a local password is refused at startup rather than
resolved by precedence: whichever won, half the configuration would be a lie,
and the half that loses is the half somebody believed was protecting the page.

### Theme — `heyo_theme`

```text
HEYO_UI_COOKIE_DOMAIN=example.com     the parent domain; unset = host-only
HEYO_UI_COOKIE_NAME=heyo_theme        override if two fleets share a domain
```

Per-app overrides win over the fleet-wide variable, the same precedence
`CI_HEYOSECRET_URL` has over `HEYOSECRET_URL`:

```text
CI_UI_COOKIE_DOMAIN  APP_LB_UI_COOKIE_DOMAIN  APP_OBS_UI_COOKIE_DOMAIN
ART_UI_COOKIE_DOMAIN  HEYOSECRET_UI_COOKIE_DOMAIN
```

Values are `dark` (the default), `light`, and `system` (follow the OS). A domain
a browser would discard — no dot, or one the page is not served from — is
refused at startup and the app falls back to a host-only cookie, because a
silently dropped cookie is a toggle that appears to work and then forgets.

**The server reads the cookie and stamps `data-theme` on `<html>`.** That is the
whole reason it is a cookie and not localStorage, twice over: it crosses
origins, and it is available *before the first byte*, so no page flashes the
wrong ground on the way to being corrected by script. `theme.js` only handles
clicks.

## Dark, light, and what is not themed

Dark is canonical — it is what the sites look like. Light is a full second
palette rather than an inversion, because app-lb and app-obs were light-first
and their charts were validated on a warm paper ground; a light theme that is
merely dark flipped goes grey and muddy.

Three tokens are **not** themed decoration and should not be retinted to match
the accent:

```text
--series-1  --series-2  --series-3
```

They are the chart series, chosen for separation under the common forms of
colour-vision deficiency and checked against both grounds. A palette that reads
as one family is the wrong goal for data; the goal is that no two lines can be
confused. `--grid` and `--axis` are the plot furniture that sits under them.

## Fonts

Self-hosted, not fetched from Google. A control plane for a private network
cannot depend on `fonts.googleapis.com` being reachable, and one that phones out
on every page load is a surprise nobody asked for. Six faces, latin subsets,
76 KB total — less than one chart page weighs. Both families are SIL Open Font
License 1.1; the licences ship beside them in `fonts/`.

To update one, re-download the latin subset from the Google Fonts CSS API and
replace the file — the names in `heyo.css` and in `ui.rs`'s `asset()` must stay
in step, and a test in `ui.rs` fails if they drift.

## Changing the design

Anything a second app would want belongs in `heyo.css`. What is left in an app
is its own vocabulary — ci's step accordion, artifacts' capacity meter,
app-obs's log table. Two rules keep it that way, and both are enforced by tests:

- an app's local stylesheet declares **no palette** — no `:root` tokens, no
  `prefers-color-scheme`, no hard-coded `#rrggbb`;
- every colour is a `var(--token)`, so it follows the theme.

`ui.rs`'s own tests check that both themes define the same token set, that every
font the CSS asks for is a font the app serves, that a display name cannot
inject markup into the top bar, and that a cookie domain a browser would drop
never reaches the page.
