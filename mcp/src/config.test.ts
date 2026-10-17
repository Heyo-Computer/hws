/**
 * Where app-lb is and whose credential goes with it. Everything downstream is
 * a path appended to `APPLB_URL`; nothing here ever points at the Heyo cloud.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { applbService, configured, credentialFaults, loadConfig, withForwardedAuth } from "./config.js";

test("a plain APPLB_URL is app-lb's own listener", () => {
  const cfg = applbService("http://127.0.0.1:8080/", undefined, "tok");
  assert.equal(cfg?.baseUrl, "http://127.0.0.1:8080");
  assert.equal(cfg?.auth, "Bearer tok");
  assert.equal(cfg?.namespace, undefined);
});

test("APPLB_NAMESPACE names the namespace and never changes the URL", () => {
  const config = loadConfig({
    APPLB_URL: "https://admin.us5.heyo.work",
    APPLB_NAMESPACE: "team-a",
    APPLB_TOKEN: "applb_x",
  });
  assert.equal(config.applb?.baseUrl, "https://admin.us5.heyo.work");
  assert.equal(config.applb?.namespace, "team-a");
  assert.deepEqual(configured(config), ["app-lb (namespace team-a)"]);
});

test("the caller's bearer is forwarded only to a service with no credential of its own", () => {
  const anonymous = loadConfig({ APPLB_URL: "https://admin.us5.heyo.work" });
  const forwarded = withForwardedAuth(anonymous, { authorization: "Bearer applb_caller" });
  assert.notEqual(forwarded, anonymous);
  assert.equal(forwarded.applb?.auth, "Bearer applb_caller");
  assert.equal(forwarded.applb?.baseUrl, anonymous.applb?.baseUrl);

  // A JWT is borrowed too when app-lb has nothing of its own.
  assert.equal(
    withForwardedAuth(anonymous, { authorization: "Bearer eyJ.x.y" }).applb?.auth,
    "Bearer eyJ.x.y",
  );

  // Configured, and a caller whose bearer is not app-lb's own kind: the same
  // object comes back and the per-process tool set is reused.
  const fully = loadConfig({ APPLB_URL: "http://127.0.0.1:8080", APPLB_TOKEN: "t" });
  assert.equal(withForwardedAuth(fully, { authorization: "Bearer eyJ.x.y" }), fully);

  assert.equal(withForwardedAuth(anonymous, {}), anonymous);
  assert.equal(withForwardedAuth(anonymous, { authorization: "   " }), anonymous);
  assert.equal(withForwardedAuth(loadConfig({}), { authorization: "Bearer x" }).applb, undefined);
});

test("an app-lb-minted token is never traded up for this process's own", () => {
  // The escalation this closes: a token scoped to one deployment, admitted by
  // an app-token gate, reaching app-lb as whatever fleet-wide credential the
  // operator configured. The caller's own token wins, so app-lb scope-checks
  // the principal that was actually authenticated.
  const own = loadConfig({ APPLB_URL: "http://127.0.0.1:8080", APPLB_TOKEN: "applb_fleet_wide" });
  const scoped = withForwardedAuth(own, { authorization: "Bearer applb_abc123_secret" });
  assert.equal(scoped.applb?.auth, "Bearer applb_abc123_secret");
  assert.equal(scoped.applb?.baseUrl, own.applb?.baseUrl);

  // Basic-gated dashboards are configured the same way and get the same rule.
  const basic = loadConfig({ APPLB_URL: "http://127.0.0.1:8080", APPLB_BASIC: "admin:hunter2" });
  assert.equal(
    withForwardedAuth(basic, { authorization: "Bearer applb_abc123_secret" }).applb?.auth,
    "Bearer applb_abc123_secret",
  );

  // Only app-lb's own kind of token. A JWT from the heyo auth API means nothing
  // to app-lb's admin API, so a jwt-gated deployment keeps acting as itself
  // rather than forwarding a credential app-lb cannot read.
  const jwtCaller = withForwardedAuth(own, { authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x" });
  assert.equal(jwtCaller.applb?.auth, "Bearer applb_fleet_wide");


  // The prefix is tested on the token, not the raw header, so neither the
  // scheme's spelling nor a bearer that merely mentions the prefix decides it.
  // Detection is deliberately looser than app-lb's own `strip_prefix("Bearer ")`,
  // because the two failure directions are not symmetric: a form detected here
  // that app-lb will not parse is a 401, while one app-lb accepts and this
  // missed would fall back to the configured token — the escalation. The header
  // itself is still forwarded byte for byte, as the Basic case requires.
  assert.equal(
    withForwardedAuth(own, { authorization: "bearer   applb_abc123_secret" }).applb?.auth,
    "bearer   applb_abc123_secret",
  );
  assert.equal(
    withForwardedAuth(own, { authorization: "Basic applb_not_a_bearer" }).applb?.auth,
    "Bearer applb_fleet_wide",
  );
  assert.equal(
    withForwardedAuth(own, { authorization: "Bearer x_applb_suffix" }).applb?.auth,
    "Bearer applb_fleet_wide",
  );

  // And the reuse path survives: fully configured, with a caller whose bearer
  // is nobody's business here, the same object comes back.
  assert.equal(withForwardedAuth(own, { authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x" }), own);
});

test("nothing points at the Heyo cloud, and a leftover cloud setup is reported", () => {
  // HEYO_API_KEY alone used to configure everything through cloud's door. Now
  // it configures nothing, and saying so beats every app-lb tool failing.
  const legacy = loadConfig({ HEYO_API_KEY: "heyo_api_x", HEYO_BASE_URL: "https://server.heyo.computer" });
  assert.equal(legacy.applb, undefined);
  assert.equal(JSON.stringify(legacy).includes("server.heyo.computer"), false);
  assert.match(credentialFaults(legacy)[0]?.summary ?? "", /HEYO_API_KEY is set but no longer used/);

  const door = loadConfig({ APPLB_URL: "https://server.heyo.computer/namespaces/team-a/lb", APPLB_TOKEN: "k" });
  assert.match(credentialFaults(door)[0]?.summary ?? "", /namespace door/);

  assert.deepEqual(credentialFaults(loadConfig({ APPLB_URL: "https://admin.us5.heyo.work" })), []);
  // The remote no longer falls back to a cloud key either.
  assert.equal(loadConfig({ REMOTE_URL: "https://git.us5.heyo.work", HEYO_API_KEY: "k" }).remote?.auth, undefined);
});

test("no credential at all configures nothing", () => {
  const config = loadConfig({});
  assert.equal(config.applb, undefined);
  assert.deepEqual(configured(config), []);
});

test("app-obs and ci act as the caller when app-lb is what gates them", () => {
  // The VM shape: obs and ci are reached at their public hostnames, behind
  // app-lb gates, so the credential is an app-lb token and nothing is
  // configured here. Each caller's own token clears each gate, which is what
  // makes a caller whose scope omits app-obs unable to read app-obs.
  const gated = loadConfig({
    APPLB_URL: "https://admin.us2.heyo.work",
    APP_OBS_URL: "https://obs.us2.heyo.work",
    CI_URL: "https://ci.us2.heyo.work",
  });
  assert.equal(gated.obs?.auth, undefined);
  const asCaller = withForwardedAuth(gated, { authorization: "Bearer applb_abc123_secret" });
  assert.equal(asCaller.applb?.auth, "Bearer applb_abc123_secret");
  assert.equal(asCaller.obs?.auth, "Bearer applb_abc123_secret");
  assert.equal(asCaller.ci?.auth, "Bearer applb_abc123_secret");
  assert.equal(asCaller.obs?.baseUrl, gated.obs?.baseUrl);

  // A configured fallback that is itself an app-lb token is still only a
  // fallback: it says "the gate authenticates here", not "act as me".
  const withFallback = loadConfig({
    APP_OBS_URL: "https://obs.us2.heyo.work",
    APP_OBS_API_TOKEN: "applb_svc_fallback",
    CI_URL: "https://ci.us2.heyo.work",
    CI_TOKEN: "applb_svc_fallback",
  });
  const overridden = withForwardedAuth(withFallback, {
    authorization: "Bearer applb_abc123_secret",
  });
  assert.equal(overridden.obs?.auth, "Bearer applb_abc123_secret");
  assert.equal(overridden.ci?.auth, "Bearer applb_abc123_secret");
});

test("app-obs and ci reached directly keep their own service tokens", () => {
  // The regression this guards: the loopback deployment, where APP_OBS_API_TOKEN
  // is app-obs's *own* token and app-obs compares it to what it was configured
  // with. An app-lb token means nothing there, so forwarding one would 401 every
  // obs and ci tool on a deployment that was working. The shape of what is
  // configured is what tells the two apart — no `applb_` prefix, no gate.
  const loopback = loadConfig({
    APPLB_URL: "http://127.0.0.1:8080",
    APP_OBS_URL: "http://127.0.0.1:9600",
    APP_OBS_API_TOKEN: "obs_service_secret",
    CI_URL: "http://127.0.0.1:9555",
    CI_TOKEN: "ci_service_secret",
  });
  const called = withForwardedAuth(loopback, { authorization: "Bearer applb_abc123_secret" });
  assert.equal(called.obs?.auth, "Bearer obs_service_secret");
  assert.equal(called.ci?.auth, "Bearer ci_service_secret");
  // app-lb itself still yields, because app-lb is always its own authenticator.
  assert.equal(called.applb?.auth, "Bearer applb_abc123_secret");

  // And only an app-lb token reaches obs and ci at all. A JWT is not a
  // credential either of them has any use for, gated or not.
  const gated = loadConfig({
    APP_OBS_URL: "https://obs.us2.heyo.work",
    CI_URL: "https://ci.us2.heyo.work",
  });
  for (const bearer of ["Bearer eyJhbGciOiJIUzI1NiJ9.e30.x"]) {
    const out = withForwardedAuth(gated, { authorization: bearer });
    assert.equal(out.obs?.auth, undefined, bearer);
    assert.equal(out.ci?.auth, undefined, bearer);
  }

  // Nothing to change on any of the four: the same object comes back and the
  // per-process tool set is reused.
  const settled = loadConfig({
    APPLB_URL: "http://127.0.0.1:8080",
    APPLB_TOKEN: "applb_fleet_wide",
    APP_OBS_URL: "http://127.0.0.1:9600",
    APP_OBS_API_TOKEN: "obs_service_secret",
  });
  assert.equal(withForwardedAuth(settled, { authorization: "Bearer eyJ.x.y" }), settled);
});
