// The contract with app-lb.
//
// `testdata/wire/*.json` is written by app-lb's own response types (see
// `src/wire_golden.rs`). This asserts every key in them is one this package
// declares — because to a JS client an unknown field and an absent one look
// identical, which is exactly how five fields went missing from the Rust client
// without a single test failing.
//
// A field app-lb starts sending fails this test instead of silently going
// unread.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const WIRE = join(here, "..", "..", "..", "testdata", "wire");

/**
 * Keys this package understands, per fixture. Hand-written on purpose: it is the
 * declaration that has to be checked, and generating it from the types would
 * only prove the generator agrees with itself.
 */
const KNOWN = {
  common: {
    DeploymentStatus: ["rollout_revision", "spec", "kind", "desired_replicas", "ready", "pending", "total_in_flight", "vms", "workspace", "site"],
    SiteRootStatus: ["root", "status", "index_present", "hint"],
    VmStatus: ["sandbox_id", "addr", "in_flight", "healthy", "draining"],
    DeploymentSpec: ["id", "namespace", "account_id", "user_id", "routes", "vm", "scaling", "health", "upstreams", "discovery", "build", "artifact", "site", "update", "auth", "feed"],
    DiscoverySpec: ["service_id"],
    WorkspaceArchive: ["archive_id", "s3_key", "size_bytes"],
    RouteRule: ["host", "host_suffix", "path_prefix"],
    VmSpec: ["driver", "image", "port", "start_command", "size_class", "disk_size_gb", "working_directory", "env_vars", "setup_hooks", "open_ports", "mounts", "workspace", "env_from", "workspace_archive", "image_download_url", "image_size_bytes", "image_sha256", "ttl_seconds"],
    MountSpec: ["path", "store", "ref", "auth", "strip_components", "read_only", "digest"],
    ScalingPolicy: ["min_replicas", "max_replicas", "warm_pool", "target_concurrency", "scale_to_zero_after_secs", "cold_start_timeout_secs", "drain_timeout_secs", "boot_timeout_secs", "idle_action"],
    HealthCheck: ["expected_header", "path", "port", "timeout_secs"],
    ExpectedHeader: ["name", "value"],
    BuildSpec: ["repo", "store", "ref", "dockerfile", "context", "image_name", "image_size_mb", "auth"],
    ArtifactSpec: ["store", "ref", "auth", "grow_gb", "image_name", "strip_components"],
    SiteSpec: ["root", "index", "not_found", "spa", "cache_control"],
    UpdateSpec: ["working_dir", "commands", "env", "env_from", "auth", "timeout_secs", "verify_timeout_secs"],
    SecretEnv: ["secret", "key", "as", "namespace"],
    SecretRef: ["secret", "key", "username", "namespace"],
    AuthGate: ["provider", "client_id", "client_secret", "allowed_domains", "allowed_emails", "public_paths", "session_scope", "base_path", "session_ttl_secs", "cookie_name", "cookie_domain", "redirect_url", "forward_identity", "jwt", "provider_ref"],
    AuthProviderView: ["name", "namespace", "description", "created_at", "provider", "client_id", "client_secret", "allowed_domains", "allowed_emails", "jwt", "cookie_domain"],
    PublicPath: ["path", "scope"],
    JwtSpec: ["secret", "public_key", "jwks_url", "algorithms", "issuer", "audience", "require", "subject_claim", "email_claim", "name_claim", "leeway_secs", "cookie", "login_endpoint", "login_url", "login_redirect_param", "authorize_url", "token_url"],
    DeploymentView: ["id", "namespace", "account_id", "kind", "upstreams", "routed", "hosts", "urls", "site_root", "site_spa", "job_kind", "pool", "vms", "pending_vms", "metrics"],
    UpstreamTrafficStatus: ["deployment_id", "upstream", "state", "healthy", "in_flight", "reason", "started_at"],
    PoolStatus: ["desired_replicas", "ready", "draining", "pending", "total_in_flight", "target_concurrency", "min_replicas", "max_replicas", "warm_pool", "utilization", "cpu_percent", "memory_bytes", "boot_timeout_secs", "cold_start_timeout_secs"],
    VmView: ["sandbox_id", "addr", "in_flight", "healthy", "draining", "uptime_secs", "cpu_percent", "memory_bytes"],
    PendingVmView: ["sandbox_id", "age_secs", "status"],
    DeploymentMetrics: ["requests", "latency_ms", "cold_start_s", "autoscale"],
    StatusCounts: ["total", "c2xx", "c3xx", "c4xx", "c5xx", "errors"],
    Histogram: ["count", "sum", "mean", "p50", "p90", "p99", "buckets"],
    Bucket: ["le", "count"],
    AutoscaleCounts: ["vms_created", "vms_drained", "vms_reaped", "scale_up_events", "scale_down_events", "cold_start_waits", "cold_start_hits", "cold_start_timeouts", "boot_timeouts", "create_failures", "last_create_error"],
    HostUsage: ["available", "cpu_count", "cpu_percent", "memory_total_bytes", "memory_used_bytes", "sampled_at_ms"],
    FleetPool: ["deployments", "ready", "draining", "pending", "total_in_flight"],
    ObsStats: ["queued", "dropped", "shipped", "failed", "healthy"],
    DaemonSnapshot: ["reachable", "last_error"],
    MetricsResponse: ["generated_at", "uptime_secs", "host", "fleet", "global", "obs", "security", "daemon", "deployments", "matched", "tracked_deployments", "host_sandboxes"],
    HostSandboxView: ["sandbox_id", "name", "status", "image", "size_class", "guest_ip", "uptime_secs", "cpu_percent", "memory_bytes", "account_id", "created_at"],
    DiskInventory: ["complete", "incomplete_reason", "data_dir", "tmp_dir", "ttl_secs", "sweep_secs", "archive_enabled", "archive_on_expire", "archive_target", "free_bytes", "filesystem_bytes", "orphan_ttl_secs", "totals", "disks", "archives"],
    DiskTotals: ["disks", "bytes", "apparent_bytes", "running", "stopped", "orphan", "retained", "expiring_now", "reclaimable_bytes"],
    DiskInfo: ["sandbox_id", "name", "deployment", "state", "claimed", "retain", "note", "bytes", "apparent_bytes", "modified_at", "expires_at", "held_by", "archived", "parts", "roots"],
    DiskPart: ["kind", "path", "bytes", "apparent_bytes", "modified_at"],
    ArchiveRecord: ["uri", "at", "bytes"],
    ArchiveView: ["id", "sandbox_id", "uri", "started_at", "finished_at", "status", "bytes", "expected_bytes", "error", "purged"],
    SecuritySummary: ["open", "urgent", "dropped", "clients_at_capacity", "rules", "blocked"],
    SecurityResponse: ["generated_at", "enabled", "window_secs", "alerts", "totals", "rules", "guard", "stats"],
    // `ecs` is a free-form ECS map by design, so it has no declaration to check
    // against — app-lb may add fields there without this being a contract change.
    SecurityAlert: ["id", "ts", "last_ts", "rule", "severity", "title", "client", "deployment", "path", "technique", "count", "ecs", "response"],
    AlertResponse: ["investigate", "actions", "caveat"],
    SuggestedAction: ["kind", "label", "effect", "rule"],
    RuleSpec: ["action", "match", "expires_in_secs", "note"],
    RuleMatch: ["client", "host", "deployment", "path_prefix", "path_contains", "method", "user_agent_contains"],
    RuleView: ["id", "action", "match", "summary", "note", "created_at", "expires_at", "hits", "last_hit", "enforcing", "hits_recent"],
    GuardStats: ["rules", "blocked", "exempted", "enforcing", "blocked_recent", "exempted_recent", "hits_bucket_secs", "hits_window_secs"],
    SeverityTotals: ["info", "low", "medium", "high", "critical"],
    SiemStats: ["observed", "dropped", "analyzed", "raised", "suppressed", "tracked_clients", "clients_at_capacity"],
    WorkflowSpec: ["id", "repo", "ref", "path", "network", "auth", "secrets_prefix", "enabled"],
    WorkflowList: ["workflows"],
    JobRecord: ["id", "deployment", "kind", "status", "started_at", "finished_at", "error", "log", "repo", "ref", "commit", "dockerfile", "image", "rolled_out", "store", "artifact", "digest", "bytes", "reused", "site_root", "files", "working_dir", "commands_total", "commands_run", "verified", "mounts"],
    MountOutcome: ["path", "store", "ref", "digest", "tree", "files", "bytes", "unpacked", "reused", "changed"],
    SecretSummary: ["id", "namespace", "description", "keys", "updated_at", "encrypted_at_rest"],
    CertStatus: ["host", "not_after", "issuer", "needs_renewal"],
    ExecOutput: ["sandbox_id", "exit_code", "stdout", "stderr", "output"],
    EvictOutcome: ["sandbox_id", "outcome"],
    TokenSummary: ["id", "name", "admin", "namespace", "deployments", "created_at", "expires_at", "last_used_at"],
    MintedToken: ["id", "name", "admin", "namespace", "deployments", "created_at", "expires_at", "last_used_at", "token"],
    ApiError: ["error"],
    FeedSpec: ["announce", "issues", "expose"],
    FeedIndexEntry: ["namespace", "events"],
    FeedEvent: ["id", "ts", "last_ts", "count", "namespace", "deployment", "kind", "title", "detail"],
    PluginView: ["id", "name", "description", "config_schema", "enabled", "config", "updated_at", "last_error", "status", "per_namespace", "installed_in"],
    NamespacePlugin: ["id", "name", "description", "enabled", "installed", "installed_at", "installed_by", "config"],
    PluginInstalls: ["plugin", "enabled", "namespaces", "installs"],
    NamespaceInstall: ["installed_at", "installed_by", "config"],
  },
};

/** Which declaration each fixture is an instance of. */
const FIXTURES = {
  "deployment-status-vm": "DeploymentStatus",
  "deployment-status-vm-owned": "DeploymentStatus",
  "deployment-status-site": "DeploymentStatus",
  "deployment-status-static": "DeploymentStatus",
  "deployment-status-artifact": "DeploymentStatus",
  "deployment-status-site-artifact": "DeploymentStatus",
  "deployment-status-jwt": "DeploymentStatus",
  "deployment-view-site": "DeploymentView",
  "metrics-response": "MetricsResponse",
  "disks": "DiskInventory",
  "security-response": "SecurityResponse",
  "job-build": "JobRecord",
  "job-pull": "JobRecord",
  "job-site-pull": "JobRecord",
  "job-update": "JobRecord",
  "job-mount-pull": "JobRecord",
  "job-failed": "JobRecord",
  "workflow": "WorkflowSpec",
  "workflow-minimal": "WorkflowSpec",
  "workflow-list": "WorkflowList",
  "secret-summary": "SecretSummary",
  "cert-status": "CertStatus",
  "exec-response": "ExecOutput",
  "evict-response": "EvictOutcome",
  "api-error": "ApiError",
  "token-summary": "TokenSummary",
  "token-summary-scoped": "TokenSummary",
  "token-summary-namespaced": "TokenSummary",
  "minted-token": "MintedToken",
  "upstream-traffic-status": "UpstreamTrafficStatus",
  "feed-event": "FeedEvent",
  "feed-index": "FeedIndexEntry",
  "plugins": "PluginView",
  "namespace-plugins": "NamespacePlugin",
  "plugin-installs": "PluginInstalls",
  "auth-provider-google": "AuthProviderView",
  "auth-provider-heyo": "AuthProviderView",
  "deployment-inherited-gate": "DeploymentSpec",
};

/**
 * Keys holding a map whose *keys* are data (a namespace name, say) and whose
 * values are all one declaration.
 */
const MAPS = {
  installs: "NamespaceInstall",
};

/** Which declaration governs a nested object, by the key that holds it. */
const NESTED = {
  spec: "DeploymentSpec", vm: "VmSpec", scaling: "ScalingPolicy", health: "HealthCheck",
  expected_header: "ExpectedHeader",
  discovery: "DiscoverySpec", build: "BuildSpec", artifact: "ArtifactSpec", site: "SiteSpec", update: "UpdateSpec",
  auth: "AuthGate", client_secret: "SecretRef", pool: "PoolStatus", host: "HostUsage",
  // Each entry is a path plus the scope app-lb requires there; a client that
  // read only the path would render an admin-only route as an open one.
  public_paths: "PublicPath",
  // `jwt` is the gate's verification policy. Its own `secret` is a SecretRef,
  // and `require` is a free-form claim map with no declaration to check against
  // — app-lb may carry any claim name there without that being an API change.
  jwt: "JwtSpec",
  feed: "FeedSpec", workspace_archive: "WorkspaceArchive",
  fleet: "FleetPool", obs: "ObsStats", daemon: "DaemonSnapshot", metrics: "DeploymentMetrics",
  security: "SecuritySummary", totals: "SeverityTotals", stats: "SiemStats",
  archived: "ArchiveRecord",
  response: "AlertResponse", guard: "GuardStats",
  // `rule` is a bare string on an alert and a whole RuleSpec on a suggested
  // action; `check` only recurses into objects, so one entry serves both.
  rule: "RuleSpec", match: "RuleMatch",
  global: "DeploymentMetrics", requests: "StatusCounts", latency_ms: "Histogram",
  cold_start_s: "Histogram", autoscale: "AutoscaleCounts",
};

/** Which declaration governs the *elements* of an array, by its key. */
const ELEMENTS = {
  routes: "RouteRule", vms: "VmStatus", deployments: "DeploymentView", alerts: "SecurityAlert",
  pending_vms: "PendingVmView", host_sandboxes: "HostSandboxView", buckets: "Bucket", env_from: "SecretEnv",
  disks: "DiskInfo", archives: "ArchiveView", parts: "DiskPart",
  actions: "SuggestedAction", rules: "RuleView",
  workflows: "WorkflowSpec",
  // `mounts` is a MountSpec on a VmSpec and a MountOutcome on a JobRecord — the
  // spec's declaration of a mount, and what one pull of it did. Disambiguated
  // below by the declaration we are inside, the same way `vms` and `auth` are.
  mounts: "MountSpec",
};

const K = KNOWN.common;

function check(value, declName, path, unknown) {
  const known = K[declName];
  assert.ok(known, `no declaration named ${declName} (at ${path})`);
  for (const [key, child] of Object.entries(value)) {
    if (!known.includes(key)) {
      unknown.push(`${path}.${key}`);
      continue;
    }
    if (child && typeof child === "object" && !Array.isArray(child) && MAPS[key]) {
      for (const [k, v] of Object.entries(child)) {
        if (v && typeof v === "object") check(v, MAPS[key], `${path}.${key}.${k}`, unknown);
      }
    } else if (child && typeof child === "object" && !Array.isArray(child)) {
      // Two keys mean different things depending on where they sit, so the
      // declaration we are inside disambiguates them: `vms` is VmStatus under a
      // DeploymentStatus and VmView under a DeploymentView, and `auth` is the
      // sign-in gate on a spec but a secret *reference* on a build, an artifact
      // or an update.
      let nested = NESTED[key];
      if (key === "vms") nested = declName === "DeploymentView" ? "VmView" : "VmStatus";
      // ...and a mount's `auth` is a store credential, which the same rule
      // already resolves to SecretRef.
      if (key === "auth") nested = declName === "DeploymentSpec" ? "AuthGate" : "SecretRef";
      if (key === "secret") nested = "SecretRef";
      if (key === "totals" && declName === "DiskInventory") nested = "DiskTotals";
      // A spec's `site` is how to serve it; a status's is whether it can.
      if (key === "site") nested = declName === "DeploymentStatus" ? "SiteRootStatus" : "SiteSpec";
      // A plugin's `config` and `status` are its own business.
      if ((key === "config" || key === "status") && /Plugin|Install/.test(declName)) nested = undefined;
      // A free-form claim map: the keys are whatever the issuer sends.
      if (key === "require") nested = undefined;
      if (nested) check(child, nested, `${path}.${key}`, unknown);
    } else if (Array.isArray(child)) {
      let elem = ELEMENTS[key];
      if (key === "vms") elem = declName === "DeploymentView" ? "VmView" : "VmStatus";
      if (key === "mounts") elem = declName === "JobRecord" ? "MountOutcome" : "MountSpec";
      if (elem) {
        child.forEach((item, i) => {
          if (item && typeof item === "object") check(item, elem, `${path}.${key}[${i}]`, unknown);
        });
      }
    }
  }
}

const files = readdirSync(WIRE).filter((f) => f.endsWith(".json"));

test("every wire fixture is covered by a declaration", () => {
  const covered = files.map((f) => f.replace(/\.json$/, ""));
  const missing = covered.filter((n) => !(n in FIXTURES));
  assert.deepEqual(missing, [], "app-lb writes fixtures this package does not check");
});

for (const file of files) {
  const name = file.replace(/\.json$/, "");
  if (!(name in FIXTURES)) continue;
  test(`${name} has no fields this package would silently drop`, () => {
    const value = JSON.parse(readFileSync(join(WIRE, file), "utf8"));
    const unknown = [];
    // A collection route's fixture is a bare array; its declaration names the
    // element type.
    if (Array.isArray(value)) {
      value.forEach((item, i) => check(item, FIXTURES[name], `${name}[${i}]`, unknown));
    } else {
      check(value, FIXTURES[name], name, unknown);
    }
    assert.deepEqual(
      unknown,
      [],
      `app-lb sends fields this package does not declare — add them to src/types.ts:\n  ${unknown.join("\n  ")}`,
    );
  });
}
