/**
 * The admin API's JSON, as types.
 *
 * Every field is optional in practice — app-lb omits what is absent and adds
 * fields over time — so these describe what you *may* find rather than what is
 * guaranteed. The runtime never validates them: an unknown field is carried
 * through untouched, which is what makes a client one version behind still work.
 *
 * `test/wire-contract.test.ts` reads `testdata/wire/*.json`, written by app-lb's
 * own response types, and asserts every key in them is declared here. A field
 * app-lb starts sending fails that test instead of silently going unread.
 */

export type DeploymentKind = "vm" | "static" | "site";

export interface RouteRule {
  host?: string;
  host_suffix?: string;
  path_prefix?: string;
  strip_prefix?: boolean;
}

export interface ScalingPolicy {
  min_replicas?: number;
  max_replicas?: number;
  warm_pool?: number;
  target_concurrency?: number;
  scale_to_zero_after_secs?: number;
  cold_start_timeout_secs?: number;
  drain_timeout_secs?: number;
  /** `destroy` kills an idle VM; `retain` stops it, keeping its data disk. */
  idle_action?: "destroy" | "retain";
  boot_timeout_secs?: number;
}

export interface ExpectedHeader {
  name: string;
  value: string;
}

export interface HealthCheck {
  /** Require 2xx and one exact response header; rollout requires x-heyo-revision. */
  expected_header?: ExpectedHeader;
  /** `null` means a bare TCP connect rather than an HTTP probe. */
  path?: string | null;
  port?: number;
  timeout_secs?: number;
}

export interface VmSpec {
  driver: "firecracker" | "kvm" | "libvirt";
  image?: string;
  port: number;
  start_command?: string;
  size_class?: "micro" | "mini" | "small" | "medium" | "large" | "xlarge";
  disk_size_gb?: number;
  working_directory?: string;
  env_vars?: Record<string, string>;
  setup_hooks?: string[];
  open_ports?: number[];
  /**
   * Directories every replica boots with, unpacked from tarballs in an artifact
   * store. Attached at boot, so editing this list recycles the pool.
   */
  mounts?: MountSpec[];
  /**
   * A writable directory owned by the deployment rather than by any one VM:
   * captured when a replica retires (rollout, restart, eviction, idle
   * suspend) and seeded into its replacement, with every snapshot pushed to
   * `store`. Requires `scaling.max_replicas: 1`, `warm_pool: 0` and the
   * firecracker driver.
   */
  workspace?: WorkspaceSpec;
  /**
   * Secret values exported to every replica as environment variables,
   * resolved when the VM is created. The spec carries the reference and the
   * store the value — the reason `env_vars` is the wrong place for a token.
   * Resolved in the deployment's own namespace.
   */
  env_from?: SecretEnv[];
  /**
   * A gzipped tarball every replica's `/workspace` is unpacked from at boot.
   * Name it by `archive_id` through the Heyo cloud API, which checks the
   * caller owns it and fills in `s3_key`; app-lb refuses the id alone.
   * Unlike `workspace` nothing is captured back, so it composes with a pool of
   * any size. Mutually exclusive with `workspace`.
   */
  workspace_archive?: WorkspaceArchive;
  /**
   * Where the daemon may fetch `image` from when it does not hold it — a
   * public-image catalog URL with the size and digest the download is
   * verified against. Filled in by cloud from its catalog; leave unset when
   * posting to app-lb directly against a daemon that already has the image.
   */
  image_download_url?: string;
  image_size_bytes?: number;
  image_sha256?: string;
  ttl_seconds?: number;
}

export interface WorkspaceArchive {
  /** The cloud archive id (`ar-…`). */
  archive_id?: string;
  /** The object key the daemon fetches; resolved by cloud, never guessed. */
  s3_key?: string;
  size_bytes?: number;
}

/** `GET /ingress` — where DNS should point a deployment's hostname. Empty until `APP_LB_PUBLIC_IPS` is set. */
export interface Ingress {
  ipv4: string[];
  ipv6: string[];
}

export interface WorkspaceSpec {
  /** Guest path. Defaults to `/workspace`, which `disk_size_gb` then sizes. */
  path?: string;
  /** `s3://bucket[/prefix]`, an `http(s)://` artifact store, or a local store root. */
  store: string;
  /** Tag the newest snapshot is published under (artifact stores). Defaults to `workspace-<id>`. */
  ref?: string;
  auth?: SecretRef;
}

export interface WorkspaceStatus {
  path: string;
  store: string;
  /** The snapshot the pool runs from; `null` is the empty workspace. */
  digest: string | null;
  captured_at: number | null;
  captured_from: string | null;
  files: number;
  bytes: number;
  /** The snapshot the store is known to hold. */
  pushed: string | null;
  pushed_at: number | null;
  push_pending: boolean;
  phase: "idle" | "restoring" | "capturing" | "pushing" | "blocked";
  /** Why no replica can be created right now, when none can. */
  blocked?: string;
  pending?: { sandbox_id: string; then: "kill" | "suspend"; queued_at: number; attempts: number }[];
  last_error?: string;
}

/**
 * One directory handed to every replica of a managed deployment, unpacked from a
 * tarball in an artifact store.
 *
 * The counterpart of `ArtifactSpec` for *data* rather than for the image: the
 * rootfs decides what the guests run, this decides what they hold. A mount whose
 * `digest` is absent has not been pulled on the target host, and a deployment
 * with one has no pool at all — app-lb refuses to boot a guest that would be
 * missing its data. `POST /deployments/:id/mounts/pull` is what fills it in, and
 * registering or editing the deployment starts one of those automatically.
 */
export interface MountSpec {
  /** Absolute path inside the guest. Unique within the deployment, and never
   *  nested inside another mount. */
  path: string;
  /** An `art serve` URL, or an absolute store root on the app-lb host. */
  store: string;
  /** A tag or a 64-hex digest naming a `tar`/`tar.gz` of the directory. */
  ref: string;
  auth?: SecretRef;
  /** Leading path components to drop while unpacking, as
   *  `tar --strip-components` does. */
  strip_components?: number;
  /**
   * Whether the guest mounts it read-only. Defaults to `true`, and is **refused
   * on the `kvm` driver** when false: that driver syncs a writable mount back
   * into the host tree every other replica boots from.
   */
  read_only?: boolean;
  /** What `ref` resolved to on the last pull — which bytes the guests hold. */
  digest?: string;
}

export interface SecretRef {
  secret: string;
  key?: string;
  username?: string;
  /**
   * The namespace the secret lives in. Stamped by app-lb from the
   * deployment's own namespace on register/edit; a value sent by a client is
   * overwritten, so a spec can only ever name secrets behind its own wall.
   */
  namespace?: string;
}

/**
 * Where a managed deployment's guest image is built from. Exactly one of `repo`
 * and `store` is set — both name the Dockerfile, and a build with two recipes
 * has no answer to which one produced the image.
 */
export interface BuildSpec {
  /** Git remote. Absent when the recipe comes from `store`. */
  repo?: string;
  /**
   * An artifact store holding a Dockerfile manifest (`heyvm.dockerfile.v1`):
   * an `art serve` URL, or an absolute store root on the app-lb host.
   */
  store?: string;
  /**
   * Which version of the source to build: a branch, tag or commit for `repo`
   * (absent follows the remote's default branch), or the tag or digest of a
   * Dockerfile manifest for `store`, where it is required.
   */
  ref?: string;
  /** Git source only — a Dockerfile manifest already names its own recipe. */
  dockerfile?: string;
  /** Git source only. */
  context?: string;
  image_name?: string;
  image_size_mb?: number;
  /** A git token for `repo`, or the store's API key for `store`. */
  auth?: SecretRef;
}

export interface ArtifactSpec {
  store: string;
  ref: string;
  auth?: SecretRef;
  grow_gb?: number;
  image_name?: string;
  /** Site bundles only: leading path components to drop while unpacking. */
  strip_components?: number;
}

export interface SiteSpec {
  root: string;
  index?: string;
  not_found?: string;
  spa?: boolean;
  cache_control?: string;
}

export interface SecretEnv {
  secret: string;
  key?: string;
  as?: string;
  /** Stamped from the deployment's namespace, as on {@link SecretRef}. */
  namespace?: string;
}

export interface UpdateSpec {
  working_dir: string;
  commands: string[];
  env?: Record<string, string>;
  env_from?: SecretEnv[];
  auth?: SecretRef;
  timeout_secs?: number;
  verify_timeout_secs?: number;
}

/**
 * `provider` is a bare string for one and an array for several — they are
 * alternatives, so any one of them admits a request. A gate written before
 * app-tokens existed omits it entirely and means `"google"`.
 */
/** One entry in {@link AuthGate.public_paths}. */
export interface PublicPath {
  path: string;
  /**
   * `public` | `none` | `view` | `admin`. The lower three mirror an app-token's
   * `admin` scope; `public` is the only one that needs no credential.
   */
  scope: "public" | "none" | "view" | "admin";
}

export interface AuthGate {
  provider?: AuthProvider | AuthProvider[];
  /** Required for `google`, meaningless without it. */
  client_id?: string;
  client_secret?: SecretRef;
  allowed_domains?: string[];
  allowed_emails?: string[];
  /**
   * Path prefixes the *sign-in* gate does not sit in front of, and what app-lb
   * requires instead. `public` is the only scope that admits a request
   * presenting no credential; a bare string written by hand means `admin`.
   */
  public_paths?: PublicPath[];
  /**
   * When set, signing in at this gate mints an app-token with this scope and
   * app-lb presents it upstream for the life of the session — so an upstream
   * that authenticates for itself can accept a signed-in person without its
   * own authentication being turned off. Absent means no token is minted.
   */
  session_scope?: "none" | "view" | "admin";
  base_path?: string;
  session_ttl_secs?: number;
  cookie_name?: string;
  cookie_domain?: string;
  redirect_url?: string;
  forward_identity?: boolean;
  /** How to verify a JWT, when `jwt` is among the providers. */
  jwt?: JwtSpec;
  /**
   * Inherit the identity half of this gate — `provider`, the OAuth credentials
   * and allow-lists, `jwt`, `cookie_domain` — from a named provider declared on
   * the deployment's namespace, resolved live on every request. When set, this
   * gate carries only the route-scoped fields (`public_paths`, `session_scope`,
   * `base_path`, `cookie_name`, `redirect_url`, `forward_identity`,
   * `session_ttl_secs`); setting an identity field alongside it is refused.
   */
  provider_ref?: string;
}

export type AuthProvider = "google" | "app-token" | "jwt";

/**
 * How a gate verifies a JWT somebody else issued, and which ones it lets past.
 *
 * The `jwt` provider holds no state: there is no session cookie and no token
 * table, because the credential carries its own proof. Everything the gate needs
 * is therefore configuration — which key, which algorithm, which issuer, which
 * claim is the user, which claims must hold — which is also what makes one gate
 * front the Heyo auth API, an Auth0 tenant or a Keycloak realm.
 *
 * Exactly one of `secret`, `public_key` and `jwks_url` is set.
 */
export interface JwtSpec {
  /** HMAC shared secret (the `HS*` algorithms), as a secret-store reference. */
  secret?: SecretRef;
  /** An inline PEM public key or certificate, for `RS*`/`PS*`/`ES*`. */
  public_key?: string;
  /** The issuer's JWKS endpoint, for a provider that rotates keys. */
  jwks_url?: string;
  /**
   * The signature algorithms this gate accepts, e.g. `["HS256"]`.
   *
   * Required, with no default: the algorithm is named in the token's own header,
   * and a verifier that trusted that would accept an unsigned token.
   */
  algorithms: string[];
  /** The `iss` a token must carry, exactly. Required. */
  issuer: string;
  /** The `aud` a token must carry, if the issuer sets one. */
  audience?: string;
  /**
   * Claims a token must satisfy on top of verifying. A value or a list of them
   * per claim: a list is an OR within that claim, and the map is an AND across
   * claims. A claim that is itself a list — scopes, roles, groups — is satisfied
   * by containing one of the wanted values.
   */
  require?: Record<string, unknown>;
  /** Which claim is forwarded as `x-auth-request-user`. Defaults to `sub`. */
  subject_claim?: string;
  /** Which claim is forwarded as `x-auth-request-email`. Defaults to `email`. */
  email_claim?: string;
  /** Which claim is forwarded as `x-auth-request-name`. Defaults to `name`. */
  name_claim?: string;
  /** Clock skew allowed on `exp`/`nbf`, in seconds. Capped at 300. */
  leeway_secs?: number;
  /**
   * A cookie to read the token from when there is no `Authorization` header —
   * the only way a browser page navigation can carry one. The header wins when
   * both are present.
   */
  cookie?: string;
  /**
   * Heyo Auth `/api/auth/login` endpoint for browser email/password sign-in.
   * Requires `cookie`; app-lb stores neither passwords nor refresh tokens.
   */
  login_endpoint?: string;
  /**
   * Hosted sign-in: where to redirect a token-less *browser* (a request that
   * accepts HTML). The issuer signs the person in, sets the JWT in `cookie`, and
   * redirects back to the URL passed in `login_redirect_param`; app-lb keeps no
   * session of its own. A program still gets a 401. Requires `cookie`, and must
   * be `https://` (loopback `http://` aside).
   */
  login_url?: string;
  /** The query parameter the hosted sign-in reads the return URL from. Only with `login_url`; defaults to `redirect_uri`. */
  login_redirect_param?: string;
  /**
   * Scoped sign-in: the issuer's OAuth authorization endpoint. With
   * `token_url`, a token-less browser is sent through an authorization-code
   * flow (PKCE S256) asking for this deployment's namespace; the token that
   * comes back must name this host (`gateHost`) and namespace, and app-lb keeps
   * a host-only session. Cannot be combined with a `cookie_domain` realm.
   */
  authorize_url?: string;
  /** Scoped sign-in: the issuer's token endpoint, called server to server. */
  token_url?: string;
}

export interface DeploymentSpec {
  id: string;
  /**
   * The namespace this deployment belongs to. Absent means `"default"`.
   * Namespaces segregate use: a namespace-confined token reaches only the
   * deployments in it, and the event feed is kept per namespace.
   */
  namespace?: string;
  /**
   * The heyo account this deployment's VMs are metered to, and the user who
   * registered it. The managed service stamps both from the caller's
   * credential (the namespace's owning account) and ignores what the body
   * says; a self-hosted app-lb keeps what it was sent, usually nothing.
   */
  account_id?: string;
  user_id?: string;
  routes: RouteRule[];
  /** Return HTTP 503 for routed proxy traffic while admin management remains available. */
  maintenance?: boolean;
  vm?: VmSpec;
  scaling?: ScalingPolicy;
  health?: HealthCheck;
  upstreams?: string[];
  discovery?: DiscoverySpec;
  build?: BuildSpec;
  artifact?: ArtifactSpec;
  site?: SiteSpec;
  update?: UpdateSpec;
  auth?: AuthGate;
  feed?: FeedSpec;
  /** Anything app-lb sent that this build has no name for. */
  [extra: string]: unknown;
}

/** Orchestrator-owned endpoint membership for a static deployment. */
export interface DiscoverySpec {
  service_id: string;
}

/**
 * A deployment's opt-in hooks into its namespace's event feed. Everything
 * defaults to off — a deployment publishes nothing its spec did not ask for.
 */
export interface FeedSpec {
  /** Publish lifecycle events (registered, updated, removed). */
  announce?: boolean;
  /** Publish operational issues (boot failures, cold-start timeouts, …). */
  issues?: boolean;
  /**
   * Serve the namespace's feed as RSS at this path on this deployment's own
   * routes — the only way a feed becomes reachable outside the admin listener.
   * Runs behind the deployment's `auth` gate, if it has one.
   */
  expose?: string;
}

export interface VmStatus {
  sandbox_id: string;
  addr: string;
  in_flight: number;
  healthy: boolean;
  draining: boolean;
}

export interface DeploymentStatus {
  /** Opaque persisted token for conditional service rollout; absent on older servers. */
  rollout_revision?: string;
  spec: DeploymentSpec;
  kind: DeploymentKind;
  desired_replicas: number;
  ready: number;
  pending: number;
  total_in_flight: number;
  vms: VmStatus[];
  /** Present when the spec declares `vm.workspace`. */
  workspace?: WorkspaceStatus;
  /** Present for a site: whether its root on the LB host can serve. */
  site?: SiteRootStatus;
}

/** A site's root as the LB host sees it. */
export interface SiteRootStatus {
  root: string;
  status: "ok" | "missing" | "not_a_directory" | "unreadable" | "empty";
  index_present?: boolean;
  /** Why it cannot serve, and how to fill it. */
  hint?: string;
}

export interface UpstreamTrafficStatus {
  deployment_id: string;
  upstream: string;
  state: "accepting" | "draining" | "drained";
  healthy: boolean;
  in_flight: number;
  reason: string | null;
  started_at: number | null;
}

// -- metrics ---------------------------------------------------------------

export interface StatusCounts {
  total: number;
  c2xx: number;
  c3xx: number;
  c4xx: number;
  c5xx: number;
  errors: number;
}

export interface Bucket {
  /** `null` is the `+Inf` bucket. */
  le: number | null;
  count: number;
}

export interface Histogram {
  count: number;
  sum: number;
  mean: number;
  p50: number;
  p90: number;
  p99: number;
  buckets: Bucket[];
}

export interface AutoscaleCounts {
  vms_created: number;
  vms_drained: number;
  vms_reaped: number;
  scale_up_events: number;
  scale_down_events: number;
  cold_start_waits: number;
  cold_start_hits: number;
  cold_start_timeouts: number;
  boot_timeouts: number;
  /** Creates the daemon refused or that failed client-side, since app-lb started. */
  create_failures: number;
  /** What the most recent failed create said; absent until one has failed. */
  last_create_error?: string;
}

export interface DeploymentMetrics {
  requests: StatusCounts;
  latency_ms: Histogram;
  cold_start_s: Histogram;
  autoscale: AutoscaleCounts;
}

export interface HostUsage {
  available: boolean;
  cpu_count: number;
  cpu_percent: number;
  memory_total_bytes: number;
  memory_used_bytes: number;
  sampled_at_ms: number;
}

export interface FleetPool {
  deployments: number;
  ready: number;
  draining: number;
  pending: number;
  total_in_flight: number;
}

export interface PoolStatus {
  desired_replicas: number;
  ready: number;
  draining: number;
  pending: number;
  total_in_flight: number;
  target_concurrency: number;
  min_replicas: number;
  max_replicas: number;
  warm_pool: number;
  /** `null` means no capacity to divide by — not zero load. */
  utilization: number | null;
  cpu_percent: number | null;
  memory_bytes: number | null;
  boot_timeout_secs: number;
  cold_start_timeout_secs: number;
  /** Failed boots in a row since the last VM that passed its health check. */
  boot_failures: number;
  /**
   * Seconds until the autoscaler may create a VM again while the boot-failure
   * backoff holds it off; `null` when it may create one now. Any spec write
   * clears it.
   */
  boot_backoff_secs: number | null;
}

export interface VmView {
  sandbox_id: string;
  addr: string;
  in_flight: number;
  healthy: boolean;
  draining: boolean;
  uptime_secs: number;
  cpu_percent: number | null;
  memory_bytes: number | null;
}

export interface PendingVmView {
  sandbox_id: string;
  age_secs: number;
  status?: string;
}

export interface DeploymentView {
  id: string;
  /** Absent for the default namespace. */
  namespace?: string;
  /** The account this deployment's VMs are metered to, when app-lb knows it. */
  account_id?: string;
  kind: DeploymentKind;
  upstreams: string[];
  /** Whether at least one data-plane route points at this deployment. */
  routed: boolean;
  hosts: string[];
  urls?: string[];
  site_root?: string;
  site_spa?: boolean;
  job_kind?: "build" | "pull" | "update";
  pool: PoolStatus;
  vms: VmView[];
  pending_vms: PendingVmView[];
  metrics: DeploymentMetrics;
}

export interface ObsStats {
  queued: number;
  dropped: number;
  shipped: number;
  failed: number;
  healthy: boolean;
}

/**
 * Whether app-lb can reach the VM daemon. When it cannot, the autoscaler
 * abandons every tick, so nothing scales or boots and every other number in
 * the metrics response is frozen at whatever it was when the daemon went away.
 */
export interface DaemonSnapshot {
  reachable: boolean;
  /** What the last failed listing said; absent while it is reachable. */
  last_error?: string;
}

export interface MetricsResponse {
  generated_at: number;
  uptime_secs: number;
  host: HostUsage;
  fleet: FleetPool;
  global: DeploymentMetrics;
  obs?: ObsStats;
  /** Absent when `APP_LB_SIEM=0`. */
  security?: SecuritySummary;
  daemon: DaemonSnapshot;
  deployments: DeploymentView[];
  /** How many matched before `limit`/`offset`, so you can page. */
  matched: number;
  tracked_deployments: number;
  /**
   * Sandboxes on the host that no deployment owns — created through the heyvm
   * CLI, the cloud API or the desktop rather than by app-lb. They share the
   * host with every pool. Absent from an older app-lb, empty under
   * `summary=true`, and narrowed to the caller's own accounts for a namespace
   * caller.
   */
  host_sandboxes?: HostSandboxView[];
}

/** One sandbox on the host that app-lb reports but does not manage. */
export interface HostSandboxView {
  sandbox_id: string;
  name: string;
  /** The daemon's status string: `running`, `stopped`, `provisioning`, …. */
  status: string;
  image: string;
  size_class?: string;
  guest_ip?: string;
  uptime_secs: number;
  cpu_percent: number | null;
  memory_bytes: number | null;
  /** The heyo account the sandbox is billed to, when the daemon knows. */
  account_id?: string;
  /** RFC 3339, when the daemon reports it. */
  created_at?: string;
}

// -- host disks ------------------------------------------------------------

export type DiskState = "running" | "stopped" | "orphan" | "unknown";
export type DiskPartKind = "data" | "rootfs" | "mount" | "snapshot" | "other";
export type ArchiveStatus = "running" | "succeeded" | "failed";

export interface DiskPart {
  kind: DiskPartKind;
  path: string;
  bytes: number;
  apparent_bytes: number;
  modified_at: number;
}

export interface ArchiveRecord {
  uri: string;
  at: number;
  bytes: number;
}

export interface DiskInfo {
  sandbox_id: string;
  name?: string;
  deployment?: string;
  state: DiskState;
  claimed: boolean;
  retain: boolean;
  note?: string;
  bytes: number;
  apparent_bytes: number;
  modified_at: number;
  expires_at?: number;
  held_by?: string;
  archived?: ArchiveRecord;
  parts: DiskPart[];
  roots: string[];
}

export interface ArchiveView {
  id: string;
  sandbox_id: string;
  uri: string;
  started_at: number;
  finished_at?: number;
  status: ArchiveStatus;
  bytes: number;
  expected_bytes: number;
  error?: string;
  purged?: boolean;
}

export interface DiskTotals {
  disks: number;
  bytes: number;
  apparent_bytes: number;
  running: number;
  stopped: number;
  orphan: number;
  retained: number;
  expiring_now: number;
  reclaimable_bytes: number;
}

export interface DiskInventory {
  complete: boolean;
  incomplete_reason?: string;
  data_dir: string;
  tmp_dir: string;
  ttl_secs: number;
  sweep_secs: number;
  archive_enabled: boolean;
  archive_on_expire: boolean;
  archive_target?: string;
  free_bytes?: number;
  filesystem_bytes?: number;
  orphan_ttl_secs: number;
  totals: DiskTotals;
  disks: DiskInfo[];
  archives: ArchiveView[];
}

// -- security --------------------------------------------------------------

/** The alert counts carried on `/metrics`, for a status tile. */
export interface SecuritySummary {
  /** Alerts currently held in app-lb's in-memory ring. */
  open: number;
  /** How many of those are `high` or `critical`. */
  urgent: number;
  /**
   * Observations dropped because the analysis queue was full. Non-zero means
   * detection is sampling rather than complete — the figure to watch, since a
   * SIEM that has stopped looking is indistinguishable from a quiet network.
   */
  dropped: number;
  /** Whether the per-source table is full, which means the same for addresses. */
  clients_at_capacity: boolean;
  /** Guard rules currently in force. */
  rules: number;
  /** Requests those rules have refused since app-lb started. */
  blocked: number;
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface SecurityAlert {
  id: number;
  /** Epoch millis of the first occurrence folded into this alert. */
  ts: number;
  last_ts: number;
  /** e.g. `auth.brute-force`, `web.sqli`, `traffic.scanner`. */
  rule: string;
  severity: Severity;
  title: string;
  client?: string;
  /** Absent for admin-plane and unrouted findings. */
  deployment?: string;
  /** Never carries a query string. */
  path?: string;
  /** MITRE ATT&CK technique id, e.g. `T1110`. */
  technique?: string;
  /**
   * Occurrences folded into this alert. A scanner produces one alert whose
   * count climbs, not ten thousand alerts.
   */
  count: number;
  /**
   * The triggering event in ECS field names (`source.ip`, `url.path`, …). A
   * free-form map: app-lb may add fields, and `url.query` is never among them.
   */
  ecs?: Record<string, unknown>;
  /** What to do about it. Derived server-side, so a client renders rather than
   * reasons. */
  response: AlertResponse;
}

/** The runbook half of an alert: what to check, and what can be applied. */
export interface AlertResponse {
  /** Ordered, short. What to check before refusing anyone's traffic. */
  investigate: string[];
  /** Rules that would mitigate this, ready to `POST /security/rules`. */
  actions: SuggestedAction[];
  /** Present where the obvious action does not do what it looks like it does —
   * notably that guard rules are never applied to app-lb's own admin API. */
  caveat?: string;
}

export interface SuggestedAction {
  /** `block-client`, `block-client-deployment`, `block-path`, `exempt-client`. */
  kind: string;
  label: string;
  /** What it stops and what it leaves alone. Show this next to the button. */
  effect: string;
  /** Post verbatim to `/security/rules`. */
  rule: RuleSpec;
}

// -- guard rules -----------------------------------------------------------

export type RuleAction = "block" | "allow";

/**
 * Conditions on a request. Every field present must match; absent fields are
 * not checked. All literal — app-lb runs no regular expressions on the request
 * path.
 */
export interface RuleMatch {
  /** An address or CIDR: `203.0.113.9`, `203.0.113.0/24`, `2001:db8::/32`. */
  client?: string;
  host?: string;
  deployment?: string;
  path_prefix?: string;
  path_contains?: string;
  method?: string;
  user_agent_contains?: string;
}

/** The body of `POST /security/rules`. */
export interface RuleSpec {
  action: RuleAction;
  /** At least one condition — an empty match is refused, since it would apply
   * to every request to the data plane. */
  match: RuleMatch;
  /** Seconds from now. Omitted means permanent. */
  expires_in_secs?: number;
  note?: string;
}

/** One rule in force. */
export interface RuleView {
  id: string;
  action: RuleAction;
  match: RuleMatch;
  /** The conditions as a phrase, so a client need not render them. */
  summary: string;
  note?: string;
  created_at: number;
  expires_at?: number;
  /** Cumulative since this rule was created. The number to trust. */
  hits: number;
  last_hit?: number;
  /** `false` under `APP_LB_GUARD_ENFORCE=0`: matched and counted, not refused. */
  enforcing: boolean;
  /**
   * Hits per bucket over the last window, oldest first — see
   * {@link GuardStats.hits_bucket_secs}. In-memory on the LB, so it is absent
   * from the persisted rule file and starts empty after a restart. All-zero
   * means "no hits", not "no data": a rule that has never fired is exactly what
   * this is for spotting.
   *
   * Approximate at bucket boundaries by design — the LB will not take a lock on
   * the request path to make a chart exact. Use `hits` for anything that has to
   * add up.
   */
  hits_recent?: number[];
}

export interface GuardStats {
  rules: number;
  blocked: number;
  /** Requests an `allow` rule exempted from a block. */
  exempted: number;
  enforcing: boolean;
  /** Requests refused per bucket over the last window, oldest first. */
  blocked_recent?: number[];
  /** The same for requests an `allow` rule exempted. */
  exempted_recent?: number[];
  /** Seconds each entry of the `*_recent` series covers. */
  hits_bucket_secs: number;
  /** Total seconds the `*_recent` series spans. */
  hits_window_secs: number;
}

export interface SeverityTotals {
  info: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface SiemStats {
  observed: number;
  dropped: number;
  analyzed: number;
  raised: number;
  suppressed: number;
  tracked_clients: number;
  clients_at_capacity: boolean;
}

/** `GET /security`. */
export interface SecurityResponse {
  generated_at: number;
  /** `false` with an empty list when `APP_LB_SIEM=0` — not a 404. */
  enabled: boolean;
  /** Seconds each rate-based rule counts over. */
  window_secs: number;
  /** Newest first. */
  alerts: SecurityAlert[];
  totals: SeverityTotals;
  /** The block rules in force. Served here so a console renders findings and
   * interventions from one fetch. Narrowed for a deployment-scoped token. */
  rules: RuleView[];
  guard: GuardStats;
  /** Withheld from a deployment-scoped token, for whom it would describe
   * traffic it cannot see. */
  stats?: SiemStats;
}

// -- workflows, jobs, secrets, certs --------------------------------------

/** A repository workflow registered with app-lb. */
export interface WorkflowSpec {
  id: string;
  repo: string;
  ref: string;
  path: string;
  network: string;
  /** A stored credential reference, never the credential value. */
  auth?: SecretRef;
  secrets_prefix?: string;
  enabled: boolean;
}

export interface WorkflowList {
  workflows: WorkflowSpec[];
}

export type JobKind =
  | "image-build"
  | "artifact-pull"
  | "mount-pull"
  | "host-update";
export type JobStatus = "running" | "succeeded" | "failed";

export interface JobRecord {
  id: string;
  deployment: string;
  kind: JobKind;
  status: JobStatus;
  started_at: number;
  finished_at?: number | null;
  error?: string | null;
  log: string[];
  repo?: string;
  ref?: string;
  commit?: string;
  dockerfile?: string;
  image?: string;
  rolled_out?: boolean;
  store?: string;
  artifact?: string;
  digest?: string;
  bytes?: number;
  reused?: boolean;
  /** Site pulls only: the directory the bundle was unpacked into. */
  site_root?: string;
  /** Site pulls only: regular files unpacked. */
  files?: number;
  /**
   * Mount pulls only: one entry per guest mount, in spec order. A mount pull
   * covers every mount on the deployment, so the single `store`/`digest` fields
   * above stay empty on this kind.
   */
  mounts?: MountOutcome[];
  working_dir?: string;
  commands_total?: number;
  commands_run?: number;
  verified?: boolean;
}

/** What one guest mount's pull did. */
export interface MountOutcome {
  /** The guest path, which identifies the mount within the deployment. */
  path: string;
  store: string;
  ref: string;
  digest?: string;
  /** The tree on the app-lb host the guests mount. */
  tree?: string;
  /** Regular files unpacked. Absent on a reuse, where nothing was unpacked. */
  files?: number;
  /** Bytes transferred. `0` with `reused` means the tree was already there. */
  bytes?: number;
  /** Uncompressed size of the tree — what the mount costs the host's disk. */
  unpacked?: number;
  reused?: boolean;
  /** Whether this mount's digest changed, which is what recycles the pool. */
  changed?: boolean;
}

export interface SecretSummary {
  id: string;
  /** The namespace wall the secret sits behind; `default` when unset. */
  namespace: string;
  description: string | null;
  /** Key *names*. Values never leave app-lb. */
  keys: string[];
  updated_at: number;
  encrypted_at_rest: boolean;
}

export interface CertStatus {
  host: string;
  not_after: string;
  issuer: string;
  needs_renewal: boolean;
}

export interface ExecOutput {
  sandbox_id: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  /** stdout and stderr interleaved as the guest wrote them. */
  output: string;
}

export interface EvictOutcome {
  sandbox_id: string;
  /** `killed` (immediate) or `draining` (still serving what it has). */
  outcome: "killed" | "draining";
}

// -- app-tokens ------------------------------------------------------------

/** What a token may do on the admin API. */
export type AdminScope = "none" | "view" | "admin";

export interface TokenSummary {
  id: string;
  name: string;
  admin: AdminScope;
  /**
   * The namespace this token is confined to, if any. Inside it, an empty
   * `deployments` list means every deployment there; outside it the token
   * reaches nothing.
   */
  namespace?: string;
  /** Deployment ids, or `["*"]` for all of them. */
  deployments: string[];
  created_at: number;
  expires_at?: number;
  /**
   * `undefined` also means "not used since the store was last written" — the
   * stamp is flushed opportunistically, not per request.
   */
  last_used_at?: number;
  /** Minted at a control plane and valid on every server that mirrors it. */
  fleet?: boolean;
  /**
   * Set when this server holds the token only as a mirror: the control plane
   * it came from, which is where it is changed or revoked.
   */
  mirrored_from?: string;
}

// -- the event feed --------------------------------------------------------

/** One namespace that has feed events, from `GET /feeds`. */
export interface FeedIndexEntry {
  namespace: string;
  events: number;
}

/**
 * One event from a namespace's feed (`GET /feeds/:ns?format=json`) — the same
 * entries the RSS document carries; `id` is the RSS `<guid>`.
 */
export interface FeedEvent {
  id: number;
  /** When the event first happened (unix seconds). */
  ts: number;
  /** When it last happened — repeats of the same issue fold into one entry. */
  last_ts: number;
  count: number;
  namespace: string;
  deployment: string;
  kind: "deployed" | "updated" | "removed" | "issue";
  title: string;
  detail: string;
}

/**
 * The reply to a mint. **`token` is the only time the secret is returned** —
 * app-lb stores only its hash and no endpoint reads it back.
 */
export interface MintedToken extends TokenSummary {
  token: string;
}

/** `GET /api/plugins` — a built-in plugin, its stored record and its live status. */
export interface PluginView {
  id: string;
  name: string;
  description: string;
  /** JSON Schema for `config`. Advisory; app-lb validates on write. */
  config_schema: unknown;
  enabled: boolean;
  /** Kept while disabled, so re-enabling does not lose it. */
  config: unknown;
  updated_at: number;
  /** Why the last apply failed. A plugin can be enabled *and* failing. */
  last_error?: string;
  /** Whatever the plugin reports about itself; the shape is per plugin. */
  status: unknown;
  /** Whether namespaces install this plugin themselves. */
  per_namespace?: boolean;
  /** The namespaces that have, for a per-namespace plugin. */
  installed_in?: string[];
}

// -- whoami ------------------------------------------------------------------

/**
 * `GET /whoami` — what the server makes of the credential presented. Needs no
 * tier, so it answers even for a token every other route refuses.
 */
export interface WhoAmI {
  /** `ungated`, `operator`, `app-token` or `federated`. */
  caller: string;
  /** `none`, `view`, `admin` — or `unchecked` on an ungated listener. */
  admin_scope: string;
  /** Whether this credential may use the fleet-wide routes. */
  fleet: boolean;
  /** Whether it is behind a namespace wall. */
  confined: boolean;
  may: { read_view_routes: boolean; use_admin_routes: boolean; [extra: string]: unknown };
  token?: { id: string; name: string; [extra: string]: unknown };
  /** An app-token's namespace, when it is confined to one. */
  namespace?: string;
  /** `["*"]` is every deployment; empty on a namespace token is all of it. */
  deployments?: string[];
  expires_at?: number;
  expires_in_secs?: number;
  /** A federated caller's identity, as the auth service reported it. */
  subject?: unknown;
  /** A federated caller's namespaces and its tier in each. */
  namespaces?: Record<string, string>;
  detail?: string;
  note?: string;
  [extra: string]: unknown;
}

// -- rollouts ----------------------------------------------------------------

/** `POST /deployments/:id/rollouts` and `GET …/rollouts/:operation`. */
export interface RolloutOperation {
  operation_id: string;
  deployment: string;
  /** The `rollout_revision` the operation was admitted against. */
  source_revision: string;
  target_spec_sha256: string;
  /** `running`, `succeeded`, `failed` or `reconciliation_required`. */
  status: string;
  phase: string;
  readiness_verified: boolean;
  previous_stopped: boolean;
  error?: string | null;
  preparation_stage?: string | null;
  /** Present once a failed rollout's candidates have been reclaimed. */
  failure_settlement?: unknown;
  [extra: string]: unknown;
}

// -- discovery ---------------------------------------------------------------

/** `GET /deployments/:id/discovery-status`. camelCase on the wire. */
export interface DiscoveryStatus {
  serviceId: string;
  sourceUrl?: string | null;
  version?: number | null;
  /** The regional discovery state; its shape belongs to the regional protocol. */
  regional?: unknown;
  upstreams: { peer: string; draining: boolean; inFlight: number; [extra: string]: unknown }[];
  [extra: string]: unknown;
}

// -- namespaces, auth providers ----------------------------------------------

/** `GET /namespaces` — one namespace the credential can see. */
export interface NamespaceEntry {
  namespace: string;
  /** How many of its deployments this credential may view. */
  deployments: number;
  /** Whether it was declared, rather than only named by a deployment. */
  declared: boolean;
  description?: string;
  created_at?: number;
  [extra: string]: unknown;
}

/** `GET /auth-providers` — a declared identity provider. */
export interface AuthProviderView {
  name: string;
  namespace: string;
  description?: string;
  created_at: number;
  provider: AuthProvider | AuthProvider[];
  client_id?: string;
  client_secret?: SecretRef;
  allowed_domains?: string[];
  allowed_emails?: string[];
  jwt?: JwtSpec;
  cookie_domain?: string;
  [extra: string]: unknown;
}

// -- namespace plugins -------------------------------------------------------

/**
 * `GET /namespaces/:ns/plugins` — a plugin as one namespace sees it. `enabled`
 * is the operator's fleet switch; `installed` is this namespace's. A plugin
 * does nothing for a namespace unless both are true.
 */
export interface NamespacePlugin {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  installed: boolean;
  installed_at?: number;
  /** `token:<id>` or `user:<id>`; absent for the operator. */
  installed_by?: string;
  config?: unknown;
  [extra: string]: unknown;
}

export interface NamespaceInstall {
  installed_at: number;
  installed_by?: string | null;
  config: unknown;
  [extra: string]: unknown;
}

/** `GET /api/plugins/:id/installs` — fleet scope only. */
export interface PluginInstalls {
  plugin: string;
  enabled: boolean;
  namespaces: string[];
  installs: Record<string, NamespaceInstall>;
  [extra: string]: unknown;
}

// -- telemetry (the obs plugin) ----------------------------------------------

/** Whether recently ingested telemetry is queryable yet. */
export interface ObsFreshness {
  buffered_rows: number;
  flush_secs: number;
  dropped: number;
  [extra: string]: unknown;
}

/** One time bucket. A `null` measure means nothing was sampled, not zero. */
export interface ObsMetricBucket {
  /** Bucket start, epoch milliseconds UTC. */
  t: number;
  requests_per_sec?: number | null;
  errors_per_sec?: number | null;
  mean_latency_ms?: number | null;
  p50_ms?: number | null;
  p90_ms?: number | null;
  p99_ms?: number | null;
  cpu_percent?: number | null;
  memory_bytes?: number | null;
  in_flight?: number | null;
  ready?: number | null;
  pending?: number | null;
  draining?: number | null;
  [extra: string]: unknown;
}

export interface ObsLogBucket {
  t: number;
  lines: number;
  errors: number;
  [extra: string]: unknown;
}

export interface ObsFleetRow {
  id: string;
  buckets: ObsMetricBucket[];
  log_buckets: ObsLogBucket[];
  latest: ObsMetricBucket;
  log_lines: number;
  error_logs: number;
  [extra: string]: unknown;
}

/** `…/plugins/obs/api/fleet` — a namespace's telemetry overview. */
export interface ObsFleet {
  generated_at_ms: number;
  from_ms: number;
  to_ms: number;
  step_secs: number;
  window: string;
  windows: string[];
  retain_days: number;
  freshness: ObsFreshness;
  /** Operator view only; absent in a namespace's. */
  host?: ObsMetricBucket[];
  deployments: ObsFleetRow[];
  /** Operator view only. */
  host_sandboxes?: unknown;
  [extra: string]: unknown;
}

/** `…/plugins/obs/api/deployments/:id`. */
export interface ObsDeployment {
  id: string;
  generated_at_ms: number;
  from_ms: number;
  to_ms: number;
  step_secs: number;
  window: string;
  windows: string[];
  retain_days: number;
  freshness: ObsFreshness;
  buckets: ObsMetricBucket[];
  log_buckets: ObsLogBucket[];
  latest: ObsMetricBucket;
  log_lines: number;
  error_logs: number;
  /** Backends that logged in the window. */
  backends: string[];
  [extra: string]: unknown;
}

/** One stored log line. */
export interface ObsLogRow {
  /** Epoch milliseconds UTC. */
  ts: number;
  level?: string | null;
  /** `stdout`, `stderr`, `console`, `access`, `security`, … */
  source: string;
  message: string;
  backend?: string | null;
  host?: string | null;
  /** The structured payload, still a JSON string. */
  fields?: string | null;
  [extra: string]: unknown;
}

/** `…/plugins/obs/api/deployments/:id/logs` — one page, newest first. */
export interface ObsLogs {
  id: string;
  from_ms: number;
  to_ms: number;
  rows: ObsLogRow[];
  /**
   * Pass back as `before` for the next page; `null` at the end. Inclusive, so
   * the next page may repeat lines from the same millisecond.
   */
  next_before_ms: number | null;
  limit: number;
  [extra: string]: unknown;
}

/** An alert rule, from `…/plugins/obs/api/alerts`. */
export interface ObsAlert {
  id: string;
  deployment: string;
  namespace?: string | null;
  /** `errors` — errors over the trailing minute. */
  metric: string;
  threshold: number;
  webhook_url: string;
  [extra: string]: unknown;
}
