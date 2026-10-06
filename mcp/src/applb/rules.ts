/**
 * The rules a JSON Schema cannot state, written out once.
 *
 * A generated schema describes each field in isolation, and roughly half of what
 * a spec gets wrong is a relationship *between* fields: which backend blocks
 * exclude each other, which combinations a driver forbids, which policy a
 * feature imposes on the pool around it. `serde` cannot express any of that and
 * neither can the schema derived from it, so this is the one part of the spec
 * that is deliberately hand-written.
 *
 * Every entry mirrors a check in `DeploymentSpec::validate` (`app-lb/src/config.rs`).
 * They are stated in the order the server checks them, and phrased the way the
 * server's own error is phrased, so a rule violated here and a rule violated
 * there read as the same sentence.
 *
 * Kept out of `tools/list` — `applb_spec_schema` returns the ones relevant to a
 * block, and the composite deploy path checks them before app-lb has to.
 */

export interface SpecRule {
  /** Schema blocks this rule constrains; `"*"` for whole-spec rules. */
  readonly blocks: readonly string[];
  readonly rule: string;
}

export const SPEC_RULES: readonly SpecRule[] = [
  {
    blocks: ["*", "VmSpec", "SiteSpec"],
    rule:
      "Exactly one backend: `vm` (app-lb boots and autoscales microVMs), `upstreams` " +
      "(host:port addresses you run yourself) or `site` (static files served from disk). " +
      "Two is BothBackendKinds, none is NoBackendKind, and `site` beside either of the " +
      "others is SiteWithOtherBackend.",
  },
  {
    blocks: ["*", "RouteRule"],
    rule:
      "Every route must set at least one of `host`, `host_suffix` or `path_prefix`; an " +
      "object with none of them is EmptyRoute. `strip_prefix` requires `path_prefix`.",
  },
  {
    blocks: ["*", "RouteRule"],
    rule:
      "`routes: []` is legal only for a `vm` deployment, which is then reachable by exec " +
      "and shell but takes no HTTP traffic. A static deployment and a site are reachable " +
      "only through the proxy, so both need a route.",
  },
  {
    blocks: ["*", "AuthGate"],
    rule:
      "`auth` requires at least one route — a deployment taking no HTTP traffic has " +
      "nothing for a gate to sit in front of (AuthWithoutRoutes).",
  },
  {
    blocks: ["BuildSpec", "ArtifactSpec"],
    rule:
      "`build` and `artifact` are mutually exclusive (BothImageSources). Both rewrite " +
      "`vm.image`, and a deployment with two sources for it has no answer to which one " +
      "the running image came from.",
  },
  {
    blocks: ["SiteSpec", "BuildSpec"],
    rule:
      "`site.root` is a directory ON THE APP-LB HOST, not on your machine: a path that " +
      "exists only where you are registers fine and 404s every request. A site's files " +
      "come from exactly one of `build` (a git repo: `repo`, `ref`, `context` and `auth` " +
      "only — the checkout's `context` is copied into the root, nothing is run), " +
      "`artifact` (a bundle from an art store) or `update` (commands on the host). " +
      "repo_create + repo_deploy set this up from files you have.",
  },
  {
    blocks: ["BuildSpec"],
    rule:
      "`build` takes exactly one source: `repo` (a git remote, with `dockerfile` and " +
      "`context` relative to the checkout) or `store` (an artifact store holding a " +
      "Dockerfile manifest). `dockerfile` and `context` are meaningful only with `repo`. " +
      "A repo on the Heyo git remote is private and needs `auth`; applb_deploy and " +
      "repo_deploy add it for you. A namespace credential may only use https:// repos and stores.",
  },
  {
    blocks: ["WorkspaceSpec", "ScalingPolicy", "VmSpec"],
    rule:
      "`vm.workspace` forces the pool around it: `scaling.max_replicas` must be 1, " +
      "`scaling.warm_pool` must be 0, and the driver must be `firecracker`. Two replicas " +
      "would each capture their own divergent copy of a single-writer workspace and the " +
      "last one to retire would win.",
  },
  {
    blocks: ["WorkspaceSpec", "VmSpec"],
    rule:
      "`vm.workspace` and `vm.workspace_archive` are mutually exclusive — both own " +
      "`/workspace`. `workspace_archive` is filled in by cloud; a hand-written one with " +
      "only `archive_id` is refused (UnresolvedWorkspaceArchive).",
  },
  {
    blocks: ["IngressSpec", "VmSpec"],
    rule:
      "`ingress.cloud` requires `vm` (IngressWithoutVm): a cloud URL is a bind on a VM's " +
      "port, and neither a static deployment's upstreams nor a site's files are on a " +
      "daemon that could bind one.",
  },
  {
    blocks: ["Driver", "VmSpec"],
    rule:
      "Driver `lxc` forbids `workspace_archive`, `image_download_url`, `setup_hooks`, " +
      "`open_ports`, `mounts`, `build`, `artifact` and `ingress` — an Incus system " +
      "container is not a heyvm microVM and none of those have a meaning there.",
  },
  {
    blocks: ["Driver"],
    rule:
      "`libvirt` and `firecracker_containerd` parse and are then refused at registration " +
      "(UnsupportedDriver). They exist as variants so a spec naming one gets an " +
      "explanation instead of a deserialization error. The drivers that work are " +
      "`firecracker`, `kvm` and `lxc`.",
  },
  {
    blocks: ["HealthCheck"],
    rule:
      "`health.path` distinguishes absent from null. Absent means `\"/\"`; an explicit " +
      "`null` means no HTTP probe at all — a bare TCP connect, which is what a non-HTTP " +
      "service wants. This is the field most often got wrong by a client that treats " +
      "null and missing as the same thing.",
  },
  {
    blocks: ["MountSpec"],
    rule:
      "Mount paths must be absolute, unique within the deployment, and non-nested; at " +
      "most 8 per deployment. A writable mount is refused on the `kvm` driver.",
  },
  {
    blocks: ["AuthGate"],
    rule:
      "In `auth.public_paths`, a bare string means scope `admin` — the most closed scope, " +
      "not the most open. Write `{\"path\": \"/x\", \"scope\": \"public\"}` to actually " +
      "open a path.",
  },
  {
    blocks: ["*", "RouteRule"],
    rule:
      "TLS is automatic for an exact `host` route: registering nudges ACME and the " +
      "certificate is issued within seconds, selected per-handshake from SNI. There is no " +
      "call to make — `applb_certs` only reads. A `host_suffix` route NEVER gets its own " +
      "certificate; it needs a wildcard configured on the fleet, and a suffix no wildcard " +
      "covers is served a fallback certificate that will not validate.",
  },
  {
    blocks: ["*"],
    rule:
      "A token confined to a namespace must set `namespace` to that namespace. " +
      "Registering does not fill it in, and a spec without one means `default` — which " +
      "such a token cannot reach, so it is refused with the same 403 as any request " +
      "outside the token's scope.",
  },
];

/** The rules touching a named block, plus the whole-spec ones. */
export function rulesFor(block?: string): readonly SpecRule[] {
  if (!block) return SPEC_RULES;
  return SPEC_RULES.filter((r) => r.blocks.includes(block) || r.blocks.includes("*"));
}

/**
 * Cross-field rules a spec breaks, checked here rather than at app-lb.
 *
 * Not a reimplementation of `DeploymentSpec::validate` — app-lb remains the
 * authority and will refuse anything this misses. This is the subset that can
 * be decided from the document alone, checked early so the answer is the rule
 * in the caller's own vocabulary instead of a `SpecError` arriving as a 400
 * string after a round trip.
 *
 * Deliberately conservative: a rule is reported only when the spec definitely
 * breaks it. Anything ambiguous is left to the server, because a client that
 * refuses a spec app-lb would accept is the failure this whole design is
 * organised against.
 */
export interface CheckOptions {
  /**
   * The caller is confined to a namespace (a tenant). app-lb refuses such a
   * caller any field that acts on its host; naming the alternative here, before
   * the round trip, is what keeps an agent from guessing.
   */
  confined?: boolean;
}

export function checkSpec(spec: unknown, opts: CheckOptions = {}): string[] {
  if (!spec || typeof spec !== "object" || Array.isArray(spec)) {
    return ["The spec must be a JSON object."];
  }
  const s = spec as Record<string, unknown>;
  const problems: string[] = [];
  const has = (k: string) => s[k] !== undefined && s[k] !== null;

  const backends = ["vm", "upstreams", "site"].filter(
    (k) => has(k) && !(Array.isArray(s[k]) && (s[k] as unknown[]).length === 0),
  );
  if (backends.length === 0) {
    problems.push(
      "No backend: set exactly one of `vm` (app-lb boots microVMs), `upstreams` " +
        "(addresses you run yourself) or `site` (static files).",
    );
  } else if (backends.length > 1) {
    problems.push(`Two backends (${backends.join(" and ")}); exactly one is allowed.`);
  }

  const site = (has("site") ? s.site : undefined) as Record<string, unknown> | undefined;
  const build = (has("build") ? s.build : undefined) as Record<string, unknown> | undefined;
  if (site && build) {
    for (const k of ["store", "dockerfile", "image_name", "image_size_mb"]) {
      if (build[k] !== undefined) {
        problems.push(
          `\`build.${k}\` does not apply to a site: a site's build copies a git checkout into ` +
            "its root and builds no image. Use `repo`, `ref`, `context` and `auth` only.",
        );
      }
    }
  }
  if (site && [has("build"), has("artifact"), has("update")].filter(Boolean).length > 1) {
    problems.push(
      "A site takes one of `build`, `artifact` or `update` — each writes the files under " +
        "`site.root`, so two have no answer to where what is served came from.",
    );
  }

  if (has("build") && has("artifact")) {
    problems.push(
      "`build` and `artifact` are mutually exclusive — both rewrite `vm.image`, so a " +
        "deployment with each has no answer to where its running image came from.",
    );
  }

  const routes = Array.isArray(s.routes) ? (s.routes as Record<string, unknown>[]) : [];
  if (!Array.isArray(s.routes)) {
    problems.push("`routes` is required; use `[]` for a vm deployment that takes no HTTP traffic.");
  }
  routes.forEach((r, i) => {
    if (!r || typeof r !== "object") return;
    if (r.host === undefined && r.host_suffix === undefined && r.path_prefix === undefined) {
      problems.push(`routes[${i}] sets none of \`host\`, \`host_suffix\` or \`path_prefix\`.`);
    }
    if (r.strip_prefix === true && r.path_prefix === undefined) {
      problems.push(`routes[${i}] sets \`strip_prefix\` without a \`path_prefix\`.`);
    }
  });

  if (routes.length === 0 && backends.length === 1 && backends[0] !== "vm") {
    problems.push(
      `A \`${backends[0]}\` deployment is reachable only through the proxy, so it needs at ` +
        "least one route. Only a `vm` deployment may have none.",
    );
  }
  if (has("auth") && routes.length === 0) {
    problems.push("`auth` needs at least one route — there is nothing for a gate to sit in front of.");
  }

  const vm = (has("vm") ? s.vm : undefined) as Record<string, unknown> | undefined;
  const ingress = (has("ingress") ? s.ingress : undefined) as Record<string, unknown> | undefined;
  if (ingress?.cloud === true && !vm) {
    problems.push("`ingress.cloud` requires a `vm` backend — a cloud URL is a bind on a VM's port.");
  }

  if (vm) {
    if (vm.workspace !== undefined && vm.workspace_archive !== undefined) {
      problems.push("`vm.workspace` and `vm.workspace_archive` both own /workspace; set one.");
    }
    if (vm.workspace !== undefined) {
      const scaling = (s.scaling ?? {}) as Record<string, unknown>;
      if (scaling.max_replicas !== undefined && scaling.max_replicas !== 1) {
        problems.push(
          "`vm.workspace` requires `scaling.max_replicas: 1` — two replicas would each " +
            "capture a divergent copy of a single-writer workspace.",
        );
      }
      if (scaling.warm_pool !== undefined && scaling.warm_pool !== 0) {
        problems.push("`vm.workspace` requires `scaling.warm_pool: 0`, for the same reason.");
      }
      if (vm.driver !== undefined && vm.driver !== "firecracker") {
        problems.push("`vm.workspace` requires the `firecracker` driver.");
      }
    }
    if (vm.driver === "libvirt" || vm.driver === "firecracker_containerd") {
      problems.push(
        `\`${String(vm.driver)}\` parses and is then refused at registration. The drivers ` +
          "that work are `firecracker`, `kvm` and `lxc`.",
      );
    }
  }

  if (site && !has("build") && !has("artifact") && !has("update")) {
    problems.push(
      "A `site` with no `build` or `artifact` is never filled, so every request 404s. Use " +
        "repo_deploy (kind site) for files in a repo, or `artifact` from art_publish_files.",
    );
  }
  if (opts.confined) {
    if (site && typeof site.root === "string" && site.root.trim() !== "") {
      problems.push("Leave out `site.root`: app-lb assigns your site a root in your namespace.");
    }
    for (const k of ["update", "gateway", "discovery"]) {
      if (has(k)) {
        problems.push(
          `\`${k}\` is operator-only: it acts on the app-lb host. Use \`build\` (repo_deploy) or ` +
            "`artifact` (art_publish_files) instead.",
        );
      }
    }
    const vm = s.vm as Record<string, unknown> | undefined;
    if (vm?.image_download_url) {
      problems.push("`vm.image_download_url` is set by Heyo cloud; use `build` or `artifact` for the image.");
    }
    const artifact = s.artifact as Record<string, unknown> | undefined;
    for (const [name, v] of [
      ["build.repo", build?.repo],
      ["build.store", build?.store],
      ["artifact.store", artifact?.store],
    ] as const) {
      if (typeof v === "string" && !v.startsWith("https://")) {
        problems.push(
          `\`${name}\` must be an https:// URL for a namespace credential (no host paths, ssh or ` +
            "s3://). repo_create gives you an https repo on the Heyo remote.",
        );
      }
    }
  }
  return problems;
}

/**
 * Route hostnames that will not get their own certificate.
 *
 * A `host_suffix` names a subtree, and the certificate for a subtree is a
 * wildcard configured on the fleet — ACME never issues per-suffix. One no
 * wildcard covers is warned about once in app-lb's log and then served a
 * fallback certificate that will not validate, which from outside looks like
 * TLS being simply broken.
 */
export function suffixRoutesWithoutCerts(spec: unknown): string[] {
  const routes = (spec as { routes?: unknown })?.routes;
  if (!Array.isArray(routes)) return [];
  return routes
    .map((r) => (r as { host_suffix?: unknown })?.host_suffix)
    .filter((h): h is string => typeof h === "string");
}
