/**
 * Why a VM deployment's guest never answers its health check.
 *
 * The pool counters say *that* a guest booted and never answered; only the
 * guest says *why*. A VM that never passes health is killed at
 * `boot_timeout_secs`, so the evidence has to be read while one is still
 * booting — app-lb's exec route runs in a booting VM when no VM is ready,
 * which is what this leans on.
 *
 * Everything here is pure (spec in, text out) so the decisions are testable
 * without a guest; the tool in diagnose.ts does the two requests.
 */

export interface StartCommandParts {
  /** The directory the command `cd`s into, if it does. */
  workdir?: string;
  /** Files the app's stdout/stderr are sent to instead of heyvm's capture. */
  redirects: string[];
  /** Whether it ends in `&`, i.e. returns. */
  backgrounded: boolean;
  /** The same command run in the foreground with its output on stdout. */
  foreground: string;
}

/**
 * Read a `start_command` of the shape repo_deploy and the guide produce:
 * `cd /app && export K=V && setsid nohup node server.js </dev/null >/f 2>&1 &`.
 */
export function parseStartCommand(cmd: string): StartCommandParts {
  const trimmed = cmd.trim();
  const backgrounded = /&\s*$/.test(trimmed) && !/&&\s*$/.test(trimmed);
  const workdir = /(?:^|&&|;)\s*cd\s+("[^"]+"|'[^']+'|[^\s;&]+)/.exec(trimmed)?.[1]?.replace(/^["']|["']$/g, "");
  const redirects: string[] = [];
  for (const m of trimmed.matchAll(/(?:^|[\s;])(?:[12]|&)?>>?\s*("[^"]+"|'[^']+'|[^\s;&|]+)/g)) {
    const target = (m[1] ?? "").replace(/^["']|["']$/g, "");
    if (target !== "/dev/null" && !target.startsWith("&")) redirects.push(target);
  }
  const foreground = trimmed
    .replace(/&\s*$/, "")
    .replace(/\b(setsid|nohup)\s+/g, "")
    .replace(/(?:^|\s)(?:[12]|&)?>>?\s*(?:&[12]|"[^"]+"|'[^']+'|[^\s;&|]+)/g, " ")
    .replace(/(?:^|\s)<\s*\/dev\/null/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return { workdir, redirects, backgrounded, foreground };
}

export interface Finding {
  severity: "error" | "warning";
  title: string;
  detail: string;
}

/** What is wrong with a VM spec before anything is run. */
export function lintVmSpec(vm: Record<string, unknown> | undefined): Finding[] {
  const out: Finding[] = [];
  if (!vm) return out;
  const cmd = typeof vm.start_command === "string" ? vm.start_command : undefined;
  if (!cmd) {
    out.push({
      severity: "error",
      title: "No start_command",
      detail:
        "A VM does not run the image's CMD or ENTRYPOINT. Without vm.start_command nothing starts.",
    });
    return out;
  }
  const p = parseStartCommand(cmd);
  if (!p.backgrounded) {
    out.push({
      severity: "error",
      title: "start_command does not return",
      detail:
        "It must end in `&` (e.g. `setsid nohup node server.js </dev/null &`); a foreground " +
        "command never lets the VM finish booting.",
    });
  }
  if (p.redirects.length > 0) {
    out.push({
      severity: "warning",
      title: "start_command hides the app's output",
      detail:
        `stdout/stderr go to ${p.redirects.join(", ")} inside the guest, so a crash never ` +
        "reaches heyvm's capture (/var/log/heyvm-start.log), deployment_logs, or app-lb's " +
        "boot-timeout report, and the file dies with the VM. Drop the redirect: " +
        "`setsid nohup <cmd> </dev/null &` keeps the output where it can be read.",
    });
  }
  if (/\b(HOST|BIND|LISTEN_ADDR)=(127\.0\.0\.1|localhost)\b/.test(cmd)) {
    out.push({
      severity: "error",
      title: "App bound to loopback",
      detail: "app-lb health-checks the guest's own address; listen on 0.0.0.0.",
    });
  }
  return out;
}

/**
 * The read-only battery run in the guest. Plain `;`-joined commands: the
 * exec channel can mangle backslashes and nested `$(…)`, so none are used.
 */
export function probeScript(opts: { port?: number; healthPath?: string; parts?: StartCommandParts }): string {
  const lines = [
    "echo '== heyvm-start.log (start_command stdout)'",
    "tail -n 60 /var/log/heyvm-start.log 2>&1",
    "echo '== heyvm-start.err.log (start_command stderr)'",
    "tail -n 60 /var/log/heyvm-start.err.log 2>&1",
  ];
  for (const f of opts.parts?.redirects ?? []) {
    lines.push(`echo '== ${f} (start_command redirect)'`, `tail -n 80 '${f}' 2>&1`);
  }
  lines.push(
    "echo '== processes'",
    // Kernel threads print as `[name]`; a bracket expression rather than a
    // backslash, which the exec channel strips.
    "ps -eo pid,args 2>/dev/null | grep -v ' [[]' || ps 2>&1",
    "echo '== listening sockets'",
    "ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null || cat /proc/net/tcp /proc/net/tcp6 2>&1",
  );
  if (opts.port) {
    const path = opts.healthPath ?? "/";
    const url = `http://127.0.0.1:${opts.port}${path}`;
    lines.push(
      `echo '== GET ${url}'`,
      `curl -sS -m 3 -o /dev/null -w 'HTTP %{http_code}' '${url}' 2>&1 || wget -q -T 3 -S -O /dev/null '${url}' 2>&1 || echo '(no answer from curl or wget)'`,
      "echo",
    );
  }
  const wd = opts.parts?.workdir;
  if (wd) {
    lines.push(
      `echo '== ${wd}'`,
      `ls -la '${wd}' 2>&1 | head -n 40`,
      `echo '== ${wd}/package.json'`,
      `head -c 1500 '${wd}/package.json' 2>/dev/null || echo 'none'`,
    );
  }
  return lines.join("; ");
}

/** The app in the foreground for `secs`, output and exit code on stdout. */
export function foregroundScript(parts: StartCommandParts, secs = 15): string {
  const quoted = parts.foreground.replace(/'/g, `'"'"'`);
  return `echo '== ${quoted.length > 200 ? "start_command" : quoted} (foreground, ${secs}s)'; timeout ${secs} sh -c '${quoted}' 2>&1; echo "exit=$?"`;
}

/** What an exec refusal means for a pool that cannot hold a VM. */
/** The pool fields app-lb reports about its boot-failure backoff. */
export interface BackoffState {
  boot_failures?: number;
  boot_backoff_secs?: number | null;
}

function minutes(secs: number): string {
  return secs < 90 ? `${Math.round(secs)}s` : `${Math.round(secs / 60)} min`;
}

/**
 * The autoscaler holding off after failed boots. app-lb doubles the wait from
 * 30 seconds to an hour; any spec write builds a fresh deployment and clears
 * it. Without saying so, a held-off pool reads as `pending: 0, ready: 0` with
 * nothing booting — which an agent on us5 reported as a platform-wide outage.
 */
export function backoffFinding(pool: BackoffState | undefined): Finding | undefined {
  const wait = pool?.boot_backoff_secs;
  if (typeof wait !== "number" || wait <= 0) return undefined;
  return {
    severity: "warning",
    title: "Boot backoff — no VM is booting by design",
    detail:
      `${pool?.boot_failures ?? "Several"} boots in a row failed their health check, so app-lb ` +
      `waits ${minutes(wait)} before creating the next VM. Nothing is wrong with the platform ` +
      "because of this. Any spec write clears it at once — applb_scale with the current values " +
      "is enough — and the write that ships your fix does too.",
  };
}

export function noVmFinding(error: string, pool?: BackoffState): Finding | undefined {
  if (!/has no VM|no running VM|none became available|cold-start|cold start/.test(error)) return undefined;
  const held = typeof pool?.boot_backoff_secs === "number" && pool.boot_backoff_secs > 0;
  return {
    severity: "warning",
    title: "No VM to probe right now",
    detail:
      (held
        ? `The pool is in its boot-failure backoff (next VM in ${minutes(pool!.boot_backoff_secs!)}). `
        : "A pool whose VMs keep failing their health check backs off creating new ones, " +
          "doubling from 30 seconds up to an hour, so there may be none to probe. ") +
      "To get one now, make any spec write — applb_scale with the current values clears the " +
      "backoff and boots a VM at once — then call this again while it boots. The spec lint " +
      "above still applies.",
  };
}

/**
 * VM deployments that have a VM in their pool — every pool VM passed its
 * health check to get there — out of whatever `/metrics` returned.
 *
 * The caller passes the `/metrics` it read with its own credential, which
 * app-lb narrows to the deployments that credential may view (and the
 * managed door pins to its namespace), so this never names a deployment the
 * caller could not already see. It deliberately takes no wider view.
 */
export function healthyPeers(metrics: unknown, exceptId: string): string[] {
  const deps = (metrics as { deployments?: Array<Record<string, unknown>> } | undefined)?.deployments ?? [];
  return deps
    .filter((d) => d.id !== exceptId && d.kind === "vm")
    .filter((d) => {
      const pool = d.pool as { ready?: number; draining?: number } | undefined;
      return (pool?.ready ?? 0) - (pool?.draining ?? 0) > 0;
    })
    .map((d) => String(d.id));
}

/**
 * Other VMs booting fine is the fastest way to rule out the platform: the
 * same host, daemon and network boot them, so a failure that spares them is
 * in this deployment's image, spec or code.
 */
export function peerFinding(peers: string[]): Finding | undefined {
  if (peers.length === 0) return undefined;
  const shown = peers.slice(0, 5).join(", ") + (peers.length > 5 ? `, +${peers.length - 5} more` : "");
  return {
    severity: "warning",
    title: "Other VM deployments are healthy",
    detail:
      `${shown} ${peers.length === 1 ? "has" : "have"} VMs that passed their health check, among ` +
      "the deployments you can see. The platform boots VMs; look at this deployment's " +
      "start_command, image and app before concluding otherwise.",
  };
}

/** Known failure signatures in guest output, turned into what to change. */
export function interpret(output: string, port?: number): Finding[] {
  const out: Finding[] = [];
  const has = (re: RegExp) => re.test(output);
  if (has(/require is not defined in ES module scope|ERR_REQUIRE_ESM|Cannot use import statement outside a module/)) {
    out.push({
      severity: "error",
      title: "Node module-type mismatch — the app crashes on load",
      detail:
        "The entry file's syntax does not match package.json `type`. CommonJS (`require`) " +
        "under `\"type\": \"module\"`: remove `\"type\": \"module\"` from package.json, or " +
        "rename the file to .cjs and start `node server.cjs`, or convert it to `import`. " +
        "The reverse (`import` without `type: module`): add `\"type\": \"module\"` or use .mjs. " +
        "Then commit and redeploy.",
    });
  }
  if (has(/Cannot find module|MODULE_NOT_FOUND|ModuleNotFoundError|No module named/)) {
    out.push({
      severity: "error",
      title: "A module is missing from the image",
      detail:
        "The Dockerfile did not install a dependency, or the start command runs a file the " +
        "build never produced (e.g. dist/ without a build step). Fix the Dockerfile and redeploy.",
    });
  }
  if (has(/EADDRINUSE/)) {
    out.push({
      severity: "error",
      title: "Port already in use",
      detail: "Another process holds the port — often a second start of the same app.",
    });
  }
  if (has(/: not found|command not found|No such file or directory/)) {
    out.push({
      severity: "warning",
      title: "Something the start command runs is missing",
      detail: "A binary or path in start_command does not exist in the image.",
    });
  }
  if (has(/SQLITE_CANTOPEN|unable to open database file|EACCES|EROFS/)) {
    out.push({
      severity: "error",
      title: "The app cannot write where it expects to",
      detail: "Create the data directory in the Dockerfile, or point the app at a writable path.",
    });
  }
  if (port && has(/Connection refused|can't connect to remote host|Failed to connect/)) {
    out.push({
      severity: "error",
      title: `Nothing is listening on :${port}`,
      detail:
        "The app is not running in the guest — it crashed on start or never started. Its own " +
        "output (above, or with foreground: true) says why.",
    });
  }
  if (port && (has(new RegExp(`127\\.0\\.0\\.1:${port}\\b`)) || has(new RegExp(`localhost:${port}\\b`)))
    && !has(new RegExp(`(0\\.0\\.0\\.0|\\*|::|\\[::\\]):${port}\\b`))) {
    out.push({
      severity: "error",
      title: "Listening on loopback only",
      detail: `The app is on 127.0.0.1:${port}; app-lb checks the guest address. Bind 0.0.0.0.`,
    });
  }
  return out;
}
