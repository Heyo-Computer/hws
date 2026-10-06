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
    "ps -eo pid,args 2>/dev/null || ps 2>&1",
    "echo '== listening sockets'",
    "ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null || cat /proc/net/tcp /proc/net/tcp6 2>&1",
  );
  if (opts.port) {
    const path = opts.healthPath ?? "/";
    const url = `http://127.0.0.1:${opts.port}${path}`;
    lines.push(
      `echo '== GET ${url}'`,
      `curl -sS -m 3 -o /dev/null -w 'HTTP %{http_code}' '${url}' 2>&1 || wget -q -T 3 -S -O /dev/null '${url}' 2>&1 || echo 'no curl or wget in the image'`,
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
