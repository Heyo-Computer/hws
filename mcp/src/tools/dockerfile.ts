/**
 * What a Dockerfile says about starting its app, turned into a `start_command`.
 *
 * A guest's rootfs is a `docker export`, which keeps the files and drops the
 * image config: `CMD`, `ENTRYPOINT`, `ENV` and `WORKDIR` never reach the VM.
 * An agent that wrote an ordinary Dockerfile, deployed it, and gave no
 * `start_command` got a VM in which nothing ever started — a pool that cold
 * starts forever. The Dockerfile already says what to run, so read it.
 */

export interface StartInfo {
  workdir?: string;
  env: [string, string][];
  /** The process, as a shell command line, or undefined if none is declared. */
  command?: string;
  port?: number;
}

/** Joined instruction lines of the final stage, with continuations folded. */
function finalStage(text: string): string[] {
  const lines: string[] = [];
  let cur = "";
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (!cur && (line.trim() === "" || line.trimStart().startsWith("#"))) continue;
    if (line.endsWith("\\")) {
      cur += line.slice(0, -1) + " ";
      continue;
    }
    lines.push((cur + line).trim());
    cur = "";
  }
  if (cur.trim()) lines.push(cur.trim());
  let last = 0;
  lines.forEach((l, i) => {
    if (/^FROM\s/i.test(l)) last = i;
  });
  return lines.slice(last);
}

/** A JSON-array form (`["node", "server.js"]`), or undefined for shell form. */
function execForm(arg: string): string[] | undefined {
  if (!arg.startsWith("[")) return undefined;
  try {
    const v = JSON.parse(arg);
    return Array.isArray(v) && v.every((x) => typeof x === "string") ? v : undefined;
  } catch {
    return undefined;
  }
}

const quote = (s: string) => (/^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

export function readStartInfo(dockerfile: string): StartInfo {
  const info: StartInfo = { env: [] };
  let entrypoint: { exec?: string[]; shell?: string } | undefined;
  let cmd: { exec?: string[]; shell?: string } | undefined;
  for (const line of finalStage(dockerfile)) {
    const m = /^(\w+)\s+(.*)$/s.exec(line);
    if (!m) continue;
    const op = m[1]!.toUpperCase();
    const arg = m[2]!.trim();
    if (op === "WORKDIR") {
      info.workdir = arg.startsWith("/") || !info.workdir ? arg : `${info.workdir.replace(/\/$/, "")}/${arg}`;
    } else if (op === "ENV") {
      // `ENV K=V K2="v 2"` or the legacy `ENV K V`.
      const pairs = [...arg.matchAll(/(\w+)=("(?:[^"\\]|\\.)*"|'[^']*'|\S+)/g)];
      if (pairs.length > 0) {
        for (const p of pairs) info.env.push([p[1]!, p[2]!.replace(/^["']|["']$/g, "")]);
      } else {
        const legacy = /^(\w+)\s+(.+)$/.exec(arg);
        if (legacy) info.env.push([legacy[1]!, legacy[2]!]);
      }
    } else if (op === "EXPOSE") {
      const port = Number(arg.split(/\s+/)[0]?.split("/")[0]);
      if (info.port === undefined && Number.isInteger(port) && port > 0) info.port = port;
    } else if (op === "CMD" || op === "ENTRYPOINT") {
      const exec = execForm(arg);
      const v = exec ? { exec } : { shell: arg };
      if (op === "CMD") cmd = v;
      else {
        entrypoint = v;
        cmd = undefined; // ENTRYPOINT resets an earlier CMD
      }
    }
  }
  const words = (v?: { exec?: string[]; shell?: string }) =>
    v?.exec ? v.exec.map(quote).join(" ") : v?.shell;
  if (entrypoint?.shell) info.command = entrypoint.shell; // shell-form ENTRYPOINT ignores CMD
  else if (entrypoint?.exec) info.command = [words(entrypoint), cmd?.exec ? words(cmd) : undefined].filter(Boolean).join(" ");
  else info.command = words(cmd);
  return info;
}

/**
 * A `start_command` that recreates what the image config would have done,
 * backgrounded so it returns, logging to /var/log/app.log.
 */
export function startCommand(info: StartInfo): string | undefined {
  if (!info.command) return undefined;
  const parts: string[] = [];
  if (info.workdir) parts.push(`cd ${quote(info.workdir)}`);
  for (const [k, v] of info.env) {
    // Keep `$` expansions (ENV PATH=/app/bin:$PATH) working.
    parts.push(`export ${k}=${v.includes("$") ? `"${v.replace(/"/g, '\\"')}"` : quote(v)}`);
  }
  parts.push(`setsid nohup ${info.command} </dev/null >/var/log/app.log 2>&1 &`);
  // The trailing `&` backgrounds the whole list, so it returns at once and
  // the `cd` and exports apply to the app.
  return parts.join(" && ");
}
