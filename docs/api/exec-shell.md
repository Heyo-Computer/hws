# Exec and shell

These two endpoints run commands inside a deployment's VM: `exec` runs one command and returns its output, and `shell` opens an interactive terminal over a WebSocket.

Back to the [API reference](overview.md).

Both are CRUD tier and work on VM deployments only; static deployments and sites answer `400`. They are the only way into a deployment with no routes.

## Exec

`POST /deployments/:id/exec`

**Crate:** `Client::exec(id, &ExecRequest) -> ExecOutput`

| Field | Default | Meaning |
| --- | --- | --- |
| `command` | required | Run through `sh -c` in the guest. Must not be blank; the crate refuses a blank command with `Error::Invalid` before sending. |
| `cwd` | guest default | Working directory. |
| `env` | none | Object of extra environment variables. |
| `timeout_secs` | `60` | Clamped to 1–3600. Bounds app-lb's call to the daemon. **It does not kill the command.** |
| `wake` | `true` | Boot or resume a VM if none is running, waiting up to `cold_start_timeout_secs`. With `false`, no running VM is a `409`. |
| `sandbox_id` | pool's choice | Run in this VM. Not in the deployment: `404`. Not started or draining: `409`. A named VM is never woken. The crate's `ExecRequest` does not set this field. |

```rust
use hws::ExecRequest;

let out = lb.exec("demo", &ExecRequest::new("ls /nope; ls /")
    .cwd("/")
    .env("RUST_LOG", "debug")
    .timeout_secs(30)).await?;
if !out.ok() {
    eprintln!("exit {}: {}", out.exit_code, out.stderr);
}
```

```json
{
  "sandbox_id": "applb-sandbox-a1b2c3",
  "exit_code": 1,
  "stdout": "total 0\n",
  "stderr": "ls: cannot access '/nope': No such file or directory\n",
  "output": "total 0\nls: cannot access '/nope': No such file or directory\n"
}
```

| Field | Meaning |
| --- | --- |
| `sandbox_id` | The VM that ran it. After a resume or rebuild this is a different VM than last time. |
| `exit_code` | The command's exit status. `ExecOutput::ok()` is `exit_code == 0`. |
| `stdout`, `stderr` | Each stream on its own. |
| `output` | Both streams interleaved in the order the guest wrote them. |

A command that fails is still `200`, and the crate returns it as `Ok`. Output is buffered until the command exits; there is no streaming and no cancel. If no VM has passed its health check yet, the command runs in one that is still booting. An open `exec` counts as in-flight work, so the VM is not reaped under it.

| Status | `hws::Error` | When |
| --- | --- | --- |
| `400` | `Api` | Not a VM deployment, or an empty command. |
| `404` | `NotFound` | No such deployment, or `sandbox_id` is not in it. |
| `409` | `NoRunningVm` | `wake: false` and nothing is running. |
| `409` | `Conflict` | The named VM is not ready or is draining, or the deployment is frozen for retirement. |
| `502` | `Upstream` | The daemon could not run the command, **or app-lb's call timed out**. On a timeout the command is still running in the guest. |
| `503` | `ColdStartTimeout` | No VM became ready within `cold_start_timeout_secs`. Retryable. |

### Client deadline

The crate sets its own deadline on an `exec` request so that it never gives up before app-lb does. `ExecRequest::patience()` is `timeout_secs` (default 60, clamped to 1–3600), plus 120 seconds when `wake` is set (app-lb's default `cold_start_timeout_secs`), plus a 15-second margin. A deployment configured with a longer cold start needs `.patient_for(d)`.

## Shell

`GET /deployments/:id/shell` (WebSocket upgrade)

**Crate:** `Client::shell(id, &ShellOptions) -> Shell`

Opens an interactive PTY. The crate builds `ws://` or `wss://` from the client's base URL and authenticates the upgrade with the same `Authorization` header as every other request. A browser cannot set headers on a WebSocket, so app-lb also accepts `?app_token=applb_…` on this route only. Query strings end up in logs, so mint a short-lived token for that.

| Query | Default | Meaning | `ShellOptions` |
| --- | --- | --- | --- |
| `cols`, `rows` | `80`, `24` | Initial terminal size. | `.size(cols, rows)` |
| `cwd` | guest default | Working directory. | `.cwd(path)` |
| `wake` | `true` | As for `exec`. | `.no_wake()` |
| `sandbox_id` | pool's choice | As for `exec`. | `.vm(sandbox_id)` |
| `app_token` | | App-token for clients that cannot set headers. | not used |

Every refusal (`404`, `409`, `502`, `503`) is an ordinary HTTP response before the upgrade, and the crate maps it as it would for `exec`. Once the socket is open, the framing is:

| Direction | Frame | Content |
| --- | --- | --- |
| server → client | text | `{"type":"ready","sandbox_id":"…"}`, sent once, first. |
| client → server | binary | `0x01` followed by stdin bytes. |
| client → server | text | `{"type":"resize","cols":N,"rows":N}` |
| server → client | binary | `0x02` followed by output bytes. The PTY merges stderr into stdout. |
| server → client | text | `{"type":"exit","code":N}`, then the server closes. |
| server → client | text | `{"type":"error","message":"…"}` |

Client binary frames that do not start with `0x01` are dropped.

```rust
use hws::{ShellEvent, ShellOptions};

let mut sh = lb.shell("demo", &ShellOptions::default().size(120, 40)).await?;
println!("connected to {}", sh.sandbox_id());
sh.write(b"uname -a\nexit\n").await?;
while let Some(ev) = sh.next().await {
    match ev {
        ShellEvent::Output(bytes) => print!("{}", String::from_utf8_lossy(&bytes)),
        ShellEvent::Error(msg) => eprintln!("error: {msg}"),
    }
}
let exit = sh.exit().cloned();
```

`Shell::write` frames stdin, `Shell::resize` sends a resize, and `Shell::next` yields output and errors until the session ends. `Shell::exit()` then returns a `ShellExit { code, error }`, and `ShellExit::is_clean()` is true only when the code is `0` and no error was reported.

app-lb reports an unknown exit status as `0`, which is also what a VM dying under the session looks like, so treat an `error` before the `exit` as unclean. There is no resume: if the socket drops, the session is gone, and reconnecting opens a new shell.
