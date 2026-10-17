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

## Background operations

`exec` holds the request, and the guest's only console, until the command ends. For anything longer than about 30 seconds, start it as an operation instead: it runs detached in its own session, and you look at it with short requests while it runs. Several operations can run on one VM at once.

| Route | Does |
| --- | --- |
| `POST /deployments/:id/operations` | `{command, cwd?, env?, max_runtime_secs? (default 3600, max 21600), wake?, sandbox_id?}`. Starts the command and returns `201` with the record (`id: "op_…"`, `state: "running"`, `sandbox_id`). At most 16 running per deployment (`429` past that). |
| `GET /deployments/:id/operations` | `{operations: [...]}`, newest first, without output. |
| `GET /deployments/:id/operations/:op?offset=&max_bytes=&tail=` | The record, refreshed from the guest, plus `output: {offset, bytes, next_offset, total_bytes, encoding, data}`. Pages are 64 KiB by default, at most 256 KiB; `tail=true` pages the last `max_bytes`. `encoding` is `utf-8`, or `base64` when the bytes are not text. `stale: true` means the guest could not be asked (its console was busy) and this is the last known record. |
| `DELETE /deployments/:id/operations/:op` | Cancel it: SIGTERM to its process group, SIGKILL 10 s later. `202` with `state: "cancelling"`. `?purge=true` instead forgets a finished operation and removes its directory. |

`state` is `running`, `cancelling`, `succeeded`, `failed` (non-zero `exit_code`), `cancelled`, `timed_out` (ran past `max_runtime_secs`), or `lost`. An operation is lost when its VM was restarted, replaced or stopped under it, or when its process ended without recording an exit code.

Each operation lives in one guest directory: `/workspace/.heyo/ops/<id>` when the VM has a data disk, otherwise `/var/tmp/heyo-ops/<id>`. It holds the command (`cmd`), output (`out`, stdout and stderr together), `pid` and `exit`. On `/workspace`, the output survives a stop and can be read again after a start.

While an operation runs, app-lb holds an in-flight slot on its VM. That stops the pool from scaling the VM to zero or reaping it, and the idle clock starts when the last operation ends. A watcher looks at every running operation every 15 seconds and records state changes, so a finished operation shows its final state even if nobody asks. Records persist across an app-lb restart.

## Files

The console is also the only way to a file inside a running guest. heyvmd's own file routes act on host directories the guest never sees.

| Route | Does |
| --- | --- |
| `GET /deployments/:id/files?path=&offset=&length=` | Up to 256 KiB (default 96 KiB) of the file from `offset`: `{sandbox_id, path, size, offset, bytes, next_offset?, encoding, content}`. `404` for a missing file. |
| `PUT /deployments/:id/files?path=&append=` | Write the raw request body (at most 1 MiB) to the file, replacing it or with `append=true` adding to it. Parent directories are created. `{sandbox_id, path, wrote, size}`. |

`path` must be absolute and free of quotes, backslashes and newlines. Both take `wake` and `sandbox_id` like `exec`. The console moves tens of KB/s, which suits configuration, logs and small artifacts; move anything larger with a transfer.

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

## Transfers

Files too large for the console travel through one-time URLs instead. app-lb keeps the bytes on its own disk for a while, and the guest fetches or pushes them with `curl` (or `wget`) at network speed. A transfer needs `APP_LB_TRANSFER_URL` (otherwise `501`). An image with neither `curl` nor `wget` still works up to 8 MiB: app-lb then moves the bytes over the console instead, which takes minutes rather than seconds.

| Route | Does |
| --- | --- |
| `POST /deployments/:id/transfers` | `{direction, path, extract?, strip_components?, ttl_secs? (default 3600, max 21600), max_bytes?, apply_on_upload? (default true), sandbox_id?, wait_secs?}` |
| `PUT /transfers/:token` | Upload. Streamed, capped at `max_bytes` (`413`), hashed. With `apply_on_upload`, the guest fetches and places the bytes before the response, which waits for them. That takes seconds with curl or wget and up to about ten minutes for 8 MiB over the console. `202` with `applying` means it is still going after 15 minutes. |
| `GET /transfers/:token` | Download an outbound transfer, up to three times. |
| `GET /deployments/:id/transfers[/:tid]` | List, or one transfer's state (`awaiting_upload`, `uploaded`, `applying`, `applied`, `collecting`, `ready`, `failed`), size, sha256 and error. URLs appear only in the create response. |
| `POST /deployments/:id/transfers/:tid/apply` | Place an uploaded transfer again, for example after starting a stopped sandbox. |
| `DELETE /deployments/:id/transfers/:tid` | Discard it and its bytes. |

**In:** create with `direction: "in"` and get `upload_url`. `PUT` the bytes there; it takes no credential, since the URL is one. The guest downloads them into a temporary file beside `path` and checks the sha256 when it has `sha256sum`. `extract: "none"` puts the file at `path`. `tar`, `tar.gz` or `auto` (which sniffs gzip) unpacks it into the directory `path`, optionally with `strip_components`.

```sh
curl -sS -XPOST "$LB/deployments/sb-acme/transfers" -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"direction": "in", "path": "/workspace/app", "extract": "auto"}'
curl -sS -T repo.tar.gz "<upload_url>"
```

**Out:** create with `direction: "out"` and `path`, a file or a directory (sent as a tar.gz). The guest pushes it, and the response carries `download_url` once it is stored (`202` with `collecting` if that takes longer than `wait_secs`, default 50).

Every URL is single-purpose and expires with the transfer. An upload URL is spent by one complete upload, and a download URL by three downloads. The guest's own URLs last 10 minutes and reach it through its exec environment, never its command line. Anything not a live token is `404`. Transfer paths are logged as `/transfers/<token>`. At most 8 open transfers per deployment.
