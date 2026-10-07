#!/usr/bin/env python3
"""Host-side pooler-only replacement, invoked by an app-lb managed update job."""
import base64
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

LIMIT = 256 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, data, mode=0o600):
    path = Path(path)
    metadata = path.stat() if path.exists() else None
    fd, name = tempfile.mkstemp(prefix=".pooler-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            if metadata is not None:
                os.fchown(out.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(out.fileno(), mode)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        Path(name).unlink(missing_ok=True)


def executable(archive, revision):
    require(len(archive) <= LIMIT, "artifact too large")
    wanted = {"dist/pg-vm-pool", "dist/BUILD-INFO", "dist/SHA256SUMS"}
    found = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r|gz") as tar:
        for member in tar:
            total += member.size
            require(total <= LIMIT, "expanded artifact too large")
            require(not member.name.startswith("/") and ".." not in member.name.split("/"), "unsafe artifact path")
            require(member.isfile() or member.isdir(), "artifact links are forbidden")
            if member.name in wanted:
                require(member.name not in found and member.isfile(), "ambiguous artifact")
                if member.name != "dist/pg-vm-pool":
                    require(member.size <= 65536, "oversized metadata")
                found[member.name] = tar.extractfile(member).read()
    require(found.keys() == wanted, "missing artifact identity")
    commits = [line for line in found["dist/BUILD-INFO"].decode().splitlines() if line.startswith("commit ")]
    require(commits == ["commit " + revision], "artifact revision differs")
    binary = found["dist/pg-vm-pool"]
    require(binary.startswith(b"\x7fELF"), "pooler must be a Linux ELF executable")
    sums = found["dist/SHA256SUMS"].decode().splitlines()
    for name in ("pg-vm-pool", "BUILD-INFO"):
        entries = [line for line in sums if line.split()[1:] == [name]]
        require(entries == [sha(found["dist/" + name]) + "  " + name], "artifact checksum differs")
    return binary


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def download(request):
    url = request["artifact_url"]
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment, "artifact requires credential-free HTTPS URL")
    headers = {}
    if os.environ.get("ART_API_KEY"):
        headers["Authorization"] = "Bearer " + os.environ["ART_API_KEY"]
    with urllib.request.build_opener(NoRedirect()).open(urllib.request.Request(url, headers=headers), timeout=120) as response:
        data = response.read(LIMIT + 1)
    require(len(data) <= LIMIT and sha(data) == request["artifact_sha256"], "artifact digest differs")
    return executable(data, request["revision"])


def command(argv, timeout=45, env=None):
    result = subprocess.run(argv, cwd="/", stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, env=env)
    # Child output may contain connection credentials; never copy it to CI logs.
    require(result.returncode == 0, "pooler process/probe command failed")
    return result.stdout.decode().strip()


def sql_environment(value, port, tls_server_name=None):
    url = urllib.parse.urlsplit(value)
    require(url.scheme in ("postgres", "postgresql") and url.hostname and url.username
            and url.path.startswith("/") and len(url.path) > 1, "SQL probe requires a database URL")
    options = urllib.parse.parse_qs(url.query, strict_parsing=True)
    allowed = {"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY",
               "application_name": "PGAPPNAME"}
    require(all(key in allowed and len(values) == 1 for key, values in options.items()), "unsupported SQL URL options")
    # Never pass a credential-bearing URL in argv or inherit a service/host
    # override which would accidentally probe a different pooler.
    env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
    env.update({"PGHOST": tls_server_name or url.hostname, "PGHOSTADDR": "127.0.0.1", "PGPORT": str(port),
                "PGDATABASE": urllib.parse.unquote(url.path[1:]), "PGUSER": urllib.parse.unquote(url.username),
                "PGPASSWORD": urllib.parse.unquote(url.password or ""), "PGCONNECT_TIMEOUT": "3",
                "PGOPTIONS": "-c default_transaction_read_only=on -c statement_timeout=3000"})
    env.update({allowed[key]: values[0] for key, values in options.items()})
    return env


class Pooler:
    def __init__(self, config):
        self.config = config
        self.binary = Path(config["executable"])
        require(self.binary.name == "pg-vm-pool" and self.binary.is_absolute()
                and self.binary.is_file() and not self.binary.is_symlink(), "invalid installed pooler executable")
        manager = config["manager"]
        service = config["service"]
        require(manager in ("systemd", "supervisor") and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]*", service)
                and service != "all", "invalid exact service mapping")
        self.ctl = "/usr/bin/systemctl" if manager == "systemd" else "/usr/bin/supervisorctl"
        require(config["config_files"] and 0 < len(config["sql_url_envs"]) <= 16, "configuration files and SQL probes are required")
        require(type(config["port"]) is int and 0 < config["port"] <= 65535, "invalid local pooler port")
        if config.get("tls_server_name"):
            require(re.fullmatch(r"[A-Za-z0-9.-]+", config["tls_server_name"]), "invalid pooler TLS hostname")
        for name in config["sql_url_envs"]:
            require(re.fullmatch(r"[A-Z_][A-Z0-9_]*", name), "invalid credential environment reference")
            sql_environment(os.environ[name], config["port"])

    def pid(self):
        if self.config["manager"] == "systemd":
            return int(command([self.ctl, "show", self.config["service"], "--property=MainPID", "--value"]))
        result = subprocess.run([self.ctl, "pid", self.config["service"]], cwd="/",
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
        value = result.stdout.decode().strip()
        # Supervisor uses NOT_RUNNING (7), with PID 0, after a successful stop.
        require(result.returncode == 0 or (result.returncode == 7 and value == "0"),
                "could not determine pooler PID")
        return int(value)

    def control(self, action):
        command([self.ctl, action, self.config["service"]])

    def fingerprint(self):
        return {path: sha(Path(path).read_bytes()) for path in self.config["config_files"]}

    def bindings(self):
        result = {}
        for line in Path(self.config["registry"]).read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            require(len(parts) >= 2 and parts[0] not in result, "invalid registry")
            result[parts[0]] = parts[1]
        require(result, "refusing an empty registry")
        return result

    def verify(self, digest, config, bindings):
        require(self.fingerprint() == config, "service configuration changed")
        current = self.bindings()
        require(all(current.get(key) == value for key, value in bindings.items()), "database VM binding changed")
        pid = self.pid()
        require(pid > 0 and sha(Path(f"/proc/{pid}/exe").read_bytes()) == digest, "running pooler digest differs")
        # Validate only the state-path metadata; credentials are neither used
        # nor logged from the running service's environment.
        metadata = dict(item.split(b"=", 1) for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
                        if item.startswith((b"PG_VM_POOL_STATE_FILE=", b"HOME=")))
        state = Path(os.fsdecode(metadata.get(b"PG_VM_POOL_STATE_FILE",
                     metadata.get(b"HOME", b".") + b"/.heyo/pg-vm-pool/registry.tsv")))
        if not state.is_absolute():
            state = Path(f"/proc/{pid}/cwd").resolve() / state
        require(state.resolve() == Path(self.config["registry"]).resolve(), "running pooler registry differs")
        for name in self.config["sql_url_envs"]:
            require(command(["/usr/bin/psql", "-XAtw", "-v", "ON_ERROR_STOP=1", "-c", "SELECT 1"], timeout=5,
                            env=sql_environment(os.environ[name], self.config["port"], self.config.get("tls_server_name"))) == "1", "SQL readiness probe did not return 1")

    def wait(self, digest, config, bindings):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                self.verify(digest, config, bindings)
                return
            except (RuntimeError, OSError, subprocess.TimeoutExpired):
                time.sleep(2)
        self.verify(digest, config, bindings)

    def stop(self):
        old = self.pid()
        try:
            self.control("stop")
        except RuntimeError:
            # Supervisor returns nonzero when an already stopped/FATAL service
            # is stopped again. BACKOFF/STARTING are not safe: they may restart.
            require(self.config["manager"] == "supervisor", "pooler stop failed")
            status = subprocess.run([self.ctl, "status", self.config["service"]], cwd="/",
                                    capture_output=True, timeout=45).stdout.decode().split()
            require(len(status) >= 2 and status[0] == self.config["service"]
                    and status[1] in ("STOPPED", "FATAL"), "pooler stop is unresolved")
        require(self.pid() == 0 and not Path(f"/proc/{old}").exists(), "old pooler did not stop")


def replace(pooler, request, candidate, directory):
    """The journal refuses ambiguous replays; it never restores database state."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    journal = directory / "receipt.json"
    identity = sha(json.dumps({"request": request, "target": pooler.config}, sort_keys=True).encode())
    digest = sha(candidate)
    if journal.exists():
        receipt = json.loads(journal.read_text())
        require(receipt["request"] == identity, "operation inputs changed")
        require(receipt["status"] == "succeeded", "previous operation failed or was interrupted; reconcile before retry")
        pooler.verify(digest, receipt["config"], receipt["bindings"])
        return receipt
    old = pooler.binary.read_bytes()
    config, bindings = pooler.fingerprint(), pooler.bindings()
    pooler.verify(sha(old), config, bindings)
    require(sha(candidate) == request["binary_sha256"], "candidate digest differs")
    receipt = {"request": identity, "status": "prepared", "binary_sha256": digest,
               "previous_sha256": sha(old), "config": config, "bindings": bindings}
    atomic(directory / "previous", old, 0o700)
    atomic(directory / "candidate", candidate, 0o700)

    def persist(status):
        receipt["status"] = status
        atomic(journal, json.dumps(receipt, sort_keys=True).encode())

    persist("stopping")
    # A failed/ambiguous stop must not install anything or start a second copy.
    pooler.stop()
    try:
        require(pooler.fingerprint() == config and pooler.bindings() == bindings, "state changed before replacement")
        atomic(pooler.binary, candidate, pooler.binary.stat().st_mode & 0o777)
        persist("starting")
        pooler.control("start")
        pooler.wait(digest, config, bindings)
        persist("succeeded")
    except Exception:
        persist("rolling_back")
        # Stop even a partially started replacement before restoring the binary.
        pooler.stop()
        atomic(pooler.binary, old, pooler.binary.stat().st_mode & 0o777)
        pooler.control("start")
        pooler.wait(sha(old), config, bindings)
        persist("rolled_back")
        raise RuntimeError("replacement failed; previous executable restored and verified") from None
    return receipt


def main(envelope):
    config, request = envelope["target"], envelope["request"]
    require(re.fullmatch(r"[a-f0-9]{64}", request["artifact_sha256"])
            and re.fullmatch(r"[a-f0-9]{40}", request["revision"]), "invalid artifact identity")
    require(re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", request["operation"]), "invalid operation")
    state = Path(config["update_state"])
    require(state.is_absolute(), "update state must be absolute")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state / "replace.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pooler = Pooler(config)
        candidate = download(request)
        if envelope.get("preflight"):
            pooler.verify(sha(pooler.binary.read_bytes()), pooler.fingerprint(), pooler.bindings())
            print("POOLER_PREFLIGHT_OK", flush=True)
            return
        receipt = replace(pooler, request, candidate, state / request["operation"])
        print("POOLER_REPLACEMENT=" + json.dumps({"status": receipt["status"], "binary_sha256": receipt["binary_sha256"],
              "operation": request["operation"]}), flush=True)


if __name__ == "__main__":
    try:
        main(json.loads(base64.b64decode(sys.argv[1])))
    except Exception as error:
        # URLs and child output can contain secrets. Keep errors deliberately bounded.
        reason = str(error) if type(error) is RuntimeError else type(error).__name__
        print("pooler replacement failed: " + reason + "; inspect the protected host receipt", file=sys.stderr)
        sys.exit(1)
