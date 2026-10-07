import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import replace_pooler as installer
from rollout_poolers import Host, rollout


OLD = b"\x7fELFold executable"
NEW = b"\x7fELFnew executable"
REVISION = "a" * 40


def bundle(duplicate=False, wrong_checksum=False):
    out = io.BytesIO()
    stamp = ("commit " + REVISION + "\n").encode()
    sums = (installer.sha(OLD if wrong_checksum else NEW) + "  pg-vm-pool\n"
            + installer.sha(stamp) + "  BUILD-INFO\n").encode()
    files = [("pg-vm-pool", NEW), ("BUILD-INFO", stamp), ("SHA256SUMS", sums)]
    if duplicate:
        files.append(("pg-vm-pool", NEW))
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, data in files:
            member = tarfile.TarInfo("dist/" + name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return out.getvalue()


class FakePooler:
    def __init__(self, root):
        self.binary = root / "pg-vm-pool"
        self.binary.write_bytes(OLD)
        self.config = {"service": "pooler"}
        self.running = OLD
        self.events = []
        self.fail_new = False
        self.fail_stop = False
        self.mapping = {"auth": "sb-one", "ci": "sb-two"}

    def fingerprint(self):
        return {"config": "unchanged"}

    def bindings(self):
        return dict(self.mapping)

    def pid(self):
        return 123 if self.running else 0

    def stop(self):
        self.events.append("stop")
        if self.fail_stop:
            raise RuntimeError("stop uncertain")
        self.running = None

    def control(self, action):
        assert action == "start"
        assert self.running is None, "never overlap poolers"
        self.running = self.binary.read_bytes()
        self.events.append("start-new" if self.running == NEW else "start-old")

    def verify(self, digest, config, bindings):
        installer.require(self.running is not None and installer.sha(self.running) == digest, "wrong process")
        installer.require(config == self.fingerprint() and bindings == self.bindings(), "state drift")
        installer.require(not (self.fail_new and self.running == NEW), "new SQL probe failed")

    wait = verify


class ReplacementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pooler = FakePooler(self.root)
        self.directory = self.root / "operation"
        self.request = {"revision": REVISION, "binary_sha256": installer.sha(NEW)}

    def replace(self):
        return installer.replace(self.pooler, self.request, NEW, self.directory)

    def test_exact_artifact_and_provenance(self):
        self.assertEqual(installer.executable(bundle(), REVISION), NEW)
        for data, rev in [(bundle(True), REVISION), (bundle(wrong_checksum=True), REVISION), (bundle(), "b" * 40)]:
            with self.assertRaises(RuntimeError):
                installer.executable(data, rev)

    def test_replace_preserves_bindings_and_replay_does_not_restart(self):
        self.assertEqual(self.replace()["status"], "succeeded")
        self.assertEqual(self.pooler.events, ["stop", "start-new"])
        self.assertEqual((self.directory / "previous").read_bytes(), OLD)
        self.assertEqual(self.pooler.bindings(), {"auth": "sb-one", "ci": "sb-two"})
        self.assertEqual(self.replace()["status"], "succeeded")
        self.assertEqual(self.pooler.events, ["stop", "start-new"])
        self.pooler.config["service"] = "different"
        with self.assertRaisesRegex(RuntimeError, "inputs changed"):
            self.replace()

    def test_unhealthy_candidate_rolls_back_and_still_fails_release(self):
        self.pooler.fail_new = True
        with self.assertRaisesRegex(RuntimeError, "previous executable restored"):
            self.replace()
        self.assertEqual(self.pooler.events, ["stop", "start-new", "stop", "start-old"])
        self.assertEqual(self.pooler.binary.read_bytes(), OLD)
        self.assertEqual(json.loads((self.directory / "receipt.json").read_text())["status"], "rolled_back")
        with self.assertRaisesRegex(RuntimeError, "reconcile"):
            self.replace()
        self.assertEqual(len(self.pooler.events), 4)

    def test_ambiguous_stop_never_installs_or_starts(self):
        self.pooler.fail_stop = True
        with self.assertRaisesRegex(RuntimeError, "stop uncertain"):
            self.replace()
        self.assertEqual(self.pooler.binary.read_bytes(), OLD)
        with self.assertRaisesRegex(RuntimeError, "reconcile"):
            self.replace()
        self.assertEqual(self.pooler.events, ["stop"])

    def test_corrupt_candidate_never_stops_service(self):
        self.request["binary_sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "candidate digest differs"):
            self.replace()
        self.assertEqual(self.pooler.events, [])

    def test_changed_binding_is_not_restored_from_receipt(self):
        self.replace()
        self.pooler.mapping["ci"] = "sb-other"
        with self.assertRaisesRegex(RuntimeError, "state drift"):
            self.replace()
        self.assertEqual(self.pooler.mapping["ci"], "sb-other")

    def test_supervisor_stopped_pid_is_not_a_command_failure(self):
        pooler = object.__new__(installer.Pooler)
        pooler.config = {"manager": "supervisor", "service": "pooler"}
        pooler.ctl = "/usr/bin/supervisorctl"
        for code, output, expected in [(0, b"123\n", 123), (7, b"0\n", 0),
                                       (7, b"123\n", None), (4, b"0\n", None)]:
            result = installer.subprocess.CompletedProcess([], code, stdout=output)
            with patch.object(installer.subprocess, "run", return_value=result):
                if expected is None:
                    with self.assertRaisesRegex(RuntimeError, "determine pooler PID"):
                        pooler.pid()
                else:
                    self.assertEqual(pooler.pid(), expected)

    def test_sql_probe_forces_local_pooler_and_decodes_credentials_without_argv(self):
        with patch.dict(os.environ, {"PGSERVICE": "wrong-service", "PGHOSTADDR": "203.0.113.1"}):
            env = installer.sql_environment("postgresql://reader:encoded%40value@pg.example/db%2Dname?sslmode=verify-full&application_name=pooler%20probe", 6432)
        self.assertEqual(env["PGHOSTADDR"], "127.0.0.1")
        self.assertEqual(env["PGPORT"], "6432")
        self.assertEqual(env["PGHOST"], "pg.example")
        self.assertEqual(env["PGDATABASE"], "db-name")
        self.assertEqual(env["PGPASSWORD"], "encoded@value")
        self.assertEqual(env["PGSSLMODE"], "verify-full")
        self.assertEqual(env["PGAPPNAME"], "pooler probe")
        self.assertNotIn("PGSERVICE", env)
        self.assertIn("default_transaction_read_only=on", env["PGOPTIONS"])
        regional = installer.sql_environment("postgresql://reader@writer.example/db?sslmode=verify-full", 6432, "replica.example")
        self.assertEqual(regional["PGHOST"], "replica.example")
        self.assertEqual(regional["PGHOSTADDR"], "127.0.0.1")
        self.assertEqual(regional["PGSSLMODE"], "verify-full")
        with self.assertRaises(RuntimeError):
            installer.sql_environment("postgresql://reader@pg.example/db?hostaddr=203.0.113.2", 6432)
        with self.assertRaises(RuntimeError):
            installer.sql_environment("postgresql://reader@pg.example/db?application_name=one&application_name=two", 6432)

    def test_managed_job_receipt_and_replay(self):
        host = object.__new__(Host)
        host.target = {"pooler": {}, "namespace": "default", "env_from": []}
        records = {"spec": None, "jobs": [], "starts": 0}
        request = {"operation": "test-operation", "binary_sha256": "b" * 64}

        def call(path, body=None):
            if path == "/deployments":
                records["spec"] = body
                return body
            if path.endswith("/jobs"):
                return records["jobs"]
            if path.endswith("/update"):
                records["starts"] += 1
                records["jobs"] = [{"deployment": records["spec"]["id"], "kind": "host-update", "status": "succeeded",
                                    "log": ["POOLER_REPLACEMENT=" + json.dumps({"status": "succeeded", **request})]}]
                return records["jobs"][0]
            if records["spec"] is None:
                raise urllib.error.HTTPError("https://admin.example", 403, "not accessible", {}, None)
            return {"spec": records["spec"]}

        host.call = call
        host.run(request, False)
        host.run(request, False)
        self.assertEqual(records["starts"], 1)
        records["jobs"][0]["log"] = ['POOLER_REPLACEMENT={"status":"succeeded","operation":"wrong","binary_sha256":"wrong"}']
        with self.assertRaisesRegex(RuntimeError, "receipt differs"):
            host.run(request, False)

    def test_regional_order_and_failure_stop(self):
        events = []

        class Host:
            def __init__(self, name, failure=None):
                self.target = {"name": name}
                self.failure = failure

            def run(self, request, preflight):
                events.append((self.target["name"], preflight))
                if self.failure == preflight:
                    raise RuntimeError("failed")

        rollout([Host("first"), Host("second")], {})
        self.assertEqual(events, [("first", True), ("second", True), ("first", False), ("second", False)])
        events.clear()
        with self.assertRaises(RuntimeError):
            rollout([Host("first", False), Host("second")], {})
        self.assertEqual(events, [("first", True), ("second", True), ("first", False)])
        events.clear()
        with self.assertRaises(RuntimeError):
            rollout([Host("first"), Host("second", True)], {})
        self.assertEqual(events, [("first", True), ("second", True)])


if __name__ == "__main__":
    unittest.main()
