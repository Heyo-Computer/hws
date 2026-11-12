import importlib.util
import io
import json
import os
import pathlib
import stat
import tarfile
import tempfile
import unittest

SOURCE = pathlib.Path(__file__).parents[1] / "src" / "host_heyvm_bootstrap.py"
spec = importlib.util.spec_from_file_location("bootstrap", SOURCE)
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)


def tar(entries, gz=True):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz" if gz else "w") as archive:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name); info.size = len(data)
            if kind == "file": archive.addfile(info, io.BytesIO(data))
            elif kind == "link": info.type = tarfile.SYMTYPE; info.linkname = "heyvm"; archive.addfile(info)
    return out.getvalue()


class Response(io.BytesIO):
    status = 200
    def __enter__(self): return self
    def __exit__(self, *_): pass


class Opener:
    def __init__(self, data, status=200): self.data=data; self.status=status
    def open(self, *_args, **_kwargs): r=Response(self.data); r.status=self.status; return r


class FakeHost(b.Host):
    def __init__(self, target, old, new, fail=None, rollback_fail=False):
        self.target=target; self.old=old; self.new=new; self.current=old; self.pid=10; self.start="1"; self.fail=fail; self.rollback_fail=rollback_fail; self.calls=[]
    def command(self, argv):
        self.calls.append(tuple(argv))
        action = argv[1] if len(argv)>1 else ""
        if self.fail == action: self.fail=None; raise RuntimeError(action)
        if action == "restart":
            disk=pathlib.Path(self.target["executable"]).read_bytes()
            if self.rollback_fail and disk == self.old: self.current=self.new
            else: self.current=disk
            self.pid += 1; self.start=str(int(self.start)+1)
        return "LoadState=loaded\nActiveState=active\nKillMode=process\nMainPID=%s\nExecStart={ path=%s ; argv[]=/misleading/heyvm --serve ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n" % (self.pid,self.target["executable"])
    def boot_id(self): return "boot"
    def starttime(self, _pid): return self.start
    def proc_exe(self, _pid): return os.path.realpath(self.target["executable"])
    def proc_digest(self, _pid): return b.sha(self.current)
    def cgroup_pids(self, _group): return {self.pid}
    def environment_has(self, _pid, _expected):
        if self.fail == "environment": self.fail=None; return False
        return True
    def health(self, _url):
        if self.fail == "health": self.fail=None; raise RuntimeError("health")
        return {"status":"healthy","backendId":self.target["backend_server_id"],"backendRegion":self.target["region"]}


class SupervisorHost(FakeHost):
    def command(self, argv):
        self.calls.append(tuple(argv))
        if argv[:2] == ["supervisorctl", "pid"]: return str(self.pid)
        if argv[:2] == ["supervisorctl", "restart"]:
            if self.fail == "restart": self.fail=None; raise RuntimeError("restart")
            disk=pathlib.Path(self.target["executable"]).read_bytes()
            if self.rollback_fail and disk == self.old: self.current=self.new
            else: self.current=disk
            self.pid += 1; self.start=str(int(self.start)+1); return "restarted"
        raise AssertionError(argv)


class Tests(unittest.TestCase):
    def target(self, root):
        return {"repository":b.REPOSITORY,"app_lb_admin_url":"https://admin.example","app_lb_deployment":"host",
          "app_lb_namespace":"default","runner_hd_id":"runner","backend_server_id":"backend","executable":str(root/"bin/heyvm"),
          "unit":"heyvmd.service","state_dir":str(root/"state"),"config_json_path":str(root/"etc/config.json"),
          "systemd_drop_in_path":str(root/"etc/systemd/heyvmd.service.d/update.conf"),"local_health_url":"http://127.0.0.1:8080/health",
          "target_alias":"eu1","region":"eu1"}
    def req(self, binary=b"\x7fELFnew"):
        return {"operation_id":"op-1","artifact_url":"https://art.example/blob","artifact_sha256":"a"*64,"artifact_size":1,
          "inner_path":"validation/heyvm.tar.gz","inner_archive_sha256":"b"*64,"heyvm_sha256":b.sha(binary)}

    def test_mapping_closed_and_safe(self):
        with tempfile.TemporaryDirectory() as td:
            target=self.target(pathlib.Path(td)); raw=json.dumps({"eu1":target})
            self.assertEqual(b.mapping(raw,"eu1"),target)
            for edit in ({"extra":"x"},{"repository":"public"},{"unit":"heyvmd"},{"executable":"../bad"},{"app_lb_admin_url":"http://admin"},{"local_health_url":"http://example/health"}):
                bad=target.copy(); bad.update(edit)
                with self.assertRaises(ValueError): b.mapping(json.dumps({"eu1":bad}),"eu1")
            with self.assertRaises(ValueError): b.mapping(raw,"unknown")

    def test_download_size_hash_status_and_no_redirect_handler(self):
        req=self.req(); data=b"x"; req.update(artifact_size=1,artifact_sha256=b.sha(data))
        self.assertEqual(b.download(req,Opener(data)),data)
        for payload,status in [(b"xx",200),(b"x",302),(b"y",200)]:
            with self.assertRaises(ValueError): b.download(req,Opener(payload,status))
        self.assertIsNone(b.NoRedirect().redirect_request(None,None,None,None,None,None))

    def test_private_download_authenticates_and_never_follows_redirects(self):
        import http.server
        import threading
        data=b"private release bytes"
        token="7"*64
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302); self.send_header("Location", "/must-not-follow"); self.end_headers(); return
                if self.path == "/must-not-follow":
                    self.server.followed=True
                if self.headers.get("Authorization") != "Bearer "+token:
                    self.send_response(401); self.end_headers(); return
                self.send_response(200); self.end_headers(); self.wfile.write(data)
        server=http.server.HTTPServer(("127.0.0.1",0),Handler); server.followed=False
        thread=threading.Thread(target=server.serve_forever); thread.start()
        try:
            req=self.req(); req.update(artifact_size=len(data),artifact_sha256=b.sha(data),download_token=token)
            self.assertEqual(b.request(req),req)
            req["artifact_url"]=f"http://127.0.0.1:{server.server_port}/blob"
            self.assertEqual(b.download(req),data)
            for wrong in (None,"8"*64):
                bad=req.copy()
                if wrong is None: del bad["download_token"]
                else: bad["download_token"]=wrong
                with self.assertRaises(b.urllib.error.HTTPError) as caught: b.download(bad)
                caught.exception.close()
            req["artifact_url"]=f"http://127.0.0.1:{server.server_port}/redirect"
            with self.assertRaises(b.urllib.error.HTTPError) as caught: b.download(req)
            caught.exception.close()
            self.assertFalse(server.followed)
        finally:
            server.shutdown(); thread.join(); server.server_close()

    def test_service_uses_authoritative_systemd_path_not_argv(self):
        with tempfile.TemporaryDirectory() as td:
            target=self.target(pathlib.Path(td)); exe=pathlib.Path(target["executable"]); exe.parent.mkdir(); exe.write_bytes(b"old")
            host=FakeHost(target,b"old",b"new")
            self.assertEqual(b.service(host,target)["pid"],10)
            host.command=lambda _argv: "LoadState=loaded\nActiveState=active\nKillMode=process\nMainPID=10\nExecStart={ path=/wrong/heyvm ; argv[]=%s ; }\n" % target["executable"]
            with self.assertRaises(ValueError): b.service(host,target)

    def test_legacy_launcher_symlink_is_verified_and_restored_exactly(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); target=self.target(root); old=b"\x7fELFold"; new=b"\x7fELFnew"
            release=root/"releases/old/heyvm"; release.parent.mkdir(parents=True); release.write_bytes(old); release.chmod(0o755)
            exe=pathlib.Path(target["executable"]); exe.parent.mkdir(); exe.symlink_to(release)
            host=FakeHost(target,old,new)
            host.proc_exe=lambda _pid: os.path.realpath(target["executable"])
            self.assertEqual(b.service(host,target)["disk_sha256"],b.sha(old))
            exe.unlink(); exe.write_bytes(new); exe.chmod(0o755); host.current=new
            journal={"service":{"disk_sha256":b.sha(old),"running_sha256":b.sha(old)},"predecessors":{
              "executable":{"present":True,"link_target":str(release)},"config":{"present":False},"drop_in":{"present":False}}}
            b.restore(host,target,journal)
            self.assertTrue(exe.is_symlink()); self.assertEqual(os.readlink(exe),str(release)); self.assertEqual(exe.read_bytes(),old)

    def test_control_group_restart_is_only_allowed_for_an_isolated_daemon(self):
        with tempfile.TemporaryDirectory() as td:
            target=self.target(pathlib.Path(td)); exe=pathlib.Path(target["executable"]); exe.parent.mkdir(); exe.write_bytes(b"old")
            host=FakeHost(target,b"old",b"new"); command=host.command
            host.command=lambda argv: command(argv).replace("KillMode=process", "KillMode=control-group\nControlGroup=/system.slice/heyvmd.service")
            self.assertEqual(b.service(host,target,"heyvmd")["pid"],10)
            with self.assertRaises(ValueError): b.service(host,target,"heyvm")
            for members in ({10,11}, set(), {11}):
                host.cgroup_pids=lambda _group: members
                with self.assertRaises(ValueError): b.service(host,target,"heyvmd")
            self.assertEqual(exe.read_bytes(),b"old")

    def test_service_startup_wait_keeps_strict_isolation(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as td:
            target=self.target(pathlib.Path(td)); exe=pathlib.Path(target["executable"]); exe.parent.mkdir(); exe.write_bytes(b"old")
            host=FakeHost(target,b"old",b"new"); command=host.command
            host.command=lambda argv: command(argv).replace("KillMode=process", "KillMode=control-group")
            with patch.object(host,"cgroup_pids",side_effect=[{10,11},{10}]), patch.object(b.time,"sleep") as sleep:
                self.assertEqual(b.wait_for_service(host,target,"heyvmd")["pid"],10)
                sleep.assert_called_once_with(1)
            with patch.object(host,"cgroup_pids",return_value={10,11}), patch.object(b.time,"monotonic",side_effect=[0,30]), patch.object(b.time,"sleep") as sleep:
                with self.assertRaises(b.ServiceStarting): b.wait_for_service(host,target,"heyvmd")
                sleep.assert_not_called()
            with patch.object(host,"proc_exe",return_value="/wrong/executable"), patch.object(b.time,"sleep") as sleep:
                with self.assertRaisesRegex(ValueError,"executable differs"): b.wait_for_service(host,target,"heyvmd")
                sleep.assert_not_called()

    def test_systemd_executor_must_transition_to_exact_service_before_deadline(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as td:
            target=self.target(pathlib.Path(td)); exe=pathlib.Path(target["executable"]); exe.parent.mkdir(); exe.write_bytes(b"old")
            host=FakeHost(target,b"old",b"new")
            executor="/usr/lib/systemd/systemd-executor"
            with patch.object(host,"proc_exe",side_effect=[executor,os.path.realpath(exe)]), patch.object(b.time,"sleep") as sleep:
                self.assertEqual(b.wait_for_service(host,target,"heyvmd")["running_sha256"],b.sha(b"old"))
                sleep.assert_called_once_with(1)
            with patch.object(host,"proc_exe",return_value=executor), patch.object(b.time,"monotonic",side_effect=[0,30]), patch.object(b.time,"sleep") as sleep:
                with self.assertRaises(b.ServiceStarting): b.wait_for_service(host,target,"heyvmd")
                sleep.assert_not_called()
            with patch.object(host,"proc_exe",side_effect=[executor,"/wrong/executable"]), patch.object(b.time,"sleep") as sleep:
                with self.assertRaisesRegex(ValueError,"executable differs"): b.wait_for_service(host,target,"heyvmd")
                sleep.assert_called_once_with(1)
            command=host.command
            host.command=lambda argv: command(argv).replace("path="+str(exe),"path=/wrong/service")
            with patch.object(host,"proc_exe",return_value=executor), patch.object(b.time,"sleep") as sleep:
                with self.assertRaisesRegex(ValueError,"executable differs"): b.wait_for_service(host,target,"heyvmd")
                sleep.assert_not_called()

    def test_failure_record_captures_check_without_command_secrets(self):
        target = {"unit":"probe.service", "executable":"/usr/bin/probe"}
        host = FakeHost(target, b"old", b"new")
        host.command = lambda _: "LoadState=loaded\nActiveState=active\nKillMode=control-group\nMainPID=10\nControlGroup=/system.slice/probe.service\nExecStart={ path=/usr/bin/probe ; argv[]=/usr/bin/probe --token=SECRET ; }\n"
        host.cgroup_pids = lambda _: {11, 12}
        try:
            b.wait_for_service(host, target, "heyvmd")
            self.fail("expected process-group rejection")
        except ValueError as error:
            record = b.failure_record(error)
        self.assertEqual(record["check"], "service main process is outside its group")
        self.assertEqual(record["service"]["MainPID"], "10")
        self.assertEqual(record["service"]["cgroup_pids"], [11, 12])
        self.assertEqual(record["frames"][-1]["function"], "observe_service")
        self.assertNotIn("SECRET", json.dumps(record))
        self.assertNotIn("argv", json.dumps(record))
        try:
            raise ValueError("response contains SECRET")
        except ValueError as error:
            self.assertNotIn("SECRET", json.dumps(b.failure_record(error)))

    def test_rollback_recovery_is_read_only_and_rejects_drift(self):
        from unittest.mock import patch
        from itertools import product
        for status, drift in product(("rolled_back", "rollback_failed"), (None,"binary","health","journal","request","running")):
            temp,target,host,result,old,new=self.run_install("health")
            try:
                self.assertEqual(result["status"],"rolled_back")
                journal=pathlib.Path(target["state_dir"])/"op-1.json"
                data=json.loads(journal.read_text())
                data["status"]=status; data["result"]["status"]=status
                journal.write_text(json.dumps(data))
                if drift=="binary": pathlib.Path(target["executable"]).write_bytes(new)
                if drift=="running": host.current=new
                if drift=="health": host.health=lambda _: {"status":"healthy","backendId":"other","backendRegion":"eu1"}
                if drift=="journal":
                    data=json.loads(journal.read_text()); data["result"]["operation_id"]="other"; journal.write_text(json.dumps(data))
                if drift=="request":
                    data=json.loads(journal.read_text()); data["request_sha256"]="other"; journal.write_text(json.dumps(data))
                before=journal.read_bytes(); host.calls.clear()
                def snapshot(path,limit,**options):
                    p=pathlib.Path(path)
                    if not p.exists(): return {"present":False}
                    return {"present":True,"mode":stat.S_IMODE(p.stat().st_mode),"bytes":__import__('base64').b64encode(p.read_bytes()).decode()}
                with patch.object(b,"secure_file",snapshot), patch.object(b,"atomic",side_effect=AssertionError("write")), patch.object(b,"download",side_effect=AssertionError("download")):
                    if drift:
                        with self.assertRaises(ValueError): b.verify_existing(target,self.req(new),host)
                    else: self.assertEqual(b.verify_existing(target,self.req(new),host),result)
                self.assertEqual(journal.read_bytes(),before)
                self.assertTrue(all(call[:2]==("systemctl","show") for call in host.calls))
            finally: temp.cleanup()

    def test_archives_reject_traversal_links_ambiguity_and_hashes(self):
        binary=b"\x7fELFpayload"; inner=tar([("heyvm",binary,"file")]); outer=tar([("validation/heyvm.tar.gz",inner,"file")],False)
        req=self.req(binary); req.update(artifact_size=len(outer),artifact_sha256=b.sha(outer),inner_archive_sha256=b.sha(inner))
        self.assertEqual(b.executable(outer,req),binary)
        cases=[tar([("../escape",b"x","file"),("validation/heyvm.tar.gz",inner,"file")],False),
               tar([("validation/heyvm.tar.gz",b"","link")],False),
               tar([("validation/heyvm.tar.gz",inner,"file"),("validation/heyvm.tar.gz",inner,"file")],False)]
        for value in cases:
            with self.assertRaises(ValueError): b.executable(value,req)
        linked=tar([("heyvm",b"","link")]); out=tar([("validation/heyvm.tar.gz",linked,"file")],False); bad=req.copy(); bad["inner_archive_sha256"]=b.sha(linked)
        with self.assertRaises(ValueError): b.executable(out,bad)

    def test_heyvmd_member_is_selected_exactly_and_corruption_precedes_side_effects(self):
        daemon=b"\x7fELFdaemon"; cli=b"\x7fELFcli"; inner=tar([("heyvm",cli,"file"),("heyvmd",daemon,"file")]); outer=tar([("validation/heyvm.tar.gz",inner,"file")],False)
        req=self.req(daemon); req.update(component="heyvmd",artifact_size=len(outer),artifact_sha256=b.sha(outer),inner_archive_sha256=b.sha(inner))
        self.assertEqual(b.executable(outer,req),daemon)
        for corrupt in (tar([("heyvm",cli,"file")]), tar([("heyvmd",daemon,"file"),("heyvmd",daemon,"file")])):
            badouter=tar([("validation/heyvm.tar.gz",corrupt,"file")],False); bad=req.copy(); bad["inner_archive_sha256"]=b.sha(corrupt)
            with self.assertRaises(ValueError): b.executable(badouter,bad)

    def run_install(self, fail=None, rollback_fail=False):
        temp=tempfile.TemporaryDirectory(); root=pathlib.Path(temp.name); target=self.target(root)
        old=b"\x7fELFold"; new=b"\x7fELFnew"; exe=pathlib.Path(target["executable"]); exe.parent.mkdir(); exe.write_bytes(old); exe.chmod(0o755)
        original=b.secure_file
        def test_secure(path,limit,**_options):
            p=pathlib.Path(path)
            if not p.exists(): return {"present":False}
            return {"present":True,"mode":stat.S_IMODE(p.stat().st_mode),"bytes":__import__('base64').b64encode(p.read_bytes()).decode()}
        b.secure_file=test_secure
        original_regular=b.exact_regular; b.exact_regular=lambda path,mode: stat.S_IMODE(pathlib.Path(path).stat().st_mode) == mode
        host=FakeHost(target,old,new,fail,rollback_fail)
        try: result=b.install(target,self.req(new),new,host)
        finally: b.secure_file=original; b.exact_regular=original_regular
        return temp,target,host,result,old,new

    def test_success_replay_conflict_and_predecessor_drift(self):
        temp,target,host,result,old,new=self.run_install()
        try:
            self.assertEqual(result["status"],"succeeded"); self.assertEqual(pathlib.Path(target["executable"]).read_bytes(),new)
            self.assertEqual(b.install(target,self.req(new),new,host),result)
            changed=self.req(new); changed["artifact_size"]=2
            with self.assertRaises(ValueError): b.install(target,changed,new,host)
        finally: temp.cleanup()
        temp,target,host,_,old,new=self.run_install(); temp.cleanup()
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); target=self.target(root); p=pathlib.Path(target["executable"]); p.parent.mkdir(); p.write_bytes(old)
            host=FakeHost(target,old,new); host.current=b"different"
            with self.assertRaises(ValueError): b.install(target,self.req(new),new,host)

    def test_recovery_verifies_live_state_without_mutations(self):
        from unittest.mock import patch
        for drift in (None, "running", "config", "drop", "journal", "health", "environment", "mode"):
            temp,target,host,result,old,new=self.run_install()
            try:
                if drift == "running": host.current=old
                if drift in ("config", "drop"):
                    pathlib.Path(target["config_json_path" if drift == "config" else "systemd_drop_in_path"]).write_bytes(b"drift")
                if drift == "journal":
                    p=pathlib.Path(target["state_dir"])/"op-1.json"; saved=json.loads(p.read_bytes()); saved["request_sha256"]="0"*64; p.write_text(json.dumps(saved))
                if drift == "health": host.health=lambda _: {"status":"healthy","backendId":"wrong","backendRegion":"eu1"}
                if drift == "environment": host.fail="environment"
                if drift == "mode": pathlib.Path(target["executable"]).chmod(0o777)
                files={p:p.read_bytes() for p in pathlib.Path(temp.name).rglob("*") if p.is_file()}
                host.calls.clear()
                with patch.object(b,"exact_regular",side_effect=lambda path,mode: stat.S_IMODE(pathlib.Path(path).stat().st_mode)==mode), \
                     patch.object(b,"atomic",side_effect=AssertionError("verification wrote a file")), \
                     patch.object(b,"download",side_effect=AssertionError("verification downloaded an artifact")):
                    if drift:
                        with self.assertRaises(ValueError): b.verify_existing(target,self.req(new),host)
                    else:
                        self.assertEqual(b.verify_existing(target,self.req(new),host),result)
                self.assertTrue(all(call[:2] == ("systemctl","show") for call in host.calls))
                self.assertEqual({p:p.read_bytes() for p in files},files)
            finally: temp.cleanup()

    def test_all_mutation_boundaries_roll_back_and_rollback_failure_is_retained(self):
        for failure in ("daemon-reload","restart","health","environment"):
            temp,target,_host,result,old,_new=self.run_install(failure)
            try:
                self.assertEqual(result["status"],"rolled_back",failure); self.assertEqual(pathlib.Path(target["executable"]).read_bytes(),old)
                journal=json.loads((pathlib.Path(target["state_dir"])/"op-1.json").read_text())
                self.assertEqual(journal["failure"]["type"],"ValueError" if failure=="environment" else "RuntimeError")
                line=SOURCE.read_text().splitlines()[journal["failure"]["line"]-1]
                self.assertIn({"daemon-reload":"daemon-reload", "restart":"restart", "health":"wait_for_health", "environment":"host.environment_has"}[failure],line)
                self.assertNotIn("rollback_failure",journal)
                self.assertEqual(journal["result"],result)
            finally: temp.cleanup()
        # Atomic write failures at each of the three writes.
        for index in range(3):
            temp=tempfile.TemporaryDirectory(); root=pathlib.Path(temp.name); target=self.target(root); old=b"\x7fELFold"; new=b"\x7fELFnew"
            p=pathlib.Path(target["executable"]); p.parent.mkdir(); p.write_bytes(old); host=FakeHost(target,old,new)
            original_secure,original_atomic,original_regular=b.secure_file,b.atomic,b.exact_regular; count=[0]
            b.secure_file=lambda path,limit,**_options: ({"present":True,"mode":0o644,"bytes":__import__('base64').b64encode(pathlib.Path(path).read_bytes()).decode()} if pathlib.Path(path).exists() else {"present":False})
            b.exact_regular=lambda path,mode: stat.S_IMODE(pathlib.Path(path).stat().st_mode) == mode
            def failing(path,data,mode):
                count[0]+=1
                if count[0] == index+2: raise RuntimeError("write") # journal is write one
                return original_atomic(path,data,mode)
            b.atomic=failing
            try: result=b.install(target,self.req(new),new,host); self.assertEqual(result["status"],"rolled_back")
            finally: b.secure_file=original_secure; b.atomic=original_atomic; b.exact_regular=original_regular; temp.cleanup()
        temp,target,host,result,_old,_new=self.run_install("health",True)
        try:
            self.assertEqual(result["status"],"rollback_failed")
            journal=json.loads((pathlib.Path(target["state_dir"])/"op-1.json").read_text())
            self.assertEqual(journal["failure"]["type"],"RuntimeError")
            self.assertEqual(journal["rollback_failure"]["type"],"ValueError")
            self.assertNotEqual(journal["failure"]["line"],journal["rollback_failure"]["line"])
            self.assertEqual(b.install(target,self.req(),b"\x7fELFnew",host)["status"],"rollback_failed")
            self.assertEqual(json.loads((pathlib.Path(target["state_dir"])/"op-1.json").read_text()),journal)
        finally: temp.cleanup()

    def test_heyvmd_systemd_and_supervisor_restart_identity_rollback_and_replay(self):
        for manager in ("systemd", "supervisor"):
            with tempfile.TemporaryDirectory() as td:
                root=pathlib.Path(td); target=self.target(root); target["process_manager"]=manager
                if manager == "supervisor": target["unit"]="heyvmd-ci"
                old=b"\x7fELFold"; new=b"\x7fELFdaemon"; exe=pathlib.Path(target["executable"]); exe.parent.mkdir(); exe.write_bytes(old); exe.chmod(0o755)
                host=(SupervisorHost if manager == "supervisor" else FakeHost)(target,old,new)
                req=self.req(new); req["component"]="heyvmd"
                original_regular,original_secure=b.exact_regular,b.secure_file; b.exact_regular=lambda path,mode: stat.S_IMODE(pathlib.Path(path).stat().st_mode)==mode
                b.secure_file=lambda path,limit,**opts: {"present":True,"mode":0o755,"bytes":__import__('base64').b64encode(pathlib.Path(path).read_bytes()).decode()}
                try:
                    result=b.install(target,req,new,host); self.assertEqual(result["status"],"succeeded")
                    self.assertEqual(b.install(target,req,new,host),result)
                    self.assertFalse(pathlib.Path(target["config_json_path"]).exists(),"daemon rollout must not modify unit/drop-in config")
                finally: b.exact_regular=original_regular; b.secure_file=original_secure
            with tempfile.TemporaryDirectory() as td:
                root=pathlib.Path(td); target=self.target(root); target["process_manager"]=manager
                if manager == "supervisor": target["unit"]="heyvmd-ci"
                old=b"\x7fELFold"; new=b"\x7fELFdaemon"; exe=pathlib.Path(target["executable"]); exe.parent.mkdir(); exe.write_bytes(old); exe.chmod(0o755)
                host=(SupervisorHost if manager == "supervisor" else FakeHost)(target,old,new,fail="health")
                req=self.req(new); req["component"]="heyvmd"; original_regular,original_secure=b.exact_regular,b.secure_file; b.exact_regular=lambda path,mode: True
                b.secure_file=lambda path,limit,**opts: {"present":True,"mode":0o755,"bytes":__import__('base64').b64encode(pathlib.Path(path).read_bytes()).decode()}
                try:
                    result=b.install(target,req,new,host); self.assertEqual(result["status"],"rolled_back"); self.assertEqual(exe.read_bytes(),old)
                finally: b.exact_regular=original_regular; b.secure_file=original_secure


    def test_listener_startup_wait_is_bounded_and_does_not_hide_bad_identity(self):
        from unittest.mock import patch
        import urllib.error
        original=FakeHost.health
        attempts=[]
        def starting(host,url):
            attempts.append(url)
            if len(attempts)==1: raise urllib.error.URLError("listener not ready")
            if len(attempts)==2: raise urllib.error.HTTPError(url,503,"starting",{},io.BytesIO())
            return original(host,url)
        with patch.object(FakeHost,"health",starting), patch.object(b.time,"sleep"):
            temp,target,host,result,old,new=self.run_install()
        try:
            self.assertEqual(result["status"],"succeeded")
            self.assertEqual(len(attempts),3)
        finally: temp.cleanup()
        for failure in (urllib.error.URLError("still starting"), urllib.error.HTTPError("http://localhost",401,"denied",{},io.BytesIO())):
            with patch.object(FakeHost,"health",side_effect=failure) as health, patch.object(b.time,"monotonic",side_effect=[0,31]), patch.object(b.time,"sleep") as sleep:
                temp,target,host,result,old,new=self.run_install()
            try:
                self.assertEqual(result["status"],"rolled_back")
                self.assertEqual(health.call_count,1)
                sleep.assert_not_called()
            finally: temp.cleanup()
        with patch.object(FakeHost,"health",return_value={"status":"healthy","backendId":"other","backendRegion":"eu1"}) as health, patch.object(b.time,"sleep") as sleep:
            temp,target,host,result,old,new=self.run_install()
        try:
            self.assertEqual(result["status"],"rolled_back")
            self.assertEqual(health.call_count,1)
            sleep.assert_not_called()
        finally: temp.cleanup()
        def restarted(host,url):
            host.pid += 1
            return original(host,url)
        with patch.object(FakeHost,"health",restarted):
            temp,target,host,result,old,new=self.run_install()
        try:
            self.assertEqual(result["status"],"rolled_back")
            self.assertEqual(pathlib.Path(target["executable"]).read_bytes(),old)
        finally: temp.cleanup()


if __name__ == "__main__": unittest.main()
