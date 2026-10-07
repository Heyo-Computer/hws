"""Two real proxies and a disposable echo app; no deployed services are touched.

Build with --features reqwest/rustls-tls-native-roots so both TLS stacks trust
the disposable SSL_CERT_FILE. Certificate and hostname verification stay enabled.
"""
import base64, concurrent.futures, hashlib, json, os, pathlib, socket, subprocess, tempfile, threading, time, urllib.request, urllib.error
from regional_app import RegionalApp, server

BINARY = os.environ.get('APP_LB_TEST_BINARY', str(pathlib.Path(__file__).resolve().parents[1] / 'target/debug/app-lb'))

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

held_started, held_release = threading.Event(), threading.Event()
held_port = None
class App(RegionalApp):
    def hold(self, seconds):
        global held_port
        held_port = self.server.server_port
        held_started.set()
        assert held_release.wait(10), 'held request was not released'

    def respond(self):
        if self.path == '/sql-tunnel':
            if self.headers.get('Upgrade', '').lower() != 'pg-fc-sql/1' or 'upgrade' not in self.headers.get('Connection', '').lower().split(','):
                self.send_error(400, 'SQL upgrade headers missing')
                return
            assert self.command == 'POST'
            assert not any(k.lower().startswith('x-heyo-peer') for k in self.headers)
            assert json.loads(self.rfile.read(int(self.headers['Content-Length']))) == {'startup': [0, 17, 255], 'claim': 'fixture'}
            self.send_response(101)
            self.send_header('Upgrade', 'pg-fc-sql/1')
            self.send_header('Connection', 'Upgrade')
            self.end_headers()
            self.wfile.write(b'\x00SQL-ready\xff')
            self.wfile.flush()
            payload = self.rfile.read(7)
            self.wfile.write(payload[::-1])
            self.wfile.flush()
            self.close_connection = True
            return
        if self.path == '/socket':
            assert not any(k.lower().startswith('x-heyo-peer') for k in self.headers)
            accept = base64.b64encode(hashlib.sha1((self.headers['Sec-WebSocket-Key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            self.send_response(101)
            self.send_header('Upgrade','websocket')
            self.send_header('Connection','Upgrade')
            self.send_header('Sec-WebSocket-Accept',accept)
            self.end_headers()
            head=self.rfile.read(2)
            assert head[0]==0x81 and head[1]&0x80
            size=head[1]&0x7f
            assert size<126
            mask=self.rfile.read(4)
            data=self.rfile.read(size)
            self.wfile.write(bytes([0x81,size])+bytes(v^mask[i%4] for i,v in enumerate(data)))
            self.wfile.flush()
            self.close_connection=True
            return
        super().respond()

def request(url, data=None, headers=None, method=None):
    r = urllib.request.Request(url, data=None if data is None else json.dumps(data).encode(), headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as f: return f.status, f.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

with tempfile.TemporaryDirectory(prefix='heyo-gateway-smoke-') as tmp:
    root = pathlib.Path(tmp)
    key, cert = root/'key.pem', root/'cert.pem'
    ca, ca_key, csr, extensions = root/'ca.pem', root/'ca-key.pem', root/'leaf.csr', root/'extensions'
    extensions.write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    def openssl(*args):
        subprocess.run(['openssl',*map(str,args)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',ca_key,'-out',ca,'-days','1','-subj','/CN=Disposable gateway test CA','-addext','basicConstraints=critical,CA:TRUE')
    openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout',key,'-out',csr,'-subj','/CN=localhost')
    openssl('x509','-req','-in',csr,'-CA',ca,'-CAkey',ca_key,'-CAcreateserial','-out',cert,'-days','1','-extfile',extensions)
    backend = server('eu1', 'fixture-v1', handler=App)
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    alternate = server('eu1', 'fixture-v1', handler=App)
    threading.Thread(target=alternate.serve_forever,daemon=True).start()
    processes=[]
    def start(name, tls=False):
        directory=root/name; directory.mkdir()
        proxy,admin,tlsport=port(),port(),port()
        env={k:v for k,v in os.environ.items() if not k.startswith('APP_LB_')}
        env.update({'APP_LB_PROXY_ADDR':f'127.0.0.1:{proxy}','APP_LB_ADMIN_ADDR':f'127.0.0.1:{admin}','APP_LB_MOUNTS_DIR':str(directory/'mounts'),'APP_LB_WORKSPACES_DIR':str(directory/'workspaces'),'APP_LB_IMAGES_DIR':str(directory/'images'),'APP_LB_BUILD_DIR':str(directory/'build'),'APP_LB_SIEM':'0','SSL_CERT_FILE':str(ca),'APP_LB_DISK_TTL_SECS':'0','APP_LB_DAEMON_URL':'http://127.0.0.1:9','APP_LB_INSTANCE_LOCK':str(directory/'instance.lock')})
        if tls: env.update({'APP_LB_PROXY_TLS_ADDR':f'[::1]:{tlsport}','APP_LB_TLS_CERT':str(cert),'APP_LB_TLS_KEY':str(key)})
        log=open(directory/'log','w')
        p=subprocess.Popen([BINARY],cwd=directory,env=env,stdout=log,stderr=log);processes.append((p,log,directory))
        for _ in range(100):
            try:
                if request(f'http://127.0.0.1:{admin}/healthz')[0]==200: break
            except OSError: pass
            if p.poll() is not None: raise RuntimeError((directory/'log').read_text()[-4000:])
            time.sleep(.1)
        else: raise RuntimeError('startup timeout')
        with urllib.request.urlopen(f'http://127.0.0.1:{admin}/deployments',timeout=5) as response:
            assert response.headers.get('X-App-Lb-Gateway')=='1'
            assert response.headers.get('X-App-Lb-Discovery-Region')=='1'
        status,_=request(f'http://127.0.0.1:{admin}/secrets',{'id':'peer','data':{'token':'disposable-test-token'}},{'Content-Type':'application/json'})
        assert status in (200,201),status
        return proxy,admin,tlsport
    try:
        dest,da,dt=start('destination',True)
        source,sa,_=start('source')
        def register(admin,mode,*upstreams):
            spec={'id':'smoke','routes':[{'host':'smoke.example'}],'upstreams':list(upstreams),'health':{'path':'/health','expected_header':{'name':'x-heyo-revision','value':'fixture-v1'}},'gateway':{'mode':mode,'service':'smoke','region':'eu1','auth':{'secret':'peer'}}}
            status,body=request(f'http://127.0.0.1:{admin}/deployments',spec,{'Content-Type':'application/json'})
            assert status in (200,201),(status,body)
        register(da,'local',f'127.0.0.1:{backend.server_port}',f'127.0.0.1:{alternate.server_port}')
        register(sa,'forward',f'https://localhost:{dt}')
        h={'Host':'smoke.example','Authorization':'Bearer application-value'}
        for _ in range(80):
            status,body=request(f'http://127.0.0.1:{source}/ready?q=one%20two',headers=h)
            if status==200: break
            time.sleep(.25)
        assert status==200,(status,body)
        status,body=request(f'http://127.0.0.1:{source}/action?q=a%2Fb',{'asymmetric':17},h)
        result=json.loads(body)
        assert status==200 and result['method']=='POST' and result['path']=='/action?q=a%2Fb',result
        assert result['region']=='eu1' and result['revision']=='fixture-v1',result
        assert result['host']=='smoke.example' and result['authorizationSha256']==hashlib.sha256(h['Authorization'].encode()).hexdigest() and not result['peerHeaders'],result
        assert b'Bearer application-value' not in body
        assert json.loads(result['body'])=={'asymmetric':17}
        assert len([r for r in [*backend.admissions,*alternate.admissions] if r['method']=='POST'])==1
        assert request(f'http://127.0.0.1:{dest}/private',headers=h)[0]==403
        assert request(f'http://127.0.0.1:{source}/loop',headers={**h,'x-heyo-peer-region':'eu1'})[0]==508
        with socket.create_connection(('127.0.0.1',source),timeout=5) as ws:
            ws.sendall(b'GET /socket HTTP/1.1\r\nHost: smoke.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n')
            with ws.makefile('rb') as stream:
                assert stream.readline().startswith(b'HTTP/1.1 101')
                response_headers=[]
                while (line:=stream.readline()) not in (b'\r\n',b''):
                    response_headers.append(line.lower())
                assert b'sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo=\r\n' in response_headers
                payload,mask=b'asymmetric-echo-17',b'abcd'
                ws.sendall(bytes([0x81,0x80|len(payload)])+mask+bytes(v^mask[i%4] for i,v in enumerate(payload)))
                assert stream.read(2)==bytes([0x81,len(payload)])
                assert stream.read(len(payload))==payload
        # pg-fc sends a JSON POST before switching to raw, bidirectional SQL.
        # A WebSocket-only check misses Pingora stripping this custom upgrade.
        with socket.create_connection(('127.0.0.1',source),timeout=5) as tunnel:
            body=json.dumps({'startup':[0,17,255],'claim':'fixture'}).encode()
            tunnel.sendall(b'POST /sql-tunnel HTTP/1.1\r\nHost: smoke.example\r\nConnection: Upgrade\r\nUpgrade: pg-fc-sql/1\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
            with tunnel.makefile('rb') as stream:
                assert stream.readline().startswith(b'HTTP/1.1 101')
                response_headers=[]
                while (line:=stream.readline()) not in (b'\r\n',b''):
                    response_headers.append(line.lower())
                assert b'upgrade: pg-fc-sql/1\r\n' in response_headers
                assert stream.read(11)==b'\x00SQL-ready\xff'
                # No application heartbeat: both proxy hops must keep an idle
                # accepted SQL tunnel past Pingora's 60-second body deadline.
                time.sleep(65)
                payload=b'\x00\xffsql\x13\x80'
                tunnel.sendall(payload)
                assert stream.read(len(payload))==payload[::-1]
        assert request(f'http://127.0.0.1:{source}/sql-tunnel',{},
            {**h,'Connection':'Upgrade','Upgrade':'unsupported/1'})[0]==400
        with concurrent.futures.ThreadPoolExecutor() as pool:
            held=pool.submit(request,f'http://127.0.0.1:{source}/held',None,h)
            assert held_started.wait(5), 'request did not reach the app'
            drain_url=f'http://127.0.0.1:{da}/deployments/smoke/upstreams/127.0.0.1%3A{held_port}/drain'
            status,body=request(drain_url,{'reason':'disposable gateway test'},{'Content-Type':'application/json'},'PUT')
            state=json.loads(body)
            assert status==202 and state['state']=='draining' and state['in_flight']==1,(status,state)
            # Replaying the spec must retain both drain intent and the in-flight
            # backend object held by the already admitted peer request.
            register(da,'local',f'127.0.0.1:{backend.server_port}',f'127.0.0.1:{alternate.server_port}')
            for i in range(12):
                status,body=request(f'http://127.0.0.1:{source}/during-drain/{i}',headers=h)
                assert status==200 and json.loads(body)['port']!=held_port,(status,body)
            assert not held.done(), 'drain terminated the admitted request'
            held_release.set()
            assert held.result()[0]==200
            for _ in range(20):
                status,body=request(drain_url,{}, {'Content-Type':'application/json'},'PUT')
                if status==200: break
                time.sleep(.1)
            assert status==200 and json.loads(body)['in_flight']==0,(status,body)
        # Let health reconciliation run: it must not mistake an unauthenticated
        # peer response for proof of application readiness.
        time.sleep(7)
        assert request(f'http://127.0.0.1:{source}/after-probe',headers=h)[0]==200
        print('PASS: two app-lb processes; verified HTTPS; Host/query/body/Authorization preserved; peer headers consumed; POST executes once; WebSocket and SQL upgrade round trips; unsupported upgrade rejected; invalid admission and second hop rejected; held response body drains to zero across spec replay while 12 new requests use alternate backend; health reconciliation retains serving path')
    except Exception:
        for p,log,directory in processes:
            log.flush();print(directory.name,(directory/'log').read_text()[-4500:])
        raise
    finally:
        held_release.set()
        backend.shutdown()
        alternate.shutdown()
        for p,log,_ in processes:
            p.terminate()
        for p,log,_ in processes:
            try:p.wait(timeout=40)
            except subprocess.TimeoutExpired:p.kill();p.wait()
            log.close()
