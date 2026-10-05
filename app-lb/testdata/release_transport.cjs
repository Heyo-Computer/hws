// Real app-lb HTTP routes, fixture Heyo auth and HTTPS CI ingress. No live state.
// Build with --features reqwest/rustls-tls-native-roots so SSL_CERT_FILE trusts
// this test's ephemeral CA. Production's public WebPKI verification is unchanged.
const assert = require('node:assert/strict'), fs = require('node:fs'), os = require('node:os');
const path = require('node:path'), http = require('node:http'), https = require('node:https');
const {spawn,execFileSync} = require('node:child_process');
const root = fs.mkdtempSync(path.join(os.tmpdir(),'release-transport-'));
const listen = s => new Promise(r=>s.listen(0,'127.0.0.1',()=>r(s.address().port)));
let child; const servers = [], received = [];
(async()=>{
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',root+'/ca-key',
    '-out',root+'/ca','-subj','/CN=fixture-ca'],{stdio:'ignore'});
  execFileSync('openssl',['req','-new','-newkey','rsa:2048','-nodes','-keyout',root+'/key',
    '-out',root+'/csr','-subj','/CN=localhost'],{stdio:'ignore'});
  fs.writeFileSync(root+'/extensions','subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n');
  execFileSync('openssl',['x509','-req','-in',root+'/csr','-CA',root+'/ca','-CAkey',root+'/ca-key',
    '-CAcreateserial','-days','1','-out',root+'/cert','-extfile',root+'/extensions'],{stdio:'ignore'});
  const auth = http.createServer((req,res)=>{
    res.setHeader('Content-Type','application/json');
    if(req.headers.authorization!=='Bearer fixture-admin'){res.writeHead(401);res.end('{}');return;}
    res.end(JSON.stringify({success:true,data:{subject:{userId:'fixture',email:'operator@example.test',platformRole:'admin'},scopes:['fleet:admin'],expiresIn:3600}}));
  }); servers.push(auth); const authPort = await listen(auth);
  const ci = https.createServer({key:fs.readFileSync(root+'/key'),cert:fs.readFileSync(root+'/cert')},(req,res)=>{
    let data=''; req.on('data',chunk=>data+=chunk); req.on('end',()=>{
      received.push({method:req.method,url:req.url,authorization:req.headers.authorization,spoof:req.headers['x-auth-request-user'],body:data});
      res.setHeader('Content-Type','application/json');
      if(req.method==='POST'){res.writeHead(202);res.end('{"run_id":"promoted"}');}
      else res.end('{"releases":[]}');
    });
  }); servers.push(ci); const ciPort = await listen(ci);
  const reservation=http.createServer(), port=await listen(reservation);await new Promise(r=>reservation.close(r));
  const log=fs.openSync(root+'/log','w');
  child=spawn(path.resolve(__dirname,'../target/debug/app-lb'),[],{cwd:root,env:{...process.env,
    SSL_CERT_FILE:root+'/ca',APP_LB_INSTANCE_LOCK:root+'/instance.lock',
    APP_LB_ADMIN_ADDR:'127.0.0.1:'+port,APP_LB_PROXY_ADDR:'127.0.0.1:0',APP_LB_DAEMON_URL:'http://127.0.0.1:9',
    APP_LB_ADMIN_AUTH:'1',APP_LB_DASHBOARD_AUTH:'1',APP_LB_DASHBOARD_USER:'admin',APP_LB_DASHBOARD_PASSWORD:'fixture-password',
    APP_LB_AUTH_URL:'http://127.0.0.1:'+authPort,APP_LB_RELEASE_CI_URL:'https://localhost:'+ciPort,
    APP_LB_SIEM:'0',APP_LB_DISK_TTL_SECS:'0',APP_LB_MOUNTS_DIR:root+'/mounts',APP_LB_WORKSPACES_DIR:root+'/workspaces',
    APP_LB_IMAGES_DIR:root+'/images',APP_LB_BUILD_DIR:root+'/build'},stdio:['ignore',log,log]});fs.closeSync(log);
  const base='http://127.0.0.1:'+port;
  for(let i=0;i<100;i++){try{if((await fetch(base+'/healthz')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
  const headers={Authorization:'Bearer fixture-admin','Content-Type':'application/json','x-auth-request-user':'forged'};
  let response=await fetch(base+'/api/releases/releases?before=prior',{headers});
  assert.equal(response.status,200,await response.text());
  assert.deepEqual(received[0],{method:'GET',url:'/releases?before=prior',authorization:'Bearer fixture-admin',spoof:undefined,body:''});
  response=await fetch(base+'/api/releases/release-promotions',{method:'POST',headers,body:JSON.stringify({environment:'stage',bundle_id:'release',request_id:'once'})});
  assert.equal(response.status,202); assert.deepEqual(await response.json(),{run_id:'promoted'});
  assert.equal(received.length,2); assert.equal(JSON.parse(received[1].body).request_id,'once');
  response=await fetch(base+'/api/releases/releases',{headers:{Authorization:'Basic '+Buffer.from('admin:fixture-password').toString('base64')}});
  assert.equal(response.status,403);assert.equal(received.length,2);
  response=await fetch(base+'/api/releases/release-promotions',{method:'POST',headers:{Cookie:'__Host-heyo-admin=fixture-admin',Origin:'https://evil.test','Content-Type':'application/json'},body:'{}'});
  assert.equal(response.status,403);assert.equal(received.length,2);
  response=await fetch(base+'/api/releases/secrets',{headers});assert.equal(response.status,400);assert.equal(received.length,2);
  console.log('PASS real control-panel transport: authenticated bearer, cursor, promotion payload/status, no spoofed identity forwarding, local credentials and cross-origin cookie writes refused. CI ingress is a fixture.');
})().catch(error=>{console.error(error);if(fs.existsSync(root+'/log'))console.error(fs.readFileSync(root+'/log','utf8'));process.exitCode=1}).finally(async()=>{
  if(child && child.exitCode===null){child.kill('SIGKILL');await new Promise(r=>child.once('exit',r));}
  for(const server of servers){server.closeAllConnections();server.close();}
  fs.rmSync(root,{recursive:true,force:true});
});
