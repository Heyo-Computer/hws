// Actual recovery page with Cloud API fixtures; never mutates live VMs.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../..');
(async () => {
  const browser = await chromium.launch({headless:true, executablePath:process.env.CHROMIUM_EXECUTABLE});
  try {
    const page = await browser.newPage({viewport:{width:1320,height:1050}});
    const errors=[],posts=[]; let operations=[], unavailable=false, interrupted=true;
    let policy={enabled:false,interval_seconds:3600,retain_count:3}, policyWrites=[];
    let pendingState='pending';
    const checkpoint='12345678-0000-4000-8000-000000000001';
    page.on('pageerror', e=>errors.push(e.message));
    page.on('dialog', d=>d.accept());
    await page.route('https://panel.test/**',async route=>{
      const req=route.request(),url=new URL(req.url());
      if(url.pathname.startsWith('/api/vm-recovery/')) {
        if(unavailable)return route.fulfill({status:503,json:{error:'Cloud unavailable'}});
        if(url.pathname.endsWith('/checkpoint-policy')) {
          if(req.method()==='PUT'){policy=req.postDataJSON();policyWrites.push(policy);}
          return route.fulfill({json:policy});
        }
        if(req.method()==='POST') {
          const body=req.postDataJSON();posts.push(body);
          operations=[{...body,sandbox_id:'dep-demo',source_backend_id:'host-a',recovery_checkpoint_id:body.checkpoint_id,phase:'restore',error:null,created_at:new Date().toISOString(),updated_at:new Date().toISOString()}];
          if(interrupted){interrupted=false;return route.abort();}
          return route.fulfill({json:operations[0]});
        }
        if(url.pathname.endsWith('/checkpoints'))return route.fulfill({json:[{checkpoint_id:checkpoint,state:'committed',backend_id:'host-a',committed_at:new Date(Date.now()-600000).toISOString()},{checkpoint_id:'pending-checkpoint',state:pendingState,committed_at:pendingState==='committed'?new Date().toISOString():null,created_at:new Date().toISOString()}]});
        if(url.pathname.endsWith('/destinations'))return route.fulfill({json:{source_backend_id:'host-a',destinations:[{id:'host-b',region:'eu',eligible:true},{id:'host-c',region:'us',eligible:false,reason:'destination lacks memory capacity'}]}});
        return route.fulfill({json:url.pathname.endsWith('/recoveries')?operations:operations[0]});
      }
      if(url.pathname.startsWith('/__ui/'))return route.fulfill({path:path.join(root,'ui',url.pathname.slice(6))});
      return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(root,'app-lb/src/vm_recovery.html'),'utf8').replace('{{HTML_ATTRS}}','data-theme="dark"').replace('{{WHO}}','operator@example.test')});
    });
    const screenshots=process.env.SCREENSHOT_DIR;
    async function capture(name){if(screenshots){fs.mkdirSync(screenshots,{recursive:true});await page.screenshot({path:path.join(screenshots,name+'.png'),fullPage:true});}}
    await page.goto('https://panel.test/vm-recovery');
    assert(await page.locator('#start').isDisabled());await capture('recovery-default');
    await page.locator('#vm').fill('dep-demo');await page.locator('#load').click();
    await page.waitForFunction(()=>!document.getElementById('checkpoint').disabled);
    await page.waitForFunction(()=>!document.getElementById('policy-fields').disabled);
    assert.equal(await page.locator('#policy-enabled').isChecked(),false);
    await page.locator('#policy-enabled').check();
    await page.locator('#policy-interval').fill('120');await page.locator('#policy-retain').fill('2');
    await page.getByRole('button',{name:'Save protection',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('policy-status').textContent.includes('Protection enabled'));
    assert.deepEqual(policyWrites,[{enabled:true,interval_seconds:120,retain_count:2}]);
    assert((await page.locator('#capture-status').innerText()).includes('1 retained'));
    await capture('protection-enabled');
    policy.error='Checkpoint storage unavailable';await page.locator('#policy-refresh').click();
    await page.waitForFunction(()=>document.getElementById('policy-status').textContent.includes('Checkpoint storage unavailable'));
    await capture('protection-error');
    policy.error=null;
    await page.locator('#policy-enabled').uncheck();await page.getByRole('button',{name:'Save protection',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('policy-status').textContent.includes('Protection disabled'));
    assert.equal(policyWrites[1].enabled,false);
    await capture('protection-disabled');
    pendingState='committed';await page.locator('#policy-refresh').click();
    await page.waitForFunction(()=>document.getElementById('capture-status').textContent.includes('2 retained'));
    assert(await page.locator('option[value="pending-checkpoint"]').isEnabled(),'new capture is immediately selectable');
    await page.locator('#checkpoint').selectOption('pending-checkpoint');
    pendingState='deleted';await page.locator('#policy-refresh').click();
    await page.waitForFunction(()=>!document.getElementById('policy-fields').disabled);
    assert.equal(await page.locator('#checkpoint').inputValue(),'','retention removes stale selection');
    assert(await page.locator('option[value="pending-checkpoint"]').isDisabled());
    assert(await page.locator('option[value="host-c"]').isDisabled());
    await page.locator('#checkpoint').selectOption(checkpoint);await page.locator('#destination').selectOption('host-b');
    await page.locator('#fenced').check();assert(await page.locator('#start').isDisabled());
    await page.locator('#evidence').fill('Hypervisor power-off receipt TEST-104; restart disabled.');
    assert(await page.locator('#start').isEnabled());await capture('recovery-selected');
    await page.locator('#start').click();await page.waitForFunction(()=>document.querySelector('.operation'));
    assert.equal(posts.length,1);assert.equal(posts[0].source_fenced,true);
    await page.reload();await page.waitForFunction(()=>!document.getElementById('intent').hidden);
    assert.equal(posts.length,1,'reload must not issue a mutation');
    await page.locator('#retry').click();await page.waitForFunction(()=>document.getElementById('message').textContent.includes('accepted'));
    assert.equal(posts.length,2);assert.deepEqual(posts[1],posts[0],'retry must retain immutable operation ID and intent');
    operations[0].error='Destination unavailable; source must remain fenced.';
    await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('operations').textContent.includes('Needs attention'));
    await capture('recovery-error');
    operations[0].error=null;operations[0].phase='completed';
    await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('intent').hidden);
    assert(await page.locator('#start').isDisabled());await capture('recovery-completed');
    await page.setViewportSize({width:390,height:844});await capture('recovery-mobile');
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'no horizontal overflow');
    unavailable=true;await page.locator('#load').click();await page.waitForFunction(()=>document.getElementById('message').textContent.includes('Cloud unavailable'));
    assert(await page.locator('#start').isDisabled());assert.equal(posts.length,2);assert.deepEqual(errors,[]);
    console.log('PASS: fencing, eligibility, interrupted POST, reload, exact retry, durable error/completion, mobile, unavailable API');
  } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exit(1);});
