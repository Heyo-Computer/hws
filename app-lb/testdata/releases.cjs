// Exercise actual panel HTML with API fixtures, never live deployments.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../..');
(async () => {
  const browser = await chromium.launch({headless:true});
  try {
    const page = await browser.newPage({viewport:{width:1440,height:1000}});
    const errors = [], posts = [];
    page.on('pageerror', error => errors.push(error.message));
    const candidate = (id, service, repository='repo') => ({id,name:id,repository,created_at:'2026-10-07T12:00:00Z',manifest:{retained:true,revision:id.padEnd(40,'a'),components:{[service]:{}}}});
    const releases = [candidate('ci-new','ci'),candidate('ci-current','ci'),candidate('ci-old','ci'),candidate('auth-new','auth'),candidate('foreign-ci','ci','another-repo')];
    const ci = {service:'ci',state:{current_bundle:'ci-current',previous_bundle:'ci-old',automation_held:true},history:[]};
    const stage = {name:'stage',repository:'repo',mode:'automatic',services:[ci,{service:'auth',state:{},history:[]},{service:'cloud',state:{},history:[]}]};
    const environments = [stage,{name:'unconfigured',repository:'repo',mode:'manual',services:[]}];
    let unavailable = false;
    await page.route('https://panel.test/**', async route => {
      const request = route.request(), url = new URL(request.url());
      if (url.pathname.startsWith('/api/releases/')) {
        const resource = url.pathname.split('/').pop();
        if (unavailable) return route.fulfill({status:503,json:{error:'CI unavailable'}});
        if (request.method() === 'POST') {
          const data = request.postDataJSON(); posts.push({resource,data});
          if (resource === 'release-automation') ci.state.automation_held = data.held;
          return route.fulfill({json:{run_id:'accepted'}});
        }
        return route.fulfill({json:resource === 'releases' ? {releases} : resource === 'release-environments' ? {environments} : {builds:[]}});
      }
      if (url.pathname === '/fleet/deployments') return route.fulfill({json:{configured:true,gateways:[],rows:[]}});
      if (url.pathname === '/services') return route.fulfill({json:{configured:true,inventory:{services:[],nextCursor:null}}});
      if (url.pathname.startsWith('/__ui/')) return route.fulfill({path:path.join(root,'ui',url.pathname.slice(6))});
      return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(root,'app-lb/src/releases.html'),'utf8').replace('{{HTML_ATTRS}}','data-theme="dark"').replace('{{WHO}}','operator@example.test')});
    });
    const settled = () => page.waitForFunction(() => !document.querySelector('#refresh').disabled && document.querySelector('#updated').textContent.startsWith('Refreshed'));
    const refresh = async () => { await page.locator('#refresh').click(); await settled(); };
    const screenshot = async name => { if (process.env.SCREENSHOT_DIR) await page.screenshot({path:path.join(process.env.SCREENSHOT_DIR,name+'.png'),fullPage:true}); };
    await page.goto('https://panel.test/releases'); await settled();
    assert.deepEqual(await page.locator('#candidate option').allTextContents(),['ci-new','ci-current','ci-old']);
    assert.equal(await page.locator('#catalog [data-release]').count(),3);
    assert.equal(await page.locator('#inventory').isVisible(),false);
    await screenshot('release-console-desktop');
    // Choose a non-default row: the confirmation must not use the first candidate.
    await page.locator('[data-release="ci-old"]').click();
    assert.match(await page.locator('#confirm-body').innerText(),/Service: ci/);
    assert.match(await page.locator('#confirm-body').innerText(),/Release: ci-old/);
    assert.equal(posts.length,0);
    await screenshot('release-console-confirmation');
    await page.locator('#confirm').click(); await settled();
    assert.equal(posts[0].data.bundle_id,'ci-old');
    assert.equal(posts[0].data.service,'ci');
    assert.equal(posts[0].data.environment,'stage');
    assert(posts[0].data.request_id);
    await page.selectOption('#service','auth');
    assert.deepEqual(await page.locator('#candidate option').allTextContents(),['auth-new']);
    assert.equal(await page.locator('#catalog [data-release]').count(),1);
    assert(await page.locator('[data-action="rollback"]').isDisabled());
    await page.selectOption('#service','cloud');
    assert.equal(await page.locator('#catalog [data-release]').count(),0);
    assert(await page.locator('#build').isVisible());
    assert.match(await page.locator('#catalog').innerText(),/No retained candidates for cloud/);
    await screenshot('release-console-no-candidates');
    await page.selectOption('#service','ci');
    ci.recovery_required = true; ci.recovery_bundle = 'ci-current';
    await refresh();
    assert(await page.locator('[data-action="rollback"]').isDisabled());
    await page.locator('[data-action="recover"]').click();
    await page.locator('#confirm').click(); await settled();
    assert.equal(posts[1].data.bundle_id,'ci-current');
    assert.equal(posts[1].data.recover,true);
    ci.state.active_run = 'deploying'; await refresh();
    assert(await page.locator('[data-action="deploy"]').isDisabled());
    assert(await page.locator('[data-action="recover"]').isDisabled());
    for (const button of await page.locator('#catalog [data-release]').all()) assert(await button.isDisabled());
    delete ci.state.active_run; ci.recovery_required = false; await refresh();
    await page.locator('[data-action="rollback"]').click();
    await page.locator('#confirm').click(); await settled();
    assert.equal(posts[2].data.bundle_id,'ci-old');
    assert.notEqual(posts[2].data.request_id,posts[0].data.request_id);
    page.on('dialog', dialog => dialog.accept());
    await page.getByRole('button',{name:'Resume automation'}).click(); await settled();
    assert.deepEqual(posts[3],{resource:'release-automation',data:{environment:'stage',service:'ci',held:false}});
    await page.setViewportSize({width:390,height:844});
    await screenshot('release-console-mobile');
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.setViewportSize({width:1440,height:1000});
    await page.selectOption('#environment','unconfigured');
    assert(await page.locator('#service').isDisabled());
    assert.equal(await page.locator('#catalog [data-release]').count(),0);
    assert.match(await page.locator('#catalog').innerText(),/not configured/);
    await screenshot('release-console-unconfigured');
    unavailable = true;
    await page.locator('#refresh').click();
    await page.getByText('CI unavailable',{exact:false}).waitFor();
    assert.deepEqual(errors,[]);
    console.log('PASS: service/repository candidate isolation, row-selected confirmation, scoped deployment, rollback/recovery, active guards, hold/resume, empty policies/candidates and mobile layout. APIs are fixtures.');
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1});
