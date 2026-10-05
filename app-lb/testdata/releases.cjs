// Render the actual control-panel source with API fixtures, not live deployments.
// PLAYWRIGHT_MODULE selects an installed Playwright; SCREENSHOT_DIR is optional.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../..');
(async () => {
  const browser = await chromium.launch({headless:true});
  try {
    const page = await browser.newPage({viewport:{width:1280,height:1000}});
    const releases = [
      {id:'new',name:'2026-10-05.1',repository:'repo',manifest:{revision:'a'.repeat(40),retained:true}},
      {id:'old',name:'2026-10-04.1',repository:'repo',manifest:{revision:'b'.repeat(40),retained:true}},
      {id:'legacy',name:'Legacy',repository:'repo',manifest:{revision:'c'.repeat(40)}},
    ];
    let unavailable = false;
    const posts = [], environments = [
      {name:'stage',repository:'repo',mode:'automatic',state:{current_bundle:'new',previous_bundle:'old',automation_held:true},history:[]},
      {name:'production',repository:'repo',mode:'manual',state:{current_bundle:'old',active_run:'deploy-123'},history:[{run_id:'deploy-123',bundle_id:'new',status:'running',deployments:[{service:'auth',revision:'a'.repeat(12),status:'running'}]}]},
    ];
    await page.route('https://panel.test/**', async route => {
      const req = route.request(), url = new URL(req.url());
      if (url.pathname.startsWith('/api/releases/')) {
        const resource = url.pathname.split('/').pop();
        if (unavailable) return route.fulfill({status:503,json:{error:'CI unavailable'}});
        if (req.method() === 'POST') {
          const data = req.postDataJSON(); posts.push({resource,data});
          if (resource === 'release-automation') environments[0].state.automation_held = data.held;
          return route.fulfill({json:{run_id:'accepted'}});
        }
        return route.fulfill({json:resource === 'releases' ? {releases} : resource === 'release-environments' ? {environments} : {builds:[{name:'2026-10-05.1',revision:'a'.repeat(12),status:'ready'}]}});
      }
      if (url.pathname.startsWith('/__ui/')) {
        const file = path.join(root, 'ui', url.pathname.slice(6));
        return route.fulfill({path:file});
      }
      return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(root,'app-lb/src/releases.html'),'utf8').replace('{{HTML_ATTRS}}','data-theme="dark"').replace('{{WHO}}','operator@example.test')});
    });
    await page.goto('https://panel.test/releases');
    await page.getByText('Status updated.',{exact:true}).waitFor();
    const stage = page.locator('article').filter({has:page.getByRole('heading',{name:'stage',exact:true})});
    const production = page.locator('article').filter({has:page.getByRole('heading',{name:'production',exact:true})});
    assert.equal(await stage.locator('option').count(),2);
    assert.equal(await production.getByRole('button',{name:'Deploy selected'}).isDisabled(),true);
    assert.equal(await production.getByRole('button',{name:'Hold automation'}).isDisabled(),true);
    page.on('dialog', dialog => dialog.accept());
    await stage.getByRole('button',{name:'Roll back',exact:true}).click();
    await page.getByText('Status updated.',{exact:true}).waitFor();
    assert.equal(posts[0].resource,'release-promotions');
    assert.equal(posts[0].data.bundle_id,'old');
    assert.equal(posts[0].data.environment,'stage');
    assert(posts[0].data.request_id);
    await stage.getByRole('button',{name:'Resume automation'}).click();
    await page.getByText('Status updated.',{exact:true}).waitFor();
    assert.deepEqual(posts[1],{resource:'release-automation',data:{environment:'stage',held:false}});
    if (process.env.SCREENSHOT_DIR) await page.screenshot({path:path.join(process.env.SCREENSHOT_DIR,'release-console-desktop.png'),fullPage:true});
    await page.setViewportSize({width:390,height:844});
    if (process.env.SCREENSHOT_DIR) await page.screenshot({path:path.join(process.env.SCREENSHOT_DIR,'release-console-mobile.png'),fullPage:true});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth), JSON.stringify(await page.evaluate(()=>[...document.querySelectorAll('body *')].filter(e=>e.getBoundingClientRect().right>innerWidth).map(e=>[e.tagName,e.className]))));
    unavailable = true;
    await page.getByRole('button',{name:'Refresh status'}).click();
    await page.getByText('CI unavailable',{exact:false}).waitFor();
    console.log('PASS: release selection, rollback payload, hold/resume, active-run restrictions, mobile layout and unavailable state. APIs are fixtures.');
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1});
