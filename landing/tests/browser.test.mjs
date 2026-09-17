import {test, before, after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {chromium} from 'playwright';
import AxeBuilder from '@axe-core/playwright';
const base=process.env.LANDING_URL || 'http://127.0.0.1:8938';
let browser;
before(async()=>{browser=await chromium.launch(); await mkdir('test-results',{recursive:true});});
after(async()=>{await browser?.close();});
for (const lang of ['es','en']) {
  for (const width of [320,375,768,1280]) {
    test(`${lang}: layout, links and accessibility at ${width}px`,async()=>{
      const context=await browser.newContext({viewport:{width,height:900},reducedMotion:'reduce'});
      const page=await context.newPage();
      const errors=[]; page.on('pageerror',e=>errors.push(e.message));
      const failures=[];page.on('response',r=>{if(r.status()>=400) failures.push(r.url());});
      await page.goto(`${base}/${lang}/`);
      await page.evaluate(()=>document.fonts.ready);
      await page.waitForFunction(()=>!document.querySelector('[data-case="0"]').disabled);
      assert.equal(await page.locator('html').getAttribute('lang'),lang);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
      assert.equal(await page.evaluate(()=>getComputedStyle(document.documentElement).scrollBehavior),'auto');
      assert.equal(await page.locator('h1').count(),1);
      await page.screenshot({path:`test-results/${lang}-${width}.png`,fullPage:true});
      const result=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();
      assert.deepEqual(result.violations.map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[]);
      assert.deepEqual(errors,[]);assert.deepEqual(failures,[]);
      await page.close();
    });
  }
  test(`${lang}: evidence scenarios reflect frozen records`,async()=>{
    const page=await browser.newPage(); await page.goto(`${base}/${lang}/`);
    await page.waitForFunction(()=>!document.querySelector('[data-case="0"]').disabled);
    const results=['—','—','contradicted','corroborated','contradicted','contradicted','pending','unknown'];
    for(let i=0;i<results.length;i++){
      await page.locator(`[data-case="${i}"]`).click();
      assert.equal(await page.locator('#observer-value').textContent(),results[i]);
      assert.equal(await page.locator('#gateway-value').textContent(),'unknown');
      assert.equal(await page.locator('#destination-value').textContent(),i===0?'—':'committed');
      assert.equal(await page.locator('[data-case][aria-pressed="true"]').count(),1);
      const trace=await page.locator('#method-trace').textContent();
      assert.equal(trace.split('\n').filter(m=>m==='tools/call').length,1);
      assert.equal(trace.includes('mcpzt/evidence/get'),i!==0);
      const fixture=await (await page.request.get(new URL(await page.locator('#raw-fixture').getAttribute('href'),base).href)).json();
      if(i>1) assert.equal(fixture.observations.at(-1).payload.result,results[i]);
    }
    await page.close();
  });
}
test('mobile keyboard menu, language and copy fallbacks',async()=>{
  const page=await browser.newPage({viewport:{width:375,height:812}});
  await page.goto(`${base}/es/`);
  const menu=page.locator('.menu-toggle');
  assert.equal(await page.locator('#navigation').isVisible(),false);
  await menu.focus();await page.keyboard.press('Enter');
  assert.equal(await page.locator('#navigation').isVisible(),true);
  await page.keyboard.press('Escape');assert.equal(await menu.getAttribute('aria-expanded'),'false');
  assert.equal(await menu.evaluate(e=>e===document.activeElement),true);
  await page.evaluate(()=>location.hash='examples');
  await page.locator('.language a[lang="en"]').click();
  assert.equal(new URL(page.url()).pathname,'/en/');assert.equal(new URL(page.url()).hash,'#examples');
  assert.match(await page.evaluate(()=>document.cookie),/mcpzt_lang=en/);
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async t=>{window.copiedText=t;}}}));
  await page.locator('[data-copy="pip-command"]').click();
  assert.match(await page.locator('#copy-status').textContent(),/Command copied/);
  assert.equal(await page.evaluate(()=>window.copiedText),'python -m pip install mcp-zero-trust-layer==0.6.0');
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:undefined}));
  await page.locator('[data-copy="pip-command"]').click();
  assert.match(await page.locator('#copy-status').textContent(),/Could not copy/);
  assert.match(await page.evaluate(()=>getSelection().toString()),/mcp-zero-trust-layer==0.6.0/);
  await page.close();
});
test('content and navigation work without JavaScript',async()=>{
  const page=await browser.newPage({javaScriptEnabled:false,viewport:{width:320,height:800}});
  await page.goto(`${base}/en/`);
  assert.equal(await page.locator('#navigation').isVisible(),true);
  assert.equal(await page.locator('noscript').isVisible(),true);
  assert.equal(await page.locator('.scenario-controls').isVisible(),false);
  await page.locator('.language a[lang="es"]').click();
  assert.match(page.url(),/\/es\/$/);await page.close();
});
test('missing fixture data has an actionable fallback',async()=>{
  const page=await browser.newPage();
  await page.route('**/scenarios.*.json',route=>route.abort());
  await page.goto(`${base}/es/`);
  await page.locator('#demo-error').waitFor({state:'visible'});
  assert.equal(await page.locator('.scenario-controls').isVisible(),false);
  assert.equal((await page.request.get(new URL(await page.locator('#raw-fixture').getAttribute('href'),base).href)).status(),200);
  await page.close();
});
test('policy examples disclose dispatch and remain usable on mobile',async()=>{
  const page=await browser.newPage({viewport:{width:320,height:800}});
  await page.goto(`${base}/es/`);
  const cases=page.locator('.policy-cases details');
  assert.equal(await cases.count(),3);
  for(let i=0;i<3;i++){
    await cases.nth(i).locator('summary').click();
    const result=JSON.parse(await cases.nth(i).locator('code').textContent());
    if(i===0) assert.ok(result.result);
    if(i===1) assert.equal(result.error.code,-32001);
    if(i===2) assert.ok(result.error.data.approval_id);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  }
  await page.close();
});
for (const lang of ['es','en']) {
  test(`${lang}: contract map binds displayed documents and preserves missing evidence`,async()=>{
    const page=await browser.newPage({viewport:{width:375,height:812}});
    await page.goto(`${base}/${lang}/`);
    await page.waitForFunction(()=>!document.querySelector('[data-contract="0"]').disabled);
    const buttons=page.locator('[data-contract]');
    assert.equal(await buttons.count(),4);
    await buttons.nth(2).click();
    assert.equal(await page.locator('#contract-empty').isVisible(),true);
    assert.equal(await buttons.nth(2).getAttribute('data-present'),'false');
    await page.locator('[data-case="2"]').click();
    const fixture=await (await page.request.get(new URL(await page.locator('#raw-fixture').getAttribute('href'),base).href)).json();
    const records=[fixture.evidence.permit.authorization,fixture.evidence.permit.attempt,fixture.evidence.receipt,fixture.observations.at(-1)];
    for(let i=0;i<4;i++){
      await buttons.nth(i).focus();await page.keyboard.press('Enter');
      assert.equal(await buttons.nth(i).getAttribute('aria-pressed'),'true');
      assert.equal(await buttons.nth(i).getAttribute('data-present'),'true');
      assert.equal(await page.locator('#contract-empty').isVisible(),false);
      const fields=await page.locator('#contract-fields>div').evaluateAll(rows=>Object.fromEntries(rows.map(row=>[row.querySelector('dt').textContent,row.querySelector('dd').textContent])));
      for(const [key,value] of Object.entries(fields)) assert.equal(value,String(records[i].payload[key]));
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    }
    await page.locator('[data-case="0"]').click();
    assert.equal(await page.locator('#contract-empty').isVisible(),true);
    assert.equal(await page.locator('#contract-fields>div').count(),0);
    await page.close();
  });
}
