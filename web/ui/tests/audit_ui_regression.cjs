// UI regression checks for the audit fixes (login error handling, honest dashboard,
// nameserver display, bulk import, tenant records route, audit page, viewer role).
//
// Needs a running stack: control API on :8080 and the UI (vite dev server with its
// /api proxy, or the nginx image). It expects two extra accounts to exist:
//   ui_editor / editorpass12 (role editor) and ui_viewer / viewerpass12 (role viewer)
// Run:  UI_BASE=http://127.0.0.1:5173 ADMIN_USER=... ADMIN_PASS=... node tests/audit_ui_regression.cjs
const { chromium } = require('playwright-core');
const BASE=process.env.UI_BASE||'http://127.0.0.1:5173';
const ADMIN_USER=process.env.ADMIN_USER||'admin', ADMIN_PASS=process.env.ADMIN_PASS||'Adm1n-Strong-Pw-77';
const API=process.env.API_BASE||'http://127.0.0.1:8080';
const crypto=require('crypto');
async function api(m,p,tok,body){const r=await fetch(API+p,{method:m,headers:{'content-type':'application/json',...(tok?{authorization:'Bearer '+tok}:{})},body:body?JSON.stringify(body):undefined});let j=null;try{j=await r.json()}catch(e){};return [r.status,j]}
function totp(secretB32){const A='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const c of secretB32.replace(/=+$/,''))bits+=A.indexOf(c).toString(2).padStart(5,'0');const key=Buffer.from(bits.match(/.{8}/g).map(b=>parseInt(b,2)));const ctr=Buffer.alloc(8);ctr.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const h=crypto.createHmac('sha1',key).update(ctr).digest();const o=h[19]&15;return String(((h.readUInt32BE(o)&0x7fffffff)%1000000)).padStart(6,'0')}
const os=require('os'), path=require('path'); const CSV=path.join(os.tmpdir(),'outis-bulk.csv');
const results=[]; const ok=(n,c,extra='')=>{results.push([c?'PASS':'FAIL',n,extra]); console.log((c?'PASS ':'FAIL ')+n+(extra?'  -- '+extra:''));};
async function login(page,u,p){
  await page.goto(BASE+'/login'); await page.fill('input[placeholder="Enter your username"]',u); await page.fill('input[placeholder="Enter your password"]',p);
  await page.click('button[type="submit"]'); 
}
(async()=>{
  const browser=await chromium.launch(); 
  const dialogs=[]; 
  // ---- 1. wrong password: stays on login with a credentials error, not "session expired"
  let ctx=await browser.newContext(); let page=await ctx.newPage(); page.on('dialog',d=>{dialogs.push(d.message()); d.accept()});
  await login(page,ADMIN_USER,'wrong-password'); await page.waitForTimeout(1500);
  const body=await page.textContent('body');
  ok('wrong password shows an error and stays on /login', page.url().includes('/login') && /invalid|failed|credentials/i.test(body), page.url());
  ok('wrong password is not reported as an expired session', !/session has expired/i.test(body));
  // ---- 2. admin login + dashboard honesty
  await login(page,ADMIN_USER,ADMIN_PASS); await page.waitForURL('**/admin**',{timeout:8000}).catch(()=>{});
  ok('admin lands on /admin', page.url().includes('/admin'), page.url());
  await page.waitForTimeout(1500);
  const dash=await page.textContent('body');
  ok('dashboard no longer shows the fabricated +12.5% query chart', !dash.includes("+12.5%") && /Query statistics are not configured|No query statistics/.test(dash));
  ok('dashboard has no Start/Stop server buttons', (await page.locator('button:has-text("Start"), button:has-text("Stop")').count())===0);
  // ---- 3. create a zone through the UI
  await page.goto(BASE+'/admin/zones'); await page.waitForTimeout(800);
  await page.fill('input[placeholder="example.com"]','ui-test.example'); 
  await page.click('button:has-text("Create")').catch(async()=>{await page.click('button.btn-primary')}); await page.waitForTimeout(2000);
  ok('zone created via UI appears in list', (await page.textContent('body')).includes('ui-test.example'));
  ok('zone list shows nameservers (not "No NS records")', !(await page.locator('tr:has-text("ui-test.example")').textContent()).includes('No NS records'));
  // ---- 4. records page + bulk import of a CSV with MX priority
  await page.locator('tr:has-text("ui-test.example") a').first().click(); await page.waitForTimeout(1500);
  ok('records page opened', /\/zones\/.+\/records/.test(page.url()), page.url());
  const csv='name,record_type,value,ttl,priority\nwww,A,192.0.2.1,300,\nmail,A,192.0.2.2,300,\n@,MX,mail.ui-test.example.,300,10\n@,TXT,v=spf1 mx -all,300,\n';
  require('fs').writeFileSync(CSV,csv);
  await page.setInputFiles('input[type=file]',CSV);
  await page.click('button:has-text("Import")'); await page.waitForTimeout(2500);
  ok('bulk import reports success', dialogs.some(d=>/Imported 4 record/.test(d)), JSON.stringify(dialogs.slice(-1)));
  const rec=await page.textContent('body');
  ok('imported records are listed', rec.includes('192.0.2.2') && rec.includes('mail.ui-test.example'));
  // ---- 5. users page: create an editor, appears with role
  await page.goto(BASE+'/admin/audit'); await page.waitForTimeout(1500);
  const audit=await page.textContent('body');
  ok('audit page lists real events (create_zone / import_zone)', /create_zone/.test(audit) && /import_zone/.test(audit));
  await ctx.close();
  // ---- 6. editor (tenant) sees only own zones and can open the records page under /user
  ctx=await browser.newContext(); page=await ctx.newPage(); page.on('dialog',d=>{dialogs.push(d.message()); d.accept()});
  await login(page,'ui_editor','editorpass12'); await page.waitForURL('**/user**',{timeout:8000}).catch(()=>{}); await page.waitForTimeout(1200);
  ok('editor lands on /user', page.url().includes('/user'), page.url());
  ok('editor does not see admin zone', !(await page.textContent('body')).includes('ui-test.example'));
  await page.fill('input[placeholder="example.com"]','editor-zone.example'); await page.click('button:has-text("Create")').catch(async()=>{await page.click('button.btn-primary')}); await page.waitForTimeout(2000);
  ok('editor created own zone', (await page.textContent('body')).includes('editor-zone.example'));
  await page.locator('tr:has-text("editor-zone.example") a').first().click(); await page.waitForTimeout(1500);
  ok('editor can open records page (/user/zones/:id/records)', /\/user\/zones\/.+\/records/.test(page.url()) && !page.url().includes('/login'), page.url());
  // add a record as owner (this used to be 403 for owners)
  const inputs=page.locator('input'); 
  await ctx.close();
  // ---- 7. viewer: can look, cannot create
  ctx=await browser.newContext(); page=await ctx.newPage(); page.on('dialog',d=>{dialogs.push(d.message()); d.accept()});
  await login(page,'ui_viewer','viewerpass12'); await page.waitForURL('**/user**',{timeout:8000}).catch(()=>{}); await page.waitForTimeout(1200);
  ok('viewer does not get a "create zone" form (permissions reflected in the UI)', (await page.locator('input[placeholder="example.com"]').count())===0);
  const vtok=await page.evaluate(()=>localStorage.getItem('token'));
  const [vst]=await api('POST','/api/v1/zones',vtok,{domain:'viewer-zone.example'});
  ok('and the API refuses a viewer-created zone', vst===403, String(vst));
  await ctx.close();

  // ---------- 8. new workflows ----------
  const [, lg] = await api('POST','/api/v1/auth/login',null,{username:ADMIN_USER,password:ADMIN_PASS}); const AT=lg.token;
  ctx=await browser.newContext(); page=await ctx.newPage(); page.on('dialog',d=>{dialogs.push(d.message()); d.accept()});
  await login(page,ADMIN_USER,ADMIN_PASS); await page.waitForURL('**/admin**',{timeout:8000}).catch(()=>{}); await page.waitForTimeout(2500);
  const dash2=await page.textContent('body');
  ok('dashboard shows publication status', /Publication/.test(dash2) && /Bundle v\d+/.test(dash2));
  ok('dashboard says query statistics are not configured (no fake numbers)', /Query statistics are not configured/.test(dash2));
  // audit page: real columns + paging controls
  await page.goto(BASE+'/admin/audit'); await page.waitForTimeout(1500);
  const rows=await page.locator('tbody tr').first().textContent();
  ok('audit rows show time, user and action (not blank)', /\d{4}/.test(rows) && /create_zone|import_zone|login/.test(rows), rows.slice(0,80));
  ok('audit page has paging', /Page 1 \/ \d+/.test(await page.textContent('body')));
  await page.fill('input[placeholder="action"]','import_zone'); await page.waitForTimeout(1200);
  const ab=await page.locator('tbody tr').allTextContents();
  ok('audit action filter is applied by the server', ab.length>0 && ab.every(t=>/import_zone/.test(t)), String(ab.length));
  // agents: register via API, toggle + sync from the UI
  const [, ag]=await api('POST','/api/v1/agents/register',AT,{name:'ui-agent',addr:'10.9.9.9:53'});
  await page.goto(BASE+'/admin/agents'); await page.waitForTimeout(1500);
  const card=page.locator('div:has(> div:has-text("ui-agent"))').first();
  ok('agent card shows configuration sync state', /Behind|In sync/.test(await page.textContent('body')));
  await page.locator('button:has-text("Disable")').first().click(); await page.waitForTimeout(1200);
  const [, al]=await api('GET','/api/v1/agents',AT); ok('Disable button really disables the agent', al.find(a=>a.id===ag.id).enabled===false);
  await page.locator('button:has-text("Enable")').first().click(); await page.waitForTimeout(1200);
  const [, al2]=await api('GET','/api/v1/agents',AT); ok('Enable button re-enables it', al2.find(a=>a.id===ag.id).enabled===true);
  await page.locator('button:has-text("Sync now")').first().click(); await page.waitForTimeout(1200);
  const [, al3]=await api('GET','/api/v1/agents',AT); ok('Sync now flags a sync request', al3.find(a=>a.id===ag.id).sync_requested===true);
  // sharing through the Manage dialog; the viewer then sees a read-only zone
  await page.goto(BASE+'/admin/zones'); await page.waitForTimeout(1500);
  await page.locator('tr:has-text("ui-test.example") button:has-text("Manage")').click(); await page.waitForTimeout(800);
  await page.fill('input[placeholder="username"]','ui_viewer'); await page.locator('button:has-text("Share")').click(); await page.waitForTimeout(1200);
  ok('zone shared with ui_viewer is listed in the dialog', (await page.textContent('body')).includes('ui_viewer'));
  await page.locator('button:has-text("History")').click(); await page.waitForTimeout(800);
  ok('history tab lists revisions', (await page.locator('tbody tr').count())>0 && /Restore/.test(await page.textContent('body')));
  await ctx.close();
  ctx=await browser.newContext(); page=await ctx.newPage();
  await login(page,'ui_viewer','viewerpass12'); await page.waitForURL('**/user**',{timeout:8000}).catch(()=>{}); await page.waitForTimeout(1800);
  ok('shared zone appears for the viewer, marked as shared', /ui-test\.example/.test(await page.textContent('body')) && /shared: viewer/.test(await page.textContent('body')));
  await page.locator('tr:has-text("ui-test.example") a').first().click(); await page.waitForTimeout(1500);
  ok('records page of a viewer-shared zone has no edit form or delete buttons', (await page.locator('button:has(svg.lucide-trash-2)').count())===0 && (await page.locator('button:has-text("Import")').count())===0);
  await ctx.close();
  // MFA: enrol through the API, then the login page asks for the code
  const [, mu]=await api('POST','/api/v1/users',AT,{username:'ui_mfa',password:'mfapass12345',role:'editor'});
  const [, ml]=await api('POST','/api/v1/auth/login',null,{username:'ui_mfa',password:'mfapass12345'});
  const [, su]=await api('POST','/api/v1/auth/mfa/setup',ml.token,{});
  await api('POST','/api/v1/auth/mfa/enable',ml.token,{code:totp(su.secret)});
  ctx=await browser.newContext(); page=await ctx.newPage();
  await login(page,'ui_mfa','mfapass12345'); await page.waitForTimeout(1500);
  ok('login asks for the authentication code after the password', await page.locator('input#otp').count()===1 && page.url().includes('/login'));
  await page.fill('input#otp',totp(su.secret)); await page.click('button[type="submit"]'); await page.waitForURL('**/user**',{timeout:8000}).catch(()=>{});
  ok('login completes with a valid code', page.url().includes('/user'), page.url());
  await ctx.close();
  await browser.close();
  const failed=results.filter(r=>r[0]==='FAIL'); console.log(`\n${results.length-failed.length}/${results.length} UI checks passed`); process.exit(failed.length?1:0);
})().catch(e=>{console.error('SCRIPT ERROR',e); process.exit(2)});
