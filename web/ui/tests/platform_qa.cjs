// Platform QA (browser, live stack from scripts/ui_stack.sh):
//  Nameservers / DNS Servers / GeoRules CRUD, bulk import, DNS Lookup for all 12 types (real DNS server),
//  tenants + quotas + members, tenant isolation, persistent analytics (admin + customer), authorization,
//  overview without per-zone requests, and overview performance with thousands of zones.
// Usage: source <stack>/env.sh; node tests/platform_qa.cjs     (playwright-core from the scratch copy via NODE_PATH)
const { chromium } = require('playwright-core');
const { execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');
const BASE = process.env.UI_BASE, API = process.env.API_BASE;
const ADMIN = [process.env.ADMIN_USER, process.env.ADMIN_PASS];
const STACK = process.env.STACK_DIR, DNS_PORT = process.env.DNS_PORT;
let pass = 0, fail = 0;
const ok = (n, c, x = '') => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + n + (x ? '  -- ' + String(x).slice(0, 220) : '')); };
async function api(m, p, tok, body) { const r = await fetch(API + p, { method: m, headers: { 'content-type': 'application/json', ...(tok ? { authorization: 'Bearer ' + tok } : {}) }, body: body ? JSON.stringify(body) : undefined }); let j = null; try { j = await r.json(); } catch (e) {} return [r.status, j, r.headers]; }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const psql = (sql) => execFileSync('docker', ['exec', process.env.PG_CONTAINER, 'psql', '-U', 'postgres', '-d', process.env.PG_DB, '-qtAc', sql]).toString().trim();
async function login(page, u, p) {
  await page.goto(BASE + '/login'); await page.fill('input[placeholder="Enter your username"]', u); await page.fill('input[placeholder="Enter your password"]', p);
  await page.click('button[type="submit"]'); await page.waitForURL(/\/(admin|user)/, { timeout: 10000 }).catch(() => {});
}
const body = (page) => page.textContent('body');
const confirmYes = async (page) => { await page.click('[data-testid="confirm-yes"]'); };
async function waitFor(fn, ms = 15000, step = 500) { const t = Date.now(); while (Date.now() - t < ms) { try { const v = await fn(); if (v) return v; } catch (e) {} await sleep(step); } return null; }

(async () => {
  const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  const [, lg] = await api('POST', '/api/v1/auth/login', null, { username: ADMIN[0], password: ADMIN[1] });
  const AT = lg.token;
  const mkUser = async (name, role) => { await api('POST', '/api/v1/users', AT, { username: name, password: 'Customer-Pw-12345', role }); const [, l] = await api('POST', '/api/v1/auth/login', null, { username: name, password: 'Customer-Pw-12345' }); return l.token; };
  const ctx = await browser.newContext({ viewport: { width: 1360, height: 900 } }); const page = await ctx.newPage();
  await login(page, ...ADMIN);

  // ===== 1. Nameservers CRUD
  await page.goto(BASE + '/admin/nameservers'); await page.waitForSelector('h1');
  await page.locator('button:has-text("Add")').first().click().catch(async () => { await page.locator('button.btn-primary').first().click(); });
  await page.fill('input[placeholder="e.g., ns1.example.com"]', 'qa-ns1.example.net'); await page.fill('input[placeholder="e.g., 192.0.2.1"]', '192.0.2.53');
  await page.click('button:has-text("Create")'); await page.waitForTimeout(1200);
  ok('nameservers: created via UI and listed', (await body(page)).includes('qa-ns1.example.net'));
  const [, nsList] = await api('GET', '/api/v1/nameservers', AT); const ns = nsList.find((n) => n.hostname === 'qa-ns1.example.net');
  ok('nameservers: persisted by the API with the entered IP', ns && ns.ip_address === '192.0.2.53');
  await page.click('button[aria-label^="Edit qa-ns1.example.net"]'); await page.waitForTimeout(300);
  await page.fill('input[placeholder="e.g., ns1.example.com"]', 'qa-ns1b.example.net'); await page.click('button:has-text("Update")'); await page.waitForTimeout(1200);
  ok('nameservers: edit saved', (await body(page)).includes('qa-ns1b.example.net') && !(await body(page)).includes('qa-ns1.example.net'));
  await page.click('button[aria-label^="Delete qa-ns1b.example.net"]'); await confirmYes(page); await page.waitForTimeout(1200);
  ok('nameservers: delete asks for confirmation and removes the row', !(await body(page)).includes('qa-ns1b.example.net'));
  const [, nsAfter] = await api('GET', '/api/v1/nameservers', AT); ok('nameservers: gone in the API', !nsAfter.some((n) => n.hostname.startsWith('qa-ns1')));
  await page.goto(BASE + '/admin/nameservers'); await page.locator('button.btn-primary').first().click();
  await page.click('button:has-text("Create")'); await page.waitForTimeout(600);
  ok('nameservers: empty form is rejected with a message', /required/i.test(await body(page)));

  // ===== 2. DNS Servers CRUD
  await page.goto(BASE + '/admin/servers'); await page.waitForSelector('h1');
  await page.locator('button.btn-primary').first().click();
  await page.fill('input[placeholder="e.g., US-East-1 Primary"]', 'qa-server-1'); await page.fill('input[placeholder="e.g., 192.168.1.10"]', '127.0.0.1'); await page.fill('input[placeholder="e.g., us-east"]', 'qa-region');
  await page.click('button:has-text("Create Server")'); await page.waitForTimeout(1500);
  ok('servers: created and listed', (await body(page)).includes('qa-server-1'));
  const [, svs] = await api('GET', '/api/v1/servers', AT); const sv = svs.find((s) => s.name === 'qa-server-1');
  ok('servers: API reports a real probe status (not invented)', sv && ['running', 'stopped', 'unknown', 'error', 'unreachable'].includes(sv.status), sv && sv.status);
  await page.click('button[aria-label="Delete qa-server-1"]'); await confirmYes(page); await page.waitForTimeout(1200);
  ok('servers: delete (with confirmation) removes it', !(await body(page)).includes('qa-server-1'));

  // ===== 3. GeoRules CRUD (zone with GeoDNS enabled)
  const [, gz] = await api('POST', '/api/v1/zones', AT, { domain: 'geo-qa.example', geodns_enabled: true }); const geoZone = gz.id || gz.data?.id;
  await api('POST', `/api/v1/zones/${geoZone}/records`, AT, { name: 'www', record_type: 'A', value: '192.0.2.5', ttl: 300 });
  await page.goto(BASE + '/admin/georules'); await page.waitForSelector('h1'); await page.waitForTimeout(800);
  await page.selectOption('select >> nth=0', { label: 'geo-qa.example' });
  await page.selectOption('select >> nth=1', 'city');
  ok('georules: City is offered as a match type (backend supports it)', true);
  await page.fill('input[placeholder^="e.g., US, EU"]', 'DE:Berlin'); await page.fill('input[placeholder="e.g., 192.0.2.1"]', '192.0.2.77');
  await page.fill('input[placeholder="optional"]', 'www'); await page.fill('input[placeholder="e.g., A, AAAA"]', 'A');
  await page.click('button:has-text("Add Rule")'); await page.waitForTimeout(1500);
  const [, rules] = await api('GET', '/api/v1/georules', AT); const rule = rules.find((r) => r.match_type === 'city');
  ok('georules: city rule created through the UI', rule && rule.match_value === 'DE:Berlin' && rule.target === '192.0.2.77', JSON.stringify(rule));
  ok('georules: rule is listed on the page', (await body(page)).includes('DE:Berlin'));
  await page.click('button[aria-label="Edit rule DE:Berlin"]'); await page.waitForTimeout(300);
  await page.fill('input[placeholder="e.g., 192.0.2.1"]', '192.0.2.88'); await page.click('button:has-text("Update Rule")'); await page.waitForTimeout(1500);
  const [, rules2] = await api('GET', '/api/v1/georules', AT); ok('georules: edit saved', rules2.some((r) => r.target === '192.0.2.88'));
  await page.click('button[aria-label="Delete rule DE:Berlin"]'); await confirmYes(page); await page.waitForTimeout(1200);
  const [, rules3] = await api('GET', '/api/v1/georules', AT); ok('georules: delete (with confirmation) removes the rule', !rules3.some((r) => r.match_type === 'city'));

  // ===== 4. Bulk import (UI): success, then validation failure keeps the zone unchanged
  const [, bz] = await api('POST', '/api/v1/zones', AT, { domain: 'bulk-qa.example', geodns_enabled: false }); const bulkZone = bz.id || bz.data?.id;
  await page.goto(BASE + `/admin/zones/${bulkZone}/records`); await page.waitForSelector('input[type=file]', { state: 'attached' });
  const csv = path.join(os.tmpdir(), 'qa-bulk.csv'); fs.writeFileSync(csv, 'name,record_type,value,ttl,priority\nwww,A,192.0.2.1,300,\nmail,A,192.0.2.2,300,\n@,MX,mail.bulk-qa.example.,300,10\n@,TXT,v=spf1 mx -all,300,\n');
  await page.setInputFiles('input[type=file]', csv); await page.click('button:has-text("Import")'); await page.waitForTimeout(2500);
  ok('bulk import: success toast with the number of records', /Imported 4 record/.test(await body(page)));
  const [, brecs] = await api('GET', `/api/v1/zones/${bulkZone}/records`, AT); ok('bulk import: records are in the API', brecs.length >= 4 && brecs.some((r) => r.record_type === 'MX'));
  const before = brecs.length; fs.writeFileSync(csv, 'name,record_type,value,ttl,priority\nok1,A,192.0.2.9,300,\nbad,A,not-an-ip,300,\n');
  await page.setInputFiles('input[type=file]', csv); await page.click('button:has-text("Import")'); await page.waitForTimeout(2000);
  const [, brecs2] = await api('GET', `/api/v1/zones/${bulkZone}/records`, AT);
  ok('bulk import: an invalid row rejects the whole file (fail-fast, nothing half-imported)', brecs2.length === before && /failed|invalid/i.test(await body(page)), `${before} -> ${brecs2.length}`);

  // ===== 5. DNS Lookup in the browser: every advertised type against the REAL DNS server
  const mk = async (d) => { const [, z] = await api('POST', '/api/v1/zones', AT, { domain: d, geodns_enabled: false }); return z.id || z.data?.id; };
  const P = await mk('lkp.test'), C = await mk('child.lkp.test');
  const rec = (z, name, t, v, ttl = 300) => api('POST', `/api/v1/zones/${z}/records`, AT, { name, record_type: t, value: v, ttl });
  await rec(C, 'www', 'A', '192.0.2.10', 301); await rec(C, 'www', 'AAAA', '2001:db8::10', 302); await rec(C, '@', 'MX', '10 mail.child.lkp.test.', 303); await rec(C, 'mail', 'A', '192.0.2.25');
  await rec(C, 'txt', 'TXT', 'v=spf1 mx -all', 304); await rec(C, 'alias', 'CNAME', 'www.child.lkp.test.', 306); await rec(C, '_sip._tcp', 'SRV', '5 6 5060 sip.child.lkp.test.', 308); await rec(C, 'sip', 'A', '192.0.2.30');
  await rec(C, 'ptr', 'PTR', 'host.child.lkp.test.', 309); await rec(C, '@', 'CAA', '0 issue "letsencrypt.org"', 310);
  await rec(P, 'child', 'NS', 'ns1.example.test.');
  const [, en] = await api('POST', `/api/v1/zones/${C}/dnssec/enable`, AT, {}); const ds = en.keys[0].ds[0].text.replace(/^.* IN DS /, '');
  await rec(P, 'child', 'DS', ds, 312);
  await api('POST', `/api/v1/zones/${P}/dnssec/enable`, AT, {});
  const served = await waitFor(async () => { const [s, j] = await api('POST', '/api/v1/dns/lookup', AT, { domain: 'www.child.lkp.test', record_type: 'A' }); return s === 200 && j.records.length === 1 && j; }, 20000);
  ok('lookup: the real DNS server picked the new zones up (hot reload)', !!served);
  const cases = [
    ['A', 'www.child.lkp.test', '192.0.2.10', 301], ['AAAA', 'www.child.lkp.test', '2001:db8::10', 302], ['MX', 'child.lkp.test', 'mail.child.lkp.test.', 303],
    ['TXT', 'txt.child.lkp.test', 'v=spf1 mx -all', 304], ['NS', 'child.lkp.test', 'ns', null], ['CNAME', 'alias.child.lkp.test', 'www.child.lkp.test.', 306],
    ['SOA', 'child.lkp.test', 'hostmaster', null], ['SRV', '_sip._tcp.child.lkp.test', 'sip.child.lkp.test.', 308], ['PTR', 'ptr.child.lkp.test', 'host.child.lkp.test.', 309],
    ['CAA', 'child.lkp.test', 'letsencrypt.org', 310], ['DNSKEY', 'child.lkp.test', '257 3 13', null], ['DS', 'child.lkp.test', '13 2', null],
  ];
  await page.goto(BASE + '/admin/dns-lookup'); await page.waitForSelector('input[aria-label="Domain name or IP address"]');
  const optionTypes = await page.$$eval('select[aria-label="Record type"] option', (o) => o.map((x) => x.value));
  ok('lookup: the selector offers exactly the 12 supported types', optionTypes.join() === 'A,AAAA,MX,TXT,NS,CNAME,SOA,SRV,PTR,DNSKEY,DS,CAA', optionTypes.join());
  for (const [t, name, needle, ttl] of cases) {
    await page.fill('input[aria-label="Domain name or IP address"]', name); await page.selectOption('select[aria-label="Record type"]', t);
    await page.click('button:has-text("Lookup")'); await page.waitForSelector('[data-testid="lookup-status"]', { timeout: 8000 }).catch(() => {});
    await page.waitForFunction((t) => document.querySelector('[data-testid="lookup-summary"]')?.textContent.includes(t), t, { timeout: 8000 }).catch(() => {});
    const st = await page.textContent('[data-testid="lookup-status"]').catch(() => ''); const vals = await page.$$eval('[data-testid="lookup-value"]', (e) => e.map((x) => x.textContent));
    const ttlTxt = await page.locator('text=/TTL: \\d+/').first().textContent().catch(() => '');
    ok(`lookup UI ${t}: NOERROR with the real value`, st === 'NOERROR' && vals.some((v) => v.toLowerCase().includes(needle.toLowerCase())) && (ttl == null || ttlTxt.includes('TTL: ' + ttl)), `${st} ${vals.join(' | ').slice(0, 90)} ${ttlTxt}`);
  }
  await page.fill('input[aria-label="Domain name or IP address"]', 'nope.child.lkp.test'); await page.selectOption('select[aria-label="Record type"]', 'A'); await page.click('button:has-text("Lookup")');
  await page.waitForFunction(() => document.querySelector('[data-testid="lookup-status"]')?.textContent === 'NXDOMAIN', null, { timeout: 8000 }).catch(() => {});
  ok('lookup UI: NXDOMAIN is shown as such, with no records', (await page.textContent('[data-testid="lookup-status"]')) === 'NXDOMAIN' && (await page.$$('[data-testid="lookup-value"]')).length === 0);
  await page.fill('input[aria-label="Domain name or IP address"]', 'www.child.lkp.test'); await page.selectOption('select[aria-label="Record type"]', 'MX'); await page.click('button:has-text("Lookup")');
  await page.waitForSelector('[data-testid="lookup-empty"]', { timeout: 8000 }).catch(() => {});
  ok('lookup UI: NODATA explained honestly', /no MX records/.test(await page.textContent('[data-testid="lookup-empty"]').catch(() => '')));
  await page.fill('input[aria-label="Domain name or IP address"]', ''); await page.click('button:has-text("Lookup")'); await page.waitForTimeout(300);
  ok('lookup UI: empty input is rejected client-side', /enter a domain/i.test(await body(page)));

  // ===== 6. Customers, tenants, quotas, isolation
  const alice = await mkUser('qa_alice', 'editor'), carol = await mkUser('qa_carol', 'editor'); const viewer = await mkUser('qa_viewer2', 'viewer');
  const [s1] = await api('POST', '/api/v1/zones', alice, { domain: 'alice-qa.example' }); const [s2] = await api('POST', '/api/v1/zones', carol, { domain: 'carol-qa.example' });
  ok('tenants: customers get a personal tenant when creating their first zone', s1 === 201 && s2 === 201);
  fs.writeFileSync(path.join(STACK, 'zones.txt'), 'alice-qa.example\ncarol-qa.example\n');   // feeds the metrics stub
  await page.goto(BASE + '/admin/tenants'); await page.waitForSelector('[data-testid="tenants-table"]'); await page.waitForTimeout(500);
  const trow = (n) => page.locator(`tr:has-text("${n}")`);
  ok('tenants page lists both personal tenants with usage', (await trow('personal-qa_alice').count()) === 1 && (await trow('personal-qa_carol').count()) === 1);
  await page.click('button:has-text("New tenant")'); await page.fill('#t-name', 'Acme Corp'); await page.fill('#t-zones', '3'); await page.fill('#t-records', '50'); await page.click('button:has-text("Save")'); await page.waitForTimeout(1000);
  ok('tenants: create with quotas via UI', (await trow('Acme Corp').count()) === 1 && /3/.test(await trow('Acme Corp').textContent()));
  await page.click('button[aria-label="Edit Acme Corp"]'); await page.fill('#t-zones', ''); await page.click('button:has-text("Save")'); await page.waitForTimeout(1000);
  ok('tenants: clearing a quota makes it unlimited', /unlimited/.test(await trow('Acme Corp').textContent()));
  await page.click('button[aria-label="Members of Acme Corp"]'); await page.waitForSelector('[data-testid="members-table"]');
  await page.fill('#m-user', 'qa_carol'); await page.selectOption('#m-role', 'viewer'); await page.click('button:has-text("Add member")'); await page.waitForTimeout(800);
  ok('tenants: member added with a role', /qa_carol/.test(await page.textContent('[data-testid="members-table"]')));
  await page.click('button[aria-label="Remove qa_carol"]'); await confirmYes(page); await page.waitForTimeout(800);
  ok('tenants: member removed after confirmation', !/qa_carol/.test(await page.textContent('[data-testid="members-table"]')));
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);
  await page.click('button[aria-label="Delete Acme Corp"]'); await confirmYes(page); await page.waitForTimeout(900);
  ok('tenants: delete (empty tenant) works', (await trow('Acme Corp').count()) === 0);
  // quota for alice: 2 zones
  const [, tl] = await api('GET', '/api/v1/tenants', AT); const at = tl.find((t) => t.name === 'personal-qa_alice');
  await page.click('button[aria-label="Edit personal-qa_alice"]'); await page.fill('#t-zones', '2'); await page.click('button:has-text("Save")'); await page.waitForTimeout(900);
  ok('tenants: admin lowers a customer quota in the UI', (await api('GET', '/api/v1/tenants', AT))[1].find((t) => t.id === at.id).max_zones === 2);

  const actx = await browser.newContext({ viewport: { width: 1360, height: 900 } }); const apg = await actx.newPage(); await login(apg, 'qa_alice', 'Customer-Pw-12345');
  await apg.goto(BASE + '/user'); await apg.waitForSelector('[data-testid="user-overview"]'); await apg.waitForTimeout(800);
  ok('quota card shows zones used / limit on the customer overview', /1 \/ 2/.test(await apg.textContent('[data-testid="quota-zones"]')));
  await apg.goto(BASE + '/user/zones'); await apg.waitForSelector('input[placeholder="example.com"]');
  await apg.fill('input[placeholder="example.com"]', 'alice-two.example'); await apg.click('button:has-text("Create Zone")'); await apg.waitForSelector('text=alice-two.example', { timeout: 10000 }).catch(() => {});
  ok('quota: second zone allowed', (await body(apg)).includes('alice-two.example'));
  await apg.fill('input[placeholder="example.com"]', 'alice-three.example'); await apg.click('button:has-text("Create Zone")');
  const quotaToast = await apg.waitForSelector('text=/Quota reached/', { timeout: 10000 }).then((e) => e.textContent()).catch(() => '');
  ok('quota: third zone refused with a clear message', /Quota reached/.test(quotaToast) && !(await body(apg)).includes('alice-three.example'), quotaToast);
  await apg.goto(BASE + '/user'); await apg.waitForSelector('[data-testid="quota-zones"]'); await apg.waitForTimeout(600);
  ok('quota card now shows 2 / 2', /2 \/ 2/.test(await apg.textContent('[data-testid="quota-zones"]')));
  // isolation in the browser
  const [, cz] = await api('GET', '/api/v1/zones', carol); const carolZone = cz.data.find((z) => z.domain === 'carol-qa.example').id;
  await apg.goto(BASE + `/user/zones/${carolZone}/records`); await apg.waitForTimeout(1500);
  ok("isolation: alice cannot open carol's zone records (no data shown)", !(await body(apg)).includes('carol-qa.example') || /denied|forbidden|not allowed|failed/i.test(await body(apg)));
  await apg.goto(BASE + '/admin/tenants'); await apg.waitForTimeout(800);
  ok('authorization: a customer opening /admin/tenants is redirected to /user', apg.url().includes('/user') && !apg.url().includes('/admin'), apg.url());
  ok('isolation: alice\'s overview never mentions carol', !(await (async () => { await apg.goto(BASE + '/user'); await apg.waitForTimeout(800); return body(apg); })()).includes('carol-qa'));

  // ===== 7. Analytics (collector reads the deterministic Prometheus stub every 2 s)
  await sleep(9000);
  await apg.goto(BASE + '/user/analytics'); await apg.waitForSelector('[data-testid="analytics-history"]'); await apg.waitForTimeout(1500);
  const aTop = await apg.textContent('[data-testid="top-zones"]').catch(() => '');
  ok('analytics (customer): own zone listed with query counts, other tenants absent', aTop.includes('alice-qa.example') && !aTop.includes('carol-qa'), aTop.slice(0, 120));
  ok('analytics (customer): a chart is drawn from persisted history', (await apg.locator('[data-testid="queries-chart"] svg').count()) > 0);
  const [, aApi] = await api('GET', '/api/v1/analytics/tenant?range=1h', alice); const [, cApi] = await api('GET', '/api/v1/analytics/tenant?range=1h', carol);
  ok('analytics (API): counts are exact multiples of the stub increments (10 ok + 1 error per scrape)', aApi.total_queries > 0 && aApi.total_queries % 11 === 0 && cApi.total_queries > 0, `${aApi.total_queries} / ${cApi.total_queries}`);
  ok('analytics (API): tenants are disjoint', aApi.zones.every((z) => z.domain.startsWith('alice')) && cApi.zones.every((z) => z.domain.startsWith('carol')));
  await apg.selectOption('#an-range', '7d'); await apg.waitForTimeout(1200);
  ok('analytics (customer): range filter reloads data', (await apg.locator('[data-testid="top-zones"]').count()) === 1);
  await page.goto(BASE + '/admin/metrics'); await page.waitForSelector('[data-testid="analytics-history"]'); await page.waitForTimeout(1500);
  const adminTop = await page.textContent('[data-testid="top-zones"]');
  ok('analytics (admin): global view lists zones of every tenant', adminTop.includes('alice-qa.example') && adminTop.includes('carol-qa.example'));
  const tid = (await api('GET', '/api/v1/tenants', AT))[1].find((t) => t.name === 'personal-qa_carol').id;
  await page.selectOption('#an-tenant', tid); await page.waitForTimeout(1500);
  const filtered = await page.textContent('[data-testid="top-zones"]');
  ok('analytics (admin): tenant filter narrows to that tenant', filtered.includes('carol-qa.example') && !filtered.includes('alice-qa.example'));
  const [gs, gl] = await api('GET', '/api/v1/analytics/global?range=1h', AT);
  ok('analytics (admin): global request counter includes unattributed requests', gs === 200 && gl.total > aApi.total_queries, `${gl.total}`);
  ok('analytics (API): customers cannot read the global view', (await api('GET', '/api/v1/analytics/global', alice))[0] === 403);

  // ===== 8. Viewer and authorization checks in the browser
  const vctx = await browser.newContext(); const vpg = await vctx.newPage(); await login(vpg, 'qa_viewer2', 'Customer-Pw-12345');
  await vpg.goto(BASE + '/user/dns-lookup'); await vpg.fill('input[aria-label="Domain name or IP address"]', 'www.child.lkp.test'); await vpg.click('button:has-text("Lookup")');
  ok('viewer: read-only account can run DNS lookups', !!(await vpg.waitForSelector('[data-testid="lookup-status"]', { timeout: 8000 }).catch(() => null)));
  const [vs] = await api('POST', '/api/v1/zones', viewer, { domain: 'viewer-should-fail.example' }); ok('viewer: cannot create zones', vs === 403);
  ok('authorization: customers get 403 on infrastructure endpoints', (await api('GET', '/api/v1/agents', alice))[0] === 403 && (await api('GET', '/api/v1/servers', alice))[0] === 403 && (await api('GET', '/api/v1/tenants', null))[0] === 401);

  // ===== 9. Overview: no per-zone requests, then scale with thousands of zones
  const reqs = []; const spy = (pg) => pg.on('request', (r) => { const u = r.url(); if (u.includes('/api/')) reqs.push(u.replace(BASE, '')); });
  const octx = await browser.newContext({ viewport: { width: 1360, height: 900 } }); const opg = await octx.newPage(); spy(opg); await login(opg, ...ADMIN);
  await opg.goto(BASE + '/admin'); await opg.waitForSelector('[data-testid="admin-overview"]'); await opg.waitForTimeout(2500);
  const perZone = reqs.filter((u) => /\/zones\/[0-9a-f-]{36}\/records/.test(u));
  ok('admin overview: ZERO per-zone /records requests (N+1 removed)', perZone.length === 0 && reqs.filter((u) => u.includes('/api/v1/overview')).length >= 1, `${perZone.length} per-zone, overview calls=${reqs.filter((u) => u.includes('/api/v1/overview')).length}`);
  reqs.length = 0; const cctx = await browser.newContext({ viewport: { width: 1360, height: 900 } }); const cpg = await cctx.newPage(); spy(cpg); await login(cpg, 'qa_alice', 'Customer-Pw-12345');
  await cpg.goto(BASE + '/user'); await cpg.waitForSelector('[data-testid="user-overview"]'); await cpg.waitForTimeout(2000);
  ok('customer overview: ZERO per-zone /records requests', reqs.filter((u) => /\/zones\/[0-9a-f-]{36}\/records/.test(u)).length === 0 && reqs.filter((u) => u.includes('/api/v1/overview')).length >= 1);
  psql("INSERT INTO zones (id, domain, owner, tenant_id) SELECT gen_random_uuid(), 'perf' || g || '.example', NULL, NULL FROM generate_series(1, 5000) g");
  psql("INSERT INTO records (id, zone_id, name, record_type, value, ttl) SELECT gen_random_uuid(), z.id, 'h' || g, 'A', '192.0.2.' || (g % 250 + 1), 300 FROM zones z, generate_series(1, 8) g WHERE z.domain LIKE 'perf%'");
  const t0 = Date.now(); const [ps, pj] = await api('GET', '/api/v1/overview?limit=0', AT); const apiMs = Date.now() - t0;
  ok('performance: admin overview API over 5,000+ zones / 40,000+ records', ps === 200 && pj.zones_total >= 5000 && pj.records_total >= 40000 && apiMs < 2500, `${pj.zones_total} zones, ${pj.records_total} records, ${apiMs} ms`);
  const t1 = Date.now(); await opg.goto(BASE + '/admin'); await opg.waitForFunction(() => /5,?0\d\d/.test(document.querySelector('[data-testid="admin-overview"]')?.textContent || ''), null, { timeout: 15000 }).catch(() => {});
  const uiMs = Date.now() - t1; ok('performance: admin overview page renders 5,000+ zones quickly', uiMs < 5000, `${uiMs} ms`);
  const t2 = Date.now(); const [, small] = await api('GET', '/api/v1/overview', alice); const custMs = Date.now() - t2;
  ok('performance: customer overview stays fast and scoped while 5,000 other zones exist', small.zones_total === 2 && custMs < 500, `${small.zones_total} zones, ${custMs} ms`);
  psql("DELETE FROM records WHERE zone_id IN (SELECT id FROM zones WHERE domain LIKE 'perf%'); DELETE FROM zones WHERE domain LIKE 'perf%'");

  await browser.close();
  console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(2); });
