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
const TEST_DOMAINS = ['geo-qa.example', 'bulk-qa.example', 'lkp.test', 'child.lkp.test', 'alice-qa.example', 'carol-qa.example', 'alice-two.example', 'alice-three.example', 'alice-four.example', 'alice-api-bypass.example', 'viewer-should-fail.example', 'xfer-one.example', 'xfer-two.example'];
const domainList = TEST_DOMAINS.map((d) => `'${d}'`).join(',');
function cleanupTestData() {
  try {
    psql(`DELETE FROM zone_query_samples WHERE domain IN (${domainList}) OR domain LIKE 'perf%'`);
    psql(`DELETE FROM zone_qtype_samples WHERE domain IN (${domainList}) OR domain LIKE 'perf%'`);
    psql(`DELETE FROM zone_country_samples WHERE domain IN (${domainList}) OR domain LIKE 'perf%'`);
    psql(`DELETE FROM tenant_usage_samples WHERE tenant_id IN (SELECT id FROM tenants WHERE name IN ('Acme Corp', 'Transfer Target') OR name LIKE 'personal-qa\_%')`);
    psql(`DELETE FROM zones WHERE domain IN (${domainList}) OR domain LIKE 'perf%.example'`);
    psql("DELETE FROM tenants WHERE name IN ('Acme Corp', 'Transfer Target') OR name LIKE 'personal-qa\_%'");
    psql("DELETE FROM users WHERE username IN ('qa_alice', 'qa_carol', 'qa_viewer2')");
    psql("DELETE FROM nameservers WHERE hostname LIKE 'qa-ns1%'");
    psql("DELETE FROM servers WHERE name LIKE 'qa-server-1%'");
  } catch (e) { console.error('cleanup:', e.message); }
}
async function login(page, u, p) {
  await page.goto(BASE + '/login'); await page.fill('input[placeholder="Enter your username"]', u); await page.fill('input[placeholder="Enter your password"]', p);
  await page.click('button[type="submit"]'); await page.waitForURL(/\/(admin|user)/, { timeout: 10000 }).catch(() => {});
}
const body = (page) => page.textContent('body');
const confirmYes = async (page) => { await page.click('[data-testid="confirm-yes"]'); };
async function waitFor(fn, ms = 15000, step = 500) { const t = Date.now(); while (Date.now() - t < ms) { try { const v = await fn(); if (v) return v; } catch (e) {} await sleep(step); } return null; }
const percentile = (values, p) => { const a = [...values].sort((x, y) => x - y); return a[Math.min(a.length - 1, Math.max(0, Math.ceil((p / 100) * a.length) - 1))]; };
function apiMemoryKb() {
  try {
    const pids = execFileSync('pgrep', ['-x', 'control_api']).toString().trim().split(/\s+/).filter(Boolean);
    const rss = pids.map((pid) => Number(execFileSync('ps', ['-o', 'rss=', '-p', pid]).toString().trim())).filter(Number.isFinite);
    return rss.length ? Math.max(...rss) : null;
  } catch (e) { return null; }
}

(async () => {
  cleanupTestData();
  const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  try {
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
  const [, brecs] = await api('GET', `/api/v1/zones/${bulkZone}/records`, AT); const bulkRecs = Array.isArray(brecs) ? brecs : []; ok('bulk import: records are in the API', bulkRecs.length >= 4 && bulkRecs.some((r) => r.record_type === 'MX'));
  const before = bulkRecs.length; fs.writeFileSync(csv, 'name,record_type,value,ttl,priority\nok1,A,192.0.2.9,300,\nbad,A,not-an-ip,300,\n');
  await page.setInputFiles('input[type=file]', csv); await page.click('button:has-text("Import")'); await page.waitForTimeout(2000);
  const [, brecs2] = await api('GET', `/api/v1/zones/${bulkZone}/records`, AT); const bulkAfter = Array.isArray(brecs2) ? brecs2 : [];
  ok('bulk import: an invalid row rejects the whole file (fail-fast, nothing half-imported)', bulkAfter.length === before && /failed|invalid/i.test(await body(page)), `${before} -> ${bulkAfter.length}`);

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
  // hot reload must also publish updates and deletions, not just new zones
  const [, lookupRecs] = await api('GET', `/api/v1/zones/${C}/records`, AT); const wwwA = lookupRecs.find((r) => r.name === 'www' && r.record_type === 'A');
  await api('PUT', `/api/v1/zones/${C}/records/${wwwA.id}`, AT, { name: 'www', record_type: 'A', value: '192.0.2.99', ttl: 311 });
  const updated = await waitFor(async () => { const [st, j] = await api('POST', '/api/v1/dns/lookup', AT, { domain: 'www.child.lkp.test', record_type: 'A' }); return st === 200 && j.records.length === 1 && j.records[0].value === '192.0.2.99' && j.records[0].ttl === 311 && j; }, 20000);
  ok('lookup: record updates are published by hot reload', !!updated, updated ? JSON.stringify(updated.records[0]) : 'timeout');
  await api('DELETE', `/api/v1/zones/${C}/records/${wwwA.id}`, AT);
  const deleted = await waitFor(async () => { const [st, j] = await api('POST', '/api/v1/dns/lookup', AT, { domain: 'www.child.lkp.test', record_type: 'A' }); return st === 200 && j.records.length === 0 && j; }, 20000);
  ok('lookup: record deletions are published by hot reload', !!deleted);

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
  const [bypass] = await api('POST', '/api/v1/zones', alice, { domain: 'alice-api-bypass.example' });
  ok('quota: API creation is refused too (no UI-only bypass)', bypass === 403);
  const [, aliceZones] = await api('GET', '/api/v1/zones', alice); const aliceZone = aliceZones.data.find((z) => z.domain === 'alice-qa.example');
  const usedRecords = Number(psql(`SELECT count(*) FROM records r JOIN zones z ON z.id = r.zone_id JOIN tenants t ON t.id = z.tenant_id WHERE t.name = 'personal-qa_alice'`));
  await api('PUT', `/api/v1/tenants/${at.id}`, AT, { name: at.name, max_zones: 2, max_records: usedRecords + 1 });
  const [rec1] = await api('POST', `/api/v1/zones/${aliceZone.id}/records`, alice, { name: 'quota-one', record_type: 'A', value: '192.0.2.1', ttl: 300 });
  const [rec2] = await api('POST', `/api/v1/zones/${aliceZone.id}/records`, alice, { name: 'quota-two', record_type: 'A', value: '192.0.2.2', ttl: 300 });
  ok('quota: records quota is enforced with a clear 403', (rec1 === 200 || rec1 === 201) && rec2 === 403, `${rec1} / ${rec2}, quota ${usedRecords + 1}`);
  await api('PUT', `/api/v1/tenants/${at.id}`, AT, { name: at.name, max_zones: 2, max_records: null });
  const aliceTwo = aliceZones.data.find((z) => z.domain === 'alice-two.example');
  const [del] = await api('DELETE', `/api/v1/zones/${aliceTwo.id}`, alice);
  const [recreate] = await api('POST', '/api/v1/zones', alice, { domain: 'alice-four.example' });
  ok('quota: deleting a zone releases its quota slot', del === 200 && recreate === 201);
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
  // record-type and country breakdowns (stub emits 6 A + 4 MX and 7 DE + 2 private + 1 unknown per scrape and zone)
  const bdA = aApi.breakdown, bdC = cApi.breakdown;
  const q = (b, t) => (b.qtypes.find((x) => x.qtype === t) || {}).queries || 0;
  ok('breakdown (API): record types keep the 6:4 ratio emitted by the exporter', q(bdA, 'A') > 0 && q(bdA, 'A') * 4 === q(bdA, 'MX') * 6, `${q(bdA, 'A')}:${q(bdA, 'MX')}`);
  ok('breakdown (API): countries are DE / private / unknown only, labelled honestly', bdA.countries.some((c) => c.code === 'DE') && bdA.countries.some((c) => c.kind === 'private') && bdA.countries.some((c) => c.kind === 'unknown') && !bdA.countries.some((c) => c.kind === 'no_geoip'));
  await apg.waitForSelector('[data-testid="breakdowns"]'); await apg.waitForTimeout(500);
  ok('breakdown (customer UI): record-type chart shows A and MX from the database', /A/.test(await apg.textContent('[data-testid="qtype-chart"]')) && /MX/.test(await apg.textContent('[data-testid="qtype-chart"]')));
  const ctext = await apg.textContent('[data-testid="country-chart"]');
  ok('breakdown (customer UI): countries list DE and explains private / unknown', /DE/.test(ctext) && /Private \/ reserved/.test(ctext) && /Not found in the GeoIP database/.test(ctext));
  ok('breakdown (customer UI): GeoIP database age is shown from the exporter data', /GeoIP database \d+ days old/.test(await apg.textContent('body')));
  await apg.selectOption('#an-interval', '1h'); await apg.waitForTimeout(1000);
  ok('analytics (customer): interval filter reloads data', (await apg.locator('[data-testid="queries-chart"]').count()) === 1);
  await page.goto(BASE + '/admin/metrics'); await page.waitForSelector('[data-testid="breakdowns"]'); await page.waitForTimeout(800);
  ok('breakdown (admin UI): global view shows both charts', (await page.locator('[data-testid="qtype-chart"]').count()) === 1 && /DE/.test(await page.textContent('[data-testid="country-chart"]')));
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
  ok('analytics (API): an unsupported interval is rejected', (await api('GET', '/api/v1/analytics/tenant?range=1h&interval=2m', alice))[0] === 400);
  ok('analytics (API): an unsupported range is rejected', (await api('GET', '/api/v1/analytics/tenant?range=forever', alice))[0] === 400);

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
  const perfStart = Date.now();
  psql("INSERT INTO zones (id, domain, owner, tenant_id) SELECT gen_random_uuid(), 'perf' || g || '.example', NULL, NULL FROM generate_series(1, 5000) g");
  psql("INSERT INTO records (id, zone_id, name, record_type, value, ttl) SELECT gen_random_uuid(), z.id, 'h' || g, 'A', '192.0.2.' || (g % 250 + 1), 300 FROM zones z, generate_series(1, 8) g WHERE z.domain LIKE 'perf%'");
  await api('GET', '/api/v1/overview?limit=0', AT); // warmup
  const apiTimes = []; let ps = 0, pj = null;
  const memBefore = apiMemoryKb();
  for (let i = 0; i < 20; i++) { const t = Date.now(); [ps, pj] = await api('GET', '/api/v1/overview?limit=0', AT); apiTimes.push(Date.now() - t); }
  const memAfter = apiMemoryKb();
  const apiAvg = Math.round(apiTimes.reduce((a, b) => a + b, 0) / apiTimes.length), apiP95 = percentile(apiTimes, 95), apiP99 = percentile(apiTimes, 99), apiMax = Math.max(...apiTimes);
  const memDelta = memBefore != null && memAfter != null ? memAfter - memBefore : null;
  ok('performance: admin overview API over 5,000+ zones / 40,000+ records (20 requests)', ps === 200 && pj.zones_total >= 5000 && pj.records_total >= 40000 && apiP95 < 2500, `${pj.zones_total} zones, ${pj.records_total} records, avg ${apiAvg} ms, p95 ${apiP95} ms, p99 ${apiP99} ms, max ${apiMax} ms, RSS ${memBefore}->${memAfter} KiB (delta ${memDelta})`);
  const uiTimes = [];
  for (let i = 0; i < 3; i++) {
    const t = Date.now(); await opg.goto(BASE + '/admin'); await opg.waitForFunction(() => /5,?0\d\d/.test(document.querySelector('[data-testid="admin-overview"]')?.textContent || ''), null, { timeout: 15000 }).catch(() => {});
    uiTimes.push(Date.now() - t);
  }
  ok('performance: admin overview page renders 5,000+ zones quickly (3 loads)', Math.max(...uiTimes) < 5000, `avg ${Math.round(uiTimes.reduce((a, b) => a + b, 0) / uiTimes.length)} ms, max ${Math.max(...uiTimes)} ms`);
  const custTimes = []; let small = null;
  for (let i = 0; i < 5; i++) { const t = Date.now(); [, small] = await api('GET', '/api/v1/overview', alice); custTimes.push(Date.now() - t); }
  const custP95 = percentile(custTimes, 95);
  ok('performance: customer overview stays fast and scoped while 5,000 other zones exist', small.zones_total === 2 && custP95 < 500, `${small.zones_total} zones, p95 ${custP95} ms, max ${Math.max(...custTimes)} ms`);
  psql("DELETE FROM records WHERE zone_id IN (SELECT id FROM zones WHERE domain LIKE 'perf%.example'); DELETE FROM zones WHERE domain LIKE 'perf%.example'");
  ok('performance: 5,000-zone fixtures cleaned up', Number(psql("SELECT count(*) FROM zones WHERE domain LIKE 'perf%.example'")) === 0, `${Date.now() - perfStart} ms total`);

  // ===== 10. Zone transfer between tenants (admin workflow)
  {
    const [, nt] = await api('POST', '/api/v1/tenants', AT, { name: 'Transfer Target', max_zones: 1, max_records: null });
    const xferIds = {};
    for (const d of ['xfer-one.example', 'xfer-two.example']) { const [, z] = await api('POST', '/api/v1/zones', AT, { domain: d, geodns_enabled: false }); xferIds[d] = z.id || z.data?.id; }
    await api('POST', `/api/v1/zones/${xferIds['xfer-one.example']}/records`, AT, { name: 'www', record_type: 'A', value: '192.0.2.200', ttl: 300 });
    await api('POST', '/api/v1/georules', AT, { zone_id: xferIds['xfer-one.example'], match_type: 'country', match_value: 'US', target: '192.0.2.201', record_name: 'www', record_type: 'A', priority: 1, enabled: true });
    const search = async (d) => { await page.goto(BASE + '/admin/zones'); await page.fill('input[placeholder="Search zones by domain..."]', d); await page.waitForSelector(`[data-testid="zone-tenant-${d}"]`, { timeout: 10000 }); };
    await search('xfer-one.example');
    ok('transfer: admin sees the current tenant of a zone', /Platform zone/.test(await page.textContent('[data-testid="zone-tenant-xfer-one.example"]')));
    await page.click('button[aria-label="Transfer xfer-one.example"]'); await page.waitForSelector('[data-testid="transfer-form"]');
    ok('transfer: dialog shows the source tenant', /Platform \(no tenant\)/.test(await page.textContent('[data-testid="transfer-source"]')));
    ok('transfer: submit is disabled until a destination is chosen', await page.locator('[data-testid="transfer-form"] button[type="submit"]').isDisabled());
    await page.waitForFunction(() => [...document.querySelectorAll('#transfer-dest option')].some((o) => /Transfer Target/.test(o.textContent)), null, { timeout: 10000 });
    const optVal = await page.$$eval('#transfer-dest option', (o) => o.find((x) => /Transfer Target/.test(x.textContent))?.value);
    await page.selectOption('#transfer-dest', optVal); await page.click('[data-testid="transfer-form"] button[type="submit"]');
    await page.waitForSelector('[data-testid="confirm-dialog"]');
    const msg = await page.textContent('[data-testid="confirm-dialog"]');
    ok('transfer: confirmation names source and destination', /Platform \(no tenant\)/.test(msg) && /Transfer Target/.test(msg), msg.slice(0, 160));
    await page.keyboard.press('Escape'); await page.waitForTimeout(400);
    const [, still] = await api('GET', '/api/v1/zones?q=xfer-one.example', AT);
    ok('transfer: cancelling the confirmation changes nothing', !still.data[0].tenant_id);
    await page.click('[data-testid="transfer-form"] button[type="submit"]'); await page.waitForSelector('[data-testid="confirm-dialog"]'); await confirmYes(page);
    const okToast = await page.waitForSelector('text=/moved to Transfer Target/', { timeout: 10000 }).then((e) => e.textContent()).catch(() => '');
    ok('transfer: success notification', /moved to Transfer Target/.test(okToast), okToast);
    await search('xfer-one.example');
    ok('transfer: list shows the new tenant', /Tenant: Transfer Target/.test(await page.textContent('[data-testid="zone-tenant-xfer-one.example"]')));
    const [, movedRecs] = await api('GET', `/api/v1/zones/${xferIds['xfer-one.example']}/records`, AT);
    const [, movedRules] = await api('GET', '/api/v1/georules', AT);
    ok('transfer: records and GeoDNS rules moved with the zone', Array.isArray(movedRecs) && movedRecs.some((r) => r.name === 'www' && r.value === '192.0.2.200') && movedRules.some((r) => r.zone_id === xferIds['xfer-one.example']));
    // tenant members: viewer can read the new tenant's zone but cannot modify it
    const [memberAdd] = await api('PUT', `/api/v1/tenants/${nt.id}/members`, AT, { username: 'qa_viewer2', role: 'viewer' });
    const [memberRead] = await api('GET', `/api/v1/zones/${xferIds['xfer-one.example']}/records`, viewer);
    const [memberWrite] = await api('POST', `/api/v1/zones/${xferIds['xfer-one.example']}/records`, viewer, { name: 'nope', record_type: 'A', value: '192.0.2.9', ttl: 300 });
    const [, members] = await api('GET', `/api/v1/tenants/${nt.id}/members`, AT);
    const viewerMember = members.find((m) => m.username === 'qa_viewer2');
    const [memberRemove] = await api('DELETE', `/api/v1/tenants/${nt.id}/members/${viewerMember.user_id}`, AT);
    ok('membership: viewer can read but not write tenant zones', memberAdd === 200 && memberRead === 200 && memberWrite === 403 && memberRemove === 200);
    ok('tenants: a tenant that still owns zones cannot be deleted', (await api('DELETE', `/api/v1/tenants/${nt.id}`, AT))[0] === 409);
    // quota failure: the target tenant allows only one zone
    await search('xfer-two.example');
    await page.click('button[aria-label="Transfer xfer-two.example"]'); await page.waitForSelector('[data-testid="transfer-form"]');
    await page.waitForFunction(() => [...document.querySelectorAll('#transfer-dest option')].some((o) => /Transfer Target/.test(o.textContent)), null, { timeout: 10000 });
    await page.selectOption('#transfer-dest', await page.$$eval('#transfer-dest option', (o) => o.find((x) => /Transfer Target/.test(x.textContent))?.value));
    await page.click('[data-testid="transfer-form"] button[type="submit"]'); await page.waitForSelector('[data-testid="confirm-dialog"]'); await confirmYes(page);
    const errToast = await page.waitForSelector('text=/Quota reached/', { timeout: 10000 }).then((e) => e.textContent()).catch(() => '');
    ok('transfer: quota failure is reported and the zone is unchanged', /Quota reached/.test(errToast) && /not changed/.test(errToast), errToast);
    const [, two] = await api('GET', '/api/v1/zones?q=xfer-two.example', AT); ok('transfer: refused zone still has no tenant', !two.data[0].tenant_id);
    // authorization
    await apg.goto(BASE + '/user/zones'); await apg.waitForTimeout(1200);
    ok('transfer: customers get no Transfer action', (await apg.locator('button:has-text("Transfer")').count()) === 0);
    const [fz] = (await api('GET', '/api/v1/zones', alice))[1].data;
    ok('transfer: customers are refused by the API (403)', (await api('PUT', `/api/v1/zones/${fz.id}/tenant`, alice, { tenant_id: nt.id }))[0] === 403);
    const [, au] = await api('GET', '/api/v1/audit/logs?action=zone.transfer&limit=5', AT);
    ok('transfer: recorded in the audit log with source and destination', JSON.stringify(au).includes('Transfer Target') && JSON.stringify(au).includes('xfer-one.example'));
  }

  console.log(`\n${pass} passed, ${fail} failed`); process.exitCode = fail ? 1 : 0;
  } catch (e) {
    console.error('FATAL', e); process.exitCode = 2;
  } finally {
    await browser.close().catch(() => {});
    cleanupTestData();
  }
})();
