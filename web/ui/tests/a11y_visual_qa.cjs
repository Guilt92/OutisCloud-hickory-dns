// Accessibility (axe-core, WCAG 2.0/2.1 A+AA) and visual-regression checks for every dashboard route.
//   node tests/a11y_visual_qa.cjs a11y                 -> axe on all routes x dark/light (desktop) + mobile subset
//   node tests/a11y_visual_qa.cjs visual update        -> (re)create baselines in tests/visual-baseline
//   node tests/a11y_visual_qa.cjs visual compare       -> compare against the baselines (pixelmatch), fail on drift
//   node tests/a11y_visual_qa.cjs visual selftest      -> proves the comparer detects a deliberate style change
// Needs the stack from scripts/ui_stack.sh (env.sh sourced) with accounts admin / ui_editor; packages axe-core, pixelmatch, pngjs.
const { chromium } = require('playwright-core');
const fs = require('fs'), path = require('path');
const BASE = process.env.UI_BASE, API = process.env.API_BASE;
const ADMIN = [process.env.ADMIN_USER, process.env.ADMIN_PASS], EDITOR = ['ui_editor', 'editorpass12'];
const OUT = process.env.QA_OUT || path.join(process.cwd(), 'qa-out');
const BASELINE = process.env.VISUAL_BASELINE || path.join(__dirname, 'visual-baseline');
const MAX_DIFF_RATIO = Number(process.env.MAX_DIFF_RATIO || 0.002);
const ADMIN_ROUTES = ['/admin', '/admin/metrics', '/admin/zones', '/admin/nameservers', '/admin/georules', '/admin/dns-lookup', '/admin/servers', '/admin/agents', '/admin/config', '/admin/tenants', '/admin/users', '/admin/audit', '/admin/settings'];
const USER_ROUTES = ['/user', '/user/zones', '/user/analytics', '/user/dns-lookup', '/user/settings', '/user/help'];
// deterministic pages only: no clocks, charts, audit trails or pages whose content depends on data created by other suites (e.g. tenants)
const VISUAL = { admin: ['/admin/nameservers', '/admin/dns-lookup', '/admin/settings', '/admin/config'], user: ['/user/dns-lookup', '/user/help', '/user/settings'] };
let pass = 0, fail = 0;
const ok = (n, c, x = '') => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + n + (x ? '  -- ' + String(x).slice(0, 300) : '')); };
async function login(page, [u, p]) {
  await page.goto(BASE + '/login'); await page.fill('input[placeholder="Enter your username"]', u); await page.fill('input[placeholder="Enter your password"]', p);
  await page.click('button[type="submit"]'); await page.waitForURL(/\/(admin|user)/, { timeout: 10000 }).catch(() => {});
}
async function setTheme(page, theme) {
  await page.evaluate((t) => { localStorage.setItem('outis-theme', t); document.documentElement.classList.toggle('dark', t === 'dark'); document.documentElement.dataset.theme = t; }, theme);
}
async function settle(page) { await page.waitForLoadState('networkidle').catch(() => {}); await page.waitForTimeout(600); }
async function stabilize(page) {
  await page.addStyleTag({ content: '*,*::before,*::after{animation:none!important;transition:none!important;caret-color:transparent!important}' });
  await page.evaluate(() => {
    const re = /\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?|\d{1,2}[:.]\d{2}(:\d{2})?\s?(AM|PM)?|\d+ (seconds?|minutes?|hours?|days?) ago|\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/g;
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT); let n; while ((n = w.nextNode())) { if (re.test(n.nodeValue)) n.nodeValue = n.nodeValue.replace(re, 'TIME'); re.lastIndex = 0; }
  });
}

async function a11y(browser) {
  const axeSrc = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
  const all = []; fs.mkdirSync(OUT, { recursive: true });
  for (const [role, creds, routes] of [['admin', ADMIN, ADMIN_ROUTES], ['customer', EDITOR, USER_ROUTES]]) {
    for (const [vpName, w, h] of [['desktop', 1280, 900], ['mobile', 390, 844]]) {
      const ctx = await browser.newContext({ viewport: { width: w, height: h } }); const page = await ctx.newPage(); await login(page, creds);
      for (const theme of ['dark', 'light']) {
        if (vpName === 'mobile' && theme === 'light' && role === 'admin') continue; // keep the run short: mobile light only for customers
        for (const route of ['/login', ...routes]) {
          if (route === '/login') { const c2 = await browser.newContext({ viewport: { width: w, height: h } }); const p2 = await c2.newPage(); await p2.goto(BASE + '/login'); await setTheme(p2, theme); await p2.reload(); await settle(p2); await p2.addScriptTag({ content: axeSrc });
            const r = await p2.evaluate(() => axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] } })); r.violations.forEach((v) => all.push({ role: 'anon', vpName, theme, route, id: v.id, impact: v.impact, nodes: v.nodes.length, sample: v.nodes[0]?.target?.join(' '), help: v.help })); ok(`axe ${role}/${vpName}/${theme} /login`, true); await c2.close(); continue; }
          await page.goto(BASE + route); await setTheme(page, theme); await page.reload(); await settle(page);
          await page.addScriptTag({ content: axeSrc });
          const res = await page.evaluate(() => axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] } }));
          for (const v of res.violations) all.push({ role, vpName, theme, route, id: v.id, impact: v.impact, nodes: v.nodes.length, sample: v.nodes[0]?.target?.join(' '), html: v.nodes[0]?.html?.slice(0, 120), help: v.help });
        }
      }
      await ctx.close();
    }
  }
  fs.writeFileSync(path.join(OUT, 'axe-violations.json'), JSON.stringify(all, null, 2));
  const by = {}; for (const v of all) { const k = `${v.impact}:${v.id}`; (by[k] = by[k] || { n: 0, routes: new Set(), sample: v.sample, html: v.html, help: v.help }); by[k].n += v.nodes; by[k].routes.add(v.route); }
  console.log('\nAxe violation summary (rule: nodes, routes):');
  for (const [k, v] of Object.entries(by).sort()) console.log(`  ${k}: ${v.n} node(s) on ${v.routes.size} route(s) -- ${v.help} -- e.g. ${v.sample}`);
  const blocking = all.filter((v) => v.impact === 'critical' || v.impact === 'serious');
  ok(`accessibility: no critical/serious WCAG A/AA violations on ${new Set(all.map((a) => a.route)).size || 'any'} flagged route(s)`, blocking.length === 0, blocking.slice(0, 6).map((b) => `${b.role}/${b.theme}${b.route}:${b.id}`).join(' | '));
  ok('accessibility: no violations of any impact (moderate/minor included)', all.length === 0, `${all.length} violation record(s)`);
}

const png = () => ({ PNG: require('pngjs').PNG, pm: require('pixelmatch') });
function compare(a, b) { const { PNG, pm } = png(); const A = PNG.sync.read(a), B = PNG.sync.read(b); if (A.width !== B.width || A.height !== B.height) return { ratio: 1, dims: true, A, B };
  const diff = new PNG({ width: A.width, height: A.height }); const n = pm(A.data, B.data, diff.data, A.width, A.height, { threshold: 0.1 }); return { ratio: n / (A.width * A.height), diff: PNG.sync.write(diff) }; }

async function visual(browser, mode) {
  fs.mkdirSync(BASELINE, { recursive: true }); fs.mkdirSync(path.join(OUT, 'visual-diff'), { recursive: true });
  const shots = [];
  for (const [role, creds, routes] of [['admin', ADMIN, VISUAL.admin], ['user', EDITOR, VISUAL.user]]) {
    for (const [vpName, w, h] of [['desktop', 1280, 800], ['mobile', 390, 800]]) {
      const ctx = await browser.newContext({ viewport: { width: w, height: h }, deviceScaleFactor: 1 }); const page = await ctx.newPage(); await login(page, creds);
      for (const theme of ['dark', 'light']) for (const route of routes) {
        await page.goto(BASE + route); await setTheme(page, theme); await page.reload(); await settle(page); await stabilize(page);
        const name = `${role}${route.replace(/\//g, '_')}-${theme}-${vpName}.png`;
        shots.push([name, await page.screenshot({ fullPage: false })]);
      }
      await ctx.close();
    }
  }
  if (mode === 'update') { for (const [n, b] of shots) fs.writeFileSync(path.join(BASELINE, n), b); ok(`visual: wrote ${shots.length} baselines to ${path.relative(process.cwd(), BASELINE)}`, shots.length > 0); return; }
  if (mode === 'selftest') {
    const [n, b] = shots[0]; const base = fs.readFileSync(path.join(BASELINE, n));
    const same = compare(base, b); ok(`visual selftest: unchanged page is within tolerance (${(same.ratio * 100).toFixed(3)}%)`, same.ratio <= MAX_DIFF_RATIO);
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } }); const page = await ctx.newPage(); await login(page, ADMIN); await page.goto(BASE + VISUAL.admin[0]); await setTheme(page, 'dark'); await page.reload(); await settle(page); await stabilize(page);
    await page.addStyleTag({ content: 'h1{color:#ff00ff!important} .btn-primary{background:#00aaff!important}' });
    const changed = compare(base, await page.screenshot()); ok(`visual selftest: a deliberate style change IS detected (${(changed.ratio * 100).toFixed(3)}% > ${(MAX_DIFF_RATIO * 100).toFixed(2)}%)`, changed.ratio > MAX_DIFF_RATIO);
    return;
  }
  for (const [n, b] of shots) {
    const p = path.join(BASELINE, n);
    if (!fs.existsSync(p)) { ok(`visual ${n}: baseline exists`, false, 'run "visual update" first'); continue; }
    const r = compare(fs.readFileSync(p), b);
    if (r.ratio > MAX_DIFF_RATIO && r.diff) fs.writeFileSync(path.join(OUT, 'visual-diff', n), r.diff);
    ok(`visual ${n}: ${(r.ratio * 100).toFixed(3)}% pixels differ (limit ${(MAX_DIFF_RATIO * 100).toFixed(2)}%)`, r.ratio <= MAX_DIFF_RATIO);
  }
}

(async () => {
  const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  const what = process.argv[2];
  if (what === 'a11y') await a11y(browser); else if (what === 'visual') await visual(browser, process.argv[3] || 'compare'); else { console.log('usage: a11y | visual update|compare|selftest'); process.exit(2); }
  await browser.close(); console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(2); });
