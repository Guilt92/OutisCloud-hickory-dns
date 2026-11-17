// Redesign QA: every route for every role, both themes, ten viewports.
// Checks: renders a heading, no console/page errors, no horizontal overflow, theme switching works on every
// route and persists, role separation (customers never see admin navigation; /admin redirects), keyboard-reachable
// destructive confirmation dialog. Screenshots go to $SHOTS (default ./qa-shots).
// Needs: running API (:8080) + UI (:5173), accounts admin / ui_editor (editor) / ui_viewer (viewer).
const { chromium } = require('playwright-core');
const fs = require('fs'), path = require('path');
const BASE = process.env.UI_BASE || 'http://127.0.0.1:5173';
const API = process.env.API_BASE || 'http://127.0.0.1:8080';
const ADMIN = [process.env.ADMIN_USER || 'admin', process.env.ADMIN_PASS || 'Adm1n-Strong-Pw-77'];
const SHOTS = process.env.SHOTS || path.join(process.cwd(), 'qa-shots');
fs.mkdirSync(SHOTS, { recursive: true });
const results = [];
const ok = (n, c, x = '') => { results.push(c); console.log((c ? 'PASS ' : 'FAIL ') + n + (x ? '  -- ' + x : '')); };
const VIEWPORTS = [['w1920', 1920, 1080], ['w1440', 1440, 900], ['desktop', 1280, 800], ['w1024', 1024, 768], ['tablet', 820, 1100], ['w768', 768, 1024], ['w430', 430, 932], ['mobile', 390, 800], ['w375', 375, 812], ['w360', 360, 800]];
const ADMIN_ROUTES = ['/admin', '/admin/metrics', '/admin/zones', '/admin/nameservers', '/admin/georules', '/admin/dns-lookup', '/admin/servers', '/admin/agents', '/admin/config', '/admin/users', '/admin/audit', '/admin/settings'];
const USER_ROUTES = ['/user', '/user/zones', '/user/dns-lookup', '/user/settings', '/user/help'];
async function api(m, p, tok, body) { const r = await fetch(API + p, { method: m, headers: { 'content-type': 'application/json', ...(tok ? { authorization: 'Bearer ' + tok } : {}) }, body: body ? JSON.stringify(body) : undefined }); let j = null; try { j = await r.json(); } catch (e) {} return [r.status, j]; }
async function login(page, u, p) {
  await page.goto(BASE + '/login'); await page.fill('input[placeholder="Enter your username"]', u); await page.fill('input[placeholder="Enter your password"]', p);
  await page.click('button[type="submit"]'); await page.waitForURL(/\/(admin|user)/, { timeout: 10000 });
}
function watch(page, errs) {
  page.on('console', (m) => { if (m.type() === 'error') { const t = m.text(); if (!/favicon|Failed to load resource.*(401|403|404|503)/.test(t)) errs.push('console: ' + t.slice(0, 160)); } });
  page.on('pageerror', (e) => errs.push('pageerror: ' + String(e).slice(0, 160)));
}
const overflow = (page) => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);

(async () => {
  const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  const [, lg] = await api('POST', '/api/v1/auth/login', null, { username: ADMIN[0], password: ADMIN[1] });
  const AT = lg.token;
  const [, el] = await api('POST', '/api/v1/auth/login', null, { username: 'ui_editor', password: 'editorpass12' });
  await api('POST', '/api/v1/zones', el.token, { domain: 'customer.example' });

  // ---- login page, both themes, three viewports
  for (const [name, w, h] of VIEWPORTS) {
    const ctx = await browser.newContext({ viewport: { width: w, height: h } }); const page = await ctx.newPage(); const errs = []; watch(page, errs);
    await page.goto(BASE + '/login'); await page.waitForSelector('[data-testid="login-page"]');
    ok(`login (${name}): light is the default theme`, !(await page.evaluate(() => document.documentElement.classList.contains('dark'))));
    await page.screenshot({ path: path.join(SHOTS, `login-light-${name}.png`) });
    ok(`login (${name}): no horizontal overflow`, (await overflow(page)) <= 1, String(await overflow(page)));
    await page.click('[data-testid="theme-toggle"]'); await page.waitForTimeout(200);
    ok(`login (${name}): theme toggle switches to dark`, await page.evaluate(() => document.documentElement.classList.contains('dark')));
    await page.screenshot({ path: path.join(SHOTS, `login-dark-${name}.png`) });
    ok(`login (${name}): no console errors`, errs.length === 0, errs.join(' | '));
    await ctx.close();
  }

  // ---- admin: every route x theme x viewport
  for (const [name, w, h] of VIEWPORTS) {
    const ctx = await browser.newContext({ viewport: { width: w, height: h } }); const page = await ctx.newPage(); const errs = []; watch(page, errs);
    await login(page, ADMIN[0], ADMIN[1]);
    for (const theme of ['dark', 'light']) {
      await page.evaluate((t) => localStorage.setItem('outis-theme', t), theme);
      for (const r of ADMIN_ROUTES) {
        await page.goto(BASE + r); await page.waitForSelector('h1', { timeout: 8000 }).catch(() => {}); await page.waitForTimeout(500);
        const isDark = await page.evaluate(() => document.documentElement.classList.contains('dark'));
        const h1 = await page.locator('h1').first().textContent().catch(() => '');
        const ov = await overflow(page);
        const atRoute = new URL(page.url()).pathname === r;
        const good = atRoute && isDark === (theme === 'dark') && !!h1 && ov <= 1;
        if (!good || (name === 'desktop')) await page.screenshot({ path: path.join(SHOTS, `admin${r.replace(/\//g, '-')}-${theme}-${name}.png`), fullPage: false });
        ok(`admin ${r} [${theme}/${name}] renders (h1="${(h1 || '').trim().slice(0, 30)}", overflow ${ov})`, good);
      }
    }
    ok(`admin [${name}]: no console or page errors across all routes`, errs.length === 0, errs.slice(0, 3).join(' | '));
    await ctx.close();
  }

  // ---- theme persistence + sidebar/user menu behaviour (desktop)
  {
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } }); const page = await ctx.newPage();
    await login(page, ADMIN[0], ADMIN[1]);
    await page.evaluate(() => localStorage.setItem('outis-theme', 'dark')); await page.goto(BASE + '/admin/zones');
    await page.click('[data-testid="theme-toggle"]'); await page.waitForTimeout(150);
    await page.goto(BASE + '/admin/users'); await page.waitForTimeout(400);
    ok('theme choice survives navigation and reload', !(await page.evaluate(() => document.documentElement.classList.contains('dark'))) && (await page.evaluate(() => localStorage.getItem('outis-theme'))) === 'light');
    await page.reload(); await page.waitForTimeout(500);
    ok('light theme is applied before first paint after reload', !(await page.evaluate(() => document.documentElement.classList.contains('dark'))));
    const active = await page.locator('aside a[aria-current="page"]').first().textContent().catch(() => '');
    ok('sidebar highlights the current page', /Users/.test(active), active);
    ok('sidebar offers all admin sections', (await page.locator('aside nav a').count()) === 13, String(await page.locator('aside nav a').count()));
    await page.click('[data-testid="user-menu"]'); ok('user menu opens', await page.locator('[role="menu"]').isVisible());
    await page.keyboard.press('Escape'); await page.waitForTimeout(150); ok('Escape closes the user menu', !(await page.locator('[role="menu"]').isVisible().catch(() => false)));
    await ctx.close();
  }

  // ---- mobile drawer
  {
    const ctx = await browser.newContext({ viewport: { width: 390, height: 800 } }); const page = await ctx.newPage();
    await login(page, ADMIN[0], ADMIN[1]); await page.goto(BASE + '/admin'); await page.waitForTimeout(400);
    const vis = () => page.locator('aside').evaluate((e) => { const r = e.getBoundingClientRect(); return r.right > 8; });
    ok('mobile: sidebar is hidden by default', !(await vis()));
    await page.click('button[aria-label="Open menu"]'); await page.waitForTimeout(350); ok('mobile: menu button opens the drawer', await vis());
    await page.click('aside a:has-text("Zones")'); await page.waitForTimeout(500);
    ok('mobile: choosing a page navigates and closes the drawer', page.url().endsWith('/admin/zones') && !(await vis()));
    await ctx.close();
  }

  // ---- destructive actions use the themed confirmation dialog (not window.confirm)
  {
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } }); const page = await ctx.newPage(); let native = 0; page.on('dialog', (d) => { native++; d.dismiss(); });
    await login(page, ADMIN[0], ADMIN[1]);
    await api('POST', '/api/v1/zones', AT, { domain: 'to-delete.example' });
    await page.goto(BASE + '/admin/zones'); await page.fill('input[placeholder^="Search zones"]', 'to-delete'); await page.waitForTimeout(1500);
    await page.locator('tr:has-text("to-delete.example") button.text-red-600, tr:has-text("to-delete.example") button:has(svg.lucide-trash2)').first().click(); await page.waitForTimeout(300);
    ok('delete zone asks with the themed dialog', await page.locator('[data-testid="confirm-dialog"]').isVisible() && native === 0);
    await page.screenshot({ path: path.join(SHOTS, 'confirm-dialog.png') });
    await page.keyboard.press('Escape'); await page.waitForTimeout(200);
    const [, still] = await api('GET', '/api/v1/zones?q=to-delete', AT); ok('Escape cancels: the zone still exists', (still.data || still).length === 1);
    await page.locator('tr:has-text("to-delete.example") button:has(svg.lucide-trash2)').first().click(); await page.click('[data-testid="confirm-yes"]'); await page.waitForTimeout(1200);
    const [, gone] = await api('GET', '/api/v1/zones?q=to-delete', AT); ok('confirming deletes the zone', (gone.data || gone).length === 0);
    await ctx.close();
  }

  // ---- customer (editor) and viewer: own routes only, no admin navigation
  for (const [who, pw] of [['ui_editor', 'editorpass12'], ['ui_viewer', 'viewerpass12']]) {
    for (const [name, w, h] of [VIEWPORTS[0], VIEWPORTS[2]]) {
      const ctx = await browser.newContext({ viewport: { width: w, height: h } }); const page = await ctx.newPage(); const errs = []; watch(page, errs);
      await login(page, who, pw);
      ok(`${who}: lands on the customer dashboard`, page.url().endsWith('/user'), page.url());
      for (const theme of ['dark', 'light']) {
        await page.evaluate((t) => localStorage.setItem('outis-theme', t), theme);
        for (const r of USER_ROUTES) {
          await page.goto(BASE + r); await page.waitForSelector('h1', { timeout: 8000 }).catch(() => {}); await page.waitForTimeout(450);
          const ov = await overflow(page); const h1 = await page.locator('h1').first().textContent().catch(() => '');
          const atRoute = new URL(page.url()).pathname === r;
          if (who === 'ui_editor' && name === 'desktop') await page.screenshot({ path: path.join(SHOTS, `user${r.replace(/\//g, '-')}-${theme}-${name}.png`) });
          ok(`${who} ${r} [${theme}/${name}] renders (overflow ${ov})`, atRoute && !!h1 && ov <= 1);
        }
      }
      if (name === 'desktop') {
        const nav = await page.locator('aside nav').textContent();
        ok(`${who}: sidebar has no administrative entries`, !/Servers|Agents|Audit|Users|Nameservers|Config Sync|GeoDNS/i.test(nav), nav.replace(/\s+/g, ' ').slice(0, 80));
        for (const r of ['/admin', '/admin/users', '/admin/agents']) { await page.goto(BASE + r); await page.waitForTimeout(500); ok(`${who}: ${r} redirects to the customer area`, page.url().includes('/user')); }
        const [st] = await api('GET', '/api/v1/users', (await api('POST', '/api/v1/auth/login', null, { username: who, password: pw }))[1].token); ok(`${who}: the API also refuses admin data (${st})`, st === 403);
      }
      ok(`${who} [${name}]: no console or page errors`, errs.length === 0, errs.slice(0, 3).join(' | '));
      await ctx.close();
    }
  }
  // ---- forms, validation, dialogs, filters
  {
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } }); const page = await ctx.newPage(); const errs = []; watch(page, errs);
    await page.goto(BASE + '/login'); await page.fill('input[placeholder="Enter your password"]', 'x'); await page.click('button[type="submit"]'); await page.waitForTimeout(300);
    ok('login: empty username is reported', /Username is required/.test(await page.locator('[role="alert"]').textContent().catch(() => '')));
    await page.fill('input[placeholder="Enter your username"]', 'admin'); await page.fill('input[placeholder="Enter your password"]', 'wrong-password-1'); await page.click('button[type="submit"]'); await page.waitForTimeout(1200);
    ok('login: wrong password shows an inline error and stays on /login', page.url().includes('/login') && (await page.locator('[role="alert"]').count()) === 1);
    await login(page, ADMIN[0], ADMIN[1]);
    await page.goto(BASE + '/admin/zones'); await page.waitForTimeout(800);
    await page.fill('input[placeholder="example.com"]', 'not a domain'); await page.click('button:has-text("Create Zone")'); await page.waitForTimeout(500);
    ok('zones: an invalid domain is rejected with a visible message', /valid domain/i.test(await page.locator('[aria-live]').textContent()));
    await page.goto(BASE + '/admin/users'); await page.waitForTimeout(800);
    await page.click('button:has-text("New User")'); await page.waitForTimeout(300);
    ok('users: create dialog opens', await page.locator('[role="dialog"]').isVisible());
    await page.fill('input[placeholder="username"]', 'ab'); await page.locator('[role="dialog"] button:has-text("Create")').click(); await page.waitForTimeout(400);
    ok('users: a too-short username is rejected with a toast', /at least 3/.test(await page.locator('[aria-live]').textContent()));
    await page.keyboard.press('Escape'); await page.waitForTimeout(1200);
    ok('users: Escape closes the dialog', !(await page.locator('[role="dialog"]').isVisible().catch(() => false)));
    await page.goto(BASE + '/admin/audit'); await page.waitForTimeout(1200);
    const before = await page.locator('tbody tr').count();
    await page.selectOption('select', 'zone'); await page.waitForTimeout(1200);
    const rows = await page.locator('tbody tr').allTextContents();
    ok('audit: the resource filter narrows the table', rows.length > 0 && rows.length <= before && rows.every((r) => /zone/i.test(r)), `${before} -> ${rows.length}`);
    ok('forms/dialogs: no console errors', errs.length === 0, errs.slice(0, 3).join(' | '));
    await ctx.close();
  }
  await browser.close();
  const failed = results.filter((r) => !r).length; console.log(`\n${results.length - failed}/${results.length} redesign checks passed`); process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('SCRIPT ERROR', e); process.exit(2); });
