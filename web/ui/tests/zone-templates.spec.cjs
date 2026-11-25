const { test, expect } = require('@playwright/test')

test('zone template form validates variables and submits a web template', async ({ page }) => {
  let submitted
  await page.addInitScript(() => {
    localStorage.setItem('token', 'ui-template-token')
    localStorage.setItem('user', JSON.stringify({ username: 'template-admin', role: 'admin' }))
    localStorage.setItem('auth-storage', JSON.stringify({ state: {
      token: 'ui-template-token', user: { username: 'template-admin', role: 'admin' }, isAuthenticated: true,
    }, version: 0 }))
  })
  await page.route('**/api/v1/zone-templates', (route) => route.fulfill({ status: 200, json: [
    { id: 'web', name: 'Web site', variables: [
      { name: 'ipv4', label: 'IPv4 address', input: 'ipv4', required: true },
      { name: 'ipv6', label: 'IPv6 address', input: 'ipv6', required: false },
    ] },
  ] }))
  await page.route('**/api/v1/nameservers', (route) => route.fulfill({ status: 200, json: [] }))
  await page.route('**/api/v1/zones**', async (route) => {
    if (route.request().method() === 'POST') {
      submitted = route.request().postDataJSON()
      await route.fulfill({ status: 201, json: { id: 'new-zone', nameservers: [] } })
    } else {
      await route.fulfill({ status: 200, headers: { 'x-total-count': '0' }, json: [] })
    }
  })

  await page.goto('/admin/zones')
  await page.getByLabel('Domain').fill('template.example')
  await page.getByLabel('Template').selectOption('web')
  await expect(page.getByLabel('IPv4 address')).toBeVisible()
  await page.getByLabel('IPv4 address').fill('192.0.2.10')
  await page.getByLabel('IPv6 address').fill('2001:db8::10')
  await page.getByRole('button', { name: 'Create Zone' }).click()
  await expect.poll(() => submitted).toMatchObject({
    domain: 'template.example.',
    template_id: 'web',
    template_variables: { ipv4: '192.0.2.10', ipv6: '2001:db8::10' },
  })
})

test('zone history diff renders revision setting changes', async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('token', 'ui-template-token')
    localStorage.setItem('user', JSON.stringify({ username: 'template-admin', role: 'admin' }))
    localStorage.setItem('auth-storage', JSON.stringify({ state: {
      token: 'ui-template-token', user: { username: 'template-admin', role: 'admin' }, isAuthenticated: true,
    }, version: 0 }))
  })
  await page.route('**/api/v1/nameservers', (route) => route.fulfill({ status: 200, json: [] }))
  await page.route('**/api/v1/zones/ui-history-zone/members', (route) => route.fulfill({ status: 200, json: [] }))
  await page.route('**/api/v1/zones/ui-history-zone/revisions', (route) => route.fulfill({ status: 200, json: [
    { id: 'revision-1', domain: 'history.example', reason: 'zone updated', user: 'admin', created_at: '2026-01-01T00:00:00Z', record_count: 3 },
  ] }))
  await page.route('**/api/v1/zones/ui-history-zone/revisions/revision-1/diff', (route) => route.fulfill({ status: 200, json: {
    added: [], removed: [], changed: [],
    settings_changed: {
      from: { domain: 'history.example', geodns_enabled: false, ecs_enabled: false, tags: [] },
      to: { domain: 'history.example', geodns_enabled: true, ecs_enabled: false, tags: [] },
    },
  } }))
  await page.route('**/api/v1/zones**', (route) => {
    const path = new URL(route.request().url()).pathname
    if (path.endsWith('/revisions/revision-1/diff')) {
      return route.fulfill({ status: 200, json: {
        added: [], removed: [], changed: [],
        settings_changed: {
          from: { domain: 'history.example', geodns_enabled: false, ecs_enabled: false, tags: [] },
          to: { domain: 'history.example', geodns_enabled: true, ecs_enabled: false, tags: [] },
        },
      } })
    }
    if (path.endsWith('/members')) return route.fulfill({ status: 200, json: [] })
    if (path.endsWith('/revisions')) return route.fulfill({ status: 200, json: [
      { id: 'revision-1', domain: 'history.example', reason: 'zone updated', user: 'admin', created_at: '2026-01-01T00:00:00Z', record_count: 3 },
    ] })
    return route.fulfill({ status: 200, headers: { 'x-total-count': '1' }, json: [{
      id: 'ui-history-zone', domain: 'history.example', status: 'active', zone_type: 'primary',
      access: 'owner', geodns_enabled: false, ecs_enabled: false, tags: [],
    }] })
  })

  await page.goto('/admin/zones')
  await page.getByRole('button', { name: 'Manage history.example' }).click()
  await page.getByRole('button', { name: 'History', exact: true }).click()
  await page.getByRole('button', { name: 'Diff' }).click()
  await expect(page.getByRole('heading', { name: 'Zone settings' })).toBeVisible()
  await expect(page.getByText('geodns_enabled: false → true')).toBeVisible()
})
