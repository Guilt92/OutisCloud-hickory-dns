const { test, expect } = require('@playwright/test')

test('GeoDNS target weights are submitted, displayed, and preserved while editing', async ({ page }) => {
  const rules = []
  let nextId = 1
  await page.addInitScript(() => {
    localStorage.setItem('token', 'geo-weight-test-token')
    localStorage.setItem('user', JSON.stringify({ username: 'geo-admin', role: 'admin' }))
    localStorage.setItem('auth-storage', JSON.stringify({ state: {
      token: 'geo-weight-test-token', user: { username: 'geo-admin', role: 'admin' }, isAuthenticated: true,
    }, version: 0 }))
  })
  await page.route('**/api/v1/zones**', route => route.fulfill({ status: 200, json: [
    { id: 'zone-1', domain: 'weighted.example' },
  ] }))
  await page.route('**/api/v1/georules**', async route => {
    const request = route.request()
    if (request.method() === 'GET') return route.fulfill({ status: 200, json: rules })
    if (request.method() === 'POST') {
      const payload = request.postDataJSON()
      rules.push({ ...payload, id: `rule-${nextId++}`, enabled: true })
      return route.fulfill({ status: 201, json: rules[rules.length - 1] })
    }
    return route.continue()
  })
  await page.route('**/api/v1/georules/*', async route => {
    if (route.request().method() !== 'PUT') return route.continue()
    const id = new URL(route.request().url()).pathname.split('/').pop()
    const index = rules.findIndex(rule => rule.id === id)
    const payload = route.request().postDataJSON()
    rules[index] = { ...rules[index], ...payload }
    await route.fulfill({ status: 200, json: rules[index] })
  })

  await page.goto('/admin/georules')
  await page.getByLabel('Zone').selectOption('zone-1')
  await page.getByLabel('Match value').fill('US')
  await page.getByLabel('Target IP').fill('192.0.2.10')
  await page.getByLabel('Target weight').fill('7')
  await page.getByRole('button', { name: 'Add Rule' }).click()
  await expect(page.getByRole('cell', { name: '7', exact: true })).toBeVisible()
  expect(rules[0].weight).toBe(7)

  await page.getByRole('button', { name: 'Edit rule US' }).click()
  await expect(page.getByLabel('Target weight')).toHaveValue('7')
  await page.getByLabel('Target weight').fill('9')
  await page.getByRole('button', { name: 'Update Rule' }).click()
  await expect(page.getByRole('cell', { name: '9', exact: true })).toBeVisible()
  expect(rules[0].weight).toBe(9)
})
