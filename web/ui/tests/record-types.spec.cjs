const { test, expect } = require('@playwright/test')

test('CAA editor submits and displays the canonical advanced record value', async ({ page }) => {
  const records = []
  let submitted

  await page.addInitScript(() => {
    localStorage.setItem('token', 'ui-test-token')
    localStorage.setItem('user', JSON.stringify({ username: 'ui-test', role: 'admin' }))
  })
  await page.route('**/api/v1/zones/ui-test-zone**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    if (url.pathname.endsWith('/records') && request.method() === 'POST') {
      submitted = request.postDataJSON()
      records.push({
        id: 'caa-record', zone_id: 'ui-test-zone', name: submitted.name,
        record_type: submitted.record_type, value: submitted.value,
        ttl: submitted.ttl, priority: submitted.priority || 0,
      })
      await route.fulfill({ status: 201, json: { id: 'caa-record', ...records[0] } })
      return
    }
    if (url.pathname.endsWith('/records')) {
      await route.fulfill({ status: 200, headers: { 'x-total-count': String(records.length) }, json: records })
      return
    }
    await route.fulfill({ status: 200, json: { id: 'ui-test-zone', domain: 'ui-test.example', access: 'owner' } })
  })

  await page.goto('/admin/zones/ui-test-zone/records')
  await expect(page.getByLabel('Record type')).toBeVisible()
  const type = page.getByLabel('Record type')
  await expect(type.locator('option[value="CAA"]')).toHaveText(/Certificate Authority Authorization/)
  await expect(type.locator('option[value="DNAME"]')).toHaveCount(0)
  await expect(type.locator('option[value="LOC"]')).toHaveCount(0)

  await page.getByLabel('Record name').fill('@')
  await type.selectOption('CAA')
  await page.getByLabel('Record value').fill('0 issue "letsencrypt.org"')
  await page.getByLabel('Record TTL').fill('300')
  await page.getByRole('button', { name: 'Add Record' }).click()

  await expect.poll(() => submitted).toEqual({
    name: '@', record_type: 'CAA', value: '0 issue "letsencrypt.org"', ttl: 300,
  })
  await expect(page.locator('tbody')).toContainText('CAA')
  await expect(page.locator('tbody')).toContainText('0 issue "letsencrypt.org"')
})
