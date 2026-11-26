const { test, expect } = require('@playwright/test')

test('bulk delete sends selected records only after an explicit confirmation', async ({ page }) => {
  let bulkDelete
  const records = [
    { id: 'record-a', name: 'www', record_type: 'A', value: '192.0.2.10', ttl: 300 },
    { id: 'record-b', name: 'mail', record_type: 'A', value: '192.0.2.11', ttl: 300 },
  ]
  await page.addInitScript(() => {
    localStorage.setItem('token', 'bulk-delete-ui-token')
    localStorage.setItem('user', JSON.stringify({ username: 'bulk-admin', role: 'admin' }))
    localStorage.setItem('auth-storage', JSON.stringify({ state: {
      token: 'bulk-delete-ui-token', user: { username: 'bulk-admin', role: 'admin' }, isAuthenticated: true,
    }, version: 0 }))
  })
  await page.route('**/api/v1/zones/zone-bulk/records**', async route => {
    const request = route.request()
    if (request.method() === 'POST' && new URL(request.url()).pathname.endsWith('/bulk-delete')) {
      bulkDelete = request.postDataJSON()
      await route.fulfill({ status: 200, json: { deleted: bulkDelete.record_ids.length } })
      return
    }
    await route.fulfill({ status: 200, headers: { 'x-total-count': String(records.length) }, json: records })
  })
  await page.route('**/api/v1/zones/zone-bulk', route => route.fulfill({ status: 200, json: { access: 'owner' } }))

  await page.goto('/admin/zones/zone-bulk/records')
  await page.getByLabel('Select record www A').check()
  await page.getByRole('button', { name: 'Delete selected' }).click()
  await expect(page.getByRole('alertdialog')).toContainText('selection is deleted as one zone-scoped operation')
  await expect(page.getByRole('alertdialog').getByRole('button', { name: 'Delete 1 records' })).toBeVisible()
  expect(bulkDelete).toBeUndefined()
  await page.getByTestId('confirm-yes').click()
  await expect.poll(() => bulkDelete).toEqual({ record_ids: ['record-a'] })
  await expect(page.getByText('1 record selected')).toHaveCount(0)
})
