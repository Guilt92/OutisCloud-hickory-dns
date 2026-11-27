const { test, expect } = require('@playwright/test')

test('nameserver dialog has labeled fields, traps focus and submits the configured server', async ({ page }) => {
  await page.addInitScript(() => {
    const user = { username: 'nameserver-admin', role: 'admin' }
    localStorage.setItem('token', 'nameserver-test-token')
    localStorage.setItem('user', JSON.stringify(user))
    localStorage.setItem('auth-storage', JSON.stringify({ state: {
      token: 'nameserver-test-token', user, isAuthenticated: true,
    }, version: 0 }))
  })
  let submitted
  await page.route('**/api/v1/nameservers**', route => {
    if (route.request().method() === 'POST') {
      submitted = route.request().postDataJSON()
      return route.fulfill({ status: 201, json: { id: 'ns1', ...submitted } })
    }
    return route.fulfill({ status: 200, json: [] })
  })
  await page.goto('/admin/nameservers')
  const opener = page.getByRole('button', { name: 'Add nameserver' }).first()
  await opener.click()
  const dialog = page.getByRole('dialog', { name: 'Add nameserver' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Close dialog' })).toBeFocused()
  await dialog.getByLabel('Hostname').fill('ns1.example.test')
  await dialog.getByLabel('IP address').fill('192.0.2.10')
  await dialog.getByLabel('Glue IP').fill('192.0.2.10')
  await dialog.getByLabel('Sort order').fill('2')
  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()
  await expect(opener).toBeFocused()
  await opener.click()
  await dialog.getByLabel('Hostname').fill('ns1.example.test')
  await dialog.getByLabel('IP address').fill('192.0.2.10')
  await dialog.getByLabel('Glue IP').fill('192.0.2.10')
  await dialog.getByLabel('Sort order').fill('2')
  await dialog.getByRole('button', { name: 'Create nameserver' }).click()
  await expect.poll(() => submitted).toMatchObject({
    hostname: 'ns1.example.test', ip_address: '192.0.2.10', glue_ip: '192.0.2.10', sort_order: 2,
  })
})
