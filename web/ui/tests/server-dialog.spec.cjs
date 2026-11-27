const { test, expect } = require('@playwright/test')

test('server management dialog labels fields, restores focus and submits configuration', async ({ page }) => {
  await page.addInitScript(() => {
    const user = { username: 'server-admin', role: 'admin' }
    localStorage.setItem('token', 'server-test-token')
    localStorage.setItem('user', JSON.stringify(user))
    localStorage.setItem('auth-storage', JSON.stringify({ state: {
      token: 'server-test-token', user, isAuthenticated: true,
    }, version: 0 }))
  })
  let submitted
  await page.route('**/api/v1/servers**', route => {
    if (route.request().method() === 'POST') {
      submitted = route.request().postDataJSON()
      return route.fulfill({ status: 201, json: { id: 's1', ...submitted } })
    }
    return route.fulfill({ status: 200, json: [] })
  })
  await page.goto('/admin/servers')
  const opener = page.getByRole('button', { name: 'Add Server' }).first()
  await opener.click()
  const dialog = page.getByRole('dialog', { name: 'Add DNS server' })
  await expect(dialog.getByRole('button', { name: 'Close dialog' })).toBeFocused()
  await dialog.getByLabel('Server Name').fill('test-dns')
  await dialog.getByLabel('IP Address').fill('192.0.2.20')
  await dialog.getByLabel('Port').fill('5353')
  await dialog.getByLabel('Region').fill('lab')
  await dialog.getByLabel('Max Cache TTL (seconds)').fill('300')
  await dialog.getByLabel('Min Cache TTL (seconds)').fill('60')
  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()
  await expect(opener).toBeFocused()
  await opener.click()
  await dialog.getByLabel('Server Name').fill('test-dns')
  await dialog.getByLabel('IP Address').fill('192.0.2.20')
  await dialog.getByRole('button', { name: 'Create Server' }).click()
  await expect.poll(() => submitted).toMatchObject({ name: 'test-dns', address: '192.0.2.20', port: 53 })
})
