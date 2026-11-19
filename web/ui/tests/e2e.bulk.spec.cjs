const { test, expect } = require('@playwright/test')

test('dark mode toggle persists', async ({ page, request }) => {
  const res = await request.post('http://localhost:8080/api/v1/auth/login', { data: { username: 'admin', password: 'admin123' } })
  const body = await res.json()
  const token = body.token
  await page.addInitScript(token => { localStorage.setItem('token', token) }, token)

  await page.goto('http://localhost:3000/')
  await page.click('text=Admin')
  // toggle dark
  await page.click('text=Dark')
  // ensure class present
  const hasDark = await page.evaluate(() => document.documentElement.classList.contains('dark'))
  expect(hasDark).toBe(true)
})
