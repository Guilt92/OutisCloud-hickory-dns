const { test, expect } = require('@playwright/test')

if (process.env.OUTIS_BROWSER_PATH) {
  test.use({ launchOptions: { executablePath: process.env.OUTIS_BROWSER_PATH } })
}

test('UI CSP blocks injected inline script', async ({ page }) => {
  const response = await page.goto(process.env.OUTIS_TEST_UI_URL || 'http://127.0.0.1:18081/')
  expect(response.status()).toBe(200)
  const policy = response.headers()['content-security-policy']
  expect(policy).toContain("script-src 'self'")
  expect(policy).toContain("object-src 'none'")

  await page.evaluate(() => {
    const script = document.createElement('script')
    script.textContent = 'window.__outisCspProbe = true'
    document.body.append(script)
  })
  expect(await page.evaluate(() => window.__outisCspProbe)).toBeUndefined()
})
