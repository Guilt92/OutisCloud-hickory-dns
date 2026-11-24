const { test, expect } = require('@playwright/test')

if (process.env.OUTIS_BROWSER_PATH) {
  test.use({ launchOptions: { executablePath: process.env.OUTIS_BROWSER_PATH } })
}

test('failed route chunk shows a recoverable error instead of a blank page', async ({ page }) => {
  await page.route('**/assets/Login-*.js', route => route.abort())
  await page.goto(`${process.env.OUTIS_TEST_UI_URL || 'http://127.0.0.1:18081'}/login`)
  await expect(page.getByRole('heading', { name: 'This page could not load' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Go to dashboard' })).toHaveAttribute('href', '/')
})
