const { test, expect } = require('@playwright/test')

if (process.env.OUTIS_BROWSER_PATH) {
  test.use({ launchOptions: { executablePath: process.env.OUTIS_BROWSER_PATH } })
}

test('modal traps Tab and restores focus after Escape', async ({ page }) => {
  await page.goto(`${process.env.OUTIS_TEST_VITE_URL || 'http://127.0.0.1:18082'}/tests/fixtures/modal-focus.html`)
  const opener = page.getByRole('button', { name: 'Open dialog' })
  await opener.click()
  const dialog = page.getByRole('dialog', { name: 'Focus test' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Close dialog' })).toBeFocused()

  await page.keyboard.press('Shift+Tab')
  await expect(dialog.getByRole('button', { name: 'Last action' })).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(dialog.getByRole('button', { name: 'Close dialog' })).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()
  await expect(opener).toBeFocused()
})
