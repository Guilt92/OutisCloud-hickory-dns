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

test('bulk import file picker can be reached and used by keyboard', async ({ page }) => {
  await page.goto(`${process.env.OUTIS_TEST_VITE_URL || 'http://127.0.0.1:18082'}/tests/fixtures/modal-focus.html`)
  await page.getByRole('button', { name: 'Open dialog' }).focus()
  await page.keyboard.press('Tab')
  const picker = page.getByLabel('Choose import file')
  await expect(picker).toBeFocused()
  await picker.setInputFiles({ name: 'zone.json', mimeType: 'application/json', buffer: Buffer.from('[]') })
  await expect(page.getByRole('button', { name: 'Preview import', exact: true })).toBeEnabled()
  await expect(page.getByText('zone.json')).toBeVisible()
})

test('CSV preview preserves quoted TXT and requires confirmation before import', async ({ page }) => {
  const bodies = []
  await page.route('**/test/import', route => {
    const body = route.request().postDataJSON()
    bodies.push(body)
    return route.fulfill({ json: body.dry_run ? { dry_run: true, would_import: 1, skipped: 0 } : { imported: 1 } })
  })
  await page.goto(`${process.env.OUTIS_TEST_VITE_URL || 'http://127.0.0.1:18082'}/tests/fixtures/modal-focus.html`)
  await page.getByLabel('Choose import file').setInputFiles({
    name: 'zone.csv', mimeType: 'text/csv', buffer: Buffer.from('name,type,value\n@,TXT,"one,two"')
  })
  await page.getByRole('button', { name: 'Preview import' }).click()
  await expect(page.getByRole('status')).toContainText('1 to import')
  expect(bodies).toHaveLength(1)
  expect(bodies[0].records[0].value).toBe('one,two')
  await page.getByRole('button', { name: 'Import', exact: true }).click()
  await expect.poll(() => bodies.length).toBe(2)
  expect(bodies[1]).toEqual({ records: bodies[0].records })
})
