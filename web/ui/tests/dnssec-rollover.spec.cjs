const { test, expect } = require('@playwright/test')

test('DNSSEC rollover carries the active algorithm and protects the replacement key', async ({ page }) => {
  const ds = (tag) => ({ key_tag: tag, algorithm: 15, digest_type: 2, digest_name: 'SHA-256', text: `dnssec.example. IN DS ${tag} 15 2 AABB` })
  const key = (tag, status) => ({
    key_tag: tag, algorithm: 'ED25519', status,
    dnskey: `dnssec.example. IN DNSKEY 257 3 15 KEY${tag}`,
    ds: [ds(tag)],
  })
  let info = { enabled: true, next_steps: 'Publish DS at parent', proof: { type: 'nsec', nsec3_salt: '', nsec3_iterations: 0, nsec3_opt_out: false }, keys: [key(401, 'active')] }
  let submitted
  let submittedProof
  await page.addInitScript(() => {
    localStorage.setItem('token', 'ui-dnssec-token')
    localStorage.setItem('user', JSON.stringify({ username: 'dnssec-admin', role: 'admin' }))
    localStorage.setItem('auth-storage', JSON.stringify({ state: {
      token: 'ui-dnssec-token', user: { username: 'dnssec-admin', role: 'admin' }, isAuthenticated: true,
    }, version: 0 }))
  })
  await page.route('**/api/v1/nameservers', (route) => route.fulfill({ status: 200, json: [] }))
  await page.route('**/api/v1/zones**', (route) => {
    const path = new URL(route.request().url()).pathname
    if (path.endsWith('/dnssec') && route.request().method() === 'GET') {
      return route.fulfill({ status: 200, json: info })
    }
    if (path.endsWith('/dnssec/rollover') && route.request().method() === 'POST') {
      submitted = route.request().postDataJSON()
      info = { ...info, enabled: true, next_steps: 'Publish replacement DS at parent', keys: [key(401, 'active'), key(902, 'new')] }
      return route.fulfill({ status: 201, json: info })
    }
    if (path.endsWith('/dnssec/proof') && route.request().method() === 'PUT') {
      submittedProof = route.request().postDataJSON()
      info = { ...info, proof: { type: 'nsec3', nsec3_salt: 'a1b2', nsec3_iterations: 12, nsec3_opt_out: true } }
      return route.fulfill({ status: 200, json: info })
    }
    if (path.endsWith('/members')) return route.fulfill({ status: 200, json: [] })
    if (path.endsWith('/revisions')) return route.fulfill({ status: 200, json: [] })
    return route.fulfill({
      status: 200, headers: { 'x-total-count': '1' }, json: [{
        id: 'dnssec-ui-zone', domain: 'dnssec.example', status: 'active', zone_type: 'primary',
        access: 'owner', geodns_enabled: false, ecs_enabled: false, tags: [],
      }],
    })
  })

  await page.goto('/admin/zones')
  await page.getByRole('button', { name: 'Manage dnssec.example' }).click()
  await page.getByRole('button', { name: 'DNSSEC', exact: true }).click()
  await page.getByRole('button', { name: 'Start key rollover' }).click()
  await expect.poll(() => submitted).toEqual({ algorithm: 'ED25519' })
  await expect(page.getByText('new (rollover)')).toBeVisible()
  const retire = page.getByRole('button', { name: 'Retire this key' })
  await expect(retire).toHaveCount(1)
  await expect(retire).toBeDisabled()
  await page.getByLabel('The replacement DS is published at the registrar and the old DS has expired from caches').check()
  await expect(retire).toBeEnabled()

  await page.getByLabel('Denial proof type').selectOption('nsec3')
  await page.getByLabel('NSEC3 salt').fill('a1b2')
  await page.getByLabel('NSEC3 iterations').fill('12')
  await page.getByLabel('Enable NSEC3 Opt-Out').check()
  await page.getByRole('button', { name: 'Save denial proof' }).click()
  await expect.poll(() => submittedProof).toEqual({
    proof_type: 'nsec3', nsec3_salt: 'a1b2', nsec3_iterations: 12, nsec3_opt_out: true,
  })
})
