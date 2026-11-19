#!/usr/bin/env node
const fs = require('fs')
const path = require('path')

const root = path.resolve(__dirname, '..')
const sourceRoots = [path.join(root, 'src')]

const ALLOWED = [
  /^\/health$/,
  /^\/ready$/,
  /^\/metrics$/,
  /^\/api\/v1\/auth\/(login|logout|refresh|change-password|admin-reset-password|me)$/,
  /^\/api\/v1\/auth\/mfa\/(setup|enable|disable)$/,
  /^\/api\/v1\/users$/,
  /^\/api\/v1\/users\/\*$/,
  /^\/api\/v1\/servers$/,
  /^\/api\/v1\/servers\/\*$/,
  /^\/api\/v1\/servers\/\*\/status$/,
  /^\/api\/v1\/nameservers$/,
  /^\/api\/v1\/nameservers\/\*$/,
  /^\/api\/v1\/zones$/,
  /^\/api\/v1\/zones\/\*$/,
  /^\/api\/v1\/zones\/\*\/(export|import|records|members|revisions|verify|dnssec|tenant)$/,
  /^\/api\/v1\/zones\/\*\/records\/\*$/,
  /^\/api\/v1\/zones\/\*\/members\/\*$/,
  /^\/api\/v1\/zones\/\*\/revisions\/\*\/restore$/,
  /^\/api\/v1\/zones\/\*\/dnssec\/(enable|disable|rollover|rollover\/complete)$/,
  /^\/api\/v1\/zones\/\*\/dnssec\/\*$/,
  /^\/api\/v1\/agents\/\*\/(config|zones|bundle|ack|token\/rotate)$/,
  /^\/api\/v1\/agents\/(register|heartbeat)$/,
  /^\/api\/v1\/agents$/,
  /^\/api\/v1\/agents\/\*$/,
  /^\/api\/v1\/dns\/(generate|lookup|status)$/,
  /^\/api\/v1\/georules$/,
  /^\/api\/v1\/georules\/\*$/,
  /^\/api\/v1\/georules\/resolve$/,
  /^\/api\/v1\/config\/push$/,
  /^\/api\/v1\/audit\/logs$/,
  /^\/api\/v1\/tenants$/,
  /^\/api\/v1\/tenants\/\*$/,
  /^\/api\/v1\/tenants\/\*\/members$/,
  /^\/api\/v1\/tenants\/\*\/members\/\*$/,
  /^\/api\/v1\/overview$/,
  /^\/api\/v1\/analytics\/(global|tenant|queries)$/,
  /^\/api\/v1\/metrics\/queries$/,
]

const files = []
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(p)
    else if (/\.(js|jsx)$/.test(entry.name)) files.push(p)
  }
}
sourceRoots.forEach(walk)

const found = new Set()
for (const file of files) {
  const text = fs.readFileSync(file, 'utf8')
  const re = /api\.(?:get|post|put|delete|patch)\(\s*[`']([^`']+)[`']/g
  let m
  while ((m = re.exec(text))) {
    const endpoint = m[1].replace(/\$\{[^}]+\}/g, '*')
    found.add(endpoint)
  }
}

const violations = [...found].filter((endpoint) => !ALLOWED.some((re) => re.test(endpoint))).sort()
if (violations.length) {
  console.error('Frontend route contract violations:')
  for (const v of violations) console.error(`  ${v}`)
  process.exit(1)
}

console.log(`Route contract OK: ${found.size} frontend endpoints match backend routes`)
