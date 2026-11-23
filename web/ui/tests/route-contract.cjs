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
  /^\/api\/v1\/users\/\*\/password$/,
  /^\/api\/v1\/servers$/,
  /^\/api\/v1\/servers\/\*$/,
  /^\/api\/v1\/servers\/\*\/status$/,
  /^\/api\/v1\/nameservers$/,
  /^\/api\/v1\/nameservers\/\*$/,
  /^\/api\/v1\/zones$/,
  /^\/api\/v1\/zones\/\*$/,
  /^\/api\/v1\/zones\/\*\/(export|import|records|members|revisions|verify|dnssec|tenant|metadata|clone|lifecycle|transfer-policy)$/,
  /^\/api\/v1\/zones\/\*\/records\/\*$/,
  /^\/api\/v1\/zones\/\*\/records\/\*\/metadata$/,
  /^\/api\/v1\/zones\/\*\/members\/\*$/,
  /^\/api\/v1\/zones\/\*\/revisions\/\*\/restore$/,
  /^\/api\/v1\/zones\/\*\/revisions\/\*\/diff$/,
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
  /^\/api\/v1\/audit\/logs\/export$/,
  /^\/api\/v1\/audit\/logs\/\*$/,
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
const backendRoutes = new Set()
const backendRoot = path.resolve(root, '../../crates/control_api/src')
for (const entry of fs.readdirSync(backendRoot)) {
  if (!entry.endsWith('.rs') || entry.endsWith('_tests.rs')) continue
  const source = fs.readFileSync(path.join(backendRoot, entry), 'utf8')
  const route = /\.route\(\s*"([^"]+)"\s*,\s*web::(get|post|put|patch|delete)\(\)/g
  let match
  while ((match = route.exec(source))) {
    backendRoutes.add(`${match[2].toUpperCase()} ${match[1].replace(/\{[^}]+\}/g, '*')}`)
  }
}
for (const file of files) {
  const text = fs.readFileSync(file, 'utf8')
  const re = /api\.(get|post|put|delete|patch)\(\s*[`']([^`']+)[`']/g
  let m
  while ((m = re.exec(text))) {
    if (m[2].includes('${path}')) {
      const actions = [...text.matchAll(/\bact\('([^']+)'/g)]
      if (!actions.length) throw new Error(`Unresolved dynamic API path in ${file}`)
      for (const action of actions) {
        found.add(`${m[1].toUpperCase()} ${m[2].replace('${path}', action[1]).replace(/\$\{[^}]+\}/g, '*')}`)
      }
    } else {
      const endpoint = m[2].replace(/\$\{[^}]+\}/g, '*')
      found.add(`${m[1].toUpperCase()} ${endpoint}`)
    }
  }
}

const violations = [...found].filter((route) => {
  const endpoint = route.slice(route.indexOf(' ') + 1)
  return !ALLOWED.some((re) => re.test(endpoint)) || !backendRoutes.has(route)
}).sort()
if (violations.length) {
  console.error('Frontend route contract violations:')
  for (const v of violations) console.error(`  ${v}`)
  process.exit(1)
}

console.log(`Route contract OK: ${found.size} frontend method/path pairs match backend routes`)
