#!/usr/bin/env bash
# Generate a static status page from local health/readiness endpoints.
# Usage: scripts/status_page.sh [output.html]
# Exit 0 when all components are healthy, 1 when any check fails (the page is still written).
set -euo pipefail
OUT=${1:-status.html}
api=${API_HEALTH_URL:-http://127.0.0.1:8080/health}
dns=${DNS_HEALTH_URL:-http://127.0.0.1:9000/health}
ready=${DNS_READY_URL:-http://127.0.0.1:9000/ready}
check() { if curl -fsS --max-time 5 "$1" >/dev/null 2>&1; then echo up; else echo down; fi; }
api_s=$(check "$api"); dns_s=$(check "$dns"); ready_s=$(check "$ready")
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if [ "$api_s$dns_s$ready_s" = upupup ]; then overall=operational; rc=0; else overall=degraded; rc=1; fi
cat > "$OUT" <<HTML
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OutisCloud DNS status</title>
<style>body{font:16px system-ui,sans-serif;max-width:42rem;margin:3rem auto;padding:0 1rem;color:#111}
.up{color:#0a7d32}.down{color:#b00020}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:.5rem;border-bottom:1px solid #ddd}</style>
</head><body><h1>OutisCloud DNS</h1>
<p><strong class="$([ "$rc" = 0 ] && echo up || echo down)">$overall</strong> — checked $now UTC</p>
<table><thead><tr><th>Component</th><th>Status</th></tr></thead><tbody>
<tr><td>Control API</td><td class="$api_s">$api_s</td></tr>
<tr><td>DNS service</td><td class="$dns_s">$dns_s</td></tr>
<tr><td>DNS readiness</td><td class="$ready_s">$ready_s</td></tr>
</tbody></table>
<p>This page reports only availability; incident details are published separately.</p>
</body></html>
HTML
echo "wrote $OUT ($overall)"
exit "$rc"
