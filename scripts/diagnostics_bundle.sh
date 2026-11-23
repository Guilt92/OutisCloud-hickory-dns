#!/usr/bin/env bash
# Collect a redacted diagnostics bundle for incident support. Never includes env
# file contents, tokens, passwords or DNSSEC private keys.
set -euo pipefail
OUT=${1:-"diagnostics-$(date +%Y%m%d-%H%M%S).tar.gz"}
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/logs" "$TMP/state"
{
  echo "generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host=$(hostname)"
  echo "commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "kernel=$(uname -a)"
  docker compose version 2>/dev/null || true
} > "$TMP/summary.txt"
docker compose ps > "$TMP/state/compose-ps.txt" 2>&1 || true
docker compose config --services > "$TMP/state/services.txt" 2>&1 || true
for svc in control-api dns-server db ui prometheus alertmanager grafana; do
  docker compose logs --no-color --since 6h "$svc" > "$TMP/logs/$svc.log" 2>&1 || true
done
for url in http://127.0.0.1:8080/health http://127.0.0.1:9000/health http://127.0.0.1:9000/ready; do
  name=$(echo "$url" | tr '/:' '__'); curl -fsS --max-time 5 "$url" > "$TMP/state/$name.json" 2>&1 || echo "unreachable" > "$TMP/state/$name.json"
done
curl -fsS --max-time 5 http://127.0.0.1:9000/metrics > "$TMP/state/dns-metrics.txt" 2>&1 || true
curl -fsS --max-time 5 http://127.0.0.1:8080/metrics > "$TMP/state/api-metrics.txt" 2>&1 || true
df -h > "$TMP/state/disk.txt" 2>&1 || true
docker stats --no-stream > "$TMP/state/docker-stats.txt" 2>&1 || true
find "$TMP" -type f -exec sed -i -E \
  -e 's/(ocd_[A-Za-z0-9_-]{8})[A-Za-z0-9_-]+/\1REDACTED/g' \
  -e 's/((password|secret|token|license_key|authorization)[^:=]*[:=][[:space:]]*)[^[:space:]",]+/\1REDACTED/Ig' {} +
tar -czf "$OUT" -C "$TMP" .
echo "wrote $OUT"
