#!/usr/bin/env bash
# Check TLS certificate expiry. Exit 0 = all outside warning window, 1 = warning,
# 2 = critical/unparseable. Usage: scripts/check_certs.sh FILE_OR_DIR... [--json]
# Environment: CERT_WARN_DAYS (default 30), CERT_CRIT_DAYS (default 7).
set -euo pipefail
WARN=${CERT_WARN_DAYS:-30}; CRIT=${CERT_CRIT_DAYS:-7}; JSON=0; OPENSSL=${OPENSSL:-openssl}
files=()
for arg in "$@"; do
  case "$arg" in
    --json) JSON=1 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) if [ -d "$arg" ]; then
         while IFS= read -r f; do files+=("$f"); done < <(find "$arg" -type f \( -name '*.pem' -o -name '*.crt' \) | sort)
       else files+=("$arg"); fi ;;
  esac
done
[ "${#files[@]}" -gt 0 ] || { echo "usage: $0 FILE_OR_DIR... [--json]" >&2; exit 2; }
now=$(date +%s); worst=0; rows=()
for f in "${files[@]}"; do
  if ! end=$("$OPENSSL" x509 -in "$f" -noout -enddate 2>/dev/null | cut -d= -f2-); then
    rows+=("$f|unparseable|0|2"); worst=2; continue
  fi
  exp=$(date -d "$end" +%s 2>/dev/null || date -j -f '%b %d %T %Y %Z' "$end" +%s 2>/dev/null || true)
  if [ -z "${exp:-}" ]; then rows+=("$f|unparseable|0|2"); worst=2; continue; fi
  days=$(( (exp - now) / 86400 ))
  status=ok; code=0
  if [ "$days" -le "$CRIT" ]; then status=critical; code=2; worst=2
  elif [ "$days" -le "$WARN" ]; then status=warning; code=1; [ "$worst" -lt 1 ] && worst=1; fi
  rows+=("$f|$status|$days|$code")
done
if [ "$JSON" = 1 ]; then
  printf '['
  first=1
  for row in "${rows[@]}"; do
    IFS='|' read -r f status days code <<<"$row"
    [ "$first" = 1 ] || printf ','; first=0
    printf '{"file":"%s","status":"%s","days_left":%s}' "$f" "$status" "$days"
  done
  printf ']\n'
else
  printf '%-60s %-10s %s\n' FILE STATUS DAYS_LEFT
  for row in "${rows[@]}"; do IFS='|' read -r f status days code <<<"$row"; printf '%-60s %-10s %s\n' "$f" "$status" "$days"; done
fi
exit "$worst"
