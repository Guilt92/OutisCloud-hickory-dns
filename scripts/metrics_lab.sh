#!/bin/bash
# Query-statistics lab: the REAL hickory-dns Prometheus exporter feeding the control API's
# GET /api/v1/metrics/queries (dashboard "queries" counter), plus the API's /metrics gauges.
# Usage: scripts/metrics_lab.sh <control_api> <hickory-dns> <postgres-url-without-dbname> <dbname> [dnsload binary]
set -u
API_BIN=${1:?}; DNS_BIN=${2:?}; PGURL=${3:?}; DB=${4:?}; LOAD=${5:-}
W=$(mktemp -d); chmod 755 "$W"; fail=0; SRV=""; APIP=""
cleanup() { [ -n "$SRV" ] && kill $SRV 2>/dev/null; [ -n "$APIP" ] && kill $APIP 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
ok() { if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
export DATABASE_URL="$PGURL/$DB" JWT_SECRET=metrics-lab-secret-0123456789abcdef0123456789 ADMIN_USERNAME=admin ADMIN_PASSWORD='Lab-Admin-Pw-9911' \
  ALLOWED_ORIGINS=http://127.0.0.1:5173 HICKORY_DNS_DIR="$W/dns" PUBLIC_NAMESERVERS=ns1.example.test.,ns2.example.test. BIND_ADDR=127.0.0.1:18091 \
  LISTEN_ADDRS_IPV4=127.0.0.1 PROMETHEUS_LISTEN_ADDR=127.0.0.1:19100 DNS_METRICS_URL=http://127.0.0.1:19100/metrics METRICS_TOKEN=lab-metrics-token-123
mkdir -p "$W/dns"; "$API_BIN" >"$W/api.log" 2>&1 & APIP=$!
for i in $(seq 1 60); do curl -sf http://127.0.0.1:18091/health >/dev/null 2>&1 && break; sleep 0.5; done
TOK=$(curl -s -X POST http://127.0.0.1:18091/api/v1/auth/login -H 'content-type: application/json' -d '{"username":"admin","password":"Lab-Admin-Pw-9911"}' | j 'd["token"]')
api() { curl -s -X "$1" "http://127.0.0.1:18091$2" -H "authorization: Bearer $TOK" -H 'content-type: application/json' ${3:+-d "$3"}; }
ZID=$(api POST /api/v1/zones '{"domain":"metrics.test","geodns_enabled":false}' | j 'd.get("id") or d["data"]["id"]')
api POST /api/v1/zones/$ZID/records '{"name":"www","record_type":"A","value":"192.0.2.10","ttl":300}' >/dev/null
chmod -R a+rX "$W/dns"; cp "$DNS_BIN" "$W/hickory-dns"; chmod 755 "$W/hickory-dns"
grep -q 'prometheus_listen_addr = "127.0.0.1:19100"' "$W/dns/named.toml"; ok "API wrote the exporter address into named.toml" $?
"$W/hickory-dns" -c "$W/dns/named.toml" -z "$W/dns" --port 5401 >"$W/dns.log" 2>&1 & SRV=$!
for i in $(seq 1 60); do curl -sf http://127.0.0.1:19100/metrics >/dev/null 2>&1 && break; sleep 0.5; done
curl -s http://127.0.0.1:19100/metrics | grep -q "^hickory_"; ok "DNS server exports hickory_* Prometheus metrics" $?
before=$(api GET /api/v1/metrics/queries | j 'd["requests_total"]')
if [ -n "$LOAD" ]; then "$LOAD" -s 127.0.0.1:5401 -d 3 -t 2 -w 32 -q www.metrics.test:A,nope.metrics.test:A >/dev/null; else for i in $(seq 1 300); do dig +time=1 +tries=1 +short @127.0.0.1 -p 5401 www.metrics.test A >/dev/null; done; fi
sleep 1
after=$(api GET /api/v1/metrics/queries | j 'd["requests_total"]')
python3 -c "import sys; b,a=float('$before'),float('$after'); sys.exit(0 if a-b>=290 else 1)"; ok "GET /api/v1/metrics/queries counts real queries (before=$before after=$after)" $?
api GET /api/v1/metrics/queries | j 'sorted(d["counters"].keys())' | grep -q request; ok "per-counter breakdown comes from the exporter" $?
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18091/metrics); [ "$code" = 401 ] || [ "$code" = 403 ]; ok "API /metrics is refused without the token ($code)" $?
curl -s -H 'authorization: Bearer lab-metrics-token-123' http://127.0.0.1:18091/metrics | grep -q "control_api"; ok "API /metrics works with METRICS_TOKEN and exposes publication gauges" $?
[ $fail = 0 ] && echo "ALL METRICS LAB CHECKS PASSED" || echo "METRICS LAB FAILED"
exit $fail
