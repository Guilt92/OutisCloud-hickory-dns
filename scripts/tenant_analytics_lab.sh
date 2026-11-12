#!/bin/bash
# Tenant analytics lab: the REAL hickory-dns server with DNS_ZONE_QUERY_METRICS=true -> Prometheus exporter ->
# the control API's collector (persisted in PostgreSQL) -> /api/v1/analytics/{tenant,global}.
# Sends a KNOWN number of queries per zone with dig and expects exactly those numbers per tenant.
# Usage: scripts/tenant_analytics_lab.sh <control_api> <hickory-dns> <postgres-url-without-dbname> <dbname>
set -u
API_BIN=${1:?}; DNS_BIN=${2:?}; PGURL=${3:?}; DB=${4:?}
W=$(mktemp -d); chmod 755 "$W"; fail=0; SRV=""; APIP=""; P=18092; D=5403
cleanup() { [ -n "$SRV" ] && kill $SRV 2>/dev/null; [ -n "$APIP" ] && kill $APIP 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
ok() { if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
export DATABASE_URL="$PGURL/$DB" JWT_SECRET=tenant-lab-secret-0123456789abcdef0123456789 ADMIN_USERNAME=admin ADMIN_PASSWORD='Lab-Admin-Pw-9911' \
  ALLOWED_ORIGINS=http://127.0.0.1:5173 HICKORY_DNS_DIR="$W/dns" PUBLIC_NAMESERVERS=ns1.example.test.,ns2.example.test. LOGIN_RATE_PER_IP=1000 BIND_ADDR=127.0.0.1:$P \
  LISTEN_ADDRS_IPV4=127.0.0.1 PROMETHEUS_LISTEN_ADDR=127.0.0.1:19101 DNS_METRICS_URL=http://127.0.0.1:19101/metrics ANALYTICS_SAMPLE_SECS=2
mkdir -p "$W/dns"; "$API_BIN" >"$W/api.log" 2>&1 & APIP=$!
for i in $(seq 1 60); do curl -sf http://127.0.0.1:$P/health >/dev/null 2>&1 && break; sleep 0.5; done
login() { curl -s -X POST http://127.0.0.1:$P/api/v1/auth/login -H 'content-type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}" | j 'd["token"]'; }
api() { local t=$1; shift; curl -s -X "$1" "http://127.0.0.1:$P$2" -H "authorization: Bearer $t" -H 'content-type: application/json' ${3:+-d "$3"}; }
AT=$(login admin 'Lab-Admin-Pw-9911')
for u in alice carol; do api $AT POST /api/v1/users "{\"username\":\"lab_$u\",\"password\":\"Lab-Customer-Pw-$u-1\",\"role\":\"editor\"}" >/dev/null; done
TA=$(login lab_alice 'Lab-Customer-Pw-alice-1'); TC=$(login lab_carol 'Lab-Customer-Pw-carol-1')
ZA=$(api $TA POST /api/v1/zones '{"domain":"alice-lab.example","geodns_enabled":false}' | j 'd.get("id") or d["data"]["id"]')
ZC=$(api $TC POST /api/v1/zones '{"domain":"carol-lab.example","geodns_enabled":false}' | j 'd.get("id") or d["data"]["id"]')
api $TA POST /api/v1/zones/$ZA/records '{"name":"www","record_type":"A","value":"192.0.2.10","ttl":300}' >/dev/null
api $TC POST /api/v1/zones/$ZC/records '{"name":"www","record_type":"A","value":"192.0.2.20","ttl":300}' >/dev/null
chmod -R a+rX "$W/dns"; cp "$DNS_BIN" "$W/hickory-dns"; chmod 755 "$W/hickory-dns"
DNS_ZONE_QUERY_METRICS=true "$W/hickory-dns" -c "$W/dns/named.toml" -z "$W/dns" --port $D >"$W/dns.log" 2>&1 & SRV=$!
for i in $(seq 1 60); do curl -sf http://127.0.0.1:19101/metrics >/dev/null 2>&1 && break; sleep 0.5; done
sleep 5   # the collector takes its baseline scrape(s) before any traffic
q() { for i in $(seq 1 $3); do dig +time=1 +tries=1 +short @127.0.0.1 -p $D "$2" A >/dev/null 2>&1; done; }
q x www.alice-lab.example 30; q x nope.alice-lab.example 10; q x www.carol-lab.example 7; q x outside.invalid 5
curl -s http://127.0.0.1:19101/metrics | grep -q 'hickory_zone_queries_total{.*zone="alice-lab.example."'; ok "DNS server exports hickory_zone_queries_total per zone when DNS_ZONE_QUERY_METRICS=true" $?
sleep 7
A=$(api $TA GET '/api/v1/analytics/tenant?range=1h'); C=$(api $TC GET '/api/v1/analytics/tenant?range=1h')
echo "$A" | j 'd["total_queries"]' | grep -qx 40; ok "alice's tenant: exactly 40 queries (30 answered + 10 NXDOMAIN) -> got $(echo "$A" | j 'd["total_queries"]')" $?
echo "$C" | j 'd["total_queries"]' | grep -qx 7; ok "carol's tenant: exactly 7 queries -> got $(echo "$C" | j 'd["total_queries"]')" $?
echo "$A" | j '[z["domain"] for z in d["zones"]]' | grep -q "carol"; [ $? -ne 0 ]; ok "alice's analytics never mention carol's zone" $?
echo "$C" | j '[z["domain"] for z in d["zones"]]' | grep -q "alice"; [ $? -ne 0 ]; ok "carol's analytics never mention alice's zone" $?
G=$(api $AT GET '/api/v1/analytics/global?range=1h'); GT=$(echo "$G" | j 'd["total"]')
python3 -c "import sys; sys.exit(0 if $GT >= 52 else 1)"; ok "admin global counter includes the 5 unattributed REFUSED queries too (total=$GT >= 52)" $?
AD=$(api $AT GET '/api/v1/analytics/tenant?range=1h'); echo "$AD" | j 'd["total_queries"]' | grep -qx 47; ok "admin sees all attributed queries (47 = 40 + 7)" $?
[ "$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $TA" http://127.0.0.1:$P/api/v1/analytics/global)" = 403 ]; ok "customers cannot read the global view" $?
# persistence: history survives an API restart and keeps accumulating
kill $APIP; sleep 1; "$API_BIN" >"$W/api2.log" 2>&1 & APIP=$!
for i in $(seq 1 60); do curl -sf http://127.0.0.1:$P/health >/dev/null 2>&1 && break; sleep 0.5; done
TA=$(login lab_alice 'Lab-Customer-Pw-alice-1'); A2=$(api $TA GET '/api/v1/analytics/tenant?range=1h')
echo "$A2" | j 'd["total_queries"]' | grep -qx 40; ok "history is persisted: still 40 after restarting the API" $?
[ $fail = 0 ] && echo "ALL TENANT ANALYTICS LAB CHECKS PASSED" || echo "TENANT ANALYTICS LAB FAILED"; exit $fail
