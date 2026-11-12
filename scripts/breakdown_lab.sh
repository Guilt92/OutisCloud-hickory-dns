#!/bin/bash
# Record-type / country breakdown lab (real DNS server + real GeoLite2-Country + real control API collector).
# The DNS server runs in a network namespace and is queried with `dig -b <addr>` from addresses that belong to known
# countries (they exist only inside the lab namespace). A relay on the host forwards the namespace's Prometheus endpoint
# to the control API collector. Expected counts are exact.
# Needs: root, iproute2, dig, python3, curl, PostgreSQL, built binaries, GeoLite2-Country.mmdb.
# Usage: scripts/breakdown_lab.sh <control_api> <hickory-dns> <geoip.mmdb> <postgres-url-without-dbname> <dbname> <pg-docker-container>
set -u
API_BIN=${1:?}; DNS_BIN=${2:?}; MMDB=${3:?}; PGURL=${4:?}; DB=${5:?}; PGC=${6:?}
W=$(mktemp -d); chmod 755 "$W"; fail=0; SRV=""; APIP=""; RELAY=""; P=18120
cleanup() { ip netns del bd-srv 2>/dev/null; ip netns del bd-cli 2>/dev/null; kill $SRV $APIP $RELAY 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
ok() { if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
docker exec "$PGC" psql -U postgres -qc "DROP DATABASE IF EXISTS $DB WITH (FORCE)" -c "CREATE DATABASE $DB" >/dev/null
cp "$MMDB" "$W/geo.mmdb"; chmod 644 "$W/geo.mmdb"

ip netns add bd-srv; ip netns add bd-cli
ip link add vS type veth peer name vC; ip link set vS netns bd-srv; ip link set vC netns bd-cli
ip -n bd-srv addr add 10.210.0.1/24 dev vS; ip -n bd-srv link set vS up; ip -n bd-srv link set lo up
ip -n bd-cli addr add 10.210.0.2/24 dev vC; ip -n bd-cli link set vC up; ip -n bd-cli link set lo up
for a in 8.8.8.8 5.9.0.1 200.160.2.3; do ip -n bd-cli addr add $a/32 dev vC; ip -n bd-srv route add $a/32 dev vS; done
ip netns exec bd-srv sysctl -qw net.ipv4.ip_unprivileged_port_start=0

# relay: the collector (host) -> the exporter inside the namespace
cat > "$W/relay.py" <<'PY'
import http.server, subprocess
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        b = subprocess.run(["ip","netns","exec","bd-srv","curl","-s","http://127.0.0.1:19121/metrics"], capture_output=True).stdout
        self.send_response(200); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
http.server.HTTPServer(("127.0.0.1", 19122), H).serve_forever()
PY
python3 "$W/relay.py" & RELAY=$!

export DATABASE_URL="$PGURL/$DB" JWT_SECRET=bd-lab-secret-0123456789abcdef0123456789 ADMIN_USERNAME=admin ADMIN_PASSWORD='Lab-Admin-Pw-9911' \
  ALLOWED_ORIGINS=http://127.0.0.1:5173 HICKORY_DNS_DIR="$W/dns" PUBLIC_NAMESERVERS=ns1.example.test.,ns2.example.test. LOGIN_RATE_PER_IP=1000 BIND_ADDR=127.0.0.1:$P \
  LISTEN_ADDRS_IPV4=0.0.0.0 PROMETHEUS_LISTEN_ADDR=127.0.0.1:19121 DNS_METRICS_URL=http://127.0.0.1:19122/metrics ANALYTICS_SAMPLE_SECS=2 DNS_LOOKUP_RESOLVERS=127.0.0.1:9
mkdir -p "$W/dns"; "$API_BIN" >"$W/api.log" 2>&1 & APIP=$!
for i in $(seq 1 60); do curl -sf http://127.0.0.1:$P/health >/dev/null 2>&1 && break; sleep 0.5; done
login() { curl -s -X POST http://127.0.0.1:$P/api/v1/auth/login -H 'content-type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}" | j 'd["token"]'; }
api() { local t=$1; shift; curl -s -X "$1" "http://127.0.0.1:$P$2" -H "authorization: Bearer $t" -H 'content-type: application/json' ${3:+-d "$3"}; }
AT=$(login admin 'Lab-Admin-Pw-9911')
for u in alice carol; do api $AT POST /api/v1/users "{\"username\":\"bd_$u\",\"password\":\"Lab-Customer-Pw-$u-1\",\"role\":\"editor\"}" >/dev/null; done
TA=$(login bd_alice 'Lab-Customer-Pw-alice-1'); TC=$(login bd_carol 'Lab-Customer-Pw-carol-1')
ZA=$(api $TA POST /api/v1/zones '{"domain":"bd-alice.example","geodns_enabled":false}' | j 'd.get("id") or d["data"]["id"]')
ZC=$(api $TC POST /api/v1/zones '{"domain":"bd-carol.example","geodns_enabled":false}' | j 'd.get("id") or d["data"]["id"]')
api $TA POST /api/v1/zones/$ZA/records '{"name":"www","record_type":"A","value":"192.0.2.10","ttl":300}' >/dev/null
api $TC POST /api/v1/zones/$ZC/records '{"name":"www","record_type":"A","value":"192.0.2.20","ttl":300}' >/dev/null
chmod -R a+rX "$W/dns"; cp "$DNS_BIN" "$W/hickory-dns"; chmod 755 "$W/hickory-dns"
start_dns() { # extra env
  ip netns exec bd-srv env DNS_ZONE_QUERY_METRICS=true DNS_ZONE_BREAKDOWN=true PROMETHEUS_LISTEN_ADDR=127.0.0.1:19121 "$@" "$W/hickory-dns" -c "$W/dns/named.toml" -z "$W/dns" --port 53 >"$W/dns.log" 2>&1 & SRV=$!
  for i in $(seq 1 60); do ip netns exec bd-srv curl -sf http://127.0.0.1:19121/metrics >/dev/null 2>&1 && break; sleep 0.5; done; }
start_dns GEOIP_DB_PATH="$W/geo.mmdb"
sleep 6   # collector baseline before any traffic
q() { # src zone type count
  for i in $(seq 1 $4); do ip netns exec bd-cli dig -b $1 +time=1 +tries=1 +short @10.210.0.1 $2 $3 >/dev/null 2>&1; done; }
q 8.8.8.8 www.bd-alice.example A 6; q 5.9.0.1 www.bd-alice.example A 4; q 200.160.2.3 bd-alice.example MX 3; q 10.210.0.2 bd-alice.example TXT 2
q 5.9.0.1 www.bd-carol.example A 5
sleep 8
A=$(api $TA GET '/api/v1/analytics/tenant?range=1h'); C=$(api $TC GET '/api/v1/analytics/tenant?range=1h')
echo "$A" | j '{x["qtype"]:x["queries"] for x in d["breakdown"]["qtypes"]}' | grep -q "{'A': 10, 'MX': 3, 'TXT': 2}"; ok "alice record types exactly A=10 MX=3 TXT=2 -> $(echo "$A" | j '{x["qtype"]:x["queries"] for x in d["breakdown"]["qtypes"]}')" $?
echo "$A" | j '{(x["code"] or x["kind"]):x["queries"] for x in d["breakdown"]["countries"]}' | grep -q "'US': 6" && echo "$A" | j '{(x["code"] or x["kind"]):x["queries"] for x in d["breakdown"]["countries"]}' | grep -q "'DE': 4" && echo "$A" | j '{(x["code"] or x["kind"]):x["queries"] for x in d["breakdown"]["countries"]}' | grep -q "'BR': 3" && echo "$A" | j '{(x["code"] or x["kind"]):x["queries"] for x in d["breakdown"]["countries"]}' | grep -q "'private': 2"
ok "alice countries US=6 DE=4 BR=3 private=2 (real GeoLite2 lookups) -> $(echo "$A" | j '{(x["code"] or x["kind"]):x["queries"] for x in d["breakdown"]["countries"]}')" $?
echo "$C" | j '{x["qtype"]:x["queries"] for x in d["breakdown"]["qtypes"]}' | grep -q "{'A': 5}"; ok "carol sees only her own 5 A queries" $?
echo "$C" | j '{(x["code"] or x["kind"]):x["queries"] for x in d["breakdown"]["countries"]}' | grep -q "{'DE': 5}"; ok "carol countries exactly DE=5 (no data of alice's zone)" $?
echo "$A" | j 'd["breakdown"]["country_status"]' | grep -qx ok; ok "country status ok; GeoIP info reported: $(echo "$A" | j 'd["breakdown"]["geoip"]')" $?
grep -q "10.210.0.2\|8.8.8.8\|5.9.0.1" <(ip netns exec bd-srv curl -s http://127.0.0.1:19121/metrics); [ $? -ne 0 ]; ok "no client IP address appears in the exporter output (only aggregated country codes)" $?
[ "$(psql_c() { docker exec $PGC psql -U postgres -d $DB -qtAc "$1"; }; psql_c "select count(*) from zone_country_samples where country ~ '[.:]'")" = 0 ]; ok "no address-like value is stored in the country table" $?
# GeoIP database unavailable: the SAME public address must now be reported as 'no GeoIP data', not as unknown and not as a country
kill $SRV; sleep 1; start_dns GEOIP_DB_PATH=/nonexistent/geo.mmdb
sleep 6; q 8.8.8.8 www.bd-carol.example A 4; sleep 8
C2=$(api $TC GET '/api/v1/analytics/tenant?range=1h')
echo "$C2" | j '{(x["code"] or x["kind"]):x["queries"] for x in d["breakdown"]["countries"]}' | grep -q "'no_geoip': 4"; ok "without a GeoIP database the queries are 'no_geoip' (4), distinct from unknown -> $(echo "$C2" | j '{(x["code"] or x["kind"]):x["queries"] for x in d["breakdown"]["countries"]}')" $?
echo "$C2" | j '{(x["code"] or x["kind"]):x["queries"] for x in d["breakdown"]["countries"]}' | grep -q "'DE': 5"; ok "earlier DE=5 history preserved across the DNS server restart (counter reset handled)" $?
# an address missing from a loaded database is 'unknown' (routable but not in the database): 0.0.0.0/8 reserved -> private; use a TEST-NET-like check instead
echo; [ $fail = 0 ] && echo "ALL BREAKDOWN LAB CHECKS PASSED" || echo "BREAKDOWN LAB FAILED"; exit $fail
