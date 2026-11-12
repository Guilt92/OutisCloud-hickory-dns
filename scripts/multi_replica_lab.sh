#!/bin/bash
# Multi-replica lab: TWO real control_api processes against ONE PostgreSQL database.
# Verifies (with real processes, not unit tests): shared rate limits, single analytics writer, no duplicate or lost
# samples, behaviour after killing the writer / restarting replicas, and after a database outage.
# Usage: scripts/multi_replica_lab.sh <control_api> <postgres-url-without-dbname> <dbname> <pg-docker-container>
set -u
API_BIN=${1:?}; PGURL=${2:?}; DB=${3:?}; PGC=${4:?}
W=$(mktemp -d); chmod 755 "$W"; fail=0; PA=18101; PB=18102; PIDA=""; PIDB=""; STUB=""
cleanup() { kill $PIDA $PIDB $STUB ${RES:-} 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
ok() { if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
psqlq() { docker exec "$PGC" psql -U postgres -d "$DB" -qtAc "$1"; }
docker exec "$PGC" psql -U postgres -qc "DROP DATABASE IF EXISTS $DB WITH (FORCE)" -c "CREATE DATABASE $DB" >/dev/null

# deterministic exporter: every scrape adds 7 to the global counter and 10 ok + 1 error to one zone; /freeze stops the counting
cat > "$W/stub.py" <<'PY'
import http.server, sys
log = open(sys.argv[1], "a"); st = {"t": 1000, "z": 0, "e": 0, "frozen": False}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/freeze": st["frozen"] = True; self.send_response(200); self.end_headers(); return
        if not st["frozen"]: st["t"] += 7; st["z"] += 10; st["e"] += 1
        log.write("%d %d\n" % (st["t"], st["z"] + st["e"])); log.flush()
        b = ('hickory_request_total{class="in"} %d\nhickory_zone_queries_total{zone="rep-lab.example.",result="ok"} %d\nhickory_zone_queries_total{zone="rep-lab.example.",result="error"} %d\n' % (st["t"], st["z"], st["e"])).encode()
        self.send_response(200); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
http.server.HTTPServer(("127.0.0.1", 19110), H).serve_forever()
PY
python3 "$W/stub.py" "$W/scrapes.log" & STUB=$!
# instant DNS answers (NOERROR, no data) so that lookups finish in milliseconds and a 30-call burst stays inside one 60 s limiter window
cat > "$W/resolver.py" <<'PYRES'
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 19111))
while True:
    q, a = s.recvfrom(1500); i = 12
    while q[i]: i += 1 + q[i]
    s.sendto(q[:2] + struct.pack(">HHHHH", 0x8180, 1, 0, 0, 0) + q[12:i + 5], a)
PYRES
python3 "$W/resolver.py" & RES=$!

export DATABASE_URL="$PGURL/$DB" JWT_SECRET=replica-lab-secret-0123456789abcdef0123456789 ADMIN_USERNAME=admin ADMIN_PASSWORD='Lab-Admin-Pw-9911' \
  ALLOWED_ORIGINS=http://127.0.0.1:5173 LISTEN_ADDRS_IPV4=127.0.0.1 LOGIN_RATE_PER_IP=100000 DNS_LOOKUP_RATE_PER_MIN=20 DNS_LOOKUP_RESOLVERS=127.0.0.1:19111 DNS_LOOKUP_TIMEOUT_MS=500 \
  DNS_METRICS_URL=http://127.0.0.1:19110/metrics ANALYTICS_SAMPLE_SECS=2 ANALYTICS_LEASE_SECS=6 PUBLIC_NAMESERVERS=ns1.example.test.,ns2.example.test.
start() { # name port
  mkdir -p "$W/dns$1"; HICKORY_DNS_DIR="$W/dns$1" BIND_ADDR=127.0.0.1:$2 "$API_BIN" >"$W/api$1.log" 2>&1 & echo $!
}
waitup() { for i in $(seq 1 80); do curl -sf http://127.0.0.1:$1/health >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }
# --- start both replicas AT THE SAME TIME (concurrent migrations)
PIDA=$(start A $PA); PIDB=$(start B $PB)
waitup $PA; ok "replica A is up" $?; waitup $PB; ok "replica B is up (simultaneous start, concurrent migrations)" $?
login() { curl -s -X POST http://127.0.0.1:$1/api/v1/auth/login -H 'content-type: application/json' -d "{\"username\":\"$2\",\"password\":\"$3\"}"; }
TA=$(login $PA admin 'Lab-Admin-Pw-9911' | j 'd["token"]'); TB=$(login $PB admin 'Lab-Admin-Pw-9911' | j 'd["token"]')
[ -n "$TA" ] && [ -n "$TB" ]; ok "admin token issued by A is accepted by B (shared secret) " $?
curl -s -X POST http://127.0.0.1:$PA/api/v1/users -H "authorization: Bearer $TA" -H 'content-type: application/json' -d '{"username":"repl_user","password":"Repl-User-Pw-1234","role":"editor"}' >/dev/null
curl -s -X POST http://127.0.0.1:$PA/api/v1/zones -H "authorization: Bearer $TA" -H 'content-type: application/json' -d '{"domain":"rep-lab.example","geodns_enabled":false}' >/dev/null
UT=$(login $PA repl_user 'Repl-User-Pw-1234' | j 'd["token"]')
[ -n "$UT" ] && [ "$UT" != None ]; ok "customer account can log in on A and B" $?
lk() { curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:$1/api/v1/dns/lookup -H "authorization: Bearer $UT" -H 'content-type: application/json' -d '{"domain":"x.example","record_type":"A"}'; }
# stay away from a 60 s window boundary (windows are aligned on the database clock)
wait_window() { while [ "$(psqlq "select (extract(second from now()))::int < 35 and (extract(second from now()))::int > 3")" != t ]; do sleep 1; done; }

# --- 1. shared lookup budget (20/min) across replicas
wait_window
allowed=0; limited=0
codes=""
for i in $(seq 1 30); do if [ $((i%2)) = 0 ]; then c=$(lk $PA); else c=$(lk $PB); fi; codes="$codes $c"; [ "$c" = 429 ] && limited=$((limited+1)) || allowed=$((allowed+1)); done
echo "     status codes:$codes"
[ $allowed = 20 ] && [ $limited = 10 ]; ok "lookup budget is shared: 30 calls alternating A/B -> $allowed allowed, $limited limited (expected 20/10)" $?
# --- 2. a restart does not reset the budget; switching replica does not either
kill -9 $PIDA; wait $PIDA 2>/dev/null; PIDA=$(start A $PA); waitup $PA
[ "$(lk $PA)" = 429 ] && [ "$(lk $PB)" = 429 ]; ok "after SIGKILL+restart of A the exhausted budget is still exhausted on both replicas" $?
# --- 3. shared login budget (10/min per username)
wait_window
first10=0; rest=0
for i in $(seq 1 14); do P=$PA; [ $((i%2)) = 0 ] && P=$PB; c=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:$P/api/v1/auth/login -H 'content-type: application/json' -d '{"username":"victim","password":"wrong"}'); if [ $i -le 10 ]; then [ "$c" = 401 ] && first10=$((first10+1)); else [ "$c" = 429 ] && rest=$((rest+1)); fi; done
[ $first10 = 10 ] && [ $rest = 4 ]; ok "login budget is shared: attempts 1-10 -> 401 ($first10), attempts 11-14 alternating replicas -> 429 ($rest)" $?
# --- 4. exactly one analytics writer
sleep 8
holders=$(psqlq "select count(*) from collector_lease where name='analytics' and expires_at > now()")
[ "$holders" = 1 ]; ok "exactly one valid collector lease" $?
LEADER=$(psqlq "select holder from collector_lease where name='analytics'" | cut -d- -f1)
echo "     lease holder pid: $LEADER (A=$PIDA B=$PIDB)"
nlead=$(grep -c "is now the writer" "$W/apiA.log" "$W/apiB.log" | awk -F: '{s+=$2} END{print s}')
# --- 5. kill the writer: the other replica must take over, samples stay exact
if [ "$LEADER" = "$PIDA" ]; then kill -9 $PIDA; wait $PIDA 2>/dev/null; DEAD=A; else kill -9 $PIDB; wait $PIDB 2>/dev/null; DEAD=B; fi
sleep 14
NEWL=$(psqlq "select holder from collector_lease where name='analytics' and expires_at > now()" | cut -d- -f1)
[ -n "$NEWL" ] && [ "$NEWL" != "$LEADER" ]; ok "after killing the writer (SIGKILL) the surviving replica took the lease within the lease time (new holder $NEWL)" $?
# restart the dead replica: it must not become a second writer
if [ $DEAD = A ]; then PIDA=$(start A $PA); waitup $PA; else PIDB=$(start B $PB); waitup $PB; fi
sleep 6
[ "$(psqlq "select count(*) from collector_lease where name='analytics' and expires_at > now()")" = 1 ]; ok "restarted replica joined as follower (still exactly one lease)" $?
# --- 6. database outage
docker stop "$PGC" >/dev/null; sleep 9; docker start "$PGC" >/dev/null
for i in $(seq 1 40); do docker exec "$PGC" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
for i in $(seq 1 40); do curl -sf http://127.0.0.1:$PA/ready >/dev/null 2>&1 && curl -sf http://127.0.0.1:$PB/ready >/dev/null 2>&1 && break; sleep 1; done
sleep 12
curl -sf http://127.0.0.1:$PA/health >/dev/null && curl -sf http://127.0.0.1:$PB/health >/dev/null; ok "both replicas survived a 9 s database outage and are healthy again" $?
[ "$(psqlq "select count(*) from collector_lease where name='analytics' and expires_at > now()")" = 1 ]; ok "after the outage there is again exactly one collector lease" $?
grep -qi "retry\|cannot renew\|unavailable\|failed" "$W/apiA.log" "$W/apiB.log"; ok "the outage was logged by the collector/pool (not silent)" $?
# --- 7. exactness: freeze the exporter, let the collector catch up, compare with the exporter's own log
curl -s http://127.0.0.1:19110/freeze >/dev/null; sleep 9
read -r T0 Z0 < <(head -1 "$W/scrapes.log"); read -r T1 Z1 < <(tail -1 "$W/scrapes.log")
sumr=$(psqlq "select coalesce(sum(requests),0) from analytics_samples"); sumz=$(psqlq "select coalesce(sum(queries),0) from zone_query_samples where domain='rep-lab.example'")
echo "     exporter: global $T0 -> $T1 (delta $((T1-T0))), zone $Z0 -> $Z1 (delta $((Z1-Z0)))   stored: global $sumr, zone $sumz"
[ "$sumr" = "$((T1-T0))" ]; ok "stored global samples == exporter delta ($sumr): no duplicates and nothing lost across leader kill, restarts and DB outage" $?
[ "$sumz" = "$((Z1-Z0))" ]; ok "stored per-zone samples == exporter delta ($sumz)" $?
dups=$(psqlq "select count(*) from (select ts from analytics_samples group by ts having count(*)>1) x")
[ "$dups" = 0 ]; ok "no timestamp has more than one global sample row" $?
echo; [ $fail = 0 ] && echo "ALL MULTI-REPLICA LAB CHECKS PASSED" || echo "MULTI-REPLICA LAB FAILED"; exit $fail
