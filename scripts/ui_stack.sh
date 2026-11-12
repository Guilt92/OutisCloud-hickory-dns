#!/bin/bash
# Disposable full stack for the browser test suites (web/ui/tests/*.cjs):
#   PostgreSQL database (existing container/server) + control API + hickory-dns + a deterministic Prometheus stub
#   (for the analytics collector) + the Vite dev server (UI built from the given UI directory).
# Usage: scripts/ui_stack.sh start <workdir> <ui-dir> <control_api> <hickory-dns> <postgres-url-without-dbname> <pg-docker-container>
#        scripts/ui_stack.sh stop  <workdir>
# After `start`, `source <workdir>/env.sh` exports the URLs/credentials the tests use.
set -u
cmd=${1:?start|stop}; W=${2:?workdir}
if [ "$cmd" = stop ]; then
  [ -f "$W/pids" ] && while read -r p; do kill "$p" 2>/dev/null; done < "$W/pids"; sleep 1; exit 0
fi
UI=${3:?ui dir}; API_BIN=${4:?}; DNS_BIN=${5:?}; PGURL=${6:?}; PGC=${7:?}
mkdir -p "$W/dns"; chmod 755 "$W"; : > "$W/pids"; : > "$W/zones.txt"
docker exec "$PGC" psql -U postgres -qc "DROP DATABASE IF EXISTS outis_ui" -c "CREATE DATABASE outis_ui" >/dev/null
ADMIN_PW='Adm1n-Strong-Pw-77'
cat > "$W/metrics_stub.py" <<'PY'
import http.server, os
STATE = os.environ["STATE"]; zones = {}; total = [1000]
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        names = [l.strip().rstrip(".").lower() for l in open(STATE) if l.strip()]
        for z in names:
            ok, er = zones.get(z, (0, 0)); zones[z] = (ok + 10, er + 1)
        total[0] += 11 * len(names) + 5          # + unattributed requests (names outside any zone)
        out = ["# TYPE hickory_request_total counter", 'hickory_request_total{class="in"} %d' % total[0]]
        for z, (ok, er) in zones.items():
            out.append('hickory_zone_queries_total{zone="%s.",result="ok"} %d' % (z, ok))
            out.append('hickory_zone_queries_total{zone="%s.",result="error"} %d' % (z, er))
            n = ok // 10                      # scrapes seen for this zone: deterministic breakdowns (6 A + 4 MX, 7 DE + 2 private + 1 unknown + 1 GeoIP-less per scrape)
            out.append('hickory_zone_qtype_total{zone="%s.",qtype="A"} %d' % (z, 6 * n)); out.append('hickory_zone_qtype_total{zone="%s.",qtype="MX"} %d' % (z, 4 * n))
            out.append('hickory_zone_country_total{zone="%s.",country="DE"} %d' % (z, 7 * n)); out.append('hickory_zone_country_total{zone="%s.",country="ZZ-private"} %d' % (z, 2 * n))
            out.append('hickory_zone_country_total{zone="%s.",country="ZZ-unknown"} %d' % (z, 1 * n)); out.append('hickory_zone_country_total{zone="%s.",country="ZZ-nodata"} %d' % (z, 0 * n))
        out.append('hickory_geoip_build_epoch 1771921361')
        b = ("\n".join(out) + "\n").encode()
        self.send_response(200); self.send_header("content-type", "text/plain"); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
http.server.HTTPServer(("127.0.0.1", 19100), H).serve_forever()
PY
STATE="$W/zones.txt" python3 "$W/metrics_stub.py" >"$W/stub.log" 2>&1 & echo $! >> "$W/pids"
export DATABASE_URL="$PGURL/outis_ui" JWT_SECRET=ui-stack-secret-0123456789abcdef0123456789 ADMIN_USERNAME=admin ADMIN_PASSWORD="$ADMIN_PW" \
  ALLOWED_ORIGINS=http://127.0.0.1:5173 HICKORY_DNS_DIR="$W/dns" PUBLIC_NAMESERVERS=ns1.example.test.,ns2.example.test. LOGIN_RATE_PER_IP=5000 \
  BIND_ADDR=127.0.0.1:8080 LISTEN_ADDRS_IPV4=127.0.0.1 DNS_VERIFY_RESOLVER=127.0.0.1:5402 DNS_LOOKUP_RATE_PER_MIN=500 \
  ANALYTICS_SAMPLE_SECS=2 RUST_LOG=warn
# NO_METRICS=1 starts the API without DNS_METRICS_URL (the "query statistics are not configured" state)
[ -z "${NO_METRICS:-}" ] && export DNS_METRICS_URL=http://127.0.0.1:19100/metrics
"$API_BIN" >"$W/api.log" 2>&1 & echo $! >> "$W/pids"
for i in $(seq 1 60); do curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1 && break; sleep 0.5; done
TOK=$(curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login -H 'content-type: application/json' -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
mk() { curl -s -X POST http://127.0.0.1:8080/api/v1/users -H "authorization: Bearer $TOK" -H 'content-type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\",\"role\":\"$3\"}" >/dev/null; }
mk ui_editor editorpass12 editor; mk ui_viewer viewerpass12 viewer
chmod -R a+rX "$W/dns"; cp "$DNS_BIN" "$W/hickory-dns"; chmod 755 "$W/hickory-dns"
( while sleep 1; do chmod -R a+rX "$W/dns" 2>/dev/null; done ) >/dev/null 2>&1 & echo $! >> "$W/pids"   # server runs as `nobody` after dropping privileges
"$W/hickory-dns" -c "$W/dns/named.toml" -z "$W/dns" --port 5402 >"$W/dns.log" 2>&1 & echo $! >> "$W/pids"
# UI_PREVIEW=1 serves the production bundle ($UI/dist, run `npm run build` first) which is more stable and closer to production
if ! curl -sf http://127.0.0.1:5173/ >/dev/null 2>&1; then   # reuse a UI server that is already serving
  if [ -n "${UI_PREVIEW:-}" ]; then VCMD="vite preview"; else VCMD="vite"; fi
  ( cd "$UI" && exec npx $VCMD --host 127.0.0.1 --port 5173 --strictPort >"$W/vite.log" 2>&1 ) >/dev/null 2>&1 & echo $! >> "$W/pids"
fi
for i in $(seq 1 60); do curl -sf http://127.0.0.1:5173/ >/dev/null 2>&1 && break; sleep 0.5; done
cat > "$W/env.sh" <<E
export UI_BASE=http://127.0.0.1:5173 API_BASE=http://127.0.0.1:8080 ADMIN_USER=admin ADMIN_PASS='$ADMIN_PW'
export STACK_DIR='$W' DNS_PORT=5402 PG_CONTAINER='$PGC' PG_DB=outis_ui
E
echo "stack up: $W/env.sh"
