#!/bin/bash
# DNS protocol conformance lab on an isolated test domain (real hickory-dns + real control API; loopback only).
# UDP + TCP, SOA/NS/A/AAAA/MX/TXT, TTLs, AA flag, no recursion, NXDOMAIN/NODATA with SOA (RFC 2308 negative TTL), REFUSED
# for foreign zones, EDNS/truncation with TCP retry, case-insensitivity, plus positive and negative controls for
# scripts/delegation_check.sh. Usage: scripts/dns_conformance_lab.sh <control_api> <hickory-dns> <postgres-url> <db> <pg-container>
set -u
API_BIN=${1:?}; DNS_BIN=${2:?}; PGURL=${3:?}; DB=${4:?}; PGC=${5:?}
W=$(mktemp -d); chmod 755 "$W"; fail=0; SRV=""; APIP=""; P=18130; D=5410
cleanup() { kill ${SRV2:-} $SRV $APIP 2>/dev/null; rm -rf "$W"; }; trap cleanup EXIT
ok() { if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
docker exec "$PGC" psql -U postgres -qc "DROP DATABASE IF EXISTS $DB WITH (FORCE)" -c "CREATE DATABASE $DB" >/dev/null
export DATABASE_URL="$PGURL/$DB" JWT_SECRET=conf-lab-secret-0123456789abcdef0123456789 ADMIN_USERNAME=admin ADMIN_PASSWORD='Lab-Admin-Pw-9911' \
  ALLOWED_ORIGINS=http://127.0.0.1:5173 HICKORY_DNS_DIR="$W/dns" PUBLIC_NAMESERVERS=ns1.example.test.,ns2.example.test. LOGIN_RATE_PER_IP=1000 BIND_ADDR=127.0.0.1:$P LISTEN_ADDRS_IPV4=127.0.0.1 DNS_LOOKUP_RESOLVERS=127.0.0.1:9 PROMETHEUS_LISTEN_ADDR=127.0.0.1:19131
mkdir -p "$W/dns"; "$API_BIN" >"$W/api.log" 2>&1 & APIP=$!
for i in $(seq 1 60); do curl -sf http://127.0.0.1:$P/health >/dev/null 2>&1 && break; sleep 0.5; done
TOK=$(curl -s -X POST http://127.0.0.1:$P/api/v1/auth/login -H 'content-type: application/json' -d '{"username":"admin","password":"Lab-Admin-Pw-9911"}' | j 'd["token"]')
api() { curl -s -X "$1" "http://127.0.0.1:$P$2" -H "authorization: Bearer $TOK" -H 'content-type: application/json' ${3:+-d "$3"}; }
mk() { api POST /api/v1/zones "{\"domain\":\"$1\",\"geodns_enabled\":false}" | j 'd.get("id") or d["data"]["id"]'; }
rec() { local v=${4//\"/\\\"}; api POST /api/v1/zones/$1/records "{\"name\":\"$2\",\"record_type\":\"$3\",\"value\":\"$v\",\"ttl\":${5:-300}}" >/dev/null; }
Z=$(mk conf.test); PZ=$(mk parent.test); CZ=$(mk child.parent.test); BZ=$(mk bad.parent.test)
rec $Z www A 192.0.2.10 301; rec $Z www AAAA 2001:db8::10 302; rec $Z @ MX "10 mail.conf.test." 303; rec $Z mail A 192.0.2.25 300; rec $Z txt TXT "hello conformance" 304
for i in $(seq 1 12); do rec $Z big TXT "$(printf 'x%.0s' $(seq 1 120))-$i" 300; done      # > 1.4 KB RRset: needs TCP at EDNS 512
rec $PZ child NS ns1.example.test.; rec $PZ child NS ns2.example.test.; rec $PZ bad NS ns1.example.test.      # bad: parent lists ONE ns, the child zone serves TWO
chmod -R a+rX "$W/dns"; cp "$DNS_BIN" "$W/hickory-dns"; chmod 755 "$W/hickory-dns"
PROMETHEUS_LISTEN_ADDR=127.0.0.1:19131 "$W/hickory-dns" -c "$W/dns/named.toml" -z "$W/dns" --port $D >"$W/dns.log" 2>&1 & SRV=$!
for i in $(seq 1 60); do dig +time=1 +tries=1 +short @127.0.0.1 -p $D www.conf.test A >/dev/null 2>&1 && break; sleep 0.5; done
[ -n "${LAB_DEBUG:-}" ] && { sleep 2; ss -lun | grep ":$D" >&2; tail -5 "$W/dns.log" >&2; }
Q() { dig +time=2 +tries=1 +norec "$@"; }
for proto in "" "+tcp"; do L=${proto:-udp}; L=${L#+}
  o=$(Q $proto @127.0.0.1 -p $D conf.test SOA); echo "$o" | grep -q "status: NOERROR" && echo "$o" | grep -q "flags: qr aa"; ok "[$L] SOA answered authoritatively (AA), NOERROR" $?
  echo "$o" | grep -q "flags:.* ra"; [ $? -ne 0 ]; ok "[$L] recursion not offered (RA clear)" $?
  o=$(Q $proto @127.0.0.1 -p $D conf.test NS); echo "$o" | grep -c "IN\s*NS" | grep -qE '^[3-9]|^2'; ok "[$L] apex NS set returned" $?
  o=$(Q $proto +noall +answer @127.0.0.1 -p $D www.conf.test A); echo "$o" | grep -q "301.*192.0.2.10"; ok "[$L] A answer with the configured TTL (301)" $?
  o=$(Q $proto +noall +answer @127.0.0.1 -p $D www.conf.test AAAA); echo "$o" | grep -q "302.*2001:db8::10"; ok "[$L] AAAA answer with TTL 302" $?
  o=$(Q $proto +noall +answer @127.0.0.1 -p $D conf.test MX); echo "$o" | grep -q "303.*10 mail.conf.test."; ok "[$L] MX answer with TTL 303" $?
  o=$(Q $proto +noall +answer @127.0.0.1 -p $D txt.conf.test TXT); echo "$o" | grep -q '304.*"hello conformance"'; ok "[$L] TXT answer with TTL 304" $?
  o=$(Q $proto @127.0.0.1 -p $D nope.conf.test A); echo "$o" | grep -q "status: NXDOMAIN" && echo "$o" | grep -q "flags: qr aa"; ok "[$L] NXDOMAIN is authoritative" $?
  echo "$o" | awk '/AUTHORITY SECTION/{f=1;next} /^$/{f=0} f && $4=="SOA"{ if ($2<=$NF && $2>0) ok=1 } END{exit ok?0:1}'; ok "[$L] NXDOMAIN carries the SOA with negative TTL <= SOA minimum (RFC 2308)" $?
  o=$(Q $proto @127.0.0.1 -p $D www.conf.test MX); echo "$o" | grep -q "status: NOERROR" && echo "$o" | grep -q "ANSWER: 0" && echo "$o" | grep -q "SOA"; ok "[$L] NODATA is NOERROR with an empty answer and the SOA" $?
  o=$(Q $proto @127.0.0.1 -p $D foreign.invalid A); echo "$o" | grep -q "status: REFUSED"; ok "[$L] names outside our zones are REFUSED" $?
  o=$(Q $proto +noall +answer @127.0.0.1 -p $D WWW.Conf.TEST A); echo "$o" | grep -qi "192.0.2.10"; ok "[$L] names are case-insensitive" $?
done
o=$(dig +time=2 +tries=1 +norec +bufsize=512 +ignore @127.0.0.1 -p $D big.conf.test TXT); echo "$o" | grep -q "flags:.* tc"; ok "large answer is truncated (TC) over UDP with a 512-byte EDNS buffer" $?
o=$(dig +time=2 +tries=1 +norec +tcp @127.0.0.1 -p $D big.conf.test TXT); [ "$(echo "$o" | grep -c 'IN\s*TXT')" -ge 12 ]; ok "the full RRset (12 TXT) is delivered over TCP" $?
o=$(Q +edns=0 +bufsize=1232 @127.0.0.1 -p $D www.conf.test A); echo "$o" | grep -q "OPT PSEUDOSECTION"; ok "EDNS0 is answered with an OPT record" $?
# KNOWN LIMITATION (documented): this DNS server does not generate referrals for names below a zone cut inside a zone it serves
# (upstream added that later). It is shown explicitly instead of being hidden:
r=$(Q @127.0.0.1 -p $D www.child.parent.test A)
echo "$r" | grep -q "flags:.* aa" && echo "NOTE  known limitation: a delegated sub-zone inside a hosted zone is answered authoritatively by the parent (no referral): $(echo "$r" | grep -o 'status: [A-Z]*')"
# parent stub that DOES answer with referrals, so delegation_check.sh can be exercised against a realistic parent
cat > "$W/parent_stub.py" <<'PYSTUB'
import socket, struct, sys
port = int(sys.argv[1]); s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port))
DELEG = {b"child.parent.test": [b"ns1.example.test", b"ns2.example.test"], b"bad.parent.test": [b"ns1.example.test"]}
def name(n): return b"".join(bytes([len(l)]) + l for l in n.split(b".")) + b"\x00"
while True:
    q, a = s.recvfrom(1500)
    i = 12; labels = []
    while q[i]: labels.append(q[i + 1:i + 1 + q[i]]); i += 1 + q[i]
    qname = b".".join(labels).lower(); qend = i + 5
    zone = next((z for z in DELEG if qname == z or qname.endswith(b"." + z)), None)
    if zone is None:
        s.sendto(q[:2] + struct.pack(">HHHHH", 0x8583, 1, 0, 0, 0) + q[12:qend], a); continue
    rr = b"".join(name(zone) + struct.pack(">HHIH", 2, 1, 900, len(name(n))) + name(n) for n in DELEG[zone])
    s.sendto(q[:2] + struct.pack(">HHHHH", 0x8000, 1, 0, len(DELEG[zone]), 0) + q[12:qend] + rr, a)
PYSTUB
python3 "$W/parent_stub.py" $((D+1)) & SRV2=$!; sleep 1
# delegation_check.sh controls (read-only tool pointed at the lab)
M="--map ns1.example.test.=127.0.0.1 --map ns2.example.test.=127.0.0.1 --ns-port $D"
out=$(scripts/delegation_check.sh child.parent.test --parent 127.0.0.1:$((D+1)) $M 2>&1); [ -n "${LAB_DEBUG:-}" ] && echo "$out" >&2; echo "$out" | grep -q "RESULT: delegation consistent" && echo "$out" | grep -q "same NS set as the parent"; ok "delegation_check: consistent delegation is confirmed (positive control)" $?
echo "$out" | grep -q "share ONE address"; ok "delegation_check: warns that both name servers share one address" $?
out=$(scripts/delegation_check.sh bad.parent.test --parent 127.0.0.1:$((D+1)) $M 2>&1); echo "$out" | grep -q "FAILED.*serves NS"; ok "delegation_check: parent/child NS mismatch is reported (negative control)" $?
out=$(scripts/delegation_check.sh missing.parent.test --parent 127.0.0.1:$((D+1)) $M 2>&1); echo "$out" | grep -q "NO delegation"; ok "delegation_check: a name that is not delegated is reported" $?
echo; [ $fail = 0 ] && echo "ALL CONFORMANCE LAB CHECKS PASSED" || echo "CONFORMANCE LAB FAILED"; exit $fail
