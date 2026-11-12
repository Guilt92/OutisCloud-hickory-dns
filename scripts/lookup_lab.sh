#!/bin/bash
# DNS Lookup end-to-end lab: the control API's POST /api/v1/dns/lookup against the REAL hickory-dns
# server, for all 12 advertised record types, cross-checked against `dig` (independent client).
# Also covers NXDOMAIN, NODATA, authorization, validation and the per-account rate limit.
# Needs: dig, python3, curl, PostgreSQL (url without db name + scratch db name), the two binaries.
# Usage: scripts/lookup_lab.sh <control_api> <hickory-dns> <postgres-url-without-dbname> <dbname>
set -u
API_BIN=${1:?control_api binary}; DNS_BIN=${2:?hickory-dns binary}; PGURL=${3:?postgres://user:pw@host:port}; DB=${4:?scratch db name}
W=$(mktemp -d); chmod 755 "$W"; fail=0; SRV=""; APIP=""; APIPORT=18091; DNSPORT=5401
cleanup() { [ -n "$SRV" ] && kill $SRV 2>/dev/null; [ -n "$APIP" ] && kill $APIP 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
ok() { if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
api() { curl -s -X "$1" "http://127.0.0.1:$APIPORT$2" -H "authorization: Bearer ${TOK:-}" -H 'content-type: application/json' ${3:+-d "$3"}; }

export DATABASE_URL="$PGURL/$DB" JWT_SECRET=lookup-lab-secret-0123456789abcdef0123456789 ADMIN_USERNAME=admin ADMIN_PASSWORD='Lab-Admin-Pw-9911' \
  ALLOWED_ORIGINS=http://127.0.0.1:5173 HICKORY_DNS_DIR="$W/dns" PUBLIC_NAMESERVERS=ns1.example.test.,ns2.example.test. LOGIN_RATE_PER_IP=1000 \
  BIND_ADDR=127.0.0.1:$APIPORT LISTEN_ADDRS_IPV4=127.0.0.1 DNS_VERIFY_RESOLVER=127.0.0.1:$DNSPORT DNS_LOOKUP_RATE_PER_MIN=40
mkdir -p "$W/dns"
"$API_BIN" >"$W/api.log" 2>&1 & APIP=$!
for i in $(seq 1 60); do curl -sf http://127.0.0.1:$APIPORT/health >/dev/null 2>&1 && break; sleep 0.5; done
TOK=$(curl -s -X POST http://127.0.0.1:$APIPORT/api/v1/auth/login -H 'content-type: application/json' -d '{"username":"admin","password":"Lab-Admin-Pw-9911"}' | j 'd["token"]')
[ -n "$TOK" ]; ok "API up and admin login works" $?

mkzone() { api POST /api/v1/zones "{\"domain\":\"$1\",\"geodns_enabled\":false}" | j 'd.get("id") or d.get("data",{}).get("id")'; }
PZ=$(mkzone parent.test); CZ=$(mkzone child.parent.test)
rec() { local v=${4//\"/\\\"}; local r; r=$(api POST /api/v1/zones/$1/records "{\"name\":\"$2\",\"record_type\":\"$3\",\"value\":\"$v\",\"ttl\":${5:-300}}"); echo "$r" | grep -q '"error"' && echo "  (record $2 $3 rejected: $r)" >&2; return 0; }
rec $CZ www A 192.0.2.10 301; rec $CZ www AAAA 2001:db8::10 302; rec $CZ @ MX "10 mail.child.parent.test." 303; rec $CZ mail A 192.0.2.25
rec $CZ txt TXT "v=spf1 mx -all" 304; rec $CZ alias CNAME www.child.parent.test. 306
rec $CZ _sip._tcp SRV "5 6 5060 sip.child.parent.test." 308; rec $CZ sip A 192.0.2.30
rec $CZ ptr PTR host.child.parent.test. 309; rec $CZ @ CAA '0 issue "letsencrypt.org"' 310
rec $PZ child NS ns1.example.test.
R=$(api POST /api/v1/zones/$CZ/dnssec/enable '{}'); CDS=$(echo "$R" | j 'd["keys"][0]["ds"][0]["text"]')
rec $PZ child DS "$(echo "$CDS" | sed 's/^.* IN DS //')" 312
api POST /api/v1/zones/$PZ/dnssec/enable '{}' >/dev/null
chmod -R a+rX "$W/dns"; cp "$DNS_BIN" "$W/hickory-dns"; chmod 755 "$W/hickory-dns"
"$W/hickory-dns" -c "$W/dns/named.toml" -z "$W/dns" --port $DNSPORT >"$W/dns.log" 2>&1 & SRV=$!
for i in $(seq 1 60); do dig +time=1 +tries=1 +short @127.0.0.1 -p $DNSPORT www.child.parent.test A >/dev/null 2>&1 && break; sleep 0.5; done

# customers: a normal user and a read-only viewer
api POST /api/v1/users '{"username":"lookupuser","password":"Lookup-User-Pw-77","role":"editor"}' >/dev/null
api POST /api/v1/users '{"username":"lookupview","password":"Lookup-View-Pw-77","role":"viewer"}' >/dev/null
UT=$(curl -s -X POST http://127.0.0.1:$APIPORT/api/v1/auth/login -H 'content-type: application/json' -d '{"username":"lookupuser","password":"Lookup-User-Pw-77"}' | j 'd["token"]')
VT=$(curl -s -X POST http://127.0.0.1:$APIPORT/api/v1/auth/login -H 'content-type: application/json' -d '{"username":"lookupview","password":"Lookup-View-Pw-77"}' | j 'd["token"]')
lk() { curl -s -X POST http://127.0.0.1:$APIPORT/api/v1/dns/lookup -H "authorization: Bearer $1" -H 'content-type: application/json' -d "{\"domain\":\"$2\",\"record_type\":\"$3\"}"; }

check() { # type name expected_ttl
  local t=$1 n=$2 ttl=$3 out api_vals dig_vals
  out=$(lk "$UT" "$n" "$t")
  api_vals=$(echo "$out" | j '"\n".join(sorted("".join(r["value"].lower().replace(chr(34),"").split()) for r in d["records"] if r["type"]=="'"$t"'"))')
  dig_vals=$(dig +time=2 +tries=1 +short @127.0.0.1 -p $DNSPORT "$n" "$t" | tr -d '"' | tr 'A-Z' 'a-z' | tr -d ' ' | sort)
  st=$(echo "$out" | j 'd["status"]'); got_ttl=$(echo "$out" | j 'd["records"][0]["ttl"] if d["records"] else -1')
  [ "$st" = NOERROR ] && [ -n "$api_vals" ] && [ "$api_vals" = "$dig_vals" ]; local a=$?
  [ -z "$ttl" ] || [ "$got_ttl" = "$ttl" ]; local b=$?
  ok "$t $n: status=$st, value(s) equal dig [$(echo $api_vals | cut -c1-60)], ttl=$got_ttl" $((a|b))
}
check A www.child.parent.test 301
check AAAA www.child.parent.test 302
check MX child.parent.test 303
check TXT txt.child.parent.test 304
check NS child.parent.test ""
check CNAME alias.child.parent.test 306
check SOA child.parent.test ""
check SRV _sip._tcp.child.parent.test 308
check PTR ptr.child.parent.test 309
check CAA child.parent.test 310
check DNSKEY child.parent.test ""
check DS child.parent.test ""
# PTR from an IP address becomes the reverse name (no such zone here: honest NXDOMAIN/REFUSED, never fake data)
out=$(lk "$UT" 192.0.2.10 PTR); echo "$out" | j 'd["domain"]=="192.0.2.10" and d["records"]==[] and d["status"] in ("NXDOMAIN","REFUSED","NOERROR")' | grep -q True; ok "PTR by IP address sends the reverse name and returns no invented data" $?
out=$(lk "$UT" nope.child.parent.test A); echo "$out" | j 'd["status"]=="NXDOMAIN" and d["records"]==[] and d["authoritative"]' | grep -q True; ok "NXDOMAIN reported as such (authoritative, empty)" $?
out=$(lk "$UT" www.child.parent.test MX); echo "$out" | j 'd["status"]=="NOERROR" and d["records"]==[] and "no MX" in d["note"]' | grep -q True; ok "NODATA reported as NOERROR with an explanatory note" $?
out=$(lk "$UT" outside.invalid A); echo "$out" | j 'd["status"]=="REFUSED" and d["records"]==[]' | grep -q True; ok "name outside our zones: REFUSED passed through (not turned into an empty success)" $?
# authorization / validation
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:$APIPORT/api/v1/dns/lookup -H 'content-type: application/json' -d '{"domain":"a.b"}')" = 401 ]; ok "lookup requires authentication (401)" $?
out=$(lk "$VT" www.child.parent.test A); echo "$out" | j 'd["status"]' | grep -q NOERROR; ok "read-only (viewer) accounts can use the lookup tool" $?
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:$APIPORT/api/v1/dns/lookup -H "authorization: Bearer $UT" -H 'content-type: application/json' -d '{"domain":"a.b","record_type":"ANY"}')" = 400 ]; ok "unsupported type (ANY) rejected with 400" $?
# rate limit: 40/min configured; the loop below pushes one account over
lim=0; for i in $(seq 1 60); do c=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:$APIPORT/api/v1/dns/lookup -H "authorization: Bearer $VT" -H 'content-type: application/json' -d '{"domain":"www.child.parent.test"}'); [ "$c" = 429 ] && lim=$((lim+1)); done
[ $lim -ge 15 ]; ok "per-account rate limit returns 429 ($lim of 60 calls limited)" $?
out=$(lk "$UT" www.child.parent.test A); echo "$out" | j 'd["status"]' | grep -q NOERROR; ok "another account is unaffected by that limit" $?
echo; [ $fail = 0 ] && echo "ALL LOOKUP LAB CHECKS PASSED" || echo "SOME CHECKS FAILED"; exit $fail
