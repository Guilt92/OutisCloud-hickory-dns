#!/bin/bash
# DNSSEC end-to-end lab: control API (key generation, DS) + the real hickory-dns server
# (zone signing, NSEC, hot reload) + ISC `delv` as an independent validating client.
# Builds a two-level chain of trust on loopback:  parent.test (trust anchor = its DS)
#   -> child.parent.test (DS published in the parent zone through the API).
# Needs: dig, delv (bind9-dnsutils), python3, a reachable PostgreSQL (DATABASE_URL, will use
# a throw-away database name given as $4), the two release binaries. No external network.
# Usage: scripts/dnssec_lab.sh <control_api> <hickory-dns> <postgres-url-without-dbname> <dbname>
set -u
API_BIN=${1:?control_api binary}; DNS_BIN=${2:?hickory-dns binary}; PGURL=${3:?postgres://user:pw@host:port}; DB=${4:?scratch db name}
W=$(mktemp -d); chmod 755 "$W"; fail=0; SRV=""; APIP=""
APIPORT=18090; DNSPORT=5400
cleanup() { [ -n "$SRV" ] && kill $SRV 2>/dev/null; [ -n "$APIP" ] && kill $APIP 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
ok() { if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }   # j 'expr using d'
api() { # method path [json]
  curl -s -X "$1" "http://127.0.0.1:$APIPORT$2" -H "authorization: Bearer $TOK" -H 'content-type: application/json' ${3:+-d "$3"}; }

export DATABASE_URL="$PGURL/$DB" JWT_SECRET=dnssec-lab-secret-0123456789abcdef0123456789 ADMIN_USERNAME=admin ADMIN_PASSWORD='Lab-Admin-Pw-9911' \
  ALLOWED_ORIGINS=http://127.0.0.1:5173 HICKORY_DNS_DIR="$W/dns" PUBLIC_NAMESERVERS=ns1.example.test.,ns2.example.test. LOGIN_RATE_PER_IP=1000 BIND_ADDR=127.0.0.1:$APIPORT LISTEN_ADDRS_IPV4=127.0.0.1 LISTEN_ADDRS_IPV6=::1
mkdir -p "$W/dns"
"$API_BIN" >"$W/api.log" 2>&1 & APIP=$!
for i in $(seq 1 60); do curl -sf http://127.0.0.1:$APIPORT/health >/dev/null 2>&1 && break; sleep 0.5; done
TOK=$(curl -s -X POST http://127.0.0.1:$APIPORT/api/v1/auth/login -H 'content-type: application/json' -d '{"username":"admin","password":"Lab-Admin-Pw-9911"}' | j 'd["token"]')
[ -n "$TOK" ]; ok "API up and admin login works" $?

mkzone() { api POST /api/v1/zones "{\"domain\":\"$1\",\"geodns_enabled\":false}" | j 'd.get("id") or d.get("data",{}).get("id")'; }
PZ=$(mkzone parent.test); CZ=$(mkzone child.parent.test)
[ -n "$PZ" ] && [ -n "$CZ" ]; ok "parent and child zones created" $?
rec() { api POST /api/v1/zones/$1/records "{\"name\":\"$2\",\"record_type\":\"$3\",\"value\":\"$4\",\"ttl\":300}" >/dev/null; }
rec $CZ www A 192.0.2.10; rec $CZ www AAAA 2001:db8::10; rec $CZ @ MX "10 mail.child.parent.test."; rec $CZ mail A 192.0.2.25
rec $CZ txt TXT "v=spf1 mx -all"; rec $CZ alias CNAME www.child.parent.test.
rec $CZ '*.wild' A 192.0.2.77
# delegation (NS owned by the parent; out of bailiwick so no glue needed)
rec $PZ child NS ns1.example.test.

# --- enable DNSSEC on the child, publish its DS in the parent, then sign the parent
R=$(api POST /api/v1/zones/$CZ/dnssec/enable '{}')
CDS=$(echo "$R" | j 'd["keys"][0]["ds"][0]["text"]'); CTAG=$(echo "$R" | j 'd["keys"][0]["key_tag"]')
echo "$CDS" | grep -q "^child.parent.test. IN DS "; ok "child DNSSEC enabled, DS returned: $CDS" $?
dsval() { echo "$1" | sed 's/^.* IN DS //'; }
rec $PZ child DS "$(dsval "$CDS")"
R=$(api POST /api/v1/zones/$PZ/dnssec/enable '{"algorithm":"ECDSAP384SHA384"}')
PDS=$(echo "$R" | j 'd["keys"][0]["ds"][0]["text"]')
echo "$PDS" | grep -q "^parent.test. IN DS "; ok "parent DNSSEC enabled (ECDSAP384SHA384), DS: $PDS" $?
# trust anchor for the validator = parent's DS
read -r PTAG PALG PDT PDIG <<<"$(dsval "$PDS")"
cat > "$W/anchor.conf" <<A
trust-anchors { "parent.test" static-ds $PTAG $PALG $PDT "$PDIG"; };
A

chmod -R a+rX "$W/dns"; cp "$DNS_BIN" "$W/hickory-dns"; chmod 755 "$W/hickory-dns"
cat "$W/dns/named.toml" | sed -n 1,40p > "$W/named.shown"
RESIGN_INTERVAL_HOURS=0.0017 "$W/hickory-dns" -c "$W/dns/named.toml" -z "$W/dns" --port $DNSPORT >"$W/dns.log" 2>&1 & SRV=$!
for i in $(seq 1 60); do dig +time=1 +tries=1 +short @127.0.0.1 -p $DNSPORT www.child.parent.test A >/dev/null 2>&1 && break; sleep 0.5; done
D() { dig +time=2 +tries=1 +dnssec +noall +answer +authority +comments @127.0.0.1 -p $DNSPORT "$@"; }
vok() { local d=$1; shift; local o; o=$(V "$@"); if echo "$o" | grep -q "fully_validated"; then echo "PASS $d"; else echo "FAIL $d"; echo "$o" | head -12 | sed "s/^/    | /"; fail=1; fi; }
V() { delv +yaml +root=parent.test -a "$W/anchor.conf" @127.0.0.1 -p $DNSPORT "$@" 2>&1; }

D www.child.parent.test A | grep -q "RRSIG.*A 13 "; ok "A answer carries an RRSIG (ECDSAP256SHA256, alg 13)" $?
D parent.test DNSKEY | grep -q "DNSKEY.*257 3 14"; ok "parent DNSKEY published (flags 257, alg 14)" $?
vok "delv: www A fully validated through DS chain parent -> child" www.child.parent.test A
vok "delv: AAAA fully validated" www.child.parent.test AAAA
vok "delv: MX fully validated" child.parent.test MX
vok "delv: TXT fully validated" txt.child.parent.test TXT
vok "delv: CNAME chain fully validated" alias.child.parent.test A
vok "delv: child DNSKEY validated by the parent's DS" child.parent.test DNSKEY
out=$(V nope.child.parent.test A); echo "$out" | grep -qi "ncache nxdomain\|NXDOMAIN"; r1=$?; echo "$out" | grep -qi "validation failure\|insecurity proof failed\|bogus"; [ $? -ne 0 ] && [ $r1 = 0 ]; ok "delv: NXDOMAIN accepted with a valid NSEC proof" $?
out=$(V www.child.parent.test TXT); echo "$out" | grep -qi "ncache nxrrset\|NXRRSET\|nodata\|no answer"; r1=$?; echo "$out" | grep -qi "validation failure\|insecurity proof failed"; [ $? -ne 0 ] && [ $r1 = 0 ]; ok "delv: NODATA accepted with a valid NSEC proof" $?
out=$(V x.wild.child.parent.test A); echo "$out" | grep -q "192.0.2.77" && echo "$out" | grep -q "fully_validated"; ok "delv: wildcard expansion validated" $?
# IPv6 transport
dig -6 +time=2 +tries=1 +noall +answer +dnssec @::1 -p $DNSPORT www.child.parent.test A | grep -q RRSIG; ok "signed answers over IPv6 transport" $?
dig +tcp +time=2 +tries=1 +dnssec +noall +answer @127.0.0.1 -p $DNSPORT www.child.parent.test A | grep -q RRSIG; ok "signed answers over TCP" $?
# a validator with the wrong trust anchor must reject the chain
printf 'trust-anchors { "parent.test" static-ds 1234 14 2 "%s"; };\n' "$(printf '0%.0s' $(seq 1 64))" > "$W/bad.conf"
out=$(delv +yaml +root=parent.test -a "$W/bad.conf" @127.0.0.1 -p $DNSPORT www.child.parent.test A 2>&1); echo "$out" | grep -q "fully_validated"; [ $? -ne 0 ]; ok "wrong trust anchor is rejected (no false validation)" $?
# unsigned data: a record the operator adds is signed after the hot reload, same process
pid_before=$SRV
rec $CZ new A 192.0.2.99; sleep 3
vok "record added through the API is signed and validated after hot reload" new.child.parent.test A
kill -0 $pid_before 2>/dev/null; ok "DNS process was not restarted by the reload" $?

# --- signatures are refreshed periodically (RESIGN_INTERVAL_HOURS=0.0017 -> every ~6 s here)
inc() { dig +time=2 +tries=1 +dnssec +noall +answer @127.0.0.1 -p $DNSPORT new.child.parent.test A | awk '$4=="RRSIG"{print $10}' | head -1; }
i1=$(inc); sleep 14; i2=$(inc)
[ -n "$i1" ] && [ -n "$i2" ] && [ "$i1" != "$i2" ]; ok "RRSIG inception moves forward without any zone change (periodic re-sign: $i1 -> $i2)" $?
vok "answers are still valid after the periodic re-sign" new.child.parent.test A

# --- key rollover, validated with the parent's DS set changing underneath
R=$(api POST /api/v1/zones/$CZ/dnssec/rollover '{"algorithm":"ED25519"}')
NDS=$(echo "$R" | j 'd["keys"][1]["ds"][0]["text"]'); NTAG=$(echo "$R" | j 'd["keys"][1]["key_tag"]')
rec $PZ child DS "$(dsval "$NDS")"; sleep 4
vok "during rollover (two DS, two DNSKEY) the chain validates" www.child.parent.test A
dig +short +time=2 @127.0.0.1 -p $DNSPORT child.parent.test DNSKEY | wc -l | grep -q '^2$'; ok "child DNSKEY RRset holds both keys during rollover" $?
api POST /api/v1/zones/$CZ/dnssec/rollover/complete "{\"retire_key_tag\":$CTAG}" >/dev/null; sleep 4
dig +short +time=2 @127.0.0.1 -p $DNSPORT child.parent.test DNSKEY | wc -l | grep -q '^1$'; ok "old key retired: single DNSKEY remains" $?
vok "after completing the rollover (old DS still in parent) the chain validates" www.child.parent.test A
# now drop the stale DS from the parent
OLDID=$(api GET /api/v1/zones/$PZ/records | j '[r["id"] for r in d if r["name"]=="child" and r["record_type"]=="DS" and r["value"].startswith("'"$CTAG"' ")][0]')
api DELETE /api/v1/zones/$PZ/records/$OLDID >/dev/null; sleep 4
vok "with only the new DS published the chain validates" www.child.parent.test A

# --- disabling needs the DS gone first; afterwards the child is an insecure delegation
r=$(api POST /api/v1/zones/$CZ/dnssec/disable '{}'); echo "$r" | grep -q ds_not_confirmed; ok "disable is refused while the DS may still be published" $?
NEWID=$(api GET /api/v1/zones/$PZ/records | j '[r["id"] for r in d if r["name"]=="child" and r["record_type"]=="DS"][0]')
api DELETE /api/v1/zones/$PZ/records/$NEWID >/dev/null
api POST /api/v1/zones/$CZ/dnssec/disable '{"confirm_ds_removed":true}' >/dev/null; sleep 4
D www.child.parent.test A | grep -q RRSIG; [ $? -ne 0 ]; ok "after disabling, the child zone is served unsigned" $?
out=$(V www.child.parent.test A); echo "$out" | grep -qi "unsigned\|insecure\|192.0.2.10"; ok "delv: unsigned child under a signed parent is an insecure delegation, not bogus" $?
echo; echo "named.toml (signed zones):"; grep -n "keys\|key_path\|zone =" "$W/dns/named.toml" | sed 's#\("/[^"]*/\)#"…/#' | head
[ $fail = 0 ] && echo "ALL DNSSEC LAB CHECKS PASSED" || { echo "DNSSEC LAB FAILED"; tail -20 "$W/dns.log"; }
exit $fail
