#!/bin/bash
# GeoDNS end-to-end lab. Runs the real hickory-dns binary against a generated
# named.toml inside an isolated network namespace and asks it, with `dig`, from
# client addresses that really belong to different countries (the addresses
# exist only inside the lab namespaces; the host network is not touched).
#
# Requires: root, iproute2, dig, a built hickory-dns binary, GeoLite2-Country.mmdb.
# Usage:  scripts/geodns_lab.sh <hickory-dns-binary> <geoip.mmdb>
set -uo pipefail
BIN=${1:?path to hickory-dns binary}; MMDB=${2:?path to GeoLite2-Country.mmdb}; BIN_MMDB=$MMDB
W=$(mktemp -d); L=$(mktemp -d)   # $L (server log) must live outside the watched zone dir
trap 'ip netns del outis-srv 2>/dev/null||true; ip netns del outis-cli 2>/dev/null||true; kill $SRV 2>/dev/null||true; rm -rf "$W" "$L"' EXIT
chmod 755 "$W"
cat > "$W/zone.geo.lab.test" <<'Z'
geo.lab.test. 3600 IN SOA ns1.lab.test. hostmaster.geo.lab.test. 2026010101 3600 3600 604800 3600
geo.lab.test. 3600 IN NS ns1.lab.test.
www.geo.lab.test. 300 IN A 192.0.2.11
www.geo.lab.test. 300 IN AAAA 2001:db8::11
api.geo.lab.test. 300 IN A 192.0.2.12
Z
cat > "$W/zone.plain.lab.test" <<'Z'
plain.lab.test. 3600 IN SOA ns1.lab.test. hostmaster.plain.lab.test. 2026010101 3600 3600 604800 3600
plain.lab.test. 3600 IN NS ns1.lab.test.
www.plain.lab.test. 300 IN A 192.0.2.21
Z
cat > "$W/named.toml" <<T
listen_addrs_ipv4 = ["0.0.0.0"]
listen_addrs_ipv6 = ["::"]

[[zones]]
zone = "geo.lab.test"
zone_type = "Primary"
geodns = { enabled = true, ecs = true, rules = [
  { match_type = "country", match_value = "BR", target = "192.0.2.66", priority = 5, enabled = true, },
  { match_type = "country", match_value = "US", target = "192.0.2.77", priority = 20, enabled = true, record_name = "www", record_type = "A", },
  { match_type = "country", match_value = "DE", target = "192.0.2.78", priority = 20, enabled = true, record_name = "www", record_type = "A", },
  { match_type = "continent", match_value = "EU", target = "192.0.2.88", priority = 10, enabled = true, record_name = "www", record_type = "A", },
  { match_type = "default", match_value = "", target = "192.0.2.99", priority = 0, enabled = true, record_name = "www", record_type = "A", },
] }
[[zones.stores]]
type = "file"
zone_path = "$W/zone.geo.lab.test"

[[zones]]
zone = "plain.lab.test"
zone_type = "Primary"
geodns = { enabled = true, rules = [
  { match_type = "country", match_value = "US", target = "192.0.2.77", priority = 1, enabled = true, },
] }
[[zones.stores]]
type = "file"
zone_path = "$W/zone.plain.lab.test"
T
ip netns add outis-srv; ip netns add outis-cli
ip link add vS type veth peer name vC; ip link set vS netns outis-srv; ip link set vC netns outis-cli
ip -n outis-srv addr add 10.200.0.1/24 dev vS; ip -n outis-srv addr add fd00:200::1/64 dev vS nodad; ip -n outis-srv link set vS up; ip -n outis-srv link set lo up
ip -n outis-cli addr add 10.200.0.2/24 dev vC; ip -n outis-cli addr add fd00:200::2/64 dev vC nodad; ip -n outis-cli link set vC up; ip -n outis-cli link set lo up
for a in 8.8.8.8 5.9.0.1 80.246.31.97 41.0.0.1 200.160.2.3; do ip -n outis-cli addr add $a/32 dev vC; ip -n outis-srv route add $a/32 dev vS; done
for a in 2001:4860:4860::8888 2a00:1450:4001:81b::200e 2001:db8::5; do ip -n outis-cli addr add $a/128 dev vC nodad; ip -n outis-srv route add $a/128 dev vS; done
ip netns exec outis-srv sysctl -qw net.ipv4.ip_unprivileged_port_start=0
# run as an unprivileged user like the container does
chmod -R a+rX "$W"; cp "$BIN" "$W/hickory-dns"; cp "$MMDB" "$W/geo.mmdb"; chmod 755 "$W/hickory-dns"; chmod 644 "$W/geo.mmdb"
start_server() { # extra env as args
  env "$@" GEOIP_DB_PATH="$W/geo.mmdb" ip netns exec outis-srv setpriv --reuid 65534 --regid 65534 --clear-groups "$W/hickory-dns" -c "$W/named.toml" -z "$W" >"$L/server.log" 2>&1 &
  SRV=$!; sleep 2
}
start_server X=1
fail=0
SERVER=${SERVER:-10.200.0.1}
check() { # <description> <expected> <source ip> [dig args...]
  local d=$1 want=$2 src=$3; shift 3
  got=$(ip netns exec outis-cli dig +time=2 +tries=1 +short -b "$src" @"$SERVER" "$@" | head -1) || true
  if [ "$got" = "$want" ]; then echo "PASS $d -> $got"; else echo "FAIL $d: want $want got '$got'"; fail=1; fi
}
check "US client"                     192.0.2.77 8.8.8.8       www.geo.lab.test A
check "DE client (country beats continent)" 192.0.2.78 5.9.0.1 www.geo.lab.test A
check "LV client (continent EU)"      192.0.2.88 80.246.31.97  www.geo.lab.test A
check "ZA client (default rule)"      192.0.2.99 41.0.0.1      www.geo.lab.test A
check "BR client (priority-5 BR rule beats default)" 192.0.2.66 200.160.2.3 www.geo.lab.test A
check "private client (default rule)" 192.0.2.99 10.200.0.2    www.geo.lab.test A
check "US client over TCP"            192.0.2.77 8.8.8.8       +tcp www.geo.lab.test A
check "AAAA is never answered with an IPv4 target" 2001:db8::11 8.8.8.8 www.geo.lab.test AAAA
SERVER=fd00:200::1
check "IPv6 transport, US IPv6 client" 192.0.2.77 2001:4860:4860::8888 www.geo.lab.test A
check "IPv6 transport, DE IPv6 client" 192.0.2.78 2a00:1450:4001:81b::200e www.geo.lab.test A
check "IPv6 transport, unlisted IPv6 client (default rule)" 192.0.2.99 2001:db8::5 www.geo.lab.test A
# ---- existing names only, ECS, hot reload, bad reload, rate limiting -----------------
SERVER=10.200.0.1
q() { ip netns exec outis-cli dig +time=2 +tries=1 "$@"; }
ok_if() { # <description> <condition-result: 0=true>
  if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi
}
check "zone-wide rule still answers an existing name (BR, api)" 192.0.2.66 200.160.2.3 api.geo.lab.test A
st=$(q -b 200.160.2.3 @$SERVER nope.geo.lab.test A +noall +comments | grep -o 'status: [A-Z]*'); [ "$st" = "status: NXDOMAIN" ]; ok_if "zone-wide rule does not invent a missing name (got '$st')" $?
# ECS: a resolver in a private network asks on behalf of a US client
check "ECS selects the US client (zone with ecs=true)" 192.0.2.77 10.200.0.2 +subnet=8.8.8.0/24 www.geo.lab.test A
out=$(q @$SERVER +subnet=8.8.8.0/24 www.geo.lab.test A); echo "$out" | grep -q "CLIENT-SUBNET: 8.8.8.0/24/24"; ok_if "ECS option echoed with scope /24" $?
got=$(q @$SERVER +short +subnet=8.8.8.0/24 www.plain.lab.test A | head -1); [ "$got" = "192.0.2.21" ]; ok_if "non-ECS zone ignores the subnet and serves its own data ($got)" $?
out=$(q @$SERVER +subnet=8.8.8.0/24 www.plain.lab.test A); echo "$out" | grep -q "CLIENT-SUBNET"; [ $? -ne 0 ]; ok_if "non-ECS zone does not echo ECS" $?
check "ECS with source prefix 0 falls back to the resolver address" 192.0.2.99 10.200.0.2 +subnet=0.0.0.0/0 www.geo.lab.test A

# hot reload: replace a zone file atomically while queries run; PID must not change
pid_before=$SRV
( end=$((SECONDS+5)); bad=0; while [ $SECONDS -lt $end ]; do
    r=$(ip netns exec outis-cli dig +time=1 +tries=1 +short -b 8.8.8.8 @$SERVER www.geo.lab.test A | head -1); [ "$r" = "192.0.2.77" ] || bad=$((bad+1)); done; echo $bad > "$L/bad" ) &
LOOP=$!; sleep 1
sed 's/ 2026010101 / 2026010102 /' "$W/zone.geo.lab.test" > "$W/zone.geo.lab.test.tmp"; echo 'new.geo.lab.test. 300 IN A 192.0.2.50' >> "$W/zone.geo.lab.test.tmp"; mv "$W/zone.geo.lab.test.tmp" "$W/zone.geo.lab.test"
sleep 2; got=$(q @$SERVER +short new.geo.lab.test A | head -1); [ "$got" = "192.0.2.50" ]; ok_if "new record is served after hot reload ($got)" $?
wait $LOOP; bad=$(cat "$L/bad"); [ "$bad" = 0 ]; ok_if "no query failed during the reload ($bad failures)" $?
kill -0 $pid_before 2>/dev/null; ok_if "DNS process was not restarted" $?
grep -q "without restarting" "$L/server.log"; ok_if "server logged an in-place reload" $?
# GeoIP database refresh: a valid replacement is picked up without a restart ...
n_before=$(grep -c "without restarting" "$L/server.log")
cp "$W/geo.mmdb" "$W/geo.mmdb.new"; mv "$W/geo.mmdb.new" "$W/geo.mmdb"; sleep 2
n_after=$(grep -c "without restarting" "$L/server.log"); [ "$n_after" -gt "$n_before" ]; ok_if "replacing the GeoIP database triggers an in-place reload" $?
# ... and a corrupt one is rejected while geo routing keeps working on the previous data
head -c 1000 /dev/urandom > "$W/geo.mmdb.new"; mv "$W/geo.mmdb.new" "$W/geo.mmdb"; sleep 2
grep -q "GeoIP database .* is invalid" "$L/server.log"; ok_if "corrupt GeoIP database is rejected and logged" $?
kill -0 $pid_before 2>/dev/null; ok_if "DNS process survived the corrupt GeoIP file" $?
cp "$BIN_MMDB" "$W/geo.mmdb" 2>/dev/null; sleep 2
# a broken publication must not take the server down or change answers
echo 'this is not a zone file' > "$W/zone.geo.lab.test.tmp"; mv "$W/zone.geo.lab.test.tmp" "$W/zone.geo.lab.test"; sleep 2
got=$(q @$SERVER +short -b 8.8.8.8 www.geo.lab.test A | head -1); [ "$got" = "192.0.2.77" ]; ok_if "still serving the previous data after a broken reload ($got)" $?
grep -q "reload aborted" "$L/server.log"; ok_if "broken reload was rejected and logged" $?
kill -0 $pid_before 2>/dev/null; ok_if "DNS process survived the broken reload" $?
# a listener change needs a restart (process exits so the supervisor starts it again)
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null

# rate limiting: 5 qps, burst 10 per source
cp "$W/zone.plain.lab.test" "$W/zone.geo.lab.test"
sed -i 's/plain.lab.test/geo.lab.test/g' "$W/zone.geo.lab.test"; echo 'www.geo.lab.test. 300 IN A 192.0.2.11' >> "$W/zone.geo.lab.test"; echo 'api.geo.lab.test. 300 IN A 192.0.2.12' >> "$W/zone.geo.lab.test"
start_server DNS_RATE_LIMIT_QPS=5 DNS_RATE_LIMIT_BURST=10
# 120 UDP queries in parallel from one source, well beyond burst 10 + 5/s (+ignore: no automatic TCP retry on TC)
out=$(seq 1 120 | xargs -P 60 -I{} ip netns exec outis-cli dig +time=2 +tries=1 +ignore +noall +comments +answer -b 5.9.0.1 @$SERVER api.geo.lab.test A)
answered=$(echo "$out" | grep -c 'ANSWER: 1,'); truncated=$(echo "$out" | grep -c 'flags:.* tc\|flags: qr tc'); fail_q=$((120-answered))
[ $fail_q -gt 60 ] && [ $answered -ge 8 ]; ok_if "rate limit drops excess UDP queries from one source (answered $answered, not answered $fail_q of 120)" $?
[ $truncated -ge 5 ] && [ $truncated -lt $((fail_q)) ]; ok_if "slip: some over-budget queries get a TC=1 reply, the rest are dropped ($truncated truncated)" $?
got=$(q -b 41.0.0.1 +short @$SERVER api.geo.lab.test A | head -1); [ "$got" = "192.0.2.12" ]; ok_if "a different source is unaffected" $?
got=$(q -b 5.9.0.1 +tcp +short @$SERVER api.geo.lab.test A | head -1); [ "$got" = "192.0.2.12" ]; ok_if "the flooding source still gets answers over TCP (exempt from the limit)" $?
exit $fail
