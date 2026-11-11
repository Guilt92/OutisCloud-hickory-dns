#!/bin/bash
# City / region / country / continent GeoDNS lab. Runs the real hickory-dns binary
# in an isolated network namespace against a MaxMind *City* database and asks it
# with `dig` from client addresses that the database places in specific cities.
#
# Database: any GeoLite2-City / GeoIP2-City .mmdb. For CI/lab use MaxMind's open
# test database (https://github.com/maxmind/MaxMind-DB/tree/main/test-data):
#   GeoLite2-City-Test.mmdb  (London 81.2.69.142, Boxford/England 2.125.160.216,
#                             Milton/Washington 216.160.83.56, Sweden 89.160.20.128,
#                             Japan 2001:218::/32)
# Requires: root, iproute2, dig. Usage: scripts/geodns_city_lab.sh <hickory-dns> <city.mmdb>
BIN=${1:?path to hickory-dns binary}; MMDB=${2:?path to a GeoIP City .mmdb}
W=$(mktemp -d); L=$(mktemp -d)
cleanup() { [ -n "$SRV" ] && kill $SRV 2>/dev/null; ip netns del outis-csrv 2>/dev/null; ip netns del outis-ccli 2>/dev/null; rm -rf "$W" "$L"; }
trap cleanup EXIT
cat > "$W/zone.city.lab.test" <<'Z'
city.lab.test. 3600 IN SOA ns1.lab.test. hostmaster.city.lab.test. 2026010101 3600 3600 604800 3600
city.lab.test. 3600 IN NS ns1.lab.test.
www.city.lab.test. 300 IN A 192.0.2.10
Z
cat > "$W/named.toml" <<T
listen_addrs_ipv4 = ["0.0.0.0"]
listen_addrs_ipv6 = ["::"]
[[zones]]
zone = "city.lab.test"
zone_type = "Primary"
geodns = { enabled = true, rules = [
  { match_type = "city",      match_value = "GB:London", target = "192.0.2.1", priority = 0, enabled = true },
  { match_type = "region",    match_value = "GB-ENG",    target = "192.0.2.2", priority = 0, enabled = true },
  { match_type = "region",    match_value = "US-WA",     target = "192.0.2.3", priority = 0, enabled = true },
  { match_type = "country",   match_value = "JP",        target = "192.0.2.4", priority = 0, enabled = true },
  { match_type = "continent", match_value = "EU",        target = "192.0.2.5", priority = 0, enabled = true },
  { match_type = "default",   match_value = "*",         target = "192.0.2.9", priority = -10, enabled = true },
] }
[[zones.stores]]
type = "file"
zone_path = "$W/zone.city.lab.test"
T
ip netns add outis-csrv; ip netns add outis-ccli
ip link add cS type veth peer name cC; ip link set cS netns outis-csrv; ip link set cC netns outis-ccli
ip -n outis-csrv addr add 10.201.0.1/24 dev cS; ip -n outis-csrv addr add fd00:201::1/64 dev cS nodad; ip -n outis-csrv link set cS up; ip -n outis-csrv link set lo up
ip -n outis-ccli addr add 10.201.0.2/24 dev cC; ip -n outis-ccli addr add fd00:201::2/64 dev cC nodad; ip -n outis-ccli link set cC up; ip -n outis-ccli link set lo up
for a in 81.2.69.142 2.125.160.216 216.160.83.56 89.160.20.128; do ip -n outis-ccli addr add $a/32 dev cC; ip -n outis-csrv route add $a/32 dev cS; done
for a in 2001:218::5 2001:db8::5; do ip -n outis-ccli addr add $a/128 dev cC nodad; ip -n outis-csrv route add $a/128 dev cS; done
ip netns exec outis-csrv sysctl -qw net.ipv4.ip_unprivileged_port_start=0
chmod -R a+rX "$W"; cp "$BIN" "$W/hickory-dns"; cp "$MMDB" "$W/geo.mmdb"; chmod 755 "$W/hickory-dns"; chmod 644 "$W/geo.mmdb"
GEOIP_DB_PATH="$W/geo.mmdb" ip netns exec outis-csrv setpriv --reuid 65534 --regid 65534 --clear-groups "$W/hickory-dns" -c "$W/named.toml" -z "$W" >"$L/server.log" 2>&1 &
SRV=$!; sleep 2
fail=0; SERVER=10.201.0.1
check() { local d=$1 want=$2 src=$3; shift 3
  got=$(ip netns exec outis-ccli dig +time=2 +tries=1 +short -b "$src" @"$SERVER" "$@" | head -1) || true
  if [ "$got" = "$want" ]; then echo "PASS $d -> $got"; else echo "FAIL $d: want $want got '$got'"; fail=1; fi; }
check "London client: city rule wins over region/continent" 192.0.2.1 81.2.69.142 www.city.lab.test A
check "Boxford (England, not London): region rule"          192.0.2.2 2.125.160.216 www.city.lab.test A
check "Milton, Washington: US-WA region rule"               192.0.2.3 216.160.83.56 www.city.lab.test A
check "Sweden: continent EU rule"                           192.0.2.5 89.160.20.128 www.city.lab.test A
check "private client: default rule"                        192.0.2.9 10.201.0.2 www.city.lab.test A
check "London client over TCP"                              192.0.2.1 81.2.69.142 +tcp www.city.lab.test A
SERVER=fd00:201::1
check "IPv6 transport, IPv6 client in Japan (country rule)"  192.0.2.4 2001:218::5 www.city.lab.test A
check "IPv6 transport, unlisted IPv6 client (default rule)"  192.0.2.9 2001:db8::5 www.city.lab.test A
[ $fail = 0 ] && echo "ALL CITY/REGION LAB CHECKS PASSED" || echo "CITY/REGION LAB FAILED"
exit $fail
