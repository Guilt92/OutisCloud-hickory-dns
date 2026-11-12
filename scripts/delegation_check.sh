#!/bin/bash
# READ-ONLY delegation / registrar consistency check (only sends DNS queries; changes nothing anywhere).
#   scripts/delegation_check.sh <domain> [--parent <ip[:port]>] [--ns-port <port>]
# 1. asks the parent zone's servers (the TLD servers, or --parent) which NS (and glue) the domain is delegated to
# 2. checks glue for in-domain nameservers
# 3. asks every delegated nameserver, over UDP and TCP, for SOA and NS and compares: authoritative (AA), same NS set as the
#    parent, same SOA serial everywhere, reachable, and not all on one address
# Exit status 0 = everything confirmed, 1 = at least one FAIL.
set -u
D=${1:?domain}; shift; PARENT=""; NSPORT=53
MAPS=""   # lab use: --map ns.name.=ip pins a name server name to an address instead of resolving it
while [ $# -gt 0 ]; do case "$1" in --parent) PARENT=$2; shift 2;; --ns-port) NSPORT=$2; shift 2;; --map) MAPS="$MAPS $2"; shift 2;; *) shift;; esac; done
D=${D%.}; fail=0; warn=0
ok() { echo "CONFIRMED  $1"; }; bad() { echo "FAILED     $1"; fail=1; }; wr() { echo "WARNING    $1"; warn=1; }; na() { echo "UNVERIFIABLE $1"; }
dg() { timeout 12 dig +norec +time=3 +tries=1 "$@" 2>&1; }
if [ -z "$PARENT" ]; then
  TLD=${D##*.}; PS=$(dig +short +time=3 +tries=2 NS "$TLD." | head -4)
  [ -n "$PS" ] || { na "cannot resolve the TLD ($TLD) name servers from here"; exit 1; }
  PADDR=""; for p in $PS; do a=$(dig +short +time=3 +tries=1 A "$p" | head -1); [ -n "$a" ] && PADDR="$PADDR $a"; done
else PADDR=${PARENT%%:*}; PPORT=${PARENT#*:}; [ "$PPORT" = "$PARENT" ] && PPORT=53; fi
PPORT=${PPORT:-53}
OUT=""; for pa in $PADDR; do OUT=$(dg -p $PPORT @$pa "$D" NS); echo "$OUT" | grep -q "status: NOERROR\|status: NXDOMAIN" && { PSEL=$pa; break; }; done
[ -n "${PSEL:-}" ] || { na "no parent server answered (network path or firewall from this vantage point)"; exit 1; }
echo "parent server used: $PSEL:$PPORT"
DELEG=$(echo "$OUT" | awk '/AUTHORITY SECTION/{f=1;next} /^$/{f=0} f && $4=="NS" {print $5}' | sort -u)
if [ -z "$DELEG" ]; then bad "the parent zone has NO delegation for $D (not registered, or registered with other name servers)"; exit 1; fi
ok "parent zone delegates $D to: $(echo $DELEG | tr '\n' ' ')"
GLUE=$(echo "$OUT" | awk '/ADDITIONAL SECTION/{f=1;next} /^$/{f=0} f && ($4=="A"||$4=="AAAA") {print $1" "$5}')
ADDRS=""
for ns in $DELEG; do
  n=${ns%.}; ga=$(echo "$GLUE" | awk -v n="$ns" '$1==n{print $2}')
  if [[ "$n" == *"$D" ]]; then
    [ -n "$ga" ] && ok "glue present at the parent for in-domain nameserver $n ($ga)" || bad "in-domain nameserver $n has NO glue at the parent (resolution would be circular)"
  fi
  for m in $MAPS; do [ "${m%%=*}" = "$ns" ] || [ "${m%%=*}" = "$n" ] && ga=${m#*=}; done
  [ -z "$ga" ] && ga=$(dig +short +time=3 +tries=1 A "$n" | head -1)
  [ -z "$ga" ] && { bad "$n does not resolve to an address"; continue; }
  ADDRS="$ADDRS $n=$ga"
done
IPS=$(for p in $ADDRS; do echo ${p#*=}; done | sort -u | wc -l)
[ $(echo $DELEG | wc -w) -gt 1 ] && [ "$IPS" = 1 ] && wr "all delegated name servers share ONE address — no redundancy"
SERIALS=""
for p in $ADDRS; do n=${p%%=*}; a=${p#*=}
  for proto in "" "+tcp"; do
    r=$(dg $proto -p $NSPORT @$a "$D" SOA); label=${proto:-+udp}
    if echo "$r" | grep -q "status: NOERROR"; then
      echo "$r" | grep -q "flags:.* aa" && ok "$n ($a) answers SOA authoritatively over ${label#+}" || bad "$n ($a) answers over ${label#+} but NOT authoritatively (lame delegation)"
      [ -z "$proto" ] && SERIALS="$SERIALS $(echo "$r" | awk '$4=="SOA"{print $7}' | head -1)"
    else bad "$n ($a) did not answer SOA over ${label#+}: $(echo "$r" | grep -oE 'status: [A-Z]+|timed out|no servers could be reached|connection refused' | head -1)"; fi
  done
  r=$(dg -p $NSPORT @$a "$D" NS)
  if echo "$r" | grep -q "status: NOERROR"; then own=$(echo "$r" | awk '/ANSWER SECTION/{f=1;next} /^$/{f=0} f && $4=="NS"{print $5}' | sort -u | tr '\n' ' ')
    [ "$own" = "$(echo $DELEG | tr ' ' '\n' | sort -u | tr '\n' ' ')" ] && ok "$n serves the same NS set as the parent" || bad "$n serves NS {$own} but the parent delegates {$(echo $DELEG | tr '\n' ' ')}"; fi
done
U=$(echo $SERIALS | tr ' ' '\n' | grep -v '^$' | sort -u | wc -l)
[ "$U" -gt 1 ] && bad "SOA serials differ between name servers: $SERIALS" || { [ "$U" = 1 ] && ok "all reachable name servers report the same SOA serial ($SERIALS)"; }
echo; [ $fail = 0 ] && echo "RESULT: delegation consistent${warn:+ (with warnings)}" || echo "RESULT: FAILED — see FAILED lines"; exit $fail
