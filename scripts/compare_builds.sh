#!/bin/bash
# Run the DNS-behaviour labs against two builds (baseline vs candidate) and diff the PASS/FAIL lines.
#   scripts/compare_builds.sh <api-A> <dns-A> <api-B> <dns-B> <pgurl> <pg-container> <outdir>
set -u
AA=$1; DA=$2; AB=$3; DB_=$4; PGURL=$5; PGC=$6; OUT=$7; mkdir -p "$OUT"
fresh() { docker exec "$PGC" psql -U postgres -qc "DROP DATABASE IF EXISTS $1 WITH (FORCE)" -c "CREATE DATABASE $1" >/dev/null 2>&1; }
for tag in A B; do
  if [ $tag = A ]; then API=$AA; DNS=$DA; else API=$AB; DNS=$DB_; fi
  : > "$OUT/full_$tag.log"
  run() { # name, command...   (each lab in its own shell, with a pause so ports and namespaces are released)
    local name=$1; shift; echo "=== $name" >> "$OUT/full_$tag.log"; timeout 170 "$@" >> "$OUT/full_$tag.log" 2>&1; echo "=== $name exit=$?" >> "$OUT/full_$tag.log"; sleep 3; }
  run geodns scripts/geodns_lab.sh "$DNS" deploy/dns/GeoLite2-Country.mmdb
  fresh cmp_lookup_${tag,,}; run lookup scripts/lookup_lab.sh "$API" "$DNS" "$PGURL" cmp_lookup_${tag,,}
  fresh cmp_conf_${tag,,}; run conformance scripts/dns_conformance_lab.sh "$API" "$DNS" "$PGURL" cmp_conf_${tag,,} "$PGC"
  fresh cmp_bd_${tag,,}; run breakdown scripts/breakdown_lab.sh "$API" "$DNS" deploy/dns/GeoLite2-Country.mmdb "$PGURL" cmp_bd_${tag,,} "$PGC"
  fresh cmp_ta_${tag,,}; run tenant scripts/tenant_analytics_lab.sh "$API" "$DNS" "$PGURL" cmp_ta_${tag,,}
  fresh cmp_dnssec_${tag,,}; run dnssec scripts/dnssec_lab.sh "$API" "$DNS" "$PGURL" cmp_dnssec_${tag,,}
  fresh cmp_metrics_${tag,,}; run metrics scripts/metrics_lab.sh "$API" "$DNS" "$PGURL" cmp_metrics_${tag,,}
  grep -E "^(PASS|FAIL|NOTE|===)" "$OUT/full_$tag.log" | sed -E 's/\(answered [0-9]+, not answered [0-9]+ of [0-9]+\)//; s/[0-9]+ truncated//; s/-> .*$//; s/\([0-9.]+ ?ms\)//; s/ exit=[0-9]+//' > "$OUT/labs_$tag.txt"
done
echo "A: $(grep -c ^PASS "$OUT/labs_A.txt") pass / $(grep -c ^FAIL "$OUT/labs_A.txt") fail     B: $(grep -c ^PASS "$OUT/labs_B.txt") pass / $(grep -c ^FAIL "$OUT/labs_B.txt") fail"
diff <(sed -E 's/[0-9]+//g' "$OUT/labs_A.txt") <(sed -E 's/[0-9]+//g' "$OUT/labs_B.txt") > "$OUT/diff.txt" && echo "IDENTICAL behaviour on every check" || { echo "DIFFERENCES:"; cat "$OUT/diff.txt"; }
