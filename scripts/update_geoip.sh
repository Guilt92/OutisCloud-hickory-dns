#!/bin/bash
# Download/refresh a MaxMind GeoLite2 database and install it atomically so the
# running DNS server hot-reloads it (it watches GEOIP_DB_PATH). Safe to run from cron.
#
#   MAXMIND_LICENSE_KEY=...  scripts/update_geoip.sh /path/to/GeoLite2-City.mmdb [edition]
#
# edition defaults to GeoLite2-City (use GeoLite2-Country for country-only data).
# A free MaxMind account + licence key is required (https://www.maxmind.com/en/geolite2/signup).
# Never prints the licence key. The new file is validated (mmdb magic + non-trivial size +
# SHA-256 from MaxMind) before it replaces the old one; on any failure the old file stays.
# MAXMIND_BASE_URL overrides the download host (used by the self-test).
set -euo pipefail
DEST=${1:?destination .mmdb path}; EDITION=${2:-GeoLite2-City}
: "${MAXMIND_LICENSE_KEY:?set MAXMIND_LICENSE_KEY}"
BASE=${MAXMIND_BASE_URL:-https://download.maxmind.com/geoip/databases}
TMP=$(mktemp -d "$(dirname "$DEST")/.geoip.XXXXXX"); trap 'rm -rf "$TMP"' EXIT
fetch() { curl -fsSL --retry 3 --max-time 300 -u "${MAXMIND_ACCOUNT_ID:-0}:${MAXMIND_LICENSE_KEY}" "$1" -o "$2"; }
fetch "$BASE/$EDITION/download?suffix=tar.gz" "$TMP/db.tar.gz"
fetch "$BASE/$EDITION/download?suffix=tar.gz.sha256" "$TMP/db.sha256"
want=$(awk '{print $1}' "$TMP/db.sha256"); got=$(sha256sum "$TMP/db.tar.gz" | awk '{print $1}')
[ "$want" = "$got" ] || { echo "checksum mismatch for $EDITION (download corrupted); keeping the old database" >&2; exit 1; }
tar -xzf "$TMP/db.tar.gz" -C "$TMP" --wildcards '*.mmdb' --strip-components=1
NEW=$(ls "$TMP"/*.mmdb | head -1)
[ -s "$NEW" ] && [ "$(stat -c %s "$NEW")" -gt 10000 ] || { echo "downloaded database looks empty; keeping the old one" >&2; exit 1; }
grep -qa $'\xab\xcd\xefMaxMind.com' "$NEW" || { echo "not a MaxMind database; keeping the old one" >&2; exit 1; }
chmod 644 "$NEW"; mv -f "$NEW" "$DEST"   # same filesystem -> atomic rename
echo "installed $EDITION -> $DEST ($(stat -c %s "$DEST") bytes)"
