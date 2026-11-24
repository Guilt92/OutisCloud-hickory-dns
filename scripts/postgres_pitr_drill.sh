#!/usr/bin/env bash
# PostgreSQL physical recovery drill. All data lives in this disposable container.
set -euo pipefail
db=$(docker run -d --rm --network none --memory 768m --cpus 1 --tmpfs /var/lib/postgresql/data --tmpfs /drill:size=384m postgres:16-alpine sleep infinity)
trap 'docker stop "$db" >/dev/null' EXIT
docker exec "$db" chown postgres /drill
docker exec -i -u postgres "$db" sh -eu <<'SH'
cd /drill
mkdir archive
initdb -D source -A trust --no-locale >/dev/null
cat >>source/postgresql.conf <<'CONFIG'
listen_addresses = ''
archive_mode = on
archive_command = 'test ! -f /drill/archive/%f && cp %p /drill/archive/%f'
CONFIG
pg_ctl -D source -l /drill/source.log -w start
sql() { psql -XAtq -v ON_ERROR_STOP=1 -d postgres -c "$1"; }
sql 'CREATE TABLE zone_state(domain text PRIMARY KEY)'
pg_basebackup -D base -X stream --checkpoint=fast
pg_verifybackup base
sql "INSERT INTO zone_state VALUES ('before.invalid')"
sql "SELECT pg_create_restore_point('verified_zone')"
sql "INSERT INTO zone_state VALUES ('after.invalid')"
test "$(sql 'SELECT count(*) FROM zone_state')" = 2
segment=$(sql 'SELECT pg_walfile_name(pg_current_wal_insert_lsn())')
sql 'SELECT pg_switch_wal()'
i=0
until test -f "source/pg_wal/archive_status/$segment.done"; do
  i=$((i+1)); test "$i" -lt 60; sleep 1
done
pg_ctl -D source -m fast -w stop
cat >>base/postgresql.conf <<'CONFIG'
archive_mode = off
restore_command = 'cp /drill/archive/%f %p'
recovery_target_name = 'verified_zone'
recovery_target_action = 'promote'
CONFIG
touch base/recovery.signal
pg_ctl -D base -l /drill/recovery.log -w start || { tail -20 recovery.log; exit 1; }
i=0
until test "$(sql 'SELECT pg_is_in_recovery()')" = f; do
  i=$((i+1)); test "$i" -lt 60; sleep 1
done
test "$(sql 'SELECT domain FROM zone_state ORDER BY domain')" = before.invalid
pg_ctl -D base -m fast -w stop
echo 'PASS verified physical backup and recovered the transaction before the target only'
SH
