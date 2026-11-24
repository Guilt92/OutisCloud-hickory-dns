#!/usr/bin/env bash
# Run from the repository root on a Docker host with GnuPG and PostgreSQL 16 image.
set -euo pipefail
umask 077
work=$(mktemp -d)
export GNUPGHOME="$work/keyring"
mkdir -m 700 "$GNUPGHOME"
db=$(docker run -d --rm --network none --tmpfs /var/lib/postgresql/data --env POSTGRES_HOST_AUTH_METHOD=trust postgres:16-alpine)
cleanup() {
  docker stop "$db" >/dev/null
  gpgconf --kill gpg-agent
  rm -rf -- "$work"
}
trap cleanup EXIT
for ((i=0; i<60; i++)); do
  docker exec "$db" pg_isready -h 127.0.0.1 -U postgres >/dev/null && break
  sleep 1
done
sql() { docker exec -i "$db" psql -XqAt -v ON_ERROR_STOP=1 -U postgres -d "$1"; }
docker exec "$db" createdb -U postgres fixture
sql fixture < crates/control_api/migrations/001_initial_schema.sql
sql fixture <<< "INSERT INTO zones(id, domain) VALUES ('00000000-0000-0000-0000-000000000001','drill.invalid');"
gpg --batch --passphrase '' --quick-generate-key 'Disposable restore drill' rsa2048 encr 1d >/dev/null 2>&1
recipient=$(gpg --with-colons --list-keys | awk -F: '$1=="fpr"{print $10;exit}')
archive="$work/fixture.gpg"
scripts/backup_postgres.sh "$db" fixture postgres "$recipient" "$archive"
digest=$(sha256sum "$archive")
if scripts/backup_postgres.sh "$db" missing_database postgres "$recipient" "$work/failed.gpg" 2>/dev/null; then exit 1; fi
[[ ! -e "$work/failed.gpg" ]]
if scripts/backup_postgres.sh "$db" fixture postgres "$recipient" "$archive" 2>/dev/null; then exit 1; fi
sha256sum --check <<< "$digest"
docker exec "$db" createdb -U postgres restored
start=$SECONDS
gpg --batch --decrypt "$archive" | docker exec -i "$db" pg_restore --single-transaction -U postgres -d restored
[[ $(sql restored <<< 'SELECT domain FROM zones') == drill.invalid ]]
echo "PASS encrypted dump, checksum, failed-dump cleanup, overwrite refusal, restore and zone lookup (restore took $((SECONDS-start))s)"
