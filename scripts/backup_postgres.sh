#!/usr/bin/env bash
# Usage: backup_postgres.sh CONTAINER DATABASE PGUSER GPG_FINGERPRINT OUTPUT
set -euo pipefail
umask 077
[[ $# == 5 ]] || { echo "Expected container, database, user, recipient fingerprint and output" >&2; exit 2; }
[[ $4 =~ ^([[:xdigit:]]{40}|[[:xdigit:]]{64})$ ]] || { echo "Full recipient fingerprint required" >&2; exit 2; }
out=$5
tmp=$(mktemp -- "$(dirname -- "$out")/.pg-dump.XXXXXXXX")
trap 'rm -f -- "$tmp"' EXIT
docker exec "$1" pg_dump --no-password --format=custom --username="$3" --dbname="$2" |
  gpg --batch --no-tty --trust-model always --encrypt --recipient "$4" > "$tmp"
# Same filesystem, atomic publication with no overwrite.
ln -T -- "$tmp" "$out"
