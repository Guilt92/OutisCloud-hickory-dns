# Rollback runbook

Rollback is a forward operation on the host: check out the last known good commit,
rebuild the affected images, and restart one service at a time. Database migrations
are additive and idempotent; there is **no automatic down-migration**. Take a
PostgreSQL dump before rolling back across a schema change.

## Prepare

```bash
cd /root/OutisCloud-hickory-dns
git fetch origin
git log --oneline -5
git rev-parse HEAD                 # current (bad) commit
git rev-parse origin/main          # candidate good commit
docker compose exec -T db pg_dump -U postgres -Fc postgres > /root/backup-$(date +%Y%m%d-%H%M).dump
```

Never `git reset --hard`, `git clean`, or force-push a deployed branch.

## Roll back the control API (schema compatible)

```bash
git checkout <good-commit>
docker compose build control-api
docker compose up -d --no-deps control-api
curl -fsS http://127.0.0.1:8080/health
```

Watch the logs until the startup publication finishes (`zones published`) before
declaring success.

## Roll back the DNS server

```bash
git checkout <good-commit>
docker compose build dns-server
docker compose up -d --no-deps dns-server
curl -fsS http://127.0.0.1:9000/ready
dig @127.0.0.1 example.com SOA +short
```

The DNS server reads generated files from the shared zone volume; the control API
remains the writer. Do not edit files in that volume by hand.

## Roll back the UI

```bash
docker compose build ui
docker compose up -d --no-deps ui
```

## If the schema must go back

1. Stop `control-api` only.
2. Restore the dump into a **new** database, point `DATABASE_URL` at it via
   `env/api.env`, and start the good API version.
3. Keep the old database until validation completes.
4. Owner approval is required; this destroys writes made after the dump.

## Verify

- `/health` on API and DNS exporter, `/ready` on DNS.
- A known zone resolves identically over UDP and TCP, with DNSSEC if enabled.
- Create/update/delete a disposable test zone and record.
- `docker compose ps` shows every service healthy.
