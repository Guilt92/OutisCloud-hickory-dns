# Incident response runbook

Use this when customers report resolution failures, the control API is unavailable,
or a security event is suspected. It assumes the Docker Compose deployment from the
repository root on the DNS host.

## 1. Classify and open the incident

| Severity | Example | First response |
|---|---|---|
| SEV-1 | DNS answers wrong or absent for many zones; data loss; secret leak | page the owner, freeze deployments, follow rollback |
| SEV-2 | control API down, one tenant broken, DNSSEC bogus | investigate within 15 minutes |
| SEV-3 | UI degraded, one non-critical endpoint failing | next business day |

Record: start time (UTC), reporter, affected zones/tenants, current commit
(`git rev-parse HEAD`), last known good commit, and actions taken.

## 2. Triage (read-only)

```bash
docker compose ps
docker compose logs --since 30m control-api dns-server
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:9000/health
curl -fsS http://127.0.0.1:9000/ready
docker compose exec control-api curl -fsS http://localhost:8080/health
dig @127.0.0.1 example.com SOA +short
dig @127.0.0.1 example.com +dnssec
```

Check PostgreSQL reachability and disk space **before** restarting anything:

```bash
docker compose exec db pg_isready -U postgres
df -h /var/lib/docker
docker stats --no-stream
```

Do not run `docker compose down --volumes`, delete zone files, or restore a database
snapshot until the owner approves.

## 3. Stabilise

- DNS wrong after a deploy: roll back (see `ROLLBACK.md`).
- DNS server unhealthy but API healthy: restart only `dns-server`, then re-check
  `/ready` and a known-good zone.
- API unhealthy: check database connectivity, migrations and disk first. Restarting
  the API republishes every zone before listening, so allow several minutes.
- Suspected secret exposure: stop using the credential, rotate with
  `scripts/rotate_secrets.py` after owner approval, and preserve logs.
- Suspected abusive tenant: revoke API tokens and suspend the tenant through the API;
  keep evidence.

## 4. Communicate

Send a short status update every 30 minutes for SEV-1/SEV-2: impact, start time,
current mitigation, next update. Never include customer data or secrets.

## 5. Close

- Confirm resolution with `dig` against every authoritative node, `/ready`, and a
  test zone create/update/delete.
- Preserve logs and the output of `scripts/diagnostics_bundle.sh`.
- Write a blameless postmortem within 5 business days: timeline, root cause,
  detection gap, and tracked follow-up tasks.
