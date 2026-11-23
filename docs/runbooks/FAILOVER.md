# Failover and recovery

This deployment currently runs one control-API writer and one DNS server per host.
Multi-host HA and anycast are **not** implemented (see `TASK_STATUS.md`, HA-001..006);
this runbook covers single-host failure recovery and manual promotion.

## Detect

- External probe: DNS query for a known zone over UDP and TCP, and HTTPS `/health`
  through the proxy.
- Local: `docker compose ps`, `/health`, `/ready`, Prometheus alerts from
  `deploy/prometheus/outis-alerts.yml`.
- A DNS failure usually surfaces as SERVFAIL/timeouts; a control-plane failure leaves
  existing zone files serving but blocks changes.

## Recover the host

1. If the host is lost, provision a replacement with the same repository commit and
   restore PostgreSQL from the latest verified dump (`docs/runbooks/ROLLBACK.md`).
2. Restore the zone/DNSSEC key volume and `named.toml`; DNSSEC private keys live under
   the zone directory and are required to keep signatures valid.
3. Start `db`, then `control-api`, then `dns-server`, then `ui`. Wait for the startup
   publication and `/ready`.
4. Repoint DNS delegation or the load balancer only after local validation.

## Manual promotion of a standby (when one exists)

- Promote only a host with the same commit and a database restored from the writer.
- Stop the old writer first (split-brain protection); the publication advisory lock
  protects zone generation, not operator intent.
- Update the DNS delegation/anycast advertisement, then verify from multiple public
  resolvers with `scripts/delegation_check.sh <domain>`.

## Failback

Treat failback as a new change: freeze writes, take a fresh dump, restore/verify on the
primary, switch traffic, and keep the former active host as standby. Record RPO/RTO
actuals; targets are in `docs/adr/ADR-0003-*`.
