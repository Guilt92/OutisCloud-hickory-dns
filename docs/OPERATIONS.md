# OutisCloud DNS — architecture notes, configuration and migrations (phase 7)

## DNS query logging

`DNS_QUERY_LOG_LEVEL=info` (the default) logs response summaries;
`DNS_QUERY_LOG_LEVEL=debug` also logs request details when the process tracing
filter allows DEBUG; `off` disables per-query logs. Client addresses and query
names are redacted by default; use `DNS_QUERY_LOG_REDACT=false` only for isolated
debugging. `DNS_QUERY_LOG_SAMPLE_EVERY=N` logs roughly one in N requests using
the DNS request ID (default `1`, valid range `1` to `65535`). Sampling covers
request, response, malformed-packet, and refused-query logs. It controls log
volume but is not a statistically independent sample.

## Zone revision retention

`ZONE_REVISION_RETENTION` sets the number of recent snapshots kept per zone.
The default is 50; accepted values are 1 through 1000. Invalid values fall
back to 50. Pruning occurs after a new, non-duplicate revision is inserted.
This setting is not a replacement for PostgreSQL backup or PITR.

## Components
`hickory-dns` (authoritative DNS, hot reload, GeoDNS, DNSSEC) ← zone files + `named.toml` written by → `control_api` (REST API, PostgreSQL, tenants/quotas, analytics collector) ← `web/ui` (React). Agents (`crates/agent`) pull signed bundles from the API to replicas.
PostgreSQL is the only shared state of the control plane.

## Running several control-API replicas
| Concern | Mechanism | Behaviour |
|---|---|---|
| Rate limits (login per user, login per address, DNS Lookup per account) | `shared_rate_limits`: one atomic `INSERT .. ON CONFLICT DO UPDATE .. RETURNING` per request on the **database clock**, 60 s fixed windows | the budget is shared by all replicas, survives restarts, cannot be bypassed by switching replicas; up to 2x the budget can pass around a window boundary. If PostgreSQL is unreachable each replica falls back to its stricter in-process limiter and logs a warning (never fail-open). Old windows are purged after 15 min. |
| Analytics collector | lease `collector_lease` (atomic upsert, TTL `ANALYTICS_LEASE_SECS`, default max(3 x interval, 15 s)) + persisted counters `collector_state` + advisory transaction lock | exactly one replica writes. A replica that joins stays idle; if the writer is killed, restarts or loses the database, another replica takes over after the lease expires and continues from the **persisted** counters, so nothing is duplicated and nothing is lost (counters are cumulative: the first successful step after an outage records the whole gap). A failed write rolls back samples and counters together. Set `ANALYTICS_SAMPLE_SECS=0` on replicas that must never collect. |
| Schema migrations | idempotent `CREATE .. IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`, retried on a concurrent-DDL race | replicas may start together; take a backup before the first start of a new version (there is no automatic down-migration) |
| Publication | PostgreSQL advisory lock around zone generation | one publisher at a time; **start-up publishes every zone before the API listens** (measured: ~105 s for 5,006 zones in a release build) — plan rolling restarts accordingly |

Verified with two real processes on one database by `scripts/multi_replica_lab.sh` (see `AUDIT_REPORT.md`).

## DNS Lookup resolvers
`DNS_LOOKUP_RESOLVERS="internal=10.0.0.53,backup=[2001:db8::53]:53,192.0.2.1:5353"` — ordered failover list (max 8; optional `label=`, IPv4 `ip[:port]`, IPv6 `[ip]:port` or bare ip, default port 53). Invalid entries stop the API at start (exit 2).
Fallback if unset: an explicitly set `DNS_VERIFY_RESOLVER`, then the host's `/etc/resolv.conf`. **There is no built-in public resolver**: with nothing configured the tool answers `503 not_configured`.
Strategy: *failover for everybody, selection only for administrators* (`"resolver":"<label>"` in the request, for diagnostics). Each resolver is tried at most once (`DNS_LOOKUP_TIMEOUT_MS`, default 2000) within one overall deadline (`DNS_LOOKUP_DEADLINE_MS`, default 6000); TCP only for truncated answers. NOERROR/NXDOMAIN stop the search; timeouts, network errors, SERVFAIL, REFUSED and FORMERR move to the next resolver (if every resolver answers such a status the last status is returned as-is). A resolver that failed in the last 15 s is tried last, so a dead primary costs one timeout, not one per query. Customers never see resolver addresses, labels or per-resolver outcomes (generic `resolver_unavailable`); administrators get `resolver` and `attempts`.

## Analytics and breakdowns
DNS server: `DNS_ZONE_QUERY_METRICS=true` (per-zone totals) and `DNS_ZONE_BREAKDOWN=true` (adds `hickory_zone_qtype_total{zone,qtype}` and `hickory_zone_country_total{zone,country}`), `GEOIP_DB_PATH`, `GEOIP_MAX_AGE_DAYS` (warn threshold, default 180).
Cardinality is bounded: `qtype` is one of 14 fixed labels (else `OTHER`); a zone keeps at most 32 distinct country codes plus the sentinels below.
Privacy: only the aggregated country **code** is kept — never client addresses (the resolver address, or the ECS subnet when the query carries one, is looked up in memory and dropped).
Country sentinels (never a fabricated country): `ZZ-private` private/reserved/documentation/CGNAT/loopback addresses · `ZZ-unknown` routable address not in a loaded GeoIP database · `ZZ-nodata` **no GeoIP database loaded** (distinct from unknown) · `ZZ-other` per-zone overflow.
Control API: `ANALYTICS_SAMPLE_SECS` (60), `ANALYTICS_RETENTION_DAYS` (90), `ANALYTICS_LEASE_SECS`. `GET /api/v1/analytics/tenant|global?range=1h|6h|24h|7d|30d|90d&interval=auto|1m|5m|15m|1h|6h|1d&zone=&tenant_id=` (≤ 2,000 buckets). Customers can only read their own tenant; history is attributed to the tenant that owned the zone when the sample was taken (a transfer does not move history).
Growth: one row per zone, dimension value and sample interval. At 60 s sampling, 1,000 busy zones produce ~1.4 M base rows per day per dimension table — use `ANALYTICS_SAMPLE_SECS=300` and a shorter retention on large installations (see the benchmark in `AUDIT_REPORT.md`).

## GeoIP
`GEOIP_DB_PATH` (DNS server). The repository ships only `deploy/dns/GeoLite2-Country.mmdb` (no City database exists in the repository or in its GitHub copy). City/Region need `GeoLite2-City.mmdb` from MaxMind (free account + licence key, EULA forbids redistribution): `scripts/update_geoip.sh` downloads it with checksum verification and replaces it atomically; the server reloads it in place. Keys are read from the environment and never logged. Country statistics report the database age; an old or missing database degrades to the sentinels above.

## Zone transfer between tenants
`PUT /api/v1/zones/{id}/tenant {"tenant_id": "<uuid>|null", "keep_shares": false}` (admin only; UI: Zones → Transfer). One transaction with `FOR UPDATE` on the zone and the destination tenant: destination quotas (1 zone + the zone's records) are enforced race-free; records, GeoDNS rules, DNSSEC keys and revisions stay attached to the zone (nothing is copied); the zone `owner` is kept only if that user belongs to the destination tenant, otherwise it moves to a destination owner (or is cleared); explicit per-user shares are removed unless `keep_shares`; the audit entry `zone.transfer` records actor, zone, source/destination tenant (id and name), record count, shares removed and whether the owner changed. Analytics history stays with the tenant that owned the zone at the time.

## Delegation / registrar checks (read-only)
`scripts/delegation_check.sh <domain>` queries the parent zone's servers for the NS set and glue, then every delegated name server over UDP and TCP (authoritative answer, same NS set, same SOA serial, redundancy). It sends DNS queries only and changes nothing.

## Migrations added in this phase (all additive, idempotent)
`shared_rate_limits`, `collector_lease`, `collector_state`, `zone_qtype_samples`, `zone_country_samples` (+ indexes). Earlier: `tenants`, `tenant_members`, `zones.tenant_id`, analytics tables (phase 6).

## Environment variables (new in phase 7)
`DNS_LOOKUP_RESOLVERS`, `DNS_LOOKUP_TIMEOUT_MS`, `DNS_LOOKUP_DEADLINE_MS`, `ANALYTICS_LEASE_SECS` (control API) · `DNS_ZONE_BREAKDOWN`, `GEOIP_MAX_AGE_DAYS` (DNS server). `DNS_LOOKUP_RATE_PER_MIN` and the login limits are now shared across replicas.


## Monitoring

Prometheus scrapes the DNS exporter at `dns-server:9000/metrics` and the control API at
`control-api:8080/metrics`. Alert rules are loaded from `deploy/prometheus/outis-alerts.yml`
and delivered through Alertmanager. Grafana dashboards are provisioned from
`deploy/grafana/provisioning`. The DNS `/health` and `/ready` endpoints are served from the
same exporter listener; `/ready` returns 503 when the catalog is stale or listeners failed.

The metrics endpoints are intended for the internal Docker network only. Do not expose
ports 9000/9090/9093 publicly without authentication and network policy. Both exporters
accept an optional bearer token: set `METRICS_TOKEN` (control API) and
`METRICS_TOKEN` or `PROMETHEUS_TOKEN` (DNS server). When a token is set, configure
Prometheus with `authorization.credentials_file` for each scrape job; never inline the
token in `prometheus.yml`. `/health` and `/ready` remain unauthenticated so probes work.

## Runbooks

- `docs/runbooks/INCIDENT_RESPONSE.md` — severity, triage and communication.
- `docs/runbooks/ROLLBACK.md` — application and database rollback.
- `docs/runbooks/CERTIFICATE_LIFECYCLE.md` — TLS inventory, renewal and `scripts/check_certs.sh`.
- `docs/runbooks/GEOIP.md` — MaxMind refresh and staleness handling.
- `docs/runbooks/FAILOVER.md` — single-host recovery and manual promotion.

Support bundles: `scripts/diagnostics_bundle.sh` (redacted logs, health, metrics).
Release SBOMs: `scripts/release_sbom.sh dist/sbom`.

## JWT secret rotation

Set `JWT_SECRET` to the new value and list the old value(s) in
`JWT_PREVIOUS_SECRETS` (comma separated) for one access-token lifetime (15
minutes) or longer. New tokens are signed with `JWT_SECRET`; tokens signed with
a previous secret are still verified during the overlap window, then stop
working when the variable is cleared. Refresh tokens are hashed in the database
and are not affected by this setting; rotate them by revoking sessions if the
signing secret may have leaked.
