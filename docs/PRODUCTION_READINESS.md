# Production-readiness review (OPS-008)

**Date:** 2026-11-23
**Commit reviewed:** `e29e8d6c1` (plus the JWT rotation change in the working tree)
**Verdict: NOT READY FOR PRODUCTION.** The review was performed; the P0 gate
remains open because several required controls depend on owner decisions,
credentials, or infrastructure that are outside the repository.

## Evidence used

- Control API: 172 automated tests on isolated PostgreSQL 16 (171 before the JWT
  rotation test), including schema-drift, auth/RBAC, lifecycle, import, jobs,
  webhooks, health checks and security-header tests.
- DNS: `cargo test -p hickory-dns --lib`, `/health` and `/ready` integration test.
- Server/resolver/GeoDNS suites as recorded in `TASK_STATUS.md`.
- Frontend: lint, production build, 60-route contract check.
- CI: `.github/workflows/ci.yml` now runs fmt, clippy, DB-backed tests, UI build,
  route contract, docs check, DNS tests, audit/deny and image builds.
- Runbooks: incident, rollback, certificate, GeoIP, failover.

## Gate checklist

| Area | Requirement | Status | Evidence / gap |
|---|---|---|---|
| Secrets | No live secrets in git; documented rotation | **FAIL** | ARCH-007 blocked: tracked `.env`, `env/*.env`, `k8s/secret.yaml` contain live-looking values. |
| TLS | Public API served over TLS with managed certificates | **FAIL** | SEC-001/OPS-001 blocked on deployment topology and CA issuance; expiry checker/runbook added. |
| Backups | PostgreSQL backup/PITR and restore drill | **FAIL** | BAK-002/004 blocked on storage target and drill environment. |
| DNSSEC keys | KMS/HSM custody, encrypted backup, rollover drills | **FAIL** | DNSSEC-001/004 blocked on custody decision. |
| HA | Redundant API/DNS/database, failure drills | **FAIL** | HA-001..006 blocked on multi-host infrastructure. |
| Secondary DNS | Standards-based secondary/transfer/replication | **FAIL** | SECONDARY/REPL blocked; scope documented in ADR-0002. |
| Supply chain | Audit/deny gates, SBOM, signed release artifacts | **PARTIAL** | `deny.toml`, CI audit/deny, SBOM script and keyless release checksum signing added; image-signature policy and public provenance publication pending. |
| Monitoring | Scrape configs, alerts, dashboards, runbooks | **PARTIAL** | Configs and runbooks exist; no runtime Prometheus/Alertmanager/Grafana smoke test on a production-like host. |
| Rate limiting | API, tenant and DNS abuse controls | **PARTIAL** | Per-IP/tenant API budgets and per-source DNS QPS limiter; full response-rate-limiting by name/type is pending (SEC-007). |
| Identity | MFA recovery, encrypted TOTP secrets, OIDC/SAML | **FAIL** | SEC-004 and CUST-002 blocked on key custody and IdP decision. |
| Data lifecycle | Retention/export/erasure policy | **PARTIAL** | Audit/analytics retention configurable; formal erasure/export decision pending (ANA-003). |
| Operations | CI, runbooks, status page, diagnostics | **PARTIAL** | CI repaired, runbooks/status page/diagnostics bundle added; production deployment and on-call ownership not exercised. |
| Capacity | Repeatable load/capacity model | **PARTIAL** | Local benchmark exists; no dedicated load generator or capacity plan (PERF-004). |

## P0 blockers (must close before launch)

1. ARCH-007 — rotate and untrack secrets; purge history if required.
2. SEC-001/OPS-001 — deploy behind TLS with automated certificate renewal.
3. BAK-002/003/004 — PostgreSQL PITR plus DNSSEC key backup and a passed restore drill.
4. DNSSEC-001/004 — key custody and encrypted backup decision.
5. HA-001..006 — redundant topology, shared publication state and failover drill.
6. OPS-002 — validated Kubernetes manifests or an explicit decision to stay on Compose.
7. OPS-008 — re-run this review after the items above and attach drill evidence.

## What can be signed off now

The application layer is internally consistent and tested for the implemented
scope: auth/RBAC, zone lifecycle, records/import, DNSSEC operations (without
KMS), GeoDNS policy, analytics, audit, tokens/jobs/webhooks, health checks,
security headers and monitoring configuration. This is **not** a production
readiness claim; it is evidence that the remaining gate items are external
decisions or infrastructure work rather than missing product code.
