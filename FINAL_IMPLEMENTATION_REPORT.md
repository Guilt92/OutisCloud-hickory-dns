# Final implementation report — 2026-11-24

## A. Executive summary

Roadmap: 133 tasks. Completed: 34; partially completed: 50; needs verification: 8; blocked: 40; not started: 1. Completion: 25.6%.

The full roadmap is **not complete**. This report uses the 133-row status matrix in `task.md` §19 with the source-verified corrections in §20. Those statuses have not all been revalidated during this execution. The latest code changes complete CORE-006 query-log controls and CORE-007 cache tests, fix ZONE-003 clone target rewriting, add a CSP/browser regression for SEC-005, add a recoverable route error for CUI-003, and repair the active image workflow dependency gate. Other roadmap gaps remain.

## B. Completed tasks

The following items are reported completed in the current roadmap matrix. The text is the existing implementation evidence; historical per-task commit attribution is unavailable in that matrix. The API-010 improvement is part of this report’s delivery commit.

- **ARCH-004 (P0, phase 0):** Frontend route-contract and lint checks pass; dead controls removed.
- **ARCH-005 (P1, phase 0):** Docs consistency check passes; README/DELIVERY_SUMMARY corrected.
- **ARCH-006 (P0, phase 0):** ADR-0002 accepted; scope decision documented.
- **ARCH-008 (P0, phase 0):** ADR-0003 accepted; topology/SLO/RPO/RTO targets documented.
- **CORE-012 (P2, phase 4):** Dynamic-update policy documented; prerequisite/prescan tests exist.
- **ZONE-001 (P1, phase 2):** JSON import dry-run/row errors plus BIND import (Hickory parser, `$ORIGIN`, quoted TXT, byte cap) tested; bulk import runs as a durable job.
- **ZONE-002 (P1, phase 2):** Authenticated `POST /api/v1/zones/bulk-import` with limits, dry-run, per-zone row errors, durable job progress/cancel and UI.
- **ZONE-004 (P2, phase 2):** Description/tags API, server-side `?tag=` filter with `X-Total-Count`, UI tag filter, and integration test.
- **ZONE-005 (P0, phase 2):** TXT and NS-delegation verification (`method=txt|ns`), rate limits/retries, fail-safe pending state, and `verified_via` evidence.
- **ZONE-006 (P1, phase 2):** active/held/suspended/archived lifecycle with hold reason/until, archived write blocking, serving effects, audit and integration tests.
- **REC-001 (P2, phase 2):** Comment/tags columns, tenant-safe metadata API, list payload, and record editor dialog with integration-test coverage.
- **REC-002 (P0, phase 2):** Publish-failure rollback API tests pass.
- **REC-003 (P1, phase 2):** `PUT /api/v1/zones/{id}/rrsets` applies an all-or-nothing RRset batch with validation, audit and rollback.
- **REC-004 (P3, phase 11):** Apex-alias non-goal documented in docs/RECORD_TYPES.md.
- **DNSSEC-006 (P1, phase 3):** `GET .../dnssec/ds-status` queries parent DS, reports missing/stale records, and dispatches `dnssec.ds_mismatch` webhook alerts.
- **DNSSEC-007 (P2, phase 3):** GeoDNS/DNSSEC exclusion enforced by guards and covered by tests.
- **DNSSEC-008 (P1, phase 3):** Rollover algorithm carry and new-key protection API test passes.
- **XFR-006 (P3, phase 4):** ADR-0007 documents catalog zones as out of scope.
- **GEO-005 (P2, phase 5):** GeoRule API pagination/search plus UI search by zone/match/target/record and explicit priority-order guidance.
- **TRAF-001 (P2, phase 5):** Deterministic policy engine has 3 passing unit tests.
- **HLTH-001 (P2, phase 5):** Health-check CRUD, public-IP-only DNS probes (SSRF-safe), scheduler, thresholds and persisted results with tests.
- **HLTH-002 (P1, phase 6):** State machine with consecutive thresholds, result history/pruning, webhook/audit transitions and worker wired into startup.
- **MON-004 (P1, phase 6):** Both API and DNS metrics endpoints support constant-time bearer-token checks (`METRICS_TOKEN`/`PROMETHEUS_TOKEN`); health/readiness stay open.
- **TEN-001 (P1, phase 8):** Quota reservation concurrency and usage tests pass.
- **API-002 (P1, phase 7):** `platform_middleware` replays/stores `Idempotency-Key` responses for every mutating request, in addition to the explicit create-zone path and tests.
- **API-004 (P1, phase 7):** Global per-IP limiter plus tenant-scoped budgets in `platform_middleware` with 429/Retry-After and tests.
- **API-005 (P2, phase 7):** Signed webhooks (HMAC), SSRF-safe target validation, durable deliveries with retry/backoff and dead-letter status.
- **API-006 (P2, phase 7):** Durable jobs with progress/cancel/retention, bulk import endpoint, recovery worker and integration test.
- **API-010 (P1, phase 7):** Route-contract check runs in CI, schema-drift test runs against PostgreSQL in CI, and both are part of the documented validation command set.
- **ADM-002 (P0, phase 11):** Clone dialog, lifecycle (active/held/suspended/archived) controls, tag filtering and metadata editing surfaced in the zone console.
- **OPS-004 (P1, phase 12):** Prometheus/Alertmanager/Grafana configs plus incident, rollback, certificate, GeoIP and failover runbooks.
- **OPS-005 (P1, phase 12):** `docs/runbooks/` covers incident response, rollback, certificate lifecycle, GeoIP and failover/recovery.

- **CORE-006 (P1, phase 1):** Query logs now support off/info/debug and sampled logging; DEBUG and error-path PII is redacted by default. `cargo test -p hickory-server --lib query_log_tests` passed 2/2. Implemented in commit `0835ca439a8656f88585656298c1e6dd69b37af7`.

- **CORE-007 (P2, phase 1):** Forwarder cache default is configurable at 512. `docs/FORWARDING.md` defines the authoritative boundary. A deterministic cache miss → hit → TTL expiry test and existing caching-client tests pass; `cargo test -p hickory-resolver --lib` passed 79/79 with 3 ignored. New regression test commit: `7d3d980d9976c5215d791f41f357693f8b9d6c06`.

## C. Remaining tasks

Each entry gives the current status and the specific remaining gap recorded in the authoritative matrix. Dependencies and acceptance criteria are in `task.md` §18; these entries should be rechecked against code before implementation.

- **ARCH-001 (P0, phase 0; PARTIALLY COMPLETED):** PostgreSQL migration/runtime parity was verified; SQLite verification is not applicable to the PostgreSQL-only control plane.
- **ARCH-002 (P0, phase 0; PARTIALLY COMPLETED):** Implemented: ADR-0001 exists. Remaining: durable outbox implementation deferred to PERF-001/002.
- **ARCH-003 (P0, phase 0; PARTIALLY COMPLETED):** Implemented: ADR-0005 selects a model. Remaining: benchmark and implementation pending.
- **ARCH-007 (P0, phase 0; BLOCKED):** Tracked live-looking secrets require owner-provided values and coordinated rotation/untracking.
- **CORE-001 (P1, phase 1; NEEDS VERIFICATION):** Implemented: TCP-only and chunked AXFR with TSIG MAC chaining implemented. Remaining: signed interop unvalidated. Verification gap: Signed AXFR multi-message interoperability against an independent implementation was not run.
- **CORE-002 (P1, phase 1; NEEDS VERIFICATION):** Implemented: Journal transactions, delta query and IXFR path exist. Remaining: SQLite end-to-end IXFR test pending. Verification gap: SQLite-backed end-to-end IXFR exchange was not run.
- **CORE-003 (P1, phase 1; PARTIALLY COMPLETED):** Implemented: NOTIFY ACK and bounded sender retry exist. Remaining: no peer config or secondary refresh.
- **CORE-004 (P0, phase 1; PARTIALLY COMPLETED):** DNS /health and /ready integration test passes; Helm DNS probes now render. Cluster-level probe transitions and key/catalog/freshness failure checks remain unverified.
- **CORE-005 (P1, phase 1; NEEDS VERIFICATION):** Implemented: Admission semaphores and unit test exist. Remaining: no high-fanout load proof. Verification gap: High-fanout load/backpressure proof and port-exhaustion check were not run.
- **CORE-008 (P1, phase 1; PARTIALLY COMPLETED):** Existing dig/delv labs and a new malformed UDP packet/recovery integration test pass. The local dual-stack test verifies IPv4 and reports that `::1` is unavailable; new-code IPv6 and unified external delegation/DNSSEC conformance remain.
- **CORE-009 (P2, phase 1; PARTIALLY COMPLETED):** Implemented: Forwarding/recursion boundary documented. Remaining: trust-anchor and hardening work pending.
- **CORE-010 (P1, phase 1; NEEDS VERIFICATION):** Implemented: H3 features, CLI/config and listener wired. Remaining: no H3 client integration test. Verification gap: DoH3 client integration test was not run.
- **CORE-011 (P2, phase 1; PARTIALLY COMPLETED):** Implemented: Record-type policy documented. Remaining: advanced types and UI round-trip tests pending.
- **CORE-013 (P1, phase 1; NEEDS VERIFICATION):** Implemented: Per-zone fingerprint reload implemented. Remaining: no load proof under write pressure. Verification gap: Incremental reload proof under write pressure was not run.
- **ZONE-003 (P2, phase 2; PARTIALLY COMPLETED):** Clone API/UI and audit exist. Clone target rewriting now preserves TXT and unrelated names; unit and disposable PostgreSQL integration tests pass. Remaining: built-in template picker and NS/DNSSEC settings acceptance tests.
- **ZONE-007 (P1, phase 2; PARTIALLY COMPLETED):** Diff endpoint/UI exist. Bounded `ZONE_REVISION_RETENTION` and `outis_zone_snapshot_failures_total` are implemented; isolated PostgreSQL pruning/diff tests pass. Remaining: zone-setting snapshots, rollback coverage, and API-visible snapshot failure status. Commit `dfac6ec2bf96aa99b3bbd5fe211f994b52b574ab`.
- **REC-005 (P1, phase 11; PARTIALLY COMPLETED):** Implemented: Delete confirmation added. Remaining: record diff/history and bulk safeguards pending.
- **DNSSEC-001 (P0, phase 3; BLOCKED):** Needs KMS/HSM decision and approved key-store migration.
- **DNSSEC-002 (P1, phase 3; PARTIALLY COMPLETED):** Implemented: Manual CSK rollover works. Remaining: scheduler/KSK-ZSK/emergency rollover pending.
- **DNSSEC-003 (P2, phase 3; BLOCKED):** Needs signed-zone content design and parent-side coordination policy.
- **DNSSEC-004 (P0, phase 3; BLOCKED):** Depends on DNSSEC-001; encrypted backup format/restore drill unavailable.
- **DNSSEC-005 (P3, phase 3; BLOCKED):** Requires multi-operator product decision and external coordination.
- **DNSSEC-009 (P1, phase 3; PARTIALLY COMPLETED):** Implemented: Local negative tests exist. Remaining: NSEC3 and expired-signature cases pending.
- **SECONDARY-001 (P1, phase 4; BLOCKED):** Requires secondary-zone schema, refresh engine and UI lifecycle decision.
- **SECONDARY-002 (P1, phase 4; BLOCKED):** Depends on SECONDARY-001 and TRANSFER-001; no peer/timer model.
- **SECONDARY-003 (P2, phase 4; BLOCKED):** Depends on SECONDARY-002; split-brain policy undecided.
- **SECONDARY-004 (P1, phase 4; BLOCKED):** Depends on SECONDARY-002/TRANSFER-003.
- **TRANSFER-001 (P1, phase 4; PARTIALLY COMPLETED):** Implemented: Per-zone axfr_policy field and endpoint exist. Remaining: config emission and AllowSigned enforcement pending.
- **TRANSFER-002 (P1, phase 4; BLOCKED):** Depends on DNSSEC-001/ARCH-007; SIG(0) removed upstream; external signed interop required.
- **TRANSFER-003 (P1, phase 4; BLOCKED):** Depends on TRANSFER-001 completion; no transfer audit/metrics events.
- **REPL-001 (P1, phase 4; BLOCKED):** Depends on ARCH-007; mTLS and separate agent signing keys require key infrastructure.
- **REPL-002 (P0, phase 4; BLOCKED):** Requires topology/infrastructure choice and deferred publication outbox.
- **REPL-003 (P1, phase 4; BLOCKED):** Depends on REPL-002.
- **GEO-001 (P2, phase 5; PARTIALLY COMPLETED):** Implemented: Deterministic weighted policy engine exists. Remaining: DNS/API/UI propagation pending.
- **GEO-002 (P2, phase 5; PARTIALLY COMPLETED):** Implemented: Engine accepts injected health state. Remaining: real health-driven failover pending.
- **GEO-003 (P2, phase 5; PARTIALLY COMPLETED):** Implemented: Dataset watcher/atomic install/staleness exist. Remaining: licensed City data is external.
- **GEO-004 (P2, phase 5; BLOCKED):** Requires policy/version schema and activation design.
- **TRAF-002 (P3, phase 5; BLOCKED):** Requires external location/latency data sources.
- **TRAF-003 (P3, phase 5; BLOCKED):** Requires pool/region schema design.
- **TRAF-004 (P2, phase 5; BLOCKED):** Depends on TRAF-003.
- **ANA-001 (P2, phase 6; PARTIALLY COMPLETED):** Implemented: Query-log redaction/level controls exist. Remaining: structured sampling/persistence/export pending.
- **ANA-002 (P1, phase 6; PARTIALLY COMPLETED):** Implemented: RCODE counters exist. Remaining: latency histogram/history tables pending.
- **ANA-003 (P2, phase 6; BLOCKED):** Requires export format/tenant-scope decision.
- **MON-001 (P0, phase 6; NEEDS VERIFICATION):** Implemented: Scrape config corrected. Remaining: no runtime Prometheus scrape smoke test. Verification gap: Runtime Prometheus scrape smoke test was not run.
- **MON-002 (P1, phase 6; NEEDS VERIFICATION):** Implemented: Alertmanager config/rules added. Remaining: no runtime delivery test. Verification gap: Runtime Alertmanager delivery test was not run.
- **MON-003 (P1, phase 6; NEEDS VERIFICATION):** Implemented: Grafana dashboard JSON added. Remaining: no runtime provisioning test. Verification gap: Runtime Grafana provisioning test was not run.
- **MON-005 (P1, phase 6; BLOCKED):** Multi-location probes require external infrastructure.
- **CUST-001 (P1, phase 8; BLOCKED):** Requires email provider, user-status schema and invite/reset token model.
- **CUST-002 (P3, phase 8; BLOCKED):** Requires external IdP/OIDC/SAML dependency and demand approval.
- **CUST-003 (P3, phase 8; BLOCKED):** Depends on CUST-002.
- **TEN-002 (P3, phase 8; BLOCKED):** Depends on RBAC-001 permission catalog.
- **TEN-003 (P0, phase 8; PARTIALLY COMPLETED):** Implemented: Deterministic tenant matrix exists. Remaining: analytics/agents/search cases pending.
- **RBAC-001 (P3, phase 8; BLOCKED):** Requires permission catalog tables and policy engine across handlers.
- **RBAC-002 (P1, phase 8; PARTIALLY COMPLETED):** User role and per-user reset are tested; effective-permission display is not implemented.
- **API-001 (P1, phase 7; PARTIALLY COMPLETED):** Implemented: OpenAPI spec route with component schemas exists. Remaining: full route annotation and lint pending.
- **API-003 (P1, phase 7; BLOCKED):** Depends on API-001 completion and ARCH-007 secret decision.
- **API-007 (P1, phase 7; PARTIALLY COMPLETED):** Implemented: Pagination exists for several lists. Remaining: remaining lists and error envelopes pending.
- **API-008 (P2, phase 7; BLOCKED):** Depends on API-001 completion.
- **API-009 (P3, phase 7; BLOCKED):** Depends on API-008 and external provider toolchain.
- **AUD-001 (P1, phase 8; PARTIALLY COMPLETED):** Implemented: Audit detail and CSV export endpoints tested. Remaining: UI detail/export wiring pending.
- **AUD-002 (P0, phase 8; PARTIALLY COMPLETED):** Implemented: Broad audit coverage exists. Remaining: coverage-matrix ADR and failure-policy decision pending.
- **AUD-003 (P2, phase 8; PARTIALLY COMPLETED):** Implemented: Retention configurable. Remaining: archive/SIEM target external.
- **BAK-002 (P0, phase 12; BLOCKED):** Requires PostgreSQL backup/PITR storage target and restore drill.
- **BAK-003 (P0, phase 3; BLOCKED):** Depends on DNSSEC-001; no encrypted key export/restore target.
- **BAK-004 (P0, phase 12; BLOCKED):** Depends on BAK-002/BAK-003.
- **BAK-005 (P0, phase 12; PARTIALLY COMPLETED):** ADR-0003 documents RPO/RTO targets; per-component DR exercise, owner assignment and drill evidence are missing.
- **SEC-001 (P0, phase 9; BLOCKED):** Requires certificate issuance and reverse-proxy deployment topology.
- **SEC-002 (P0, phase 9; BLOCKED):** Requires CA/certificate provisioning and connection-string migration.
- **SEC-003 (P0, phase 9; PARTIALLY COMPLETED):** Rotation tool exists; JWT key IDs/rotation and separate agent signing keys are not implemented.
- **SEC-004 (P1, phase 9; BLOCKED):** Depends on key custody decision and user lifecycle schema.
- **SEC-005 (P1, phase 9; PARTIALLY COMPLETED):** UI Nginx now sends a CSP, verified by syntax and live-header tests in disposable Nginx. A Playwright Chromium test against disposable Nginx verified that an injected inline script was blocked by CSP. Remaining: secure-cookie option and token-storage migration.
- **SEC-006 (P1, phase 9; NOT STARTED):** No abuse scoring, zone holds/locks or transfer-protection operator workflow exists.
- **SEC-007 (P0, phase 9; PARTIALLY COMPLETED):** Implemented: Per-source governor and admission limits exist. Remaining: full RRL coverage pending.
- **SEC-008 (P1, phase 9; PARTIALLY COMPLETED):** Added `deny.toml`, CI audit/deny gates, CycloneDX SBOM script, release checksum signing and provenance workflow. Remaining: image signature verification policy.
- **PERF-001 (P0, phase 10; PARTIALLY COMPLETED):** Implemented: ADR state machine exists. Remaining: outbox implementation pending.
- **PERF-002 (P0, phase 10; PARTIALLY COMPLETED):** Implemented: ADR selected concurrency model. Remaining: benchmark/implementation pending.
- **PERF-003 (P1, phase 10; PARTIALLY COMPLETED):** A repeatable 5,000-zone harness and results exist; required 1k/10k/50k scenarios and SLO thresholds are absent.
- **PERF-004 (P1, phase 10; PARTIALLY COMPLETED):** DNS admission limits and tenant quotas exist; per-tenant/zone cardinality limits, fair queuing and 429 tests are absent.
- **HA-001 (P0, phase 10; PARTIALLY COMPLETED):** Multi-replica lab and advisory publication lock exist; shared/versioned zone state, deterministic writer and convergence proof are absent.
- **HA-002 (P0, phase 12; BLOCKED):** Depends on HA-001 and shared publication state.
- **HA-003 (P1, phase 10; BLOCKED):** Requires redundant DNS/anycast/multi-region infrastructure.
- **HA-004 (P0, phase 10; PARTIALLY COMPLETED):** Health/readiness endpoints exist; publication-aware readiness, graceful drain, maintenance mode and rolling-restart tests are absent.
- **HA-005 (P1, phase 12; BLOCKED):** Requires chaos/failure-injection environment.
- **HA-006 (P0, phase 12; BLOCKED):** Depends on HA-005 and BAK-004 drills.
- **ADM-001 (P1, phase 11; PARTIALLY COMPLETED):** Dashboard empty/error/disabled/publication states exist; SLO target display and browser truth tests are absent.
- **ADM-003 (P1, phase 11; PARTIALLY COMPLETED):** Record delete confirmation exists; type-aware forms, record diff/history UX and keyboard/a11y tests remain incomplete.
- **ADM-004 (P1, phase 11; PARTIALLY COMPLETED):** Audit filters/pagination/export and server/status UX exist; row detail and full permission-aware catalog remain.
- **ADM-005 (P2, phase 11; BLOCKED):** Requires notification model and settings schema.
- **UX-001 (P1, phase 11; PARTIALLY COMPLETED):** Viewer/editor/admin UI permission tests exist; systematic no-hidden-403/404 contract and new-control checks remain.
- **CUI-001 (P2, phase 11; PARTIALLY COMPLETED):** Implemented: Customer dashboard exists. Remaining: onboarding/error polish pending.
- **CUI-002 (P2, phase 11; PARTIALLY COMPLETED):** Implemented: Analytics UX exists. Remaining: provenance/export/missing-data polish pending.
- **CUI-003 (P1, phase 11; PARTIALLY COMPLETED):** Existing WCAG checks pass. A route error boundary now offers retry and dashboard actions; a Chromium test aborting the lazy login chunk confirms the fallback. Shared Modal focus trapping and restoration (`eb75ba752`) pass a Chromium Tab/Escape test. Bulk-import file selection is keyboard reachable (`6c758dc3a`) and passes a Chromium test. Remaining: other dialogs, labels, chart alternatives and a full WCAG audit.
- **CUI-004 (P2, phase 11; PARTIALLY COMPLETED):** Implemented: Responsive/error work partial. Remaining: customer journeys need regression pass.
- **OPS-001 (P0, phase 12; BLOCKED):** Requires TLS reverse proxy, certificates and production topology decision.
- **OPS-003 (P0, phase 12; PARTIALLY COMPLETED):** CI/CD workflow includes DB/UI/DNS/security gates, and per-image GHCR tags plus DNS image build were repaired. GitHub reports CI and CI/CD workflows `disabled_manually`, so required gates have not run. Enable both workflows with repository Actions permissions, run them on this branch, and require passing results. Active Docker Hub workflow run `45341283543` succeeded for API, DNS and UI images. The workflow now gates publishing on PostgreSQL-backed API/DNS tests, UI lint/build, Helm, docs and dependency policy. Run `45342563964` passed all steps except dependency policy and correctly skipped publishing; local lockfile/policy fixes pass both audit and deny, run `45344351797` passed all validation steps on GitHub; image builds are in progress.
- **OPS-002 (P1, phase 12; PARTIALLY COMPLETED):** Helm now renders API/DNS/UI Deployments and Services, Ingress, ConfigMaps, shared pre-provisioned RWX zone claim mounts, and DNS readiness/liveness probes. Lint/render and structural checks pass. Agent/DB templates, external Secret/images/RWX claim, and cluster rollout validation remain.
- **OPS-006 (P1, phase 12; PARTIALLY COMPLETED):** GeoIP atomic update automation exists; production certificate lifecycle and upgrade/rollback tests are absent.
- **OPS-007 (P2, phase 12; PARTIALLY COMPLETED):** Added static status-page generator, CycloneDX SBOM script, signed release checksums/provenance workflow and redacted diagnostics bundle. Remaining: publish SBOM/provenance to a public transparency log.
- **OPS-008 (P0, phase 12; PARTIALLY COMPLETED):** Review documented in `docs/PRODUCTION_READINESS.md`; gate deliberately remains open on ARCH-007, TLS, backups, DNSSEC custody, HA and OPS-002.

## D. Blockers

The blocked entries in section C identify the missing dependency or decision. OPS-003 is partial because the required GitHub workflows are manually disabled; no GitHub API token is available in this environment to enable them. An owner must enable CI and CI/CD in repository settings or provide a scoped Actions token, then verify required runs. Secret rotation requires replacement credentials and a coordinated window; DNSSEC key custody requires a KMS/HSM design; multi-host replication requires topology and infrastructure; PITR requires backup storage and an isolated restore drill. Some legacy BLOCKED labels describe engineering work that can proceed locally and should be reassessed rather than treated as an approval gate. No destructive server action was taken.

## E. Testing and validation

| Procedure | Environment | Expected | Actual | Status |
|---|---|---|---|---|
| `node web/ui/tests/route-contract.cjs` | Local | Frontend method/path pairs registered by API | 83 pairs matched | PASS |
| `npm --prefix web/ui run test:routes` | Local | Contract passes | 83 pairs matched | PASS |
| `npm --prefix web/ui run lint` | Local | No ESLint errors | Exit 0 | PASS |
| `npm --prefix web/ui run build` | Local | Production bundle builds with route recovery | 2,264 modules transformed; exit 0 | PASS |
| `git diff --check` | Local | No whitespace errors | Exit 0 | PASS |
| `cargo test -p control_api --bin control_api clone_target_tests -- --test-threads=1` | Local | Only DNS targets change | 1 passed | PASS |
| `TEST_DATABASE_URL=postgres://postgres:***@127.0.0.1:55435/roadmap_test cargo test -p control_api --bin control_api clone_zone_copies_records_with_rewritten_domain -- --test-threads=1` | Disposable local PostgreSQL 16 | CNAME rewritten, TXT preserved | 1 passed | PASS |
| `cargo test -p hickory-server --lib query_log_tests` | Local | Redaction and sampling correct | 2 passed | PASS |
| `cargo test -p hickory-server --lib` | Local | Server library regression suite passes | 30 passed | PASS |
| `cargo test -p hickory-resolver --lib response_cache_miss_hit_and_expiry` | Local | Cache misses before insert, hits with decremented TTL, and expires | 1 passed | PASS |
| `cargo test -p hickory-resolver --lib` | Local | Resolver regression suite passes | 79 passed, 3 ignored | PASS |
| `cargo test -p hickory-dns --test integration malformed_udp_packet_does_not_disrupt_authoritative_queries -- --test-threads=1` | Local | Headerless packet dropped; server still answers valid query | 1 passed | PASS |
| `cargo test -p hickory-dns --test integration test_ipv4_and_ipv6_toml_startup -- --test-threads=1` | Local | IPv4 and IPv6 answer where loopback available | IPv4 passed; IPv6 could not run (`::1` bind returned `EADDRNOTAVAIL`) | PARTIAL |
| Initial dual-stack test before environment guard | Local | IPv6 client connects | Failed at IPv6 connect with `EADDRNOTAVAIL`; direct `::1` bind check reproduced the runner limitation | ENVIRONMENT FAILURE |
| `cargo test -p control_api --bin control_api revision_retention_tests -- --test-threads=1` | Local | Bounded revision retention parser | 1 passed | PASS |
| `cargo test -p control_api --bin control_api snapshot_failures_are_exposed_in_metrics -- --test-threads=1` | Local | Failure counter registered and increments | 1 passed | PASS |
| `TEST_DATABASE_URL=postgres://postgres:***@127.0.0.1:55436/revision_test cargo test -p control_api --bin control_api revision_retention_prunes_old_snapshots -- --test-threads=1` | Disposable local PostgreSQL 16 | Prune to two revisions | 1 passed | PASS |
| `TEST_DATABASE_URL=postgres://postgres:***@127.0.0.1:55436/revision_test cargo test -p control_api --bin control_api revision_diff_reports_added_and_removed_records -- --test-threads=1` | Disposable local PostgreSQL 16 | Revision diff still reports added/removed records | 1 passed | PASS |
| SHA256 verification of Helm 3.16.4 archive from get.helm.sh | Local `/tmp` | Download matches published checksum | `sha256sum -c` OK | PASS |
| `/tmp/linux-amd64/helm lint helm/hickory-dns` | Local | Chart lints | 1 chart, 0 failures; icon recommendation only | PASS |
| `/tmp/linux-amd64/helm template outis helm/hickory-dns` with full and disabled-component values, then YAML structural assertions | Local | Valid resources, references, selectors, shared claim, DNS probes and UI proxy | 16 full resources; 8 minimal resources; assertions passed | PASS |
| `nginx -t` against rendered UI ConfigMap in disposable Nginx container | Local | Generated UI proxy config valid | Syntax OK | PASS |
| Python YAML inspection of `.github/workflows/ci-cd.yml` | Local | Four image builds use matching metadata outputs | API, DNS, agent and UI references matched | PASS |
| GitHub Actions workflows API query for the repository | GitHub | Required workflows active and runnable | CI and CI/CD reported `disabled_manually`; active Docker Hub image workflow separate | REQUIRED GATE NOT RUN |
| GitHub Actions run `45341283543` for `be40b3196`, job/step API inspection | GitHub | Active Docker Hub images build and push | Run and control API, DNS, UI image steps completed successfully | PASS (IMAGE PATH ONLY) |
| `python3 scripts/docs_check.py` | Local | Documentation consistency check completes | Completed; four existing broken-link warnings | PASS WITH WARNINGS |
| `cargo-audit v0.23.0 audit --db <local RustSec advisory checkout> --no-fetch` | Local | No known vulnerabilities in lockfile | No vulnerabilities; four unmaintained warnings | PASS WITH WARNINGS |
| `cargo-deny 0.22.0 check` | Local | Advisories, bans, licenses and sources policy passes | All four categories OK after lockfile and manifest fixes | PASS |
| GitHub Actions run `45342563964` | GitHub | Validation gate passes before images publish | API/DNS/UI/Helm/docs passed; dependency policy failed on original lockfile; publishing skipped | FAIL (REPAIRED) |
| GitHub Actions run `45344351797` validation job | GitHub | Full gate passes before image build | PostgreSQL-backed API, DNS, UI, Helm, docs, and dependency policy all passed | PASS |
| `cargo fmt --all -- --check` | Local | Formatting clean | Exit 0 | PASS |
| `cargo test -p control_api --bin control_api -- --test-threads=1` after dependency updates | Local without `TEST_DATABASE_URL` | Non-DB API tests pass | 176 passed; DB cases skip internally without URL | PASS (NON-DB ONLY) |
| `cargo test -p hickory-server --lib` after dependency updates | Local | Server regression tests pass | 30 passed | PASS |
| `docker run --rm --add-host control-api:127.0.0.1 -v web/ui/nginx.conf:/etc/nginx/nginx.conf:ro nginx:alpine nginx -t` | Disposable local Nginx | Configuration accepted | Syntax OK | PASS |
| Initial `nginx -t` without a `control-api` DNS alias | Disposable local Nginx | Configuration accepted | Failed resolving `control-api`; the Compose service name was absent from the isolated container. Retried with a disposable host alias above. | ENVIRONMENT SETUP FAILURE |
| `curl -fsSI http://127.0.0.1:18081/` against disposable Nginx | Local | HTTP 200 with CSP and security headers | HTTP 200; CSP, Referrer-Policy and nosniff present | PASS |
| `OUTIS_BROWSER_PATH=/snap/bin/chromium npx playwright test tests/route-recovery.spec.cjs tests/security-headers.spec.cjs --config=tests/playwright.config.cjs --project=chromium` | Local Chromium and disposable Nginx | CSP blocks inline script; failed login chunk shows recoverable error | 2 passed in 8.4s | PASS |
| `npm run dev -- --host 127.0.0.1 --port 18082 --strictPort` and `OUTIS_BROWSER_PATH=/snap/bin/chromium npx playwright test tests/modal-focus.spec.cjs --config=tests/playwright.config.cjs --project=chromium` | Local Vite/Chromium | Modal traps Tab/restores opener; file picker works by keyboard | 2 passed in 11.6s; Vite stopped. Watcher emitted `EMFILE` warnings despite raised soft file limit; tests passed. | PASS WITH ENVIRONMENT WARNING |
| `dig @127.0.0.1 -p 53 example.com SOA +norecurse +time=2 +tries=1 +noall +comments` over UDP/TCP | germ test host | Authoritative server refuses unrelated zone | REFUSED on both transports | PASS |
| `dig @127.0.0.1 -p 53 uid0.ir SOA +norecurse +time=2 +tries=1 +noall +comments +answer` over UDP/TCP | germ test host | Hosted zone answers authoritatively | NOERROR, `aa`, matching SOA serial `2026111900` on both transports | PASS |
| `dig @127.0.0.1 -p 53 uid0.ir AXFR +tcp +time=3 +tries=1 +noall +comments +stats` | germ test host | Transfer follows existing policy | REFUSED; no transfer authorized | PASS |
| `ssh -o BatchMode=yes germ` with hostname, kernel, service/resource and container inspection | germ | Reach host and inspect without mutation | Reached `fastcreate-472995`; four OutisCloud containers healthy; 7.8 GiB RAM; 6.1 GiB disk available | PASS |
| `curl` to `127.0.0.1:8080/health`, `/ready`, and `127.0.0.1:8081/` over SSH | germ | HTTP 200 | HTTP 200 on all three | PASS |

No database migration, DNS transfer, DNSSEC rollover, backup/restore, or load test was run in this execution. A targeted browser CSP test was run. Both disposable PostgreSQL containers used for clone and revision tests were stopped afterward. `cargo test -p hickory-server --lib` passed 30/30; `python3 scripts/docs_check.py` completed with four existing broken-link warnings. Historical test claims in `task.md` and `TASK_STATUS.md` were not repeated. The user confirmed germ is a test environment.

Helm packaging now includes API, DNS, and UI deployments, but cluster validation and agent/DB templates remain. The initial Helm image fetch (`docker run --rm alpine/helm:3.16.4 version --short`) failed with a Docker Hub TLS handshake timeout. Helm 3.16.4 was then downloaded from get.helm.sh to `/tmp`, checksum verified, and used to lint/render the chart.

## F. Production readiness

Implemented and locally tested: the strengthened API method/path contract, DNS query-log controls, clone rewrite fix, and UI CSP. Integration tested: the static frontend/backend route mapping and clone behavior against disposable PostgreSQL 16. Validated on available test server: connectivity, container health reports, API health/readiness and UI HTTP response, authoritative SOA over UDP/TCP, and transfer-policy refusal. The new local code has not been deployed to germ. The Helm chart is render-tested but has not been applied to a cluster. Safe for production deployment: **not established**. The platform is **not yet production-ready** under the roadmap’s P0 gate, especially while tracked secrets, recovery drills, and replication gaps remain.

## G. Git delivery

Branch: `main`; upstream: `origin/main`. The previous delivery commit is `2e62264678588fff46b0cff8fb8f89ee5160ee6f`; the clone/logging code and tests are in `0835ca439a8656f88585656298c1e6dd69b37af7`, and the UI CSP is in `3cc9b4f14066d8ba6292dd6b6e0d842c044a9e52`, CORE-007 cache regression is in `7d3d980d9976c5215d791f41f357693f8b9d6c06`, chart implementation is in `36d52bd06d0fd76dfe9bae7f73c1d2bf275693c3`, CI image-tag/DNS-build repair is in `ce8c471549ef12636dce4ddc28c2016843a62f99`, CORE-008 conformance tests are in `6ca552095b72602870d30d58db9b468179d80ddd`, and revision-retention/metric work is in `dfac6ec2bf96aa99b3bbd5fe211f994b52b574ab`. Browser CSP regression: `dffbb3e01`; dependency policy repair: `e61dea001`; route error recovery: `3170df46d`; shared modal focus: `eb75ba752`; keyboard file picker: `6c758dc3a`. The status/report commit is the commit containing this file. The pushed remote head was verified with `git ls-remote origin refs/heads/main` after delivery. Pre-existing user edits remain outside these commits. No environment file, secret, or runtime DNS state is included in the delivery commit.
