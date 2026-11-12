# Proposed Features — approved and implemented where possible

These proposals were approved. Each now carries an implementation **Status**; the original proposal text below it is kept for reference. (Authoritative details, tests and risks: `AUDIT_REPORT.md`.)

Every item either added behaviour that did not exist before, or changed an architectural property (restart-based reload, single DB connection, agent protocol). They came out of the
audit in `AUDIT_REPORT.md`; the reference in brackets points at the finding that motivated each one.

Complexity scale: **S** ≈ a day, **M** ≈ a few days, **L** ≈ 1–2 weeks, **XL** ≈ multi-week / design needed.

Each proposal answers: (1) name, (2) description, (3) problem, (4) why needed, (5) expected functionality,
(6) technical approach, (7) API changes, (8) DB changes, (9) UI changes, (10) dependencies/infrastructure,
(11) security & compatibility, (12) risks, (13) complexity.

---

## Phase 7 additions (2026-11-12) — details and exact results in `AUDIT_REPORT.md` (Phase 7) and `docs/OPERATIONS.md`

| ID | Proposal | Status | Notes |
|---|---|---|---|
| CP-13 | **Admin zone transfer between tenants** (transactional, quota-checked, audited, UI) | **COMPLETED** | owner/share policy defined; concurrent transfers resolve to exactly one winner; browser + API tests incl. permission and quota failures |
| CP-14 | **DNS Lookup with multiple resolvers** (ordered failover, IPv4/IPv6, timeouts, admin-only selection, no public default, no information leakage) | **COMPLETED** | breaking default: nothing configured → 503 `not_configured` (no more implicit 1.1.1.1) |
| CP-15 | **Multi-replica coordination** (shared rate limits; single-writer analytics collector with persisted state) | **COMPLETED** — verified with two real API processes | fixed windows (≤ 2x burst at a boundary); per-replica fallback if PostgreSQL is down |
| CP-16 | **Record-type and country breakdowns** (bounded cardinality, no addresses stored, honest sentinels) | **COMPLETED** — needs `DNS_ZONE_BREAKDOWN=true` and a GeoIP database for countries | country = resolver address (or ECS subnet), not the end user; hourly rollup bounds growth |
| OPS-05 | **Release benchmarks + query-plan review** | **COMPLETED** | two real defects found and fixed (non-sargable tenant predicates; unbounded samples); start-up publication time with many zones documented, not fixed |
| OPS-04 | **Upstream Hickory v0.26.3 merge** | **MERGED AND VALIDATED IN AN ISOLATED WORKTREE; NOT APPLIED TO `main` (needs your commit approval)** | 8 conflicts resolved, 65+ mechanical API edits, all labs identical on both builds |
| OPS-06 | **Read-only delegation / registrar checker and DNS conformance lab** | **COMPLETED** | `scripts/delegation_check.sh`, `scripts/dns_conformance_lab.sh`; the project's domain is delegated but its name server is unreachable from here |
| OPS-07 | **GeoLite2-City in production** | **BLOCKED — EXTERNAL DEPENDENCY** | no City database in the repository or GitHub; needs a MaxMind licence key (`scripts/update_geoip.sh`) |

## Phase 6 additions and status of the Phase 5 "remaining features" list (2026-11-12)

Statuses: **COMPLETED** = implemented and tested locally (see `AUDIT_REPORT.md` Phase 6 for exact results) · **NOT IMPLEMENTED** · **REQUIRES YOUR DECISION**. Nothing here is externally verified.

### Newly implemented proposals

| ID | Proposal | Status | Notes |
|---|---|---|---|
| CP-09 | **Real DNS Lookup** (A AAAA MX TXT NS CNAME SOA SRV PTR DNSKEY DS CAA; wire queries, TTLs, rcodes, NXDOMAIN/NODATA, TCP retry; rate-limited; usable by read-only accounts) | **COMPLETED** | unit + API tests, `scripts/lookup_lab.sh` 22/22 (real server, `dig` cross-check), browser test for all 12 types. Limits: one configurable resolver, no DNSSEC-validation display, no ANY/AXFR. |
| CP-10 | **Tenants, membership and quotas** (zones, records; owner/editor/viewer roles; personal-tenant backfill of existing users; admin UI; customer quota card) | **COMPLETED** | Non-destructive, idempotent migration; quotas enforced on create zone, create record, import and revision restore. Limits: check-then-insert (can overshoot by the request concurrency); the admin screen for moving zones now exists (CP-13). |
| CP-11 | **Persistent, tenant-aware analytics** (history in PostgreSQL, ranges 1 h–90 d, tenant/zone filters, retention `ANALYTICS_RETENTION_DAYS`, admin global view kept) | **COMPLETED** — requires `DNS_ZONE_QUERY_METRICS=true` on the DNS server | Needed an architecture change: per-zone query counter `hickory_zone_queries_total{zone,result}` in the DNS server. `scripts/tenant_analytics_lab.sh` 9/9 with exact counts. No per-type/per-country split yet. |
| CP-12 | **Aggregated overview endpoint** (`GET /api/v1/overview`) replacing one request per zone | **COMPLETED** | 5,007 zones / 40,038 records: 610 ms (admin API), 175 ms (customer with 2 zones). |
| OPS-04 | **Upstream Hickory merge strategy** | **ANALYSED + TRIAL MERGE TESTED — REQUIRES YOUR DECISION** | Recommended: merge `v0.26.3` (8 conflict files, 44 mechanical `control_api` edits). Trial binary passes the GeoDNS lab 32/32. `main` needs a `Catalog::lookup` re-implementation. |
| QA-01 | **Browser, accessibility and visual-regression suites** | **COMPLETED** | `platform_qa.cjs` 66/66, axe-core 0 violations, 32 visual baselines + self-test, `redesign_qa` 165/165, `audit_ui_regression` 50/50. Harness: `scripts/ui_stack.sh`. |

### Phase 5 "remaining feature development" list — current status

| Tier | Feature | Status |
|---|---|---|
| Essential | Real multi-type DNS lookup | **COMPLETED** (CP-09) |
| Essential | Registrar/NS delegation check + status | NOT IMPLEMENTED (needs external DNS; design: compare parent NS with configured NS) |
| Essential | Secondary zones, AXFR/IXFR, NOTIFY, TSIG | NOT IMPLEMENTED (large; REQUIRES YOUR DECISION on priority) |
| Essential | Extra record types (TLSA, SVCB/HTTPS, ALIAS) | NOT IMPLEMENTED |
| Essential | API tokens for automation | NOT IMPLEMENTED |
| Important | Per-zone analytics with persisted history | **COMPLETED** (CP-11); per-type/per-country **COMPLETED** (CP-16) |
| Important | Alert rules wired into a running Prometheus/Alertmanager | NOT IMPLEMENTED (infrastructure) |
| Important | Shared rate-limit state for several API replicas | **COMPLETED** (CP-15); sessions are stateless JWTs + a database token blacklist |
| Important | Backup/restore tooling for DB + DNSSEC keys | NOT IMPLEMENTED |
| Important | Account lifecycle (invites, suspend, sessions) | NOT IMPLEMENTED |
| Important | Quotas / tenants | **COMPLETED** (CP-10) |
| Important | CI pipeline for unit/UI/lab suites; accessibility + visual regression | suites **COMPLETED** (QA-01); CI definition NOT IMPLEMENTED |
| Important | Self-hosted fonts, CSP headers | NOT IMPLEMENTED |
| Advanced | NSEC3, automatic key rollover, CDS/CDNSKEY; GeoDNS+DNSSEC together; failover; DoT/DoH/DoQ | NOT IMPLEMENTED |

---

## Category DNS — data plane

### DNS-01 — Hot reload without restarting the DNS process  *(AUDIT C-6)*
**Status (implementation phase):** **COMPLETED** — in-process reload via `SwapHandler`; lab-verified (0 failed queries, same PID, broken reload rejected).

1. **Name:** In-process zone reload.
2. **Description:** Reload `named.toml` and zone files inside the running `hickory-dns` process instead of exiting and being restarted by the wrapper.
3. **Problem:** Every change makes the server exit; measured port-53 interruption was ≈3.2 s per change with the old wrapper and ≈1 s with the corrected wrapper (queries during the gap are lost).
4. **Why:** An API write should never make the authoritative server unavailable.
5. **Expected:** Zero dropped queries during publication; atomic swap of the zone catalog; failed reload keeps serving the old catalog.
6. **Approach:** In `bin/src/lib.rs` replace "cancel the shutdown token" with re-building the `Catalog` and swapping it behind an `ArcSwap`; keep the `notify` watcher (debounced) or add SIGHUP.
7. **API:** none.  8. **DB:** none.  9. **UI:** none.
10. **Dependencies:** `arc-swap` (small).
11. **Security/compat:** None; the wrapper keeps working as a fallback.
12. **Risks:** Touches the upstream-derived server loop; needs soak testing.
13. **Complexity:** M–L

### DNS-02 — IPv6 listener in generated configuration  *(AUDIT C-7)*
**Status (implementation phase):** **COMPLETED** — `LISTEN_ADDRS_IPV4/IPV6`; default unchanged (IPv4 only).

1. **Name:** Configurable listen addresses.
2. **Description:** Emit `listen_addrs_ipv6` (and optionally specific IPv4 addresses) into the generated `named.toml`.
3. **Problem:** `TomlConfigBuilder` hard-codes `listen_addrs_ipv4 = ["0.0.0.0"]`; the server does not answer on IPv6 at all (verified with `dig -6`). The server itself supports IPv6 (verified with a hand-written config in `scripts/geodns_lab.sh`).
4. **Why:** Public authoritative DNS must be reachable over IPv6; many resolvers prefer it.
5. **Expected:** `LISTEN_ADDRS_IPV4` / `LISTEN_ADDRS_IPV6` env vars on the control API; defaults unchanged (IPv4 only) so nothing breaks on hosts without IPv6.
6. **Approach:** Read env in `generate_all`, pass to `TomlConfigBuilder`.
7. **API:** none.  8. **DB:** none.  9. **UI:** optional read-only display.
10. **Dependencies:** Docker/k8s must publish `:53` on IPv6 (compose currently maps IPv4 only).
11. **Security/compat:** Opt-in; default behaviour unchanged.
12. **Risks:** A wrong address makes the server fail to bind and exit (wrapper then loops).
13. **Complexity:** S

### DNS-03 — Geo rules that never invent names  *(AUDIT C-8)*
**Status (implementation phase):** **COMPLETED** — zone-wide rules only answer names that exist; explicit `record_name` rules unchanged.

1. **Name:** Restrict geo answers to existing owner names.
2. **Description:** A geo rule without `record_name` currently answers *every* A/AAAA query in the zone — including names that do not exist (verified: `nope.geo.lab.test` → NOERROR with the geo target for a BR client) and it shadows the zone's real A records for all names.
3. **Problem:** Surprising wildcard behaviour; NXDOMAIN becomes NOERROR for matching clients.
4. **Why:** Correct authoritative semantics and fewer accidental overrides.
5. **Expected:** Rule applies only to names that exist in the zone with an A/AAAA RRset (or to the explicit `record_name`).
6. **Approach:** In `GeoZoneHandler::lookup`, consult the next handler's existence of the name first, or pass the set of A/AAAA owner names into the engine.
7. **API:** none.  8. **DB:** none.  9. **UI:** copy on the GeoRules page.
10. **Dependencies:** none.
11. **Security/compat:** changes answers for existing zone-wide rules — hence approval.
12. **Risks:** Operators may rely on the wildcard effect.
13. **Complexity:** M

### DNS-04 — City / region GeoIP datasets and update handling  *(AUDIT D-3)*
**Status (implementation phase):** **COMPLETED (software)** — `city` / ISO 3166-2 `region` matching verified on real MaxMind City data (`scripts/geodns_city_lab.sh`, 8/8, IPv4+IPv6+TCP; `geodns` unit tests with the MaxMind open test DB); specificity order city > region > country > continent; `scripts/update_geoip.sh` (checksum-verified atomic download, file-watch reload). **BLOCKED — EXTERNAL** only for production data: a MaxMind licence key for the full GeoLite2-City.

1. **Name:** City-level geo matching with dataset management.
2. **Description:** Support `GeoLite2-City` (subdivision `US-CA`, city) and reload of the MMDB when it changes.
3. **Problem:** Only `GeoLite2-Country` is shipped. `region` rules only match a bare country code (legacy behaviour); ISO 3166-2 matching is implemented but unverified for lack of a City dataset. There is no `city` match type and no dataset refresh (loaded once at start; the shipped file is dated 2026-02-24).
4. **Why:** The request asked for city/region-level routing; stale data gives wrong answers.
5. **Expected:** `city` match type; scheduled download (MaxMind licence key) with integrity check; atomic swap; metric for dataset age.
6. **Approach:** Extend `GeoDB`/`GeoRuleEngine` (already has `region()`), add a `city()` accessor, watcher/reloader task.
7. **API:** `match_type=city`; optional `GET /api/v1/geoip/status`.  8. **DB:** none.  9. **UI:** City option + dataset status card.
10. **Dependencies:** MaxMind account/licence key (infrastructure), outbound HTTPS.
11. **Security/compat:** the licence key must be a secret.
12. **Risks:** City accuracy is low for IPv6 and for resolvers (see DNS-05).
13. **Complexity:** M

### DNS-05 — EDNS Client Subnet-aware geo decisions  *(AUDIT C-9)*
**Status (implementation phase):** **COMPLETED** — opt-in per zone (`ecs_enabled`), ECS option echoed with scope; lab-verified; dashboard toggle (browser-tested).

1. **Name:** ECS support in GeoDNS.
2. **Description:** Today the client IP used for routing is the *recursive resolver's* address.
3. **Problem:** Users of public resolvers (8.8.8.8, 1.1.1.1…) are located at the resolver, not at themselves.
4. **Why:** Accuracy of country/continent routing.
5. **Expected:** If the query carries ECS, locate the ECS prefix and echo scope in the answer.
6. **Approach:** Read the EDNS option in `GeoZoneHandler`, set scope on the response.
7. **API:** none.  8. **DB:** none (optional per-zone toggle).  9. **UI:** optional toggle.
10. **Dependencies:** none.
11. **Security/compat:** ECS exposes client prefixes (privacy); make it opt-in.
12. **Risks:** Cache fragmentation.
13. **Complexity:** M

### DNS-06 — DNSSEC signing and DS management  *(AUDIT C-10)*
**Status (implementation phase):** **COMPLETED** — per-zone DNSSEC (ECDSAP256/384, Ed25519), key generation, DS (SHA-256/384) + DNSKEY shown in API and dashboard, guarded double-signing key rollover, guarded disable, periodic re-signing, NSEC proofs. Validated end to end with ISC `delv` through a parent→child DS chain (`scripts/dnssec_lab.sh`, 30/30). Limits: GeoDNS and DNSSEC are mutually exclusive per zone; NSEC3 and automatic key rollover scheduling are not implemented; DS must be published at the registrar by the operator.

1. **Name:** DNSSEC for hosted zones.
2. **Description:** `servers.dnssec` is a stored flag that nothing reads; no zone is signed (`DNSKEY` query → empty NOERROR, no RRSIG with `+dnssec`).
3. **Problem:** The UI field suggests DNSSEC exists.
4. **Why:** Integrity of answers; required by some TLDs/registrars.
5. **Expected:** Per-zone enable, key generation/rotation, DS record shown for the registrar.
6. **Approach:** Use Hickory's `__dnssec` feature (zone signing with keys stored outside the DB), publish DS in the API.
7. **API:** `/zones/{id}/dnssec` (enable, DS).  8. **DB:** key metadata table.  9. **UI:** DNSSEC card with DS.
10. **Dependencies:** key storage (file/KMS).
11. **Security/compat:** key custody becomes a new sensitive asset.
12. **Risks:** Key loss/rollover mistakes break resolution.
13. **Complexity:** XL

### DNS-07 — Multi-replica distribution (agents) and secondary zones  *(AUDIT C-3, C-4)*
**Status (implementation phase):** **COMPLETED** — registration credentials, signed + versioned bundles, atomic apply, acknowledgements, push, enable/disable, health; `scripts/agent_e2e.py` 6/6.

1. **Name:** Real agent protocol.
2. **Description:** Replace the placeholder agent with a pull-based protocol: authenticate with the agent token, fetch a *versioned, signed* zone bundle, apply atomically, acknowledge version, report health.
3. **Problem:** The agent cannot even register (registration requires an admin JWT it does not have), the config endpoint returns a bare zone list, there are no acknowledgements, and `/config/push` is a stub (now an honest 501).
4. **Why:** Multi-replica consistency and "is it really deployed?" status.
5. **Expected:** Replicas converge on the same bundle version; control plane shows per-agent applied version; stale agents are flagged.
6. **Approach:** New `GET /agents/{id}/bundle?since=`, `POST /agents/{id}/ack`; bundle = zone files + `named.toml` + checksum/signature; agent writes to a staging dir and swaps.
7. **API:** the two endpoints above.
8. **DB:** `agents.applied_version`, `zone_bundles` (or use `agent_configs`, which already exists and is unused).
9. **UI:** applied-version column; enable/disable toggle (the Agents page toggle is currently a TODO no-op).
10. **Dependencies:** the agent must build without OpenSSL headers (`reqwest` with `rustls-tls` only).
11. **Security/compat:** mTLS or signed bundles.
12. **Risks:** Largest design item.
13. **Complexity:** XL

---

## Category CP — control plane

### CP-01 — Database connection pool with reconnect  *(AUDIT C-5)*
**Status (implementation phase):** **COMPLETED** — `db_pool.rs` (+1 reserved transaction connection, automatic reconnect); recovery test.

1. **Name:** Pooled PostgreSQL access.
2. **Description:** The API shares **one** `tokio_postgres::Client`. Requests serialize on it and a dropped connection used to leave the API permanently broken (it now exits so the supervisor restarts it).
3. **Problem:** Throughput ceiling and restart-on-blip availability.
4. **Why:** Production resilience.
5. **Expected:** N pooled connections, automatic replacement of broken ones, `/ready` reflects pool health.
6. **Approach:** `deadpool-postgres`; mechanical change of `data.db` call sites.
7. **API:** none.  8. **DB:** none.  9. **UI:** none.
10. **Dependencies:** `deadpool-postgres`.
11. **Compat:** none.
12. **Risks:** The publish path relies on read-your-writes on one connection today; pooling needs the publish lock (already present) plus a transaction for the read side.
13. **Complexity:** M

### CP-02 — Domain ownership verification  *(AUDIT E)*
**Status (implementation phase):** **COMPLETED** (TXT challenge, `VERIFY_DOMAINS=true`, tested with a local fake resolver) · **BLOCKED — EXTERNAL DEPENDENCY** (lookup against real public DNS unverified; NS-delegation proof not implemented).

1. **Name:** Prove control of a domain before serving it.
2. **Description:** Any user can create a zone for any name (e.g. `bank.com`) as long as no other tenant holds it; the API only prevents overlap between tenants.
3. **Problem:** Tenants can squat or impersonate third-party domains on your name servers.
4. **Why:** Abuse prevention.
5. **Expected:** Zone starts `pending`; activated after a TXT or NS-delegation check against the public DNS; admins can bypass.
6. **Approach:** New `status` column; background verifier using `hickory-resolver` (already a workspace dependency).
7. **API:** `POST /zones/{id}/verify`.  8. **DB:** `zones.status`, `zones.verify_token`.  9. **UI:** verification instructions/state.
10. **Dependencies:** outbound DNS from the API host.
11. **Compat:** existing zones grandfathered as `active`.
12. **Risks:** Support load.
13. **Complexity:** M

### CP-03 — Real role-based access control  *(AUDIT C-12)*
**Status (implementation phase):** **COMPLETED** — viewer/editor zone sharing, owner-only management, UI dialog.

1. **Name:** RBAC beyond admin / owner.
2. **Description:** The API now honours `admin`, `viewer` (read-only) and treats `editor`/`user` as "manage own zones". There is no way to share a zone with another user or to give an editor access to *all* zones.
3. **Problem:** The Users page describes "Editor: can manage zones and records" more broadly than the backend does.
4. **Why:** Teams need shared zone management.
5. **Expected:** Zone membership with per-zone roles.
6. **Approach:** `zone_members` table consulted by `zone_access`.
7. **API:** `/zones/{id}/members`.  8. **DB:** `zone_members`.  9. **UI:** share dialog.
10. **Dependencies:** none.
11. **Compat:** additive.
12. **Risks:** Authorisation bugs — keep a single choke point (`zone_access`).
13. **Complexity:** M

### CP-04 — Query metrics and server health  *(AUDIT B-35, C-9)*
**Status (implementation phase):** **COMPLETED** — server health, publication status, dashboard, query counters verified against the real Prometheus exporter (`scripts/metrics_lab.sh`, 6/6).

1. **Name:** Real dashboard data.
2. **Description:** The "DNS Queries – last 24 h" chart was hard-coded fake data (replaced by an honest empty state) and server "status" is never populated.
3. **Problem:** The dashboard cannot show real activity or health.
4. **Why:** Operability.
5. **Expected:** Query counters per zone/rcode/protocol, server liveness, agent applied version.
6. **Approach:** Use Hickory's existing Prometheus endpoint (`bin/src/prometheus_server.rs`) and have the API query Prometheus, or have agents report counters.
7. **API:** `/metrics/queries`, `/servers/{id}/status` (the UI client already names them).  8. **DB:** none.  9. **UI:** wire the chart.
10. **Dependencies:** Prometheus (the compose file has it commented out).
11. **Compat:** none.
12. **Risks:** Metric cardinality.
13. **Complexity:** M

### CP-05 — Pagination and retention for lists and audit logs  *(AUDIT C-13)*
**Status (implementation phase):** **COMPLETED** — audit log, zones, records and users: opt-in `limit`/`offset`/`q`, `X-Total-Count`; dashboard uses server-side paging/search (browser-tested).

1. **Name:** Paged APIs.
2. **Description:** `GET /audit/logs` returns a fixed latest 100; lists return everything.
3. **Problem:** Large installations get slow/huge responses; audit history is truncated.
4. **Why:** Scalability and forensics.
5. **Expected:** `?limit&cursor`, filters (user, action, date), retention job.
6. **Approach:** keyset pagination.
7. **API:** query params (backward compatible: defaults match today).  8. **DB:** index on `audit_logs(created_at)` already exists.  9. **UI:** paging controls.
10. **Dependencies:** none.
11. **Security/compat:** audit logs contain usernames/IPs — keep admin-only.
12. **Risks:** none significant.
13. **Complexity:** S–M

### CP-06 — Zone history and rollback  *(AUDIT B-20)*
**Status (implementation phase):** **COMPLETED** — revisions on every change, transactional restore, UI History tab.

1. **Name:** Versioned zones.
2. **Description:** Keep each published zone revision and allow restoring one.
3. **Problem:** The last known-good *file* is preserved on failure, but there is no history after a successful bad edit.
4. **Why:** Recovery from operator mistakes.
5. **Expected:** List revisions, diff, restore.
6. **Approach:** `zone_revisions(zone_id, serial, content, created_at, user_id)` written by the publisher.
7. **API:** `/zones/{id}/revisions`, `/restore`.  8. **DB:** new table.  9. **UI:** History tab.
10. **Dependencies:** storage.
11. **Security/compat:** tenant isolation via `zone_access`.
12. **Risks:** growth → retention policy.
13. **Complexity:** M

### CP-07 — Authentication hardening  *(AUDIT C-13, D-6)*
**Status (implementation phase):** **COMPLETED** — `TRUSTED_PROXIES`, per-address + per-username login budgets, TOTP MFA (API + UI).

1. **Name:** Proxy-aware rate limiting, MFA.
2. **Description:** Login throttling is per username only (an attacker can lock a victim out for a minute; spraying many usernames from one IP is unlimited). Behind nginx every client has the proxy's address, so a per-IP limit needs a trusted `X-Forwarded-For`.
3. **Problem:** Brute-force and credential-stuffing resistance is partial.
4. **Why:** Admin accounts control all DNS.
5. **Expected:** Per-IP + per-username buckets, trusted-proxy config, optional TOTP.
6. **Approach:** `governor` keyed limiter (already used), `TRUSTED_PROXIES` env.
7. **API:** MFA enrol/verify endpoints.  8. **DB:** `users.totp_secret`.  9. **UI:** MFA enrolment.
10. **Dependencies:** a TOTP crate.
11. **Security/compat:** trusting a spoofable header is dangerous if misconfigured.
12. **Risks:** lock-out of legitimate users.
13. **Complexity:** M

### CP-08 — Agent enable/disable  *(AUDIT C-4)*
**Status (implementation phase):** **COMPLETED** — `PUT /agents/{id}`; UI toggle wired.

1. **Name:** Agent toggle.
2. **Description:** The Agents page toggle is a TODO no-op although `agents.enabled` exists and is now honoured by heartbeat/config.
3. **Problem:** The UI promises an action that does nothing.
4. **Why:** Operators need to disable a compromised or retired agent without deleting it.
5. **Expected:** `PUT /agents/{id}` with `{enabled}`.
6. **Approach:** one UPDATE.
7. **API:** that endpoint.  8. **DB:** none.  9. **UI:** wire the button.
10. **Dependencies:** none.
11. **Security/compat:** admin only.
12. **Risks:** none.
13. **Complexity:** S

---

## Category OPS

### OPS-01 — Refuse to start with placeholder secrets  *(AUDIT C-16)*
**Status (implementation phase):** **COMPLETED** — startup refuses placeholder secrets/unsafe bootstrap (`ALLOW_INSECURE_DEFAULTS` to override for development). Existing deployments must edit `env/api.env` first.

1. **Name:** Secret hygiene.
2. **Description:** `env/api.env`, `env/db.env`, `k8s/secret.yaml` are committed with placeholder values (`CHANGE_ME_STRONG_PASSWORD`, `postgres:password`), `ALLOWED_ORIGINS=*`, and `FORCE_BOOTSTRAP=true`, which resets the admin password to `ADMIN_PASSWORD` at *every* start.
3. **Problem:** A deployment copied as-is is insecure.
4. **Why:** Prevent accidental insecure production deployments.
5. **Expected:** Startup check rejecting known placeholders; docs recommending Docker/K8s secrets; `FORCE_BOOTSTRAP` default false.
6. **Approach:** env validation in `main()`.
7. **API:** none.  8. **DB:** none.  9. **UI:** none.
10. **Dependencies:** none.
11. **Security/compat:** could stop existing deployments that still use placeholders (intended).
12. **Risks:** outage on upgrade if they do.
13. **Complexity:** S

### OPS-02 — Dependency upgrades  *(AUDIT E-D1)*
**Status (implementation phase):** **COMPLETED** — `cargo audit`: 0 vulnerabilities (was 25 against the current advisory DB); `npm audit`: 0; vite 8 / react-router 7 / axios upgraded; agent on reqwest 0.13 (rustls only); rusqlite 0.41, maxminddb 0.27, actix-web-prom 0.10. Two unmaintained transitive crates remain (pin-utils, proc-macro-error: warnings only). Upstream Hickory fixes: the ones that apply to this build were ported (see `AUDIT_REPORT.md` Phase 3).

1. **Name:** Security upgrades.
2. **Description:** `trivy` reports 17 HIGH Rust advisories (aws-lc-sys, openssl, rustls-webpki, quinn-proto, postgres-protocol, hickory-net/resolver 0.26.0-alpha.1) and 15 HIGH npm advisories (axios 1.13.4 → ≥1.16.0, form-data, lodash).
3. **Problem:** Known vulnerabilities in the supply chain. **Not done** because you asked not to upgrade dependencies without approval.
4. **Why:** Risk reduction.
5. **Expected:** Upgrade to the fixed versions listed in the report; re-run tests.
6. **Approach:** `cargo update -p …`, `npm install axios@^1.16`.
7. **API:** none.  8. **DB:** none.  9. **UI:** none.
10. **Dependencies:** network access to registries.
11. **Security/compat:** the Hickory crates are an in-tree fork at `0.26.0-alpha.1`; upstream fixes (0.26.1/0.26.2) must be merged, not just bumped.
12. **Risks:** API drift in axios/hickory.
13. **Complexity:** M (npm alone: S)

### OPS-03 — Publication status metrics
**Status (implementation phase):** **COMPLETED** — Prometheus gauges, `/dns/status`, dashboard banner, example alert rules (`deploy/prometheus/outis-alerts.yml`).

1. **Name:** Prometheus gauges for publication.
2. **Description:** Expose `zones_published`, `zones_failed`, `last_publish_timestamp`, per-zone serial.
3. **Problem:** Publication failures are visible only in logs today.
4. **Why:** Alerting on stale zones.
5. **Expected:** Gauges + alert examples.
6. **Approach:** use the existing `prometheus` crate in the control API.
7. **API:** additions to `/metrics`.  8. **DB:** none.  9. **UI:** none.
10. **Dependencies:** Prometheus.
11. **Security/compat:** `/metrics` is unauthenticated today — decide whether to protect it.
12. **Risks:** none.
13. **Complexity:** S
