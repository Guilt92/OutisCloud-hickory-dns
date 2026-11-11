# OutisCloud Hickory DNS — Audit Report

Scope: Hickory DNS core as used by the project, the custom Control API (`crates/control_api`), the GeoDNS crate and
server handler, the zone publication pipeline, the agent, the web dashboard (`web/ui`) and deployment files.
Work was done on branch `main`; **nothing was committed or pushed.** `helm/`, `deploy/` (including
`deploy/dns/zone.uid0.ir`, which is not present in this checkout), image/tag locks and any existing `node_modules`
were not touched.

**How things were verified.** A throw-away PostgreSQL 16 container (`outis-audit-pg`, removed afterwards), the real
`control_api` binary, the real `hickory-dns` binary and `dig` were run together; GeoDNS was exercised from client
addresses that exist only inside private network namespaces (host network untouched); the dashboard was driven with a
real headless Chromium. No part of this was verified against public DNS — see section D.

Legend: *Locally verified* = reproduced/verified on this machine. *Externally verified* = checked against the public
internet. **Nothing in this report is externally verified.**

---

## Phase 3 — deferred work completed after the storage upgrade (supersedes the BLOCKED rows below)

The host disk was enlarged (60 GB), so everything previously blocked by storage was done and tested. Where a row in Phase 2,
section C or "Deferred tasks" below still says BLOCKED — STORAGE, **this section is authoritative**. Still **not** externally
verified: nothing was checked against the public internet, a registrar or a licensed GeoLite2-City file.

| Item | Status | Evidence (all local) |
|---|---|---|
| DNSSEC signing + DS management | **COMPLETED** | `crates/control_api/src/dnssec.rs`: per-zone enable (ECDSAP256/384, Ed25519), PKCS#8 key files (0640, never returned by the API), DNSKEY + DS (SHA-256/384) in API and dashboard tab, double-signing rollover (`rollover`, `rollover/complete`), disable only with `confirm_ds_removed`, audit trail, periodic re-signing (`RESIGN_INTERVAL_HOURS`, default weekly), NSEC proofs. `scripts/dnssec_lab.sh`: **30/30** with ISC `delv` as independent validator (parent→child DS chain, A/AAAA/MX/TXT/CNAME, NXDOMAIN, NODATA, wildcard, IPv6, TCP, wrong trust anchor rejected, hot-reload signing, rollover, insecure delegation after disable). API tests + independent DS/key-tag recomputation. Server bugs found and fixed on the way: the geo handler did not compile with DNSSEC; DS queries were answered from the child instead of the parent zone; signed zones lacked an NSEC proof unless configured. **Limits:** GeoDNS and DNSSEC are mutually exclusive per zone; no NSEC3; rollover is operator-driven; the DS must be published at the registrar by the operator. |
| City / Region GeoDNS | **COMPLETED (software)** / **BLOCKED — EXTERNAL** (production data) | verified on real MaxMind City data (MaxMind open test database): `geodns` unit tests and `scripts/geodns_city_lab.sh` (**8/8**, IPv4, IPv6, TCP). Rule tie-break is now explicit: scoped record > zone-wide, city > region > country > continent. `scripts/update_geoip.sh` (checksum-verified atomic download; tested with a mock server incl. corrupt download). A MaxMind licence is needed for the full GeoLite2-City. |
| ECS dashboard toggle | **COMPLETED** | per-zone toggle (GeoDNS zones), browser-tested; lab ECS checks unchanged. |
| Pagination Zones / Records / Users | **COMPLETED** | opt-in `limit`/`offset`/`q` + `X-Total-Count`, no params = unchanged output; dashboard uses server paging and search. API test + browser checks. |
| Vite 8 / react-router 7 | **COMPLETED** | vite 8.3, plugin-react 6, react-router-dom 7.18, `npm audit`: 0; UI Dockerfile on Node 22. Browser regression **50/50** (Chromium, live API). |
| Query counters from the real exporter | **COMPLETED** | Prometheus exporter is now a default feature (loopback only unless `PROMETHEUS_LISTEN_ADDR`); `scripts/metrics_lab.sh` **6/6**. |
| `zone_file_reload.rs` | **COMPLETED** | rewritten (no library import, current client API); asserts hot reload, rejection of a broken zone, recovery, same PID. Found: the server aborted privilege drop on Debian (no `nobody` group) — now falls back to `nogroup`. |
| Full `cargo test --workspace` | **COMPLETED** | **862 passed, 0 failed, 26 ignored** (`TEST_DATABASE_URL` + City test DB set). One upstream test (`named_metrics_tests::test_updates`) is `#[ignore]`d with a reason: this fork never emitted `hickory_zone_records_modified_total`; it only started compiling when the exporter became a default feature. The previous stale `txt_tests::test_zone` expectation (SOA TTL now defaults to MINIMUM, commit 65741f113) was corrected. |
| Release builds | **COMPLETED** | `cargo build --release` of `hickory-dns`, `control_api`, `control_agent`; the DNS-server Docker image was built from `bin/Dockerfile` (test image removed). Dockerfiles moved from `rust:1.85` to `rust:1.99` because the lock now needs Rust ≥ 1.89 (workspace `rust-version` = 1.89). |
| Load / performance | **COMPLETED** | `scripts/dnsload.rs` (std-only UDP load generator), release build, 4-core shared VM with the generator on the same host: ~31–40k qps closed loop, 0 loss and p99 ≈ 6.5 ms at a paced 20k qps; static, GeoDNS and DNSSEC-flagged queries are within ±15 %. **Found and fixed a real DoS-amplifier:** every NXDOMAIN scanned all RRsets (a 20,000-record zone answered only ~600 qps of misses); now O(log n): **611 → 31,165 qps** (regression test compares 1k vs 30k RRsets). |
| Dependency review | **COMPLETED** | `cargo audit` against the 2026-11-11 advisory DB: **25 → 0 vulnerabilities** (actix-http/web, h2, bytes, quinn-proto, rustls, tokio, time, webpki-roots, postgres-protocol/tokio-postgres, rusqlite→libsqlite3 0.39, maxminddb 0.27, protobuf via actix-web-prom 0.10, agent on reqwest 0.13 so rustls-webpki 0.101 is gone). 2 *unmaintained* transitive warnings remain (pin-utils, proc-macro-error). |
| Upstream Hickory fixes (0.26.2/0.26.3, 30 advisories) | **COMPLETED (applicable ones)** / reviewed | Ported: unbounded pre-allocation from wire RR counts (GHSA-67wc), zone-lexer panic on tokens > 4095 chars (GHSA-4rph; reachable from API record values), tests for both. Already not present in this fork: TSIG underflow, SVCB/HTTPS text-parser panics (the parser does not exist here). Not applicable to this build (features not compiled or not used): DoH/DoQ (g5xf, 2f4m, 5r56, g8wg), recursor and DNSSEC *validation* (resolver/net client side: 3w89, vrv5, p2jv, 5j98, 929p, 8hq4, vcjp, v44v, 6f2x, cx5j, qw83, 9px7, 57pw, 7php, rx82, j2rc, 86vr, 624w, 3r6v, xv7c, 29q9). **If you enable forwarding/recursion or validation, merge upstream v0.26.3 first.** A wholesale merge was not attempted: the fork has diverged in `catalog`, `zone_handler`, `proto` zone parsing. |
| RRL "slip", TCP exemption | **COMPLETED** | every 2nd over-budget UDP query gets an empty TC=1 reply (`DNS_RATE_LIMIT_SLIP`), TCP is not limited; lab 32 checks incl. these. |
| Cross-instance publish lock | **COMPLETED** | PostgreSQL advisory lock around publication (test with a second connection). Login/rate-limit state is still per instance. |
| Schema upgrades | **COMPLETED** | automated: fresh schema in every API test; `legacy_schema_upgrades_in_place_keeping_data` replays the original migration SQL (fixtures in `crates/control_api/tests/fixtures`), upgrades twice, checks data, login, publication. Found and fixed: the legacy `type`→`record_type` rename looked at all schemas (`information_schema` without `table_schema`). |

**Test totals (final):** `cargo test --workspace` 862 passed / 0 failed / 26 ignored; GeoDNS lab 32/32 · City lab 8/8 · DNSSEC lab 30/30 ·
metrics lab 6/6 · agent e2e 6/6 · browser regression 50/50 · `cargo audit` 0 vulnerabilities · `npm audit` 0.
**Remaining honest gaps:** no public-internet/registrar verification; GeoLite2-City licence; GeoDNS+DNSSEC exclusivity; no NSEC3; the
UI redesign requested afterwards is not part of this commit. New knobs: `BIND_ADDR`, `DNSSEC_KEY_MODE`, `RESIGN_INTERVAL_HOURS`,
`PROMETHEUS_LISTEN_ADDR`, `DNS_RATE_LIMIT_SLIP`, `MAXMIND_*` (update script). Back up `<zone dir>/dnssec-keys/` with the database.

---

## Phase 2 — implementation of the remaining scope (status per item)

Statuses: **COMPLETED** (implemented and tested) · **IMPLEMENTED — TEST PENDING** · **BLOCKED — STORAGE** ·
**BLOCKED — EXTERNAL DEPENDENCY** · **NOT COMPLETED**. "Lab" = `scripts/geodns_lab.sh` (real `hickory-dns` + `dig` in
network namespaces, 30 checks); "API tests" = `crates/control_api/src/api_tests.rs` against a real PostgreSQL.

### DNS core and GeoDNS
| Item | Status | Evidence / note |
|---|---|---|
| In-process hot reload (no restart) | **COMPLETED** | `SwapHandler` swaps the catalog; lab: new record served after reload, 0 failed queries in a continuous query loop, same PID, in-place reload logged. A broken zone file/config is rejected and the previous data keeps being served. A change to listeners/privileges/TLS still restarts the process (by design, logged). |
| Configurable IPv6 listener | **COMPLETED** | `LISTEN_ADDRS_IPV4` / `LISTEN_ADDRS_IPV6` env vars on the control API → `named.toml`; defaults unchanged (IPv4 only). API test for the generated config; lab verified the server answering over IPv6 transport (US/DE/unlisted IPv6 clients). |
| Geo rules no longer answer for non-existent names | **COMPLETED** | zone-wide rules apply only to names that exist (A/AAAA) in the zone file; explicit `record_name` rules unchanged. Lab: missing name → NXDOMAIN, existing name → geo answer; unit tests in `geodns` and `hickory-server`. |
| City and Region GeoDNS | **IMPLEMENTED — TEST PENDING** (+ BLOCKED — EXTERNAL) | `city` match type (`CC:City` or plain name), `region` (ISO 3166-2) and API validation implemented. Only `GeoLite2-Country` is available, so matching against real city/subdivision data could not be verified; tests prove they stay silent on a Country database. Needs a MaxMind licence key to obtain `GeoLite2-City` (≈ 65–80 MB). |
| GeoIP database update and reload | **COMPLETED** (reload) / **BLOCKED — EXTERNAL** (download) | The server watches the database file: a valid replacement is picked up in place, a corrupt file is rejected and logged while the previous data keeps serving (lab). An automatic *download* job needs the MaxMind licence key and is not implemented. |
| EDNS Client Subnet (opt-in per zone) | **COMPLETED** | `ecs_enabled` per zone (API + generated `ecs = true`). The catalog echoes the ECS option with scope = source prefix for ECS-enabled zones (RFC 7871), prefix 0 falls back to the resolver address, non-ECS zones ignore and do not echo it. Lab: 5 ECS checks. Privacy/caching: opt-in, answers are scoped to the received prefix. |
| Response correctness / compatibility | **COMPLETED** | Phase 1 fixes plus: address-family check, `dig` UDP/TCP/IPv4/IPv6 matrix, case-insensitive names, NXDOMAIN with SOA. |
| DNSSEC signing and DS management | **BLOCKED — STORAGE** | see "Deferred" below. |
| DNS query rate limiting | **COMPLETED** | per-source token bucket (IPv6 per /64), `DNS_RATE_LIMIT_QPS` / `DNS_RATE_LIMIT_BURST`, off by default; excess queries are dropped (no reflection). Lab: 120 parallel queries from one source → 23 answered, another source unaffected. Unit tests for key aggregation and burst. |

### Agents
| Item | Status | Evidence |
|---|---|---|
| Registration + authentication workflow | **COMPLETED** | admin registers → id, token and per-agent signing key shown once (also on rotate); agent crate rewritten (env-driven, no OpenSSL needed: rustls only). |
| Config synchronisation, signed + versioned bundles | **COMPLETED** | `GET /agents/{id}/bundle` (version = content hash changes, HMAC-SHA256 per-agent key, path-templated `named.toml`), agent verifies hash, signature and file names, stages and swaps atomically (zone files first, `named.toml` last), moves removed zones to `.orphaned/`. Unit tests (tamper, wrong key, replay of a changed version, path traversal, failed apply keeps old files) and `control_api`↔agent shared test vector. |
| Push | **COMPLETED** | `POST /config/push` flags one/all enabled agents; delivered in the next heartbeat answer, cleared by the acknowledgement (202). |
| Enable / disable | **COMPLETED** | `PUT /agents/{id}`; disabled agents are refused on heartbeat/bundle/ack. UI button wired. |
| Acknowledgements, health, sync status | **COMPLETED** | `applied_version`, `desired_version`, `in_sync`, `last_ack_at`, `last_error` (failed apply never advances the version), `last_seen_ip`; dashboard + agents page. |
| Multi-replica | **COMPLETED** (functional) | `scripts/agent_e2e.py` 6/6: first sync, falls behind after a change, converges, replica files contain the change, push acknowledged, wrong key refused and reported. |

### Control API and database
| Item | Status | Evidence |
|---|---|---|
| PostgreSQL connection pool | **COMPLETED** | `db_pool.rs`: N connections (`DB_POOL_SIZE`, default 8) + 1 reserved transaction connection, automatic reconnect; test kills all backends and the pool recovers. |
| Domain ownership verification | **COMPLETED** (logic) / **BLOCKED — EXTERNAL** (public DNS) | `VERIFY_DOMAINS=true`: non-admin zones start `pending` (not served), TXT challenge at `_outis-challenge.<domain>`, `POST /zones/{id}/verify`. Tested against a local fake resolver; a lookup against a real public resolver was not performed. NS-delegation proof is not implemented. |
| RBAC and zone sharing | **COMPLETED** | `zone_members` (viewer/editor); owner/admin/editor/viewer levels enforced in one function; API test covers read/write/owner-only operations for every role and immediate revocation; listings include shared zones and geo rules. |
| Query metrics and server health | **COMPLETED** (health) / **IMPLEMENTED — TEST PENDING** (query counters) | server status is a real TCP probe on `GET /servers` and `/servers/{id}/status`; `GET /dns/status` (last publication, failures, bundle version, DB pool). `GET /metrics/queries` scrapes `DNS_METRICS_URL`; tested against a fake exporter only (the DNS server's Prometheus feature was not run). |
| Pagination and retention | **COMPLETED** (audit) / **NOT COMPLETED** (other lists) | audit log: `limit/offset`, `action`/`user_id`/`resource_type`/`since` filters, `X-Total-Count`, retention job (`AUDIT_RETENTION_DAYS`, default 365). Zones/records/users APIs are still unpaginated (the UI paginates client-side). |
| Zone history and rollback | **COMPLETED** | revisions (max 50/zone) written on every change; restore in one DB transaction after re-validating, restore is itself recorded. |
| Authentication: MFA | **COMPLETED** | TOTP (RFC 6238 vectors), enrol/enable/disable (password + code to disable), login asks for the code; UI card + login step. |
| Proxy-aware client IP and rate limiting | **COMPLETED** | `TRUSTED_PROXIES`; right-most untrusted `X-Forwarded-For` entry from a trusted proxy only; per-username (10/min) and per-address (`LOGIN_RATE_PER_IP`, 60/min) login budgets; audit log records the real address. |
| SOA after rename | **COMPLETED** | stored SOA names rewritten on rename (API test + zone file check). |
| Authorization / tenant isolation review | **COMPLETED** | second pass: server list is now admin-only; metrics can require `METRICS_TOKEN`; every new endpoint is covered by cross-role tests. |

### Dashboard
All of the following are exercised by `web/ui/tests/audit_ui_regression.cjs` (**32/32 PASS** with a real browser against the real API):
agents (enable/disable/sync/credentials display), push page (agent picker, real result), dashboard (server health from real probes,
publication status, out-of-sync agents, query counter or an explicit "not configured"), audit page (correct columns — they were
rendering blank because of wrong field names — server-side paging and filters), zone Manage dialog (sharing, history/rollback,
verification), pending badge, MFA settings card and login step, read-only mode for viewer accounts and viewer-shared zones,
the login page no longer advertises `admin / admin123`, and the login form keeps its state during a sign-in (it used to be
unmounted by the global loading screen, which also made an MFA step impossible).
**Status: COMPLETED.** Not covered by browser tests: the nameserver/server CRUD pages and the GeoRules page beyond what Phase 1 tested.

### Security and operations
| Item | Status | Evidence |
|---|---|---|
| Remove insecure defaults / refuse placeholder secrets | **COMPLETED** | startup rejects placeholder JWT/DB/admin secrets, weak admin passwords and `FORCE_BOOTSTRAP` unless `ALLOW_INSECURE_DEFAULTS=true`; unit test. **Operational impact: see risks.** |
| CORS | **COMPLETED** | wildcard now warns, `X-Total-Count` exposed to browsers, defaults unchanged. (Rejecting `*` outright was judged too disruptive: tokens travel in a header, not cookies.) |
| Dependency vulnerabilities | **PARTIALLY COMPLETED** | see "Dependency review". |
| Publication monitoring / alerting | **COMPLETED** | Prometheus gauges (`outis_zones_failed`, `outis_last_publish_ok`, `outis_last_publish_timestamp_seconds`, `outis_bundle_version`, `outis_agents_out_of_sync`, `outis_db_connections_healthy`), `GET /dns/status`, dashboard banner, example rules `deploy/prometheus/outis-alerts.yml` (new file, not wired in). |
| Migration validation | **COMPLETED** | fresh schema (tests); legacy layout A = original `001`+`002` SQL incl. the seeded default admin; legacy layout B = tables as the original `migrate_db` created them incl. the unique constraint. Both upgraded in place: data preserved, `admin123` replaced, RRset constraint dropped, new tables/columns added, zones regenerated. |
| Logging / operational errors | **COMPLETED** | publication, auth, pool, reload and GeoIP failures are logged with context; secrets are never logged. |
| docker-compose GeoIP path | **COMPLETED** | the DNS server looked for `/etc/outiscloud/GeoLite2-Country.mmdb` but only `/etc/hickory` is mounted, so GeoIP was silently off in the compose deployment; now `/etc/hickory/GeoLite2-Country.mmdb`. |

### Dependency review
| Package | Finding | Action |
|---|---|---|
| axios 1.13.4 (13 advisories), form-data, lodash | HIGH | **upgraded** (axios → 1.21.1 within 1.x; transitive fixes via lock). Built and exercised by the 32 UI checks. |
| openssl 0.10.75 (5) | HIGH | **removed**: the agent no longer uses native TLS (rustls only), so it is no longer in the lock. |
| quinn-proto 0.11.13 (2) | HIGH | **0.11.15** (a newer patch drags in rand 0.10; avoided). Lock only: not compiled by any build here. |
| rustls-webpki 0.103.9 | HIGH | **0.103.16** in the lock. |
| aws-lc-sys 0.36 (5) | HIGH | lock updated (aws-lc-rs 1.19 / aws-lc-sys 0.47). **Not compiled** by any build on this host (feature not enabled) → IMPLEMENTED — TEST PENDING; first compile will build C code (≈0.5–0.8 GB). |
| postgres-protocol 0.6.10 | HIGH (a *malicious database server* can burn CPU via SCRAM iterations) | **NOT COMPLETED**: 0.6.12 pulls sha2 0.11 / hmac 0.13 / md-5 0.11 / rand 0.10 into the tree. Low exposure (you control the DB); take it with the next tokio-postgres upgrade. |
| rustls-webpki 0.101.7 | HIGH (panic on malformed CRL) | **NOT COMPLETED**: comes from reqwest 0.11 / rustls 0.21 in the agent; needs reqwest 0.12 (major). The agent configures no CRLs. |
| hickory-net / hickory-resolver 0.26.0-alpha.1 | HIGH | **BLOCKED — EXTERNAL**: these are the in-tree fork; the fixes (0.26.1 / 0.26.2) must be merged from upstream. |
| vite 5 / esbuild, react-router 6 | moderate/high (dev-server, open redirect) | **NOT COMPLETED**: fixes need vite 8 and react-router-dom 7 (majors); needs a migration. |

---

## A. Confirmed and working

| Area | Evidence (all locally verified) |
|---|---|
| Authoritative answers from the real server: SOA, NS (+ glue), A, AAAA, MX, TXT, NXDOMAIN with SOA in AUTHORITY, REFUSED for out-of-zone, case-insensitive names, AA flag | `dig` against `hickory-dns` in a network namespace |
| UDP and TCP on port 53 | same, `dig +tcp` |
| IPv4 and IPv6 *transport* (when the server is configured to listen on `::`) and IPv4/IPv6 *client* geolocation | `scripts/geodns_lab.sh` — 11/11 checks, run 3× |
| GeoDNS by **country**, **continent**, **default/fallback**, priority order, record-level rules, private/reserved/unlisted clients → fallback, IPv4-mapped IPv6 | real `GeoLite2-Country.mmdb` (build 2026-02-24); unit tests + live `dig` matrix: US→`.77`, DE→`.78` (country beats continent), LV→`.88` (EU), ZA/BR/private/unlisted→default |
| Control API: auth/session, users, zones, records, import/export, nameservers, georules, agents, audit | 17 DB-backed integration tests + live probes (request validation, auth, tenant isolation, conflict handling). `servers`, `dns/generate` and `dns/lookup` were exercised only by manual probes/UI, not by automated tests. |
| Atomic zone-file replacement, validation by Hickory's parser before replacement, last-known-good preserved | `one_broken_zone_never_blocks_or_replaces_others`, `failing_zone_keeps_last_known_good…`, `database_failure_never_wipes_published_zones` |
| Restart recovery | API restart with unchanged data leaves zone files byte-identical and triggers **0** DNS reloads; stale `*.tmp` files do not block publication |
| DNS keeps answering while the control plane/DB is down | PostgreSQL stopped; API exited (by design, see B-29); `dig` still answered |
| Crash-safe writes | temp file + `fsync` + rename + directory `fsync` (code) ; no partial files observed in 16-way concurrent write test |
| Dashboard flows | 16/16 Playwright checks (login error handling, dashboard honesty, zone create, NS display, CSV bulk import, audit page, tenant `/user` records route, viewer read-only) |

---

## B. Fixed issues

Format: **ID — problem** → root cause → fix → verification. "Live" = reproduced against the running stack *before*
the fix and re-run after.

### Authentication, sessions, accounts
- **B-1 — Built-in administrator `admin` / `admin123`** → hard-coded in `migrate_db` *and* seeded by `migrations/001_initial_schema.sql`; `POST /auth/login admin/admin123` returned **200** (live). With `ADMIN_USERNAME=admin` the bootstrap would see an existing argon2 hash and keep the default password (from the code, not exercised live). → Removed both seeds; bootstrap now replaces a password that still verifies as `admin123` with `ADMIN_PASSWORD`; startup logs an ERROR for any user still using it. → Live: now 401; test `session_lifecycle_and_no_default_credentials`.
- **B-2 — Sessions never worked** → login/logout inserted `String` params into `UUID` columns (Postgres "error serializing parameter"), so refresh tokens were never stored and logout never blacklisted anything; refresh also decoded a `timestamptz` as `String`. `POST /auth/refresh` always returned 401 (live), so the UI forced a re-login every 15 minutes. → proper casts, SQL-side expiry check; login fails loudly if the session row cannot be stored. → test `session_lifecycle…`.
- **B-3 — Revoked/deleted/demoted users kept access** → access tokens were never checked against the blacklist or the database. → `auth_middleware` rejects revoked tokens and deleted users and takes the **role from the database** on every request. → tests `deleted_user_and_demoted_admin_lose_access_immediately`, logout test (live: token after logout 200 → 401).
- **B-4 — Token digests used `DefaultHasher`** (64-bit, non-cryptographic, unstable across Rust versions) → SHA-256.
- **B-5 — No brute-force protection; user-enumeration by timing** → per-username limiter (10/min → 429 + `Retry-After`), constant-work dummy hash for unknown users. Live: 30 bad logins all processed before → 429 after 10. (See C-13/CP-07 for limits of this design.)
- **B-31 — Roles** → `create_user` ignored `role`; update applied username *or* role and accepted any string; the dashboard's "Viewer: read-only" was not enforced. → roles `admin/editor/viewer/user` validated; one atomic update; admins cannot demote themselves; **viewer is enforced read-only** (middleware) except logout/refresh/change-password. Test `roles_viewer_is_read_only…`.

### Multi-tenant isolation and input validation
- **B-6 — Cross-tenant reads** (any logged-in user): `GET /zones/{id}`, `/records`, `/export`, `/users/{id}`, `GET /georules` (all tenants), `POST /georules/resolve` → central `zone_access()` (admin or owner) on every zone route; georules list filtered by owner. Live: 200 → 403.
- **B-7 — Cross-tenant WRITE** — `POST /zones/{id}/import` had **no authorisation check**: any user could add records to any zone (live: bob imported `6.6.6.6` into alice's zone) → fixed with `zone_access()`; test `tenants_cannot_touch_each_others_zones` checks 13 operations.
- **B-8 — Zone owners were locked out of their own data** → `owner` (UUID) was read as `String`, always `None`, so non-admin owners got 403 on update/delete record and update/delete zone (live). → comparison through text in one helper.
- **B-9 — Namespace hijack** → a tenant could create a parent/child of another tenant's zone (`shop.alice.example`) → rejected (409) for non-admins.
- **B-10 — Injection into `named.toml`** → geo rule fields were pasted into TOML unescaped and not validated; a rule value of `US"\n[[zones]]\nzone="pwn"` produced a bogus extra zone in the server config (live; could take down the DNS server or add zones). → strict field validation (match types, ISO codes, target must be an IP) **and** TOML string escaping in the builder (defence in depth). Tests `georule_update_and_input_validation`, `toml_escape_neutralises_metacharacters`.
- **B-11 — Zone domain validation** → `.` (root zone!), `com`, upper-case duplicates (two zones, one file) were accepted; names fed file paths and TOML. → `normalize_zone_domain`: lower-case LDH labels, ≥2 labels, ≤253, stored canonical. Test `zone_domain_validation`.
- **B-12 — One record could break publication for every tenant** → `ttl: 4294967295` was validated as `i32::MAX` but stored as `-1`; zone generation then failed for **all** zones (live). → TTL 1…2³¹−1 enforced; plus B-19.
- **B-13 — Records outside the zone** (`www.victim.org.` in `alice.example`) accepted → rejected.
- **B-14 — NS allow-list only enforced on create** → enforced on update and import as well.
- **B-15 — `PUT /georules/{id}` returned 500 for `priority`/`enabled`** (bound as text to INT/BOOLEAN; live) → typed single-statement update.
- **B-16 — Non-atomic updates** → `update_record` updated column by column, discarded errors and returned success; `import` could stop half-way despite "fail-fast". → one validated statement; import is one `INSERT … unnest` after validating the whole resulting zone. Test `import_is_all_or_nothing…`.
- **B-17 — RRsets impossible** → `UNIQUE(zone_id,name,record_type)` (databases created by `migrate_db`) rejected the second NS/A/MX/TXT of a name (live log: "Failed to add default NS record"). → constraint dropped, exact-duplicate guard added (`uq_records_rrset_value`). **This is a schema change — see H for the review note.**

### Publication pipeline and reliability
- **B-18 — A transient DB error could erase every zone** → the generator used `unwrap_or_default()` on all queries; an empty result then "cleaned up" all `zone.*` files and wrote an empty `named.toml`. → every read propagates errors; nothing is touched on failure. Test `database_failure_never_wipes_published_zones`.
- **B-19 — One tenant's bad data blocked everyone** → the first invalid record aborted the whole run (live). → per-zone isolation: a failing zone keeps its last known-good file (and stays in `named.toml`), other zones publish; result reported per zone. Tests `one_broken_zone_never_blocks…`, `failing_zone_keeps_last_known_good…`, `brand_new_zone_that_fails_is_not_configured`.
- **B-20 — API said "success" before/without publication** → generation errors were only logged ("Still return success"). → mutations are pre-checked by rendering + parsing the *resulting* zone with Hickory **before** saving (400 with the reason); after saving, publication failure is returned (500, `saved`/`published` flags); creates and imports are rolled back if their zone cannot be published; a new zone that cannot be published is not kept.
- **B-21 — Race conditions** → concurrent regenerations interleaved and an older DB snapshot could overwrite a newer one (stale zone); `with_extension("zone.tmp")` made `zone.a.com` and `zone.a.net` share one temp file. → publish lock around read+write, safe temp names, DB reads done under the lock. Test `concurrent_writes_all_end_up_published` (16 parallel creates).
- **B-22 — SOA serial did not change** → serial was `YYYYMMDD00` fixed per day; edits within a day were invisible to secondaries and caches. → monotonic serial (`max(today00, previous+1)`), only bumped when content changes; unchanged regeneration neither rewrites files nor reloads the DNS server. Tests `soa_serial_*`.
- **B-23 — TXT records were corrupted on disk** → `v=spf1 mx -all` was written unquoted and served as three strings (`"v=spf1" "mx" "-all"`; live with `dig`), i.e. broken SPF/DMARC/DKIM. → TXT written quoted/escaped; **every record is parsed back and compared before publication** so any other non-round-tripping type is refused rather than served wrong. Tests `txt_*`.
- **B-24 — CNAME conflicts** (CNAME + other data, double CNAME, apex CNAME) → rejected at API and generator.
- **B-25 — Destructive/noisy file handling** → orphan zone files were `rm`'d (the protected `zone.uid0.ir` would be deleted if its zone were absent from the DB) → now moved to `.orphaned/`; `named.toml` is only rewritten when it changes (each rewrite makes the server restart); files and the directory are `fsync`'d.
- **B-26 — Nameserver/glue** → nameserver IP was unvalidated (a typo broke every zone) and IPv6 glue was emitted as `A`; SOA MNAME was a non-existent `ns1.<zone>`. → input validated (hostname FQDN, IP/IPv6), `AAAA` glue, MNAME = first enabled nameserver; changes report publication failure.
- **B-29 — API silently broken after a DB connection drop** → now exits so the supervisor restarts it.
- **B-30 — Audit log was always empty** → table existed, nothing wrote to it. → login/logout/failed login, user, zone, record, import, nameserver, georule, agent events are recorded.
- **B-34 — DNS wrapper** → each change cost a ≈3.2 s port-53 outage (the "reload requested" file it checks is never created, so it always slept 2 s) and SIGTERM was ignored. → clean exit restarts immediately (measured ≈1 s window), crash back-off kept, SIGTERM forwarded. Measured with a 1 s-timeout `dig` loop during an API write.

### GeoDNS
- **B-32 — GeoDNS never worked in the running server** → `GeoZoneHandler::search`, the method the catalog calls, returned `Skip` unconditionally, so rules were never evaluated: every client received the static record (live). → `search` now delegates to its `lookup`. Live matrix above.
- **B-33 — Engine/handler defects** → `record_name` rules like `www` never matched (the server compares FQDNs); an IPv4 target could be returned inside an AAAA RRset; `continent` was treated as a country code (never matched); tie-breaking depended on DB row order and random ids (replicas could disagree); IPv4-mapped IPv6 clients were not normalised. → fixed, deterministic ordering, `GeoDB::continent()/region()`.

### Dashboard
- **B-35 — Fabricated data and dead controls** → the "DNS Queries – last 24 h" chart plotted hard-coded numbers with a made-up "+12.5%"; Start/Stop buttons called `/api/v1/dns/start|stop` (do not exist) and every server showed "Inactive"; the record counter only counted the first 3 zones. → honest empty state, buttons removed, all zones counted.
- **B-36 — Other UI defects** → bulk import posted to `/records/bulk` (no such route; CSV priority unsupported); a wrong password cleared storage and showed "session expired"; nameservers never displayed because the response envelope was unwrapped twice; non-admin users could not open the records page (`/admin/...` only). Also `DELETE /agents/{id}` (called by the UI) did not exist → added. Verified by Playwright.
- **B-28 — Agents** → heartbeat looked up by `addr` with `query_one` (two agents sharing an address broke it), ignored `enabled`; `push-config` pretended to queue (B-27: now an honest **501**).

### Tests that were themselves broken
- **B-37** — 3 of 4 `geodns` unit tests failed on the original code (they expected country matches with no GeoIP database); the `hickory-server` GeoDNS unit tests did not compile, which broke `cargo test -p hickory-server`. Both were rewritten to use the real `GeoLite2-Country.mmdb`; no assertions were weakened — the old ones could not have passed honestly.

---

## C. Remaining issues

| ID | Issue |
|---|---|
| C-1 | `bin/tests/integration/zone_file_reload.rs` does not compile (imports `control_api` as a library, missing `tempfile`, outdated `hickory_net::Client` API). Pre-existing; superseded in practice by the lab reload checks but still broken. **NOT COMPLETED** |
| C-2 | Full-workspace test run (`proto`, `net`, `resolver`, `tests/integration-tests`, upstream crates) never fit on the disk. **BLOCKED — STORAGE** |
| C-3 | DNSSEC signing / DS management. **BLOCKED — STORAGE** (and needs a key-management design). |
| C-4 | Region/City matching verified only against "no data" (Country dataset). **BLOCKED — EXTERNAL** (licence for GeoLite2-City) |
| C-5 | Query counters verified against a fake exporter only. **IMPLEMENTED — TEST PENDING** |
| C-6 | Pagination exists for the audit log only. **NOT COMPLETED** for zones/records/users APIs. |
| C-7 | Rate limiting drops excess queries; there is no "slip" (occasional truncated reply) and no response-rate-limiting by response content. |
| C-8 | A zone-wide geo rule still replaces the static A/AAAA data of *existing* names for matching clients (by design, documented). |
| C-9 | Domain verification supports the TXT challenge only. |
| C-10 | Dependency items listed above as NOT COMPLETED / BLOCKED. |
| C-11 | Zone `ecs_enabled` is available in the API but has no toggle in the UI. **NOT COMPLETED** (UI) |
| C-12 | No performance/load testing was done (release builds do not fit on the disk). |
| C-13 | `schema_consistency_tests` in `main.rs` still assert on their own string literals (pre-existing); behaviour is covered by the DB-backed tests. |
| C-14 | Control-plane shared state is per instance: the login rate limiter and the publication lock are in-process, so several API replicas would each apply their own budget and would not serialise publication to a shared directory. |

---

## Deferred tasks — BLOCKED — STORAGE (host disk: 30 GB, 96–99 % used, shared with other services)

The disk had **58 MB free at its lowest point** during this phase, despite removing only disposable files this project created
(incremental-compile cache, superseded test executables, the Playwright browser and a scratch `node_modules`). No Docker data,
volumes or other projects' files were touched.

| Deferred task | Why it cannot run now | Estimated extra disk |
|---|---|---|
| DNSSEC signing + DS management | needs the `dnssec-ring`/`__dnssec` feature set of `hickory-proto`, `hickory-server` and `hickory-dns`: a full rebuild of the crypto stack and tests, plus key storage and new tests | 2–3 GB (debug build output) |
| Full `cargo test --workspace` | all upstream crates plus `tests/integration-tests`; the earlier attempt exhausted the disk | 6–9 GB |
| Compiling and testing the updated `aws-lc-sys` 0.47 / `quinn-proto` / `rustls-webpki` lock entries | first compile builds the C library and the QUIC/TLS stacks (needs the quic/tls features enabled) | 1–2 GB |
| Release-mode builds and DNS load/performance tests | optimised builds of the workspace | 3–4 GB |
| Re-running the browser tests | Playwright's Chromium + `npm ci` (these were removed to recover space) | ≈ 0.6 GB each time |
| Upgrading vite 5→8 / react-router 6→7 and re-testing the UI | new `node_modules` + migration work | ≈ 0.6 GB |
| Merging upstream Hickory fixes into the in-tree fork | large diff and rebuild | 3–5 GB (also needs a decision on the fork) |

Recommended minimum before resuming: **15 GB free** (20 GB to run everything in one go).

## D. Infrastructure-dependent issues / manual actions

| ID | Item | What is needed |
|---|---|---|
| D-1 | Delegation / glue at the parent (`.ir`): not testable here. | Registrar action by the domain owner. |
| D-2 | Public reachability, propagation, resolver compatibility, `dig +trace`, DNSSEC chain. Nothing was checked from the internet. Domain verification against a *real* public resolver. | Run from outside after deployment. |
| D-3 | GeoIP: shipped `GeoLite2-Country.mmdb` is dated 2026-02-24; City/region needs `GeoLite2-City`; automatic download needs a MaxMind licence key. | Licence key + update job (the server already reloads on file replacement). |
| D-4 | **Existing deployments must edit their configuration before upgrading**: `env/api.env` as committed contains placeholder secrets and `FORCE_BOOTSTRAP=true`; the API now refuses to start with them (set real values, or `ALLOW_INSECURE_DEFAULTS=true` for development only). | Operator. |
| D-5 | Real secrets, restrictive `ALLOWED_ORIGINS`, `TRUSTED_PROXIES` (set to the nginx/ingress range so audit logs and rate limits see real client addresses), `METRICS_TOKEN`. | Operator. |
| D-6 | PostgreSQL `max_connections` must allow `DB_POOL_SIZE + 1` connections per API instance (default 9). | Operator. |
| D-7 | Existing production databases: take a backup before the first start of the new version; the migrations are additive/idempotent (see below) but drop one constraint. | Operator. |
| D-8 | Agents: every agent needs `AGENT_ID`, `AGENT_TOKEN`, `AGENT_SIGNING_KEY`, `AGENT_ADDR` (shown once at registration). The previous placeholder agent will stop working. | Operator. |

## E. Security findings

Phase 1 findings (default admin, cross-tenant read/write, TOML injection, publication DoS, session defects, …) are fixed (section B).
Additional in this phase: login page advertised `admin/admin123` (removed); `GET /servers` exposed internal addresses to every
authenticated user (admin-only); `/metrics` unauthenticated (optional token); GeoIP corruption could silently disable geo (now rejected);
per-IP and proxy-aware login throttling; MFA available; viewer role enforced.

Open: dependency items above (vite/esbuild dev-server issue affects development only; react-router open-redirect via `<Link>` is
moderate and needs the v7 migration); no ownership proof unless `VERIFY_DOMAINS=true` (off by default for compatibility);
`ALLOWED_ORIGINS=*` is still accepted (warned); the in-process rate limiters are per replica (C-14).

## F. Test results (actual)

`CARGO_INCREMENTAL=0`; DB-backed tests use `TEST_DATABASE_URL` (throw-away PostgreSQL 16 container, removed afterwards).

| Command / suite | Result |
|---|---|
| `cargo test -p control_api` | **95 passed, 0 failed** (27 of them run against PostgreSQL: auth/session, tenant isolation, validation, publication safety, concurrency, agents, sharing, history, verification with a fake resolver, MFA, audit, status/health, metrics, pool recovery) |
| `cargo test -p geodns` | **15 passed** (real `GeoLite2-Country.mmdb`) |
| `cargo test -p hickory-server --lib` | **27 passed** (incl. swap handler, rate limiter keys, geo handler) |
| `cargo test -p hickory-dns --lib --bins` | **14 passed** |
| `cargo test -p control_agent` | **6 passed** (builds without OpenSSL) |
| `scripts/geodns_lab.sh target/debug/hickory-dns deploy/dns/GeoLite2-Country.mmdb` (root, netns) | **30/30 PASS** (geo by country/continent/default, IPv4+IPv6, TCP, existing-names-only, ECS, hot reload without outage, broken reload, GeoIP refresh and corrupt file, rate limit) |
| `scripts/agent_e2e.py` | **6/6 PASS** |
| `node web/ui/tests/audit_ui_regression.cjs` (Chromium, live API + Vite) | **32/32 PASS** |
| Legacy-schema upgrade (A: original `001`+`002` SQL; B: original `migrate_db` tables), manual | both upgraded in place; verified default-password replacement, data kept, RRset insert works, zone regenerated |
| `vite build` | builds (axios upgraded) |
| `cargo test -p hickory-dns` integration target | still does not compile (C-1) |
| Not run | whole-workspace tests (C-2), performance tests, anything against the public internet, GeoIP city/region on real data |

## G. Proposed features — implementation status

`PROPOSED_FEATURES.md` carries the same status per proposal: DNS-01 hot reload **COMPLETED**; DNS-02 IPv6 **COMPLETED**;
DNS-03 existing-names-only **COMPLETED**; DNS-04 City/region + update **IMPLEMENTED — TEST PENDING / BLOCKED — EXTERNAL**;
DNS-05 ECS **COMPLETED**; DNS-06 DNSSEC **BLOCKED — STORAGE**; DNS-07 agent protocol **COMPLETED**;
CP-01 pool **COMPLETED**; CP-02 verification **COMPLETED (logic) / BLOCKED — EXTERNAL (public DNS)**; CP-03 RBAC/sharing **COMPLETED**;
CP-04 metrics/health **COMPLETED / IMPLEMENTED — TEST PENDING (query counters)**; CP-05 pagination **COMPLETED (audit) / NOT COMPLETED (other lists)**;
CP-06 history/rollback **COMPLETED**; CP-07 auth hardening **COMPLETED**; CP-08 agent toggle **COMPLETED**;
OPS-01 secret hygiene **COMPLETED**; OPS-02 dependencies **PARTIALLY COMPLETED**; OPS-03 publication metrics **COMPLETED**.

## H. Modified files, migrations, compatibility and operational risks

**Database changes (all idempotent, run by the API at start; no data is deleted):** `zones.status/verify_token/verified_at/ecs_enabled`;
tables `zone_members`, `zone_revisions`, `publish_state`; `users.totp_secret/totp_enabled`; `agents.applied_version/last_ack_at/last_error/sync_requested/last_seen_ip`;
the legacy `UNIQUE(zone_id,name,record_type)` constraint is dropped and `uq_records_rrset_value` (exact-duplicate guard) is created
(creation is non-fatal if legacy duplicates exist). `migrations/001_initial_schema.sql` no longer seeds `admin/admin123`. There is no automatic down-migration.

**New configuration (all optional unless noted):** `ALLOW_INSECURE_DEFAULTS`, `DB_POOL_SIZE`, `TRUSTED_PROXIES`, `LOGIN_RATE_PER_IP`, `VERIFY_DOMAINS`,
`DNS_VERIFY_RESOLVER`, `DNS_METRICS_URL`, `METRICS_TOKEN`, `AUDIT_RETENTION_DAYS`, `LISTEN_ADDRS_IPV4`, `LISTEN_ADDRS_IPV6` (control API);
`DNS_RATE_LIMIT_QPS`, `DNS_RATE_LIMIT_BURST`, `GEOIP_DB_PATH` (DNS server); `CONTROL_API`, `AGENT_ID`, `AGENT_TOKEN`, `AGENT_SIGNING_KEY`, `AGENT_ADDR`, `AGENT_NAME`, `AGENT_ZONE_DIR`, `HEARTBEAT_SECS` (agent).

**API changes (additive unless noted):** new routes for members, revisions, verification, MFA, agent enable/bundle/ack, `dns/status`, `servers/{id}/status`, `metrics/queries`;
`POST /config/push` now answers 202 (was a fake 200 / earlier 501); `GET /servers` is admin-only (**behaviour change**); `GET /audit/logs` accepts paging/filter parameters (default unchanged);
zones carry `status`, `access`, `ecs_enabled`; login accepts `otp`; register/rotate return `signing_key`.

**Files changed (34 tracked + 13 new):** `Cargo.lock`; `bin/hickory-wrapper.sh`, `bin/src/{lib,config/mod}.rs`; `crates/agent/*`; `crates/control_api/{Cargo.toml,migrations/001…,src/*}` (new: `db_pool.rs`, `ext.rs`, `metrics.rs`, `api_tests.rs`);
`crates/geodns/src/lib.rs`; `crates/server/{Cargo.toml,src/zone_handler/{catalog,geodns,mod}.rs}` (new: `swap.rs`); `docker-compose.yml` (GeoIP path only);
`web/ui/{package.json,package-lock.json,src/**}` (new: `ZoneTools.jsx`, `MfaCard.jsx`); new `deploy/prometheus/outis-alerts.yml`, `scripts/{geodns_lab.sh,agent_e2e.py}`, `web/ui/tests/audit_ui_regression.cjs`, `AUDIT_REPORT.md`, `PROPOSED_FEATURES.md`. Nothing under `helm/`, nothing else under `deploy/`, no image locks, no `node_modules` of the repo.

**Risks to review before deploying:**
1. The API refuses to start with the committed placeholder `env/api.env` (D-4) — intended, but it is an outage if nobody edits it.
2. `viewer` accounts are now truly read-only; the UI's default role for new users is *viewer*.
3. `GET /servers` is admin-only; any external client using it as a non-admin will get 403.
4. The DNS server now reloads in place; a listener/TLS/privilege change still restarts it. Reload requires working inotify in the container.
5. Connection pool size × replicas must fit `max_connections` (D-6).
6. Login/rate limits and the publication lock are per API instance (C-14): run one API instance per zone directory.
7. The unique-constraint drop changes how duplicates are detected (exact duplicates only).
8. The agent is a different program with a different contract; roll it out together with the new control API.
9. Lockfile bumps for aws-lc/quinn/webpki were not compiled here (C: deferred).

## I. Overall project status

The control plane, dashboard, agents and DNS data plane now implement everything that could be built and verified with the
available disk, with tests at every layer and live DNS checks. What stands between this and a production-ready release is
(1) the deferred storage-bound work (DNSSEC, full-workspace tests, dependency re-validation, performance tests),
(2) external verification (public delegation, real resolvers, City dataset, licence-backed GeoIP refresh), and
(3) the operator actions in D-4…D-8, in particular replacing the placeholder secrets before the first start of this version.
