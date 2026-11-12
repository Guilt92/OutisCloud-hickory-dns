# OutisCloud Hickory DNS — Audit Report

Scope: Hickory DNS core as used by the project, the custom Control API (`crates/control_api`), the GeoDNS crate and
server handler, the zone publication pipeline, the agent, the web dashboard (`web/ui`) and deployment files.
Work was done on branch `main`; changes are committed locally (see Phase 5 for exact commits); **nothing was pushed.** `helm/`, `deploy/` (including
`deploy/dns/zone.uid0.ir`, which is not present in this checkout), image/tag locks and any existing `node_modules`
were not touched.

**How things were verified.** A throw-away PostgreSQL 16 container (`outis-audit-pg`, removed afterwards), the real
`control_api` binary, the real `hickory-dns` binary and `dig` were run together; GeoDNS was exercised from client
addresses that exist only inside private network namespaces (host network untouched); the dashboard was driven with a
real headless Chromium. No part of this was verified against public DNS — see section D.

Legend: *Locally verified* = reproduced/verified on this machine. *Externally verified* = checked against the public
internet. **Nothing in this report is externally verified.**

---

## Phase 6 — Final development phase (2026-11-12): DNS Lookup, tenants/quotas, analytics, overview, security, tests, upstream analysis

Everything below was implemented and **run locally**; nothing was committed or pushed and nothing was checked against the public internet. Status words follow the earlier legend.
Where this section disagrees with Phase 5 ("Remaining bugs / features"), this section is authoritative.

### 6.1 Requested item → outcome

| # | Request | Status | Evidence (actual results) |
|---|---|---|---|
| 1 | DNS Lookup with real queries for all advertised types | **COMPLETED AND VERIFIED** (local) | `crates/control_api/src/lookup.rs`: wire-protocol client (UDP + EDNS0, TCP retry on truncation, off-path-spoof filter, transaction-id check). All **12** types advertised in the UI are really answered: A AAAA MX TXT NS CNAME SOA SRV PTR DNSKEY DS CAA. Response code, AA flag, TTLs, authority SOA, elapsed time, resolver and transport are returned as received; NXDOMAIN, NODATA, REFUSED and resolver failure (502) are reported as such, never as fake empty successes. PTR accepts an IP address and builds the `in-addr.arpa`/`ip6.arpa` name. Unit tests 4/4; API tests (fake UDP+TCP resolver, every type, TTLs, NXDOMAIN, NODATA, TCP fallback, validation, authz, rate limit, unreachable resolver) pass; **`scripts/lookup_lab.sh` 22/22** against the real `hickory-dns` server, every type cross-checked with `dig`; **browser: all 12 types + NXDOMAIN + NODATA + empty input** (`platform_qa.cjs`). |
| 2 | Security fixes (lookup authz + rate limit, `GET /nameservers`, RBAC, tenant isolation, other endpoints) | **COMPLETED AND VERIFIED** (local) | See 6.5. All 77 routes were reviewed one by one; 4 defects fixed. |
| 3 | Dashboard performance (N+1) | **COMPLETED AND VERIFIED** (local) | New `GET /api/v1/overview[?limit=]`: one tenant-scoped query with exact record counts, per-type breakdown and quota usage. Admin and customer overview pages send **zero** per-zone `/records` requests (asserted in the browser). With **5,007 zones / 40,038 records**: admin overview API **610–1,061 ms**, page renders in **776–1,151 ms** (two runs); a customer with 2 zones among those 5,007 gets **149–175 ms** (the same query took 750 ms before the indexed rewrite). API test with 3,003 zones asserts < 3 s / < 0.5 s. |
| 4 | Tenant-aware persistent analytics | **COMPLETED AND VERIFIED** (local) — needs `DNS_ZONE_QUERY_METRICS=true` on the DNS server | The DNS server did **not** provide per-zone counters (the existing `zone_handler` label is a static store label), so the required architecture change was made instead of inventing numbers: `hickory_zone_queries_total{zone,result}` in `Catalog::lookup` (opt-in; one time series per zone and result). The control API collector (`ANALYTICS_SAMPLE_SECS`, default 60) stores deltas in PostgreSQL (`analytics_samples`, `zone_query_samples`, `tenant_usage_samples`), handles counter resets and API restarts, retention `ANALYTICS_RETENTION_DAYS` (default 90). `GET /analytics/global` (admin) and `GET /analytics/tenant?range&tenant_id&zone` (customers only their tenant); UI: range 1h–90d, tenant and zone filters, queries/failed over time, top zones, zones/records usage over time. **`scripts/tenant_analytics_lab.sh` 9/9**: real server, known traffic via `dig` → exactly 40 queries for alice, 7 for carol, 47 for the admin view, unattributed REFUSED queries only in the global counter, history survives an API restart. |
| 5 | Tenant entity and quotas | **COMPLETED AND VERIFIED** (local) | `tenants`, `tenant_members` (owner/editor/viewer), `zones.tenant_id`; zone access via owner, sharing **or** tenant role; quotas on zones and records enforced for create zone, create record, import and revision restore (admins are exempt); tenant CRUD, members, zone reassignment API; admin "Tenants & Quotas" page; quota card on the customer overview. **Non-destructive backfill**: every non-admin user gets a personal (unlimited) tenant owning their existing zones; verified idempotent. |
| 6 | Hickory upstream fork | **ANALYSED + TRIAL MERGE TESTED — REQUIRES MY DECISION** | See 6.7. Real merge base found; merge of `v0.26.3` has 8 conflicting files; conflicts resolved in an isolated scratch tree; merged tree compiles (proto, server, bin), `hickory-dns` lib 19/19 and `geodns` 18/18 pass, and the **geodns lab passes 32/32 against a binary built from the merged tree**. 44 mechanical API-rename errors remain in `control_api` (+2 in server test code). The production tree was not changed. |
| 7 | Test coverage (Nameservers, Servers, GeoRules, bulk import, lookup, analytics, tenant isolation, quotas, authorization, dashboard performance, accessibility, visual) | **COMPLETED AND VERIFIED** (local) | See 6.3. |
| 8 | Repository cleanup | **COMPLETED** | See 6.8: 9 tracked files + 1 untracked file inspected, classified and removed (all recoverable from git). |
| 9 | Git restrictions | **Kept** | No commit, no push, no reset/clean. Working tree contains all changes uncommitted. |

### 6.2 Implemented changes (files)

| Area | Files |
|---|---|
| DNS Lookup | `crates/control_api/src/lookup.rs` (new), `main.rs` (`dns_lookup`, viewer allow-list), `web/ui/src/pages/Admin/DnsLookup.jsx` (status badge, TTL, resolver/transport/elapsed, authority section, NODATA/NXDOMAIN/502/429 messages, labelled controls), `scripts/lookup_lab.sh` (new) |
| Tenants / quotas / overview / analytics | `crates/control_api/src/tenants.rs` (new: schema + backfill, quota checks, tenant/member/zone-move API, `/overview`, collector, `/analytics/*`), `main.rs` (zone access via tenant role, `list_zones`/`list_georules` visibility, `create_zone` tenant+quota, `create_record`/`import_zone` quota, nameserver listing, collector start), `ext.rs` (`server_status` admin-only, restore quota, `http_get` public), `crates/server/src/zone_handler/catalog.rs` (per-zone query counter) |
| UI | `pages/Admin/Tenants.jsx`, `pages/UserAnalytics.jsx`, `components/AnalyticsHistory.jsx`, `components/Quota.jsx`, `api/errors.js` (new); `Dashboard.jsx`, `User.jsx`, `Analytics.jsx`, `Layout.jsx`, `App.jsx`, `Zones.jsx`, `Records.jsx`, `BulkImport.jsx`, `GeoRules.jsx` (City match type), `Servers.jsx`, `Nameservers.jsx`, `Users.jsx`, `AuditLogs.jsx`, `ConfigPush.jsx`, `Settings.jsx`, `PasswordChangeForm.jsx`, `index.css` (accessibility fixes) |
| DNS server | `crates/server/src/zone_handler/catalog.rs` (`DNS_ZONE_QUERY_METRICS`), `bin/src/lib.rs` (a watch that cannot be installed is now logged as an error instead of silently disabling hot reload) |
| Tests / harness | `crates/control_api/src/api_tests.rs` (+8 tests), `scripts/{lookup_lab,tenant_analytics_lab,ui_stack}.sh`, `web/ui/tests/{platform_qa,a11y_visual_qa}.cjs`, `web/ui/tests/visual-baseline/` (32 PNG baselines, 2.4 MB) |

### 6.3 Tests and actual results

| Suite | Result |
|---|---|
| `cargo test -p control_api` (PostgreSQL 16, 115 tests incl. 12 new: lookup 4 unit + 2 API, nameserver/server-status authz, legacy→tenant migration, tenant isolation + quotas (zones, records, import, restore), tenant roles/membership, overview accuracy + scale, analytics isolation/retention) | **115 passed, 0 failed** (inside the workspace run; 12 of them new) |
| `cargo test --workspace` | **874 passed, 0 failed, 27 ignored** in 28 test binaries (previous full run: 862 / 0 / 26; the 27 ignored tests are all upstream tests that need the network or are marked ignored upstream/with a reason) |
| `scripts/lookup_lab.sh` (real API + real DNS server, `dig` cross-check) | **22/22 PASS** |
| `scripts/tenant_analytics_lab.sh` (real per-zone counters → tenant history) | **9/9 PASS** |
| `scripts/geodns_lab.sh` (current binary) | **32/32 PASS** |
| `scripts/geodns_lab.sh` (binary built from the **trial merge** with upstream v0.26.3) | **32/32 PASS** |
| `web/ui/tests/platform_qa.cjs` (final run on the production bundle; Nameservers, Servers, GeoRules incl. City, bulk import incl. fail-fast, lookup ×12 + NXDOMAIN/NODATA/empty, tenants CRUD/members/quota edit, quota refusal message, isolation, authorization, analytics admin+customer+filters, zero-N+1, 5,000-zone performance) | **66/66 PASS** |
| `web/ui/tests/a11y_visual_qa.cjs a11y` (axe-core, WCAG 2.0/2.1 A+AA, 19 routes + login, dark/light, desktop+mobile subset) | **0 violations** (first run found 105 unlabeled buttons, 15 unlabeled form controls, 75 low-contrast nodes, 5 non-focusable scroll regions — all fixed) |
| `a11y_visual_qa.cjs visual compare` (32 baselines: 8 deterministic pages × dark/light × desktop/mobile, pixelmatch, 0.2 % tolerance) | **32/32 PASS**; `visual selftest` proves a deliberate style change (1.24 %) is detected |
| `web/ui/tests/redesign_qa.cjs` (all routes × roles × themes × viewports) | **165/165 PASS** (sidebar expectation updated 12 → 13 for the new Tenants entry) |
| `web/ui/tests/audit_ui_regression.cjs` | **50/50 PASS** (production bundle via `vite preview`, API without `DNS_METRICS_URL`; two fixed 1.5 s waits were replaced by waiting for the alert / OTP field because debug-build Argon2 logins can take longer) |
| `npm run build` (Vite 8) | builds; the final browser runs (platform 66/66, a11y 0 violations, visual 32/32, audit_ui 50/50) used this production bundle |

### 6.4 Database migrations (all idempotent, additive, run at API start)

`tenants` (id, name unique, max_zones, max_records, created_at) · `tenant_members` (tenant_id, user_id, role owner/editor/viewer) · `zones.tenant_id` (nullable FK, `ON DELETE SET NULL`) + indexes `idx_zones_tenant`, `idx_zones_owner`, `idx_tenant_members_user` ·
`analytics_samples`, `zone_query_samples` (domain-keyed, **no foreign key**, so history survives zone deletion), `tenant_usage_samples` ·
**backfill**: personal tenant `personal-<username>` (deterministic UUID, unlimited quotas) for every non-admin user without membership, membership `owner`, and `zones.tenant_id` set for zones those users own. Admin-owned zones stay tenant-less (platform zones). Nothing is dropped or rewritten in `users`/`zones`/`records`; re-running changes nothing (test). Back up the database before the first start as with every release (no automatic down-migration).

### 6.5 Security improvements

| Finding | Fix |
|---|---|
| `POST /dns/lookup` used the host OS resolver for any name for any logged-in user, unthrottled | real queries to one configured resolver (`DNS_VERIFY_RESOLVER`), per-account fixed window `DNS_LOOKUP_RATE_PER_MIN` (default 30) → 429 + `Retry-After`; the lookup target is a DNS name only (no connection is made to the name, so it cannot be used to probe internal hosts) |
| `GET /nameservers` readable by any user, including disabled/internal entries | customers get enabled entries only (they need them to delegate); admins everything; writes remain admin-only (tested) |
| `GET /servers/{id}/status` let any user make the control plane open TCP connections to registered servers | admin only |
| Read-only (`viewer`) accounts were blocked from the harmless lookup tool **and from enrolling MFA** (all POSTs refused) | allow-list extended to `dns/lookup` and `auth/mfa/*` (tested) |
| Tenant isolation | zone visibility and access derive from owner / sharing / tenant role in one code path; verified for zones, records, georules, overview, analytics, tenant members, zone move; customers cannot raise their own quota, create zones in another tenant or move zones |
| Quota bypass via import / revision restore | both enforced |
| Silent loss of hot reload when the server user cannot traverse the zone path | now logged as an error at startup |
| All 77 routes reviewed for authentication and role/ownership checks (table generated from the router) | no other gap found; agent endpoints authenticate with their own token/signature |

### 6.6 Performance improvements

Overview: N+1 → one request (see 6.1; customer overview 750 ms → 175 ms after replacing text-cast visibility predicates with indexed UUID lookups; index `idx_zones_owner` added). Zone listing uses the same indexed predicate. Collector overhead: one HTTP scrape per `ANALYTICS_SAMPLE_SECS` plus ≤ one small upsert per active zone.

### 6.7 Hickory upstream fork — analysis and strategy

* **Real merge base**: upstream `db923c34` (2026-01-26, "replace ResponseSigner w/ TSigResponseContext"). The fork has **57 commits** since then; upstream `main` has **811** (proto 187, server 136, resolver 163, net 220, bin 56); release `v0.26.3` is a separate backport line (+362 commits from the base) that carries the advisory fixes.
* **OutisCloud-specific DNS modifications** (everything else is new crates): `crates/server/src/zone_handler/{swap.rs, geodns.rs}` (new), `catalog.rs` (ECS echo, DS-from-parent, per-zone counter), `mod.rs`, `store/in_memory/mod.rs` (NXDOMAIN O(log n) fix), `bin/src/lib.rs` (+205 lines: hot reload, rate limit/slip, privilege-drop fallback, watchers), `bin/src/config/*`, `crates/proto` (`message.rs` allocation cap, `zone_lex.rs` token cap, `zone.rs` SOA TTL), `crates/geodns` (new), `crates/control_api`, `crates/agent` (new).
* **Overlap with upstream changes**: 22 files changed on both sides. **`main`**: 11 conflicting files (Catalog::lookup was refactored: `Request`/`ResponseHandle` removed, `Metadata`, `DecodeError`) — a re-implementation of ECS/DS/metrics hooks against the new API. **`v0.26.3`**: **8** conflicting files, mostly trivial (Cargo.toml/lock, 2 test files, conformance helper) plus 3 real hunks (`bin/src/lib.rs` imports + privilege-drop flag, `catalog.rs` imports, `message.rs` where upstream already contains our allocation cap for records).
* **Trial (isolated scratch tree, production untouched)**: merged `v0.26.3` + fork, resolved the 8 conflicts, adapted 3 call sites in our handlers (`request.edns` is now a field; `Header` → `Metadata`; `ResponseInfo::from(Header{..})`). Result: `hickory-proto`, `hickory-server`, `hickory-dns` **compile**; `hickory-dns` lib tests 19/19, `geodns` 18/18; **`geodns_lab.sh` 32/32 with the merged binary** (hot reload, ECS, rate limit/slip, GeoIP refresh all intact). Not yet adapted: `control_api` (44 mechanical errors: accessor methods became public fields — `Record::data()/ttl()`, `Message::id()/response_code()`, `SOA::serial()`…, `RDataParser` import) and two test helpers in `hickory-server` tests.
* **Recommended strategy**: (1) merge **v0.26.3**, not `main`, into a branch; (2) resolve the 8 files as in the trial; (3) mechanically port `control_api` (44 edits) and server tests; (4) run `cargo test --workspace` and all labs (geodns 32, city 8, dnssec 30, metrics 6, lookup 22, tenant analytics 9, agent e2e 6); (5) only then consider `main` as a second, separate step because it needs the `Catalog::lookup` re-implementation. **Not applied** to the production tree: it needs your decision (6.10).

### 6.8 Repository cleanup (inspected first; removed only when confirmed safe)

| File | Classification | Evidence | Action |
|---|---|---|---|
| `web/ui/debug_admin.png` | generated | written by `tests/debug_admin.spec.cjs`; referenced nowhere else | removed |
| `web/ui/tests/debug*.spec.cjs` (6) | obsolete | ad-hoc debugging scripts that hard-code the removed `admin/admin123` login and ports 3000/8080; not referenced by CI or `package.json`; real suites are `e2e.*`, `audit_ui_regression`, `redesign_qa`, `platform_qa` | removed |
| `web/ui/test-results/.last-run.json` | generated | Playwright state of a failed February run | removed |
| `web/ui/src/pages/Admin.jsx` (user wrote `web/ui/pages/Admin.jsx`) | obsolete | wrapper from before the router; imported nowhere; Vite bundles only imported modules; build passes without it | removed |
| `tests/test-data/test_configs/example.com_dnssec_update_2.jrnl` (user wrote `update2`) | generated | SQLite journal written by upstream test `named_metrics_tests.rs:586` on every run; not tracked | removed (the test recreates it) |

All tracked removals are recoverable with `git checkout -- <path>`. `target/debug/deps` also had ~5 GB of superseded test executables older than 3 hours (safe, regenerated on demand) — removed to keep the disk usable.

### 6.9 Remaining limitations (honest list)

1. **Per-tenant query analytics requires `DNS_ZONE_QUERY_METRICS=true`** on the DNS server (one Prometheus time series per zone and result — fine for thousands of zones, review before 100 k+). Queries that match no zone (REFUSED) are only visible in the global counter. Per-record-type/per-country breakdowns are not collected.
2. Quota checks are check-then-insert: two simultaneous requests can overshoot a quota by the concurrency level (no row lock). The two NS records created automatically with a zone count towards the record quota but are not blocked by it.
3. Admin UI has no zone→tenant reassignment screen (API `PUT /zones/{id}/tenant` exists); `tenant_id` can be set when an admin creates a zone through the API.
4. DNS Lookup queries one resolver (`DNS_VERIFY_RESOLVER`, default 1.1.1.1:53 — **set an internal resolver in production**); it does not request DNSSEC validation (no DO/AD display) and no `ANY`/`AXFR`.
5. Rate limits (login, lookup) and the analytics collector are per API instance; running several API replicas would collect duplicates (use one collector instance, or set `ANALYTICS_SAMPLE_SECS=0` on the others).
6. Visual baselines were produced on this Chromium build/fonts (system fallback fonts offline); re-baseline (`visual update`) after font or browser changes.
7. Backend suites in the browser harness run against a **debug** build; absolute timings (610–1,061 ms / 149–175 ms) will be lower in release.
8. Not externally verified: public DNS, registrar delegation, MaxMind GeoLite2-City, behaviour on a real production database copy.
9. Upstream merge not applied (6.7). `main`-line upstream changes are not evaluated beyond conflict counting.
10. Pre-existing: 26 upstream tests remain `#[ignore]`d; `named_metrics_tests::test_updates` is ignored with a reason (fork never emitted that metric).

### 6.10 Decisions still requiring your approval

1. **Merge upstream `v0.26.3`** onto a branch (recommended, ~half a day: 8 conflict files + 44 mechanical edits + full test/lab run), and whether to follow with `main`.
2. **Default quotas for newly created personal tenants** (`DEFAULT_TENANT_MAX_ZONES` / `DEFAULT_TENANT_MAX_RECORDS`; unset = unlimited, which is what migrated tenants got).
3. **Enable `DNS_ZONE_QUERY_METRICS=true` in production** (cardinality trade-off above) and point `DNS_METRICS_URL` at the DNS server.
4. **Resolver for DNS Lookup** (`DNS_VERIFY_RESOLVER`).
5. Whether to **commit** this work (and in how many commits) and whether/when to **push**; nothing has been committed or pushed.
6. Whether to keep `web/ui/tests/visual-baseline/` (2.4 MB of PNG) in the repository or generate it in CI.

### 6.11 New configuration

`DNS_LOOKUP_RATE_PER_MIN` (30), `DEFAULT_TENANT_MAX_ZONES`, `DEFAULT_TENANT_MAX_RECORDS`, `ANALYTICS_SAMPLE_SECS` (60, `0` = off), `ANALYTICS_RETENTION_DAYS` (90) — control API; `DNS_ZONE_QUERY_METRICS` (off) — DNS server. Test-only: `CHROMIUM_PATH`, `NO_METRICS` (stack script).


### 6.12 Phase 5 findings — resolution

| Phase 5 finding | Now |
|---|---|
| DNS Lookup offered types the backend could not answer | **fixed** (all 12 real) |
| `POST /dns/lookup`, `GET /nameservers` too permissive; no lookup rate limit | **fixed** |
| Admin/customer overview: one `/records` request per zone | **fixed** (`/overview`) |
| Analytics without history; no per-tenant data; no tenant entity or quotas | **fixed** (needs `DNS_ZONE_QUERY_METRICS`); tenants + quotas implemented |
| Settings: unused imports | **fixed** (the page still has no notification settings — none are implemented, none are advertised) |
| Dead/legacy files (`Admin.jsx`, debug specs, `debug_admin.png`, `.last-run.json`, `.jrnl`) | **removed** after inspection |
| No browser CRUD tests for Nameservers, Servers, GeoRules, bulk import; no a11y/visual tests; analytics rate maths untested | **added** (analytics is now server-side and tested with exact counts instead of a browser-side rate) |
| GeoRules page could not create `city` rules although the backend supports them | **fixed** (City match type) |
| Icon-only buttons, selects and inputs without accessible names; low-contrast text; non-focusable scroll regions | **fixed** (axe: 0 violations) |
| Viewer accounts could not use the lookup tool or enrol MFA | **fixed** |
| `GET /servers/{id}/status` open to every user | **fixed** (admin only) |
| Fonts from Google Fonts CDN; CSP headers | still open |
| Servers edit-in-place, user suspend, audit export, bulk zone actions, record multi-select, API tokens, account lifecycle | still open (NOT IMPLEMENTED, see PROPOSED_FEATURES.md) |
| Per-replica rate limits / collector; no persisted alert wiring | still open |

### 6.13 Final status table

| Item | Status |
|---|---|
| DNS Lookup (12 types), authorization, rate limit | COMPLETED AND VERIFIED (local) |
| Overview aggregation endpoint + both overview pages | COMPLETED AND VERIFIED (local) |
| Tenants, membership, quotas (zones, records), backfill migration | COMPLETED AND VERIFIED (local) |
| Persistent tenant-aware analytics (with `DNS_ZONE_QUERY_METRICS`) | COMPLETED AND VERIFIED (local) |
| Browser, accessibility, visual suites | COMPLETED AND VERIFIED (local) |
| Repository cleanup | COMPLETED |
| Upstream Hickory v0.26.3 merge | PARTIALLY IMPLEMENTED (trial only) — REQUIRES MY DECISION |
| Zone→tenant reassignment screen, quota row-locking, per-type analytics | NOT IMPLEMENTED |
| Production verification (public DNS, registrar, GeoLite2-City, production data copy) | BLOCKED BY EXTERNAL DEPENDENCY |
| Commit / push | NOT DONE (by instruction) — REQUIRES MY DECISION |

---

## Phase 5 — Complete implementation status report (inspection only, 2026-11-12)

Phase 6 (above) supersedes this section where they disagree. This section is **authoritative** otherwise and supersedes the older header note ("nothing was committed"), section C, the "Deferred tasks — BLOCKED — STORAGE"
table, section F and parts of Phase 2 wherever they disagree. It was produced by inspection only: no source was changed, nothing was committed, pushed or deleted
(except that, at the user's request, `target/debug/incremental` and `target/debug/examples` were removed to free ~10 GB; disk is now 46 GB used / 11 GB free).
"Tested" below means a test that was **actually run and passed locally**; nothing is externally verified (no public DNS, registrar, or licensed GeoLite2-City).

### 5.1 Repository and commit verification

| Check | Result |
|---|---|
| Branch | `main`, **ahead of `origin/main` by 5 commits** (`591a819da` "revi" was already local before this work) |
| Latest commits | `6ca461f86` docs · `7a7fa19c7` feat(ui) redesign · `9caebbe3a` docs · `0b4e6c0f8` feat(ui) pagination/ECS/DNSSEC/Vite 8 · `7b2147aa2` feat backend |
| Working tree | clean except 1 untracked file: `tests/test-data/test_configs/example.com_dnssec_update_2.jrnl` (SQLite journal written by an upstream workspace test; not mine to delete, not committed). Nothing staged. |
| Pushed? | **No.** No `git push` was ever run. |
| `7a7fa19c7` | 37 files, +1525/−1488, only `web/ui/**` (App, Layout, ui.jsx, pages, index.css, tailwind config, index.html, favicon, 2 test files). No backend, `helm/`, `deploy/` or lock-file change. |
| `6ca461f86` | `AUDIT_REPORT.md` only (+17 lines). |
| Do the reported UI test results match the current code? | `web/ui/src`, `tailwind.config.js` and `index.html` are **byte-identical** (`diff -rq`) to the scratch copy from which `redesign_qa.cjs` (165/165) and `audit_ui_regression.cjs` (50/50) were built and run. So yes for the UI. The backend test totals (862/0/26, labs) were produced on the backend as committed in `7b2147aa2`; the redesign commits did not touch the backend. They were **not re-run during this inspection** (no stack is running; the throw-away Postgres was removed). |
| Generated files / artifacts remaining | tracked but stale/junk: `web/ui/debug_admin.png`, `web/ui/test-results/.last-run.json`, six `web/ui/tests/debug*.spec.cjs` (pre-existing, from before this work, left alone). Untracked: the `.jrnl` above. Ignored build output: `target/` (≈ 23 GB → ≈ 14 GB after cleanup; `deps` 12 GB, `release` 1.6 GB). Scratch (outside repo): UI copy, Playwright browsers. Legacy unused `web/ui/src/pages/Admin.jsx` (not imported anywhere). |

### 5.2 Implemented work, by category

Legend — Origin: **Existing** (present before) · **New** · **Extended**. Result = exact figure from the run.

| Category | What | Key files | Origin | Tested / exact result |
|---|---|---|---|---|
| Admin dashboard | Overview with real data only (needs-attention list, counts, publication/server health, agent sync chart, query counters or "not configured", recent audit) | `pages/Admin/Dashboard.jsx` | Rewritten | `redesign_qa.cjs` 165/165 (render, no console errors, no overflow, 3 viewports × 2 themes); data correctness covered by `audit_ui_regression.cjs` 50/50 |
| Admin dashboard | Analytics page: query rate from successive Prometheus samples | `pages/Admin/Analytics.jsx`, `GET /metrics/queries` | New | render in 165/165; counters vs real exporter: `metrics_lab.sh` 6/6. **Rate maths on the page has no dedicated assertion.** |
| User dashboard | Customer overview, "My Zones", account & security, help | `pages/User.jsx`, `UserSettings.jsx`, `Help.jsx`, routes in `App.jsx` | Rewritten + New (Help) | 165/165 incl. role separation (editor, viewer) |
| Design system | tokens, buttons, tables, badges, skeleton, focus ring, reduced motion, shared components (PageHeader, StatCard, StatusBadge, Empty/Error/Skeleton, ConfirmProvider, Brand, FlowArt, ThemeToggle) | `index.css`, `tailwind.config.js`, `components/ui.jsx`; 17 pages normalised | New | visual review of screenshots + 165/165; **no automated contrast/a11y audit (axe etc.) was run** |
| Themes | dark default, light equal, persisted (`outis-theme`), applied before first paint on every route | `index.html`, `store/index.js`, `ui.jsx` | New | theme toggle + persistence in 165/165 |
| Navigation / responsive | role-grouped sidebar, breadcrumbs, user menu, mobile drawer, skip link, ARIA | `Layout.jsx`, `Modal.jsx`, `Notifications.jsx` | Rewritten | tablet/mobile/desktop overflow checks, drawer + menu behaviour in 165/165 |
| DNS management | zones CRUD, records CRUD, import/export, bulk import, nameservers, history/rollback, sharing, verification | `Zones.jsx`, `Records.jsx`, `ZoneTools.jsx`, `BulkImport.jsx`, `Nameservers.jsx`; API in `main.rs`, `ext.rs` | Existing + Extended (history, sharing, verification, pagination new) | API tests (`cargo test -p control_api`, part of 862/0/26 workspace total); UI flows 50/50. **Nameservers CRUD page and bulk import have no browser test.** |
| DNSSEC | per-zone enable (ECDSAP256/384, Ed25519), DNSKEY/DS, rollover/complete, guarded disable, re-sign job, NSEC | `crates/control_api/src/dnssec.rs`, `DnssecTab.jsx` | New | `dnssec_lab.sh` **30/30** (ISC `delv`), API tests, UI flow in 50/50 |
| ECS | per-zone opt-in, ECS echo with scope | `crates/server` catalog, `Zones.jsx` toggle | New | `geodns_lab.sh` 32/32 (5 ECS checks), UI toggle in 50/50 |
| GeoDNS | country/continent/city/region rules, specificity order, existing-names-only, hot reload, GeoIP update script | `crates/geodns`, `crates/server/.../geodns.rs`, `GeoRules.jsx`, `scripts/update_geoip.sh` | Existing + Extended | `geodns_lab.sh` 32/32; `geodns_city_lab.sh` 8/8 (MaxMind **open test DB**, not GeoLite2); `geodns` unit tests. **GeoRules page: only render checks in 165/165; CRUD not browser-tested.** |
| Control API | pagination (`limit/offset/q`, `X-Total-Count`), status/health, metrics, audit filters, dual-stack listeners, publish lock | `main.rs`, `ext.rs`, `db_pool.rs` | Extended | `cargo test --workspace` **862 passed / 0 failed / 26 ignored** |
| Agents | registration with one-time token + signing key, signed versioned bundles, atomic apply, ack, push, enable/disable, rotate | `crates/agent`, `Agents.jsx`, `ConfigPush.jsx` | Rewritten | `agent_e2e.py` 6/6; agent unit tests; UI in 50/50 |
| AuthN/Z, RBAC | admin/editor/viewer, zone sharing (viewer/editor), tenant isolation, TOTP MFA, per-IP/username login limits, trusted proxies | `main.rs`, `ext.rs`, `MfaCard.jsx`, `Login.jsx`, `App.jsx` | Extended | API tests per role; 165/165 role separation (editor, viewer); MFA flow in 50/50 |
| Database | idempotent migrations, advisory publish lock, legacy-schema upgrade, pool with reconnect | `migrations/`, `db_pool.rs` | Extended | `legacy_schema_upgrades_in_place_keeping_data`, pool-recovery test (in 862) |
| Analytics / monitoring | Prometheus exporter default-on, `outis_*` gauges, `/dns/status`, example alert rules (`deploy/prometheus/outis-alerts.yml`, **not wired in**) | `ext.rs`, `metrics.rs` | New | `metrics_lab.sh` 6/6 |
| Security | placeholder-secret refusal, `GET /servers` admin-only, METRICS_TOKEN, RRL + slip, privilege-drop fallback, upstream Hickory memory/lexer fixes, 25→0 `cargo audit` vulns, `npm audit` 0 | many | New/Extended | regression tests per fix; `cargo audit` 0 vulns (2 *unmaintained* warnings); lab rate-limit checks |
| Performance | NXDOMAIN O(n)→O(log n) (611→31,165 qps on a 20k-RRset zone); load test 31–40k qps, p99 ≈ 6.5 ms at 20k qps paced | `crates/server/src/store/in_memory/mod.rs`, `scripts/dnsload.rs` | New | measured on a shared 4-core VM, generator on same host — indicative only |
| Testing / QA | `redesign_qa.cjs`, `audit_ui_regression.cjs`, 5 labs, regression tests | `web/ui/tests`, `scripts/` | New | see above |
| Documentation | `AUDIT_REPORT.md`, `PROPOSED_FEATURES.md` | repo root | New | n/a |

### 5.3 Dashboard route-by-route review

All routes: guarded by `ProtectedRoute` (unauthenticated → `/login`); `/admin/*` is `requireAdmin` (editor/viewer → `/user`); the API is the real enforcement point.

**Admin (`/admin/…`)**

| Route | Function / actions | Backend | Missing / problems | Roles |
|---|---|---|---|---|
| `/admin` Overview | attention list, counts, health, agent chart, audit feed | `agents, audit/logs, dns/status, metrics/queries, servers, users, zones, records` (N+1 record-count calls per zone) | record counts are fetched per zone, so cost grows with zone count; no auto-refresh interval | admin only (API 403 otherwise) |
| `/admin/metrics` Analytics | live query rate, totals | `metrics/queries` | history exists only while the page is open (no persisted time series); global counters only, no per-zone/per-type/per-country breakdown | admin only |
| `/admin/zones` | list, search, server paging, create, edit, delete, GeoDNS/ECS toggles, import/export, manage dialog (sharing, history, verify), DNSSEC tab | `zones*`, `members`, `revisions`, `verify`, `dnssec*` | GeoDNS+DNSSEC mutually exclusive (UI explains); no bulk zone actions; no zone templates | admin full; same component serves customers |
| `/admin/zones/:id/records` | list/paging/search, add, edit, delete, bulk import | `zones/{id}/records*` | no per-record bulk delete/multi-select; no record-level audit view | admin full |
| `/admin/dns-lookup` | resolve a name | `POST /dns/lookup` | **Backend implements only A/AAAA via the OS resolver, but the UI offers MX, TXT, NS, CNAME, SOA, SRV, PTR, DNSKEY, DS, CAA — those always return empty with a "not supported" note.** Any authenticated user can make the API host resolve arbitrary names (no rate limit). | any role |
| `/admin/users` | list, search, paging, create, edit role, delete, reset password | `users*`, `admin-reset-password` | no suspend/disable flag, no last-login column, no invite/email flow | admin only |
| `/admin/servers` | list with real TCP probe, add, delete | `servers*` | no edit; delete confirmation only; probe is TCP connect, not a DNS query | admin only |
| `/admin/nameservers` | CRUD of NS/glue entries | `nameservers*` | `GET /nameservers` is readable by any authenticated user (low impact); no browser CRUD test | admin edits |
| `/admin/agents` | register (credentials shown once), enable/disable, rotate, delete, sync status, push | `agents*`, `config/push` | no per-agent logs/history; no alerting on out-of-sync | admin only |
| `/admin/georules` | CRUD of rules, resolve tester | `georules*` | no map/visual editor; no import/export of rules; CRUD not browser-tested | admin (owners may manage rules via API for their zones) |
| `/admin/config` Config Sync | push to one/all agents | `config/push` | thin page; duplicates part of Agents | admin only |
| `/admin/audit` | filter, paging | `audit/logs` | no export (CSV); no per-resource drill-down | admin only |
| `/admin/settings` | theme, profile, password, admin password reset, MFA | `auth/*` | **imports unused icons (`Bell`, `Shield`, `Monitor`, `Palette`, …); "notifications" are not a feature**; no system settings (retention, limits) editable in UI | admin |

**Customer (`/user/…`)**

| Route | Function | Problems |
|---|---|---|
| `/user` | own zones, record count, verification, service status | zone record counts are N+1 requests; no query analytics (no per-tenant data exists) |
| `/user/zones` (+ `/:id/records`) | same components as admin, scoped by API (owner / shared) | viewers and viewer-shared zones are read-only (tested); no zone-creation limits/quotas |
| `/user/dns-lookup` | as admin | see lookup limitation above |
| `/user/settings` | profile, password, MFA | no session list/revoke, no API tokens |
| `/user/help` | static help text (25 lines) | minimal; fonts via Google Fonts CDN |

**Routes removed / renamed / relocated in the redesign (`7a7fa19c7`)**: the fake "SSL/Certificates" route was removed (no certificate backend exists); duplicate "Records" and "Metrics" entries were folded into `zones/:id/records` and `/admin/metrics` (now the Analytics page); customer zones moved from a combined overview to `/user/zones`; `/user/settings` now renders `UserSettings` (was the admin settings page); `/user/help` added. Reason: remove dead UI, give customers a separate surface. The old `pages/Admin.jsx` wrapper is dead code.

### 5.4 Remaining bugs, gaps and risks

**Functional / UX**
1. DNS Lookup record-type selector offers types the backend cannot answer (see above). — *fix: either implement a real resolver query (hickory-resolver is in the workspace) or reduce the list to A/AAAA.*
2. Admin overview and customer overview issue one `/records` request per zone to count records (N+1).
3. Analytics has no persisted history; leaving the page resets the graph.
4. Settings: unused imports and no real notification settings; Help page minimal.
5. Fonts load from Google Fonts (privacy/offline); system fallback only.
6. Dead/legacy files: `pages/Admin.jsx`, tracked debug specs and `debug_admin.png`, tracked `test-results/.last-run.json`.
7. No Servers edit, no user suspend, no audit export, no zone bulk operations, no record multi-select.
8. No per-user/tenant query analytics (DNS server only exports global counters); no tenant entity beyond ownership/sharing; no quotas.

**Security**
1. `POST /dns/lookup` and `GET /nameservers` need only a valid login (no role check, no rate limit on lookup).
2. Rate limiters and login throttling are per API instance (C-14); JWT is held client-side (localStorage-style token header, no cookies; XSS would expose it).
3. `ALLOWED_ORIGINS=*` still accepted with a warning; `VERIFY_DOMAINS` off by default; TXT-only ownership proof.
4. GeoDNS and DNSSEC cannot be enabled on the same zone; no NSEC3; DNSSEC rollover is operator-driven; DS must be published at the registrar by the operator; DNSSEC key files must be backed up with the DB.
5. Dependencies: 2 unmaintained crates (pin-utils, proc-macro-error); fork has diverged from upstream Hickory — merge v0.26.3 before enabling forwarding/recursion/validation.
6. Production `env/*.env` placeholders make the API refuse to start (intended).

**Performance**: load numbers are from a shared VM; no sustained soak test; no large-zone (>100k records) publication-time test; publication regenerates files per change.

**Database**: no automatic down-migrations; one legacy unique constraint is dropped; migration safety proven on fixtures, **not on a copy of production data**.

**Tests**: no automated browser CRUD tests for Nameservers, GeoRules, Servers, bulk import; no accessibility (axe) or visual-regression baseline; no CI definition runs the labs; lab scripts need root/netns; one upstream test is `#[ignore]`d (`named_metrics_tests::test_updates`); `schema_consistency_tests` assert on string literals (C-13); 26 ignored tests overall (upstream, need network/features) were not individually reviewed here; backend suites were not re-run during this inspection.

### 5.5 Remaining feature development

| Tier | Feature | Practical value |
|---|---|---|
| **Essential** (for a complete DNS platform) | Real multi-type DNS lookup (or reduced selector) | tool currently misleads |
| | Registrar/NS delegation check + status (parent NS vs configured) | catches the #1 cause of "my zone doesn't work" |
| | Secondary zones / AXFR/IXFR + NOTIFY, TSIG | needed to interoperate with other DNS providers |
| | Missing record types in UI/API validation review (CAA, SRV, TLSA, SVCB/HTTPS, ALIAS/ANAME at apex) | common customer needs; apex CNAME alternative |
| | API tokens for automation (scoped, revocable) | customers need scripted/ACME DNS-01 updates |
| **Important** (production-ready) | Per-zone/per-type query analytics + persisted time series (Prometheus/Grafana or TSDB) | capacity, abuse, customer reporting |
| | Wire alert rules into a running Prometheus/Alertmanager | alerts exist only as an example file |
| | Shared rate-limit/session state (Redis or DB) for multiple API replicas | C-14 |
| | Backup/restore tooling for DB + DNSSEC keys | key loss = zone failure |
| | Account lifecycle: invites, suspend, session list/revoke, password-reset email | admin operations today are manual |
| | Quotas / plans per customer; tenant (organisation) entity | multi-customer billing/limits |
| | CI pipeline running unit, UI and lab suites; accessibility + visual regression tests | prevents regressions |
| | Self-hosted fonts; CSP headers in `nginx.conf` | privacy, XSS hardening |
| **Advanced** | NSEC3, automatic key rollover scheduler, CDS/CDNSKEY automation | DNSSEC operations at scale |
| | GeoDNS + DNSSEC together (per-view signing) | currently mutually exclusive |
| | Health-checked failover / weighted routing | dynamic traffic steering |
| | DoT/DoH/DoQ listeners; anycast guidance; zone transfer in/out between OutisCloud nodes | modern transports and HA |
| | Import from BIND/Cloudflare/Route53 | onboarding |
| **Optional** | Map-based GeoDNS editor, notification centre, white-label themes, usage billing, webhooks | convenience; no current dependency |

`PROPOSED_FEATURES.md` statuses (DNS-01…07, CP-01…08, OPS-01…03) are as recorded there and in Phase 3: all **COMPLETED** locally; the only external qualifiers are DNS-04 (needs a MaxMind licence for GeoLite2-City) and CP-02 (public-resolver verification), both **BLOCKED — EXTERNAL**.

### 5.6 Final status table

| Item | Status | Next step / can it be done safely now? |
|---|---|---|
| DNS core: hot reload, IPv6, existing-names-only, ECS, RRL+slip, NXDOMAIN fix | COMPLETED AND VERIFIED (local) | none |
| DNSSEC (ECDSA/Ed25519, DS, rollover, re-sign) | COMPLETED AND VERIFIED (local, `delv` 30/30) | operator publishes DS at registrar |
| GeoDNS country/continent | COMPLETED AND VERIFIED (lab 32/32) | none |
| GeoDNS city/region | COMPLETED AND VERIFIED on MaxMind **test** DB; production data BLOCKED BY EXTERNAL DEPENDENCY | needs MaxMind licence key; safe afterwards via `update_geoip.sh` |
| Control API, RBAC, sharing, MFA, history, pagination, pool, publish lock | COMPLETED AND VERIFIED (862/0/26) | none |
| Agents (bundles, ack, push, enable) | COMPLETED AND VERIFIED (e2e 6/6) | production rollout with real credentials (operator) |
| Dashboard redesign (shell, themes, nav, design system, Overview, Analytics, customer UI) | COMPLETED AND VERIFIED (165/165 + 50/50, code identical to tested copy) | none |
| Nameservers / Servers / GeoRules / bulk-import CRUD in browser | IMPLEMENTED — TESTING INCOMPLETE | add Playwright CRUD tests (safe, scratch stack) |
| Analytics rate calculation | IMPLEMENTED — TESTING INCOMPLETE | add assertion against a stub exporter (safe) |
| Accessibility / contrast / visual regression | IMPLEMENTED — TESTING INCOMPLETE | run axe in scratch copy (safe) |
| DNS Lookup | PARTIALLY IMPLEMENTED (A/AAAA only; UI offers more) | **REQUIRES MY DECISION**: real resolver query vs trimmed selector |
| Per-user/tenant analytics, quotas, tenant entity | NOT IMPLEMENTED | **REQUIRES MY DECISION** (data model + DNS-server per-zone counters) |
| Persisted analytics history, alert wiring | NOT IMPLEMENTED | needs a Prometheus/TSDB instance (infrastructure decision; no production changes made) |
| Account lifecycle (suspend, sessions, invites, API tokens) | NOT IMPLEMENTED | safe to build; **REQUIRES MY DECISION** on scope |
| Secondary zones / AXFR / TSIG, NSEC3, GeoDNS+DNSSEC, failover | NOT IMPLEMENTED | large design items; safe locally with current 11 GB, decision needed on priority |
| Public delegation, propagation, registrar, real-resolver verification | BLOCKED BY EXTERNAL DEPENDENCY | run from outside after deployment |
| Upstream Hickory v0.26.3 full merge | PARTIALLY IMPLEMENTED (applicable fixes ported) | **REQUIRES MY DECISION** (fork policy); required before enabling recursion/validation |
| Multi-replica shared rate-limit/session state | NOT IMPLEMENTED | needs Redis/DB design decision |
| Repo hygiene (debug specs, `debug_admin.png`, `Admin.jsx`, `.jrnl`) | PARTIALLY IMPLEMENTED (documented, untouched) | **REQUIRES MY DECISION** to delete tracked files |
| Disk | BLOCKED BY STORAGE — resolved for now (11 GB free); `target/` still ≈ 14 GB | rebuilds will regrow `incremental` (≈ 9 GB) |
| Push to `origin` | NOT DONE (by instruction) | **REQUIRES MY DECISION** |

---

## Phase 4 — dashboard redesign (admin and customer)

New visual identity (original, inspired by the requested direction): electric-yellow accent on deep ink, restrained blue/violet,
Space Grotesk + Inter, flowing-line artwork, both themes first-class (dark default, light equal, persisted, applied before first paint on every route including login).

| Area | What changed |
|---|---|
| Design system | CSS-variable tokens (`index.css`) bound to Tailwind (`tailwind.config.js`): palette, surfaces, radius, shadows, buttons, inputs, tables, badges, tabs, skeletons, focus ring, reduced-motion support; shared components in `components/ui.jsx` (page header, stat card, status badge, empty/error/skeleton states, themed confirmation dialog, theme toggle, logo, flow art). Legacy markup in 17 files was normalised onto the tokens. |
| Navigation | Role-based sidebar with grouped sections (admin: Overview, Analytics, Zones, Nameservers, GeoDNS, DNS Lookup, DNS Servers, Agents, Config Sync, Users & Roles, Audit Log, Settings; customer: Overview, My Zones, DNS Lookup, Account & Security, Help & Docs), breadcrumb top bar, user menu, mobile drawer. Removed dead/fake entries (a fake "SSL" page, duplicate "Records" and "Metrics" routes). |
| Admin overview | Real data only: "needs attention" list (failed publication, agents behind, servers down, pending zones), zone/record/server/agent/user counts, publication and server health, agent synchronisation chart, query counters (or an explicit "not configured"), recent audit activity. New **Analytics** page (query rate computed from consecutive samples of the real Prometheus counters). |
| Customer dashboard | Separate, simpler overview (own zones, record count, verification status, service status, help), own-zones page, account & security page, help page. No infrastructure controls; `/admin/*` redirects customers to `/user`, and the API still enforces tenancy/RBAC. |
| UX | Native `confirm()`/`alert()` replaced by themed confirmation dialogs and toasts (zones, records restore, users, servers, nameservers, GeoDNS rules, agents, DNSSEC key retirement/disable); restyled pagination; Escape closes dialogs/menus; skip link, ARIA labels, live regions. Fixed a layout bug where zone rows were wrapped in a `div` inside `tbody`. |
| Tests | `web/ui/tests/redesign_qa.cjs`: **165/165** (every admin route and every customer route × dark/light × desktop/tablet/mobile: renders, no horizontal overflow, no console/page errors; theme toggle + persistence; sidebar/user-menu/mobile-drawer behaviour; role separation for editor and viewer; login/zone/user form validation; confirmation dialog; audit filter). `audit_ui_regression.cjs` (backend-integration flows, pagination, ECS, DNSSEC UI): **50/50**. |
| Notes | Web fonts load from Google Fonts (system fonts are the fallback offline). Not done: per-user query analytics (the DNS server only exports global counters), tenant management beyond user ownership/sharing (no tenant entity exists in the API). |

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
