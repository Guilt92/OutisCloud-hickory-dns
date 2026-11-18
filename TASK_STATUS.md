# Task Status — Audit Remediation and Platform QA

**Repository:** `/home/outis/work-github/OutisCloud-hickory-dns`
**Branch:** `main`
**Base commit:** `7ec82cf0f feat(ui): redesign admin and customer consoles`
**Audit-remediation commit:** `a6bcf9ad5 fix(security): complete audit remediation across API, DNS, and UI` (local, not pushed)
**Follow-up state:** platform-QA and analytics-hardening changes are committed locally on top of `a6bcf9ad5`; **not pushed**.
**Report basis:** current source, executed test suites, browser runs, database state, and captured logs. Prior documentation was not treated as proof of completion.

---

## 1. Executive summary

The confirmed in-scope audit findings are implemented and covered by executed regression tests. A follow-up platform pass resolved the previously blocked live hot-reload check: the failure was caused by stale debug binaries, not by the current source. The rebuilt release stack now passes DNS publication for zone creation, record updates, and record deletions, followed by all supported lookup types in the browser.

The latest results are:

- **Platform QA: 96/96 passed** on the release stack, repeated successfully without stale-data failures.
- **Control API: 140/140 passed** against an isolated PostgreSQL test database.
- **5,000-zone performance:** admin overview p95 **100 ms**, p99 **116 ms**; customer overview p95 **72 ms**; API RSS stable at **131,512 KiB**.
- **Analytics persistence:** history survived a clean control API restart (20 pre-restart samples, 0 missing).
- **Browser stability:** the full platform journey completed repeatedly with reliable browser cleanup.
- **Remote validation:** still blocked because no safe test host is available; the only documented server is explicitly marked production and was not modified.

No production migration was executed. Database-backed work used isolated schemas or the disposable local database `outis_ui`. No secrets, generated DNS state, or production data were committed.

---

## 2. Scope and constraints

### In scope

- Audit-remediation code and regression tests in `control_api`, `control_agent`, `geodns`, `hickory-server`, the DNS binary, and the admin/customer UI.
- Tenant, quota, membership, analytics, authorization, overview, zone-transfer, and publication behavior.
- Platform QA in a disposable local stack using real PostgreSQL, real control API, real DNS server, real Vite UI, and a deterministic metrics stub.
- Performance and reliability validation at 5,000 zones and 40,000 records.
- Remote validation only where an authorized, non-production test environment is available.
- `TASK_STATUS.md` as the required delivery report.

### Explicitly out of scope

- AUTH-05 HTTP/TLS/reverse-proxy/HSTS/CSP/Referrer-Policy/public-port hardening.
- DNS-02 DNS-over-TLS, port 853, TLS certificates/listeners.
- Dockerfiles, Docker Compose, container networking, deployment infrastructure.
- CI/CD, GitHub Actions, Helm, Kubernetes manifests, deployment pipelines.
- Shell scripts, operational scripts, README, existing documentation, deployment instructions.
- Production data, production schema migration, or production deployment.
- `/home/outis/work-github/res` was not inspected or modified.

### Safety constraints applied

- No push, force-push, amend, reset-hard, clean, or destructive Git operation.
- No secrets or runtime configuration staged (`.env`, `env/api.env`, `env/db.env`).
- No generated/runtime DNS state staged (`deploy/dns/named.toml`, `deploy/dns/.orphaned/`).
- No `docker-compose down --volumes`; tests used a disposable database/schema and cleaned up their own fixtures.
- Browser tests clean test-owned zones, users, tenants, members, servers, nameservers, and analytics samples before and after each run.
- A production server was never modified or deployed to.

---

## 3. Changes made

### 3.1 Audit finding status

| Finding | Status | Evidence |
|---|---|---|
| AUTH-01 — invalidate access tokens after password change/reset | **FIXED AND VERIFIED** | `password_change_and_admin_reset_revoke_access_and_refresh_tokens` |
| AUTH-02 — refresh rotation and replay prevention | **FIXED AND VERIFIED** | `refresh_rotation_replay_revokes_the_whole_session` |
| AUTH-03 — MFA changes invalidate existing sessions | **FIXED AND VERIFIED** | `mfa_enrol_login_and_disable` |
| AUTH-04 — logout invalidates all relevant sessions/access tokens | **FIXED AND VERIFIED** | `logout_invalidates_every_session_for_the_user` |
| ZONE-01 — safe deletion when publication fails | **FIXED AND VERIFIED** | `failed_zone_delete_publication_restores_the_zone` |
| ZONE-02 — safe rename when publication fails | **FIXED AND VERIFIED** | `zone_rename_rewrites_soa_and_ecs_flag`, rollback path in `rename_zone` |
| ZONE-03 — nameserver insertion failures during creation | **FIXED AND VERIFIED** | `zone_creation_rolls_back_when_default_records_fail`, `nameserver_input_is_validated_and_applied` |
| ZONE-04 — accurate publication status/errors | **FIXED AND VERIFIED** | `one_broken_zone_never_blocks_or_replaces_others`, `publication_is_serialised_across_api_instances` |
| ZONE-05 — transactional zone creation consistency | **FIXED AND VERIFIED** | `zone_creation_rolls_back_when_default_records_fail`, `concurrent_zone_creates_cannot_exceed_quota` |
| DNS-01 — DNSSEC publication fails closed | **FIXED AND VERIFIED** | `dnssec_publication_fails_closed_when_a_key_file_is_missing` |
| GeoDNS/DNSSEC inconsistent state prevention | **FIXED AND VERIFIED** | `dnssec_lifecycle_keys_ds_rollover_and_guards`, `georule_update_and_input_validation`, generator guard |
| Frontend/backend IP validation | **FIXED AND VERIFIED** | `nameserver_input_is_validated_and_applied`, `useFormValidation.jsx`, UI regression suite |
| GeoDNS resolution rate limiting evaluated/addressed | **FIXED AND VERIFIED (opt-in)** | Per-source limiter in `SwapHandler`; `limiter_enforces_burst_then_blocks_per_source`, `ipv6_sources_share_a_budget_per_slash_64`; enabled by `DNS_RATE_LIMIT_QPS` |
| E-02 — agents restricted to explicit zones/bundles | **FIXED AND VERIFIED** | `agents_are_default_denied_and_only_receive_assigned_zones`, `agent_lifecycle_register_heartbeat_bundle_ack_push_disable` |
| E-03 — server create/update/delete audited | **FIXED AND VERIFIED** | `server_create_update_delete_are_audited_and_update_in_place` |
| API-01 — server update instead of duplicate insert | **FIXED AND VERIFIED** | `server_create_update_delete_are_audited_and_update_in_place` |
| API-02 — DB errors not converted to misleading 404 | **FIXED AND VERIFIED** | `database_errors_do_not_look_like_missing_zones_or_agents` |
| API-03 — bounded default pagination | **FIXED AND VERIFIED** | `zones_records_users_support_opt_in_pagination_and_search` |
| API-04 — remove `generate_all` N+1 queries | **FIXED AND VERIFIED** | `generate_all_uses_bounded_database_queries` |
| API-05 — bound agent-heartbeat Argon2 work | **FIXED AND VERIFIED** | `legacy_heartbeat_argon2_work_is_bounded_and_rate_limited` |
| API-06 — independent rate-limit cleanup | **FIXED AND VERIFIED** | `shared_rate_limit_is_atomic_under_concurrency`; independent cleanup task starts in `main` |
| API-07 — remove `Box::leak` pool leak | **FIXED AND VERIFIED** | `pool_replaces_dropped_connections`; `Arc<Client>` slots |
| API-08 — audit coverage/dead paths/serialization | **FIXED AND VERIFIED** | `audit_trail_records_mutations`, `audit_pagination_filters_and_retention`, `roles_viewer_is_read_only_and_create_user_honours_role` |
| Users email frontend/backend consistency | **FIXED AND VERIFIED** | Users schema/API/UI; `roles_viewer_is_read_only_and_create_user_honours_role` |
| Servers edit updates selected row | **FIXED AND VERIFIED** | API test above plus UI regression suite |
| Zones page nameserver N+1 | **FIXED AND VERIFIED** | Single nameserver fetch in `Zones.jsx`; UI regression suite |
| Agent zone-assignment modal response handling | **FIXED AND VERIFIED** | Envelope unwrapping in `Agents.jsx`; browser test with intercepted route passed |
| Platform live DNS hot-reload journey | **FIXED AND VERIFIED** | Rebuilt release stack; `platform_qa.cjs` 96/96; creation, update, and deletion observed through the real DNS server |
| Analytics invalid range/interval handling | **FIXED AND VERIFIED** | API returns 400; backend and platform assertions added |
| Remote-environment execution | **BLOCKED — NO SAFE TEST HOST** | `germ` is documented as production; other local SSH aliases failed host-key verification; see section 9 |

### 3.2 Authentication and session security

- Added a persisted session generation (`users.token_version`) and a `ver` JWT claim. Access tokens are accepted only while their generation matches the database and they are not blacklisted.
- Password change and administrator password reset now update the password, bump `token_version`, and delete refresh-token sessions in one transaction.
- Refresh tokens are single-use and rotated under a row lock. Reuse of a rotated token revokes the entire session, including outstanding access tokens.
- MFA enable and disable bump the session generation and retire refresh sessions, so pre-change tokens cannot survive either transition.
- Logout bumps the generation, deletes all refresh sessions, and blacklists the presented access token.
- Legacy tokens without `ver` decode as generation `0`, matching existing rows.

### 3.3 Zone management and publication integrity

- Zone creation reserves quota, inserts the zone and default records, and inserts nameservers in one transaction; any failure rolls the whole operation back.
- Zone deletion marks the row `deleting`, publishes, then deletes. A failed publication restores the previous status and keeps the last known-good zone file.
- Zone rename compensates database changes when publication fails and reports `state_uncertain` if restoring the previous configuration also fails.
- Publication reports per-zone failures without overwriting valid files for unrelated zones. Publication is serialised across API instances with an advisory lock.
- DNSSEC key metadata and file contents are validated before any file is written. Missing/empty key files abort publication instead of downgrading a signed zone.
- A zone cannot be both DNSSEC-signed and GeoDNS-enabled; the API and generator reject that state.
- Nameserver and GeoRule inputs are validated server-side, including IPv4/IPv6 addresses and GeoDNS scoping rules.
- The live stack now verifies hot reload for new zones, changed records, and deleted records, not only the initial publish.

### 3.4 Agent authorization and auditability

- Added `agent_zones`; an agent with no explicit assignment receives no zones.
- Agent bundle generation filters both the zone list and published configuration to the assigned domains. The TOML is parsed and rebuilt rather than string-spliced.
- Agent tokens use a SHA-256 fingerprint for the common verification path. Legacy agents without a fingerprint are verified with bounded Argon2 work, rate-limited per legacy source, and upgraded on success.
- Agent registration, heartbeat, bundle, acknowledgement, enable/disable, token rotation, deletion, and zone assignment are covered by backend checks. Bundle bodies are signed with a per-agent HMAC key.
- Server create, update, and delete emit audit entries with actor, action, resource type, resource ID, details, client IP, and timestamp. Audit details do not contain passwords, tokens, or key material.

### 3.5 API and backend correctness

- API-02: selected handlers now return `500` for database failures and only return `404` for genuinely missing resources.
- API-03: list pagination defaults to 100, clamps `limit` to `1..=1000`, normalises negative offsets to 0, and reports `X-Total-Count`.
- API-04: `generate_all` now performs one zones query, one records query, one georules query, one nameservers query, and one DNSSEC key query instead of per-zone queries. A test-only counter verifies the bound.
- API-05: legacy heartbeat verification checks at most eight rows for one address and applies a `20/60s` per-address bucket.
- API-06: rate-limit cleanup runs on an independent five-minute task, not only inside the analytics collector.
- API-07: `Box::leak` was removed. Pool slots hold `Arc<Client>`, and statements borrow a client that remains alive during reconnection.
- API-08: removed the dead duplicate audit-list path; the live endpoint paginates, filters, exports, retains, and serialises audit entries consistently.
- Analytics `range` is now validated explicitly. Unknown values return `400` instead of silently becoming `24h`; unknown intervals already returned `400`. The response documents the valid ranges.
- Overview query-count assertions now prove the data path stays bounded at 3,003 zones: admin is auth + one data query; customer is auth + two data queries.

### 3.6 Frontend and admin panel

- Users page sends and displays `email` consistently with the API.
- Servers page uses `PUT /api/v1/servers/{id}` and no longer creates duplicates on edit.
- Frontend IP validation now accepts valid IPv4/IPv6 and rejects malformed input, matching backend validation.
- Zones page loads nameservers once and derives per-zone labels in memory.
- Agent zone management unwraps the `{ success, data }` response envelope before rendering; the old code treated the envelope as an array.
- Existing routes, RBAC behavior, dialogs, pagination, filters, and design conventions were preserved.

### 3.7 Platform QA follow-up

- `web/ui/tests/platform_qa.cjs` now cleans only its known fixture domains, users, tenants, servers, nameservers, and analytics samples before and after a run, making repeated runs reliable.
- The suite closes the browser in a `finally` block, so failures cannot leave Chromium or contexts behind.
- Added hot-reload assertions for record update and deletion through the real DNS lookup path.
- Added quota bypass, record-quota, and quota-release assertions; added viewer-membership read/write checks; added non-empty-tenant deletion protection.
- Added transfer verification for records, GeoDNS rules, audit details, and success/cancel/error paths.
- Added 20-request and repeated-UI-load performance measurements with average, p95, p99, maximum, API RSS, and fixture-cleanup duration.
- Added invalid analytics range and interval checks.
- No production behavior was changed to make tests pass.

---

## 4. Database and migration notes

All application schema updates are idempotent startup DDL in `migrate_db` and module schemas. No production migration was run.

- `users`: `totp_secret`, `totp_enabled`, `token_version`, `email`; unique case-insensitive email index.
- `token_blacklist`: `token_type`, `session_id`, `rotated_at`, `replaced_by_hash`; hash/session indexes. Existing rows are migrated once to `token_type = 'refresh'` where they represented refresh sessions.
- `agents`: `applied_version`, `last_ack_at`, `last_error`, `sync_requested`, `last_seen_ip`, `token_sha256`; token fingerprint index.
- `zones`: `status`, `verify_token`, `verified_at`, `ecs_enabled`, `dnssec_enabled`, `tenant_id`.
- `records`: legacy `type` renamed/handled as `record_type`; the old `(zone_id, name, record_type)` unique constraint is dropped so valid multi-record RRsets are allowed while exact duplicates remain guarded.
- New tables: `zone_members`, `zone_revisions`, `dnssec_keys`, `agent_zones`, `publish_state`, `tenants`, `tenant_members`, `analytics_samples`, `zone_query_samples`, `zone_qtype_samples`, `zone_country_samples`, `tenant_usage_samples`, `shared_rate_limits`, `collector_lease`, `collector_state`.
- Analytics samples have no foreign key to zones, so query history survives zone deletion and application restarts, subject to configurable retention.
- Compatibility: existing zones default to `active`, existing users default to session generation 0, legacy agents without fingerprints continue through the bounded upgrade path, and existing rows are never deleted by the migration.

The platform tests used the disposable database `outis_ui` in the existing `outiscloud-db` container. Backend tests used throw-away schemas created from `TEST_DATABASE_URL`. No production schema was touched.

---

## 5. Test coverage

### Backend and libraries

| Command | Result |
|---|---|
| `cargo test -p control_api --bin control_api` with isolated `TEST_DATABASE_URL` | **140 passed, 0 failed** (67.05s) |
| `cargo test -p control_agent` | **6 passed, 0 failed** |
| `cargo test -p geodns` | **19 passed, 0 failed** |
| `cargo test -p hickory-server` | **27 passed, 0 failed**, plus 1 doctest |
| `cargo test -p hickory-dns --test integration` | **99 passed, 6 failed** — host-environment failures (section 11) |
| Targeted `zone_file_reload::reload_on_zonefile_change` | **passed** after freeing the test's fixed Prometheus port |
| `database_failure_never_wipes_published_zones` | **passed** |
| `cargo fmt --all -- --check` | **passed** |
| `cargo clippy -p control_api -p control_agent --all-targets --no-deps` | completed; inherited warnings remain (section 11) |
| `cargo check -p control_api` | **passed** |
| Release build `cargo build --release -p control_api -p hickory-dns` | **passed** (5m36s) |

The control API run includes the focused regressions for AUTH, ZONE, DNS, E-02/E-03, API-01 through API-08, tenant isolation, quota concurrency, overview query counts, analytics retention/range validation, real DNS lookup, metrics authorization, and UI-facing serialization.

### Frontend and platform

| Command | Result |
|---|---|
| `npm run lint` | **passed** |
| `npm run build` | **passed** (Vite production build) |
| `node tests/redesign_qa.cjs` | **368/368 passed** |
| `node tests/audit_ui_regression.cjs` | **50/50 passed** after test-data cleanup |
| `node tests/a11y_visual_qa.cjs a11y` | **9 passed, 0 failed**; zero axe violations |
| `node tests/a11y_visual_qa.cjs visual` | **28 passed, 0 failed**; all baselines `0.000%` |
| `node tests/a11y_visual_qa.cjs selftest` | **2/2 passed** |
| `node tests/platform_qa.cjs` | **96/96 passed** on release stack, repeated; see section 6 |
| Analytics restart check | **passed** — 20 samples before restart, 0 missing after |
| Agent modal browser check with intercepted agent-zone route | **PASS** |

Evidence logs are in `/tmp/opencode/`: `platform-qa2-release-final2.log`, `platform-qa2-release-run6.log`, `control-api-platform-final.log`, `control-api-full-final2.log`, `redesign-final2.log`, `audit-ui-final2.log`, `a11y-final.log`, `visual-final.log`, `agent-modal-qa.log`, and `hickory-dns-tests.log`.

---

## 6. Platform QA results

The full browser journey was run against:

- Vite UI at `127.0.0.1:5173`
- release control API at `127.0.0.1:8080`
- release hickory-dns at `127.0.0.1:5402`
- disposable PostgreSQL database `outis_ui`
- deterministic Prometheus/GeoIP stub for analytics

Latest result: **96 passed, 0 failed**, then repeated as **96 passed, 0 failed** with the same database and no manual cleanup.

Covered behavior:

- **Infrastructure CRUD:** nameservers create/edit/delete/validation; DNS servers create/list/real probe/delete; GeoRules create/edit/delete including city rules.
- **Bulk import:** successful import and fail-fast validation that leaves the zone unchanged.
- **DNS publication and lookup:** real server observed new zones, record updates, and deletions. Browser lookup verified A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, PTR, DNSKEY, DS, and CAA with TTLs; NXDOMAIN, NODATA, and empty input are handled honestly.
- **Tenants and quotas:** personal tenant creation, UI quota edits, clearing a quota, zone quota, record quota, API bypass refusal, quota release after zone deletion, and clear user-facing messages.
- **Membership and isolation:** add/remove member, viewer read access, viewer write refusal, cross-tenant zone denial, customer overview isolation, and admin-only routes.
- **Analytics:** persisted history, customer/admin scope, exact increments, disjoint tenants, record-type and country breakdowns, GeoIP age, interval/range filters, global authorization, and invalid value rejection.
- **Authorization:** admin/customer redirects, customer 403s on infrastructure and global analytics, viewer behavior.
- **Overview:** zero per-zone `/records` browser requests for admin and customer; totals and scoped data remain correct.
- **Performance:** 5,000 extra zones and 40,000 records measured without per-zone N+1 calls.
- **Zone transfer:** source/destination display, disabled submit until destination chosen, confirmation text, cancel, successful move, records plus GeoDNS rules present, target quota failure with rollback, non-empty tenant deletion refusal, customer API refusal, and audit details.
- **Stability:** browser closed in `finally`; no page-closed fatal error; fixtures removed before and after the run.

The earlier `FAIL lookup: the real DNS server picked the new zones up (hot reload)` was reproduced against stale debug binaries. After rebuilding from current source and restarting the stack, the same checks passed repeatedly. The current source had no hot-reload defect.

---

## 7. Performance results

### 5,000-zone platform measurement

Release binaries were used for the final measurement. The database contained **5,007 zones / 40,038 records** during the test.

| Measurement | Result |
|---|---|
| Admin overview API, 20 requests | average **95 ms**, p95 **100 ms**, p99 **116 ms**, max **116 ms** |
| Admin overview UI, 3 loads | average **490 ms**, max **553 ms** |
| Customer overview, 5 requests | p95 **72 ms**, max **72 ms** |
| API RSS during test | **131,512 KiB**, unchanged from before measurement |
| Fixture creation, measurement, verification, cleanup | **7,378 ms** total |
| Per-zone `/records` requests | **0** |

### Overview query count

The backend test at **3,003 zones / 30,015 records** measured:

- Admin overview: **2 queries** including auth metadata = **auth + 1 data query**.
- Customer overview: **3 queries** including auth metadata = **auth + 2 bounded data queries**.
- Debug-build timing from that test: admin **380 ms**, customer **83 ms**; these are not production benchmarks.

The platform test additionally proves the browser does not fetch records per zone. Performance conclusions are limited to this local environment and dataset; see section 15.

---

## 8. Reliability and security validation

- **Session revocation:** password changes, administrator resets, MFA transitions, and logout invalidate access tokens through the persisted session generation, not only through process-local state.
- **Refresh-token replay:** rotation is transactional and one-time; replay revokes the session and its access tokens.
- **Agent isolation:** assignment is explicit; bundles are filtered and signed; unassigned agents receive no zones; legacy verification work is bounded and rate-limited.
- **Publication integrity:** DNSSEC failures cannot silently downgrade a signed zone; failed deletes/renames preserve or restore the last known-good configuration.
- **Failed-reload safety:** `database_failure_never_wipes_published_zones` passes, and the targeted `zone_file_reload` integration test passes when its fixed port is available. The full integration suite is limited by host resources, not assertion failures in changed code.
- **Hot-reload correctness:** live create, update, and delete operations all reached the real DNS server.
- **Analytics durability:** 20 stored samples were present before a clean API restart and all 20 remained afterward; the total remained 12,374.
- **Test isolation:** repeated platform runs pass because fixtures are removed before and after each run; no application data is deleted, only known test-owned names.
- **Browser reliability:** browser/context cleanup is guaranteed by `finally`; no fatal page-closed path remained in the successful runs.
- **Error honesty:** unknown analytics ranges/intervals return `400`; database failures stay distinct from missing resources.
- **Audit:** mutations record actor/action/resource/details/IP/time without credentials or key material.
- **Rate limiting:** login is bounded per username and per client; legacy agent heartbeat work is bounded per address; DNS resolution has an optional per-source limiter covering GeoDNS.
- **No secret exposure:** `.env`, `env/*.env`, tokens, keys, and generated runtime DNS state remain unstaged.

---

## 9. Remote/deployment verification

No remote test or deployment was performed. This is an explicit residual block, not an untested claim:

- `WORK_PROGRESS.md` identifies `ssh germ` as the **production** server with `/root/OutisCloud-hickory-dns`. It was not modified, deployed to, or used for destructive testing.
- Two other local SSH aliases were probed read-only and both failed host-key verification with `REMOTE HOST IDENTIFICATION HAS CHANGED`. The safe action was to stop; no `StrictHostKeyChecking=no` bypass was used.
- No repository documentation identifies a separate authorized test/staging host.
- No remote connection details were guessed, and no deployment/rebuild of the running production containers was attempted.
- The legacy `outiscloud-control-api` container was stopped only to free local port 8080 for the disposable stack. It is restored after the local run; the old DNS/API containers were not rebuilt or changed.

To finish remote validation, a genuinely non-production host must be identified with verified SSH host keys. That is the only missing external input.

---

## 10. Git status and commit state

- Base before this follow-up: `a6bcf9ad5` on top of `7ec82cf0f`; branch `main` has not been pushed.
- The platform-QA/analytics follow-up is committed locally as one clean commit with only:
  - `crates/control_api/src/tenants.rs` — reject unknown analytics ranges.
  - `crates/control_api/src/api_tests.rs` — range/interval tests and bounded overview query-count assertions.
  - `web/ui/tests/platform_qa.cjs` — repeatable fixtures, hot-reload update/delete checks, quota/member/transfer coverage, performance measurement, browser cleanup.
  - `TASK_STATUS.md` — this report.
- Explicitly not staged: `.env`, `env/api.env`, `env/db.env`, `deploy/dns/named.toml`, `deploy/dns/.orphaned/`, `WORK_PROGRESS.md`, the task prompt file.
- The follow-up commit was created locally with **no amend and no push**; this report is included in that commit. A docs-only correction records the final repository state.
- Before committing, `git diff --check` passed, the staged diff was inspected, and no secret or generated runtime file was included.

---

## 11. Remaining issues and next actions

1. **Remote validation remains blocked.** No safe test host with verified host keys was found; `germ` is production and the other aliases failed verification. Do not deploy to production to satisfy this check.
2. **Six `hickory-dns` integration tests fail for host-environment reasons.**
   - `named_metrics_tests::test_prometheus_endpoint_startup`
   - `named_tests::test_allow_networks_toml_startup`
   - `named_tests::test_deny_allow_networks_toml_startup`
   - `named_tests::test_deny_networks_toml_startup`
   - `named_tests::test_ipv4_and_ipv6_toml_startup`
   - `zone_file_reload::reload_on_zonefile_change`

   Observed causes: `Cannot assign requested address` for startup network-binding tests and `Too many open files` for the reload test. The targeted reload test passes when port 9000 is free; these are not changed-code assertion failures.
3. **Clippy is not warning-free with `-D warnings`.** `control_api` and dependency crates contain inherited warnings (dead code, style, missing docs). New warnings introduced by this work were removed; full cleanup would require unrelated refactoring.
4. **Performance is local-environment evidence only.** It validates the current implementation and dataset, not production capacity, network latency, or concurrent load.
5. **No production migration/deployment.** Schema changes remain idempotent startup DDL for a controlled deployment process.
6. **No functional platform blocker remains** for local validation; the earlier hot-reload block was stale binaries.

---

## 12. Architecture and runtime notes

- **Publication path:** API transaction updates zones/records/nameservers/georules, then generates zone files and `named.toml` under the configured DNS directory. A shared advisory lock serialises publication. The DNS process watches the directory and reloads.
- **Failure path:** the API keeps the last known-good file when generation fails; delete/rename compensate database state. The DNS integration test verifies reload behavior, and the backend test verifies a database failure does not wipe published zones.
- **Tenancy:** users get a personal tenant when needed; `tenant_members` roles are `owner`, `editor`, `viewer`; quotas are nullable (`NULL` = unlimited); admin users bypass tenant quotas. Zone ownership and explicit `zone_members` shares remain supported.
- **Analytics:** a leader-elected collector reads the Prometheus endpoint, stores deltas in `analytics_samples` and per-zone tables, and supports hourly rollups plus configurable retention. History has no FK to zones so it survives zone deletion.
- **Overview:** one tenant-scoped lateral query returns zones and record totals; customer responses add one bounded tenant-usage query. `limit` shortens only the returned list, never the totals.
- **Local QA stack:** `scripts/ui_stack.sh` starts the API, DNS, metrics stub, and Vite UI in `/tmp/opencode/platform-qa2`, using a disposable `outis_ui` database. It is not part of the committed change and is not a production deployment.
- **Ports used locally:** UI 5173, API 8080, DNS 5402, metrics stub 19100. The DNS integration test also uses fixed Prometheus port 9000, which required temporarily stopping the local DNS process for the targeted run.

---

## 13. Files changed

### Audit-remediation commit (`a6bcf9ad5`)

- `crates/control_api/src/main.rs` — auth/session flows, schema additions, zone transactions and publication, server CRUD, agent routes, audit, metrics, validation, application wiring.
- `crates/control_api/src/api_tests.rs` — regression coverage for corrected backend behavior, including API-04/API-05 tests and audit serialization assertions.
- `crates/control_api/src/db_pool.rs` — pool rewrite without `Box::leak`; `Arc<Client>` slots; inherent query helpers; test query counter.
- `crates/control_api/src/ext.rs` — MFA, pagination, audit listing, agent bundles/signing/authentication/authorization, publication status, trusted-proxy handling.
- `crates/control_api/src/tenants.rs` — tenant schema/quotas/analytics and database-error handling fixes.
- `crates/control_api/src/dnssec.rs` — key lifecycle and fail-closed key loading.
- `crates/control_api/src/zone_file_generator.rs` — bulk `generate_all` queries, generation safeguards, DNSSEC/GeoDNS conflict prevention.
- `crates/control_api/src/dns_builder.rs`, `dns_validator.rs`, `dns_manager.rs`, `metrics.rs`, `shared.rs` — supporting validation, publication, metrics, and independent cleanup changes.
- `crates/control_api/Cargo.toml`, `Cargo.lock` — added the existing workspace `toml` dependency for safe bundle filtering.
- `crates/agent/src/main.rs` — agent ID in `Hello`, bundle/ack/version handling, heartbeat behavior.
- `bin/src/lib.rs` — optional per-source DNS rate limiting and hot-reload support code; remaining changes are formatting.
- `bin/src/config/mod.rs`, `bin/tests/integration/in_memory.rs`, `bin/tests/integration/zone_file_reload.rs`, `crates/geodns/src/lib.rs`, `crates/proto/src/serialize/txt/zone_lex.rs`, `crates/server/src/zone_handler/catalog.rs`, `geodns.rs`, `mod.rs`, `swap.rs` — formatting in the remediation commit; `swap.rs` contains the tested per-source limiter used for GeoDNS/global resolution.
- `web/ui/src/api/client.js` — agent zone API calls and refresh-session persistence.
- `web/ui/src/hooks/useFormValidation.jsx` — IPv4/IPv6 validation.
- `web/ui/src/pages/Admin/Agents.jsx` — zone assignment modal and envelope handling.
- `web/ui/src/pages/Admin/Nameservers.jsx` — validation/error handling.
- `web/ui/src/pages/Admin/Servers.jsx` — in-place edit flow.
- `web/ui/src/pages/Admin/Users.jsx` — email field consistency.
- `web/ui/src/pages/Admin/Zones.jsx` — single nameserver fetch and derived labels.

### Platform-QA follow-up (this report's commit)

- `crates/control_api/src/tenants.rs` — explicit analytics range validation.
- `crates/control_api/src/api_tests.rs` — invalid range/interval regression and overview query-count assertions.
- `web/ui/tests/platform_qa.cjs` — repeatable fixture cleanup, browser cleanup, expanded hot-reload/tenant/quota/member/transfer coverage, performance measurement.
- `TASK_STATUS.md` — this updated report.

### Excluded from commits

- `.env`, `env/api.env`, `env/db.env` — runtime secrets/configuration.
- `deploy/dns/named.toml`, `deploy/dns/.orphaned/` — generated/runtime DNS state.
- `WORK_PROGRESS.md` — stale prior progress notes.
- `"# OutisCloud Hickory DNS — Audit Remedia.md"` — task prompt.
- No excluded source area (AUTH-05, DNS-02, Docker/Compose, CI/CD/Kubernetes, scripts/docs) was modified.

---

## 14. Reproduction commands

### Local platform stack

```bash
# Release binaries are required for representative performance measurements.
cargo build --release -p control_api -p hickory-dns

scripts/ui_stack.sh start /tmp/opencode/platform-qa2 \
  "$PWD/web/ui" "$PWD/target/release/control_api" "$PWD/target/release/hickory-dns" \
  "$TEST_POSTGRES_URL" outiscloud-db
source /tmp/opencode/platform-qa2/env.sh

export CHROMIUM_PATH=/home/outis/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome
export NODE_PATH="$PWD/web/ui/node_modules"
(cd web/ui && node tests/platform_qa.cjs)

scripts/ui_stack.sh stop /tmp/opencode/platform-qa2
```

`TEST_POSTGRES_URL` is a test-only PostgreSQL URL; never commit it. The stack creates the disposable `outis_ui` database and cleans only test-owned fixtures.

### Backend and frontend regression

```bash
TEST_DATABASE_URL="$TEST_POSTGRES_URL" cargo test -p control_api --bin control_api
cargo test -p control_agent
cargo test -p geodns
cargo test -p hickory-server
cargo fmt --all -- --check
(cd web/ui && npm run lint && npm run build)
```

### Targeted reload and persistence checks

```bash
# Stop anything listening on the integration test's fixed port 9000 first.
cargo test -p hickory-dns --test integration zone_file_reload -- --nocapture

# Backend tests use isolated schemas and clean them up.
TEST_DATABASE_URL="$TEST_POSTGRES_URL" \
  cargo test -p control_api --bin control_api \
  overview_is_one_accurate_tenant_scoped_query_and_scales database_failure_never_wipes_published_zones
```

---

## 15. Limitations and residual risks

- Platform QA ran against a local disposable stack with one PostgreSQL instance, one API instance, one DNS instance, and a deterministic metrics stub. It does not prove production throughput, HA behavior, geographic latency, or multi-replica contention.
- The 5,000-zone numbers are single-run local measurements; they are useful for regression detection but are not capacity guarantees.
- Six upstream `hickory-dns` integration tests remain limited by host network interfaces and file-descriptor budget. The targeted reload test passes when its port is free.
- Clippy remains warning-prone because of inherited code, not because of unhandled new lints.
- No safe remote test host was identified. Remote validation and remote deployment remain outstanding external actions.
- The production deployment is not updated by this work. Schema migrations are idempotent startup DDL and must be applied through the normal controlled deployment process.
- Browser tests are Chromium-based; cross-browser behavior was not re-proven in this pass.
- No production database, zone file, container, or server was modified.

---

## 16. Final verification checklist

- [x] Audit-remediation code committed locally in `a6bcf9ad5`.
- [x] Current source builds in debug and release configurations.
- [x] Control API: 140/140 tests pass against isolated PostgreSQL.
- [x] Agent: 6/6 tests pass.
- [x] GeoDNS: 19/19 tests pass.
- [x] Hickory server: 27/27 tests plus doctest.
- [x] Targeted zone-file reload test passes with its fixed port available.
- [x] Database-failure publication rollback test passes.
- [x] Frontend lint and production build pass.
- [x] Platform QA passes 96/96 on the release stack and repeats without stale-data failures.
- [x] Hot reload verified for zone creation, record update, and record deletion.
- [x] All 12 DNS lookup types plus NXDOMAIN/NODATA/empty input verified in the browser.
- [x] Tenant, quota, membership, analytics, authorization, overview, and transfer journeys verified.
- [x] 5,000-zone performance measured with average/p95/p99, UI timing, RSS, and cleanup.
- [x] Overview N+1 removed at browser-request and database-query-count levels.
- [x] Analytics samples survive a clean API restart.
- [x] Invalid analytics ranges/intervals rejected with `400`.
- [x] Test fixtures cleaned before and after platform runs.
- [x] No secrets or generated runtime state staged.
- [x] No push, amend, reset, or production deployment performed.
- [ ] Remote validation on an authorized non-production host — blocked; no safe host identified.
