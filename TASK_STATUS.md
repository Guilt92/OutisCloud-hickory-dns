# Task Status — Audit Remediation

**Repository:** `/home/outis/work-github/OutisCloud-hickory-dns`
**Branch:** `main`
**Base commit:** `7ec82cf0f feat(ui): redesign admin and customer consoles`
**Remediation state:** committed locally on top of the base commit; **not pushed**.
**Report basis:** current source, executed test suites, and captured logs. Prior documentation was not treated as proof of completion.

---

## 1. Executive summary

All confirmed in-scope code findings are implemented and covered by executed regression tests. The backend, agent, GeoDNS, and DNS-server crates build and test successfully within the supported environment. The frontend passes lint, production build, redesign, functional regression, accessibility, and visual-regression suites.

The only blocked end-to-end check is live DNS hot-reload through the already-deployed containers. The running API and DNS containers contain older binaries and were not rebuilt because Docker/Compose/deployment infrastructure is explicitly out of scope. That limitation is documented in section 9.

No production database migration was executed. Database-backed tests used isolated schemas in the test database.

---

## 2. Finding status

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
| Platform live DNS hot-reload journey | **BLOCKED — REQUIRES EXTERNAL ACTION** | Running containers are stale; see section 9 |
| Remote-environment test execution | **BLOCKED — REQUIRES EXTERNAL ACTION** | No usable remote connection details were available; not guessed |

---

## 3. Implemented fixes

### 3.1 Authentication and session security

- Added a persisted session generation (`users.token_version`) and a `ver` JWT claim. Access tokens are accepted only while their generation matches the database and they are not blacklisted.
- Password change and administrator password reset now update the password, bump `token_version`, and delete refresh-token sessions in one transaction.
- Refresh tokens are single-use and rotated under a row lock. Reuse of a rotated token revokes the entire session, including outstanding access tokens.
- MFA enable and disable bump the session generation and retire refresh sessions, so pre-change tokens cannot survive either transition.
- Logout bumps the generation, deletes all refresh sessions, and blacklists the presented access token.
- Legacy tokens without `ver` decode as generation `0`, matching existing rows.

### 3.2 Zone management and publication integrity

- Zone creation reserves quota, inserts the zone and default records, and inserts nameservers in one transaction; any failure rolls the whole operation back.
- Zone deletion marks the row `deleting`, publishes, then deletes. A failed publication restores the previous status and keeps the last known-good zone file.
- Zone rename compensates database changes when publication fails and reports `state_uncertain` if restoring the previous configuration also fails.
- Publication reports per-zone failures without overwriting valid files for unrelated zones. Publication is serialised across API instances with an advisory lock.
- DNSSEC key metadata and file contents are validated before any file is written. Missing/empty key files abort publication instead of downgrading a signed zone.
- A zone cannot be both DNSSEC-signed and GeoDNS-enabled; the API and generator reject that state.
- Nameserver and GeoRule inputs are validated server-side, including IPv4/IPv6 addresses and GeoDNS scoping rules.

### 3.3 Agent authorization and auditability

- Added `agent_zones`; an agent with no explicit assignment receives no zones.
- Agent bundle generation filters both the zone list and published configuration to the assigned domains. The TOML is parsed and rebuilt rather than string-spliced.
- Agent tokens use a SHA-256 fingerprint for the common verification path. Legacy agents without a fingerprint are verified with bounded Argon2 work, rate-limited per legacy source, and upgraded on success.
- Agent registration, heartbeat, bundle, acknowledgement, enable/disable, token rotation, deletion, and zone assignment are covered by backend checks. Bundle bodies are signed with a per-agent HMAC key.
- Server create, update, and delete emit audit entries with actor, action, resource type, resource ID, details, client IP, and timestamp. Audit details do not contain passwords, tokens, or key material.

### 3.4 API and backend correctness

- API-02: selected handlers now return `500` for database failures and only return `404` for genuinely missing resources.
- API-03: list pagination defaults to 100, clamps `limit` to `1..=1000`, normalises negative offsets to 0, and reports `X-Total-Count`.
- API-04: `generate_all` now performs one zones query, one records query, one georules query, one nameservers query, and one DNSSEC key query instead of per-zone queries. A test-only counter verifies the bound.
- API-05: legacy heartbeat verification checks at most eight rows for one address and applies a `20/60s` per-address bucket.
- API-06: rate-limit cleanup runs on an independent five-minute task, not only inside the analytics collector.
- API-07: `Box::leak` was removed. Pool slots hold `Arc<Client>`, and statements borrow a client that remains alive during reconnection.
- API-08: removed the dead duplicate audit-list path; the live endpoint paginates, filters, exports, retains, and serialises audit entries consistently.

### 3.5 Frontend and admin panel

- Users page sends and displays `email` consistently with the API.
- Servers page uses `PUT /api/v1/servers/{id}` and no longer creates duplicates on edit.
- Frontend IP validation now accepts valid IPv4/IPv6 and rejects malformed input, matching backend validation.
- Zones page loads nameservers once and derives per-zone labels in memory.
- Agent zone management unwraps the `{ success, data }` response envelope before rendering; the old code treated the envelope as an array.
- Existing routes, RBAC behavior, dialogs, pagination, filters, and design conventions were preserved.

---

## 4. Files changed

### Backend and shared crates

- `crates/control_api/src/main.rs` — auth/session flows, schema additions, zone transactions and publication, server CRUD, agent routes, audit, metrics, validation, application wiring.
- `crates/control_api/src/api_tests.rs` — regression coverage for every corrected backend behavior, including new API-04/API-05 tests and audit serialization assertions.
- `crates/control_api/src/db_pool.rs` — pool rewrite without `Box::leak`; `Arc<Client>` slots; inherent query helpers; test query counter.
- `crates/control_api/src/ext.rs` — MFA, pagination, audit listing, agent bundles/signing/authentication/authorization, publication status, trusted-proxy handling.
- `crates/control_api/src/tenants.rs` — tenant schema/quotas/analytics and database-error handling fixes.
- `crates/control_api/src/dnssec.rs` — key lifecycle and fail-closed key loading.
- `crates/control_api/src/zone_file_generator.rs` — bulk `generate_all` queries, generation safeguards, DNSSEC/GeoDNS conflict prevention.
- `crates/control_api/src/dns_builder.rs`, `dns_validator.rs`, `dns_manager.rs`, `metrics.rs`, `shared.rs` — supporting validation, publication, metrics, and independent cleanup changes.
- `crates/control_api/Cargo.toml`, `Cargo.lock` — added the existing workspace `toml` dependency for safe bundle filtering.
- `crates/agent/src/main.rs` — agent ID in `Hello`, bundle/ack/version handling, heartbeat behavior.
- `bin/src/lib.rs` — optional per-source DNS rate limiting and hot-reload support code; remaining changes in this file are formatting.
- `bin/src/config/mod.rs`, `bin/tests/integration/in_memory.rs`, `bin/tests/integration/zone_file_reload.rs`, `crates/geodns/src/lib.rs`, `crates/proto/src/serialize/txt/zone_lex.rs`, `crates/server/src/zone_handler/catalog.rs`, `geodns.rs`, `mod.rs`, `swap.rs` — formatting in the remediation commit; `swap.rs` contains the tested per-source limiter used for GeoDNS/global resolution.

### Frontend

- `web/ui/src/api/client.js` — agent zone API calls and refresh-session persistence.
- `web/ui/src/hooks/useFormValidation.jsx` — IPv4/IPv6 validation.
- `web/ui/src/pages/Admin/Agents.jsx` — zone assignment modal and envelope handling.
- `web/ui/src/pages/Admin/Nameservers.jsx` — validation/error handling.
- `web/ui/src/pages/Admin/Servers.jsx` — in-place edit flow.
- `web/ui/src/pages/Admin/Users.jsx` — email field consistency.
- `web/ui/src/pages/Admin/Zones.jsx` — single nameserver fetch and derived labels.

### Excluded from the commit

- `.env`, `env/api.env`, `env/db.env` — runtime secrets/configuration; not staged.
- `deploy/dns/named.toml`, `deploy/dns/.orphaned/` — generated/runtime DNS state; not staged.
- `WORK_PROGRESS.md` — stale prior progress notes; not modified or staged.
- `"# OutisCloud Hickory DNS — Audit Remedia.md"` — task prompt; not staged.
- No excluded source file (AUTH-05, DNS-02, Docker/Compose, CI/CD/Kubernetes, scripts/docs) was modified.

---

## 5. Database changes

All application schema updates are idempotent startup DDL in `migrate_db` and module schemas. No production migration was run.

- `users`: `totp_secret`, `totp_enabled`, `token_version`, `email`; unique case-insensitive email index.
- `token_blacklist`: `token_type`, `session_id`, `rotated_at`, `replaced_by_hash`; hash/session indexes. Existing rows are migrated once to `token_type = 'refresh'` where they represented refresh sessions.
- `agents`: `applied_version`, `last_ack_at`, `last_error`, `sync_requested`, `last_seen_ip`, `token_sha256`; token fingerprint index.
- `zones`: `status`, `verify_token`, `verified_at`, `ecs_enabled`, `dnssec_enabled`, `tenant_id`.
- `records`: legacy `type` renamed/handled as `record_type`; the old `(zone_id, name, record_type)` unique constraint is dropped so valid multi-record RRsets are allowed while exact duplicates remain guarded.
- New tables: `zone_members`, `zone_revisions`, `dnssec_keys`, `agent_zones`, `publish_state`, `tenants`, `tenant_members`, `analytics_samples`, `zone_query_samples`, `zone_qtype_samples`, `zone_country_samples`, `tenant_usage_samples`, `shared_rate_limits`, `collector_lease`, `collector_state`.
- Compatibility: existing zones default to `active`, existing users default to session generation 0, legacy agents without fingerprints continue through the bounded upgrade path, and existing rows are never deleted by the migration.

---

## 6. Tests executed

### Backend and libraries

| Command | Result |
|---|---|
| `cargo test -p control_api --bin control_api` with isolated `TEST_DATABASE_URL` | **140 passed, 0 failed** (65.11s) |
| `cargo test -p control_agent` | **6 passed, 0 failed** |
| `cargo test -p geodns` | **19 passed, 0 failed** |
| `cargo test -p hickory-server` | **27 passed, 0 failed**, plus 1 doctest |
| `cargo test -p hickory-dns --test integration` | **99 passed, 6 failed** — environment failures (section 9) |
| `cargo fmt --all -- --check` | **passed** |
| `cargo clippy -p control_api -p control_agent --all-targets --no-deps` | completed; inherited warnings remain (section 9) |
| `cargo check -p control_api` | **passed** |

The control API run includes the focused regressions for AUTH, ZONE, DNS, E-02/E-03, API-01 through API-08, tenant isolation, quota concurrency, real DNS lookup, metrics authorization, and UI-facing serialization.

### Frontend

| Command | Result |
|---|---|
| `npm run lint` | **passed** |
| `npm run build` | **passed** (Vite production build) |
| `node tests/redesign_qa.cjs` | **368/368 passed** |
| `node tests/audit_ui_regression.cjs` | **50/50 passed** after test-data cleanup |
| `node tests/a11y_visual_qa.cjs a11y` | **9 passed, 0 failed**; zero axe violations |
| `node tests/a11y_visual_qa.cjs visual` | **28 passed, 0 failed**; all baselines `0.000%` |
| `node tests/a11y_visual_qa.cjs selftest` | **2/2 passed** |
| Agent modal browser check with intercepted agent-zone route | **PASS** — modal lists zones and saves the selected zone |
| `node tests/platform_qa.cjs` | **BLOCKED** at live DNS hot-reload assertion; see section 9 |

Evidence logs are in `/tmp/opencode/` (for example `control-api-full-final2.log`, `clippy-control-final2.log`, `redesign-final2.log`, `audit-ui-final2.log`, `a11y-final.log`, `visual-final.log`, `agent-modal-qa.log`, `hickory-dns-tests.log`).

---

## 7. Security impact

- **Session revocation:** password changes, administrator resets, MFA transitions, and logout now invalidate access tokens through the persisted session generation, not only through the current process's state.
- **Refresh-token replay:** rotation is transactional and one-time; replay revokes the session and its access tokens.
- **Agent isolation:** assignment is explicit; bundles are filtered and signed; unassigned agents receive no zones; legacy verification work is bounded and rate-limited.
- **Publication integrity:** DNSSEC failures cannot silently downgrade a signed zone; failed deletes/renames preserve or restore the last known-good configuration.
- **Error handling:** database failures no longer masquerade as missing resources.
- **Audit:** mutations record actor/action/resource/details/IP/time without credentials or key material.
- **Rate limiting:** login is bounded per username and per client; legacy agent heartbeat work is bounded per address; DNS resolution has an optional per-source limiter covering GeoDNS.
- **No secret exposure:** `.env`, `env/*.env`, tokens, keys, and generated runtime DNS state remain unstaged.

---

## 8. Excluded areas

Confirmed not modified:

- AUTH-05 (HTTP/TLS, reverse proxy, HSTS/CSP/Referrer-Policy, public ports/firewall).
- DNS-02 (DNS-over-TLS, port 853, TLS certificates/listeners).
- Dockerfiles, Docker Compose, container networking, deployment infrastructure.
- CI/CD, GitHub Actions, Helm, Kubernetes manifests, deployment pipelines.
- Shell scripts, operational scripts, README, existing documentation, deployment instructions.

`TASK_STATUS.md` is the only documentation file changed, as required by the task.

---

## 9. Unresolved items and residual risks

1. **Live platform hot-reload test is blocked by stale deployed containers.**
   `platform_qa.cjs` failed at `FAIL lookup: the real DNS server picked the new zones up (hot reload)`, then `FAIL lookup UI A`, and the browser closed fatally at `web/ui/tests/platform_qa.cjs:116:16`. The running API (`/usr/local/bin/control_api`) and DNS containers are older binaries; the API container does not expose the new agent-zone endpoint. Rebuilding/restarting those containers is a deployment-infrastructure action and is explicitly out of scope. The backend endpoint and the UI modal were verified separately with integration tests and browser route interception.

2. **Six `hickory-dns` integration tests fail for host-environment reasons.**
   - `named_metrics_tests::test_prometheus_endpoint_startup`
   - `named_tests::test_allow_networks_toml_startup`
   - `named_tests::test_deny_allow_networks_toml_startup`
   - `named_tests::test_deny_networks_toml_startup`
   - `named_tests::test_ipv4_and_ipv6_toml_startup`
   - `zone_file_reload::reload_on_zonefile_change`

   Observed causes: `Io(Os { code: 99, kind: AddrNotAvailable, message: "Cannot assign requested address" })` for startup network-binding tests and `failed to create file watcher: Too many open files (os error 24)` for the reload test. These are environment/resource limits, not assertion failures in the changed code. They require a host with the expected network interfaces/file-descriptor budget to execute cleanly.

3. **Clippy is not warning-free with `-D warnings`.**
   `control_api` and dependency crates contain inherited warnings (dead code, complex types, style lints, missing docs). Warnings introduced by this work were removed; a full warning cleanup would require unrelated refactoring outside the remediation scope. `cargo clippy` itself completes and the affected binary/tests compile.

4. **Remote-environment execution was not performed.**
   No usable SSH/scp connection details were located, and none were guessed. No remote deployment or remote test was attempted.

5. **Frontend new-endpoint integration with the real running API was not possible.**
   This is a consequence of item 1. The current UI code is covered by lint/build, browser suites for existing routes, and a mocked agent-zone integration test; the backend endpoint is covered against a real PostgreSQL test database.

---

## 10. Regression assessment

- Backend: 140/140 control API tests, 6/6 agent tests, 19/19 GeoDNS tests, and 27/27 server tests pass.
- DNS core: 99/105 integration tests pass; all six failures are attributable to host address/file-watcher limits.
- Frontend: lint and production build pass; redesign, regression, accessibility, and visual suites pass with zero axe violations and zero visual diffs.
- No existing zone data or production schema was modified by the tests; database-backed tests used isolated schemas and test artifacts were cleaned up.
- Main residual risk is deployment drift: the running containers are older than the source, so live hot-reload and new-endpoint end-to-end behavior still require a controlled rebuild/restart in an environment where deployment infrastructure changes are permitted.
