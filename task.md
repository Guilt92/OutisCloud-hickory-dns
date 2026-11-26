# OutisCloud DNS Platform — Benchmark, Architecture Assessment, and Multi-Phase Roadmap

> **Further execution evidence, 2026-11-24:** CORE-006 query logging now supports level and sampling controls and redacts DEBUG/error paths; focused tests pass. ZONE-003 clone rewriting preserves TXT text while rewriting zone-local DNS targets; a unit test and isolated PostgreSQL clone integration test pass. ZONE-003 remains partial because built-in templates and NS/DNSSEC clone acceptance tests are absent. See the current entries in §20 and `TASK_STATUS.md`.
> **SEC-005 progress:** UI Nginx now sends a CSP; syntax and live-header tests pass in a disposable container. A Playwright browser check now confirms an injected inline script is blocked by the served CSP. Secure cookies and token-storage migration remain, so the task is PARTIALLY COMPLETED.
> **germ read-only DNS validation:** Independent `dig` queries for the hosted `uid0.ir` SOA returned authoritative NOERROR over UDP and TCP with matching serial `2026111900`; a TCP AXFR request was REFUSED. No local change was deployed to germ.
> **Helm packaging progress:** The chart now renders control API, DNS server, and UI Deployments/Services/Ingress with shared pre-provisioned RWX zone storage, DNS health/readiness probes, generated ConfigMaps, and a release-specific UI proxy. Helm lint/render and rendered-resource checks pass. CORE-004 and OPS-002 remain PARTIALLY COMPLETED until cluster-level probe, RWX, Secret, image, and rollout validation succeeds; agent/DB templates are not included.
> **Current corrected counts:** see the authoritative execution ledger at the end of this file. Earlier status summaries are historical.

> **Execution evidence, 2026-11-24:** API-010 remains COMPLETED. The frontend contract check validates 83 method/path pairs against registered Rust routes. `germ` is a test environment. The authoritative current status, test, blocker, and delivery record is the execution ledger at the end of this file.

> **Current implementation status:** see §19 below. Earlier sections remain the canonical requirements and historical roadmap.

**Repository:** `/home/outis/work-github/OutisCloud-hickory-dns`
**Assessment date:** 2026-11-19
**Code baseline:** `a028a360c` (`docs: record final platform QA commit state`)
**Scope:** research, benchmarking, architecture assessment, and planning only. No feature implementation is included or authorized by this document.
**Reference product:** Cloudflare DNS, used as an engineering and product-design reference, not as a template to clone.

> **Evidence rule.** A feature is marked implemented only when current code and executed behavior support it. A route, database column, UI control, or proposal document is not proof by itself. The execution ledger at the end of this file is the sole task-status and delivery record. Historical assessment material is retained for provenance.

---

## 1. Executive Summary

OutisCloud is already a working, single-region, primary-authoritative DNS platform. It combines a forked Hickory DNS server with a Rust/Actix control API, PostgreSQL, a React/Vite console, signed agent bundles, GeoDNS/ECS, DNSSEC signing, tenant quotas, zone history, persistent analytics, and a substantial automated test suite. The strongest parts are the primary-zone CRUD path, atomic file publication with last-known-good preservation, authentication/session revocation, tenant-scoped API authorization, signed agent distribution, and end-to-end browser coverage.

It is not yet a production-grade authoritative DNS platform for multiple replicas, secondary DNS, large write volumes, enterprise operations, or disaster recovery. The most important gaps are:

1. **No real secondary DNS or standards-complete zone transfer path.** AXFR is partial and single-message, IXFR and NOTIFY are absent, secondary zones are configuration labels, and TSIG/SIG(0) support is incomplete.
2. **Publication scales with total data.** Every mutation regenerates all zones synchronously; transaction concurrency is serialized through one reserved connection; cluster publication relies on a best-effort advisory lock and a shared writable zone directory.
3. **Transport and secret custody are not production-hardened.** The API has no native TLS, PostgreSQL uses `NoTls`, MFA secrets and DNSSEC private keys are not encrypted, the JWT secret is a single trust anchor, and live-looking secrets are tracked in Git.
4. **Recovery is incomplete.** There is no product backup/restore, no DNSSEC key backup workflow, no PITR, no restore drill, and no documented RPO/RTO.
5. **The automation ecosystem is thin.** No scoped API tokens, idempotency keys, webhooks, OpenAPI contract, SDK/CLI, API-wide quotas, or async job model.
6. **Operational artifacts are not trustworthy.** CI action references are invalid, database tests skip in CI, Helm/Kubernetes manifests are incomplete or inconsistent, monitoring scrape targets are wrong, alert rules are not loaded, and status documents contradict each other.
7. **Several UI controls promise behavior the backend does not provide.** Multi-zone bulk import calls a nonexistent endpoint, secondary-zone controls are rejected, certificate/server-lifecycle client methods are dead, and permission affordances are not consistently enforced in the UI.

The feature matrix in §7 assesses **130 capabilities**: **25 implemented and verified, 55 implemented but incomplete, 2 implemented but unverified, 45 not implemented, 2 requiring architectural review, and 1 not applicable**. The roadmap defines **13 phases (0–12)** and **133 implementation tasks** (34 P0, 60 P1, 29 P2, 10 P3) with stable IDs, dependencies, measurable acceptance criteria, and test requirements. The recommended long-term direction is an API-first, multi-tenant authoritative DNS platform for operators and managed-service providers, built on the existing Hickory engine and control plane — not a clone of Cloudflare's proxy/CDN/recursive-resolver business.

**Highest-priority next steps:** fix the publication and consistency contract; decide the secondary/transfer product scope; close the security baseline (secrets, TLS, key custody); repair the operational artifacts; and add scoped automation APIs before scaling the control plane.

---

## 2. Research Methodology and Sources

### 2.1 Method

The assessment used five evidence classes:

1. **Source inspection.** Read-only inspection of the workspace, control API routes and migrations, DNS server stores and handlers, agent protocol, GeoDNS engine, frontend routes/components, deployment files, tests, and status documents.
2. **Independent read-only audits.** Four audit reports covered the control plane, DNS engine, frontend/API wiring, and documentation/deployment/test state. Their claims were checked against current code; two stale claims were corrected (shared login rate limiting and the record RRset unique index).
3. **Executed evidence.** `control_api` 140/140, platform QA 96/96, UI redesign 368/368, accessibility 9/9, visual regression 28/28, hickory integration 99 passed with 6 environment-limited failures, and `cargo fmt --all -- --check` passing. Database tests require `TEST_DATABASE_URL` and skip when it is absent.
4. **Primary documentation research.** Official Cloudflare documentation and primary documentation for BIND 9, Knot DNS, PowerDNS, Amazon Route 53, Google Cloud DNS, Azure DNS, OctoDNS, DNSControl, and Zonemaster.
5. **Verification and reconciliation.** Cross-checking frontend routes against backend routes, schema/runtime DDL against tests, audit findings against current source, and status claims against Git and logs.

### 2.2 Classification labels

| Label | Meaning |
|---|---|
| **Verified fact** | Directly observed in current source, executed tests/logs, or primary documentation. |
| **Inference** | A technical conclusion drawn from verified facts; may need a focused test to become a verified fact. |
| **Recommendation** | Engineering or product advice; not a statement that the capability exists or is required. |
| **Assumption** | A planning input that must be confirmed before implementation. |
| **Not applicable** | A Cloudflare-specific capability that does not belong in an authoritative DNS hosting product without a separate architecture decision. |

### 2.3 Source limitations

- Cloudflare documentation describes Cloudflare's managed service; it does not disclose all internal implementation details, pricing, or enterprise controls. Cloudflare-specific anycast, proxy, registrar, and enterprise-hold behavior is therefore not treated as a requirement.
- Some vendor documentation is JavaScript-heavy or access-restricted; findings are limited to content retrieved and cited.
- No production or third-party environment was accessed. Remote validation is blocked because `germ` is documented as production and other SSH aliases failed host-key verification. Public delegation, resolver behavior, and production capacity remain externally unverified.
- Local performance evidence uses a 4-vCPU, 7.9 GB single-host setup with the load generator sharing CPU. It validates the implementation, not production capacity.

---

## 3. Cloudflare DNS Feature Inventory

Cloudflare is useful because it exposes the operational shape of a mature DNS product: safe zone lifecycle, large-scale record management, DNSSEC, transfer/secondary setups, load balancing, analytics, auditability, and automation. The inventory below separates generally applicable DNS-platform capability from Cloudflare-specific service categories.

### 3.1 DNS management

| Capability | What it solves | Evidence | Applicability to OutisCloud |
|---|---|---|---|
| Zone lifecycle, activation, status, and deletion | Prevents serving a zone before delegation/verification and makes destructive operations explicit. | Cloudflare DNS docs; zone holds docs | Required. OutisCloud has primary CRUD but no hold/archive lifecycle. |
| Record CRUD and validation | Rejects malformed or conflicting DNS data before publication. | Cloudflare record docs | Required. Core is implemented; advanced types and attributes are partial. |
| Supported record types | Covers normal hosting and modern HTTPS/SVCB service binding. | Cloudflare record-types reference | Required for common types; advanced types are P2/P3. |
| Bulk record operations | Makes large migrations and fleet changes practical. | Cloudflare import/export docs | Required. Per-zone JSON import exists; BIND/CSV and multi-zone bulk are missing or broken. |
| Zone import/export | Enables migration, backup, and provider interchange. | Cloudflare import/export: 256 KiB zone-file limit and 3 import requests/minute/user | Required with explicit limits, dry-run, and partial-error reporting. OutisCloud exports generated zone files and imports JSON only. |
| Zone templates | Reduces repeated configuration and errors for similar zones. | Cloudflare product docs; general industry practice | Advanced P2. Not implemented. |
| Record comments and tags | Supports ownership, automation metadata, and filtering without changing DNS data. | Cloudflare record attributes | P2. Requires schema and API design; not implemented. |
| Record change history and rollback | Recovers from successful-but-wrong changes, not only failed publication. | Cloudflare audit/history; industry practice | Required. OutisCloud has revisions and restore, but snapshots are record-only and retention/diff UX is limited. |
| Publication status and propagation | Distinguishes database success from authoritative serving success. | Cloudflare DNS/audit docs; OutisCloud publication code | Required. OutisCloud has publication status and last-known-good files, but no end-to-end replica freshness proof. |
| Proxy/orange-cloud behavior | Cloudflare-specific reverse proxy and WAF integration. | Cloudflare proxy docs | **Not applicable** to an authoritative hosting product. Do not copy. |

### 3.2 DNS infrastructure

| Capability | What it solves | Evidence | Applicability |
|---|---|---|---|
| Authoritative query serving over UDP/TCP | Baseline DNS service. | Cloudflare DNS; RFC 1035/7766 | Required; implemented. |
| Multi-region/anycast distribution | Low latency and resilience to regional failure. | Cloudflare network/architecture docs | Long-term P3; requires architecture and capital, not a UI feature. |
| Primary/secondary topology | Independent authoritative replicas and delegated secondary service. | Cloudflare zone setups; BIND/Knot/PowerDNS docs | Required for professional maturity; absent in OutisCloud control plane. |
| AXFR/IXFR and NOTIFY | Standards-based zone replication and change propagation. | RFC 5936/1995/1996; Cloudflare zone-transfer docs | Required. AXFR is partial; IXFR/NOTIFY absent. |
| TSIG and SIG(0) | Authenticates transfers and dynamic updates. | RFC 8945/2931; BIND/Knot docs | Required for transfers; TSIG partial, SIG(0) absent. |
| DNSSEC signing and DS publication | Answer integrity and delegation trust. | Cloudflare DNSSEC; RFC 4033-4035 | Required; core signing and DS output implemented. |
| Multi-signer DNSSEC | Multiple operators can sign one zone during migrations/redundancy. | Cloudflare multi-signer docs | Advanced P3; architecture-heavy. |
| Caching and TTL behavior | Correct negative caching and resolver behavior. | RFC 2308; Cloudflare docs | Required at authoritative TTL level; recursive caching is a different product category. |
| Health checks and failover | Removes unhealthy targets from answers. | Cloudflare LB/health-check docs | Advanced P2; absent in authoritative serving tier. |
| Disaster recovery | Restores service after data, key, or region loss. | Industry standard; Cloudflare resilience material | Required for production; absent as a product capability. |

### 3.3 Security

| Capability | What it solves | Evidence | Applicability |
|---|---|---|---|
| DNSSEC validation | Protects resolvers from forged answers. | RFC 4033-4035; Cloudflare DNSSEC | Resolver/forwarder feature; engine has trust-anchor validation, but this is not a hosting differentiator. |
| API tokens with scopes and expiry | Least-privilege automation without sharing user sessions. | Cloudflare API tokens | Required P1. Not implemented. |
| RBAC and team permissions | Separates platform, account, zone, and read-only duties. | Cloudflare roles/permissions docs | Required. Basic roles and zone sharing exist; custom/granular roles absent. |
| Audit logs | Forensic traceability and change accountability. | Cloudflare Audit Logs v2 | Required. Partial coverage/list, no detail/tamper evidence. |
| Rate limiting and abuse prevention | Protects auth, APIs, and authoritative service. | Cloudflare API limits and DDoS docs | Required. Login limits exist; API-wide/tenant quotas and DNS abuse controls are partial. |
| Zone holds and change protection | Prevents accidental or malicious zone deletion/transfer. | Cloudflare zone holds (Enterprise) | Advanced P2. Not implemented; do not assume Enterprise semantics are required. |
| Account/session security | MFA, recovery, revocation, token rotation. | Cloudflare account security docs | Required. Core session revocation exists; MFA recovery/secrets and SSO absent. |
| DDoS/anycast scrubbing | Cloudflare-specific global network defense. | Cloudflare DDoS docs | **Not applicable** as a direct copy; outsource or architect separately. |

### 3.4 Advanced DNS and traffic

| Capability | What it solves | Evidence | Applicability |
|---|---|---|---|
| GeoDNS and ECS | Location-aware answers without breaking resolver caching. | Cloudflare LB/Geo steering; RFC 7871 | Implemented in limited form; City data and signed-zone compatibility are gaps. |
| Load balancing pools and monitors | Selects healthy origins and supports failover. | Cloudflare LB quickstart | Advanced P2; absent. |
| Steering policies | Standard, geo, dynamic, proximity, least-outstanding-requests. | Cloudflare steering-policies docs | Advanced P2/P3; requires a policy model, health data, and observability. |
| Weighted records | Gradual migration and capacity distribution. | Cloudflare/Route 53/NS1 docs | P2; absent in authoritative tier. |
| Failover | Removes failed targets. | Cloudflare LB health checks | P2; absent. |
| Dynamic DNS / RFC 2136 updates | Programmatic record mutation and dynamic endpoints. | RFC 2136; BIND/Knot docs | Partial: SQLite-only, TSIG-required, no file-store update. REST CRUD is not a substitute. |
| DoH/DoT/DoQ/DoH3 | Encrypted client transport. | RFC 8484/7858/9250; Cloudflare docs | P1/P2 for authoritative service; feature-gated server support exists, DoH3 binary path missing. |
| Advanced routing policies | Proximity/dynamic decisions from live signals. | Cloudflare steering docs | P3; not appropriate before health and analytics foundations. |

### 3.5 Analytics and monitoring

| Capability | What it solves | Evidence | Applicability |
|---|---|---|---|
| Query volume and trends | Capacity planning and customer reporting. | Cloudflare analytics | Required. Per-zone metrics and persistent history exist. |
| RCODE/NXDOMAIN/SERVFAIL breakdown | Detects misconfiguration and attacks. | Cloudflare analytics | Required. Exporter has counters; historical/event analytics are incomplete. |
| Latency/response-time measurement | Detects degradation and SLO violations. | Cloudflare analytics | P1/P2; no authoritative latency history. |
| Geographic distribution | Routing validation and abuse detection. | Cloudflare analytics | Partial country metrics; City data absent. |
| Zone/account analytics | Tenant and customer visibility. | Cloudflare analytics | Core implemented; export and scale retention incomplete. |
| Alerts and notifications | Turns metrics into action. | Cloudflare notifications; Prometheus practice | Required operationally; Alertmanager/rules not deployed. |
| Query logs/streaming | Deep troubleshooting and SIEM integration. | Cloudflare logs; enterprise DNS practice | P2; absent and privacy-sensitive. |

### 3.6 API and automation

| Capability | What it solves | Evidence | Applicability |
|---|---|---|---|
| Zone/record REST APIs | Infrastructure automation. | Cloudflare API | Implemented for primary zones. |
| Scoped tokens and auth | Least privilege for automation. | Cloudflare API tokens | Required; absent. |
| Pagination and consistent errors | Scales and makes clients reliable. | Cloudflare API reference | Partial; offset pagination is inconsistent and error envelopes vary. |
| Bulk operations | Fleet changes. | Cloudflare API | Partial; per-zone JSON import only. |
| Idempotency | Safe retries after timeouts. | Industry API practice | Required; absent. |
| Rate limits | Fair use and abuse resistance. | Cloudflare global API limit: 1,200 requests/5 minutes/user | Required; no API-wide/tenant quotas. |
| Webhooks/events | Decoupled automation and notifications. | Cloudflare notifications/events | Advanced P2; absent. |
| OpenAPI/SDK/CLI | Client integration and contract testing. | Cloudflare API ecosystem | Required P1/P2; absent. |

### 3.7 User experience and product design

Cloudflare's dashboard organizes work around account → zone → DNS records, with status, analytics, security, and rules adjacent to the zone. The transferable principles are:

- Zone state must be visible before destructive actions.
- Record edits need validation, review, and safe undo.
- Bulk operations need previews, limits, and per-row errors.
- Permissions should hide or disable actions the user cannot perform.
- Analytics must be honest about missing data rather than showing fabricated or empty-success states.
- Account-level and zone-level settings must be clearly separated.
- Activity history must be searchable and exportable server-side.

**Recommendation:** keep OutisCloud's simpler admin/customer split and existing visual language. Add information architecture and safety patterns, not Cloudflare's navigation or branding.

---

## 4. Operational Lessons and Engineering Insights

### Lesson 1 — Database success is not DNS publication success

- **Problem:** A control-plane write can commit while zone generation or replica application fails.
- **Why it matters:** Customers see a successful API response while the authoritative server serves old data.
- **Mechanism:** Transactional outbox/publication queue, explicit publication state, per-zone generation status, replica acknowledgements, and retry with last-known-good files.
- **OutisCloud state:** Partial. Creation/delete/rename have compensating logic; record update/delete can commit and return `publish_failed`; a best-effort advisory lock does not guarantee cross-replica ordering.
- **Recommendation:** Make publication a first-class state machine with idempotent jobs and observable convergence (ARCH-002, CORE-013, PERF-001).

### Lesson 2 — Full regeneration becomes a throughput ceiling

- **Problem:** Every write reads all zones, records, nameservers, GeoRules, and DNSSEC metadata and rewrites all output.
- **Why it matters:** Write latency grows with total tenant data, startup takes about 106 seconds for 5,000 zones, and large customers create backpressure for everyone.
- **Mechanism:** Per-zone dependency tracking, debounced/incremental publication, queue workers, and independent verification.
- **OutisCloud state:** Synchronous full regeneration confirmed in `dns_manager.rs` and `zone_file_generator.rs`.
- **Recommendation:** Queue plus incremental generation before scaling write volume.

### Lesson 3 — Record identity needs a database invariant, not only a pre-check

- **Problem:** Concurrent create requests can both pass an application duplicate check.
- **Why it matters:** Duplicate RRset rows produce ambiguous zone files and inconsistent counts.
- **Mechanism:** Database uniqueness on zone/name/type/value plus transactional mutation.
- **OutisCloud state:** A unique index `uq_records_rrset_value` exists in current runtime DDL; the earlier audit claim that no database guard exists is outdated. The runtime/migration drift still needs reconciliation.
- **Recommendation:** Keep the invariant, test migration parity, and make update/delete publication-atomic.

### Lesson 4 — DNSSEC failures are outages, not cosmetic errors

- **Problem:** Missing/invalid keys, wrong DS records, or unsupported algorithms cause validation failures across the Internet.
- **Why it matters:** DNSSEC failures are often total for validating resolvers and can persist in caches.
- **Mechanism:** Key custody, staged rollover, DS verification, negative tests, and fail-closed publication.
- **OutisCloud state:** Signing and DS output verified end-to-end; fail-closed behavior tested; no KMS, automatic rollover, CDS/CDNSKEY, DS monitoring, or backup.
- **Recommendation:** Treat key custody and rollover as a security program (Phase 3).

### Lesson 5 — Import/export needs explicit limits and dry-run behavior

- **Problem:** Large or malformed zone files can exhaust memory or partially apply.
- **Why it matters:** Migration is a high-risk, high-volume operation.
- **Mechanism:** Size limits, streaming, dry-run, atomic apply, per-row errors, and rate limits. Cloudflare documents a 256 KiB zone-file limit and 3 import requests/minute/user for its zone-file flow.
- **OutisCloud state:** Per-zone JSON import is all-or-nothing with a 5,000-record limit; no BIND parser, preview, or multi-zone route.
- **Recommendation:** Build a migration-grade import/export pipeline (Phase 2).

### Lesson 6 — Secondary DNS is a protocol product, not a zone-type label

- **Problem:** A secondary must refresh from a primary, authenticate transfers, receive NOTIFY, and serve consistent SOA serials.
- **Why it matters:** Operators need independent replicas and delegated secondary service.
- **Mechanism:** AXFR/IXFR client/server, NOTIFY, TSIG, SOA timers, transfer ACLs, and observability.
- **OutisCloud state:** `ZoneType::Secondary` exists, but there is no refresh/AXFR client/NOTIFY receiver; AXFR is partial single-message; IXFR absent.
- **Recommendation:** Decide scope explicitly. If implemented, replace the label with a complete protocol path (Phase 4).

### Lesson 7 — Tenant isolation must be enforced at every layer

- **Problem:** A single missing scope check leaks zones, records, analytics, or audit data.
- **Why it matters:** Multi-tenant DNS is a high-impact isolation boundary.
- **Mechanism:** Central authorization choke points, tenant-scoped queries, negative tests, and audit trails.
- **OutisCloud state:** Strong API scoping and zone membership checks; DNS serving is zone-file based; quotas have a check-then-insert race.
- **Recommendation:** Add cross-tenant property tests and quota transaction tests (Phase 8).

### Lesson 8 — Rate limits must be shared and layer-specific

- **Problem:** Per-process limits multiply across replicas; plain TCP bypass can be abused; API-wide quotas are absent.
- **Why it matters:** Brute force, scraping, and DNS amplification remain possible.
- **Mechanism:** Shared counters, per-identity/per-tenant quotas, protocol-aware limits, and response-rate limiting.
- **OutisCloud state:** Login rate limiting is shared via `shared::limited` with an in-process fallback; DNS limiter is per-process and plain TCP exempt; no API-wide quotas.
- **Recommendation:** Define budgets per endpoint/identity and centralize enforcement (Phase 9).

### Lesson 9 — Observability must answer “is the data actually served?”

- **Problem:** Process up and database reachable do not prove zone freshness or replica convergence.
- **Why it matters:** Silent staleness is worse than a visible outage.
- **Mechanism:** Publication age, per-zone serial, replica applied version, query RCODEs, and synthetic DNS probes.
- **OutisCloud state:** `/health` is always OK; `/ready` checks only DB; DNS server has no health endpoint; metrics scrape config targets the wrong port; alerts are not loaded.
- **Recommendation:** Add publication-aware readiness and end-to-end DNS probes (Phase 6 and Phase 10).

### Lesson 10 — Recovery must be rehearsed

- **Problem:** Backups that are never restored are assumptions, not recovery.
- **Why it matters:** DNSSEC key loss can be unrecoverable; database loss can erase all tenants.
- **Mechanism:** PITR, encrypted key backup, restore drills, documented RPO/RTO, and incident runbooks.
- **OutisCloud state:** Zone revisions exist; no product backup/restore, no DNSSEC key backup, no PITR or drills.
- **Recommendation:** Make backup/restore a release blocker (Phase 12).

### Lesson 11 — UI truthfulness is a security property

- **Problem:** Controls that cannot succeed train users to ignore errors and hide authorization gaps.
- **Why it matters:** False affordances cause operational mistakes and support load.
- **Mechanism:** Permission-aware rendering, route-contract tests, honest empty/error states, and feature flags.
- **OutisCloud state:** Bulk-zone import 404s, secondary controls are rejected, several client methods have no backend, disabled servers appear as failures, and audit search is page-local.
- **Recommendation:** Add UI/API contract tests and remove dead controls until implemented (ARCH-004, Phase 11).

### Lesson 12 — API reliability requires idempotency and stable contracts

- **Problem:** Retries after timeouts duplicate creates or produce ambiguous state.
- **Why it matters:** DNS automation is often unattended.
- **Mechanism:** Idempotency keys, stable error codes, versioning, OpenAPI, and webhooks with replay protection.
- **OutisCloud state:** Some duplicate creates are rejected incidentally, but there is no generic retry semantics or contract.
- **Recommendation:** Add the automation contract after core correctness (Phase 7).

---

## 5. Additional Industry Benchmark Findings

### 5.1 Authoritative DNS software

**BIND 9**

- Primary/secondary roles, AXFR/IXFR, NOTIFY, TSIG, dynamic update policies, views, response-policy zones, catalog zones, zone validation, and detailed statistics are mature, documented capabilities.
- Lessons: separate transfer policy from zone data; make zone validation and journaling explicit; support operational tooling such as `named-checkzone` and `rndc`.
- OutisCloud already uses Hickory for query serving and has a control-plane abstraction. It should not replace Hickory; it should close protocol gaps in the existing engine/control-plane boundary.

**Knot DNS**

- Emphasizes automatic DNSSEC signing, zone transfers, catalog zones, ZONEMD, key management, and high-performance authoritative serving.
- Lessons: automatic signing/rollover must be designed with key storage; catalog zones are a scalable fleet-management mechanism; transfer status is an operational feature.

**PowerDNS Authoritative**

- A clean HTTP API over zones and RRsets, primary/secondary support, DNSSEC, metadata, search, views, and catalog zones.
- Lessons: an RRset-centric API is easier to automate safely than record-by-record mutation; metadata belongs beside zones; API documentation and consistent pagination are product features.

### 5.2 Managed DNS providers

**Amazon Route 53**

- Hosted zones, record sets, alias records, routing policies (simple, weighted, latency, failover, geolocation, geoproximity, multivalue), health checks, DNSSEC, query logging, and resolver services.
- Lessons: routing policy is a first-class model; health checks and failover are inseparable; query logging is a separate product surface with privacy implications.

**Google Cloud DNS**

- Managed zones, record sets, DNSSEC, IAM, audit logging, private zones, peering, and routing policies.
- Lessons: cloud IAM and audit are platform-level capabilities; private zones are a separate product category from public authoritative hosting.

**Azure DNS**

- Hosted zones, record sets, alias records, DNSSEC, RBAC, activity logs, private zones, and traffic-manager integration.
- Lessons: alias records solve apex/cloud-target problems; activity logs must be queryable; private DNS is not the same as public authoritative DNS.

### 5.3 Automation and validation

**OctoDNS**

- Declarative DNS configuration, multiple providers, plan/apply, and import. Lesson: declarative desired state and dry-run are valuable for large fleets, but require a stable provider contract.

**DNSControl**

- Infrastructure-as-code for DNS with previews, provider adapters, and validation. Lesson: a preview/diff workflow reduces accidental changes; provider capability differences must be explicit.

**Zonemaster**

- Delegation and DNSSEC conformance testing across parent and child. Lesson: a hosted zone is not “working” until delegation, NS, DS, and DNSSEC behavior are validated externally.

**Prometheus/Alertmanager and external-dns**

- Operational monitoring and Kubernetes automation are ecosystem expectations. Lesson: expose stable metrics and APIs; do not couple the core control plane to one orchestrator.

### 5.4 Benchmark conclusions

1. **Do not pursue Cloudflare parity.** OutisCloud should not build a CDN, reverse proxy, public recursive resolver, registrar, or global anycast network as part of this roadmap.
2. **Prioritize authoritative correctness and operational safety.** Secondary/transfers, publication consistency, DNSSEC custody, and recovery are more valuable than cosmetic dashboard features.
3. **Adopt proven product patterns, not vendor architecture.** RRset-centric APIs, routing-policy objects, preview/dry-run, scoped tokens, and delegation validation are broadly applicable.
4. **Keep Hickory.** The existing engine is the foundation; extend it where protocol gaps exist and isolate control-plane responsibilities.
5. **Make automation a first-class product.** API contracts, tokens, idempotency, and webhooks are required for professional adoption.

---

## 6. Existing OutisCloud Architecture

### 6.1 Repository and components

| Component | Role | Important paths |
|---|---|---|
| `crates/proto` | DNS wire protocol, record types, DNSSEC types | `crates/proto/src/rr/` |
| `crates/server` | Query handling, zone stores, transports, metrics, DNSSEC signing, GeoDNS handler | `crates/server/src/` |
| `bin` | `hickory-dns` binary, config loading, hot reload, Prometheus listener | `bin/src/` |
| `crates/control_api` | Actix control plane, auth, zones, records, tenants, DNSSEC, agents, analytics | `crates/control_api/src/` |
| `crates/agent` | Pull-based replica agent, signed bundle verification, atomic apply | `crates/agent/src/` |
| `crates/geodns` | MaxMind lookup and GeoRule engine | `crates/geodns/src/` |
| `web/ui` | React/Vite admin and customer console | `web/ui/src/` |
| `deploy/` | DNS config, GeoIP data, Prometheus examples | `deploy/` |
| `helm/`, `k8s/` | Incomplete deployment packaging | `helm/hickory-dns/`, `k8s/` |

### 6.2 Runtime topology

The supported path is a single-host Docker Compose stack: PostgreSQL, control API, DNS server, and UI. Agents can pull signed bundles for additional DNS replicas. Control-plane replicas can share PostgreSQL, but generated zone files are also shared state; the Helm chart declares multiple replicas without a shared read-write-many zone volume. There is no secondary DNS protocol path, database HA, anycast, or tested failover.

### 6.3 Data model

Core tables include `users`, `token_blacklist`, `servers`, `zones`, `records`, `nameservers`, `agents`, `agent_zones`, `georules`, `audit_logs`, `publish_state`, `tenants`, `tenant_members`, `zone_members`, `zone_revisions`, `analytics_samples`, `dnssec_keys`, `shared_rate_limits`, `collector_lease`, and `collector_state`. `acls`, `dns_views`, `agent_configs`, `rate_limits`, and `agent_health_history` are created but unused or migration-only. Two migrations share the `002_` prefix, runtime DDL and SQL migrations drift, and the legacy `type` column is renamed at runtime.

### 6.4 Publication path

1. API validates input and performs a database mutation.
2. `DnsManager::regenerate_zones` regenerates all active zones.
3. `zone_file_generator` reads all zones, records, nameservers, GeoRules, and DNSSEC metadata.
4. `dns_builder` writes validated zone files using temporary file + fsync + rename.
5. `named.toml` is atomically swapped after zone files.
6. The DNS server watches the directory, debounces, rebuilds the full catalog, and swaps it.
7. A shared advisory lock attempts to serialize publication across API replicas; timeout/error proceeds anyway.

Strengths: Hickory validation before commit, atomic files, last-known-good preservation, fail-closed DNSSEC key handling, and orphan quarantine. Weaknesses: full regeneration, one transaction slot, best-effort cross-replica locking, and no publication queue or end-to-end convergence proof.

### 6.5 Authentication and authorization

- Argon2 password hashing, dummy-hash timing defense, 15-minute JWT access tokens, rotating refresh tokens with hashed storage, replay detection, `token_version` session generation, and access-token blacklisting.
- TOTP MFA with ±1 step; secret stored unencrypted; no recovery codes or QR code.
- Global roles `admin`, `editor`, `viewer`, `user`; zone membership and tenant membership; viewer read-only enforcement.
- Shared login rate limiting via PostgreSQL with an in-process fallback; no API-wide or tenant-wide quotas.
- JWT secret is the sole symmetric trust anchor; agent signing keys derive from it; no key ID/rotation.
- API binds plain HTTP on `0.0.0.0:8080`; PostgreSQL uses `NoTls`; TLS must be terminated externally.
- Access tokens are stored in browser `localStorage`; no cookie-based alternative or CSP defense in depth.

### 6.6 DNS engine capabilities

- UDP/TCP authoritative serving; IPv4/IPv6 listeners; configurable addresses.
- DoT/DoH/DoQ server support behind `__tls`/`__https`/`__quic` features; DoH3 is server-only, not wired into the binary; no certificate management.
- File, in-memory, SQLite, forwarder, and recursor stores.
- DNSSEC signing with NSEC/NSEC3, ECDSA/EdDSA/RSA, periodic re-sign, and trust-anchor validation for forwarding/recursion.
- GeoDNS/ECS with country/city rules, A/AAAA only, no weights or health; DNSSEC and GeoDNS are mutually exclusive.
- Per-source rate limiting (IPv4 per address, IPv6 per `/64`), opt-in, plain TCP exempt, per-process.
- Prometheus exporter on `127.0.0.1:9000` by default; per-zone metrics opt-in; per-query INFO logging on by default.
- AXFR single-message and accepted over UDP; IXFR absent; NOTIFY `NotImp`; secondary zones label-only; TSIG partial; dynamic update SQLite-only and TSIG-required; no SIG(0).
- No DNS health/readiness endpoint, upstream health checks, failover, or weighted authoritative routing.

### 6.7 Frontend

React/Vite with admin and customer routes. Core flows are wired: login/MFA/logout, dashboards, primary zone CRUD, record CRUD/import, sharing, revisions, DNSSEC, GeoDNS, nameservers, servers, agents, tenants, analytics, and DNS lookup. Known broken or incomplete flows: multi-zone bulk import (`/api/v1/zones/bulk` does not exist), secondary-zone selector, zone export UI, certificates, server lifecycle methods, per-user password reset, audit detail, page-local audit search/CSV, permission false affordances, disabled-server status, password focus bug, modal accessibility, and stale E2E/docs.

### 6.8 Analytics and observability

The control API exposes Prometheus metrics, `/metrics/queries`, persistent `analytics_samples`, tenant/global overview, and a leader-elected collector with hourly rollups and retention. The DNS server exposes query counters and optional per-zone breakdowns. Gaps: no query-log pipeline, no latency/NXDOMAIN/SERVFAIL history, no analytics export, no deployed Prometheus/Grafana/Alertmanager, wrong scrape port, alert rules not loaded, and PII-heavy default logging.

### 6.9 Tests and deployment evidence

Verified locally: `control_api` 140/140, platform QA 96/96, UI redesign 368/368, accessibility 9/9, visual regression 28/28, hickory integration 99 passed/6 environment-limited, `cargo fmt` clean. Database-backed tests skip without `TEST_DATABASE_URL`; CI does not provide it. `cargo clippy -D warnings` is not clean. Compose is single-host; Helm/Kubernetes are structurally incomplete; GitHub Actions use invalid action references and wrong Docker contexts; there is no backup/restore, TLS, or production monitoring.

---

## 7. Current Feature Coverage Matrix

**Status values:** `IMPLEMENTED_AND_VERIFIED`, `IMPLEMENTED_BUT_INCOMPLETE`, `IMPLEMENTED_BUT_UNVERIFIED`, `NOT_IMPLEMENTED`, `NOT_APPLICABLE`, `REQUIRES_ARCHITECTURAL_REVIEW`. Priorities are P0–P3. Phases refer to §10. A dash in the task column means no implementation task is needed; the feature is verified or out of scope.

Source keys are defined in §17: `CF` (Cloudflare), `HICK` (Hickory/source), `CODE` (current repository), `BIND`, `KNOT`, `PDNS`, `R53`, `GCP`, `AZ`, `OCTO`, `DNSCTL`, `ZM`, `RFC`.

### 7.1 DNS Core

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| CORE-01 | Authoritative UDP/TCP serving over IPv4/IPv6. Baseline reachability and dual-stack correctness. | RFC, HICK | File store, catalog dispatch, UDP/TCP listeners, separate IPv4/IPv6 address config. Verified by integration tests and QA. | IMPLEMENTED_AND_VERIFIED | Deployment maps IPv4 only in places; concurrency caps absent. | P0 | 1 | — |
| CORE-02 | Encrypted DNS transports: DoT, DoH, DoQ, DoH3. Protects client queries and meets modern resolver expectations. | CF, RFC | Server binary exposes TLS/HTTPS/QUIC/H3 behind features; local Hickory H3 client integration verifies listener, certificate validation, and DNS response. No certificate lifecycle or compose TLS. | IMPLEMENTED_BUT_INCOMPLETE | Certificate lifecycle and deployment remain. | P1 | 1 | CORE-010 |
| CORE-03 | Hot reload and atomic publication. Avoids dropping queries during changes and preserves last-known-good state. | HICK, CODE | File/config watcher, 300 ms debounce, full catalog rebuild/swap, atomic zone files, last-known-good behavior. Verified. | IMPLEMENTED_AND_VERIFIED | Full-catalog rebuild; no per-zone reload or incremental update. | P0 | 1 | CORE-013 |
| CORE-04 | Record type coverage and protocol correctness. Supports real-world zones and DNSSEC-aware types. | CF, HICK | Common types and many advanced types exist; DNAME, LOC, AFSDB, APL, DHCID, HIP, IPSECKEY, KX absent; UI exposes only 10 types. | IMPLEMENTED_BUT_INCOMPLETE | Type policy, advanced editing, conformance tests. | P2 | 2 | CORE-011 |
| CORE-05 | Forwarding, recursion, caching. Supports resolver-style deployments where applicable. | RFC, CODE | Forwarder and experimental recursor exist; AXFR denied; configurable cache default 512; recursor defaults to root DNSSEC validation; not the primary product path. | IMPLEMENTED_AND_VERIFIED | Broader operational abuse review remains follow-up hardening. | P2 | 1 | CORE-009 |
| CORE-06 | RFC 2136 dynamic update. Enables dynamic endpoints and standards-based updates. | BIND, KNOT, RFC | SQLite-only, TSIG required, no file/in-memory update, no SIG(0). | IMPLEMENTED_BUT_INCOMPLETE | Store coverage, policy model, SIG(0), tests. | P2 | 4 | CORE-012 |
| CORE-07 | Query rate limiting, amplification control, and concurrency backpressure. Protects availability under abuse. | CF, RFC | Per-source/per-process limiter, IPv4/IPv6 `/64` keying, plain TCP exempt; UDP spawns unbounded tasks. | IMPLEMENTED_BUT_INCOMPLETE | Shared budgets, TCP/TLS coverage, concurrency semaphores, response-rate limits. | P0 | 9 | SEC-007 |
| CORE-08 | Query logging and PII controls. Enables troubleshooting without leaking names/addresses by default. | CF, CODE | Every response/query name logged at INFO, including client IP/port, default level INFO. | IMPLEMENTED_BUT_INCOMPLETE | Configurable levels, redaction, retention, audit-safe diagnostics. | P1 | 6 | CORE-006 |

### 7.2 Zone Management

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| ZONE-01 | Primary zone CRUD and lifecycle. Core hosted-zone workflow. | CF, CODE | Create/read/update/delete, default NS/SOA, rename, safe delete, owner checks, quotas, audit. Verified. | IMPLEMENTED_AND_VERIFIED | Secondary/hold/archive lifecycle absent. | P0 | 2 | — |
| ZONE-02 | Ownership verification and zone hold/suspend. Prevents squatting and unsafe service states. | CF, CODE | TXT challenge with local fake resolver; pending status when `VERIFY_DOMAINS=true`; no public-DNS proof, NS proof, or hold. | IMPLEMENTED_BUT_UNVERIFIED | Public DNS validation, NS delegation proof, hold/archive states. | P0 | 2 | ZONE-005, ZONE-006 |
| ZONE-03 | Zone history, diff, and rollback. Recovers from successful bad changes. | CF, CODE | Revisions on change, transactional restore, 50-revision cap, record-only snapshots, swallowed snapshot failures. | IMPLEMENTED_BUT_INCOMPLETE | Diff, retention policy, complete snapshots, failure visibility. | P1 | 2 | ZONE-007 |
| ZONE-04 | Import/export, bulk zone operations, and templates. Migration and fleet management. | CF, BIND | Per-zone JSON import/export API; no BIND parser, no multi-zone bulk endpoint (UI 404), no templates. | IMPLEMENTED_BUT_INCOMPLETE | BIND/CSV parsing, preview, multi-zone route, templates. | P1 | 2 | ZONE-001, ZONE-002 |
| ZONE-05 | Zone metadata, tags, search. Ownership and automation metadata without changing DNS data. | CF, PDNS | Only domain/owner/tenant/status-style fields; zones list supports pagination/search. | NOT_IMPLEMENTED | Schema/API/UI for metadata and tags. | P2 | 2 | ZONE-004 |
| ZONE-06 | Publication status and safe mutation. Makes success visible and localizes failures. | CF, CODE | Publication gauges, `/dns/status`, dashboard banner, last-known-good, two-phase create/delete/rename. | IMPLEMENTED_BUT_INCOMPLETE | Per-zone convergence, update/delete rollback consistency, replica proof. | P0 | 0 | ARCH-002, REC-002 |

### 7.3 DNS Record Management

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| REC-01 | Record CRUD, validation, NS allowlist, owner names. Prevents malformed zones. | CF, HICK | Hickory parser gate, TTL/priority bounds, in-zone name validation, NS allowlist. Verified by API tests. | IMPLEMENTED_AND_VERIFIED | Advanced type editing and batch semantics. | P0 | 2 | — |
| REC-02 | RRset uniqueness and transactional publication. Prevents duplicate/ambiguous data. | CF, CODE | Unique index `uq_records_rrset_value` on `(zone_id, lower(name), record_type, value)`; application duplicate check. Unique invariant verified. | IMPLEMENTED_BUT_INCOMPLETE | Update/delete publication atomicity; runtime/migration drift. | P0 | 0 | REC-002, ARCH-001 |
| REC-03 | TTL, priority, and record-type coverage. Correct answer semantics. | CF, HICK | TTL 1..MAX, priority 0..65535, broad Hickory types; UI limited to 10 common types. | IMPLEMENTED_BUT_INCOMPLETE | UI/type policy and tests for advanced types. | P2 | 2 | CORE-011 |
| REC-04 | Record comments, tags, and ownership metadata. Operational traceability. | CF | No schema or API fields. | NOT_IMPLEMENTED | Design and migration. | P2 | 2 | REC-001 |
| REC-05 | Bulk/batch record operations with preview and errors. Large-zone safety. | CF, PDNS | Per-zone JSON import max 5,000, all-or-nothing; naive CSV UI parser; no batch endpoint. | IMPLEMENTED_BUT_INCOMPLETE | BIND/CSV preview, per-row errors, batch RRset operations. | P1 | 2 | REC-003, ZONE-001 |
| REC-06 | Apex alias/CNAME flattening and safe UI editing. Solves apex aliasing and destructive mistakes. | CF, R53 | Engine supports ANAME; UI/control exposure is not documented; no flattening; delete has no confirmation. | IMPLEMENTED_BUT_INCOMPLETE | Product decision, API/UI exposure, confirmation/diff. | P3 | 11 | REC-004, REC-005 |

### 7.4 DNSSEC

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| DNSSEC-01 | Zone signing, DNSKEY/DS output, algorithms. Provides answer integrity. | CF, RFC, CODE | ECDSAP256/384 and Ed25519, DS SHA-256/384, manual rollover, NSEC, fail-closed publication. Verified end-to-end with `delv`. | IMPLEMENTED_AND_VERIFIED | KMS/key custody, automatic rollover, NSEC3/CDS. | P0 | 3 | — |
| DNSSEC-02 | Automatic key lifecycle and rollover. Prevents expiry and operator error. | CF, KNOT | Manual enable/rollover/complete; single CSK per generation; no scheduler or KSK/ZSK split. | IMPLEMENTED_BUT_INCOMPLETE | Key state machine, timers, rollover tests. | P1 | 3 | DNSSEC-002 |
| DNSSEC-03 | NSEC3 and CDS/CDNSKEY automation. Modern DNSSEC operation and migration. | CF, KNOT | Engine supports NSEC3; control plane exposes NSEC only; no CDS/CDNSKEY publication. | IMPLEMENTED_BUT_INCOMPLETE | Config exposure, CDS/CDNSKEY, parent polling. | P2 | 3 | DNSSEC-003 |
| DNSSEC-04 | Key encryption, KMS/HSM, backup, and compromise recovery. Protects the root of trust. | CF, KNOT, CODE | Plaintext PKCS#8 PEM under the zone directory; no encryption, KMS, backup, or documented recovery. | NOT_IMPLEMENTED | Key-store abstraction, encryption, backup/restore, runbooks. | P0 | 3 | DNSSEC-001, DNSSEC-004 |
| DNSSEC-05 | Multi-signer DNSSEC. Supports migrations and multi-operator redundancy. | CF | Absent. | NOT_IMPLEMENTED | DNSKEY/CDS model and signing coordination. | P3 | 3 | DNSSEC-005 |
| DNSSEC-06 | GeoDNS and DNSSEC coexistence. Avoids choosing between routing and integrity. | CF, CODE | Mutually exclusive by API/generator; synthesized geo answers cannot be signed. | REQUIRES_ARCHITECTURAL_REVIEW | Signed synthesis or a documented permanent exclusion. | P2 | 3 | DNSSEC-007 |
| DNSSEC-07 | DS verification and monitoring. Detects delegation/DS mistakes before they become outages. | CF, ZM | DS values displayed; no parent check, Zonemaster/DNSViz integration, or alerts. | NOT_IMPLEMENTED | Delegation checker, monitoring, alerts. | P1 | 3 | DNSSEC-006 |

### 7.5 Primary/Secondary DNS

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| PS-01 | Secondary zone hosting. Independent authoritative replicas and delegated secondary service. | CF, BIND, KNOT | Hickory config/server supports secondary-zone masters, inbound NOTIFY, refresh by AXFR, monotonic serial checks, atomic replacement and catalog reload. Control-plane zone lifecycle/peer configuration and freshness UI remain absent. | IMPLEMENTED_BUT_INCOMPLETE | Tenant-safe secondary-zone API/UI, persisted peer model, initial-transfer-before-serving lifecycle and control-plane integration tests. | P1 | 4 | SECONDARY-001 |
| PS-02 | Primary peer configuration and SOA refresh/retry/expire. Defines and maintains replication. | BIND, KNOT | No peer table/API, no refresh scheduler, no serial comparison. | NOT_IMPLEMENTED | Peer model, timers, transfer client. | P1 | 4 | SECONDARY-002 |
| PS-03 | Promotion/failover and conflict resolution. Recovers from primary loss without inconsistent zones. | PDNS, BIND | No promotion, multi-primary, or conflict policy. | NOT_IMPLEMENTED | State machine and serial/version conflict tests. | P2 | 4 | SECONDARY-003 |
| PS-04 | Secondary status/observability. Shows whether replicas are current. | CF, KNOT | Only agent applied-version, not DNS secondary state. | NOT_IMPLEMENTED | Per-zone transfer status, lag, errors, logs. | P1 | 4 | SECONDARY-004 |
| PS-05 | Secondary deletion/retirement and primary reassignment. Prevents orphaned replicas and stale delegation. | BIND, PDNS | Absent. | NOT_IMPLEMENTED | Lifecycle and cleanup tests. | P2 | 4 | SECONDARY-003 |

### 7.6 Zone Transfers

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| XFR-01 | AXFR server and client. Standards-based full-zone replication. | RFC, BIND, KNOT | TCP-only server streams multi-message transfers; Hickory client consumes AXFR; BIND `dig` and BIND 9.20 server interop tested; file-backed AllowSigned verifies TSIG. | IMPLEMENTED_AND_VERIFIED | Policy administration/audit and SIG(0) remain separate transfer roadmap work. | P1 | 1 | CORE-001 |
| XFR-02 | IXFR. Efficient incremental replication and journal use. | RFC, BIND, KNOT | Current-serial request returns one SOA; stale serial is explicitly refused because recovery-journal rows lack RFC 1995 old/new SOA boundaries. | IMPLEMENTED_BUT_INCOMPLETE | Versioned delta journal, IXFR server/client, and interop tests; clients must use AXFR for stale serials. | P1 | 1 | CORE-002 |
| XFR-03 | NOTIFY. Fast propagation of zone changes. | RFC, BIND, KNOT | Catalog returns `NotImp`; no sender or receiver. | NOT_IMPLEMENTED | NOTIFY sender/receiver and retry tests. | P1 | 1 | CORE-003 |
| XFR-04 | TSIG and SIG(0). Authenticates transfers and updates. | RFC, BIND, KNOT | TSIG for SQLite updates/AXFR and file-store AXFR policy; no SIG(0). | IMPLEMENTED_BUT_INCOMPLETE | Control-plane key management, SIG(0), and key storage remain. | P1 | 4 | TRANSFER-002 |
| XFR-05 | Transfer ACLs, configuration, audit, and metrics. Safe operation at scale. | CF, BIND | Engine policy is default Deny but there is no control-plane ACL/peer/key management or transfer audit. | NOT_IMPLEMENTED | Schema, API, UI, audit, metrics. | P1 | 4 | TRANSFER-001, TRANSFER-003 |
| XFR-06 | Catalog zones. Fleet-scale zone membership and provisioning. | KNOT, PDNS | Absent. | NOT_IMPLEMENTED | Catalog-zone format and provisioning. | P3 | 4 | XFR-006 |

### 7.7 GeoDNS

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| GEO-01 | Country, city, and region matching. Location-aware answers. | CF, CODE | Country rules verified; region/city engine code exists; production GeoLite2-City data absent. | IMPLEMENTED_BUT_INCOMPLETE | City dataset/license, region validation, data lifecycle. | P2 | 5 | GEO-003 |
| GEO-02 | EDNS Client Subnet. Uses the resolver-provided prefix instead of the resolver address. | CF, RFC | Opt-in per zone, ECS echoed with scope, browser-tested. | IMPLEMENTED_AND_VERIFIED | Cache/privacy policy and broader tests. | P2 | 5 | — |
| GEO-03 | Weighted, multi-target, and health-aware geo answers. Enables gradual rollout and failover. | CF, R53 | A/AAAA-only numeric targets; no weights, health, CNAME targets, or multiple targets. | NOT_IMPLEMENTED | Answer model and selection engine. | P2 | 5 | GEO-001, GEO-002 |
| GEO-04 | DNSSEC-compatible geo synthesis. Avoids a permanent routing-versus-integrity tradeoff. | CF, CODE | Mutually exclusive. | REQUIRES_ARCHITECTURAL_REVIEW | Signed synthesis architecture or explicit permanent non-goal. | P2 | 3 | DNSSEC-007 |
| GEO-05 | GeoIP dataset lifecycle, validation, and operations. Prevents stale or wrong routing. | CF, CODE | Environment path, file watcher, update script, age gauge; no upload/management API or City data. | IMPLEMENTED_BUT_INCOMPLETE | Dataset API/status, license handling, validation. | P2 | 5 | GEO-003 |

### 7.8 Traffic Management

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| TRAF-01 | Weighted routing. Gradual migration and capacity distribution. | CF, R53 | Absent in authoritative and GeoDNS paths. | NOT_IMPLEMENTED | Weighted answer model and deterministic selection. | P2 | 5 | GEO-001 |
| TRAF-02 | Proximity, latency, and dynamic steering. Uses live signals to choose answers. | CF, R53 | Absent; resolver ordering exists only for forwarding/recursion. | NOT_IMPLEMENTED | Health/latency data and policy engine. | P3 | 5 | TRAF-002 |
| TRAF-03 | Load-balancer pools and regions. Groups targets and composes routing policies. | CF, R53 | Absent. | NOT_IMPLEMENTED | Pool/region model, API, UI. | P3 | 5 | GEO-002 |
| TRAF-04 | Traffic-policy API/UI and validation. Makes policies reviewable and testable. | CF, R53 | Absent; GeoRules have limited CRUD/validation. | NOT_IMPLEMENTED | Policy schema, simulation, tests. | P2 | 5 | TRAF-001, GEO-004 |

### 7.9 Health Checks and Failover

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| HLTH-01 | DNS server health and readiness endpoints. Distinguishes process health from serving readiness. | CF, CODE | Control API has `/health` (always OK) and `/ready` (DB only); DNS server has none. | NOT_IMPLEMENTED | Serving-ready probe, publication freshness, listener checks. | P0 | 1 | CORE-004 |
| HLTH-02 | Upstream target health checks. Removes unhealthy targets from answers. | CF, R53 | No active checks in the authoritative tier; resolver probes are unrelated. | NOT_IMPLEMENTED | Monitor model, scheduler, state store. | P2 | 5 | HLTH-001 |
| HLTH-03 | Failover policies. Preserves availability when a target or region fails. | CF, R53 | Absent. | NOT_IMPLEMENTED | Policy engine and fail-open/fail-closed rules. | P2 | 5 | HLTH-001, GEO-002 |
| HLTH-04 | Health history, synthetic probes, and alerts. Makes failover observable. | CF, CODE | No health history or synthetic DNS probes; metrics are process counters. | NOT_IMPLEMENTED | Time-series storage, probes, alert integration. | P1 | 6 | HLTH-002, MON-005 |

### 7.10 DNS Analytics

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| ANA-01 | Per-zone query metrics. Customer and capacity visibility. | CF, CODE | `hickory_zone_queries_total{zone,result}`, opt-in `DNS_ZONE_QUERY_METRICS`; verified by analytics lab. | IMPLEMENTED_AND_VERIFIED | Env-path coverage and default operations. | P1 | 6 | — |
| ANA-02 | Query-type and country breakdowns. Detects usage patterns and anomalies without high cardinality. | CF, CODE | Bounded qtype/country labels, sentinels, 32-country cap, opt-in `DNS_ZONE_BREAKDOWN`; verified. | IMPLEMENTED_AND_VERIFIED | City-level and signed-zone combinations. | P2 | 6 | — |
| ANA-03 | Persistent history and tenant/account views. Answers historical questions after restart. | CF, CODE | PostgreSQL `analytics_samples`, 1 h–90 d ranges, tenant/global filters, restart persistence verified. | IMPLEMENTED_AND_VERIFIED | Export and large-scale retention tests. | P1 | 6 | — |
| ANA-04 | Latency, RCODE, NXDOMAIN, and SERVFAIL history. Detects degradation and misconfiguration. | CF | Exporter has counters; no latency histograms or historical error analytics. | IMPLEMENTED_BUT_INCOMPLETE | Metric schema, storage, UI. | P1 | 6 | ANA-002 |
| ANA-05 | Query-log pipeline and streaming. Deep troubleshooting and SIEM integration. | CF | No query-log export; per-query INFO logs are not a structured pipeline. | NOT_IMPLEMENTED | Opt-in pipeline, sampling, redaction, retention. | P2 | 6 | ANA-001 |
| ANA-06 | Analytics export, rollup, and scale retention. Supports large tenants and external reporting. | CF, CODE | Hourly rollups and configurable retention exist; no export API or capacity test. | IMPLEMENTED_BUT_INCOMPLETE | Export, partitioning, scale tests. | P2 | 6 | ANA-003 |

### 7.11 Monitoring and Alerting

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| MON-01 | Prometheus metrics for API/control plane. Operational baseline. | CODE | API metrics endpoint, publication/bundle/agent/DB gauges; optional `METRICS_TOKEN`; verified. | IMPLEMENTED_AND_VERIFIED | SLO/reliability metrics and histogram coverage. | P1 | 6 | — |
| MON-02 | Correct monitoring deployment and scrape targets. Prevents blind operation. | CODE | DNS exporter defaults to `127.0.0.1:9000`; compose scrape targets `dns-server:53`; Prometheus/Grafana commented out. | IMPLEMENTED_BUT_INCOMPLETE | Fix target, deploy stack, document. | P0 | 12 | MON-001, OPS-004 |
| MON-03 | Alert rules and Alertmanager. Turns metrics into action. | CF | `outis-alerts.yml` exists but is not loaded; no Alertmanager. | NOT_IMPLEMENTED | Rule wiring, routing, tests. | P1 | 6 | MON-002 |
| MON-04 | Metrics authentication and transport security. Prevents information leakage. | CF, CODE | API token optional; DNS exporter plain HTTP with no auth. | IMPLEMENTED_BUT_INCOMPLETE | mTLS/TLS, network policy, token default. | P1 | 9 | MON-004, SEC-001 |
| MON-05 | SLO dashboards, synthetic DNS probes, and publication alerts. Proves the service is actually serving. | CF, CODE | No SLO dashboards or synthetic DNS probes; publication gauges exist. | NOT_IMPLEMENTED | Probe runner, dashboards, alert rules. | P1 | 6 | MON-003, MON-005 |

### 7.12 Customer Management

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| CUST-01 | User CRUD, authentication, and session revocation. Account baseline. | CF, CODE | Users API, Argon2, JWT/refresh rotation, logout, token version, admin reset. Verified. | IMPLEMENTED_AND_VERIFIED | Invites, email, lifecycle states. | P0 | 8 | — |
| CUST-02 | TOTP MFA. Stronger login security for privileged accounts. | CF, CODE | TOTP setup/enable/disable and session invalidation; secret unencrypted; no QR/recovery codes. | IMPLEMENTED_BUT_INCOMPLETE | Secret encryption, recovery, QR, policy. | P1 | 9 | SEC-004 |
| CUST-03 | Invitations, suspension, deletion, and self-service reset. Complete account lifecycle. | CF | No invite, suspend, delete workflow, email delivery, or forgot-password flow. | NOT_IMPLEMENTED | Email/provider, token model, lifecycle tests. | P1 | 8 | CUST-001 |
| CUST-04 | SSO (OIDC/SAML) and SCIM. Enterprise identity integration. | CF, AZ | Absent. | NOT_IMPLEMENTED | Identity provider abstraction, group mapping. | P3 | 8 | CUST-002, CUST-003 |
| CUST-05 | Customer dashboard. Self-service visibility. | CF, CODE | `/user` dashboard, zones, analytics, DNS lookup, settings, help; verified by platform QA. | IMPLEMENTED_AND_VERIFIED | Error states, onboarding, notifications. | P1 | 11 | — |

### 7.13 Multi-Tenancy

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| TEN-01 | Tenants, membership, roles, and personal-tenant backfill. Isolation baseline. | CF, CODE | `tenants`, `tenant_members`, owner/editor/viewer, quota checks, tenant move. Verified. | IMPLEMENTED_AND_VERIFIED | Hierarchy and enterprise org model. | P0 | 8 | — |
| TEN-02 | Zone and record quotas. Prevents noisy-neighbor and accidental exhaustion. | CF, CODE | Transactional quota reservation for create zone, record, import, revision restore; admin bypass. Verified. | IMPLEMENTED_AND_VERIFIED | Usage reporting and soft/hard limits. | P1 | 8 | — |
| TEN-03 | Quota concurrency and usage reporting. Prevents overshoot and supports billing. | CODE | Check-then-insert can overshoot by request concurrency; no usage report or invoice export. | IMPLEMENTED_BUT_INCOMPLETE | Atomic quota enforcement and usage API. | P1 | 8 | TEN-001 |
| TEN-04 | Tenant hierarchy and delegated administration. Supports resellers and organizations. | CF, PDNS | Flat tenants only. | NOT_IMPLEMENTED | Org/sub-tenant model and authorization. | P3 | 8 | TEN-002 |
| TEN-05 | Tenant isolation verification. Prevents cross-tenant data access. | CF, CODE | Tenant-scoped API queries and tests; zone membership and admin bypass are implemented. | IMPLEMENTED_AND_VERIFIED | Property tests across every endpoint. | P0 | 8 | TEN-003 |

### 7.14 RBAC and Permissions

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| RBAC-01 | Global roles and read-only enforcement. Baseline least privilege. | CF, CODE | `admin/editor/viewer/user`, viewer write lock, backend checks. Verified. | IMPLEMENTED_AND_VERIFIED | Custom roles and SSO mapping. | P0 | 8 | — |
| RBAC-02 | Per-zone membership. Team sharing without broad account access. | CF, CODE | `zone_members`, owner/editor/viewer, owner-gated management. Verified. | IMPLEMENTED_AND_VERIFIED | Granular permissions and audit UX. | P1 | 8 | — |
| RBAC-03 | Custom roles and granular permissions. Enterprise separation of duties. | CF, AZ | Fixed global/zone roles only. | NOT_IMPLEMENTED | Permission catalog, policy engine, tests. | P3 | 8 | RBAC-001 |
| RBAC-04 | Role UI consistency and complete role management. Prevents unsupported actions. | CF, CODE | Backend accepts `user`; Users page omits it; no per-user reset; permission false affordances. | IMPLEMENTED_BUT_INCOMPLETE | UI role alignment, reset flow, contract tests. | P1 | 11 | RBAC-002, UX-001 |

### 7.15 API and Automation

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| API-01 | Zone, record, tenant, DNSSEC, agent, and analytics REST APIs. Automation foundation. | CF, CODE | Broad Actix route surface with validation and auth; verified. | IMPLEMENTED_AND_VERIFIED | Contract/versioning and consistent envelopes. | P0 | 7 | — |
| API-02 | Pagination and consistent errors. Makes clients reliable at scale. | CF | Offset pagination is inconsistent; some lists are unpaginated; error envelopes vary. | IMPLEMENTED_BUT_INCOMPLETE | Contract, keyset pagination, error catalog. | P1 | 7 | API-007 |
| API-03 | Idempotency keys. Safe retries after timeouts. | CF | Absent. | NOT_IMPLEMENTED | Idempotency table/TTL and mutation integration. | P1 | 7 | API-002 |
| API-04 | Scoped API tokens with expiry/rotation. Least-privilege automation. | CF | Only JWTs and agent tokens; no personal API keys/scopes. | NOT_IMPLEMENTED | Token model, scopes, rotation, UI. | P1 | 7 | API-003 |
| API-05 | API-wide and tenant rate limits. Fairness and abuse resistance. | CF | Login/shared limits only; no API-wide or tenant quotas. | IMPLEMENTED_BUT_INCOMPLETE | Token-bucket budgets and 429 contract. | P1 | 9 | API-004, SEC-007 |
| API-06 | Webhooks and event notifications. Decoupled automation. | CF | Absent. | NOT_IMPLEMENTED | Event outbox, signing, retries, replay protection. | P2 | 7 | API-005 |
| API-07 | OpenAPI, SDK, and CLI. Integration ergonomics and contract testing. | CF | No OpenAPI or generated clients; scripts are bespoke. | NOT_IMPLEMENTED | Spec-first contract, SDK, CLI. | P1 | 7 | API-001, API-008 |
| API-08 | Async jobs, bulk endpoints, and infrastructure-as-code. Fleet operations. | CF, DNSCTL | Per-zone JSON import; no async jobs, multi-zone bulk, or Terraform provider. | IMPLEMENTED_BUT_INCOMPLETE | Job model, bulk routes, provider. | P2 | 7 | API-006, API-009 |

### 7.16 Audit and Activity History

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| AUD-01 | Audit coverage of mutations. Accountability for DNS changes. | CF, CODE | Audit inserts and tests for many mutations; failed audit inserts do not fail requests; coverage is selective. | IMPLEMENTED_BUT_INCOMPLETE | Complete event catalog and failure policy. | P0 | 8 | AUD-002 |
| AUD-02 | Audit detail, server-side filters, and export. Investigation and compliance. | CF, CODE | List/purge with filters; no detail endpoint; UI search is page-local and CSV is current-page only. | IMPLEMENTED_BUT_INCOMPLETE | Detail, complete filters, server-side export. | P1 | 8 | AUD-001 |
| AUD-03 | Audit retention. Bounds storage while preserving evidence. | CF, CODE | 365-day default retention; verified. | IMPLEMENTED_AND_VERIFIED | Policy configurability and archive. | P1 | 8 | — |
| AUD-04 | Tamper-evident audit storage. Detects deletion or modification. | CF | No hash chain/WORM/immutable archive. | NOT_IMPLEMENTED | Append-only design and verification. | P2 | 8 | AUD-002 |
| AUD-05 | Activity-history UI. Makes audit usable for admins and customers. | CF, CODE | Admin page only; no zone/customer activity view; poor filters. | IMPLEMENTED_BUT_INCOMPLETE | Shared activity component and permissions. | P1 | 11 | ADM-004 |

### 7.17 Backup and Recovery

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| BAK-01 | Zone revisions and snapshots. Recovers record-level mistakes. | CODE | `zone_revisions`, restore, 50-revision cap; record-only and failure-swallowing. | IMPLEMENTED_BUT_INCOMPLETE | Complete snapshots, retention, diff, failure handling. | P1 | 2 | ZONE-007 |
| BAK-02 | PostgreSQL backup and PITR. Recovers tenants, zones, users, and audit data. | CF | No product backup route, WAL archiving, or PITR. | NOT_IMPLEMENTED | Backup jobs, encryption, restore tooling. | P0 | 12 | OPS-004 |
| BAK-03 | DNSSEC key and configuration backup. Prevents irreversible trust loss. | CF | No key backup/export workflow; docs mention manual key directory backup only. | NOT_IMPLEMENTED | Encrypted backup, escrow, restore. | P0 | 3 | DNSSEC-004, BAK-003 |
| BAK-04 | Restore drills and verification. Proves recovery rather than assuming it. | CF | No restore drills or verification procedure. | NOT_IMPLEMENTED | Drill scripts, RTO evidence, CI/manual schedule. | P0 | 12 | OPS-004 |
| BAK-05 | RPO/RTO and disaster recovery. Defines acceptable loss and recovery. | CF | No documented objectives or DR plan; topology is single-host. | NOT_IMPLEMENTED | ADR, runbooks, exercises. | P0 | 0 | ARCH-008, BAK-005 |

### 7.18 Security and Abuse Protection

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| SEC-01 | Password hashing, refresh rotation, session revocation. Account protection. | CF, CODE | Argon2, dummy hash, rotating refresh tokens, replay detection, `token_version`, blacklist, logout. Verified. | IMPLEMENTED_AND_VERIFIED | Key rotation and stronger session policy. | P0 | 9 | — |
| SEC-02 | MFA with secure secret storage and recovery. Privileged-account protection. | CF, CODE | TOTP enable/disable and session invalidation; plaintext secret; no recovery codes/QR. | IMPLEMENTED_BUT_INCOMPLETE | Encryption, recovery, QR, policy. | P1 | 9 | SEC-004 |
| SEC-03 | API and database transport security. Protects credentials and data in transit. | CF | API plain HTTP on `0.0.0.0:8080`; PostgreSQL `NoTls`. | NOT_IMPLEMENTED | TLS termination/native TLS, DB TLS, HSTS. | P0 | 9 | SEC-001, SEC-002 |
| SEC-04 | Secret management and key separation. Limits blast radius. | CF, CODE | JWT secret is sole trust anchor; agent keys derive from it; no secret manager. | IMPLEMENTED_BUT_INCOMPLETE | KMS/secret manager, key IDs, rotation, separate agent keys. | P0 | 9 | SEC-003 |
| SEC-05 | Rate limits, abuse detection, and amplification protection. Availability and fair use. | CF, RFC | Shared login limits; per-process DNS limiter; no API-wide quotas, abuse scoring, or response-rate limiting. | IMPLEMENTED_BUT_INCOMPLETE | Budgets, metadata, response-rate controls, alerts. | P1 | 9 | SEC-006, SEC-007, API-004 |
| SEC-06 | Zone holds, ownership verification, and change protection. Prevents hijack and destructive changes. | CF | TXT challenge exists; no zone holds, transfer lock, or registrar/delegation proof. | IMPLEMENTED_BUT_INCOMPLETE | Hold/lock states and public verification. | P1 | 2 | ZONE-005, ZONE-006 |
| SEC-07 | Browser hardening and token storage. Mitigates XSS impact. | CF | Tokens in `localStorage`; no CSP/HSTS/Referrer-Policy; no cookie alternative. | IMPLEMENTED_BUT_INCOMPLETE | CSP, security headers, HttpOnly cookie option, XSS tests. | P1 | 9 | SEC-005 |
| SEC-08 | Supply-chain security. Detects vulnerable dependencies and build artifacts. | CF | `cargo audit`/`npm audit` performed historically; no CI gate, SBOM, or signing. | IMPLEMENTED_BUT_INCOMPLETE | CI scanning, deny.toml, SBOM, provenance. | P1 | 9 | SEC-008, OPS-007 |
| SEC-09 | Global DDoS scrubbing and anycast. Cloudflare-specific network defense. | CF | Not part of an authoritative hosting product's application layer. | NOT_APPLICABLE | Outsource or treat as a separate infrastructure program. | P3 | 10 | — |

### 7.19 Performance and Scalability

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| PERF-01 | Publication queue and incremental generation. Removes total-data scaling from write latency. | CODE | Every write regenerates all zones; startup publication ~106 s for 5,000 zones. | IMPLEMENTED_BUT_INCOMPLETE | Outbox/queue, per-zone generation, convergence metrics. | P0 | 10 | PERF-001 |
| PERF-02 | Database write concurrency. Removes the single transaction-slot ceiling. | CODE | One reserved connection serializes all multi-statement transactions. | IMPLEMENTED_BUT_INCOMPLETE | Pool/transaction redesign, contention tests. | P0 | 10 | PERF-002 |
| PERF-03 | Bounded overview and list queries. Prevents N+1 and unbounded samples. | CODE | Overview N+1 removed; 5,000-zone benchmark shows p95 ~112 ms admin, customer ~72 ms. Verified. | IMPLEMENTED_AND_VERIFIED | Larger-scale and concurrent-load evidence. | P1 | 10 | — |
| PERF-04 | Repeatable capacity benchmark. Validates throughput, latency, memory, and saturation. | CODE | Local single-host benchmark exists; load generator shares CPU; no capacity model. | IMPLEMENTED_BUT_UNVERIFIED | Dedicated load generator, scenarios, published harness. | P1 | 10 | PERF-003 |
| PERF-05 | Cardinality and resource limits. Prevents metric/tenant blowups. | CODE | Bounded qtype/country labels, 32-country cap, 100k limiter keys; no global/per-IP connection caps. | IMPLEMENTED_BUT_INCOMPLETE | Limits per tenant/zone, backpressure, tests. | P1 | 10 | PERF-004 |

### 7.20 High Availability and Reliability

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| HA-01 | Control-plane replicas. Removes single API point of failure. | CODE | Shared PostgreSQL, advisory publication lock, signed agents; no shared RWX zone volume or deterministic writer. | IMPLEMENTED_BUT_INCOMPLETE | Shared storage/queue, leader/writer model, failover tests. | P0 | 10 | HA-001 |
| HA-02 | Shared zone-state storage and publication topology. Ensures replicas serve the same data. | CODE | Zone files are generated on shared filesystem assumptions; Helm declares replicas without RWX volume. | IMPLEMENTED_BUT_INCOMPLETE | Object storage or database-backed publication with versioning. | P0 | 10 | HA-001, PERF-001 |
| HA-03 | PostgreSQL HA and PITR. Removes database single point of failure and data loss. | CF | Single PostgreSQL instance/volume; no backup/PITR/PDB. | NOT_IMPLEMENTED | Managed HA, WAL archiving, failover drills. | P0 | 12 | HA-002, OPS-004 |
| HA-04 | DNS redundancy and global distribution. Survives process, host, or region loss. | CF | Agent replicas exist; compose runs one DNS process; no anycast or multi-region design. | IMPLEMENTED_BUT_INCOMPLETE | Redundant serving, health-based routing, anycast ADR. | P1 | 10 | HA-003 |
| HA-05 | Graceful shutdown, readiness, and failover. Avoids dropping queries or traffic. | CODE | Control API health/ready limited; DNS server no health endpoint; no tested replica failover. | IMPLEMENTED_BUT_INCOMPLETE | Serving probes, graceful drain, failover tests. | P0 | 10 | HA-004, CORE-004 |
| HA-06 | Chaos, soak, DR, and restore testing. Proves resilience. | CF | No chaos/soak/DR test suite; restore never exercised. | NOT_IMPLEMENTED | Game days, fault injection, restore drills. | P1 | 12 | HA-005, OPS-004 |

### 7.21 Admin Dashboard

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| ADM-01 | Admin overview and operational status. Single place to understand the platform. | CF, CODE | `/admin` dashboard, tenant/overview, publication banner, live server probes; verified. | IMPLEMENTED_AND_VERIFIED | Truthful error/disabled states and SLOs. | P1 | 11 | — |
| ADM-02 | Zone and record management UX. Safe day-to-day operations. | CF, CODE | Zones/records pages wired for primary CRUD/import; secondary selector broken; bulk 404; no export UI. | IMPLEMENTED_BUT_INCOMPLETE | Remove/fix dead controls, add import/export, previews. | P0 | 11 | ADM-002, ADM-003 |
| ADM-03 | Audit, agent, server, and config operations UI. Troubleshooting and control. | CF, CODE | Audit page, agents, servers, config push; audit search/export limited; config push copy overstates. | IMPLEMENTED_BUT_INCOMPLETE | Detail/filter/export, truthful copy, lifecycle actions. | P1 | 11 | ADM-004 |
| ADM-04 | Permission-aware controls and role UX. Prevents false affordances. | CF, CODE | GeoDNS/ECS and verification actions can appear for users who receive 403; `user` role missing. | IMPLEMENTED_BUT_INCOMPLETE | Permission-aware rendering and contract tests. | P1 | 11 | UX-001, RBAC-002 |
| ADM-05 | System settings and notification center. Operational configuration without redeploy. | CF | No system settings, persistent notification center, or console impersonation. | NOT_IMPLEMENTED | Settings model, audit, permissions. | P2 | 11 | ADM-005 |

### 7.22 Customer Dashboard

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| CUI-01 | Customer overview. Self-service visibility. | CF, CODE | `/user` dashboard and route guards; verified by platform QA. | IMPLEMENTED_AND_VERIFIED | Better empty/error states and onboarding. | P1 | 11 | — |
| CUI-02 | Customer zone and record management. Core self-service workflow. | CF, CODE | Shared zones/records components; primary CRUD and import wired. | IMPLEMENTED_AND_VERIFIED | Same bulk/export/secondary gaps as admin. | P1 | 11 | ADM-002 |
| CUI-03 | Customer analytics. Usage visibility. | CF, CODE | `/user/analytics`, history and breakdowns; verified. | IMPLEMENTED_AND_VERIFIED | Export, latency/error views, clearer data provenance. | P1 | 11 | — |
| CUI-04 | Accessibility, responsive design, and error states. Inclusive, trustworthy UI. | CF, CODE | Axe 9/9 but modal focus trap, labels, charts, file input, and route error boundary gaps remain. | IMPLEMENTED_BUT_INCOMPLETE | Full WCAG audit and fixes. | P1 | 11 | CUI-003 |
| CUI-05 | Onboarding, help, and notifications. Reduces support load. | CF | Static help page; no guided onboarding, notifications, or support workflow. | NOT_IMPLEMENTED | Onboarding and notification model. | P2 | 11 | CUI-001 |

### 7.23 Operational Management and Troubleshooting

| ID | Capability and why it matters | Source | Current implementation and components | Status | Missing / dependency | Priority | Phase | Task |
|---|---|---|---|---|---|---|---|---|
| OPS-01 | Production Compose topology with TLS and reverse proxy. Deployable baseline. | CODE | Single-host compose; no TLS/proxy/resource limits/DB HA; port 853 exposed but nonfunctional. | IMPLEMENTED_BUT_INCOMPLETE | Production compose, proxy, secrets, limits. | P0 | 12 | OPS-001 |
| OPS-02 | Helm/Kubernetes packaging. Reproducible orchestration. | CODE | Incomplete chart/manifests; namespace, Service/Ingress, ConfigMap, RWX storage, probes, and DB host mismatches. | IMPLEMENTED_BUT_INCOMPLETE | Repair, `helm template`, kubeconform, cluster dry-run. | P1 | 12 | OPS-002 |
| OPS-03 | CI/CD with real tests. Prevents unvalidated releases. | CODE | Invalid action refs, wrong Docker contexts, wrong test target, no DB URL, no UI/lab gates, unsigned `latest`. | IMPLEMENTED_BUT_INCOMPLETE | Repair workflows and release gates. | P0 | 12 | OPS-003 |
| OPS-04 | Monitoring/alerts/runbooks deployment. Operable service. | CODE | Prometheus/Grafana disabled; scrape target wrong; alerts not loaded; no Alertmanager; no runbooks. | IMPLEMENTED_BUT_INCOMPLETE | Deploy, wire, document. | P1 | 12 | OPS-004, OPS-005, MON-001, MON-002 |
| OPS-05 | Certificate, GeoIP, and upgrade lifecycle. Keeps the service current and trusted. | CODE | GeoIP update script exists; no certificate lifecycle; migrations are startup DDL; no upgrade/rollback runbook. | IMPLEMENTED_BUT_INCOMPLETE | Cert automation, migration policy, upgrade tests. | P1 | 12 | OPS-006 |
| OPS-06 | Status page, release signing, SBOM, and support diagnostics. Release maturity. | CF | No status page, signed releases, SBOM/provenance, or support bundle. | NOT_IMPLEMENTED | Release pipeline and diagnostics. | P2 | 12 | OPS-007, OPS-008 |

---

## 8. Missing and Incomplete Features

### 8.1 Priority summary

| Priority | Gaps that must close | Why now |
|---|---|---|
| **P0** | Publication state machine and record-update atomicity; API/DB TLS; secret and DNSSEC-key custody; backup/restore and DR; DNS readiness/probes; quota/rate-limit correctness; CI/deployment truth; broken UI controls. | These cause data loss, outage, unauthorized access, or false confidence. They block any production claim. |
| **P1** | Secondary DNS and complete transfers; scoped API tokens/idempotency/webhooks/OpenAPI; automatic DNSSEC rollover and DS verification; alerting and synthetic probes; account lifecycle; audit detail/export; accessibility; Helm/Compose repair. | Required for a professional platform and credible operations. |
| **P2** | Zone templates/metadata/comments/tags; BIND/CSV import and preview; weighted/health-aware answers; City GeoIP; NSEC3/CDS; SSO; status page; SBOM. | Meaningful customer value after correctness and security are stable. |
| **P3** | Multi-signer DNSSEC; proximity/dynamic steering; custom roles/SCIM; anycast/global network; catalog zones; Terraform provider. | Specialized or capital-intensive; validate demand first. |

### 8.2 Features that appear present but are not backed by behavior

| Surface | Observed behavior | Correct action |
|---|---|---|
| Multi-zone bulk import | UI posts to `/api/v1/zones/bulk`; no route exists (404). | Remove control until ZONE-002 or ZONE-001 delivers the endpoint. |
| Secondary zone selector | UI offers Secondary; backend rejects non-primary. | Hide until SECONDARY-001, or implement the complete protocol path. |
| Certificates | Client methods exist; no backend or page. | Remove dead client code and README claims until OPS-006. |
| Server lifecycle | Client methods for start/stop/restart; backend has CRUD/status only. | Hide actions or implement an agent/supervisor contract. |
| Per-user password reset | Client calls `/users/{id}/password`; no route; admin uses raw UUID form. | Implement CUST-001/RBAC-002. |
| Audit detail | Client calls `/audit/logs/{id}`; no route. | Implement AUD-001 or remove the call. |
| “Push Configuration” | Only sets `sync_requested`; does not deploy zone configuration. | Rename to “Request agent sync” and document. |
| Zone nameserver display | Shows global enabled nameservers for every zone. | Show actual delegation/NS data or label as global defaults. |
| Disabled servers | Dashboard treats disabled as offline/failure. | Render a distinct disabled state. |
| Metrics/alert deployment | Compose scrapes `dns-server:53`; exporter is `127.0.0.1:9000`; alerts are not loaded. | Fix MON-001/MON-002 before claiming monitoring. |

### 8.3 Verified capabilities that must be preserved

Primary zone CRUD, record validation and uniqueness guard, safe create/delete/rename publication, live hot reload, common record serving, DNSSEC signing/DS output, GeoDNS country rules/ECS, tenant scoping and quotas, refresh-token rotation and session revocation, agent signed bundles, zone revisions, persistent analytics, overview N+1 removal, browser QA, and accessibility baseline. The roadmap must extend these, not rewrite them.

---

## 9. Target Product Architecture

The architecture keeps Hickory as the DNS engine and the existing Rust control plane as the management foundation. New capabilities are added through explicit module boundaries: a publication/transfer layer, an automation API layer, and an operations layer. No module requires a wholesale rewrite.

### 9.1 DNS Core

- **Purpose:** Serve correct authoritative answers over required transports with predictable resource use.
- **Required functionality:** UDP/TCP, IPv4/IPv6, hot reload, common record types, DNSSEC serving, query metrics, rate limits, health/readiness.
- **Advanced functionality:** DoT/DoH/DoQ/DoH3, per-zone reload, RFC 2136, response-rate limiting, anycast.
- **Dependencies:** `crates/server`, `crates/proto`, `bin`, control-plane zone generation.
- **Backend responsibilities:** Catalog and store correctness, transport lifecycle, reload atomicity, query accounting, protocol enforcement.
- **API requirements:** No public query API; control-plane transport/listener settings and status endpoints.
- **Database requirements:** None for query serving; zone data arrives through files or a future database-backed store.
- **Frontend requirements:** Read-only transport/listener status and health in the admin console.
- **Security considerations:** TSIG/SIG(0), amplification limits, PII-safe logging, TLS certificate handling, resource caps.
- **Testing requirements:** Protocol conformance, dual-stack, malformed packets, reload under load, fuzzing, soak/load.

### 9.2 Zone Management

- **Purpose:** Provide safe lifecycle operations for hosted zones, including verification and migration.
- **Required functionality:** Primary CRUD, verification, import/export, history/rollback, publication status, ownership transfer, quotas.
- **Advanced functionality:** BIND import, templates, metadata/tags, holds/archive, catalog zones.
- **Dependencies:** DNS Core, Record Management, Tenancy, Audit, Publication.
- **Backend responsibilities:** Transactional state changes, verification jobs, import validation, revision capture.
- **API requirements:** Zone CRUD, verify, import/export, bulk, revisions, metadata, hold.
- **Database requirements:** Zone status/hold fields, metadata/tags, revision retention, import job state.
- **Frontend requirements:** Lifecycle states, import preview, export, filters, revision diff, permission-aware actions.
- **Security considerations:** Ownership verification, hold/transfer locks, tenant isolation, import size limits.
- **Testing requirements:** Concurrent create/rename/delete, verification success/failure, import limits, rollback.

### 9.3 DNS Record Management

- **Purpose:** Manage RRsets safely and efficiently without corrupting zone semantics.
- **Required functionality:** CRUD, validation, uniqueness, TTL/priority, advanced types, import/export, history.
- **Advanced functionality:** RRset batch API, preview, comments/tags, aliases/flattening, conflict detection.
- **Dependencies:** Zone Management, DNS Core, Publication.
- **Backend responsibilities:** Normalize values, enforce RRset rules, reject DNSSEC/geo conflicts, publish atomically.
- **API requirements:** Record CRUD, batch/RRset operations, import with dry-run, comments/tags.
- **Database requirements:** Comments/tags, operation/idempotency keys, RRset-safe constraints.
- **Frontend requirements:** Type-aware editor, bulk preview, delete confirmation, diff/history.
- **Security considerations:** Input limits, owner-name scoping, NS allowlists, no secret leakage in errors.
- **Testing requirements:** Boundary values, malformed records, concurrent duplicates, publication failure/rollback.

### 9.4 DNSSEC

- **Purpose:** Provide trustworthy signing, key lifecycle, and delegation verification.
- **Required functionality:** Enable/disable, key generation, DS/DNSKEY output, algorithms, NSEC, fail-closed publication.
- **Advanced functionality:** NSEC3, KSK/ZSK separation, automatic rollover, CDS/CDNSKEY, multi-signer, KMS/HSM.
- **Dependencies:** Record/Zone Management, secret storage, publication, delegation checker.
- **Backend responsibilities:** Key state machine, signing, DS encoding, parent checks, backup/restore.
- **API requirements:** Status, enable/disable, rollover/complete, key inventory, DS verification.
- **Database requirements:** Key metadata/state, encrypted material or external key references, rollover events.
- **Frontend requirements:** Safe rollover guidance, algorithm display, DS copy, key state, warnings.
- **Security considerations:** Key custody, least privilege, audit, no plaintext keys, recovery runbooks.
- **Testing requirements:** `delv` chains, negative/NSEC3 cases, rollover, missing-key failure, DS mismatch.

### 9.5 Primary/Secondary DNS

- **Purpose:** Operate primary and secondary authoritative roles with correct refresh and failure behavior.
- **Required functionality:** Secondary zone configuration, primary peers, SOA timers, serial checks, status.
- **Advanced functionality:** Promotion/failover, multi-primary, conflict resolution, hidden primaries.
- **Dependencies:** Transfers, DNS Core, Zone Management, Audit.
- **Backend responsibilities:** Refresh scheduler, transfer client, serial comparison, state transitions.
- **API requirements:** Secondary CRUD, peer configuration, refresh/retry, promotion.
- **Database requirements:** Peer/zone role, transfer state, serial/lag, timers.
- **Frontend requirements:** Role, peer, freshness, last transfer, error state, promotion controls.
- **Security considerations:** Authenticated transfers, peer allowlists, no open recursion, audit.
- **Testing requirements:** Refresh/retry/expire, primary failure, promotion, serial rollback, isolation.

### 9.6 Zone Transfers

- **Purpose:** Implement standards-based, authenticated, observable AXFR/IXFR/NOTIFY.
- **Required functionality:** AXFR over TCP, multi-message streaming, IXFR, NOTIFY, TSIG, ACLs.
- **Advanced functionality:** SIG(0), catalog zones, transfer metrics, transfer history.
- **Dependencies:** DNS Core, Primary/Secondary, key management.
- **Backend responsibilities:** Stream generation, journal/IXFR, authentication, retry, audit.
- **API requirements:** Transfer policy, TSIG keys, peers, status/history.
- **Database requirements:** Keys, peers, ACLs, transfer events, journal metadata.
- **Frontend requirements:** Policy editor, key rotation, transfer status/history.
- **Security considerations:** Prevent open transfers, constant-time auth, key rotation, replay/rate limits.
- **Testing requirements:** TCP-only enforcement, multi-message, IXFR fallback, NOTIFY retries, TSIG failure.

### 9.7 GeoDNS

- **Purpose:** Return location-aware answers without violating DNS or DNSSEC semantics.
- **Required functionality:** Country/city/region rules, ECS, deterministic ordering, validation, dataset status.
- **Advanced functionality:** Weights, multiple targets, health-aware selection, signed synthesis.
- **Dependencies:** DNS Core, GeoIP data, Traffic Management, DNSSEC.
- **Backend responsibilities:** Rule evaluation, answer synthesis, ECS scope, dataset reload.
- **API requirements:** Geo rule CRUD, resolve/test, dataset status, pagination.
- **Database requirements:** Rules, targets, dataset metadata, versioning.
- **Frontend requirements:** Rule editor, test tool, dataset freshness, precedence display.
- **Security considerations:** ECS privacy, dataset license, no invented names, cardinality caps.
- **Testing requirements:** IPv4/IPv6, private/unknown IPs, precedence, ECS, stale dataset, signed zones.

### 9.8 Traffic Management

- **Purpose:** Express and execute routing policies beyond static records.
- **Required functionality:** Weighted answers, pools, health-aware failover, policy validation.
- **Advanced functionality:** Latency/proximity/dynamic steering, policy simulation, canary rollout.
- **Dependencies:** GeoDNS, Health Checks, Analytics.
- **Backend responsibilities:** Policy model, deterministic selection, health gating, fallback.
- **API requirements:** Policy CRUD, simulation, activation, status.
- **Database requirements:** Policies, pools, targets, weights, versions.
- **Frontend requirements:** Policy builder, preview, health overlay, rollback.
- **Security considerations:** Prevent self-targeting loops, cap fan-out, audit changes.
- **Testing requirements:** Determinism, weights, health transitions, fail-open/closed, signed-zone interactions.

### 9.9 Health Checks and Failover

- **Purpose:** Determine whether targets and serving paths are healthy and act on that state.
- **Required functionality:** Health-check model, schedulers, state history, failover policy, DNS readiness.
- **Advanced functionality:** Multi-region probes, quorum, adaptive thresholds, maintenance windows.
- **Dependencies:** Traffic Management, Monitoring, DNS Core.
- **Backend responsibilities:** Probe workers, state machines, debounce, failover evaluation, audit.
- **API requirements:** Monitor CRUD, test, pause, status/history.
- **Database requirements:** Monitors, results, state transitions, policy bindings.
- **Frontend requirements:** Monitor builder, health timeline, current state, alert links.
- **Security considerations:** SSRF-safe probes, rate limits, credential isolation.
- **Testing requirements:** Flap suppression, timeout/error cases, quorum, failover and recovery.

### 9.10 DNS Analytics

- **Purpose:** Provide trustworthy usage, error, and performance insight per customer and platform.
- **Required functionality:** Query counts, RCODE/type/country breakdowns, historical ranges, tenant scoping.
- **Advanced functionality:** Latency histograms, NXDOMAIN/SERVFAIL trends, query-log export, anomaly detection.
- **Dependencies:** DNS metrics, collector, PostgreSQL/time-series storage, tenants.
- **Backend responsibilities:** Collection, aggregation, retention, tenant-safe queries, provenance.
- **API requirements:** Query metrics, history, breakdowns, export, health of collection.
- **Database requirements:** Partitioned/rollup tables, retention policies, indexes.
- **Frontend requirements:** Honest charts, range controls, missing-data states, export.
- **Security considerations:** PII minimization, tenant isolation, cardinality limits.
- **Testing requirements:** Exact-count labs, restart persistence, invalid ranges, retention, scale.

### 9.11 Monitoring and Alerting

- **Purpose:** Detect and route operational problems before customers report them.
- **Required functionality:** Metrics scrape, alert rules, Alertmanager, publication/agent/DB alerts, synthetic probes.
- **Advanced functionality:** SLOs/error budgets, multi-window burn rates, status page integration.
- **Dependencies:** DNS/API metrics, Analytics, deployment.
- **Backend responsibilities:** Stable metric names/labels, health endpoints, alertable events.
- **API requirements:** Metrics endpoints, protected admin status, alert test hooks.
- **Database requirements:** Minimal; alert state belongs to Alertmanager or a dedicated store.
- **Frontend requirements:** Operational dashboard, alert links, runbook links.
- **Security considerations:** Metrics auth/TLS, network isolation, no PII in labels/logs.
- **Testing requirements:** Rule unit tests, scrape tests, alert delivery, synthetic probe failure.

### 9.12 Customer Management

- **Purpose:** Manage account lifecycle and customer identity safely.
- **Required functionality:** User CRUD, MFA, invites, suspension, password reset, session control.
- **Advanced functionality:** SSO, SCIM, email verification, notification preferences, impersonation with audit.
- **Dependencies:** Auth, tenancy, email provider, audit.
- **Backend responsibilities:** Lifecycle state machine, tokens, email jobs, policy enforcement.
- **API requirements:** Users, invitations, reset, suspend/reactivate, sessions, SSO.
- **Database requirements:** Lifecycle status, invite/reset tokens, identity links, notification prefs.
- **Frontend requirements:** User list, invite flow, lifecycle states, MFA recovery, session management.
- **Security considerations:** Enumeration resistance, token expiry, recovery abuse prevention, audit.
- **Testing requirements:** Invite expiry, reset replay, suspension, MFA recovery, SSO mapping.

### 9.13 Multi-Tenancy

- **Purpose:** Isolate tenants and enforce quotas while supporting organizational growth.
- **Required functionality:** Tenants, membership, personal tenants, quotas, tenant moves, isolation tests.
- **Advanced functionality:** Hierarchy/reseller model, usage reporting, billing, delegated admin.
- **Dependencies:** Auth/RBAC, zones/records, analytics.
- **Backend responsibilities:** Authoritative tenant scoping, atomic quota enforcement, move transactions.
- **API requirements:** Tenant CRUD, members, quotas/usage, move zone, hierarchy.
- **Database requirements:** Tenant/member tables, quota/usage counters, foreign keys/indexes.
- **Frontend requirements:** Tenant selector, quota/usage cards, move flow, admin bypass visibility.
- **Security considerations:** Cross-tenant negative tests, admin bypass audit, no IDOR.
- **Testing requirements:** Property-based scoping, quota concurrency, move isolation, deletion cleanup.

### 9.14 RBAC and Permissions

- **Purpose:** Grant the minimum access needed for platform, tenant, zone, and automation work.
- **Required functionality:** Global roles, zone membership, viewer read-only, owner-only actions.
- **Advanced functionality:** Custom roles, granular permissions, SSO group mapping, time-bound access.
- **Dependencies:** Auth, tenancy, API, UI.
- **Backend responsibilities:** Central policy enforcement, permission-aware serializers, audit.
- **API requirements:** Roles, permissions, assignments, effective-access introspection.
- **Database requirements:** Role/permission catalog, assignments, scope bindings.
- **Frontend requirements:** Role editor, effective-permission display, hidden/disabled actions.
- **Security considerations:** Deny by default, no client-only enforcement, privilege escalation tests.
- **Testing requirements:** Role matrix, cross-tenant access, owner/editor/viewer, custom roles.

### 9.15 API and Automation

- **Purpose:** Provide a reliable contract for infrastructure automation and integrations.
- **Required functionality:** Versioned REST, pagination, error catalog, idempotency, scoped tokens, rate limits.
- **Advanced functionality:** Webhooks, async jobs, OpenAPI, SDK/CLI, Terraform provider, bulk operations.
- **Dependencies:** Core control-plane modules, auth/RBAC, audit.
- **Backend responsibilities:** Contract stability, idempotent mutation, job orchestration, event delivery.
- **API requirements:** OpenAPI spec, token management, idempotency, jobs, events, dry-run.
- **Database requirements:** Idempotency keys, jobs, events/outbox, token scopes.
- **Frontend requirements:** Token management, job status, webhook configuration, API docs.
- **Security considerations:** Scope minimization, token expiry, replay protection, SSRF-safe webhooks.
- **Testing requirements:** Contract tests, retry/replay, pagination, rate limits, webhook signatures.

### 9.16 Audit and Activity History

- **Purpose:** Provide trustworthy, queryable evidence of who changed what and when.
- **Required functionality:** Mutation coverage, actor/resource/details/IP/time, retention, filters, export.
- **Advanced functionality:** Detail view, tamper evidence, SIEM export, customer activity views.
- **Dependencies:** All mutating modules, auth, tenancy.
- **Backend responsibilities:** Event schema, append path, redaction, retention, query/indexing.
- **API requirements:** List/detail, filters, export, retention config.
- **Database requirements:** Indexed append-only table, optional hash chain/archive.
- **Frontend requirements:** Server-side search/filter, detail drawer, export, permission-aware views.
- **Security considerations:** No secrets/key material, tamper resistance, tenant visibility rules.
- **Testing requirements:** Coverage matrix, failed-write semantics, filters, retention, tamper checks.

### 9.17 Backup and Recovery

- **Purpose:** Restore service and data after corruption, deletion, key loss, or region failure.
- **Required functionality:** PostgreSQL backup/PITR, zone/config export, DNSSEC key backup, restore verification.
- **Advanced functionality:** Cross-region copies, immutable backups, automated drills, per-tenant restore.
- **Dependencies:** Database, object storage/KMS, DNSSEC, operations.
- **Backend responsibilities:** Backup jobs, encryption, retention, restore APIs/CLI, integrity checks.
- **API requirements:** Backup status, trigger, download/restore, audit.
- **Database requirements:** Backup metadata; PITR managed externally.
- **Frontend requirements:** Backup status, restore wizard, warnings, audit trail.
- **Security considerations:** Encryption at rest/in transit, access control, key escrow, no plaintext dumps.
- **Testing requirements:** Restore drills, checksum verification, RPO/RTO measurement, partial failure.

### 9.18 Security and Abuse Protection

- **Purpose:** Protect accounts, APIs, DNS service, and tenants from abuse and compromise.
- **Required functionality:** TLS, secret management, MFA, rate limits, zone ownership, audit, secure headers.
- **Advanced functionality:** Abuse scoring, response-rate limiting, WAF integration, anomaly detection.
- **Dependencies:** Auth, API, DNS Core, operations.
- **Backend responsibilities:** Enforce policy server-side, fail closed on key errors, emit security events.
- **API requirements:** Token scopes, security settings, abuse reports, key rotation.
- **Database requirements:** Security events, abuse state, key references.
- **Frontend requirements:** Security settings, audit visibility, recovery flows.
- **Security considerations:** Threat model, least privilege, blast-radius reduction, supply chain.
- **Testing requirements:** Auth bypass, IDOR, SSRF, rate limits, secret scanning, dependency scans.

### 9.19 Performance and Scalability

- **Purpose:** Maintain predictable latency and cost as zones, records, and tenants grow.
- **Required functionality:** Incremental publication, DB concurrency, bounded queries, cardinality limits.
- **Advanced functionality:** Sharding, read replicas, regional publication, autoscaling, load shedding.
- **Dependencies:** Publication, database, metrics, HA.
- **Backend responsibilities:** Queue/worker model, efficient SQL, resource limits, backpressure.
- **API requirements:** Job status, capacity/usage endpoints, pagination.
- **Database requirements:** Indexes, partitioning, connection pool tuning.
- **Frontend requirements:** Performance-safe lists, virtualized tables, loading states.
- **Security considerations:** Prevent resource-exhaustion attacks; per-tenant fairness.
- **Testing requirements:** Load, stress, soak, query-plan, cardinality, failure injection.

### 9.20 High Availability and Reliability

- **Purpose:** Serve DNS and control-plane operations through component and region failures.
- **Required functionality:** Redundant DNS, multi-replica API, shared state, DB HA, readiness, graceful drain.
- **Advanced functionality:** Multi-region, anycast, automated failover, chaos engineering.
- **Dependencies:** Publication, database, deployment, observability.
- **Backend responsibilities:** Leader/writer election, idempotent publication, replica convergence, health.
- **API requirements:** Topology/status, failover controls, maintenance mode.
- **Database requirements:** HA configuration, replication, PITR.
- **Frontend requirements:** Health/topology view, incident banner, maintenance state.
- **Security considerations:** Split-brain prevention, quorum, credential distribution.
- **Testing requirements:** Replica kill, DB failover, network partition, DNS failover, restore.

### 9.21 Admin Dashboard

- **Purpose:** Give platform operators a truthful, actionable view and safe controls.
- **Required functionality:** Overview, zones/records, servers/agents, tenants, audit, analytics, settings.
- **Advanced functionality:** SLOs, capacity, incident mode, impersonation with audit, bulk operations.
- **Dependencies:** All control-plane modules; API/UI contract.
- **Backend responsibilities:** Efficient aggregate endpoints, permission checks, status truth.
- **API requirements:** Overview, health, publication, agent/replica status, settings.
- **Database requirements:** Aggregate-friendly indexes; no new source of truth.
- **Frontend requirements:** Honest empty/error states, permission-aware actions, drill-down, responsive.
- **Security considerations:** Admin-only enforcement, CSRF/XSS defense, safe impersonation.
- **Testing requirements:** Browser journeys, permission matrix, error injection, accessibility.

### 9.22 Customer Dashboard

- **Purpose:** Let customers manage DNS and understand usage without operator intervention.
- **Required functionality:** Zones/records, analytics, DNSSEC/GeoDNS, settings, activity, help.
- **Advanced functionality:** Onboarding, notifications, API tokens, export, support diagnostics.
- **Dependencies:** Admin capabilities exposed through scoped APIs.
- **Backend responsibilities:** Tenant scoping, quotas, safe defaults, clear errors.
- **API requirements:** Customer-safe endpoints, usage, activity, settings.
- **Database requirements:** Same underlying data; no duplicate customer store.
- **Frontend requirements:** Guided flows, accessible charts, export, error recovery.
- **Security considerations:** Tenant isolation, least privilege, no enumeration.
- **Testing requirements:** End-to-end journeys, quota errors, permissions, accessibility.

### 9.23 Operational Management and Troubleshooting

- **Purpose:** Deploy, upgrade, observe, and repair the platform with repeatable procedures.
- **Required functionality:** Reproducible deployment, migrations, monitoring, backups, runbooks, diagnostics.
- **Advanced functionality:** GitOps, canary, automated rollback, status page, support bundles.
- **Dependencies:** All modules; CI/CD; infrastructure.
- **Backend responsibilities:** Health/status endpoints, migration safety, structured logs, diagnostics.
- **API requirements:** Health/ready, version, config validation, support bundle.
- **Database requirements:** Migration ledger, safe DDL, backup hooks.
- **Frontend requirements:** Version/health display, maintenance banner, admin diagnostics.
- **Security considerations:** Least-privilege deployment, secret injection, signed artifacts.
- **Testing requirements:** Upgrade/downgrade, migration rollback, restore, runbook drills.

---

## 10. Multi-Phase Implementation Roadmap

Phases are dependency layers, not strictly serial calendar blocks. Security, testing, and documentation are continuous. A phase is complete only when its tasks meet the definition of done, including tests and operational documentation.

### Phase 0 — Architecture and Correctness Baseline

- **Objectives:** Establish the invariants, topology, and contracts every later phase depends on.
- **Features/tasks:** ARCH-001 through ARCH-008; ZONE-06, REC-02, BAK-05.
- **Backend/API/DB/DNS:** Reconcile runtime DDL with migrations; write publication-state ADR; design transaction concurrency; remove/fix dead UI endpoints; decide secondary scope; establish secret baseline and topology/SLOs.
- **Frontend:** Remove dead controls; add route-contract tests; make publication/health state truthful.
- **Security/reliability:** Rotate tracked secrets; define key custody and RPO/RTO; choose single-host or replicated topology.
- **Tests:** Schema-drift test, migration-from-empty test, route-contract tests, publication failure matrix, secret scan.
- **Dependencies/risks:** No functional dependency. Risk: architecture decisions may change task ordering; resolve before broad implementation.
- **Acceptance/DoD:** ADRs approved; CI can prove schema parity; no dead control is reachable; secret rotation plan executed; topology and SLOs documented.

### Phase 1 — DNS Core and Protocol Correctness

- **Objectives:** Make the authoritative serving path standards-correct and observable.
- **Features/tasks:** CORE-001 through CORE-013; XFR-01/02/03; HLTH-01.
- **Backend/API/DB/DNS:** AXFR over TCP with streaming; IXFR/NOTIFY; DNS health/readiness; concurrency caps; PII-safe logging; cache defaults; DoH3 wiring; type policy; per-zone reload.
- **Frontend:** Transport/listener status; remove incorrect protocol claims.
- **Security/reliability:** Amplification controls, rate limits, per-connection caps, certificate path.
- **Tests:** Protocol conformance (`dig`, `delv`, Zonemaster-style checks), AXFR/IXFR/NOTIFY labs, dual-stack, malformed packets, load.
- **Dependencies/risks:** Phase 0. Risk: Hickory engine changes affect upstream merge strategy; keep changes isolated.
- **Acceptance/DoD:** AXFR/IXFR/NOTIFY pass interoperability tests; DNS readiness reflects serving state; no unbounded query task growth under load.

### Phase 2 — Complete Zone and Record Management

- **Objectives:** Make migration, bulk editing, history, and lifecycle safe for real customers.
- **Features/tasks:** ZONE-001 through ZONE-008; REC-001 through REC-006; BAK-01.
- **Backend/API/DB/DNS:** BIND/CSV import with dry-run; multi-zone bulk; templates; metadata/tags; verification/hold; revision diff; batch/RRset operations.
- **Frontend:** Import preview/errors, export, template picker, record diff/delete confirmation, permission-aware actions.
- **Security/reliability:** Size limits, rate limits, ownership verification, atomic apply, audit.
- **Tests:** Migration fixtures, malformed/quoted records, partial errors, concurrent edits, rollback.
- **Dependencies/risks:** Phase 0/1. Risk: import parsing and publication consistency; use one validated pipeline.
- **Acceptance/DoD:** A 256 KiB-class zone imports with preview and per-row errors; export round-trips; no 404/dead bulk path remains.

### Phase 3 — DNSSEC and Key Security

- **Objectives:** Make DNSSEC operationally safe, recoverable, and automatable.
- **Features/tasks:** DNSSEC-001 through DNSSEC-009; BAK-03.
- **Backend/API/DB/DNS:** KMS/encrypted key store; automatic rollover; NSEC3/CDS/CDNSKEY; key backup; DS verification; safe rollover UI; conformance tests.
- **Frontend:** Key state, algorithm, DS copy, rollover guidance, warnings.
- **Security/reliability:** Key custody, least privilege, audit, compromise runbook, fail-closed behavior.
- **Tests:** `delv` parent-child chain, NSEC3 negative cases, rollover, DS mismatch, missing key, backup restore.
- **Dependencies/risks:** Phase 0/2. Risk: key loss or wrong DS causes global outage; use staged labs and dual-signing where possible.
- **Acceptance/DoD:** Keys encrypted and backed up; automatic rollover tested in a lab; DS mismatch is detected before/alerted after publication.

### Phase 4 — Primary/Secondary, Transfers, and Replication

- **Objectives:** Deliver real secondary DNS and standards-based replication.
- **Features/tasks:** PS-01 through PS-05; XFR-04/05/06; SECONDARY-001 through SECONDARY-004; TRANSFER-001 through TRANSFER-003; REPL-001 through REPL-003; CORE-012.
- **Backend/API/DB/DNS:** Peer model, SOA refresh, TSIG keys/ACLs, transfer client/server, NOTIFY, promotion, conflict policy, status, agent hardening.
- **Frontend:** Secondary/peer/key/transfer screens; freshness and errors.
- **Security/reliability:** Authenticated transfers, least privilege, no open transfer, audit, split-brain prevention.
- **Tests:** Interop with BIND/Knot/PowerDNS, refresh/retry/expire, promotion, conflict, TSIG/SIG(0), replica convergence.
- **Dependencies/risks:** Phase 1. Risk: largest protocol/design item; scope secondary explicitly and do not ship labels.
- **Acceptance/DoD:** A zone can be served by a secondary, refreshed by NOTIFY/AXFR/IXFR, and promoted safely; operators can see lag and errors.

### Phase 5 — GeoDNS, Traffic Management, and Health Checks

- **Objectives:** Add routing policies only after health and data foundations exist.
- **Features/tasks:** GEO-001 through GEO-005; TRAF-001 through TRAF-004; HLTH-001/002; DNSSEC-007.
- **Backend/API/DB/DNS:** Weights, multiple targets, pools, health state, steering policies, City data, signed synthesis decision.
- **Frontend:** Policy builder, simulation, health overlay, dataset status.
- **Security/reliability:** SSRF-safe monitors, ECS privacy, deterministic selection, fail-open/closed policy.
- **Tests:** Weight/health transitions, proximity/latency simulation, signed/unsigned zones, stale datasets.
- **Dependencies/risks:** Phase 1/3/4. Risk: complexity and DNSSEC conflict; implement weighted/failover before proximity/dynamic.
- **Acceptance/DoD:** Operators can preview, activate, and roll back a weighted/failover policy with health-driven behavior and tests.

### Phase 6 — Analytics, Monitoring, and Alerting

- **Objectives:** Make the platform observable and alertable end to end.
- **Features/tasks:** ANA-001 through ANA-006; MON-001 through MON-005; HLTH-004.
- **Backend/API/DB/DNS:** Query-log pipeline, latency/error history, export, fixed scrape, Alertmanager, synthetic probes, PII controls.
- **Frontend:** Honest analytics, export, SLO/ops dashboards, alert links.
- **Security/reliability:** Metrics auth/TLS, redaction, cardinality limits, retention.
- **Tests:** Exact-count analytics, restart persistence, invalid ranges, alert delivery, probe failure, metric contract.
- **Dependencies/risks:** Phase 1/5. Risk: privacy and cardinality; make query logs opt-in and sampled.
- **Acceptance/DoD:** A synthetic DNS failure produces an alert with a runbook link; analytics survive restart and match known counts.

### Phase 7 — API and Automation

- **Objectives:** Provide a reliable automation contract and least-privilege access.
- **Features/tasks:** API-001 through API-010.
- **Backend/API/DB/DNS:** OpenAPI, idempotency, scoped tokens, quotas, webhooks, async jobs/bulk, consistent pagination/errors, CLI/SDK, Terraform.
- **Frontend:** Token management, job status, webhook settings, API docs.
- **Security/reliability:** Scope enforcement, expiry/rotation, replay protection, SSRF-safe webhooks.
- **Tests:** Contract tests, retries/replays, token scopes, quota 429s, webhook signatures, provider acceptance.
- **Dependencies/risks:** Phase 0/2/3. Risk: API surface expands faster than enforcement; spec-first and contract tests are mandatory.
- **Acceptance/DoD:** A CI client can create/update/delete a zone idempotently with a scoped token and receive a signed webhook.

### Phase 8 — Multi-Tenancy, RBAC, and Enterprise Management

- **Objectives:** Support teams, resellers, and enterprise identity without weakening isolation.
- **Features/tasks:** CUST-001 through CUST-004; TEN-001 through TEN-005; RBAC-001/002; AUD-001/002; AUD-004.
- **Backend/API/DB/DNS:** Invite/lifecycle, SSO/SCIM, quota race fixes, hierarchy, custom roles, audit detail/tamper evidence.
- **Frontend:** Invite/suspend, role editor, tenant hierarchy, usage, activity history.
- **Security/reliability:** Deny by default, cross-tenant negative tests, recovery abuse prevention.
- **Tests:** Property-based isolation, role matrix, invite/reset replay, quota concurrency, audit coverage.
- **Dependencies/risks:** Phase 7. Risk: enterprise scope creep; deliver SSO/SCIM behind demand gates.
- **Acceptance/DoD:** Cross-tenant access attempts fail in automated tests; quotas cannot overshoot under concurrency; admins can audit every mutation.

### Phase 9 — Platform Security and Abuse Protection

- **Objectives:** Close transport, secret, browser, and abuse gaps.
- **Features/tasks:** SEC-001 through SEC-008.
- **Backend/API/DB/DNS:** API TLS/proxy, DB TLS, secret manager, JWT rotation, MFA encryption/recovery, CSP/cookies, abuse controls, supply chain.
- **Frontend:** Secure session storage, security settings, recovery, security headers.
- **Security/reliability:** Threat model, key separation, blast-radius limits, response-rate limiting, SBOM.
- **Tests:** TLS scans, auth bypass/IDOR/SSRF, CSP, rate limits, secret scanning, dependency/SBOM gates.
- **Dependencies/risks:** Phase 0/3/7. Risk: TLS/secret migrations can lock out operators; stage with rollback.
- **Acceptance/DoD:** No plaintext credentials or keys at rest/in transit; security regression suite passes; token rotation is rehearsed.

### Phase 10 — Performance, High Availability, and Resilience

- **Objectives:** Remove architectural scaling ceilings and prove failure behavior.
- **Features/tasks:** PERF-001 through PERF-005; HA-001 through HA-006; CORE-004; OPS-004.
- **Backend/API/DB/DNS:** Publication queue/incremental generation, DB concurrency, indexes, resource limits, replicated API, shared state, DB HA/PITR, DNS redundancy.
- **Frontend:** Topology/health, capacity, maintenance mode.
- **Security/reliability:** Split-brain prevention, quorum, failover, backup/restore, graceful drain.
- **Tests:** Load/soak/chaos, DB failover, replica kill, publication convergence, restore drills, capacity report.
- **Dependencies/risks:** Phase 0/1/6/9. Risk: distributed-systems complexity; do not claim HA without repeatable failure tests.
- **Acceptance/DoD:** Defined SLO/RTO/RPO are met in a drill; publication converges across replicas; no single process/DB is an unmitigated SPOF.

### Phase 11 — Admin and Customer Experience

- **Objectives:** Make every visible control truthful, accessible, and safe.
- **Features/tasks:** ADM-001 through ADM-005; CUI-001 through CUI-005; UX-001; RBAC-002.
- **Backend/API/DB/DNS:** Aggregate/status endpoints, settings, notification model, permission-aware responses.
- **Frontend:** Dashboard truth, bulk/export/import UX, record diff/confirm, audit UX, onboarding, accessibility, error states.
- **Security/reliability:** Permission-aware rendering, XSS/CSP, safe impersonation, no data leakage.
- **Tests:** Browser journeys, permission matrix, error injection, WCAG audit, visual regression.
- **Dependencies/risks:** Phase 7/8/9. Risk: UI can mask backend gaps; contract tests gate every control.
- **Acceptance/DoD:** No visible action returns an undocumented 404/403; accessibility audit has no critical issues; error states are distinguishable from empty states.

### Phase 12 — Production Readiness and Operational Maturity

- **Objectives:** Make deployment, upgrade, recovery, and support repeatable.
- **Features/tasks:** OPS-001 through OPS-008; BAK-002/004/005; HA-002/006.
- **Backend/API/DB/DNS:** Production Compose/TLS/proxy, Helm/K8s repair, CI gates, backup/PITR, runbooks, cert/GeoIP/upgrade automation, status page/release signing.
- **Frontend:** Version/health/maintenance/status surfaces.
- **Security/reliability:** Signed artifacts, SBOM, secret injection, least-privilege deployment.
- **Tests:** `helm template`/kubeconform, compose smoke, restore drill, upgrade/downgrade, runbook exercise.
- **Dependencies/risks:** All prior phases. Risk: declaring readiness without external validation; require evidence, not documentation.
- **Acceptance/DoD:** A new environment can be deployed, upgraded, backed up, restored, and monitored from documented steps; release artifacts are signed and traceable.

---

## 11. Detailed Task Breakdown with IDs

Each task states an implementable outcome and a verification method. Dependencies are task IDs unless marked “external”. “Tests” means committed automated tests plus any required lab evidence.

| ID | Phase | Priority | Implementable outcome and verification | Depends on |
|---|---|---|---|---|
| ARCH-001 | 0 | P0 | Reconcile runtime DDL with SQL migrations; add a migration-from-empty and schema-drift test; preserve the `uq_records_rrset_value` invariant. Verify on SQLite/PostgreSQL test databases. | — |
| ARCH-002 | 0 | P0 | Write and approve the publication state-machine ADR: outbox schema, per-zone job, retry/backoff, last-known-good, replica ack, failure semantics. Add a failure-mode test matrix. | ARCH-001 |
| ARCH-003 | 0 | P0 | Design and benchmark transaction-concurrency options (dedicated writer vs pool slots vs per-tenant queue); choose one with measured contention and rollback behavior. | ARCH-002 |
| ARCH-004 | 0 | P0 | Inventory every UI route/client method against backend routes; remove or gate dead controls (bulk, secondary, certificates, server lifecycle, user password, audit detail); add route-contract tests. | — |
| ARCH-005 | 0 | P1 | Reconcile `TASK_STATUS.md`, `AUDIT_REPORT.md`, `DELIVERY_SUMMARY.md`, README/SETUP claims with Git and executed evidence; add a docs consistency check. | ARCH-004 |
| ARCH-006 | 0 | P0 | Approve an ADR that either commits to full secondary/transfer support or explicitly removes the feature from the product; record scope, effort, and non-goals. | — |
| ARCH-007 | 0 | P0 | Rotate tracked live-looking secrets, add `.env`/`env/*.env`/K8s secret exclusions, add secret scanning, and document history-purge decision without rewriting history silently. | — |
| ARCH-008 | 0 | P0 | Approve topology, SLO, RPO, and RTO for single-host and replicated modes; map dependencies and required infrastructure. | ARCH-002, ARCH-006 |
| CORE-001 | 1 | P1 | Enforce AXFR over TCP only; stream multiple messages; keep per-zone policy; add interop tests with `dig` and BIND/Knot clients. | ARCH-006 |
| CORE-002 | 1 | P1 | Implement IXFR server/client or explicitly reject it with a documented decision and tests; integrate journal/serial behavior where supported. | CORE-001 |
| CORE-003 | 1 | P1 | Implement NOTIFY sender and receiver with retry/backoff, TSIG integration, and tests for accepted, refused, and timed-out notifications. | CORE-001 |
| CORE-004 | 1 | P0 | Add DNS `/health` and `/ready` endpoints that check listeners, catalog load, key availability, and publication freshness; wire compose/Helm probes. | — |
| CORE-005 | 1 | P1 | Add bounded concurrency for UDP tasks, TCP/TLS connections, and HTTP/2 streams; add load tests proving backpressure and no port exhaustion. | CORE-004 |
| CORE-006 | 1 | P1 | Make query/response logging configurable by level/sampling; redact or omit client IP and query names by default; add PII tests. | — |
| CORE-007 | 1 | P2 | Raise/configure forwarder cache defaults, document recursion versus forwarding, and add cache-hit/miss and expiry tests. | CORE-009 |
| CORE-008 | 1 | P1 | Build a repeatable protocol-conformance suite: `dig`, `delv`, Zonemaster-style delegation/DNSSEC checks, malformed packets, and dual-stack. | CORE-001, CORE-004 |
| CORE-009 | 1 | P2 | Define the forwarding/recursion product boundary; harden cache size, AXFR denial, trust anchors, and operational documentation. | ARCH-008 |
| CORE-010 | 1 | P1 | Wire DoH3 into the binary or remove H3 claims; add TLS/HTTPS/QUIC/H3 startup and certificate-path tests. | CORE-004, CORE-005 |
| CORE-011 | 1 | P2 | Define supported record types and add DNAME/LOC/etc. support or explicit rejects; expose advanced types in API/UI with round-trip tests. | ARCH-001 |
| CORE-012 | 4 | P2 | Define RFC 2136 update policy, require TSIG/SIG(0), support file/in-memory stores or document SQLite-only; add prerequisite/prescan tests. | CORE-001, TRANSFER-002 |
| CORE-013 | 1 | P1 | Implement per-zone catalog/reload or incremental generation; prove no full-cluster rebuild for a single-zone change under load. | ARCH-002 |
| ZONE-001 | 2 | P1 | Add BIND zone-file import and export with size limits, dry-run, per-row errors, and round-trip tests for quoted/escaped records. | ARCH-001 |
| ZONE-002 | 2 | P1 | Implement authenticated multi-zone bulk import with async progress, limits, dry-run, and an idempotent retry contract; fix or remove the current 404 UI. | ZONE-001 |
| ZONE-003 | 2 | P2 | Add zone templates/clone with variable validation, audit, and tests for default records/NS/DNSSEC settings. | ZONE-001 |
| ZONE-004 | 2 | P2 | Add zone metadata/tags, server-side filters, and UI filtering; migrate and index without breaking existing queries. | ARCH-001 |
| ZONE-005 | 2 | P0 | Harden ownership verification with public DNS TXT and NS-delegation proof, rate limits, retries, and fail-safe pending state. | CORE-009 |
| ZONE-006 | 2 | P1 | Add suspend/hold/archive states with explicit effects on serving, publication, transfer, and deletion; add policy and audit tests. | ARCH-002, ZONE-005 |
| ZONE-007 | 2 | P1 | Complete revision snapshots/diff/retention; make snapshot failures visible; add rollback tests for zone settings and records. | ARCH-001 |
| REC-001 | 2 | P2 | Add record comments/tags/ownership metadata with tenant-safe APIs, indexes, and UI editing. | ARCH-001 |
| REC-002 | 2 | P0 | Make record update/delete publication-atomic; add concurrent mutation and publish-failure tests proving DB/served state convergence. | ARCH-002 |
| REC-003 | 2 | P1 | Add RRset/batch mutation with dry-run, conflict detection, all-or-nothing semantics, and partial-error reporting. | REC-002 |
| REC-004 | 11 | P3 | Decide and implement apex alias/CNAME flattening or document it as not supported; add API/UI and correctness tests. | ZONE-001 |
| REC-005 | 11 | P1 | Add delete confirmation, record diff/history, and bulk-delete safeguards; add browser tests. | ZONE-007 |
| DNSSEC-001 | 3 | P0 | Introduce a key-store abstraction with encryption/KMS; migrate existing keys safely; ensure no plaintext key material in DB/backups/logs. | ARCH-007 |
| DNSSEC-002 | 3 | P1 | Implement KSK/ZSK or CSK state machine with scheduled pre-publish, activate, retire, and emergency rollover; test timers and failure paths. | DNSSEC-001, DNSSEC-004 |
| DNSSEC-003 | 3 | P2 | Expose NSEC3 parameters and publish CDS/CDNSKEY; add parent polling and tests for NSEC3 opt-out and DS transitions. | DNSSEC-002 |
| DNSSEC-004 | 3 | P0 | Implement encrypted DNSSEC key backup/restore and a compromise runbook; drill restore in a test environment. | DNSSEC-001 |
| DNSSEC-005 | 3 | P3 | Implement or explicitly reject multi-signer DNSSEC; if implemented, add DNSKEY/CDS coordination and lab tests. | DNSSEC-003 |
| DNSSEC-006 | 3 | P1 | Add DS verification against parent, Zonemaster/DNSViz-style checks, and alerts for missing/wrong DS. | CORE-008 |
| DNSSEC-007 | 3 | P2 | Decide GeoDNS+DNSSEC: implement signed synthesis or document a permanent exclusion; add regression tests for the chosen behavior. | DNSSEC-001 |
| DNSSEC-008 | 3 | P1 | Harden rollover UI: carry the original algorithm, prevent retiring the new key, confirm DS publication, and add browser tests. | DNSSEC-002 |
| DNSSEC-009 | 3 | P1 | Add DNSSEC conformance/negative tests: missing keys, wrong DS, expired signatures, NSEC3, algorithm changes, and fail-closed publication. | DNSSEC-006 |
| SECONDARY-001 | 4 | P1 | Add a real secondary zone model, API, and UI; remove the current label-only behavior; add lifecycle tests. | ARCH-006, CORE-001 |
| SECONDARY-002 | 4 | P1 | Add primary peer configuration, SOA refresh/retry/expire scheduling, and transfer-client state; test timeout and serial comparison. | SECONDARY-001, TRANSFER-001 |
| SECONDARY-003 | 4 | P2 | Add promotion, multi-primary/conflict policy, secondary deletion/retirement, and split-brain tests. | SECONDARY-002 |
| SECONDARY-004 | 4 | P1 | Expose secondary freshness, last transfer, serial/lag, errors, and audit events in API/UI/metrics. | SECONDARY-002, TRANSFER-003 |
| TRANSFER-001 | 4 | P1 | Add transfer ACL/policy management (allow/deny, peers, TSIG requirements) and enforce it in the server; add negative tests. | ARCH-006, CORE-001 |
| TRANSFER-002 | 4 | P1 | Add TSIG key CRUD/rotation and SIG(0) support; store keys securely; add signed AXFR/update interoperability tests. | DNSSEC-001 |
| TRANSFER-003 | 4 | P1 | Add transfer audit, metrics, and troubleshooting views for success/failure/latency. | TRANSFER-001 |
| XFR-006 | 4 | P3 | Implement catalog zones or document them as out of scope; if implemented, add provisioning and failover tests. | SECONDARY-001 |
| REPL-001 | 4 | P1 | Harden agent auth: separate signing keys, token expiry/scopes, rotation, optional mTLS, replay protection, and tests. | ARCH-007 |
| REPL-002 | 4 | P0 | Choose and implement the replicated publication topology: shared RWX storage, object store, or database-backed publication; document failure semantics. | ARCH-002, ARCH-008 |
| REPL-003 | 4 | P1 | Add replica consistency checks: bundle version, applied version, zone serials, drift detection, and operator-visible convergence. | REPL-002, SECONDARY-004 |

| GEO-001 | 5 | P2 | Extend the GeoDNS answer model to multiple A/AAAA targets with deterministic weights; add validation, API/UI, and distribution tests. | GEO-003 |
| GEO-002 | 5 | P2 | Add pools/regions and health-aware selection with fail-open/fail-closed policy; test target and pool failover. | GEO-001, HLTH-001 |
| GEO-003 | 5 | P2 | Add City/region dataset lifecycle: licensed data ingestion, validation, atomic reload, status API/UI, and stale-data alerts. | ARCH-007 |
| GEO-004 | 5 | P2 | Add a traffic-policy API/UI with simulation/preview, activation, rollback, and audit; reuse GeoDNS validation. | GEO-001, TRAF-001 |
| GEO-005 | 5 | P2 | Harden GeoRule API/UI: pagination, test by name/type, precedence display, input errors, and browser tests. | GEO-001 |
| TRAF-001 | 5 | P2 | Define a validated traffic-policy model (weights, pools, health, fallback) and shared engine contract; add unit/property tests. | GEO-001 |
| TRAF-002 | 5 | P3 | Add proximity/latency/dynamic steering behind a feature flag with simulation and bounded data sources; document non-goals. | TRAF-001 |
| TRAF-003 | 5 | P3 | Add load-balancer pool/region CRUD and composition with policies; add API/UI and validation tests. | TRAF-001 |
| TRAF-004 | 5 | P2 | Add policy preview/simulation, activation/rollback, and canary percentage; test deterministic behavior and audit. | TRAF-001, GEO-004 |
| HLTH-001 | 5 | P2 | Implement SSRF-safe active health monitors with intervals, timeouts, thresholds, maintenance windows, and state transitions. | ARCH-007, TRAF-001 |
| HLTH-002 | 6 | P1 | Persist health results/state history and expose API/UI timelines, alerts, and flapping suppression. | HLTH-001 |
| ANA-001 | 6 | P2 | Add an opt-in structured query-log pipeline with sampling, redaction, retention, and export; document privacy tradeoffs. | CORE-006, ARCH-008 |
| ANA-002 | 6 | P1 | Add latency/RCODE/NXDOMAIN/SERVFAIL history with bounded labels, retention, and tenant-safe queries. | ANA-003 |
| ANA-003 | 6 | P2 | Add analytics export and scale tests: partitions/rollups, 90-day retention, tenant isolation, and known-count verification. | ARCH-001 |
| MON-001 | 6 | P0 | Fix Prometheus scrape targets and deploy a working local/production monitoring path; add scrape smoke test. | ARCH-008, CORE-004 |
| MON-002 | 6 | P1 | Wire alert rules and Alertmanager with routing, inhibition, runbook links, and delivery tests. | MON-001 |
| MON-003 | 6 | P1 | Add SLO/error-budget dashboards for query success, publication freshness, API latency, and replica convergence. | MON-001, HLTH-002 |
| MON-004 | 6 | P1 | Protect metrics endpoints with authentication/TLS or network policy; add tests that unauthenticated external access fails. | MON-002 |
| MON-005 | 6 | P1 | Add synthetic DNS probes from multiple locations or processes; alert on NXDOMAIN/SERVFAIL/timeout and export results. | CORE-004, MON-002 |
| CUST-001 | 8 | P1 | Add invitation, suspension, reactivation, deletion, and email-backed password reset with expiry/replay protection and tests. | ARCH-007 |
| CUST-002 | 8 | P3 | Add OIDC/SAML SSO with group/role mapping, discovery, and account-linking tests. | RBAC-001 |
| CUST-003 | 8 | P3 | Add SCIM provisioning/deprovisioning with idempotency, conflict handling, and audit. | CUST-002 |
| TEN-001 | 8 | P1 | Fix quota check-then-insert races with atomic enforcement under concurrency; add usage aggregation and admin/customer reporting. | ARCH-003 |
| TEN-002 | 8 | P3 | Add tenant hierarchy/reseller model with scoped administration and permission tests. | TEN-001, RBAC-001 |
| TEN-003 | 8 | P0 | Add cross-tenant property tests across every API list/get/mutate path, including analytics, audit, agents, and search. | TEN-001 |
| RBAC-001 | 8 | P3 | Add a permission catalog and custom roles with deny-by-default enforcement; test privilege escalation and scope combinations. | TEN-003 |
| RBAC-002 | 8 | P1 | Align backend roles with the Users UI (`user` role), add per-user reset and effective-permission display; add browser tests. | ARCH-004 |
| API-001 | 7 | P1 | Publish an OpenAPI 3 contract generated/validated from routes and schemas; add lint and breaking-change checks. | API-010 |
| API-002 | 7 | P1 | Add idempotency keys for mutating endpoints with a TTL store, response replay, and conflict tests. | ARCH-001 |
| API-003 | 7 | P1 | Add scoped personal API tokens with expiry, rotation, revocation, last-used tracking, and least-privilege tests. | API-001, ARCH-007 |
| API-004 | 7 | P1 | Add API-wide and tenant-level rate limits with 429/Retry-After, metrics, and abuse tests. | API-003 |
| API-005 | 7 | P2 | Add signed webhooks/events with retry/backoff, replay protection, SSRF-safe delivery, and dead-letter handling. | API-002 |
| API-006 | 7 | P2 | Add an async job model and bulk endpoints with progress, cancellation, idempotency, and result retention. | API-002, API-007 |
| API-007 | 7 | P1 | Standardize pagination, filters, sorting, and error envelopes across all list endpoints; add contract tests. | API-001 |
| API-008 | 7 | P2 | Add a CLI and generated SDK from OpenAPI with auth, pagination, retries, and integration tests. | API-001 |
| API-009 | 7 | P3 | Add a Terraform provider or equivalent declarative automation with plan/dry-run and acceptance tests. | API-008 |
| API-010 | 7 | P1 | Add API contract tests for every frontend call and documented endpoint; fail CI on route/schema drift. | ARCH-004 |
| AUD-001 | 8 | P1 | Add audit detail, complete server-side filters, and streaming export with permission checks; add browser/API tests. | AUD-002 |
| AUD-002 | 8 | P0 | Complete audit coverage across all mutations, including failures/security events; add a coverage matrix and tamper-evidence design. | ARCH-004 |
| AUD-003 | 8 | P2 | Make retention/archive configurable, verify deletion policy, and add SIEM/export integration tests. | AUD-001 |
| BAK-002 | 12 | P0 | Add PostgreSQL backup/PITR automation, encryption, retention, and restore verification; document/run a drill. | ARCH-008 |
| BAK-003 | 3 | P0 | Add DNSSEC key/configuration export and encrypted backup/restore; test key-loss and restore scenarios. | DNSSEC-001 |
| BAK-004 | 12 | P0 | Add restore drills with checksums, RPO/RTO measurement, and published evidence; include zone/config and key material. | BAK-002, BAK-003 |
| BAK-005 | 12 | P0 | Document and exercise per-region/per-component DR, including DNS, API, DB, and key recovery; assign owners. | BAK-004, HA-006 |
| SEC-001 | 9 | P0 | Add API TLS/reverse-proxy deployment, HSTS/security headers, secure cookies, and a TLS smoke test. | ARCH-007, ARCH-008 |
| SEC-002 | 9 | P0 | Add PostgreSQL TLS verification and configuration; test hostname/certificate validation and failure behavior. | SEC-003 |
| SEC-003 | 9 | P0 | Add a secret manager and key hierarchy: JWT key IDs/rotation, separate agent signing keys, and no shared trust anchor. | ARCH-007 |
| SEC-004 | 9 | P1 | Encrypt MFA secrets, add recovery codes and QR enrollment, and test lockout/recovery abuse paths. | SEC-003 |
| SEC-005 | 9 | P1 | Reduce XSS blast radius: CSP, secure cookie option, token-storage decision, and browser security tests. | SEC-001 |
| SEC-006 | 9 | P1 | Add abuse detection, zone holds/locks, transfer protection, and operator workflows with audit and tests. | ZONE-006 |
| SEC-007 | 9 | P0 | Add DNS response-rate limiting/amplification controls, TCP/TLS coverage, shared budgets, and abuse load tests. | CORE-005 |
| SEC-008 | 9 | P1 | Add CI dependency scanning, `deny.toml`, SBOM generation, and signed-artifact verification. | — |
| PERF-001 | 10 | P0 | Implement the publication queue and incremental per-zone generation; measure write latency versus total zones and prove convergence. | ARCH-002, CORE-013 |
| PERF-002 | 10 | P0 | Replace the single transaction slot with a measured concurrency model; add contention and correctness tests. | ARCH-003 |
| PERF-003 | 10 | P1 | Publish a repeatable load/capacity harness with scenarios, SLO thresholds, and results for 1k/10k/50k zones. | PERF-001 |
| PERF-004 | 10 | P1 | Add per-tenant/zone cardinality and resource limits with fair queuing and 429/backpressure tests. | CORE-005 |
| HA-001 | 10 | P0 | Implement replicated control-plane topology with shared publication state, deterministic writes, and failover tests. | REPL-002, PERF-001 |
| HA-002 | 12 | P0 | Deploy PostgreSQL HA with backups/PITR and test failover without data loss or split-brain. | BAK-002 |
| HA-003 | 10 | P1 | Design/implement redundant DNS serving and a documented anycast/multi-region path; test host/process failure. | REPL-002 |
| HA-004 | 10 | P0 | Add graceful drain, maintenance mode, publication-aware readiness, and rolling restart tests. | CORE-004 |
| HA-005 | 12 | P1 | Add chaos/soak/failure-injection suites for API, DNS, DB, publication, and agents; record recovery times. | HA-001, HA-002, HA-003 |
| HA-006 | 12 | P0 | Define and exercise RPO/RTO and failover runbooks with evidence; align with BAK-005 and ARCH-008. | HA-005, BAK-004 |
| ADM-001 | 11 | P1 | Fix dashboard truth: distinguish empty/error/disabled, show publication/SLO state, and add browser tests. | MON-003 |
| ADM-002 | 11 | P0 | Implement safe bulk import/export UX with preview, progress, limits, and per-row errors; remove the 404 path. | ZONE-001, ZONE-002 |
| ADM-003 | 11 | P1 | Improve record editor: type-aware forms, diff, delete confirmation, history, and keyboard/accessibility tests. | REC-005 |
| ADM-004 | 11 | P1 | Add audit/agent/server/config operational UX with truthful copy, filters, detail, and status; add browser tests. | AUD-001, REPL-003 |
| ADM-005 | 11 | P2 | Add system settings and a persistent notification center with permission checks and audit. | SEC-003 |
| UX-001 | 11 | P1 | Add permission-aware UI contract tests: no visible action may return an undocumented 403/404; cover owner/editor/viewer/user. | API-010, RBAC-002 |
| CUI-001 | 11 | P2 | Add customer onboarding, guided zone creation, support diagnostics, and contextual help. | ADM-002 |
| CUI-002 | 11 | P2 | Improve customer analytics UX: provenance, retention, export, missing-data states, and accessible charts. | ANA-003 |
| CUI-003 | 11 | P1 | Complete WCAG audit/fixes: focus trap/restoration, labels, chart alternatives, keyboard file upload, route error boundary. | CUI-001 |
| CUI-004 | 11 | P2 | Add responsive/mobile layouts and resilient error/retry states for customer journeys. | CUI-003 |
| OPS-001 | 12 | P0 | Deliver a production Compose topology with TLS reverse proxy, resource limits, secrets, healthchecks, and backup hooks. | SEC-001 |
| OPS-002 | 12 | P1 | Repair Helm/Kubernetes: namespaces, ConfigMaps, RWX storage, services/ingress, probes, secrets, DB host, and validation. | OPS-001, HA-001 |
| OPS-003 | 12 | P0 | Repair CI: valid action refs, Docker contexts, integration target, `TEST_DATABASE_URL`, UI/lab tests, and release gates. | ARCH-005, API-010 |
| OPS-004 | 12 | P1 | Deploy and document monitoring, alerting, backup, restore, and on-call; link runbooks from alerts. | MON-001, MON-002, BAK-004 |
| OPS-005 | 12 | P1 | Add incident, rollback, certificate renewal, GeoIP update, database failover, and key-compromise runbooks with drills. | OPS-004 |
| OPS-006 | 12 | P1 | Automate certificate lifecycle and GeoIP updates; add upgrade/downgrade and migration rollback tests. | CORE-010, GEO-003 |
| OPS-007 | 12 | P2 | Add a status page, release signing/provenance, SBOM publication, and support diagnostics bundle. | SEC-008 |
| OPS-008 | 12 | P0 | Run a production-readiness review against §15 with evidence; resolve blockers and archive the decision record. | OPS-007; §12.5 P0 gate (all P0 tasks listed there except this final review) |

---

## 12. Priority and Dependency Matrix

### 12.1 Phase dependency graph

| Phase | Depends on | Unlocks | Exit gate |
|---|---|---|---|
| 0 | — | 1–12 | ADRs, schema parity, secret plan, topology/SLO |
| 1 | 0 | 2, 4, 6, 10 | Protocol correctness, readiness, resource safety |
| 2 | 0, 1 | 3, 7, 8, 11 | Migration-grade zone/record management |
| 3 | 0, 2 | 4, 5, 9 | Key custody, rollover, DS verification |
| 4 | 1, 3 | 5, 6, 10 | Real secondary/transfer topology |
| 5 | 1, 3, 4 | 6, 10 | Routing policies with health and validation |
| 6 | 1, 5 | 10, 11 | Observable, alertable service |
| 7 | 0, 2, 3 | 8, 9, 11 | Automation contract and tokens |
| 8 | 7 | 9, 11 | Enterprise identity, roles, audit |
| 9 | 0, 3, 7 | 10, 12 | Transport/secret/browser/abuse baseline |
| 10 | 1, 4, 6, 9 | 12 | Scale and failure evidence |
| 11 | 7, 8, 9 | 12 | Truthful, accessible UX |
| 12 | All | Production | Readiness review and drills |

### 12.2 Critical path

P0 release chain: `ARCH-001 → ARCH-002 → {REC-002, REPL-002} → PERF-001 → HA-001 → OPS-001 → OPS-002 → OPS-008`.

Security gating sequence: `ARCH-007 → SEC-003 → SEC-002`; `SEC-001` requires `ARCH-007`/`ARCH-008`; monitoring protection is `MON-002 → MON-004`.

DNSSEC gating sequence: `DNSSEC-001 → DNSSEC-004`; `DNSSEC-001`/`DNSSEC-004` → `DNSSEC-002 → DNSSEC-003`; `CORE-008 → DNSSEC-006 → DNSSEC-009`.

Transfer prerequisite sequence: `ARCH-006 → CORE-001 → TRANSFER-001 → SECONDARY-001/002`; `DNSSEC-001 → TRANSFER-002`; `SECONDARY-002 → SECONDARY-003/004`.

### 12.3 Priority rules

- **P0:** Must be closed before any production claim. Any P0 without a test is still open.
- **P1:** Required for professional maturity; may ship behind explicit feature flags only if the flag cannot create a false production-ready claim.
- **P2:** Valuable differentiator; sequence after P0/P1 and validate demand.
- **P3:** Optional/specialized; require an ADR and a demand signal.

### 12.4 Dependency rules

- No task may be closed while its dependency is marked incomplete, unless the dependency is explicitly waived in the decision log.
- All P0 tasks must have automated tests or a documented manual drill with captured evidence.
- No UI task may be closed before its backend contract test passes.
- No “HA” or “production-ready” claim may be closed without a failure drill and restore test.

### 12.5 P0 gate

`OPS-008` is gated on all P0 tasks except itself:

ARCH-001, ARCH-002, ARCH-003, ARCH-004, ARCH-006, ARCH-007, ARCH-008, CORE-004, ZONE-005, REC-002, DNSSEC-001, DNSSEC-004, REPL-002, MON-001, TEN-003, AUD-002, BAK-002, BAK-003, BAK-004, BAK-005, SEC-001, SEC-002, SEC-003, SEC-007, PERF-001, PERF-002, HA-001, HA-002, HA-004, HA-006, ADM-002, OPS-001, OPS-003.

The gate is closed only when each task has its required test evidence and no dependency waiver is unresolved.

### 12.6 Task counts by phase

| Phase | Tasks | P0 |
|---|---|---|
| 0 | 8 | 7 |
| 1 | 12 | 1 |
| 2 | 10 | 2 |
| 3 | 10 | 3 |
| 4 | 12 | 1 |
| 5 | 10 | 0 |
| 6 | 9 | 1 |
| 7 | 10 | 0 |
| 8 | 11 | 2 |
| 9 | 8 | 4 |
| 10 | 7 | 4 |
| 11 | 12 | 1 |
| 12 | 14 | 8 |
| **Total** | **133** | **34** |

---

## 13. Security and Reliability Requirements

### 13.1 Security invariants

1. **Deny by default.** Every API route, zone lookup, analytics query, audit query, and UI action must have an explicit authorization check.
2. **Tenant isolation is server-side.** Hiding UI controls is not authorization. Negative cross-tenant tests are mandatory.
3. **No plaintext secrets at rest.** Passwords use Argon2; MFA secrets and DNSSEC private keys must be encrypted or externalized; API tokens are hashed.
4. **No shared trust anchor.** JWT signing, agent authentication, and DNSSEC key material require separate keys, rotation, and audit.
5. **Transport security is mandatory.** API traffic requires TLS; PostgreSQL requires verified TLS; DNS transports use valid certificates and documented cipher policy.
6. **DNSSEC fails closed.** Missing/invalid keys must stop publication for the affected zone, never silently downgrade or serve unsigned data.
7. **Audit is append-oriented.** Security-relevant actions record actor, action, resource, tenant, timestamp, source, and outcome without credentials or key material.
8. **Resource limits are enforced.** API bodies, imports, batch sizes, query sizes, connection counts, and metric cardinality have documented limits.
9. **Abuse controls are layered.** Auth, API, and DNS have separate budgets; response-rate limiting and amplification controls are explicit.
10. **Supply chain is verifiable.** Dependencies are scanned; builds produce SBOM/provenance; release artifacts are signed.

### 13.2 Threat model summary

| Asset | Threat | Required controls |
|---|---|---|
| User/admin session | Credential stuffing, XSS, token theft | MFA, rate limits, rotation, revocation, CSP, secure storage, short-lived tokens |
| Tenant data | IDOR/cross-tenant leakage | Central authorization, scoped queries, property tests, audit |
| Zone data | Unauthorized change/deletion | RBAC, zone holds, audit, revisions, publication safety |
| DNSSEC keys | Theft/loss/misconfiguration | KMS/encryption, least privilege, backup/restore, staged rollover, DS checks |
| DNS service | Amplification, DDoS, cache poisoning | Rate limits, RRL, minimal responses, DNSSEC validation where applicable, redundant serving |
| API | Abuse, replay, data exfiltration | Tokens/scopes, quotas, idempotency, TLS, audit, error hygiene |
| Control plane | Compromise via dependencies/CI | Pinned actions, scanning, SBOM, least-privilege CI, signed artifacts |
| Backups | Data/key disclosure | Encryption, access control, separate trust domain, restore audit |

### 13.3 Reliability requirements

- **Publication:** every mutation has a durable publication intent; failures retry; operators can see per-zone state and age.
- **Consistency:** database state and served state converge deterministically; compensating actions are idempotent.
- **Availability:** no single API process, DNS process, database, or filesystem is an unmitigated SPOF for the claimed topology.
- **Recovery:** documented RPO/RTO, tested restore, key recovery, and DNS failover.
- **Observability:** metrics, logs, and traces answer “what is broken, for whom, and since when?” without exposing PII.
- **Capacity:** publication and query paths have measured limits and backpressure; tenant noise is bounded.
- **Maintenance:** upgrades, migrations, certificate/GeoIP updates, and rollbacks are rehearsed.

### 13.4 Data integrity requirements

- RRset identity is enforced by the database, not only the application.
- Zone edits are transactional with their publication intent.
- Import/export is round-trip safe and size-bounded.
- Serial changes are monotonic per zone and visible to operators.
- Revision snapshots include enough data to restore the zone, not only records.
- Audit retention does not silently delete required evidence.

---

## 14. Testing and Acceptance Strategy

### 14.1 Test layers

| Layer | Scope | Required evidence |
|---|---|---|
| Unit | Parsers, validators, policy engines, state machines | `cargo test`, table/property tests |
| API integration | Auth, RBAC, tenancy, CRUD, quotas, audit, idempotency | PostgreSQL-backed tests with `TEST_DATABASE_URL` |
| DNS protocol | UDP/TCP, AXFR/IXFR/NOTIFY, TSIG, DNSSEC, ECS, malformed packets | `dig`, `delv`, interoperability fixtures, Zonemaster-style checks |
| Publication/replica | Atomic files, last-known-good, convergence, rollback | Fault injection and multi-process labs |
| Browser/E2E | Admin/customer journeys, permissions, errors, accessibility | Existing platform QA + new contract/a11y suites |
| Performance | Query throughput, write latency, publication scaling, memory | Repeatable harness and published results |
| Chaos/DR | Process/DB/network failure, restore, failover | Game-day scripts with RTO/RPO measurements |
| Security | Auth bypass, IDOR, SSRF, rate limits, secrets, dependencies | Automated negative tests and scans |

### 14.2 CI gates

- Formatting, linting, unit tests, and API integration tests with a real PostgreSQL database.
- UI lint/build, browser smoke, accessibility scan, and permission-contract tests.
- DNS protocol lab: AXFR/IXFR/NOTIFY/TSIG/DNSSEC/GeoDNS/ECS.
- Helm template + kubeconform; compose smoke; migration-from-empty and upgrade tests.
- Secret scanning, dependency audit, SBOM generation, and image signing.
- Performance regression thresholds for publication and overview queries.

### 14.3 Acceptance criteria template

A task is accepted only when:

1. The stated behavior exists in the backend, not only the UI.
2. Authorization and tenant isolation are tested negatively.
3. Failure paths are tested (publication failure, timeout, retry, partial failure).
4. The database migration is safe from the previous release and from an empty database.
5. User-facing errors are actionable and do not leak secrets.
6. Documentation and operational notes are updated.
7. The relevant test layers pass in CI and the evidence is linked.

### 14.4 Current test gaps to close

- `TEST_DATABASE_URL` is not provided by CI, so database tests can skip.
- No AXFR-over-UDP rejection, IXFR, NOTIFY, secondary refresh, or DNS health tests.
- No per-zone metrics environment-path test.
- No restore drill, key-loss drill, DB failover, or multi-replica publication chaos test.
- No API contract test tying the frontend to backend routes.
- No automatic verification of Helm/Kubernetes manifests.
- No SBOM/signing/dependency gate in CI.

---

## 15. Production Readiness Criteria

Production readiness is an evidence claim, not a documentation state. The following criteria are mandatory for any public production release.

### 15.1 DNS and protocol

- [ ] Authoritative UDP/TCP and IPv4/IPv6 serving verified from external networks.
- [ ] Delegation verified: parent NS, child NS, glue, SOA, and serial behavior.
- [ ] AXFR/IXFR/NOTIFY/TSIG interoperability tested with at least one independent implementation.
- [ ] Secondary zones refresh, retry, expire, and report lag/errors.
- [ ] DNSSEC parent-child chain verified with `delv` or Zonemaster; DS mismatch is alerted.
- [ ] DoT/DoH/DoQ (and H3 if claimed) pass certificate, ALPN, and malformed-request tests.
- [ ] DNS readiness reflects catalog load and publication freshness, not only process liveness.
- [ ] Rate limiting, response-rate limiting, and concurrency caps tested under abuse load.

### 15.2 Control plane and data

- [ ] All API mutations are transactional with publication state; failures converge.
- [ ] Record RRset uniqueness and all declared invariants are enforced by the database.
- [ ] Migrations work from empty and from the previous release; rollback is documented/tested.
- [ ] Tenant isolation, RBAC, and quota checks pass negative/property tests.
- [ ] Audit covers all security-relevant mutations with filters/detail/export and retention.
- [ ] Idempotency, pagination, error contracts, scoped tokens, and API quotas are tested.
- [ ] Zone import/export is bounded, previewable, and round-trip safe.

### 15.3 Security

- [ ] No live secrets in Git or images; secret scanning passes; historical exposure assessed.
- [ ] API TLS, DB TLS, HSTS, CSP, and security headers verified.
- [ ] MFA secrets and DNSSEC keys encrypted/externalized; key rotation rehearsed.
- [ ] Agent authentication uses separate keys, expiry/scopes, and optional mTLS.
- [ ] Zone holds/ownership verification and abuse controls are active.
- [ ] Dependency/SBOM/signing gates pass; images are traceable to commits.

### 15.4 Reliability and operations

- [ ] A documented topology with no unmitigated single point of failure for the claimed SLA.
- [ ] PostgreSQL HA/PITR and restore drill meet RPO/RTO.
- [ ] DNSSEC key backup/restore drill passes.
- [ ] Publication convergence, replica failover, and DNS failover tested.
- [ ] Prometheus/Alertmanager deployed; scrape targets, alert rules, and runbook links verified.
- [ ] Dashboard, audit, agent, and publication status are truthful under failure.
- [ ] Capacity benchmark covers expected zones, records, queries, and write rate.
- [ ] Deployment, upgrade, rollback, certificate renewal, GeoIP update, and incident runbooks exercised.

### 15.5 Product and support

- [ ] No visible control returns an undocumented 404/403; route-contract tests pass.
- [ ] Accessibility audit has no critical blockers; errors are distinguishable from empty states.
- [ ] Customer onboarding, export, analytics, and support diagnostics work.
- [ ] Documentation matches the released code and infrastructure.
- [ ] A named owner accepts operational responsibility and the residual-risk register.

### 15.6 Go/no-go rule

If a P0 criterion is unmet, the release is **no-go** regardless of feature completeness. If a claim depends on external infrastructure that has not been tested, label it “unverified” and keep it out of the production claim.

---

## 16. Risks, Constraints, and Technical Decisions

### 16.1 Risk register

| Risk | Impact | Mitigation | Trigger / owner |
|---|---|---|---|
| Tracked live-looking secrets in `.env`/`env/*.env` and history | Credential compromise, data breach | Rotate, purge history if shared, add scanning and ignore rules | Immediate / security owner |
| Publication is synchronous and full-cluster | Write latency and outage amplification at scale | ARCH-002, PERF-001, PERF-002, capacity tests | Before growth / platform owner |
| Record update/delete commits before publication | DB and served data diverge | REC-002, explicit publication state, compensating tests | Before production / backend owner |
| Secondary/transfer scope ambiguity | Broken UI or large unplanned effort | ARCH-006 decision; implement or remove controls | Phase 0 / product owner |
| DNSSEC key loss or wrong DS | Global validation outage | DNSSEC-001/004/006/009, backups, staged rollout | Before signing at scale / security owner |
| No safe staging host | Unverified deployment behavior | Provision isolated staging; never use production | Immediate / operations owner |
| Helm/K8s manifests are not deployable | Failed or unsafe deployments | OPS-002, schema/port/storage/probe tests | Before orchestration use / platform owner |
| CI does not execute real DB/UI/lab tests | False green builds | OPS-003, required checks, test database service | Before next release / release owner |
| Monitoring/alerting is not wired | Silent outages | MON-001/002/003, synthetic probes, runbooks | Before production / SRE owner |
| Backup/restore untested | Permanent data/key loss | BAK-002/003/004/005, restore drills | Before production / operations owner |
| Hickory fork drift | Security/correctness regressions | Upstream merge policy, conformance suite, pinned revisions | Ongoing / DNS owner |
| Tenant quota race | Oversubscription | TEN-001, atomic constraints, concurrency tests | Phase 8 / backend owner |
| API surface expands without contract | Client breakage and security gaps | API-001/010, OpenAPI, contract tests | Phase 7 / API owner |
| Scope creep toward Cloudflare parity | Wasted effort and complexity | Non-goals in §18, demand gates, ADRs | Ongoing / product owner |
| Single-maintainer knowledge concentration | Slow recovery and review gaps | Runbooks, ADRs, paired review, automated tests | Ongoing / engineering lead |

### 16.2 Assumptions

1. OutisCloud intends to remain an **authoritative DNS hosting/control platform**, not a public recursive resolver, CDN, proxy, registrar, or global anycast operator in the near term.
2. Hickory remains the DNS engine; replacing it is out of scope unless a specific protocol gap cannot be closed safely.
3. PostgreSQL remains the control-plane source of truth; a database-backed publication model is preferable to shared mutable files for multi-replica correctness.
4. The existing admin/customer product split and React console are retained.
5. A non-production staging environment can be provided for external validation.
6. Enterprise features (SSO, SCIM, custom roles, holds) can be demand-gated.

### 16.3 Unresolved questions

1. **Secondary scope — resolved by ADR-0002:** Standards-based delegated secondary DNS is a product requirement; agent replication is a separate feature.
2. **Topology:** Single-host plus external TLS proxy, or multi-replica with shared RWX/object storage? What SLA is being sold?
3. **Key custody:** Is a cloud KMS acceptable, or is on-premises HSM/offline key custody required?
4. **Publication:** Are zone files an implementation detail or a customer-visible export format? This affects the migration path.
5. **DNSSEC + GeoDNS:** Is signed synthesis required, or is the exclusion permanent?
6. **API compatibility:** Is a versioned public API contract promised? What deprecation window?
7. **Data residency/privacy:** Are query logs and client IPs allowed, and for how long?
8. **Billing/usage:** Are quotas soft limits or billable meters?
9. **Commercial support:** What response times and channels are promised?

### 16.4 Recommended decisions

- Keep Hickory; invest in protocol completeness and a clean control-plane boundary.
- Make PostgreSQL + a publication queue/outbox the source of truth; treat files as generated artifacts.
- Adopt leader/writer publication or a deterministic per-zone worker model for replicas.
- Implement secondary/transfers as a first-class product if the target market includes DNS operators; otherwise remove the UI and document the non-goal.
- Use a KMS-backed key store and separate agent/JWT keys.
- Require TLS everywhere, scoped automation tokens, idempotency, and OpenAPI before ecosystem investment.
- Do not build Cloudflare-specific proxy/anycast/registrar capabilities.

---

## 17. Research References

### 17.1 Cloudflare primary documentation

Accessed 2026-11-19. Cloudflare-specific proxy, anycast, registrar, and enterprise-hold behavior is reference material, not a requirement.

| Key | Source | Key facts used |
|---|---|---|
| CF-HOME | https://developers.cloudflare.com/dns/ | DNS product overview, record/zone/DNSSEC/zone-setup entry points. |
| CF-API | https://developers.cloudflare.com/api/ | API product surface and automation expectations. |
| CF-RECORDS | https://developers.cloudflare.com/dns/manage-dns-records/ | Record management workflows and validation concepts. |
| CF-IMPORT | https://developers.cloudflare.com/dns/manage-dns-records/how-to/import-and-export/ | Zone-file import/export limit **256 KiB**; API import limit **3 requests/minute/user**. |
| CF-ANALYTICS | https://developers.cloudflare.com/dns/additional-options/analytics/ | DNS analytics query volume, RCODEs, NXDOMAIN/SERVFAIL, response time, and plan-dependent history intervals. |
| CF-LIMITS | https://developers.cloudflare.com/fundamentals/api/reference/limits/ | Global API limit **1,200 requests per 5 minutes per user**. |
| CF-AUDIT | https://developers.cloudflare.com/fundamentals/account/account-security/audit-logs/ | Audit Logs v2 and account-level activity history. |
| CF-STEERING | https://developers.cloudflare.com/load-balancing/understand-basics/traffic-steering/steering-policies/ | Steering policies: standard, geo, dynamic, proximity, least outstanding requests; ECS `location_strategy`. |
| CF-MULTISIGNER | https://developers.cloudflare.com/dns/dnssec/multi-signer-dnssec/ | Multi-signer DNSSEC concepts and coordination requirements. |
| CF-TRANSFERS | https://developers.cloudflare.com/dns/zone-setups/zone-transfers/ | Primary/secondary zone transfers, AXFR/IXFR, peers, and TSIG. |
| CF-HOLDS | https://developers.cloudflare.com/fundamentals/account/account-security/zone-holds/ | Zone holds as an enterprise protection mechanism. |
| CF-ATTRIBUTES | https://developers.cloudflare.com/dns/manage-dns-records/reference/record-attributes/ | Record comments/tags and metadata limits. |
| CF-LB | https://developers.cloudflare.com/load-balancing/get-started/quickstart/ | Load-balancer pools, monitors, and health-check workflow. |
| CF-TYPES | https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/ | Supported record types; **4,096-byte wire-format** and **8,192-character combined-content** limits. |
| CF-TOKENS | https://developers.cloudflare.com/fundamentals/api/get-started/create-token/ | Scoped API token creation and least-privilege model. |
| CF-DNSSEC | https://developers.cloudflare.com/dns/dnssec/ | DNSSEC signing, DS publication, and operational guidance. |
| CF-TROUBLESHOOT | https://developers.cloudflare.com/dns/troubleshooting/ | Delegation, propagation, and DNSSEC troubleshooting concepts. |

### 17.2 Industry primary sources

| Key | Source | Use |
|---|---|---|
| BIND | https://bind9.readthedocs.io/en/stable/chapter6.html | Primary/secondary, transfers, NOTIFY, TSIG, dynamic update, catalog zones, statistics. |
| KNOT | https://www.knot-dns.cz/docs/latest/singlehtml/index.html | Authoritative serving, automatic DNSSEC, transfers, catalog zones, ZONEMD. |
| PDNS | https://doc.powerdns.com/authoritative/http-api/zone.html | Zone/RRset API model, primary/secondary, DNSSEC, metadata. |
| R53 | https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/route-53-concepts.html | Hosted zones, record sets, routing policies, health checks, alias records. |
| GCP | https://cloud.google.com/dns/docs | Managed zones, DNSSEC, IAM, audit, private zones. |
| AZ | https://learn.microsoft.com/en-us/azure/dns/dns-overview | Hosted zones, record sets, alias, RBAC, activity logs. |
| OCTO | https://octodns.readthedocs.io/ | Declarative DNS, providers, plan/apply. |
| DNSCTL | https://docs.dnscontrol.org/ | DNS-as-code, previews, provider capability differences. |
| ZM | https://zonemaster.net/en/faq | Delegation and DNSSEC conformance testing. |

### 17.3 RFCs and protocol references

- RFC 1035 — Domain names and original DNS protocol.
- RFC 2308 — Negative caching and TTL behavior.
- RFC 1995 / 1996 / 5936 — IXFR, NOTIFY, AXFR.
- RFC 2136 — Dynamic updates.
- RFC 2931 / 8945 — SIG(0) and TSIG.
- RFC 4033 / 4034 / 4035 — DNSSEC introduction, records, and protocol.
- RFC 5155 — NSEC3.
- RFC 7871 — EDNS Client Subnet.
- RFC 8484 / 7858 / 9250 — DoH, DoT, DoQ.
- RFC 7766 — DNS over TCP.

### 17.4 Source-key resolution

| Key | Meaning |
|---|---|
| CF | Cloudflare primary documentation in §17.1 only; not a product requirement. |
| HICK | Hickory DNS upstream project documentation and source: https://github.com/hickory-dns/hickory-dns |
| CODE | Direct inspection of this repository, tests, migrations, configuration, and captured evidence listed in §17.5. |
| RFC | Protocol references in §17.3. |
| BIND, KNOT, PDNS, R53, GCP, AZ, OCTO, DNSCTL, ZM | Industry sources defined in §17.2. |

### 17.5 Repository evidence

| Evidence | Location |
|---|---|
| Control API routes/auth/RBAC/publication | `crates/control_api/src/main.rs` |
| Shared rate limiting | `crates/control_api/src/shared.rs`; calls at `main.rs:1215`, `main.rs:1227` |
| Record uniqueness guard | `main.rs:1024-1045` creates `uq_records_rrset_value` and removes the legacy constraint |
| Publication manager | `crates/control_api/src/dns_manager.rs` |
| Zone-file generation | `crates/control_api/src/zone_file_generator.rs` |
| Atomic DNS file builder | `crates/control_api/src/dns_builder.rs` |
| DNSSEC control plane | `crates/control_api/src/dnssec.rs` |
| Control-plane audits | `/tmp/opencode/audit_control_api.txt` |
| DNS-engine audit | `/tmp/opencode/audit_dns_engine_final.txt` |
| Frontend audit | `/tmp/opencode/audit_frontend.txt` |
| Docs/deployment audit | `/tmp/opencode/audit_docs_final.txt` |
| Test evidence | `/tmp/opencode/control-api-full-final2.log`, `/tmp/opencode/platform-qa2-release-final2.log`, `/tmp/opencode/redesign-final2.log`, `/tmp/opencode/hickory-dns-tests.log` |
| Existing feature proposals | `PROPOSED_FEATURES.md`, `TASK_STATUS.md`, `AUDIT_REPORT.md`, `DELIVERY_SUMMARY.md`, `docs/OPERATIONS.md` |
| Deployment evidence | `docker-compose.yml`, `docker-compose.prod.yml`, `helm/hickory-dns/`, `k8s/`, `.github/workflows/` |

### 17.6 Verification notes

- The earlier audit statement that login rate limiting was per-process is corrected: current code uses the shared limiter with an in-process fallback.
- The earlier audit statement that no database uniqueness guard existed is corrected: `uq_records_rrset_value` exists in current runtime DDL. The remaining issue is migration/runtime drift, not absence.
- UI calls `/api/v1/zones/bulk` with no matching backend route; confirmed by route inspection.
- `README.md` advertises certificate management that has no backend route; treat it as a documentation defect.
- Remote/public delegation and production capacity remain unverified because no safe external test environment was available.

---

## 18. Recommended Long-Term Product Direction

### 18.1 Positioning

OutisCloud should position itself as an **API-first, multi-tenant authoritative DNS platform for operators, hosting providers, and managed-service providers**. The value proposition is safe automation, delegation correctness, DNSSEC operations, tenant isolation, and operational visibility — not Cloudflare's CDN/proxy/registrar breadth.

### 18.2 Horizon 1 — Trustworthy core (0–6 months)

- Close Phase 0–3: publication consistency, secondary/transfer decision, DNSSEC key custody, TLS/secrets, backup/restore.
- Repair CI and deployment truth; make monitoring/alerting real.
- Remove or implement every broken UI control.
- Deliver a reliable single-region production topology with verified backups and runbooks.

**Success measures:** no P0 gaps; restore and DNSSEC drills pass; external delegation/conformance tests pass; no plaintext keys/secrets.

### 18.3 Horizon 2 — Professional platform (6–18 months)

- Complete Phase 4–8: real secondary/transfers, weighted/health-aware routing, analytics/alerting, scoped tokens/idempotency/webhooks/OpenAPI, enterprise identity and roles.
- Implement migration-grade import/export, templates, comments/tags, and safe bulk operations.
- Add staging, load/capacity testing, and multi-replica control plane.

**Success measures:** API automation used by real integrations; measured scale targets; secondary failover; customer self-service; audit/export accepted by security reviewers.

### 18.4 Horizon 3 — Scale and specialization (18+ months)

- Evaluate anycast/multi-region, proximity/dynamic steering, multi-signer DNSSEC, catalog zones, custom roles/SCIM, and white-label/reseller hierarchy.
- Only pursue capabilities with validated customer demand and an operational model.
- Maintain a documented non-goal list to prevent Cloudflare parity creep.

### 18.5 Build/buy decisions

| Capability | Recommendation | Rationale |
|---|---|---|
| Authoritative engine | Build on Hickory | Existing investment; protocol gaps are tractable. |
| Secondary/transfers | Build if operator market is targeted; otherwise buy/adopt a complementary engine | Protocol correctness is substantial but core to the product. |
| Anycast/global network | Buy/partner or defer | Capital and operational intensity; not an application feature. |
| Email delivery | Buy | Commodity; avoid deliverability/abuse burden. |
| KMS/HSM | Buy/cloud service | Key custody is security-critical and expensive to build. |
| Monitoring stack | Buy/use OSS (Prometheus/Alertmanager/Grafana) | Mature; integrate rather than reinvent. |
| Status page | Buy/use OSS | Commodity operational surface. |
| Billing | Buy or integrate | Avoid premature billing complexity. |
| Terraform/SDK | Build thin layers on OpenAPI | Ecosystem leverage without a separate product. |

### 18.6 Long-term KPIs

- **Correctness:** delegation/DNSSEC conformance pass rate; publication convergence time; zero undetected drift.
- **Reliability:** query availability; p95/p99 authoritative latency; failover RTO; restore RPO/RTO.
- **Security:** mean time to rotate keys; zero plaintext secrets; % endpoints with scoped auth and audit.
- **Operations:** change failure rate; time to detect/restore; alert precision; backup success rate.
- **Product:** automation adoption; API success rate; onboarding time; customer zone/record growth; support ticket rate.

### 18.7 Non-goals (unless separately approved)

- Public recursive resolver service.
- CDN/reverse-proxy/WAF and “orange-cloud” behavior.
- Domain registrar or registration lifecycle.
- Global anycast network in the near term.
- Cloning Cloudflare's UI, account model, or enterprise-only controls without demand.
- Rewriting Hickory or the control plane in a different language/framework as a prerequisite.

**Final recommendation:** stabilize the core, make security and recovery real, then invest in transfers/routing/automation in that order. The platform already has a credible foundation; the fastest path to production quality is disciplined closure of the P0 gaps, not a broad feature race.

---

## 19. Current Implementation Status — 2026-11-20

This section is authoritative and supersedes any conflicting status labels in earlier sections. Historical status text is preserved for auditability.

Validation performed for this status update:
- `cargo test -p control_api --bin control_api -- --test-threads=1`: 156 passed, 0 failed on isolated PostgreSQL 16.
- `cargo test -p hickory-dns --lib`: 22 passed, 0 failed.
- `cargo test -p hickory-dns --test integration test_health_and_ready_endpoints`: 1 passed, 0 failed.
- `cargo test -p hickory-server --features sqlite --lib`: 32 passed, 0 failed.
- `cargo test -p geodns --lib`: 22 passed, 0 failed.
- `cargo test -p hickory-resolver --lib`: 78 passed, 0 failed, 3 ignored.
- `cargo check -p hickory-dns --features h3-ring`: passed.
- `node web/ui/tests/route-contract.cjs`: 58 frontend endpoints matched.
- `npm --prefix web/ui run lint`: passed.
- `python3 scripts/docs_check.py`: passed with 4 pre-existing broken-link warnings.
- `cargo fmt --all -- --check` and `git diff --check`: clean.
- `python3 -m unittest scripts.test_secret_scan`: passed 4/4; `python3 scripts/secret_scan.py`: passed with no live-looking assignments in tracked config. Local full-history Gitleaks 8.16 passed with 0 unignored findings after exact historical test-fixture fingerprints were allowlisted. Current `main` no longer tracks local env/secret files.

### Phase-level status
| Phase | Status | Counts | Gate note |
|---|---|---|---|
| 0 | COMPLETED | COMPLETED: 8, PARTIALLY COMPLETED: 0 | All Phase 0 acceptance criteria are implemented and verified in the repository and germ test environment. Production state was not modified. |
| 1 | COMPLETED | COMPLETED: 12, PARTIALLY COMPLETED: 0 | All Phase 1 tasks meet their listed acceptance criteria. The live uid0.ir conformance check confirms parent delegation and authoritative responses; it also reports no NS address diversity and an unsigned delegation, which are recorded operational observations rather than CORE-008 implementation failures. |
| 2 | COMPLETED | COMPLETED: 10, PARTIALLY COMPLETED: 0, NOT STARTED: 0 | All Phase 2 roadmap tasks are implemented; ZONE-003 and ZONE-007 follow-up validation passed on germ/Chromium. |
| 3 | PARTIALLY COMPLETED | COMPLETED: 4, PARTIALLY COMPLETED: 1, BLOCKED: 5 | DNSSEC protocol negative tests and rollover UX are verified. Key custody and encrypted recovery remain the prerequisite for automatic rollover/NSEC3 parent coordination; multi-signer remains separately blocked. |
| 4 | PARTIALLY COMPLETED | COMPLETED: 2, PARTIALLY COMPLETED: 3, BLOCKED: 7 | ADR-0002 resolves the secondary product-scope decision in favor of standards-based secondary DNS; Hickory transfer/refresh primitives exist, while control-plane lifecycle and replication work remain. Peer ACL/key custody is also incomplete. |
| 5 | PARTIALLY COMPLETED | COMPLETED: 4, PARTIALLY COMPLETED: 2, BLOCKED: 4 | GEO-001 weighted multi-target GeoDNS is implemented and verified. Health-driven pools, licensed City data, and traffic-policy activation remain partial or blocked. |
| 6 | PARTIALLY COMPLETED | COMPLETED: 2, PARTIALLY COMPLETED: 2, NEEDS VERIFICATION: 3, BLOCKED: 2 | Analytics export and runtime monitoring validation remain blocked/unverified. |
| 7 | PARTIALLY COMPLETED | COMPLETED: 5, PARTIALLY COMPLETED: 2, BLOCKED: 3 | Scoped tokens, webhooks, jobs, SDK and Terraform provider remain incomplete. |
| 8 | PARTIALLY COMPLETED | COMPLETED: 2, PARTIALLY COMPLETED: 4, BLOCKED: 5 | Identity federation, custom roles, tamper evidence and lifecycle email remain blocked. |
| 9 | PARTIALLY COMPLETED | PARTIALLY COMPLETED: 5, BLOCKED: 3 | TLS certificates, secret rotation, user lifecycle encryption and SBOM/signing remain blocked/partial. |
| 10 | PARTIALLY COMPLETED | COMPLETED: 1, PARTIALLY COMPLETED: 2, NEEDS VERIFICATION: 1, BLOCKED: 3 | Replication, HA, backup/PITR and capacity proof remain blocked/unverified. |
| 11 | PARTIALLY COMPLETED | COMPLETED: 2, PARTIALLY COMPLETED: 8, NEEDS VERIFICATION: 1, BLOCKED: 1 | Permission-aware UX, notification center and re-audit of new controls remain open. |
| 12 | PARTIALLY COMPLETED | COMPLETED: 3, PARTIALLY COMPLETED: 6, BLOCKED: 5 | Release readiness is not met; remaining launch, customer evidence, security and deployment tasks are explicit below. |

### Task-level status
| Phase | Task | Priority | Status | Evidence, test result, or exact blocker |
|---|---|---|---|---|
| 0 | ARCH-001 | P0 | COMPLETED | Migration-from-empty and SQL/runtime schema-drift tests pass on isolated PostgreSQL. |
| 0 | ARCH-002 | P0 | COMPLETED | Durable per-zone outbox, retry worker, terminal state and admin requeue implemented. Germ/PostgreSQL and filesystem tests cover enqueue/persistence, actual separate-process restart recovery, pool recovery, DB and filesystem failures, competing workers, rollback, migration upgrade, last-known-good preservation and atomic rename failure. The separate-process recovery regression is in `3be400ed9`. |
| 0 | ARCH-003 | P0 | COMPLETED | Chosen measured model: bounded transaction pool plus FIFO per-tenant admission, with retry limited to replay-safe serializable operations. Isolated germ/PostgreSQL evidence measures four concurrent 200 ms transactions at 1.336 s versus 3.837 s for the single-slot baseline (2.87x), validates cross-tenant progress, quota race safety, bounded serialization retry, and rollback counters. This meets the task’s required design/benchmark/rollback criteria. Broader workload sweeps and retry adoption in additional handlers are follow-up hardening, not acceptance criteria for this roadmap item. |
| 0 | ARCH-004 | P0 | COMPLETED | Frontend route-contract and lint checks pass; dead controls removed. |
| 0 | ARCH-005 | P1 | COMPLETED | Docs consistency check passes; README/DELIVERY_SUMMARY corrected. |
| 0 | ARCH-006 | P0 | COMPLETED | ADR-0002 accepted; scope decision documented. |
| 0 | ARCH-007 | P0 | COMPLETED | Removed `.env`, `env/*.env`, and `k8s/secret.yaml` from the Git index while preserving local ignored copies; added placeholder-only env/Kubernetes templates and setup references. On germ, rotated the active PostgreSQL role password, API JWT secret, and admin account password; DB/API were recreated and healthy, new admin authorization and `/ready` passed, and old password/token were rejected. Configs are mode 0600 with a verified backup. Secret scanner tests pass 4/4; full-history Gitleaks 8.16 has 0 unignored findings after 34 exact historical Hickory test-fixture fingerprints were allowlisted. Decision: do not rewrite history; exact known fixture findings are retained, active germ credentials have been rotated, and rewriting shared history would disrupt existing clones. No production deployment was modified or claimed. Commits `f426ac56c`, `bfa08fb72`, and `f8cb79bcd` pushed. |
| 0 | ARCH-008 | P0 | COMPLETED | ADR-0003 accepted; topology/SLO/RPO/RTO targets documented. |
| 1 | CORE-001 | P1 | COMPLETED | TCP-only bounded multi-message AXFR server and Hickory streaming client are verified. Independent BIND `dig` validates signed 80-record transfer and refusal of unsigned/invalid transfers; Hickory client consumes an 84-record multi-message transfer; a separate BIND 9.20 primary on germ returns a valid AXFR to the Hickory client. File-backed `AllowSigned` loads TSIG keys and accepts valid signatures while refusing unsigned and invalid signatures. Code/tests committed in `37a2cc326` and pushed. See CORE-001 implementation evidence below. |
| 1 | CORE-002 | P1 | COMPLETED | IXFR has an explicit safe compatibility boundary: current-serial requests return one SOA; stale-serial requests return NOTIMP until journal entries contain RFC 1995 old/new SOA boundaries. Isolated SQLite integration uses `nsupdate` to advance the serial and independent `dig` to verify current-serial success and stale-history refusal. |
| 1 | CORE-003 | P1 | COMPLETED | Primary peer configuration and retrying TCP NOTIFY; inbound NOTIFY returns NOERROR only for served zones and validates configured file-store TSIG; accepted master NOTIFY triggers a complete TCP AXFR, serial-monotonic validation, atomic zone-file replacement, and hot catalog reload. A denied AXFR leaves the last-known-good secondary response unchanged. Focused integration tests pass for accepted/refused requests, signed/invalid TSIG, primary reload notification, retry after timeout, successful secondary refresh, and failed-transfer preservation. Commit `3be400ed9`. |
| 1 | CORE-004 | P0 | COMPLETED | `/health` and `/ready` endpoints are wired to compose and Helm probes. Readiness is marked only after configured zones and listeners initialize, ages out, and becomes unavailable on failed reload; the last-known-good catalog remains in service and readiness recovers after valid reload. Missing configured DNSSEC key fails zone loading; listener task failure aborts sibling listeners and exits the process. Focused readiness, reload recovery, missing-key, and listener failure tests pass. |
| 1 | CORE-005 | P1 | COMPLETED | Bounded UDP/TCP/TLS connection and HTTP/2 stream admission are verified at unit and wire levels. Tests: 96 idle TCP connections and a 32-query UDP burst under caps of 8 followed by an authoritative recovery query; 64 concurrent DoH2 streams under `DNS_MAX_H2_STREAMS=2`; 24 concurrent TLS/HTTP2 connections under `DNS_MAX_TCP_CONNECTIONS=8`. The H2 and TLS tests observed real stream/connection rejection logs, retained successful requests, then established a fresh HTTPS connection and answered an authoritative query. `https_h2_fanout_is_bounded_and_service_recovers` passed three consecutive times; `protocol_admission_fanout_keeps_service_available` passed 1/1; `concurrent_protocol_admission_never_exceeds_configured_caps` passed 1/1. CI runs the feature-enabled H2 test. Commit `026023193` pushed. |
| 1 | CORE-006 | P1 | COMPLETED | PII redaction unit test passes. |
| 1 | CORE-007 | P2 | COMPLETED | Forwarder cache default is configurable and 512; docs/FORWARDING.md states the product boundary. Cache miss/hit/expiry and caching-client tests pass in the 79/79 resolver library suite (3 ignored). |
| 1 | CORE-008 | P1 | COMPLETED | Repeatable protocol checks cover `dig`, `delv`, parent/child delegation consistency, malformed packets, and dual-stack. BIND `delv` accepted a locally signed test zone with the correct trust anchor and rejected a wrong anchor. On germ, `scripts/delegation_check.sh uid0.ir` confirmed parent NS delegation/glue, authoritative UDP/TCP SOA from both names, matching NS sets, and matching SOA serials; it warns both names share one IPv4 address. `uid0.ir` currently has no DNSKEY or parent DS and is unsigned. CI runs the dual-stack and malformed-packet tests. CI changes are in `3be400ed9`. |
| 1 | CORE-009 | P2 | COMPLETED | Forwarder/recursion boundary and cache sizing are documented; External-zone AXFR is refused before upstream contact; recursor config defaults to built-in root DNSSEC validation and a missing configured trust anchor fails closed. `cargo test -p hickory-dns --test integration axfr_for_external_zone_is_refused_without_upstream_contact -- --nocapture` passed 1/1; `cargo test -p hickory-resolver --lib --features 'recursor dnssec-ring serde toml tokio' trust_anchor_policy -- --nocapture` passed 2/2; full resolver suite passed 96, 0 failed, 5 ignored. Commits `2c9d09e85` and `efeddc221` pushed. |
| 1 | CORE-010 | P1 | COMPLETED | DoH3 is wired into the binary and test harness discovers the HTTP/3 listener. A real Hickory H3 client performs a DNS query against an isolated running Hickory binary over QUIC/HTTP3 using a freshly generated localhost certificate validated through a test root store. `cargo test -p hickory-dns --test integration --features 'h3-ring https-ring' doh3_client_queries_local_authoritative_server -- --nocapture` passed 1/1; the enabled test server started TLS, HTTPS, QUIC, and HTTP/3 listeners. CI now runs this feature-enabled integration test. Commit `91b9cd7ad` is pushed. |
| 1 | CORE-011 | P2 | COMPLETED | Editable CAA is supported end-to-end; DNAME, LOC, AFSDB, APL, DHCID, HIP, IPSECKEY, and KX are explicitly rejected because Hickory has no RDATA parser for them. Validation evidence (2026-11-25): validator tests round-trip CAA and assert specific rejection errors for all eight unsupported types; PostgreSQL-backed API integration against germ uses an isolated schema to create CAA, verify list response and published zone-file RDATA, and verify DNAME/LOC return HTTP 400 without publication; Chromium Playwright browser test verifies CAA option, absence of unsupported options, request payload, and displayed result. Commit `2a29c6b07` pushed. Commands and outcomes are recorded in §21. |
| 4 | CORE-012 | P2 | COMPLETED | Dynamic-update policy documented; prerequisite/prescan tests exist. |
| 1 | CORE-013 | P1 | COMPLETED | Per-zone fingerprint reload preserves unchanged handlers and rebuilds only the changed zone. An isolated two-zone test queries both zones continuously while one zone file changes, verifies the updated answer appears without query failures, then scrapes Prometheus and asserts exactly one rebuilt zone and at least one reused zone. `cargo test -p hickory-dns --test integration --no-run` passed; the built test binary ran under a disposable Debian 13 container as root because the local desktop user's inotify-instance quota was exhausted. `single_zone_reload_reuses_unchanged_catalog_during_query_load` passed 1/1 in 0.48s; `readiness_tracks_failed_zone_reload_and_recovery` passed 1/1 in 0.68s. CI runs the reload test. The test harness now drains child stdout continuously and retains the last 256 lines, avoiding pipe backpressure during load tests. Files: `bin/src/lib.rs`, `bin/tests/integration/named_metrics_tests.rs`, `bin/tests/integration/server_harness.rs`, `.github/workflows/ci.yml`. Commit `36b2c6f7c` pushed. |
| 2 | ZONE-001 | P1 | COMPLETED | JSON import dry-run/row errors plus BIND import (Hickory parser, `$ORIGIN`, quoted TXT, byte cap) tested; bulk import runs as a durable job. |
| 2 | ZONE-002 | P1 | COMPLETED | Authenticated `POST /api/v1/zones/bulk-import` with limits, dry-run, per-zone row errors, durable job progress/cancel and UI. |
| 2 | ZONE-003 | P2 | COMPLETED | Built-in `web` and `mail` templates are exposed by an authenticated catalog endpoint and selectable in the zone create form. Variables are validated before creation; records are inserted in the same transaction as default SOA/NS records, included in quota reservation, published, and audited by template ID. Clone preserves SOA/NS and rewrites in-zone targets; DNSSEC signing keys are not cloned and the new zone remains unsigned. Files: `crates/control_api/src/main.rs`, `crates/control_api/src/api_tests.rs`, `web/ui/src/pages/Admin/Zones.jsx`, `web/ui/src/hooks/useFormValidation.jsx`, `web/ui/tests/route-contract.cjs`, `web/ui/tests/zone-templates.spec.cjs`. Tests on isolated PostgreSQL 15 via germ: `TEST_DATABASE_URL=... cargo test -p control_api --bin control_api api_tests::zone_templates_are_authenticated_validated_and_persist_defaults_and_records -- --exact --nocapture` passed 1/1; `TEST_DATABASE_URL=... cargo test -p control_api --bin control_api api_tests::clone_zone_copies_records_with_rewritten_domain -- --exact --nocapture` passed 1/1. `npm run lint`, `npm run build`, and `npm run test:routes` passed (84 route pairs); `PLAYWRIGHT_CHROMIUM_EXECUTABLE=/snap/bin/chromium npx playwright test --config=tests/playwright.config.cjs tests/zone-templates.spec.cjs --workers=1` passed 2/2 including template form behavior. Commit `284ce8dbf933732a3280e5f5578cd3c11830d654`. |
| 2 | ZONE-004 | P2 | COMPLETED | Description/tags API, server-side `?tag=` filter with `X-Total-Count`, UI tag filter, and integration test. |
| 2 | ZONE-005 | P0 | COMPLETED | TXT and NS-delegation verification (`method=txt|ns`), rate limits/retries, fail-safe pending state, and `verified_via` evidence. |
| 2 | ZONE-006 | P1 | COMPLETED | active/held/suspended/archived lifecycle with hold reason/until, archived write blocking, serving effects, audit and integration tests. |
| 2 | ZONE-007 | P1 | COMPLETED | Snapshots include the zone domain, records, and publication settings with retention/diff; restores apply domain/records/settings transactionally. Snapshot persistence returns explicit status from create/update/delete/import/clone/restore responses; restore aborts before mutation when its recovery snapshot cannot be saved. Domain restore validates and collision-checks the saved domain. ZoneTools displays setting diffs and warns when the post-restore snapshot fails. Evidence on germ isolated PostgreSQL 15: `TEST_DATABASE_URL=... cargo test -p control_api --bin control_api api_tests::revision_restore_restores_renamed_domain_and_reports_snapshot_failures -- --exact --nocapture` passed 1/1 (rename restore, zone file cleanup, visible failure from injected trigger, pre-restore failure refuses to change current records); `... api_tests::revision_restore_restores_zone_publication_settings -- --exact --nocapture` passed 1/1; `... api_tests::zone_history_and_rollback -- --exact --nocapture` passed 1/1; previous retention/diff and migration/schema consistency tests are recorded in the earlier ZONE-007 entry. The exact Chromium command above passed 2/2, including `zone history diff renders revision setting changes`. `cargo fmt --all`, `cargo check -p control_api --tests`, `npm run lint`, `npm run build`, and `npm run test:routes` pass. Base history/settings work is in `66b60fc1b`; follow-up commit `284ce8dbf933732a3280e5f5578cd3c11830d654`. |
| 2 | REC-001 | P2 | COMPLETED | Comment/tags columns, tenant-safe metadata API, list payload, and record editor dialog with integration-test coverage. |
| 2 | REC-002 | P0 | COMPLETED | Publish-failure rollback API tests pass. |
| 2 | REC-003 | P1 | COMPLETED | `PUT /api/v1/zones/{id}/rrsets` applies an all-or-nothing RRset batch with validation, audit and rollback. |
| 11 | REC-004 | P3 | COMPLETED | Apex-alias non-goal documented in docs/RECORD_TYPES.md. |
| 11 | REC-005 | P1 | PARTIALLY COMPLETED | Implemented: Delete confirmation added. Remaining: record diff/history and bulk safeguards pending. |
| 3 | DNSSEC-001 | P0 | PARTIALLY COMPLETED | Added `hickory-key-store`: AES-256-GCM authenticated envelopes with versioned header, injected base64 256-bit wrapping key (`DNSSEC_KEY_ENCRYPTION_KEY`), optional strict rejection of plaintext (`DNSSEC_REQUIRE_ENCRYPTED_KEYS=true`), legacy read compatibility, atomic per-file migration CLI, restrictive 0600 key files/0700 key directory, symlink rejection, and encryption/decryption integration in the API writer and Hickory signer loader. Unit tests cover tampering/wrong key, strict-mode fail-closed behavior, migration idempotency, and symlink rejection; Hickory tests verify encrypted signer-key loading. `cargo test -p hickory-key-store` passed 5/5; `cargo test -p hickory-dns dnssec::tests --lib` passed 3/3; `cargo check -p control_api --tests` passed; germ test-server isolated migration of a temporary fixture encrypted 1 file, retry encrypted 0, and mode was 600. Commits: `44e0be710` (storage/integration), `4f74f4820` (backup tool). Remaining: configure a managed KMS/HSM or equivalent secret provider; make encryption mandatory in deployment without breaking legacy reads; include DB/config metadata in recovery; verify migration against a recoverable test backup; automated scheduled key rotation. Current implementation deliberately remains backward-compatible and writes plaintext if no wrapping key is configured, so do not treat the security requirement as complete. |
| 3 | DNSSEC-002 | P1 | PARTIALLY COMPLETED | Manual CSK rollover remains the implemented lifecycle. Hardened failure recovery: key completion/disable archive private-key files only after successful publication, and DNSSEC publication failures enter the durable per-zone publication outbox for retry. Germ isolated PostgreSQL 15 regression `dnssec_rollover_publication_failure_queues_retry_and_preserves_retired_key_file` passed: injected invalid zone data during rollover completion and DNSSEC disable preserved configured key files, queued retry, and successful retry acknowledged the outbox and published the expected key configuration. Existing `dnssec_lifecycle_keys_ds_rollover_and_guards` passed for normal rollover/retirement/disable; `cargo check -p control_api --tests` passed. Code commit: `753dec375`; extended retry/disable regression: `f1e162f5b`. Remaining: scheduled prepublish/activate/retire, KSK/ZSK lifecycle, and emergency rollover remain unimplemented. DNSSEC-001 key custody/backup prerequisites remain explicitly tracked. |
| 3 | DNSSEC-003 | P2 | PARTIALLY COMPLETED | DNSSEC secure-zone publication now derives CDNSKEY and CDS SHA-256/SHA-384 records from all SEP DNSKEYs before denial-chain generation/signing. The generated child-signaling RRsets are themselves included in the zone signatures, and stale CDS/CDNSKEY RRsets are cleared and rebuilt from the current DNSKEY set on each signing pass. Hickory integration battery test `cargo test -p hickory-dns --test integration --features dnssec-ring test_child_signaling -- --nocapture` passed 2/2 for file and SQLite zone stores; it verifies SEP count, two digest records per SEP key, and signed RRsets. `cargo check -p hickory-server --features dnssec-ring` passed after fixes to the RecordSet iterator and PublicKey trait usage. Remaining: configurable NSEC3 parameters in API/control-plane, NSEC3 opt-out configuration coverage, and parent DS polling/transition monitoring. Parent polling remains separate from child publication and cannot automatically update a registrar. |
| 3 | DNSSEC-004 | P0 | PARTIALLY COMPLETED | Added authenticated encrypted key-directory backup archive (64 MiB/10,000-file bounds, symlink/path-traversal rejection) and restore into a new destination only; restore refuses overwrite and creates 0600 key files under 0700 directories. Added explicit `dnssec-key-backup backup|restore` CLI; backup creates new archive files only with mode 0600. `cargo test -p hickory-key-store` passed 5/5 including backup confidentiality, restore of active+retired keys, wrong-key rejection, symlink rejection, and refusal to overwrite. Germ isolated recovery drill using temporary fake active/retired fixtures passed: encrypted archive did not contain fixture text, mode 600, restored 2 keys byte-for-byte, and second restore refused to overwrite. Commits: `44e0be710`, `4f74f4820`. Remaining: API/CLI backup orchestration with DB DNSSEC metadata/config consistency, recovery runbook, and a recovery procedure covering active DB metadata. |
| 3 | DNSSEC-005 | P3 | BLOCKED | Requires multi-operator product decision and external coordination. |
| 3 | DNSSEC-006 | P1 | COMPLETED | `GET .../dnssec/ds-status` queries parent DS, reports missing/stale records, and dispatches `dnssec.ds_mismatch` webhook alerts. |
| 3 | DNSSEC-007 | P2 | COMPLETED | GeoDNS/DNSSEC exclusion enforced by guards and covered by tests. |
| 3 | DNSSEC-008 | P1 | COMPLETED | Rollover API carries the active key algorithm and rejects retiring the replacement key. UI carries the algorithm, hides retirement for the new key, and requires explicit DS-publication/cache-expiry confirmation before enabling retirement. Germ PostgreSQL test `api_tests::dnssec_rollover_carries_algorithm_and_protects_new_key` passed 1/1. Chromium test `dnssec-rollover.spec.cjs` passed 1/1. `npm run lint`, `npm run build`, and `npm run test:routes` passed. |
| 3 | DNSSEC-009 | P1 | COMPLETED | Added signature validity boundary regression: RRSIG is accepted at its expiration second and rejected one second later. Hickory net unit tests passed: `cargo test -p hickory-net --lib dnssec::test:: --features dnssec-ring` 10/10 including new expiry case; `cargo test -p hickory-net --lib dnssec::nsec3:: --features dnssec-ring` 6/6. Germ isolated PostgreSQL API tests passed for missing-key fail-closed publication, rollover algorithm/key protections, and signing/DS lifecycle. `delv` wrong-trust-anchor rejection and DS mismatch webhook/status validation are recorded under CORE-008 and DNSSEC-006. Files: `crates/net/src/dnssec/mod.rs`, existing control API DNSSEC tests, `web/ui/tests/dnssec-rollover.spec.cjs`. |
| 4 | SECONDARY-001 | P1 | PARTIALLY COMPLETED | Product decision is resolved by ADR-0002. Server startup now attempts a complete primary AXFR before loading a configured secondary into the serving catalog; an unavailable primary is tolerated only when the configured file parses and contains an SOA (validated last-known-good fallback). The secondary refresh integration test verifies initial transfer, later NOTIFY refresh, monotonic serial replacement, and last-known-good preservation when transfer authorization fails. `cargo test -p hickory-dns --test integration accepted_notify_refreshes_secondary_by_axfr_and_preserves_last_known_good_on_failure -- --nocapture` passed 1/1. Remaining: tenant-safe secondary-zone create/update/delete API and UI, persisted primary peer model, PostgreSQL lifecycle coverage, and API-visible transfer freshness/errors. |
| 4 | SECONDARY-002 | P1 | PARTIALLY COMPLETED | Implemented startup AXFR before serving, configured-primary fallback on startup, SOA refresh/retry/expire timer scheduling with SERVFAIL fail-closed behavior after expiry, configured-primary failover, NOTIFY-triggered AXFR with bounded retries, source-IP master matching, AXFR boundary/parser validation, SOA serial monotonicity, atomic file replacement, and explicit catalog reload only after an installed newer zone. No-change or stale valid transfers count as successful refreshes but no longer cause redundant catalog reloads. Focused regression `cargo test -p hickory-dns --lib unchanged_or_stale_axfr_is_successful_without_replacing_last_known_good_file -- --nocapture` passed 1/1, and `cargo test -p hickory-dns --test integration accepted_notify_refreshes_secondary_by_axfr_and_preserves_last_known_good_on_failure -- --nocapture` passed 1/1. `cargo check -p hickory-dns --tests` passed. Germ real-server validation on `fastcreate-472995` used the newly built Hickory binary and two isolated processes on 127.0.0.1:53053/53054 with temporary files: startup AXFR and SOA timer served primary answer `192.0.2.22`; subsequent same-serial transfer retained the same zone-file SHA-256 `7959908d77c9f9ac14209b0b3d59d94df51ea405d7d54291c156cece8044ba61`. Processes, ports, binary, and temp files were cleaned; four existing project containers stayed healthy. Local `cargo fmt --all -- --check` passed. Local grouped suite `cargo test -p hickory-dns --test integration secondary_ -- --test-threads=1` previously ran 3 tests: 2 passed; `primary_notifies_configured_secondary_after_zone_reload` failed because watcher creation reported `Too many open files` (local `fs.inotify.max_user_instances=128`, 130 instances already present). SOA-expire regression `cargo test -p hickory-dns --test integration expired_secondary_fails_closed_after_primary_is_unavailable -- --nocapture` passed 1/1; unit test `cargo test -p hickory-server --lib expired_zone_rejects_its_apex_and_children_but_not_siblings` passed 1/1, and `cargo check -p hickory-dns --tests` passed. Germ isolated runtime test with the new binary served `192.0.2.9` after startup AXFR and returned SERVFAIL with no stale answer after the primary process was stopped and the 3-second SOA expire elapsed. Only temporary processes/files/binary and ports 53153/53154 were used; all were removed, and four existing containers remained healthy. Earlier real-server test verified timer convergence from serial 1 to 2 without NOTIFY. Code commit `7da2bf7cd`; prior validation record `75a99515c`. Remaining: SOA expire enforcement/withdrawal, persisted peer/timer state in control plane, timeout and serial arithmetic matrix tests, and tenant-facing status reporting. No-change AXFR follow-up was committed and pushed as `b6afdf0c0`; SOA-expire enforcement follow-up is currently uncommitted.
| 4 | SECONDARY-003 | P2 | BLOCKED | Depends on SECONDARY-002; split-brain policy undecided. |
| 4 | SECONDARY-004 | P1 | BLOCKED | Depends on SECONDARY-002/TRANSFER-003. |
| 4 | TRANSFER-001 | P1 | PARTIALLY COMPLETED | Per-zone Deny/AllowAll policy and an exact source-IP ACL (up to 64 addresses) are emitted into Hickory config and enforced by the file store. The API validates/canonicalizes peers, publishes policy changes, and restores old policy/ACL on publication failure. Germ/PostgreSQL API coverage verifies policy/ACL config output, invalid-IP rejection, and failed-publish rollback; independent Hickory integration confirms an unlisted peer receives REFUSED. Remaining: managed TSIG key custody/configuration, AllowSigned API policy, and signed-transfer negative interoperability coverage; do not offer AllowSigned until keys are managed safely. |
| 4 | TRANSFER-002 | P1 | BLOCKED | Depends on DNSSEC-001/ARCH-007; SIG(0) removed upstream; external signed interop required. |
| 4 | TRANSFER-003 | P1 | PARTIALLY COMPLETED | Hickory emits bounded-cardinality AXFR outcome counters and latency histograms plus structured per-transfer zone/client/outcome logs. Isolated server integration verifies successful and refused AXFR metrics and histogram export. Remaining: control-plane searchable audit/troubleshooting views and peer/key details await TRANSFER-001 ACL/key management. |
| 4 | XFR-006 | P3 | COMPLETED | ADR-0007 documents catalog zones as out of scope. |
| 4 | REPL-001 | P1 | BLOCKED | Depends on ARCH-007; mTLS and separate agent signing keys require key infrastructure. |
| 4 | REPL-002 | P0 | BLOCKED | Requires topology/infrastructure choice and deferred publication outbox. |
| 4 | REPL-003 | P1 | BLOCKED | Depends on REPL-002. |
| 5 | GEO-001 | P2 | COMPLETED | Added persisted/configured per-target weights with a backward-compatible default of 1, API bounds 0–1,000,000, admin UI create/edit/display, deterministic weighted multi-address A/AAAA responses, and family filtering before selection. Fixed generator initialization so loaded DB GeoRules actually enter the generated Hickory config. Evidence: `cargo test -p geodns` passed 24/24, including 10,000-client distribution test for configured 1:4 weights and A/AAAA family filtering; `cargo test -p hickory-server zone_handler::geodns -- --nocapture` passed 7/7 including wire-data RRset assembly and deterministic order; isolated germ PostgreSQL `TEST_DATABASE_URL=postgres://postgres@127.0.0.1:55432/postgres cargo test -p control_api --bin control_api georule_update_and_input_validation -- --nocapture --test-threads=1` passed 1/1; same environment `... migration_files_and_runtime_ddl_have_no_schema_drift ...` passed 1/1; `npm run lint`, `npm run build`, and `PLAYWRIGHT_CHROMIUM_EXECUTABLE=/snap/bin/chromium npx playwright test --config=tests/playwright.config.cjs tests/geo-weight.spec.cjs --workers=1` passed (1/1). `cargo fmt --all` and `git diff --check` passed. Germ used only a dedicated disposable PostgreSQL 15 container; removed after tests, existing project containers stayed healthy. Files: `crates/geodns/src/lib.rs`, `crates/server/src/zone_handler/geodns.rs`, `crates/control_api/{migrations/001_initial_schema.sql,migrations/010_georule_weights.sql,src/main.rs,src/api_tests.rs,src/dns_builder.rs,src/zone_file_generator.rs}`, `bin/src/config/mod.rs`, `web/ui/src/pages/Admin/GeoRules.jsx`, `web/ui/tests/geo-weight.spec.cjs`. Commit: `11a35a1ee`. |
| 5 | GEO-002 | P2 | PARTIALLY COMPLETED | Implemented: Engine accepts injected health state. Remaining: real health-driven failover pending. |
| 5 | GEO-003 | P2 | PARTIALLY COMPLETED | Implemented: Dataset watcher/atomic install/staleness exist. Remaining: licensed City data is external. |
| 5 | GEO-004 | P2 | BLOCKED | Requires policy/version schema and activation design. |
| 5 | GEO-005 | P2 | COMPLETED | GeoRule API pagination/search plus UI search by zone/match/target/record and explicit priority-order guidance. |
| 5 | TRAF-001 | P2 | COMPLETED | Deterministic policy engine has 3 passing unit tests. |
| 5 | TRAF-002 | P3 | BLOCKED | Requires external location/latency data sources. |
| 5 | TRAF-003 | P3 | BLOCKED | Requires pool/region schema design. |
| 5 | TRAF-004 | P2 | BLOCKED | Depends on TRAF-003. |
| 5 | HLTH-001 | P2 | COMPLETED | Health-check CRUD, public-IP-only DNS probes (SSRF-safe), scheduler, thresholds and persisted results with tests. |
| 6 | HLTH-002 | P1 | COMPLETED | State machine with consecutive thresholds, result history/pruning, webhook/audit transitions and worker wired into startup. |
| 6 | ANA-001 | P2 | PARTIALLY COMPLETED | Implemented: Query-log redaction/level controls exist. Remaining: structured sampling/persistence/export pending. |
| 6 | ANA-002 | P1 | PARTIALLY COMPLETED | Implemented: RCODE counters exist. Remaining: latency histogram/history tables pending. |
| 6 | ANA-003 | P2 | BLOCKED | Requires export format/tenant-scope decision. |
| 6 | MON-001 | P0 | NEEDS VERIFICATION | Implemented: Scrape config corrected. Remaining: no runtime Prometheus scrape smoke test. Verification gap: Runtime Prometheus scrape smoke test was not run. |
| 6 | MON-002 | P1 | NEEDS VERIFICATION | Implemented: Alertmanager config/rules added. Remaining: no runtime delivery test. Verification gap: Runtime Alertmanager delivery test was not run. |
| 6 | MON-003 | P1 | NEEDS VERIFICATION | Implemented: Grafana dashboard JSON added. Remaining: no runtime provisioning test. Verification gap: Runtime Grafana provisioning test was not run. |
| 6 | MON-004 | P1 | COMPLETED | Both API and DNS metrics endpoints support constant-time bearer-token checks (`METRICS_TOKEN`/`PROMETHEUS_TOKEN`); health/readiness stay open. |
| 6 | MON-005 | P1 | BLOCKED | Multi-location probes require external infrastructure. |
| 8 | CUST-001 | P1 | BLOCKED | Requires email provider, user-status schema and invite/reset token model. |
| 8 | CUST-002 | P3 | BLOCKED | Requires external IdP/OIDC/SAML dependency and demand approval. |
| 8 | CUST-003 | P3 | BLOCKED | Depends on CUST-002. |
| 8 | TEN-001 | P1 | COMPLETED | Quota reservation concurrency and usage tests pass. |
| 8 | TEN-002 | P3 | BLOCKED | Depends on RBAC-001 permission catalog. |
| 8 | TEN-003 | P0 | PARTIALLY COMPLETED | Implemented: Deterministic tenant matrix exists. Remaining: analytics/agents/search cases pending. |
| 8 | RBAC-001 | P3 | BLOCKED | Requires permission catalog tables and policy engine across handlers. |
| 8 | RBAC-002 | P1 | COMPLETED | Per-user password reset and session-revocation test passes. |
| 7 | API-001 | P1 | PARTIALLY COMPLETED | Implemented: OpenAPI spec route with component schemas exists. Remaining: full route annotation and lint pending. |
| 7 | API-002 | P1 | COMPLETED | `platform_middleware` replays/stores `Idempotency-Key` responses for every mutating request, in addition to the explicit create-zone path and tests. |
| 7 | API-003 | P1 | BLOCKED | Depends on API-001 completion and ARCH-007 secret decision. |
| 7 | API-004 | P1 | COMPLETED | Global per-IP limiter plus tenant-scoped budgets in `platform_middleware` with 429/Retry-After and tests. |
| 7 | API-005 | P2 | COMPLETED | Signed webhooks (HMAC), SSRF-safe target validation, durable deliveries with retry/backoff and dead-letter status. |
| 7 | API-006 | P2 | COMPLETED | Durable jobs with progress/cancel/retention, bulk import endpoint, recovery worker and integration test. |
| 7 | API-007 | P1 | PARTIALLY COMPLETED | Implemented: Pagination exists for several lists. Remaining: remaining lists and error envelopes pending. |
| 7 | API-008 | P2 | BLOCKED | Depends on API-001 completion. |
| 7 | API-009 | P3 | BLOCKED | Depends on API-008 and external provider toolchain. |
| 7 | API-010 | P1 | COMPLETED | Route-contract check runs in CI, schema-drift test runs against PostgreSQL in CI, and both are part of the documented validation command set. |
| 8 | AUD-001 | P1 | PARTIALLY COMPLETED | Implemented: Audit detail and CSV export endpoints tested. Remaining: UI detail/export wiring pending. |
| 8 | AUD-002 | P0 | PARTIALLY COMPLETED | Implemented: Broad audit coverage exists. Remaining: coverage-matrix ADR and failure-policy decision pending. |
| 8 | AUD-003 | P2 | PARTIALLY COMPLETED | Implemented: Retention configurable. Remaining: archive/SIEM target external. |
| 12 | BAK-002 | P0 | PARTIALLY COMPLETED | Encrypted PostgreSQL dump and restore verified on germ (746c4f89a). Scheduled retention, off-host storage and WAL point-in-time recovery remain. |
| 3 | BAK-003 | P0 | BLOCKED | Depends on DNSSEC-001; no encrypted key export/restore target. |
| 12 | BAK-004 | P0 | PARTIALLY COMPLETED | Isolated restore verified checksums and recovered a zone in one second on germ (746c4f89a). DNSSEC keys, configuration recovery and RPO measurement remain. |
| 12 | BAK-005 | P0 | COMPLETED | ADR-0003 documents RPO/RTO targets; drills remain blocked. |
| 9 | SEC-001 | P0 | BLOCKED | Requires certificate issuance and reverse-proxy deployment topology. |
| 9 | SEC-002 | P0 | BLOCKED | Requires CA/certificate provisioning and connection-string migration. |
| 9 | SEC-003 | P0 | PARTIALLY COMPLETED | Implemented: Rotation tool added. Remaining: real secret rotation blocked by owner credentials. |
| 9 | SEC-004 | P1 | BLOCKED | Depends on key custody decision and user lifecycle schema. |
| 9 | SEC-005 | P1 | PARTIALLY COMPLETED | Implemented: Login/DNS/API/verification limits exist. Remaining: tenant abuse scoring pending. |
| 9 | SEC-006 | P1 | PARTIALLY COMPLETED | Implemented: DNSSEC/agent keys separate; `JWT_PREVIOUS_SECRETS` overlap window enables JWT rotation without logging everyone out. Remaining: scheduled automatic rotation. |
| 9 | SEC-007 | P0 | PARTIALLY COMPLETED | Implemented: Per-source governor and admission limits exist. Remaining: full RRL coverage pending. |
| 9 | SEC-008 | P1 | PARTIALLY COMPLETED | Added `deny.toml`, CI audit/deny gates, CycloneDX SBOM script, release checksum signing and provenance workflow. Remaining: image signature verification policy. |
| 10 | PERF-001 | P0 | PARTIALLY COMPLETED | Implemented: ADR state machine exists. Remaining: outbox implementation pending. |
| 10 | PERF-002 | P0 | PARTIALLY COMPLETED | Implemented: bounded transaction sessions with reconnect supervision; germ run showed 2.87x over one-session baseline for the measured workload. Broader load/latency sweeps and fairness remain. |
| 10 | PERF-003 | P1 | COMPLETED | Overview/query-count tests and local 5,000-zone benchmark exist. |
| 10 | PERF-004 | P1 | NEEDS VERIFICATION | Implemented: Admission limits implemented. Remaining: capacity proof pending. Verification gap: High-concurrency capacity proof was not run. |
| 10 | HA-001 | P0 | BLOCKED | Requires multi-replica infrastructure and publication outbox. |
| 12 | HA-002 | P0 | BLOCKED | Depends on HA-001 and shared publication state. |
| 10 | HA-003 | P1 | BLOCKED | Requires redundant DNS/anycast/multi-region infrastructure. |
| 10 | HA-004 | P0 | BLOCKED | Depends on HA-001/HA-003 failure evidence. |
| 12 | HA-005 | P1 | BLOCKED | Requires chaos/failure-injection environment. |
| 12 | HA-006 | P0 | BLOCKED | Depends on HA-005 and BAK-004 drills. |
| 11 | ADM-001 | P1 | PARTIALLY COMPLETED | Implemented: Metadata UI added. Remaining: truthful health/lifecycle controls still partial. |
| 11 | ADM-002 | P0 | COMPLETED | Clone dialog, lifecycle (active/held/suspended/archived) controls, tag filtering and metadata editing surfaced in the zone console. |
| 11 | ADM-003 | P1 | PARTIALLY COMPLETED | Implemented: Audit backend endpoints exist. Remaining: UI drawer/export wiring pending. |
| 11 | ADM-004 | P1 | PARTIALLY COMPLETED | Implemented: Viewer enforcement exists. Remaining: full permission-aware catalog depends on RBAC-001. |
| 11 | ADM-005 | P2 | BLOCKED | Requires notification model and settings schema. |
| 11 | UX-001 | P1 | NEEDS VERIFICATION | Implemented: Existing a11y suite passes. Remaining: new metadata/reset UI not re-audited. Verification gap: New metadata and password-reset UI controls have not been re-audited. |
| 11 | CUI-001 | P2 | PARTIALLY COMPLETED | Implemented: Customer dashboard exists. Remaining: onboarding/error polish pending. |
| 11 | CUI-002 | P2 | PARTIALLY COMPLETED | Implemented: Analytics UX exists. Remaining: provenance/export/missing-data polish pending. |
| 11 | CUI-003 | P1 | PARTIALLY COMPLETED | Implemented: Existing WCAG checks pass; a route error boundary (`3170df46d`) now provides accessible retry/home actions, with a browser chunk-failure test. The shared modal now traps Tab and restores focus (`eb75ba752`), verified in Chromium. The bulk-import file picker is now keyboard accessible (`6c758dc3a`) with a Chromium selection test. Remaining: other dialogs, labels, chart alternatives, and a full WCAG audit. |
| 11 | CUI-004 | P2 | PARTIALLY COMPLETED | Implemented: Responsive/error work partial. Remaining: customer journeys need regression pass. |
| 12 | OPS-001 | P0 | BLOCKED | Requires TLS reverse proxy, certificates and production topology decision. |
| 12 | OPS-002 | P1 | BLOCKED | Requires Kubernetes/RWX storage and validated manifests. |
| 12 | OPS-003 | P0 | PARTIALLY COMPLETED | The active Docker Hub workflow now gates publishing on PostgreSQL-backed API tests, DNS tests, UI lint/build, Helm rendering, documentation, and dependency policy. Run 45342563964 passed all steps except dependency policy, so publishing was skipped. Patched lockfile dependencies and local crate policy metadata (`e61dea001`) pass local audit/deny checks. Run 45344351797 passed all validation steps on GitHub; image builds are in progress. CI and CI/CD workflows remain `disabled_manually`. |
| 12 | OPS-004 | P1 | COMPLETED | Prometheus/Alertmanager/Grafana configs plus incident, rollback, certificate, GeoIP and failover runbooks. |
| 12 | OPS-005 | P1 | COMPLETED | `docs/runbooks/` covers incident response, rollback, certificate lifecycle, GeoIP and failover/recovery. |
| 12 | OPS-006 | P1 | PARTIALLY COMPLETED | GeoIP atomic refresh + certificate expiry checker (`scripts/check_certs.sh`) and lifecycle runbook. Remaining: ACME issuance automation is deployment-specific. |
| 12 | OPS-007 | P2 | PARTIALLY COMPLETED | Added static status-page generator, CycloneDX SBOM script, signed release checksums/provenance workflow and redacted diagnostics bundle. Remaining: publish SBOM/provenance to a public transparency log. |
| 12 | OPS-008 | P0 | PARTIALLY COMPLETED | Review documented in `docs/PRODUCTION_READINESS.md`; gate deliberately remains open on ARCH-007, TLS, backups, DNSSEC custody, HA and OPS-002. |

---

## 20. Source-Verified Status Corrections

## 0.15 Source-Verified Corrections to Status Matrix

This section supersedes conflicting rows in §0.14. It was produced by direct source, route, test-name, ADR and config verification.

| Task | Corrected status | Verified correction |
|---|---|---|
| ARCH-001 | PARTIALLY COMPLETED | PostgreSQL migration/runtime parity was verified; SQLite verification is not applicable to the PostgreSQL-only control plane. |
| CORE-004 | PARTIALLY COMPLETED | DNS /health and /ready integration test passes. Compose and newly rendered Helm DNS probes target `/health` and `/ready`; cluster-level probe transition and key/catalog/freshness failure checks remain unverified. |
| XFR-02 | IMPLEMENTED_BUT_INCOMPLETE | Current serial returns one SOA and stale serial returns NOTIMP; full IXFR deltas remain disabled because the durable update journal does not encode the required old/new SOA boundaries. |
| CORE-006 | COMPLETED | Query logging now supports off/info/debug and `DNS_QUERY_LOG_SAMPLE_EVERY`; request, response, refused and parse-error paths redact addresses, and DEBUG query names are redacted. `cargo test -p hickory-server --lib query_log_tests` passes 2/2. |
| BAK-005 | PARTIALLY COMPLETED | ADR-0003 documents RPO/RTO targets; per-component DR exercise, owner assignment and drill evidence are missing. |
| SEC-003 | PARTIALLY COMPLETED | Rotation tool exists; JWT key IDs/rotation and separate agent signing keys are not implemented. |
| SEC-005 | PARTIALLY COMPLETED | UI Nginx now emits a CSP for the SPA. `nginx -t`, a disposable-container HTTP header smoke test, and a Chromium Playwright inline-script blocking test (`dffbb3e01`) pass. Secure-cookie option and token-storage change remain. |
| SEC-006 | NOT STARTED | No abuse scoring, zone holds/locks or transfer-protection operator workflow exists. |
| RBAC-002 | PARTIALLY COMPLETED | User role and per-user reset are tested; effective-permission display is not implemented. |
| PERF-003 | PARTIALLY COMPLETED | A repeatable 5,000-zone harness and results exist; required 1k/10k/50k scenarios and SLO thresholds are absent. |
| PERF-004 | PARTIALLY COMPLETED | DNS admission limits and tenant quotas exist; per-tenant/zone cardinality limits, fair queuing and 429 tests are absent. |
| HA-001 | PARTIALLY COMPLETED | Multi-replica lab and advisory publication lock exist; shared/versioned zone state, deterministic writer and convergence proof are absent. |
| HA-004 | PARTIALLY COMPLETED | Health/readiness endpoints exist; publication-aware readiness, graceful drain, maintenance mode and rolling-restart tests are absent. |
| ADM-001 | PARTIALLY COMPLETED | Dashboard empty/error/disabled/publication states exist; SLO target display and browser truth tests are absent. |
| ADM-003 | PARTIALLY COMPLETED | Record delete confirmation exists; type-aware forms, record diff/history UX and keyboard/a11y tests remain incomplete. |
| ADM-004 | PARTIALLY COMPLETED | Audit filters/pagination/export and server/status UX exist; row detail and full permission-aware catalog remain. |
| UX-001 | PARTIALLY COMPLETED | Viewer/editor/admin UI permission tests exist; systematic no-hidden-403/404 contract and new-control checks remain. |
| OPS-002 | PARTIALLY COMPLETED | Helm now renders API, DNS and UI Deployments/Services/Ingress, ConfigMaps, shared pre-provisioned RWX claim mounts, and probes; lint/render and structural checks pass. Agent/DB templates and Kubernetes cluster validation remain; external Secret, images and claim must be supplied. |
| OPS-006 | PARTIALLY COMPLETED | GeoIP atomic update automation exists; production certificate lifecycle and upgrade/rollback tests are absent. |

## 21. Single-File Execution Ledger — 2026-11-25

This ledger is the only current task and implementation report. Historical status matrices above are preserved, but their counts are superseded here. Phase 0 and Phase 1 are verified complete. Phase 2 is now complete: ZONE-003 templates and ZONE-007 caller-visible snapshot handling, domain restore, and setting-diff UI are implemented and tested. Continue to Phase 3.

### Current roadmap totals

133 tasks total. COMPLETED 55 (41.4%), PARTIALLY COMPLETED 39 (29.3%), NEEDS VERIFICATION 5 (3.8%), BLOCKED 34 (25.6%), NOT STARTED 0. Incomplete: 78. Counts exclude prose-only feature-matrix rows and count each roadmap task ID once. CORE-001 has BIND server/client interop and file-store TSIG policy evidence; CORE-002 meets its documented safe-refusal alternative; CORE-003 verifies signed NOTIFY and end-to-end secondary AXFR refresh; CORE-005 has real TLS/HTTP2 fanout and recovery evidence; CORE-008 includes live delegation and dual-stack CI coverage; CORE-011 has CAA API/database/publication and browser round-trip evidence with explicit unsupported-type rejection; CORE-013 has sustained-query reload and per-zone reuse evidence; GEO-001 has a 10,000-client weight-distribution test plus database-to-Hickory publication and UI edit coverage. SECONDARY-001 is no longer represented as externally blocked: ADR-0002 already accepted full secondary support; its unimplemented control-plane lifecycle is tracked as partial work. DNSSEC-001 and DNSSEC-004 now have encrypted local key-store, migration, backup, and restore primitives, but managed key custody and integrated recovery remain incomplete. SECONDARY-001/002 now validate initial transfer-before-serve, NOTIFY refresh, serial monotonicity, and last-known-good behavior in an isolated Hickory integration test. DNSSEC-003 moved from BLOCKED to PARTIALLY COMPLETED after CDS/CDNSKEY generation and signed file/SQLite tests were added.

### Phase 0 and Phase 1 execution state

| Phase | Gate | Outstanding acceptance work |
|---|---|---|
| 0 | CLOSED | All eight Phase 0 tasks meet their repository/test-environment acceptance criteria. Active germ credentials are rotated, tracked runtime secrets are removed, scanning is green, and the no-history-rewrite decision is documented. No production deployment was changed. |
| 1 | CLOSED | All 12 Phase 1 tasks satisfy their listed implementation and verification criteria. CORE-002 uses the roadmap's documented safe-refusal alternative; full IXFR deltas remain unsupported. See task rows in §19 and the implementation updates below. |

### Latest implementation and validation evidence

- **Bulk import UX (ZONE-001, ADM-002, CUI-003): PARTIAL.** CSV parser, dry-run preview, 1 MiB and 5,000-row client limits, duplicate/error feedback, and keyboard reachable file selection were committed in `a75b0e87b` and pushed. Existing browser test evidence is in the earlier work log; CUI-003 remains partially complete because other dialog, labeling, chart alternatives and full WCAG review remain.
- **germ environment inspection:** `ssh germ` succeeded. Host `fastcreate-472995` runs four healthy containers: UI, DNS, control API, and PostgreSQL 15. Read-only checks through SSH returned API `/health` 200, `/ready` 200, and UI 200. Local direct curls returned proxy 503 because `HTTP_PROXY` routes loopback; this is local test setup, not a germ service failure.
- **germ authoritative DNS smoke:** `dig @127.0.0.1 uid0.ir SOA +norecurse` returned authoritative NOERROR and serial `2026111900`; unrelated `example.com` returned REFUSED; AXFR of `uid0.ir` returned REFUSED. These are read-only tests of the deployed service, not evidence that local uncommitted code was deployed.
- **PostgreSQL backup/PITR drills:** `scripts/postgres_restore_drill.sh` on germ verified encrypted dump checksum, failed-dump cleanup, overwrite refusal, and restored `drill.invalid` in one second. `scripts/postgres_pitr_drill.sh` verified the physical base backup with `pg_verifybackup` and restored to a named point, retaining the pre-target row and excluding the post-target row. Both used isolated, network-disabled disposable PostgreSQL 16 containers on tmpfs. Code commits are `746c4f89a` and `d0a8eee58`; status documentation commit is `0341a909c`.
- **Browser hardening/accessibility:** commits `dffbb3e01`, `3170df46d`, `eb75ba752`, and `6c758dc3a` provide CSP script blocking test, route error recovery, modal focus trap/restoration, and keyboard file input. Browser tests passed locally. Dependency policy fixes are in `e61dea001`; GitHub run `45344351797` passed validation, image build completion is not recorded in this ledger.
- **CORE-011 advanced record support (2026-11-25): COMPLETED.** The API now returns an explicit `record_type` error for DNAME, LOC, AFSDB, APL, DHCID, HIP, IPSECKEY, and KX because the checked-in Hickory implementation has no RDATA parser for those types. CAA remains the supported advanced editable type, is labeled in the record editor, and record form fields have accessible names. Tests actually run: `cargo fmt --all -- --check` passed; `cargo test -p control_api --bin control_api dns_validator::tests::caa_rdata_round_trips_through_hickory -- --nocapture` passed 1/1; `cargo test -p control_api --bin control_api dns_validator::tests::unsupported_advanced_record_types_fail_explicitly -- --nocapture` passed 1/1; `cargo test -p control_api --bin control_api caa_record_roundtrips_through_api_database_and_zone_publication -- --nocapture` passed 1/1 using germ PostgreSQL 15 over an SSH tunnel and a unique test schema (CAA POST/list/published zone-file value plus HTTP 400 rejection checks); `PLAYWRIGHT_CHROMIUM_EXECUTABLE=/snap/bin/chromium npx playwright test --config=tests/playwright.config.cjs tests/record-types.spec.cjs --workers=1` passed 1/1 (real Chromium UI, stubbed API); `npm run lint`, `npm run build`, and `npm run test:routes` all passed (83 route pairs). Browser download from Playwright CDN returned HTTP 403, so the system Chromium override is used. The legacy comprehensive E2E test's hard-coded germ admin credentials returned HTTP 401; no live UI-to-germ API E2E pass is claimed. API behavior was exercised against germ PostgreSQL in the isolated-schema integration test. Commit `2a29c6b07` pushed. Files: `crates/control_api/src/dns_validator.rs`, `crates/control_api/src/api_tests.rs`, `web/ui/src/pages/Records.jsx`, `web/ui/tests/playwright.config.cjs`, `web/ui/tests/record-types.spec.cjs`, and `docs/RECORD_TYPES.md`.
- **Preserved user changes:** Local `.env`, `env/api.env`, `env/db.env`, and `env/grafana.env` files remain in place as ignored files; the user's pre-existing contents were not changed. `deploy/dns/named.toml`, `web/ui/src/pages/Admin/AuditLogs.jsx`, `WORK_PROGRESS.md`, the audit markdown file, and `deploy/dns/.orphaned/` remain untouched. The user removed `TASK_STATUS.md` and `FINAL_IMPLEMENTATION_REPORT.md`; those unstaged deletions are preserved. On germ, `.env`, `env/api.env`, and `env/db.env` were already locally modified before this execution. Their original state was backed up; only DB/JWT/admin secret assignments were rotated, other content was preserved, and permissions were tightened to 0600. No germ runtime state or credentials were committed.

### Delivery state

Current branch is `main`; remote is `origin`; `origin/main` is synchronized at `f8cb79bcd2b12c77401d148de1e212da7b305232`. This execution pushed code commits `66b60fc1b` (zone revision settings), `f426ac56c` (untrack secret files/templates), and `bfa08fb72` (scanner regression coverage), plus task ledger commits `e77475d91` and `f8cb79bcd`. Earlier commits remain in history. No environment values, test-server configs, databases, or runtime DNS state were staged. The user’s pre-existing local report deletions and unrelated UI/deploy/audit working files remain unstaged and untouched. On germ, the previous config state and PostgreSQL archive are preserved under `/root/outiscloud-secret-rotation-20261125T141234Z` with directory mode 0700 and files mode 0600; restore listing and byte comparison verified the backup before rotation.

### Phase 0 completion worklist

| Task | Status | Remaining implementation and verification |
|---|---|---|
| ARCH-002 | COMPLETED | Durable outbox, retries, acknowledgement, operator requeue and all defined failure-mode tests are complete; evidence is recorded below. |
| ARCH-003 | COMPLETED | Bounded pool plus FIFO tenant gate selected and measured; cross-tenant progress, rollback, retry, pool recovery, mutation, and quota-race tests pass on isolated germ/PostgreSQL. Additional retries and broader workload sweeps are follow-up optimization, not remaining acceptance. |
| ARCH-007 | COMPLETED | Repository hygiene, templates, custom scanner, exact historical test-fixture baseline, and germ DB/JWT/admin credential rotation are complete. Local scanner and redacted full-history Gitleaks pass; germ API health/readiness and new login pass after DB/API restart, while old password/token fail. A no-history-rewrite decision is recorded. This validates the repository and test environment only; no production deployment was changed or claimed. Commits `f426ac56c`, `bfa08fb72`, and `f8cb79bcd` are pushed. |

### ARCH-002 implementation update — 2026-11-25

**Status: COMPLETED.** Added `publication_outbox` with one idempotent job per zone, pending/failed state, attempt count, due timestamp and last error. On a zone publication failure, the API persists a retry job. A background worker claims due jobs with `FOR UPDATE SKIP LOCKED`, regenerates from the currently committed database state, acknowledges successful publications by deleting the job, and uses exponential backoff capped at 256 seconds. After ten attempts, the job is marked failed; an admin-only audited endpoint requeues terminal jobs. Successful synchronous publication clears stale retry rows. Since jobs contain only the zone domain and the worker reads current committed state, a rolled-back update cannot be published from a stale retry payload. Existing callers retain synchronous publication behavior.

Files: `crates/control_api/src/main.rs`, `crates/control_api/migrations/007_publication_outbox.sql`.

Executed on isolated PostgreSQL 16 containers on `germ` (never the running project DB): `publication_outbox_persists_retries_and_serializes_concurrent_workers` passed 1/1; `failed_publication_retries_latest_database_state_after_restart` passed 1/1 with a real `BEGIN`/`ROLLBACK` and committed-state verification; `publication_worker_recovers_persisted_jobs_and_stops_after_ten_attempts` passed 1/1, including filesystem failure, new-pool recovery, terminating both worker pool sessions, automatic reconnect, and successful retry; `publication_retry_requeue_requires_admin_and_resets_terminal_job` passed 1/1 (viewer denied; admin requeue resets terminal row); `publication_outbox_upgrade_adds_missing_status_column_idempotently` passed 1/1. Local filesystem checks `failing_zone_keeps_last_known_good_and_does_not_stop_others` and `atomic_zone_rename_failure_preserves_last_known_good_file` each passed 1/1. Unit tests `publication_retry_tests` passed 2/2; `cargo fmt --all -- --check` and `git diff --check` pass. A first rollback test attempt failed because the test omitted `BEGIN`; after correcting the test, the actual rollback check passed and the candidate value was absent from the republished file. Commits: `e939d7853`, `ba0dda5e6`, `13fb2de3c`, `6270a728e` (pushed). Isolated containers were stopped after runs.

**Restart recovery strengthened and rerun on 2026-11-25:** `failed_publication_retries_latest_database_state_after_restart` now launches the same test executable as a new child process and asserts the child test actually ran and passed. The child opens the parent's isolated PostgreSQL schema and zone directory, claims the persisted outbox job, republishes only the committed DB state after the parent's real rollback, and removes the job. On `germ` (`fastcreate-472995`), an ephemeral PostgreSQL 16 Alpine container was exposed only on remote loopback and reached through an SSH local forward; command `TEST_DATABASE_URL='postgres://postgres@127.0.0.1:55432/postgres' cargo test -p control_api --bin control_api publication_ -- --nocapture` passed 11 tests, 0 failed, 1 intentionally ignored helper (203.55 s). The focused parent test also passed 1/1 (55.11 s). Container and tunnel were stopped; read-only `docker ps` confirmed the four existing project containers remained healthy and no test container/port remained.

### ARCH-003 / PERF-002 implementation update — 2026-11-25

**Roadmap status: COMPLETED.** The original acceptance outcome is a measured design decision covering transaction concurrency, contention and rollback. The evidence below verifies the chosen bounded pool and per-tenant gate, the comparison against the serialized baseline, rollback behavior, and safe retry boundaries. Additional workload sweeps and expanding retries to other handlers remain useful follow-up hardening, but are not prerequisites stated by ARCH-003.

**Implementation detail:** Replaced the single reserved transaction session with a separately bounded transaction pool. `DB_TRANSACTION_POOL_SIZE` sets the ceiling and defaults to `min(DB_POOL_SIZE, 4)`; each slot is exclusively held for a transaction and has automatic reconnect supervision. Query and transaction pool sizes are reported independently by the pool, while transaction sessions are included in health checks. `.env.example` documents the capacity knobs. ADR-0005 now records the implemented state and remaining architecture work.

Files: `crates/control_api/src/db_pool.rs`, `crates/control_api/src/main.rs`, `crates/control_api/src/api_tests.rs`, `.env.example`, `docs/adr/ADR-0005-transaction-concurrency.md`.

On `germ` (Ubuntu test host `fastcreate-472995`; isolated PostgreSQL 16 Docker container reached over SSH local forwarding; existing project containers and database were not modified), `TEST_DATABASE_URL=... cargo test -p control_api --bin control_api bounded_transaction_pool_runs_concurrently_and_rolls_back_isolated_work -- --nocapture` passed 1/1. Four concurrent 200 ms transactions on four distinct PostgreSQL backend sessions took 1.5076 s versus 4.3310 s through the single-slot baseline (2.87x measured speedup); the test also asserts a rolled-back insert is absent. `cargo test -p control_api --bin control_api pool_replaces_dropped_connections -- --nocapture` passed 1/1 after terminating all six pool sessions; both query and transaction pools recovered. `cargo fmt --all` and `git diff --check` pass. The database container was stopped after testing. Remaining: tenant-fair admission control, bounded retry on serialization conflicts, explicit rollback metrics, and broader concurrency/load sweeps. This benchmark does not establish production capacity.

Commit: `b8ad0f418` (`perf(api): add bounded transaction pool with germ benchmark`), pushed to `origin/main`.

### ARCH-003 rollback metrics update — 2026-11-25

Rollback calls in control API transaction handlers now go through a shared helper that logs failures and increments Prometheus counters `outis_db_transaction_rollbacks_total` and `outis_db_transaction_rollback_failures_total`. The metrics test verifies attempt/failure increments and scrape registration. Executed `cargo test -p control_api --bin control_api transaction_rollback_attempts_and_failures_are_exposed -- --nocapture`: passed 1/1; `cargo fmt --all` ran before the test. Files: `crates/control_api/src/main.rs`, `crates/control_api/src/metrics.rs`. Remaining ARCH-003 work is per-tenant admission/fairness and bounded serialization retry. Rollback metrics were committed as `91132b968` and pushed.

### ARCH-003 tenant fairness and bounded retry update — 2026-11-25

`Pool::begin_for` uses a FIFO tenant gate with weak-reference cleanup. Zone creation, record creation/import, zone update and compensation, delete, and clone now acquire tenant-owned transactions through that gate. `Pool::run_transaction` executes serializable transactions with bounded exponential backoff and retries only PostgreSQL serialization/deadlock errors (SQLSTATE 40001/40P01); it rolls back every failed attempt and documents that retryable closures must not perform external side effects. It remains opt-in until each handler's side effects are reviewed for replay safety.

Files: `crates/control_api/src/db_pool.rs`, `crates/control_api/src/main.rs`, `crates/control_api/src/api_tests.rs`, `docs/adr/ADR-0005-transaction-concurrency.md`. On `germ` (`fastcreate-472995`), a disposable PostgreSQL 15 container with tmpfs data and SSH local forwarding ran `serializable_transactions_retry_only_retryable_database_conflicts` (1/1; successful retry, no retry for division-by-zero, and exactly two attempts when capped at two) and `tenant_transaction_gate_isolates_bursts_without_blocking_other_tenants` (1/1; tenant B proceeds while tenant A's second transaction waits; A proceeds after release). `pool_replaces_dropped_connections` passed 1/1. The repeated bounded-pool comparison measured four concurrent 200 ms transactions at 1.336 s versus 3.837 s for the single-slot baseline (2.87x); `bounded_transaction_pool_runs_concurrently_and_rolls_back_isolated_work` passed 1/1. `transaction_rollback_attempts_and_failures_are_exposed` passed 1/1. `password_change_and_admin_reset_revoke_access_and_refresh_tokens` passed 1/1 with password/session revocation routed through the retry helper. After extending gate use, `record_validation_rrsets_and_atomic_update` passed 1/1 (102.41 s), `import_is_all_or_nothing_and_never_partial` passed 1/1 (37.82 s), `concurrent_zone_creates_cannot_exceed_quota` passed 1/1 (41.65 s), `concurrent_record_creates_cannot_exceed_quota` passed 1/1 (55.71 s), and `concurrent_imports_cannot_exceed_quota` passed 1/1 (50.73 s). All DB tests used isolated per-test schemas; each temporary PostgreSQL container was stopped after its run and no existing project containers/database were changed. `cargo fmt --all -- --check`, `git diff --check`, and `cargo check -p control_api --tests` exited 0. `cargo clippy -p control_api --bin control_api --tests` also exited 0 with existing workspace warnings. Implementation commits `fa6e5a8cd` (pool/retry/fairness), `eb6261838` (zone mutation gate adoption), and `6aa701d14` (password transaction retry) are pushed. Combined with the measured benchmark and rollback evidence above, these satisfy ARCH-003; further retry adoption and workload-scale sweeps are follow-up optimization.

### CORE-008 germ dual-stack wire validation update — 2026-11-25

Connected to `germ` and ran an isolated stripped build of `target/debug/hickory-dns` (not the running customer/test service) on 127.0.0.1 and ::1, port 10553, with an isolated `example.test` file zone. Independent BIND `dig` returned authoritative A `192.0.2.80` for all four checks: UDP/TCP over IPv4 and UDP/TCP over IPv6 (`dig -4 @127.0.0.1 -p 10553 www.example.test A`, same with `+tcp`, and corresponding `dig -6 @::1` commands). Expected: each query returns the fixture A record; actual: all four returned it. The temporary process was stopped, its dedicated files removed, and `ss -lntup | grep 10553` confirmed the test port was released. No existing container or project database was changed. This verifies dual-stack authoritative serving on germ, not external DNSSEC delegation conformance.

Independent DNSSEC validation on germ: launched an isolated stripped local Hickory build bound only to `127.0.0.1:10553`, using the checked-in `example.com` test zone and test-only Ed25519 key. `dig @127.0.0.1 -p 10553 example.com DNSKEY +dnssec` returned DNSKEY and RRSIG; `dig @127.0.0.1 -p 10553 www.example.com A +dnssec +time=2 +tries=1 +noall +answer` returned A and RRSIG. BIND `delv -a /tmp/outis-dnssec-lab.WH2qIr/anchor.conf +root=example.com -p 10553 @127.0.0.1 www.example.com A +vtrace` reported `fully validated` and returned A `127.0.0.1`. The negative control was run with `sed "s/578GcTk81Y9jCj5nNhz6arQhns6wvqCe81opArzyYN0=/A78GcTk81Y9jCj5nNhz6arQhns6wvqCe81opArzyYN0=/" /tmp/outis-dnssec-lab.WH2qIr/anchor.conf >/tmp/outis-dnssec-lab.WH2qIr/wrong-anchor.conf`, then `delv -a /tmp/outis-dnssec-lab.WH2qIr/wrong-anchor.conf +root=example.com -p 10553 @127.0.0.1 www.example.com A`; the expected rejection was confirmed by asserting output contained `resolution failed: broken trust chain`. Note: BIND `delv` returns exit code 0 even for that validation failure, so the diagnostic text—not its exit status—was the assertion. The first command used `trusted-keys` and BIND 9.18 did not load it; changing to `trust-anchors` plus `+root=example.com` fixed the test. The running project’s `uid0.ir` DNSKEY query returned no key and `delv @127.0.0.1` could not validate because that deployed listener is authoritative-only and refused the recursive parent DS fetch; this does not establish a deployed-zone DNSSEC defect. The isolated process was stopped, its port confirmed released, and all temporary files removed. External parent delegation validation remains outstanding.


### ARCH-007 secret hygiene update — 2026-11-25

Added `.github/workflows/secrets.yml` to run full-history Gitleaks on pushes, pull requests, manual runs, and daily schedules without uploading findings. `.env`, `env/api.env`, `env/db.env`, `env/grafana.env`, and `k8s/secret.yaml` have been removed from the Git index; `test -f` confirmed each local copy remained present and ignored by existing `.gitignore` rules. Added `env/{api,db,grafana}.env.example`, `k8s/secret.example.yaml`, and updated README/setup instructions. `docker-compose -f docker-compose.yml config -q` and a Ruby YAML parse of the two Kubernetes example documents passed. `python3 scripts/secret_scan.py` initially found only test workflow literals and Kubernetes template placeholders; exemptions are now restricted to loopback test database URLs, ephemeral CI PostgreSQL values and example templates, with 4 unit tests passing (`python3 -m unittest scripts.test_secret_scan`). The scanner now reports no live-looking assignment in tracked config files. A local Gitleaks 8.16 full-history scan initially found 34 fingerprints in 26 upstream test fixtures/example config paths (private test keys and fake test tokens; no `.env`, `env/*.env`, or Kubernetes secret paths). Those exact fingerprints, not paths or rules generally, are listed in `.gitleaksignore`; rerun on commit `bfa08fb72` passed with exit 0 and zero unignored findings. The official Gitleaks container pull was denied by the local Docker registry policy, so the Ubuntu package was downloaded to a temporary directory and removed after scanning. No secret values were displayed, copied into task tracking, or committed. GitHub hosted status remains unverified (`gh` unavailable; unauthenticated Actions API had returned HTTP 403 rate limiting). No history rewrite was performed; see the subsequent germ credential rotation entry for completion evidence.

### CORE-009 forwarder transfer-abuse hardening — 2026-11-25

`Catalog` now refuses AXFR for `External` zones before asking any handler to perform the transfer, preventing forwarding zones from relaying transfer probes or upstream zone data. The regression test configures a fake local TCP upstream, sends AXFR over TCP using Hickory’s client, asserts DNS RCODE REFUSED, and verifies the fake upstream accepted no connection. The recursor config defaults to built-in root DNSSEC validation, while missing custom trust-anchor files fail closed. `cargo test -p hickory-dns --test integration axfr_for_external_zone_is_refused_without_upstream_contact -- --nocapture` passed 1/1; `cargo test -p hickory-resolver --lib --features 'recursor dnssec-ring serde toml tokio' trust_anchor_policy -- --nocapture` passed 2/2 and the full resolver suite passed 96, 0 failed, 5 ignored. `cargo check -p hickory-resolver --no-default-features --features 'recursor serde toml tokio'` passed. Commits `2c9d09e85` and `efeddc221` are pushed. CORE-009 acceptance is complete; additional abuse-resistance review is follow-up hardening.

### CORE-010 DoH3 end-to-end verification — 2026-11-25

The test harness now passes `--h3-port=0`, recognizes the server’s `HTTP/3` listener log, and records the H3 socket. Added an isolated end-to-end test with a generated, current localhost certificate: the test starts the real Hickory binary with TLS, HTTPS, QUIC, and H3 enabled, validates the certificate using a dedicated root store, sends a DNS query using Hickory’s `H3ClientStream`, and asserts the authoritative A answer. Initial runs found the harness did not recognize the `HTTP/3` log label and the existing checked-in certificate was expired; both test problems were fixed without weakening certificate validation. `cargo test -p hickory-dns --test integration --features 'h3-ring https-ring' doh3_client_queries_local_authoritative_server -- --nocapture` passed 1/1. `cargo fmt --all -- --check` and `git diff --check` passed. The CI DNS job now runs this test. `ssh germ` reconfirmed host `fastcreate-472995`, four healthy project containers, and read-only authoritative SOA response for `uid0.ir` (serial `2026111900`); no server state was changed. Commit `91b9cd7ad` was pushed to `origin/main`.

### CORE-004 DNSSEC readiness and CORE-005 admission validation update — 2026-11-25

CORE-004 key availability: added `dnssec_zone_with_unavailable_signing_key_fails_load`, which builds a valid temporary primary zone with a configured but missing private signing key and asserts catalog zone loading fails with the key path in the error. Since startup marks readiness only after configured zones are loaded, this verifies a required signing key cannot be silently skipped and the process cannot mark itself serving-ready with that broken DNSSEC zone. `cargo test -p hickory-dns --lib dnssec_zone_with_unavailable_signing_key_fails_load -- --nocapture` passed 1/1. `cargo test -p hickory-dns --test integration test_health_and_ready_endpoints` passed 1/1 in this update; `cargo fmt --all -- --check` and `git diff --check` passed. Code/test commit `8872598e7` is pushed. Together with compose/Helm probe configuration, failed reload/recovery and listener-failure propagation tests, CORE-004 meets its roadmap acceptance criteria. Cluster rolling-transition drills remain a higher-level operational validation, not a missing endpoint acceptance item.

### CORE-005 TCP and UDP admission validation update — 2026-11-25

The isolated test server starts with `DNS_MAX_TCP_CONNECTIONS=8` and `DNS_MAX_INFLIGHT_UDP=8`, opens 96 concurrent idle TCP sockets, confirms at least 32 excess connections close, sends a bounded 32-query UDP burst, and verifies a fresh authoritative UDP query succeeds within three seconds. The first run exposed a misspelled UDP environment variable; correcting it exercised the actual semaphore. A 512-query burst did not provide a valid short-recovery assertion because it continued to occupy the receive queue, so the acceptance test now uses bounded pressure and verifies recovery after the burst. Executed `cargo test -p hickory-dns --test integration protocol_admission_fanout_keeps_service_available -- --nocapture`: passed 1/1 in 0.83 s. Follow-up `cargo test -p hickory-server --features sqlite --lib listener_failure_aborts_and_drains_other_server_tasks` and `cargo test -p hickory-dns --test integration readiness_tracks_failed_zone_reload_and_recovery` both exited 0 (1/1 each); `cargo fmt --all -- --check` and `git diff --check` exited 0. Changes were pushed in `42694c91f` and test evidence in `b31cfcdf4`/`922dbfc71`. A concurrent saturation test, `cargo test -p hickory-server --features sqlite --lib concurrent_protocol_admission_never_exceeds_configured_caps -- --nocapture`, passed 1/1 and concurrently admitted exactly eight workers (the configured cap) across UDP, TCP/TLS, and HTTP/2 permit paths; release completed and all paths recovered. Initial compilation exposed that Hickory `Protocol` has no TLS/HTTPS variants; the test now uses explicit transport labels and the actual semaphore selectors. At the time of this update, TLS and HTTP/2 wire-level load testing remained unverified; see the CORE-005 completion below. `ssh germ 'hostname; uname -a; uptime; docker ps --format ...'` verified `fastcreate-472995` and four healthy project containers. Read-only `ssh germ 'dig @127.0.0.1 uid0.ir SOA +norecurse +time=2 +tries=1 +noall +answer'` returned authoritative SOA serial `2026111900`; no local code was deployed. Files: `.github/workflows/ci.yml`, `bin/tests/integration/named_tests.rs`; CI runs this check.

### Phase 1 completion worklist

Use the task-level status table in §19 as the canonical list of Phase 1 IDs and dependencies. Phase 1's current germ and isolated-environment verification is recorded in the task rows and evidence entries above. Both Phase 0 and Phase 1 are closed; continue with Phase 2 in roadmap order.

### CORE-001 implementation update — 2026-11-25

**Status: COMPLETED.** The server rejects AXFR over datagrams, streams bounded multi-message transfers, and signs chained TSIG responses correctly. File-backed zones now implement the configured `Deny`, `AllowAll`, and `AllowSigned` policy; file store config accepts per-zone TSIG keys with a default 300-second fudge, verifies request MAC/time, and returns signed error/success context. The Hickory AXFR client is exercised against both the repository server and an independent BIND 9.20 primary.

Files changed for this completion: `crates/server/src/store/file.rs`, `bin/src/config/mod.rs`, `bin/src/config/tests.rs`, `bin/tests/integration/store_file_tests.rs`, `bin/tests/integration/named_tests.rs`, `.github/workflows/ci.yml`. Prior server streaming/TSIG chain changes are in `crates/server/src/zone_handler/catalog.rs` and `crates/proto/src/rr/tsig.rs`.

Executed and passed: `cargo test -p hickory-dns --test integration hickory_axfr_client_consumes_multipart_transfer -- --nocapture` (Hickory client read 84 records including both SOA boundaries); `cargo test -p hickory-dns --test integration signed_axfr_stream_verifies_with_independent_dig_client -- --nocapture` (BIND `dig` client validated signed multi-message AXFR and unsigned denial); `cargo test -p hickory-dns --test integration signed_axfr_is_supported_for_file_backed_zones -- --nocapture` (valid file-store TSIG succeeded; unsigned and wrong-secret AXFR were refused); `cargo test -p hickory-server --features 'sqlite dnssec-ring' --lib store::file -- --nocapture` (1/1); `cargo check -p hickory-dns --features dnssec-ring`; `cargo check -p hickory-server --no-default-features --features dnssec-ring`; `cargo check -p hickory-dns --no-default-features --features sqlite`; `cargo fmt --all -- --check`; `git diff --check` all passed.

Independent server evidence on germ: ran disposable `internetsystemsconsortium/bind9:9.20` container `outiscloud-bind-axfr-interop`, with a test-only `interop.test` zone and TCP bound only to `127.0.0.1:15353`; BIND `dig @127.0.0.1 -p 15353 interop.test AXFR +tcp` returned opening SOA, NS, A records, and closing SOA. Forwarded only that loopback port over SSH to local `127.0.0.1:25353`; `HICKORY_AXFR_INTEROP_ADDR=127.0.0.1:25353 cargo test -p hickory-dns --test integration named_tests::hickory_axfr_client_interoperates_with_independent_bind -- --ignored --exact --nocapture` passed 1/1. The ephemeral BIND container and its exact temporary config directory were removed, port 15353 was confirmed free, and all four existing project containers remained healthy. Commit `5b85126d5` contains server stream/TSIG chain work; file-store TSIG, transfer tests, and CI additions were committed and pushed in `37a2cc326`.

### CORE-004 implementation update — 2026-11-25

**Status: COMPLETED.** DNS `/health` and `/ready` are wired into compose and Helm probes. Readiness is marked after zone loading and listener binding, expires if it is not refreshed, and changes to unavailable after a failed zone reload; the server keeps serving its last-known-good catalog and returns to ready after valid recovery. Missing configured DNSSEC signing keys fail zone loading before readiness. Listener task failure aborts sibling listeners and terminates the process rather than leaving a half-alive service.

Files changed: `bin/src/lib.rs`, `bin/tests/integration/server_harness.rs`, `bin/tests/integration/named_metrics_tests.rs`, `.github/workflows/ci.yml`. Executed `cargo test -p hickory-dns --test integration readiness_tracks_failed_zone_reload_and_recovery -- --nocapture`: passed 1/1. CI now runs both initial readiness and failed-reload recovery tests. Evidence: `cargo test -p hickory-dns --test integration readiness_tracks_failed_zone_reload_and_recovery` passed 1/1; `cargo test -p hickory-dns --test integration test_health_and_ready_endpoints` passed previously and is rerun in this execution; `cargo test -p hickory-dns --lib dnssec_zone_with_unavailable_signing_key_fails_load` passed 1/1; `cargo test -p hickory-server --features sqlite --lib listener_failure_aborts_and_drains_other_server_tasks` passed 1/1. Compose/Helm templates provide `/ready` probes. Code commits `8872598e7` and `a91de153c` are pushed. Cluster-wide rolling transition is operational validation beyond the single-instance readiness acceptance criteria.

### CORE-004 listener failure propagation update — 2026-11-25

`Server::block_until_done` now returns immediately when a listener task fails, aborts and drains its sibling listener tasks, and lets the process fail rather than waiting forever with one protocol still down. This makes process health fail closed on listener loss. Added `listener_failure_aborts_and_drains_other_server_tasks`, which combines an injected listener error with a pending sibling and verifies prompt error propagation and task cleanup. `cargo test -p hickory-server --features sqlite --lib listener_failure_aborts_and_drains_other_server_tasks -- --nocapture` passed 1/1. The DNS integration checks `readiness_tracks_failed_zone_reload_and_recovery` and `tcp_connection_limit_rejects_fanout_and_keeps_service_available` also passed after the change. Files: `crates/server/src/server/mod.rs`. Remaining CORE-004 gaps: explicit signing-key readiness state and cluster/compose transition tests.

### CORE-002 implementation update — 2026-11-25

**Status: COMPLETED by the roadmap's explicit-rejection alternative.** Testing exposed that the existing recovery journal does not encode RFC 1995 old/new SOA boundaries: a stale IXFR request could otherwise receive an incomplete delta. The server now returns NOTIMP for stale serials and never publishes those unframed journal records as an IXFR answer. A request at the current SOA serial receives exactly one current SOA, per RFC 1995. Full IXFR delta replication remains unsupported; clients must use AXFR until the journal is redesigned.

Files changed: `crates/server/src/zone_handler/catalog.rs`, `bin/tests/integration/named_tests.rs`, `.github/workflows/ci.yml`. `cargo test -p hickory-dns --test integration ixfr_current_serial_succeeds_and_stale_serial_is_refused_safely -- --nocapture` passed 1/1 on an isolated temporary SQLite server. `dig` verified the one-SOA current-serial response; a TSIG-authenticated `nsupdate` advanced the zone serial; the stale IXFR request then returned promptly as `Transfer failed` and server logs recorded response code NOTIMP, with no incomplete records returned. This preserves honest protocol behavior instead of silently claiming IXFR replication.

### CORE-003 NOTIFY receiver test update — 2026-11-25

Added a wire-level test using Hickory's `ClientHandle::notify`: a configured local zone returns NOERROR and a name outside configured zones returns NOTAUTH. An initial assertion used `missing.example.test`, which correctly matched the parent zone; the fixture was corrected to `missing.other.test` and the test passes. Executed `cargo test -p hickory-dns --test integration notify_acknowledges_local_zone_and_rejects_unknown_zone -- --nocapture`: passed 1/1. CI runs the test. This does not claim peer delivery or secondary refresh; CORE-003 stays partial. Files: `bin/tests/integration/named_tests.rs`, `.github/workflows/ci.yml`, `task.md`.

### Latest validation sweep — 2026-11-25

Executed the four current DNS integration checks in one fail-fast shell chain: signed AXFR via `dig`, current/stale IXFR behavior via `dig` plus TSIG `nsupdate`, NOTIFY NOERROR/NOTAUTH behavior, and readiness loss/recovery on invalid/valid zone reload. All four tests passed (1/1 each). `cargo check -p hickory-proto --no-default-features --features std` passed; `cargo test -p hickory-proto --features dnssec-ring test_sign_and_verify_message_tsig -- --nocapture` passed 3/3. `cargo clippy -p control_api --all-targets` and `cargo clippy -p hickory-dns --test integration` both exited successfully; they report existing lint warnings across the workspace, and no warning was suppressed. `cargo fmt --all -- --check` and `git diff --check` pass. The germ DNS/HTTP containers were not replaced or modified during this sweep.

### CORE-003 primary NOTIFY sender update — 2026-11-25

Implemented per-zone `notify_peers` configuration with optional file-backed TSIG signer configuration. A successful hot reload now sends SOA NOTIFY to each configured primary-zone peer over TCP; connection and response timeouts retry three times with exponential backoff, NOERROR/NOTIMP complete successfully, and a terminal refusal is logged without retry. The receiver continues to acknowledge served zones and return NOTAUTH for unknown zones. This adds the primary sender but does not claim the secondary refresh transaction: receiving a valid NOTIFY still needs to trigger a secure AXFR/IXFR and atomic persistence, and inbound NOTIFY TSIG verification remains unimplemented.

Executed using the built integration binary in the isolated Debian 13 container (needed because the local desktop user's inotify-instance quota is exhausted): `named_tests::notify_acknowledges_local_zone_and_rejects_unknown_zone` passed 1/1; `named_tests::primary_notifies_configured_secondary_after_zone_reload` passed 1/1 and observed the receiver's NOTIFY operation metric; `named_tests::primary_notifies_with_tsig_and_retries_unresponsive_peer` passed 1/1 in 7.03 s, captured TSIG on the wire, and observed all three unanswered attempts. `cargo test -p hickory-dns --test integration --no-run`, `cargo check -p hickory-dns`, `cargo check -p hickory-dns --no-default-features --features sqlite`, and formatting/diff checks passed. One early assertion looked for TSIG in the ordinary Additional list; Hickory parses it into `Message::signature()`, and the test now inspects that field. CI runs both peer delivery and signed-timeout tests. Source files: `bin/src/config/mod.rs`, `bin/src/lib.rs`, `bin/tests/integration/named_tests.rs`, `.github/workflows/ci.yml`.

Implementation commit `a85fe51e7` pushed to `origin/main`.

### CORE-003 secondary refresh and inbound TSIG completion — 2026-11-25

**Status: COMPLETED.** An accepted NOTIFY now queues a serialized refresh only for configured secondary zones and only when the source IP matches a configured master. The worker authenticates AXFR when a master TSIG key is configured, caps connection/response times and transfer size, validates matching opening/closing SOAs, owner names, and the Hickory zone parser, rejects stale serials using RFC 1982 arithmetic, writes/fsyncs a unique staged file, and atomically renames it before the file watcher swaps the served catalog. A rejected/invalid transfer leaves the existing file and catalog unchanged. Incoming signed NOTIFY is validated against configured file-store TSIG keys; bad or missing signatures are refused.

Files: `bin/src/config/mod.rs`, `bin/src/lib.rs`, `bin/tests/integration/named_tests.rs`, `bin/tests/integration/server_harness.rs`, `crates/server/src/store/file.rs`, `crates/server/src/zone_handler/catalog.rs`, `crates/server/src/zone_handler/mod.rs`, `.github/workflows/ci.yml`.

Verification: `cargo test -p hickory-dns --test integration --features 'https-ring' --no-run` passed. In an isolated Debian 13 container using the built Hickory binary, `named_tests::accepted_notify_refreshes_secondary_by_axfr_and_preserves_last_known_good_on_failure` passed 1/1 (successful AXFR changed the served A record; a denied transfer preserved the original answer), `notify_acknowledges_local_zone_and_rejects_unknown_zone` passed 1/1, `notify_requires_and_verifies_configured_file_store_tsig` passed 1/1, `primary_notifies_configured_secondary_after_zone_reload` passed 1/1, and `primary_notifies_with_tsig_and_retries_unresponsive_peer` passed 1/1 with three observed unanswered attempts. The first real transfer test exposed that the temporary server directory was inaccessible after the DNS child dropped to `nobody`; the test harness now explicitly grants replacement access only to that isolated temporary directory. Existing deployment startup assigns the mounted zone directory to the service UID. `cargo test -p hickory-dns --test integration --no-default-features --features sqlite --no-run` also passed after gating metrics-only tests. The broad Debian `named_tests::` run was not accepted as green: 18 passed and 5 failed because `dig`/`nsupdate` binaries are absent in that minimal image; the targeted NOTIFY tests above do not depend on those external tools.

### CORE-008 repeatable delegation and dual-stack completion — 2026-11-25

Added dual-stack and malformed-packet recovery tests to the DNS CI job. Executed `named_tests::test_ipv4_and_ipv6_toml_startup` and `named_tests::malformed_udp_packet_does_not_disrupt_authoritative_queries` from the built feature-enabled integration binary in an isolated Debian container: both passed 1/1, including TCP queries over IPv4 and IPv6 loopback. Existing `scripts/delegation_check.sh` was run on `germ` against the live `uid0.ir` delegation: parent TLD delegation and in-bailiwick glue were confirmed; both delegated names answered authoritative SOA over UDP and TCP; parent/child NS sets and SOA serial `2026111900` matched. The checker reported a warning that `ns1.uid0.ir` and `ns2.uid0.ir` resolve to the same IPv4 address (`143.20.60.135`), so this is not nameserver address redundancy. `dig +trace uid0.ir SOA`, direct authoritative SOA queries to both names, and `delv uid0.ir SOA` confirmed the live child delegation is unsigned (no DNSKEY/DS; `delv` reports an unsigned answer). This read-only probe did not change the public delegation. The isolated signed-zone `delv` positive/negative trust-anchor evidence is recorded in the prior CORE-008 entry. |

### CORE-005 TLS and HTTP/2 wire-load completion — 2026-11-25

**Status: COMPLETED.** Added a feature-enabled isolated TLS/DoH2 integration test with `DNS_MAX_TCP_CONNECTIONS=8` and `DNS_MAX_H2_STREAMS=2`. It synchronizes 64 query streams on one HTTP/2 connection, asserts the server admits work and rejects excess streams, then opens 24 concurrent TLS/HTTP2 connections and asserts connection admission rejects excess connections. A fresh HTTPS connection answers an authoritative query after both fanout waves. The test-server output ring captured actual `HTTP/2 stream limit reached` and `HTTPS connection limit reached` logs. CI runs this test with `https-ring`.

Executed `cargo test -p hickory-dns --test integration --features https-ring --no-run` (pass); the feature-enabled integration binary ran in the isolated Debian 13 container under UID 0 due the local desktop user's inotify-instance limit. `https_h2_fanout_is_bounded_and_service_recovers` passed three consecutive runs (1/1 each: 0.16 s, 0.12 s, 0.13 s). `named_tests::protocol_admission_fanout_keeps_service_available` passed 1/1 in 0.87 s with `TDNS_WORKSPACE_ROOT` set to the checkout. `cargo test -p hickory-server --features sqlite --lib concurrent_protocol_admission_never_exceeds_configured_caps -- --nocapture` passed 1/1 and observed all protocol permits recover. The first run found a test-fixture config field unsupported under the HTTPS-only feature set; removing unrelated QUIC/H3 config keys resolved it. CI runs `cargo test -p hickory-dns --test integration --features https-ring https_h2_fanout_is_bounded_and_service_recovers`. Implementation commit `026023193` is pushed to `origin/main`.

### CORE-013 incremental zone reload load validation — 2026-11-25

**Status: COMPLETED.** Added reload counters for rebuilt and reused zone handlers. A two-zone isolated-server integration test runs a bounded query worker over both zones while replacing one zone file, confirms the new answer becomes visible and all query responses remain successful, then checks the counters report one rebuilt zone and at least one reused zone. The test-server harness previously left child stdout undrained after startup; the sustained-query test found this could block the DNS process on its output pipe. The harness now continuously drains output into a bounded 256-line buffer and prints the captured tail during cleanup.

Executed `cargo test -p hickory-dns --test integration --no-run` (pass); because this workstation's UID had exhausted its Linux inotify instance quota, executed the built integration binary in a disposable Debian 13 container under a separate UID: `docker run --rm --user 0 -v "$PWD:$PWD" -w "$PWD" debian:trixie-slim "$PWD/target/debug/deps/integration-3ccbdefe3f5f86a8" named_metrics_tests::single_zone_reload_reuses_unchanged_catalog_during_query_load --exact` (pass, 1/1, 0.48 s) and the same invocation with `named_metrics_tests::readiness_tracks_failed_zone_reload_and_recovery` (pass, 1/1, 0.68 s). `cargo fmt --all -- --check` and `git diff --check` pass. CI now runs the load test. Commit `36b2c6f7c` was pushed to `origin/main`; remote HEAD matches. This validates the isolated binary, not a deployment of this revision onto germ's running containers.

### ZONE-007 revision settings and rollback update — 2026-11-25

`zone_revisions` now stores publishable zone settings (`zone_type`, GeoDNS/ECS flags, description, tags and AXFR policy) beside the domain and records. Revision diffs return `settings_changed`; restores apply record and settings changes in the same database transaction. Existing revisions with an empty settings object continue to restore records without altering current settings. Added migration `008_zone_revision_settings.sql` and matching idempotent runtime DDL. Added PostgreSQL integration coverage for settings diff and restoration.

Files: `crates/control_api/migrations/008_zone_revision_settings.sql`, `crates/control_api/src/main.rs`, `crates/control_api/src/ext.rs`, `crates/control_api/src/api_tests.rs`. Commit `66b60fc1b` pushed to `origin/main`; local and remote `main` both resolve to `66b60fc1bde1d43e383e93a43b85b69941fcbfbd`.

On `germ` (`fastcreate-472995`), used a disposable PostgreSQL 15 container with tmpfs and SSH local forwarding; existing project containers stayed healthy. `TEST_DATABASE_URL=... cargo test -p control_api --bin control_api api_tests::revision_restore_restores_zone_publication_settings -- --exact --nocapture` passed 1/1, including diff values and restore behavior. `... cargo test ... api_tests::revision_ -- --nocapture` passed 3/3 (diff, retention, setting restore); `... cargo test ... api_tests::zone_history_and_rollback -- --exact --nocapture` passed 1/1; and `... cargo test ... api_tests::migration_files_and_runtime_ddl_have_no_schema_drift -- --exact --nocapture` passed 1/1. The first schema-drift attempt caught that migration 008 did not create the revision table on a from-empty database; migration 008 was corrected to create the complete table and index before adding the settings column, and the rerun passed. `cargo fmt --all` and `cargo check -p control_api --tests` passed. The disposable container and SSH tunnel were removed; `docker ps` confirmed only the four pre-existing healthy project services remained.

ZONE-007 remains PARTIALLY COMPLETED: snapshot failures are logged and counted by `outis_zone_snapshot_failures_total` but are not returned to the mutation caller; restoring a renamed domain and UI rendering of the setting diff still need coverage. No change was deployed to the running germ application containers.

### ARCH-007 germ credential rotation and Phase 0 closure — 2026-11-25

The server is the test host `fastcreate-472995`; before changes it ran four healthy containers (PostgreSQL 15, control API, DNS, and UI). The active API/database credential values were not printed. Before rotation, an authenticated admin login using the server's configured account returned HTTP 200, confirming the credential was active. The PostgreSQL database was approximately 7 MB. A private backup was made at `/root/outiscloud-secret-rotation-20261125T141234Z`: copies of `.env`, `env/api.env`, `env/db.env`, `env/grafana.env`, and `k8s/secret.yaml`, plus a PostgreSQL custom archive. The config copies passed byte-for-byte comparison; the archive was 53,367 bytes and its catalog passed `pg_restore --list` inside the PostgreSQL container. Directory permissions are 0700 and backup files are 0600. The first attempted archive check used `pg_restore --list -`; this client treats `-` as a filename and rejected it. Copying the archive into the container and listing it by path succeeded; no restore or database write was performed during backup verification.

On germ, generated replacement values without emitting them, changed the PostgreSQL role password, reset the active admin account through the admin API, and replaced the API JWT signing secret. Updated only the corresponding settings in germ `.env`, `env/api.env`, and `env/db.env`, preserving other configuration lines, and changed those files to mode 0600. Recreated only the `db` and `control-api` Compose services; no volume was removed and no data migration was run. The existing verified database backup remains available for recovery. Local workstation env files were not changed.

Post-rotation acceptance evidence: the new admin login succeeded and `/api/v1/auth/me` returned the admin role; the old admin password returned HTTP 401; the old JWT returned HTTP 401; `/health` and `/ready` returned HTTP 200. `docker ps` showed all four original project containers healthy. `dig @127.0.0.1 uid0.ir SOA +norecurse +short` still returned authoritative SOA serial `2026111900`; no zone contents or delegation were changed. `docker compose -f docker-compose.yml config -q` on germ succeeded before recreation. Final runtime configs match the replacement values internally (comparison result only, no values printed).

Repository verification after the secret hygiene commits: `python3 -m unittest scripts.test_secret_scan` passed 4/4; `python3 scripts/secret_scan.py` reported no live-looking tracked assignments; local `docker-compose -f docker-compose.yml config -q` passed; the Ruby YAML parser accepted the Kubernetes Secret and ConfigMap templates. Full-history Gitleaks 8.16 with redacted report passed on `bfa08fb72` with exit 0 and zero unignored findings. The pre-baseline scan found 34 historical findings in 26 upstream test fixtures/example configuration paths; `.gitleaksignore` records only those exact fingerprints. A history rewrite was not performed: the remaining detected keys/tokens are deterministic test fixtures, the active germ credentials are rotated, and rewriting shared repository history would disrupt existing clones. No production environment or Kubernetes cluster was accessed or changed.

The replacement admin password is stored only in `/root/OutisCloud-hickory-dns/env/api.env` on germ with mode 0600; retrieve it there over SSH if test UI access is needed. Phase 0 and Phase 1 are now CLOSED. Proceed to Phase 2; the only remaining actions outside these completed phase criteria are any separate production credential rotation required by an external deployment owner.

### TRANSFER-001 policy publication update — 2026-11-25

Completed the previously missing per-zone AXFR policy publication path. `TomlConfigBuilder` emits `axfr_policy` for each zone, defaults to `Deny`, recognizes only the Hickory policy variants, and maps unknown persisted values to `Deny`. `generate_all` now reads the database policy and passes it to config generation. The transfer-policy API now regenerates/publishes the zone configuration after a database update; if publication fails, it restores the previous database value and attempts to republish the previous config. The API continues to reject `AllowSigned` because transfer TSIG key custody is not implemented.

Files: `crates/control_api/src/dns_builder.rs`, `crates/control_api/src/zone_file_generator.rs`, `crates/control_api/src/main.rs`, `crates/control_api/src/api_tests.rs`. `cargo fmt --all` passed. `cargo test -p control_api --bin control_api dns_builder::tests::axfr_policy_is_per_zone_and_unknown_values_fail_closed -- --exact` passed 1/1. On `germ` (`fastcreate-472995`), confirmed the four existing project containers remained healthy and started a separate PostgreSQL 15 test container bound only to server loopback, reached through an SSH local tunnel. `TEST_DATABASE_URL=postgres://postgres@127.0.0.1:55432/postgres cargo test -p control_api --bin control_api api_tests::zone_transfer_policy_endpoint_and_validation -- --exact --nocapture` passed 1/1. The integration test verifies persisted policy, generated Hickory config for AllowAll and Deny, rejection of AllowSigned, and a simulated database-read publication failure that rolls the DB back to Deny while preserving the already published Deny configuration. The disposable test DB and tunnel are removed after test execution; the running project containers and their data are untouched.

TRANSFER-001 remains PARTIALLY COMPLETED: peer-address ACL and managed TSIG key configuration/rotation are not present, so the endpoint safely supports only Deny and AllowAll. No test or production DNS delegation was changed. Implementation commit `3a6040ccaeeeac9c2e3a7c74d751e64156bab979` and tracking commit `e8ce483e6da7d5dbbf96658a50a7c574dff48bbe` were pushed successfully to `origin/main` as part of later push `cf8fe1b4533f8199172d508c0240d5cccc289dff`. The first two push attempts received transient GitHub Internal Server Error responses (request IDs `C8E9:268410:AEEBB:18BF89:6B07056B` and `F3D7:1AD458:B0630:18D6DB:6B070588`); retry succeeded without reconciliation or overwrite. `origin/main` is now at `cf8fe1b4533f8199172d508c0240d5cccc289dff`.

### TRANSFER-003 transfer observability implementation update — 2026-11-25

Added Hickory authoritative AXFR outcome counter (`hickory_zone_transfers_total`, bounded `success`/`refused`/`failure` result labels) and duration histogram (`hickory_zone_transfer_duration_seconds`, result label only; no zone/client label cardinality). Structured INFO events capture zone, client socket, DNS response code, and result for completed TCP transfers; UDP AXFR refusals are counted and retain their refusal warning. Added explicit metric descriptions for the existing query-duration histogram and registered transfer histogram buckets with the Prometheus exporter after the integration test exposed the missing query-histogram description and bucket configuration.

Files: `crates/server/src/zone_handler/catalog.rs`, `bin/src/prometheus_server.rs`, `bin/tests/integration/named_metrics_tests.rs`. `cargo test -p hickory-dns --test integration --features prometheus-metrics named_metrics_tests::axfr_outcomes_and_latency_are_exported_without_zone_cardinality -- --exact --nocapture` passed 1/1; the real isolated Hickory server served a 4-record AXFR under AllowAll and refused the Deny zone, and Prometheus scrape showed one success, one refusal, and both latency result series with valid buckets. The initial test correctly found that Hickory's client represents a DNS REFUSED response as a valid response message rather than a stream error; the assertion was fixed to inspect its DNS response code. The first metrics run also exposed missing help text for the existing query-duration histogram; explicit description was added and the rerun passed. `cargo check -p hickory-server --no-default-features` passed; `cargo fmt --all -- --check` and `git diff --check` passed. The isolated runtime logs an existing file-watcher startup warning (`Too many open files`) on this workstation; it did not affect serving, transfer metrics, or test results. This was a local isolated integration runtime, not a redeployment of germ's running containers.

TRANSFER-003 is PARTIALLY COMPLETED: control-plane searchable audit/troubleshooting pages and transfer peer/key details remain dependent on the ACL/TSIG management work in TRANSFER-001. Transfer metrics and logs are operationally useful independently. Implementation commit `cf8fe1b4533f8199172d508c0240d5cccc289dff` and its policy/test prerequisites were pushed successfully; `origin/main` was verified at that commit. Earlier transient remote Internal Server Errors did not result in lost work.

### ARCH-002 isolated database failure-suite rerun — 2026-11-25

Re-ran the database-backed publication tests on `germ` (`fastcreate-472995`) using a dedicated PostgreSQL 15 container exposed only on server loopback and an SSH local-forward. Exact command: `TEST_DATABASE_URL=postgres://postgres@127.0.0.1:55432/postgres cargo test -p control_api --bin control_api publication_ -- --nocapture --test-threads=1`. Actual result: 12 passed, 0 failed, 1 ignored, 183 filtered out (426.68 s). The ignored child test is intentionally launched as a separate process by the parent restart-recovery test; the parent itself passed. The run covered outbox persistence/concurrent workers, failure retry and state-based recovery after restart, terminal attempts and admin requeue, and retry schedule invariants. The separate filesystem test `zone_file_generator::tests::failing_zone_keeps_last_known_good_and_does_not_stop_others` remains recorded as passing in the earlier ARCH-002 evidence above. The temporary PostgreSQL container was removed; SSH forwarding was closed; `docker ps` confirmed the four pre-existing germ services were healthy and unchanged. No project database or DNS data was modified.

### TRANSFER-001 peer ACL enforcement update — 2026-11-25

Added `zones.axfr_allowed_peers TEXT[]` with migration `009_transfer_peer_acl.sql` and idempotent runtime DDL. `PUT /api/v1/zones/{id}/transfer-policy` accepts optional `allowed_peers`, validates at most 64 exact IPv4/IPv6 addresses, canonicalizes/deduplicates them, publishes the resulting Hickory config, and rolls policy plus ACL back on publish failure. The TOML builder writes addresses in each zone's file-store block; Hickory refuses AXFR before policy/TSIG authorization when the source is outside a configured non-empty allowlist. Empty peers retains policy-only behavior. TSIG key CRUD/custody remains unavailable, and `AllowSigned` remains rejected.

Files: `crates/control_api/migrations/001_initial_schema.sql`, `crates/control_api/migrations/009_transfer_peer_acl.sql`, `crates/control_api/src/main.rs`, `crates/control_api/src/dns_builder.rs`, `crates/control_api/src/zone_file_generator.rs`, `crates/control_api/src/api_tests.rs`, `crates/server/src/store/file.rs`, `bin/src/config/mod.rs`, `bin/tests/integration/named_tests.rs`, `bin/tests/integration/store_file_tests.rs`. `cargo check -p control_api --tests` passed. `cargo test -p hickory-dns --test integration --features prometheus-metrics named_tests::file_store_axfr_peer_acl_refuses_unlisted_client -- --exact --nocapture` passed 1/1; isolated Hickory answered the unlisted client's TCP AXFR with DNS REFUSED. Existing independent TSIG interoperability regression `cargo test -p hickory-dns --test integration --features prometheus-metrics named_tests::signed_axfr_stream_verifies_with_independent_dig_client -- --exact --nocapture` passed 1/1. `cargo check -p hickory-server --no-default-features` passed. On `germ` (`fastcreate-472995`), with a separate PostgreSQL 15 container and SSH local forwarding, `TEST_DATABASE_URL=postgres://postgres@127.0.0.1:55432/postgres cargo test -p control_api --bin control_api api_tests::zone_transfer_policy_endpoint_and_validation -- --exact --nocapture` passed 1/1 (policy/ACL emission, invalid IP, rollback preservation); `... cargo test ... api_tests::migration_files_and_runtime_ddl_have_no_schema_drift -- --exact --nocapture` passed 1/1. `cargo fmt --all` and `git diff --check` passed. The temporary database and tunnel were removed; only the four existing germ containers remain healthy. The isolated runtime again logged the workstation's file-watcher `Too many open files` warning, but network serving and refusal assertions passed. Commit `572639f47e9854121f4b1d994f2a3c9b51fa60e6` was pushed to `origin/main`.

### Secondary SOA expire enforcement and DNSSEC child signaling — 2026-11-26

Implemented SOA expire enforcement for configured secondaries. The scheduler now reads refresh/retry/expire from the loaded SOA, tracks last successful AXFR (using zone-file mtime on process start), and marks a zone expired after continuous transfer failure past expire. `SwapHandler` responds SERVFAIL without stale records for the expired zone and its subdomains; a successful recovery clears the expired gate and reloads the catalog even if the primary serial is unchanged. Local integration `cargo test -p hickory-dns --test integration expired_secondary_fails_closed_after_primary_is_unavailable -- --nocapture` passed 1/1 after stopping the primary; the unit test `cargo test -p hickory-server --lib expired_zone_rejects_its_apex_and_children_but_not_siblings` passed 1/1. `cargo check -p hickory-dns --tests`, formatting, and diff checks passed. Germ test `fastcreate-472995`: copied the newly built binary to a temporary path; used isolated primary/secondary processes and ports 53153/53154, verified `dig` initially returned `192.0.2.9`, stopped the isolated primary, then independently observed SERVFAIL after the 3-second SOA expire with no answer. Temporary binary, files, processes, and ports were cleaned; existing containers remained healthy. Commit `3d2be9007` pushed to `origin/main`.

Implemented signed DNSSEC child signaling. Each signing pass rebuilds apex CDNSKEY and CDS (SHA-256 and SHA-384) from current SEP DNSKEYs before NSEC/NSEC3 and signature generation, allowing rollover key sets to publish current CDS without retaining retired records. `cargo test -p hickory-dns --test integration --features dnssec-ring test_child_signaling -- --nocapture` passed 2/2 for file and SQLite stores; `cargo check -p hickory-server --features dnssec-ring` passed. NSEC3 API parameter exposure and parent-side DS polling remain outstanding.
