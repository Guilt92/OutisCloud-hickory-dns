# ADR-0005: Transaction concurrency model

- **Status:** Partially implemented; bounded transaction pool, tenant admission gate, bounded retry helper, rollback metrics, and remote DB tests added; broader handler adoption and load measurements remain
- **Date:** 2026-11-19
- **Roadmap task:** ARCH-003

## Context

`migrate_db` and the control API currently serialize transactions through a single reserved PostgreSQL connection. This caps write throughput and couples unrelated tenants. Publication regeneration further amplifies contention.

## Decision

Adopt a bounded transaction pool with per-tenant admission control:

1. Replace the single reserved connection with a separately bounded pool (`DB_TRANSACTION_POOL_SIZE`, defaults to `min(DB_POOL_SIZE, 4)`).
2. Add a per-tenant queue for write transactions so one tenant cannot monopolize all writers.
3. Keep a global concurrency ceiling based on database capacity measurements.
4. Retry only on serialization failures with bounded backoff.
5. Make rollback behavior observable through metrics and tests.

A representative test-server benchmark compares one transaction slot with the configured four-slot bound using four concurrent `pg_sleep(200ms)` transactions; it also verifies four distinct PostgreSQL backend sessions and rollback isolation. An unbounded comparison is intentionally omitted because it has no safe operational ceiling and is not a candidate design. `Pool::begin_for` adds a FIFO per-tenant gate and is used for zone creation, record creation/import, zone update/rollback, deletion, and clone transactions. `Pool::run_transaction` provides a bounded serializable transaction wrapper that retries only SQLSTATE 40001/40P01, rolls back each failed attempt, and uses capped exponential delay. Database-backed tests prove retry success, bounded exhaustion, no retry for non-retryable errors, and that queued work for one tenant does not block another tenant. Password replacement and refresh-session revocation now use this helper because both operations are entirely database-backed and safely repeatable. Other handlers remain opt-in until their side effects are reviewed. Additional throughput/latency sweeps remain required before this ADR is complete.

## Consequences

- All primary zone lifecycle and record write handlers use per-tenant admission; unrelated auth/admin transactions remain globally pooled.
- Per-tenant fairness has a database-backed concurrency test; workload-scale fairness still needs measurement.
- The global ceiling must be configurable and documented.
- Retryable transaction closures may execute more than once; callers must keep side effects external to the database transaction.
