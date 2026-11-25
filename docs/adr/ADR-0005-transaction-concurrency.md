# ADR-0005: Transaction concurrency model

- **Status:** Partially implemented; bounded transaction pool and remote DB benchmark added; per-tenant admission control remains
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

A representative test-server benchmark compares one transaction slot with the configured four-slot bound using four concurrent `pg_sleep(200ms)` transactions; it also verifies four distinct PostgreSQL backend sessions and rollback isolation. An unbounded comparison is intentionally omitted because it has no safe operational ceiling and is not a candidate design. Per-tenant admission control, retry-on-serialization, rollback metrics, and additional throughput/latency sweeps remain required before this ADR is complete.

## Consequences

- Requires per-tenant admission control to be wired into write handlers in later phases.
- Per-tenant fairness must be tested with concurrent workloads.
- The global ceiling must be configurable and documented.
