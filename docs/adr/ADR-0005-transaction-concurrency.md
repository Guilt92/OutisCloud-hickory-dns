# ADR-0005: Transaction concurrency model

- **Status:** Accepted for design; benchmark evidence pending
- **Date:** 2026-11-19
- **Roadmap task:** ARCH-003

## Context

`migrate_db` and the control API currently serialize transactions through a single reserved PostgreSQL connection. This caps write throughput and couples unrelated tenants. Publication regeneration further amplifies contention.

## Decision

Adopt a bounded transaction pool with per-tenant admission control:

1. Replace the single reserved connection with a small bounded pool.
2. Add a per-tenant queue for write transactions so one tenant cannot monopolize all writers.
3. Keep a global concurrency ceiling based on database capacity measurements.
4. Retry only on serialization failures with bounded backoff.
5. Make rollback behavior observable through metrics and tests.

A representative benchmark must compare the old reserved-connection model, an unbounded pool, and the selected bounded/per-tenant model. Until that evidence exists, this ADR is `PARTIAL`, not `DONE`.

## Consequences

- Requires changes to `Pool`/`AppState` and write handlers in later phases.
- Per-tenant fairness must be tested with concurrent workloads.
- The global ceiling must be configurable and documented.
