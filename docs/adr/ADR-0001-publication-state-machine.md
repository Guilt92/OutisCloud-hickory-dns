# ADR-0001: Publication state machine

- **Status:** Accepted
- **Date:** 2026-11-19
- **Roadmap task:** ARCH-002

## Context

Zone and record mutations currently update PostgreSQL, then regenerate every zone file synchronously. Publication failure is reported, but there is no durable per-zone job state, no bounded retry, and no replica acknowledgement. Operators cannot prove that database state and served state have converged.

## Decision

Adopt an explicit durable publication state machine:

`pending -> queued -> generating -> published -> acknowledged`

Failure states: `retrying`, `failed`, `quarantined`.

Requirements:

1. A transactional outbox row is written in the same database transaction as the zone/record mutation.
2. A per-zone worker consumes jobs in serial order; different zones may proceed concurrently.
3. Retries use bounded exponential backoff with jitter; exhausted jobs move to `failed` without discarding last-known-good files.
4. A job is `published` only after validated zone files and configuration are atomically swapped.
5. A job is `acknowledged` only after every configured replica/agent reports the expected publication revision.
6. Empty jobs are harmless; repeated jobs are idempotent by revision.

Full implementation is scheduled with PERF-001/002. Phase 0 establishes the contract and failure-mode tests.

## Consequences

- Operators gain a truthful per-zone publication state and age.
- Full-cluster regeneration is no longer on the synchronous write path.
- The schema needs an outbox/job table and revision column; these are added in later phases with backward-compatible migrations.
- Failure handling must be explicit; a `failed` job must never be silently retried forever.

## Failure-mode matrix

| Failure | Expected behavior |
|---|---|
| Database commit succeeds, outbox write fails | Whole transaction rolls back; no zone change is visible |
| Generator rejects invalid zone | Job moves to `failed`; last-known-good files remain served |
| File write interrupted | Temporary file discarded; active files unchanged |
| Replica unavailable | Job remains `published`, not `acknowledged`; alert is raised |
| Duplicate worker delivery | Revision check makes apply idempotent |
| Retry storm | Backoff/jitter and per-zone serial execution bound work |
