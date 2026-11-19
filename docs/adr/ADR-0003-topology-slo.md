# ADR-0003: Topology, SLO, RPO and RTO

- **Status:** Proposed — blocked by ADR-0001/ADR-0002 implementation evidence
- **Date:** 2026-11-19
- **Roadmap task:** ARCH-008

## Context

Current deployment is a single-host Compose stack with one PostgreSQL instance, one control API, one DNS process, and agent-based bundle replicas. No approved availability targets, RPO, or RTO exist. Helm declares multiple replicas without shared publication state.

## Proposed decision

Two supported profiles:

1. **Single-host profile (development/small deployment).** No HA claim. Best-effort backups. RPO up to 24 h, RTO best effort.
2. **Replicated production profile (target).** Multiple control API instances, PostgreSQL HA/PITR, durable publication outbox, shared/versioned zone state, at least two authoritative DNS servers with health-checked failover.

Proposed targets for the replicated profile:

- Authoritative DNS query availability: 99.99% monthly, measured externally.
- Authoritative DNS p95 latency: < 50 ms within region; p99 < 100 ms.
- Control API p95: < 200 ms for read paths; < 1 s for write paths excluding publication acknowledgement.
- RPO: ≤ 5 minutes for control-plane data; DNSSEC keys replicated separately with RPO ≤ 1 hour.
- RTO: ≤ 30 minutes for control plane; ≤ 5 minutes for DNS serving via replicas.

These are proposed targets, not achieved metrics. No production-readiness claim is valid until monitoring, restore, and failover drills produce evidence.

## Dependencies

- ADR-0001 publication state machine.
- ADR-0002 secondary/transfer scope.
- PostgreSQL HA/PITR, backup/restore, monitoring/alerting, and capacity evidence from later phases.

## Consequences

- Current single-host documentation must not claim HA.
- Deployment profiles must be explicit in docs and UI status surfaces.
- SLO dashboards and alert rules are required before approval can be finalized.
