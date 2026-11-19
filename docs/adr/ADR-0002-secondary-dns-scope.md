# ADR-0002: Secondary DNS and transfer scope

- **Status:** Proposed — requires product owner approval
- **Date:** 2026-11-19
- **Roadmap task:** ARCH-006

## Context

The product exposes secondary-zone UI controls, but the control API rejects non-primary zones. AXFR is partial and single-message; IXFR and NOTIFY are absent. The roadmap includes Phase 4 for secondary DNS, transfers, and replication, but no approved product decision distinguishes "agent-based replica distribution" from "standards-based delegated secondary service".

## Options

1. **Commit to full secondary/transfer support.** Implement AXFR streaming over TCP, IXFR, NOTIFY, TSIG/SIG(0), transfer ACLs, real secondary zone state, and operator-facing freshness. High effort; aligns with the roadmap and operator expectations.
2. **Remove secondary UI and document agent-based replicas as the only supported model.** Lower effort; contradicts the current roadmap and reduces product fit for DNS operators.
3. **Keep secondary as a premium/enterprise feature flag.** Defer implementation but keep a truthful "not available" gate. Requires a launch decision.

## Recommendation

Choose option 1. The roadmap, matrix, and task IDs already assume standards-based secondary support, and removing it would silently narrow product scope. Implementation must be gated by this ADR's approval and delivered in Phase 4.

## Consequences

- Until approved, secondary controls must be hidden or disabled rather than accepting values that return 400.
- No secondary/transfer capability may be claimed in production documentation until Phase 4 exit evidence exists.
- The decision affects DNS engine changes (CORE-001..003), replication (REPL-002/003), and UI truthfulness (ADM-002).
