# ADR-0007: Catalog zones are out of scope

- **Status:** Accepted
- **Date:** 2026-11-19
- **Roadmap task:** XFR-006

## Context

Catalog zones (RFC 9432) automate secondary provisioning by publishing a catalog of member zones. OutisCloud does not yet have a production secondary-zone model (SECONDARY-001/002), and ADR-0002 commits to building standard primary/secondary behaviour first.

## Decision

Catalog zones are explicitly out of scope for the current roadmap. We will not implement catalog-zone generation or consumption. This task is closed as a documented non-goal, not as implemented functionality.

## Consequences

- Operators must configure secondary zones explicitly until a later decision revisits this ADR.
- No catalog-zone capability may be claimed in documentation or UI.
- Revisiting this decision requires SECONDARY-001/002 completion plus a new ADR.
