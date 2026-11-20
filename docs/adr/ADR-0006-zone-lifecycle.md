# ADR-0006: Zone lifecycle states

- **Status:** Accepted
- **Date:** 2026-11-19
- **Roadmap task:** ZONE-006

## Context

Zones previously had only `active`, `pending`, and `deleting` states. Operators need a reversible way to stop serving a zone without deleting its data, and customers must not be able to bypass domain verification.

## Decision

Introduce `suspended` as a first-class zone state:

- `active`: zone is generated and served.
- `suspended`: zone data remains in the database and revisions, but the zone file is removed and the zone is not served.
- `pending`: unchanged; requires ownership verification before activation.
- `deleting`: unchanged.

Only owners/admins may transition between `active` and `suspended`. The transition is atomic with republication and rolls back on publish failure. A `pending` zone cannot be activated through the lifecycle endpoint.

## Consequences

- Suspension is reversible and safe for operational use.
- Deletion holds, transfer locks and archival are separate later capabilities; this ADR does not claim them.
- Existing generator already publishes only `active` zones, so no serving-path bypass is introduced.
