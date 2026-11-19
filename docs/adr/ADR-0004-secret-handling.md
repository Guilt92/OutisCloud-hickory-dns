# ADR-0004: Secret handling and history policy

- **Status:** Accepted as policy; rotation action required
- **Date:** 2026-11-19
- **Roadmap task:** ARCH-007

## Context

Several environment and Kubernetes secret files are tracked in Git and contain live-looking credentials. Some were modified in the working tree; those changes are user-owned and must not be overwritten by tooling. Secret values in Git history must be treated as compromised.

## Decision

1. Treat all tracked live-looking credentials as compromised and rotate them through the normal secret-management process.
2. Do not rewrite Git history silently. Any history purge requires explicit owner approval, a coordinated window, and communication to all clone holders.
3. Add future-facing ignore rules for `.env`, `env/*.env`, and Kubernetes secret manifests while keeping `.env.example` tracked.
4. Add automated secret scanning to CI and a local `just secret-scan` recipe.
5. Keep agent signing keys and DNSSEC private keys separate from the JWT signing secret.

## Current blockers

- Rotation requires new secret values and coordinated deployment changes. This cannot be fabricated in code.
- Untracking already-tracked secret files changes repository state and must not be done without owner approval.

## Consequences

- ARCH-007 remains `BLOCKED` until rotation and untracking are approved and executed.
- Scanning and ignore rules reduce recurrence but do not remove existing history exposure.
