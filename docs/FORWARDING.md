# Forwarding and recursion boundary

OutisCloud is an **authoritative DNS hosting platform first**. Forwarding and recursive resolution are optional resolver-style capabilities, not part of the authoritative product claim.

## Supported modes

- **Authoritative only (default/recommended).** The server answers only for zones in its catalog. AXFR/IXFR/NOTIFY follow the transfer policy and are never used for recursion.
- **Forwarding zone.** A configured zone forwards queries to explicit upstream resolvers. The resolver cache defaults to 512 responses (previously 32) and is configurable per resolver config.
- **Experimental recursor.** Available behind the `recursor` feature and not covered by authoritative SLAs.

## Explicit non-goals

- No open recursive resolver by default.
- No trust-anchor management UI.
- No recursive cache shared with authoritative zone state.
- No use of forwarding to mask missing authoritative zones.

## Required tests

- Cache hit/miss and TTL expiry tests live in the resolver and recursor suites.
- AXFR over UDP is refused by the catalog regardless of forwarding configuration.
- Deployment docs must state which mode is enabled before any operational claim.
