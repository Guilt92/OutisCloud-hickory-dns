# Dynamic update (RFC 2136) policy

Dynamic updates are supported only by the SQLite-backed primary zone handler. File, in-memory, secondary, forwarder and GeoDNS handlers return `NotImp`.

## Security policy

- `allow_update = false` (default) returns `Refused`.
- Unsigned updates are refused; TSIG is required and verified for key name, MAC and fudge window.
- SIG(0) is unavailable: support was deliberately removed upstream. Do not claim SIG(0).
- Prerequisites (TTL=0, NXDOMAIN/NXRRSET/YXDOMAIN/YXRRSET, NOTZONE) and prescan checks (AXFR/IXFR/metatypes) are enforced before mutation.
- Journal writes for a set of records are atomic.

## Deployment guidance

Dynamic update is opt-in per SQLite zone. The equivalent control-plane API with tenant authorization is the preferred customer path. Never expose unsigned update access on a public authoritative server.
