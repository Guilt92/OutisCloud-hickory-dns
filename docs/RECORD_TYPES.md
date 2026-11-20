# Record type policy

The control API accepts record types through `validate_record_type_str` in `crates/control_api/src/dns_validator.rs`. The DNS engine parses a broader set of types than the UI exposes.

## Product policy

- **Editable/common types:** A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA.
- **Read-only/importable:** types parsed by Hickory that are validated on import/export but not offered in the customer editor.
- **Explicitly rejected:** unknown/metatypes (AXFR, IXFR, ANY) as user records, and any type without a validated value parser.
- **Future types:** DNAME, LOC, AFSDB, APL, DHCID, HIP, IPSECKEY, KX require parser, validator, API, UI, and round-trip tests before being marked supported.

All mutations are validated before database commit and again by Hickory zone-file generation before publication. Unsupported types must fail with a clear API error, never a silent no-op.

## Apex alias decision (REC-004)

ANAME/ALIAS-style apex CNAME flattening is **not supported** and is not on the near-term roadmap. Apex `CNAME` records remain rejected by validation (`zone_file_generator.rs` and `api_tests.rs::apex_cname_is_rejected`). Customers must use A/AAAA records at the apex. This is a deliberate product decision, not an implementation gap.
