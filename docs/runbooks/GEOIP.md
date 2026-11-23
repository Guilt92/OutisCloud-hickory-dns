# GeoIP data lifecycle

GeoDNS uses a MaxMind-format database. The repository ships only a small
`GeoLite2-Country.mmdb` for tests; City/Region answers need a licensed
`GeoLite2-City.mmdb` obtained with a MaxMind account. The EULA forbids redistributing
the City database, so it is never committed.

## Install and refresh

```bash
MAXMIND_ACCOUNT_ID=... MAXMIND_LICENSE_KEY=... \
  scripts/update_geoip.sh /etc/hickory/GeoLite2-City.mmdb GeoLite2-City
```

The script downloads over HTTPS, verifies MaxMind's SHA-256, checks the MMDB magic and
size, then atomically renames the file into place. The DNS server watches
`GEOIP_DB_PATH` and reloads it without a restart. On any failure the old database is
kept. Schedule it weekly from cron; never echo the licence key.

## Health

- `/metrics` exposes database age/staleness (`GEOIP_MAX_AGE_DAYS`, default 180) and
  `ZZ-nodata` / `ZZ-unknown` country sentinels.
- Missing database: GeoDNS rules still resolve deterministically but country matches
  fall back to the default answer; country analytics report `ZZ-nodata`.
- Stale database: alert on the staleness metric; refresh before it crosses the
  threshold.

## Failure handling

- Download/checksum failure: keep the existing file, retry later, and alert if the
  database will cross the staleness threshold.
- Corrupt file installed by another process: restore the previous file from backup,
  restart `dns-server`, and verify a known geo rule.
- Licence expired: refresh credentials, download, and verify. GeoDNS continues with
  the old data until replaced.
