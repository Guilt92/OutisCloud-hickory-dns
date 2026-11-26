# DNSSEC key backup and recovery

This procedure keeps the private-key tree and the matching public DNSSEC
metadata together. It never overwrites a live key directory or database. Run
recovery into an isolated environment first; an operator must verify the pair
before configuring it for service.

## Create a paired recovery set

Use the same maintenance window and recovery point for the PostgreSQL backup
and key archive. DNSSEC key create, rollover, completion, and disable actions
must not run while the pair is being captured. `pg_dump` provides a consistent
database snapshot; the operator must keep its resulting backup with the key
archive and manifest.

```sh
umask 077
install -d -m 0700 "$RECOVERY_DIR"
psql "$DATABASE_URL" -XAt -v ON_ERROR_STOP=1 > "$RECOVERY_DIR/recovery-manifest.json" <<'SQL'
  SELECT jsonb_build_object(
    'format_version', 1,
    'captured_at', transaction_timestamp(),
    'zones', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'id', id, 'domain', domain,
        'dnssec_enabled', COALESCE(dnssec_enabled, false),
        'proof_type', COALESCE(dnssec_proof_type, 'nsec'),
        'nsec3_salt', COALESCE(dnssec_nsec3_salt, ''),
        'nsec3_iterations', COALESCE(dnssec_nsec3_iterations, 0),
        'nsec3_opt_out', COALESCE(dnssec_nsec3_opt_out, false)
      ) ORDER BY domain)
      FROM zones WHERE COALESCE(dnssec_enabled, false)
    ), '[]'::jsonb),
    'keys', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'zone_id', k.zone_id, 'key_tag', k.key_tag,
        'algorithm', k.algorithm, 'public_key', k.public_key,
        'key_file', k.key_file, 'status', k.status,
        'created_at', k.created_at, 'retired_at', k.retired_at
      ) ORDER BY k.zone_id, k.key_tag)
      FROM dnssec_keys k JOIN zones z ON z.id = k.zone_id
      WHERE COALESCE(z.dnssec_enabled, false) OR k.status = 'retired'
    ), '[]'::jsonb)
  )::text;
SQL
chmod 0600 "$RECOVERY_DIR/recovery-manifest.json"
pg_dump "$DATABASE_URL" --format=custom --file="$RECOVERY_DIR/control-db.dump"
cargo run -p hickory-key-store --bin dnssec-key-backup -- \
  backup "$DNSSEC_KEY_DIR" "$RECOVERY_DIR/dnssec-keys.enc" \
  "$RECOVERY_DIR/recovery-manifest.json"
sha256sum "$RECOVERY_DIR/control-db.dump" "$RECOVERY_DIR/dnssec-keys.enc" \
  > "$RECOVERY_DIR/SHA256SUMS"
chmod 0600 "$RECOVERY_DIR"/*
```

The key archive is authenticated and encrypted with AES-256-GCM. The wrapping
key is loaded from `DNSSEC_KEY_ENCRYPTION_KEY` or the private mounted
`DNSSEC_KEY_ENCRYPTION_KEY_FILE`; keep it in a secret manager separate from
this recovery set. The manifest contains public key material and operational
metadata, and is encrypted inside the key archive as well as retained as a
0600 comparison file. Store the database dump, archive, checksums, and recovery
key in separate protected locations according to the organization's escrow
policy. Verify checksums after copying the set off host.

## Isolated restore drill

1. Verify the recovery set checksums with `cd "$RECOVERY_DIR" && sha256sum --check SHA256SUMS`.
2. Restore `control-db.dump` to a fresh isolated PostgreSQL database, never to
   an existing database.
3. Restore the encrypted key archive to a new, empty directory:

   ```sh
   cargo run -p hickory-key-store --bin dnssec-key-backup -- \
     restore "$RECOVERY_DIR/dnssec-keys.enc" "$RESTORE_KEY_DIR"
   ```

4. Compare `$RESTORE_KEY_DIR/recovery-manifest.json` byte-for-byte with the
   paired manifest. Query the restored `zones` and `dnssec_keys` rows and
   verify zone IDs, algorithms, tags, public keys, statuses, and key paths
   against that manifest. Verify every non-retired key path exists, decrypts
   with the wrapping key, and derives the stored public DNSKEY/key tag.
5. Generate configuration from the restored database and key directory. Run
   DNSKEY, CDS/CDNSKEY, and signed-answer checks against an isolated listener;
   use an independent validator with a test trust anchor. Do not change parent
   DS records during a recovery drill.
6. Record measured restore time and the age of the database snapshot. A restore
   is not complete until the restored server answers and validates correctly.

The restore command refuses an existing destination and applies restrictive
directory/file permissions. It does not modify a database or activate keys;
this lets an operator compare both halves and obtain a second-person review
before service activation.

## Suspected key compromise

Treat the signing key as compromised if private material or its wrapping key
may have escaped. Restrict access to the affected key store and preserve
security logs. Use the authenticated rollover flow to publish a replacement
key and both old/new DS expectations, validate the new signed zone, and
coordinate removal of the compromised DS with the parent operator after the
replacement DS is visible. Do not disable signing or retire the old key while
the parent still publishes its DS: validating resolvers would see a broken
chain. If the parent cannot promptly replace the compromised DS, escalate to
the parent operator and incident lead; this service cannot change registrar
delegation automatically. Rebuild affected secrets from the verified recovery
set only after the compromised wrapping key has been replaced through the
deployment's secret-management process.
