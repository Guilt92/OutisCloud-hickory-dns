# DNSSEC key backup and recovery

This procedure keeps the private-key tree and the matching public DNSSEC
metadata together. It never overwrites a live key directory or database. Run
recovery into an isolated environment first; an operator must verify the pair
before configuring it for service.

## Create a paired recovery set

Use the same maintenance window and recovery point for the PostgreSQL backup
and key archive. DNSSEC key create, rollover, completion, and disable actions
must not run while the pair is being captured. The recovery verifier compares
the encrypted metadata snapshot with the restored database and refuses to
accept a mismatched pair.

```sh
umask 077
install -d -m 0700 "$RECOVERY_DIR"
pg_dump "$DATABASE_URL" --format=custom --file="$RECOVERY_DIR/control-db.dump"
DATABASE_URL="$DATABASE_URL" cargo run -p control_api --bin dnssec-recovery -- \
  backup "$DNSSEC_KEY_DIR" "$RECOVERY_DIR/dnssec-keys.enc" "$DNS_NAMED_TOML"
sha256sum "$RECOVERY_DIR/control-db.dump" "$RECOVERY_DIR/dnssec-keys.enc" \
  > "$RECOVERY_DIR/SHA256SUMS"
chmod 0600 "$RECOVERY_DIR"/*
```

The key archive is authenticated and encrypted with AES-256-GCM. The wrapping
key is loaded from `DNSSEC_KEY_ENCRYPTION_KEY` or the private mounted
`DNSSEC_KEY_ENCRYPTION_KEY_FILE`; keep it in a secret manager separate from
this recovery set. The manifest contains public key material and operational
metadata, and is encrypted inside the key archive. Store the database dump,
archive (which also contains the authenticated `named.toml`), checksums, and recovery
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

4. Compare the restored database to the encrypted metadata snapshot and check
   active key files:

   ```sh
   DATABASE_URL="$RESTORED_DATABASE_URL" cargo run -p control_api --bin dnssec-recovery -- \
     verify "$RESTORE_KEY_DIR"
   ```

   This checks zone IDs/domains and proof settings, key tags, algorithms,
   public keys, statuses, key paths, and the restored `named.toml` digest against
   the manifest, then confirms each active/prepublished key exists and decrypts. It fails closed if the
   database dump and key archive came from different metadata states.
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
