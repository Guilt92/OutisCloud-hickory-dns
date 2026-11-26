//! DNSSEC key management and DS records.
//!
//! Each signed zone uses one combined signing key (CSK, flags 257: zone key +
//! secure entry point) per generation. The DNS server loads the private key
//! files named in `named.toml` and signs the zone when it loads; this module
//! generates the keys, remembers them in the database, derives the DS records
//! the operator must publish at the registrar, and implements a safe
//! double-signing key rollover:
//!
//!   enable    -> one active key; publish its DS at the parent
//!   rollover  -> a second key joins ("new"); both sign; publish the new DS,
//!                keep the old DS until its TTL has expired
//!   complete  -> the old key is retired and removed from the zone
//!   disable   -> keys are retired; requires `confirm_ds_removed` because a DS
//!                without a matching DNSKEY makes the zone BOGUS for validators
//!
//! Private keys are PKCS#8 PEM files (mode `DNSSEC_KEY_MODE`, default 0640)
//! under `<zone dir>/dnssec-keys/`, never stored in the database or returned
//! by the API. Back this directory up together with the database.
//!
//! GeoDNS and DNSSEC are mutually exclusive per zone: geo answers are
//! synthesised per client and cannot carry a valid pre-computed signature.

use super::*;
use hickory_proto::dnssec::{
    Algorithm, DigestType, PublicKey, PublicKeyBuf, SigningKey,
    crypto::{EcdsaSigningKey, Ed25519SigningKey},
    rdata::{DNSKEY, DS},
};
use hickory_proto::rr::Name;
use rustls_pki_types::PrivatePkcs8KeyDer;
use std::str::FromStr;

pub const DEFAULT_ALGORITHM: &str = "ECDSAP256SHA256";

pub fn parse_algorithm(s: &str) -> Option<Algorithm> {
    match s.trim().to_ascii_uppercase().as_str() {
        "ECDSAP256SHA256" | "13" => Some(Algorithm::ECDSAP256SHA256),
        "ECDSAP384SHA384" | "14" => Some(Algorithm::ECDSAP384SHA384),
        "ED25519" | "15" => Some(Algorithm::ED25519),
        _ => None,
    }
}

pub fn algorithm_name(a: Algorithm) -> &'static str {
    match a {
        Algorithm::ECDSAP256SHA256 => "ECDSAP256SHA256",
        Algorithm::ECDSAP384SHA384 => "ECDSAP384SHA384",
        Algorithm::ED25519 => "ED25519",
        _ => "UNSUPPORTED",
    }
}

/// A freshly generated key: the private PEM (to be written once, then never
/// shown again) and the public data stored in the database.
pub struct NewKey {
    pub pem: String,
    pub key_tag: u16,
    pub algorithm: Algorithm,
    pub public_key: Vec<u8>,
}

fn pem_encode(der: &[u8]) -> String {
    let b64 = data_encoding::BASE64.encode(der);
    let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    out
}

pub fn dnskey_for(algorithm: Algorithm, public_key: &[u8]) -> DNSKEY {
    // flags 257 = zone key + secure entry point, exactly what the server publishes
    DNSKEY::new(
        true,
        true,
        false,
        PublicKeyBuf::new(public_key.to_vec(), algorithm),
    )
}

pub fn generate_key(algorithm: Algorithm) -> Result<NewKey, String> {
    let (der, public): (PrivatePkcs8KeyDer<'static>, Vec<u8>) =
        match algorithm {
            Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => {
                let der = EcdsaSigningKey::generate_pkcs8(algorithm)
                    .map_err(|e| format!("key generation failed: {e}"))?;
                let key = EcdsaSigningKey::from_pkcs8(&der, algorithm)
                    .map_err(|e| format!("generated key unusable: {e}"))?;
                let public = key
                    .to_public_key()
                    .map_err(|e| e.to_string())?
                    .public_bytes()
                    .to_vec();
                (der, public)
            }
            Algorithm::ED25519 => {
                let der = Ed25519SigningKey::generate_pkcs8()
                    .map_err(|e| format!("key generation failed: {e}"))?;
                let key = Ed25519SigningKey::from_pkcs8(&der)
                    .map_err(|e| format!("generated key unusable: {e}"))?;
                let public = key
                    .to_public_key()
                    .map_err(|e| e.to_string())?
                    .public_bytes()
                    .to_vec();
                (der, public)
            }
            _ => return Err(
                "unsupported DNSSEC algorithm (use ECDSAP256SHA256, ECDSAP384SHA384 or ED25519)"
                    .into(),
            ),
        };
    let key_tag = dnskey_for(algorithm, &public)
        .calculate_key_tag()
        .map_err(|e| e.to_string())?;
    Ok(NewKey {
        pem: pem_encode(der.secret_pkcs8_der()),
        key_tag,
        algorithm,
        public_key: public,
    })
}

/// `zone. IN DNSKEY 257 3 13 <base64>`
pub fn dnskey_text(zone: &str, algorithm: Algorithm, public_key: &[u8]) -> String {
    format!(
        "{}. IN DNSKEY {}",
        zone.trim_end_matches('.'),
        dnskey_for(algorithm, public_key)
    )
}

/// DS records (SHA-256 and SHA-384 digests) for the key, in presentation form.
pub fn ds_records(
    zone: &str,
    algorithm: Algorithm,
    public_key: &[u8],
) -> Result<Vec<serde_json::Value>, String> {
    let name =
        Name::from_str(&format!("{}.", zone.trim_end_matches('.'))).map_err(|e| e.to_string())?;
    let dnskey = dnskey_for(algorithm, public_key);
    let tag = dnskey.calculate_key_tag().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for (dt, label) in [
        (DigestType::SHA256, "SHA-256"),
        (DigestType::SHA384, "SHA-384"),
    ] {
        let digest = dnskey.to_digest(&name, dt).map_err(|e| e.to_string())?;
        let ds = DS::new(tag, algorithm, dt, digest.as_ref().to_vec());
        out.push(serde_json::json!({
            "key_tag": tag, "algorithm": u8::from(algorithm), "digest_type": u8::from(dt), "digest_name": label,
            "digest": data_encoding::HEXUPPER.encode(digest.as_ref()),
            "text": format!("{}. IN DS {}", zone.trim_end_matches('.'), ds),
        }));
    }
    Ok(out)
}

pub fn key_dir(zone_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(zone_dir).join("dnssec-keys")
}

/// Write the private key atomically with restrictive permissions.
pub fn write_key_file(path: &std::path::Path, pem: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let stored = hickory_key_store::encrypt_configured(pem.as_bytes())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let tmp = path.with_file_name(tmp_name);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    if let Err(error) = f.write_all(&stored).and_then(|_| f.sync_all()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    drop(f);
    if let Err(error) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    if let Some(dir) = path.parent() {
        if let Ok(dir) = std::fs::File::open(dir) {
            dir.sync_all()?;
        }
    }
    Ok(())
}

pub fn key_file_name(zone: &str, key_tag: u16) -> String {
    format!(
        "{}.{}.pem",
        zone.trim_end_matches('.').to_ascii_lowercase(),
        key_tag
    )
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

pub const SCHEMA: &str = "
    ALTER TABLE zones ADD COLUMN IF NOT EXISTS dnssec_enabled BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE zones ADD COLUMN IF NOT EXISTS dnssec_proof_type TEXT NOT NULL DEFAULT 'nsec';
    ALTER TABLE zones ADD COLUMN IF NOT EXISTS dnssec_nsec3_salt TEXT NOT NULL DEFAULT '';
    ALTER TABLE zones ADD COLUMN IF NOT EXISTS dnssec_nsec3_iterations INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE zones ADD COLUMN IF NOT EXISTS dnssec_nsec3_opt_out BOOLEAN NOT NULL DEFAULT false;
    DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='zones_dnssec_proof_type_check') THEN
            ALTER TABLE zones ADD CONSTRAINT zones_dnssec_proof_type_check CHECK (dnssec_proof_type IN ('nsec', 'nsec3'));
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='zones_dnssec_nsec3_iterations_check') THEN
            ALTER TABLE zones ADD CONSTRAINT zones_dnssec_nsec3_iterations_check CHECK (dnssec_nsec3_iterations BETWEEN 0 AND 150);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='zones_dnssec_nsec3_salt_hex_check') THEN
            ALTER TABLE zones ADD CONSTRAINT zones_dnssec_nsec3_salt_hex_check CHECK (dnssec_nsec3_salt ~ '^([0-9a-fA-F]{2}){0,32}$');
        END IF;
    END $$;
    CREATE TABLE IF NOT EXISTS dnssec_keys (
        id UUID PRIMARY KEY,
        zone_id UUID NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
        key_tag INTEGER NOT NULL,
        algorithm TEXT NOT NULL,
        public_key TEXT NOT NULL,
        key_file TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        retired_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone ON dnssec_keys(zone_id);
";

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct EnableReq {
    pub algorithm: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct DisableReq {
    #[serde(default)]
    pub confirm_ds_removed: bool,
}

#[derive(Deserialize)]
pub struct CompleteReq {
    pub retire_key_tag: i32,
}

#[derive(Deserialize)]
pub struct NxProofReq {
    pub proof_type: String,
    #[serde(default)]
    pub nsec3_salt: String,
    #[serde(default)]
    pub nsec3_iterations: i32,
    #[serde(default)]
    pub nsec3_opt_out: bool,
}

fn db_err(what: &str, e: &tokio_postgres::Error) -> HttpResponse {
    warn!("dnssec {}: {}", what, full_error_string(e));
    HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
}

async fn describe(
    db: &Pool,
    zone_id: &str,
    domain: &str,
) -> Result<serde_json::Value, HttpResponse> {
    let zone: tokio_postgres::Row = match db
        .query_one(
            "SELECT dnssec_enabled, COALESCE(dnssec_proof_type, 'nsec'), COALESCE(dnssec_nsec3_salt, ''), COALESCE(dnssec_nsec3_iterations, 0), COALESCE(dnssec_nsec3_opt_out, false) FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zone_id],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return Err(db_err("describe", &e)),
    };
    let enabled: bool = zone.get(0);
    let proof_type: String = zone.get(1);
    let nsec3_salt: String = zone.get(2);
    let nsec3_iterations: i32 = zone.get(3);
    let nsec3_opt_out: bool = zone.get(4);
    let rows = db
        .query(
            "SELECT key_tag, algorithm, public_key, status, created_at::text FROM dnssec_keys \
             WHERE CAST(zone_id AS varchar) = $1 AND status <> 'retired' ORDER BY created_at, key_tag",
            &[&zone_id],
        )
        .await
        .map_err(|e| db_err("describe keys", &e))?;
    let mut keys = Vec::new();
    for r in rows {
        let tag: i32 = r.get(0);
        let alg_s: String = r.get(1);
        let pk_b64: String = r.get(2);
        let alg = parse_algorithm(&alg_s).unwrap_or(Algorithm::ECDSAP256SHA256);
        let pk = data_encoding::BASE64
            .decode(pk_b64.as_bytes())
            .unwrap_or_default();
        keys.push(serde_json::json!({
            "key_tag": tag, "algorithm": alg_s, "algorithm_number": u8::from(alg), "flags": 257,
            "status": r.get::<_, String>(3), "created_at": r.get::<_, String>(4),
            "dnskey": dnskey_text(domain, alg, &pk),
            "ds": ds_records(domain, alg, &pk).unwrap_or_default(),
        }));
    }
    let next_steps = if !enabled {
        "DNSSEC is off. Enable it, then publish the returned DS record at your registrar (or parent zone)."
    } else if keys.len() > 1 {
        "Rollover in progress: publish the DS of the new key at the registrar, wait for the old DS TTL to expire, then complete the rollover to retire the old key."
    } else {
        "Publish the DS record at your registrar (or parent zone). Until the DS is published the zone is signed but not validated; do not remove it while DNSSEC is enabled."
    };
    Ok(
        serde_json::json!({ "enabled": enabled, "domain": domain, "keys": keys, "next_steps": next_steps,
            "proof": { "type": proof_type, "nsec3_salt": nsec3_salt,
                "nsec3_iterations": nsec3_iterations, "nsec3_opt_out": nsec3_opt_out } }),
    )
}

pub async fn get_dnssec(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &tok, Level::Read).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match describe(&data.db, &zone_id, &access.domain).await {
        Ok(v) => HttpResponse::Ok().json(v),
        Err(r) => r,
    }
}

pub async fn set_nx_proof(
    path: web::Path<String>,
    body: web::Json<NxProofReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let token = match auth_from_header(&req, &data.jwt_secret) {
        Some(token) => token,
        None => return unauthorized(),
    };
    let zone_id = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &token, Level::Owner).await {
        Ok(access) => access,
        Err(response) => return response,
    };
    let proof_type = body.proof_type.trim().to_ascii_lowercase();
    let (salt, iterations, opt_out) = match proof_type.as_str() {
        "nsec"
            if body.nsec3_salt.is_empty() && body.nsec3_iterations == 0 && !body.nsec3_opt_out =>
        {
            (String::new(), 0, false)
        }
        "nsec3" => {
            let encoded = body.nsec3_salt.trim();
            if encoded.len() > 64
                || encoded.len() % 2 != 0
                || data_encoding::HEXLOWER
                    .decode(encoded.to_ascii_lowercase().as_bytes())
                    .is_err()
            {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "nsec3_salt must be 0 to 32 bytes encoded as hexadecimal"
                }));
            }
            if !(0..=150).contains(&body.nsec3_iterations) {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "nsec3_iterations must be between 0 and 150"
                }));
            }
            (
                encoded.to_ascii_lowercase(),
                body.nsec3_iterations,
                body.nsec3_opt_out,
            )
        }
        "nsec" => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "NSEC does not accept NSEC3 parameters"
            }));
        }
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "proof_type must be nsec or nsec3"
            }));
        }
    };
    let previous = match data.db.query_opt(
        "SELECT dnssec_enabled, COALESCE(dnssec_proof_type, 'nsec'), COALESCE(dnssec_nsec3_salt, ''), COALESCE(dnssec_nsec3_iterations, 0), COALESCE(dnssec_nsec3_opt_out, false) FROM zones WHERE CAST(id AS varchar) = $1",
        &[&zone_id],
    ).await {
        Ok(Some(row)) => row,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error":"zone not found"})),
        Err(error) => return db_err("read denial proof settings", &error),
    };
    if !previous.get::<_, bool>(0) {
        return HttpResponse::Conflict().json(serde_json::json!({"error":"DNSSEC must be enabled before changing denial proof settings"}));
    }
    let old_type: String = previous.get(1);
    let old_salt: String = previous.get(2);
    let old_iterations: i32 = previous.get(3);
    let old_opt_out: bool = previous.get(4);
    if let Err(error) = data.db.execute(
        "UPDATE zones SET dnssec_proof_type=$2, dnssec_nsec3_salt=$3, dnssec_nsec3_iterations=$4, dnssec_nsec3_opt_out=$5, updated_at=now() WHERE CAST(id AS varchar)=$1",
        &[&zone_id, &proof_type, &salt, &iterations, &opt_out],
    ).await {
        return db_err("update denial proof settings", &error);
    }
    if let Some(error) = publish(&data, &access.domain).await {
        if let Err(restore_error) = data.db.execute(
            "UPDATE zones SET dnssec_proof_type=$2, dnssec_nsec3_salt=$3, dnssec_nsec3_iterations=$4, dnssec_nsec3_opt_out=$5, updated_at=now() WHERE CAST(id AS varchar)=$1",
            &[&zone_id, &old_type, &old_salt, &old_iterations, &old_opt_out],
        ).await {
            warn!("failed to restore denial proof settings for {}: {}", zone_id, full_error_string(&restore_error));
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error":"publish_failed_rollback_failed", "saved":false, "published":false
            }));
        }
        let _ = data.dns_manager.regenerate_zones(data.db.clone()).await;
        return publish_failed_rolled_back(&error);
    }
    audit(
        &data.db,
        Some(&token.claims.sub),
        "dnssec_denial_proof_updated",
        "zone",
        Some(zone_id.clone()),
        &req,
        serde_json::json!({"proof_type":proof_type,"nsec3_salt":salt,"nsec3_iterations":iterations,"nsec3_opt_out":opt_out}),
    ).await;
    match describe(&data.db, &zone_id, &access.domain).await {
        Ok(description) => HttpResponse::Ok().json(description),
        Err(response) => response,
    }
}

fn ds_equal(expected: &serde_json::Value, found: &serde_json::Value) -> bool {
    expected["key_tag"] == found["key_tag"]
        && expected["algorithm"] == found["algorithm"]
        && expected["digest_type"] == found["digest_type"]
        && expected["digest"]
            .as_str()
            .zip(found["digest"].as_str())
            .map(|(a, b)| a.eq_ignore_ascii_case(b))
            .unwrap_or(false)
}

/// Verify that the parent publishes the DS records for every live key and
/// report missing/stale entries (DNSSEC-006). Read-only: no state is changed.
pub async fn ds_status(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &tok, Level::Read).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let enabled: bool = match data
        .db
        .query_one(
            "SELECT COALESCE(dnssec_enabled, false) FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zone_id],
        )
        .await
    {
        Ok(r) => r.get(0),
        Err(e) => return db_err("ds-status", &e),
    };
    if !enabled {
        return HttpResponse::Ok().json(serde_json::json!({
            "enabled": false, "domain": access.domain, "published": false,
            "message": "DNSSEC is not enabled for this zone"
        }));
    }
    let rows = match data
        .db
        .query(
            "SELECT key_tag, algorithm, public_key, status FROM dnssec_keys \
             WHERE CAST(zone_id AS varchar) = $1 AND status <> 'retired'",
            &[&zone_id],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return db_err("ds-status keys", &e),
    };
    let mut expected = Vec::new();
    for r in rows {
        let tag: i32 = r.get(0);
        let alg_s: String = r.get(1);
        let pk_b64: String = r.get(2);
        let status: String = r.get(3);
        let alg = parse_algorithm(&alg_s).unwrap_or(Algorithm::ECDSAP256SHA256);
        let pk = data_encoding::BASE64
            .decode(pk_b64.as_bytes())
            .unwrap_or_default();
        for mut ds in ds_records(&access.domain, alg, &pk).unwrap_or_default() {
            ds["key_tag"] = serde_json::json!(tag);
            ds["key_status"] = serde_json::json!(status);
            expected.push(ds);
        }
    }
    let found = match ext::lookup_ds(data.verify_resolver, &access.domain).await {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "parent DS lookup failed", "details": e
            }));
        }
    };
    let missing: Vec<serde_json::Value> = expected
        .iter()
        .filter(|e| !found.iter().any(|f| ds_equal(e, f)))
        .cloned()
        .collect();
    let stale: Vec<serde_json::Value> = found
        .iter()
        .filter(|f| !expected.iter().any(|e| ds_equal(e, f)))
        .cloned()
        .collect();
    let published = !found.is_empty() && missing.is_empty() && stale.is_empty();
    if !published {
        automation::dispatch_event(
            &data.db,
            "dnssec.ds_mismatch",
            "zone",
            Some(&zone_id),
            &serde_json::json!({
                "zone_id": zone_id, "domain": access.domain,
                "missing": missing, "stale": stale,
            }),
        )
        .await;
    }
    HttpResponse::Ok().json(serde_json::json!({
        "enabled": true,
        "domain": access.domain,
        "published": published,
        "expected": expected,
        "found": found,
        "missing": missing,
        "stale": stale,
        "checked_at": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn publish(data: &AppState, zone_domain: &str) -> Option<String> {
    let warning = match data.dns_manager.regenerate_zones(data.db.clone()).await {
        Ok(rep) if rep.failed.is_empty() => None,
        Ok(rep) => Some(format!(
            "publication reported failed zones: {:?}",
            rep.failed
        )),
        Err(e) => Some(format!("publication failed: {e}")),
    };
    if let Some(error) = warning.as_deref() {
        if let Err(queue_error) = data
            .db
            .execute(
                "INSERT INTO publication_outbox(zone_domain, attempts, next_attempt, last_error) \
                 VALUES($1, 0, now(), $2) ON CONFLICT(zone_domain) DO UPDATE SET \
                 attempts=0, status='pending', next_attempt=now(), last_error=EXCLUDED.last_error, updated_at=now()",
                &[&zone_domain, &error],
            )
            .await
        {
            warn!(
                "dnssec publication retry could not be queued for {}: {}",
                zone_domain,
                full_error_string(&queue_error)
            );
        }
    }
    warning
}

/// Store a new key (file first, then the row) for the zone.
async fn add_key(
    data: &AppState,
    zone_id: &str,
    domain: &str,
    algorithm: Algorithm,
    status: &str,
) -> Result<NewKey, HttpResponse> {
    let key = generate_key(algorithm)
        .map_err(|e| HttpResponse::InternalServerError().json(serde_json::json!({"error": e})))?;
    let file = key_file_name(domain, key.key_tag);
    let path = key_dir(data.dns_manager.zone_dir()).join(&file);
    // a (tiny) tag collision with an existing key of this zone would make two keys indistinguishable
    let clash = data.db.query_one("SELECT count(*) FROM dnssec_keys WHERE CAST(zone_id AS varchar) = $1 AND key_tag = $2 AND status <> 'retired'", &[&zone_id, &(key.key_tag as i32)]).await
        .map(|r| r.get::<_, i64>(0)).unwrap_or(0);
    if clash > 0 || path.exists() {
        return Err(
            HttpResponse::Conflict().json(serde_json::json!({"error": "key tag collision, retry"}))
        );
    }
    write_key_file(&path, &key.pem).map_err(|e| {
        warn!("dnssec: cannot write key file {:?}: {}", path, e);
        HttpResponse::InternalServerError().json(serde_json::json!({"error": "cannot write the key file; check DNS directory permissions"}))
    })?;
    let res = data.db.execute(
        "INSERT INTO dnssec_keys (id, zone_id, key_tag, algorithm, public_key, key_file, status) VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6, $7)",
        &[&Uuid::new_v4().to_string(), &zone_id, &(key.key_tag as i32), &algorithm_name(algorithm), &data_encoding::BASE64.encode(&key.public_key), &file, &status],
    ).await;
    if let Err(e) = res {
        let _ = std::fs::remove_file(&path);
        return Err(db_err("insert key", &e));
    }
    Ok(key)
}

pub async fn enable_dnssec(
    path: web::Path<String>,
    body: Option<web::Json<EnableReq>>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &tok, Level::Owner).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let alg_s = match body.and_then(|b| b.algorithm.clone()) {
        Some(algorithm) => algorithm,
        None => data.db.query_opt(
            "SELECT algorithm FROM dnssec_keys WHERE CAST(zone_id AS varchar) = $1 AND status <> 'retired' ORDER BY created_at DESC LIMIT 1",
            &[&zone_id],
        ).await.ok().flatten().map(|r| r.get::<_, String>(0)).unwrap_or_else(|| DEFAULT_ALGORITHM.to_string()),
    };
    let Some(algorithm) = parse_algorithm(&alg_s) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "algorithm must be ECDSAP256SHA256, ECDSAP384SHA384 or ED25519"}));
    };
    let enabled: bool = match data
        .db
        .query_one(
            "SELECT dnssec_enabled FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zone_id],
        )
        .await
    {
        Ok(r) => r.get(0),
        Err(e) => return db_err("enable", &e),
    };
    if enabled {
        return HttpResponse::Conflict()
            .json(serde_json::json!({"error": "DNSSEC is already enabled for this zone"}));
    }
    let active_rules: i64 = data
        .db
        .query_one(
            "SELECT count(*) FROM georules WHERE CAST(zone_id AS varchar) = $1 AND enabled",
            &[&zone_id],
        )
        .await
        .map(|r| r.get(0))
        .unwrap_or(0);
    if active_rules > 0 {
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "geodns_rules_present",
            "details": "GeoDNS answers are synthesised per client and cannot carry a valid signature. Delete or disable this zone's GeoDNS rules before enabling DNSSEC."
        }));
    }
    if let Err(r) = add_key(&data, &zone_id, &access.domain, algorithm, "active").await {
        return r;
    }
    if let Err(e) = data.db.execute("UPDATE zones SET dnssec_enabled = true, geodns_enabled = false, updated_at = now() WHERE CAST(id AS varchar) = $1", &[&zone_id]).await { return db_err("enable flag", &e); }
    let warn_pub = publish(&data, &access.domain).await;
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "dnssec_enable",
        "zone",
        Some(zone_id.clone()),
        &req,
        serde_json::json!({"algorithm": algorithm_name(algorithm)}),
    )
    .await;
    match describe(&data.db, &zone_id, &access.domain).await {
        Ok(mut v) => {
            if let Some(w) = warn_pub {
                v["publish_warning"] = serde_json::json!(w);
            }
            HttpResponse::Created().json(v)
        }
        Err(r) => r,
    }
}

pub async fn rollover_dnssec(
    path: web::Path<String>,
    body: Option<web::Json<EnableReq>>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &tok, Level::Owner).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let enabled: bool = match data
        .db
        .query_one(
            "SELECT dnssec_enabled FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zone_id],
        )
        .await
    {
        Ok(r) => r.get(0),
        Err(e) => return db_err("rollover", &e),
    };
    if !enabled {
        return HttpResponse::Conflict()
            .json(serde_json::json!({"error": "DNSSEC is not enabled for this zone"}));
    }
    let n: i64 = data.db.query_one("SELECT count(*) FROM dnssec_keys WHERE CAST(zone_id AS varchar) = $1 AND status <> 'retired'", &[&zone_id]).await.map(|r| r.get(0)).unwrap_or(0);
    if n >= 2 {
        return HttpResponse::Conflict().json(
            serde_json::json!({"error": "a rollover is already in progress; complete it first"}),
        );
    }
    let alg_s = match body.and_then(|b| b.algorithm.clone()) {
        Some(algorithm) => algorithm,
        None => data
            .db
            .query_opt(
                "SELECT algorithm FROM dnssec_keys WHERE CAST(zone_id AS varchar) = $1 \
                 AND status <> 'retired' ORDER BY created_at DESC LIMIT 1",
                &[&zone_id],
            )
            .await
            .ok()
            .flatten()
            .map(|row| row.get::<_, String>(0))
            .unwrap_or_else(|| DEFAULT_ALGORITHM.to_string()),
    };
    let Some(algorithm) = parse_algorithm(&alg_s) else {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "unsupported algorithm"}));
    };
    if let Err(r) = add_key(&data, &zone_id, &access.domain, algorithm, "new").await {
        return r;
    }
    let warn_pub = publish(&data, &access.domain).await;
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "dnssec_rollover",
        "zone",
        Some(zone_id.clone()),
        &req,
        serde_json::json!({"algorithm": algorithm_name(algorithm)}),
    )
    .await;
    match describe(&data.db, &zone_id, &access.domain).await {
        Ok(mut v) => {
            if let Some(w) = warn_pub {
                v["publish_warning"] = serde_json::json!(w);
            }
            HttpResponse::Created().json(v)
        }
        Err(r) => r,
    }
}

pub async fn complete_rollover(
    path: web::Path<String>,
    body: web::Json<CompleteReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &tok, Level::Owner).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let live = match data.db.query("SELECT key_tag, key_file, status FROM dnssec_keys WHERE CAST(zone_id AS varchar) = $1 AND status <> 'retired'", &[&zone_id]).await { Ok(r) => r, Err(e) => return db_err("complete", &e) };
    if live.len() < 2 {
        return HttpResponse::Conflict()
            .json(serde_json::json!({"error": "no rollover in progress (only one key)"}));
    }
    let Some(victim) = live
        .iter()
        .find(|r| r.get::<_, i32>(0) == body.retire_key_tag)
    else {
        return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "no such active key tag"}));
    };
    let victim_status: String = victim.get(2);
    if victim_status == "new" {
        return HttpResponse::Conflict()
            .json(serde_json::json!({"error": "cannot_retire_new_key"}));
    }
    let file: String = victim.get(1);
    if let Err(e) = data.db.execute(
        "UPDATE dnssec_keys SET status = 'retired', retired_at = now() WHERE CAST(zone_id AS varchar) = $1 AND key_tag = $2 AND status <> 'retired'", &[&zone_id, &body.retire_key_tag]).await { return db_err("retire", &e); }
    // the remaining key becomes the single active key
    let _ = data.db.execute("UPDATE dnssec_keys SET status = 'active' WHERE CAST(zone_id AS varchar) = $1 AND status = 'new'", &[&zone_id]).await;
    let warn_pub = publish(&data, &access.domain).await;
    // keep the retired private key (renamed) rather than deleting it: it may be needed to explain old signatures / undo
    if warn_pub.is_none() {
        let dir = key_dir(data.dns_manager.zone_dir());
        if let Err(e) = std::fs::create_dir_all(dir.join("retired")) {
            warn!("dnssec: cannot create retired key directory: {}", e);
        } else if let Err(e) = std::fs::rename(dir.join(&file), dir.join("retired").join(&file)) {
            warn!("dnssec: cannot archive retired key {}: {}", file, e);
        }
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "dnssec_rollover_complete",
        "zone",
        Some(zone_id.clone()),
        &req,
        serde_json::json!({"retired_key_tag": body.retire_key_tag}),
    )
    .await;
    match describe(&data.db, &zone_id, &access.domain).await {
        Ok(mut v) => {
            if let Some(w) = warn_pub {
                v["publish_warning"] = serde_json::json!(w);
            }
            HttpResponse::Ok().json(v)
        }
        Err(r) => r,
    }
}

pub async fn disable_dnssec(
    path: web::Path<String>,
    body: Option<web::Json<DisableReq>>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &tok, Level::Owner).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let enabled: bool = match data
        .db
        .query_one(
            "SELECT dnssec_enabled FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zone_id],
        )
        .await
    {
        Ok(r) => r.get(0),
        Err(e) => return db_err("disable", &e),
    };
    if !enabled {
        return HttpResponse::Conflict()
            .json(serde_json::json!({"error": "DNSSEC is not enabled for this zone"}));
    }
    if !body.map(|b| b.confirm_ds_removed).unwrap_or(false) {
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "ds_not_confirmed",
            "details": "Remove the DS record at the registrar first and wait for its TTL to expire. Turning DNSSEC off while a DS is still published makes the zone fail validation (SERVFAIL for validating resolvers). Retry with {\"confirm_ds_removed\": true}."
        }));
    }
    let files = data.db.query("SELECT key_file FROM dnssec_keys WHERE CAST(zone_id AS varchar) = $1 AND status <> 'retired'", &[&zone_id]).await.unwrap_or_default();
    if let Err(e) = data.db.execute("UPDATE dnssec_keys SET status = 'retired', retired_at = now() WHERE CAST(zone_id AS varchar) = $1 AND status <> 'retired'", &[&zone_id]).await { return db_err("disable keys", &e); }
    if let Err(e) = data.db.execute("UPDATE zones SET dnssec_enabled = false, updated_at = now() WHERE CAST(id AS varchar) = $1", &[&zone_id]).await { return db_err("disable flag", &e); }
    let warn_pub = publish(&data, &access.domain).await;
    if warn_pub.is_none() {
        let dir = key_dir(data.dns_manager.zone_dir());
        if let Err(e) = std::fs::create_dir_all(dir.join("retired")) {
            warn!("dnssec: cannot create retired key directory: {}", e);
        } else {
            for f in files {
                let f: String = f.get(0);
                if let Err(e) = std::fs::rename(dir.join(&f), dir.join("retired").join(&f)) {
                    warn!("dnssec: cannot archive retired key {}: {}", f, e);
                }
            }
        }
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "dnssec_disable",
        "zone",
        Some(zone_id.clone()),
        &req,
        serde_json::json!({}),
    )
    .await;
    match describe(&data.db, &zone_id, &access.domain).await {
        Ok(mut v) => {
            if let Some(w) = warn_pub {
                v["publish_warning"] = serde_json::json!(w);
            }
            HttpResponse::Ok().json(v)
        }
        Err(r) => r,
    }
}

/// Active key files per zone id for the generator: `(file path, algorithm name)`.
pub async fn load_key_paths(
    db: &Pool,
    zone_dir: &str,
) -> anyhow::Result<HashMap<String, Vec<(String, String)>>> {
    let rows = db.query(
        "SELECT CAST(k.zone_id AS varchar), k.key_file, k.algorithm FROM dnssec_keys k JOIN zones z ON z.id = k.zone_id \
         WHERE z.dnssec_enabled AND k.status <> 'retired' ORDER BY k.created_at, k.key_tag", &[]).await?;
    let dir = key_dir(zone_dir);
    let mut out: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for r in rows {
        let id: String = r.get(0);
        let file: String = r.get(1);
        out.entry(id)
            .or_default()
            .push((dir.join(file).to_string_lossy().to_string(), r.get(2)));
    }
    Ok(out)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn generated_keys_have_consistent_tag_and_ds() {
        for alg in [
            Algorithm::ECDSAP256SHA256,
            Algorithm::ECDSAP384SHA384,
            Algorithm::ED25519,
        ] {
            let k = generate_key(alg).unwrap();
            assert!(
                k.pem.starts_with("-----BEGIN PRIVATE KEY-----\n")
                    && k.pem.trim_end().ends_with("-----END PRIVATE KEY-----")
            );
            let ds = ds_records("Example.COM.", alg, &k.public_key).unwrap();
            assert_eq!(ds.len(), 2);
            assert_eq!(ds[0]["key_tag"].as_u64().unwrap(), k.key_tag as u64);
            assert_eq!(ds[0]["digest"].as_str().unwrap().len(), 64); // SHA-256
            assert_eq!(ds[1]["digest"].as_str().unwrap().len(), 96); // SHA-384
            // owner name is case-insensitive: same digest for any spelling
            let ds2 = ds_records("example.com", alg, &k.public_key).unwrap();
            assert_eq!(ds[0]["digest"], ds2[0]["digest"]);
            assert!(
                ds[0]["text"]
                    .as_str()
                    .unwrap()
                    .starts_with("Example.COM. IN DS ")
            );
        }
    }

    #[test]
    fn ds_comparison_is_case_insensitive_and_checks_all_fields() {
        let a =
            serde_json::json!({"key_tag": 1, "algorithm": 13, "digest_type": 2, "digest": "ABcd"});
        let b =
            serde_json::json!({"key_tag": 1, "algorithm": 13, "digest_type": 2, "digest": "abcd"});
        assert!(ds_equal(&a, &b));
        let mut c = b.clone();
        c["key_tag"] = serde_json::json!(2);
        assert!(!ds_equal(&a, &c));
    }

    #[test]
    fn known_vector_ds_matches_rfc_4509_style_computation() {
        // digest = SHA-256( lowercase-wire(owner) | DNSKEY RDATA ); recompute independently with sha2
        let k = generate_key(Algorithm::ECDSAP256SHA256).unwrap();
        let mut rdata = vec![0x01, 0x01, 3, 13];
        rdata.extend(&k.public_key);
        let mut wire = Vec::new();
        for l in ["example", "com"] {
            wire.push(l.len() as u8);
            wire.extend(l.as_bytes());
        }
        wire.push(0);
        let want = data_encoding::HEXUPPER.encode(&Sha256::digest([wire, rdata].concat()));
        let got = ds_records("example.com", Algorithm::ECDSAP256SHA256, &k.public_key).unwrap();
        assert_eq!(got[0]["digest"].as_str().unwrap(), want);
        // key tag by RFC 4034 appendix B, independently
        let mut r = vec![0x01, 0x01, 3, 13];
        r.extend(&k.public_key);
        let mut ac: u32 = 0;
        for (i, b) in r.iter().enumerate() {
            ac += if i & 1 == 1 {
                *b as u32
            } else {
                (*b as u32) << 8
            };
        }
        ac += (ac >> 16) & 0xFFFF;
        assert_eq!((ac & 0xFFFF) as u16, k.key_tag);
    }

    #[test]
    fn algorithm_parsing() {
        assert_eq!(parse_algorithm("ed25519"), Some(Algorithm::ED25519));
        assert_eq!(parse_algorithm("13"), Some(Algorithm::ECDSAP256SHA256));
        assert_eq!(parse_algorithm("RSASHA1"), None);
        assert_eq!(parse_algorithm("md5"), None);
    }
}

/// Is DNSSEC on for this zone? (GeoDNS may not be turned on for signed zones.)
pub async fn zone_is_signed(db: &Pool, zone_id: &str) -> bool {
    db.query_opt(
        "SELECT dnssec_enabled FROM zones WHERE CAST(id AS varchar) = $1",
        &[&zone_id],
    )
    .await
    .ok()
    .flatten()
    .map(|r| r.get::<_, bool>(0))
    .unwrap_or(false)
}

pub fn geo_conflict() -> HttpResponse {
    HttpResponse::Conflict().json(serde_json::json!({
        "error": "dnssec_enabled",
        "details": "This zone is DNSSEC-signed. GeoDNS answers cannot carry a valid signature; disable DNSSEC first (remove the DS at the registrar, then POST /dnssec/disable)."
    }))
}
