//! Snapshot DNSSEC database metadata and key files into one encrypted archive,
//! or verify a restored key directory against its restored database.

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, IsolationLevel, NoTls};

const MANIFEST: &str = "recovery-manifest.json";
const SNAPSHOT_SQL: &str = r#"
SELECT jsonb_build_object(
  'format_version', 1,
  'captured_at', transaction_timestamp(),
  'zones', COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
      'id', z.id,
      'domain', z.domain,
      'dnssec_enabled', COALESCE(z.dnssec_enabled, false),
      'proof_type', COALESCE(z.dnssec_proof_type, 'nsec'),
      'nsec3_salt', COALESCE(z.dnssec_nsec3_salt, ''),
      'nsec3_iterations', COALESCE(z.dnssec_nsec3_iterations, 0),
      'nsec3_opt_out', COALESCE(z.dnssec_nsec3_opt_out, false)
    ) ORDER BY z.domain)
    FROM zones z
    WHERE COALESCE(z.dnssec_enabled, false)
  ), '[]'::jsonb),
  'keys', COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
      'zone_id', k.zone_id,
      'key_tag', k.key_tag,
      'algorithm', k.algorithm,
      'public_key', k.public_key,
      'key_file', k.key_file,
      'status', k.status,
      'created_at', k.created_at,
      'retired_at', k.retired_at
    ) ORDER BY k.zone_id, k.key_tag)
    FROM dnssec_keys k
    JOIN zones z ON z.id = k.zone_id
    WHERE COALESCE(z.dnssec_enabled, false) OR k.status = 'retired'
  ), '[]'::jsonb)
)
"#;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("DNSSEC recovery operation failed: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let mut args = env::args_os().skip(1);
    let operation = args
        .next()
        .context("usage: dnssec-recovery <backup key-dir archive | verify restored-key-dir>")?;
    let first = args.next().context("key directory is required")?;
    let second = args.next();
    let third = args.next();
    if args.next().is_some() {
        bail!(
            "usage: dnssec-recovery <backup key-dir archive [named.toml] | verify restored-key-dir>"
        );
    }
    let database_url = env::var("DATABASE_URL")
        .context("DATABASE_URL must be supplied through the deployment secret source")?;
    let mut client = connect(&database_url).await?;
    match operation.to_str() {
        Some("backup") => {
            let archive_path = PathBuf::from(second.context("archive destination is required")?);
            let key_dir = Path::new(&first);
            let mut manifest = snapshot_manifest(&mut client).await?;
            validate_active_key_paths(&manifest, key_dir)?;
            let wrapping_key = hickory_key_store::configured_wrapping_key()?;
            let config = if let Some(path) = third {
                let path = PathBuf::from(path);
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    bail!("DNS configuration must be a regular, non-symlink file");
                }
                let bytes = fs::read(path)?;
                manifest["config_sha256"] = Value::String(format!("{:x}", Sha256::digest(&bytes)));
                Some(bytes)
            } else {
                None
            };
            let encoded = serde_json::to_vec(&manifest)?;
            let archive = match config.as_deref() {
                Some(config) => hickory_key_store::create_encrypted_backup_with_config(
                    key_dir,
                    &wrapping_key,
                    &encoded,
                    config,
                )?,
                None => hickory_key_store::create_encrypted_backup_with_manifest(
                    key_dir,
                    &wrapping_key,
                    &encoded,
                )?,
            };
            write_new_private_file(&archive_path, &archive)?;
            println!("wrote encrypted DNSSEC key and metadata recovery archive");
        }
        Some("verify") => {
            if second.is_some() || third.is_some() {
                bail!("usage: dnssec-recovery verify <restored-key-dir>");
            }
            let restored_dir = Path::new(&first);
            let manifest: Value = serde_json::from_slice(&fs::read(restored_dir.join(MANIFEST))?)
                .context("recovery manifest is not valid JSON")?;
            let current = snapshot_manifest(&mut client).await?;
            if manifest.get("zones") != current.get("zones")
                || manifest.get("keys") != current.get("keys")
            {
                bail!("restored database DNSSEC metadata does not match the encrypted manifest");
            }
            if let Some(expected) = manifest.get("config_sha256").and_then(Value::as_str) {
                let config = fs::read(restored_dir.join("named.toml"))
                    .context("restored DNS configuration is missing")?;
                if format!("{:x}", Sha256::digest(&config)) != expected {
                    bail!("restored DNS configuration does not match encrypted manifest");
                }
            }
            validate_restored_active_key_paths(&current, restored_dir)?;
            println!("restored DNSSEC metadata and active key files match");
        }
        _ => bail!("operation must be backup or verify"),
    }
    Ok(())
}

async fn connect(database_url: &str) -> anyhow::Result<Client> {
    let (client, connection) = tokio_postgres::connect(database_url, NoTls)
        .await
        .context("connect to control database")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            log::error!("DNSSEC recovery database connection ended: {error}");
        }
    });
    Ok(client)
}

async fn snapshot_manifest(client: &mut Client) -> anyhow::Result<Value> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await
        .context("begin repeatable-read DNSSEC metadata snapshot")?;
    let row = tx
        .query_one(SNAPSHOT_SQL, &[])
        .await
        .context("read DNSSEC zone and key metadata")?;
    let manifest: Value = row.get(0);
    tx.commit()
        .await
        .context("finish DNSSEC metadata snapshot")?;
    Ok(manifest)
}

fn active_keys(manifest: &Value) -> impl Iterator<Item = &Value> {
    manifest["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|key| matches!(key["status"].as_str(), Some("active" | "new")))
}

fn validate_active_key_paths(manifest: &Value, key_dir: &Path) -> anyhow::Result<()> {
    let root = key_dir
        .canonicalize()
        .context("canonicalize DNSSEC key directory")?;
    for key in active_keys(manifest) {
        let stored = Path::new(
            key["key_file"]
                .as_str()
                .context("key metadata has no path")?,
        );
        let path = if stored.is_absolute() {
            stored.to_path_buf()
        } else {
            root.join(stored)
        };
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("active DNSSEC key file is missing: {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("active DNSSEC key path is not a regular file");
        }
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&root) {
            bail!("active DNSSEC key path is outside the configured key directory");
        }
    }
    Ok(())
}

fn validate_restored_active_key_paths(manifest: &Value, restored_dir: &Path) -> anyhow::Result<()> {
    for key in active_keys(manifest) {
        let name = Path::new(
            key["key_file"]
                .as_str()
                .context("key metadata has no path")?,
        )
        .file_name()
        .context("invalid key filename")?;
        let path = restored_dir.join(name);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("restored active key file is missing: {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("restored active key path is not a regular file");
        }
        let bytes = fs::read(path)?;
        hickory_key_store::decrypt_configured(&bytes)
            .context("restored active key failed authenticated decryption")?;
    }
    Ok(())
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .context("create encrypted archive without replacing existing files")?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error).context("write and sync encrypted DNSSEC archive");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn selects_only_active_and_prepublished_keys_for_file_checks() {
        let manifest = json!({"keys":[
            {"status":"active"}, {"status":"new"}, {"status":"retired"}
        ]});
        assert_eq!(active_keys(&manifest).count(), 2);
    }

    #[test]
    fn active_key_paths_must_be_inside_key_tree_and_regular() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("keys");
        fs::create_dir(&root).unwrap();
        let key = root.join("zone.42.pem");
        fs::write(&key, b"key fixture").unwrap();
        let inside = json!({"keys":[{"status":"active","key_file":key.to_string_lossy()}]});
        assert!(validate_active_key_paths(&inside, &root).is_ok());
        let outside = json!({"keys":[{"status":"active","key_file":temp.path().join("outside.pem").to_string_lossy()}]});
        fs::write(temp.path().join("outside.pem"), b"outside").unwrap();
        assert!(validate_active_key_paths(&outside, &root).is_err());
    }
}
